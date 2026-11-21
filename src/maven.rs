//! Maven Central metadata. The search API answers with versions and publish
//! timestamps (milliseconds); it has no owners, downloads, repository, or
//! deprecation concept.

use std::sync::Arc;

use serde::Deserialize;

use crate::http::{HttpClient, HttpError};
use crate::model::PackageSpec;
use crate::registry::PackageMeta;

const DEFAULT_MAVEN_BASE: &str = "https://search.maven.org";

#[derive(Debug, thiserror::Error)]
pub enum MavenError {
    #[error("artifact '{0}' was not found on Maven Central")]
    PackageNotFound(String),
    #[error("'{version}' of '{package}' was not found on Maven Central; pass an exact version")]
    VersionNotFound { package: String, version: String },
    #[error("Maven Central request failed: {0}")]
    Http(String),
    #[error("Maven Central sent a response dep-vet could not read: {0}")]
    Decode(String),
}

pub struct MavenClient {
    http: Arc<HttpClient>,
    base: String,
}

impl MavenClient {
    pub fn from_env(http: Arc<HttpClient>) -> Self {
        let base =
            std::env::var("DEPVET_MAVEN_BASE").unwrap_or_else(|_| DEFAULT_MAVEN_BASE.to_string());
        Self::with_base(http, base)
    }

    pub fn with_base(http: Arc<HttpClient>, base: impl Into<String>) -> Self {
        Self {
            http,
            base: base.into(),
        }
    }

    fn search_url(&self, name: &str) -> Option<String> {
        let (group, artifact) = name.split_once(':')?;
        Some(format!(
            "{}/solrsearch/select?q=g:%22{group}%22+AND+a:%22{artifact}%22&core=gav&rows=200&wt=json",
            self.base.trim_end_matches('/')
        ))
    }

    pub fn fetch(&self, spec: &PackageSpec) -> Result<PackageMeta, MavenError> {
        let url = self
            .search_url(&spec.name)
            .ok_or_else(|| MavenError::PackageNotFound(spec.name.clone()))?;
        let body = match self.http.get(&url) {
            Ok(body) => body,
            Err(HttpError::Status { status: 404, .. }) => {
                return Err(MavenError::PackageNotFound(spec.name.clone()));
            }
            Err(error) => return Err(MavenError::Http(error.to_string())),
        };
        parse_search(spec, &body, &url)
    }
}

fn parse_search(spec: &PackageSpec, body: &str, url: &str) -> Result<PackageMeta, MavenError> {
    let response: SearchResponse =
        serde_json::from_str(body).map_err(|error| MavenError::Decode(error.to_string()))?;
    let docs = response.response.docs;
    if docs.is_empty() {
        return Err(MavenError::PackageNotFound(spec.name.clone()));
    }

    let release = match &spec.version {
        Some(requested) => docs.iter().find(|doc| doc.v == *requested).ok_or_else(|| {
            MavenError::VersionNotFound {
                package: spec.name.clone(),
                version: requested.clone(),
            }
        })?,
        None => docs
            .iter()
            .max_by_key(|doc| doc.timestamp.unwrap_or(0))
            .unwrap_or(&docs[0]),
    };

    let seconds = |millis: i64| millis / 1000;
    let first_published_at = docs
        .iter()
        .filter_map(|doc| doc.timestamp)
        .map(seconds)
        .min();
    let published_at = release.timestamp.map(seconds);

    Ok(PackageMeta {
        name: spec.name.clone(),
        version: release.v.clone(),
        first_published_at,
        published_at,
        maintainers: Vec::new(),
        publisher: None,
        maintainers_known: false,
        install_scripts: Vec::new(),
        build_from_source: false,
        repository: None,
        deprecated: None,
        registry_url: url.to_string(),
    })
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    response: SearchBody,
}

#[derive(Debug, Deserialize)]
struct SearchBody {
    #[serde(default)]
    docs: Vec<Doc>,
    #[serde(rename = "numFound", default)]
    _num_found: u64,
}

#[derive(Debug, Deserialize)]
struct Doc {
    v: String,
    #[serde(default)]
    timestamp: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::date;

    fn spec(name: &str, version: Option<&str>) -> PackageSpec {
        PackageSpec {
            name: name.to_string(),
            version: version.map(str::to_string),
        }
    }

    fn fetch(body: &str, version: Option<&str>) -> Result<PackageMeta, MavenError> {
        parse_search(
            &spec("org.slf4j:slf4j-api", version),
            body,
            "https://maven.test/search",
        )
    }

    const SEARCH: &str = r#"{
        "response": {
            "numFound": 3,
            "docs": [
                { "v": "2.0.17", "timestamp": 1740501794416 },
                { "v": "2.0.16", "timestamp": 1723281308316 },
                { "v": "1.7.36", "timestamp": 1635900000000 }
            ]
        }
    }"#;

    #[test]
    fn resolves_the_newest_version() {
        let meta = fetch(SEARCH, None).unwrap();
        assert_eq!(meta.version, "2.0.17");
        assert_eq!(
            meta.published_at,
            date::parse_timestamp("2025-02-25T16:43:14Z")
        );
    }

    #[test]
    fn resolves_an_exact_version() {
        let meta = fetch(SEARCH, Some("1.7.36")).unwrap();
        assert_eq!(meta.version, "1.7.36");
        assert_eq!(
            meta.first_published_at,
            date::parse_timestamp("2021-11-03T00:40:00Z")
        );
    }

    #[test]
    fn missing_version_is_an_error() {
        assert!(matches!(
            fetch(SEARCH, Some("9.9.9")),
            Err(MavenError::VersionNotFound { .. })
        ));
    }

    #[test]
    fn empty_results_are_not_found() {
        assert!(matches!(
            fetch(r#"{ "response": { "docs": [] } }"#, None),
            Err(MavenError::PackageNotFound(_))
        ));
    }

    #[test]
    fn missing_timestamps_are_tolerated() {
        let body = r#"{ "response": { "docs": [{ "v": "1.0.0" }] } }"#;
        let meta = fetch(body, None).unwrap();
        assert_eq!(meta.first_published_at, None);
        assert_eq!(meta.published_at, None);
    }

    #[test]
    fn malformed_json_is_a_decode_error() {
        assert!(matches!(fetch("{ nope", None), Err(MavenError::Decode(_))));
    }

    #[test]
    fn coordinates_build_the_search_url() {
        let client =
            MavenClient::with_base(Arc::new(HttpClient::with_cache(None)), "https://maven.test");
        assert_eq!(
            client.search_url("org.slf4j:slf4j-api").unwrap(),
            "https://maven.test/solrsearch/select?q=g:%22org.slf4j%22+AND+a:%22slf4j-api%22&core=gav&rows=200&wt=json"
        );
        assert!(client.search_url("no-colon").is_none());
    }
}
