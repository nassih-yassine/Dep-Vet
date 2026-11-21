//! Go module metadata from deps.dev, the keyless index that carries publish
//! times and deprecation for every version.
//!
//! Go has no install-time execution, no owner list, no download figure, and no
//! repository link in this API; `Profile::GO` reports those as not checked.

use std::sync::Arc;

use serde::Deserialize;

use crate::date;
use crate::http::{HttpClient, HttpError};
use crate::model::PackageSpec;
use crate::registry::PackageMeta;

const DEFAULT_GO_BASE: &str = "https://api.deps.dev";

#[derive(Debug, thiserror::Error)]
pub enum GoError {
    #[error("module '{0}' was not found on the Go module index")]
    PackageNotFound(String),
    #[error(
        "'{version}' of '{package}' was not found in the Go module index; pass an exact version or tag"
    )]
    VersionNotFound { package: String, version: String },
    #[error("Go module index request failed: {0}")]
    Http(String),
    #[error("Go module index sent a response dep-vet could not read: {0}")]
    Decode(String),
}

pub struct GoClient {
    http: Arc<HttpClient>,
    base: String,
}

impl GoClient {
    pub fn from_env(http: Arc<HttpClient>) -> Self {
        let base = std::env::var("DEPVET_GO_BASE").unwrap_or_else(|_| DEFAULT_GO_BASE.to_string());
        Self::with_base(http, base)
    }

    pub fn with_base(http: Arc<HttpClient>, base: impl Into<String>) -> Self {
        Self {
            http,
            base: base.into(),
        }
    }

    /// Module paths travel as one encoded segment, case preserved.
    pub fn package_url(&self, module: &str) -> String {
        format!(
            "{}/v3/systems/go/packages/{}",
            self.base.trim_end_matches('/'),
            module.replace('/', "%2F")
        )
    }

    pub fn fetch(&self, spec: &PackageSpec) -> Result<PackageMeta, GoError> {
        let url = self.package_url(&spec.name);
        let body = match self.http.get(&url) {
            Ok(body) => body,
            Err(HttpError::Status { status: 404, .. }) => {
                return Err(GoError::PackageNotFound(spec.name.clone()));
            }
            Err(error) => return Err(GoError::Http(error.to_string())),
        };
        parse_module(spec, &body, &url)
    }
}

fn parse_module(spec: &PackageSpec, body: &str, url: &str) -> Result<PackageMeta, GoError> {
    let response: PackageResponse =
        serde_json::from_str(body).map_err(|error| GoError::Decode(error.to_string()))?;

    let not_found = || GoError::VersionNotFound {
        package: spec.name.clone(),
        version: spec.version.clone().unwrap_or_else(|| "latest".to_string()),
    };

    if response.versions.is_empty() {
        return Err(not_found());
    }

    let release = match &spec.version {
        Some(requested) => response
            .versions
            .iter()
            .find(|release| release.version_key.version == *requested)
            .ok_or_else(not_found)?,
        None => response
            .versions
            .iter()
            .find(|release| release.is_default)
            .or_else(|| {
                response.versions.iter().max_by_key(|release| {
                    release
                        .published_at
                        .as_deref()
                        .and_then(date::parse_timestamp)
                        .unwrap_or(0)
                })
            })
            .ok_or_else(not_found)?,
    };

    let first_published_at = response
        .versions
        .iter()
        .filter_map(|release| release.published_at.as_deref())
        .filter_map(date::parse_timestamp)
        .min();

    let deprecated = release
        .is_deprecated
        .then(|| match release.deprecated_reason.trim() {
            "" => "this version is deprecated".to_string(),
            reason => format!("this version is deprecated: {reason}"),
        });

    Ok(PackageMeta {
        name: response.package_key.name,
        version: release.version_key.version.clone(),
        first_published_at,
        published_at: release
            .published_at
            .as_deref()
            .and_then(date::parse_timestamp),
        maintainers: Vec::new(),
        publisher: None,
        maintainers_known: false,
        install_scripts: Vec::new(),
        build_from_source: false,
        repository: None,
        deprecated,
        registry_url: url.to_string(),
        review_url: None,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageResponse {
    package_key: PackageKey,
    #[serde(default)]
    versions: Vec<Release>,
}

#[derive(Debug, Deserialize)]
struct PackageKey {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Release {
    version_key: VersionKey,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    is_default: bool,
    #[serde(default)]
    is_deprecated: bool,
    #[serde(default)]
    deprecated_reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionKey {
    version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, version: Option<&str>) -> PackageSpec {
        PackageSpec {
            name: name.to_string(),
            version: version.map(str::to_string),
        }
    }

    fn fetch(body: &str, version: Option<&str>) -> Result<PackageMeta, GoError> {
        parse_module(
            &spec("github.com/gin-gonic/gin", version),
            body,
            "https://deps.test/v3/systems/go/packages/github.com%2Fgin-gonic%2Fgin",
        )
    }

    const GIN: &str = r#"{
        "packageKey": { "system": "GO", "name": "github.com/gin-gonic/gin" },
        "versions": [
            {
                "versionKey": { "version": "v1.8.0" },
                "publishedAt": "2022-05-30T00:00:00Z",
                "isDefault": false
            },
            {
                "versionKey": { "version": "v1.9.1" },
                "publishedAt": "2023-06-13T00:00:00Z",
                "isDefault": true
            }
        ]
    }"#;

    #[test]
    fn resolves_the_default_version() {
        let meta = fetch(GIN, None).unwrap();
        assert_eq!(meta.version, "v1.9.1");
        assert_eq!(meta.name, "github.com/gin-gonic/gin");
        assert_eq!(meta.deprecated, None);
    }

    #[test]
    fn resolves_an_exact_version() {
        let meta = fetch(GIN, Some("v1.8.0")).unwrap();
        assert_eq!(meta.version, "v1.8.0");
    }

    #[test]
    fn missing_version_is_an_error() {
        let error = fetch(GIN, Some("v9.9.9")).unwrap_err();
        assert!(matches!(error, GoError::VersionNotFound { .. }));
    }

    #[test]
    fn without_a_default_the_newest_publish_wins() {
        let body = r#"{
            "packageKey": { "name": "example.com/m" },
            "versions": [
                { "versionKey": { "version": "v0.2.0" }, "publishedAt": "2020-01-01T00:00:00Z" },
                { "versionKey": { "version": "v0.3.0" }, "publishedAt": "2021-01-01T00:00:00Z" },
                { "versionKey": { "version": "v0.1.0" }, "publishedAt": "2019-01-01T00:00:00Z" }
            ]
        }"#;
        assert_eq!(fetch(body, None).unwrap().version, "v0.3.0");
    }

    #[test]
    fn first_publish_is_the_earliest_version() {
        let meta = fetch(GIN, None).unwrap();
        assert_eq!(
            meta.first_published_at,
            date::parse_timestamp("2022-05-30T00:00:00Z")
        );
        assert_eq!(
            meta.published_at,
            date::parse_timestamp("2023-06-13T00:00:00Z")
        );
    }

    #[test]
    fn deprecation_carries_its_reason() {
        let body = r#"{
            "packageKey": { "name": "example.com/old" },
            "versions": [{
                "versionKey": { "version": "v1.0.0" },
                "isDefault": true,
                "isDeprecated": true,
                "deprecatedReason": "use example.com/new"
            }]
        }"#;
        assert_eq!(
            fetch(body, None).unwrap().deprecated.as_deref(),
            Some("this version is deprecated: use example.com/new")
        );
    }

    #[test]
    fn deprecation_without_a_reason_still_warns() {
        let body = r#"{
            "packageKey": { "name": "example.com/old" },
            "versions": [{ "versionKey": { "version": "v1.0.0" }, "isDefault": true, "isDeprecated": true }]
        }"#;
        assert_eq!(
            fetch(body, None).unwrap().deprecated.as_deref(),
            Some("this version is deprecated")
        );
    }

    #[test]
    fn a_module_without_versions_is_an_error() {
        let body = r#"{ "packageKey": { "name": "example.com/m" }, "versions": [] }"#;
        assert!(matches!(
            fetch(body, None),
            Err(GoError::VersionNotFound { .. })
        ));
    }

    #[test]
    fn missing_publish_times_are_tolerated() {
        let body = r#"{
            "packageKey": { "name": "example.com/m" },
            "versions": [{ "versionKey": { "version": "v1.0.0" }, "isDefault": true }]
        }"#;
        let meta = fetch(body, None).unwrap();
        assert_eq!(meta.first_published_at, None);
        assert_eq!(meta.published_at, None);
    }

    #[test]
    fn malformed_json_is_a_decode_error() {
        assert!(matches!(fetch("{ nope", None), Err(GoError::Decode(_))));
    }

    #[test]
    fn uppercase_module_paths_are_preserved_and_encoded() {
        let client =
            GoClient::with_base(Arc::new(HttpClient::with_cache(None)), "https://deps.test");
        assert_eq!(
            client.package_url("github.com/BurntSushi/toml"),
            "https://deps.test/v3/systems/go/packages/github.com%2FBurntSushi%2Ftoml"
        );
    }
}
