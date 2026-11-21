//! Maven Central metadata. The search API answers with versions and publish
//! timestamps (milliseconds); it has no owners, downloads, repository, or
//! deprecation concept.

use std::sync::Arc;

use serde::Deserialize;

use crate::http::{HttpClient, HttpError};
use crate::model::PackageSpec;
use crate::registry::PackageMeta;

const DEFAULT_MAVEN_BASE: &str = "https://search.maven.org";
/// Google publishes AndroidX, AGP, Firebase, and Play libraries here, not on
/// Maven Central. It has no search API: versions come from maven-metadata.xml.
const DEFAULT_GOOGLE_BASE: &str = "https://dl.google.com/dl/android/maven2";

#[derive(Debug, thiserror::Error)]
pub enum MavenError {
    #[error("artifact '{0}' was not found on Maven Central")]
    PackageNotFound(String),
    #[error("'{version}' of '{package}' was not found on Maven Central; pass an exact version")]
    VersionNotFound { package: String, version: String },
    #[error("Maven Central rate-limited this client (HTTP 403); retry in a few minutes")]
    Throttled,
    #[error("Maven Central request failed: {0}")]
    Http(String),
    #[error("Maven Central sent a response dep-vet could not read: {0}")]
    Decode(String),
}

pub struct MavenClient {
    http: Arc<HttpClient>,
    base: String,
    google: String,
}

impl MavenClient {
    pub fn from_env(http: Arc<HttpClient>) -> Self {
        let base =
            std::env::var("DEPVET_MAVEN_BASE").unwrap_or_else(|_| DEFAULT_MAVEN_BASE.to_string());
        let google = std::env::var("DEPVET_GOOGLE_MAVEN_BASE")
            .unwrap_or_else(|_| DEFAULT_GOOGLE_BASE.to_string());
        Self::with_bases(http, base, google)
    }

    pub fn with_base(http: Arc<HttpClient>, base: impl Into<String>) -> Self {
        Self::with_bases(http, base, DEFAULT_GOOGLE_BASE)
    }

    pub fn with_bases(
        http: Arc<HttpClient>,
        base: impl Into<String>,
        google: impl Into<String>,
    ) -> Self {
        Self {
            http,
            base: base.into(),
            google: google.into(),
        }
    }

    /// Version list from Google Maven, or `None` when the group is not hosted
    /// there or the artifact does not exist.
    fn google_versions(&self, name: &str) -> Result<Option<(Vec<String>, String)>, MavenError> {
        let (group, artifact) = match name.split_once(':') {
            Some(parts) => parts,
            None => return Ok(None),
        };
        let url = format!(
            "{}/{}/{artifact}/maven-metadata.xml",
            self.google.trim_end_matches('/'),
            group.replace('.', "/")
        );
        let body = match self.http.get(&url) {
            Ok(body) => body,
            Err(HttpError::Status { status: 404, .. }) => return Ok(None),
            Err(error) => return Err(MavenError::Http(error.to_string())),
        };
        let versions = parse_metadata_versions(&body);
        if versions.is_empty() {
            return Ok(None);
        }
        Ok(Some((versions, url)))
    }

    /// Search URL. An exact version is part of the query, because Solr returns
    /// at most 200 rows and older versions of a long-lived artifact fall off
    /// the page (spring-core has 300+).
    fn search_url(&self, name: &str, version: Option<&str>) -> Option<String> {
        let (group, artifact) = name.split_once(':')?;
        let version_filter = version
            .map(|version| format!("+AND+v:%22{version}%22"))
            .unwrap_or_default();
        Some(format!(
            "{}/solrsearch/select?q=g:%22{group}%22+AND+a:%22{artifact}%22{version_filter}&core=gav&rows=200&wt=json",
            self.base.trim_end_matches('/')
        ))
    }

    /// Oldest row of the artifact, used only when the newest page is truncated.
    fn oldest_url(&self, name: &str, start: u64) -> Option<String> {
        let (group, artifact) = name.split_once(':')?;
        Some(format!(
            "{}/solrsearch/select?q=g:%22{group}%22+AND+a:%22{artifact}%22&core=gav&start={start}&rows=1&wt=json",
            self.base.trim_end_matches('/')
        ))
    }

    pub fn fetch(&self, spec: &PackageSpec) -> Result<PackageMeta, MavenError> {
        if is_google_group(&spec.name) {
            match self.google_versions(&spec.name) {
                Ok(Some((versions, url))) => return google_meta(spec, &versions, &url),
                Ok(None) => {}
                Err(error) => return Err(error),
            }
        }

        let result = self.fetch_central(spec);
        // AndroidX and friends are absent from Central, but a Central-hosted
        // artifact can still be named under a Google-looking group.
        let missing = matches!(result, Err(MavenError::PackageNotFound(_)))
            || matches!(result, Err(MavenError::VersionNotFound { .. }));
        if missing && let Ok(Some((versions, url))) = self.google_versions(&spec.name) {
            return google_meta(spec, &versions, &url);
        }
        result
    }

    fn fetch_central(&self, spec: &PackageSpec) -> Result<PackageMeta, MavenError> {
        let url = self
            .search_url(&spec.name, spec.version.as_deref())
            .ok_or_else(|| MavenError::PackageNotFound(spec.name.clone()))?;
        let body = match self.http.get(&url) {
            Ok(body) => body,
            Err(HttpError::Status { status: 404, .. }) => {
                return Err(MavenError::PackageNotFound(spec.name.clone()));
            }
            // Sonatype answers 403 when a client bursts the search API.
            Err(HttpError::Status { status: 403, .. }) => return Err(MavenError::Throttled),
            Err(error) => return Err(MavenError::Http(error.to_string())),
        };
        let response: SearchResponse =
            serde_json::from_str(&body).map_err(|error| MavenError::Decode(error.to_string()))?;

        // A truncated page means "first seen" would be the oldest row we saw,
        // not the oldest release. Ask for the last row instead of guessing.
        let truncated = response.response.doc_count() > response.response.docs.len();
        let oldest = if spec.version.is_none() && truncated {
            self.oldest_url(&spec.name, response.response.num_found.saturating_sub(1))
                .and_then(|url| self.http.get(&url).ok())
                .and_then(|body| serde_json::from_str::<SearchResponse>(&body).ok())
                .and_then(|response| {
                    response
                        .response
                        .docs
                        .iter()
                        .filter_map(|doc| doc.timestamp)
                        .min()
                })
        } else {
            None
        };

        parse_search(spec, &response.response, oldest, &url)
    }
}

fn parse_search(
    spec: &PackageSpec,
    response: &SearchBody,
    oldest: Option<i64>,
    url: &str,
) -> Result<PackageMeta, MavenError> {
    let docs = &response.docs;
    if docs.is_empty() {
        return Err(match &spec.version {
            Some(version) => MavenError::VersionNotFound {
                package: spec.name.clone(),
                version: version.clone(),
            },
            None => MavenError::PackageNotFound(spec.name.clone()),
        });
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
            .filter(|doc| !is_prerelease(&doc.v))
            .max_by_key(|doc| doc.timestamp.unwrap_or(0))
            .or_else(|| docs.iter().max_by_key(|doc| doc.timestamp.unwrap_or(0)))
            .unwrap_or(&docs[0]),
    };

    let latest_version = docs
        .iter()
        .filter(|doc| !is_prerelease(&doc.v))
        .max_by_key(|doc| doc.timestamp.unwrap_or(0))
        .or_else(|| docs.iter().max_by_key(|doc| doc.timestamp.unwrap_or(0)))
        .map(|doc| doc.v.clone());

    let seconds = |millis: i64| millis / 1000;
    let first_published_at = oldest.map(seconds).or_else(|| {
        docs.iter()
            .filter_map(|doc| doc.timestamp)
            .map(seconds)
            .min()
    });
    let recent_releases = crate::registry::count_recent(
        docs.iter().map(|doc| doc.timestamp.map(seconds)),
        crate::cache::now_seconds(),
        crate::registry::HISTORY_WINDOW_DAYS,
    );
    let published_at = release.timestamp.map(seconds);
    let previous = {
        let entries: Vec<(&str, Option<i64>)> = docs
            .iter()
            .map(|doc| (doc.v.as_str(), doc.timestamp.map(seconds)))
            .collect();
        crate::registry::previous_release(&entries, &release.v, published_at)
    };

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
        provenance: crate::model::Provenance::Unavailable,
        attestation_subject_matches: None,
        attestation: None,
        registry_url: url.to_string(),
        review_url: None,
        latest_version,
        candidate_weekly_downloads: None,
        release: crate::registry::ReleaseHistory {
            previous_version: previous.as_ref().map(|(previous, _)| previous.clone()),
            previous_published_at: previous.as_ref().map(|(_, time)| *time),
            recent_releases,
            ..crate::registry::ReleaseHistory::default()
        },
    })
}

/// Groups that publish to Google Maven instead of (or as well as) Central.
fn is_google_group(name: &str) -> bool {
    let group = name.split_once(':').map(|(group, _)| group).unwrap_or(name);
    [
        "androidx.",
        "com.android.",
        "com.google.android.",
        "com.google.firebase",
        "com.google.mlkit",
        "com.google.ar.",
    ]
    .iter()
    .any(|prefix| group.starts_with(prefix))
}

fn google_meta(
    spec: &PackageSpec,
    versions: &[String],
    url: &str,
) -> Result<PackageMeta, MavenError> {
    let version = match &spec.version {
        Some(requested) => versions
            .iter()
            .find(|version| *version == requested)
            .cloned()
            .ok_or_else(|| MavenError::VersionNotFound {
                package: spec.name.clone(),
                version: requested.clone(),
            })?,
        None => versions
            .iter()
            .rfind(|version| !is_prerelease(version))
            .or_else(|| versions.last())
            .cloned()
            .unwrap_or_default(),
    };

    let (group, artifact) = spec.name.split_once(':').unwrap_or((&spec.name, ""));
    Ok(PackageMeta {
        name: spec.name.clone(),
        version: version.clone(),
        // Google's metadata carries no publish times.
        first_published_at: None,
        published_at: None,
        maintainers: Vec::new(),
        publisher: None,
        maintainers_known: false,
        install_scripts: Vec::new(),
        build_from_source: false,
        repository: None,
        deprecated: None,
        provenance: crate::model::Provenance::Unavailable,
        attestation_subject_matches: None,
        attestation: None,
        registry_url: url.to_string(),
        review_url: Some(format!(
            "https://maven.google.com/web/index.html#{group}:{artifact}:{version}"
        )),
        latest_version: versions
            .iter()
            .rfind(|candidate| !is_prerelease(candidate))
            .or_else(|| versions.last())
            .cloned(),
        candidate_weekly_downloads: None,
        release: crate::registry::ReleaseHistory::default(),
    })
}

/// Reads `<version>` elements from `maven-metadata.xml`, in file order.
fn parse_metadata_versions(xml: &str) -> Vec<String> {
    let mut versions = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<version>") {
        let after = &rest[start + "<version>".len()..];
        let Some(end) = after.find("</version>") else {
            break;
        };
        let version = after[..end].trim();
        if !version.is_empty() {
            versions.push(version.to_string());
        }
        rest = &after[end + "</version>".len()..];
    }
    versions
}

/// Maven has no stable flag; milestones, release candidates, and snapshots
/// are recognisable suffixes. Asking for "the latest" should not return one.
fn is_prerelease(version: &str) -> bool {
    let Some((_, suffix)) = version.rsplit_once('-') else {
        return false;
    };
    let suffix = suffix.to_ascii_lowercase();
    [
        "alpha",
        "beta",
        "rc",
        "cr",
        "m",
        "milestone",
        "preview",
        "snapshot",
        "eap",
    ]
    .iter()
    .any(|marker| {
        suffix
            .strip_prefix(marker)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(|c: char| c.is_ascii_digit()))
            || suffix.starts_with(&format!("{marker}-"))
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
    num_found: u64,
}

impl SearchBody {
    /// Solr reports the real number of rows; `docs` may be a truncated page.
    fn doc_count(&self) -> usize {
        self.num_found.max(self.docs.len() as u64) as usize
    }
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
        fetch_with_oldest(body, version, None)
    }

    fn fetch_with_oldest(
        body: &str,
        version: Option<&str>,
        oldest: Option<i64>,
    ) -> Result<PackageMeta, MavenError> {
        let response: SearchResponse = serde_json::from_str(body).unwrap();
        parse_search(
            &spec("org.slf4j:slf4j-api", version),
            &response.response,
            oldest,
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
    fn latest_skips_milestones_and_release_candidates() {
        let body = r#"{ "response": { "numFound": 4, "docs": [
            { "v": "7.0.0-M6", "timestamp": 1749723257000 },
            { "v": "7.0.0-RC1", "timestamp": 1749723256000 },
            { "v": "6.2.11", "timestamp": 1740000000000 },
            { "v": "6.2.10", "timestamp": 1730000000000 }
        ] } }"#;
        let meta = fetch(body, None).unwrap();
        assert_eq!(meta.version, "6.2.11");
    }

    #[test]
    fn only_prereleases_still_resolve_to_the_newest() {
        let body = r#"{ "response": { "numFound": 1, "docs": [
            { "v": "1.0.0-SNAPSHOT", "timestamp": 1730000000000 }
        ] } }"#;
        let meta = fetch(body, None).unwrap();
        assert_eq!(meta.version, "1.0.0-SNAPSHOT");
    }

    #[test]
    fn stable_suffixes_are_not_prereleases() {
        for version in ["1.0.0", "1.0.0.RELEASE", "2.0-jre", "3.0.0.Final"] {
            assert!(!is_prerelease(version), "{version}");
        }
        for version in ["1.0.0-M1", "1.0.0-rc1", "1.0.0-SNAPSHOT", "2.0-beta"] {
            assert!(is_prerelease(version), "{version}");
        }
    }

    #[test]
    fn records_the_previous_release() {
        let meta = fetch(SEARCH, Some("2.0.16")).unwrap();
        assert_eq!(meta.release.previous_version.as_deref(), Some("1.7.36"));
    }

    #[test]
    fn reports_the_newest_stable_version_for_an_older_pin() {
        let meta = fetch(SEARCH, Some("1.7.36")).unwrap();
        assert_eq!(meta.latest_version.as_deref(), Some("2.0.17"));
    }

    #[test]
    fn google_metadata_reports_its_newest_stable_version() {
        let versions = parse_metadata_versions(GOOGLE_METADATA);
        let meta = google_meta(
            &spec("androidx.core:core-ktx", Some("1.13.0")),
            &versions,
            "u",
        )
        .unwrap();
        assert_eq!(meta.latest_version.as_deref(), Some("1.13.1"));
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
        assert!(serde_json::from_str::<SearchResponse>("{ nope").is_err());
    }

    const GOOGLE_METADATA: &str = r#"<?xml version='1.0' encoding='UTF-8'?>
<metadata>
  <groupId>androidx.core</groupId>
  <artifactId>core-ktx</artifactId>
  <versioning>
    <latest>1.14.0-alpha01</latest>
    <release>1.14.0-alpha01</release>
    <versions>
      <version>1.12.0</version>
      <version>1.13.0</version>
      <version>1.13.1</version>
      <version>1.14.0-alpha01</version>
    </versions>
  </versioning>
</metadata>"#;

    #[test]
    fn google_metadata_lists_versions_in_order() {
        assert_eq!(
            parse_metadata_versions(GOOGLE_METADATA),
            vec!["1.12.0", "1.13.0", "1.13.1", "1.14.0-alpha01"]
        );
    }

    #[test]
    fn google_latest_skips_alphas() {
        let versions = parse_metadata_versions(GOOGLE_METADATA);
        let meta = google_meta(
            &spec("androidx.core:core-ktx", None),
            &versions,
            "https://maven.test/meta.xml",
        )
        .unwrap();
        assert_eq!(meta.version, "1.13.1");
        assert_eq!(meta.published_at, None);
        assert_eq!(
            meta.review_url.as_deref(),
            Some("https://maven.google.com/web/index.html#androidx.core:core-ktx:1.13.1")
        );
    }

    #[test]
    fn google_resolves_an_exact_version() {
        let versions = parse_metadata_versions(GOOGLE_METADATA);
        let meta = google_meta(
            &spec("androidx.core:core-ktx", Some("1.13.0")),
            &versions,
            "u",
        )
        .unwrap();
        assert_eq!(meta.version, "1.13.0");
    }

    #[test]
    fn google_missing_version_is_an_error() {
        let versions = parse_metadata_versions(GOOGLE_METADATA);
        assert!(matches!(
            google_meta(
                &spec("androidx.core:core-ktx", Some("9.9.9")),
                &versions,
                "u"
            ),
            Err(MavenError::VersionNotFound { .. })
        ));
    }

    #[test]
    fn google_groups_are_recognised() {
        for name in [
            "androidx.core:core-ktx",
            "com.android.tools.build:gradle",
            "com.google.android.material:material",
            "com.google.firebase:firebase-messaging",
        ] {
            assert!(is_google_group(name), "{name}");
        }
        for name in [
            "org.slf4j:slf4j-api",
            "com.google.guava:guava",
            "junit:junit",
        ] {
            assert!(!is_google_group(name), "{name}");
        }
    }

    #[test]
    fn google_fetch_falls_back_to_central() {
        let versions = parse_metadata_versions(GOOGLE_METADATA);
        assert!(google_meta(&spec("x:y", None), &versions, "u").is_ok());
    }

    #[test]
    fn coordinates_build_the_search_url() {
        let client =
            MavenClient::with_base(Arc::new(HttpClient::with_cache(None)), "https://maven.test");
        assert_eq!(
            client.search_url("org.slf4j:slf4j-api", None).unwrap(),
            "https://maven.test/solrsearch/select?q=g:%22org.slf4j%22+AND+a:%22slf4j-api%22&core=gav&rows=200&wt=json"
        );
        assert_eq!(
            client
                .search_url("org.slf4j:slf4j-api", Some("1.7.36"))
                .unwrap(),
            "https://maven.test/solrsearch/select?q=g:%22org.slf4j%22+AND+a:%22slf4j-api%22+AND+v:%221.7.36%22&core=gav&rows=200&wt=json"
        );
        assert!(client.search_url("no-colon", None).is_none());
    }

    #[test]
    fn an_exact_version_query_that_matches_nothing_is_version_not_found() {
        let body = r#"{ "response": { "numFound": 0, "docs": [] } }"#;
        assert!(matches!(
            fetch(body, Some("9.9.9")),
            Err(MavenError::VersionNotFound { .. })
        ));
    }

    #[test]
    fn a_truncated_page_uses_the_oldest_row_for_first_seen() {
        let page = r#"{
            "response": {
                "numFound": 311,
                "docs": [
                    { "v": "7.0.0-M6", "timestamp": 1749723257000 },
                    { "v": "6.1.16", "timestamp": 1720000000000 }
                ]
            }
        }"#;
        let meta = fetch_with_oldest(page, None, Some(1135357565000)).unwrap();
        assert_eq!(
            meta.first_published_at,
            date::parse_timestamp("2005-12-23T17:06:05Z")
        );
    }

    #[test]
    fn an_untruncated_page_reports_its_own_oldest_row() {
        let meta = fetch(SEARCH, None).unwrap();
        assert_eq!(
            meta.first_published_at,
            date::parse_timestamp("2021-11-03T00:40:00Z")
        );
    }
}
