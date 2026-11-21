//! crates.io metadata. The API needs a User-Agent (the shared client sets one)
//! and returns owner logins separately, so maintainer agreement costs a second
//! request that is allowed to fail.

use std::sync::Arc;

use serde::Deserialize;

use crate::date;
use crate::http::{HttpClient, HttpError};
use crate::model::PackageSpec;
use crate::registry::PackageMeta;

const DEFAULT_CRATES_BASE: &str = "https://crates.io";

#[derive(Debug, thiserror::Error)]
pub enum CratesError {
    #[error("crate '{0}' was not found on crates.io")]
    PackageNotFound(String),
    #[error("'{version}' of '{package}' was not found on crates.io; pass an exact version")]
    VersionNotFound { package: String, version: String },
    #[error("crates.io request failed: {0}")]
    Http(String),
    #[error("crates.io sent a response dep-vet could not read: {0}")]
    Decode(String),
}

pub struct CratesClient {
    http: Arc<HttpClient>,
    base: String,
}

impl CratesClient {
    pub fn from_env(http: Arc<HttpClient>) -> Self {
        let base =
            std::env::var("DEPVET_CRATES_BASE").unwrap_or_else(|_| DEFAULT_CRATES_BASE.to_string());
        Self::with_base(http, base)
    }

    pub fn with_base(http: Arc<HttpClient>, base: impl Into<String>) -> Self {
        Self {
            http,
            base: base.into(),
        }
    }

    pub fn crate_url(&self, name: &str) -> String {
        format!("{}/api/v1/crates/{name}", self.base.trim_end_matches('/'))
    }

    pub fn fetch(&self, spec: &PackageSpec) -> Result<PackageMeta, CratesError> {
        let url = self.crate_url(&spec.name);
        let body = match self.http.get(&url) {
            Ok(body) => body,
            Err(HttpError::Status { status: 404, .. }) => {
                return Err(CratesError::PackageNotFound(spec.name.clone()));
            }
            Err(error) => return Err(CratesError::Http(error.to_string())),
        };

        // Owners are optional: a failure degrades to "maintainer list
        // unavailable", never to "no maintainer problem found".
        let owners_url = format!("{}/owners", url);
        let owners = self.http.get(&owners_url).ok();

        parse_crate(spec, &body, &url, owners.as_deref())
    }
}

fn parse_crate(
    spec: &PackageSpec,
    body: &str,
    url: &str,
    owners_body: Option<&str>,
) -> Result<PackageMeta, CratesError> {
    let response: CrateResponse =
        serde_json::from_str(body).map_err(|error| CratesError::Decode(error.to_string()))?;

    let version = spec
        .version
        .clone()
        .or_else(|| response.krate.max_stable_version.clone())
        .unwrap_or_else(|| response.krate.max_version.clone());
    let release = response
        .versions
        .iter()
        .find(|release| release.num == version)
        .ok_or_else(|| CratesError::VersionNotFound {
            package: spec.name.clone(),
            version: version.clone(),
        })?;

    let (maintainers, maintainers_known) = match owners_body.and_then(parse_owner_logins) {
        Some(logins) => (logins, true),
        // Missing or unreadable owners is "unknown", never "none".
        None => (Vec::new(), false),
    };

    let deprecated = release.yanked.then(|| match &release.yank_message {
        Some(message) if !message.trim().is_empty() => {
            format!("this version is yanked: {message}")
        }
        _ => "this version is yanked".to_string(),
    });

    Ok(PackageMeta {
        name: response.krate.name,
        version,
        first_published_at: response
            .krate
            .created_at
            .as_deref()
            .and_then(date::parse_timestamp),
        published_at: release
            .created_at
            .as_deref()
            .and_then(date::parse_timestamp),
        maintainers,
        publisher: release.published_by.as_ref().map(|user| user.login.clone()),
        maintainers_known,
        install_scripts: Vec::new(),
        // crates.io metadata does not list files, so build.rs cannot be seen.
        build_from_source: false,
        repository: response
            .krate
            .repository
            .filter(|url| !url.trim().is_empty()),
        deprecated,
        registry_url: url.to_string(),
        review_url: None,
    })
}

fn parse_owner_logins(body: &str) -> Option<Vec<String>> {
    let owners: OwnersResponse = serde_json::from_str(body).ok()?;
    Some(owners.users.into_iter().map(|user| user.login).collect())
}

#[derive(Debug, Deserialize)]
struct CrateResponse {
    #[serde(rename = "crate")]
    krate: CrateInfo,
    #[serde(default)]
    versions: Vec<Release>,
}

#[derive(Debug, Deserialize)]
struct CrateInfo {
    name: String,
    max_version: String,
    #[serde(default)]
    max_stable_version: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    repository: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Release {
    num: String,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    yank_message: Option<String>,
    #[serde(default)]
    published_by: Option<User>,
}

#[derive(Debug, Deserialize)]
struct User {
    login: String,
}

#[derive(Debug, Deserialize)]
struct OwnersResponse {
    #[serde(default)]
    users: Vec<User>,
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

    fn fetch(body: &str, version: Option<&str>) -> Result<PackageMeta, CratesError> {
        parse_crate(
            &spec("serde", version),
            body,
            "https://crates.test/api/v1/crates/serde",
            Some(r#"{"users":[{"login":"dtolnay"},{"login":"oli-obk"}]}"#),
        )
    }

    const SERDE: &str = r#"{
        "crate": {
            "name": "serde",
            "max_version": "1.0.229",
            "max_stable_version": "1.0.229",
            "created_at": "2014-12-20T00:00:00Z",
            "repository": "https://github.com/serde-rs/serde"
        },
        "versions": [
            {
                "num": "1.0.229",
                "created_at": "2026-10-01T00:00:00Z",
                "yanked": false,
                "published_by": { "login": "dtolnay" }
            },
            {
                "num": "1.0.1",
                "created_at": "2015-01-01T00:00:00Z",
                "yanked": true,
                "yank_message": "broken build",
                "published_by": { "login": "oli-obk" }
            }
        ]
    }"#;

    #[test]
    fn resolves_the_latest_stable_version() {
        let meta = fetch(SERDE, None).unwrap();
        assert_eq!(meta.version, "1.0.229");
        assert_eq!(meta.name, "serde");
        assert_eq!(meta.publisher.as_deref(), Some("dtolnay"));
        assert_eq!(meta.maintainers, vec!["dtolnay", "oli-obk"]);
        assert!(meta.maintainers_known);
        assert_eq!(meta.deprecated, None);
    }

    #[test]
    fn resolves_an_exact_version() {
        let meta = fetch(SERDE, Some("1.0.1")).unwrap();
        assert_eq!(meta.version, "1.0.1");
        assert_eq!(meta.publisher.as_deref(), Some("oli-obk"));
        assert_eq!(
            meta.deprecated.as_deref(),
            Some("this version is yanked: broken build")
        );
    }

    #[test]
    fn missing_version_is_an_error() {
        let error = fetch(SERDE, Some("9.9.9")).unwrap_err();
        assert!(matches!(error, CratesError::VersionNotFound { .. }));
    }

    #[test]
    fn yanked_without_message_still_warns() {
        let body = r#"{
            "crate": { "name": "x", "max_version": "1.0.0" },
            "versions": [{ "num": "1.0.0", "yanked": true }]
        }"#;
        assert_eq!(
            fetch(body, None).unwrap().deprecated.as_deref(),
            Some("this version is yanked")
        );
    }

    #[test]
    fn owners_failure_marks_the_list_unknown() {
        let meta = parse_crate(
            &spec("serde", None),
            SERDE,
            "https://crates.test/api/v1/crates/serde",
            None,
        )
        .unwrap();
        assert!(!meta.maintainers_known);
        assert!(meta.maintainers.is_empty());
    }

    #[test]
    fn malformed_owners_is_unknown_not_empty() {
        let meta = parse_crate(
            &spec("serde", None),
            SERDE,
            "https://crates.test/api/v1/crates/serde",
            Some("not json"),
        )
        .unwrap();
        assert!(!meta.maintainers_known);
    }

    #[test]
    fn trusted_publishing_without_a_publisher_is_fine() {
        let body = r#"{
            "crate": { "name": "x", "max_version": "1.0.0" },
            "versions": [{ "num": "1.0.0", "published_by": null }]
        }"#;
        let meta = fetch(body, None).unwrap();
        assert_eq!(meta.publisher, None);
        assert_eq!(meta.maintainers.len(), 2);
    }

    #[test]
    fn timestamps_and_repository_come_through() {
        let meta = fetch(SERDE, None).unwrap();
        assert_eq!(
            meta.first_published_at,
            date::parse_timestamp("2014-12-20T00:00:00Z")
        );
        assert_eq!(
            meta.repository.as_deref(),
            Some("https://github.com/serde-rs/serde")
        );
        assert!(!meta.build_from_source, "crates never claim build.rs");
    }

    #[test]
    fn malformed_json_is_a_decode_error() {
        assert!(matches!(fetch("{ nope", None), Err(CratesError::Decode(_))));
    }

    #[test]
    fn missing_stable_version_falls_back_to_max_version() {
        let body = r#"{
            "crate": { "name": "x", "max_version": "0.0.1-alpha.1" },
            "versions": [{ "num": "0.0.1-alpha.1" }]
        }"#;
        assert_eq!(fetch(body, None).unwrap().version, "0.0.1-alpha.1");
    }
}
