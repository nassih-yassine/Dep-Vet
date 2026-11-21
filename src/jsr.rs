//! JSR metadata. JSR publishes versions, timestamps, a GitHub repository, and
//! an archived flag; it has no owner list, download count, install hooks, or
//! OSV advisories, which `Profile::JSR` reports as not checked.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Deserialize;

use crate::date;
use crate::http::{HttpClient, HttpError};
use crate::model::PackageSpec;
use crate::registry::PackageMeta;

const DEFAULT_JSR_BASE: &str = "https://jsr.io";

#[derive(Debug, thiserror::Error)]
pub enum JsrError {
    #[error("package '{0}' was not found on JSR")]
    PackageNotFound(String),
    #[error("'{version}' of '{package}' was not found on JSR; pass an exact version")]
    VersionNotFound { package: String, version: String },
    #[error("JSR request failed: {0}")]
    Http(String),
    #[error("JSR sent a response dep-vet could not read: {0}")]
    Decode(String),
}

pub struct JsrClient {
    http: Arc<HttpClient>,
    base: String,
}

impl JsrClient {
    pub fn from_env(http: Arc<HttpClient>) -> Self {
        let base =
            std::env::var("DEPVET_JSR_BASE").unwrap_or_else(|_| DEFAULT_JSR_BASE.to_string());
        Self::with_base(http, base)
    }

    pub fn with_base(http: Arc<HttpClient>, base: impl Into<String>) -> Self {
        Self {
            http,
            base: base.into(),
        }
    }

    pub fn meta_url(&self, name: &str) -> String {
        format!("{}/{name}/meta.json", self.base.trim_end_matches('/'))
    }

    fn package_url(&self, scope: &str, name: &str) -> String {
        format!(
            "{}/api/scopes/{scope}/packages/{name}",
            self.base.trim_end_matches('/')
        )
    }

    pub fn fetch(&self, spec: &PackageSpec) -> Result<PackageMeta, JsrError> {
        let (scope, name) =
            split_name(&spec.name).ok_or_else(|| JsrError::PackageNotFound(spec.name.clone()))?;

        let meta_url = self.meta_url(&spec.name);
        let meta_body = match self.http.get(&meta_url) {
            Ok(body) => body,
            Err(HttpError::Status { status: 404, .. }) => {
                return Err(JsrError::PackageNotFound(spec.name.clone()));
            }
            Err(error) => return Err(JsrError::Http(error.to_string())),
        };

        // Repository and archived state are nice-to-have; a failure here must
        // not turn a readable package into a tool error.
        let package_body = self.http.get(&self.package_url(scope, name)).ok();

        parse_package(spec, &meta_body, package_body.as_deref(), &meta_url)
    }
}

fn split_name(name: &str) -> Option<(&str, &str)> {
    name.strip_prefix('@')?.split_once('/')
}

fn parse_package(
    spec: &PackageSpec,
    meta_body: &str,
    package_body: Option<&str>,
    url: &str,
) -> Result<PackageMeta, JsrError> {
    let meta: Meta =
        serde_json::from_str(meta_body).map_err(|error| JsrError::Decode(error.to_string()))?;
    let info: Option<PackageInfo> = package_body.and_then(|body| serde_json::from_str(body).ok());

    let version = spec
        .version
        .clone()
        .or_else(|| meta.latest.clone())
        .ok_or_else(|| JsrError::VersionNotFound {
            package: spec.name.clone(),
            version: "latest".to_string(),
        })?;
    let release = meta
        .versions
        .get(&version)
        .ok_or_else(|| JsrError::VersionNotFound {
            package: spec.name.clone(),
            version: version.clone(),
        })?;

    let first_published_at = meta
        .versions
        .values()
        .filter_map(|release| release.created_at.as_deref())
        .filter_map(date::parse_timestamp)
        .min();

    let repository = info
        .as_ref()
        .and_then(|info| info.github_repository.as_ref())
        .map(|repo| format!("https://github.com/{}/{}", repo.owner, repo.name));
    let published_at = release
        .created_at
        .as_deref()
        .and_then(date::parse_timestamp);
    let previous = {
        let entries: Vec<(&str, Option<i64>)> = meta
            .versions
            .iter()
            .map(|(version, release)| {
                (
                    version.as_str(),
                    release
                        .created_at
                        .as_deref()
                        .and_then(date::parse_timestamp),
                )
            })
            .collect();
        crate::registry::previous_release(&entries, &version, published_at)
    };
    let latest_version = meta.latest.clone();

    let deprecated = info
        .as_ref()
        .filter(|info| info.is_archived)
        .map(|_| "this package is archived by its publisher".to_string());

    Ok(PackageMeta {
        name: spec.name.clone(),
        version,
        first_published_at,
        published_at,
        maintainers: Vec::new(),
        publisher: None,
        maintainers_known: false,
        install_scripts: Vec::new(),
        build_from_source: false,
        repository,
        deprecated,
        registry_url: url.to_string(),
        review_url: None,
        latest_version,
        candidate_weekly_downloads: None,
        release: crate::registry::ReleaseHistory {
            previous_version: previous.as_ref().map(|(previous, _)| previous.clone()),
            previous_published_at: previous.map(|(_, time)| time),
            ..crate::registry::ReleaseHistory::default()
        },
    })
}

#[derive(Debug, Deserialize)]
struct Meta {
    #[serde(default)]
    latest: Option<String>,
    #[serde(default)]
    versions: BTreeMap<String, Release>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Release {
    #[serde(default)]
    created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageInfo {
    #[serde(default)]
    is_archived: bool,
    #[serde(default)]
    github_repository: Option<Repository>,
}

#[derive(Debug, Deserialize)]
struct Repository {
    owner: String,
    name: String,
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

    fn fetch(
        meta: &str,
        package: Option<&str>,
        version: Option<&str>,
    ) -> Result<PackageMeta, JsrError> {
        parse_package(
            &spec("@std/assert", version),
            meta,
            package,
            "https://jsr.test/@std/assert/meta.json",
        )
    }

    const META: &str = r#"{
        "scope": "std",
        "name": "assert",
        "latest": "1.0.19",
        "versions": {
            "0.1.0": { "createdAt": "2024-01-01T00:00:00.000Z" },
            "1.0.19": { "createdAt": "2026-02-20T07:56:26.774Z" }
        }
    }"#;

    const PACKAGE: &str = r#"{
        "scope": "std",
        "name": "assert",
        "createdAt": "2023-12-22T10:58:46.184Z",
        "isArchived": false,
        "githubRepository": { "owner": "denoland", "name": "std" }
    }"#;

    #[test]
    fn resolves_the_latest_version() {
        let meta = fetch(META, Some(PACKAGE), None).unwrap();
        assert_eq!(meta.version, "1.0.19");
        assert_eq!(meta.name, "@std/assert");
        assert_eq!(
            meta.repository.as_deref(),
            Some("https://github.com/denoland/std")
        );
        assert_eq!(meta.deprecated, None);
    }

    #[test]
    fn records_the_previous_release() {
        let meta = fetch(META, None, Some("1.0.19")).unwrap();
        assert_eq!(meta.release.previous_version.as_deref(), Some("0.1.0"));
    }

    #[test]
    fn reports_the_meta_latest_for_an_older_pin() {
        let meta = fetch(META, None, Some("0.1.0")).unwrap();
        assert_eq!(meta.latest_version.as_deref(), Some("1.0.19"));
    }

    #[test]
    fn resolves_an_exact_version() {
        let meta = fetch(META, None, Some("0.1.0")).unwrap();
        assert_eq!(meta.version, "0.1.0");
        assert_eq!(
            meta.first_published_at,
            date::parse_timestamp("2024-01-01T00:00:00Z")
        );
        assert_eq!(
            meta.published_at,
            date::parse_timestamp("2024-01-01T00:00:00Z")
        );
    }

    #[test]
    fn missing_version_is_an_error() {
        assert!(matches!(
            fetch(META, None, Some("9.9.9")),
            Err(JsrError::VersionNotFound { .. })
        ));
    }

    #[test]
    fn an_archived_package_is_deprecated() {
        let package = r#"{"isArchived": true}"#;
        let meta = fetch(META, Some(package), None).unwrap();
        assert_eq!(
            meta.deprecated.as_deref(),
            Some("this package is archived by its publisher")
        );
    }

    #[test]
    fn package_info_failure_still_reports_versions() {
        let meta = fetch(META, None, None).unwrap();
        assert_eq!(meta.repository, None);
        assert_eq!(meta.deprecated, None);
    }

    #[test]
    fn missing_latest_and_version_is_an_error() {
        let body = r#"{ "versions": {} }"#;
        assert!(matches!(
            fetch(body, None, None),
            Err(JsrError::VersionNotFound { .. })
        ));
    }

    #[test]
    fn malformed_meta_is_a_decode_error() {
        assert!(matches!(
            fetch("{ nope", None, None),
            Err(JsrError::Decode(_))
        ));
    }

    #[test]
    fn split_name_requires_a_scope() {
        assert_eq!(split_name("@std/assert"), Some(("std", "assert")));
        assert_eq!(split_name("std/assert"), None);
        assert_eq!(split_name("@std"), None);
    }
}
