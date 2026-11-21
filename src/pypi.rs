//! PyPI metadata: the JSON API gives one project with all releases, so the
//! first-publish date and yanked status come from the same response.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Deserialize;

use crate::date;
use crate::http::{HttpClient, HttpError};
use crate::model::PackageSpec;
use crate::registry::PackageMeta;

const DEFAULT_PYPI_BASE: &str = "https://pypi.org";

#[derive(Debug, thiserror::Error)]
pub enum PypiError {
    #[error("package '{0}' was not found on PyPI")]
    PackageNotFound(String),
    #[error("'{}' of '{}' was not found on PyPI; pass an exact version", .version, .package)]
    VersionNotFound { package: String, version: String },
    #[error("PyPI request failed: {0}")]
    Http(String),
    #[error("PyPI sent a response dep-vet could not read: {0}")]
    Decode(String),
}

pub struct PypiClient {
    http: Arc<HttpClient>,
    base: String,
}

impl PypiClient {
    pub fn from_env(http: Arc<HttpClient>) -> Self {
        let base =
            std::env::var("DEPVET_PYPI_BASE").unwrap_or_else(|_| DEFAULT_PYPI_BASE.to_string());
        Self::with_base(http, base)
    }

    pub fn with_base(http: Arc<HttpClient>, base: impl Into<String>) -> Self {
        Self {
            http,
            base: base.into(),
        }
    }

    pub fn project_url(&self, name: &str) -> String {
        format!("{}/pypi/{name}/json", self.base.trim_end_matches('/'))
    }

    pub fn fetch(&self, spec: &PackageSpec) -> Result<PackageMeta, PypiError> {
        let url = self.project_url(&spec.name);
        let body = match self.http.get(&url) {
            Ok(body) => body,
            Err(HttpError::Status { status: 404, .. }) => {
                return Err(PypiError::PackageNotFound(spec.name.clone()));
            }
            Err(error) => return Err(PypiError::Http(error.to_string())),
        };
        parse_project(spec, &body, &url)
    }
}

fn parse_project(spec: &PackageSpec, body: &str, url: &str) -> Result<PackageMeta, PypiError> {
    let project: Project =
        serde_json::from_str(body).map_err(|error| PypiError::Decode(error.to_string()))?;

    let version = spec
        .version
        .clone()
        .unwrap_or_else(|| project.info.version.clone());
    let files = project.releases.get(&version).cloned().unwrap_or_else(|| {
        if version == project.info.version {
            project.urls.clone()
        } else {
            Vec::new()
        }
    });
    if files.is_empty() && version != project.info.version {
        return Err(PypiError::VersionNotFound {
            package: spec.name.clone(),
            version,
        });
    }

    let has_wheel = files
        .iter()
        .any(|file| file.packagetype.as_deref() == Some("bdist_wheel") && !file.yanked);
    let has_sdist = files
        .iter()
        .any(|file| file.packagetype.as_deref() == Some("sdist") && !file.yanked);
    let all_yanked = !files.is_empty() && files.iter().all(|file| file.yanked);
    let yanked_reason = files
        .iter()
        .find_map(|file| file.yanked_reason.clone())
        .filter(|reason| !reason.trim().is_empty());

    let first_published_at = project
        .releases
        .values()
        .flatten()
        .filter_map(file_time)
        .min();
    let published_at = files.iter().filter_map(file_time).min();

    let repository = project
        .info
        .project_urls
        .as_ref()
        .and_then(|urls| {
            urls.iter()
                .find(|(label, _)| {
                    let label = label.to_ascii_lowercase();
                    label.contains("source")
                        || label.contains("repository")
                        || label.contains("code")
                })
                .map(|(_, url)| url.clone())
        })
        .or_else(|| project.info.home_page.clone())
        .filter(|url| !url.trim().is_empty());

    let deprecated = if all_yanked {
        Some(match yanked_reason {
            Some(reason) => format!("this release is yanked: {reason}"),
            None => "this release is yanked".to_string(),
        })
    } else {
        None
    };

    Ok(PackageMeta {
        name: project.info.name,
        version,
        first_published_at,
        published_at,
        maintainers: Vec::new(),
        publisher: None,
        maintainers_known: false,
        install_scripts: Vec::new(),
        build_from_source: has_sdist && !has_wheel,
        repository,
        deprecated,
        registry_url: url.to_string(),
        review_url: None,
    })
}

fn file_time(file: &File) -> Option<i64> {
    file.upload_time_iso_8601
        .as_deref()
        .or(file.upload_time.as_deref())
        .and_then(date::parse_timestamp)
}

#[derive(Debug, Deserialize)]
struct Project {
    info: Info,
    #[serde(default)]
    urls: Vec<File>,
    #[serde(default)]
    releases: BTreeMap<String, Vec<File>>,
}

#[derive(Debug, Deserialize)]
struct Info {
    name: String,
    version: String,
    #[serde(default)]
    home_page: Option<String>,
    #[serde(default)]
    project_urls: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
struct File {
    #[serde(default)]
    packagetype: Option<String>,
    #[serde(default)]
    upload_time: Option<String>,
    #[serde(default)]
    upload_time_iso_8601: Option<String>,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    yanked_reason: Option<String>,
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

    fn fetch(body: &str, version: Option<&str>) -> Result<PackageMeta, PypiError> {
        parse_project(
            &spec("requests", version),
            body,
            "https://pypi.test/pypi/requests/json",
        )
    }

    const WHEEL_AND_SDIST: &str = r#"{
        "info": {
            "name": "requests",
            "version": "2.31.0",
            "home_page": "https://requests.readthedocs.io",
            "project_urls": {
                "Source": "https://github.com/psf/requests",
                "Documentation": "https://docs.example.test"
            }
        },
        "urls": [
            { "packagetype": "bdist_wheel", "upload_time": "2023-05-22T12:00:00" },
            { "packagetype": "sdist", "upload_time": "2023-05-22T12:00:00" }
        ],
        "releases": {
            "2.30.0": [{ "packagetype": "sdist", "upload_time": "2023-05-01T00:00:00" }],
            "2.31.0": [
                { "packagetype": "bdist_wheel", "upload_time": "2023-05-22T12:00:00" },
                { "packagetype": "sdist", "upload_time": "2023-05-22T12:00:00" }
            ]
        }
    }"#;

    #[test]
    fn resolves_the_latest_version() {
        let meta = fetch(WHEEL_AND_SDIST, None).unwrap();
        assert_eq!(meta.version, "2.31.0");
        assert_eq!(meta.name, "requests");
        assert!(!meta.build_from_source, "a wheel exists");
        assert!(meta.maintainers.is_empty());
        assert_eq!(meta.publisher, None);
    }

    #[test]
    fn resolves_an_exact_version() {
        let meta = fetch(WHEEL_AND_SDIST, Some("2.30.0")).unwrap();
        assert_eq!(meta.version, "2.30.0");
        assert!(meta.build_from_source, "sdist only");
    }

    #[test]
    fn missing_version_is_an_error() {
        let error = fetch(WHEEL_AND_SDIST, Some("9.9.9")).unwrap_err();
        assert!(matches!(error, PypiError::VersionNotFound { .. }));
    }

    #[test]
    fn first_publish_is_the_earliest_upload() {
        let meta = fetch(WHEEL_AND_SDIST, None).unwrap();
        assert_eq!(
            meta.first_published_at,
            date::parse_timestamp("2023-05-01T00:00:00")
        );
        assert_eq!(
            meta.published_at,
            date::parse_timestamp("2023-05-22T12:00:00")
        );
    }

    #[test]
    fn source_url_is_preferred_over_homepage() {
        let meta = fetch(WHEEL_AND_SDIST, None).unwrap();
        assert_eq!(
            meta.repository.as_deref(),
            Some("https://github.com/psf/requests")
        );
    }

    #[test]
    fn homepage_is_the_repository_fallback() {
        let body = r#"{
            "info": { "name": "x", "version": "1.0", "home_page": "https://example.test/x" },
            "urls": [{ "packagetype": "bdist_wheel", "upload_time": "2024-01-01T00:00:00" }]
        }"#;
        assert_eq!(
            fetch(body, None).unwrap().repository.as_deref(),
            Some("https://example.test/x")
        );
    }

    #[test]
    fn yanked_release_is_a_deprecation() {
        let body = r#"{
            "info": { "name": "x", "version": "1.0" },
            "urls": [
                { "packagetype": "sdist", "yanked": true, "yanked_reason": "malware" }
            ]
        }"#;
        let meta = fetch(body, None).unwrap();
        assert_eq!(
            meta.deprecated.as_deref(),
            Some("this release is yanked: malware")
        );
    }

    #[test]
    fn partially_yanked_files_are_not_a_yanked_release() {
        let body = r#"{
            "info": { "name": "x", "version": "1.0" },
            "urls": [
                { "packagetype": "sdist", "yanked": true },
                { "packagetype": "bdist_wheel", "yanked": false }
            ]
        }"#;
        let meta = fetch(body, None).unwrap();
        assert_eq!(meta.deprecated, None);
        assert!(!meta.build_from_source, "the wheel is still installable");
    }

    #[test]
    fn missing_optional_fields_still_produce_a_report() {
        let body = r#"{
            "info": { "name": "bare", "version": "0.0.1" },
            "urls": []
        }"#;
        let meta = fetch(body, None).unwrap();
        assert_eq!(meta.version, "0.0.1");
        assert_eq!(meta.first_published_at, None);
        assert_eq!(meta.repository, None);
        assert!(!meta.build_from_source);
    }

    #[test]
    fn malformed_json_is_a_decode_error() {
        assert!(matches!(fetch("{ nope", None), Err(PypiError::Decode(_))));
    }

    #[test]
    fn iso_timestamps_with_z_are_understood() {
        let body = r#"{
            "info": { "name": "x", "version": "1.0" },
            "urls": [
                { "packagetype": "bdist_wheel", "upload_time_iso_8601": "2024-02-29T10:00:00.000Z" }
            ]
        }"#;
        assert_eq!(
            fetch(body, None).unwrap().published_at,
            date::parse_timestamp("2024-02-29T10:00:00Z")
        );
    }
}
