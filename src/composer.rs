//! Packagist metadata for Composer packages. The `p2` endpoint lists every
//! version with its publish time and source URL; the package endpoint adds the
//! maintainer list, download totals, and the abandoned flag.

use std::sync::Arc;

use serde::Deserialize;

use crate::date;
use crate::http::{HttpClient, HttpError};
use crate::model::PackageSpec;
use crate::registry::{PackageMeta, normalize_repository};

const DEFAULT_COMPOSER_BASE: &str = "https://repo.packagist.org";
const DEFAULT_PACKAGIST_BASE: &str = "https://packagist.org";

#[derive(Debug, thiserror::Error)]
pub enum ComposerError {
    #[error("package '{0}' was not found on Packagist")]
    PackageNotFound(String),
    #[error("'{version}' of '{package}' was not found on Packagist; pass an exact version")]
    VersionNotFound { package: String, version: String },
    #[error("Packagist request failed: {0}")]
    Http(String),
    #[error("Packagist sent a response dep-vet could not read: {0}")]
    Decode(String),
}

pub struct ComposerClient {
    http: Arc<HttpClient>,
    base: String,
    packagist: String,
}

impl ComposerClient {
    pub fn from_env(http: Arc<HttpClient>) -> Self {
        let base = std::env::var("DEPVET_COMPOSER_BASE")
            .unwrap_or_else(|_| DEFAULT_COMPOSER_BASE.to_string());
        let packagist = std::env::var("DEPVET_PACKAGIST_BASE")
            .unwrap_or_else(|_| DEFAULT_PACKAGIST_BASE.to_string());
        Self::with_bases(http, base, packagist)
    }

    pub fn with_bases(
        http: Arc<HttpClient>,
        base: impl Into<String>,
        packagist: impl Into<String>,
    ) -> Self {
        Self {
            http,
            base: base.into(),
            packagist: packagist.into(),
        }
    }

    fn p2_url(&self, name: &str) -> String {
        format!("{}/p2/{name}.json", self.base.trim_end_matches('/'))
    }

    fn package_url(&self, name: &str) -> String {
        format!(
            "{}/packages/{name}.json",
            self.packagist.trim_end_matches('/')
        )
    }

    pub fn fetch(&self, spec: &PackageSpec) -> Result<PackageMeta, ComposerError> {
        let url = self.p2_url(&spec.name);
        let body = match self.http.get(&url) {
            Ok(body) => body,
            Err(HttpError::Status { status: 404, .. }) => {
                return Err(ComposerError::PackageNotFound(spec.name.clone()));
            }
            Err(error) => return Err(ComposerError::Http(error.to_string())),
        };

        // Maintainers and the abandoned flag live on the package endpoint only.
        // A failure still leaves versions and times, so it is best effort.
        let package = self
            .http
            .get(&self.package_url(&spec.name))
            .ok()
            .and_then(|body| serde_json::from_str::<PackageWrapper>(&body).ok())
            .map(|wrapper| wrapper.package);

        parse_metadata(spec, &body, package.as_ref(), &url)
    }
}

fn parse_metadata(
    spec: &PackageSpec,
    body: &str,
    package: Option<&Package>,
    url: &str,
) -> Result<PackageMeta, ComposerError> {
    let response: P2 =
        serde_json::from_str(body).map_err(|error| ComposerError::Decode(error.to_string()))?;
    let releases = response
        .packages
        .and_then(|mut packages| packages.remove(&spec.name));
    let releases = match releases {
        Some(releases) if !releases.is_empty() => releases,
        _ => return Err(ComposerError::PackageNotFound(spec.name.clone())),
    };

    let release = match &spec.version {
        Some(requested) => releases
            .iter()
            .find(|release| release.matches(requested))
            .ok_or_else(|| ComposerError::VersionNotFound {
                package: spec.name.clone(),
                version: requested.clone(),
            })?,
        None => latest(&releases),
    };

    let first_published_at = releases
        .iter()
        .filter_map(|release| release.time.as_deref())
        .filter_map(date::parse_timestamp)
        .min();

    let repository = release
        .source
        .as_ref()
        .map(|source| source.url.as_str())
        .filter(|url| !url.trim().is_empty())
        .map(normalize_repository)
        .or_else(|| {
            package
                .and_then(|package| package.repository.clone())
                .filter(|url| !url.trim().is_empty())
        });

    let (maintainers, maintainers_known) = match package {
        Some(package) => (
            package
                .maintainers
                .iter()
                .map(|maintainer| maintainer.name.clone())
                .collect(),
            true,
        ),
        None => (Vec::new(), false),
    };

    Ok(PackageMeta {
        name: spec.name.clone(),
        version: release.version.clone(),
        first_published_at,
        published_at: release.time.as_deref().and_then(date::parse_timestamp),
        maintainers,
        // Composer records authors, not who published this version.
        publisher: None,
        maintainers_known,
        install_scripts: Vec::new(),
        build_from_source: false,
        repository,
        deprecated: package.and_then(|package| abandoned(&package.abandoned)),
        registry_url: url.to_string(),
    })
}

/// Newest tagged release by publish time. Branch aliases (`dev-main`) are not
/// releases and are skipped.
fn latest(releases: &[Release]) -> &Release {
    releases
        .iter()
        .filter(|release| !is_dev(&release.version))
        .max_by_key(|release| release.time.as_deref().and_then(date::parse_timestamp))
        .unwrap_or(&releases[0])
}

fn is_dev(version: &str) -> bool {
    version.starts_with("dev-") || version.ends_with("-dev")
}

fn abandoned(value: &Option<serde_json::Value>) -> Option<String> {
    match value.as_ref()? {
        serde_json::Value::String(replacement) if !replacement.trim().is_empty() => Some(format!(
            "this package is abandoned; the publisher suggests {replacement}"
        )),
        serde_json::Value::Bool(true) | serde_json::Value::String(_) => {
            Some("this package is abandoned on Packagist".to_string())
        }
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
struct P2 {
    #[serde(default)]
    packages: Option<std::collections::BTreeMap<String, Vec<Release>>>,
}

#[derive(Debug, Deserialize)]
struct Release {
    version: String,
    #[serde(default)]
    time: Option<String>,
    #[serde(default)]
    source: Option<Source>,
}

impl Release {
    /// Composer allows a leading `v` in pretty versions and lockfiles, while
    /// the registry may drop it (or keep it); compare without it.
    fn matches(&self, requested: &str) -> bool {
        let strip = |version: &str| version.trim_start_matches('v').to_string();
        self.version == requested || strip(&self.version) == strip(requested)
    }
}

#[derive(Debug, Deserialize)]
struct Source {
    url: String,
}

#[derive(Debug, Deserialize)]
struct PackageWrapper {
    package: Package,
}

#[derive(Debug, Deserialize)]
struct Package {
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    maintainers: Vec<Maintainer>,
    #[serde(default)]
    abandoned: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Maintainer {
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

    const P2: &str = r#"{
        "packages": {
            "monolog/monolog": [
                {
                    "version": "dev-main",
                    "source": { "url": "https://github.com/Seldaek/monolog.git" }
                },
                {
                    "version": "3.13.0",
                    "time": "2026-11-16T10:43:05+00:00",
                    "source": { "url": "https://github.com/Seldaek/monolog.git" }
                },
                {
                    "version": "3.0.0",
                    "time": "2024-01-01T00:00:00+00:00",
                    "source": { "url": "https://github.com/Seldaek/monolog.git" }
                }
            ]
        }
    }"#;

    const PACKAGE: &str = r#"{
        "package": {
            "name": "monolog/monolog",
            "repository": "https://github.com/Seldaek/monolog",
            "maintainers": [{ "name": "Seldaek" }],
            "abandoned": false
        }
    }"#;

    fn package() -> Package {
        serde_json::from_str::<PackageWrapper>(PACKAGE)
            .unwrap()
            .package
    }

    #[test]
    fn resolves_the_newest_release_and_skips_dev_branches() {
        let meta =
            parse_metadata(&spec("monolog/monolog", None), P2, Some(&package()), "url").unwrap();
        assert_eq!(meta.version, "3.13.0");
        assert_eq!(
            meta.repository.as_deref(),
            Some("https://github.com/Seldaek/monolog.git")
        );
    }

    #[test]
    fn resolves_an_exact_version() {
        let meta = parse_metadata(
            &spec("monolog/monolog", Some("3.0.0")),
            P2,
            Some(&package()),
            "url",
        )
        .unwrap();
        assert_eq!(meta.version, "3.0.0");
        assert_eq!(
            meta.first_published_at,
            date::parse_timestamp("2024-01-01T00:00:00Z")
        );
    }

    #[test]
    fn a_leading_v_resolves_either_way() {
        let body = r#"{ "packages": { "x/y": [ { "version": "v1.2.3", "time": "2024-01-01T00:00:00Z" } ] } }"#;
        let meta = parse_metadata(&spec("x/y", Some("1.2.3")), body, None, "url").unwrap();
        assert_eq!(meta.version, "v1.2.3");
    }

    #[test]
    fn maintainers_come_from_the_package_endpoint() {
        let meta =
            parse_metadata(&spec("monolog/monolog", None), P2, Some(&package()), "url").unwrap();
        assert!(meta.maintainers_known);
        assert_eq!(meta.maintainers, vec!["Seldaek".to_string()]);
    }

    #[test]
    fn a_missing_package_endpoint_is_unknown_not_empty() {
        let meta = parse_metadata(&spec("monolog/monolog", None), P2, None, "url").unwrap();
        assert!(!meta.maintainers_known);
        assert!(meta.maintainers.is_empty());
    }

    #[test]
    fn abandoned_packages_are_deprecated() {
        let body = r#"{
            "package": {
                "maintainers": [],
                "abandoned": "symfony/console"
            }
        }"#;
        let package = serde_json::from_str::<PackageWrapper>(body)
            .unwrap()
            .package;
        let meta =
            parse_metadata(&spec("monolog/monolog", None), P2, Some(&package), "url").unwrap();
        assert_eq!(
            meta.deprecated.as_deref(),
            Some("this package is abandoned; the publisher suggests symfony/console")
        );
    }

    #[test]
    fn repository_falls_back_to_the_package_endpoint() {
        let p2 = r#"{ "packages": { "x/y": [ { "version": "1.0.0", "time": "2024-01-01T00:00:00Z" } ] } }"#;
        let meta = parse_metadata(&spec("x/y", None), p2, Some(&package()), "url").unwrap();
        assert_eq!(
            meta.repository.as_deref(),
            Some("https://github.com/Seldaek/monolog")
        );
    }

    #[test]
    fn unknown_package_is_not_found() {
        assert!(matches!(
            parse_metadata(&spec("x/y", None), r#"{ "packages": {} }"#, None, "url"),
            Err(ComposerError::PackageNotFound(_))
        ));
    }

    #[test]
    fn missing_version_is_an_error() {
        assert!(matches!(
            parse_metadata(&spec("monolog/monolog", Some("9.9.9")), P2, None, "url"),
            Err(ComposerError::VersionNotFound { .. })
        ));
    }

    #[test]
    fn malformed_json_is_a_decode_error() {
        assert!(matches!(
            parse_metadata(&spec("x/y", None), "{ nope", None, "url"),
            Err(ComposerError::Decode(_))
        ));
    }
}
