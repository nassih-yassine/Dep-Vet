//! RubyGems metadata. The API lists every version with timestamps and
//! per-version metadata; OSV covers the ecosystem, so advisories work.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Deserialize;

use crate::date;
use crate::http::{HttpClient, HttpError};
use crate::model::PackageSpec;
use crate::registry::PackageMeta;

const DEFAULT_RUBYGEMS_BASE: &str = "https://rubygems.org";

#[derive(Debug, thiserror::Error)]
pub enum GemError {
    #[error("gem '{0}' was not found on RubyGems")]
    PackageNotFound(String),
    #[error("'{version}' of '{package}' was not found on RubyGems; pass an exact version")]
    VersionNotFound { package: String, version: String },
    #[error("RubyGems request failed: {0}")]
    Http(String),
    #[error("RubyGems sent a response dep-vet could not read: {0}")]
    Decode(String),
}

pub struct GemClient {
    http: Arc<HttpClient>,
    base: String,
}

impl GemClient {
    pub fn from_env(http: Arc<HttpClient>) -> Self {
        let base = std::env::var("DEPVET_RUBYGEMS_BASE")
            .unwrap_or_else(|_| DEFAULT_RUBYGEMS_BASE.to_string());
        Self::with_base(http, base)
    }

    pub fn with_base(http: Arc<HttpClient>, base: impl Into<String>) -> Self {
        Self {
            http,
            base: base.into(),
        }
    }

    fn versions_url(&self, name: &str) -> String {
        format!(
            "{}/api/v1/versions/{name}.json",
            self.base.trim_end_matches('/')
        )
    }

    fn gem_url(&self, name: &str) -> String {
        format!(
            "{}/api/v1/gems/{name}.json",
            self.base.trim_end_matches('/')
        )
    }

    pub fn fetch(&self, spec: &PackageSpec) -> Result<PackageMeta, GemError> {
        let versions_url = self.versions_url(&spec.name);
        let body = match self.http.get(&versions_url) {
            Ok(body) => body,
            Err(HttpError::Status { status: 404, .. }) => {
                return Err(GemError::PackageNotFound(spec.name.clone()));
            }
            Err(error) => return Err(GemError::Http(error.to_string())),
        };
        // Latest-version record carries source/yanked for the current release.
        let latest_body = self.http.get(&self.gem_url(&spec.name)).ok();

        parse_versions(spec, &body, latest_body.as_deref(), &versions_url)
    }
}

/// Gemfile.lock records native builds as `number-platform`. OSV keys gems by
/// the registry number, so the platform suffix must be stripped; prerelease
/// suffixes such as `-beta` or `.pre` are part of the version and stay.
pub fn osv_version(version: &str) -> &str {
    const PLATFORMS: &[&str] = &[
        "linux",
        "darwin",
        "mingw",
        "ucrt",
        "musl",
        "java",
        "jruby",
        "windows",
        "universal",
        "arm64",
        "aarch64",
        "x86_64",
        "x86",
        "x64",
        "arm",
    ];
    let Some((number, suffix)) = version.split_once('-') else {
        return version;
    };
    if !number.starts_with(|c: char| c.is_ascii_digit()) {
        return version;
    }
    let platform = suffix
        .split('-')
        .any(|part| PLATFORMS.contains(&part.to_ascii_lowercase().as_str()));
    if platform { number } else { version }
}

fn parse_versions(
    spec: &PackageSpec,
    body: &str,
    latest_body: Option<&str>,
    url: &str,
) -> Result<PackageMeta, GemError> {
    let releases: Vec<Release> =
        serde_json::from_str(body).map_err(|error| GemError::Decode(error.to_string()))?;
    let latest: Option<Latest> = latest_body.and_then(|body| serde_json::from_str(body).ok());

    let requested = spec.version.as_deref();
    let release = match requested {
        Some(requested) => releases
            .iter()
            .find(|release| release.matches(requested))
            .ok_or_else(|| GemError::VersionNotFound {
                package: spec.name.clone(),
                version: requested.to_string(),
            })?,
        None => {
            let latest_number = latest.as_ref().map(|latest| latest.version.clone());
            match latest_number {
                Some(number) => releases
                    .iter()
                    .find(|release| release.number == number)
                    .or_else(|| releases.first())
                    .ok_or_else(|| GemError::PackageNotFound(spec.name.clone()))?,
                None => releases
                    .first()
                    .ok_or_else(|| GemError::PackageNotFound(spec.name.clone()))?,
            }
        }
    };

    let first_published_at = releases
        .iter()
        .filter_map(|release| release.created_at.as_deref())
        .filter_map(date::parse_timestamp)
        .min();

    let repository = release
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("source_code_uri").cloned())
        .or_else(|| {
            latest
                .as_ref()
                .and_then(|latest| latest.source_code_uri.clone())
        })
        .or_else(|| {
            latest
                .as_ref()
                .and_then(|latest| latest.homepage_uri.clone())
        })
        .filter(|url| !url.trim().is_empty());

    let published_at = release
        .created_at
        .as_deref()
        .and_then(date::parse_timestamp);
    let previous = {
        let entries: Vec<(&str, Option<i64>)> = releases
            .iter()
            .map(|release| {
                (
                    release.number.as_str(),
                    release
                        .created_at
                        .as_deref()
                        .and_then(date::parse_timestamp),
                )
            })
            .collect();
        crate::registry::previous_release(&entries, &release.number, published_at)
    };
    let recent_releases = crate::registry::count_recent(
        releases.iter().map(|release| {
            release
                .created_at
                .as_deref()
                .and_then(date::parse_timestamp)
        }),
        crate::cache::now_seconds(),
        crate::registry::HISTORY_WINDOW_DAYS,
    );
    let latest_version = latest
        .as_ref()
        .map(|latest| latest.version.clone())
        .or_else(|| {
            releases
                .iter()
                .max_by_key(|release| {
                    release
                        .created_at
                        .as_deref()
                        .and_then(date::parse_timestamp)
                })
                .map(|release| release.number.clone())
        });

    let is_latest = latest
        .as_ref()
        .is_some_and(|latest| latest.version == release.number);
    let deprecated = latest
        .as_ref()
        .filter(|latest| is_latest && latest.yanked)
        .map(|_| "this version is yanked".to_string());

    Ok(PackageMeta {
        name: spec.name.clone(),
        version: release.number.clone(),
        first_published_at,
        published_at,
        maintainers: Vec::new(),
        publisher: None,
        maintainers_known: false,
        install_scripts: Vec::new(),
        build_from_source: false,
        repository,
        deprecated,
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

        scorecard: None,
        license: latest
            .as_ref()
            .map(|latest| {
                latest
                    .licenses
                    .iter()
                    .filter_map(|license| crate::license::normalize(license))
                    .collect::<Vec<_>>()
                    .join(" OR ")
            })
            .filter(|license| !license.is_empty()),
    })
}

#[derive(Debug, Deserialize)]
struct Release {
    number: String,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    metadata: Option<BTreeMap<String, String>>,
}

impl Release {
    /// Gemfile.lock records native builds as `number-platform`; the registry
    /// keys versions by `number` alone.
    fn matches(&self, requested: &str) -> bool {
        if self.number == requested {
            return true;
        }
        self.platform
            .as_deref()
            .filter(|platform| *platform != "ruby")
            .is_some_and(|platform| format!("{}-{platform}", self.number) == requested)
    }
}

#[derive(Debug, Deserialize)]
struct Latest {
    version: String,
    #[serde(default)]
    source_code_uri: Option<String>,
    #[serde(default)]
    homepage_uri: Option<String>,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    licenses: Vec<String>,
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
        body: &str,
        latest: Option<&str>,
        version: Option<&str>,
    ) -> Result<PackageMeta, GemError> {
        parse_versions(
            &spec("rack", version),
            body,
            latest,
            "https://gems.test/api/v1/versions/rack.json",
        )
    }

    const VERSIONS: &str = r#"[
        {
            "number": "3.2.9",
            "created_at": "2024-06-01T23:14:58.183Z",
            "platform": "ruby",
            "metadata": { "source_code_uri": "https://github.com/rack/rack" }
        },
        {
            "number": "3.0.0",
            "created_at": "2024-01-01T00:00:00.000Z",
            "platform": "ruby"
        },
        {
            "number": "1.16.0",
            "created_at": "2023-01-01T00:00:00.000Z",
            "platform": "x86_64-linux"
        }
    ]"#;

    const LATEST: &str = r#"{
        "version": "3.2.9",
        "source_code_uri": "https://github.com/rack/rack",
        "homepage_uri": "https://rack.github.io",
        "yanked": false
    }"#;

    #[test]
    fn resolves_the_latest_version() {
        let meta = fetch(VERSIONS, Some(LATEST), None).unwrap();
        assert_eq!(meta.version, "3.2.9");
        assert_eq!(
            meta.repository.as_deref(),
            Some("https://github.com/rack/rack")
        );
        assert_eq!(meta.deprecated, None);
    }

    #[test]
    fn records_the_previous_release() {
        let meta = fetch(VERSIONS, Some(LATEST), Some("3.0.0")).unwrap();
        assert_eq!(meta.release.previous_version.as_deref(), Some("1.16.0"));
    }

    #[test]
    fn reports_the_latest_gem_for_an_older_pin() {
        let meta = fetch(VERSIONS, Some(LATEST), Some("3.0.0")).unwrap();
        assert_eq!(meta.latest_version.as_deref(), Some("3.2.9"));
    }

    #[test]
    fn resolves_an_exact_version() {
        let meta = fetch(VERSIONS, Some(LATEST), Some("3.0.0")).unwrap();
        assert_eq!(meta.version, "3.0.0");
        assert_eq!(
            meta.first_published_at,
            date::parse_timestamp("2023-01-01T00:00:00Z")
        );
    }

    #[test]
    fn osv_lookups_strip_only_real_platform_suffixes() {
        assert_eq!(osv_version("1.16.0-x86_64-linux"), "1.16.0");
        assert_eq!(osv_version("1.16.0-arm64-darwin"), "1.16.0");
        assert_eq!(osv_version("1.0.0-java"), "1.0.0");
        assert_eq!(osv_version("9.4.5.0.pre"), "9.4.5.0.pre");
        assert_eq!(osv_version("1.0.0-beta"), "1.0.0-beta");
        assert_eq!(osv_version("3.2.9"), "3.2.9");
    }

    #[test]
    fn a_platform_suffix_resolves_to_its_number() {
        let meta = fetch(VERSIONS, Some(LATEST), Some("1.16.0-x86_64-linux")).unwrap();
        assert_eq!(meta.version, "1.16.0");
    }

    #[test]
    fn missing_version_is_an_error() {
        assert!(matches!(
            fetch(VERSIONS, Some(LATEST), Some("9.9.9")),
            Err(GemError::VersionNotFound { .. })
        ));
    }

    #[test]
    fn a_yanked_latest_version_is_deprecated() {
        let latest = r#"{ "version": "3.2.9", "yanked": true }"#;
        let meta = fetch(VERSIONS, Some(latest), None).unwrap();
        assert_eq!(meta.deprecated.as_deref(), Some("this version is yanked"));
    }

    #[test]
    fn source_falls_back_to_the_latest_record() {
        let body = r#"[{ "number": "1.0.0", "platform": "ruby" }]"#;
        let meta = fetch(body, Some(LATEST), None).unwrap();
        assert_eq!(
            meta.repository.as_deref(),
            Some("https://github.com/rack/rack")
        );
    }

    #[test]
    fn malformed_json_is_a_decode_error() {
        assert!(matches!(
            fetch("{ nope", None, None),
            Err(GemError::Decode(_))
        ));
    }
}
