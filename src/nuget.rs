//! NuGet metadata. Flat-container lists versions; the registration index adds
//! publish times, listing state, and deprecation.

use std::sync::Arc;

use serde::Deserialize;

use crate::date;
use crate::http::{HttpClient, HttpError};
use crate::model::PackageSpec;
use crate::registry::PackageMeta;

const DEFAULT_NUGET_BASE: &str = "https://api.nuget.org";

#[derive(Debug, thiserror::Error)]
pub enum NugetError {
    #[error("package '{0}' was not found on NuGet")]
    PackageNotFound(String),
    #[error("'{version}' of '{package}' was not found on NuGet; pass an exact version")]
    VersionNotFound { package: String, version: String },
    #[error("NuGet request failed: {0}")]
    Http(String),
    #[error("NuGet sent a response dep-vet could not read: {0}")]
    Decode(String),
}

pub struct NugetClient {
    http: Arc<HttpClient>,
    base: String,
}

impl NugetClient {
    pub fn from_env(http: Arc<HttpClient>) -> Self {
        let base =
            std::env::var("DEPVET_NUGET_BASE").unwrap_or_else(|_| DEFAULT_NUGET_BASE.to_string());
        Self::with_base(http, base)
    }

    pub fn with_base(http: Arc<HttpClient>, base: impl Into<String>) -> Self {
        Self {
            http,
            base: base.into(),
        }
    }

    fn flat_url(&self, id: &str) -> String {
        format!(
            "{}/v3-flatcontainer/{id}/index.json",
            self.base.trim_end_matches('/')
        )
    }

    fn registration_url(&self, id: &str) -> String {
        format!(
            "{}/v3/registration5-gz-semver2/{id}/index.json",
            self.base.trim_end_matches('/')
        )
    }

    pub fn fetch(&self, spec: &PackageSpec) -> Result<PackageMeta, NugetError> {
        let id = spec.name.to_ascii_lowercase();
        let flat_url = self.flat_url(&id);
        let body = match self.http.get(&flat_url) {
            Ok(body) => body,
            Err(HttpError::Status { status: 404, .. }) => {
                return Err(NugetError::PackageNotFound(spec.name.clone()));
            }
            Err(error) => return Err(NugetError::Http(error.to_string())),
        };

        // Registration adds times and deprecation; a failure here still leaves
        // a usable version list, so it is best effort.
        let registration = self
            .http
            .get(&self.registration_url(&id))
            .ok()
            .map(|body| parse_registration(&body, |url| self.http.get(url).ok()))
            .unwrap_or_default();

        parse_versions(spec, &body, &registration, &flat_url)
    }
}

fn parse_versions(
    spec: &PackageSpec,
    body: &str,
    registration: &[RegVersion],
    url: &str,
) -> Result<PackageMeta, NugetError> {
    let flat: Flat =
        serde_json::from_str(body).map_err(|error| NugetError::Decode(error.to_string()))?;
    if flat.versions.is_empty() {
        return Err(NugetError::PackageNotFound(spec.name.clone()));
    }

    let version = match &spec.version {
        Some(requested) => flat
            .versions
            .iter()
            .find(|version| version.eq_ignore_ascii_case(requested))
            .cloned()
            .ok_or_else(|| NugetError::VersionNotFound {
                package: spec.name.clone(),
                version: requested.clone(),
            })?,
        None => flat
            .versions
            .iter()
            .rev()
            .find(|version| !version.contains('-'))
            .or_else(|| flat.versions.last())
            .cloned()
            .unwrap_or_default(),
    };

    let latest_version = flat
        .versions
        .iter()
        .rev()
        .find(|version| !version.contains('-'))
        .or_else(|| flat.versions.last())
        .cloned();

    // NuGet writes 1900-01-01 for "unknown"; it is not a real publish date.
    let real_date = |epoch: i64| (epoch > 0).then_some(epoch);
    let first_published_at = registration
        .iter()
        .filter_map(|release| release.published)
        .filter_map(real_date)
        .min();
    let release = registration
        .iter()
        .find(|release| release.version.eq_ignore_ascii_case(&version));
    let published_at = release
        .and_then(|release| release.published)
        .filter(|epoch| *epoch > 0);
    let previous = {
        let entries: Vec<(&str, Option<i64>)> = registration
            .iter()
            .map(|release| {
                (
                    release.version.as_str(),
                    release.published.filter(|epoch| *epoch > 0),
                )
            })
            .collect();
        crate::registry::previous_release(&entries, &version, published_at)
    };
    let current_dependencies = release
        .map(|release| release.dependencies.clone())
        .unwrap_or_default();
    let previous_dependencies = previous
        .as_ref()
        .and_then(|(version, _)| {
            registration
                .iter()
                .find(|release| release.version == *version)
        })
        .map(|release| release.dependencies.clone())
        .unwrap_or_default();
    let recent_releases = crate::registry::count_recent(
        registration
            .iter()
            .map(|release| release.published.filter(|epoch| *epoch > 0)),
        crate::cache::now_seconds(),
        crate::registry::HISTORY_WINDOW_DAYS,
    );
    let deprecated = release
        .filter(|release| release.deprecated)
        .map(|_| "this version is deprecated or unlisted on NuGet".to_string());

    Ok(PackageMeta {
        public: Default::default(),
        name: spec.name.clone(),
        version,
        first_published_at,
        published_at,
        maintainers: Vec::new(),
        publisher: None,
        maintainers_known: false,
        install_scripts: Vec::new(),
        build_from_source: false,
        // NuGet metadata exposes no source repository in these endpoints.
        repository: None,
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
            previous_dependencies,
            dependencies: current_dependencies,
            history_known: previous.is_some(),
            ..crate::registry::ReleaseHistory::default()
        },

        scorecard: None,
        license: release.and_then(|release| release.license.clone()),
    })
}

#[derive(Debug, Default)]
struct RegVersion {
    version: String,
    published: Option<i64>,
    deprecated: bool,
    dependencies: Vec<String>,
    license: Option<String>,
}

fn parse_registration(
    body: &str,
    mut fetch_page: impl FnMut(&str) -> Option<String>,
) -> Vec<RegVersion> {
    let index: Registration = serde_json::from_str(body).unwrap_or_default();
    let mut releases = Vec::new();

    for page in index.items {
        if let Some(entries) = page.items {
            collect_page(entries, &mut releases);
        } else if let Some(url) = page.id
            && let Some(body) = fetch_page(&url)
            && let Ok(page) = serde_json::from_str::<Page>(&body)
            && let Some(entries) = page.items
        {
            collect_page(entries, &mut releases);
        }
    }

    releases
}

fn collect_page(entries: Vec<Entry>, releases: &mut Vec<RegVersion>) {
    for entry in entries {
        let catalog = entry.catalog_entry;
        let mut dependencies: Vec<String> = catalog
            .dependency_groups
            .iter()
            .flat_map(|group| group.dependencies.iter())
            .map(|dependency| dependency.id.clone())
            .filter(|id| !id.is_empty())
            .collect();
        dependencies.sort();
        dependencies.dedup();
        releases.push(RegVersion {
            version: catalog.version,
            published: catalog.published.as_deref().and_then(date::parse_timestamp),
            deprecated: !catalog.listed.unwrap_or(true) || catalog.deprecation.is_some(),
            dependencies,
            license: catalog
                .license_expression
                .as_deref()
                .and_then(crate::license::normalize),
        });
    }
}

#[derive(Debug, Default, Deserialize)]
struct Flat {
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Registration {
    #[serde(default)]
    items: Vec<Page>,
}

#[derive(Debug, Default, Deserialize)]
struct Page {
    #[serde(rename = "@id", default)]
    id: Option<String>,
    #[serde(default)]
    items: Option<Vec<Entry>>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    #[serde(rename = "catalogEntry")]
    catalog_entry: Catalog,
}

#[derive(Debug, Deserialize)]
struct Catalog {
    version: String,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    listed: Option<bool>,
    #[serde(default)]
    deprecation: Option<serde_json::Value>,
    #[serde(rename = "dependencyGroups", default)]
    dependency_groups: Vec<DependencyGroup>,
    #[serde(rename = "licenseExpression", default)]
    license_expression: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DependencyGroup {
    #[serde(default)]
    dependencies: Vec<Dependency>,
}

#[derive(Debug, Deserialize)]
struct Dependency {
    #[serde(default)]
    id: String,
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

    const FLAT: &str = r#"{ "versions": ["12.0.3", "13.0.1", "13.0.4-beta1"] }"#;

    #[test]
    fn resolves_the_latest_stable_version() {
        let meta = parse_versions(&spec("newtonsoft.json", None), FLAT, &[], "url").unwrap();
        assert_eq!(meta.version, "13.0.1");
    }

    #[test]
    fn records_dependencies_from_registration_groups() {
        let body = r#"{ "items": [ { "items": [
            { "catalogEntry": { "version": "1.0.0", "published": "2024-01-01T00:00:00Z", "listed": true,
                "dependencyGroups": [ { "dependencies": [ { "id": "Newtonsoft.Json" }, { "id": "Serilog" } ] } ] } }
        ] } ] }"#;
        let registration = parse_registration(body, |_| None);
        let meta = parse_versions(
            &spec("x", Some("1.0.0")),
            r#"{ "versions": ["1.0.0"] }"#,
            &registration,
            "url",
        )
        .unwrap();
        assert_eq!(
            meta.release.dependencies,
            vec!["Newtonsoft.Json".to_string(), "Serilog".to_string()]
        );
    }

    #[test]
    fn the_1900_sentinel_is_not_a_previous_release() {
        let registration = vec![
            RegVersion {
                version: "1.0.0".to_string(),
                published: date::parse_timestamp("1900-01-01T00:00:00Z"),
                deprecated: false,
                dependencies: Vec::new(),
                license: None,
            },
            RegVersion {
                version: "2.0.0".to_string(),
                published: date::parse_timestamp("2024-03-01T00:00:00Z"),
                deprecated: false,
                dependencies: Vec::new(),
                license: None,
            },
        ];
        let meta = parse_versions(
            &spec("x", Some("2.0.0")),
            r#"{ "versions": ["1.0.0", "2.0.0"] }"#,
            &registration,
            "url",
        )
        .unwrap();
        assert_eq!(meta.release.previous_version, None);
    }

    #[test]
    fn records_the_previous_release_from_registration() {
        let registration = vec![
            RegVersion {
                version: "12.0.3".to_string(),
                published: date::parse_timestamp("2020-01-01T00:00:00Z"),
                deprecated: false,
                dependencies: Vec::new(),
                license: None,
            },
            RegVersion {
                version: "13.0.1".to_string(),
                published: date::parse_timestamp("2024-03-01T00:00:00Z"),
                deprecated: false,
                dependencies: Vec::new(),
                license: None,
            },
        ];
        let meta = parse_versions(
            &spec("x", Some("13.0.1")),
            r#"{ "versions": ["12.0.3", "13.0.1"] }"#,
            &registration,
            "url",
        )
        .unwrap();
        assert_eq!(meta.release.previous_version.as_deref(), Some("12.0.3"));
    }

    #[test]
    fn reports_the_last_stable_version_for_an_older_pin() {
        let meta =
            parse_versions(&spec("newtonsoft.json", Some("12.0.3")), FLAT, &[], "url").unwrap();
        assert_eq!(meta.latest_version.as_deref(), Some("13.0.1"));
    }

    #[test]
    fn resolves_an_exact_version_case_insensitively() {
        let meta = parse_versions(
            &spec("Newtonsoft.Json", Some("13.0.4-beta1")),
            FLAT,
            &[],
            "url",
        )
        .unwrap();
        assert_eq!(meta.version, "13.0.4-beta1");
    }

    #[test]
    fn missing_version_is_an_error() {
        assert!(matches!(
            parse_versions(&spec("x", Some("9.9.9")), FLAT, &[], "url"),
            Err(NugetError::VersionNotFound { .. })
        ));
    }

    #[test]
    fn registration_adds_times_and_deprecation() {
        let registration = vec![
            RegVersion {
                version: "13.0.1".to_string(),
                published: date::parse_timestamp("2024-03-01T00:00:00Z"),
                deprecated: false,
                dependencies: Vec::new(),
                license: None,
            },
            RegVersion {
                version: "12.0.3".to_string(),
                published: date::parse_timestamp("2020-01-01T00:00:00Z"),
                deprecated: true,
                dependencies: Vec::new(),
                license: None,
            },
        ];
        let meta = parse_versions(&spec("x", Some("12.0.3")), FLAT, &registration, "url").unwrap();
        assert_eq!(
            meta.deprecated.as_deref(),
            Some("this version is deprecated or unlisted on NuGet")
        );
        assert_eq!(
            meta.first_published_at,
            date::parse_timestamp("2020-01-01T00:00:00Z")
        );
    }

    #[test]
    fn registration_pages_are_fetched_when_not_inline() {
        let index = r#"{ "items": [ { "@id": "https://page", "items": null } ] }"#;
        let page = r#"{
            "items": [ { "catalogEntry": { "version": "1.0.0", "published": "2024-01-01T00:00:00Z", "listed": true } } ]
        }"#;
        let releases = parse_registration(index, |url| {
            assert_eq!(url, "https://page");
            Some(page.to_string())
        });
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].version, "1.0.0");
        assert!(!releases[0].deprecated);
    }

    #[test]
    fn unlisted_is_deprecated_and_explicit_deprecation_counts() {
        let body = r#"{ "items": [ { "items": [
            { "catalogEntry": { "version": "1.0.0", "listed": false } },
            { "catalogEntry": { "version": "2.0.0", "deprecation": { "reasons": ["Legacy"] } } }
        ] } ] }"#;
        let releases = parse_registration(body, |_| None);
        assert!(releases.iter().all(|release| release.deprecated));
    }

    #[test]
    fn nuget_sentinel_dates_are_ignored() {
        let registration = vec![
            RegVersion {
                version: "1.0.0".to_string(),
                published: date::parse_timestamp("1900-01-01T00:00:00Z"),
                deprecated: false,
                dependencies: Vec::new(),
                license: None,
            },
            RegVersion {
                version: "2.0.0".to_string(),
                published: date::parse_timestamp("2024-01-01T00:00:00Z"),
                deprecated: false,
                dependencies: Vec::new(),
                license: None,
            },
        ];
        let meta = parse_versions(
            &spec("x", None),
            r#"{ "versions": ["2.0.0"] }"#,
            &registration,
            "url",
        )
        .unwrap();
        assert_eq!(
            meta.first_published_at,
            date::parse_timestamp("2024-01-01T00:00:00Z")
        );

        let meta = parse_versions(
            &spec("x", Some("1.0.0")),
            r#"{ "versions": ["1.0.0"] }"#,
            &registration,
            "url",
        )
        .unwrap();
        assert_eq!(meta.published_at, None);
    }

    #[test]
    fn malformed_registration_is_ignored() {
        assert!(parse_registration("{ nope", |_| None).is_empty());
    }

    #[test]
    fn malformed_flat_is_a_decode_error() {
        assert!(matches!(
            parse_versions(&spec("x", None), "{ nope", &[], "url"),
            Err(NugetError::Decode(_))
        ));
    }
}
