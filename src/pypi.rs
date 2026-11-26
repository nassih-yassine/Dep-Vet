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
    /// Names routed to a private index, by the same configuration npm uses.
    router: Option<crate::registries::Router>,
    /// pip's configured indexes, in order. The first one replaces PyPI; the
    /// extras are tried when a name is not on it, which is the closest honest
    /// reading of pip's multi-index install.
    simple: Vec<String>,
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
            router: None,
            simple: Vec::new(),
        }
    }

    /// Route some names to a private index. A routed name is read from that
    /// index's simple API only; it never falls back to PyPI's JSON API.
    pub fn with_router(mut self, router: crate::registries::Router) -> Self {
        self.router = Some(router);
        self
    }

    /// pip's index, used for every name that has no explicit route.
    pub fn with_simple_bases(mut self, bases: Vec<String>) -> Self {
        self.simple = bases;
        self
    }

    fn route(&self, name: &str) -> Option<&crate::registries::Route> {
        self.router
            .as_ref()
            .and_then(|router| router.route(crate::model::Ecosystem::Pypi, name))
    }

    pub fn project_url(&self, name: &str) -> String {
        format!("{}/pypi/{name}/json", self.base.trim_end_matches('/'))
    }

    pub fn fetch(&self, spec: &PackageSpec) -> Result<PackageMeta, PypiError> {
        if let Some(route) = self.route(&spec.name) {
            let token = crate::registries::token(route).map_err(PypiError::Http)?;
            return self.fetch_simple_at(spec, &route.base, token.as_deref(), route.probe_public);
        }
        if !self.simple.is_empty() {
            // A general index proxies public names too, so a public copy is
            // expected rather than suspicious: no confusion probe here.
            let mut last = None;
            for base in &self.simple {
                match self.fetch_simple_at(spec, base, None, false) {
                    Ok(meta) => return Ok(meta),
                    // Not on this index: the next configured one decides.
                    Err(PypiError::PackageNotFound(_)) => continue,
                    Err(error) => {
                        last = Some(error);
                        break;
                    }
                }
            }
            return Err(last.unwrap_or_else(|| PypiError::PackageNotFound(spec.name.clone())));
        }
        let url = self.project_url(&spec.name);
        let body = match self.http.get(&url) {
            Ok(body) => body,
            Err(HttpError::Status { status: 404, .. }) => {
                return Err(PypiError::PackageNotFound(spec.name.clone()));
            }
            Err(error) => return Err(PypiError::Http(error.to_string())),
        };
        let mut meta = parse_project(spec, &body, &url)?;
        self.enrich_history(&mut meta);
        if let Some(filename) = provenance_filename(&body) {
            let provenance = format!(
                "{}/integrity/{}/{}/{filename}/provenance",
                self.base.trim_end_matches('/'),
                meta.name,
                meta.version
            );
            meta.provenance = match self
                .http
                .head_trusted(crate::model::Ecosystem::Pypi, &provenance)
            {
                Ok(true) => crate::model::Provenance::Present,
                Ok(false) => crate::model::Provenance::Missing,
                Err(_) => crate::model::Provenance::Unavailable,
            };
        }
        Ok(meta)
    }

    /// The PEP 691 simple index a private mirror actually publishes. Fields the
    /// index cannot answer (maintainers, license, repository, history) stay
    /// empty and surface as not checked.
    fn fetch_simple_at(
        &self,
        spec: &PackageSpec,
        index_base: &str,
        token: Option<&str>,
        probe_public: bool,
    ) -> Result<PackageMeta, PypiError> {
        use crate::registry::PublicProbe;
        let folded = crate::pypi_simple::fold(&spec.name);
        let url = format!("{}/{folded}/", index_base.trim_end_matches('/'));
        let authorization = token.map(|token| {
            use base64::Engine as _;
            let pair =
                base64::engine::general_purpose::STANDARD.encode(format!("__token__:{token}"));
            format!("Basic {pair}")
        });
        let mut headers = vec![("Accept", "application/vnd.pypi.simple.v1+json")];
        if let Some(authorization) = authorization.as_deref() {
            headers.push(("Authorization", authorization));
        }
        let body = self
            .http
            .get_with_headers(&url, &headers)
            .map_err(|error| match error {
                HttpError::Status { status: 404, .. } => {
                    PypiError::PackageNotFound(spec.name.clone())
                }
                other => PypiError::Http(other.to_string()),
            })?;
        let index = crate::pypi_simple::parse(&body).map_err(PypiError::Decode)?;
        let version = match &spec.version {
            Some(version) => version.clone(),
            None => index
                .newest()
                .map(str::to_string)
                .ok_or_else(|| PypiError::PackageNotFound(spec.name.clone()))?,
        };
        let files = index.files_for(&spec.name, &version);
        if files.is_empty() {
            return Err(match spec.version {
                Some(_) => PypiError::VersionNotFound {
                    package: spec.name.clone(),
                    version,
                },
                None => PypiError::PackageNotFound(spec.name.clone()),
            });
        }
        let public = if probe_public {
            self.probe_public(&spec.name)
        } else {
            PublicProbe::NotApplicable
        };
        Ok(PackageMeta {
            public,
            name: spec.name.clone(),
            version,
            first_published_at: index.first_upload(),
            published_at: files.iter().filter_map(|file| file.upload_time).min(),
            maintainers: Vec::new(),
            publisher: None,
            maintainers_known: false,
            install_scripts: Vec::new(),
            build_from_source: crate::pypi_simple::SimpleIndex::sdist_only(&files),
            repository: None,
            deprecated: crate::pypi_simple::SimpleIndex::all_yanked(&files)
                .then(|| "this release is yanked".to_string()),
            provenance: crate::model::Provenance::Unavailable,
            attestation_subject_matches: None,
            attestation: None,
            registry_url: url,
            review_url: None,
            latest_version: index.newest().map(str::to_string),
            candidate_weekly_downloads: None,
            release: crate::registry::ReleaseHistory::default(),
            scorecard: None,
            license: None,
        })
    }

    /// One public PyPI lookup for a routed name. A 404 is an answer; any other
    /// failure is `Unchecked`, never "absent".
    fn probe_public(&self, name: &str) -> crate::registry::PublicProbe {
        use crate::registry::PublicProbe;
        let url = format!("{}/pypi/{name}/json", self.base.trim_end_matches('/'));
        match self.http.get(&url) {
            Ok(body) => match serde_json::from_str::<Project>(&body) {
                Ok(project) => PublicProbe::Known {
                    latest: Some(project.info.version),
                    versions: project.releases.keys().cloned().collect(),
                },
                Err(_) => PublicProbe::Unchecked,
            },
            Err(HttpError::Status { status: 404, .. }) => PublicProbe::Known {
                latest: None,
                versions: Vec::new(),
            },
            Err(_) => PublicProbe::Unchecked,
        }
    }

    /// Requires-dist for this release and the previous one, only for releases
    /// inside the history window. Older versions cannot match the transition
    /// signals, so they must not cost two requests.
    fn enrich_history(&self, meta: &mut PackageMeta) {
        let Some(published) = meta.published_at else {
            return;
        };
        if crate::cache::now_seconds() - published
            > crate::registry::HISTORY_WINDOW_DAYS * crate::date::SECONDS_PER_DAY
        {
            return;
        }
        let Some(previous) = meta.release.previous_version.clone() else {
            return;
        };
        let (Some(current), Some(previous_dependencies)) = (
            self.version_dependencies(&meta.name, &meta.version),
            self.version_dependencies(&meta.name, &previous),
        ) else {
            return;
        };
        meta.release.dependencies = current;
        meta.release.previous_dependencies = previous_dependencies;
        meta.release.history_known = true;
    }

    fn version_dependencies(&self, name: &str, version: &str) -> Option<Vec<String>> {
        let url = format!(
            "{}/pypi/{name}/{version}/json",
            self.base.trim_end_matches('/')
        );
        let body = self.http.get(&url).ok()?;
        let project = serde_json::from_str::<Project>(&body).ok()?;
        Some(dependency_names(
            project.info.requires_dist.as_deref().unwrap_or_default(),
        ))
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

    let previous = {
        let entries: Vec<(&str, Option<i64>)> = project
            .releases
            .iter()
            .map(|(version, files)| (version.as_str(), files.iter().filter_map(file_time).min()))
            .collect();
        crate::registry::previous_release(&entries, &version, published_at)
    };

    let recent_releases = crate::registry::count_recent(
        project
            .releases
            .values()
            .map(|files| files.iter().filter_map(file_time).min()),
        crate::cache::now_seconds(),
        crate::registry::HISTORY_WINDOW_DAYS,
    );

    let deprecated = if all_yanked {
        Some(match yanked_reason {
            Some(reason) => format!("this release is yanked: {reason}"),
            None => "this release is yanked".to_string(),
        })
    } else {
        None
    };

    // PyPI's `info.version` is the project's latest. A fully yanked latest is
    // not a suggestion, so it becomes unknown rather than a false upgrade.
    let latest_is_yanked = project
        .releases
        .get(&project.info.version)
        .is_some_and(|files| !files.is_empty() && files.iter().all(|file| file.yanked));
    let latest_version = (!latest_is_yanked).then(|| project.info.version.clone());
    let license = pypi_license(&project.info);

    Ok(PackageMeta {
        public: Default::default(),
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
        license,
    })
}

/// Prefer the SPDX expression, then the free-text field, then a Trove
/// classifier. Prose that is not a license id yields `None`.
fn pypi_license(info: &Info) -> Option<String> {
    info.license_expression
        .as_deref()
        .and_then(crate::license::normalize)
        .or_else(|| info.license.as_deref().and_then(crate::license::normalize))
        .or_else(|| {
            info.classifiers.iter().find_map(|classifier| {
                classifier
                    .strip_prefix("License :: ")
                    .and_then(|rest| rest.rsplit(" :: ").next())
                    .and_then(crate::license::normalize)
            })
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

/// The first published file for this release, preferring the sdist. Provenance
/// is attached per file, and PyPI serves it from the Integrity API.
fn provenance_filename(body: &str) -> Option<String> {
    let project: Project = serde_json::from_str(body).ok()?;
    project
        .urls
        .iter()
        .find(|file| file.packagetype.as_deref() == Some("sdist"))
        .or_else(|| project.urls.first())
        .and_then(|file| file.filename.clone())
}

/// PEP 508 strings to bare names: drop markers, extras, and version operators.
fn dependency_names(requirements: &[String]) -> Vec<String> {
    let mut names: Vec<String> = requirements
        .iter()
        .map(|requirement| requirement.as_str())
        .map(|requirement| requirement.split(';').next().unwrap_or(requirement))
        .map(|requirement| {
            requirement
                .split(['<', '>', '=', '!', '~', '[', '(', ' '])
                .next()
                .unwrap_or(requirement)
                .trim()
        })
        .filter(|name| !name.is_empty() && !name.eq_ignore_ascii_case("extra"))
        .map(str::to_string)
        .collect();
    names.sort();
    names.dedup();
    names
}

#[derive(Debug, Deserialize)]
struct Info {
    name: String,
    version: String,
    #[serde(default)]
    requires_dist: Option<Vec<String>>,
    #[serde(default)]
    home_page: Option<String>,
    #[serde(default)]
    project_urls: Option<BTreeMap<String, String>>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    license_expression: Option<String>,
    #[serde(default)]
    classifiers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct File {
    #[serde(default)]
    filename: Option<String>,
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
            { "filename": "requests-2.31.0-py3-none-any.whl", "packagetype": "bdist_wheel", "upload_time": "2023-05-22T12:00:00Z" },
            { "filename": "requests-2.31.0.tar.gz", "packagetype": "sdist", "upload_time": "2023-05-22T12:00:00Z" }
        ],
        "releases": {
            "2.30.0": [{ "packagetype": "sdist", "upload_time": "2023-05-01T00:00:00Z" }],
            "2.31.0": [
                { "packagetype": "bdist_wheel", "upload_time": "2023-05-22T12:00:00Z" },
                { "packagetype": "sdist", "upload_time": "2023-05-22T12:00:00Z" }
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
    fn provenance_prefers_the_sdist_filename() {
        assert_eq!(
            provenance_filename(WHEEL_AND_SDIST).as_deref(),
            Some("requests-2.31.0.tar.gz")
        );
        assert!(provenance_filename("{}").is_none());
    }

    #[test]
    fn dependency_strings_become_bare_names() {
        let names = dependency_names(&[
            "requests[socks]>=2.0".to_string(),
            "tomli; python_version < '3.11'".to_string(),
            "typing-extensions".to_string(),
        ]);
        assert_eq!(
            names,
            vec![
                "requests".to_string(),
                "tomli".to_string(),
                "typing-extensions".to_string()
            ]
        );
    }

    #[test]
    fn records_the_previous_release() {
        let meta = fetch(WHEEL_AND_SDIST, Some("2.31.0")).unwrap();
        assert_eq!(meta.release.previous_version.as_deref(), Some("2.30.0"));
    }

    #[test]
    fn reports_the_project_latest_version_for_an_older_pin() {
        let meta = fetch(WHEEL_AND_SDIST, Some("2.30.0")).unwrap();
        assert_eq!(meta.latest_version.as_deref(), Some("2.31.0"));
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
            date::parse_timestamp("2023-05-01T00:00:00Z")
        );
        assert_eq!(
            meta.published_at,
            date::parse_timestamp("2023-05-22T12:00:00Z")
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
