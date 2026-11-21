//! npm registry access: one packument fetch per package, plus a best-effort
//! download count.
//!
//! Base URLs are overridable through `DEPVET_REGISTRY_BASE` and
//! `DEPVET_DOWNLOADS_BASE` so tests (and registry mirrors) never touch the
//! public registry.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;

use crate::date;
use crate::model::{InstallScript, PackageSpec};

const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";
const DEFAULT_DOWNLOADS: &str = "https://api.npmjs.org/downloads/point";
/// Packuments for very large packages exceed ureq's 10 MB default.
const MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;
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
    pub install_scripts: Vec<InstallScript>,
    pub repository: Option<String>,
    pub deprecated: Option<String>,
    pub registry_url: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("package '{0}' was not found on npm")]
    PackageNotFound(String),
    #[error(
        "'{version}' of '{package}' was not found on npm; dep-vet takes an exact version or dist-tag, not a range"
    )]
    VersionNotFound { package: String, version: String },
    #[error("npm registry request failed: {0}")]
    Http(String),
    #[error("npm registry sent a response dep-vet could not read: {0}")]
    Decode(String),
}

pub struct RegistryClient {
    agent: ureq::Agent,
    registry_base: String,
    downloads_base: String,
}

impl RegistryClient {
    pub fn from_env() -> Self {
        let registry =
            std::env::var("DEPVET_REGISTRY_BASE").unwrap_or_else(|_| DEFAULT_REGISTRY.to_string());
        let downloads = std::env::var("DEPVET_DOWNLOADS_BASE")
            .unwrap_or_else(|_| DEFAULT_DOWNLOADS.to_string());
        Self::with_bases(registry, downloads)
    }

    pub fn with_bases(registry_base: impl Into<String>, downloads_base: impl Into<String>) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .user_agent(concat!("dep-vet/", env!("CARGO_PKG_VERSION")))
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
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
        let body = match self.get(&url) {
            Ok(body) => body,
            Err(FetchError::Status(404 | 403)) => {
                return Err(RegistryError::PackageNotFound(spec.name.clone()));
            }
            Err(FetchError::Status(code)) => {
                return Err(RegistryError::Http(format!("{url} returned HTTP {code}")));
            }
            Err(FetchError::Io(message)) => return Err(RegistryError::Http(message)),
        };
        parse_packument(spec, &body, &url)
    }

    /// Best effort: download counts are a nice-to-have, never a reason to fail.
    pub fn weekly_downloads(&self, name: &str) -> Option<u64> {
        let url = format!(
            "{}/last-week/{}",
            self.downloads_base.trim_end_matches('/'),
            encode_name(name)
        );
        let body = self.get(&url).ok()?;
        #[derive(Deserialize)]
        struct Downloads {
            downloads: u64,
        }
        serde_json::from_str::<Downloads>(&body)
            .ok()
            .map(|downloads| downloads.downloads)
    }

    fn get(&self, url: &str) -> Result<String, FetchError> {
        match self.agent.get(url).call() {
            Ok(mut response) => response
                .body_mut()
                .with_config()
                .limit(MAX_BODY_BYTES)
                .read_to_string()
                .map_err(|error| FetchError::Io(error.to_string())),
            Err(ureq::Error::StatusCode(code)) => Err(FetchError::Status(code)),
            Err(error) => Err(FetchError::Io(error.to_string())),
        }
    }
}

enum FetchError {
    Status(u16),
    Io(String),
}

/// Scoped names travel as one path segment: `@scope%2Fname`.
fn encode_name(name: &str) -> String {
    name.replace('/', "%2F")
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

#[derive(Debug, Deserialize)]
struct VersionDoc {
    #[serde(default)]
    scripts: BTreeMap<String, String>,
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
            None => {
                return Err(RegistryError::VersionNotFound {
                    package: spec.name.clone(),
                    version: requested.clone(),
                });
            }
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

    let install_scripts = doc
        .scripts
        .iter()
        .filter(|(hook, _)| INSTALL_HOOKS.contains(&hook.as_str()))
        .map(|(name, command)| InstallScript {
            name: name.clone(),
            command: command.clone(),
        })
        .collect();

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
        install_scripts,
        repository,
        deprecated: normalize_deprecated(doc.deprecated.clone()),
        registry_url: url.to_string(),
    })
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
fn normalize_repository(raw: &str) -> String {
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
