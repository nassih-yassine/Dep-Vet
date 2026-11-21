//! Resolve, download, verify, and extract one release archive.

use base64::Engine;
use sha2::{Digest, Sha256, Sha512};

use crate::archive::{ArchiveKind, Extracted, Limits, extract};
use crate::http::{HttpClient, HttpError};
use crate::model::{Ecosystem, PackageSpec};

#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    #[error("archive is not available for {0}: {1}")]
    Unavailable(Ecosystem, String),
    #[error("archive download failed: {0}")]
    Http(String),
    #[error("archive could not be inspected: {0}")]
    Archive(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checksum {
    Sha1Hex(String),
    Sha256Hex(String),
    Sha512Base64(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Integrity {
    Verified,
    Unverified,
    Mismatch { expected: String, actual: String },
}

#[derive(Debug)]
pub struct Prepared {
    pub url: String,
    pub kind: ArchiveKind,
    pub integrity: Integrity,
    pub extracted: Extracted,
    pub bytes: usize,
}

struct ArchiveRef {
    url: String,
    kind: ArchiveKind,
    checksum: Option<Checksum>,
}

pub fn inspect_archive(
    http: &HttpClient,
    ecosystem: Ecosystem,
    spec: &PackageSpec,
    limits: Limits,
) -> Result<Prepared, InspectError> {
    let version = spec
        .version
        .as_deref()
        .ok_or_else(|| InspectError::Unavailable(ecosystem, "pass an exact version".to_string()))?;
    let source = resolve(http, ecosystem, &spec.name, version)?;
    let bytes = get_bytes(http, ecosystem, &source.url, limits.max_compressed)?;
    let integrity = match &source.checksum {
        Some(checksum) => verify(checksum, &bytes),
        None => Integrity::Unverified,
    };
    let extracted = extract(source.kind, &bytes, limits)
        .map_err(|error| InspectError::Archive(error.to_string()))?;
    Ok(Prepared {
        url: source.url,
        kind: source.kind,
        integrity,
        extracted,
        bytes: bytes.len(),
    })
}

fn get_bytes(
    http: &HttpClient,
    ecosystem: Ecosystem,
    url: &str,
    limit: u64,
) -> Result<Vec<u8>, InspectError> {
    let mut response = http.get_raw(url).map_err(|error| match error {
        HttpError::Status { status: 404, .. } => {
            InspectError::Unavailable(ecosystem, format!("{url} returned 404"))
        }
        other => InspectError::Http(other.to_string()),
    })?;
    let body = response
        .body_mut()
        .with_config()
        .limit(limit + 1)
        .read_to_vec()
        .map_err(|error| InspectError::Http(error.to_string()))?;
    if body.len() as u64 > limit {
        return Err(InspectError::Archive(format!(
            "archive is larger than {limit} bytes"
        )));
    }
    Ok(body)
}

/// Compare the registry-published digest with the bytes we received.
pub fn verify(checksum: &Checksum, bytes: &[u8]) -> Integrity {
    let (expected, actual) = match checksum {
        Checksum::Sha1Hex(expected) => (expected.clone(), hex(&sha1::Sha1::digest(bytes))),
        Checksum::Sha256Hex(expected) => (expected.clone(), hex(&Sha256::digest(bytes))),
        Checksum::Sha512Base64(expected) => {
            let actual = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes));
            (expected.clone(), actual)
        }
    };
    if expected.eq_ignore_ascii_case(&actual) {
        Integrity::Verified
    } else {
        Integrity::Mismatch { expected, actual }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn resolve(
    http: &HttpClient,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> Result<ArchiveRef, InspectError> {
    match ecosystem {
        Ecosystem::Npm => resolve_npm(http, name, version),
        Ecosystem::Pypi => resolve_pypi(http, name, version),
        Ecosystem::CratesIo => resolve_crates(http, name, version),
        Ecosystem::Go => Ok(resolve_go(name, version)),
        Ecosystem::RubyGems => resolve_gem(http, name, version),
        Ecosystem::NuGet => Ok(resolve_nuget(name, version)),
        Ecosystem::Maven => resolve_maven(name, version),
        Ecosystem::Composer => resolve_composer(http, name, version),
        Ecosystem::Jsr => Err(InspectError::Unavailable(
            Ecosystem::Jsr,
            "the JSR archive URL is not documented yet".to_string(),
        )),
    }
}

fn get_json(http: &HttpClient, url: &str) -> Result<serde_json::Value, InspectError> {
    let body = http
        .get(url)
        .map_err(|error| InspectError::Http(error.to_string()))?;
    serde_json::from_str(&body).map_err(|error| InspectError::Archive(error.to_string()))
}

fn base(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

fn resolve_npm(http: &HttpClient, name: &str, version: &str) -> Result<ArchiveRef, InspectError> {
    let base = base("DEPVET_REGISTRY_BASE", "https://registry.npmjs.org");
    let encoded = name.replace('/', "%2F");
    let doc = get_json(http, &format!("{base}/{encoded}/{version}"))?;
    let dist = &doc["dist"];
    let url = dist["tarball"]
        .as_str()
        .ok_or_else(|| InspectError::Unavailable(Ecosystem::Npm, "no tarball URL".to_string()))?;
    let checksum = dist["integrity"]
        .as_str()
        .and_then(|value| value.strip_prefix("sha512-"))
        .map(|value| Checksum::Sha512Base64(value.to_string()))
        .or_else(|| {
            dist["shasum"]
                .as_str()
                .map(|value| Checksum::Sha1Hex(value.to_string()))
        });
    Ok(ArchiveRef {
        url: url.to_string(),
        kind: ArchiveKind::TarGz,
        checksum,
    })
}

fn resolve_pypi(http: &HttpClient, name: &str, version: &str) -> Result<ArchiveRef, InspectError> {
    let base = base("DEPVET_PYPI_BASE", "https://pypi.org");
    let doc = get_json(http, &format!("{base}/pypi/{name}/{version}/json"))?;
    let files = doc["urls"]
        .as_array()
        .ok_or_else(|| InspectError::Unavailable(Ecosystem::Pypi, "no files".to_string()))?;
    let sdist = files
        .iter()
        .find(|file| file["packagetype"].as_str() == Some("sdist"))
        .or_else(|| files.first())
        .ok_or_else(|| InspectError::Unavailable(Ecosystem::Pypi, "no files".to_string()))?;
    let url = sdist["url"]
        .as_str()
        .ok_or_else(|| InspectError::Unavailable(Ecosystem::Pypi, "no URL".to_string()))?;
    let sha = sdist["digests"]["sha256"]
        .as_str()
        .map(|value| Checksum::Sha256Hex(value.to_string()));
    Ok(ArchiveRef {
        url: url.to_string(),
        kind: if url.ends_with(".zip") {
            ArchiveKind::Zip
        } else {
            ArchiveKind::TarGz
        },
        checksum: sha,
    })
}

fn resolve_crates(
    http: &HttpClient,
    name: &str,
    version: &str,
) -> Result<ArchiveRef, InspectError> {
    let base = base("DEPVET_CRATES_BASE", "https://crates.io");
    let doc = get_json(http, &format!("{base}/api/v1/crates/{name}/{version}"))?;
    let checksum = doc["version"]["checksum"]
        .as_str()
        .map(|value| Checksum::Sha256Hex(value.to_string()));
    Ok(ArchiveRef {
        url: format!("{base}/api/v1/crates/{name}/{version}/download"),
        kind: ArchiveKind::TarGz,
        checksum,
    })
}

/// Go module paths are case-encoded on the proxy: an uppercase letter becomes
/// `!` plus its lowercase form.
fn escape_go(module: &str) -> String {
    let mut escaped = String::with_capacity(module.len());
    for character in module.chars() {
        if character.is_ascii_uppercase() {
            escaped.push('!');
            escaped.push(character.to_ascii_lowercase());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

fn resolve_go(name: &str, version: &str) -> ArchiveRef {
    let base = base("DEPVET_GOPROXY_BASE", "https://proxy.golang.org");
    ArchiveRef {
        url: format!("{base}/{}/@v/{version}.zip", escape_go(name)),
        kind: ArchiveKind::Zip,
        checksum: None,
    }
}

fn resolve_gem(http: &HttpClient, name: &str, version: &str) -> Result<ArchiveRef, InspectError> {
    let base = base("DEPVET_RUBYGEMS_BASE", "https://rubygems.org");
    let doc = get_json(http, &format!("{base}/api/v1/versions/{name}.json"))?;
    let checksum = doc
        .as_array()
        .and_then(|versions| {
            versions
                .iter()
                .find(|release| release["number"].as_str() == Some(version))
        })
        .and_then(|release| release["sha"].as_str())
        .map(|value| Checksum::Sha256Hex(value.to_string()));
    Ok(ArchiveRef {
        url: format!("{base}/gems/{name}-{version}.gem"),
        kind: ArchiveKind::Gem,
        checksum,
    })
}

fn resolve_nuget(name: &str, version: &str) -> ArchiveRef {
    let base = base("DEPVET_NUGET_BASE", "https://api.nuget.org");
    let id = name.to_ascii_lowercase();
    ArchiveRef {
        url: format!("{base}/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg"),
        kind: ArchiveKind::Zip,
        checksum: None,
    }
}

fn resolve_maven(name: &str, version: &str) -> Result<ArchiveRef, InspectError> {
    let (group, artifact) = name.split_once(':').ok_or_else(|| {
        InspectError::Unavailable(Ecosystem::Maven, "bad coordinates".to_string())
    })?;
    let google = ["androidx.", "com.android.", "com.google.android."]
        .iter()
        .any(|prefix| group.starts_with(prefix));
    let base = if google {
        base(
            "DEPVET_GOOGLE_MAVEN_BASE",
            "https://dl.google.com/dl/android/maven2",
        )
    } else {
        base("DEPVET_MAVEN_REPO_BASE", "https://repo1.maven.org/maven2")
    };
    Ok(ArchiveRef {
        url: format!(
            "{base}/{}/{artifact}/{version}/{artifact}-{version}-sources.jar",
            group.replace('.', "/")
        ),
        kind: ArchiveKind::Zip,
        checksum: None,
    })
}

fn resolve_composer(
    http: &HttpClient,
    name: &str,
    version: &str,
) -> Result<ArchiveRef, InspectError> {
    let base = base("DEPVET_COMPOSER_BASE", "https://repo.packagist.org");
    let doc = get_json(http, &format!("{base}/p2/{name}.json"))?;
    let entry = doc["packages"][name]
        .as_array()
        .and_then(|releases| {
            releases
                .iter()
                .find(|release| release["version"].as_str() == Some(version))
        })
        .ok_or_else(|| {
            InspectError::Unavailable(Ecosystem::Composer, "version not found".to_string())
        })?;
    let dist = &entry["dist"];
    let url = dist["url"]
        .as_str()
        .ok_or_else(|| InspectError::Unavailable(Ecosystem::Composer, "no dist URL".to_string()))?;
    let checksum = dist["shasum"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(|value| Checksum::Sha1Hex(value.to_string()));
    Ok(ArchiveRef {
        url: url.to_string(),
        kind: ArchiveKind::Zip,
        checksum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BYTES: &[u8] = b"hello archive";

    #[test]
    fn checksums_verify_and_mismatch() {
        let sha256 = hex(&Sha256::digest(BYTES));
        assert_eq!(
            verify(&Checksum::Sha256Hex(sha256.clone()), BYTES),
            Integrity::Verified
        );
        assert!(matches!(
            verify(&Checksum::Sha256Hex("00".to_string()), BYTES),
            Integrity::Mismatch { .. }
        ));

        let sha512 = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(BYTES));
        assert_eq!(
            verify(&Checksum::Sha512Base64(sha512), BYTES),
            Integrity::Verified
        );

        let sha1 = hex(&sha1::Sha1::digest(BYTES));
        assert_eq!(verify(&Checksum::Sha1Hex(sha1), BYTES), Integrity::Verified);
    }

    #[test]
    fn go_module_paths_are_case_escaped() {
        assert_eq!(
            escape_go("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );
        assert_eq!(
            escape_go("github.com/gin-gonic/gin"),
            "github.com/gin-gonic/gin"
        );
    }
}

/// A finished inspection, ready for rendering.
#[derive(Debug, serde::Serialize)]
pub struct InspectionReport {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub archive_url: String,
    pub archive_kind: &'static str,
    pub bytes: usize,
    pub integrity: String,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub findings: Vec<crate::rules::RuleFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_checked: Vec<String>,
}

impl InspectionReport {
    pub fn verdict(&self) -> crate::model::Severity {
        self.findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(crate::model::Severity::Info)
    }

    pub fn exit_code(&self) -> u8 {
        self.verdict().exit_code()
    }
}

pub fn build_report(
    ecosystem: Ecosystem,
    spec: &PackageSpec,
    prepared: Prepared,
) -> InspectionReport {
    let mut findings = crate::rules::scan(&prepared.extracted.files);
    let integrity = match &prepared.integrity {
        Integrity::Verified => "verified".to_string(),
        Integrity::Unverified => "unverified".to_string(),
        Integrity::Mismatch { expected, actual } => {
            findings.push(crate::rules::RuleFinding {
                rule: "ARCHIVE-CHECKSUM-001",
                title: "archive checksum does not match the registry",
                severity: crate::model::Severity::High,
                confidence: crate::model::Confidence::High,
                file: String::new(),
                line: 0,
                evidence: format!("expected {expected}, got {actual}"),
                recommendation: "Do not install; the download does not match the published release.",
            });
            format!("MISMATCH (expected {expected}, got {actual})")
        }
    };
    findings.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then(left.line.cmp(&right.line))
            .then(left.rule.cmp(right.rule))
    });

    let mut not_checked = Vec::new();
    if prepared.extracted.files.is_empty() {
        not_checked.push("source analysis (no text files in the archive)".to_string());
    }
    InspectionReport {
        ecosystem,
        name: spec.name.clone(),
        version: spec.version.clone().unwrap_or_default(),
        archive_url: prepared.url,
        archive_kind: match prepared.kind {
            ArchiveKind::TarGz => "tar.gz",
            ArchiveKind::Zip => "zip",
            ArchiveKind::Gem => "gem",
        },
        bytes: prepared.bytes,
        integrity,
        files_scanned: prepared.extracted.files.len(),
        files_skipped: prepared.extracted.skipped_binary + prepared.extracted.skipped_unsafe,
        findings,
        not_checked,
    }
}

/// Security-focused comparison of two releases.
#[derive(Debug, serde::Serialize)]
pub struct DiffReport {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub from_version: String,
    pub to_version: String,
    pub from_integrity: String,
    pub to_integrity: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
    pub unchanged: usize,
    /// Rule findings present in the new release but not the old one.
    pub findings: Vec<crate::rules::RuleFinding>,
    /// Findings that disappeared.
    pub resolved: Vec<crate::rules::RuleFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_checked: Vec<String>,
}

impl DiffReport {
    pub fn verdict(&self) -> crate::model::Severity {
        self.findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(crate::model::Severity::Info)
    }

    pub fn exit_code(&self) -> u8 {
        self.verdict().exit_code()
    }
}

fn integrity_label(integrity: &Integrity) -> String {
    match integrity {
        Integrity::Verified => "verified".to_string(),
        Integrity::Unverified => "unverified".to_string(),
        Integrity::Mismatch { expected, actual } => {
            format!("MISMATCH (expected {expected}, got {actual})")
        }
    }
}

fn compare_files(
    old: &[crate::archive::ExtractedFile],
    new: &[crate::archive::ExtractedFile],
) -> (Vec<String>, Vec<String>, Vec<String>, usize) {
    use std::collections::BTreeMap;
    let old_map: BTreeMap<&str, &str> = old
        .iter()
        .map(|file| (file.path.as_str(), file.text.as_str()))
        .collect();
    let new_map: BTreeMap<&str, &str> = new
        .iter()
        .map(|file| (file.path.as_str(), file.text.as_str()))
        .collect();

    let added = new_map
        .keys()
        .filter(|path| !old_map.contains_key(**path))
        .map(|path| path.to_string())
        .collect();
    let removed = old_map
        .keys()
        .filter(|path| !new_map.contains_key(**path))
        .map(|path| path.to_string())
        .collect();
    let modified = new_map
        .iter()
        .filter(|(path, text)| old_map.get(**path).is_some_and(|old| old != *text))
        .map(|(path, _)| path.to_string())
        .collect();
    let unchanged = new_map
        .iter()
        .filter(|(path, text)| old_map.get(**path).is_some_and(|old| old == *text))
        .count();
    (added, removed, modified, unchanged)
}

/// New shell scripts and shebang files are worth a line in a release diff.
fn new_script_findings(
    new_files: &[crate::archive::ExtractedFile],
    added: &[String],
) -> Vec<crate::rules::RuleFinding> {
    let by_path: std::collections::BTreeMap<&str, &str> = new_files
        .iter()
        .map(|file| (file.path.as_str(), file.text.as_str()))
        .collect();
    added
        .iter()
        .filter_map(|path| {
            let text = by_path.get(path.as_str())?;
            let shell = path.ends_with(".sh")
                || path.ends_with(".bash")
                || path.ends_with(".ps1")
                || path.ends_with(".bat");
            let shebang = text.starts_with("#!");
            if !shell && !shebang {
                return None;
            }
            Some(crate::rules::RuleFinding {
                rule: "DIFF-NEW-SCRIPT-001",
                title: "this release adds an executable script",
                severity: crate::model::Severity::Warn,
                confidence: crate::model::Confidence::Medium,
                file: path.clone(),
                line: 1,
                evidence: text
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .chars()
                    .take(160)
                    .collect(),
                recommendation: "Review the new script before installing the update.",
            })
        })
        .collect()
}

pub fn build_diff(
    ecosystem: Ecosystem,
    name: &str,
    from_spec: &PackageSpec,
    to_spec: &PackageSpec,
    old: &Prepared,
    new: &Prepared,
) -> DiffReport {
    let (added, removed, modified, unchanged) =
        compare_files(&old.extracted.files, &new.extracted.files);

    let old_findings = crate::rules::scan(&old.extracted.files);
    let new_findings = crate::rules::scan(&new.extracted.files);
    let key = |finding: &crate::rules::RuleFinding| (finding.rule, finding.file.clone());
    let old_keys: std::collections::HashSet<_> = old_findings.iter().map(key).collect();
    let new_keys: std::collections::HashSet<_> = new_findings.iter().map(key).collect();

    let mut findings: Vec<_> = new_findings
        .iter()
        .filter(|finding| !old_keys.contains(&key(finding)))
        .cloned()
        .collect();
    findings.extend(new_script_findings(&new.extracted.files, &added));
    let resolved: Vec<_> = old_findings
        .into_iter()
        .filter(|finding| !new_keys.contains(&key(finding)))
        .collect();
    findings.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then(left.line.cmp(&right.line))
            .then(left.rule.cmp(right.rule))
    });

    let mut not_checked = Vec::new();
    if new.extracted.files.is_empty() {
        not_checked.push("source analysis (no text files in the new archive)".to_string());
    }
    if matches!(new.integrity, Integrity::Unverified) {
        not_checked.push("archive checksum (registry publishes none)".to_string());
    }

    DiffReport {
        ecosystem,
        name: name.to_string(),
        from_version: from_spec.version.clone().unwrap_or_default(),
        to_version: to_spec.version.clone().unwrap_or_default(),
        from_integrity: integrity_label(&old.integrity),
        to_integrity: integrity_label(&new.integrity),
        added,
        removed,
        modified,
        unchanged,
        findings,
        resolved,
        not_checked,
    }
}
