//! `.depvet.toml`: reviewer-approved exceptions, each with a reason.
//!
//! An allowed finding stays in the report as INFO with the reason attached;
//! it never disappears. A config that cannot be read or understood is a tool
//! error, not an empty allowlist.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::model::{PackageReport, Severity};

const CONFIG_NAME: &str = ".depvet.toml";

/// Every finding id dep-vet can emit. Keep in step with `signals.rs`.
pub const KNOWN_FINDINGS: &[&str] = &[
    "advisory",
    "advisories-truncated",
    "advisory-check-unavailable",
    "install-scripts",
    "build-from-source",
    "typosquat",
    "fresh-package",
    "fresh-version",
    "publisher-not-maintainer",
    "maintainer-check-unavailable",
    "deprecated",
    "no-repository",
];

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    #[serde(default)]
    allow: Vec<AllowEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowEntry {
    package: String,
    #[serde(default)]
    finding: Option<String>,
    reason: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AllowError {
    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is not valid TOML: {message}")]
    Toml { path: String, message: String },
    #[error("{path}: allow entry for '{package}' must have a reason")]
    MissingReason { path: String, package: String },
    #[error("{path}: '{finding}' is not a finding dep-vet emits")]
    UnknownFinding { path: String, finding: String },
}

impl Allowlist {
    /// Explicit path wins; otherwise the nearest `.depvet.toml` walking up.
    pub fn load(explicit: Option<&Path>) -> Result<Self, AllowError> {
        let path = match explicit {
            Some(path) => path.to_path_buf(),
            None => match nearest(Path::new(".")) {
                Some(path) => path,
                None => return Ok(Self::default()),
            },
        };
        let body = std::fs::read_to_string(&path).map_err(|source| AllowError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&path, &body)
    }

    pub fn parse(path: &Path, body: &str) -> Result<Self, AllowError> {
        let list: Allowlist = toml::from_str(body).map_err(|error| AllowError::Toml {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;

        for entry in &list.allow {
            if entry.reason.trim().is_empty() {
                return Err(AllowError::MissingReason {
                    path: path.display().to_string(),
                    package: entry.package.clone(),
                });
            }
            if let Some(finding) = &entry.finding
                && !KNOWN_FINDINGS.contains(&finding.as_str())
            {
                return Err(AllowError::UnknownFinding {
                    path: path.display().to_string(),
                    finding: finding.clone(),
                });
            }
        }
        Ok(list)
    }

    /// Downgrades matching findings to INFO, keeps their evidence, and records
    /// why they were allowed.
    pub fn apply(&self, report: &mut PackageReport) {
        for finding in &mut report.findings {
            let Some(entry) = self.allow.iter().find(|entry| {
                entry.package.eq_ignore_ascii_case(&report.name)
                    && entry.finding.as_deref().is_none_or(|id| id == finding.id)
            }) else {
                continue;
            };
            if finding.allowed {
                continue;
            }
            finding.allowed = true;
            finding.severity = Severity::Info;
            finding.detail = format!(
                "allowed by {CONFIG_NAME}: {}. {}",
                entry.reason.trim(),
                finding.detail
            );
        }
        // Severity changed for some findings; keep the worst-first order.
        report
            .findings
            .sort_by_key(|finding| std::cmp::Reverse(finding.severity));
    }
}

fn nearest(start: &Path) -> Option<PathBuf> {
    let start = start.canonicalize().ok()?;
    start
        .ancestors()
        .map(|directory| directory.join(CONFIG_NAME))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, Finding, Severity};

    fn finding(id: &'static str, severity: Severity) -> Finding {
        Finding {
            id,
            severity,
            title: "title".to_string(),
            detail: "detail".to_string(),
            allowed: false,
            evidence: vec![Evidence {
                label: "e".to_string(),
                value: "v".to_string(),
                url: None,
            }],
        }
    }

    fn report(name: &str, findings: Vec<Finding>) -> PackageReport {
        PackageReport {
            ecosystem: crate::model::Ecosystem::Npm,
            name: name.to_string(),
            version: "1.0.0".to_string(),
            first_published_at: None,
            published_at: None,
            weekly_downloads: None,
            maintainers: Vec::new(),
            publisher: None,
            install_scripts: Vec::new(),
            repository: None,
            deprecated: None,
            advisories: Vec::new(),
            hidden_advisories: 0,
            not_checked: Vec::new(),
            registry_url: String::new(),
            review_url: None,
            findings,
        }
    }

    fn allowlist(body: &str) -> Allowlist {
        Allowlist::parse(Path::new(".depvet.toml"), body).unwrap()
    }

    #[test]
    fn allows_one_finding_and_keeps_the_reason() {
        let list = allowlist(
            r#"
[[allow]]
package = "crossenv"
finding = "typosquat"
reason = "internal fork, reviewed 2026-11"
"#,
        );
        let mut report = report("crossenv", vec![finding("typosquat", Severity::High)]);
        list.apply(&mut report);

        let finding = &report.findings[0];
        assert!(finding.allowed);
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.detail.contains("internal fork, reviewed 2026-11"));
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn allows_everything_for_a_package_when_finding_is_omitted() {
        let list = allowlist(
            r#"
[[allow]]
package = "legacy"
reason = "accepted risk"
"#,
        );
        let mut report = report(
            "legacy",
            vec![
                finding("typosquat", Severity::High),
                finding("install-scripts", Severity::Warn),
            ],
        );
        list.apply(&mut report);
        assert!(report.findings.iter().all(|finding| finding.allowed));
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn package_matching_is_case_insensitive_and_scoped_to_one_package() {
        let list = allowlist(
            r#"
[[allow]]
package = "CrossEnv"
finding = "typosquat"
reason = "reviewed"
"#,
        );
        let mut other = report("cross-env", vec![finding("typosquat", Severity::High)]);
        list.apply(&mut other);
        assert!(!other.findings[0].allowed);
        assert_eq!(other.exit_code(), 2);
    }

    #[test]
    fn a_different_finding_is_not_allowed() {
        let list = allowlist(
            r#"
[[allow]]
package = "pkg"
finding = "typosquat"
reason = "reviewed"
"#,
        );
        let mut report = report("pkg", vec![finding("advisory", Severity::High)]);
        list.apply(&mut report);
        assert!(!report.findings[0].allowed);
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn entries_require_a_reason() {
        let error = Allowlist::parse(
            Path::new(".depvet.toml"),
            "[[allow]]\npackage = \"x\"\nreason = \"  \"\n",
        )
        .unwrap_err();
        assert!(matches!(error, AllowError::MissingReason { .. }));
    }

    #[test]
    fn unknown_finding_ids_are_rejected() {
        let error = Allowlist::parse(
            Path::new(".depvet.toml"),
            "[[allow]]\npackage = \"x\"\nfinding = \"vibes\"\nreason = \"why\"\n",
        )
        .unwrap_err();
        assert!(matches!(error, AllowError::UnknownFinding { .. }));
    }

    #[test]
    fn a_misspelled_key_is_an_error() {
        let error = Allowlist::parse(
            Path::new(".depvet.toml"),
            r#"[[allows]]
package = "x"
reason = "why"
"#,
        )
        .unwrap_err();
        assert!(matches!(error, AllowError::Toml { .. }));

        let error = Allowlist::parse(
            Path::new(".depvet.toml"),
            r#"[[allow]]
packages = "x"
reason = "why"
"#,
        )
        .unwrap_err();
        assert!(matches!(error, AllowError::Toml { .. }));
    }

    #[test]
    fn malformed_toml_is_an_error() {
        let error = Allowlist::parse(Path::new(".depvet.toml"), "[[allow").unwrap_err();
        assert!(matches!(error, AllowError::Toml { .. }));
    }

    #[test]
    fn an_empty_file_allows_nothing() {
        let list = allowlist("");
        let mut report = report("x", vec![finding("typosquat", Severity::High)]);
        list.apply(&mut report);
        assert!(!report.findings[0].allowed);
    }

    #[test]
    fn finds_a_config_in_a_parent_directory() {
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("packages").join("app");
        std::fs::create_dir_all(&nested).unwrap();
        let config = directory.path().join(CONFIG_NAME);
        std::fs::write(&config, "").unwrap();
        assert_eq!(nearest(&nested).as_deref(), Some(config.as_path()));
    }
}
