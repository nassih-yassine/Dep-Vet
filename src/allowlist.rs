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
    "advisory-coverage-partial",
    "known-exploited",
    "threat-data-unavailable",
    "low-scorecard",
    "policy-min-age",
    "policy-min-downloads",
    "policy-provenance",
    "policy-advisory-severity",
    "policy-license",
    "policy-license-denied",
    "install-scripts",
    "build-from-source",
    "typosquat",
    "fresh-package",
    "fresh-version",
    "publisher-not-maintainer",
    "maintainer-check-unavailable",
    "deprecated",
    "no-repository",
    "release-after-dormancy",
    "install-scripts-changed",
    "dependency-added",
    "publisher-changed",
    "release-burst",
    "repository-changed",
    "provenance-dropped",
    "attestation-subject-mismatch",
    "attestation-source-mismatch",
    "archive-partially-scanned",
    "advisories-stale",
];

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    #[serde(default)]
    allow: Vec<AllowEntry>,
    #[serde(default)]
    inspect: InspectConfig,
    #[serde(default)]
    provenance: ProvenancePolicyConfig,
    #[serde(default)]
    trusted_publishers: TrustedPublishersConfig,
    #[serde(default)]
    policy: Policy,
}

/// Thresholds for the install policy. Every field is off by default, so adding
/// `[policy]` with one key never changes another rule.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The package must have been first published at least this long ago.
    pub min_age_days: Option<u64>,
    /// A known weekly download figure must be at least this many.
    pub min_weekly_downloads: Option<u64>,
    /// Require a provenance attestation where the ecosystem supports one.
    pub require_provenance: Option<bool>,
    /// Highest advisory severity the policy tolerates.
    pub max_advisory_severity: Option<Severity>,
    /// If non-empty, the package license must be on this list.
    #[serde(default)]
    pub allowed_licenses: Vec<String>,
    /// A license on this list is a HIGH finding.
    #[serde(default)]
    pub denied_licenses: Vec<String>,
    /// Severity for threshold violations. `denied_licenses` is always HIGH.
    pub severity: Option<Severity>,
}

impl Policy {
    pub fn needs_license(&self) -> bool {
        !self.allowed_licenses.is_empty() || !self.denied_licenses.is_empty()
    }

    pub fn violation_severity(&self) -> Severity {
        self.severity.unwrap_or(Severity::Warn)
    }
}

/// Opt-in provenance requirements. Both default to false, so adding this
/// section never changes a verdict by itself.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenancePolicyConfig {
    #[serde(default)]
    pub require_attestation: bool,
    #[serde(default)]
    pub require_verified_source: bool,
}

/// GitHub identities allowed to publish. Empty lists mean no publisher gate.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedPublishersConfig {
    #[serde(default)]
    pub github_organizations: Vec<String>,
    #[serde(default)]
    pub repositories: Vec<String>,
    #[serde(default)]
    pub workflows: Vec<String>,
}

/// Upper bounds for archive configuration. They are generous enough for real
/// packages but keep every stock cap well below `u64` overflow.
pub const MAX_DOWNLOAD_MB: u64 = 1_024;
pub const MAX_TOTAL_MB: u64 = 1_024;
pub const MAX_FILE_MB: u64 = 512;
pub const MAX_DECOMPRESSED_MB: u64 = 2_048;
pub const MAX_ENTRIES: usize = 1_000_000;

/// Archive-inspection settings from the same `.depvet.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectConfig {
    #[serde(default)]
    pub max_download_mb: Option<u64>,
    #[serde(default)]
    pub max_total_mb: Option<u64>,
    #[serde(default)]
    pub max_entries: Option<usize>,
    #[serde(default)]
    pub max_file_mb: Option<u64>,
    #[serde(default)]
    pub max_decompressed_mb: Option<u64>,
    #[serde(default)]
    pub disabled_rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowEntry {
    package: String,
    #[serde(default)]
    finding: Option<String>,
    reason: String,
}

impl InspectConfig {
    /// Documented defaults, with the config file able to tighten or loosen
    /// each cap. Zero is rejected at parse time.
    pub fn limits(&self) -> crate::archive::Limits {
        let defaults = crate::archive::Limits::default();
        let mb = |value: Option<u64>, fallback: u64| {
            value
                .map(|mb| mb.saturating_mul(1024 * 1024))
                .unwrap_or(fallback)
        };
        crate::archive::Limits {
            max_compressed: mb(self.max_download_mb, defaults.max_compressed),
            max_total: mb(self.max_total_mb, defaults.max_total),
            max_entries: self.max_entries.unwrap_or(defaults.max_entries),
            max_file: mb(self.max_file_mb, defaults.max_file),
            max_decompressed: mb(self.max_decompressed_mb, defaults.max_decompressed),
            max_path: defaults.max_path,
        }
    }
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
    #[error("{path}: '{rule}' is not an inspection rule")]
    UnknownRule { path: String, rule: String },
    #[error("{path}: {field} must be greater than zero")]
    ZeroLimit { path: String, field: String },
    #[error("{path}: {field} must be at most {max} (got {value})")]
    LimitTooLarge {
        path: String,
        field: String,
        value: u64,
        max: u64,
    },
    #[error("{path}: {field} contains an empty entry")]
    EmptyPolicyValue { path: String, field: String },
    #[error("{path}: '{license}' is both allowed and denied")]
    PolicyLicenseConflict { path: String, license: String },
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
        for rule in &list.inspect.disabled_rules {
            if !crate::rules::is_known_rule(rule) {
                return Err(AllowError::UnknownRule {
                    path: path.display().to_string(),
                    rule: rule.clone(),
                });
            }
        }
        for (field, value, maximum) in [
            (
                "max_download_mb",
                list.inspect.max_download_mb,
                MAX_DOWNLOAD_MB,
            ),
            ("max_total_mb", list.inspect.max_total_mb, MAX_TOTAL_MB),
            ("max_file_mb", list.inspect.max_file_mb, MAX_FILE_MB),
            (
                "max_decompressed_mb",
                list.inspect.max_decompressed_mb,
                MAX_DECOMPRESSED_MB,
            ),
        ] {
            if let Some(value) = value {
                if value == 0 {
                    return Err(AllowError::ZeroLimit {
                        path: path.display().to_string(),
                        field: field.to_string(),
                    });
                }
                if value > maximum {
                    return Err(AllowError::LimitTooLarge {
                        path: path.display().to_string(),
                        field: field.to_string(),
                        value,
                        max: maximum,
                    });
                }
            }
        }
        if let Some(entries) = list.inspect.max_entries {
            if entries == 0 {
                return Err(AllowError::ZeroLimit {
                    path: path.display().to_string(),
                    field: "max_entries".to_string(),
                });
            }
            if entries > MAX_ENTRIES {
                return Err(AllowError::LimitTooLarge {
                    path: path.display().to_string(),
                    field: "max_entries".to_string(),
                    value: entries as u64,
                    max: MAX_ENTRIES as u64,
                });
            }
        }
        for (field, values) in [
            (
                "trusted_publishers.github_organizations",
                &list.trusted_publishers.github_organizations,
            ),
            (
                "trusted_publishers.repositories",
                &list.trusted_publishers.repositories,
            ),
            (
                "trusted_publishers.workflows",
                &list.trusted_publishers.workflows,
            ),
            ("policy.allowed_licenses", &list.policy.allowed_licenses),
            ("policy.denied_licenses", &list.policy.denied_licenses),
        ] {
            if values.iter().any(|value| value.trim().is_empty()) {
                return Err(AllowError::EmptyPolicyValue {
                    path: path.display().to_string(),
                    field: field.to_string(),
                });
            }
        }
        for (field, value) in [
            ("policy.min_age_days", list.policy.min_age_days),
            (
                "policy.min_weekly_downloads",
                list.policy.min_weekly_downloads,
            ),
        ] {
            if value == Some(0) {
                return Err(AllowError::ZeroLimit {
                    path: path.display().to_string(),
                    field: field.to_string(),
                });
            }
        }
        for allowed in &list.policy.allowed_licenses {
            if crate::license::any_listed(&list.policy.denied_licenses, allowed) {
                return Err(AllowError::PolicyLicenseConflict {
                    path: path.display().to_string(),
                    license: allowed.clone(),
                });
            }
        }
        Ok(list)
    }

    pub fn inspect(&self) -> &InspectConfig {
        &self.inspect
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    /// Combine the two opt-in sections into the policy `inspect` evaluates.
    pub fn trust_policy(&self) -> crate::provenance::TrustPolicy {
        crate::provenance::TrustPolicy {
            require_attestation: self.provenance.require_attestation,
            require_verified_source: self.provenance.require_verified_source,
            github_organizations: self.trusted_publishers.github_organizations.clone(),
            repositories: self.trusted_publishers.repositories.clone(),
            workflows: self.trusted_publishers.workflows.clone(),
        }
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
            provenance: crate::model::Provenance::Unavailable,
            attestation_subject_matches: None,
            attestation: None,
            advisories: Vec::new(),
            hidden_advisories: 0,
            not_checked: Vec::new(),
            registry_url: String::new(),
            review_url: None,
            upgrades: Vec::new(),
            dependency_paths: Vec::new(),
            findings,
            scorecard: None,
            license: None,
        }
    }

    fn allowlist(body: &str) -> Allowlist {
        Allowlist::parse(Path::new(".depvet.toml"), body).unwrap()
    }

    #[test]
    fn inspect_settings_apply_and_reject_nonsense() {
        let path = Path::new(".depvet.toml");
        let config = Allowlist::parse(
            path,
            "[inspect]\nmax_download_mb = 10\nmax_entries = 500\ndisabled_rules = [\"JS-EXEC-001\"]\n",
        )
        .unwrap();
        let limits = config.inspect().limits();
        assert_eq!(limits.max_compressed, 10 * 1024 * 1024);
        assert_eq!(limits.max_entries, 500);
        assert_eq!(limits.max_decompressed, 200 * 1024 * 1024);

        let configured = Allowlist::parse(path, "[inspect]\nmax_decompressed_mb = 10\n").unwrap();
        assert_eq!(
            configured.inspect().limits().max_decompressed,
            10 * 1024 * 1024
        );
        assert!(matches!(
            Allowlist::parse(path, "[inspect]\nmax_decompressed_mb = 0\n"),
            Err(AllowError::ZeroLimit { .. })
        ));
        assert_eq!(config.inspect().disabled_rules, vec!["JS-EXEC-001"]);

        assert!(matches!(
            Allowlist::parse(path, "[inspect]\nmax_download_mb = 0\n"),
            Err(AllowError::ZeroLimit { .. })
        ));
        assert!(matches!(
            Allowlist::parse(path, "[inspect]\ndisabled_rules = [\"NOPE-000\"]\n"),
            Err(AllowError::UnknownRule { .. })
        ));
    }

    #[test]
    fn provenance_policy_is_opt_in_and_rejects_empty_entries() {
        let path = Path::new(".depvet.toml");
        assert!(!allowlist("").trust_policy().configured());

        let config = allowlist(
            "[provenance]\nrequire_attestation = true\nrequire_verified_source = true\n\n[trusted_publishers]\ngithub_organizations = [\"acme\"]\nrepositories = [\"acme/pkg\"]\nworkflows = [\"acme/pkg/.github/workflows/release.yml\"]\n",
        );
        let policy = config.trust_policy();
        assert!(policy.require_attestation && policy.require_verified_source);
        assert_eq!(policy.github_organizations, vec!["acme"]);
        assert_eq!(policy.repositories, vec!["acme/pkg"]);
        assert_eq!(
            policy.workflows,
            vec!["acme/pkg/.github/workflows/release.yml"]
        );

        assert!(matches!(
            Allowlist::parse(path, "[trusted_publishers]\nrepositories = [\"  \"]\n"),
            Err(AllowError::EmptyPolicyValue { .. })
        ));
        assert!(matches!(
            Allowlist::parse(path, "[provenance]\nrequire_attestations = true\n"),
            Err(AllowError::Toml { .. })
        ));
        assert!(matches!(
            Allowlist::parse(path, "[provenance]\nrequire_attestation = \"yes\"\n"),
            Err(AllowError::Toml { .. })
        ));
    }

    #[test]
    fn archive_limits_reject_overflow_and_excessive_values() {
        let path = Path::new(".depvet.toml");
        let max = format!(
            "[inspect]\nmax_download_mb = {MAX_DOWNLOAD_MB}\nmax_total_mb = {MAX_TOTAL_MB}\nmax_file_mb = {MAX_FILE_MB}\nmax_decompressed_mb = {MAX_DECOMPRESSED_MB}\nmax_entries = {MAX_ENTRIES}\n"
        );
        let limits = Allowlist::parse(path, &max).unwrap().inspect().limits();
        assert_eq!(limits.max_compressed, MAX_DOWNLOAD_MB * 1024 * 1024);
        assert_eq!(limits.max_total, MAX_TOTAL_MB * 1024 * 1024);
        assert_eq!(limits.max_file, MAX_FILE_MB * 1024 * 1024);
        assert_eq!(limits.max_decompressed, MAX_DECOMPRESSED_MB * 1024 * 1024);
        assert_eq!(limits.max_entries, MAX_ENTRIES);

        for (field, body) in [
            (
                "max_download_mb",
                format!("[inspect]\nmax_download_mb = {}\n", MAX_DOWNLOAD_MB + 1),
            ),
            (
                "max_total_mb",
                format!("[inspect]\nmax_total_mb = {}\n", MAX_TOTAL_MB + 1),
            ),
            (
                "max_file_mb",
                format!("[inspect]\nmax_file_mb = {}\n", MAX_FILE_MB + 1),
            ),
            (
                "max_decompressed_mb",
                format!(
                    "[inspect]\nmax_decompressed_mb = {}\n",
                    MAX_DECOMPRESSED_MB + 1
                ),
            ),
            (
                "max_entries",
                format!("[inspect]\nmax_entries = {}\n", MAX_ENTRIES + 1),
            ),
            (
                "max_download_mb",
                format!("[inspect]\nmax_download_mb = {}\n", u64::MAX),
            ),
            (
                "max_decompressed_mb",
                format!(
                    "[inspect]\nmax_decompressed_mb = {}\n",
                    u64::MAX / (1024 * 1024) + 1
                ),
            ),
        ] {
            assert!(
                matches!(
                    Allowlist::parse(path, &body),
                    Err(AllowError::LimitTooLarge { field: ref found, .. }) if found == field
                ),
                "{field}: {body}"
            );
        }

        let minimum = Allowlist::parse(
            path,
            "[inspect]\nmax_download_mb = 1\nmax_total_mb = 1\nmax_file_mb = 1\nmax_decompressed_mb = 1\nmax_entries = 1\n",
        )
        .unwrap()
        .inspect()
        .limits();
        assert_eq!(minimum.max_compressed, 1024 * 1024);
        assert_eq!(minimum.max_entries, 1);

        let defaults = Allowlist::parse(path, "").unwrap().inspect().limits();
        assert_eq!(
            defaults.max_compressed,
            crate::archive::Limits::default().max_compressed
        );
        assert!(matches!(
            Allowlist::parse(
                path,
                "[inspect]\nmax_download_mb = 10\nmax_total_mb = 99999999\n"
            ),
            Err(AllowError::LimitTooLarge {
                field: ref found,
                ..
            }) if found == "max_total_mb"
        ));

        let manually_huge = InspectConfig {
            max_download_mb: Some(u64::MAX),
            ..InspectConfig::default()
        };
        assert_eq!(manually_huge.limits().max_compressed, u64::MAX);
    }

    #[test]
    fn every_finding_id_emitted_by_signals_is_allowlistable() {
        let source = include_str!("signals/mod.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let mut ids = Vec::new();
        for line in production.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("id: \"")
                && let Some(end) = rest.find('"')
            {
                ids.push(&rest[..end]);
            }
        }
        assert!(!ids.is_empty(), "no ids found in signals/mod.rs");
        for id in ids {
            assert!(
                KNOWN_FINDINGS.contains(&id),
                "{id} is emitted by signals but missing from KNOWN_FINDINGS"
            );
        }
    }

    #[test]
    fn policy_section_parses_with_defaults_and_aliases() {
        let list = Allowlist::parse(
            Path::new(".depvet.toml"),
            r#"
[policy]
min_age_days = 30
min_weekly_downloads = 100
require_provenance = true
max_advisory_severity = "medium"
severity = "high"
allowed_licenses = ["MIT", "Apache-2.0"]
"#,
        )
        .unwrap();
        let policy = list.policy();
        assert_eq!(policy.min_age_days, Some(30));
        assert_eq!(policy.max_advisory_severity, Some(Severity::Warn));
        assert_eq!(policy.violation_severity(), Severity::High);
        assert!(policy.needs_license());

        let empty = Allowlist::parse(Path::new(".depvet.toml"), "").unwrap();
        assert_eq!(empty.policy().violation_severity(), Severity::Warn);
        assert!(!empty.policy().needs_license());
    }

    #[test]
    fn policy_config_errors_are_tool_errors() {
        for body in [
            "[policy]\nmax_age_days = 30\n",
            "[policy]\nseverity = \"nonsense\"\n",
            "[policy]\nmin_age_days = 0\n",
            "[policy]\nmin_weekly_downloads = 0\n",
            "[policy]\nallowed_licenses = [\"\"]\n",
            "[policy]\nallowed_licenses = [\"MIT\"]\ndenied_licenses = [\"mit license\"]\n",
        ] {
            assert!(
                Allowlist::parse(Path::new(".depvet.toml"), body).is_err(),
                "{body}"
            );
        }
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
        // macOS resolves /var to /private/var and Windows returns long paths.
        let expected = config.canonicalize().unwrap();
        assert_eq!(nearest(&nested).as_deref(), Some(expected.as_path()));
    }
}
