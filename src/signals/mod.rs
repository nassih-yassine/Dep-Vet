//! The rule set. Every finding is a claim plus the evidence that supports it,
//! and severity only escalates when signals reinforce each other.

use crate::date;
use crate::model::{Ecosystem, Evidence, Finding, PackageReport, Profile, Severity};
use crate::model::{InstallScript, Upgrade};
use crate::osv::{Advisory, AdvisoryList, MAX_ADVISORIES};
use crate::registry::PackageMeta;
use crate::typosquat;
use crate::version::leading_number;

/// Shortest added dependency that can escalate `dependency-added` to WARN.
const MIN_ACCUSABLE_NAME: usize = 5;

/// A package younger than this has no track record.
pub const FRESH_DAYS: i64 = 7;
/// A version newer than this on a package with no history is worth a look.
pub const RECENT_VERSION_DAYS: i64 = 7;
use crate::registry::HISTORY_WINDOW_DAYS;
/// Nothing published for this long, then a release, is the classic pattern of
/// a hijacked or revived package.
pub const DORMANCY_DAYS: i64 = 365;

/// A package used this widely is not an accidental typo. The seed is generated
/// and always has holes (`next` was missing once), and the alternative is
/// telling people to replace a framework with an unrelated test runner.
pub const ESTABLISHED_WEEKLY_DOWNLOADS: u64 = 1_000_000;
/// A misleading name this old is not the accidental-typo attack this signal
/// exists for, in any ecosystem.
pub const ESTABLISHED_AGE_DAYS: i64 = 5 * 365;

pub fn report(
    meta: PackageMeta,
    ecosystem: Ecosystem,
    weekly_downloads: Option<u64>,
    advisories: Option<&AdvisoryList>,
    local: &[String],
    profile: Profile,
    now: i64,
) -> PackageReport {
    report_with_policy(
        meta,
        ecosystem,
        weekly_downloads,
        advisories,
        local,
        profile,
        now,
        &crate::allowlist::Policy::default(),
    )
}

/// Same as [`report`] plus `.depvet.toml` `[policy]` thresholds. The default
/// policy is empty, so callers that do not have config see no change.
#[allow(clippy::too_many_arguments)]
pub fn report_with_policy(
    meta: PackageMeta,
    ecosystem: Ecosystem,
    weekly_downloads: Option<u64>,
    advisories: Option<&AdvisoryList>,
    local: &[String],
    profile: Profile,
    now: i64,
    policy: &crate::allowlist::Policy,
) -> PackageReport {
    // Age only excuses a weak resemblance. A one-edit lookalike stays
    // suspicious however old it is: crossenv is nine years old and still malware.
    let nearest = suspect_for(&meta, ecosystem, local, &profile);
    let weak = nearest
        .as_ref()
        .is_none_or(|suspect| !suspect.homoglyph && suspect.distance > 1);
    let outmatched = match (weekly_downloads, meta.candidate_weekly_downloads) {
        (Some(own), Some(candidate)) => own >= candidate,
        (Some(own), None) => own >= ESTABLISHED_WEEKLY_DOWNLOADS,
        _ => false,
    };
    let aged = weak
        && meta
            .first_published_at
            .is_some_and(|first| now - first >= ESTABLISHED_AGE_DAYS * date::SECONDS_PER_DAY);
    let established = outmatched || aged;
    let mut findings = assess(&meta, ecosystem, local, &profile, now);
    if let Some(finding) = confusion_finding(&meta) {
        findings.push(finding);
    }
    if established {
        findings.retain(|finding| finding.id != "typosquat");
    }
    match advisories {
        Some(list) => {
            findings.extend(advisory_findings(&list.advisories));
            if list.hidden > 0 {
                findings.push(advisories_hidden(list.hidden));
            }
            if let Some(error) = &list.threat_error {
                findings.push(threat_data_unavailable(error));
            }
            if let Some(age) = list.stale_seconds {
                findings.push(Finding {
                    id: "advisories-stale",
                    severity: Severity::Info,
                    title: "advisory data is stale".to_string(),
                    detail: format!(
                        "served from a {} old cache after a failed refresh; newer advisories may be missing",
                        human_age(age)
                    ),
                    allowed: false,
                    evidence: vec![Evidence {
                        label: "advisory source".to_string(),
                        value: meta.registry_url.clone(),
                        url: Some(meta.registry_url.clone()),
                    }],
                });
            }
        }
        None if !profile.advisories => findings.push(advisory_coverage_missing(ecosystem)),
        None => findings.push(advisory_check_unavailable()),
    }
    // A low score alone is not evidence about this release: it describes the
    // repository. Pair it with a publisher change, which is what makes the
    // repository's practices worth reading now.
    if let Some(scorecard) = &meta.scorecard
        && scorecard.overall < LOW_SCORECARD
        && findings
            .iter()
            .any(|finding| matches!(finding.id, "publisher-changed" | "publisher-not-maintainer"))
    {
        findings.push(low_scorecard(scorecard, meta.repository.as_deref()));
    }
    findings.extend(policy_findings(
        policy,
        &meta,
        weekly_downloads.filter(|_| profile.downloads),
        advisories,
        now,
    ));
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

    let suspect = if established { None } else { nearest };
    let upgrades = upgrade_advice(&meta, advisories, suspect.as_ref())
        .into_iter()
        .collect();

    // A registry that reports no publish date cannot support the freshness
    // rules; say so instead of letting silence read as "freshness checked".
    let mut not_checked = profile.not_checked();
    if profile.freshness && meta.published_at.is_none() && !not_checked.contains(&"freshness") {
        not_checked.push("freshness");
    }
    if profile.scorecard && meta.scorecard.is_none() && !not_checked.contains(&"scorecard") {
        not_checked.push("scorecard");
    }
    if policy.needs_license() && meta.license.is_none() && !not_checked.contains(&"license") {
        not_checked.push("license");
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
        provenance: meta.provenance,
        attestation_subject_matches: meta.attestation_subject_matches,
        attestation: meta.attestation,
        scorecard: meta.scorecard,
        license: meta.license,
        advisories: advisories
            .map(|list| list.advisories.clone())
            .unwrap_or_default(),
        hidden_advisories: advisories.map(|list| list.hidden).unwrap_or(0),
        not_checked,
        registry_url: meta.registry_url,
        review_url: meta.review_url,
        upgrades,
        dependency_paths: Vec::new(),
        findings,
    }
}

/// Advice is driven only by advisories and by a lookalike name. A package whose
/// findings are all install scripts, deprecation, or freshness gets nothing, so
/// the report never becomes an "out of date" nag.
/// A routed package that also exists on the public registry is the classic
/// dependency-confusion target: an unpinned resolver takes the public copy.
/// HIGH when that copy is the same or newer, WARN when only older versions
/// exist, INFO when the probe could not run (never silence).
fn confusion_finding(meta: &PackageMeta) -> Option<Finding> {
    use crate::registry::PublicProbe;
    let (latest, versions) = match &meta.public {
        PublicProbe::NotApplicable => return None,
        PublicProbe::Unchecked => {
            return Some(Finding {
                id: "dependency-confusion-unchecked",
                severity: Severity::Info,
                title: "the public registry was not checked".to_string(),
                detail: "this name comes from a private registry; the probe for a public \
                         copy failed, so a squatter is not ruled out"
                    .to_string(),
                allowed: false,
                evidence: vec![Evidence {
                    label: "private registry".to_string(),
                    value: meta.registry_url.clone(),
                    url: Some(meta.registry_url.clone()),
                }],
            });
        }
        PublicProbe::Known { latest, versions } => (latest, versions),
    };
    if versions.is_empty() {
        return None;
    }
    let internal = semver::Version::parse(&meta.version).ok();
    let public = latest
        .as_ref()
        .and_then(|version| semver::Version::parse(version).ok())
        .or_else(|| {
            versions
                .iter()
                .filter_map(|version| semver::Version::parse(version).ok())
                .max()
        });
    let public_url = format!("https://www.npmjs.com/package/{}", meta.name);
    let (severity, detail) = match (internal, public) {
        (Some(internal), Some(public)) if public >= internal => (
            Severity::High,
            format!(
                "the public registry has {public} for '{}'; this build resolves {internal} from a \
                 private registry, so a resolver that falls back to the public copy installs \
                 someone else's package",
                meta.name
            ),
        ),
        (Some(internal), Some(public)) => (
            Severity::Warn,
            format!(
                "the public registry has '{}' up to {public}, below this {internal}; a future \
                 version bump on the public side would shadow this private one",
                meta.name
            ),
        ),
        _ => (
            Severity::Warn,
            format!(
                "the public registry publishes '{}' but the versions could not be ordered \
                 against {}",
                meta.name, meta.version
            ),
        ),
    };
    Some(Finding {
        id: "dependency-confusion",
        severity,
        title: "this private name also exists on the public registry".to_string(),
        detail,
        allowed: false,
        evidence: vec![
            Evidence {
                label: "private registry".to_string(),
                value: meta.registry_url.clone(),
                url: Some(meta.registry_url.clone()),
            },
            Evidence {
                label: "public copy".to_string(),
                value: public_url.clone(),
                url: Some(public_url),
            },
        ],
    })
}

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

/// Commands that fetch or decode code during install. Presence alone is not a
/// verdict: it raises an already-changed script from WARN to HIGH.
///
/// Matching is by whole token, not substring: `node scripts/evaluate.js` is a
/// normal build step, while `node -e` runs inline code.
pub(crate) fn risky_install_command(command: &str) -> bool {
    let lowered = command.to_ascii_lowercase();
    let tokens: Vec<String> = lowered
        .split(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    ';' | '|' | '&' | '(' | ')' | '<' | '>' | '`' | '\'' | '"' | '='
                )
        })
        .filter(|token| !token.is_empty())
        .map(|token| {
            // `/usr/bin/curl`, `curl.exe`, and Windows paths all mean curl.
            let base = token.rsplit(['/', '\\']).next().unwrap_or(token);
            for suffix in [".exe", ".cmd", ".bat"] {
                if let Some(stripped) = base.strip_suffix(suffix) {
                    return stripped.to_string();
                }
            }
            base.to_string()
        })
        .collect();
    let word = |needle: &str| tokens.iter().any(|token| token == needle);
    if [
        "curl",
        "wget",
        "nc",
        "base64",
        "iex",
        "iwr",
        "irm",
        "powershell",
        "pwsh",
        "certutil",
        "bitsadmin",
        "mshta",
        "eval",
    ]
    .iter()
    .any(|needle| word(needle))
    {
        return true;
    }
    if (word("bash") || word("sh")) && word("-c") && lowered.contains("http") {
        return true;
    }
    for (index, token) in tokens.iter().enumerate() {
        let flags: &[&str] = match token.as_str() {
            "python" | "python2" | "python3" => &["-c"],
            "perl" | "ruby" => &["-e"],
            "php" => &["-r"],
            "node" | "nodejs" => &["-e", "-p", "--eval", "--print"],
            _ => continue,
        };
        for (skipped, next) in tokens[index + 1..].iter().take(2).enumerate() {
            if flags.contains(&next.as_str()) {
                return true;
            }
            if !next.starts_with('-') || skipped == 1 {
                break;
            }
        }
    }
    false
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

/// One finding per advisory, each linking to its OSV record. An advisory the
/// CISA KEV catalog lists also gets its own WARN finding; EPSS stays context
/// and never changes a severity.
pub fn advisory_findings(advisories: &[Advisory]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for advisory in advisories {
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
        if let Some(score) = &advisory.epss {
            evidence.push(epss_evidence(score));
        }
        if let Some(kev) = &advisory.kev {
            evidence.push(kev_evidence(kev));
        }
        findings.push(Finding {
            id: "advisory",
            severity: advisory.severity,
            title: advisory.display_title(),
            detail: advisory.summary.clone(),
            allowed: false,
            evidence,
        });

        if let Some(kev) = &advisory.kev {
            let mut detail = format!(
                "CISA lists {} as exploited in the wild (added {}; {} {}",
                kev.cve, kev.date_added, kev.vendor, kev.product
            );
            detail.push_str(if kev.ransomware {
                "; known ransomware use)"
            } else {
                ")"
            });
            detail.push('.');
            match &advisory.epss {
                Some(score) => detail.push_str(&format!(
                    " EPSS {:.3} ({}th percentile).",
                    score.epss,
                    percentile(score)
                )),
                None => detail.push_str(" EPSS score unavailable."),
            }
            findings.push(Finding {
                id: "known-exploited",
                severity: Severity::Warn,
                title: format!("{} is exploited in the wild", kev.cve),
                detail,
                allowed: false,
                evidence: vec![
                    kev_evidence(kev),
                    Evidence {
                        label: "advisory".to_string(),
                        value: advisory.id.clone(),
                        url: Some(advisory.url.clone()),
                    },
                ],
            });
        }
    }
    findings
}

fn percentile(score: &crate::exploit::EpssScore) -> i64 {
    (score.percentile * 100.0).round() as i64
}

fn epss_evidence(score: &crate::exploit::EpssScore) -> Evidence {
    Evidence {
        label: "EPSS".to_string(),
        value: format!("{:.3} ({}th percentile)", score.epss, percentile(score)),
        url: Some(format!(
            "https://api.first.org/data/v1/epss?cve={}",
            score.cve
        )),
    }
}

fn kev_evidence(kev: &crate::exploit::KevEntry) -> Evidence {
    Evidence {
        label: "exploited".to_string(),
        value: format!(
            "CISA KEV, added {}{}",
            kev.date_added,
            if kev.ransomware {
                ", known ransomware use"
            } else {
                ""
            }
        ),
        url: Some(format!(
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={}",
            kev.cve
        )),
    }
}

/// Below this overall score a repository's practices are worth a look when the
/// publisher also changed. Never a finding on its own.
pub const LOW_SCORECARD: f64 = 5.0;

fn low_scorecard(scorecard: &crate::scorecard::Scorecard, repository: Option<&str>) -> Finding {
    let project = repository.and_then(crate::scorecard::project_key);
    let weak: Vec<String> = scorecard
        .checks
        .iter()
        .filter(|check| (0..5).contains(&check.score))
        .map(|check| format!("{} {}", check.name, check.score))
        .collect();
    let mut detail = format!(
        "OpenSSF Scorecard rates {} {:.1}/10",
        project.as_deref().unwrap_or("this repository"),
        scorecard.overall
    );
    if !weak.is_empty() {
        detail.push_str(&format!("; weak checks: {}", weak.join(", ")));
    }
    detail.push_str(
        "; the publisher also changed in this release, so review who controls the repository",
    );
    let url =
        project.map(|project| format!("https://securityscorecards.dev/viewer/?uri={project}"));
    Finding {
        id: "low-scorecard",
        severity: Severity::Info,
        title: "repository scores low on OpenSSF Scorecard".to_string(),
        detail,
        allowed: false,
        evidence: vec![Evidence {
            label: "scorecard".to_string(),
            value: if scorecard.date.is_empty() {
                "no scan date".to_string()
            } else {
                scorecard.date.clone()
            },
            url,
        }],
    }
}

/// Threshold violations from `.depvet.toml` `[policy]`. Every rule is off
/// unless configured, and a value the registry did not publish is skipped, not
/// guessed: the report already says that signal was not checked.
fn policy_findings(
    policy: &crate::allowlist::Policy,
    meta: &PackageMeta,
    weekly_downloads: Option<u64>,
    advisories: Option<&AdvisoryList>,
    now: i64,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let severity = policy.violation_severity();
    let registry = || Evidence {
        label: "registry".to_string(),
        value: meta.registry_url.clone(),
        url: Some(meta.registry_url.clone()),
    };

    if let Some(days) = policy.min_age_days
        && let Some(first) = meta.first_published_at
        && now.saturating_sub(first) < days as i64 * date::SECONDS_PER_DAY
    {
        let age = (now.saturating_sub(first) / date::SECONDS_PER_DAY).max(0);
        findings.push(Finding {
            id: "policy-min-age",
            severity,
            title: "younger than the policy allows".to_string(),
            detail: format!("first published {age} days ago; the policy requires at least {days}"),
            allowed: false,
            evidence: vec![registry()],
        });
    }

    if let Some(minimum) = policy.min_weekly_downloads
        && let Some(actual) = weekly_downloads
        && actual < minimum
    {
        findings.push(Finding {
            id: "policy-min-downloads",
            severity,
            title: "downloads below the policy floor".to_string(),
            detail: format!("{actual} weekly downloads; the policy requires at least {minimum}"),
            allowed: false,
            evidence: vec![registry()],
        });
    }

    if policy.require_provenance == Some(true)
        && meta.provenance == crate::model::Provenance::Missing
    {
        findings.push(Finding {
            id: "policy-provenance",
            severity,
            title: "provenance required by policy".to_string(),
            detail: "the registry publishes no provenance attestation for this version".to_string(),
            allowed: false,
            evidence: vec![registry()],
        });
    }

    if let Some(maximum) = policy.max_advisory_severity
        && let Some(list) = advisories
    {
        for advisory in &list.advisories {
            if advisory.severity > maximum {
                findings.push(Finding {
                    id: "policy-advisory-severity",
                    severity,
                    title: format!(
                        "{} is {} than the policy allows",
                        advisory.id,
                        advisory.severity.label().to_ascii_lowercase()
                    ),
                    detail: format!(
                        "the policy accepts advisories up to {}; this one is {}",
                        maximum.label().to_ascii_lowercase(),
                        advisory.severity.label().to_ascii_lowercase()
                    ),
                    allowed: false,
                    evidence: vec![Evidence {
                        label: "advisory".to_string(),
                        value: advisory.id.clone(),
                        url: Some(advisory.url.clone()),
                    }],
                });
            }
        }
    }

    if let Some(license) = meta.license.as_deref() {
        if crate::license::any_listed(&policy.denied_licenses, license) {
            findings.push(Finding {
                id: "policy-license-denied",
                severity: Severity::High,
                title: "license denied by policy".to_string(),
                detail: format!("license '{license}' is on the denied list"),
                allowed: false,
                evidence: vec![Evidence {
                    label: "license".to_string(),
                    value: license.to_string(),
                    url: Some(crate::license::reference(license)),
                }],
            });
        } else if !policy.allowed_licenses.is_empty()
            && !crate::license::all_listed(&policy.allowed_licenses, license)
        {
            findings.push(Finding {
                id: "policy-license",
                severity,
                title: "license not allowed by policy".to_string(),
                detail: format!(
                    "license '{license}' is not on the allowed list ({})",
                    policy.allowed_licenses.join(", ")
                ),
                allowed: false,
                evidence: vec![Evidence {
                    label: "license".to_string(),
                    value: license.to_string(),
                    url: Some(crate::license::reference(license)),
                }],
            });
        }
    }

    findings
}

fn threat_data_unavailable(error: &str) -> Finding {
    Finding {
        id: "threat-data-unavailable",
        severity: Severity::Info,
        title: "exploit data unavailable".to_string(),
        detail: format!(
            "{error}; the advisories are still reported, but exploit data is incomplete"
        ),
        allowed: false,
        evidence: vec![Evidence {
            label: "CISA KEV catalog".to_string(),
            value: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog".to_string(),
            url: Some("https://www.cisa.gov/known-exploited-vulnerabilities-catalog".to_string()),
        }],
    }
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
/// The popular name this package resembles, if any. Public so a client can ask
/// npm how popular that name is before the verdict is rendered.
pub fn typosquat_candidate(name: &str, ecosystem: Ecosystem, local: &[String]) -> Option<String> {
    typosquat::closest(name, seed_for(ecosystem), local)
        .map(|suspect| suspect.candidate.to_string())
}

fn seed_for(ecosystem: Ecosystem) -> &'static [&'static str] {
    match ecosystem {
        Ecosystem::Npm => typosquat::popular_npm(),
        Ecosystem::Pypi => typosquat::popular_pypi(),
        Ecosystem::CratesIo => typosquat::popular_crates(),
        Ecosystem::Go => typosquat::POPULAR_GO,
        Ecosystem::Jsr => typosquat::POPULAR_JSR,
        Ecosystem::RubyGems => typosquat::POPULAR_RUBYGEMS,
        Ecosystem::NuGet => typosquat::popular_nuget(),
        Ecosystem::Maven => typosquat::POPULAR_MAVEN,
        Ecosystem::Composer => typosquat::POPULAR_COMPOSER,
    }
}

fn suspect_for<'a>(
    meta: &PackageMeta,
    ecosystem: Ecosystem,
    local: &'a [String],
    profile: &Profile,
) -> Option<typosquat::Suspect<'a>> {
    if !profile.typosquat {
        return None;
    }
    typosquat::closest(&meta.name, seed_for(ecosystem), local)
}

fn human_age(seconds: i64) -> String {
    if seconds >= 3600 {
        let hours = seconds / 3600;
        format!("{hours} hour{}", if hours == 1 { "" } else { "s" })
    } else if seconds >= 60 {
        let minutes = seconds / 60;
        format!("{minutes} minute{}", if minutes == 1 { "" } else { "s" })
    } else {
        format!("{seconds} seconds")
    }
}

/// Case, trailing slash, and `.git` do not make two repository URLs different.
fn same_repository(left: &str, right: &str) -> bool {
    fn canonical(url: &str) -> String {
        let trimmed = url.trim().trim_end_matches('/');
        trimmed
            .strip_suffix(".git")
            .unwrap_or(trimmed)
            .trim_end_matches('/')
            .to_ascii_lowercase()
    }
    canonical(left) == canonical(right)
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
    if meta.release.recent_releases >= 5
        && meta
            .first_published_at
            .is_some_and(|first| now - first >= DORMANCY_DAYS * date::SECONDS_PER_DAY)
    {
        findings.push(Finding {
            id: "release-burst",
            severity: Severity::Info,
            title: "unusually many releases recently".to_string(),
            detail: format!(
                "{} releases inside {} days on a package with history",
                meta.release.recent_releases, HISTORY_WINDOW_DAYS
            ),
            allowed: false,
            evidence: vec![Evidence {
                label: "release history".to_string(),
                value: meta.registry_url.clone(),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    if let (Some(previous), Some(current)) = (&meta.release.previous_repository, &meta.repository)
        && !previous.eq_ignore_ascii_case(current)
    {
        findings.push(Finding {
            id: "repository-changed",
            severity: Severity::Info,
            title: "the source repository changed".to_string(),
            detail: format!("previous release: {previous}; this release: {current}"),
            allowed: false,
            evidence: vec![Evidence {
                label: "repository".to_string(),
                value: current.clone(),
                url: Some(current.clone()),
            }],
        });
    }

    if meta.attestation_subject_matches == Some(false) {
        findings.push(Finding {
            id: "attestation-subject-mismatch",
            severity: Severity::High,
            title: "the attestation does not cover this release's tarball".to_string(),
            detail: "the published attestation names a different artifact, so this \
                     tarball is not the one that was attested"
                .to_string(),
            allowed: false,
            evidence: vec![Evidence {
                label: "registry metadata".to_string(),
                value: meta.registry_url.clone(),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    if let (Some(attestation), Some(declared)) = (&meta.attestation, &meta.repository)
        && let Some(claimed) = &attestation.source_repository
        && !same_repository(claimed, declared)
    {
        findings.push(Finding {
            id: "attestation-source-mismatch",
            severity: Severity::Info,
            title: "the attestation names a different source repository".to_string(),
            detail: format!("attested: {claimed}; package metadata: {declared}"),
            allowed: false,
            evidence: vec![Evidence {
                label: "attestation".to_string(),
                value: claimed.clone(),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    if meta.release.previous_provenance == Some(true)
        && meta.provenance != crate::model::Provenance::Present
    {
        findings.push(Finding {
            id: "provenance-dropped",
            severity: Severity::Warn,
            title: "this version no longer publishes provenance".to_string(),
            detail: "the previous release carried an attestation; this one does not".to_string(),
            allowed: false,
            evidence: vec![Evidence {
                label: "registry metadata".to_string(),
                value: meta.registry_url.clone(),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    let recent = meta
        .published_at
        .is_some_and(|published| now - published <= HISTORY_WINDOW_DAYS * date::SECONDS_PER_DAY);

    if recent && meta.release.history_known && !meta.install_scripts.is_empty() {
        let previous: std::collections::BTreeMap<&str, &str> = meta
            .release
            .previous_install_scripts
            .iter()
            .map(|script| (script.name.as_str(), script.command.as_str()))
            .collect();
        let changed: Vec<&InstallScript> = meta
            .install_scripts
            .iter()
            .filter(|script| {
                previous
                    .get(script.name.as_str())
                    .is_none_or(|command| *command != script.command)
            })
            .collect();
        if !changed.is_empty() {
            let risky = changed
                .iter()
                .any(|script| risky_install_command(&script.command));
            findings.push(Finding {
                id: "install-scripts-changed",
                severity: if risky {
                    Severity::High
                } else {
                    Severity::Warn
                },
                title: "this version added or changed an install script".to_string(),
                detail: changed
                    .iter()
                    .map(|script| {
                        format!(
                            "{}: {}",
                            script.name,
                            script.command.chars().take(160).collect::<String>()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; "),
                allowed: false,
                evidence: vec![Evidence {
                    label: "version metadata".to_string(),
                    value: meta.registry_url.clone(),
                    url: Some(meta.registry_url.clone()),
                }],
            });
        }
    }

    if recent && profile.dependencies && meta.release.history_known {
        let added: Vec<&String> = meta
            .release
            .dependencies
            .iter()
            .filter(|dependency| !meta.release.previous_dependencies.contains(dependency))
            .collect();
        if !added.is_empty() {
            // Four-letter names sit within one edit of half of a 500-name
            // seed (`unty`/`funty`), so an accusation needs a longer name.
            let lookalike = added
                .iter()
                .filter(|dependency| dependency.chars().count() >= MIN_ACCUSABLE_NAME)
                .any(|dependency| {
                    suspect_for(
                        &PackageMeta {
                            name: (*dependency).clone(),
                            ..meta.clone()
                        },
                        ecosystem,
                        local,
                        profile,
                    )
                    .is_some()
                });
            findings.push(Finding {
                id: "dependency-added",
                severity: if lookalike {
                    Severity::Warn
                } else {
                    Severity::Info
                },
                title: "this version added dependencies".to_string(),
                detail: format!(
                    "not present in {}: {}",
                    meta.release
                        .previous_version
                        .as_deref()
                        .unwrap_or("the previous release"),
                    added
                        .iter()
                        .take(5)
                        .map(|dependency| dependency.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                allowed: false,
                evidence: vec![Evidence {
                    label: "version metadata".to_string(),
                    value: meta.registry_url.clone(),
                    url: Some(meta.registry_url.clone()),
                }],
            });
        }
    }

    if let (Some(published), Some(previous)) =
        (meta.published_at, meta.release.previous_published_at)
        && now - published <= HISTORY_WINDOW_DAYS * date::SECONDS_PER_DAY
        && published - previous >= DORMANCY_DAYS * date::SECONDS_PER_DAY
    {
        findings.push(Finding {
            id: "release-after-dormancy",
            // Alone this is a hint, not a verdict: normal maintenance produces
            // year-long gaps. The actionable transition signals stay WARN.
            severity: Severity::Info,
            title: "a dormant package published this version".to_string(),
            detail: format!(
                "nothing was published between {} and {}, then this version appeared",
                date::format_date(previous),
                date::format_date(published)
            ),
            allowed: false,
            evidence: vec![Evidence {
                label: "version publish time".to_string(),
                value: meta.registry_url.clone(),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

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
            detail: match &meta.release.previous_publisher {
                Some(previous) => format!(
                    "this version was published by '{publisher}', who is not in the current maintainer list [{}]; the previous release was published by '{previous}'",
                    meta.maintainers.join(", ")
                ),
                None => format!(
                    "this version was published by '{publisher}', who is not in the current maintainer list [{}]",
                    meta.maintainers.join(", ")
                ),
            },
            allowed: false,
            evidence: vec![Evidence {
                label: "maintainers".to_string(),
                value: meta.maintainers.join(", "),
                url: Some(meta.registry_url.clone()),
            }],
        });
    }

    // A different existing maintainer shipping a version is normal rotation,
    // not a handoff; only say so when the account is already trusted.
    let listed = |name: &str| {
        !meta.maintainers.is_empty()
            && meta
                .maintainers
                .iter()
                .any(|maintainer| maintainer.eq_ignore_ascii_case(name))
    };
    if profile.maintainers
        && !publisher_mismatch
        && let (Some(publisher), Some(previous)) =
            (&meta.publisher, &meta.release.previous_publisher)
        && listed(publisher)
        && listed(previous)
        && !is_automation_publisher(publisher)
        && !publisher.eq_ignore_ascii_case(previous)
    {
        let published_before = meta
            .release
            .publishers
            .iter()
            .any(|known| known.eq_ignore_ascii_case(publisher));
        findings.push(Finding {
            id: "publisher-changed",
            severity: Severity::Info,
            title: "a different maintainer published this version".to_string(),
            detail: if !meta.release.publishers.is_empty() && !published_before {
                format!(
                    "this version was published by '{publisher}', who has not published this package before; the previous release was published by '{previous}'"
                )
            } else if let Some(last) = meta.release.publisher_last_at {
                format!(
                    "this version was published by '{publisher}', who last published this package on {}; the previous release was published by '{previous}'",
                    date::format_date(last)
                )
            } else {
                format!(
                    "the previous release was published by '{previous}'; this one by '{publisher}', who is on the maintainer list"
                )
            },
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
mod tests;
