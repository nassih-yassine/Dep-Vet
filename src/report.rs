//! Rendering: a human report for the terminal and a stable JSON shape for CI.

use owo_colors::OwoColorize;
use serde::Serialize;

use crate::model::{
    AuditReport, Finding, LockFetchError, LockReport, PackageReport, Severity, Upgrade,
};
use crate::version::leading_number;

/// Findings carry a rule-level confidence next to their severity. It is added
/// at the serialization boundary so rule structs stay unchanged.
pub fn serialize_findings<S>(findings: &[Finding], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    #[derive(Serialize)]
    struct WithConfidence<'a> {
        #[serde(flatten)]
        finding: &'a Finding,
        confidence: crate::model::Confidence,
    }

    let mut sequence = serializer.serialize_seq(Some(findings.len()))?;
    for finding in findings {
        sequence.serialize_element(&WithConfidence {
            finding,
            confidence: finding.confidence(),
        })?;
    }
    sequence.end()
}

pub fn render_json(report: &PackageReport) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct JsonReport<'a> {
        #[serde(flatten)]
        package: &'a PackageReport,
        verdict: Severity,
        exit_code: u8,
    }

    serde_json::to_string_pretty(&JsonReport {
        package: report,
        verdict: report.verdict(),
        exit_code: report.exit_code(),
    })
}

pub fn render_human(report: &PackageReport, color: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}/{}{}\n\n",
        report.ecosystem,
        report.name,
        if report.version.is_empty() {
            String::new()
        } else {
            format!("@{}", report.version)
        }
    ));

    let verdict = report.verdict();
    push_field(
        &mut out,
        "verdict",
        &format!(
            "{} (exit {})",
            paint(verdict.label(), verdict_color(verdict), color),
            report.exit_code()
        ),
    );
    if let Some(date) = report.first_published_date() {
        push_field(&mut out, "first seen", &date);
    }
    if let Some(date) = report.published_date() {
        push_field(&mut out, "published", &date);
    }
    if let Some(downloads) = report.weekly_downloads {
        push_field(
            &mut out,
            "downloads",
            &format!("{}/week", thousands(downloads)),
        );
    }
    if !report.maintainers.is_empty() {
        push_field(&mut out, "maintainers", &report.maintainers.join(", "));
    }
    if let Some(repository) = &report.repository {
        push_field(&mut out, "repository", repository);
    }
    if !report.not_checked.is_empty() {
        push_field(&mut out, "not checked", &report.not_checked.join(", "));
    }
    match report.provenance {
        crate::model::Provenance::Present => {
            let label = match report.attestation_subject_matches {
                Some(true) => {
                    "attestation present, subject matches this tarball (signature not verified)"
                }
                Some(false) => "attestation present but names a different artifact",
                None => "attestation present (not verified)",
            };
            push_field(&mut out, "provenance", label);
        }
        crate::model::Provenance::Missing => {
            push_field(&mut out, "provenance", "not published");
        }
        crate::model::Provenance::Unavailable => {}
    }
    if let Some(attestation) = &report.attestation {
        if let Some(repository) = &attestation.source_repository {
            push_field(&mut out, "attested src", &format!("{repository} (claimed)"));
        }
        if let Some(builder) = &attestation.builder {
            push_field(&mut out, "builder", &format!("{builder} (claimed)"));
        }
        if let Some(commit) = &attestation.source_commit {
            let short: String = commit.chars().take(12).collect();
            push_field(&mut out, "commit", &format!("{short} (claimed)"));
        }
    }
    if let Some(publisher) = &report.publisher {
        let is_maintainer = report
            .maintainers
            .iter()
            .any(|maintainer| maintainer.eq_ignore_ascii_case(publisher));
        if !is_maintainer {
            push_field(&mut out, "published by", publisher);
        }
    }

    out.push('\n');
    if report.findings.is_empty() {
        out.push_str("  no findings: nothing in the registry metadata stands out\n");
    } else {
        out.push_str(&format!(
            "  {} finding{}\n\n",
            report.findings.len(),
            if report.findings.len() == 1 { "" } else { "s" }
        ));

        for finding in &report.findings {
            let label = if finding.allowed {
                "[ALLOWED]".to_string()
            } else {
                format!("[{}]", finding.severity.label())
            };
            let label_color = if finding.allowed {
                verdict_color(Severity::Info)
            } else {
                verdict_color(finding.severity)
            };
            out.push_str(&format!(
                "  {}  {}\n",
                paint(&label, label_color, color),
                finding.title
            ));
            for line in wrap(&finding.detail, 92) {
                out.push_str(&format!("        {line}\n"));
            }
            for evidence in &finding.evidence {
                out.push_str(&format!(
                    "        {}: {}\n",
                    evidence.label,
                    truncate(&evidence.value, 140)
                ));
                if let Some(url) = &evidence.url {
                    out.push_str(&format!("        -> {url}\n"));
                }
            }
            out.push('\n');
        }
    }

    if !report.upgrades.is_empty() {
        out.push_str(&render_advice(&report.upgrades, &report.version));
    }

    out.push_str(&format!(
        "  review: {}\n",
        report
            .review_url
            .clone()
            .unwrap_or_else(|| report.ecosystem.package_url(&report.name, &report.version))
    ));
    out
}

/// The `fixes` block of a single-package report. A replacement hides version
/// advice: a newer copy of a lookalike is not the fix.
fn render_advice(upgrades: &[Upgrade], version: &str) -> String {
    let mut out = String::from("  fixes\n");
    let current = leading_number(version);

    for upgrade in upgrades {
        if let Some(replacement) = &upgrade.replace_with {
            out.push_str(&format!("    use {replacement} instead\n"));
            continue;
        }

        if !upgrade.fixed.is_empty() {
            let shown: Vec<&str> = upgrade.fixed.iter().take(3).map(String::as_str).collect();
            let extra = upgrade.fixed.len().saturating_sub(shown.len());
            let mut line = format!("fixed in {}", shown.join(", "));
            if extra > 0 {
                line.push_str(&format!(" (+{extra} more)"));
            }
            if !upgrade.fixes.is_empty() {
                let shown: Vec<&str> = upgrade.fixes.iter().take(3).map(String::as_str).collect();
                let extra = upgrade.fixes.len().saturating_sub(shown.len());
                line.push_str(&format!("   fixes {}", shown.join(", ")));
                if extra > 0 {
                    line.push_str(&format!(" (+{extra})"));
                }
            }
            if leading_number(&upgrade.fixed[0]) != current {
                line.push_str("   (major jump, may break)");
            }
            out.push_str(&format!("    {line}\n"));
        } else if !upgrade.fix_unknown {
            out.push_str("    no fixed version published\n");
        }
        if upgrade.fix_unknown {
            out.push_str("    fix unknown (advisory details unavailable)\n");
        }

        if let Some(newest) = &upgrade.newest {
            let jump = leading_number(newest) != current;
            let suffix = if jump { "   major jump, may break" } else { "" };
            out.push_str(&format!("    newest {newest}{suffix}\n"));
        }
    }
    out.push('\n');
    out
}

pub fn render_inspection_json(
    report: &crate::inspect::InspectionReport,
) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Json<'a> {
        #[serde(flatten)]
        report: &'a crate::inspect::InspectionReport,
        verdict: Severity,
        exit_code: u8,
    }

    serde_json::to_string_pretty(&Json {
        report,
        verdict: report.verdict(),
        exit_code: report.exit_code(),
    })
}

pub fn render_inspection_human(report: &crate::inspect::InspectionReport, color: bool) -> String {
    let mut out = format!(
        "inspection: {}/{}@{}\n\n",
        report.ecosystem, report.name, report.version
    );
    push_field(
        &mut out,
        "archive",
        &format!(
            "{} {}, {} bytes",
            report.archive_kind,
            report.integrity,
            thousands(report.bytes as u64)
        ),
    );
    push_field(
        &mut out,
        "files",
        &format!(
            "{} scanned, {} skipped",
            report.files_scanned, report.files_skipped
        ),
    );
    if !report.not_checked.is_empty() {
        push_field(&mut out, "not checked", &report.not_checked.join(", "));
    }

    out.push('\n');
    if report.findings.is_empty() {
        out.push_str("  no findings: no rule matched the files in this archive\n");
    } else {
        out.push_str(&format!(
            "  {} finding{}\n\n",
            report.findings.len(),
            if report.findings.len() == 1 { "" } else { "s" }
        ));
        for finding in &report.findings {
            out.push_str(&format!(
                "  {}  {} {}\n",
                paint(
                    &format!("[{}]", finding.severity.label()),
                    verdict_color(finding.severity),
                    color
                ),
                finding.rule,
                finding.title
            ));
            if !finding.file.is_empty() {
                out.push_str(&format!("        {}:{}\n", finding.file, finding.line));
            }
            for line in wrap(&finding.evidence, 88) {
                out.push_str(&format!("        {line}\n"));
            }
            out.push_str(&format!("        {}\n", finding.recommendation));
            if let Some(reference) = finding.references.first() {
                out.push_str(&format!("        -> {reference}\n"));
            }
            out.push('\n');
        }
    }
    out.push_str(&format!(
        "  verdict {} (exit {})\n",
        paint(
            report.verdict().label(),
            verdict_color(report.verdict()),
            color
        ),
        report.exit_code()
    ));
    out
}

pub fn render_diff_json(report: &crate::inspect::DiffReport) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Json<'a> {
        #[serde(flatten)]
        report: &'a crate::inspect::DiffReport,
        verdict: Severity,
        exit_code: u8,
    }

    serde_json::to_string_pretty(&Json {
        report,
        verdict: report.verdict(),
        exit_code: report.exit_code(),
    })
}

pub fn render_diff_human(report: &crate::inspect::DiffReport, color: bool) -> String {
    let mut out = format!(
        "diff: {}/{} {} -> {}\n\n",
        report.ecosystem, report.name, report.from_version, report.to_version
    );
    push_field(
        &mut out,
        "integrity",
        &format!("{} -> {}", report.from_integrity, report.to_integrity),
    );
    push_field(
        &mut out,
        "files",
        &format!(
            "{} added, {} removed, {} modified, {} unchanged",
            report.added.len(),
            report.removed.len(),
            report.modified.len(),
            report.unchanged
        ),
    );
    for (label, files) in [
        ("added", &report.added),
        ("removed", &report.removed),
        ("modified", &report.modified),
    ] {
        if files.is_empty() {
            continue;
        }
        let shown = files.iter().take(8).cloned().collect::<Vec<_>>().join(", ");
        let extra = files.len().saturating_sub(8);
        push_field(
            &mut out,
            label,
            &if extra > 0 {
                format!("{shown} (+{extra} more)")
            } else {
                shown
            },
        );
    }
    if !report.not_checked.is_empty() {
        push_field(&mut out, "not checked", &report.not_checked.join(", "));
    }

    out.push('\n');
    if report.findings.is_empty() {
        out.push_str("  no new findings in this release\n");
    } else {
        out.push_str(&format!(
            "  {} new finding{}\n\n",
            report.findings.len(),
            if report.findings.len() == 1 { "" } else { "s" }
        ));
        for finding in &report.findings {
            out.push_str(&format!(
                "  {}  {} {}\n",
                paint(
                    &format!("[{}]", finding.severity.label()),
                    verdict_color(finding.severity),
                    color
                ),
                finding.rule,
                finding.title
            ));
            if !finding.file.is_empty() {
                out.push_str(&format!("        {}:{}\n", finding.file, finding.line));
            }
            for line in wrap(&finding.evidence, 88) {
                out.push_str(&format!("        {line}\n"));
            }
            if let Some(reference) = finding.references.first() {
                out.push_str(&format!("        -> {reference}\n"));
            }
            out.push('\n');
        }
    }
    if !report.resolved.is_empty() {
        out.push_str(&format!(
            "  {} finding{} gone since {}\n",
            report.resolved.len(),
            if report.resolved.len() == 1 { "" } else { "s" },
            report.from_version
        ));
    }
    out.push_str(&format!(
        "\n  verdict {} (exit {})\n",
        paint(
            report.verdict().label(),
            verdict_color(report.verdict()),
            color
        ),
        report.exit_code()
    ));
    out
}

pub fn render_lock_json(report: &LockReport) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Json<'a> {
        #[serde(flatten)]
        report: &'a LockReport,
        verdict: Severity,
        exit_code: u8,
    }

    serde_json::to_string_pretty(&Json {
        report,
        verdict: report.verdict(),
        exit_code: report.exit_code(),
    })
}

pub fn render_lock_human(report: &LockReport, color: bool) -> String {
    render_tree(TreeView {
        header: format!("{} vs {}", report.lockfile, report.base),
        empty: "no new packages".to_string(),
        noun: "new package",
        plural: "new packages",
        packages: &report.new_packages,
        errors: &report.errors,
        notes: &report.notes,
        verdict: report.verdict(),
        exit_code: report.exit_code(),
        color,
    })
}

pub fn render_audit_json(report: &AuditReport) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Json<'a> {
        #[serde(flatten)]
        report: &'a AuditReport,
        verdict: Severity,
        exit_code: u8,
    }

    serde_json::to_string_pretty(&Json {
        report,
        verdict: report.verdict(),
        exit_code: report.exit_code(),
    })
}

pub fn render_audit_human(report: &AuditReport, color: bool) -> String {
    render_tree(TreeView {
        header: format!("{} (every installed package)", report.lockfile),
        empty: "lockfile has no packages".to_string(),
        noun: "package audited",
        plural: "packages audited",
        packages: &report.packages,
        errors: &report.errors,
        notes: &report.notes,
        verdict: report.verdict(),
        exit_code: report.exit_code(),
        color,
    })
}

struct TreeView<'a> {
    header: String,
    empty: String,
    noun: &'static str,
    plural: &'static str,
    packages: &'a [PackageReport],
    errors: &'a [LockFetchError],
    notes: &'a [String],
    verdict: Severity,
    exit_code: u8,
    color: bool,
}

/// One actionable block for a whole tree, worst verdict first. Clean packages
/// are absent, so this never reads as an "out of date" list.
fn render_tree_advice(packages: &[PackageReport]) -> Option<String> {
    let mut advised: Vec<&PackageReport> = packages
        .iter()
        .filter(|package| !package.upgrades.is_empty())
        .collect();
    if advised.is_empty() {
        return None;
    }
    advised.sort_by(|left, right| {
        right
            .verdict()
            .cmp(&left.verdict())
            .then_with(|| left.name.cmp(&right.name))
    });

    let mut out = String::from("\n  what to do\n\n");
    for package in advised {
        for upgrade in &package.upgrades {
            let subject = format!("{} {}", package.name, package.version);
            let action = if let Some(replacement) = &upgrade.replace_with {
                format!("→ {replacement}")
            } else if let Some(fixed) = upgrade.fixed.first() {
                let mut line = format!("→ {fixed}");
                if !upgrade.fixes.is_empty() {
                    let shown: Vec<&str> =
                        upgrade.fixes.iter().take(3).map(String::as_str).collect();
                    let extra = upgrade.fixes.len().saturating_sub(shown.len());
                    line.push_str(&format!("   fixes {}", shown.join(", ")));
                    if extra > 0 {
                        line.push_str(&format!(" (+{extra})"));
                    }
                }
                if leading_number(fixed) != leading_number(&package.version) {
                    line.push_str("   (major jump, may break)");
                }
                line
            } else if upgrade.fix_unknown {
                "→ fix unknown".to_string()
            } else if let Some(newest) = &upgrade.newest {
                format!("no fixed version published; newest {newest}")
            } else {
                "no fixed version published".to_string()
            };
            out.push_str(&format!("    {subject:<40} {action}\n"));
        }
    }
    Some(out)
}

fn render_tree(view: TreeView<'_>) -> String {
    let mut out = format!("{}\n\n", view.header);

    if view.packages.is_empty() {
        out.push_str(&format!("  {}\n", view.empty));
    } else {
        out.push_str(&format!(
            "  {} {}\n\n",
            view.packages.len(),
            if view.packages.len() == 1 {
                view.noun
            } else {
                view.plural
            }
        ));
        for package in view.packages {
            let severity = package.verdict();
            out.push_str(&format!(
                "  {:<44} {}\n",
                format!("{}@{}", package.name, package.version),
                paint(severity.label(), verdict_color(severity), view.color)
            ));
        }
        for package in view.packages.iter().filter(|package| {
            package.verdict() > Severity::Info
                || package.findings.iter().any(|finding| finding.allowed)
        }) {
            out.push('\n');
            out.push_str(&render_human(package, view.color));
        }
    }

    if !view.notes.is_empty() {
        out.push_str("\n  notes:\n");
        for note in view.notes {
            out.push_str(&format!("    {note}\n"));
        }
    }

    if !view.errors.is_empty() {
        out.push_str(&format!(
            "\n  could not check {} package{}:\n",
            view.errors.len(),
            if view.errors.len() == 1 { "" } else { "s" }
        ));
        for error in view.errors {
            out.push_str(&format!("    {}: {}\n", error.package, error.message));
        }
        out.push_str("  this report is incomplete\n");
    }

    if let Some(block) = render_tree_advice(view.packages) {
        out.push_str(&block);
    }

    out.push_str(&format!(
        "\n  verdict {} (exit {})\n",
        paint(
            view.verdict.label(),
            verdict_color(view.verdict),
            view.color
        ),
        view.exit_code
    ));
    out
}

fn push_field(out: &mut String, label: &str, value: &str) {
    out.push_str(&format!("  {label:<12} {value}\n"));
}

fn paint(text: &str, color: fn(&str) -> String, enabled: bool) -> String {
    if enabled {
        color(text)
    } else {
        text.to_string()
    }
}

fn verdict_color(severity: Severity) -> fn(&str) -> String {
    match severity {
        Severity::High => |text: &str| text.red().bold().to_string(),
        Severity::Warn => |text: &str| text.yellow().bold().to_string(),
        Severity::Info => |text: &str| text.cyan().to_string(),
    }
}

fn truncate(value: &str, limit: usize) -> String {
    let single_line = value.replace(['\n', '\r'], " ");
    if single_line.chars().count() <= limit {
        return single_line;
    }
    let mut truncated: String = single_line.chars().take(limit.saturating_sub(1)).collect();
    truncated.push('…');
    truncated
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.chars().count() + 1 + word.chars().count() > width {
            lines.push(current);
            current = String::new();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Ecosystem, Evidence, Finding, InstallScript};

    fn report(findings: Vec<Finding>) -> PackageReport {
        PackageReport {
            ecosystem: Ecosystem::Npm,
            name: "evil-pkg".to_string(),
            version: "1.0.0".to_string(),
            first_published_at: Some(1_704_067_200),
            published_at: Some(1_767_225_600),
            weekly_downloads: Some(1234),
            maintainers: vec!["alice".to_string(), "bob".to_string()],
            publisher: Some("mallory".to_string()),
            install_scripts: vec![InstallScript {
                name: "postinstall".to_string(),
                command: "node setup.js".to_string(),
            }],
            repository: Some("https://github.com/alice/evil-pkg".to_string()),
            deprecated: None,
            provenance: crate::model::Provenance::Unavailable,
            attestation_subject_matches: None,
            attestation: None,
            advisories: Vec::new(),
            hidden_advisories: 0,
            not_checked: Vec::new(),
            registry_url: "https://registry.npmjs.org/evil-pkg".to_string(),
            review_url: None,
            upgrades: Vec::new(),
            findings,
        }
    }

    fn finding(severity: Severity) -> Finding {
        Finding {
            id: "install-scripts",
            severity,
            title: "runs code during npm install".to_string(),
            detail: "install-time scripts are legitimate for native builds, but they are also how malicious packages run code".to_string(),
            allowed: false,
            evidence: vec![Evidence {
                label: "postinstall".to_string(),
                value: "node setup.js".to_string(),
                url: Some("https://registry.npmjs.org/evil-pkg".to_string()),
            }],
        }
    }

    #[test]
    fn human_report_includes_verdict_findings_and_links() {
        let text = render_human(&report(vec![finding(Severity::High)]), false);
        assert!(text.contains("npm/evil-pkg@1.0.0"));
        assert!(text.contains("HIGH (exit 2)"));
        assert!(text.contains("[HIGH]  runs code during npm install"));
        assert!(text.contains("postinstall: node setup.js"));
        assert!(text.contains("-> https://registry.npmjs.org/evil-pkg"));
        assert!(text.contains("1,234/week"));
        assert!(text.contains("https://www.npmjs.com/package/evil-pkg/v/1.0.0"));
    }

    fn report_with_upgrades(upgrades: Vec<crate::model::Upgrade>, version: &str) -> PackageReport {
        let mut report = report(Vec::new());
        report.version = version.to_string();
        report.upgrades = upgrades;
        report
    }

    fn upgrade(fixed: &[&str], newest: Option<&str>) -> crate::model::Upgrade {
        crate::model::Upgrade {
            fixed: fixed.iter().map(|value| value.to_string()).collect(),
            fix_unknown: false,
            newest: newest.map(str::to_string),
            fixes: vec!["GHSA-a".to_string()],
            replace_with: None,
        }
    }

    #[test]
    fn advice_shows_the_fixed_version_and_newest_hint() {
        let report =
            report_with_upgrades(vec![upgrade(&["2.0.1", "1.2.3"], Some("3.0.0"))], "2.1.0");
        let out = render_human(&report, false);
        assert!(out.contains("fixed in 2.0.1, 1.2.3"), "{out}");
        assert!(out.contains("newest 3.0.0"), "{out}");
        assert!(out.contains("major jump, may break"), "{out}");
    }

    #[test]
    fn unknown_fix_is_not_worded_as_no_fix() {
        let mut item = upgrade(&[], None);
        item.fix_unknown = true;
        item.fixes = vec!["GHSA-x".to_string()];
        let report = report_with_upgrades(vec![item], "1.0.0");
        let out = render_human(&report, false);
        assert!(out.contains("fix unknown"), "{out}");
        assert!(!out.contains("no fixed version published"), "{out}");
    }

    #[test]
    fn a_mixed_unknown_advisory_is_printed_as_unknown() {
        let mut item = upgrade(&["2.0.1"], None);
        item.fix_unknown = true;
        item.fixes = vec!["GHSA-fixed".to_string()];
        let report = report_with_upgrades(vec![item], "2.0.0");
        let out = render_human(&report, false);
        assert!(out.contains("fixed in 2.0.1"), "{out}");
        assert!(out.contains("fix unknown"), "{out}");
        assert!(!out.contains("GHSA-unknown"), "{out}");
    }

    #[test]
    fn a_replacement_hides_version_advice() {
        let mut item = upgrade(&["2.0.1"], Some("3.0.0"));
        item.replace_with = Some("cross-env".to_string());
        let report = report_with_upgrades(vec![item], "1.0.0");
        let out = render_human(&report, false);
        assert!(out.contains("use cross-env instead"), "{out}");
        assert!(!out.contains("fixed in"), "{out}");
    }

    #[test]
    fn a_clean_report_has_no_advice_block() {
        let report = report_with_upgrades(Vec::new(), "1.0.0");
        let out = render_human(&report, false);
        assert!(!out.contains("  fixes"), "{out}");
    }

    #[test]
    fn long_fixed_lists_are_capped() {
        let report = report_with_upgrades(
            vec![upgrade(&["2.0.1", "2.0.2", "2.0.3", "2.0.4"], None)],
            "2.0.0",
        );
        let out = render_human(&report, false);
        assert!(
            out.contains("fixed in 2.0.1, 2.0.2, 2.0.3 (+1 more)"),
            "{out}"
        );
    }

    #[test]
    fn review_link_follows_the_ecosystem() {
        let mut pypi = report(vec![]);
        pypi.ecosystem = Ecosystem::Pypi;
        pypi.name = "flask".to_string();
        pypi.version = "3.1.0".to_string();
        assert!(render_human(&pypi, false).contains("https://pypi.org/project/flask/3.1.0/"));

        let mut crates = report(vec![]);
        crates.ecosystem = Ecosystem::CratesIo;
        crates.name = "serde".to_string();
        assert!(render_human(&crates, false).contains("https://crates.io/crates/serde/1.0.0"));

        let mut go = report(vec![]);
        go.ecosystem = Ecosystem::Go;
        go.name = "github.com/gin-gonic/gin".to_string();
        assert!(
            render_human(&go, false).contains("https://pkg.go.dev/github.com/gin-gonic/gin@1.0.0")
        );
    }

    #[test]
    fn human_report_says_so_when_clean() {
        let text = render_human(&report(vec![]), false);
        assert!(text.contains("INFO (exit 0)"));
        assert!(text.contains("no findings"));
    }

    #[test]
    fn color_is_opt_in_only() {
        let plain = render_human(&report(vec![finding(Severity::High)]), false);
        assert!(!plain.contains('\u{1b}'));
        let painted = render_human(&report(vec![finding(Severity::High)]), true);
        assert!(painted.contains('\u{1b}'));
    }

    #[test]
    fn long_detail_is_wrapped_and_never_infinite() {
        let mut finding = finding(Severity::Warn);
        finding.detail = "word ".repeat(200);
        let text = render_human(&report(vec![finding]), false);
        for line in text.lines().filter(|line| line.contains("word word")) {
            assert!(line.chars().count() <= 140);
        }
    }

    #[test]
    fn multiline_evidence_is_collapsed() {
        let mut finding = finding(Severity::Warn);
        finding.evidence[0].value = "line one\nline two".to_string();
        let text = render_human(&report(vec![finding]), false);
        assert!(text.contains("postinstall: line one line two"));
    }

    #[test]
    fn json_findings_carry_confidence_next_to_severity() {
        let json = render_json(&report(vec![finding(Severity::High)])).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["findings"][0]["severity"], "high");
        assert_eq!(value["findings"][0]["confidence"], "high");
        assert_eq!(value["findings"][0]["id"], "install-scripts");
    }

    #[test]
    fn clean_package_json_omits_empty_optional_blocks() {
        let json = render_json(&report(Vec::new())).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let object = value.as_object().unwrap();
        for key in ["upgrades", "review_url"] {
            assert!(!object.contains_key(key), "{key} should be omitted");
        }
        for key in [
            "ecosystem",
            "name",
            "version",
            "findings",
            "registry_url",
            "verdict",
            "exit_code",
        ] {
            assert!(object.contains_key(key), "{key} missing");
        }
    }

    #[test]
    fn json_has_verdict_and_exit_code_at_the_top_level() {
        let json = render_json(&report(vec![finding(Severity::Warn)])).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["name"], "evil-pkg");
        assert_eq!(value["verdict"], "warn");
        assert_eq!(value["exit_code"], 1);
        assert_eq!(value["findings"][0]["severity"], "warn");
        assert!(value["findings"][0]["evidence"][0]["url"].is_string());
    }

    #[test]
    fn human_report_lists_signals_that_were_not_checked() {
        let mut report = report(vec![]);
        report.not_checked = vec!["maintainers", "downloads"];
        let text = render_human(&report, false);
        assert!(text.contains("not checked"));
        assert!(text.contains("maintainers, downloads"));
    }

    #[test]
    fn json_carries_not_checked_only_when_something_is_missing() {
        let clean: serde_json::Value =
            serde_json::from_str(&render_json(&report(vec![])).unwrap()).unwrap();
        assert!(clean.get("not_checked").is_none());

        let mut partial = report(vec![]);
        partial.not_checked = vec!["maintainers"];
        let value: serde_json::Value =
            serde_json::from_str(&render_json(&partial).unwrap()).unwrap();
        assert_eq!(value["not_checked"][0], "maintainers");
    }

    #[test]
    fn json_is_stable_for_clean_packages() {
        let json = render_json(&report(vec![])).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["verdict"], "info");
        assert_eq!(value["exit_code"], 0);
        assert_eq!(value["findings"], serde_json::json!([]));
    }

    #[test]
    fn thousands_separator() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(1234567), "1,234,567");
    }

    fn lock_report() -> LockReport {
        LockReport {
            lockfile: "package-lock.json".to_string(),
            base: "main".to_string(),
            new_packages: Vec::new(),
            errors: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn audit_report() -> AuditReport {
        AuditReport {
            lockfile: "package-lock.json".to_string(),
            packages: Vec::new(),
            errors: Vec::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn audit_report_lists_every_package() {
        let mut audit = audit_report();
        let mut risky = report(vec![finding(Severity::High)]);
        risky.name = "evil-pkg".to_string();
        let clean = report(vec![]);
        audit.packages = vec![clean, risky];

        let text = render_audit_human(&audit, false);
        assert!(text.contains("every installed package"));
        assert!(text.contains("2 packages audited"));
        assert!(text.contains("evil-pkg@1.0.0"));
        assert!(text.contains("HIGH (exit 2)"));
    }

    #[test]
    fn audit_report_prints_notes_without_failing() {
        let mut audit = audit_report();
        audit.notes = vec!["1 JSR package(s) not audited".to_string()];
        let text = render_audit_human(&audit, false);
        assert!(text.contains("notes:"));
        assert!(text.contains("1 JSR package"));
        assert!(text.contains("INFO (exit 0)"));
    }

    #[test]
    fn audit_report_handles_an_empty_lockfile() {
        let text = render_audit_human(&audit_report(), false);
        assert!(text.contains("lockfile has no packages"));
        assert!(text.contains("INFO (exit 0)"));
    }

    #[test]
    fn audit_report_with_unchecked_packages_is_incomplete() {
        let mut audit = audit_report();
        audit.errors = vec![LockFetchError {
            package: "ghost@1.0.0".to_string(),
            message: "package 'ghost' was not found on npm".to_string(),
        }];
        let value: serde_json::Value =
            serde_json::from_str(&render_audit_json(&audit).unwrap()).unwrap();
        assert_eq!(value["errors"][0]["package"], "ghost@1.0.0");
        assert_eq!(value["exit_code"], 3);
        assert!(render_audit_human(&audit, false).contains("incomplete"));
    }

    #[test]
    fn the_tree_block_lists_worst_first_and_skips_clean_packages() {
        let mut lock = lock_report();
        let mut high = report(vec![finding(Severity::High)]);
        high.name = "log4j-core".to_string();
        high.version = "2.14.1".to_string();
        high.upgrades = vec![upgrade(&["2.17.1"], None)];
        let mut warn = report(vec![finding(Severity::Warn)]);
        warn.name = "crossenv".to_string();
        warn.version = "0.0.2-security".to_string();
        warn.upgrades = vec![crate::model::Upgrade {
            fixed: Vec::new(),
            fix_unknown: false,
            newest: None,
            fixes: Vec::new(),
            replace_with: Some("cross-env".to_string()),
        }];
        let clean = report(vec![]);
        lock.new_packages = vec![clean, warn, high];

        let text = render_lock_human(&lock, false);
        let block = text.find("what to do").expect("missing block");
        let high_at = text[block..].find("log4j-core").expect("high line");
        let warn_at = text[block..].find("crossenv").expect("warn line");
        assert!(high_at < warn_at, "{text}");
        assert!(text[block..].contains("2.17.1"), "{text}");
        assert!(text[block..].contains("cross-env"), "{text}");
        assert!(!text[block..].contains("evil-pkg"), "{text}");
    }

    #[test]
    fn a_tree_without_advice_has_no_block() {
        let mut lock = lock_report();
        lock.new_packages = vec![report(Vec::new())];
        let text = render_lock_human(&lock, false);
        assert!(!text.contains("what to do"), "{text}");
    }

    #[test]
    fn lock_report_with_no_changes_is_clean() {
        let text = render_lock_human(&lock_report(), false);
        assert!(text.contains("no new packages"));
        assert!(text.contains("INFO (exit 0)"));
    }

    #[test]
    fn lock_report_lists_new_packages_and_details_for_warnings() {
        let mut lock = lock_report();
        let mut risky = report(vec![finding(Severity::High)]);
        risky.name = "evil-pkg".to_string();
        let clean = report(vec![]);
        lock.new_packages = vec![clean, risky];

        let text = render_lock_human(&lock, false);
        assert!(text.contains("2 new packages"));
        assert!(text.contains("evil-pkg@1.0.0"));
        assert!(text.contains("[HIGH]  runs code during npm install"));
        assert!(text.contains("HIGH (exit 2)"));
    }

    #[test]
    fn a_lock_report_with_unchecked_packages_is_incomplete() {
        let mut lock = lock_report();
        lock.errors = vec![crate::model::LockFetchError {
            package: "ghost@1.0.0".to_string(),
            message: "package 'ghost' was not found on npm".to_string(),
        }];
        let text = render_lock_human(&lock, false);
        assert!(text.contains("could not check 1 package"));
        assert!(text.contains("ghost@1.0.0"));
        assert!(text.contains("incomplete"));
        assert!(text.contains("exit 3"));
    }

    #[test]
    fn lock_json_carries_verdict_and_errors() {
        let mut lock = lock_report();
        lock.new_packages = vec![self::report(vec![finding(Severity::Warn)])];
        lock.errors = vec![crate::model::LockFetchError {
            package: "ghost@1.0.0".to_string(),
            message: "not found".to_string(),
        }];
        let value: serde_json::Value =
            serde_json::from_str(&render_lock_json(&lock).unwrap()).unwrap();
        assert_eq!(value["base"], "main");
        assert_eq!(value["new_packages"][0]["name"], "evil-pkg");
        assert_eq!(value["errors"][0]["package"], "ghost@1.0.0");
        assert_eq!(value["verdict"], "warn");
        assert_eq!(value["exit_code"], 3);
    }
}
