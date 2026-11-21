//! Rendering: a human report for the terminal and a stable JSON shape for CI.

use owo_colors::OwoColorize;
use serde::Serialize;

use crate::model::{LockReport, PackageReport, Severity};
use crate::registry::package_page_url;

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
        return out;
    }

    out.push_str(&format!(
        "  {} finding{}\n\n",
        report.findings.len(),
        if report.findings.len() == 1 { "" } else { "s" },
    ));

    for finding in &report.findings {
        out.push_str(&format!(
            "  {}  {}\n",
            paint(
                &format!("[{}]", finding.severity.label()),
                verdict_color(finding.severity),
                color
            ),
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

    out.push_str(&format!(
        "  review: {}\n",
        package_page_url(&report.name, &report.version)
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
    let mut out = format!("{} vs {}\n\n", report.lockfile, report.base);

    if report.new_packages.is_empty() {
        out.push_str("  no new packages\n");
    } else {
        out.push_str(&format!(
            "  {} new package{}\n\n",
            report.new_packages.len(),
            if report.new_packages.len() == 1 {
                ""
            } else {
                "s"
            }
        ));
        for package in &report.new_packages {
            let severity = package.verdict();
            out.push_str(&format!(
                "  {:<44} {}\n",
                format!("{}@{}", package.name, package.version),
                paint(severity.label(), verdict_color(severity), color)
            ));
        }
        for package in report
            .new_packages
            .iter()
            .filter(|package| package.verdict() > Severity::Info)
        {
            out.push('\n');
            out.push_str(&render_human(package, color));
        }
    }

    if !report.errors.is_empty() {
        out.push_str(&format!(
            "\n  could not check {} package{}:\n",
            report.errors.len(),
            if report.errors.len() == 1 { "" } else { "s" }
        ));
        for error in &report.errors {
            out.push_str(&format!("    {}: {}\n", error.package, error.message));
        }
        out.push_str("  this report is incomplete\n");
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
            advisories: Vec::new(),
            hidden_advisories: 0,
            not_checked: Vec::new(),
            registry_url: "https://registry.npmjs.org/evil-pkg".to_string(),
            findings,
        }
    }

    fn finding(severity: Severity) -> Finding {
        Finding {
            id: "install-scripts",
            severity,
            title: "runs code during npm install".to_string(),
            detail: "install-time scripts are legitimate for native builds, but they are also how malicious packages run code".to_string(),
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
        }
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
