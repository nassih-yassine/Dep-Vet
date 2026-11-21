//! Rendering: a human report for the terminal and a stable JSON shape for CI.

use owo_colors::OwoColorize;
use serde::Serialize;

use crate::model::{PackageReport, Severity};
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
    use crate::model::{Evidence, Finding, InstallScript};

    fn report(findings: Vec<Finding>) -> PackageReport {
        PackageReport {
            ecosystem: "npm",
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
}
