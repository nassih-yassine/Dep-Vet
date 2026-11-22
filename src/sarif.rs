//! SARIF 2.1.0 output for `audit`, so GitHub Code Scanning and other SARIF
//! consumers can ingest dep-vet findings without a second format of truth.
//!
//! One result per finding. The rule id, severity, and evidence URL come from
//! the same `Finding` the human and JSON reports use; nothing is re-derived.

use serde_json::{Value, json};

use crate::model::{AuditReport, Severity};

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const INFORMATION_URI: &str = "https://github.com/nassih-yassine/Dep-Vet";

/// SARIF level for a finding severity. Allowed findings arrive as `Info`, so
/// they become notes rather than errors.
fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Warn => "warning",
        Severity::Info => "note",
    }
}

fn kind(severity: Severity) -> &'static str {
    match severity {
        Severity::High | Severity::Warn => "fail",
        Severity::Info => "informational",
    }
}

/// The lockfile path as a SARIF artifact URI. GitHub expects forward slashes
/// and a repository-relative path when the caller supplied one.
fn artifact_uri(lockfile: &str) -> String {
    let path = std::path::Path::new(lockfile);
    let displayed = std::env::current_dir()
        .ok()
        .and_then(|cwd| {
            path.strip_prefix(cwd)
                .ok()
                .map(std::path::Path::to_path_buf)
        })
        .unwrap_or_else(|| path.to_path_buf());
    displayed.to_string_lossy().replace('\\', "/")
}

pub fn render(report: &AuditReport) -> Result<String, serde_json::Error> {
    let mut rules: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    let mut results = Vec::new();
    let uri = artifact_uri(&report.lockfile);

    for package in &report.packages {
        for finding in &package.findings {
            rules.entry(finding.id.to_string()).or_insert_with(|| {
                let mut rule = json!({
                    "id": finding.id,
                    "name": finding.id,
                    "shortDescription": { "text": finding.title },
                });
                if let Some(url) = finding
                    .evidence
                    .iter()
                    .find_map(|evidence| evidence.url.as_deref())
                {
                    rule["helpUri"] = json!(url);
                }
                rule
            });

            let mut message = format!(
                "{}@{}: {} — {}",
                package.name, package.version, finding.title, finding.detail
            );
            for evidence in &finding.evidence {
                message.push_str(&format!("\n{}: {}", evidence.label, evidence.value));
            }
            if finding.allowed {
                message.push_str("\nAllowed by .depvet.toml.");
            }

            let mut properties = json!({
                "ecosystem": package.ecosystem.to_string(),
                "package": package.name,
                "version": package.version,
                "confidence": finding.confidence(),
                "allowed": finding.allowed,
            });
            if !package.dependency_paths.is_empty() {
                properties["dependency_paths"] = json!(package.dependency_paths);
            }

            let result = json!({
                "ruleId": finding.id,
                "level": level(finding.severity),
                "kind": kind(finding.severity),
                "message": { "text": message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri }
                    }
                }],
                "partialFingerprints": {
                    "depVetFinding/v1": format!(
                        "{}:{}@{}",
                        finding.id, package.name, package.version
                    )
                },
                "properties": properties,
            });
            results.push(result);
        }
    }

    let mut driver = json!({
        "name": "dep-vet",
        "version": env!("CARGO_PKG_VERSION"),
        "informationUri": INFORMATION_URI,
    });
    if !rules.is_empty() {
        driver["rules"] = Value::Array(rules.into_values().collect());
    }

    let mut invocation = json!({
        "executionSuccessful": report.errors.is_empty(),
        "exitCode": report.exit_code(),
    });
    if !report.errors.is_empty() {
        invocation["toolExecutionNotifications"] = Value::Array(
            report
                .errors
                .iter()
                .map(|error| {
                    json!({
                        "level": "error",
                        "message": { "text": format!("{}: {}", error.package, error.message) },
                    })
                })
                .collect(),
        );
    }

    let document = json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": driver },
            "invocations": [invocation],
            "results": results,
        }],
    });
    serde_json::to_string_pretty(&document)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_map_to_sarif_vocabulary() {
        assert_eq!(level(Severity::High), "error");
        assert_eq!(level(Severity::Warn), "warning");
        assert_eq!(level(Severity::Info), "note");
        assert_eq!(kind(Severity::High), "fail");
        assert_eq!(kind(Severity::Info), "informational");
    }

    #[test]
    fn artifact_uris_use_forward_slashes() {
        assert_eq!(
            artifact_uri("sub\\package-lock.json"),
            "sub/package-lock.json"
        );
    }
}
