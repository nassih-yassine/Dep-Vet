//! Reporting for `dep-vet guard`: a command, the intents parsed from it, and
//! the audits of the packages it would install.

use crate::intent::{Intent, ParseOutcome};
use crate::model::{PackageReport, Severity};

#[derive(Debug)]
pub struct GuardReport {
    pub command: String,
    pub parse: ParseOutcome,
    pub packages: Vec<PackageReport>,
    pub errors: Vec<String>,
}

impl GuardReport {
    pub fn verdict(&self) -> Severity {
        self.packages
            .iter()
            .flat_map(|package| package.findings.iter())
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    /// Any parsed install with no vetted package is "could not check".
    pub fn exit_code(&self) -> u8 {
        if self.packages.is_empty() {
            if self.parse.intents.is_empty() && self.parse.notes.is_empty() {
                0
            } else {
                3
            }
        } else if !self.errors.is_empty()
            && self
                .packages
                .iter()
                .all(|package| package.findings.is_empty() && package.advisories.is_empty())
        {
            // Every audit failed: not a clean result.
            3
        } else {
            self.verdict().exit_code()
        }
    }

    pub fn to_json(&self) -> String {
        let value = serde_json::json!({
            "command": self.command,
            "intents": self.parse.intents.iter().map(intent_json).collect::<Vec<_>>(),
            "packages": self
                .packages
                .iter()
                .map(package_json)
                .collect::<Vec<_>>(),
            "errors": self.errors,
            "notes": self.parse.notes,
            "verdict": self.verdict().label().to_ascii_lowercase(),
            "exit_code": self.exit_code(),
        });
        value.to_string()
    }

    pub fn to_human(&self) -> String {
        let mut out = format!("guard: {}", self.command);
        if self.parse.intents.is_empty() && self.parse.notes.is_empty() {
            out.push_str("\n\n  nothing to install\n");
            return out;
        }
        out.push('\n');
        for intent in &self.parse.intents {
            for spec in &intent.specs {
                out.push_str(&format!(
                    "  {}/{}@{}\n",
                    ecosystem_label(intent),
                    spec.name,
                    spec.version.as_deref().unwrap_or("latest")
                ));
            }
            if intent.specs.is_empty() {
                out.push_str(&format!(
                    "  {} install: not checked{}\n",
                    ecosystem_label(intent),
                    intent
                        .lockfile
                        .as_deref()
                        .map(|path| format!(" (lockfile {path})"))
                        .unwrap_or_default()
                ));
            }
        }
        for note in &self.parse.notes {
            out.push_str(&format!("  note: {note}\n"));
        }
        for error in &self.errors {
            out.push_str(&format!("  error: {error}\n"));
        }
        out.push('\n');
        for package in &self.packages {
            let verdict = package
                .findings
                .iter()
                .map(|finding| finding.severity)
                .max()
                .unwrap_or(Severity::Info);
            out.push_str(&format!(
                "  {} {}@{}: {}\n",
                ecosystem_label_for(&package.ecosystem),
                package.name,
                package.version,
                verdict.label().to_ascii_lowercase()
            ));
            for finding in &package.findings {
                out.push_str(&format!(
                    "    [{}] {} ({})\n",
                    finding.severity.label(),
                    finding.title,
                    finding.id
                ));
            }
            for advisory in &package.advisories {
                out.push_str(&format!(
                    "    [{}] advisory {}\n",
                    advisory.severity.label(),
                    advisory.id
                ));
            }
        }
        out.push_str(&format!(
            "\n  verdict {} (exit {})\n",
            self.verdict().label(),
            self.exit_code()
        ));
        if self.exit_code() == 3 {
            out.push_str(
                "  not checked: direct packages only; transitive dependencies and unparsed installs were not vetted\n",
            );
        }
        out
    }
}

fn ecosystem_label(intent: &Intent) -> &'static str {
    ecosystem_label_for(&intent.ecosystem)
}

fn ecosystem_label_for(ecosystem: &crate::model::Ecosystem) -> &'static str {
    use crate::model::Ecosystem;
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "pypi",
        Ecosystem::CratesIo => "crates",
        Ecosystem::Go => "go",
        Ecosystem::Jsr => "jsr",
        Ecosystem::RubyGems => "rubygems",
        Ecosystem::NuGet => "nuget",
        Ecosystem::Maven => "maven",
        Ecosystem::Composer => "composer",
    }
}

fn intent_json(intent: &Intent) -> serde_json::Value {
    serde_json::json!({
        "ecosystem": ecosystem_label(intent),
        "kind": match intent.kind {
            crate::intent::IntentKind::Install => "install",
            crate::intent::IntentKind::Ephemeral => "ephemeral",
            crate::intent::IntentKind::Lockfile => "lockfile",
        },
        "specs": intent.specs.iter().map(|spec| serde_json::json!({
            "name": spec.name,
            "version": spec.version,
        })).collect::<Vec<_>>(),
        "lockfile": intent.lockfile,
    })
}

fn package_json(package: &PackageReport) -> serde_json::Value {
    let findings: Vec<serde_json::Value> = package
        .findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "id": finding.id,
                "severity": finding.severity.label().to_ascii_lowercase(),
                "confidence": finding.confidence(),
                "title": finding.title,
                "evidence": finding.evidence.iter().map(|evidence| serde_json::json!({
                    "label": evidence.label,
                    "value": evidence.value,
                    "url": evidence.url,
                })).collect::<Vec<_>>(),
                "replace_with": finding
                    .id
                    .eq("typosquat")
                    .then(|| package.upgrades.iter().find_map(|upgrade| upgrade.replace_with.clone()))
                    .flatten(),
                "fixed": package
                    .upgrades
                    .iter()
                    .find_map(|upgrade| upgrade.fixed.first().cloned()),
            })
        })
        .collect();
    let advisories: Vec<serde_json::Value> = package
        .advisories
        .iter()
        .map(|advisory| {
            serde_json::json!({
                "id": advisory.id,
                "severity": advisory.severity.label().to_ascii_lowercase(),
                "summary": advisory.summary,
                "url": format!("https://osv.dev/vulnerability/{}", advisory.id),
            })
        })
        .collect();
    let verdict = package
        .findings
        .iter()
        .map(|finding| finding.severity)
        .chain(package.advisories.iter().map(|advisory| advisory.severity))
        .max()
        .unwrap_or(Severity::Info);
    serde_json::json!({
        "ecosystem": ecosystem_label_for(&package.ecosystem),
        "name": package.name,
        "version": package.version,
        "verdict": verdict.label().to_ascii_lowercase(),
        "exit_code": verdict.exit_code(),
        "findings": findings,
        "advisories": advisories,
        "not_checked": package.not_checked,
    })
}
