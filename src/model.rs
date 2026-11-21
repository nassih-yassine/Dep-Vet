//! Core types: the package spec the user typed, and the evidence-backed
//! report dep-vet prints back.

use serde::Serialize;

use crate::date;

/// A package reference: `express`, `express@5.1.0`, `@scope/name@beta`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSpec {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpecError {
    #[error("package name is empty")]
    Empty,
    #[error("package name is longer than 214 characters")]
    TooLong,
    #[error("package name contains characters npm does not allow: {0}")]
    InvalidName(String),
    #[error("version or tag contains characters dep-vet will not send to the registry: {0}")]
    InvalidVersion(String),
}

impl PackageSpec {
    pub fn parse(input: &str) -> Result<Self, SpecError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(SpecError::Empty);
        }
        if trimmed.len() > 214 {
            return Err(SpecError::TooLong);
        }

        let (name, version) = match trimmed.split_once('@') {
            // Scoped name: the first `@` belongs to the scope, not the version.
            Some(("", rest)) => match rest.find('@') {
                Some(index) => (&trimmed[..index + 1], Some(&trimmed[index + 2..])),
                None => (trimmed, None),
            },
            Some((name, version)) => (name, Some(version)),
            None => (trimmed, None),
        };

        validate_name(name)?;
        let version = match version {
            Some(version) => Some(validate_version(version)?),
            None => None,
        };

        Ok(Self {
            name: name.to_string(),
            version,
        })
    }
}

fn validate_name(name: &str) -> Result<(), SpecError> {
    if name.is_empty() {
        return Err(SpecError::Empty);
    }
    if name.len() > 214 {
        return Err(SpecError::TooLong);
    }
    if let Some(scoped) = name.strip_prefix('@') {
        let (scope, package) = scoped
            .split_once('/')
            .ok_or_else(|| SpecError::InvalidName(name.to_string()))?;
        if scope.is_empty() || package.is_empty() || package.contains('/') {
            return Err(SpecError::InvalidName(name.to_string()));
        }
        if matches!(package, "." | "..") {
            return Err(SpecError::InvalidName(name.to_string()));
        }
    } else if name.contains('/') {
        return Err(SpecError::InvalidName(name.to_string()));
    }

    let allowed =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-' | '@' | '/');
    if !name.chars().all(allowed) || name.starts_with('.') || name.ends_with('.') {
        return Err(SpecError::InvalidName(name.to_string()));
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<String, SpecError> {
    let trimmed = version.trim();
    let allowed =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-' | '+' | '^');
    if trimmed.is_empty() || !trimmed.chars().all(allowed) {
        return Err(SpecError::InvalidVersion(version.to_string()));
    }
    Ok(trimmed.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    High,
}

impl Severity {
    /// Exit codes follow the project brief: 0 clean, 1 warnings, 2 high-risk.
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Warn => 1,
            Self::High => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::High => "HIGH",
        }
    }
}

/// One check, with the raw evidence a reviewer can open.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub label: String,
    pub value: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallScript {
    pub name: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageReport {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
    /// Unix seconds; `None` when the registry did not report it.
    pub first_published_at: Option<i64>,
    #[serde(rename = "published_at")]
    pub published_at: Option<i64>,
    pub weekly_downloads: Option<u64>,
    pub maintainers: Vec<String>,
    pub publisher: Option<String>,
    pub install_scripts: Vec<InstallScript>,
    pub repository: Option<String>,
    pub deprecated: Option<String>,
    pub registry_url: String,
    pub findings: Vec<Finding>,
}

impl PackageReport {
    pub fn verdict(&self) -> Severity {
        self.findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    pub fn exit_code(&self) -> u8 {
        self.verdict().exit_code()
    }

    pub fn first_published_date(&self) -> Option<String> {
        self.first_published_at.map(date::format_date)
    }

    pub fn published_date(&self) -> Option<String> {
        self.published_at.map(date::format_date)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, version: Option<&str>) -> PackageSpec {
        PackageSpec {
            name: name.to_string(),
            version: version.map(str::to_string),
        }
    }

    #[test]
    fn parses_plain_name() {
        assert_eq!(
            PackageSpec::parse("express").unwrap(),
            spec("express", None)
        );
    }

    #[test]
    fn parses_name_and_exact_version() {
        assert_eq!(
            PackageSpec::parse("express@5.1.0").unwrap(),
            spec("express", Some("5.1.0"))
        );
    }

    #[test]
    fn parses_name_and_dist_tag() {
        assert_eq!(
            PackageSpec::parse("express@next").unwrap(),
            spec("express", Some("next"))
        );
    }

    #[test]
    fn parses_scoped_name() {
        assert_eq!(
            PackageSpec::parse("@types/node").unwrap(),
            spec("@types/node", None)
        );
    }

    #[test]
    fn parses_scoped_name_with_version() {
        assert_eq!(
            PackageSpec::parse("@types/node@22.0.0").unwrap(),
            spec("@types/node", Some("22.0.0"))
        );
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(
            PackageSpec::parse("  express@5.1.0  ").unwrap(),
            spec("express", Some("5.1.0"))
        );
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(PackageSpec::parse("   "), Err(SpecError::Empty));
        assert_eq!(PackageSpec::parse(""), Err(SpecError::Empty));
    }

    #[test]
    fn rejects_missing_parts() {
        for input in ["@", "@scope/", "@/name", "foo@", "foo/bar"] {
            assert!(
                PackageSpec::parse(input).is_err(),
                "accepted invalid spec {input:?}"
            );
        }
    }

    #[test]
    fn rejects_names_that_could_escape_the_registry_path() {
        for input in [
            "../etc",
            "foo/../bar",
            "foo bar",
            "foo?x=1",
            "foo#frag",
            "foo\\bar",
        ] {
            assert!(
                PackageSpec::parse(input).is_err(),
                "accepted invalid spec {input:?}"
            );
        }
    }

    #[test]
    fn rejects_versions_that_could_escape_the_registry_path() {
        for input in ["foo@../bar", "foo@1.0.0/evil", "foo@1.0.0#x", "foo@1.0.0?x"] {
            assert!(
                PackageSpec::parse(input).is_err(),
                "accepted invalid spec {input:?}"
            );
        }
    }

    #[test]
    fn rejects_names_over_the_npm_limit() {
        let long = "a".repeat(215);
        assert_eq!(PackageSpec::parse(&long), Err(SpecError::TooLong));
    }

    #[test]
    fn severity_drives_exit_codes() {
        assert_eq!(Severity::Info.exit_code(), 0);
        assert_eq!(Severity::Warn.exit_code(), 1);
        assert_eq!(Severity::High.exit_code(), 2);
    }

    fn report(findings: Vec<Finding>) -> PackageReport {
        PackageReport {
            ecosystem: "npm",
            name: "x".into(),
            version: "1.0.0".into(),
            first_published_at: None,
            published_at: None,
            weekly_downloads: None,
            maintainers: vec![],
            publisher: None,
            install_scripts: vec![],
            repository: None,
            deprecated: None,
            registry_url: String::new(),
            findings,
        }
    }

    fn finding(severity: Severity) -> Finding {
        Finding {
            id: "test",
            severity,
            title: String::new(),
            detail: String::new(),
            evidence: vec![],
        }
    }

    #[test]
    fn empty_report_is_clean() {
        let report = report(vec![]);
        assert_eq!(report.verdict(), Severity::Info);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn verdict_is_the_worst_finding() {
        let report = report(vec![
            finding(Severity::Info),
            finding(Severity::Warn),
            finding(Severity::Info),
        ]);
        assert_eq!(report.verdict(), Severity::Warn);
        assert_eq!(report.exit_code(), 1);
    }
}
