//! Core types: the package spec the user typed, and the evidence-backed
//! report dep-vet prints back.

use serde::{Deserialize, Serialize};

use crate::date;
use crate::osv::Advisory;

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
    #[error("package name contains characters the registry does not allow: {0}")]
    InvalidName(String),
    #[error("version or tag contains characters dep-vet will not send to the registry: {0}")]
    InvalidVersion(String),
}

impl PackageSpec {
    /// For callers that already hold a name and version (lockfiles) and must
    /// still get the same validation as user input.
    pub fn new(name: impl Into<String>, version: Option<String>) -> Result<Self, SpecError> {
        let name = name.into();
        validate_name(&name)?;
        let version = version
            .map(|version| validate_version(&version))
            .transpose()?;
        Ok(Self { name, version })
    }

    /// Composer reference: `vendor/package` or `vendor/package@1.2.3`.
    pub fn parse_composer(input: &str) -> Result<Self, SpecError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(SpecError::Empty);
        }
        let (name, version) = match trimmed.split_once('@') {
            Some((name, version)) => (name, Some(version)),
            None => (trimmed, None),
        };
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
        match name.split_once('/') {
            Some((vendor, package))
                if !vendor.is_empty()
                    && !package.is_empty()
                    && !package.contains('/')
                    && vendor.chars().all(allowed)
                    && package.chars().all(allowed) => {}
            _ => {
                return Err(SpecError::InvalidName(format!(
                    "{name} (expected vendor/package)"
                )));
            }
        }
        let version = match version {
            Some(version) => Some(validate_version(version)?),
            None => None,
        };
        // Composer requires lowercase names; OSV keys Packagist by that form.
        Ok(Self {
            name: name.to_ascii_lowercase(),
            version,
        })
    }

    /// Maven reference: `group:artifact` or `group:artifact@1.2.3`.
    pub fn parse_maven(input: &str) -> Result<Self, SpecError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(SpecError::Empty);
        }
        let (coordinates, version) = match trimmed.split_once('@') {
            Some((coordinates, version)) => (coordinates, Some(version)),
            None => (trimmed, None),
        };
        let (group, artifact) = coordinates.split_once(':').ok_or_else(|| {
            SpecError::InvalidName(format!("{coordinates} (expected group:artifact)"))
        })?;
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
        if group.is_empty()
            || artifact.is_empty()
            || !group.chars().all(allowed)
            || !artifact.chars().all(allowed)
        {
            return Err(SpecError::InvalidName(coordinates.to_string()));
        }
        let version = match version {
            Some(version) => Some(validate_version(version)?),
            None => None,
        };
        Ok(Self {
            name: format!("{group}:{artifact}"),
            version,
        })
    }

    /// NuGet reference: `Id` or `Id@1.2.3`. IDs are case-insensitive.
    pub fn parse_nuget(input: &str) -> Result<Self, SpecError> {
        let spec = Self::parse(input)?;
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
        if spec.name.is_empty() || !spec.name.chars().all(allowed) {
            return Err(SpecError::InvalidName(spec.name));
        }
        // NuGet IDs are case-insensitive for lookups, but OSV matches the
        // published casing, so keep what the caller gave us.
        Ok(spec)
    }

    /// RubyGems reference: `name` or `name@1.2.3`.
    pub fn parse_gem(input: &str) -> Result<Self, SpecError> {
        let spec = Self::parse(input)?;
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
        if !spec.name.chars().all(allowed) || spec.name.is_empty() {
            return Err(SpecError::InvalidName(spec.name));
        }
        Ok(spec)
    }

    /// JSR reference: `@scope/name` or `@scope/name@1.2.3`.
    pub fn parse_jsr(input: &str) -> Result<Self, SpecError> {
        let spec = Self::parse(input)?;
        let (scope, name) = spec
            .name
            .strip_prefix('@')
            .and_then(|rest| rest.split_once('/'))
            .ok_or_else(|| SpecError::InvalidName(spec.name.clone()))?;
        if scope.is_empty() || name.is_empty() || name.contains('/') {
            return Err(SpecError::InvalidName(spec.name.clone()));
        }
        Ok(spec)
    }

    /// Go module reference: `module/path` or `module/path@v1.2.3`. Module paths
    /// are case-sensitive; uppercase is preserved for the API but folded for
    /// typosquat comparison.
    pub fn parse_go(input: &str) -> Result<Self, SpecError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(SpecError::Empty);
        }
        let (name, version) = match trimmed.split_once('@') {
            Some((name, version)) => (name, Some(version)),
            None => (trimmed, None),
        };
        validate_go_module(name)?;
        let version = match version {
            Some(version) => Some(validate_version(version)?),
            None => None,
        };
        // npm's name rules forbid slashes, so build directly after validation.
        Ok(Self {
            name: name.to_string(),
            version,
        })
    }

    /// crates.io reference: `name` or `name@1.2.3`. Crate names are ASCII
    /// letters, digits, `-` and `_`.
    pub fn parse_crates(input: &str) -> Result<Self, SpecError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(SpecError::Empty);
        }
        let (name, version) = match trimmed.split_once('@') {
            Some((name, version)) => (name, Some(version)),
            None => (trimmed, None),
        };
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_');
        if name.is_empty() || name.len() > 64 || !name.chars().all(allowed) {
            return Err(SpecError::InvalidName(name.to_string()));
        }
        Self::new(name, version.map(str::to_string))
    }

    /// PyPI reference: `name`, `name==1.2.3`, `name[extra]==1.2.3`.
    /// Extras are dropped in v1; they do not change which files exist for a
    /// version, only which of its dependencies get installed.
    pub fn parse_pypi(input: &str) -> Result<Self, SpecError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(SpecError::Empty);
        }
        let (name, version) = match trimmed.split_once("==") {
            Some((name, version)) => (name, Some(version)),
            None => (trimmed, None),
        };
        let name = match name.split_once('[') {
            Some((name, extras)) if extras.ends_with(']') => name,
            Some(_) => return Err(SpecError::InvalidName(name.to_string())),
            None => name,
        };
        validate_pypi_name(name)?;
        Self::new(name, version.map(str::to_string))
    }

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

        Self::new(name, version.map(str::to_string))
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

fn validate_go_module(name: &str) -> Result<(), SpecError> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-' | '/');
    if name.is_empty() {
        return Err(SpecError::Empty);
    }
    if name.len() > 300 {
        return Err(SpecError::TooLong);
    }
    let first_segment = name.split('/').next().unwrap_or_default();
    let has_domain = first_segment.contains('.');
    let bad_segments = name
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..");
    if !has_domain || bad_segments || !name.chars().all(allowed) {
        return Err(SpecError::InvalidName(name.to_string()));
    }
    Ok(())
}

fn validate_pypi_name(name: &str) -> Result<(), SpecError> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if name.is_empty() {
        return Err(SpecError::Empty);
    }
    if name.len() > 200 {
        return Err(SpecError::TooLong);
    }
    if !name.chars().all(allowed) || name.starts_with(['.', '-']) || name.ends_with(['.', '-']) {
        return Err(SpecError::InvalidName(name.to_string()));
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<String, SpecError> {
    let trimmed = version.trim();
    let allowed =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-' | '+' | '^' | '!');
    if trimmed.is_empty() || !trimmed.chars().all(allowed) {
        return Err(SpecError::InvalidVersion(version.to_string()));
    }
    Ok(trimmed.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[serde(alias = "low")]
    Info,
    #[serde(alias = "medium")]
    Warn,
    #[serde(alias = "critical")]
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

fn is_false(value: &bool) -> bool {
    !*value
}

/// Which package ecosystem a report describes. One variant today: add the next
/// one when its source exists, not before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Pypi,
    #[serde(rename = "crates")]
    CratesIo,
    Go,
    Jsr,
    #[serde(rename = "rubygems")]
    RubyGems,
    #[serde(rename = "nuget")]
    NuGet,
    Maven,
    #[serde(rename = "composer")]
    Composer,
}

/// Whether two package names refer to the same package. Case is folded for
/// every ecosystem; PyPI also folds the separators PEP 503 treats as equal.
pub fn names_match(ecosystem: Ecosystem, left: &str, right: &str) -> bool {
    let fold = |name: &str| match ecosystem {
        Ecosystem::Pypi => name.to_ascii_lowercase().replace(['_', '.'], "-"),
        _ => name.to_ascii_lowercase(),
    };
    fold(left) == fold(right)
}

impl Ecosystem {
    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::CratesIo => "crates",
            Self::Go => "go",
            Self::Jsr => "jsr",
            Self::RubyGems => "gem",
            Self::NuGet => "nuget",
            Self::Maven => "maven",
            Self::Composer => "composer",
        }
    }

    /// The string OSV expects in `package.ecosystem`.
    pub fn osv_name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "PyPI",
            Self::CratesIo => "crates.io",
            Self::Go => "Go",
            // OSV does not publish advisories for JSR; nothing queries this.
            Self::Jsr => "JSR",
            Self::RubyGems => "RubyGems",
            Self::NuGet => "NuGet",
            Self::Maven => "Maven",
            Self::Composer => "Packagist",
        }
    }
}

impl Ecosystem {
    /// Human-facing page for one version.
    pub fn package_url(self, name: &str, version: &str) -> String {
        match self {
            Self::Npm => format!("https://www.npmjs.com/package/{name}/v/{version}"),
            Self::Pypi => format!("https://pypi.org/project/{name}/{version}/"),
            Self::CratesIo => format!("https://crates.io/crates/{name}/{version}"),
            Self::Go => format!("https://pkg.go.dev/{name}@{version}"),
            Self::Jsr => format!("https://jsr.io/{name}/{version}"),
            Self::RubyGems => format!("https://rubygems.org/gems/{name}/{version}"),
            Self::NuGet => format!("https://www.nuget.org/packages/{name}/{version}"),
            Self::Maven => {
                let (group, artifact) = name.split_once(':').unwrap_or((name, ""));
                format!("https://search.maven.org/artifact/{group}/{artifact}/{version}/jar")
            }
            Self::Composer => format!("https://packagist.org/packages/{name}#{version}"),
        }
    }

    /// Human-facing page for the project.
    pub fn project_url(self, name: &str) -> String {
        match self {
            Self::Npm => format!("https://www.npmjs.com/package/{name}"),
            Self::Pypi => format!("https://pypi.org/project/{name}/"),
            Self::CratesIo => format!("https://crates.io/crates/{name}"),
            Self::Go => format!("https://pkg.go.dev/{name}"),
            Self::Jsr => format!("https://jsr.io/{name}"),
            Self::RubyGems => format!("https://rubygems.org/gems/{name}"),
            Self::NuGet => format!("https://www.nuget.org/packages/{name}"),
            Self::Maven => {
                let (group, artifact) = name.split_once(':').unwrap_or((name, ""));
                format!("https://search.maven.org/artifact/{group}/{artifact}")
            }
            Self::Composer => format!("https://packagist.org/packages/{name}"),
        }
    }
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.cli_name())
    }
}

/// Which signals an ecosystem can support. A disabled signal is reported as
/// "not checked", never as clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    pub execution: bool,
    pub maintainers: bool,
    pub advisories: bool,
    pub repository: bool,
    pub downloads: bool,
    pub deprecation: bool,
    pub typosquat: bool,
    pub freshness: bool,
    /// Whether the registry exposes dependency history for a release.
    pub dependencies: bool,
    /// Whether a source repository can be looked up for an OpenSSF Scorecard.
    pub scorecard: bool,
}

impl Profile {
    pub const NPM: Self = Self {
        execution: true,
        maintainers: true,
        advisories: true,
        repository: true,
        downloads: true,
        deprecation: true,
        typosquat: true,
        freshness: true,
        dependencies: true,
        scorecard: true,
    };

    /// PyPI exposes no maintainer set or download figure through its JSON API
    /// for this version of dep-vet; both are reported as not checked.
    pub const PYPI: Self = Self {
        execution: true,
        maintainers: false,
        advisories: true,
        repository: true,
        downloads: false,
        deprecation: true,
        typosquat: true,
        freshness: true,
        dependencies: true,
        scorecard: true,
    };

    /// crates.io does not expose `build.rs` in its metadata and reports
    /// 90-day downloads, not weekly ones. Neither is guessed.
    pub const CRATES: Self = Self {
        execution: false,
        maintainers: true,
        advisories: true,
        repository: true,
        downloads: false,
        deprecation: true,
        typosquat: true,
        freshness: true,
        dependencies: true,
        scorecard: true,
    };

    /// Go modules carry no install hooks, owner list, download figure, or
    /// repository link in the module index.
    pub const GO: Self = Self {
        execution: false,
        maintainers: false,
        advisories: true,
        repository: false,
        downloads: false,
        deprecation: true,
        typosquat: true,
        freshness: true,
        dependencies: false,
        scorecard: false,
    };

    /// JSR exposes no owner list, download figure, execution surface, or OSV
    /// advisories. Repository, freshness, deprecation, and typosquats work.
    pub const JSR: Self = Self {
        execution: false,
        maintainers: false,
        advisories: false,
        repository: true,
        downloads: false,
        deprecation: true,
        typosquat: true,
        freshness: true,
        dependencies: false,
        scorecard: true,
    };

    /// RubyGems exposes no owner list, weekly downloads, or install-time file
    /// data. Advisories, repository, freshness, and deprecation work.
    pub const RUBYGEMS: Self = Self {
        execution: false,
        maintainers: false,
        advisories: true,
        repository: true,
        downloads: false,
        deprecation: true,
        typosquat: true,
        freshness: true,
        dependencies: false,
        scorecard: true,
    };

    /// NuGet exposes no owner list, download figure, repository, or build-time
    /// file data. Advisories, freshness, deprecation, and typosquats work.
    pub const NUGET: Self = Self {
        execution: false,
        maintainers: false,
        advisories: true,
        repository: false,
        downloads: false,
        deprecation: true,
        typosquat: true,
        freshness: true,
        dependencies: true,
        scorecard: false,
    };

    /// Maven Central exposes no owners, download figure, source repository, or
    /// build-time data, and has no deprecation concept.
    pub const MAVEN: Self = Self {
        execution: false,
        maintainers: false,
        advisories: true,
        repository: false,
        downloads: false,
        deprecation: false,
        typosquat: true,
        freshness: true,
        dependencies: false,
        scorecard: false,
    };

    /// Packagist exposes maintainers, repository metadata, and an abandoned
    /// flag, but no install-time file list and no weekly download figure.
    pub const COMPOSER: Self = Self {
        execution: false,
        maintainers: true,
        advisories: true,
        repository: true,
        downloads: false,
        deprecation: true,
        typosquat: true,
        freshness: true,
        dependencies: true,
        scorecard: true,
    };

    pub fn not_checked(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.execution {
            missing.push("execution");
        }
        if !self.maintainers {
            missing.push("maintainers");
        }
        if !self.repository {
            missing.push("repository");
        }
        if !self.downloads {
            missing.push("downloads");
        }
        if !self.advisories {
            missing.push("advisories");
        }
        if !self.deprecation {
            missing.push("deprecation");
        }
        if !self.typosquat {
            missing.push("typosquat");
        }
        if !self.freshness {
            missing.push("freshness");
        }
        if !self.dependencies {
            missing.push("dependency history");
        }
        if !self.scorecard {
            missing.push("scorecard");
        }
        missing
    }
}

/// Exit code for "the check could not run", shared by every command.
pub const TOOL_ERROR_EXIT_CODE: u8 = 3;

/// A lockfile diff: every package the change adds, plus anything that could
/// not be checked.
#[derive(Debug, Clone, Serialize)]
pub struct LockReport {
    pub lockfile: String,
    pub base: String,
    pub new_packages: Vec<PackageReport>,
    pub errors: Vec<LockFetchError>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// A whole lockfile, audited in place. No base revision, no diff.
#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub lockfile: String,
    pub packages: Vec<PackageReport>,
    pub errors: Vec<LockFetchError>,
    /// Deliberate omissions that must not fail the run (for example JSR).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl AuditReport {
    pub fn verdict(&self) -> Severity {
        self.packages
            .iter()
            .map(PackageReport::verdict)
            .max()
            .unwrap_or(Severity::Info)
    }

    pub fn exit_code(&self) -> u8 {
        if self.errors.is_empty() {
            self.verdict().exit_code()
        } else {
            TOOL_ERROR_EXIT_CODE
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LockFetchError {
    pub package: String,
    pub message: String,
}

impl LockReport {
    pub fn verdict(&self) -> Severity {
        self.new_packages
            .iter()
            .map(PackageReport::verdict)
            .max()
            .unwrap_or(Severity::Info)
    }

    /// An incomplete audit is a tool error, even when nothing risky was found.
    pub fn exit_code(&self) -> u8 {
        if self.errors.is_empty() {
            self.verdict().exit_code()
        } else {
            TOOL_ERROR_EXIT_CODE
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
    /// Set when `.depvet.toml` allows this finding for this package.
    #[serde(skip_serializing_if = "is_false")]
    pub allowed: bool,
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
    pub ecosystem: Ecosystem,
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
    /// Provenance presence, never a cryptographic verdict.
    pub provenance: Provenance,
    /// Whether the published attestation names this release's tarball. `None`
    /// means unattested, unreadable, or not applicable; it is never "verified".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_subject_matches: Option<bool>,
    /// The SLSA predicate's claims, when published. Not verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationClaims>,
    /// OpenSSF Scorecard, when deps.dev knows the repository. Absent means
    /// not checked, never a clean score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scorecard: Option<crate::scorecard::Scorecard>,
    /// SPDX-normalised license from the registry, when it published one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    pub advisories: Vec<Advisory>,
    /// Advisories skipped after the per-run cap.
    pub hidden_advisories: usize,
    /// Signals this ecosystem cannot support; empty means everything ran.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_checked: Vec<&'static str>,
    pub registry_url: String,
    /// Overrides the ecosystem's default review page when a package does not
    /// live on its main registry (Google Maven, for example).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_url: Option<String>,
    /// Root-to-package chains from the lockfile graph, each entry
    /// `name@version`. Empty when the format has no graph or no root reaches
    /// the package; never guessed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependency_paths: Vec<Vec<String>>,
    /// What to do about this package, when there is something to do.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub upgrades: Vec<Upgrade>,
    #[serde(serialize_with = "crate::report::serialize_findings")]
    pub findings: Vec<Finding>,
}

/// What a release's attestation claims about how it was built. Every field is
/// a claim: none of it is cryptographically verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttestationClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation: Option<String>,
}

impl AttestationClaims {
    /// True when at least one claim was readable.
    pub fn has_any(&self) -> bool {
        self.build_type.is_some()
            || self.builder.is_some()
            || self.source_repository.is_some()
            || self.source_commit.is_some()
            || self.workflow.is_some()
            || self.invocation.is_some()
    }
}

/// Whether a release publishes provenance, and whether we could read it.
/// `present` never means cryptographically verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Provenance {
    Present,
    Missing,
    #[default]
    Unavailable,
}

/// How sure the rule is, separate from how bad the finding would be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Finding {
    /// Rule-level confidence. Severity says how bad this would be; confidence
    /// says how sure the evidence is. Both are needed before acting on a line.
    pub fn confidence(&self) -> Confidence {
        match self.id {
            "advisory"
            | "install-scripts"
            | "install-scripts-changed"
            | "build-from-source"
            | "advisories-truncated"
            | "advisory-check-unavailable"
            | "advisory-coverage-partial"
            | "known-exploited"
            | "threat-data-unavailable"
            | "workflow-pr-target-checkout"
            | "workflow-script-injection"
            | "workflow-curl-pipe-shell"
            | "workflow-secret-echo" => Confidence::High,
            "typosquat"
            | "publisher-not-maintainer"
            | "publisher-changed"
            | "dependency-added"
            | "release-after-dormancy"
            | "deprecated"
            | "fresh-package"
            | "fresh-version"
            | "maintainer-check-unavailable"
            | "attestation-source-mismatch"
            | "advisories-stale"
            | "low-scorecard"
            | "policy-min-age"
            | "policy-min-downloads"
            | "policy-provenance"
            | "policy-advisory-severity"
            | "policy-license"
            | "no-repository" => Confidence::Medium,
            "policy-license-denied" => Confidence::High,
            _ => Confidence::Medium,
        }
    }
}

/// One actionable line for a package. The fixed version is what OSV publishes;
/// the newest version is a hint and never claims to fix anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Upgrade {
    /// Versions OSV says fix this package's advisories, audited major first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fixed: Vec<String>,
    /// An advisory could not be read, so its fix is unknown, not absent.
    #[serde(skip_serializing_if = "is_false")]
    pub fix_unknown: bool,
    /// Highest published version, secondary hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest: Option<String>,
    /// Advisory ids whose fixes are in `fixed` or unknown.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<String>,
    /// The package a lookalike name probably meant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replace_with: Option<String>,
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
    fn new_validates_like_input_parsing() {
        assert_eq!(
            PackageSpec::new("express", Some("5.1.0".to_string())).unwrap(),
            spec("express", Some("5.1.0"))
        );
        assert_eq!(
            PackageSpec::new("@scope/pkg", None).unwrap(),
            spec("@scope/pkg", None)
        );
        assert!(PackageSpec::new("evil?x=1", None).is_err());
        assert!(PackageSpec::new("express", Some("../x".to_string())).is_err());
    }

    #[test]
    fn profile_reports_only_what_it_cannot_check() {
        assert!(Profile::NPM.not_checked().is_empty());
        let partial = Profile {
            dependencies: true,
            maintainers: false,
            downloads: false,
            ..Profile::NPM
        };
        assert_eq!(partial.not_checked(), vec!["maintainers", "downloads"]);
    }

    #[test]
    fn parses_pypi_names_and_exact_versions() {
        assert_eq!(
            PackageSpec::parse_pypi("requests").unwrap(),
            spec("requests", None)
        );
        assert_eq!(
            PackageSpec::parse_pypi("requests==2.31.0").unwrap(),
            spec("requests", Some("2.31.0"))
        );
        assert_eq!(
            PackageSpec::parse_pypi("requests[security]==2.31.0").unwrap(),
            spec("requests", Some("2.31.0"))
        );
        assert_eq!(
            PackageSpec::parse_pypi("zope.interface").unwrap(),
            spec("zope.interface", None)
        );
    }

    #[test]
    fn rejects_pypi_names_that_could_escape_the_url() {
        for input in [
            "../etc", "foo/bar", "foo bar", "foo?", "@scope/x", "-leading",
        ] {
            assert!(
                PackageSpec::parse_pypi(input).is_err(),
                "accepted {input:?}"
            );
        }
        assert!(PackageSpec::parse_pypi("requests==").is_err());
        assert!(PackageSpec::parse_pypi("requests[security").is_err());
    }

    #[test]
    fn ecosystems_map_to_osv_names() {
        assert_eq!(Ecosystem::Npm.osv_name(), "npm");
        assert_eq!(Ecosystem::Pypi.osv_name(), "PyPI");
        assert_eq!(Ecosystem::CratesIo.osv_name(), "crates.io");
        assert_eq!(Ecosystem::Go.osv_name(), "Go");
        assert_eq!(Ecosystem::RubyGems.osv_name(), "RubyGems");
        assert_eq!(Ecosystem::NuGet.osv_name(), "NuGet");
        assert_eq!(Ecosystem::Composer.osv_name(), "Packagist");
    }

    #[test]
    fn parses_composer_names() {
        assert_eq!(
            PackageSpec::parse_composer("monolog/monolog").unwrap(),
            spec("monolog/monolog", None)
        );
        assert_eq!(
            PackageSpec::parse_composer("Symfony/Console@7.2.0").unwrap(),
            spec("symfony/console", Some("7.2.0"))
        );
        for input in ["monolog", "monolog/", "/monolog", "a/b/c", "a b/c", "a/b@"] {
            assert!(
                PackageSpec::parse_composer(input).is_err(),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn package_names_match_regardless_of_case_and_pypi_separators() {
        assert!(names_match(Ecosystem::Npm, "React", "react"));
        assert!(names_match(Ecosystem::Pypi, "Flask", "flask"));
        assert!(names_match(
            Ecosystem::Pypi,
            "zope.interface",
            "zope-interface"
        ));
        assert!(names_match(
            Ecosystem::Pypi,
            "zope_interface",
            "zope.interface"
        ));
        assert!(names_match(
            Ecosystem::Maven,
            "Org.Slf4j:Slf4j-Api",
            "org.slf4j:slf4j-api"
        ));
        assert!(!names_match(Ecosystem::Npm, "react", "preact"));
        assert!(!names_match(Ecosystem::Pypi, "foo", "bar"));
    }

    #[test]
    fn parses_maven_coordinates() {
        assert_eq!(
            PackageSpec::parse_maven("org.slf4j:slf4j-api").unwrap(),
            spec("org.slf4j:slf4j-api", None)
        );
        assert_eq!(
            PackageSpec::parse_maven("org.slf4j:slf4j-api@2.0.17").unwrap(),
            spec("org.slf4j:slf4j-api", Some("2.0.17"))
        );
        for input in ["slf4j-api", "org.slf4j/thing", "a:b@", "@/x", "a b:c"] {
            assert!(
                PackageSpec::parse_maven(input).is_err(),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn parses_nuget_ids() {
        assert_eq!(
            PackageSpec::parse_nuget("Newtonsoft.Json").unwrap(),
            spec("Newtonsoft.Json", None)
        );
        assert_eq!(
            PackageSpec::parse_nuget("Serilog@3.1.1").unwrap(),
            spec("Serilog", Some("3.1.1"))
        );
        for input in ["@scope/x", "foo/bar", "foo bar", "pkg@"] {
            assert!(
                PackageSpec::parse_nuget(input).is_err(),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn parses_gem_specs() {
        assert_eq!(PackageSpec::parse_gem("rack").unwrap(), spec("rack", None));
        assert_eq!(
            PackageSpec::parse_gem("rack@3.2.9").unwrap(),
            spec("rack", Some("3.2.9"))
        );
        for input in ["@scope/x", "foo/bar", "foo bar", "rack@"] {
            assert!(PackageSpec::parse_gem(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn parses_jsr_specs() {
        assert_eq!(
            PackageSpec::parse_jsr("@std/assert").unwrap(),
            spec("@std/assert", None)
        );
        assert_eq!(
            PackageSpec::parse_jsr("@std/assert@1.0.19").unwrap(),
            spec("@std/assert", Some("1.0.19"))
        );
        for input in [
            "express",
            "@std",
            "@/assert",
            "@std/assert/deep",
            "@std/assert@",
        ] {
            assert!(PackageSpec::parse_jsr(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn parses_go_modules_with_versions_and_suffixes() {
        assert_eq!(
            PackageSpec::parse_go("github.com/gin-gonic/gin").unwrap(),
            spec("github.com/gin-gonic/gin", None)
        );
        assert_eq!(
            PackageSpec::parse_go("github.com/gin-gonic/gin@v1.9.1").unwrap(),
            spec("github.com/gin-gonic/gin", Some("v1.9.1"))
        );
        assert_eq!(
            PackageSpec::parse_go("github.com/user/repo/v2@v2.0.0").unwrap(),
            spec("github.com/user/repo/v2", Some("v2.0.0"))
        );
        assert_eq!(
            PackageSpec::parse_go("github.com/user/repo@v0.0.0-20240101120000-abcdef123456")
                .unwrap()
                .version
                .as_deref(),
            Some("v0.0.0-20240101120000-abcdef123456")
        );
        assert_eq!(
            PackageSpec::parse_go("github.com/BurntSushi/toml")
                .unwrap()
                .name,
            "github.com/BurntSushi/toml"
        );
    }

    #[test]
    fn rejects_go_modules_that_could_escape_the_url() {
        for input in [
            "gin",
            "foo/bar",
            "../etc/passwd",
            "github.com/../evil",
            "github.com/user/repo/",
            "github.com/user//repo",
            "github.com/user/re po",
            "github.com/user/repo?x=1",
            "github.com/user/repo@",
        ] {
            assert!(PackageSpec::parse_go(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn parses_crate_names_and_versions() {
        assert_eq!(
            PackageSpec::parse_crates("serde").unwrap(),
            spec("serde", None)
        );
        assert_eq!(
            PackageSpec::parse_crates("serde@1.0.229").unwrap(),
            spec("serde", Some("1.0.229"))
        );
        assert_eq!(
            PackageSpec::parse_crates("tokio-util").unwrap(),
            spec("tokio-util", None)
        );
        for input in ["serde@", "serde@../x", "ser de", "serde/x", "sérde"] {
            assert!(
                PackageSpec::parse_crates(input).is_err(),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn confidence_follows_the_rule_not_the_severity() {
        let mut item = finding(Severity::Warn);
        item.id = "typosquat";
        assert_eq!(item.confidence(), Confidence::Medium);
        item.id = "advisory";
        assert_eq!(item.confidence(), Confidence::High);
        item.id = "something-new";
        assert_eq!(item.confidence(), Confidence::Medium);
    }

    #[test]
    fn severity_drives_exit_codes() {
        assert_eq!(Severity::Info.exit_code(), 0);
        assert_eq!(Severity::Warn.exit_code(), 1);
        assert_eq!(Severity::High.exit_code(), 2);
    }

    fn report(findings: Vec<Finding>) -> PackageReport {
        PackageReport {
            ecosystem: Ecosystem::Npm,
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
            provenance: crate::model::Provenance::Unavailable,
            attestation_subject_matches: None,
            attestation: None,
            advisories: Vec::new(),
            hidden_advisories: 0,
            not_checked: Vec::new(),
            registry_url: String::new(),
            review_url: None,
            upgrades: Vec::new(),
            dependency_paths: Vec::new(),
            findings,
            scorecard: None,
            license: None,
        }
    }

    fn finding(severity: Severity) -> Finding {
        Finding {
            id: "test",
            severity,
            title: String::new(),
            detail: String::new(),
            allowed: false,
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
