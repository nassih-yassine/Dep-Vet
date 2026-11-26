//! The per-package audit: one client per ecosystem, one policy, the shared
//! scorecard memo, and the `Pre` values a tree audit already fetched.

use std::sync::Arc;

use crate::allowlist::Policy;
use crate::composer::{ComposerClient, ComposerError};
use crate::crates::{CratesClient, CratesError};
use crate::go::{GoClient, GoError};
use crate::http::HttpClient;
use crate::jsr::{JsrClient, JsrError};
use crate::maven::{MavenClient, MavenError};
use crate::memo::LookupMemo;
use crate::model::{Ecosystem, PackageReport, PackageSpec, Profile};
use crate::nuget::{NugetClient, NugetError};
use crate::osv::{AdvisoryList, OsvClient, OsvQuery};
use crate::pypi::{PypiClient, PypiError};
use crate::registry::{PackageMeta, RegistryClient, RegistryError};
use crate::rubygems::{GemClient, GemError};
use crate::scorecard::{Scorecard, ScorecardClient, project_key};
use crate::signals;

/// Lookups an audit already performed for a batch. `None` means fetch now,
/// which is how single-package commands keep working unchanged.
#[derive(Clone, Copy)]
pub struct Pre<'a> {
    pub downloads: Option<u64>,
    pub advisories: Option<&'a AdvisoryList>,
}

pub struct Auditor {
    registry: RegistryClient,
    pypi: PypiClient,
    crates: CratesClient,
    go: GoClient,
    jsr: JsrClient,
    gems: GemClient,
    nuget: NugetClient,
    maven: MavenClient,
    composer: ComposerClient,
    osv: OsvClient,
    scorecard: Option<ScorecardClient>,
    /// Repository to scorecard, memoised for the life of the run. A monorepo
    /// tree repeats the same repository dozens of times, and `watch` and the
    /// MCP server reuse this `Auditor` across reports. Single-flight, so
    /// concurrent workers do not all ask deps.dev for the same project.
    scorecards: LookupMemo<Scorecard>,
    policy: Policy,
}

impl Auditor {
    pub fn new(http: &Arc<HttpClient>, policy: &Policy) -> Self {
        Self {
            registry: RegistryClient::from_env(Arc::clone(http)),
            pypi: PypiClient::from_env(Arc::clone(http)),
            crates: CratesClient::from_env(Arc::clone(http)),
            go: GoClient::from_env(Arc::clone(http)),
            jsr: JsrClient::from_env(Arc::clone(http)),
            gems: GemClient::from_env(Arc::clone(http)),
            nuget: NugetClient::from_env(Arc::clone(http)),
            maven: MavenClient::from_env(Arc::clone(http)),
            composer: ComposerClient::from_env(Arc::clone(http)),
            osv: OsvClient::from_env(Arc::clone(http)),
            scorecard: Some(ScorecardClient::from_env(Arc::clone(http))),
            scorecards: LookupMemo::new(),
            policy: policy.clone(),
        }
    }

    /// Attach the OpenSSF Scorecard for the repository, when deps.dev has one.
    /// A miss stays `None`, which the report shows as not checked.
    fn attach_scorecard(&self, meta: &mut PackageMeta) {
        let Some(client) = &self.scorecard else {
            return;
        };
        let Some(repository) = meta.repository.as_deref() else {
            return;
        };
        // Key on the normalised project, not the raw URL: `github.com/Owner/Repo`
        // and `github.com/owner/repo` are one deps.dev project.
        let key = project_key(repository).unwrap_or_else(|| repository.to_string());
        meta.scorecard = self
            .scorecards
            .get_or_lookup(&key, || client.lookup(repository));
    }

    /// The hook budget is 8 seconds; repository reputation is context, not the
    /// install decision, so `guard` does not spend that budget on it.
    pub fn skip_scorecard(&mut self) {
        self.scorecard = None;
    }

    pub fn audit_npm(
        &self,
        spec: &PackageSpec,
        local: &[String],
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, RegistryError> {
        let mut meta = self.registry.fetch(spec)?;
        self.attach_scorecard(&mut meta);
        // One extra lookup only when the name resembles a popular one: compare
        // the two download counts instead of trusting the generated seed.
        if let Some(candidate) =
            crate::signals::typosquat_candidate(&meta.name, Ecosystem::Npm, local)
        {
            meta.candidate_weekly_downloads = self.registry.weekly_downloads(&candidate);
        }
        let (downloads, advisories) = match pre {
            Some(pre) => (pre.downloads, pre.advisories.cloned()),
            // Advisories are best effort: a failure is reported as an INFO
            // finding, never as "no known vulnerabilities".
            None => (
                self.registry.weekly_downloads(&meta.name),
                self.osv
                    .query(Ecosystem::Npm, &meta.name, &meta.version)
                    .ok(),
            ),
        };
        Ok(signals::report_with_policy(
            meta,
            Ecosystem::Npm,
            downloads,
            advisories.as_ref(),
            local,
            Profile::NPM,
            now,
            &self.policy,
        ))
    }

    /// Advisory lists for a whole tree, in package order. JSR has no advisory
    /// source; a failed batch yields `None` for every package in it.
    pub fn advisories_for(
        &self,
        ecosystem: Ecosystem,
        packages: &[crate::lockfile::LockedPackage],
    ) -> Vec<Option<AdvisoryList>> {
        if ecosystem == Ecosystem::Jsr || packages.is_empty() {
            return vec![None; packages.len()];
        }
        let queries: Vec<OsvQuery> = packages
            .iter()
            .map(|package| OsvQuery {
                ecosystem,
                name: package.name.clone(),
                // Gemfile.lock records `number-platform`; OSV keys gems by
                // the registry number.
                version: if ecosystem == Ecosystem::RubyGems {
                    crate::rubygems::osv_version(&package.version).to_string()
                } else {
                    package.version.clone()
                },
            })
            .collect();
        let mut lists = self.osv.query_batch(&queries);
        lists.resize(queries.len(), None);
        lists
    }

    /// Weekly downloads for a tree, in package order. npm only.
    pub fn downloads_for(
        &self,
        ecosystem: Ecosystem,
        packages: &[crate::lockfile::LockedPackage],
    ) -> Vec<Option<u64>> {
        if ecosystem != Ecosystem::Npm || packages.is_empty() {
            return vec![None; packages.len()];
        }
        let names: Vec<String> = packages
            .iter()
            .map(|package| package.name.clone())
            .collect();
        let counts = self.registry.weekly_downloads_many(&names);
        names.iter().map(|name| counts.get(name).copied()).collect()
    }

    pub fn audit_composer(
        &self,
        spec: &PackageSpec,
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, ComposerError> {
        let mut meta = self.composer.fetch(spec)?;
        self.attach_scorecard(&mut meta);
        let advisories = match pre {
            Some(pre) => pre.advisories.cloned(),
            None => self
                .osv
                .query(Ecosystem::Composer, &meta.name, &meta.version)
                .ok(),
        };
        Ok(signals::report_with_policy(
            meta,
            Ecosystem::Composer,
            None,
            advisories.as_ref(),
            &[],
            Profile::COMPOSER,
            now,
            &self.policy,
        ))
    }

    pub fn audit_maven(
        &self,
        spec: &PackageSpec,
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, MavenError> {
        let mut meta = self.maven.fetch(spec)?;
        self.attach_scorecard(&mut meta);
        // A review override means the package came from Google Maven, which
        // OSV's Maven index does not cover.
        let google_maven = meta.review_url.is_some();
        let advisories = match pre {
            Some(pre) => pre.advisories.cloned(),
            None => self
                .osv
                .query(Ecosystem::Maven, &meta.name, &meta.version)
                .ok(),
        };
        let mut report = signals::report_with_policy(
            meta,
            Ecosystem::Maven,
            None,
            advisories.as_ref(),
            &[],
            Profile::MAVEN,
            now,
            &self.policy,
        );
        if google_maven {
            report.findings.push(signals::advisory_coverage_partial());
        }
        Ok(report)
    }

    pub fn audit_nuget(
        &self,
        spec: &PackageSpec,
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, NugetError> {
        let mut meta = self.nuget.fetch(spec)?;
        self.attach_scorecard(&mut meta);
        let advisories = match pre {
            Some(pre) => pre.advisories.cloned(),
            None => self
                .osv
                .query(Ecosystem::NuGet, &meta.name, &meta.version)
                .ok(),
        };
        Ok(signals::report_with_policy(
            meta,
            Ecosystem::NuGet,
            None,
            advisories.as_ref(),
            &[],
            Profile::NUGET,
            now,
            &self.policy,
        ))
    }

    pub fn audit_gem(
        &self,
        spec: &PackageSpec,
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, GemError> {
        let mut meta = self.gems.fetch(spec)?;
        self.attach_scorecard(&mut meta);
        let advisories = match pre {
            Some(pre) => pre.advisories.cloned(),
            None => self
                .osv
                .query(Ecosystem::RubyGems, &meta.name, &meta.version)
                .ok(),
        };
        Ok(signals::report_with_policy(
            meta,
            Ecosystem::RubyGems,
            None,
            advisories.as_ref(),
            &[],
            Profile::RUBYGEMS,
            now,
            &self.policy,
        ))
    }

    pub fn audit_jsr(
        &self,
        spec: &PackageSpec,
        now: i64,
        _pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, JsrError> {
        let mut meta = self.jsr.fetch(spec)?;
        self.attach_scorecard(&mut meta);
        Ok(signals::report_with_policy(
            meta,
            Ecosystem::Jsr,
            None,
            None,
            &[],
            Profile::JSR,
            now,
            &self.policy,
        ))
    }

    pub fn audit_go(
        &self,
        spec: &PackageSpec,
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, GoError> {
        let mut meta = self.go.fetch(spec)?;
        self.attach_scorecard(&mut meta);
        let advisories = match pre {
            Some(pre) => pre.advisories.cloned(),
            None => self
                .osv
                .query(Ecosystem::Go, &meta.name, &meta.version)
                .ok(),
        };
        Ok(signals::report_with_policy(
            meta,
            Ecosystem::Go,
            None,
            advisories.as_ref(),
            &[],
            Profile::GO,
            now,
            &self.policy,
        ))
    }

    pub fn audit_crates(
        &self,
        spec: &PackageSpec,
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, CratesError> {
        let mut meta = self.crates.fetch(spec)?;
        self.attach_scorecard(&mut meta);
        let advisories = match pre {
            Some(pre) => pre.advisories.cloned(),
            None => self
                .osv
                .query(Ecosystem::CratesIo, &meta.name, &meta.version)
                .ok(),
        };
        Ok(signals::report_with_policy(
            meta,
            Ecosystem::CratesIo,
            None,
            advisories.as_ref(),
            &[],
            Profile::CRATES,
            now,
            &self.policy,
        ))
    }

    pub fn audit_pypi(
        &self,
        spec: &PackageSpec,
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, PypiError> {
        let mut meta = self.pypi.fetch(spec)?;
        self.attach_scorecard(&mut meta);
        let advisories = match pre {
            Some(pre) => pre.advisories.cloned(),
            None => self
                .osv
                .query(Ecosystem::Pypi, &meta.name, &meta.version)
                .ok(),
        };
        Ok(signals::report_with_policy(
            meta,
            Ecosystem::Pypi,
            None,
            advisories.as_ref(),
            &[],
            Profile::PYPI,
            now,
            &self.policy,
        ))
    }
}
