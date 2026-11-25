use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use dep_vet::cli::{Cli, Command, OutputFormat, SbomFormat};
use dep_vet::composer::{ComposerClient, ComposerError};
use dep_vet::crates::{CratesClient, CratesError};
use dep_vet::go::{GoClient, GoError};
use dep_vet::http::HttpClient;
use dep_vet::jsr::{JsrClient, JsrError};
use dep_vet::lockfile;
use dep_vet::maven::{MavenClient, MavenError};
use dep_vet::model::Ecosystem;
use dep_vet::model::{
    AuditReport, LockFetchError, LockReport, PackageReport, PackageSpec, Profile,
    TOOL_ERROR_EXIT_CODE as TOOL_ERROR,
};
use dep_vet::nuget::{NugetClient, NugetError};
use dep_vet::osv::{AdvisoryList, OsvClient, OsvQuery};
use dep_vet::pypi::{PypiClient, PypiError};
use dep_vet::registry::{PackageMeta, RegistryClient, RegistryError};
use dep_vet::report::{
    render_audit_human, render_audit_json, render_human, render_json, render_lock_human,
    render_lock_json,
};
use dep_vet::rubygems::{GemClient, GemError};
use dep_vet::signals;

/// Lookups an audit already performed for a batch. `None` means fetch now,
/// which is how single-package commands keep working unchanged.
#[derive(Clone, Copy)]
struct Pre<'a> {
    downloads: Option<u64>,
    advisories: Option<&'a AdvisoryList>,
}

/// Packages audited at once. Each one can fan out to a few OSV detail
/// requests, so keep the burst small.
const MAX_CONCURRENT_AUDITS: usize = 4;

/// Maven Central answers 403 when it sees a burst of search requests, so tree
/// audits go one coordinate at a time. Google Maven is unaffected.
const MAVEN_CONCURRENCY: usize = 1;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return usage_exit(error),
    };
    if cli.dev_registry {
        // The flag is the explicit opt-in; the HTTP layer reads the same gate.
        // SAFETY: set before any worker or client is created.
        unsafe {
            std::env::set_var("DEPVET_ALLOW_INSECURE_BASES", "1");
        }
    }
    if let Err(error) = dep_vet::netpolicy::check_overrides_env() {
        eprintln!("dep-vet: {error}");
        eprintln!("dep-vet could not start the check; this is not a verdict (exit {TOOL_ERROR}).");
        return ExitCode::from(TOOL_ERROR);
    }
    dep_vet::netpolicy::warn_once();
    match execute(&cli) {
        Ok(code) => {
            dep_vet::update::maybe_hint(&cli, code);
            ExitCode::from(code)
        }
        Err(error) => {
            eprintln!("dep-vet: {error}");
            eprintln!(
                "dep-vet could not finish the check; this is not a verdict (exit {TOOL_ERROR})."
            );
            ExitCode::from(TOOL_ERROR)
        }
    }
}

/// clap exits with 2 on usage errors, but 2 is reserved for "high risk".
/// Remap parse failures to the tool-error code; `--help` and `--version`
/// stay successful output.
fn usage_exit(error: clap::Error) -> ExitCode {
    let informational = matches!(
        error.kind(),
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
    );
    let _ = error.print();
    if informational {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "dep-vet: usage error; nothing was checked (this is not a verdict, exit {TOOL_ERROR})."
        );
        ExitCode::from(TOOL_ERROR)
    }
}

fn execute(cli: &Cli) -> anyhow::Result<u8> {
    // Hooks run on every Bash tool call and must never fail before they read
    // stdin; the guard child owns config and network errors.
    if let Command::Hook { action } = &cli.command {
        return match action {
            dep_vet::cli::HookAction::Claude { strict } => run_hook(*strict),
            dep_vet::cli::HookAction::Install {
                target,
                project,
                user,
                strict,
                write,
            } => run_hook_install(target, *project, *user, *strict, *write),
            dep_vet::cli::HookAction::Uninstall {
                target,
                project,
                user,
                write,
            } => run_hook_uninstall(target, *project, *user, *write),
        };
    }
    let http = Arc::new(HttpClient::from_env(cli.no_cache));
    let allowlist = dep_vet::allowlist::Allowlist::load(cli.config.as_deref())?;
    let mut auditor = Auditor::new(&http, allowlist.policy());

    match &cli.command {
        Command::Hook { .. } => unreachable!("handled before config and network"),

        Command::Mcp { print_config } => run_mcp(&auditor, &allowlist, *print_config),

        Command::Guard {
            check,
            json,
            stdin,
            command,
        } => {
            let command = if *stdin {
                use std::io::Read as _;
                let mut body = String::new();
                let mut reader = io::stdin().take(dep_vet::intent::MAX_COMMAND_BYTES as u64 + 1);
                let _ = reader.read_to_string(&mut body);
                body
            } else {
                command.join(" ")
            };
            if command.is_empty() {
                anyhow::bail!("pass a command after `--`, or use --stdin");
            }
            auditor.skip_scorecard();
            run_guard(&auditor, &allowlist, *check, *json, &command)
        }

        Command::Npm { package, json } => {
            let spec = PackageSpec::parse(package)?;
            // A lockfile in the current project is the same trusted-name list
            // the lock command uses; without one, the seed list stands alone.
            let local = local_candidates(cli);
            let mut report = auditor.audit_npm(&spec, &local, now_seconds(), None)?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Diff {
            ecosystem,
            from,
            to,
            json,
        } => {
            let ecosystem = inspect_ecosystem(ecosystem)?;
            let from_spec = inspect_spec(ecosystem, from)?;
            let to_spec = inspect_spec(ecosystem, to)?;
            if !from_spec.name.eq_ignore_ascii_case(&to_spec.name) {
                anyhow::bail!("diff needs two versions of the same package");
            }
            if from_spec.version.is_none() || to_spec.version.is_none() {
                anyhow::bail!("diff needs exact versions on both sides");
            }
            let http = Arc::new(HttpClient::from_env(cli.no_cache));
            let limits = allowlist.inspect().limits();
            let old = dep_vet::inspect::inspect_archive(
                &http,
                ecosystem,
                &from_spec,
                limits,
                !cli.no_cache,
            )?;
            let new = dep_vet::inspect::inspect_archive(
                &http,
                ecosystem,
                &to_spec,
                limits,
                !cli.no_cache,
            )?;
            let osv = OsvClient::from_env(Arc::clone(&http));
            let from_version = from_spec.version.clone().unwrap_or_default();
            let to_version = to_spec.version.clone().unwrap_or_default();
            let old_advisories = osv.query(ecosystem, &from_spec.name, &from_version).ok();
            let new_advisories = osv.query(ecosystem, &from_spec.name, &to_version).ok();
            let report = dep_vet::inspect::build_diff(
                ecosystem,
                &from_spec.name,
                &from_spec,
                &to_spec,
                &old,
                &new,
                &allowlist.inspect().disabled_rules,
                old_advisories.as_ref(),
                new_advisories.as_ref(),
            );
            let output = if *json {
                dep_vet::report::render_diff_json(&report)?
            } else {
                dep_vet::report::render_diff_human(&report, use_color(cli))
            };
            print!("{output}");
            Ok(report.exit_code())
        }

        Command::Plan {
            ecosystem,
            package,
            json,
        } => {
            let ecosystem = inspect_ecosystem(ecosystem)?;
            if ecosystem != Ecosystem::Npm {
                anyhow::bail!("plan supports npm only today");
            }
            let http = Arc::new(HttpClient::from_env(cli.no_cache));
            let registry = RegistryClient::from_env(http);
            let report =
                dep_vet::plan::plan(&registry, package).map_err(|error| anyhow::anyhow!(error))?;
            let output = if *json {
                dep_vet::plan::render_json(&report)?
            } else {
                dep_vet::plan::render(&report)
            };
            emit(&output, report.exit_code())
        }

        Command::McpConfig { path, json } => {
            let report = dep_vet::mcp_config::scan(path.as_deref())?;
            let output = if *json {
                dep_vet::report::render_mcp_config_json(&report)?
            } else {
                dep_vet::report::render_mcp_config_human(&report, use_color(cli))
            };
            emit(&output, report.exit_code())
        }

        Command::Workflows { path, json } => {
            let default = std::path::Path::new(".github/workflows");
            let report = dep_vet::workflows::scan(path.as_deref().unwrap_or(default))?;
            let output = if *json {
                dep_vet::report::render_workflows_json(&report)?
            } else {
                dep_vet::report::render_workflows_human(&report, use_color(cli))
            };
            emit(&output, report.exit_code())
        }

        Command::Inspect {
            ecosystem,
            package,
            json,
        } => {
            let ecosystem = inspect_ecosystem(ecosystem)?;
            let spec = inspect_spec(ecosystem, package)?;
            let http = Arc::new(HttpClient::from_env(cli.no_cache));
            let limits = allowlist.inspect().limits();
            let prepared =
                dep_vet::inspect::inspect_archive(&http, ecosystem, &spec, limits, !cli.no_cache)?;
            let mut report = dep_vet::inspect::build_report(
                ecosystem,
                &spec,
                prepared,
                &allowlist.inspect().disabled_rules,
            );
            dep_vet::inspect::apply_trust_policy(&mut report, &allowlist.trust_policy());
            let output = if *json {
                dep_vet::report::render_inspection_json(&report)?
            } else {
                dep_vet::report::render_inspection_human(&report, use_color(cli))
            };
            print!("{output}");
            Ok(report.exit_code())
        }

        Command::Composer { package, json } => {
            let spec = PackageSpec::parse_composer(package)?;
            let mut report = auditor.audit_composer(&spec, now_seconds(), None)?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Maven { package, json } => {
            let spec = PackageSpec::parse_maven(package)?;
            let mut report = auditor.audit_maven(&spec, now_seconds(), None)?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Nuget { package, json } => {
            let spec = PackageSpec::parse_nuget(package)?;
            let mut report = auditor.audit_nuget(&spec, now_seconds(), None)?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Gem { package, json } => {
            let spec = PackageSpec::parse_gem(package)?;
            let mut report = auditor.audit_gem(&spec, now_seconds(), None)?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Jsr { package, json } => {
            let spec = PackageSpec::parse_jsr(package)?;
            let mut report = auditor.audit_jsr(&spec, now_seconds(), None)?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Go { package, json } => {
            let spec = PackageSpec::parse_go(package)?;
            let mut report = auditor.audit_go(&spec, now_seconds(), None)?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Crates { package, json } => {
            let spec = PackageSpec::parse_crates(package)?;
            let mut report = auditor.audit_crates(&spec, now_seconds(), None)?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Pypi { package, json } => {
            let spec = PackageSpec::parse_pypi(package)?;
            // PyPI has no lockfile parser yet, so only the seed list applies.
            let mut report = auditor.audit_pypi(&spec, now_seconds(), None)?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Audit {
            lockfile: path,
            json,
            format,
            output,
        } => {
            let format = format.unwrap_or(if *json {
                OutputFormat::Json
            } else {
                OutputFormat::Human
            });
            run_audit(&auditor, &allowlist, path, format, output.as_deref(), cli)
        }

        Command::Update { check, json } => Ok(dep_vet::update::run(&http, *check, *json)),

        Command::Sbom {
            lockfile,
            format,
            output,
        } => {
            let path = match lockfile {
                Some(path) => path.clone(),
                None => lockfile::nearest(std::path::Path::new(".")).ok_or_else(|| {
                    anyhow::anyhow!("no package-lock.json found; pass a lockfile path")
                })?,
            };
            let lock_format = lockfile::detect(&path)?;
            let contents = lockfile::read(&path)?;
            let mut graph = None;
            let mut project = None;
            let mut checksums = std::collections::HashMap::new();
            if lock_format == lockfile::Format::Npm {
                let body = std::fs::read_to_string(&path)?;
                graph = dep_vet::graph::npm_from_package_lock(&body).ok();
                project = dep_vet::sbom::npm_project(&body);
                checksums = dep_vet::sbom::npm_checksums(&body);
            }
            let mut inventory = dep_vet::sbom::inventory(
                lock_format.ecosystem(),
                &contents,
                graph.as_ref(),
                project,
                &checksums,
            );
            if lock_format == lockfile::Format::Npm && inventory.edges.is_empty() {
                inventory
                    .notes
                    .push("no dependency relationships were readable".to_string());
            }
            let text = match format {
                SbomFormat::Cyclonedx => dep_vet::sbom::cyclonedx(
                    &inventory,
                    &path.display().to_string(),
                    now_seconds(),
                )?,
                SbomFormat::Spdx => {
                    dep_vet::sbom::spdx(&inventory, &path.display().to_string(), now_seconds())?
                }
            };
            if let Some(destination) = output {
                std::fs::write(destination, format!("{text}\n"))?;
                Ok(0)
            } else {
                emit(&text, 0)
            }
        }

        Command::Watch { lockfile } => {
            let path = match lockfile {
                Some(path) => path.clone(),
                None => lockfile::nearest(std::path::Path::new(".")).ok_or_else(|| {
                    anyhow::anyhow!("no package-lock.json found; pass a lockfile path")
                })?,
            };
            dep_vet::watch::watch(
                &path,
                || {
                    println!("watching {} (Ctrl-C to stop)", path.display());
                    if let Err(error) =
                        run_audit(&auditor, &allowlist, &path, OutputFormat::Human, None, cli)
                    {
                        eprintln!("dep-vet: {error}");
                    }
                },
                || {
                    println!("\n── change detected ──");
                    if let Err(error) =
                        run_audit(&auditor, &allowlist, &path, OutputFormat::Human, None, cli)
                    {
                        eprintln!("dep-vet: {error}");
                    }
                },
            )?;
            unreachable!("watch only returns on error")
        }

        Command::Tree {
            lockfile: path,
            json,
        } => {
            let path = match path {
                Some(path) => path.clone(),
                None => lockfile::nearest(std::path::Path::new(".")).ok_or_else(|| {
                    anyhow::anyhow!("no package-lock.json found; pass a lockfile path")
                })?,
            };
            if lockfile::detect(&path)? != lockfile::Format::Npm {
                anyhow::bail!(
                    "tree currently reads package-lock.json only; {} is not supported yet",
                    path.display()
                );
            }
            let body = std::fs::read_to_string(&path)?;
            let graph = dep_vet::graph::npm_from_package_lock(&body)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&graph)?);
            } else {
                print!(
                    "{}",
                    dep_vet::graph::render_tree(&graph, &path.display().to_string())
                );
            }
            Ok(0)
        }

        Command::Lock {
            lockfile: path,
            base,
            json,
        } => {
            let report = diff_lockfile(&auditor, &allowlist, path, base, true)?;
            let output = if *json {
                render_lock_json(&report)?
            } else {
                render_lock_human(&report, use_color(cli))
            };
            emit(&output, report.exit_code())
        }
    }
}

fn local_candidates(cli: &Cli) -> Vec<String> {
    if cli.no_local {
        return Vec::new();
    }
    lockfile::nearest(std::path::Path::new("."))
        .and_then(|path| lockfile::read(&path).ok())
        .map(|contents| {
            contents
                .packages
                .iter()
                .map(|package| package.name.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

struct Auditor {
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
    scorecard: Option<dep_vet::scorecard::ScorecardClient>,
    policy: dep_vet::allowlist::Policy,
}

impl Auditor {
    fn new(http: &Arc<HttpClient>, policy: &dep_vet::allowlist::Policy) -> Self {
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
            scorecard: Some(dep_vet::scorecard::ScorecardClient::from_env(Arc::clone(
                http,
            ))),
            policy: policy.clone(),
        }
    }

    /// Attach the OpenSSF Scorecard for the repository, when deps.dev has one.
    /// A miss stays `None`, which the report shows as not checked.
    fn attach_scorecard(&self, meta: &mut PackageMeta) {
        let Some(client) = &self.scorecard else {
            return;
        };
        if let Some(repository) = meta.repository.as_deref() {
            meta.scorecard = client.lookup(repository);
        }
    }

    /// The hook budget is 8 seconds; repository reputation is context, not the
    /// install decision, so `guard` does not spend that budget on it.
    fn skip_scorecard(&mut self) {
        self.scorecard = None;
    }

    fn audit_npm(
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
            dep_vet::signals::typosquat_candidate(&meta.name, Ecosystem::Npm, local)
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
    fn advisories_for(
        &self,
        ecosystem: Ecosystem,
        packages: &[lockfile::LockedPackage],
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
                    dep_vet::rubygems::osv_version(&package.version).to_string()
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
    fn downloads_for(
        &self,
        ecosystem: Ecosystem,
        packages: &[lockfile::LockedPackage],
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

    fn audit_composer(
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

    fn audit_maven(
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

    fn audit_nuget(
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

    fn audit_gem(
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

    fn audit_jsr(
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

    fn audit_go(
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

    fn audit_crates(
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

    fn audit_pypi(
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

fn run_guard_child(command: &str) -> (u8, Option<String>) {
    use std::io::Read as _;
    use std::process::{Command as Process, Stdio};

    let Ok(executable) = std::env::current_exe() else {
        return (3, None);
    };
    // The guard caps at the same boundary; do it before argv so a huge hook
    // input cannot hit E2BIG.
    let (command, _) = dep_vet::intent::cap_command(command);
    let mut child = Process::new(executable);
    // Pass the command on stdin: Windows caps a process command line at about
    // 32,767 characters, so a large command cannot be one argv element.
    child
        .args(["guard", "--check", "--json", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy();
        if key.starts_with("DEPVET_")
            && !matches!(key.as_ref(), "DEPVET_CACHE_DIR" | "DEPVET_DEBUG")
        {
            child.env_remove(key.as_ref());
        }
    }
    // Test seam: debug builds only. The hook otherwise ignores agent-settable
    // registry overrides, so `tests/cli.rs` must be able to point the child at
    // its local fake registry without weakening a release binary.
    if cfg!(debug_assertions)
        && let Some(test_base) = std::env::var_os("DEPVET_HOOK_TEST_BASE")
    {
        child
            .env("DEPVET_REGISTRY_BASE", &test_base)
            .env(
                "DEPVET_DOWNLOADS_BASE",
                format!("{}/downloads", test_base.to_string_lossy()),
            )
            .env("DEPVET_OSV_BASE", &test_base)
            .env("DEPVET_SCORECARD_BASE", &test_base)
            .env("DEPVET_EPSS_BASE", &test_base)
            .env(
                "DEPVET_KEV_BASE",
                format!("{}/kev.json", test_base.to_string_lossy()),
            )
            .env("DEPVET_NO_CACHE", "1")
            .env("DEPVET_ALLOW_INSECURE_BASES", "1");
    }
    let Ok(mut child) = child.spawn() else {
        return (3, None);
    };
    if let Some(mut input) = child.stdin.take() {
        use std::io::Write as _;
        let _ = input.write_all(command.as_bytes());
        // Dropping closes the pipe so the child sees EOF.
    }
    // Drain stdout concurrently: a report larger than the pipe buffer would
    // otherwise block the child while we wait for it to exit, and the deadline
    // would turn a real verdict into "allow".
    let mut pipe = match child.stdout.take() {
        Some(pipe) => pipe,
        None => return (3, None),
    };
    let reader = std::thread::spawn(move || {
        let mut body = String::new();
        let _ = pipe.read_to_string(&mut body);
        body
    });

    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(dep_vet::hook::HOOK_BUDGET_SECONDS);
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                timed_out = true;
                break;
            }
            Err(_) => {
                let _ = child.kill();
                timed_out = true;
                break;
            }
        }
    }
    let status = child.wait().ok();
    let body = reader.join().unwrap_or_default();
    if timed_out {
        return (3, None);
    }
    (
        status.and_then(|status| status.code()).unwrap_or(3) as u8,
        Some(body),
    )
}

fn hook_settings_path(project: bool, user: bool) -> anyhow::Result<std::path::PathBuf> {
    if project && user {
        anyhow::bail!("choose either --project or --user");
    }
    if user {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .ok_or_else(|| anyhow::anyhow!("could not find the home directory"))?;
        return Ok(std::path::PathBuf::from(home)
            .join(".claude")
            .join("settings.json"));
    }
    Ok(std::path::PathBuf::from(".claude").join("settings.json"))
}

fn run_hook_install(
    target: &str,
    project: bool,
    user: bool,
    strict: bool,
    write: bool,
) -> anyhow::Result<u8> {
    if target != "claude" {
        anyhow::bail!("unknown hook target '{target}'; supported: claude");
    }
    let path = hook_settings_path(project, user)?;
    let before = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    let executable = std::env::current_exe()?;
    let command = dep_vet::hook::settings::command_line(&executable, strict);
    let after = dep_vet::hook::settings::merge(
        &path.display().to_string(),
        &before,
        &command,
        dep_vet::hook::settings::TIMEOUT_SECONDS,
    )?;
    println!(
        "{}\n{}",
        path.display(),
        dep_vet::hook::settings::diff(&before, &after)
    );
    if write {
        dep_vet::hook::settings::atomic_write(&path, &after)?;
        println!("wrote {}", path.display());
    } else {
        println!("dry run; pass --write to save");
    }
    Ok(0)
}

fn run_hook_uninstall(target: &str, project: bool, user: bool, write: bool) -> anyhow::Result<u8> {
    if target != "claude" {
        anyhow::bail!("unknown hook target '{target}'; supported: claude");
    }
    let path = hook_settings_path(project, user)?;
    let before = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let executable = std::env::current_exe()?;
    for strict in [false, true] {
        let command = dep_vet::hook::settings::command_line(&executable, strict);
        let after =
            dep_vet::hook::settings::remove(&path.display().to_string(), &before, &command)?;
        if after != before {
            println!(
                "{}\n{}",
                path.display(),
                dep_vet::hook::settings::diff(&before, &after)
            );
            if write {
                dep_vet::hook::settings::atomic_write(&path, &after)?;
                println!("wrote {}", path.display());
            } else {
                println!("dry run; pass --write to save");
            }
            return Ok(0);
        }
    }
    println!("no dep-vet hook in {}", path.display());
    Ok(0)
}

fn run_hook(strict: bool) -> anyhow::Result<u8> {
    use std::io::Read as _;
    let mut stdin = std::io::stdin().take(dep_vet::hook::MAX_STDIN_BYTES + 1);
    let mut body = String::new();
    let _ = stdin.read_to_string(&mut body);
    let Some(command) = dep_vet::hook::read_command(&body) else {
        return Ok(0);
    };
    let (exit_code, guard_json) = run_guard_child(&command);
    if exit_code == 3 && !strict && std::env::var_os("DEPVET_DEBUG").is_some() {
        for note in dep_vet::hook::notes(guard_json.as_deref()) {
            eprintln!("dep-vet hook: not checked: {note}");
        }
    }
    let decision = dep_vet::hook::decide(exit_code, guard_json.as_deref(), strict);
    if let Some(output) = dep_vet::hook::render(&decision) {
        println!("{output}");
    }
    Ok(0)
}

fn audit_intent(
    auditor: &Auditor,
    ecosystem: Ecosystem,
    spec: &PackageSpec,
    now: i64,
) -> Result<PackageReport, String> {
    let result: Result<PackageReport, String> = match ecosystem {
        Ecosystem::Npm => auditor
            .audit_npm(spec, &[], now, None)
            .map_err(|error| error.to_string()),
        Ecosystem::Pypi => auditor
            .audit_pypi(spec, now, None)
            .map_err(|error| error.to_string()),
        Ecosystem::CratesIo => auditor
            .audit_crates(spec, now, None)
            .map_err(|error| error.to_string()),
        Ecosystem::Go => auditor
            .audit_go(spec, now, None)
            .map_err(|error| error.to_string()),
        Ecosystem::Jsr => auditor
            .audit_jsr(spec, now, None)
            .map_err(|error| error.to_string()),
        Ecosystem::RubyGems => auditor
            .audit_gem(spec, now, None)
            .map_err(|error| error.to_string()),
        Ecosystem::NuGet => auditor
            .audit_nuget(spec, now, None)
            .map_err(|error| error.to_string()),
        Ecosystem::Maven => auditor
            .audit_maven(spec, now, None)
            .map_err(|error| error.to_string()),
        Ecosystem::Composer => auditor
            .audit_composer(spec, now, None)
            .map_err(|error| error.to_string()),
    };
    result
}

fn audit_specs(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    parsed: &dep_vet::intent::ParseOutcome,
) -> (Vec<PackageReport>, Vec<String>) {
    let specs: Vec<(Ecosystem, PackageSpec)> = parsed
        .intents
        .iter()
        .flat_map(|intent| {
            intent
                .specs
                .iter()
                .cloned()
                .map(move |spec| (intent.ecosystem, spec))
        })
        .collect();
    let now = now_seconds();
    let mut packages = Vec::new();
    let mut errors = Vec::new();
    for batch in specs.chunks(MAX_CONCURRENT_AUDITS) {
        let outcomes: Vec<Result<PackageReport, String>> = std::thread::scope(|scope| {
            let handles: Vec<_> = batch
                .iter()
                .map(|(ecosystem, spec)| {
                    scope.spawn(move || audit_intent(auditor, *ecosystem, spec, now))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| Err("audit thread panicked".to_string()))
                })
                .collect()
        });
        for outcome in outcomes {
            match outcome {
                Ok(report) => packages.push(report),
                Err(error) => errors.push(error),
            }
        }
    }
    for report in &mut packages {
        allowlist.apply(report);
    }
    (packages, errors)
}

fn run_mcp(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    print_config: bool,
) -> anyhow::Result<u8> {
    if print_config {
        let executable = std::env::current_exe()?;
        let path = executable.display().to_string();
        let snippet = serde_json::json!({
            "mcpServers": {
                "dep-vet": {"command": path, "args": ["mcp"]}
            }
        });
        println!("{}", serde_json::to_string_pretty(&snippet)?);
        println!();
        println!("claude mcp add dep-vet -- {path} mcp");
        return Ok(0);
    }
    let stdin = io::stdin();
    let stdout = io::stdout();
    dep_vet::mcp::serve(stdin.lock(), &mut stdout.lock(), |name, arguments| {
        mcp_call(auditor, allowlist, name, arguments)
    })?;
    Ok(0)
}

fn tool_result(structured: serde_json::Value, text: String) -> serde_json::Value {
    serde_json::json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "isError": false
    })
}

fn package_summary(report: &PackageReport) -> String {
    let verdict = report
        .findings
        .iter()
        .map(|finding| finding.severity)
        .chain(report.advisories.iter().map(|advisory| advisory.severity))
        .max()
        .unwrap_or(dep_vet::model::Severity::Info);
    let mut lines = vec![format!(
        "{} {}@{}: {} (exit {})",
        report.name,
        report.ecosystem,
        report.version,
        verdict.label().to_ascii_lowercase(),
        verdict.exit_code()
    )];
    for finding in report.findings.iter().take(3) {
        let url = finding
            .evidence
            .iter()
            .find_map(|evidence| evidence.url.clone())
            .unwrap_or_default();
        lines.push(format!(
            "- [{}] {} ({}) — {url}",
            finding.severity.label(),
            finding.title,
            finding.id
        ));
    }
    for advisory in report.advisories.iter().take(3) {
        lines.push(format!(
            "- [{}] {} — https://osv.dev/vulnerability/{}",
            advisory.severity.label(),
            advisory.summary,
            advisory.id
        ));
    }
    if !report.not_checked.is_empty() {
        lines.push(format!("not checked: {}", report.not_checked.join(", ")));
    }
    lines.push("Direct packages only; transitive dependencies were not checked.".to_string());
    let mut text = lines.join("\n");
    if text.len() > 20_000 {
        text.truncate(20_000);
        text.push_str("\n_truncated_");
    }
    text
}

fn mcp_call(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    name: &str,
    arguments: &serde_json::Value,
) -> dep_vet::mcp::ToolResult {
    match name {
        "vet_package" => {
            let ecosystem = arguments["ecosystem"]
                .as_str()
                .ok_or((-32602, "ecosystem is required".to_string()))
                .and_then(|value| {
                    inspect_ecosystem(value).map_err(|error| (-32602, error.to_string()))
                })?;
            let package = arguments["name"]
                .as_str()
                .ok_or((-32602, "name is required".to_string()))?;
            let version = arguments["version"].as_str();
            let raw = match version {
                Some(version) => {
                    let separator = if ecosystem == dep_vet::model::Ecosystem::Pypi {
                        "=="
                    } else {
                        "@"
                    };
                    format!("{package}{separator}{version}")
                }
                None => package.to_string(),
            };
            let spec =
                inspect_spec(ecosystem, &raw).map_err(|error| (-32602, error.to_string()))?;
            let mut report = audit_intent(auditor, ecosystem, &spec, now_seconds())
                .map_err(|error| (-32603, error))?;
            allowlist.apply(&mut report);
            let text = package_summary(&report);
            let guard = dep_vet::guard::GuardReport {
                command: String::new(),
                parse: dep_vet::intent::ParseOutcome::default(),
                packages: vec![report],
                errors: Vec::new(),
            };
            let structured: serde_json::Value =
                serde_json::from_str(&guard.to_json()).unwrap_or_else(|_| serde_json::json!({}));
            Ok(tool_result(structured, text))
        }
        "vet_command" => {
            let command = arguments["command"]
                .as_str()
                .ok_or((-32602, "command is required".to_string()))?;
            if command.len() > dep_vet::intent::MAX_COMMAND_BYTES {
                return Err((-32602, "command is too large".to_string()));
            }
            let parsed = dep_vet::intent::parse(command);
            let (packages, errors) = audit_specs(auditor, allowlist, &parsed);
            let report = dep_vet::guard::GuardReport {
                command: command.to_string(),
                parse: parsed,
                packages,
                errors,
            };
            let structured: serde_json::Value =
                serde_json::from_str(&report.to_json()).unwrap_or_else(|_| serde_json::json!({}));
            Ok(tool_result(structured, report.to_human()))
        }
        "vet_lockfile_change" => {
            let lockfile = arguments["lockfile"]
                .as_str()
                .ok_or((-32602, "lockfile is required".to_string()))?;
            let base = arguments["base"].as_str().unwrap_or("HEAD");
            run_mcp_lockfile(auditor, allowlist, lockfile, base)
        }
        _ => Err((-32602, format!("unknown tool '{name}'"))),
    }
}

fn mcp_lockfile_path(input: &str) -> Result<std::path::PathBuf, String> {
    let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
    let cwd = cwd.canonicalize().map_err(|error| error.to_string())?;
    let candidate = std::path::Path::new(input);
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        cwd.join(candidate)
    };
    let resolved = joined.canonicalize().map_err(|error| error.to_string())?;
    if !resolved.starts_with(&cwd) {
        return Err("lockfile path is outside the working directory".to_string());
    }
    if !resolved.is_file() {
        return Err("lockfile is not a regular file".to_string());
    }
    Ok(resolved)
}

fn run_mcp_lockfile(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    lockfile: &str,
    base: &str,
) -> dep_vet::mcp::ToolResult {
    let path = mcp_lockfile_path(lockfile).map_err(|error| (-32602, error))?;
    let report = diff_lockfile(auditor, allowlist, &path, base, false)
        .map_err(|error| (-32603, error.to_string()))?;
    let intents: Vec<serde_json::Value> = report
        .new_packages
        .iter()
        .map(|package| {
            serde_json::json!({
                "ecosystem": package.ecosystem.to_string(),
                "kind": "install",
                "specs": [{
                    "name": package.name,
                    "version": package.version,
                }],
                "lockfile": null,
            })
        })
        .collect();
    let errors: Vec<String> = report
        .errors
        .iter()
        .map(|error| format!("{}: {}", error.package, error.message))
        .collect();
    let structured = serde_json::json!({
        "command": format!("lockfile change: {lockfile} vs {base}"),
        "intents": intents,
        "lockfile": report.lockfile,
        "base": report.base,
        "packages": report.new_packages,
        "errors": errors,
        "error_details": &report.errors,
        "notes": report.notes,
        "verdict": report.verdict().label().to_ascii_lowercase(),
        "exit_code": report.exit_code(),
        "unofficial_registry": dep_vet::netpolicy::insecure_active(),
    });
    let mut result = tool_result(
        structured,
        dep_vet::report::render_lock_human(&report, false),
    );
    if report.exit_code() == 3 {
        result["isError"] = serde_json::json!(true);
    }
    Ok(result)
}

fn run_guard(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    check: bool,
    json: bool,
    command: &str,
) -> anyhow::Result<u8> {
    let parsed = dep_vet::intent::parse(command);
    let specs: Vec<(Ecosystem, PackageSpec)> = parsed
        .intents
        .iter()
        .flat_map(|intent| {
            intent
                .specs
                .iter()
                .cloned()
                .map(move |spec| (intent.ecosystem, spec))
        })
        .collect();

    let mut packages = Vec::new();
    let mut errors = Vec::new();
    if check {
        let now = now_seconds();
        for batch in specs.chunks(MAX_CONCURRENT_AUDITS) {
            let outcomes: Vec<Result<PackageReport, String>> = std::thread::scope(|scope| {
                let handles: Vec<_> = batch
                    .iter()
                    .map(|(ecosystem, spec)| {
                        scope.spawn(move || audit_intent(auditor, *ecosystem, spec, now))
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|handle| {
                        handle
                            .join()
                            .unwrap_or_else(|_| Err("audit thread panicked".to_string()))
                    })
                    .collect()
            });
            for outcome in outcomes {
                match outcome {
                    Ok(report) => packages.push(report),
                    Err(error) => errors.push(error),
                }
            }
        }
        for report in &mut packages {
            allowlist.apply(report);
        }
    }

    let report = dep_vet::guard::GuardReport {
        command: command.to_string(),
        parse: parsed,
        packages,
        errors,
    };
    let output = if json {
        report.to_json()
    } else {
        report.to_human()
    };
    emit(&output, report.exit_code())
}

fn run_audit(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    path: &std::path::Path,
    format: OutputFormat,
    destination: Option<&std::path::Path>,
    cli: &Cli,
) -> anyhow::Result<u8> {
    let lock_format = lockfile::detect(path)?;
    let contents = lockfile::read(path)?;
    // No tree context: every package would otherwise look suspicious
    // to every other one. The seed list is the comparison set.
    let now = now_seconds();
    let (mut reports, mut errors) = audit_packages(
        auditor,
        lock_format.ecosystem(),
        &contents.packages,
        &[],
        now,
        true,
    );
    let (jsr_reports, jsr_errors) =
        audit_packages(auditor, Ecosystem::Jsr, &contents.jsr, &[], now, true);
    reports.extend(jsr_reports);
    errors.extend(jsr_errors);
    errors.extend(skipped_errors(&contents));
    attach_dependency_paths(lock_format, path, &mut reports);
    for report in &mut reports {
        allowlist.apply(report);
    }
    let report = AuditReport {
        lockfile: path.display().to_string(),
        packages: reports,
        errors,
        notes: contents.notes,
    };
    let output = match format {
        OutputFormat::Human => render_audit_human(&report, use_color(cli)),
        OutputFormat::Json => render_audit_json(&report)?,
        OutputFormat::Sarif => dep_vet::sarif::render(&report)?,
    };
    if let Some(path) = destination {
        std::fs::write(path, format!("{output}\n"))?;
        return Ok(report.exit_code());
    }
    emit(&output, report.exit_code())
}

/// Add the root-to-package chains the lockfile already encodes. A format with
/// no graph, or a graph that cannot be read, leaves reports without paths
/// rather than inventing one.
fn attach_dependency_paths(
    format: lockfile::Format,
    path: &std::path::Path,
    reports: &mut [PackageReport],
) {
    if format != lockfile::Format::Npm || reports.is_empty() {
        return;
    }
    let Ok(body) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(graph) = dep_vet::graph::npm_from_package_lock(&body) else {
        return;
    };
    dep_vet::graph::attach_dependency_paths(&graph, reports);
}

/// Shared differential lockfile audit for the CLI and MCP. Keeping one
/// implementation is what makes JSR entries, notes, skipped entries, and
/// dependency paths identical on both surfaces.
fn diff_lockfile(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    path: &std::path::Path,
    base: &str,
    allow_progress: bool,
) -> anyhow::Result<LockReport> {
    let format = lockfile::detect(path)?;
    let ecosystem = format.ecosystem();
    let current = lockfile::read(path)?;
    let base_contents = lockfile::at_ref(path, base)?;
    let added = lockfile::added(&current.packages, &base_contents.packages);
    let local: Vec<String> = if ecosystem == Ecosystem::Npm {
        base_contents
            .packages
            .iter()
            .map(|package| package.name.to_ascii_lowercase())
            .collect()
    } else {
        Vec::new()
    };

    let now = now_seconds();
    let (mut new_packages, mut errors) =
        audit_packages(auditor, ecosystem, &added, &local, now, allow_progress);
    let added_jsr = lockfile::added(&current.jsr, &base_contents.jsr);
    let (jsr_reports, jsr_errors) = audit_packages(
        auditor,
        Ecosystem::Jsr,
        &added_jsr,
        &[],
        now,
        allow_progress,
    );
    new_packages.extend(jsr_reports);
    errors.extend(jsr_errors);
    attach_dependency_paths(format, path, &mut new_packages);
    errors.extend(skipped_errors(&current));
    for report in &mut new_packages {
        allowlist.apply(report);
    }

    let mut notes: Vec<String> = base_contents
        .notes
        .iter()
        .map(|note| format!("base: {note}"))
        .collect();
    notes.extend(current.notes);

    Ok(LockReport {
        lockfile: path.display().to_string(),
        base: base.to_string(),
        new_packages,
        errors,
        notes,
    })
}

fn skipped_errors(contents: &lockfile::LockContents) -> Vec<LockFetchError> {
    contents
        .skipped
        .iter()
        .map(|(entry, reason)| LockFetchError {
            package: entry.clone(),
            message: reason.clone(),
        })
        .collect()
}

fn inspect_ecosystem(value: &str) -> anyhow::Result<Ecosystem> {
    Ok(match value.to_ascii_lowercase().as_str() {
        "npm" => Ecosystem::Npm,
        "pypi" => Ecosystem::Pypi,
        "crates" => Ecosystem::CratesIo,
        "go" => Ecosystem::Go,
        "jsr" => Ecosystem::Jsr,
        "gem" | "rubygems" => Ecosystem::RubyGems,
        "nuget" => Ecosystem::NuGet,
        "maven" => Ecosystem::Maven,
        "composer" => Ecosystem::Composer,
        other => anyhow::bail!("unknown ecosystem '{other}'"),
    })
}

fn inspect_spec(ecosystem: Ecosystem, input: &str) -> anyhow::Result<PackageSpec> {
    Ok(match ecosystem {
        Ecosystem::Npm => PackageSpec::parse(input)?,
        Ecosystem::Pypi => PackageSpec::parse_pypi(input)?,
        Ecosystem::CratesIo => PackageSpec::parse_crates(input)?,
        Ecosystem::Go => PackageSpec::parse_go(input)?,
        Ecosystem::Jsr => PackageSpec::parse_jsr(input)?,
        Ecosystem::RubyGems => PackageSpec::parse_gem(input)?,
        Ecosystem::NuGet => PackageSpec::parse_nuget(input)?,
        Ecosystem::Maven => PackageSpec::parse_maven(input)?,
        Ecosystem::Composer => PackageSpec::parse_composer(input)?,
    })
}

fn spec_for(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> Result<PackageSpec, dep_vet::model::SpecError> {
    match ecosystem {
        Ecosystem::Npm => PackageSpec::parse(&format!("{name}@{version}")),
        Ecosystem::Pypi => PackageSpec::parse_pypi(&format!("{name}=={version}")),
        Ecosystem::CratesIo => PackageSpec::parse_crates(&format!("{name}@{version}")),
        Ecosystem::Go => PackageSpec::parse_go(&format!("{name}@{version}")),
        Ecosystem::Jsr => PackageSpec::parse_jsr(&format!("{name}@{version}")),
        Ecosystem::RubyGems => PackageSpec::parse_gem(&format!("{name}@{version}")),
        Ecosystem::NuGet => PackageSpec::parse_nuget(&format!("{name}@{version}")),
        Ecosystem::Maven => PackageSpec::parse_maven(&format!("{name}@{version}")),
        Ecosystem::Composer => PackageSpec::parse_composer(&format!("{name}@{version}")),
    }
}

fn audit_packages(
    auditor: &Auditor,
    ecosystem: Ecosystem,
    packages: &[lockfile::LockedPackage],
    local: &[String],
    now: i64,
    allow_progress: bool,
) -> (Vec<PackageReport>, Vec<LockFetchError>) {
    let mut reports = Vec::new();
    let mut errors = Vec::new();
    // A long tree audit looks frozen without this; pipes and CI stay silent,
    // including CI runners that allocate a pseudo-TTY.
    let draw = allow_progress
        && dep_vet::progress::should_draw(
            io::stderr().is_terminal(),
            std::env::var_os("CI").is_some(),
            std::env::var("TERM").is_ok_and(|term| term == "dumb"),
        );
    let mut progress = dep_vet::progress::Progress::new(packages.len(), draw);

    // One OSV batch and one downloads batch for the whole tree. Only names
    // that pass the same validation as the per-package path may become URLs.
    let mut validated: Vec<(usize, lockfile::LockedPackage)> = Vec::new();
    for (index, package) in packages.iter().enumerate() {
        if spec_for(ecosystem, &package.name, &package.version).is_ok() {
            validated.push((index, package.clone()));
        }
    }
    let valid_packages: Vec<lockfile::LockedPackage> = validated
        .iter()
        .map(|(_, package)| package.clone())
        .collect();
    let lists = auditor.advisories_for(ecosystem, &valid_packages);
    let counts = auditor.downloads_for(ecosystem, &valid_packages);
    let mut advisories = vec![None; packages.len()];
    let mut downloads = vec![None; packages.len()];
    for ((index, _), list) in validated.iter().zip(lists) {
        advisories[*index] = list;
    }
    for ((index, _), count) in validated.iter().zip(counts) {
        downloads[*index] = count;
    }

    let concurrency = if ecosystem == Ecosystem::Maven {
        MAVEN_CONCURRENCY
    } else {
        MAX_CONCURRENT_AUDITS
    };
    for (chunk_index, batch) in packages.chunks(concurrency).enumerate() {
        let outcomes: Vec<Result<PackageReport, LockFetchError>> = std::thread::scope(|scope| {
            let handles: Vec<_> = batch
                .iter()
                .enumerate()
                .map(|(offset, package)| {
                    let index = chunk_index * concurrency + offset;
                    let pre = Pre {
                        downloads: downloads.get(index).copied().flatten(),
                        advisories: advisories.get(index).and_then(Option::as_ref),
                    };
                    (
                        package,
                        scope.spawn(move || {
                            // Lockfile contents are still input: validate
                            // before they become a URL.
                            let spec = spec_for(ecosystem, &package.name, &package.version)
                                .map_err(|error| LockFetchError {
                                    package: package.spec(),
                                    message: error.to_string(),
                                })?;
                            let audited = match ecosystem {
                                Ecosystem::Npm => auditor
                                    .audit_npm(&spec, local, now, Some(pre))
                                    .map_err(|e| e.to_string()),
                                Ecosystem::Pypi => auditor
                                    .audit_pypi(&spec, now, Some(pre))
                                    .map_err(|e| e.to_string()),
                                Ecosystem::CratesIo => auditor
                                    .audit_crates(&spec, now, Some(pre))
                                    .map_err(|e| e.to_string()),
                                Ecosystem::Go => auditor
                                    .audit_go(&spec, now, Some(pre))
                                    .map_err(|e| e.to_string()),
                                Ecosystem::Jsr => auditor
                                    .audit_jsr(&spec, now, Some(pre))
                                    .map_err(|e| e.to_string()),
                                Ecosystem::RubyGems => auditor
                                    .audit_gem(&spec, now, Some(pre))
                                    .map_err(|e| e.to_string()),
                                Ecosystem::NuGet => auditor
                                    .audit_nuget(&spec, now, Some(pre))
                                    .map_err(|e| e.to_string()),
                                Ecosystem::Maven => auditor
                                    .audit_maven(&spec, now, Some(pre))
                                    .map_err(|e| e.to_string()),
                                Ecosystem::Composer => auditor
                                    .audit_composer(&spec, now, Some(pre))
                                    .map_err(|e| e.to_string()),
                            };
                            audited.map_err(|message| LockFetchError {
                                package: package.spec(),
                                message,
                            })
                        }),
                    )
                })
                .collect();

            handles
                .into_iter()
                .map(|(package, handle)| {
                    handle.join().unwrap_or_else(|_| {
                        Err(LockFetchError {
                            package: package.spec(),
                            message: "audit worker panicked".to_string(),
                        })
                    })
                })
                .collect()
        });

        for outcome in outcomes {
            match outcome {
                Ok(report) => reports.push(report),
                // One unpublished dependency must not hide the rest.
                Err(error) => errors.push(error),
            }
            progress.advance();
        }
    }
    drop(progress);

    (reports, errors)
}

fn emit_package(cli: &Cli, json: bool, report: &PackageReport) -> anyhow::Result<u8> {
    let output = if json {
        render_json(report)?
    } else {
        let mut report_text = render_human(report, use_color(cli));
        if dep_vet::netpolicy::insecure_active() {
            report_text = format!(
                "UNOFFICIAL REGISTRY: a development override is active; results are not production registry data\n\n{report_text}"
            );
        }
        // The wordmark is for humans at a terminal; pipes and CI get the
        // report alone.
        if io::stdout().is_terminal() {
            format!(
                "{}\n\n{}",
                dep_vet::branding::banner(use_color(cli)),
                report_text
            )
        } else {
            report_text
        }
    };
    emit(&output, report.exit_code())
}

fn emit(output: &str, code: u8) -> anyhow::Result<u8> {
    match write_stdout(output) {
        Ok(()) => Ok(code),
        // `dep-vet npm x | head` is not a failure.
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(code),
        Err(error) => Err(error.into()),
    }
}

fn write_stdout(output: &str) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(output.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

fn use_color(cli: &Cli) -> bool {
    if cli.no_color {
        return false;
    }
    if std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()) {
        return false;
    }
    if std::env::var_os("FORCE_COLOR").is_some() {
        return true;
    }
    io::stdout().is_terminal()
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}
