use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use dep_vet::cli::{Cli, Command};
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
use dep_vet::registry::{RegistryClient, RegistryError};
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
    match execute(&cli) {
        Ok(code) => ExitCode::from(code),
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
    let http = Arc::new(HttpClient::from_env(cli.no_cache));
    let auditor = Auditor::new(&http);
    let allowlist = dep_vet::allowlist::Allowlist::load(cli.config.as_deref())?;

    match &cli.command {
        Command::Hook { action } => match action {
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
        },

        Command::Guard {
            check,
            json,
            command,
        } => run_guard(&auditor, &allowlist, *check, *json, &command.join(" ")),

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
            let report = dep_vet::inspect::build_diff(
                ecosystem,
                &from_spec.name,
                &from_spec,
                &to_spec,
                &old,
                &new,
                &allowlist.inspect().disabled_rules,
            );
            let output = if *json {
                dep_vet::report::render_diff_json(&report)?
            } else {
                dep_vet::report::render_diff_human(&report, use_color(cli))
            };
            print!("{output}");
            Ok(report.exit_code())
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
            let report = dep_vet::inspect::build_report(
                ecosystem,
                &spec,
                prepared,
                &allowlist.inspect().disabled_rules,
            );
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
        } => run_audit(&auditor, &allowlist, path, *json, cli),

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
                    if let Err(error) = run_audit(&auditor, &allowlist, &path, false, cli) {
                        eprintln!("dep-vet: {error}");
                    }
                },
                || {
                    println!("\n── change detected ──");
                    if let Err(error) = run_audit(&auditor, &allowlist, &path, false, cli) {
                        eprintln!("dep-vet: {error}");
                    }
                },
            )?;
            unreachable!("watch only returns on error")
        }

        Command::Lock {
            lockfile: path,
            base,
            json,
        } => {
            let format = lockfile::detect(path)?;
            let ecosystem = format.ecosystem();
            let current = lockfile::read(path)?;
            let base_contents = lockfile::at_ref(path, base)?;
            let added = lockfile::added(&current.packages, &base_contents.packages);
            // What the user already trusts: typosquats of these names matter
            // more than distance to a seed list. Only npm names are in a shape
            // the comparison can use.
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
                audit_packages(&auditor, ecosystem, &added, &local, now);
            let added_jsr = lockfile::added(&current.jsr, &base_contents.jsr);
            let (jsr_reports, jsr_errors) =
                audit_packages(&auditor, Ecosystem::Jsr, &added_jsr, &[], now);
            new_packages.extend(jsr_reports);
            errors.extend(jsr_errors);
            errors.extend(skipped_errors(&current));
            for report in &mut new_packages {
                allowlist.apply(report);
            }

            let report = LockReport {
                lockfile: path.display().to_string(),
                base: base.clone(),
                new_packages,
                errors,
                notes: current.notes,
            };
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
}

impl Auditor {
    fn new(http: &Arc<HttpClient>) -> Self {
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
        }
    }

    fn audit_npm(
        &self,
        spec: &PackageSpec,
        local: &[String],
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, RegistryError> {
        let mut meta = self.registry.fetch(spec)?;
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
        Ok(signals::report(
            meta,
            Ecosystem::Npm,
            downloads,
            advisories.as_ref(),
            local,
            Profile::NPM,
            now,
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
        let meta = self.composer.fetch(spec)?;
        let advisories = match pre {
            Some(pre) => pre.advisories.cloned(),
            None => self
                .osv
                .query(Ecosystem::Composer, &meta.name, &meta.version)
                .ok(),
        };
        Ok(signals::report(
            meta,
            Ecosystem::Composer,
            None,
            advisories.as_ref(),
            &[],
            Profile::COMPOSER,
            now,
        ))
    }

    fn audit_maven(
        &self,
        spec: &PackageSpec,
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, MavenError> {
        let meta = self.maven.fetch(spec)?;
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
        let mut report = signals::report(
            meta,
            Ecosystem::Maven,
            None,
            advisories.as_ref(),
            &[],
            Profile::MAVEN,
            now,
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
        let meta = self.nuget.fetch(spec)?;
        let advisories = match pre {
            Some(pre) => pre.advisories.cloned(),
            None => self
                .osv
                .query(Ecosystem::NuGet, &meta.name, &meta.version)
                .ok(),
        };
        Ok(signals::report(
            meta,
            Ecosystem::NuGet,
            None,
            advisories.as_ref(),
            &[],
            Profile::NUGET,
            now,
        ))
    }

    fn audit_gem(
        &self,
        spec: &PackageSpec,
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, GemError> {
        let meta = self.gems.fetch(spec)?;
        let advisories = match pre {
            Some(pre) => pre.advisories.cloned(),
            None => self
                .osv
                .query(Ecosystem::RubyGems, &meta.name, &meta.version)
                .ok(),
        };
        Ok(signals::report(
            meta,
            Ecosystem::RubyGems,
            None,
            advisories.as_ref(),
            &[],
            Profile::RUBYGEMS,
            now,
        ))
    }

    fn audit_jsr(
        &self,
        spec: &PackageSpec,
        now: i64,
        _pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, JsrError> {
        let meta = self.jsr.fetch(spec)?;
        Ok(signals::report(
            meta,
            Ecosystem::Jsr,
            None,
            None,
            &[],
            Profile::JSR,
            now,
        ))
    }

    fn audit_go(
        &self,
        spec: &PackageSpec,
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, GoError> {
        let meta = self.go.fetch(spec)?;
        let advisories = match pre {
            Some(pre) => pre.advisories.cloned(),
            None => self
                .osv
                .query(Ecosystem::Go, &meta.name, &meta.version)
                .ok(),
        };
        Ok(signals::report(
            meta,
            Ecosystem::Go,
            None,
            advisories.as_ref(),
            &[],
            Profile::GO,
            now,
        ))
    }

    fn audit_crates(
        &self,
        spec: &PackageSpec,
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, CratesError> {
        let meta = self.crates.fetch(spec)?;
        let advisories = match pre {
            Some(pre) => pre.advisories.cloned(),
            None => self
                .osv
                .query(Ecosystem::CratesIo, &meta.name, &meta.version)
                .ok(),
        };
        Ok(signals::report(
            meta,
            Ecosystem::CratesIo,
            None,
            advisories.as_ref(),
            &[],
            Profile::CRATES,
            now,
        ))
    }

    fn audit_pypi(
        &self,
        spec: &PackageSpec,
        now: i64,
        pre: Option<Pre<'_>>,
    ) -> Result<PackageReport, PypiError> {
        let meta = self.pypi.fetch(spec)?;
        let advisories = match pre {
            Some(pre) => pre.advisories.cloned(),
            None => self
                .osv
                .query(Ecosystem::Pypi, &meta.name, &meta.version)
                .ok(),
        };
        Ok(signals::report(
            meta,
            Ecosystem::Pypi,
            None,
            advisories.as_ref(),
            &[],
            Profile::PYPI,
            now,
        ))
    }
}

fn run_guard_child(command: &str) -> (u8, Option<String>) {
    use std::io::Read as _;
    use std::process::{Command as Process, Stdio};

    let Ok(executable) = std::env::current_exe() else {
        return (3, None);
    };
    let mut child = Process::new(executable);
    child
        .args(["guard", "--check", "--json", "--", command])
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
            .env("DEPVET_NO_CACHE", "1");
    }
    let Ok(mut child) = child.spawn() else {
        return (3, None);
    };
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
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(_) => return (3, None),
    };
    if timed_out {
        return (3, None);
    }
    let mut stdout = String::new();
    let mut reader = output.stdout.as_slice();
    let _ = reader.read_to_string(&mut stdout);
    (output.status.code().unwrap_or(3) as u8, Some(stdout))
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
    json: bool,
    cli: &Cli,
) -> anyhow::Result<u8> {
    let format = lockfile::detect(path)?;
    let contents = lockfile::read(path)?;
    // No tree context: every package would otherwise look suspicious
    // to every other one. The seed list is the comparison set.
    let now = now_seconds();
    let (mut reports, mut errors) =
        audit_packages(auditor, format.ecosystem(), &contents.packages, &[], now);
    let (jsr_reports, jsr_errors) =
        audit_packages(auditor, Ecosystem::Jsr, &contents.jsr, &[], now);
    reports.extend(jsr_reports);
    errors.extend(jsr_errors);
    errors.extend(skipped_errors(&contents));
    for report in &mut reports {
        allowlist.apply(report);
    }
    let report = AuditReport {
        lockfile: path.display().to_string(),
        packages: reports,
        errors,
        notes: contents.notes,
    };
    let output = if json {
        render_audit_json(&report)?
    } else {
        render_audit_human(&report, use_color(cli))
    };
    emit(&output, report.exit_code())
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
) -> (Vec<PackageReport>, Vec<LockFetchError>) {
    let mut reports = Vec::new();
    let mut errors = Vec::new();
    // A long tree audit looks frozen without this; pipes and CI stay silent,
    // including CI runners that allocate a pseudo-TTY.
    let draw = dep_vet::progress::should_draw(
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
        let report_text = render_human(report, use_color(cli));
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
