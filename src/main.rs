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
use dep_vet::osv::OsvClient;
use dep_vet::pypi::{PypiClient, PypiError};
use dep_vet::registry::{RegistryClient, RegistryError};
use dep_vet::report::{
    render_audit_human, render_audit_json, render_human, render_json, render_lock_human,
    render_lock_json,
};
use dep_vet::rubygems::{GemClient, GemError};
use dep_vet::signals;

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
        Command::Npm { package, json } => {
            let spec = PackageSpec::parse(package)?;
            // A lockfile in the current project is the same trusted-name list
            // the lock command uses; without one, the seed list stands alone.
            let local = local_candidates(cli);
            let mut report = auditor.audit_npm(&spec, &local, now_seconds())?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Composer { package, json } => {
            let spec = PackageSpec::parse_composer(package)?;
            let mut report = auditor.audit_composer(&spec, now_seconds())?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Maven { package, json } => {
            let spec = PackageSpec::parse_maven(package)?;
            let mut report = auditor.audit_maven(&spec, now_seconds())?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Nuget { package, json } => {
            let spec = PackageSpec::parse_nuget(package)?;
            let mut report = auditor.audit_nuget(&spec, now_seconds())?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Gem { package, json } => {
            let spec = PackageSpec::parse_gem(package)?;
            let mut report = auditor.audit_gem(&spec, now_seconds())?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Jsr { package, json } => {
            let spec = PackageSpec::parse_jsr(package)?;
            let mut report = auditor.audit_jsr(&spec, now_seconds())?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Go { package, json } => {
            let spec = PackageSpec::parse_go(package)?;
            let mut report = auditor.audit_go(&spec, now_seconds())?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Crates { package, json } => {
            let spec = PackageSpec::parse_crates(package)?;
            let mut report = auditor.audit_crates(&spec, now_seconds())?;
            allowlist.apply(&mut report);
            emit_package(cli, *json, &report)
        }

        Command::Pypi { package, json } => {
            let spec = PackageSpec::parse_pypi(package)?;
            // PyPI has no lockfile parser yet, so only the seed list applies.
            let mut report = auditor.audit_pypi(&spec, now_seconds())?;
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
    ) -> Result<PackageReport, RegistryError> {
        let meta = self.registry.fetch(spec)?;
        let downloads = self.registry.weekly_downloads(&meta.name);
        // Advisories are best effort: a failure is reported as an INFO
        // finding, never as "no known vulnerabilities".
        let advisories = self
            .osv
            .query(Ecosystem::Npm, &meta.name, &meta.version)
            .ok();
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

    fn audit_composer(&self, spec: &PackageSpec, now: i64) -> Result<PackageReport, ComposerError> {
        let meta = self.composer.fetch(spec)?;
        let advisories = self
            .osv
            .query(Ecosystem::Composer, &meta.name, &meta.version)
            .ok();
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

    fn audit_maven(&self, spec: &PackageSpec, now: i64) -> Result<PackageReport, MavenError> {
        let meta = self.maven.fetch(spec)?;
        // A review override means the package came from Google Maven, which
        // OSV's Maven index does not cover.
        let google_maven = meta.review_url.is_some();
        let advisories = self
            .osv
            .query(Ecosystem::Maven, &meta.name, &meta.version)
            .ok();
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

    fn audit_nuget(&self, spec: &PackageSpec, now: i64) -> Result<PackageReport, NugetError> {
        let meta = self.nuget.fetch(spec)?;
        let advisories = self
            .osv
            .query(Ecosystem::NuGet, &meta.name, &meta.version)
            .ok();
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

    fn audit_gem(&self, spec: &PackageSpec, now: i64) -> Result<PackageReport, GemError> {
        let meta = self.gems.fetch(spec)?;
        let advisories = self
            .osv
            .query(Ecosystem::RubyGems, &meta.name, &meta.version)
            .ok();
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

    fn audit_jsr(&self, spec: &PackageSpec, now: i64) -> Result<PackageReport, JsrError> {
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

    fn audit_go(&self, spec: &PackageSpec, now: i64) -> Result<PackageReport, GoError> {
        let meta = self.go.fetch(spec)?;
        let advisories = self
            .osv
            .query(Ecosystem::Go, &meta.name, &meta.version)
            .ok();
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

    fn audit_crates(&self, spec: &PackageSpec, now: i64) -> Result<PackageReport, CratesError> {
        let meta = self.crates.fetch(spec)?;
        let advisories = self
            .osv
            .query(Ecosystem::CratesIo, &meta.name, &meta.version)
            .ok();
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

    fn audit_pypi(&self, spec: &PackageSpec, now: i64) -> Result<PackageReport, PypiError> {
        let meta = self.pypi.fetch(spec)?;
        let advisories = self
            .osv
            .query(Ecosystem::Pypi, &meta.name, &meta.version)
            .ok();
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

    let concurrency = if ecosystem == Ecosystem::Maven {
        MAVEN_CONCURRENCY
    } else {
        MAX_CONCURRENT_AUDITS
    };
    for batch in packages.chunks(concurrency) {
        let outcomes: Vec<Result<PackageReport, LockFetchError>> = std::thread::scope(|scope| {
            let handles: Vec<_> = batch
                .iter()
                .map(|package| {
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
                                    .audit_npm(&spec, local, now)
                                    .map_err(|e| e.to_string()),
                                Ecosystem::Pypi => {
                                    auditor.audit_pypi(&spec, now).map_err(|e| e.to_string())
                                }
                                Ecosystem::CratesIo => {
                                    auditor.audit_crates(&spec, now).map_err(|e| e.to_string())
                                }
                                Ecosystem::Go => {
                                    auditor.audit_go(&spec, now).map_err(|e| e.to_string())
                                }
                                Ecosystem::Jsr => {
                                    auditor.audit_jsr(&spec, now).map_err(|e| e.to_string())
                                }
                                Ecosystem::RubyGems => {
                                    auditor.audit_gem(&spec, now).map_err(|e| e.to_string())
                                }
                                Ecosystem::NuGet => {
                                    auditor.audit_nuget(&spec, now).map_err(|e| e.to_string())
                                }
                                Ecosystem::Maven => {
                                    auditor.audit_maven(&spec, now).map_err(|e| e.to_string())
                                }
                                Ecosystem::Composer => auditor
                                    .audit_composer(&spec, now)
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
                "{}\n{}\n\n{}",
                dep_vet::branding::banner(use_color(cli)),
                dep_vet::branding::TAGLINE,
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
