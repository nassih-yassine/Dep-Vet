use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use dep_vet::cli::{Cli, Command};
use dep_vet::http::HttpClient;
use dep_vet::lockfile;
use dep_vet::model::{
    LockFetchError, LockReport, PackageReport, PackageSpec, Profile,
    TOOL_ERROR_EXIT_CODE as TOOL_ERROR,
};
use dep_vet::osv::OsvClient;
use dep_vet::registry::{RegistryClient, RegistryError};
use dep_vet::report::{render_human, render_json, render_lock_human, render_lock_json};
use dep_vet::signals;

/// Packages audited at once. Each one can fan out to a few OSV detail
/// requests, so keep the burst small.
const MAX_CONCURRENT_AUDITS: usize = 4;

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

    match &cli.command {
        Command::Npm { package, json } => {
            let spec = PackageSpec::parse(package)?;
            // A lockfile in the current project is the same trusted-name list
            // the lock command uses; without one, the seed list stands alone.
            let local = local_candidates(cli);
            let report = auditor.audit(&spec, &local, now_seconds())?;

            let output = if *json {
                render_json(&report)?
            } else {
                let report_text = render_human(&report, use_color(cli));
                // The wordmark is for humans at a terminal; pipes and CI get
                // the report alone.
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

        Command::Lock {
            lockfile: path,
            base,
            json,
        } => {
            let current = lockfile::read(path)?;
            let base_packages = lockfile::at_ref(path, base)?;
            let added = lockfile::added(&current, &base_packages);
            // What the user already trusts: typosquats of these names matter
            // more than distance to a seed list.
            let local: Vec<String> = base_packages
                .iter()
                .map(|package| package.name.to_ascii_lowercase())
                .collect();

            let now = now_seconds();
            let mut new_packages = Vec::new();
            let mut errors = Vec::new();

            // Borrow for the worker closures; `move` then captures a Copy reference.
            let auditor = &auditor;
            let local = &local;
            for batch in added.chunks(MAX_CONCURRENT_AUDITS) {
                let outcomes: Vec<Result<PackageReport, LockFetchError>> =
                    std::thread::scope(|scope| {
                        let handles: Vec<_> = batch
                            .iter()
                            .map(|package| {
                                (
                                    package,
                                    scope.spawn(move || {
                                        // Lockfile contents are still input:
                                        // validate before they become a URL.
                                        let spec = PackageSpec::new(
                                            package.name.clone(),
                                            Some(package.version.clone()),
                                        )
                                        .map_err(|error| LockFetchError {
                                            package: package.spec(),
                                            message: error.to_string(),
                                        })?;
                                        auditor.audit(&spec, local, now).map_err(|error| {
                                            LockFetchError {
                                                package: package.spec(),
                                                message: error.to_string(),
                                            }
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
                        Ok(report) => new_packages.push(report),
                        // One unpublished dependency must not hide the rest.
                        Err(error) => errors.push(error),
                    }
                }
            }

            let report = LockReport {
                lockfile: path.display().to_string(),
                base: base.clone(),
                new_packages,
                errors,
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
        .map(|packages| {
            packages
                .iter()
                .map(|package| package.name.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

struct Auditor {
    registry: RegistryClient,
    osv: OsvClient,
}

impl Auditor {
    fn new(http: &Arc<HttpClient>) -> Self {
        Self {
            registry: RegistryClient::from_env(Arc::clone(http)),
            osv: OsvClient::from_env(Arc::clone(http)),
        }
    }

    fn audit(
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
            .query(dep_vet::model::Ecosystem::Npm, &meta.name, &meta.version)
            .ok();
        Ok(signals::report(
            meta,
            downloads,
            advisories.as_ref(),
            local,
            Profile::NPM,
            now,
        ))
    }
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
