use std::io::{self};
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use commands::output::{emit, emit_package, now_seconds, use_color};
use dep_vet::auditor::Auditor;
use dep_vet::cli::{Cli, Command, OutputFormat, SbomFormat};
use dep_vet::http::HttpClient;
use dep_vet::lockfile;
use dep_vet::model::Ecosystem;
use dep_vet::model::{PackageSpec, TOOL_ERROR_EXIT_CODE as TOOL_ERROR};
use dep_vet::osv::OsvClient;
use dep_vet::registry::RegistryClient;
use dep_vet::report::{render_lock_human_with, render_lock_json_with};

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
    if cli.fail_on.is_some() && !cli.honours_fail_on() {
        eprintln!(
            "dep-vet: --fail-on applies to audit, lock, and the single-package checks; \
             this command keeps its own exit codes"
        );
        eprintln!("dep-vet: nothing was checked (this is not a verdict, exit {TOOL_ERROR}).");
        return ExitCode::from(TOOL_ERROR);
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

mod commands;

fn execute(cli: &Cli) -> anyhow::Result<u8> {
    // Hooks run on every Bash tool call and must never fail before they read
    // stdin; the guard child owns config and network errors.
    if let Command::Hook { action } = &cli.command {
        return match action {
            dep_vet::cli::HookAction::Claude { strict } => commands::hooks::run(*strict),
            dep_vet::cli::HookAction::Install {
                target,
                project,
                user,
                strict,
                write,
            } => commands::hooks::install(target, *project, *user, *strict, *write),
            dep_vet::cli::HookAction::Uninstall {
                target,
                project,
                user,
                write,
            } => commands::hooks::uninstall(target, *project, *user, *write),
        };
    }
    // Only the commands that fan out read the environment; an explicit
    // `--jobs` is still validated everywhere, because the user typed it.
    let requested = if cli.runs_audits() {
        std::env::var("DEPVET_JOBS").ok()
    } else {
        None
    };
    let available = std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(1);
    let jobs = dep_vet::jobs::resolve(cli.jobs, requested.as_deref(), available)
        .map_err(|error| anyhow::anyhow!(error))?;
    let allowlist = dep_vet::allowlist::Allowlist::load(cli.config.as_deref())?;
    // Routing may come from the repository; credentials only from the user's
    // own file. The router is built once and shared by every client.
    let user_registries =
        dep_vet::registries::load_user_config().map_err(|error| anyhow::anyhow!(error))?;
    let mut npm_default: Option<String> = None;
    let mut pypi_simple: Vec<String> = Vec::new();
    // pip's index replaces PyPI, the same way `pip install` uses it. Only read
    // when no DEPVET_PYPI_BASE override exists.
    if dep_vet::pip_config::enabled() && std::env::var_os("DEPVET_PYPI_BASE").is_none() {
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let discovery =
            dep_vet::pip_config::discover(|key| std::env::var(key).ok(), home.as_deref())
                .map_err(|error| anyhow::anyhow!(error))?;
        let default = "https://pypi.org/simple";
        let bases: Vec<String> = dep_vet::pip_config::indexes(&discovery, default)
            .into_iter()
            .filter(|base| base != default)
            .collect();
        if !bases.is_empty() {
            let probes: Vec<dep_vet::registries::RegistryEntry> = bases
                .iter()
                .enumerate()
                .map(|(index, url)| dep_vet::registries::RegistryEntry {
                    ecosystem: dep_vet::model::Ecosystem::Pypi,
                    r#match: format!("@pip-default-{index}"),
                    url: url.clone(),
                    auth: None,
                    probe_public: true,
                })
                .collect();
            dep_vet::registries::validate(
                &probes,
                std::env::var("DEPVET_ALLOW_INSECURE_BASES").is_ok_and(|value| value == "1"),
                true,
            )
            .map_err(|error| anyhow::anyhow!("pip config: {error}"))?;
            pypi_simple = bases;
        }
    }
    let mut router = dep_vet::registries::Router::new(allowlist.registries(), &user_registries);
    let mut npmrc_entries: Vec<dep_vet::registries::RegistryEntry> = Vec::new();
    if dep_vet::npmrc::enabled() {
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let cwd = std::env::current_dir().ok();
        let discovered = dep_vet::npmrc::discover(home.as_deref(), cwd.as_deref(), |key| {
            std::env::var(key).ok()
        });
        let entries =
            dep_vet::npmrc::as_entries(&discovered).map_err(|error| anyhow::anyhow!(error))?;
        npmrc_entries = entries.clone();
        router = router.extend_discovered(&entries);
        if let Some(base) = discovered.default_registry.clone() {
            let probe = dep_vet::registries::RegistryEntry {
                ecosystem: dep_vet::model::Ecosystem::Npm,
                r#match: "@npmrc-default".to_string(),
                url: base.clone(),
                auth: None,
                probe_public: true,
            };
            dep_vet::registries::validate(
                std::slice::from_ref(&probe),
                std::env::var("DEPVET_ALLOW_INSECURE_BASES").is_ok_and(|value| value == "1"),
                true,
            )
            .map_err(|error| anyhow::anyhow!("npmrc: {error}"))?;
            npm_default = Some(base);
        }
    }
    // Every host a route or discovered index may use, so netpolicy permits
    // exactly those and nothing else.
    let mut registry_bases: Vec<String> = allowlist
        .registries()
        .iter()
        .chain(user_registries.iter())
        .chain(npmrc_entries.iter())
        .map(|entry| entry.url.clone())
        .collect();
    registry_bases.extend(pypi_simple.iter().cloned());
    if let Some(base) = &npm_default {
        registry_bases.push(base.clone());
    }
    let http = Arc::new(HttpClient::from_env_with_registries(
        cli.no_cache,
        &registry_bases,
    ));
    let mut auditor = Auditor::new(&http, allowlist.policy(), &router, npm_default, pypi_simple);

    match &cli.command {
        Command::Hook { .. } => unreachable!("handled before config and network"),

        Command::Mcp { print_config } => {
            commands::mcp::run(&auditor, &allowlist, *print_config, jobs)
        }

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
            run_guard(&auditor, &allowlist, *check, *json, &command, jobs)
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
            let ecosystem = commands::audit::inspect_ecosystem(ecosystem)?;
            let from_spec = commands::audit::inspect_spec(ecosystem, from)?;
            let to_spec = commands::audit::inspect_spec(ecosystem, to)?;
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
            let ecosystem = commands::audit::inspect_ecosystem(ecosystem)?;
            let report = match ecosystem {
                Ecosystem::Npm => {
                    let http = Arc::new(HttpClient::from_env(cli.no_cache));
                    let registry = RegistryClient::from_env(http);
                    dep_vet::plan::plan(&registry, package)
                        .map_err(|error| anyhow::anyhow!(error))?
                }
                Ecosystem::Maven => {
                    let http = HttpClient::from_env(cli.no_cache);
                    if package.ends_with("pom.xml") || std::path::Path::new(package).is_file() {
                        dep_vet::maven_plan::plan_pom(&http, std::path::Path::new(package))
                            .map_err(|error| anyhow::anyhow!(error))?
                    } else {
                        dep_vet::maven_plan::plan(&http, package)
                            .map_err(|error| anyhow::anyhow!(error))?
                    }
                }
                _ => anyhow::bail!("plan supports npm and maven"),
            };
            let output = if *json {
                dep_vet::plan::render_json(&report)?
            } else {
                dep_vet::plan::render(&report)
            };
            emit(&output, report.exit_code())
        }

        Command::McpConfig { path, user, json } => {
            let report = dep_vet::mcp_config::scan_with(dep_vet::mcp_config::ScanOptions {
                path: path.clone(),
                user: *user,
            })?;
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
            let ecosystem = commands::audit::inspect_ecosystem(ecosystem)?;
            let spec = commands::audit::inspect_spec(ecosystem, package)?;
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
            commands::audit::run_audit(
                &auditor,
                &allowlist,
                path,
                format,
                output.as_deref(),
                cli,
                jobs,
            )
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
                    if let Err(error) = commands::audit::run_audit(
                        &auditor,
                        &allowlist,
                        &path,
                        OutputFormat::Human,
                        None,
                        cli,
                        jobs,
                    ) {
                        eprintln!("dep-vet: {error}");
                    }
                },
                || {
                    println!("\n── change detected ──");
                    if let Err(error) = commands::audit::run_audit(
                        &auditor,
                        &allowlist,
                        &path,
                        OutputFormat::Human,
                        None,
                        cli,
                        jobs,
                    ) {
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
            let report =
                commands::audit::diff_lockfile(&auditor, &allowlist, path, base, true, jobs)?;
            let fail_on = cli.fail_threshold();
            let output = if *json {
                render_lock_json_with(&report, fail_on)?
            } else {
                render_lock_human_with(&report, use_color(cli), fail_on)
            };
            emit(&output, report.exit_code_with(fail_on))
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

fn run_guard(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    check: bool,
    json: bool,
    command: &str,
    jobs: usize,
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
        let outcomes = dep_vet::pool::run(
            specs.len(),
            jobs,
            |index| {
                let (ecosystem, spec) = &specs[index];
                commands::audit::audit_intent(auditor, *ecosystem, spec, now)
            },
            || {},
        );
        for outcome in outcomes {
            match outcome {
                Some(Ok(report)) => packages.push(report),
                Some(Err(error)) => errors.push(error),
                None => errors.push("audit worker panicked".to_string()),
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
