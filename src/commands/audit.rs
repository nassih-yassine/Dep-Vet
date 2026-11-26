//! The audit pipeline: per-package intent, the ordered worker pool, and the
//! differential lockfile report shared by `lock`, `watch`, and MCP.

use std::io::{self, IsTerminal as _};

use crate::commands::output::{emit, now_seconds, use_color};
use dep_vet::auditor::{Auditor, Pre};
use dep_vet::cli::Cli;
use dep_vet::cli::OutputFormat;
use dep_vet::lockfile;
use dep_vet::model::{
    AuditReport, Ecosystem, LockFetchError, LockReport, PackageReport, PackageSpec,
};
use dep_vet::report::{render_audit_human_with, render_audit_json_with};

pub fn audit_intent(
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

pub fn audit_specs(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    parsed: &dep_vet::intent::ParseOutcome,
    jobs: usize,
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
    let outcomes = dep_vet::pool::run(
        specs.len(),
        jobs,
        |index| {
            let (ecosystem, spec) = &specs[index];
            audit_intent(auditor, *ecosystem, spec, now)
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
    (packages, errors)
}

pub fn run_audit(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    path: &std::path::Path,
    format: OutputFormat,
    destination: Option<&std::path::Path>,
    cli: &Cli,
    jobs: usize,
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
        jobs,
    );
    let (jsr_reports, jsr_errors) =
        audit_packages(auditor, Ecosystem::Jsr, &contents.jsr, &[], now, true, jobs);
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
    let fail_on = cli.fail_threshold();
    let output = match format {
        OutputFormat::Human => render_audit_human_with(&report, use_color(cli), fail_on),
        OutputFormat::Json => render_audit_json_with(&report, fail_on)?,
        OutputFormat::Sarif => dep_vet::sarif::render_with(&report, fail_on)?,
    };
    if let Some(path) = destination {
        std::fs::write(path, format!("{output}\n"))?;
        return Ok(report.exit_code_with(fail_on));
    }
    emit(&output, report.exit_code_with(fail_on))
}

/// Add the root-to-package chains the lockfile already encodes. A format with
/// no graph, or a graph that cannot be read, leaves reports without paths
/// rather than inventing one.
pub fn attach_dependency_paths(
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
pub fn diff_lockfile(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    path: &std::path::Path,
    base: &str,
    allow_progress: bool,
    jobs: usize,
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
    let (mut new_packages, mut errors) = audit_packages(
        auditor,
        ecosystem,
        &added,
        &local,
        now,
        allow_progress,
        jobs,
    );
    let added_jsr = lockfile::added(&current.jsr, &base_contents.jsr);
    let (jsr_reports, jsr_errors) = audit_packages(
        auditor,
        Ecosystem::Jsr,
        &added_jsr,
        &[],
        now,
        allow_progress,
        jobs,
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

pub fn skipped_errors(contents: &lockfile::LockContents) -> Vec<LockFetchError> {
    contents
        .skipped
        .iter()
        .map(|(entry, reason)| LockFetchError {
            package: entry.clone(),
            message: reason.clone(),
        })
        .collect()
}

pub fn inspect_ecosystem(value: &str) -> anyhow::Result<Ecosystem> {
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

pub fn inspect_spec(ecosystem: Ecosystem, input: &str) -> anyhow::Result<PackageSpec> {
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

pub fn spec_for(
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

pub fn audit_packages(
    auditor: &Auditor,
    ecosystem: Ecosystem,
    packages: &[lockfile::LockedPackage],
    local: &[String],
    now: i64,
    allow_progress: bool,
    jobs: usize,
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

    // Maven Central rate-limits bursts, so its trees stay serial. Everything
    // else uses the caller's jobs; `jobs::resolve` already capped it.
    let concurrency = if ecosystem == Ecosystem::Maven {
        MAVEN_CONCURRENCY.min(jobs)
    } else {
        jobs
    };
    let outcomes = dep_vet::pool::run(
        packages.len(),
        concurrency,
        |index| {
            let package = &packages[index];
            let pre = Pre {
                downloads: downloads.get(index).copied().flatten(),
                advisories: advisories.get(index).and_then(Option::as_ref),
            };
            // Lockfile contents are still input: validate before they become a URL.
            let spec = spec_for(ecosystem, &package.name, &package.version).map_err(|error| {
                LockFetchError {
                    package: package.spec(),
                    message: error.to_string(),
                }
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
        },
        || progress.advance(),
    );
    drop(progress);

    // A panicking worker is reported per package, not as a lost slot.
    for (index, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            Some(Ok(report)) => reports.push(report),
            Some(Err(error)) => errors.push(error),
            None => errors.push(LockFetchError {
                package: packages[index].spec(),
                message: "audit worker panicked".to_string(),
            }),
        }
    }

    (reports, errors)
}

/// Maven Central answers 403 when it sees a burst of search requests, so tree
/// audits go one coordinate at a time. Google Maven is unaffected.
pub const MAVEN_CONCURRENCY: usize = 1;
