use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use dep_vet::cli::{Cli, Command};
use dep_vet::model::PackageSpec;
use dep_vet::registry::RegistryClient;
use dep_vet::report::{render_human, render_json};
use dep_vet::signals;

/// Operational failure (network, bad response, bad input). Distinct from
/// 0/1/2 so CI can tell "this package is risky" from "the check never ran".
const TOOL_ERROR: u8 = 3;

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
    match &cli.command {
        Command::Npm { package, json } => {
            let spec = PackageSpec::parse(package)?;
            let client = RegistryClient::from_env();
            let meta = client.fetch(&spec)?;
            let downloads = client.weekly_downloads(&meta.name);
            let report = signals::report(meta, downloads, now_seconds());

            let output = if *json {
                render_json(&report)?
            } else {
                render_human(&report, use_color(cli))
            };

            match write_stdout(&output) {
                Ok(()) => Ok(report.exit_code()),
                // `dep-vet npm x | head` is not a failure.
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(report.exit_code()),
                Err(error) => Err(error.into()),
            }
        }
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
