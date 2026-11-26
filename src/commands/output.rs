//! Stdout reporting and the two environment decisions every command shares:
//! colour and the current Unix time.

use std::io::{self, IsTerminal as _, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use dep_vet::cli::Cli;
use dep_vet::model::PackageReport;
use dep_vet::report::render_human_with;

pub fn emit_package(cli: &Cli, json: bool, report: &PackageReport) -> anyhow::Result<u8> {
    let fail_on = cli.fail_threshold();
    let output = if json {
        dep_vet::report::render_json_with(report, fail_on)?
    } else {
        let mut report_text = render_human_with(report, use_color(cli), fail_on);
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
    emit(&output, report.exit_code_with(fail_on))
}

pub fn emit(output: &str, code: u8) -> anyhow::Result<u8> {
    match write_stdout(output) {
        Ok(()) => Ok(code),
        // `dep-vet npm x | head` is not a failure.
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(code),
        Err(error) => Err(error.into()),
    }
}

pub fn write_stdout(output: &str) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(output.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

pub fn use_color(cli: &Cli) -> bool {
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

pub fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}
