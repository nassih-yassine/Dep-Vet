//! `dep-vet mcp`: the stdio server and its three tools. Tool logic reuses the
//! CLI pipeline; nothing here draws progress or touches stdout except JSON-RPC.

use std::io;

use crate::commands::output::now_seconds;
use dep_vet::auditor::Auditor;
use dep_vet::model::PackageReport;

pub fn run(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    print_config: bool,
    jobs: usize,
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
        mcp_call(auditor, allowlist, name, arguments, jobs)
    })?;
    Ok(0)
}

pub fn tool_result(structured: serde_json::Value, text: String) -> serde_json::Value {
    serde_json::json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "isError": false
    })
}

pub fn package_summary(report: &PackageReport) -> String {
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

pub fn mcp_call(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    name: &str,
    arguments: &serde_json::Value,
    jobs: usize,
) -> dep_vet::mcp::ToolResult {
    match name {
        "vet_package" => {
            let ecosystem = arguments["ecosystem"]
                .as_str()
                .ok_or((-32602, "ecosystem is required".to_string()))
                .and_then(|value| {
                    crate::commands::audit::inspect_ecosystem(value)
                        .map_err(|error| (-32602, error.to_string()))
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
            let spec = crate::commands::audit::inspect_spec(ecosystem, &raw)
                .map_err(|error| (-32602, error.to_string()))?;
            let mut report =
                crate::commands::audit::audit_intent(auditor, ecosystem, &spec, now_seconds())
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
            let (packages, errors) =
                crate::commands::audit::audit_specs(auditor, allowlist, &parsed, jobs);
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
            run_mcp_lockfile(auditor, allowlist, lockfile, base, jobs)
        }
        _ => Err((-32602, format!("unknown tool '{name}'"))),
    }
}

pub fn mcp_lockfile_path(input: &str) -> Result<std::path::PathBuf, String> {
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

pub fn run_mcp_lockfile(
    auditor: &Auditor,
    allowlist: &dep_vet::allowlist::Allowlist,
    lockfile: &str,
    base: &str,
    jobs: usize,
) -> dep_vet::mcp::ToolResult {
    let path = mcp_lockfile_path(lockfile).map_err(|error| (-32602, error))?;
    let report =
        crate::commands::audit::diff_lockfile(auditor, allowlist, &path, base, false, jobs)
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
