//! End-to-end tests: the real binary against a local fake registry.
//!
//! Nothing here touches the public npm registry. The server records the paths
//! it was asked for, so encoding and retry behaviour are observable.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use predicates::prelude::*;

struct MockRegistry {
    base: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockRegistry {
    fn start(routes: HashMap<String, (u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local port");
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);

        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(path) = read_path(&mut stream) else {
                    continue;
                };
                recorded.lock().unwrap().push(path.clone());
                let (status, body) = routes
                    .get(&path)
                    .cloned()
                    .unwrap_or_else(|| (404, "{\"error\":\"Not found\"}".to_string()));
                let reason = if status == 200 { "OK" } else { "Not Found" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        Self {
            base: format!("http://127.0.0.1:{port}"),
            requests,
        }
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
            .env("DEPVET_GO_BASE", &self.base)
            .env("DEPVET_NO_CACHE", "1")
            .env("NO_COLOR", "1");
        command
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn read_path(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > 64 * 1024 {
            return None;
        }
    }
    let text = String::from_utf8_lossy(&buffer);
    let first_line = text.lines().next()?;
    let path = first_line.split_whitespace().nth(1)?.to_string();
    Some(path)
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
        .stderr(predicate::str::contains("characters npm does not allow"));

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
        .args(["maven", "org.example:thing"])
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
        .stdout(predicate::str::contains(
            "dependency risk, checked before install",
        ))
        .stdout(predicate::str::contains("####"));
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
        .stdout(predicate::str::contains("dependency risk").not())
        .stdout(predicate::str::contains("INFO"));
}

const HIGH_ADVISORY: &str = r#"{"results":[{"vulns":[{"id":"GHSA-test-0001"}]}]}"#;

const HIGH_ADVISORY_DETAIL: &str = r#"{
    "id": "GHSA-test-0001",
    "summary": "test advisory for dep-vet",
    "aliases": ["CVE-2026-0001"],
    "database_specific": { "severity": "HIGH" }
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
        .stdout(predicate::str::contains("characters npm does not allow"));

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
        { "packagetype": "bdist_wheel", "upload_time": "2025-01-15T00:00:00" },
        { "packagetype": "sdist", "upload_time": "2025-01-15T00:00:00" }
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
        .stderr(predicate::str::contains("characters npm does not allow"));

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
    { "number": "3.2.9", "created_at": "2026-11-20T23:14:58.183Z", "platform": "ruby",
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
