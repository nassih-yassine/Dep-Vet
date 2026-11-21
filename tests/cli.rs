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
        .args(["pypi", "requests"])
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
