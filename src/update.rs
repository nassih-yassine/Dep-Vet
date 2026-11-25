//! `dep-vet update`: report the latest release and the command for the channel
//! this binary came from.
//!
//! Nothing here changes a verdict. The command reads one GitHub API document,
//! compares versions, and prints guidance. Exit `0` means current, `1` means a
//! newer release exists (only with `--check`), `3` means the check failed.

use crate::http::HttpClient;
use semver::Version;
use std::path::Path;
use std::time::Duration;

/// Unauthenticated GitHub API root. `DEPVET_UPDATE_BASE` overrides it for tests.
pub const GITHUB_API: &str = "https://api.github.com";
const RELEASE_PATH: &str = "/repos/nassih-yassine/Dep-Vet/releases/latest";
/// Release URLs are only trusted under this prefix; anything else falls back.
const RELEASE_PREFIX: &str = "https://github.com/nassih-yassine/Dep-Vet/releases/";
const DEFAULT_RELEASE_URL: &str = "https://github.com/nassih-yassine/Dep-Vet/releases";
/// The latest release changes; a day-old answer would tell people to upgrade to
/// something older. Five minutes keeps the hammering down without lying.
const UPDATE_TTL_SECONDS: i64 = 5 * 60;
/// The passive hint is not a version answer the user asked for; one check a day
/// is enough, and it keeps an offline machine from retrying on every run.
pub const HINT_TTL_SECONDS: i64 = 24 * 60 * 60;
/// A failed hint is remembered for this long, so a blackholed network is paid
/// at most once per window.
pub const HINT_FAILURE_TTL_SECONDS: i64 = 6 * 60 * 60;
/// The hint may add at most this much time to an interactive command.
pub const HINT_TIMEOUT: Duration = Duration::from_secs(2);
const HINT_FAILED_KEY: &str = "update-hint-failed";

#[derive(Debug)]
pub enum UpdateError {
    Http(String),
    Parse(String),
    Version(String),
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateError::Http(message) => write!(formatter, "could not reach GitHub: {message}"),
            UpdateError::Parse(message) => write!(formatter, "unreadable release data: {message}"),
            UpdateError::Version(message) => write!(formatter, "unreadable version: {message}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Latest {
    pub version: Version,
    pub tag: String,
    pub url: String,
}

/// Compare two versions, tolerating a leading `v` on either side.
pub fn parse_version(raw: &str) -> Option<Version> {
    Version::parse(raw.trim().trim_start_matches('v')).ok()
}

/// True when `latest` is strictly newer than `current`.
pub fn is_newer(current: &str, latest: &str) -> Option<bool> {
    let current = parse_version(current)?;
    let latest = parse_version(latest)?;
    Some(latest > current)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Homebrew,
    Cargo,
    Npm,
    Scoop,
    Docker,
    Debian,
    Fedora,
    Arch,
    Alpine,
    Unknown,
}

impl Channel {
    pub fn label(self) -> &'static str {
        match self {
            Channel::Homebrew => "homebrew",
            Channel::Cargo => "cargo",
            Channel::Npm => "npm",
            Channel::Scoop => "scoop",
            Channel::Docker => "docker",
            Channel::Debian => "debian",
            Channel::Fedora => "fedora",
            Channel::Arch => "arch",
            Channel::Alpine => "alpine",
            Channel::Unknown => "unknown",
        }
    }

    /// The command that updates this channel. `None` means "no single command";
    /// print the release URL instead.
    pub fn command(self) -> Option<&'static str> {
        match self {
            Channel::Homebrew => Some("brew upgrade dep-vet"),
            Channel::Cargo => Some("cargo install dep-vet --locked --force"),
            Channel::Npm => Some("npm install --global @nassihyas/dep-vet@latest"),
            Channel::Scoop => Some("scoop update dep-vet"),
            Channel::Docker => Some("docker pull ghcr.io/nassih-yassine/dep-vet:latest"),
            Channel::Debian => Some("sudo apt update && sudo apt install --only-upgrade dep-vet"),
            Channel::Fedora => Some("sudo dnf upgrade dep-vet"),
            Channel::Arch => Some("yay -Syu dep-vet-bin"),
            Channel::Alpine => Some("sudo apk upgrade dep-vet"),
            Channel::Unknown => None,
        }
    }
}

/// Detect the install channel from the executable path, container marker, and
/// distro marker. Pure so every branch is testable.
pub fn detect_channel(executable: &Path, docker: bool, distro: Option<&str>) -> Channel {
    if docker {
        return Channel::Docker;
    }
    let path = executable.to_string_lossy().replace('\\', "/");
    if path.contains("/Cellar/")
        || path.contains("/home/linuxbrew/")
        || path.contains("/linuxbrew/")
    {
        return Channel::Homebrew;
    }
    if path.contains("/node_modules/") {
        return Channel::Npm;
    }
    if path.contains("/.cargo/bin/") || path.contains("/cargo/bin/") {
        return Channel::Cargo;
    }
    if path.contains("/scoop/apps/") {
        return Channel::Scoop;
    }
    match distro {
        Some("debian") => Channel::Debian,
        Some("fedora") => Channel::Fedora,
        Some("arch") => Channel::Arch,
        Some("alpine") => Channel::Alpine,
        _ => Channel::Unknown,
    }
}

/// Detected channel for the running binary.
pub fn current_channel() -> Channel {
    let executable = std::env::current_exe().unwrap_or_default();
    let docker = Path::new("/.dockerenv").exists();
    let distro = if Path::new("/etc/debian_version").exists() {
        Some("debian")
    } else if Path::new("/etc/fedora-release").exists() {
        Some("fedora")
    } else if Path::new("/etc/arch-release").exists() {
        Some("arch")
    } else if Path::new("/etc/alpine-release").exists() {
        Some("alpine")
    } else {
        None
    };
    detect_channel(&executable, docker, distro)
}

/// Accept a release URL only if it points at this repository's releases and
/// carries no control characters; otherwise use the known landing page.
pub fn release_url(raw: Option<&str>) -> String {
    match raw {
        Some(url)
            if url.starts_with(RELEASE_PREFIX)
                && !url.chars().any(|character| character.is_control()) =>
        {
            url.to_string()
        }
        _ => DEFAULT_RELEASE_URL.to_string(),
    }
}

fn api_base() -> String {
    // A test seam, not a feature: another host is only honoured under the same
    // gate as every other DEPVET_*_BASE override.
    let allowed = std::env::var("DEPVET_ALLOW_INSECURE_BASES").is_ok_and(|value| value == "1");
    if allowed
        && let Ok(base) = std::env::var("DEPVET_UPDATE_BASE")
        && !base.is_empty()
    {
        return base;
    }
    GITHUB_API.to_string()
}

fn latest_url() -> String {
    format!("{}{RELEASE_PATH}", api_base().trim_end_matches('/'))
}

fn parse_latest(body: &str) -> Result<Latest, UpdateError> {
    let document: serde_json::Value =
        serde_json::from_str(body).map_err(|error| UpdateError::Parse(error.to_string()))?;
    let tag = document
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| UpdateError::Parse("no tag_name".into()))?
        .to_string();
    let version = parse_version(&tag)
        .ok_or_else(|| UpdateError::Version(format!("tag {tag:?} is not a version")))?;
    let url = release_url(document.get("html_url").and_then(serde_json::Value::as_str));
    Ok(Latest { version, tag, url })
}

/// Fetch the latest release document for `dep-vet update` (5-minute cache).
pub fn check(http: &HttpClient) -> Result<Latest, UpdateError> {
    let body = http
        .get_with_ttl(&latest_url(), UPDATE_TTL_SECONDS)
        .map_err(|error| UpdateError::Http(error.to_string()))?;
    parse_latest(&body)
}

/// Fetch the latest release for the passive hint: 24-hour cache, one attempt,
/// two-second budget.
pub fn hint_check(http: &HttpClient) -> Result<Latest, UpdateError> {
    let body = http
        .get_with_deadline(&latest_url(), HINT_TTL_SECONDS, HINT_TIMEOUT)
        .map_err(|error| UpdateError::Http(error.to_string()))?;
    parse_latest(&body)
}

/// Pure gate for the passive hint: a human terminal, no CI, no opt-out.
pub fn should_hint(
    human_report: bool,
    stdout_tty: bool,
    stderr_tty: bool,
    exit_code: u8,
    env: impl Fn(&str) -> Option<String>,
) -> bool {
    if !human_report || !stdout_tty || !stderr_tty || exit_code > 1 {
        return false;
    }
    if env("CI").is_some()
        || env("DEPVET_NO_UPDATE_CHECK").is_some()
        || env("NO_UPDATE_NOTIFIER").is_some()
    {
        return false;
    }
    !env("TERM").is_some_and(|term| term == "dumb")
}

/// Print one line to stderr when a newer release exists. Never fails, never
/// changes the exit code, and never writes to stdout.
pub fn maybe_hint(cli: &crate::cli::Cli, exit_code: u8) {
    use std::io::IsTerminal as _;

    let human = should_hint(
        cli.human_report(),
        std::io::stdout().is_terminal(),
        std::io::stderr().is_terminal(),
        exit_code,
        |name| std::env::var(name).ok(),
    );
    if !human {
        return;
    }
    let http = HttpClient::from_env(false);
    if http.has_marker(HINT_FAILED_KEY, HINT_FAILURE_TTL_SECONDS) {
        return;
    }
    let Ok(latest) = hint_check(&http) else {
        http.put_marker(HINT_FAILED_KEY);
        return;
    };
    if is_newer(env!("CARGO_PKG_VERSION"), &latest.tag).unwrap_or(false) {
        println_ignoring_errors(&format!(
            "dep-vet: {} is available (you have {}); run `dep-vet update`",
            latest.version,
            env!("CARGO_PKG_VERSION")
        ));
    }
}

fn println_ignoring_errors(message: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "{message}");
}

/// Run the command and return the process exit code.
pub fn run(http: &HttpClient, check_only: bool, json: bool) -> u8 {
    let current = env!("CARGO_PKG_VERSION");
    let channel = current_channel();
    match check(http) {
        Ok(latest) => {
            let newer = is_newer(current, &latest.tag).unwrap_or(false);
            if json {
                let payload = serde_json::json!({
                    "current": current,
                    "latest": latest.version.to_string(),
                    "update_available": newer,
                    "channel": channel.label(),
                    "command": channel.command(),
                    "release_url": latest.url,
                });
                println!("{payload}");
            } else if newer {
                println!("dep-vet {current}");
                println!("latest   {}", latest.version);
                println!("channel  {}", channel.label());
                if let Some(command) = channel.command() {
                    println!("update   {command}");
                } else {
                    println!("update   download from {}", latest.url);
                }
                println!("release  {}", latest.url);
            } else {
                println!("dep-vet {current} is the latest release.");
            }
            if newer && check_only { 1 } else { 0 }
        }
        Err(error) => {
            eprintln!("dep-vet: update check failed: {error}");
            3
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tags_with_and_without_v() {
        assert_eq!(parse_version("v1.2.3").unwrap(), Version::new(1, 2, 3));
        assert_eq!(parse_version("1.2.3").unwrap(), Version::new(1, 2, 3));
        assert!(parse_version("release-1").is_none());
        assert!(parse_version("v1.2").is_none());
    }

    #[test]
    fn the_hint_has_its_own_bounded_windows() {
        assert_eq!(HINT_TTL_SECONDS, 24 * 60 * 60);
        assert_eq!(HINT_FAILURE_TTL_SECONDS, 6 * 60 * 60);
        assert_eq!(HINT_TIMEOUT, Duration::from_secs(2));
    }

    #[test]
    fn compares_versions() {
        assert_eq!(is_newer("0.13.3", "v0.13.4"), Some(true));
        assert_eq!(is_newer("0.13.3", "v0.13.3"), Some(false));
        assert_eq!(is_newer("0.13.3", "v0.13.2"), Some(false));
        assert_eq!(is_newer("0.13.3", "nonsense"), None);
    }

    #[test]
    fn detects_channels_from_paths() {
        let cases = [
            (
                "/home/linuxbrew/.linuxbrew/Cellar/dep-vet/0.1/bin/dep-vet",
                false,
                None,
                Channel::Homebrew,
            ),
            (
                "/opt/homebrew/Cellar/dep-vet/0.1/bin/dep-vet",
                false,
                None,
                Channel::Homebrew,
            ),
            (
                "/usr/lib/node_modules/@nassihyas/dep-vet/binaries/linux-x64/dep-vet",
                false,
                None,
                Channel::Npm,
            ),
            ("/home/me/.cargo/bin/dep-vet", false, None, Channel::Cargo),
            (
                "C:\\Users\\me\\scoop\\apps\\dep-vet\\current\\dep-vet.exe",
                false,
                None,
                Channel::Scoop,
            ),
            ("/usr/bin/dep-vet", false, Some("debian"), Channel::Debian),
            ("/usr/bin/dep-vet", false, Some("fedora"), Channel::Fedora),
            ("/usr/bin/dep-vet", false, Some("arch"), Channel::Arch),
            ("/usr/bin/dep-vet", false, Some("alpine"), Channel::Alpine),
            ("/usr/bin/dep-vet", true, Some("debian"), Channel::Docker),
            ("/tmp/dep-vet", false, None, Channel::Unknown),
        ];
        for (path, docker, distro, expected) in cases {
            assert_eq!(
                detect_channel(Path::new(path), docker, distro),
                expected,
                "{path}"
            );
        }
    }

    #[test]
    fn every_known_channel_but_unknown_has_a_command() {
        for channel in [
            Channel::Homebrew,
            Channel::Cargo,
            Channel::Npm,
            Channel::Scoop,
            Channel::Docker,
            Channel::Debian,
            Channel::Fedora,
            Channel::Arch,
            Channel::Alpine,
        ] {
            assert!(channel.command().is_some(), "{:?}", channel);
        }
        assert!(Channel::Unknown.command().is_none());
    }
}

#[cfg(test)]
mod hint_tests {
    use super::should_hint;

    fn env(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        move |name: &str| {
            owned
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn hints_only_on_a_human_terminal() {
        assert!(should_hint(true, true, true, 0, env(&[])));
        assert!(should_hint(true, true, true, 1, env(&[])));
        assert!(!should_hint(true, false, true, 0, env(&[])));
        assert!(!should_hint(true, true, false, 0, env(&[])));
        assert!(!should_hint(false, true, true, 0, env(&[])));
        assert!(!should_hint(true, true, true, 2, env(&[])));
        assert!(!should_hint(true, true, true, 3, env(&[])));
    }

    #[test]
    fn respects_every_opt_out() {
        assert!(!should_hint(true, true, true, 0, env(&[("CI", "1")])));
        assert!(!should_hint(
            true,
            true,
            true,
            0,
            env(&[("DEPVET_NO_UPDATE_CHECK", "1")])
        ));
        assert!(!should_hint(
            true,
            true,
            true,
            0,
            env(&[("NO_UPDATE_NOTIFIER", "1")])
        ));
        assert!(!should_hint(true, true, true, 0, env(&[("TERM", "dumb")])));
        assert!(should_hint(true, true, true, 0, env(&[("TERM", "xterm")])));
    }
}

#[cfg(test)]
mod url_tests {
    use super::{DEFAULT_RELEASE_URL, release_url};

    #[test]
    fn keeps_release_urls_from_this_repository() {
        let url = "https://github.com/nassih-yassine/Dep-Vet/releases/tag/v0.13.4";
        assert_eq!(release_url(Some(url)), url);
    }

    #[test]
    fn rejects_other_hosts_paths_and_control_characters() {
        assert_eq!(release_url(None), DEFAULT_RELEASE_URL);
        assert_eq!(
            release_url(Some("https://evil.test/releases")),
            DEFAULT_RELEASE_URL
        );
        assert_eq!(
            release_url(Some("https://github.com/other/Repo/releases/tag/v1")),
            DEFAULT_RELEASE_URL
        );
        assert_eq!(
            release_url(Some(
                "https://github.com/nassih-yassine/Dep-Vet/releases/\u{1b}[2J"
            )),
            DEFAULT_RELEASE_URL
        );
    }
}
