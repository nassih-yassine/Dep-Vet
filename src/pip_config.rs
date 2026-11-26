//! Which index a PyPI name is fetched from.
//!
//! pip already answers this question, and a company that runs a private index
//! has configured it once. Reading the same sources means dep-vet does not ask
//! for a second file: `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, then `pip.conf`
//! from the user, legacy user, and site locations, in pip's own order.

use std::path::{Path, PathBuf};

const USER_CONFIG: &str = ".config/pip/pip.conf";
const LEGACY_USER_CONFIG: &str = ".pip/pip.conf";

/// `[global]` keys we read. `index-url` replaces the default; `extra-index-url`
/// appends without replacing anything.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PipConfig {
    pub index_url: Option<String>,
    pub extra_index_urls: Vec<String>,
}

/// Ordered, de-duplicated index bases. The public PyPI is included only when
/// nothing else is configured, because pip's default would otherwise silently
/// keep querying the public index for internal names.
pub fn indexes(config: &PipConfig, default: &str) -> Vec<String> {
    let mut urls = Vec::new();
    match &config.index_url {
        Some(url) => urls.push(url.clone()),
        None => urls.push(default.to_string()),
    }
    urls.extend(config.extra_index_urls.iter().cloned());
    let mut seen = std::collections::HashSet::new();
    urls.retain(|url| seen.insert(url.to_ascii_lowercase()));
    urls
}

/// Discovery can be turned off with `DEPVET_NO_PIP_CONFIG=1`; tests set it so
/// a developer's own pip configuration cannot change a run.
pub fn enabled() -> bool {
    !std::env::var("DEPVET_NO_PIP_CONFIG").is_ok_and(|value| value == "1")
}

/// Reads the environment and the three pip.conf locations. A missing file or
/// variable is normal; a malformed URL is `None` rather than a guess, so the
/// caller can report it instead of querying the wrong host.
pub fn discover(
    env: impl Fn(&str) -> Option<String>,
    home: Option<&Path>,
) -> Result<PipConfig, String> {
    let mut config = PipConfig::default();
    if let Some(files) = pip_conf_paths(home) {
        for path in files {
            let Ok(body) = std::fs::read_to_string(&path) else {
                continue;
            };
            let parsed =
                parse_conf(&body).map_err(|error| format!("{}: {error}", path.display()))?;
            if config.index_url.is_none() {
                config.index_url = parsed.index_url;
            }
            config.extra_index_urls.extend(parsed.extra_index_urls);
        }
    }
    if let Some(url) = env("PIP_INDEX_URL").filter(|value| !value.trim().is_empty()) {
        config.index_url = Some(url.trim().to_string());
    }
    if let Some(urls) = env("PIP_EXTRA_INDEX_URL").filter(|value| !value.trim().is_empty()) {
        config
            .extra_index_urls
            .extend(urls.split_whitespace().map(str::to_string));
    }
    config.extra_index_urls.retain(|url| !url.trim().is_empty());
    Ok(config)
}

fn pip_conf_paths(home: Option<&Path>) -> Option<Vec<PathBuf>> {
    let mut paths = Vec::new();
    if let Some(home) = home {
        paths.push(home.join(USER_CONFIG));
        paths.push(home.join(LEGACY_USER_CONFIG));
    }
    paths.push(PathBuf::from("/etc/pip.conf"));
    Some(paths)
}

/// Line-wise `[global]` parsing, like the other one-file configs in this
/// repository. Comments start at `#` or `;`; a key outside `[global]` is
/// ignored because pip ignores it too.
pub fn parse_conf(body: &str) -> Result<PipConfig, String> {
    let mut config = PipConfig::default();
    let mut section = String::new();
    for (number, raw) in body.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            section = name.trim().to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {}: expected key = value", number + 1));
        };
        if section != "global" {
            continue;
        }
        match key.trim().to_ascii_lowercase().as_str() {
            "index-url" => config.index_url = Some(value.trim().to_string()),
            "extra-index-url" => config
                .extra_index_urls
                .extend(value.split_whitespace().map(str::to_string)),
            _ => {}
        }
    }
    Ok(config)
}

fn strip_comment(line: &str) -> &str {
    let mut cut = line.len();
    for (index, character) in line.char_indices() {
        if character == '#' || character == ';' {
            cut = index;
            break;
        }
    }
    &line[..cut]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_environment_wins_over_the_file() {
        let config = PipConfig {
            index_url: Some("https://file.example/simple".to_string()),
            extra_index_urls: vec![],
        };
        let env = |key: &str| match key {
            "PIP_INDEX_URL" => Some("https://env.example/simple".to_string()),
            _ => None,
        };
        let discovered = discover(env, None).unwrap();
        // The file is fictional on this machine, so only the env survives.
        assert_eq!(
            discovered.index_url.as_deref(),
            Some("https://env.example/simple")
        );
        assert_eq!(
            config.index_url.as_deref(),
            Some("https://file.example/simple")
        );
    }

    #[test]
    fn a_conf_file_is_parsed_line_wise() {
        let body = "\
[global]
index-url = https://pypi.acme.internal/simple
extra-index-url = https://one.example/simple https://two.example/simple
; a comment
# another
[install]
index-url = https://ignored.example/simple
";
        let config = parse_conf(body).unwrap();
        assert_eq!(
            config.index_url.as_deref(),
            Some("https://pypi.acme.internal/simple")
        );
        assert_eq!(
            config.extra_index_urls,
            vec![
                "https://one.example/simple".to_string(),
                "https://two.example/simple".to_string()
            ]
        );
    }

    #[test]
    fn a_line_without_a_separator_is_an_error() {
        assert!(parse_conf("[global]\nindex-url\n").is_err());
    }

    #[test]
    fn the_public_index_is_used_only_when_nothing_else_is_set() {
        let default = "https://pypi.org/simple";
        assert_eq!(
            indexes(&PipConfig::default(), default),
            vec![default.to_string()]
        );
        let configured = PipConfig {
            index_url: Some("https://internal/simple".to_string()),
            extra_index_urls: vec!["https://extra/simple".to_string()],
        };
        assert_eq!(
            indexes(&configured, default),
            vec![
                "https://internal/simple".to_string(),
                "https://extra/simple".to_string()
            ]
        );
    }

    #[test]
    fn duplicates_are_removed_case_insensitively() {
        let config = PipConfig {
            index_url: Some("https://Internal/simple".to_string()),
            extra_index_urls: vec![
                "https://internal/simple".to_string(),
                "https://other/simple".to_string(),
            ],
        };
        assert_eq!(
            indexes(&config, "https://pypi.org/simple"),
            vec![
                "https://Internal/simple".to_string(),
                "https://other/simple".to_string()
            ]
        );
    }

    #[test]
    fn files_are_read_in_pip_order() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".config/pip")).unwrap();
        std::fs::write(
            home.path().join(".config/pip/pip.conf"),
            "[global]\nindex-url = https://user/simple\n",
        )
        .unwrap();
        std::fs::create_dir_all(home.path().join(".pip")).unwrap();
        std::fs::write(
            home.path().join(".pip/pip.conf"),
            "[global]\nindex-url = https://legacy/simple\nextra-index-url = https://legacy-extra/simple\n",
        )
        .unwrap();

        let config = discover(|_| None, Some(home.path())).unwrap();
        // The first file that sets `index-url` wins; extra indexes accumulate,
        // which is what pip does with multi-value options.
        assert_eq!(config.index_url.as_deref(), Some("https://user/simple"));
        assert!(
            config
                .extra_index_urls
                .iter()
                .any(|url| url == "https://legacy-extra/simple")
        );
    }
}
