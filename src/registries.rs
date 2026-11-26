//! Private-registry routing, declared in configuration.
//!
//! Routing and credentials are separate trust decisions: a project's
//! `.depvet.toml` may say *where* a scope lives, but only the per-user file may
//! name the environment variable that carries a token. A repository that can
//! add routing cannot therefore point a CI token at its own host.

use std::path::Path;

use serde::Deserialize;

use crate::model::Ecosystem;

/// The per-user file that may carry `auth`. Kept out of the repository on
/// purpose.
pub const USER_CONFIG_PATH: &str = "~/.config/dep-vet/registries.toml";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    /// Only the ecosystems with per-name routing today.
    pub ecosystem: Ecosystem,
    /// npm scope (`@deliverect`) or a name prefix (`deliverect-`).
    pub r#match: String,
    pub url: String,
    /// `env:NAME`. Rejected outside the user-level file.
    #[serde(default)]
    pub auth: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegistryError {
    UnsupportedEcosystem { ecosystem: String },
    EmptyMatch { index: usize },
    MatchHasWhitespace { index: usize },
    DuplicateMatch { ecosystem: String, pattern: String },
    NotHttps { url: String },
    HasCredentials { url: String },
    HasQueryOrFragment { url: String },
    NotAsciiHost { url: String },
    PathTraversal { url: String },
    EmptyHost { url: String },
    BadAuthReference { value: String },
    AuthOutsideUserConfig { pattern: String },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedEcosystem { ecosystem } => write!(
                formatter,
                "registry routing supports npm and pypi today; '{ecosystem}' does not"
            ),
            Self::EmptyMatch { index } => {
                write!(formatter, "[[registries]] entry {index} has an empty match")
            }
            Self::MatchHasWhitespace { index } => write!(
                formatter,
                "[[registries]] entry {index}: match cannot contain whitespace"
            ),
            Self::DuplicateMatch { ecosystem, pattern } => {
                write!(formatter, "duplicate registry match {ecosystem}:{pattern}")
            }
            Self::NotHttps { url } => {
                write!(formatter, "registry url must be https: {url}")
            }
            Self::HasCredentials { url } => {
                write!(formatter, "registry url must not embed credentials: {url}")
            }
            Self::HasQueryOrFragment { url } => write!(
                formatter,
                "registry url must not carry a query or fragment: {url}"
            ),
            Self::NotAsciiHost { url } => {
                write!(formatter, "registry host must be ASCII or punycode: {url}")
            }
            Self::PathTraversal { url } => {
                write!(formatter, "registry url must not contain '..': {url}")
            }
            Self::EmptyHost { url } => write!(formatter, "registry url has no host: {url}"),
            Self::BadAuthReference { value } => {
                write!(formatter, "auth must be `env:VARIABLE_NAME`, got '{value}'")
            }
            Self::AuthOutsideUserConfig { pattern } => write!(
                formatter,
                "auth for {pattern} is only read from {USER_CONFIG_PATH}, never from a \
                 repository file"
            ),
        }
    }
}

impl std::error::Error for RegistryError {}

/// Validates every entry. `allow_insecure` is the same development gate the
/// `DEPVET_*_BASE` overrides use, so `http` works for a local mock registry in
/// tests and never in a release configuration.
pub fn validate(
    entries: &[RegistryEntry],
    allow_insecure: bool,
    from_user_config: bool,
) -> Result<(), RegistryError> {
    let mut seen: Vec<(Ecosystem, String)> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if !matches!(entry.ecosystem, Ecosystem::Npm | Ecosystem::Pypi) {
            return Err(RegistryError::UnsupportedEcosystem {
                ecosystem: entry.ecosystem.to_string(),
            });
        }
        let pattern = entry.r#match.trim();
        if pattern.is_empty() {
            return Err(RegistryError::EmptyMatch { index });
        }
        if pattern.chars().any(char::is_whitespace) {
            return Err(RegistryError::MatchHasWhitespace { index });
        }
        if seen
            .iter()
            .any(|(ecosystem, existing)| *ecosystem == entry.ecosystem && existing == pattern)
        {
            return Err(RegistryError::DuplicateMatch {
                ecosystem: entry.ecosystem.to_string(),
                pattern: pattern.to_string(),
            });
        }
        seen.push((entry.ecosystem, pattern.to_string()));
        validate_url(&entry.url, allow_insecure)?;
        match entry.auth.as_deref() {
            None => {}
            Some(reference) => {
                validate_auth(reference)?;
                if !from_user_config {
                    return Err(RegistryError::AuthOutsideUserConfig {
                        pattern: pattern.to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn validate_url(url: &str, allow_insecure: bool) -> Result<(), RegistryError> {
    let rest = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if allow_insecure && let Some(rest) = url.strip_prefix("http://") {
        rest
    } else {
        return Err(RegistryError::NotHttps {
            url: url.to_string(),
        });
    };
    if rest.contains('@') {
        return Err(RegistryError::HasCredentials {
            url: url.to_string(),
        });
    }
    if rest.contains('?') || rest.contains('#') {
        return Err(RegistryError::HasQueryOrFragment {
            url: url.to_string(),
        });
    }
    if rest.contains("..") {
        return Err(RegistryError::PathTraversal {
            url: url.to_string(),
        });
    }
    let host = rest.split('/').next().unwrap_or("");
    if host.is_empty() {
        return Err(RegistryError::EmptyHost {
            url: url.to_string(),
        });
    }
    if !host.is_ascii() {
        return Err(RegistryError::NotAsciiHost {
            url: url.to_string(),
        });
    }
    Ok(())
}

fn validate_auth(reference: &str) -> Result<(), RegistryError> {
    let Some(name) = reference.strip_prefix("env:") else {
        return Err(RegistryError::BadAuthReference {
            value: reference.to_string(),
        });
    };
    let mut chars = name.chars();
    let valid = chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Err(RegistryError::BadAuthReference {
            value: reference.to_string(),
        });
    }
    Ok(())
}

/// A validated route: what a name matches and where it is fetched from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub ecosystem: Ecosystem,
    pub pattern: String,
    pub base: String,
    /// Environment variable holding the token. Never the token itself.
    pub auth_env: Option<String>,
}

/// Routes in trust order: per-user entries first, then the project's. A
/// project file therefore cannot redirect a scope the user already pinned.
#[derive(Debug, Default, Clone)]
pub struct Router {
    routes: Vec<Route>,
}

impl Router {
    pub fn new(project: &[RegistryEntry], user: &[RegistryEntry]) -> Self {
        let routes = user.iter().chain(project.iter()).map(|entry| Route {
            ecosystem: entry.ecosystem,
            pattern: entry.r#match.trim().to_string(),
            base: entry.url.trim_end_matches('/').to_string(),
            auth_env: entry
                .auth
                .as_deref()
                .and_then(|value| value.strip_prefix("env:"))
                .map(str::to_string),
        });
        Self {
            routes: routes.collect(),
        }
    }

    /// First matching route, or `None` for the public registry.
    pub fn route(&self, ecosystem: Ecosystem, name: &str) -> Option<&Route> {
        let name = name.to_ascii_lowercase();
        self.routes
            .iter()
            .find(|route| route.ecosystem == ecosystem && pattern_matches(&route.pattern, &name))
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// npm scopes match the whole scope; anything else is a name prefix. A scope
/// pattern never matches a package that merely starts with the same letters.
fn pattern_matches(pattern: &str, name: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    if pattern.starts_with('@') {
        return name
            .strip_prefix(&pattern)
            .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1);
    }
    name.starts_with(&pattern)
}

/// The token for a route, read at request time. A missing variable is an error
/// naming the variable, never an unauthenticated request that 401s later.
pub fn token(route: &Route) -> Result<Option<String>, String> {
    match route.auth_env.as_deref() {
        None => Ok(None),
        Some(name) => std::env::var(name).map(Some).map_err(|_| {
            format!(
                "registry auth for {} needs ${name}, which is not set",
                route.pattern
            )
        }),
    }
}

/// Loads the per-user registry file. A missing file is not an error; it is the
/// normal case for anyone without private registries.
pub fn load_user_config() -> Result<Vec<RegistryEntry>, String> {
    let Some(path) = user_config_path() else {
        return Ok(Vec::new());
    };
    let Ok(body) = std::fs::read_to_string(&path) else {
        return Ok(Vec::new());
    };
    let entries =
        parse(&body, &path, true).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(entries)
}

pub fn user_config_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(
        std::path::PathBuf::from(home)
            .join(".config")
            .join("dep-vet")
            .join("registries.toml"),
    )
}

/// Parses a file shaped as `[[registries]]` entries.
pub fn parse(
    body: &str,
    path: &Path,
    from_user_config: bool,
) -> Result<Vec<RegistryEntry>, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct File {
        #[serde(default)]
        registries: Vec<RegistryEntry>,
    }
    let file: File =
        toml::from_str(body).map_err(|error| format!("{}: {error}", path.display()))?;
    let allow_insecure =
        std::env::var("DEPVET_ALLOW_INSECURE_BASES").is_ok_and(|value| value == "1");
    validate(&file.registries, allow_insecure, from_user_config)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(file.registries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ecosystem: Ecosystem, pattern: &str, url: &str) -> RegistryEntry {
        RegistryEntry {
            ecosystem,
            r#match: pattern.to_string(),
            url: url.to_string(),
            auth: None,
        }
    }

    #[test]
    fn a_scoped_entry_is_valid() {
        let entries = vec![entry(
            Ecosystem::Npm,
            "@deliverect",
            "https://npm.internal.example/",
        )];
        assert_eq!(validate(&entries, false, false), Ok(()));
    }

    #[test]
    fn http_needs_the_development_gate() {
        let entries = vec![entry(Ecosystem::Npm, "@x", "http://127.0.0.1:4873/")];
        assert!(matches!(
            validate(&entries, false, false),
            Err(RegistryError::NotHttps { .. })
        ));
        assert_eq!(validate(&entries, true, false), Ok(()));
    }

    #[test]
    fn urls_with_credentials_a_query_or_traversal_are_refused() {
        for url in [
            "https://user:pass@npm.example/",
            "https://npm.example/?token=x",
            "https://npm.example/#frag",
            "https://npm.example/a/../b",
        ] {
            let entries = vec![entry(Ecosystem::Npm, "@x", url)];
            assert!(
                validate(&entries, false, false).is_err(),
                "{url} should be refused"
            );
        }
    }

    #[test]
    fn a_non_ascii_host_is_refused() {
        let entries = vec![entry(Ecosystem::Npm, "@x", "https://npm.exämple/")];
        assert!(matches!(
            validate(&entries, false, false),
            Err(RegistryError::NotAsciiHost { .. })
        ));
    }

    #[test]
    fn auth_is_only_honoured_in_the_user_level_file() {
        let mut entries = vec![entry(Ecosystem::Npm, "@x", "https://npm.example/")];
        entries[0].auth = Some("env:NPM_TOKEN".to_string());
        assert!(matches!(
            validate(&entries, false, false),
            Err(RegistryError::AuthOutsideUserConfig { .. })
        ));
        assert_eq!(validate(&entries, false, true), Ok(()));
    }

    #[test]
    fn auth_must_name_an_environment_variable() {
        let mut entries = vec![entry(Ecosystem::Npm, "@x", "https://npm.example/")];
        for bad in ["NPM_TOKEN", "env:", "env:1TOKEN", "env:A-B", "file:/tmp/x"] {
            entries[0].auth = Some(bad.to_string());
            assert!(
                validate(&entries, false, true).is_err(),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn duplicate_matches_and_unsupported_ecosystems_are_refused() {
        let entries = vec![
            entry(Ecosystem::Pypi, "internal", "https://pypi.example/"),
            entry(Ecosystem::Pypi, "internal", "https://other.example/"),
        ];
        assert!(matches!(
            validate(&entries, false, true),
            Err(RegistryError::DuplicateMatch { .. })
        ));

        let entries = vec![entry(Ecosystem::CratesIo, "x", "https://crates.example/")];
        assert!(matches!(
            validate(&entries, false, true),
            Err(RegistryError::UnsupportedEcosystem { .. })
        ));

        let entries = vec![entry(Ecosystem::Npm, "  ", "https://npm.example/")];
        assert!(matches!(
            validate(&entries, false, true),
            Err(RegistryError::EmptyMatch { .. })
        ));
    }

    fn route(pattern: &str, url: &str) -> RegistryEntry {
        entry(Ecosystem::Npm, pattern, url)
    }

    #[test]
    fn a_scope_pattern_matches_the_whole_scope_only() {
        let router = Router::new(&[route("@deliverect", "https://npm.internal.example")], &[]);
        assert_eq!(
            router
                .route(Ecosystem::Npm, "@deliverect/ui")
                .map(|r| r.base.as_str()),
            Some("https://npm.internal.example")
        );
        assert!(router.route(Ecosystem::Npm, "@deliverect2/ui").is_none());
        assert!(router.route(Ecosystem::Npm, "deliverect").is_none());
        assert!(router.route(Ecosystem::Npm, "@deliverect").is_none());
    }

    #[test]
    fn a_plain_pattern_is_a_name_prefix() {
        let router = Router::new(&[route("internal-", "https://npm.internal.example")], &[]);
        assert!(router.route(Ecosystem::Npm, "internal-lib").is_some());
        assert!(router.route(Ecosystem::Npm, "notinternal-lib").is_none());
    }

    #[test]
    fn the_user_config_wins_over_the_project_file() {
        let router = Router::new(
            &[route("@deliverect", "https://project.example")],
            &[route("@deliverect", "https://user.example")],
        );
        assert_eq!(
            router
                .route(Ecosystem::Npm, "@deliverect/ui")
                .map(|r| r.base.as_str()),
            Some("https://user.example")
        );
    }

    #[test]
    fn routes_are_scoped_to_their_ecosystem() {
        let router = Router::new(
            &[entry(
                Ecosystem::Pypi,
                "internal-",
                "https://pypi.internal.example",
            )],
            &[],
        );
        assert!(router.route(Ecosystem::Pypi, "internal-lib").is_some());
        assert!(router.route(Ecosystem::Npm, "internal-lib").is_none());
    }

    #[test]
    fn a_missing_token_variable_names_itself() {
        let mut entries = vec![route("@deliverect", "https://npm.internal.example")];
        entries[0].auth = Some("env:DEPVET_TEST_UNSET_TOKEN_XYZ".to_string());
        let router = Router::new(&entries, &[]);
        let route = router.route(Ecosystem::Npm, "@deliverect/ui").unwrap();
        let error = token(route).unwrap_err();
        assert!(error.contains("DEPVET_TEST_UNSET_TOKEN_XYZ"), "{error}");
    }

    #[test]
    fn an_unknown_key_fails_the_file() {
        let body = r#"
            [[registries]]
            ecosystem = "npm"
            match = "@x"
            url = "https://npm.example/"
            token = "oops"
        "#;
        let error = parse(body, Path::new(".depvet.toml"), true).unwrap_err();
        assert!(error.contains("unknown field"), "{error}");
    }

    #[test]
    fn a_project_file_may_route_but_not_authenticate() {
        let body = r#"
            [[registries]]
            ecosystem = "npm"
            match = "@x"
            url = "https://npm.example/"
            auth = "env:NPM_TOKEN"
        "#;
        let error = parse(body, Path::new(".depvet.toml"), false).unwrap_err();
        assert!(error.contains("never from a repository file"), "{error}");
        assert!(parse(body, Path::new("registries.toml"), true).is_ok());
    }
}
