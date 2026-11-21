//! npm lockfile reading and diffing.
//!
//! Only `package-lock.json` v2/v3 is supported: v1 stores a nested dependency
//! tree that cannot be compared flatly with v2/v3, so it is rejected with the
//! upgrade command rather than guessed at.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
}

/// Every lockfile parser returns packages plus whatever it could not audit,
/// so an incomplete tree is never presented as a complete one.
#[derive(Debug)]
pub struct LockContents {
    pub packages: Vec<LockedPackage>,
    pub skipped: Vec<(String, String)>,
}

impl LockContents {
    fn packages_only(packages: Vec<LockedPackage>) -> Self {
        Self {
            packages,
            skipped: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Npm,
    Pip,
    Cargo,
    Go,
}

impl Format {
    pub fn ecosystem(self) -> crate::model::Ecosystem {
        match self {
            Self::Npm => crate::model::Ecosystem::Npm,
            Self::Pip => crate::model::Ecosystem::Pypi,
            Self::Cargo => crate::model::Ecosystem::CratesIo,
            Self::Go => crate::model::Ecosystem::Go,
        }
    }
}

/// File name decides the parser: `package-lock.json`, `Cargo.lock`, `go.mod`,
/// or a requirements file (`requirements*.txt`, `*-requirements.txt`).
pub fn detect(path: &Path) -> Result<Format, LockError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| LockError::UnsupportedFormat(path.display().to_string()))?;
    match name {
        "package-lock.json" => Ok(Format::Npm),
        "Cargo.lock" => Ok(Format::Cargo),
        "go.mod" => Ok(Format::Go),
        other if other.ends_with(".txt") && other.contains("requirement") => Ok(Format::Pip),
        other => Err(LockError::UnsupportedFormat(other.to_string())),
    }
}

pub fn parse(format: Format, body: &str) -> Result<LockContents, LockError> {
    match format {
        Format::Npm => parse_npm(body),
        Format::Pip => Ok(parse_pip(body)),
        Format::Cargo => parse_cargo(body),
        Format::Go => Ok(parse_go(body)),
    }
}

impl LockedPackage {
    pub fn spec(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "lockfileVersion {0} is not supported; run `npm install` to upgrade the lockfile to v2 or v3"
    )]
    UnsupportedVersion(u32),
    #[error("lockfile is not valid npm v2/v3 JSON: {0}")]
    Malformed(String),
    #[error("git failed: {0}")]
    Git(String),
    #[error("{0} is not inside a git repository, so there is no base revision to compare against")]
    NotInRepository(String),
    #[error(
        "unsupported lockfile '{0}': use package-lock.json, a requirements*.txt, Cargo.lock, or go.mod"
    )]
    UnsupportedFormat(String),
}

pub fn read(path: &Path) -> Result<LockContents, LockError> {
    let format = detect(path)?;
    let body = std::fs::read_to_string(path).map_err(|source| LockError::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse(format, &body)
}

/// Flattens the `packages` map into name/version pairs, dropping workspace
/// links (they have no version and point at local directories).
pub fn parse_npm(body: &str) -> Result<LockContents, LockError> {
    let lockfile: RawLockfile =
        serde_json::from_str(body).map_err(|error| LockError::Malformed(error.to_string()))?;

    if lockfile.lockfile_version < 2 {
        return Err(LockError::UnsupportedVersion(lockfile.lockfile_version));
    }
    if lockfile.packages.is_empty() {
        return Err(LockError::Malformed(
            "lockfile has no `packages` map; regenerate it with npm 7 or newer".to_string(),
        ));
    }

    let mut packages: Vec<LockedPackage> = lockfile
        .packages
        .into_iter()
        .filter(|(path, _)| path.contains("node_modules/"))
        .filter(|(_, entry)| !entry.link)
        .filter_map(|(path, entry)| {
            let version = entry.version?;
            // Aliases (`"x": "npm:real-pkg@1"`) key the path by the alias but
            // record the real package in `name`; auditing the alias would 404.
            let name = entry
                .name
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| {
                    path.rsplit("node_modules/")
                        .next()
                        .unwrap_or_default()
                        .to_string()
                });
            if name.is_empty() {
                return None;
            }
            Some(LockedPackage { name, version })
        })
        .collect();
    packages.sort();
    packages.dedup();
    Ok(LockContents::packages_only(packages))
}

/// Packages present now that the base revision did not have. A version bump
/// counts as new: the new tarball has not been reviewed.
pub fn added(current: &[LockedPackage], base: &[LockedPackage]) -> Vec<LockedPackage> {
    let mut added: Vec<LockedPackage> = current
        .iter()
        .filter(|package| !base.contains(package))
        .cloned()
        .collect();
    added.sort();
    added
}

/// Walks up from `start` looking for a `package-lock.json`, the way npm does.
pub fn nearest(start: &Path) -> Option<std::path::PathBuf> {
    let start = start.canonicalize().ok()?;
    start
        .ancestors()
        .map(|directory| directory.join("package-lock.json"))
        .find(|candidate| candidate.is_file())
}

/// Reads the same lockfile at a git revision, so the diff needs no second
/// working tree.
pub fn at_ref(lockfile: &Path, git_ref: &str) -> Result<LockContents, LockError> {
    let format = detect(lockfile)?;
    // `Path::new("package-lock.json").parent()` is `Some("")`, which git
    // rejects as a working directory.
    let directory = lockfile
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let root = git(directory, &["rev-parse", "--show-toplevel"])?;
    let root = Path::new(root.trim());
    let absolute = lockfile.canonicalize().map_err(|source| LockError::Io {
        path: lockfile.display().to_string(),
        source,
    })?;
    let relative = absolute
        .strip_prefix(root)
        .map_err(|_| LockError::NotInRepository(lockfile.display().to_string()))?;

    let blob = git(
        directory,
        &["show", &format!("{git_ref}:{}", relative.display())],
    )?;
    parse(format, &blob).map_err(|error| match error {
        LockError::Io { source, .. } => LockError::Io {
            path: format!("{git_ref}:{}", relative.display()),
            source,
        },
        other => other,
    })
}

fn git(directory: &Path, args: &[&str]) -> Result<String, LockError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(directory)
        .output()
        .map_err(|error| LockError::Git(format!("could not run git: {error}")))?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if message.contains("not a git repository") {
            return Err(LockError::NotInRepository(directory.display().to_string()));
        }
        return Err(LockError::Git(if message.is_empty() {
            format!("git {} exited with {}", args.join(" "), output.status)
        } else {
            message
        }));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| LockError::Git(format!("git printed non-UTF-8 output: {error}")))
}

#[derive(Debug, Deserialize)]
struct RawLockfile {
    #[serde(rename = "lockfileVersion", default)]
    lockfile_version: u32,
    #[serde(default)]
    packages: BTreeMap<String, Entry>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    link: bool,
}

fn parse_pip(body: &str) -> LockContents {
    let mut packages = Vec::new();
    let mut skipped = Vec::new();

    for raw in body.lines() {
        let line = raw.split(" #").next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('-') {
            skipped.push((
                line.to_string(),
                "pip option or editable install, not auditable".to_string(),
            ));
            continue;
        }
        let requirement = line.split(';').next().unwrap_or(line).trim();
        if requirement.contains("://") || requirement.contains(" @ ") {
            skipped.push((line.to_string(), "direct URL requirement".to_string()));
            continue;
        }
        // Extras sit between the name and the version: name[extra]==1.2.3.
        let without_extras = match requirement.find('[') {
            Some(start) => match requirement[start..].find(']') {
                Some(offset) => {
                    let end = start + offset;
                    format!("{}{}", &requirement[..start], &requirement[end + 1..])
                }
                None => {
                    skipped.push((line.to_string(), "malformed extras".to_string()));
                    continue;
                }
            },
            None => requirement.to_string(),
        };
        match without_extras.split_once("==") {
            Some((name, version))
                if !name.trim().is_empty()
                    && !version.trim().is_empty()
                    && !version.contains('*') =>
            {
                packages.push(LockedPackage {
                    name: name.trim().to_string(),
                    version: version.trim().to_string(),
                });
            }
            _ => skipped.push((line.to_string(), "not pinned with ==".to_string())),
        }
    }

    finish(packages, skipped)
}

fn parse_cargo(body: &str) -> Result<LockContents, LockError> {
    let lockfile: CargoLock =
        toml::from_str(body).map_err(|error| LockError::Malformed(error.to_string()))?;
    let mut packages = Vec::new();
    let mut skipped = Vec::new();

    for package in lockfile.package {
        match package.source.as_deref() {
            // Workspace members and path dependencies are not published.
            None => continue,
            Some(source) if source.starts_with("git+") => skipped.push((
                format!("{}@{}", package.name, package.version),
                "git dependency, not on crates.io".to_string(),
            )),
            Some(_) => packages.push(LockedPackage {
                name: package.name,
                version: package.version,
            }),
        }
    }

    Ok(finish(packages, skipped))
}

fn parse_go(body: &str) -> LockContents {
    let mut packages = Vec::new();
    let mut skipped = Vec::new();
    let mut block: Option<&'static str> = None;

    for raw in body.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        if let Some(kind) = block {
            if line == ")" {
                block = None;
            } else if kind == "require" {
                push_go_requirement(line, &mut packages, &mut skipped);
            }
            continue;
        }

        if let Some(kind) = line.strip_suffix('(') {
            block = Some(match kind.trim() {
                "require" => "require",
                _ => "other",
            });
            continue;
        }

        if let Some(requirement) = line.strip_prefix("require ") {
            push_go_requirement(requirement, &mut packages, &mut skipped);
        }
        // module, go, toolchain, replace, exclude, and retract carry no
        // auditable dependency, and a replaced module may not be the one built.
    }

    finish(packages, skipped)
}

fn push_go_requirement(
    line: &str,
    packages: &mut Vec<LockedPackage>,
    skipped: &mut Vec<(String, String)>,
) {
    match line.split_whitespace().collect::<Vec<_>>().as_slice() {
        [module, version] if version.starts_with('v') => packages.push(LockedPackage {
            name: (*module).to_string(),
            version: (*version).to_string(),
        }),
        _ => skipped.push((line.to_string(), "unreadable require line".to_string())),
    }
}

fn finish(mut packages: Vec<LockedPackage>, skipped: Vec<(String, String)>) -> LockContents {
    packages.sort();
    packages.dedup();
    LockContents { packages, skipped }
}

#[derive(Debug, Deserialize)]
struct CargoLock {
    #[serde(default)]
    package: Vec<CargoPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(body: &str) -> Vec<LockedPackage> {
        parse_npm(body).unwrap().packages
    }

    fn package(name: &str, version: &str) -> LockedPackage {
        LockedPackage {
            name: name.to_string(),
            version: version.to_string(),
        }
    }

    const V3: &str = r#"{
        "name": "app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": { "name": "app", "version": "1.0.0" },
            "node_modules/express": { "version": "5.1.0" },
            "node_modules/@types/node": { "version": "22.0.0" },
            "node_modules/a/node_modules/nested": { "version": "0.1.0" },
            "packages/local": { "version": "0.0.0" },
            "node_modules/linked": { "link": true }
        }
    }"#;

    #[test]
    fn flattens_top_level_scoped_and_nested_packages() {
        assert_eq!(
            lock(V3),
            vec![
                package("@types/node", "22.0.0"),
                package("express", "5.1.0"),
                package("nested", "0.1.0"),
            ]
        );
    }

    #[test]
    fn ignores_the_root_entry_workspaces_and_links() {
        let names: Vec<String> = lock(V3).into_iter().map(|package| package.name).collect();
        assert!(!names.contains(&"app".to_string()));
        assert!(!names.contains(&"local".to_string()));
        assert!(!names.contains(&"linked".to_string()));
    }

    #[test]
    fn aliased_dependencies_keep_the_real_package_name() {
        // package.json: "my-lodash": "npm:lodash@4.17.21" — npm keys the path
        // by the alias but records the real package in `name`.
        let body = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/my-lodash": { "name": "lodash", "version": "4.17.21" }
            }
        }"#;
        assert_eq!(lock(body), vec![package("lodash", "4.17.21")]);
    }

    #[test]
    fn entries_without_a_name_fall_back_to_the_path() {
        let body = r#"{
            "lockfileVersion": 3,
            "packages": { "node_modules/express": { "version": "5.1.0" } }
        }"#;
        assert_eq!(lock(body), vec![package("express", "5.1.0")]);
    }

    #[test]
    fn finds_the_nearest_lockfile_in_a_parent_directory() {
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("packages").join("app");
        std::fs::create_dir_all(&nested).unwrap();
        let lockfile = directory.path().join("package-lock.json");
        std::fs::write(&lockfile, "{}").unwrap();

        assert_eq!(nearest(&nested).as_deref(), Some(lockfile.as_path()));
    }

    #[test]
    fn detects_each_supported_lockfile() {
        assert_eq!(detect(Path::new("package-lock.json")).unwrap(), Format::Npm);
        assert_eq!(detect(Path::new("Cargo.lock")).unwrap(), Format::Cargo);
        assert_eq!(detect(Path::new("go.mod")).unwrap(), Format::Go);
        assert_eq!(detect(Path::new("requirements.txt")).unwrap(), Format::Pip);
        assert_eq!(
            detect(Path::new("dev-requirements.txt")).unwrap(),
            Format::Pip
        );
        assert!(matches!(
            detect(Path::new("poetry.lock")),
            Err(LockError::UnsupportedFormat(_))
        ));
    }

    #[test]
    fn pip_keeps_exact_pins_and_reports_the_rest() {
        let body = "\
flask==3.1.0
requests[security]==2.31.0 ; python_version >= '3.8'  # comment
unpinned-pkg
-r other.txt
https://example.test/pkg.tar.gz
wild==1.*
";
        let contents = parse(Format::Pip, body).unwrap();
        assert_eq!(
            contents.packages,
            vec![package("flask", "3.1.0"), package("requests", "2.31.0")]
        );
        let reasons: Vec<&str> = contents
            .skipped
            .iter()
            .map(|(_, reason)| reason.as_str())
            .collect();
        assert!(reasons.contains(&"not pinned with =="));
        assert!(reasons.contains(&"pip option or editable install, not auditable"));
        assert!(reasons.contains(&"direct URL requirement"));
    }

    #[test]
    fn cargo_keeps_registry_packages_and_skips_git_and_path() {
        let body = r#"
version = 3

[[package]]
name = "serde"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "local-dep"
version = "0.1.0"

[[package]]
name = "git-dep"
version = "0.2.0"
source = "git+https://github.com/example/git-dep#abc123"
"#;
        let contents = parse(Format::Cargo, body).unwrap();
        assert_eq!(contents.packages, vec![package("serde", "1.0.229")]);
        assert_eq!(contents.skipped.len(), 1);
        assert!(contents.skipped[0].1.contains("git dependency"));
    }

    #[test]
    fn cargo_rejects_malformed_toml() {
        assert!(matches!(
            parse(Format::Cargo, "not = [valid"),
            Err(LockError::Malformed(_))
        ));
    }

    #[test]
    fn go_reads_require_blocks_and_single_lines() {
        let body = "\
module example.com/app

go 1.22

require github.com/gin-gonic/gin v1.9.1

require (
	golang.org/x/text v0.3.0 // indirect
	example.com/broken
)

replace example.com/old => example.com/new v1.0.0
";
        let contents = parse(Format::Go, body).unwrap();
        assert_eq!(
            contents.packages,
            vec![
                package("github.com/gin-gonic/gin", "v1.9.1"),
                package("golang.org/x/text", "v0.3.0")
            ]
        );
        assert_eq!(contents.skipped.len(), 1, "{:?}", contents.skipped);
    }

    #[test]
    fn version_one_lockfiles_are_rejected_with_guidance() {
        let error = parse_npm(r#"{ "lockfileVersion": 1, "dependencies": {} }"#).unwrap_err();
        assert!(matches!(error, LockError::UnsupportedVersion(1)));
        assert!(error.to_string().contains("npm install"));
    }

    #[test]
    fn v2_lockfiles_are_accepted() {
        let body =
            r#"{ "lockfileVersion": 2, "packages": { "node_modules/x": { "version": "1.0.0" } } }"#;
        assert_eq!(lock(body), vec![package("x", "1.0.0")]);
    }

    #[test]
    fn missing_packages_map_is_a_clear_error() {
        let error = parse_npm(r#"{ "lockfileVersion": 3 }"#).unwrap_err();
        assert!(error.to_string().contains("packages"));
    }

    #[test]
    fn malformed_json_is_rejected() {
        assert!(matches!(parse_npm("nope"), Err(LockError::Malformed(_))));
    }

    #[test]
    fn diff_reports_additions_and_version_bumps() {
        let base = vec![package("kept", "1.0.0"), package("bumped", "1.0.0")];
        let current = vec![
            package("kept", "1.0.0"),
            package("bumped", "2.0.0"),
            package("added", "0.1.0"),
        ];
        assert_eq!(
            added(&current, &base),
            vec![package("added", "0.1.0"), package("bumped", "2.0.0")]
        );
    }

    #[test]
    fn diff_is_empty_when_nothing_changed() {
        let packages = vec![package("a", "1.0.0")];
        assert!(added(&packages, &packages).is_empty());
    }
}
