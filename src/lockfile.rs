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
}

pub fn read(path: &Path) -> Result<Vec<LockedPackage>, LockError> {
    let body = std::fs::read_to_string(path).map_err(|source| LockError::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse(&body)
}

/// Flattens the `packages` map into name/version pairs, dropping workspace
/// links (they have no version and point at local directories).
pub fn parse(body: &str) -> Result<Vec<LockedPackage>, LockError> {
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
    Ok(packages)
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
pub fn at_ref(lockfile: &Path, git_ref: &str) -> Result<Vec<LockedPackage>, LockError> {
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
    parse(&blob).map_err(|error| match error {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(body: &str) -> Vec<LockedPackage> {
        parse(body).unwrap()
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
    fn version_one_lockfiles_are_rejected_with_guidance() {
        let error = parse(r#"{ "lockfileVersion": 1, "dependencies": {} }"#).unwrap_err();
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
        let error = parse(r#"{ "lockfileVersion": 3 }"#).unwrap_err();
        assert!(error.to_string().contains("packages"));
    }

    #[test]
    fn malformed_json_is_rejected() {
        assert!(matches!(parse("nope"), Err(LockError::Malformed(_))));
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
