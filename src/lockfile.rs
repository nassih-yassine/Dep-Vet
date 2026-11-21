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
    /// Things that were intentionally not audited but must not fail the run.
    pub notes: Vec<String>,
}

impl LockContents {
    fn packages_only(packages: Vec<LockedPackage>) -> Self {
        Self {
            packages,
            skipped: Vec::new(),
            notes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Npm,
    Bun,
    Pnpm,
    Yarn,
    Deno,
    Pip,
    Poetry,
    Uv,
    Cargo,
    Go,
}

impl Format {
    pub fn ecosystem(self) -> crate::model::Ecosystem {
        match self {
            Self::Npm | Self::Bun | Self::Pnpm | Self::Yarn | Self::Deno => {
                crate::model::Ecosystem::Npm
            }
            Self::Pip | Self::Poetry | Self::Uv => crate::model::Ecosystem::Pypi,
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
        "bun.lock" => Ok(Format::Bun),
        "pnpm-lock.yaml" => Ok(Format::Pnpm),
        "yarn.lock" => Ok(Format::Yarn),
        "deno.lock" => Ok(Format::Deno),
        "Cargo.lock" => Ok(Format::Cargo),
        "go.mod" => Ok(Format::Go),
        "poetry.lock" => Ok(Format::Poetry),
        "uv.lock" => Ok(Format::Uv),
        other if other.ends_with(".txt") && other.contains("requirement") => Ok(Format::Pip),
        other => Err(LockError::UnsupportedFormat(other.to_string())),
    }
}

pub fn parse(format: Format, body: &str) -> Result<LockContents, LockError> {
    match format {
        Format::Npm => parse_npm(body),
        Format::Bun => parse_bun(body),
        Format::Pnpm => parse_pnpm(body),
        Format::Yarn => Ok(parse_yarn(body)),
        Format::Deno => parse_deno(body),
        Format::Pip => Ok(parse_pip(body)),
        Format::Poetry => parse_poetry(body),
        Format::Uv => parse_uv(body),
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

fn parse_bun(body: &str) -> Result<LockContents, LockError> {
    let cleaned = strip_jsonc(body);
    let root: serde_json::Value =
        serde_json::from_str(&cleaned).map_err(|error| LockError::Malformed(error.to_string()))?;
    let packages = root
        .get("packages")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| LockError::Malformed("bun.lock has no `packages` map".to_string()))?;

    let mut collected = Vec::new();
    let mut skipped = Vec::new();
    for value in packages.values() {
        let Some(field) = value
            .as_array()
            .and_then(|tuple| tuple.first())
            .and_then(serde_json::Value::as_str)
        else {
            skipped.push((
                value.to_string(),
                "unreadable bun package entry".to_string(),
            ));
            continue;
        };
        match field.rsplit_once('@') {
            Some((name, version)) if !name.is_empty() && !version.is_empty() => {
                collected.push(LockedPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                });
            }
            _ => skipped.push((
                field.to_string(),
                "unreadable bun package entry".to_string(),
            )),
        }
    }

    Ok(finish(collected, skipped))
}

/// bun.lock is JSON with comments and trailing commas.
fn strip_jsonc(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut without_comments = String::with_capacity(input.len());
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if in_string {
            without_comments.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        match ch {
            '"' => {
                in_string = true;
                without_comments.push(ch);
                index += 1;
            }
            '/' if bytes.get(index + 1) == Some(&b'/') => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            '/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                index = (index + 2).min(bytes.len());
            }
            _ => {
                without_comments.push(ch);
                index += 1;
            }
        }
    }

    let chars: Vec<char> = without_comments.chars().collect();
    let mut cleaned = String::with_capacity(without_comments.len());
    let mut in_string = false;
    let mut escaped = false;
    for (position, &ch) in chars.iter().enumerate() {
        if in_string {
            cleaned.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            cleaned.push(ch);
            continue;
        }
        if ch == ',' {
            let next = chars[position + 1..]
                .iter()
                .find(|candidate| !candidate.is_whitespace());
            if matches!(next, Some('}') | Some(']')) {
                continue;
            }
        }
        cleaned.push(ch);
    }
    cleaned
}

fn parse_deno(body: &str) -> Result<LockContents, LockError> {
    let lockfile: DenoLock =
        serde_json::from_str(body).map_err(|error| LockError::Malformed(error.to_string()))?;
    let mut packages = Vec::new();
    let mut skipped = Vec::new();

    for key in lockfile.npm.keys() {
        match key.rsplit_once('@') {
            Some((name, version)) if !name.is_empty() && !version.is_empty() => {
                packages.push(LockedPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                });
            }
            _ => skipped.push((key.clone(), "unreadable deno npm entry".to_string())),
        }
    }

    let mut contents = finish(packages, skipped);
    if !lockfile.jsr.is_empty() {
        contents.notes.push(format!(
            "{} JSR package(s) not audited: dep-vet has no JSR source yet",
            lockfile.jsr.len()
        ));
    }
    Ok(contents)
}

/// pnpm lockfiles are YAML, but only one section matters: the top-level
/// `packages` mapping. Reading its keys line by line avoids a YAML dependency
/// (and the unmaintained `unsafe-libyaml` it drags in).
fn parse_pnpm(body: &str) -> Result<LockContents, LockError> {
    let mut packages = Vec::new();
    let mut skipped = Vec::new();
    let mut in_packages = false;

    for raw in body.lines() {
        let line = raw.trim_end();
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            in_packages = line == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        // Only direct children of `packages:` are entries; nested keys are
        // resolution details.
        let indent = line.chars().take_while(|ch| *ch == ' ').count();
        if indent != 2 {
            continue;
        }
        let Some((key, _)) = line[2..].split_once(':') else {
            continue;
        };
        let key = key.trim_matches(['"', '\''].as_slice());
        match split_pnpm_key(key) {
            Some((name, version)) => packages.push(LockedPackage { name, version }),
            None => skipped.push((key.to_string(), "unrecognized pnpm package key".to_string())),
        }
    }

    Ok(finish(packages, skipped))
}

/// pnpm v9 keys look like `name@1.2.3`, v6 like `/name@1.2.3`, v5 like
/// `/name/1.2.3`; peer suffixes are appended as `(peer@1.0.0)`.
fn split_pnpm_key(key: &str) -> Option<(String, String)> {
    let key = key.trim_start_matches('/');
    let key = key.split('(').next().unwrap_or(key);
    if let Some((name, version)) = key.rsplit_once('@')
        && !name.is_empty()
        && starts_like_version(version)
    {
        return Some((name.to_string(), version.to_string()));
    }
    let (name, version) = key.rsplit_once('/')?;
    (starts_like_version(version)).then(|| (name.to_string(), version.to_string()))
}

fn starts_like_version(candidate: &str) -> bool {
    candidate
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_digit())
}

fn parse_yarn(body: &str) -> LockContents {
    let lines: Vec<&str> = body.lines().collect();
    let mut packages = Vec::new();
    let mut skipped = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || line.starts_with([' ', '\t']) {
            index += 1;
            continue;
        }
        let Some(header) = line.trim_end().strip_suffix(':') else {
            index += 1;
            continue;
        };
        let selector = header
            .split(',')
            .next()
            .unwrap_or(header)
            .trim()
            .trim_matches('"')
            .to_string();

        let mut version = None;
        let mut cursor = index + 1;
        while cursor < lines.len() && lines[cursor].starts_with([' ', '\t']) {
            let field = lines[cursor].trim();
            if let Some(rest) = field
                .strip_prefix("version ")
                .or_else(|| field.strip_prefix("version:"))
            {
                version = Some(rest.trim().trim_matches('"').to_string());
            }
            cursor += 1;
        }
        index = cursor;

        let Some(version) = version else {
            skipped.push((selector, "yarn entry without a version".to_string()));
            continue;
        };
        // Yarn Berry workspace packages are links to local sources.
        if version.starts_with("0.0.0-use.local") {
            continue;
        }
        // Yarn Berry records its own format version here; it is not a package.
        if selector == "__metadata" {
            continue;
        }
        match selector.rsplit_once('@') {
            Some((name, _range)) if !name.is_empty() => packages.push(LockedPackage {
                name: name.to_string(),
                version,
            }),
            _ => skipped.push((selector, "unreadable yarn selector".to_string())),
        }
    }

    finish(packages, skipped)
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

fn parse_poetry(body: &str) -> Result<LockContents, LockError> {
    let lockfile: TomlPackages =
        toml::from_str(body).map_err(|error| LockError::Malformed(error.to_string()))?;
    let mut packages = Vec::new();
    let mut skipped = Vec::new();

    for package in lockfile.package {
        let is_registry = match &package.source {
            None => true,
            Some(source) => source
                .get("type")
                .and_then(|kind| kind.as_str())
                .is_some_and(|kind| kind == "legacy"),
        };
        if is_registry {
            packages.push(LockedPackage {
                name: package.name,
                version: package.version,
            });
        } else {
            skipped.push((
                format!("{}@{}", package.name, package.version),
                "not a PyPI package (git, path, file, or URL source)".to_string(),
            ));
        }
    }

    Ok(finish(packages, skipped))
}

fn parse_uv(body: &str) -> Result<LockContents, LockError> {
    let lockfile: TomlPackages =
        toml::from_str(body).map_err(|error| LockError::Malformed(error.to_string()))?;
    let mut packages = Vec::new();
    let mut skipped = Vec::new();

    for package in lockfile.package {
        let source = package.source.unwrap_or_default();
        if source.get("registry").is_some() || source.is_empty() {
            packages.push(LockedPackage {
                name: package.name,
                version: package.version,
            });
        } else if source.get("git").is_some() || source.get("url").is_some() {
            skipped.push((
                format!("{}@{}", package.name, package.version),
                "not a PyPI package (git or URL source)".to_string(),
            ));
        }
        // editable/virtual/directory entries are local projects; nothing to audit.
    }

    Ok(finish(packages, skipped))
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
    LockContents {
        packages,
        skipped,
        notes: Vec::new(),
    }
}

#[derive(Debug, Deserialize)]
struct DenoLock {
    #[serde(default)]
    npm: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    jsr: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct TomlPackages {
    #[serde(default)]
    package: Vec<TomlPackage>,
}

#[derive(Debug, Deserialize)]
struct TomlPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<toml::Table>,
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
    fn poetry_keeps_pypi_packages_and_reports_git() {
        let body = r#"
[[package]]
name = "flask"
version = "3.1.0"
description = "A simple framework"
optional = false
python-versions = ">=3.9"

[[package]]
name = "git-dep2"
version = "0.2.0"

[package.source]
type = "git"
url = "https://github.com/example/git-dep2"
"#;
        let contents = parse(Format::Poetry, body).unwrap();
        assert_eq!(contents.packages, vec![package("flask", "3.1.0")]);
        assert_eq!(contents.skipped.len(), 1);
        assert!(contents.skipped[0].1.contains("not a PyPI package"));
    }

    #[test]
    fn uv_keeps_registry_packages_and_skips_local_edits() {
        let body = r#"
version = 1

[[package]]
name = "flask"
version = "3.1.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "my-project"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "viaduct"
version = "0.2.0"
source = { git = "https://github.com/example/viaduct" }
"#;
        let contents = parse(Format::Uv, body).unwrap();
        assert_eq!(contents.packages, vec![package("flask", "3.1.0")]);
        assert_eq!(contents.skipped.len(), 1);
        assert!(contents.skipped[0].1.contains("git or URL"));
    }

    #[test]
    fn poetry_and_uv_reject_malformed_toml() {
        assert!(matches!(
            parse(Format::Poetry, "[[package]"),
            Err(LockError::Malformed(_))
        ));
        assert!(matches!(
            parse(Format::Uv, "version = nope"),
            Err(LockError::Malformed(_))
        ));
    }

    #[test]
    fn bun_reads_its_jsonc_lockfile() {
        let body = r#"{
            // bun writes comments and trailing commas
            "lockfileVersion": 2,
            "workspaces": { "": { "name": "app", } },
            "packages": {
                "is-number": ["is-number@7.0.0", "", {}, "sha512-x"],
                "@scope/pkg": ["@scope/pkg@1.2.3", "", {}, "sha512-y"],
                "broken": [],
            },
        }"#;
        let contents = parse(Format::Bun, body).unwrap();
        assert_eq!(
            contents.packages,
            vec![
                package("@scope/pkg", "1.2.3"),
                package("is-number", "7.0.0")
            ]
        );
        assert_eq!(contents.skipped.len(), 1);
    }

    #[test]
    fn jsonc_stripping_keeps_urls_inside_strings() {
        let cleaned = strip_jsonc(r#"{ "url": "https://example.test/a//b", }"#);
        assert!(cleaned.contains("https://example.test/a//b"));
        assert!(!cleaned.contains(", }"));
    }

    #[test]
    fn bun_rejects_broken_json() {
        assert!(matches!(
            parse(Format::Bun, "{ nope"),
            Err(LockError::Malformed(_))
        ));
    }

    #[test]
    fn pnpm_reads_v9_v6_and_v5_keys() {
        let body = r#"
lockfileVersion: '9.0'
packages:
  is-number@7.0.0: {}
  '@scope/pkg@1.2.3': {}
  'peer-pkg@2.0.0(react@18.0.0)': {}
  '/legacy@1.0.0': {}
  '/old-style/0.9.0': {}
  'file:../local': {}
"#;
        let contents = parse(Format::Pnpm, body).unwrap();
        assert_eq!(
            contents.packages,
            vec![
                package("@scope/pkg", "1.2.3"),
                package("is-number", "7.0.0"),
                package("legacy", "1.0.0"),
                package("old-style", "0.9.0"),
                package("peer-pkg", "2.0.0"),
            ]
        );
        assert_eq!(contents.skipped.len(), 1);
        assert!(contents.skipped[0].1.contains("unrecognized pnpm"));
    }

    #[test]
    fn pnpm_without_a_packages_section_is_empty() {
        let contents = parse(Format::Pnpm, "lockfileVersion: '9.0'\nsettings: {}\n").unwrap();
        assert!(contents.packages.is_empty());
        assert!(contents.skipped.is_empty());
    }

    #[test]
    fn pnpm_ignores_nested_lines_and_comments() {
        let body = "packages:\n  # comment\n  quoted@1.0.0:\n    resolution:\n      integrity: x\n  '@scope/pkg@2.0.0': {}\nsnapshots:\n  other@9.9.9: {}\n";
        let contents = parse(Format::Pnpm, body).unwrap();
        assert_eq!(
            contents.packages,
            vec![package("@scope/pkg", "2.0.0"), package("quoted", "1.0.0")]
        );
    }

    #[test]
    fn yarn_reads_classic_and_berry_entries() {
        let classic = r#"
# yarn lockfile v1

"@scope/pkg@^1.0.0":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.2.3.tgz"

is-number@7.0.0:
  version "7.0.0"
"#;
        let contents = parse(Format::Yarn, classic).unwrap();
        assert_eq!(
            contents.packages,
            vec![
                package("@scope/pkg", "1.2.3"),
                package("is-number", "7.0.0")
            ]
        );

        let berry = r#"
__metadata:
  version: 8

"is-number@npm:^7.0.0":
  version: 7.0.0
  resolution: "is-number@npm:7.0.0"

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
"#;
        let contents = parse(Format::Yarn, berry).unwrap();
        assert_eq!(contents.packages, vec![package("is-number", "7.0.0")]);
        assert!(
            contents.skipped.is_empty(),
            "__metadata is not a package: {:?}",
            contents.skipped
        );
    }

    #[test]
    fn yarn_reports_entries_without_a_version() {
        let body = r#"
broken@1.0.0:
  resolved "https://example.test/broken.tgz"
"#;
        let contents = parse(Format::Yarn, body).unwrap();
        assert!(contents.packages.is_empty());
        assert_eq!(contents.skipped.len(), 1);
        assert!(contents.skipped[0].1.contains("without a version"));
    }

    #[test]
    fn deno_reads_npm_entries_and_notes_jsr() {
        let body = r#"{
            "version": "5",
            "jsr": {
                "@std/assert@1.0.0": { "integrity": "abc" },
                "@std/internal@1.0.14": { "integrity": "def" }
            },
            "npm": {
                "chalk@5.3.0": { "integrity": "sha512-x" },
                "@scope/pkg@1.2.3": { "integrity": "sha512-y" }
            }
        }"#;
        let contents = parse(Format::Deno, body).unwrap();
        assert_eq!(
            contents.packages,
            vec![package("@scope/pkg", "1.2.3"), package("chalk", "5.3.0")]
        );
        assert_eq!(contents.notes.len(), 1);
        assert!(contents.notes[0].contains("2 JSR package"));
    }

    #[test]
    fn deno_with_only_jsr_has_no_packages_but_a_note() {
        let body = r#"{ "version": "5", "jsr": { "@std/assert@1.0.0": {} } }"#;
        let contents = parse(Format::Deno, body).unwrap();
        assert!(contents.packages.is_empty());
        assert_eq!(contents.notes.len(), 1);
    }

    #[test]
    fn deno_rejects_malformed_json() {
        assert!(matches!(
            parse(Format::Deno, "{ nope"),
            Err(LockError::Malformed(_))
        ));
    }

    #[test]
    fn detects_each_supported_lockfile() {
        assert_eq!(detect(Path::new("package-lock.json")).unwrap(), Format::Npm);
        assert_eq!(detect(Path::new("Cargo.lock")).unwrap(), Format::Cargo);
        assert_eq!(detect(Path::new("go.mod")).unwrap(), Format::Go);
        assert_eq!(detect(Path::new("poetry.lock")).unwrap(), Format::Poetry);
        assert_eq!(detect(Path::new("uv.lock")).unwrap(), Format::Uv);
        assert_eq!(detect(Path::new("bun.lock")).unwrap(), Format::Bun);
        assert_eq!(detect(Path::new("pnpm-lock.yaml")).unwrap(), Format::Pnpm);
        assert_eq!(detect(Path::new("yarn.lock")).unwrap(), Format::Yarn);
        assert_eq!(detect(Path::new("deno.lock")).unwrap(), Format::Deno);
        assert_eq!(detect(Path::new("requirements.txt")).unwrap(), Format::Pip);
        assert_eq!(
            detect(Path::new("dev-requirements.txt")).unwrap(),
            Format::Pip
        );
        assert!(matches!(
            detect(Path::new("go.sum")),
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
