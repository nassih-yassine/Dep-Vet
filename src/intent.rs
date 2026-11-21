//! Parse shell commands into install intents. Pure: no I/O, no execution.
//!
//! This is a best-effort parser, not a shell. Anything it cannot parse is
//! reported as a note; callers must not treat a note-free result as a
//! guarantee that nothing installs.

use crate::model::{Ecosystem, PackageSpec};

pub const MAX_COMMAND_BYTES: usize = 64 * 1024;
/// One level of `sh -c` is understood; deeper nesting is noted, not followed.
const MAX_DEPTH: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentKind {
    Install,
    Ephemeral,
    Lockfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub ecosystem: Ecosystem,
    pub kind: IntentKind,
    pub specs: Vec<PackageSpec>,
    /// Set for `IntentKind::Lockfile`: the file the caller may audit.
    pub lockfile: Option<String>,
    /// The command segment this intent came from, trimmed.
    pub source: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParseOutcome {
    pub intents: Vec<Intent>,
    pub notes: Vec<String>,
}

/// Segment a command on `&&`, `||`, `;`, `|`, and newlines, outside quotes.
fn segments(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut chars = command.chars().peekable();
    while let Some(character) = chars.next() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(open) = quote {
            current.push(character);
            if character == open {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => {
                quote = Some(character);
                current.push(character);
            }
            '#' if current.is_empty()
                || current.chars().last().is_some_and(char::is_whitespace) =>
            {
                out.push(std::mem::take(&mut current));
                for next in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
            }
            '&' if chars.peek() == Some(&'&') => {
                chars.next();
                out.push(std::mem::take(&mut current));
            }
            '&' => out.push(std::mem::take(&mut current)),
            '|' => {
                if chars.peek() == Some(&'|') {
                    chars.next();
                }
                out.push(std::mem::take(&mut current));
            }
            ';' | '\n' => out.push(std::mem::take(&mut current)),
            '>' | '<' => {
                // Drop the fd prefix and the redirection target.
                while current.chars().last().is_some_and(|c| c.is_ascii_digit()) {
                    current.pop();
                }
                while chars.peek().is_some_and(|next| next.is_whitespace()) {
                    chars.next();
                }
                while let Some(next) = chars.peek().copied() {
                    if next.is_whitespace() || matches!(next, '&' | '|' | ';' | '<' | '>') {
                        break;
                    }
                    chars.next();
                }
            }
            _ => current.push(character),
        }
    }
    out.push(current);
    out.into_iter()
        .map(|segment| segment.trim().to_string())
        .filter(|segment| !segment.is_empty())
        .collect()
}

/// Split a segment into shell-ish words, removing quotes and backslash escapes.
fn words(segment: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut started = false;
    for character in segment.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            started = true;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(open) = quote {
            if character == open {
                quote = None;
            } else {
                current.push(character);
            }
            started = true;
            continue;
        }
        match character {
            '\'' | '"' => {
                quote = Some(character);
                started = true;
            }
            character if character.is_whitespace() => {
                if started {
                    out.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            _ => {
                current.push(character);
                started = true;
            }
        }
    }
    if started {
        out.push(current);
    }
    out
}

fn spec(ecosystem: Ecosystem, raw: &str) -> Result<PackageSpec, String> {
    match ecosystem {
        Ecosystem::Npm => PackageSpec::parse(raw),
        Ecosystem::Pypi => PackageSpec::parse_pypi(raw),
        Ecosystem::CratesIo => PackageSpec::parse_crates(raw),
        Ecosystem::Go => PackageSpec::parse_go(raw),
        Ecosystem::Jsr => PackageSpec::parse_jsr(raw),
        Ecosystem::RubyGems => PackageSpec::parse_gem(raw),
        Ecosystem::NuGet => PackageSpec::parse_nuget(raw),
        Ecosystem::Maven => PackageSpec::parse_maven(raw),
        Ecosystem::Composer => PackageSpec::parse_composer(raw),
    }
    .map_err(|error| error.to_string())
}

fn is_spec_like(token: &str) -> bool {
    !token.starts_with('-')
        && !token.contains("://")
        && !token.starts_with("git+")
        && !token.starts_with("github:")
        && !token.starts_with("gitlab:")
        && !token.starts_with("bitbucket:")
        && !token.starts_with("file:")
        && !token.starts_with("link:")
        && !token.starts_with("workspace:")
        && !token.starts_with('.')
        && !token.starts_with('/')
}

struct Collected {
    specs: Vec<PackageSpec>,
    notes: Vec<String>,
    lockfile: Option<String>,
    blocked: bool,
}

impl Collected {
    fn new() -> Self {
        Self {
            specs: Vec::new(),
            notes: Vec::new(),
            lockfile: None,
            blocked: false,
        }
    }

    fn push(&mut self, ecosystem: Ecosystem, raw: &str) {
        if !is_spec_like(raw) {
            self.notes
                .push(format!("not a registry package (not vetted): {raw}"));
            self.blocked = true;
            return;
        }
        match spec(ecosystem, raw) {
            Ok(spec) => self.specs.push(spec),
            Err(_) => {
                self.notes.push(format!("unparsed package argument: {raw}"));
                self.blocked = true;
            }
        }
    }

    fn push_name_version(&mut self, ecosystem: Ecosystem, name: &str, version: &str) {
        match spec(ecosystem, &format!("{name}@{version}")) {
            Ok(spec) => self.specs.push(spec),
            Err(_) => self
                .notes
                .push(format!("unparsed package argument: {name}")),
        }
    }
}

fn finish(
    outcome: &mut ParseOutcome,
    segment: &str,
    ecosystem: Ecosystem,
    kind: IntentKind,
    collected: Collected,
) {
    outcome.notes.extend(collected.notes);
    let lockfile = collected.lockfile;
    let kind = if collected.specs.is_empty() && lockfile.is_some() {
        IntentKind::Lockfile
    } else {
        kind
    };
    outcome.intents.push(Intent {
        ecosystem,
        kind,
        specs: collected.specs,
        lockfile,
        source: segment.to_string(),
    });
}

/// Collect package-like tokens while consuming manager-specific flags.
fn collect(
    ecosystem: Ecosystem,
    tokens: &[String],
    values: &[&str],
    version_flag: Option<&str>,
) -> Collected {
    let mut collected = Collected::new();
    let mut pending_version: Option<String> = None;
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if version_flag == Some(token.as_str()) {
            pending_version = tokens.get(index + 1).cloned();
            index += 2;
            continue;
        }
        if values.contains(&token.as_str()) {
            index += 2;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        if let Some(version) = pending_version.take() {
            if let Ok(mut spec) = spec(ecosystem, token) {
                if spec.version.is_none() {
                    spec.version = Some(version);
                }
                collected.specs.push(spec);
            } else {
                collected
                    .notes
                    .push(format!("unparsed package argument: {token}"));
            }
            index += 1;
            continue;
        }
        collected.push(ecosystem, token);
        index += 1;
    }
    collected
}

const VALUES: &[&str] = &[
    "--registry",
    "--tag",
    "--prefix",
    "--cache",
    "--userconfig",
    "--workspace",
    "-w",
    "--omit",
    "--save-prefix",
    "--before",
    "--otp",
    "--index-url",
    "-i",
    "--extra-index-url",
    "--target",
    "-t",
    "--python-version",
    "--platform",
    "--implementation",
    "--abi",
    "--only-binary",
    "--no-binary",
    "--constraint",
    "-c",
    "--source",
    "--git",
    "--path",
    "--branch",
    "--rev",
    "--features",
    "--package",
    "-p",
    "--version",
    "-v",
    "--install-dir",
    "-n",
    "--bindir",
    "--working-dir",
    "--repository",
];

fn npm_like(
    outcome: &mut ParseOutcome,
    segment: &str,
    tokens: &[String],
    kind: IntentKind,
    lockfile: &str,
) {
    let mut collected = collect(Ecosystem::Npm, tokens, VALUES, None);
    if collected.specs.is_empty() && !collected.blocked {
        collected.lockfile = Some(lockfile.to_string());
    }
    finish(outcome, segment, Ecosystem::Npm, kind, collected);
}

fn ephemeral(outcome: &mut ParseOutcome, segment: &str, tokens: &[String], ecosystem: Ecosystem) {
    let mut collected = Collected::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if matches!(token.as_str(), "--package" | "-p") {
            if let Some(raw) = tokens.get(index + 1) {
                collected.push(ecosystem, raw);
            }
            index += 2;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        // The first non-flag token is the package; the rest is its command.
        collected.push(ecosystem, token);
        break;
    }
    finish(
        outcome,
        segment,
        ecosystem,
        IntentKind::Ephemeral,
        collected,
    );
}

fn pip_install(outcome: &mut ParseOutcome, segment: &str, tokens: &[String]) {
    let mut collected = Collected::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        match token.as_str() {
            "-r" | "--requirement" => {
                if let Some(path) = tokens.get(index + 1) {
                    collected.lockfile = Some(path.clone());
                }
                index += 2;
                continue;
            }
            "-e" | "--editable" => {
                if let Some(path) = tokens.get(index + 1) {
                    collected
                        .notes
                        .push(format!("editable install (not vetted): {path}"));
                    collected.blocked = true;
                }
                index += 2;
                continue;
            }
            _ => {}
        }
        if VALUES.contains(&token.as_str()) {
            index += 2;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        collected.push(Ecosystem::Pypi, token);
        index += 1;
    }
    if collected.specs.is_empty() && collected.lockfile.is_none() && !collected.blocked {
        collected.lockfile = Some("requirements.txt".to_string());
    } else if let (Some(lockfile), false) = (&collected.lockfile, collected.specs.is_empty()) {
        collected
            .notes
            .push(format!("lockfile not audited: {lockfile}"));
    }
    finish(
        outcome,
        segment,
        Ecosystem::Pypi,
        IntentKind::Install,
        collected,
    );
}

fn composer_require(outcome: &mut ParseOutcome, segment: &str, tokens: &[String]) {
    let mut collected = Collected::new();
    for token in tokens {
        if token.starts_with('-') {
            continue;
        }
        match token.split_once(':') {
            Some((name, version)) => {
                collected.push_name_version(Ecosystem::Composer, name, version)
            }
            None => collected.push(Ecosystem::Composer, token),
        }
    }
    finish(
        outcome,
        segment,
        Ecosystem::Composer,
        IntentKind::Install,
        collected,
    );
}

fn dotnet_add(outcome: &mut ParseOutcome, segment: &str, tokens: &[String]) {
    // `dotnet add package Name --version 13`
    let mut collected = Collected::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if token == "--version" {
            if let (Some(spec), Some(version)) = (collected.specs.last_mut(), tokens.get(index + 1))
            {
                spec.version = Some(version.clone());
            }
            index += 2;
            continue;
        }
        if VALUES.contains(&token.as_str()) {
            index += 2;
            continue;
        }
        if token.starts_with('-') || token == "package" {
            index += 1;
            continue;
        }
        collected.push(Ecosystem::NuGet, token);
        index += 1;
    }
    finish(
        outcome,
        segment,
        Ecosystem::NuGet,
        IntentKind::Install,
        collected,
    );
}

fn cargo_install(outcome: &mut ParseOutcome, segment: &str, tokens: &[String]) {
    let mut collected = Collected::new();
    let mut remote = false;
    let mut index = 0;
    while index + 1 < tokens.len() {
        let token = &tokens[index];
        if matches!(token.as_str(), "--git" | "--path") {
            remote = true;
            index += 2;
            continue;
        }
        index += 1;
    }
    if remote {
        collected
            .notes
            .push(format!("source install (not vetted): {segment}"));
        collected.blocked = true;
    } else {
        collected = collect(Ecosystem::CratesIo, tokens, VALUES, Some("--version"));
    }
    finish(
        outcome,
        segment,
        Ecosystem::CratesIo,
        IntentKind::Install,
        collected,
    );
}

fn unparsed_install_like(outcome: &mut ParseOutcome, segment: &str, tokens: &[String]) {
    const MANAGERS: &[&str] = &[
        "npm", "pnpm", "yarn", "bun", "npx", "bunx", "pip", "pip3", "uv", "uvx", "pipx", "poetry",
        "pipenv", "cargo", "go", "gem", "bundle", "dotnet", "composer", "deno", "winget", "brew",
        "choco", "scoop",
    ];
    const VERBS: &[&str] = &["install", "i", "add", "get", "require", "ci", "exec", "dlx"];
    let manager = tokens
        .iter()
        .any(|token| MANAGERS.contains(&token.as_str()));
    let verb = tokens.iter().any(|token| VERBS.contains(&token.as_str()));
    if manager && verb {
        outcome
            .notes
            .push(format!("install-like command was not parsed: {segment}"));
    }
}

fn handle_segment(segment: &str, depth: u8, outcome: &mut ParseOutcome) {
    let mut tokens = words(segment);
    while let Some(token) = tokens.first().cloned() {
        if token.contains('=') && !token.starts_with('-') {
            tokens.remove(0);
            continue;
        }
        match token.as_str() {
            "sudo" | "time" | "nohup" => {
                tokens.remove(0);
                while tokens.first().is_some_and(|flag| flag.starts_with('-')) {
                    tokens.remove(0);
                }
            }
            "env" => {
                tokens.remove(0);
                while tokens
                    .first()
                    .is_some_and(|flag| flag.starts_with('-') || flag.contains('='))
                {
                    tokens.remove(0);
                }
            }
            "command" => {
                tokens.remove(0);
                if tokens
                    .first()
                    .is_some_and(|flag| flag == "-v" || flag == "-V")
                {
                    return;
                }
            }
            _ => break,
        }
    }
    if tokens.is_empty() || tokens[0] == "cd" {
        return;
    }

    if depth < MAX_DEPTH
        && matches!(tokens[0].as_str(), "bash" | "sh" | "zsh")
        && tokens
            .get(1)
            .is_some_and(|flag| flag == "-c" || flag == "-lc")
    {
        if let Some(script) = tokens.get(2) {
            let nested = parse_depth(script, depth + 1);
            outcome.notes.extend(nested.notes);
            outcome.intents.extend(nested.intents);
        }
        return;
    }

    let produced = outcome.intents.len();
    let rest = &tokens[1..];
    match tokens[0].as_str() {
        "npm" => match rest.first().map(String::as_str) {
            Some("install" | "i" | "add") => npm_like(
                outcome,
                segment,
                &rest[1..],
                IntentKind::Install,
                "package-lock.json",
            ),
            Some("ci") => {
                let mut collected = Collected::new();
                collected.lockfile = Some("package-lock.json".to_string());
                finish(
                    outcome,
                    segment,
                    Ecosystem::Npm,
                    IntentKind::Lockfile,
                    collected,
                );
            }
            _ => {}
        },
        "pnpm" => match rest.first().map(String::as_str) {
            Some("dlx") => ephemeral(outcome, segment, &rest[1..], Ecosystem::Npm),
            Some("install" | "i" | "add") => npm_like(
                outcome,
                segment,
                &rest[1..],
                IntentKind::Install,
                "pnpm-lock.yaml",
            ),
            _ => {}
        },
        "yarn" => match rest.first().map(String::as_str) {
            Some("dlx") => ephemeral(outcome, segment, &rest[1..], Ecosystem::Npm),
            Some("install" | "add") => npm_like(
                outcome,
                segment,
                &rest[1..],
                IntentKind::Install,
                "yarn.lock",
            ),
            _ => {}
        },
        "bun" => {
            if rest
                .first()
                .is_some_and(|verb| matches!(verb.as_str(), "install" | "add"))
            {
                npm_like(
                    outcome,
                    segment,
                    &rest[1..],
                    IntentKind::Install,
                    "bun.lock",
                );
            }
        }
        "bunx" => ephemeral(outcome, segment, rest, Ecosystem::Npm),
        "npx" => ephemeral(outcome, segment, rest, Ecosystem::Npm),
        "pip" | "pip3" => {
            if rest.first().is_some_and(|verb| verb == "install") {
                pip_install(outcome, segment, &rest[1..]);
            }
        }
        "python" | "python3" => {
            if rest.first().is_some_and(|flag| flag == "-m")
                && rest.get(1).is_some_and(|module| module == "pip")
                && rest.get(2).is_some_and(|verb| verb == "install")
            {
                pip_install(outcome, segment, &rest[3..]);
            }
        }
        "uv" => match rest.first().map(String::as_str) {
            Some("add") => {
                let collected = collect(Ecosystem::Pypi, &rest[1..], VALUES, None);
                finish(
                    outcome,
                    segment,
                    Ecosystem::Pypi,
                    IntentKind::Install,
                    collected,
                );
            }
            Some("pip") if rest.get(1).is_some_and(|verb| verb == "install") => {
                pip_install(outcome, segment, &rest[2..]);
            }
            Some("tool") if rest.get(1).is_some_and(|verb| verb == "install") => {
                let collected = collect(Ecosystem::Pypi, &rest[2..], VALUES, None);
                finish(
                    outcome,
                    segment,
                    Ecosystem::Pypi,
                    IntentKind::Install,
                    collected,
                );
            }
            _ => {}
        },
        "uvx" => ephemeral(outcome, segment, rest, Ecosystem::Pypi),
        "pipx" => match rest.first().map(String::as_str) {
            Some("install") => {
                let collected = collect(Ecosystem::Pypi, &rest[1..], VALUES, None);
                finish(
                    outcome,
                    segment,
                    Ecosystem::Pypi,
                    IntentKind::Install,
                    collected,
                );
            }
            Some("run") => ephemeral(outcome, segment, &rest[1..], Ecosystem::Pypi),
            _ => {}
        },
        "poetry" => {
            if rest.first().is_some_and(|verb| verb == "add") {
                let collected = collect(Ecosystem::Pypi, &rest[1..], VALUES, None);
                finish(
                    outcome,
                    segment,
                    Ecosystem::Pypi,
                    IntentKind::Install,
                    collected,
                );
            }
        }
        "pipenv" => {
            if rest.first().is_some_and(|verb| verb == "install") {
                let mut collected = collect(Ecosystem::Pypi, &rest[1..], VALUES, None);
                if collected.specs.is_empty() && !collected.blocked {
                    collected.lockfile = Some("Pipfile.lock".to_string());
                }
                finish(
                    outcome,
                    segment,
                    Ecosystem::Pypi,
                    IntentKind::Install,
                    collected,
                );
            }
        }
        "cargo" => match rest.first().map(String::as_str) {
            Some("add") => {
                let collected = collect(Ecosystem::CratesIo, &rest[1..], VALUES, None);
                finish(
                    outcome,
                    segment,
                    Ecosystem::CratesIo,
                    IntentKind::Install,
                    collected,
                );
            }
            Some("install") => cargo_install(outcome, segment, &rest[1..]),
            _ => {}
        },
        "go" => {
            if rest
                .first()
                .is_some_and(|verb| verb == "get" || verb == "install")
            {
                let collected = collect(Ecosystem::Go, &rest[1..], VALUES, None);
                finish(
                    outcome,
                    segment,
                    Ecosystem::Go,
                    IntentKind::Install,
                    collected,
                );
            }
        }
        "gem" => {
            if rest.first().is_some_and(|verb| verb == "install") {
                let mut collected = collect(Ecosystem::RubyGems, &rest[1..], VALUES, None);
                if let Some(flag) = rest
                    .iter()
                    .position(|token| token == "-v" || token == "--version")
                    && let (Some(spec), Some(version)) =
                        (collected.specs.last_mut(), rest.get(flag + 1))
                {
                    spec.version = Some(version.clone());
                }
                finish(
                    outcome,
                    segment,
                    Ecosystem::RubyGems,
                    IntentKind::Install,
                    collected,
                );
            }
        }
        "bundle" => match rest.first().map(String::as_str) {
            Some("add") => {
                let collected = collect(Ecosystem::RubyGems, &rest[1..], VALUES, None);
                finish(
                    outcome,
                    segment,
                    Ecosystem::RubyGems,
                    IntentKind::Install,
                    collected,
                );
            }
            Some("install") => {
                let mut collected = Collected::new();
                collected.lockfile = Some("Gemfile.lock".to_string());
                finish(
                    outcome,
                    segment,
                    Ecosystem::RubyGems,
                    IntentKind::Lockfile,
                    collected,
                );
            }
            _ => {}
        },
        "dotnet" => {
            if rest.first().is_some_and(|verb| verb == "add")
                && rest.get(1).is_some_and(|noun| noun == "package")
            {
                dotnet_add(outcome, segment, &rest[2..]);
            }
        }
        "composer" if rest.first().is_some_and(|verb| verb == "require") => {
            composer_require(outcome, segment, &rest[1..])
        }
        _ => {}
    }
    if outcome.intents.len() == produced {
        unparsed_install_like(outcome, segment, &tokens);
    }
}

pub fn parse(command: &str) -> ParseOutcome {
    parse_depth(command, 0)
}

/// Cut a command to the parser's byte budget without splitting a UTF-8 char.
pub fn cap_command(command: &str) -> (&str, bool) {
    if command.len() <= MAX_COMMAND_BYTES {
        return (command, false);
    }
    let mut end = MAX_COMMAND_BYTES;
    while !command.is_char_boundary(end) {
        end -= 1;
    }
    (&command[..end], true)
}

fn parse_depth(command: &str, depth: u8) -> ParseOutcome {
    let mut outcome = ParseOutcome::default();
    let (command, truncated) = cap_command(command);
    if truncated {
        outcome.notes.push(format!(
            "command truncated at {MAX_COMMAND_BYTES} bytes; the rest was not parsed"
        ));
    }
    let command = command.replace("\\\n", " ").replace("\r\n", "\n");
    for segment in segments(&command) {
        handle_segment(&segment, depth, &mut outcome);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_shell_separators_outside_quotes() {
        let parsed = parse("npm i a && npm i b; npm i c | tee log || npm i d");
        assert_eq!(parsed.intents.len(), 4, "{parsed:?}");
        assert!(
            parsed
                .intents
                .iter()
                .all(|intent| intent.kind == IntentKind::Install)
        );
    }

    #[test]
    fn keeps_quoted_separators_inside_one_command() {
        let parsed = parse(r#"npm i "left&&right" 'a;b'"#);
        assert_eq!(parsed.intents.len(), 1, "quoted separators must not split");
        assert!(parsed.notes.iter().any(|note| note.contains("unparsed")));
    }

    #[test]
    fn joins_backslash_continuations_and_crlf() {
        let parsed = parse("npm i \\\n  express\r\n");
        assert_eq!(parsed.intents.len(), 1);
        assert_eq!(parsed.intents[0].specs[0].name, "express");
    }

    fn case(command: &str, ecosystem: Ecosystem, kind: IntentKind, specs: &[(&str, Option<&str>)]) {
        let parsed = parse(command);
        let found: Vec<(Ecosystem, IntentKind)> = parsed
            .intents
            .iter()
            .map(|intent| (intent.ecosystem, intent.kind.clone()))
            .collect();
        assert!(
            found.contains(&(ecosystem, kind.clone())),
            "{command}: {parsed:?}"
        );
        let intent = parsed
            .intents
            .iter()
            .find(|intent| intent.ecosystem == ecosystem && intent.kind == kind)
            .unwrap();
        for (name, version) in specs {
            assert!(
                intent
                    .specs
                    .iter()
                    .any(|spec| { spec.name == *name && spec.version.as_deref() == *version }),
                "{command}: expected {name}@{version:?} in {parsed:?}"
            );
        }
    }

    #[test]
    fn install_commands_across_ecosystems() {
        use Ecosystem::*;
        use IntentKind::*;
        let v = |value: &'static str| Some(value);

        case("npm i express", Npm, Install, &[("express", None)]);
        case(
            "npm install express@5.1.0",
            Npm,
            Install,
            &[("express", v("5.1.0"))],
        );
        case(
            "npm i -D @scope/pkg@1.2.3",
            Npm,
            Install,
            &[("@scope/pkg", v("1.2.3"))],
        );
        case("npm i a b", Npm, Install, &[("a", None), ("b", None)]);
        case(
            "npm i --registry https://r.test express",
            Npm,
            Install,
            &[("express", None)],
        );
        case("npm add express", Npm, Install, &[("express", None)]);
        case("pnpm add express@5", Npm, Install, &[("express", v("5"))]);
        case("pnpm i express", Npm, Install, &[("express", None)]);
        case("yarn add express", Npm, Install, &[("express", None)]);
        case("yarn install express", Npm, Install, &[("express", None)]);
        case("bun add express", Npm, Install, &[("express", None)]);
        case("npx create-vite", Npm, Ephemeral, &[("create-vite", None)]);
        case("npx -y express", Npm, Ephemeral, &[("express", None)]);
        case("npx --package foo bar", Npm, Ephemeral, &[("foo", None)]);
        case("pnpm dlx express", Npm, Ephemeral, &[("express", None)]);
        case("yarn dlx express", Npm, Ephemeral, &[("express", None)]);
        case("bunx express", Npm, Ephemeral, &[("express", None)]);

        case("pip install requests", Pypi, Install, &[("requests", None)]);
        case(
            "pip3 install requests==2.31.0",
            Pypi,
            Install,
            &[("requests", v("2.31.0"))],
        );
        case(
            "pip install requests[security]==2.31.0",
            Pypi,
            Install,
            &[("requests", v("2.31.0"))],
        );
        case(
            "python -m pip install flask",
            Pypi,
            Install,
            &[("flask", None)],
        );
        case(
            "python3 -m pip install flask",
            Pypi,
            Install,
            &[("flask", None)],
        );
        case(
            "pip install -i https://pypi.test/simple flask",
            Pypi,
            Install,
            &[("flask", None)],
        );
        case("uv add flask", Pypi, Install, &[("flask", None)]);
        case("uv pip install flask", Pypi, Install, &[("flask", None)]);
        case("uvx ruff", Pypi, Ephemeral, &[("ruff", None)]);
        case("pipx install ruff", Pypi, Install, &[("ruff", None)]);
        case("pipx run ruff", Pypi, Ephemeral, &[("ruff", None)]);
        case("poetry add flask", Pypi, Install, &[("flask", None)]);
        case("pipenv install flask", Pypi, Install, &[("flask", None)]);

        case("cargo add serde", CratesIo, Install, &[("serde", None)]);
        case(
            "cargo add serde@1.0.229",
            CratesIo,
            Install,
            &[("serde", v("1.0.229"))],
        );
        case(
            "cargo install ripgrep",
            CratesIo,
            Install,
            &[("ripgrep", None)],
        );
        case(
            "cargo install --version 1.0.0 ripgrep",
            CratesIo,
            Install,
            &[("ripgrep", v("1.0.0"))],
        );
        case(
            "go get example.com/m",
            Go,
            Install,
            &[("example.com/m", None)],
        );
        case(
            "go install example.com/m@v1.2.3",
            Go,
            Install,
            &[("example.com/m", v("v1.2.3"))],
        );
        case("gem install rake", RubyGems, Install, &[("rake", None)]);
        case(
            "gem install rake -v 13.0.6",
            RubyGems,
            Install,
            &[("rake", v("13.0.6"))],
        );
        case("bundle add rake", RubyGems, Install, &[("rake", None)]);
        case(
            "dotnet add package Newtonsoft.Json",
            NuGet,
            Install,
            &[("Newtonsoft.Json", None)],
        );
        case(
            "dotnet add package Newtonsoft.Json --version 13.0.3",
            NuGet,
            Install,
            &[("Newtonsoft.Json", v("13.0.3"))],
        );
        case(
            "composer require vendor/pkg",
            Composer,
            Install,
            &[("vendor/pkg", None)],
        );
        case(
            "composer require vendor/pkg:^1.2",
            Composer,
            Install,
            &[("vendor/pkg", v("^1.2"))],
        );

        case(
            "bash -c \"npm i nested\"",
            Npm,
            Install,
            &[("nested", None)],
        );
        case("sh -c 'npm i nested'", Npm, Install, &[("nested", None)]);
        case(
            "cd /tmp && npm i after-cd",
            Npm,
            Install,
            &[("after-cd", None)],
        );
        case(
            "sudo -E env FOO=1 npm i privileged",
            Npm,
            Install,
            &[("privileged", None)],
        );
        case("time npm i timed", Npm, Install, &[("timed", None)]);
        case(
            "command npm i commanded",
            Npm,
            Install,
            &[("commanded", None)],
        );
        case("nohup npm i nohuped", Npm, Install, &[("nohuped", None)]);
        case("npm i foo; rm -rf /", Npm, Install, &[("foo", None)]);
        case(
            "npm i @scope/name@1.2.3",
            Npm,
            Install,
            &[("@scope/name", v("1.2.3"))],
        );

        case("npm install", Npm, Lockfile, &[]);
        case("npm ci", Npm, Lockfile, &[]);
        case("yarn install", Npm, Lockfile, &[]);
        case("pnpm install", Npm, Lockfile, &[]);
        case("bun install", Npm, Lockfile, &[]);
        case("pip install -r requirements.txt", Pypi, Lockfile, &[]);
        case("pipenv install", Pypi, Lockfile, &[]);
        case("bundle install", RubyGems, Lockfile, &[]);

        case("npm i -g express", Npm, Install, &[("express", None)]);
        case(
            "npm i --save-exact express@5",
            Npm,
            Install,
            &[("express", v("5"))],
        );
        case("npm i express@^5", Npm, Install, &[("express", v("^5"))]);
        case(
            "npm i @types/node@20",
            Npm,
            Install,
            &[("@types/node", v("20"))],
        );
        case("npm i -- express", Npm, Install, &[("express", None)]);
        case("pnpm i -D express", Npm, Install, &[("express", None)]);
        case("yarn add -D express", Npm, Install, &[("express", None)]);
        case(
            "bun add express@latest",
            Npm,
            Install,
            &[("express", v("latest"))],
        );
        case(
            "npx -p express create",
            Npm,
            Ephemeral,
            &[("express", None)],
        );
        case(
            "yarn dlx -p express create",
            Npm,
            Ephemeral,
            &[("express", None)],
        );
        case(
            "pip install \"requests==2.31.0\"",
            Pypi,
            Install,
            &[("requests", v("2.31.0"))],
        );
        case(
            "pip install flask --upgrade",
            Pypi,
            Install,
            &[("flask", None)],
        );
        case("uv pip install -r requirements.txt", Pypi, Lockfile, &[]);
        case(
            "cargo add tokio --features full",
            CratesIo,
            Install,
            &[("tokio", None)],
        );
        case(
            "cargo install --locked ripgrep",
            CratesIo,
            Install,
            &[("ripgrep", None)],
        );
        case(
            "go get -u example.com/m",
            Go,
            Install,
            &[("example.com/m", None)],
        );
        case(
            "gem install rails --version 7.1.0",
            RubyGems,
            Install,
            &[("rails", v("7.1.0"))],
        );
        case(
            "dotnet add package Newtonsoft.Json --version 13.0.3 --source https://api.nuget.org/v3/index.json",
            NuGet,
            Install,
            &[("Newtonsoft.Json", v("13.0.3"))],
        );
        case(
            "composer require --dev phpunit/phpunit:^10",
            Composer,
            Install,
            &[("phpunit/phpunit", v("^10"))],
        );
        case(
            "bash -c \"cd /tmp && npm i nested\"",
            Npm,
            Install,
            &[("nested", None)],
        );
        case(
            "FOO=1 BAR=2 npm i assigned",
            Npm,
            Install,
            &[("assigned", None)],
        );
        case("sudo npm i elevated", Npm, Install, &[("elevated", None)]);
        case(
            "npm i left-pad right-pad",
            Npm,
            Install,
            &[("left-pad", None), ("right-pad", None)],
        );
    }

    #[test]
    fn the_table_has_at_least_60_cases() {
        let count = include_str!("intent.rs")
            .matches("\n        case(\"")
            .count()
            + include_str!("intent.rs")
                .matches("\n        case(\n")
                .count();
        assert!(count >= 60, "the contract table has {count} cases");
    }

    #[test]
    fn comments_redirections_and_background_do_not_become_packages() {
        for command in [
            "npm i some-pkg # bump",
            "npm i some-pkg 2>&1",
            "npm i some-pkg &",
            "npm i some-pkg > build.log",
        ] {
            let parsed = parse(command);
            let names: Vec<&str> = parsed
                .intents
                .iter()
                .flat_map(|intent| intent.specs.iter().map(|spec| spec.name.as_str()))
                .collect();
            assert_eq!(names, vec!["some-pkg"], "{command}: {parsed:?}");
            assert!(parsed.notes.is_empty(), "{command}: {parsed:?}");
        }
    }

    #[test]
    fn separate_installs_keep_their_order() {
        let parsed = parse("npm i first || npm i second");
        let names: Vec<&str> = parsed
            .intents
            .iter()
            .flat_map(|intent| intent.specs.iter().map(|spec| spec.name.as_str()))
            .collect();
        assert_eq!(names, vec!["first", "second"]);
    }

    #[test]
    fn a_requirements_file_is_named_when_packages_are_also_audited() {
        let parsed = parse("pip install -r base.txt extra");
        assert!(
            parsed
                .notes
                .iter()
                .any(|note| note.contains("lockfile not audited")),
            "{parsed:?}"
        );
    }

    #[test]
    fn urls_and_paths_are_not_invented_as_packages() {
        for command in [
            "npm i https://example.test/x.tgz",
            "npm i github:user/repo",
            "npm i file:../pkg",
            "pip install git+https://example.test/repo",
            "cargo install --git https://example.test/repo",
        ] {
            let parsed = parse(command);
            assert!(
                parsed.intents.iter().all(|intent| intent.specs.is_empty()),
                "{command}: {parsed:?}"
            );
            assert!(!parsed.notes.is_empty(), "{command}");
        }
    }

    #[test]
    fn shell_substitution_never_invents_a_package() {
        let parsed = parse("npm i $(curl evil)");
        assert!(parsed.notes.iter().any(|note| note.contains("unparsed")));
        assert!(
            parsed
                .intents
                .iter()
                .all(|intent| intent.specs.iter().all(|spec| !spec.name.contains("curl")))
        );
    }

    #[test]
    fn unparsed_install_like_commands_get_a_note() {
        for command in ["deno add npm:express", "winget install x", "brew install x"] {
            let parsed = parse(command);
            assert!(
                parsed.notes.iter().any(|note| note.contains("not parsed")),
                "{command}: {parsed:?}"
            );
        }
    }

    #[test]
    fn empty_and_garbage_inputs_do_not_panic() {
        for command in ["", "   ", ";;;", "\u{0}\u{1}\u{2}", "npm"] {
            let _ = parse(command);
        }
        let _ = parse(&"(".repeat(100_000));
    }

    #[test]
    fn caps_giant_input_instead_of_hanging() {
        let parsed = parse(&"a;".repeat(MAX_COMMAND_BYTES));
        assert!(parsed.notes.iter().any(|note| note.contains("truncated")));
    }

    #[test]
    fn a_multibyte_char_at_the_cap_does_not_panic() {
        let mut command = "a".repeat(MAX_COMMAND_BYTES - 1);
        command.push('é');
        let parsed = parse(&command);
        assert!(parsed.notes.iter().any(|note| note.contains("truncated")));
    }
}
