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
            '&' if chars.peek() == Some(&'&') => {
                chars.next();
                out.push(std::mem::take(&mut current));
            }
            '|' => {
                if chars.peek() == Some(&'|') {
                    chars.next();
                }
                out.push(std::mem::take(&mut current));
            }
            ';' | '\n' => out.push(std::mem::take(&mut current)),
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

fn npm_install(segment: &str, tokens: &[String], outcome: &mut ParseOutcome) {
    let mut specs = Vec::new();
    let mut lockfile = None;
    let mut index = 2;
    while index < tokens.len() {
        let token = &tokens[index];
        match token.as_str() {
            "--registry" | "--prefix" | "--cache" | "--userconfig" | "--tag" => {
                index += 2;
                continue;
            }
            "-r" | "--require" => {
                if let Some(path) = tokens.get(index + 1) {
                    lockfile = Some(path.clone());
                }
                index += 2;
                continue;
            }
            _ => {}
        }
        if token == "ci" {
            lockfile.get_or_insert_with(|| "package-lock.json".to_string());
            index += 1;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        if is_spec_like(token) {
            match spec(Ecosystem::Npm, token) {
                Ok(spec) => specs.push(spec),
                Err(_) => outcome
                    .notes
                    .push(format!("unparsed package argument: {token}")),
            }
        } else {
            outcome.notes.push(format!(
                "not a registry package (not vetted): {token}"
            ));
        }
        index += 1;
    }
    if specs.is_empty() && lockfile.is_none() {
        lockfile = Some("package-lock.json".to_string());
    }
    outcome.intents.push(Intent {
        ecosystem: Ecosystem::Npm,
        kind: if specs.is_empty() {
            IntentKind::Lockfile
        } else {
            IntentKind::Install
        },
        specs,
        lockfile,
        source: segment.to_string(),
    });
}

pub fn parse(command: &str) -> ParseOutcome {
    parse_depth(command, 0)
}

fn parse_depth(command: &str, depth: u8) -> ParseOutcome {
    let mut outcome = ParseOutcome::default();
    if command.len() > MAX_COMMAND_BYTES {
        outcome.notes.push(format!(
            "command truncated at {MAX_COMMAND_BYTES} bytes; the rest was not parsed"
        ));
    }
    let command = &command[..command.len().min(MAX_COMMAND_BYTES)];
    let command = command.replace("\\\n", " ").replace("\r\n", "\n");
    for segment in segments(&command) {
        let mut tokens = words(&segment);
        // Drop leading assignments and wrappers.
        while let Some(token) = tokens.first() {
            if token.contains('=') && !token.starts_with('-') {
                tokens.remove(0);
                continue;
            }
            if matches!(token.as_str(), "sudo" | "env" | "time" | "command" | "nohup") {
                tokens.remove(0);
                continue;
            }
            break;
        }
        if tokens.is_empty() || tokens[0] == "cd" {
            continue;
        }
        if depth < MAX_DEPTH
            && matches!(tokens[0].as_str(), "bash" | "sh" | "zsh")
            && tokens.get(1).is_some_and(|flag| flag == "-c")
        {
            if let Some(script) = tokens.get(2) {
                let nested = parse_depth(script, depth + 1);
                outcome.notes.extend(nested.notes);
                outcome.intents.extend(nested.intents);
                continue;
            }
        }
        if tokens[0] == "npm" && tokens.get(1).is_some_and(|verb| {
            matches!(verb.as_str(), "install" | "i" | "add")
        }) {
            npm_install(&segment, &tokens, &mut outcome);
            continue;
        }
        let lowered = segment.to_ascii_lowercase();
        if ["install", "add", "require", " get ", "dlx", "npx", "uvx"]
            .iter()
            .any(|needle| lowered.contains(needle))
        {
            outcome
                .notes
                .push(format!("install-like command was not parsed: {segment}"));
        }
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

    #[test]
    fn caps_giant_input_instead_of_hanging() {
        let parsed = parse(&"a;".repeat(MAX_COMMAND_BYTES));
        assert!(parsed.notes.iter().any(|note| note.contains("truncated")));
    }
}
