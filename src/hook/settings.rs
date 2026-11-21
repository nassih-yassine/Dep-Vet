//! Merge the dep-vet PreToolUse handler into Claude settings without touching
//! anything else in the file. Idempotent, atomic, and strict about JSON: a
//! malformed file is refused, never rewritten.

use std::path::Path;

use serde_json::{Value, json};

pub const TIMEOUT_SECONDS: u32 = 30;
const MACRO: &str = "hook claude";

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("{path} is not valid JSON: {error}")]
    Parse { path: String, error: String },
    #[error("{path} is not a JSON object")]
    Shape { path: String },
    #[error("could not write {path}: {error}")]
    Write { path: String, error: String },
}

fn parse(existing: &str, path: &str) -> Result<Value, SettingsError> {
    if existing.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(existing).map_err(|error| SettingsError::Parse {
        path: path.to_string(),
        error: error.to_string(),
    })
}

fn render(value: &Value) -> Result<String, SettingsError> {
    serde_json::to_string_pretty(value).map_err(|error| SettingsError::Write {
        path: String::new(),
        error: error.to_string(),
    })
}

fn handler(command: &str, timeout: u32) -> Value {
    json!({"type": "command", "command": command, "timeout": timeout})
}

/// Add the handler if absent. Returns the input unchanged when it is already
/// present with the same timeout, so a second install is a byte-for-byte no-op.
pub fn merge(
    path: &str,
    existing: &str,
    command: &str,
    timeout: u32,
) -> Result<String, SettingsError> {
    let mut root = parse(existing, path)?;
    let object = root.as_object_mut().ok_or_else(|| SettingsError::Shape {
        path: path.to_string(),
    })?;
    let hooks = object
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| SettingsError::Shape {
            path: path.to_string(),
        })?;
    let groups = hooks
        .entry("PreToolUse")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| SettingsError::Shape {
            path: path.to_string(),
        })?;
    let group = match groups.iter_mut().find(|group| group["matcher"] == "Bash") {
        Some(group) => group,
        None => {
            groups.push(json!({"matcher": "Bash", "hooks": []}));
            groups.last_mut().expect("just pushed")
        }
    };
    let handlers = group["hooks"]
        .as_array_mut()
        .ok_or_else(|| SettingsError::Shape {
            path: path.to_string(),
        })?;
    if let Some(found) = handlers.iter_mut().find(|handler| {
        handler["type"] == "command"
            && handler["command"]
                .as_str()
                .is_some_and(|value| value == command)
    }) {
        if found["timeout"] == json!(timeout) {
            return Ok(existing.to_string());
        }
        found["timeout"] = json!(timeout);
    } else {
        handlers.push(handler(command, timeout));
    }
    render(&root)
}

/// Remove only handlers whose command matches ours, then drop empty groups.
pub fn remove(path: &str, existing: &str, command: &str) -> Result<String, SettingsError> {
    if existing.trim().is_empty() {
        return Ok(existing.to_string());
    }
    let mut root = parse(existing, path)?;
    let before = root.clone();
    let Some(object) = root.as_object_mut() else {
        return Err(SettingsError::Shape {
            path: path.to_string(),
        });
    };
    if let Some(hooks) = object.get_mut("hooks").and_then(Value::as_object_mut)
        && let Some(groups) = hooks.get_mut("PreToolUse").and_then(Value::as_array_mut)
    {
        groups.retain_mut(|group| {
            if let Some(handlers) = group.get_mut("hooks").and_then(Value::as_array_mut) {
                handlers.retain(|handler| {
                    !(handler["type"] == "command"
                        && handler["command"]
                            .as_str()
                            .is_some_and(|value| value == command))
                });
                !handlers.is_empty()
            } else {
                true
            }
        });
        if groups.is_empty() {
            hooks.remove("PreToolUse");
        }
        if hooks.is_empty() {
            object.remove("hooks");
        }
    }
    if root == before {
        return Ok(existing.to_string());
    }
    render(&root)
}

pub fn atomic_write(path: &Path, contents: &str) -> Result<(), SettingsError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| SettingsError::Write {
        path: path.display().to_string(),
        error: error.to_string(),
    })?;
    let temporary = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "settings".to_string())
    ));
    std::fs::write(&temporary, contents).map_err(|error| SettingsError::Write {
        path: temporary.display().to_string(),
        error: error.to_string(),
    })?;
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    std::fs::rename(&temporary, path).map_err(|error| SettingsError::Write {
        path: path.display().to_string(),
        error: error.to_string(),
    })
}

/// The settings `command` is a shell string, so quote a path that has spaces.
pub fn command_line(executable: &Path, strict: bool) -> String {
    let path = executable.display().to_string();
    let quoted = if path.contains(char::is_whitespace) {
        format!("\"{path}\"")
    } else {
        path
    };
    if strict {
        format!("{quoted} {MACRO} --strict")
    } else {
        format!("{quoted} {MACRO}")
    }
}

pub fn diff(before: &str, after: &str) -> String {
    if before == after {
        return "no changes\n".to_string();
    }
    let mut out = String::new();
    for line in before.lines() {
        out.push_str("- ");
        out.push_str(line);
        out.push('\n');
    }
    for line in after.lines() {
        out.push_str("+ ");
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_is_idempotent_and_preserves_unknown_keys() {
        let once = merge(
            "settings.json",
            r#"{"theme":"dark","hooks":{"PreToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"fmt"}]}]}}"#,
            "dep-vet hook claude",
            30,
        )
        .unwrap();
        assert!(once.contains("\"theme\": \"dark\""));
        assert!(once.contains("\"matcher\": \"Edit\""));
        assert!(once.contains("\"matcher\": \"Bash\""));
        let twice = merge("settings.json", &once, "dep-vet hook claude", 30).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn merge_rejects_malformed_json() {
        assert!(matches!(
            merge("settings.json", "{not json", "x", 30),
            Err(SettingsError::Parse { .. })
        ));
    }

    #[test]
    fn remove_takes_only_our_handler() {
        let merged = merge(
            "settings.json",
            r#"{"hooks":{"PreToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"fmt"}]}]}}"#,
            "dep-vet hook claude",
            30,
        )
        .unwrap();
        let removed = remove("settings.json", &merged, "dep-vet hook claude").unwrap();
        let value: Value = serde_json::from_str(&removed).unwrap();
        let groups = value["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["matcher"], "Edit");
        assert_eq!(
            remove("settings.json", "", "dep-vet hook claude").unwrap(),
            ""
        );
    }

    #[test]
    fn a_path_with_spaces_is_quoted() {
        let line = command_line(Path::new("/Users/me/My Tools/dep-vet"), false);
        assert!(line.starts_with('"'), "{line}");
        assert!(line.ends_with("hook claude"), "{line}");
    }

    #[test]
    fn writes_are_atomic_and_create_the_directory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".claude").join("settings.json");
        atomic_write(&path, "{}").unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "{}");
    }
}
