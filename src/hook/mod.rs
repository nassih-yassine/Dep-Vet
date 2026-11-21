//! Claude Code PreToolUse hook: read the tool call, vet direct installs, and
//! return a decision in Claude's documented JSON shape.
//!
//! Claude's exit code 2 means BLOCK, while dep-vet's means HIGH risk. This
//! module is the only place that maps one to the other: it always exits 0 and
//! prints exactly one `hookSpecificOutput` object, or nothing at all.

pub mod settings;

use serde::Deserialize;

pub const MAX_STDIN_BYTES: u64 = 1024 * 1024;
/// Hard budget for the child audit, independent of environment variables.
pub const HOOK_BUDGET_SECONDS: u64 = 8;
const MAX_REASON_CHARS: usize = 2_000;

#[derive(Debug, Deserialize)]
pub struct HookInput {
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Option<ToolInput>,
}

#[derive(Debug, Deserialize)]
pub struct ToolInput {
    #[serde(default)]
    pub command: Option<String>,
}

/// The Bash command in a PreToolUse payload, or `None` for any input we must
/// not act on.
pub fn read_command(stdin: &str) -> Option<String> {
    let input: HookInput = serde_json::from_str(stdin).ok()?;
    if input.tool_name.as_deref() != Some("Bash") {
        return None;
    }
    let command = input.tool_input?.command?;
    let command = command.trim().to_string();
    (!command.is_empty()).then_some(command)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Ask(String),
    Deny(String),
}

/// Map the guard's exit code and JSON to a decision. Exit 3, a timeout, or a
/// malformed report is "we could not check": allow by default, deny in strict
/// mode. HIGH always denies; WARN asks unless strict.
pub fn decide(exit_code: u8, guard_json: Option<&str>, strict: bool) -> Decision {
    match exit_code {
        0 => Decision::Allow,
        2 => Decision::Deny(reason(guard_json, "HIGH risk")),
        1 if strict => Decision::Deny(reason(guard_json, "warnings")),
        1 => Decision::Ask(reason(guard_json, "warnings")),
        _ if strict => Decision::Deny(unchecked_reason(guard_json, exit_code)),
        _ => Decision::Allow,
    }
}

/// The documented PreToolUse output, or `None` when the hook has no decision.
pub fn render(decision: &Decision) -> Option<String> {
    let (permission, text) = match decision {
        Decision::Allow => return None,
        Decision::Ask(text) => ("ask", text),
        Decision::Deny(text) => ("deny", text),
    };
    let clipped: String = text.chars().take(MAX_REASON_CHARS).collect();
    Some(
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": permission,
                "permissionDecisionReason": clipped,
            }
        })
        .to_string(),
    )
}

/// Notes from a guard report: unparsed installs, URL/path specs, lockfiles.
pub fn notes(guard_json: Option<&str>) -> Vec<String> {
    guard_json
        .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
        .and_then(|document| document["notes"].as_array().cloned())
        .map(|notes| {
            notes
                .iter()
                .filter_map(|note| note.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn unchecked_reason(guard_json: Option<&str>, exit_code: u8) -> String {
    let document = guard_json.and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok());
    let mut details = notes(guard_json);
    if let Some(intents) = document
        .as_ref()
        .and_then(|document| document["intents"].as_array())
    {
        for intent in intents {
            if intent["specs"].as_array().is_some_and(Vec::is_empty)
                && let Some(lockfile) = intent["lockfile"].as_str()
            {
                details.push(format!("lockfile not audited: {lockfile}"));
            }
        }
    }
    let detail = if details.is_empty() {
        "no named package could be vetted".to_string()
    } else {
        details.join("; ")
    };
    format!(
        "dep-vet could not check this install fully (exit {exit_code}): {detail}. \
         Do not retry. Ask the user.\n\
         Direct packages only; transitive dependencies were not checked."
    )
}

fn reason(guard_json: Option<&str>, label: &str) -> String {
    let Some(document) =
        guard_json.and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
    else {
        return format!(
            "dep-vet: {label}, but the report could not be read. Do not retry. Ask the user.\n\
             Direct packages only; transitive dependencies were not checked."
        );
    };
    let mut lines = Vec::new();
    let mut shown = 0;
    let mut replacement: Option<String> = None;
    let mut fixed: Option<String> = None;
    if let Some(packages) = document["packages"].as_array() {
        for package in packages.iter().take(3) {
            let name = package["name"].as_str().unwrap_or("package");
            let version = package["version"].as_str().unwrap_or("?");
            let verdict = package["verdict"].as_str().unwrap_or("warn");
            if shown == 0 {
                lines.push(format!("dep-vet: {label} — {name}@{version} ({verdict})"));
            }
            if let Some(findings) = package["findings"].as_array() {
                for finding in findings.iter() {
                    if shown >= 3 {
                        break;
                    }
                    let title = finding["title"].as_str().unwrap_or("finding");
                    let id = finding["id"].as_str().unwrap_or("rule");
                    let url = finding["evidence"]
                        .as_array()
                        .and_then(|evidence| evidence.first())
                        .and_then(|evidence| evidence["url"].as_str())
                        .unwrap_or("");
                    lines.push(format!("- [{id}] {title} — {url}"));
                    shown += 1;
                    if replacement.is_none() {
                        replacement = finding["replace_with"].as_str().map(str::to_string);
                    }
                    if fixed.is_none() {
                        fixed = finding["fixed"].as_str().map(str::to_string);
                    }
                }
            }
            if let Some(advisories) = package["advisories"].as_array() {
                for advisory in advisories.iter() {
                    if shown >= 3 {
                        break;
                    }
                    let id = advisory["id"].as_str().unwrap_or("advisory");
                    let url = advisory["url"].as_str().unwrap_or("");
                    lines.push(format!("- [{id}] security advisory — {url}"));
                    shown += 1;
                }
            }
        }
    }
    if lines.is_empty() {
        lines.push(format!("dep-vet: {label}, report had no details."));
    }
    if let Some(replacement) = replacement {
        lines.push(format!("Use {replacement} instead."));
    } else if let Some(fixed) = fixed {
        lines.push(format!("Fixed in {fixed}."));
    }
    lines.push("Do not retry. Ask the user.".to_string());
    lines.push("Direct packages only; transitive dependencies were not checked.".to_string());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_bash_and_malformed_input_allow_without_output() {
        assert_eq!(
            read_command(r#"{"tool_name":"Edit","tool_input":{}}"#),
            None
        );
        assert_eq!(
            read_command(r#"{"tool_name":"Bash","tool_input":{}}"#),
            None
        );
        assert_eq!(read_command("not json"), None);
        assert_eq!(render(&Decision::Allow), None);
    }

    #[test]
    fn decisions_map_and_render_as_documented() {
        let deny = render(&decide(2, None, false)).unwrap();
        assert!(deny.contains(r#""permissionDecision":"deny""#), "{deny}");
        assert!(deny.contains(r#""hookEventName":"PreToolUse""#), "{deny}");
        assert!(
            render(&decide(1, None, false))
                .unwrap()
                .contains(r#""permissionDecision":"ask""#)
        );
        assert_eq!(render(&decide(3, None, false)), None);
        assert!(
            render(&decide(3, None, true))
                .unwrap()
                .contains(r#""permissionDecision":"deny""#)
        );
    }

    #[test]
    fn the_reason_names_up_to_three_findings_and_the_advice() {
        let report = serde_json::json!({
            "packages": [{
                "name": "expresss", "version": "1.0.0", "verdict": "high",
                "findings": [
                    {"id":"typosquat","title":"looks like express","evidence":[{"url":"https://registry.npmjs.org/expresss"}],"replace_with":"express"},
                    {"id":"advisory","title":"vulnerable","evidence":[{"url":"https://osv.dev/vulnerability/GHSA-1"}]},
                    {"id":"install-scripts","title":"runs code","evidence":[{"url":"https://registry.npmjs.org/expresss"}]},
                    {"id":"fresh-version","title":"fourth","evidence":[{"url":"https://x"}]}
                ],
                "advisories": []
            }]
        })
        .to_string();
        let reason = reason(Some(&report), "HIGH risk");
        assert!(reason.contains("typosquat"), "{reason}");
        assert!(
            reason.contains("https://osv.dev/vulnerability/GHSA-1"),
            "{reason}"
        );
        assert!(!reason.contains("fourth"), "{reason}");
        assert!(reason.contains("Use express instead."), "{reason}");
        assert!(reason.contains("Do not retry. Ask the user."), "{reason}");
    }
}
