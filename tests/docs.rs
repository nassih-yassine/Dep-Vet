//! Docs that quote a release pin must follow the reusable workflow's default.
//!
//! `.github/workflows/dep-vet.yml` carries `on.workflow_call.inputs.ref.default`.
//! The README and the example workflow copy that tag in three places, and a
//! release bumps the default. Nothing used to notice when a copy was left
//! behind, so users cloned a snippet that installed an old binary.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("cannot read {}: {error}", path.display());
    })
}

/// The `default:` value of the workflow's `ref` input.
fn workflow_default_ref() -> String {
    let body = read(".github/workflows/dep-vet.yml");
    let mut in_ref_input = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed == "ref:" {
            in_ref_input = true;
            continue;
        }
        if in_ref_input {
            if let Some(value) = trimmed.strip_prefix("default:") {
                let value = value.trim().trim_matches('"').trim_matches('\'');
                assert!(
                    value.starts_with('v'),
                    "workflow ref default is not a tag: {value}"
                );
                return value.to_string();
            }
            // Another key at the same or lower indentation ends the input.
            if !trimmed.is_empty() && !line.starts_with("        ") {
                break;
            }
        }
    }
    panic!("no default under `on.workflow_call.inputs.ref` in dep-vet.yml");
}

/// Tags quoted after `dep-vet.yml@`, in `ref:` values, and in `refs/tags/`
/// attestation examples.
fn quoted_tags(body: &str) -> Vec<String> {
    let mut tags = Vec::new();
    for line in body.lines() {
        for marker in ["dep-vet.yml@", "refs/tags/"] {
            let mut rest = line;
            while let Some(index) = rest.find(marker) {
                let after = &rest[index + marker.len()..];
                let tag: String = after
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
                    .collect();
                if tag.starts_with('v') && tag.len() > 2 {
                    tags.push(tag);
                }
                rest = after;
            }
        }
        if let Some(index) = line.find("ref:") {
            let after = line[index + "ref:".len()..].trim();
            let tag: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
                .collect();
            if tag.starts_with('v') && tag.len() > 2 {
                tags.push(tag);
            }
        }
    }
    tags
}

fn assert_pins_follow_the_default(relative: &str) {
    let default = workflow_default_ref();
    let body = read(relative);
    let tags = quoted_tags(&body);
    assert!(
        tags.iter().any(|tag| tag.starts_with("v0.")),
        "{relative} no longer quotes a release tag; the pin test cannot guard it"
    );
    let stale: Vec<&String> = tags.iter().filter(|tag| **tag != default).collect();
    assert!(
        stale.is_empty(),
        "{relative} quotes {stale:?} but the reusable workflow defaults to {default}"
    );
}

#[test]
fn readme_pins_match_the_workflow_default() {
    assert_pins_follow_the_default("README.md");
}

#[test]
fn example_workflow_pins_match_the_workflow_default() {
    assert_pins_follow_the_default("examples/github-action.yml");
}

#[test]
fn workflow_default_is_a_release_tag() {
    let default = workflow_default_ref();
    let rest = default.trim_start_matches('v');
    let parts: Vec<&str> = rest.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "default {default} is not vMAJOR.MINOR.PATCH"
    );
    assert!(
        parts.iter().all(|part| part.parse::<u64>().is_ok()),
        "default {default} is not a numeric release tag"
    );
}

#[test]
fn readme_and_example_agree() {
    let readme = read("README.md");
    let example = read("examples/github-action.yml");
    for tag in quoted_tags(&example) {
        assert!(
            readme.contains(&tag),
            "example pins {tag} but README never mentions it"
        );
    }
}

#[test]
fn path_helper_is_stable() {
    // Guards against a test that silently reads from a different root.
    assert!(Path::new(&repo_root()).join("Cargo.toml").is_file());
}
