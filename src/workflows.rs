//! Line-wise GitHub Actions workflow scan.
//!
//! Workflow YAML is read without a YAML crate, the same way pnpm lockfiles are:
//! the rules only need a handful of keys, and a full parser would add a
//! dependency (and a panic surface) to a supply-chain tool.
//!
//! The scan is deliberately conservative: it reports what the text shows and
//! never claims a workflow is safe.

use std::path::{Path, PathBuf};

use crate::model::{Evidence, Finding, Severity};

/// Refuse to read an absurdly large "workflow"; real ones are a few kilobytes.
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

const UNPINNED_REFERENCE: &str = "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions";
const PR_TARGET_REFERENCE: &str =
    "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/";
const INJECTION_REFERENCE: &str = "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections";
const PERMISSIONS_REFERENCE: &str = "https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token";
const CURL_PIPE_REFERENCE: &str = "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable";
const SECRET_ECHO_REFERENCE: &str = "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#storing-credentials";

#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is larger than {MAX_FILE_BYTES} bytes; refusing to scan it")]
    TooLarge { path: String },
    #[error("{0} is not a file or directory")]
    NotADirectory(String),
}

#[derive(Debug, serde::Serialize)]
pub struct WorkflowReport {
    pub files: Vec<String>,
    pub findings: Vec<Finding>,
}

impl WorkflowReport {
    pub fn verdict(&self) -> Severity {
        self.findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    pub fn exit_code(&self) -> u8 {
        self.verdict().exit_code()
    }
}

/// Scan one workflow file or a directory of `*.yml`/`*.yaml` files.
pub fn scan(path: &Path) -> Result<WorkflowReport, WorkflowError> {
    let mut files = Vec::new();
    if path.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
            .map_err(|source| WorkflowError::Io {
                path: path.display().to_string(),
                source,
            })?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_file())
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|extension| {
                        extension.eq_ignore_ascii_case("yml")
                            || extension.eq_ignore_ascii_case("yaml")
                    })
            })
            .collect();
        entries.sort();
        files = entries;
    } else if path.is_file() {
        files.push(path.to_path_buf());
    } else {
        return Err(WorkflowError::NotADirectory(path.display().to_string()));
    }

    let mut report = WorkflowReport {
        files: Vec::new(),
        findings: Vec::new(),
    };
    for file in files {
        let size = std::fs::metadata(&file)
            .map_err(|source| WorkflowError::Io {
                path: file.display().to_string(),
                source,
            })?
            .len();
        if size > MAX_FILE_BYTES {
            return Err(WorkflowError::TooLarge {
                path: file.display().to_string(),
            });
        }
        let body = std::fs::read_to_string(&file).map_err(|source| WorkflowError::Io {
            path: file.display().to_string(),
            source,
        })?;
        let name = file.display().to_string();
        report.files.push(name.clone());
        report.findings.extend(scan_text(&name, &body));
    }
    report.findings.sort_by(|a, b| {
        let file = |finding: &Finding| {
            finding
                .evidence
                .first()
                .map(|evidence| evidence.value.clone())
                .unwrap_or_default()
        };
        file(a)
            .cmp(&file(b))
            .then_with(|| line_of(a).cmp(&line_of(b)))
            .then_with(|| a.id.cmp(b.id))
    });
    Ok(report)
}

fn line_of(finding: &Finding) -> usize {
    finding
        .evidence
        .iter()
        .find_map(|evidence| evidence.label.strip_prefix("line "))
        .and_then(|line| line.parse().ok())
        .unwrap_or(0)
}

/// The rules, applied to already-clean text. Comments are stripped first so a
/// commented-out example never becomes a finding.
fn scan_text(path: &str, body: &str) -> Vec<Finding> {
    let lines: Vec<&str> = body.lines().map(strip_comment).collect();
    let mut findings = Vec::new();
    let mut trigger_block: Option<usize> = None;
    let mut pull_request_target = false;
    let mut run_base: Option<usize> = None;
    let mut head_ref_line: Option<(usize, String)> = None;

    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();

        if let Some(base) = run_base {
            if indent > base {
                findings.extend(run_rules(path, number, trimmed));
                if has_pr_head_reference(trimmed) {
                    head_ref_line = Some((number, trimmed.to_string()));
                }
                continue;
            }
            run_base = None;
        }

        // A top-level key ends the `on:` block.
        if indent == 0 {
            trigger_block = None;
            if trimmed.starts_with("on:") || trimmed.starts_with("\"on\":") {
                trigger_block = Some(indent);
                pull_request_target |= trimmed.contains("pull_request_target");
                continue;
            }
        }
        if let Some(base) = trigger_block
            && indent > base
        {
            if trimmed.contains("pull_request_target") {
                pull_request_target = true;
            }
            continue;
        }

        if trimmed.starts_with("permissions:") {
            let value = trimmed
                .split_once(':')
                .map(|(_, value)| value.trim())
                .unwrap_or_default();
            if value == "write-all" {
                findings.push(finding(
                    Rule {
                        id: "workflow-write-all",
                        severity: Severity::Warn,
                        title: "workflow grants write-all permissions",
                        detail: "every job gets write access to the repository token".to_string(),
                        reference: PERMISSIONS_REFERENCE,
                    },
                    path,
                    number,
                    trimmed,
                ));
            }
            continue;
        }

        if let Some(uses) = uses_value(trimmed) {
            if let Some(reason) = unpinned_reason(uses) {
                findings.push(finding(
                    Rule {
                        id: "workflow-action-unpinned",
                        severity: Severity::Warn,
                        title: "action is not pinned to a commit",
                        detail: reason,
                        reference: UNPINNED_REFERENCE,
                    },
                    path,
                    number,
                    trimmed,
                ));
            }
            continue;
        }

        if let Some(rest) = trimmed
            .strip_prefix("- run:")
            .or_else(|| trimmed.strip_prefix("run:"))
        {
            let inline = rest.trim();
            if is_block_scalar(inline) {
                run_base = Some(indent);
            } else {
                findings.extend(run_rules(path, number, inline));
                if has_pr_head_reference(inline) {
                    head_ref_line = Some((number, trimmed.to_string()));
                }
            }
            continue;
        }

        if has_pr_head_reference(trimmed) {
            head_ref_line = Some((number, trimmed.to_string()));
        }
    }

    if pull_request_target && let Some((number, text)) = head_ref_line {
        findings.push(finding(
                Rule {
                    id: "workflow-pr-target-checkout",
                    severity: Severity::High,
                    title: "pull_request_target checks out untrusted code",
                    detail: "a fork's code runs with the base repository token and secrets when the workflow checks out the PR head".to_string(),
                    reference: PR_TARGET_REFERENCE,
                },
                path,
                number,
                &text,
            ));
    }

    findings
}

fn run_rules(path: &str, line: usize, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    if script_injection(text) {
        findings.push(finding(
                Rule {
                    id: "workflow-script-injection",
                    severity: Severity::High,
                    title: "event data is interpolated into a shell command",
                    detail: "a pull request title, branch name, or issue body can break out of the shell quoting".to_string(),
                    reference: INJECTION_REFERENCE,
                },
                path,
                line,
                text,
            ));
    }
    if pipe_to_shell(text) {
        findings.push(finding(
            Rule {
                id: "workflow-curl-pipe-shell",
                severity: Severity::High,
                title: "downloaded script is piped into a shell",
                detail: "the workflow executes whatever the URL serves, with no checksum or review"
                    .to_string(),
                reference: CURL_PIPE_REFERENCE,
            },
            path,
            line,
            text,
        ));
    }
    if echoes_a_secret(text) {
        findings.push(finding(
                Rule {
                    id: "workflow-secret-echo",
                    severity: Severity::High,
                    title: "secret is written to the log",
                    detail: "secrets echoed in a step are visible in the run log and to anyone who can read it".to_string(),
                    reference: SECRET_ECHO_REFERENCE,
                },
                path,
                line,
                text,
            ));
    }
    findings
}

fn uses_value(trimmed: &str) -> Option<&str> {
    let rest = trimmed
        .strip_prefix("- uses:")
        .or_else(|| trimmed.strip_prefix("uses:"))?;
    Some(rest.trim().trim_matches('"').trim_matches('\''))
}

/// Local actions and anything with a full 40-character commit SHA are pinned.
fn unpinned_reason(uses: &str) -> Option<String> {
    if uses.is_empty() || uses.starts_with("./") || uses.starts_with(".\\") {
        return None;
    }
    let Some((name, reference)) = uses.rsplit_once('@') else {
        return Some(format!(
            "'{uses}' has no reference; a tag or commit is required, and a commit is safer"
        ));
    };
    if reference.len() == 40
        && reference
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return None;
    }
    Some(format!(
        "'{name}' uses '{reference}', which can move; pin the full commit SHA"
    ))
}

/// Event fields an attacker controls. `github.event_name` and
/// `github.repository` are not in this list on purpose: interpolating them is
/// not the vulnerability this rule targets.
fn script_injection(text: &str) -> bool {
    let folded = text.to_ascii_lowercase();
    [
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.label",
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.comment.body",
        "github.event.review.body",
        "github.event.review_comment.body",
        "github.event.head_commit.message",
        "github.head_ref",
        "github.event.workflow_run.head_branch",
    ]
    .iter()
    .any(|field| folded.contains(field))
}

fn pipe_to_shell(text: &str) -> bool {
    let folded = text.to_ascii_lowercase();
    let Some((left, right)) = folded.split_once('|') else {
        return false;
    };
    let fetches = left.contains("curl") || left.contains("wget");
    let shell = right.split_whitespace().any(|word| {
        matches!(
            word.trim_matches(|character: char| !character.is_alphanumeric()),
            "sh" | "bash" | "zsh" | "fish" | "python" | "python3" | "node"
        )
    });
    fetches && shell
}

fn echoes_a_secret(text: &str) -> bool {
    let folded = text.to_ascii_lowercase();
    let prints = folded.contains("echo") || folded.contains("printf") || folded.contains("cat ");
    prints && (folded.contains("secrets.") || folded.contains("secret."))
}

fn has_pr_head_reference(text: &str) -> bool {
    text.to_ascii_lowercase()
        .contains("github.event.pull_request.head")
}

/// A YAML comment starts at `#` outside quotes and at the start or after
/// whitespace.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'\\' if double && !escaped => {
                escaped = true;
                continue;
            }
            b'\'' if !double && !escaped => single = !single,
            b'"' if !single && !escaped => double = !double,
            b'#' if !single && !double => {
                let boundary = index == 0 || bytes[index - 1].is_ascii_whitespace();
                if boundary {
                    return &line[..index];
                }
            }
            _ => {}
        }
        escaped = false;
    }
    line
}

fn is_block_scalar(value: &str) -> bool {
    let value = value.trim();
    value.starts_with('|') || value.starts_with('>')
}

fn truncate(value: &str, limit: usize) -> String {
    let trimmed = value.trim();
    if trimmed.chars().count() <= limit {
        return trimmed.to_string();
    }
    let mut out: String = trimmed.chars().take(limit).collect();
    out.push('…');
    out
}

struct Rule {
    id: &'static str,
    severity: Severity,
    title: &'static str,
    detail: String,
    reference: &'static str,
}

fn finding(rule: Rule, path: &str, line: usize, text: &str) -> Finding {
    Finding {
        id: rule.id,
        severity: rule.severity,
        title: rule.title.to_string(),
        detail: format!("{}; line: {}", rule.detail, truncate(text, 160)),
        allowed: false,
        evidence: vec![
            Evidence {
                label: "workflow".to_string(),
                value: path.to_string(),
                url: None,
            },
            Evidence {
                label: format!("line {line}"),
                value: text.trim().to_string(),
                url: None,
            },
            Evidence {
                label: "rule".to_string(),
                value: rule.id.to_string(),
                url: Some(rule.reference.to_string()),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_yaml(body: &str) -> Vec<Finding> {
        scan_text("wf.yml", body)
    }

    fn ids(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().map(|finding| finding.id).collect()
    }

    #[test]
    fn only_full_commit_pins_pass_the_action_rule() {
        let body = r#"
jobs:
  test:
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
      - uses: actions/setup-node@v4
      - uses: some/action@main
      - uses: some/action
      - uses: ./.github/actions/local
"#;
        let findings = scan_yaml(body);
        assert_eq!(
            ids(&findings),
            vec![
                "workflow-action-unpinned",
                "workflow-action-unpinned",
                "workflow-action-unpinned"
            ]
        );
        assert!(findings[0].detail.contains("v4"));
        assert!(findings[1].detail.contains("main"));
        assert!(findings[2].detail.contains("no reference"));
    }

    #[test]
    fn pull_request_target_with_a_head_checkout_is_high() {
        let body = r#"
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
"#;
        let findings = scan_yaml(body);
        let finding = findings
            .iter()
            .find(|finding| finding.id == "workflow-pr-target-checkout")
            .expect("the combination must be flagged");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.evidence[1].value.contains("pull_request.head.sha"));
    }

    #[test]
    fn pull_request_target_alone_is_not_a_finding() {
        let body = r#"
on: [pull_request_target]
jobs:
  label:
    steps:
      - uses: actions/labeler@v5
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
"#;
        assert!(!ids(&scan_yaml(body)).contains(&"workflow-pr-target-checkout"));
    }

    #[test]
    fn event_fields_in_run_are_injection() {
        let body = r#"
jobs:
  test:
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
      - run: |
          echo "${{ github.event.issue.body }}"
          curl -fsSL https://example.test/install.sh | bash
      - name: safe
        run: echo "${{ github.event_name }}"
"#;
        let findings = scan_yaml(body);
        assert_eq!(
            ids(&findings),
            vec![
                "workflow-script-injection",
                "workflow-script-injection",
                "workflow-curl-pipe-shell"
            ]
        );
        assert!(findings[1].severity == Severity::High);
    }

    #[test]
    fn write_all_and_secret_echo_are_flagged() {
        let body = r#"
permissions: write-all
jobs:
  leak:
    steps:
      - run: echo "token is ${{ secrets.NPM_TOKEN }}"
"#;
        let findings = scan_yaml(body);
        assert_eq!(
            ids(&findings),
            vec!["workflow-write-all", "workflow-secret-echo"]
        );
    }

    #[test]
    fn comment_lines_are_never_findings() {
        let body = r##"
# uses: evil/action@v1
# permissions: write-all
# run: echo "${{ github.event.pull_request.title }}"
jobs:
  test:
    steps:
      - run: echo "issue #1 is fine"
      - run: echo "#not-a-comment" # trailing comment
"##;
        assert!(scan_yaml(body).is_empty());
    }

    #[test]
    fn a_run_block_stops_at_the_next_key() {
        let body = r#"
jobs:
  test:
    steps:
      - run: |
          echo hello
      - uses: actions/checkout@v4
"#;
        assert_eq!(ids(&scan_yaml(body)), vec!["workflow-action-unpinned"]);
    }
}
