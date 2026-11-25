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
const PERSIST_CREDENTIALS_REFERENCE: &str = "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#considering-cross-repository-access";
const SELF_HOSTED_REFERENCE: &str = "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runners-are-not-guaranteed-to-be-secure";
const SECRETS_INHERIT_REFERENCE: &str = "https://docs.github.com/en/actions/sharing-automations/reusing-workflows#passing-inputs-and-secrets-to-a-reusable-workflow";

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
    let mut triggers: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut in_triggers = false;
    let mut in_jobs = false;
    let mut current_job: Option<String> = None;
    let mut run_base: Option<usize> = None;
    let mut untrusted: Vec<(Option<String>, usize, String)> = Vec::new();
    let mut checkouts: Vec<(usize, usize)> = Vec::new();
    let mut self_hosted: Vec<(usize, String)> = Vec::new();
    let mut downloads: Vec<(usize, String)> = Vec::new();
    let mut secrets_inherit: Vec<(usize, String)> = Vec::new();

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
                if untrusted_ref(trimmed) {
                    untrusted.push((current_job.clone(), number, trimmed.to_string()));
                }
                continue;
            }
            run_base = None;
        }

        if indent == 0 {
            in_triggers = false;
            in_jobs = false;
            current_job = None;
            if starts_key(trimmed, "on") {
                in_triggers = true;
                collect_triggers(trimmed, &mut triggers);
                if has_trigger_line(trimmed, "pull_request_target") {
                    triggers.insert("pull_request_target".to_string());
                }
                continue;
            }
            if starts_key(trimmed, "jobs") {
                in_jobs = true;
            }
        } else if in_triggers {
            collect_triggers(trimmed, &mut triggers);
            continue;
        } else if in_jobs
            && indent == 2
            && trimmed.ends_with(':')
            && !trimmed.starts_with('-')
            && !trimmed.starts_with("steps")
        {
            current_job = Some(trimmed.trim_end_matches(':').to_string());
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

        if trimmed.starts_with("secrets:") {
            let value = trimmed
                .split_once(':')
                .map(|(_, value)| value.trim())
                .unwrap_or_default();
            if value == "inherit" {
                secrets_inherit.push((number, trimmed.to_string()));
            }
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("runs-on:") {
            if value.to_ascii_lowercase().contains("self-hosted") {
                self_hosted.push((number, trimmed.to_string()));
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
            if uses.to_ascii_lowercase().starts_with("actions/checkout") {
                checkouts.push((number, indent));
            }
            if uses
                .to_ascii_lowercase()
                .starts_with("actions/download-artifact")
            {
                downloads.push((number, trimmed.to_string()));
            }
            continue;
        }

        if let Some(rest) = stripped_block_scalar(trimmed) {
            let inline = rest.trim();
            if is_block_scalar(inline) {
                run_base = Some(indent);
            } else {
                findings.extend(run_rules(path, number, inline));
            }
            if untrusted_ref(inline) {
                untrusted.push((current_job.clone(), number, trimmed.to_string()));
            }
            continue;
        }

        if untrusted_ref(trimmed) {
            untrusted.push((current_job.clone(), number, trimmed.to_string()));
        }
    }

    let pull_request_target = triggers.contains("pull_request_target");
    if pull_request_target {
        let mut seen_jobs: Vec<String> = Vec::new();
        for (job, number, text) in &untrusted {
            if let Some(job) = job {
                if seen_jobs.iter().any(|seen| seen == job) {
                    continue;
                }
                seen_jobs.push(job.clone());
            }
            findings.push(finding(
                Rule {
                    id: "workflow-pr-target-checkout",
                    severity: Severity::High,
                    title: "pull_request_target checks out untrusted code",
                    detail: match job {
                        Some(job) => format!(
                            "job '{job}' checks out the PR head while the workflow runs with the base repository token and secrets"
                        ),
                        None => "a fork's code runs with the base repository token and secrets when the workflow checks out the PR head".to_string(),
                    },
                    reference: PR_TARGET_REFERENCE,
                },
                path,
                *number,
                text,
            ));
        }
    }

    if triggers.contains("workflow_run") {
        for (number, text) in &downloads {
            findings.push(finding(
                Rule {
                    id: "workflow-run-artifact-download",
                    severity: Severity::Warn,
                    title: "workflow_run downloads an artifact",
                    detail: "artifacts from an untrusted workflow run can carry attacker-controlled files into this job".to_string(),
                    reference: PR_TARGET_REFERENCE,
                },
                path,
                *number,
                text,
            ));
        }
    }

    if triggers.contains("pull_request_target") || triggers.contains("workflow_run") {
        for (number, indent) in &checkouts {
            if !checkout_disables_credentials(&lines, *number, *indent) {
                findings.push(finding(
                    Rule {
                        id: "workflow-checkout-persist-credentials",
                        severity: Severity::Warn,
                        title: "checkout keeps the token in the git config",
                        detail: "this checkout runs in a privileged trigger; set persist-credentials: false so later steps cannot reuse the token".to_string(),
                        reference: PERSIST_CREDENTIALS_REFERENCE,
                    },
                    path,
                    *number,
                    lines[*number - 1].trim(),
                ));
            }
        }
    }

    if triggers.contains("pull_request") {
        for (number, text) in &self_hosted {
            findings.push(finding(
                Rule {
                    id: "workflow-self-hosted-pr",
                    severity: Severity::Warn,
                    title: "pull_request runs on a self-hosted runner",
                    detail: "text cannot prove whether a fork can reach this runner; a public repository needs approval or a fork guard".to_string(),
                    reference: SELF_HOSTED_REFERENCE,
                },
                path,
                *number,
                text,
            ));
        }
    }

    for (number, text) in &secrets_inherit {
        findings.push(finding(
            Rule {
                id: "workflow-secrets-inherit",
                severity: Severity::Warn,
                title: "every caller secret is passed through",
                detail: "secrets: inherit hands a called workflow all of the caller's secrets, including ones it does not need".to_string(),
                reference: SECRETS_INHERIT_REFERENCE,
            },
            path,
            *number,
            text,
        ));
    }

    findings
}

fn starts_key(trimmed: &str, key: &str) -> bool {
    trimmed
        .strip_prefix(key)
        .is_some_and(|rest| rest.starts_with(':') || rest.starts_with("\":"))
        || trimmed.starts_with(&format!("\"{key}\":"))
}

fn collect_triggers(line: &str, triggers: &mut std::collections::BTreeSet<String>) {
    for trigger in [
        "pull_request_target",
        "pull_request",
        "workflow_run",
        "push",
        "schedule",
        "release",
    ] {
        if has_trigger_line(line, trigger) {
            triggers.insert(trigger.to_string());
        }
    }
}

/// Token-bounded so `pull_request_target` does not also set `pull_request`.
fn has_trigger_line(line: &str, trigger: &str) -> bool {
    line.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .any(|token| token == trigger)
}

fn stripped_block_scalar(trimmed: &str) -> Option<&str> {
    for prefix in ["- run:", "run:", "- script:", "script:"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return Some(rest);
        }
    }
    None
}

/// A checkout step can turn off credential persistence anywhere inside its own
/// indented block.
fn checkout_disables_credentials(lines: &[&str], number: usize, indent: usize) -> bool {
    for line in lines.iter().skip(number) {
        if line.trim().is_empty() {
            continue;
        }
        let current = line.len() - line.trim_start().len();
        if current <= indent {
            return false;
        }
        if line
            .to_ascii_lowercase()
            .split_whitespace()
            .collect::<String>()
            .contains("persist-credentials:false")
        {
            return true;
        }
    }
    false
}

fn run_rules(path: &str, line: usize, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some((field, severity)) = script_injection(text) {
        findings.push(finding(
            Rule {
                id: "workflow-script-injection",
                severity,
                title: "event data is interpolated into a shell command",
                detail: format!(
                    "{field} comes from the event; a pull request title, branch name, issue body, or input can break out of the shell quoting"
                ),
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
    if writes_env_file_with_event(text) {
        findings.push(finding(
            Rule {
                id: "workflow-env-file-injection",
                severity: Severity::Warn,
                title: "event data is written to GITHUB_ENV or GITHUB_PATH",
                detail: "a newline in an attacker-controlled value can add environment variables or PATH entries for later steps".to_string(),
                reference: CURL_PIPE_REFERENCE,
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
    if let Some(image) = uses.strip_prefix("docker://") {
        let pinned = image.rsplit_once('@').is_some_and(|(_, digest)| {
            digest.strip_prefix("sha256:").is_some_and(|hex| {
                hex.len() == 64 && hex.chars().all(|character| character.is_ascii_hexdigit())
            })
        });
        if pinned {
            return None;
        }
        return Some(format!(
            "docker image '{image}' is not pinned by digest; use @sha256:<64 hex characters>"
        ));
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
fn script_injection(text: &str) -> Option<(&'static str, Severity)> {
    let field = event_field(text)?;
    let folded = field.to_ascii_lowercase();
    let severity = if folded.starts_with("inputs.") || folded.starts_with("github.event.inputs.") {
        Severity::Info
    } else {
        Severity::High
    };
    Some((field, severity))
}

/// Fields a caller or a contributor can set. `github.event_name` and
/// `github.repository` are not listed on purpose.
fn event_field(text: &str) -> Option<&'static str> {
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
        "github.event.workflow_run.head_branch",
        "github.event.inputs.",
        "github.head_ref",
        "inputs.",
    ]
    .into_iter()
    .find(|field| folded.contains(field))
}

fn writes_env_file_with_event(text: &str) -> bool {
    let folded = text.to_ascii_lowercase();
    let writes =
        (folded.contains("github_env") || folded.contains("github_path")) && folded.contains(">>");
    writes && event_field(text).is_some()
}

fn untrusted_ref(text: &str) -> bool {
    let folded = text.to_ascii_lowercase();
    folded.contains("github.event.pull_request.head")
        || folded.contains("github.head_ref")
        || folded.contains("refs/pull/")
}

fn pipe_to_shell(text: &str) -> bool {
    let folded = text.to_ascii_lowercase();
    let fetches = folded.contains("curl") || folded.contains("wget");
    if !fetches {
        return false;
    }
    let shells = ["sh", "bash", "zsh", "fish", "python", "python3", "node"];
    let is_shell = |word: &str| {
        shells.contains(
            &word
                .trim_matches(|character: char| !character.is_alphanumeric())
                .to_ascii_lowercase()
                .as_str(),
        )
    };
    if let Some((left, right)) = folded.split_once('|')
        && (left.contains("curl") || left.contains("wget"))
        && right.split_whitespace().any(is_shell)
    {
        return true;
    }
    // bash <(curl ...) and sh -c "$(curl ...)".
    let substitution = folded.contains("<(") || folded.contains("$(");
    substitution
        && shells.iter().any(|shell| {
            folded
                .split(|character: char| !character.is_alphanumeric())
                .any(|word| word == *shell)
        })
}

fn echoes_a_secret(text: &str) -> bool {
    let folded = text.to_ascii_lowercase();
    let prints = folded.contains("echo") || folded.contains("printf") || folded.contains("cat ");
    prints && (folded.contains("secrets.") || folded.contains("secret."))
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
    fn docker_images_need_a_digest() {
        let body = r#"
jobs:
  test:
    steps:
      - uses: docker://alpine:3.19
      - uses: docker://alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"#;
        let findings = scan_yaml(body);
        assert_eq!(ids(&findings), vec!["workflow-action-unpinned"]);
        assert!(findings[0].detail.contains("not pinned by digest"));
    }

    #[test]
    fn github_script_blocks_are_scanned_and_inputs_are_info() {
        let body = r#"
jobs:
  test:
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            console.log("${{ github.event.issue.title }}")
      - run: echo "${{ inputs.name }}"
"#;
        let findings = scan_yaml(body);
        let injections: Vec<&Finding> = findings
            .iter()
            .filter(|finding| finding.id == "workflow-script-injection")
            .collect();
        assert_eq!(injections.len(), 2);
        assert_eq!(injections[0].severity, Severity::High);
        assert_eq!(injections[1].severity, Severity::Info);
    }

    #[test]
    fn pull_request_target_is_reported_per_affected_job() {
        let body = r#"
on: pull_request_target
jobs:
  safe:
    steps:
      - uses: actions/checkout@v4
  unsafe:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"#;
        let findings = scan_yaml(body);
        let hits: Vec<&Finding> = findings
            .iter()
            .filter(|finding| finding.id == "workflow-pr-target-checkout")
            .collect();
        assert_eq!(hits.len(), 1, "{findings:?}");
        assert!(hits[0].detail.contains("'unsafe'"), "{:?}", hits[0].detail);
    }

    #[test]
    fn workflow_run_artifact_download_and_secrets_inherit_are_warned() {
        let body = r#"
on:
  workflow_run:
    workflows: [build]
    types: [completed]
jobs:
  deploy:
    uses: org/repo/.github/workflows/deploy.yml@main
    secrets: inherit
    steps:
      - uses: actions/download-artifact@v4
"#;
        let findings = scan_yaml(body);
        assert!(ids(&findings).contains(&"workflow-run-artifact-download"));
        assert!(ids(&findings).contains(&"workflow-secrets-inherit"));
        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("artifact"))
        );
    }

    #[test]
    fn privileged_checkouts_must_disable_persisted_credentials() {
        let body = r#"
on: pull_request_target
jobs:
  one:
    steps:
      - uses: actions/checkout@v4
  two:
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
"#;
        let findings = scan_yaml(body);
        let hits: Vec<&Finding> = findings
            .iter()
            .filter(|finding| finding.id == "workflow-checkout-persist-credentials")
            .collect();
        assert_eq!(hits.len(), 1, "{findings:?}");
    }

    #[test]
    fn self_hosted_pull_requests_and_env_file_writes_are_warned() {
        let body = r#"
on: pull_request
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - run: echo "FOO=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"
"#;
        let findings = scan_yaml(body);
        assert!(ids(&findings).contains(&"workflow-self-hosted-pr"));
        assert!(ids(&findings).contains(&"workflow-env-file-injection"));
    }

    #[test]
    fn process_substitution_is_a_pipe_to_shell() {
        let body = r#"
jobs:
  test:
    steps:
      - run: bash <(curl -fsSL https://example.test/install.sh)
      - run: sh -c "$(wget -qO- https://example.test/install.sh)"
      - run: curl -fsSL https://example.test/install.sh | sudo bash
"#;
        let findings = scan_yaml(body);
        assert_eq!(
            ids(&findings)
                .iter()
                .filter(|id| **id == "workflow-curl-pipe-shell")
                .count(),
            3
        );
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
