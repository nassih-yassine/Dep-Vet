//! OpenSSF Scorecard, read from deps.dev.
//!
//! The score is advisory context, never a verdict: it describes a repository,
//! not the version being installed. A lookup failure is "not checked", never a
//! clean score.

use crate::http::HttpClient;

const DEFAULT_SCORECARD_BASE: &str = "https://api.deps.dev";
/// deps.dev rebuilds its project documents weekly, so a week is the shortest
/// honest TTL.
const SCORECARD_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
/// The checks the report shows. All of them describe a project a maintainer
/// controls, which is what makes a publisher change worth reading.
const SHOWN_CHECKS: &[&str] = &[
    "Maintained",
    "Code-Review",
    "Branch-Protection",
    "Signed-Releases",
    "Dangerous-Workflow",
];
const CODE_HOSTS: &[&str] = &["github.com", "gitlab.com", "bitbucket.org"];

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Scorecard {
    pub overall: f64,
    /// The date deps.dev ran the scan, as it sent it.
    pub date: String,
    pub checks: Vec<ScorecardCheck>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ScorecardCheck {
    pub name: String,
    /// `-1` is Scorecard's "not applicable", kept as sent rather than as zero.
    pub score: i32,
}

pub struct ScorecardClient {
    http: std::sync::Arc<HttpClient>,
    base: String,
}

impl ScorecardClient {
    pub fn from_env(http: std::sync::Arc<HttpClient>) -> Self {
        let gate = std::env::var("DEPVET_ALLOW_INSECURE_BASES").is_ok_and(|value| value == "1");
        let base = match std::env::var("DEPVET_SCORECARD_BASE") {
            Ok(value) if gate && !value.is_empty() => value,
            _ => DEFAULT_SCORECARD_BASE.to_string(),
        };
        Self { http, base }
    }

    /// `None` means "no scorecard for this repository", which includes a 404,
    /// a malformed answer, a network failure, and a repository deps.dev does
    /// not cover. The caller reports it as not checked.
    pub fn lookup(&self, repository: &str) -> Option<Scorecard> {
        let project = project_key(repository)?;
        let url = format!(
            "{}/v3alpha/projects/{}",
            self.base.trim_end_matches('/'),
            project.replace('/', "%2F")
        );
        let body = self.http.get_with_ttl(&url, SCORECARD_TTL_SECONDS).ok()?;
        parse_project(&body).ok().flatten()
    }
}

/// `https://github.com/owner/repo(.git)` and its git+ssh and scp forms become
/// `github.com/owner/repo`. Anything else, including a nested path beyond the
/// repository, returns `None`.
pub fn project_key(repository: &str) -> Option<String> {
    let mut raw = repository.trim();
    raw = raw.strip_prefix("git+").unwrap_or(raw);
    for prefix in ["https://", "http://", "git://", "ssh://"] {
        if let Some(rest) = raw.strip_prefix(prefix) {
            raw = rest;
            break;
        }
    }
    let normalized = raw
        .strip_prefix("git@")
        .map(|rest| rest.replacen(':', "/", 1))
        .or_else(|| {
            raw.split_once(':')
                .filter(|(host, path)| !path.starts_with("//") && !host.contains('/'))
                .map(|(host, path)| format!("{host}/{path}"))
        });
    let raw = normalized.as_deref().unwrap_or(raw);
    let raw = raw
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .trim_end_matches('/');
    let raw = raw.strip_prefix("www.").unwrap_or(raw);
    let mut parts = raw.split('/');
    let host = parts.next()?.to_ascii_lowercase();
    let owner = parts.next()?;
    let rest = parts.next()?;
    let repo = rest.split('/').next().unwrap_or_default();
    if !CODE_HOSTS.contains(&host.as_str())
        || owner.is_empty()
        || repo.is_empty()
        || !valid_segment(owner)
        || !valid_segment(repo)
    {
        return None;
    }
    Some(format!("{host}/{owner}/{repo}"))
}

fn valid_segment(segment: &str) -> bool {
    !matches!(segment, "." | "..")
        && segment.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

/// Pull the overall score and the five displayed checks out of a deps.dev
/// project document. A project without a scorecard is `Ok(None)`.
pub fn parse_project(body: &str) -> Result<Option<Scorecard>, String> {
    let document: serde_json::Value =
        serde_json::from_str(body).map_err(|error| format!("scorecard json: {error}"))?;
    let Some(scorecard) = document.get("scorecard").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let Some(overall) = scorecard
        .get("overallScore")
        .and_then(serde_json::Value::as_f64)
    else {
        return Ok(None);
    };
    let checks = scorecard
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .map(|checks| {
            checks
                .iter()
                .filter_map(|check| {
                    let name = check.get("name")?.as_str()?;
                    if !SHOWN_CHECKS.contains(&name) {
                        return None;
                    }
                    let score = check.get("score")?.as_i64()?;
                    Some(ScorecardCheck {
                        name: name.to_string(),
                        score: i32::try_from(score).ok()?,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(Scorecard {
        overall,
        date: scorecard
            .get("date")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        checks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_forms_fold_to_one_project_key() {
        for repository in [
            "https://github.com/a/b",
            "https://github.com/a/b.git",
            "https://github.com/a/b/",
            "http://www.github.com/a/b",
            "git+https://github.com/a/b.git",
            "git@github.com:a/b.git",
            "ssh://git@github.com/a/b.git",
            "https://github.com/a/b/tree/main/crates/c",
        ] {
            assert_eq!(
                project_key(repository).as_deref(),
                Some("github.com/a/b"),
                "{repository}"
            );
        }
    }

    #[test]
    fn unknown_hosts_and_junk_are_refused() {
        for repository in [
            "https://example.com/a/b",
            "https://github.com/a",
            "https://github.com/a/b?x=1",
            "https://github.com/a/../b",
            "not a url",
            "",
        ] {
            assert_eq!(project_key(repository), None, "{repository}");
        }
        assert_eq!(
            project_key("https://gitlab.com/g/p").as_deref(),
            Some("gitlab.com/g/p")
        );
    }

    #[test]
    fn parses_the_overall_score_and_shown_checks() {
        let body = r#"{"scorecard":{
            "date":"2026-08-24T00:00:00Z",
            "overallScore":6.9,
            "checks":[
                {"name":"Maintained","score":10},
                {"name":"Code-Review","score":10},
                {"name":"Branch-Protection","score":-1},
                {"name":"Signed-Releases","score":-1},
                {"name":"Dangerous-Workflow","score":10},
                {"name":"Fuzzing","score":0}
            ]}}"#;
        let scorecard = parse_project(body).unwrap().expect("a scorecard");
        assert_eq!(scorecard.overall, 6.9);
        assert_eq!(scorecard.date, "2026-08-24T00:00:00Z");
        let names: Vec<&str> = scorecard
            .checks
            .iter()
            .map(|check| check.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "Maintained",
                "Code-Review",
                "Branch-Protection",
                "Signed-Releases",
                "Dangerous-Workflow"
            ]
        );
        assert_eq!(scorecard.checks[2].score, -1);
    }

    #[test]
    fn a_project_without_a_scorecard_is_none() {
        assert_eq!(parse_project(r#"{"projectKey":{"id":"x"}}"#).unwrap(), None);
        assert_eq!(parse_project(r#"{"scorecard":null}"#).unwrap(), None);
        assert_eq!(
            parse_project(r#"{"scorecard":{"checks":[]}}"#).unwrap(),
            None
        );
        assert!(parse_project("[]").is_ok(), "arrays are valid JSON");
        assert!(parse_project("not json").is_err());
    }

    #[test]
    fn a_scorecard_without_checks_still_reports_the_overall_score() {
        let body = r#"{"scorecard":{"date":"d","overallScore":3.1}}"#;
        let scorecard = parse_project(body).unwrap().expect("a scorecard");
        assert_eq!(scorecard.overall, 3.1);
        assert!(scorecard.checks.is_empty());
    }
}
