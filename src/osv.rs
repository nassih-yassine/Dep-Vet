//! OSV advisories for the exact version being vetted.
//!
//! `/v1/querybatch` answers with little more than advisory IDs, so each hit is
//! hydrated through `/v1/vulns/{id}`. Severity comes from OSV's
//! `database_specific` label; an advisory without one is a warning, never
//! silently dropped.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::http::{HttpClient, HttpError};
use crate::model::Severity;

const DEFAULT_OSV_BASE: &str = "https://api.osv.dev";
const OSV_VULN_URL: &str = "https://osv.dev/vulnerability";
/// Bound the number of detail requests for packages with a long advisory list.
pub const MAX_ADVISORIES: usize = 25;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub severity: Severity,
    pub aliases: Vec<String>,
    pub url: String,
}

impl Advisory {
    pub fn display_title(&self) -> String {
        format!("{} affects this version", self.id)
    }

    fn unavailable(id: &str) -> Self {
        Self {
            id: id.to_string(),
            summary: "OSV did not return details for this advisory".to_string(),
            // An advisory we know exists but cannot read is still worth a look.
            severity: Severity::Warn,
            aliases: Vec::new(),
            url: format!("{OSV_VULN_URL}/{id}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OsvError {
    #[error("OSV request failed: {0}")]
    Http(#[from] HttpError),
    #[error("OSV sent a response dep-vet could not read: {0}")]
    Decode(String),
}

pub struct OsvClient {
    http: Arc<HttpClient>,
    base: String,
}

impl OsvClient {
    pub fn from_env(http: Arc<HttpClient>) -> Self {
        let base =
            std::env::var("DEPVET_OSV_BASE").unwrap_or_else(|_| DEFAULT_OSV_BASE.to_string());
        Self::with_base(http, base)
    }

    pub fn with_base(http: Arc<HttpClient>, base: impl Into<String>) -> Self {
        Self {
            http,
            base: base.into(),
        }
    }

    pub fn query(&self, name: &str, version: &str) -> Result<Vec<Advisory>, OsvError> {
        let url = format!("{}/v1/querybatch", self.base.trim_end_matches('/'));
        let body = serde_json::json!({
            "queries": [{
                "package": { "name": name, "ecosystem": "npm" },
                "version": version
            }]
        });
        let response = self.http.post_json(&url, &body)?;
        let ids = parse_advisory_ids(&response)?;
        Ok(ids
            .into_iter()
            .take(MAX_ADVISORIES)
            .map(|id| self.advisory(&id))
            .collect())
    }

    fn advisory(&self, id: &str) -> Advisory {
        let url = format!("{}/v1/vulns/{id}", self.base.trim_end_matches('/'));
        match self
            .http
            .get(&url)
            .ok()
            .and_then(|body| parse_advisory(&body).ok())
        {
            Some(advisory) => advisory,
            None => Advisory::unavailable(id),
        }
    }
}

fn parse_advisory_ids(body: &str) -> Result<Vec<String>, OsvError> {
    let response: BatchResponse =
        serde_json::from_str(body).map_err(|error| OsvError::Decode(error.to_string()))?;

    let mut ids: Vec<String> = Vec::new();
    for result in response.results {
        for vuln in result.vulns {
            if !ids.contains(&vuln.id) {
                ids.push(vuln.id);
            }
        }
    }
    Ok(ids)
}

fn parse_advisory(body: &str) -> Result<Advisory, OsvError> {
    let vuln: VulnRecord =
        serde_json::from_str(body).map_err(|error| OsvError::Decode(error.to_string()))?;
    Ok(Advisory {
        summary: vuln
            .summary
            .filter(|summary| !summary.trim().is_empty())
            .unwrap_or_else(|| "advisory without a summary".to_string()),
        severity: severity_of(vuln.database_specific.as_ref()),
        url: format!("{OSV_VULN_URL}/{}", vuln.id),
        aliases: vuln.aliases,
        id: vuln.id,
    })
}

fn severity_of(specific: Option<&DatabaseSpecific>) -> Severity {
    match specific
        .and_then(|specific| specific.severity.as_deref())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("critical" | "high") => Severity::High,
        Some("low") => Severity::Info,
        Some("moderate" | "medium") => Severity::Warn,
        // Unknown or absent severity: an advisory is at least worth a look.
        _ => Severity::Warn,
    }
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<QueryResult>,
}

#[derive(Debug, Deserialize)]
struct QueryResult {
    #[serde(default)]
    vulns: Vec<QueryId>,
}

#[derive(Debug, Deserialize)]
struct QueryId {
    id: String,
}

#[derive(Debug, Deserialize)]
struct VulnRecord {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    database_specific: Option<DatabaseSpecific>,
}

#[derive(Debug, Deserialize)]
struct DatabaseSpecific {
    #[serde(default)]
    severity: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(ids: &[&str]) -> String {
        let vulns: Vec<String> = ids.iter().map(|id| format!(r#"{{"id":"{id}"}}"#)).collect();
        format!(
            r#"{{ "results": [ {{ "vulns": [ {} ] }} ] }}"#,
            vulns.join(",")
        )
    }

    #[test]
    fn extracts_ids_in_order() {
        assert_eq!(
            parse_advisory_ids(&batch(&["A", "B"])).unwrap(),
            vec!["A", "B"]
        );
    }

    #[test]
    fn duplicate_ids_are_collapsed() {
        assert_eq!(parse_advisory_ids(&batch(&["A", "A"])).unwrap(), vec!["A"]);
    }

    #[test]
    fn empty_results_mean_no_advisories() {
        assert_eq!(
            parse_advisory_ids(r#"{"results":[]}"#).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            parse_advisory_ids(r#"{"results":[{}]}"#).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(parse_advisory_ids("{}").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn malformed_json_is_a_decode_error() {
        assert!(matches!(
            parse_advisory_ids("not json"),
            Err(OsvError::Decode(_))
        ));
    }

    #[test]
    fn missing_id_is_a_decode_error() {
        let body = r#"{"results":[{"vulns":[{"summary":"no id"}]}]}"#;
        assert!(matches!(parse_advisory_ids(body), Err(OsvError::Decode(_))));
    }

    #[test]
    fn parses_a_high_advisory() {
        let body = r#"{
            "id": "GHSA-29mw-wpgm-hmr9",
            "summary": "Regular Expression Denial of Service in lodash",
            "aliases": ["CVE-2020-28500"],
            "database_specific": { "severity": "HIGH" }
        }"#;
        let advisory = parse_advisory(body).unwrap();
        assert_eq!(advisory.id, "GHSA-29mw-wpgm-hmr9");
        assert_eq!(advisory.severity, Severity::High);
        assert_eq!(advisory.aliases, vec!["CVE-2020-28500"]);
        assert_eq!(
            advisory.url,
            "https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9"
        );
    }

    #[test]
    fn maps_every_severity_label() {
        let cases = [
            ("CRITICAL", Severity::High),
            ("HIGH", Severity::High),
            ("high", Severity::High),
            ("MODERATE", Severity::Warn),
            ("MEDIUM", Severity::Warn),
            ("LOW", Severity::Info),
            ("UNKNOWN", Severity::Warn),
        ];
        for (label, expected) in cases {
            let body =
                format!(r#"{{ "id": "X", "database_specific": {{ "severity": "{label}" }} }}"#);
            assert_eq!(
                parse_advisory(&body).unwrap().severity,
                expected,
                "label {label}"
            );
        }
    }

    #[test]
    fn missing_severity_is_a_warning() {
        let advisory = parse_advisory(r#"{ "id": "X" }"#).unwrap();
        assert_eq!(advisory.severity, Severity::Warn);
    }

    #[test]
    fn missing_summary_gets_a_placeholder() {
        let advisory = parse_advisory(r#"{ "id": "X", "summary": "  " }"#).unwrap();
        assert_eq!(advisory.summary, "advisory without a summary");
    }

    #[test]
    fn unavailable_advisory_still_links_to_osv() {
        let advisory = Advisory::unavailable("GHSA-x");
        assert_eq!(advisory.severity, Severity::Warn);
        assert_eq!(advisory.url, "https://osv.dev/vulnerability/GHSA-x");
    }
}
