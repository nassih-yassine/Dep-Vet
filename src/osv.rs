//! OSV advisories for the exact version being vetted.
//!
//! `/v1/querybatch` answers with little more than advisory IDs, so each hit is
//! hydrated through `/v1/vulns/{id}`. Severity comes from OSV's
//! `database_specific` label; an advisory without one is a warning, never
//! silently dropped.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::http::{HttpClient, HttpError};
use crate::model::{Ecosystem, Severity, names_match};

const DEFAULT_OSV_BASE: &str = "https://api.osv.dev";
const OSV_VULN_URL: &str = "https://osv.dev/vulnerability";
/// Bound the number of detail requests for packages with a long advisory list.
pub const MAX_ADVISORIES: usize = 25;
/// OSV accepts up to 1000 queries per batch; 500 bounds the response size.
pub const MAX_QUERIES_PER_BATCH: usize = 500;

/// One package version to ask OSV about.
#[derive(Debug, Clone)]
pub struct OsvQuery {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}
/// At most this many detail requests in flight. 25 at once invited 429s.
const MAX_CONCURRENT_FETCHES: usize = 8;

/// What one query produced: the advisories we could read, and how many were
/// skipped once the cap was reached.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdvisoryList {
    pub advisories: Vec<Advisory>,
    pub hidden: usize,
    /// How old the cached advisory answer was when it was served after a
    /// failed refresh. `None` means the answer is fresh.
    pub stale_seconds: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub severity: Severity,
    pub aliases: Vec<String>,
    pub url: String,
    /// Versions OSV says fix this advisory for the audited package, in the
    /// order the ranges list them. Empty when no fix was published or the
    /// details could not be read.
    pub fixed_versions: Vec<String>,
    /// The record was listed but its details could not be fetched, so its fix
    /// is unknown rather than absent.
    #[serde(skip)]
    pub details_missing: bool,
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
            fixed_versions: Vec::new(),
            details_missing: true,
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

    pub fn query(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<AdvisoryList, OsvError> {
        let queries = [OsvQuery {
            ecosystem,
            name: name.to_string(),
            version: version.to_string(),
        }];
        self.query_batch(&queries)
            .pop()
            .flatten()
            .ok_or_else(|| OsvError::Decode("advisory batch unavailable".to_string()))
    }

    /// Ask about many packages at once. Results stay in input order; each
    /// advisory body is fetched once and filtered per package, so fixed
    /// versions remain package-specific. A failed chunk yields `None` for its
    /// packages only; later chunks still run.
    pub fn query_batch(&self, queries: &[OsvQuery]) -> Vec<Option<AdvisoryList>> {
        let mut lists = Vec::with_capacity(queries.len());
        for chunk in queries.chunks(MAX_QUERIES_PER_BATCH) {
            match self.fetch_chunk(chunk) {
                Ok(chunk_lists) => lists.extend(chunk_lists.into_iter().map(Some)),
                Err(_) => lists.extend(std::iter::repeat_n(None, chunk.len())),
            }
        }
        lists
    }

    fn fetch_chunk(&self, chunk: &[OsvQuery]) -> Result<Vec<AdvisoryList>, OsvError> {
        let url = format!("{}/v1/querybatch", self.base.trim_end_matches('/'));
        let body = serde_json::json!({
            "queries": chunk
                .iter()
                .map(|query| serde_json::json!({
                    "package": {
                        "name": query.name,
                        "ecosystem": query.ecosystem.osv_name()
                    },
                    "version": query.version
                }))
                .collect::<Vec<_>>()
        });
        let (response, source) = self.http.post_json_with_source(&url, &body)?;
        let stale_seconds = match source {
            crate::http::Source::Stale { age_seconds } => Some(age_seconds),
            _ => None,
        };
        // Cap before hydrating: the cap exists to bound detail requests.
        let capped: Vec<(Vec<String>, usize)> = parse_batch_ids(&response)?
            .into_iter()
            .map(take_capped)
            .collect();

        let mut unique: Vec<String> = Vec::new();
        for (ids, _) in &capped {
            for id in ids {
                if !unique.contains(id) {
                    unique.push(id.clone());
                }
            }
        }
        let bodies = self.fetch_bodies(&unique);
        let stale_seconds = oldest_stale(stale_seconds, &bodies);
        check_len(
            lists_from(chunk, capped, &bodies, stale_seconds),
            chunk.len(),
        )
    }

    /// Raw advisory bodies keyed by id. A failed fetch is `None`, which becomes
    /// an "unavailable" advisory rather than a missing one.
    fn fetch_bodies(&self, ids: &[String]) -> Bodies {
        let mut bodies = std::collections::HashMap::new();
        for batch in advisory_batches(ids) {
            let fetched: Vec<(String, FetchedBody)> = std::thread::scope(|scope| {
                let handles: Vec<_> = batch
                    .iter()
                    .map(|id| {
                        let url = format!("{}/v1/vulns/{id}", self.base.trim_end_matches('/'));
                        (
                            id,
                            scope.spawn(move || {
                                self.http.get_with_source(&url).ok().map(|(body, source)| {
                                    let age = match source {
                                        crate::http::Source::Stale { age_seconds } => {
                                            Some(age_seconds)
                                        }
                                        _ => None,
                                    };
                                    (body, age)
                                })
                            }),
                        )
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|(id, handle)| (id.clone(), handle.join().unwrap_or(None)))
                    .collect()
            });
            bodies.extend(fetched);
        }
        bodies
    }
}

/// A body plus how old a cached copy was, when it was served stale.
type FetchedBody = Option<(String, Option<i64>)>;
type Bodies = std::collections::HashMap<String, FetchedBody>;

/// The batch and every detail body contribute; the oldest stale age wins, so
/// the finding never understates how old the advice is.
fn oldest_stale(batch: Option<i64>, bodies: &Bodies) -> Option<i64> {
    bodies
        .values()
        .filter_map(|body| body.as_ref().and_then(|(_, age)| *age))
        .chain(batch)
        .max()
}

/// A server that answers a different number of queries than it was given has
/// broken the batch contract; the whole chunk is then unknown, never clean.
fn check_len(lists: Vec<AdvisoryList>, expected: usize) -> Result<Vec<AdvisoryList>, OsvError> {
    if lists.len() == expected {
        Ok(lists)
    } else {
        Err(OsvError::Decode(format!(
            "batch returned {} answers for {expected} queries",
            lists.len()
        )))
    }
}

/// One id list per query, in query order. An empty result stays empty.
fn parse_batch_ids(body: &str) -> Result<Vec<Vec<String>>, OsvError> {
    let response: BatchResponse =
        serde_json::from_str(body).map_err(|error| OsvError::Decode(error.to_string()))?;

    Ok(response
        .results
        .into_iter()
        .map(|result| {
            let mut ids: Vec<String> = Vec::new();
            for vuln in result.vulns {
                if !ids.contains(&vuln.id) {
                    ids.push(vuln.id);
                }
            }
            ids
        })
        .collect())
}

/// Builds one list per query from already-fetched bodies, filtering an
/// advisory's fixed versions by the package that asked.
fn lists_from(
    queries: &[OsvQuery],
    ids: Vec<(Vec<String>, usize)>,
    bodies: &Bodies,
    stale_seconds: Option<i64>,
) -> Vec<AdvisoryList> {
    queries
        .iter()
        .zip(ids)
        .map(|(query, (ids, hidden))| {
            let advisories = ids
                .iter()
                .map(|id| match bodies.get(id) {
                    Some(Some((body, _))) => parse_advisory(body, query.ecosystem, &query.name)
                        .unwrap_or_else(|_| Advisory::unavailable(id)),
                    _ => Advisory::unavailable(id),
                })
                .collect();
            AdvisoryList {
                advisories: dedupe(advisories),
                hidden,
                stale_seconds,
            }
        })
        .collect()
}

fn advisory_batches(ids: &[String]) -> impl Iterator<Item = &[String]> {
    ids.chunks(MAX_CONCURRENT_FETCHES)
}

/// OSV lists one issue under several databases (PYSEC, GHSA, CVE). Merge any
/// records whose id or alias sets overlap so a vulnerability is counted once.
fn dedupe(advisories: Vec<Advisory>) -> Vec<Advisory> {
    if advisories.len() < 2 {
        return advisories;
    }

    let mut parent: Vec<usize> = (0..advisories.len()).collect();
    fn find(parent: &mut Vec<usize>, index: usize) -> usize {
        if parent[index] != index {
            let root = find(parent, parent[index]);
            parent[index] = root;
        }
        parent[index]
    }
    fn union(parent: &mut Vec<usize>, a: usize, b: usize) {
        let (root_a, root_b) = (find(parent, a), find(parent, b));
        if root_a != root_b {
            parent[root_b] = root_a;
        }
    }

    let mut owner: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (index, advisory) in advisories.iter().enumerate() {
        for token in std::iter::once(&advisory.id).chain(advisory.aliases.iter()) {
            let token = token.to_ascii_lowercase();
            match owner.get(&token) {
                Some(&first) => union(&mut parent, first, index),
                None => {
                    owner.insert(token, index);
                }
            }
        }
    }

    let mut groups: Vec<(usize, Vec<Advisory>)> = Vec::new();
    let mut group_of: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for (index, advisory) in advisories.into_iter().enumerate() {
        let root = find(&mut parent, index);
        match group_of.get(&root) {
            Some(&group) => groups[group].1.push(advisory),
            None => {
                group_of.insert(root, groups.len());
                groups.push((index, vec![advisory]));
            }
        }
    }

    groups
        .into_iter()
        .map(|(_, group)| merge_group(group))
        .collect()
}

fn merge_group(mut group: Vec<Advisory>) -> Advisory {
    if group.len() == 1 {
        return group.remove(0);
    }
    group.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.id.len().cmp(&b.id.len()))
            .then_with(|| a.id.cmp(&b.id))
    });

    let severity = group[0].severity;
    let summary = group
        .iter()
        .map(|advisory| advisory.summary.as_str())
        .find(|summary| *summary != "advisory without a summary")
        .unwrap_or("advisory without a summary")
        .to_string();
    let mut aliases: Vec<String> = group
        .iter()
        .flat_map(|advisory| {
            std::iter::once(advisory.id.clone()).chain(advisory.aliases.iter().cloned())
        })
        .filter(|alias| !alias.eq_ignore_ascii_case(&group[0].id))
        .collect();
    aliases.sort();
    aliases.dedup();

    let mut fixed_versions: Vec<String> = Vec::new();
    for advisory in &group {
        for version in &advisory.fixed_versions {
            if !fixed_versions.contains(version) {
                fixed_versions.push(version.clone());
            }
        }
    }

    Advisory {
        id: group[0].id.clone(),
        summary,
        severity,
        aliases,
        url: group[0].url.clone(),
        fixed_versions,
        details_missing: group.iter().any(|advisory| advisory.details_missing),
    }
}

/// Keeps the first `MAX_ADVISORIES` ids and reports how many were dropped, so
/// the report can say it is partial.
fn take_capped(mut ids: Vec<String>) -> (Vec<String>, usize) {
    if ids.len() <= MAX_ADVISORIES {
        return (ids, 0);
    }
    let hidden = ids.len() - MAX_ADVISORIES;
    ids.truncate(MAX_ADVISORIES);
    (ids, hidden)
}

fn parse_advisory(body: &str, ecosystem: Ecosystem, name: &str) -> Result<Advisory, OsvError> {
    let vuln: VulnRecord =
        serde_json::from_str(body).map_err(|error| OsvError::Decode(error.to_string()))?;
    let fixed_versions = fixed_for(&vuln, ecosystem, name);
    Ok(Advisory {
        summary: vuln
            .summary
            .filter(|summary| !summary.trim().is_empty())
            .unwrap_or_else(|| "advisory without a summary".to_string()),
        severity: severity_of(vuln.database_specific.as_ref()),
        url: format!("{OSV_VULN_URL}/{}", vuln.id),
        fixed_versions,
        aliases: vuln.aliases,
        id: vuln.id,
        details_missing: false,
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
    #[serde(default)]
    affected: Vec<Affected>,
}

#[derive(Debug, Deserialize)]
struct Affected {
    package: AffectedPackage,
    #[serde(default)]
    ranges: Vec<AffectedRange>,
}

#[derive(Debug, Deserialize)]
struct AffectedPackage {
    #[serde(default)]
    name: String,
    #[serde(default)]
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct AffectedRange {
    /// OSV names the range kind; `GIT` fixes are commits, not versions.
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    events: Vec<AffectedEvent>,
}

#[derive(Debug, Deserialize)]
struct AffectedEvent {
    #[serde(default)]
    fixed: Option<String>,
}

/// Versions OSV names as fixing this advisory, limited to the package that was
/// queried (one advisory can cover several packages).
fn fixed_for(record: &VulnRecord, ecosystem: Ecosystem, name: &str) -> Vec<String> {
    let mut fixed = Vec::new();
    for affected in &record.affected {
        if !names_match(ecosystem, &affected.package.name, name)
            || !names_match(ecosystem, &affected.package.ecosystem, ecosystem.osv_name())
        {
            continue;
        }
        for range in &affected.ranges {
            if !matches!(range.kind.as_str(), "ECOSYSTEM" | "SEMVER") {
                continue;
            }
            for event in &range.events {
                if let Some(version) = &event.fixed
                    && !fixed.contains(version)
                {
                    fixed.push(version.clone());
                }
            }
        }
    }
    fixed
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
    fn batch_ids_stay_aligned_with_empty_results() {
        let body = r#"{"results":[{"vulns":[{"id":"A"}]},{},{"vulns":[{"id":"B"},{"id":"B"}]}]}"#;
        assert_eq!(
            parse_batch_ids(body).unwrap(),
            vec![vec!["A".to_string()], Vec::new(), vec!["B".to_string()]]
        );
    }

    #[test]
    fn a_shared_advisory_is_filtered_per_queried_package() {
        let record = r#"{
            "id": "GHSA-shared",
            "summary": "shared",
            "affected": [
                { "package": { "ecosystem": "npm", "name": "pkg-a" },
                  "ranges": [ { "type": "ECOSYSTEM", "events": [ { "fixed": "2.0.0" } ] } ] },
                { "package": { "ecosystem": "npm", "name": "pkg-b" },
                  "ranges": [ { "type": "ECOSYSTEM", "events": [ { "fixed": "3.0.0" } ] } ] }
            ]
        }"#;
        let queries = vec![
            OsvQuery {
                ecosystem: Ecosystem::Npm,
                name: "pkg-a".to_string(),
                version: "1.0.0".to_string(),
            },
            OsvQuery {
                ecosystem: Ecosystem::Npm,
                name: "pkg-b".to_string(),
                version: "1.0.0".to_string(),
            },
        ];
        let ids = vec![
            (vec!["GHSA-shared".to_string()], 0),
            (vec!["GHSA-shared".to_string()], 0),
        ];
        let mut bodies = std::collections::HashMap::new();
        bodies.insert("GHSA-shared".to_string(), Some((record.to_string(), None)));

        let lists = lists_from(&queries, ids, &bodies, None);
        assert_eq!(
            lists[0].advisories[0].fixed_versions,
            vec!["2.0.0".to_string()]
        );
        assert_eq!(
            lists[1].advisories[0].fixed_versions,
            vec!["3.0.0".to_string()]
        );
    }

    #[test]
    fn extracts_ids_in_order() {
        assert_eq!(
            parse_batch_ids(&batch(&["A", "B"])).unwrap(),
            vec![vec!["A".to_string(), "B".to_string()]]
        );
    }

    #[test]
    fn duplicate_ids_are_collapsed() {
        assert_eq!(
            parse_batch_ids(&batch(&["A", "A"])).unwrap(),
            vec![vec!["A".to_string()]]
        );
    }

    #[test]
    fn empty_results_mean_no_advisories() {
        assert_eq!(
            parse_batch_ids(r#"{"results":[]}"#).unwrap(),
            Vec::<Vec<String>>::new()
        );
        assert_eq!(
            parse_batch_ids(r#"{"results":[{}]}"#).unwrap(),
            vec![Vec::<String>::new()]
        );
        assert_eq!(parse_batch_ids("{}").unwrap(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn malformed_json_is_a_decode_error() {
        assert!(matches!(
            parse_batch_ids("not json"),
            Err(OsvError::Decode(_))
        ));
    }

    #[test]
    fn missing_id_is_a_decode_error() {
        let body = r#"{"results":[{"vulns":[{"summary":"no id"}]}]}"#;
        assert!(matches!(parse_batch_ids(body), Err(OsvError::Decode(_))));
    }

    #[test]
    fn a_short_answer_for_a_batch_is_rejected() {
        assert!(check_len(Vec::new(), 2).is_err());
        assert!(check_len(vec![AdvisoryList::default(); 2], 2).is_ok());
    }

    const VULN_MULTI: &str = r#"{
        "id": "GHSA-test-0001",
        "summary": "test",
        "affected": [
            { "package": { "ecosystem": "npm", "name": "left-pad" },
              "ranges": [ { "type": "ECOSYSTEM",
                            "events": [ { "introduced": "0" }, { "fixed": "1.2.3" },
                                        { "introduced": "2.0.0" }, { "fixed": "2.0.1" } ] } ] },
            { "package": { "ecosystem": "npm", "name": "other-pkg" },
              "ranges": [ { "type": "ECOSYSTEM", "events": [ { "fixed": "9.9.9" } ] } ] }
        ]
    }"#;

    #[test]
    fn fixed_versions_are_limited_to_the_audited_package() {
        let advisory = parse_advisory(VULN_MULTI, Ecosystem::Npm, "Left-Pad").unwrap();
        assert_eq!(
            advisory.fixed_versions,
            vec!["1.2.3".to_string(), "2.0.1".to_string()]
        );
    }

    #[test]
    fn git_ranges_do_not_contribute_commit_hashes_as_versions() {
        let body = r#"{ "id": "X", "affected": [
            { "package": { "ecosystem": "npm", "name": "x" },
              "ranges": [
                { "type": "GIT", "events": [ { "fixed": "0f09c3a9b462" } ] },
                { "type": "ECOSYSTEM", "events": [ { "fixed": "1.2.3" } ] }
              ] }
        ] }"#;
        let advisory = parse_advisory(body, Ecosystem::Npm, "x").unwrap();
        assert_eq!(advisory.fixed_versions, vec!["1.2.3".to_string()]);
    }

    #[test]
    fn an_advisory_without_fixed_events_has_no_fixed_versions() {
        let advisory = parse_advisory(
            r#"{ "id": "X", "affected": [ { "package": { "ecosystem": "npm", "name": "x" },
                "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "0" } ] } ] } ] }"#,
            Ecosystem::Npm,
            "x",
        )
        .unwrap();
        assert!(advisory.fixed_versions.is_empty());
        assert!(!advisory.details_missing);
    }

    #[test]
    fn an_unhydrated_advisory_marks_details_missing() {
        let advisory = Advisory::unavailable("GHSA-x");
        assert!(advisory.details_missing);
        assert!(advisory.fixed_versions.is_empty());
    }

    #[test]
    fn parses_a_high_advisory() {
        let body = r#"{
            "id": "GHSA-29mw-wpgm-hmr9",
            "summary": "Regular Expression Denial of Service in lodash",
            "aliases": ["CVE-2020-28500"],
            "database_specific": { "severity": "HIGH" }
        }"#;
        let advisory = parse_advisory(body, Ecosystem::Npm, "lodash").unwrap();
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
                parse_advisory(&body, Ecosystem::Npm, "lodash")
                    .unwrap()
                    .severity,
                expected,
                "label {label}"
            );
        }
    }

    #[test]
    fn missing_severity_is_a_warning() {
        let advisory = parse_advisory(r#"{ "id": "X" }"#, Ecosystem::Npm, "x").unwrap();
        assert_eq!(advisory.severity, Severity::Warn);
    }

    #[test]
    fn missing_summary_gets_a_placeholder() {
        let advisory =
            parse_advisory(r#"{ "id": "X", "summary": "  " }"#, Ecosystem::Npm, "x").unwrap();
        assert_eq!(advisory.summary, "advisory without a summary");
    }

    #[test]
    fn the_cap_reports_what_it_dropped() {
        let many: Vec<String> = (0..30).map(|index| format!("GHSA-{index}")).collect();
        let (kept, hidden) = take_capped(many);
        assert_eq!(kept.len(), MAX_ADVISORIES);
        assert_eq!(hidden, 5);
    }

    #[test]
    fn lists_within_the_cap_hide_nothing() {
        let some: Vec<String> = (0..3).map(|index| format!("GHSA-{index}")).collect();
        let (kept, hidden) = take_capped(some);
        assert_eq!(kept.len(), 3);
        assert_eq!(hidden, 0);
    }

    #[test]
    fn detail_fetches_are_batched_to_cap_concurrency() {
        let ids: Vec<String> = (0..MAX_ADVISORIES).map(|index| index.to_string()).collect();
        let sizes: Vec<usize> = advisory_batches(&ids).map(<[String]>::len).collect();
        assert_eq!(sizes, vec![8, 8, 8, 1]);
        assert_eq!(sizes.iter().max(), Some(&MAX_CONCURRENT_FETCHES));
    }

    fn advisory(id: &str, aliases: &[&str], severity: Severity, summary: &str) -> Advisory {
        Advisory {
            id: id.to_string(),
            summary: summary.to_string(),
            severity,
            aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
            url: format!("https://osv.dev/vulnerability/{id}"),
            fixed_versions: Vec::new(),
            details_missing: false,
        }
    }

    #[test]
    fn one_vulnerability_listed_twice_becomes_one_finding() {
        let merged = dedupe(vec![
            advisory(
                "PYSEC-2026-1",
                &["CVE-2026-1", "GHSA-aaaa"],
                Severity::Warn,
                "real summary",
            ),
            advisory(
                "GHSA-aaaa",
                &["CVE-2026-1", "PYSEC-2026-1"],
                Severity::High,
                "real summary",
            ),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].severity, Severity::High);
        assert_eq!(merged[0].id, "GHSA-aaaa");
        assert!(
            merged[0]
                .aliases
                .iter()
                .any(|alias| alias == "PYSEC-2026-1" || alias == "CVE-2026-1")
        );
    }

    #[test]
    fn merging_is_transitive_through_aliases() {
        let merged = dedupe(vec![
            advisory("A-1", &["CVE-1"], Severity::Warn, "one"),
            advisory("B-1", &["CVE-1", "CVE-2"], Severity::Warn, "one"),
            advisory("C-1", &["CVE-2"], Severity::Warn, "one"),
        ]);
        assert_eq!(merged.len(), 1);
        for alias in ["B-1", "C-1", "CVE-1", "CVE-2"] {
            assert!(
                merged[0].aliases.iter().any(|candidate| candidate == alias),
                "missing alias {alias}"
            );
        }
    }

    #[test]
    fn unrelated_advisories_keep_their_order() {
        let merged = dedupe(vec![
            advisory("A-1", &[], Severity::Warn, "a"),
            advisory("B-1", &[], Severity::High, "b"),
        ]);
        assert_eq!(
            merged.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            vec!["A-1", "B-1"]
        );
    }

    #[test]
    fn a_placeholder_summary_yields_to_a_real_one() {
        let merged = dedupe(vec![
            advisory(
                "PYSEC-1",
                &["CVE-9"],
                Severity::Warn,
                "advisory without a summary",
            ),
            advisory("GHSA-1", &["CVE-9"], Severity::Warn, "Prototype pollution"),
        ]);
        assert_eq!(merged[0].summary, "Prototype pollution");
    }

    #[test]
    fn dedupe_leaves_single_records_alone() {
        let merged = dedupe(vec![advisory("A-1", &["CVE-1"], Severity::Info, "a")]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].aliases, vec!["CVE-1"]);
    }

    #[test]
    fn unavailable_advisory_still_links_to_osv() {
        let advisory = Advisory::unavailable("GHSA-x");
        assert_eq!(advisory.severity, Severity::Warn);
        assert_eq!(advisory.url, "https://osv.dev/vulnerability/GHSA-x");
    }
}
