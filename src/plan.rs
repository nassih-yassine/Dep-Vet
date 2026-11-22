//! npm dependency planning from registry metadata.
//!
//! `plan` resolves version ranges by reading packuments, never by installing:
//! no lifecycle script runs, no tarball is downloaded, and the resolver is
//! bounded in nodes and depth. It records every range it could not resolve
//! instead of pretending the tree is complete.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use semver::{Version, VersionReq};
use serde::Serialize;

use crate::graph::{DependencyEdge, DependencyGraph, DependencyNode, EdgeKind};
use crate::model::{Ecosystem, PackageSpec};
use crate::registry::{PlanPackument, RegistryClient};

pub const MAX_NODES: usize = 2_000;
pub const MAX_DEPTH: usize = 50;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PlannedNode {
    pub id: String,
    pub name: String,
    pub version: String,
    pub direct: bool,
    pub optional: bool,
    pub peer: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PlanEdgeKind {
    Normal,
    Optional,
    Peer,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PlannedEdge {
    pub from: String,
    pub to: String,
    pub range: String,
    pub kind: PlanEdgeKind,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Conflict {
    pub name: String,
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Unresolved {
    pub from: String,
    pub name: String,
    pub range: String,
    /// Optional and peer dependencies are allowed to be absent.
    pub required: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanReport {
    pub ecosystem: Ecosystem,
    pub requested: String,
    pub root: String,
    pub nodes: Vec<PlannedNode>,
    pub edges: Vec<PlannedEdge>,
    /// Names resolved to more than one version. npm allows this; it is
    /// reported as context, not a failure.
    pub conflicts: Vec<Conflict>,
    pub unresolved: Vec<Unresolved>,
    pub truncated: bool,
}

impl PlanReport {
    /// A plan is complete when it was not cut off and every required edge
    /// resolved. Optional and peer misses do not make it incomplete.
    pub fn complete(&self) -> bool {
        !self.truncated && self.unresolved.iter().all(|entry| !entry.required)
    }

    pub fn exit_code(&self) -> u8 {
        if self.complete() { 0 } else { 3 }
    }
}

/// Split `name@range` without rejecting semver operators the audit command
/// does not accept. The name still goes through the normal validator.
pub fn split_spec(input: &str) -> Result<(String, String), String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("package name is empty".to_string());
    }
    let (name, range) = match trimmed.split_once('@') {
        Some(("", rest)) => match rest.find('@') {
            Some(index) => (&trimmed[..index + 1], Some(&trimmed[index + 2..])),
            None => (trimmed, None),
        },
        Some((name, range)) => (name, Some(range)),
        None => (trimmed, None),
    };
    let name = PackageSpec::new(name, None)
        .map_err(|error| error.to_string())?
        .name;
    let range = range
        .map(str::trim)
        .filter(|range| !range.is_empty())
        .unwrap_or("latest")
        .to_string();
    Ok((name, range))
}

/// npm allows `||`; the semver crate models Cargo requirements, which do not.
/// Each alternative is tried separately.
fn range_matches(range: &str, version: &Version) -> bool {
    range
        .split("||")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .any(|part| VersionReq::parse(part).is_ok_and(|req| req.matches(version)))
}

fn parsed_versions(packument: &PlanPackument) -> Vec<(Version, &String)> {
    packument
        .versions
        .keys()
        .filter_map(|key| Version::parse(key).ok().map(|version| (version, key)))
        .collect()
}

/// Exact key, then dist-tag, then the highest matching semver version.
fn choose_version<'a>(packument: &'a PlanPackument, requested: &str) -> Option<&'a String> {
    if let Some(version) = packument.versions.get_key_value(requested) {
        return Some(version.0);
    }
    if let Some(tagged) = packument.dist_tags.get(requested)
        && packument.versions.contains_key(tagged)
    {
        return Some(packument.versions.get_key_value(tagged)?.0);
    }
    parsed_versions(packument)
        .into_iter()
        .filter(|(version, _)| range_matches(requested, version))
        .max_by(|(left, _), (right, _)| left.cmp(right))
        .map(|(_, key)| key)
}

fn resolve(
    client: &RegistryClient,
    spec: &PackageSpec,
    requested: &str,
) -> Result<PlanReport, String> {
    let raw_name = spec.name.clone();
    // Packuments can be tens of megabytes; keeping every one would defeat the
    // node cap. Reuse comes from the on-disk HTTP cache instead.
    let fetch = |name: &str| {
        client
            .plan_packument(name)
            .map_err(|error| error.to_string())
    };

    let root_document = fetch(&raw_name)?;
    let root_version = choose_version(&root_document, requested).ok_or_else(|| {
        format!(
            "no version of '{raw_name}' matches '{requested}' (plan does not resolve non-semver or git/URL specs)"
        )
    })?;
    let root_id = format!("{raw_name}@{root_version}");
    let mut nodes = vec![PlannedNode {
        id: root_id.clone(),
        name: raw_name.clone(),
        version: root_version.clone(),
        direct: true,
        optional: false,
        peer: false,
    }];
    let mut edges = Vec::new();
    let mut unresolved = Vec::new();
    let mut truncated = false;
    let mut seen: HashMap<String, usize> = HashMap::from([(root_id.clone(), 0)]);
    let mut queue: VecDeque<(usize, String, String, PlanEdgeKind, usize)> = VecDeque::new();

    let enqueue = |queue: &mut VecDeque<_>,
                   from: usize,
                   version: &crate::registry::PlanVersion,
                   depth: usize| {
        for (name, range) in &version.dependencies {
            queue.push_back((
                from,
                name.clone(),
                range.clone(),
                PlanEdgeKind::Normal,
                depth,
            ));
        }
        for (name, range) in &version.optional_dependencies {
            queue.push_back((
                from,
                name.clone(),
                range.clone(),
                PlanEdgeKind::Optional,
                depth,
            ));
        }
        for (name, range) in &version.peer_dependencies {
            queue.push_back((from, name.clone(), range.clone(), PlanEdgeKind::Peer, depth));
        }
    };
    enqueue(&mut queue, 0, &root_document.versions[root_version], 1);

    while let Some((from, name, range, kind, depth)) = queue.pop_front() {
        let required = kind == PlanEdgeKind::Normal;
        if nodes.len() >= MAX_NODES {
            truncated = true;
            break;
        }
        if depth > MAX_DEPTH {
            truncated = true;
            unresolved.push(Unresolved {
                from: nodes[from].id.clone(),
                name,
                range,
                required,
                reason: format!("depth limit ({MAX_DEPTH}) reached"),
            });
            continue;
        }
        let document = match fetch(&name) {
            Ok(document) => document,
            Err(error) => {
                unresolved.push(Unresolved {
                    from: nodes[from].id.clone(),
                    name,
                    range,
                    required,
                    reason: error,
                });
                continue;
            }
        };
        let Some(version) = choose_version(&document, &range) else {
            unresolved.push(Unresolved {
                from: nodes[from].id.clone(),
                name,
                range,
                required,
                reason: "no published version matches this range".to_string(),
            });
            continue;
        };
        let id = format!("{name}@{version}");
        let to = if let Some(position) = seen.get(&id) {
            *position
        } else {
            let position = nodes.len();
            nodes.push(PlannedNode {
                id: id.clone(),
                name: name.clone(),
                version: version.clone(),
                direct: from == 0,
                optional: kind == PlanEdgeKind::Optional,
                peer: kind == PlanEdgeKind::Peer,
            });
            seen.insert(id.clone(), position);
            enqueue(&mut queue, position, &document.versions[version], depth + 1);
            position
        };
        if from == 0 {
            // A direct dependency can already exist as a transitive node.
            nodes[to].direct = true;
        }
        edges.push(PlannedEdge {
            from: nodes[from].id.clone(),
            to: id,
            range,
            kind,
        });
    }

    let mut by_name: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for node in &nodes {
        by_name
            .entry(node.name.clone())
            .or_default()
            .insert(node.version.clone());
    }
    let conflicts = by_name
        .into_iter()
        .filter(|(_, versions)| versions.len() > 1)
        .map(|(name, versions)| Conflict {
            name,
            versions: versions.into_iter().collect(),
        })
        .collect();
    unresolved.sort_by(|left, right| {
        left.from
            .cmp(&right.from)
            .then(left.name.cmp(&right.name))
            .then(left.range.cmp(&right.range))
    });
    edges.sort_by(|left, right| {
        left.from
            .cmp(&right.from)
            .then(left.to.cmp(&right.to))
            .then(left.range.cmp(&right.range))
    });

    Ok(PlanReport {
        ecosystem: Ecosystem::Npm,
        requested: requested.to_string(),
        root: root_id,
        nodes,
        edges,
        conflicts,
        unresolved,
        truncated,
    })
}

pub fn plan(client: &RegistryClient, input: &str) -> Result<PlanReport, String> {
    let (name, range) = split_spec(input)?;
    let spec = PackageSpec::new(name, None).map_err(|error| error.to_string())?;
    resolve(client, &spec, &range)
}

pub fn adjacency(report: &PlanReport) -> BTreeMap<&str, Vec<&PlannedEdge>> {
    let mut children: BTreeMap<&str, Vec<&PlannedEdge>> = BTreeMap::new();
    for edge in &report.edges {
        children.entry(edge.from.as_str()).or_default().push(edge);
    }
    children
}

pub fn render_json(report: &PlanReport) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Json<'a> {
        #[serde(flatten)]
        report: &'a PlanReport,
        exit_code: u8,
    }
    serde_json::to_string_pretty(&Json {
        report,
        exit_code: report.exit_code(),
    })
}

pub fn render(report: &PlanReport) -> String {
    let mut out = format!(
        "plan: npm/{} (requested {})\n\n",
        report.root, report.requested
    );
    out.push_str(&format!(
        "  {} package{}, {} edge{}\n",
        report.nodes.len(),
        if report.nodes.len() == 1 { "" } else { "s" },
        report.edges.len(),
        if report.edges.len() == 1 { "" } else { "s" }
    ));
    if !report.conflicts.is_empty() {
        out.push_str("\n  multiple versions resolved:\n");
        for conflict in report.conflicts.iter().take(10) {
            out.push_str(&format!(
                "    {}: {}\n",
                conflict.name,
                conflict.versions.join(", ")
            ));
        }
        if report.conflicts.len() > 10 {
            out.push_str(&format!("    (+{} more)\n", report.conflicts.len() - 10));
        }
    }
    if report.truncated {
        out.push_str(&format!(
            "\n  truncated at {} packages or {} levels\n",
            MAX_NODES, MAX_DEPTH
        ));
    }
    if !report.unresolved.is_empty() {
        out.push_str("\n  not resolved:\n");
        for entry in report.unresolved.iter().take(15) {
            out.push_str(&format!(
                "    {} needs {}@{}{}: {}\n",
                entry.from,
                entry.name,
                entry.range,
                if entry.required { "" } else { " (optional)" },
                entry.reason
            ));
        }
        if report.unresolved.len() > 15 {
            out.push_str(&format!("    (+{} more)\n", report.unresolved.len() - 15));
        }
    }
    out.push('\n');

    let by_id: HashMap<&str, &PlannedNode> = report
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    let graph = DependencyGraph {
        nodes: report
            .nodes
            .iter()
            .map(|node| DependencyNode {
                name: node.name.clone(),
                version: node.version.clone(),
                path: node.id.clone(),
                direct: node.direct,
                dev: false,
                optional: node.optional,
            })
            .collect(),
        edges: report
            .edges
            .iter()
            .filter_map(|edge| {
                let name = by_id.get(edge.to.as_str())?.name.clone();
                Some(DependencyEdge {
                    from: edge.from.clone(),
                    to: edge.to.clone(),
                    name,
                    kind: match edge.kind {
                        PlanEdgeKind::Normal => EdgeKind::Normal,
                        PlanEdgeKind::Optional => EdgeKind::Optional,
                        PlanEdgeKind::Peer => EdgeKind::Peer,
                    },
                })
            })
            .collect(),
        roots: report
            .nodes
            .iter()
            .filter(|node| node.direct)
            .map(|node| node.id.clone())
            .collect(),
        unresolved: report
            .unresolved
            .iter()
            .map(|entry| format!("{}:{}", entry.from, entry.name))
            .collect(),
    };
    out.push_str(&crate::graph::render_tree(&graph, "npm/plan"));
    out.push_str(&format!(
        "\n  plan {} (exit {})\n",
        if report.complete() {
            "complete"
        } else {
            "incomplete"
        },
        report.exit_code()
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PlanVersion;

    fn packument(versions: &[(&str, &[(&str, &str)])]) -> PlanPackument {
        PlanPackument {
            dist_tags: BTreeMap::from([("latest".to_string(), "1.0.0".to_string())]),
            versions: versions
                .iter()
                .map(|(version, dependencies)| {
                    (
                        version.to_string(),
                        PlanVersion {
                            dependencies: dependencies
                                .iter()
                                .map(|(name, range)| (name.to_string(), range.to_string()))
                                .collect(),
                            optional_dependencies: BTreeMap::new(),
                            peer_dependencies: BTreeMap::new(),
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn splits_a_range_without_losing_semver_operators() {
        assert_eq!(
            split_spec("express@>=5 <6").unwrap(),
            ("express".to_string(), ">=5 <6".to_string())
        );
        assert_eq!(
            split_spec("@scope/pkg@^1.2").unwrap(),
            ("@scope/pkg".to_string(), "^1.2".to_string())
        );
        assert_eq!(
            split_spec("express").unwrap(),
            ("express".to_string(), "latest".to_string())
        );
    }

    #[test]
    fn chooses_the_highest_matching_stable_version() {
        let document = packument(&[
            ("1.0.0", &[]),
            ("1.2.0", &[]),
            ("2.0.0", &[]),
            ("2.1.0-alpha.1", &[]),
        ]);
        assert_eq!(
            choose_version(&document, "^1").map(String::as_str),
            Some("1.2.0")
        );
        assert_eq!(
            choose_version(&document, "latest").map(String::as_str),
            Some("1.0.0")
        );
        assert_eq!(
            choose_version(&document, "2.0.0").map(String::as_str),
            Some("2.0.0")
        );
        // A prerelease needs an explicit prerelease comparator.
        assert_eq!(
            choose_version(&document, "^2").map(String::as_str),
            Some("2.0.0")
        );
    }

    #[test]
    fn range_alternatives_are_tried_separately() {
        let version = Version::parse("1.5.0").unwrap();
        assert!(range_matches("^1.0.0 || ^2.0.0", &version));
        assert!(!range_matches("^2.0.0 || ^3.0.0", &version));
        assert!(!range_matches(
            "git+https://example.test/repo.git",
            &version
        ));
    }
}
