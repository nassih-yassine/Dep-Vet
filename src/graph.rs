//! Dependency graphs parsed from lockfiles. The graph is evidence, not a
//! resolver: every node and edge comes from a lockfile the package manager
//! already resolved, and nothing here fetches or executes anything.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DependencyNode {
    pub name: String,
    pub version: String,
    /// npm install path, e.g. `node_modules/a/node_modules/b`.
    pub path: String,
    pub direct: bool,
    pub dev: bool,
    pub optional: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EdgeKind {
    Normal,
    Dev,
    Optional,
    Peer,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DependencyEdge {
    pub from: String,
    pub to: String,
    pub name: String,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct DependencyGraph {
    pub nodes: Vec<DependencyNode>,
    pub edges: Vec<DependencyEdge>,
    /// Paths of the root package's direct dependencies.
    pub roots: Vec<String>,
    /// `from:name` pairs named in the lockfile but absent from it.
    pub unresolved: Vec<String>,
}

/// Build the graph for an npm `package-lock.json` v2/v3.
pub fn npm_from_package_lock(body: &str) -> Result<DependencyGraph, String> {
    let lockfile: serde_json::Value = serde_json::from_str(body)
        .map_err(|error| format!("invalid package-lock.json: {error}"))?;
    let version = lockfile["lockfileVersion"].as_u64().unwrap_or(0);
    if version < 2 {
        return Err(format!(
            "package-lock.json v{version} has no `packages` map; regenerate with npm 7 or newer"
        ));
    }
    let packages = lockfile["packages"]
        .as_object()
        .ok_or_else(|| "package-lock.json has no `packages` map".to_string())?;

    let mut nodes: BTreeMap<String, DependencyNode> = BTreeMap::new();
    for (path, entry) in packages {
        if path.is_empty() || entry["link"].as_bool() == Some(true) {
            continue;
        }
        let Some(version) = entry["version"].as_str() else {
            continue;
        };
        let name = entry["name"]
            .as_str()
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .or_else(|| path.rsplit("node_modules/").next().map(str::to_string))
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        nodes.insert(
            path.clone(),
            DependencyNode {
                name,
                version: version.to_string(),
                path: path.clone(),
                direct: false,
                dev: entry["dev"].as_bool().unwrap_or(false),
                optional: entry["optional"].as_bool().unwrap_or(false),
            },
        );
    }

    let mut edges = Vec::new();
    let mut unresolved = Vec::new();
    let mut roots = Vec::new();
    for (from, entry) in packages {
        if !from.is_empty() && !nodes.contains_key(from) {
            continue;
        }
        for (field, kind) in [
            ("dependencies", EdgeKind::Normal),
            ("devDependencies", EdgeKind::Dev),
            ("optionalDependencies", EdgeKind::Optional),
            ("peerDependencies", EdgeKind::Peer),
        ] {
            let Some(dependencies) = entry[field].as_object() else {
                continue;
            };
            for name in dependencies.keys() {
                match resolve(packages, from, name) {
                    Some(to) if nodes.contains_key(&to) => {
                        if from.is_empty() {
                            roots.push(to.clone());
                        }
                        edges.push(DependencyEdge {
                            from: from.clone(),
                            to,
                            name: name.clone(),
                            kind,
                        });
                    }
                    _ => unresolved.push(format!(
                        "{}:{name}",
                        if from.is_empty() { "(root)" } else { from }
                    )),
                }
            }
        }
    }
    roots.sort();
    roots.dedup();
    for path in &roots {
        if let Some(node) = nodes.get_mut(path) {
            node.direct = true;
        }
    }
    edges.sort_by(|left, right| {
        left.from
            .cmp(&right.from)
            .then(left.name.cmp(&right.name))
            .then(left.to.cmp(&right.to))
    });
    unresolved.sort();
    unresolved.dedup();

    Ok(DependencyGraph {
        nodes: nodes.into_values().collect(),
        edges,
        roots,
        unresolved,
    })
}

/// Node resolution: a dependency starts next to its dependent, then walks up
/// through `node_modules` to the root.
fn resolve(
    packages: &serde_json::Map<String, serde_json::Value>,
    from: &str,
    name: &str,
) -> Option<String> {
    let mut base = from;
    loop {
        let candidate = if base.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{base}/node_modules/{name}")
        };
        if packages.contains_key(&candidate) {
            return Some(candidate);
        }
        if base.is_empty() {
            return None;
        }
        base = match base.rfind("/node_modules/") {
            Some(index) => &base[..index],
            None => "",
        };
    }
}

/// Render a readable tree. Cycles (possible through peer edges) are cut with a
/// visited set, and both depth and line count are bounded.
pub fn render_tree(graph: &DependencyGraph, lockfile: &str) -> String {
    const MAX_LINES: usize = 2_000;
    const MAX_DEPTH: usize = 20;

    let by_path: HashMap<&str, &DependencyNode> = graph
        .nodes
        .iter()
        .map(|node| (node.path.as_str(), node))
        .collect();
    let mut children: HashMap<&str, Vec<&DependencyEdge>> = HashMap::new();
    for edge in &graph.edges {
        children.entry(edge.from.as_str()).or_default().push(edge);
    }
    for list in children.values_mut() {
        list.sort_by(|left, right| left.name.cmp(&right.name));
    }

    let mut out = format!(
        "{lockfile}: {} packages, {} direct\n",
        graph.nodes.len(),
        graph.roots.len()
    );
    let mut lines = 0;
    let mut stack: Vec<String> = Vec::new();
    for root in &graph.roots {
        walk(
            root, "", 0, &by_path, &children, &mut stack, &mut out, &mut lines, MAX_LINES,
            MAX_DEPTH,
        );
    }
    if lines >= MAX_LINES {
        out.push_str("  … tree truncated\n");
    }
    if !graph.unresolved.is_empty() {
        out.push_str("not in the lockfile: ");
        let shown = graph
            .unresolved
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&shown);
        if graph.unresolved.len() > 10 {
            out.push_str(&format!(" (+{} more)", graph.unresolved.len() - 10));
        }
        out.push('\n');
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn walk(
    path: &str,
    indent: &str,
    depth: usize,
    nodes: &HashMap<&str, &DependencyNode>,
    children: &HashMap<&str, Vec<&DependencyEdge>>,
    stack: &mut Vec<String>,
    out: &mut String,
    lines: &mut usize,
    max_lines: usize,
    max_depth: usize,
) {
    if *lines >= max_lines || depth > max_depth {
        return;
    }
    let Some(node) = nodes.get(path) else {
        return;
    };
    if stack.iter().any(|seen| seen == path) {
        out.push_str(&format!("{indent}{}@{} (cycle)\n", node.name, node.version));
        *lines += 1;
        return;
    }
    let mut marker = String::new();
    if node.dev {
        marker.push_str(" [dev]");
    }
    if node.optional {
        marker.push_str(" [optional]");
    }
    out.push_str(&format!("{indent}{}@{}{marker}\n", node.name, node.version));
    *lines += 1;
    stack.push(path.to_string());
    let next_indent = format!("{indent}  ");
    if let Some(edges) = children.get(path) {
        for edge in edges {
            walk(
                &edge.to,
                &next_indent,
                depth + 1,
                nodes,
                children,
                stack,
                out,
                lines,
                max_lines,
                max_depth,
            );
        }
    }
    stack.pop();
}

#[cfg(test)]
mod tests {
    use super::*;

    const NESTED: &str = r#"{
      "lockfileVersion": 3,
      "packages": {
        "": {"dependencies": {"a": "^1"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1"}},
        "node_modules/a/node_modules/b": {"version": "2.0.0"},
        "node_modules/b": {"version": "1.0.0"}
      }
    }"#;

    #[test]
    fn nested_versions_resolve_to_the_nearest_node_modules() {
        let graph = npm_from_package_lock(NESTED).unwrap();
        assert!(graph.edges.iter().any(|edge| {
            edge.from == "node_modules/a"
                && edge.to == "node_modules/a/node_modules/b"
                && edge.kind == EdgeKind::Normal
        }));
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|edge| edge.from == "node_modules/a")
                .count(),
            1,
            "a resolves b to its nested copy, not the root copy: {graph:?}"
        );
        assert!(
            graph
                .nodes
                .iter()
                .any(|node| node.path == "node_modules/b" && node.version == "1.0.0"),
            "the root b is still a node: {graph:?}"
        );
    }

    #[test]
    fn v1_lockfiles_are_refused_with_an_explanation() {
        let error = npm_from_package_lock(r#"{"lockfileVersion":1}"#).unwrap_err();
        assert!(error.contains("npm 7"), "{error}");
    }

    #[test]
    fn the_tree_renderer_survives_a_cycle() {
        let graph = DependencyGraph {
            nodes: vec![
                DependencyNode {
                    name: "a".into(),
                    version: "1".into(),
                    path: "node_modules/a".into(),
                    direct: true,
                    dev: false,
                    optional: false,
                },
                DependencyNode {
                    name: "b".into(),
                    version: "1".into(),
                    path: "node_modules/b".into(),
                    direct: false,
                    dev: false,
                    optional: false,
                },
            ],
            edges: vec![
                DependencyEdge {
                    from: "node_modules/a".into(),
                    to: "node_modules/b".into(),
                    name: "b".into(),
                    kind: EdgeKind::Peer,
                },
                DependencyEdge {
                    from: "node_modules/b".into(),
                    to: "node_modules/a".into(),
                    name: "a".into(),
                    kind: EdgeKind::Peer,
                },
            ],
            roots: vec!["node_modules/a".into()],
            unresolved: vec![],
        };
        let rendered = render_tree(&graph, "package-lock.json");
        assert!(rendered.contains("a@1"));
        assert!(rendered.contains("b@1"));
        assert!(rendered.contains("cycle"));
    }
}
