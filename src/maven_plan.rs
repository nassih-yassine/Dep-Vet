//! Maven planning from POMs.
//!
//! This resolves one coordinate, it does not install anything: POMs are fetched
//! from Maven Central, the effective model is built (parents, properties,
//! `dependencyManagement`, imported BOMs), and compile/runtime dependencies are
//! walked. Profiles are never evaluated, ranges are never approximated, and a
//! version that cannot be determined is reported as unresolved.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::http::HttpClient;
use crate::model::Ecosystem;
use crate::plan::{
    Conflict, MAX_DEPTH, MAX_NODES, PlanEdgeKind, PlanReport, PlannedEdge, PlannedNode, Unresolved,
};

const DEFAULT_REPO: &str = "https://repo.maven.apache.org/maven2";
const MAX_PARENT_DEPTH: usize = 12;
const MAX_BOM_DEPTH: usize = 6;

#[derive(Debug, Clone, Default)]
struct Dependency {
    group: String,
    artifact: String,
    version: Option<String>,
    kind: String,
    classifier: Option<String>,
    scope: Option<String>,
    optional: bool,
    exclusions: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
struct Model {
    group: Option<String>,
    artifact: String,
    version: Option<String>,
    parent: Option<(String, String, String)>,
    properties: BTreeMap<String, String>,
    managed: Vec<Dependency>,
    dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone)]
struct Xml {
    name: String,
    text: String,
    children: Vec<Xml>,
}

impl Xml {
    fn child(&self, name: &str) -> Option<&Xml> {
        self.children.iter().find(|child| child.name == name)
    }

    fn text(&self, name: &str) -> Option<String> {
        self.child(name).map(|child| child.text.trim().to_string())
    }

    fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Xml> + 'a {
        self.children.iter().filter(move |child| child.name == name)
    }
}

fn parse_xml(body: &str) -> Result<Xml, String> {
    let mut reader = Reader::from_str(body);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut stack: Vec<Xml> = vec![Xml {
        name: String::new(),
        text: String::new(),
        children: Vec::new(),
    }];
    loop {
        match reader.read_event_into(&mut buffer) {
            Err(error) => return Err(format!("invalid POM XML: {error}")),
            Ok(Event::Eof) => break,
            Ok(Event::Start(start)) => stack.push(Xml {
                name: local_name(start.name().as_ref()),
                text: String::new(),
                children: Vec::new(),
            }),
            Ok(Event::Empty(start)) => {
                let node = Xml {
                    name: local_name(start.name().as_ref()),
                    text: String::new(),
                    children: Vec::new(),
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                }
            }
            Ok(Event::End(_)) => {
                if stack.len() > 1 {
                    let node = stack.pop().expect("stack has a child");
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(node);
                    }
                }
            }
            Ok(Event::Text(text)) => {
                if let Some(current) = stack.last_mut() {
                    current.text.push_str(text.as_ref());
                }
            }
            Ok(Event::CData(text)) => {
                if let Some(current) = stack.last_mut() {
                    current.text.push_str(text.as_ref());
                }
            }
            Ok(_) => {}
        }
        buffer.clear();
    }
    stack.pop().ok_or_else(|| "empty POM XML".to_string())
}

fn local_name(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_string()
}

fn parse_dependency(node: &Xml) -> Option<Dependency> {
    let group = node.text("groupId")?;
    let artifact = node.text("artifactId")?;
    let exclusions = node
        .child("exclusions")
        .map(|exclusions| {
            exclusions
                .children_named("exclusion")
                .filter_map(|exclusion| {
                    Some((exclusion.text("groupId")?, exclusion.text("artifactId")?))
                })
                .collect()
        })
        .unwrap_or_default();
    Some(Dependency {
        group,
        artifact,
        version: node.text("version").filter(|value| !value.is_empty()),
        kind: node.text("type").unwrap_or_else(|| "jar".to_string()),
        classifier: node.text("classifier").filter(|value| !value.is_empty()),
        scope: node.text("scope").filter(|value| !value.is_empty()),
        optional: node.text("optional").as_deref() == Some("true"),
        exclusions,
    })
}

fn parse_model(body: &str) -> Result<Model, String> {
    let document = parse_xml(body)?;
    let project = document
        .child("project")
        .ok_or_else(|| "POM has no project element".to_string())?;
    let parent = project.child("parent").and_then(|parent| {
        Some((
            parent.text("groupId")?,
            parent.text("artifactId")?,
            parent.text("version")?,
        ))
    });
    let properties = project
        .child("properties")
        .map(|properties| {
            properties
                .children
                .iter()
                .map(|property| (property.name.clone(), property.text.trim().to_string()))
                .collect()
        })
        .unwrap_or_default();
    let dependencies = project
        .child("dependencies")
        .map(|dependencies| {
            dependencies
                .children_named("dependency")
                .filter_map(parse_dependency)
                .collect()
        })
        .unwrap_or_default();
    let managed = project
        .child("dependencyManagement")
        .and_then(|management| management.child("dependencies"))
        .map(|dependencies| {
            dependencies
                .children_named("dependency")
                .filter_map(parse_dependency)
                .collect()
        })
        .unwrap_or_default();
    Ok(Model {
        group: project.text("groupId"),
        artifact: project.text("artifactId").unwrap_or_default(),
        version: project.text("version"),
        parent,
        properties,
        managed,
        dependencies,
    })
}

/// Replace `${...}` from the effective properties and the project fields. A
/// value that still contains `${` afterward is unresolved, not guessed.
fn interpolate(value: &str, model: &Model) -> String {
    let mut current = value.to_string();
    for _ in 0..10 {
        if !current.contains("${") {
            break;
        }
        let mut next = current.clone();
        let mut replaced = false;
        for (key, value) in model.properties.iter() {
            let placeholder = format!("${{{key}}}");
            if next.contains(&placeholder) {
                next = next.replace(&placeholder, value);
                replaced = true;
            }
        }
        if let Some(group) = &model.group {
            next = next.replace("${project.groupId}", group);
            next = next.replace("${pom.groupId}", group);
        }
        next = next.replace("${project.artifactId}", &model.artifact);
        next = next.replace("${pom.artifactId}", &model.artifact);
        if let Some(version) = &model.version {
            next = next.replace("${project.version}", version);
            next = next.replace("${pom.version}", version);
        }
        if let Some((parent_group, parent_artifact, parent_version)) = &model.parent {
            next = next.replace("${project.parent.groupId}", parent_group);
            next = next.replace("${project.parent.artifactId}", parent_artifact);
            next = next.replace("${project.parent.version}", parent_version);
        }
        if !replaced && next == current {
            break;
        }
        current = next;
    }
    current
}

struct PomClient<'a> {
    http: &'a HttpClient,
    base: String,
    cache: HashMap<(String, String, String), Model>,
}

impl<'a> PomClient<'a> {
    fn new(http: &'a HttpClient) -> Self {
        let gate = std::env::var("DEPVET_ALLOW_INSECURE_BASES").is_ok_and(|value| value == "1");
        let base = match std::env::var("DEPVET_MAVEN_REPO_BASE") {
            Ok(value) if gate && !value.is_empty() => value,
            _ => DEFAULT_REPO.to_string(),
        };
        Self {
            http,
            base,
            cache: HashMap::new(),
        }
    }

    fn url(&self, group: &str, artifact: &str, version: &str) -> Result<String, String> {
        let safe = |value: &str| {
            !value.is_empty()
                && value.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
                })
        };
        if !safe(group) || !safe(artifact) || !safe(version) {
            return Err(format!(
                "unsafe Maven coordinate {group}:{artifact}:{version}"
            ));
        }
        Ok(format!(
            "{}/{}/{}/{}/{}-{}.pom",
            self.base.trim_end_matches('/'),
            group.replace('.', "/"),
            artifact,
            version,
            artifact,
            version
        ))
    }

    fn raw(&mut self, group: &str, artifact: &str, version: &str) -> Result<Model, String> {
        let key = (group.to_string(), artifact.to_string(), version.to_string());
        if let Some(model) = self.cache.get(&key) {
            return Ok(model.clone());
        }
        let url = self.url(group, artifact, version)?;
        let body = self
            .http
            .get(&url)
            .map_err(|error| format!("could not fetch {group}:{artifact}:{version}: {error}"))?;
        let model = parse_model(&body)?;
        self.cache.insert(key, model.clone());
        Ok(model)
    }

    fn effective(
        &mut self,
        group: &str,
        artifact: &str,
        version: &str,
        depth: usize,
        visiting: &mut HashSet<(String, String, String)>,
    ) -> Result<Model, String> {
        if depth > MAX_PARENT_DEPTH {
            return Err(format!("parent chain deeper than {MAX_PARENT_DEPTH}"));
        }
        let key = (group.to_string(), artifact.to_string(), version.to_string());
        if !visiting.insert(key.clone()) {
            return Err(format!("parent cycle at {group}:{artifact}:{version}"));
        }
        let mut model = self.raw(group, artifact, version)?;
        if let Some((parent_group, parent_artifact, parent_version)) = model.parent.clone() {
            let parent_version = interpolate(&parent_version, &model);
            if parent_version.contains("${") {
                return Err(format!(
                    "parent version of {group}:{artifact} uses an unresolved property: {parent_version}"
                ));
            }
            let parent = self.effective(
                &parent_group,
                &parent_artifact,
                &parent_version,
                depth + 1,
                visiting,
            )?;
            let mut properties = parent.properties;
            properties.extend(model.properties);
            let mut managed = parent.managed;
            managed.extend(model.managed);
            model.properties = properties;
            model.managed = managed;
            if model.group.is_none() {
                model.group = parent.group;
            }
            if model.version.is_none() {
                model.version = parent.version;
            }
            model.parent = Some((parent_group, parent_artifact, parent_version));
        }
        self.expand_imports(&mut model, depth, visiting)?;
        visiting.remove(&key);
        Ok(model)
    }

    fn expand_imports(
        &mut self,
        model: &mut Model,
        depth: usize,
        visiting: &mut HashSet<(String, String, String)>,
    ) -> Result<(), String> {
        if depth > MAX_BOM_DEPTH {
            return Ok(());
        }
        let imports: Vec<Dependency> = model
            .managed
            .iter()
            .filter(|dependency| {
                dependency.scope.as_deref() == Some("import") && dependency.kind == "pom"
            })
            .cloned()
            .collect();
        for import in imports {
            let version = import
                .version
                .as_deref()
                .map(|version| interpolate(version, model));
            let Some(version) = version.filter(|version| !version.contains("${")) else {
                continue;
            };
            if let Ok(bom) = self.effective(
                &import.group,
                &import.artifact,
                &version,
                depth + 1,
                visiting,
            ) {
                model.managed.extend(bom.managed);
            }
        }
        Ok(())
    }
}

fn managed_version<'a>(model: &'a Model, dependency: &Dependency) -> Option<&'a str> {
    model
        .managed
        .iter()
        .find(|managed| {
            managed.group == dependency.group
                && managed.artifact == dependency.artifact
                && managed.kind == dependency.kind
                && managed.classifier == dependency.classifier
        })
        .or_else(|| {
            model.managed.iter().find(|managed| {
                managed.group == dependency.group && managed.artifact == dependency.artifact
            })
        })
        .and_then(|managed| managed.version.as_deref())
}

fn excluded(exclusions: &[(String, String)], group: &str, artifact: &str) -> bool {
    exclusions
        .iter()
        .any(|(excluded_group, excluded_artifact)| {
            (excluded_group == "*" || excluded_group == group)
                && (excluded_artifact == "*" || excluded_artifact == artifact)
        })
}

fn followed(scope: Option<&str>) -> bool {
    matches!(scope, None | Some("compile") | Some("runtime"))
}

/// Resolve one coordinate. `input` is `group:artifact@version`; a missing
/// version is refused because Maven ranges and metadata resolution are out of
/// scope.
pub fn plan(http: &HttpClient, input: &str) -> Result<PlanReport, String> {
    let (coordinates, version) = input
        .rsplit_once('@')
        .map(|(coordinates, version)| (coordinates, Some(version)))
        .unwrap_or((input, None));
    let version = version
        .filter(|version| !version.is_empty())
        .ok_or_else(|| "pass an exact Maven version: group:artifact@version".to_string())?;
    let (group, artifact) = coordinates
        .split_once(':')
        .ok_or_else(|| "Maven coordinates are group:artifact".to_string())?;
    let requested = format!("{group}:{artifact}@{version}");
    let mut client = PomClient::new(http);
    let root_model = client
        .effective(group, artifact, version, 0, &mut HashSet::new())
        .map_err(|error| format!("could not resolve {requested}: {error}"))?;
    let root_id = format!("{group}:{artifact}@{version}");

    let mut report = PlanReport {
        ecosystem: Ecosystem::Maven,
        requested: requested.clone(),
        root: root_id.clone(),
        nodes: vec![PlannedNode {
            id: root_id.clone(),
            name: format!("{group}:{artifact}"),
            version: version.to_string(),
            direct: true,
            optional: false,
            peer: false,
        }],
        edges: Vec::new(),
        conflicts: Vec::new(),
        unresolved: Vec::new(),
        truncated: false,
    };

    // Nearest definition wins: BFS visits shallower paths first, so the first
    // version selected for a group:artifact is the one Maven would use at that
    // distance. Later versions are recorded as conflicts, not expanded.
    let mut chosen: HashMap<(String, String), String> = HashMap::new();
    chosen.insert(
        (group.to_string(), artifact.to_string()),
        version.to_string(),
    );
    struct Queued {
        from: String,
        parent: Model,
        depth: usize,
        exclusions: Vec<(String, String)>,
    }
    let mut queue = VecDeque::new();
    queue.push_back(Queued {
        from: root_id.clone(),
        parent: root_model,
        depth: 0,
        exclusions: Vec::new(),
    });

    while let Some(item) = queue.pop_front() {
        for dependency in item.parent.dependencies.iter() {
            if dependency.optional
                || !followed(dependency.scope.as_deref())
                || dependency.kind == "pom"
            {
                continue;
            }
            if excluded(&item.exclusions, &dependency.group, &dependency.artifact) {
                continue;
            }
            let declared = dependency
                .version
                .as_deref()
                .map(|version| interpolate(version, &item.parent))
                .or_else(|| {
                    managed_version(&item.parent, dependency)
                        .map(|version| interpolate(version, &item.parent))
                });
            let name = format!("{}:{}", dependency.group, dependency.artifact);
            let Some(declared) = declared.filter(|value| !value.is_empty()) else {
                report.unresolved.push(Unresolved {
                    from: item.from.clone(),
                    name,
                    range: "no version".to_string(),
                    required: true,
                    reason: "neither the dependency nor dependencyManagement declares a version"
                        .to_string(),
                });
                continue;
            };
            if declared.contains("${") {
                report.unresolved.push(Unresolved {
                    from: item.from.clone(),
                    name,
                    range: declared.clone(),
                    required: true,
                    reason: "version uses a property that is not defined in the effective POM"
                        .to_string(),
                });
                continue;
            }
            if declared.starts_with('[')
                || declared.starts_with('(')
                || declared.contains(',')
                || declared == "LATEST"
                || declared == "RELEASE"
            {
                report.unresolved.push(Unresolved {
                    from: item.from.clone(),
                    name,
                    range: declared.clone(),
                    required: true,
                    reason: "Maven version ranges and metadata resolution are not approximated"
                        .to_string(),
                });
                continue;
            }
            if item.depth + 1 > MAX_DEPTH {
                report.truncated = true;
                continue;
            }
            if let Some(existing) =
                chosen.get(&(dependency.group.clone(), dependency.artifact.clone()))
            {
                if existing != &declared {
                    let entry = report
                        .conflicts
                        .iter_mut()
                        .find(|conflict| conflict.name == name);
                    match entry {
                        Some(conflict) => {
                            if !conflict.versions.contains(&declared) {
                                conflict.versions.push(declared);
                            }
                        }
                        None => report.conflicts.push(Conflict {
                            name,
                            versions: vec![existing.clone(), declared],
                        }),
                    }
                }
                continue;
            }
            if report.nodes.len() >= MAX_NODES {
                report.truncated = true;
                break;
            }
            let child_id = format!("{}:{}@{}", dependency.group, dependency.artifact, declared);
            let model = match client.effective(
                &dependency.group,
                &dependency.artifact,
                &declared,
                item.depth + 1,
                &mut HashSet::new(),
            ) {
                Ok(model) => model,
                Err(error) => {
                    report.unresolved.push(Unresolved {
                        from: item.from.clone(),
                        name: name.clone(),
                        range: declared.clone(),
                        required: true,
                        reason: error,
                    });
                    continue;
                }
            };
            chosen.insert(
                (dependency.group.clone(), dependency.artifact.clone()),
                declared.clone(),
            );
            report.nodes.push(PlannedNode {
                id: child_id.clone(),
                name: name.clone(),
                version: declared.clone(),
                direct: item.from == root_id,
                optional: false,
                peer: false,
            });
            report.edges.push(PlannedEdge {
                from: item.from.clone(),
                to: child_id.clone(),
                range: dependency
                    .version
                    .clone()
                    .unwrap_or_else(|| declared.clone()),
                kind: PlanEdgeKind::Normal,
            });
            let mut exclusions = item.exclusions.clone();
            exclusions.extend(dependency.exclusions.iter().cloned());
            queue.push_back(Queued {
                from: child_id,
                parent: model,
                depth: item.depth + 1,
                exclusions,
            });
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POM: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <properties>
    <lib.version>2.3.4</lib.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.example</groupId>
        <artifactId>lib</artifactId>
        <version>${lib.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib</artifactId>
      <exclusions>
        <exclusion><groupId>com.example</groupId><artifactId>leaf</artifactId></exclusion>
      </exclusions>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>test-lib</artifactId>
      <version>1.0</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>maybe</artifactId>
      <version>1.0</version>
      <optional>true</optional>
    </dependency>
  </dependencies>
</project>
"#;

    #[test]
    fn parses_the_effective_inputs_of_a_pom() {
        let model = parse_model(POM).unwrap();
        assert_eq!(model.group.as_deref(), Some("com.example"));
        assert_eq!(model.artifact, "app");
        assert_eq!(model.version.as_deref(), Some("1.0.0"));
        assert_eq!(
            model.parent.as_ref().map(|parent| parent.2.as_str()),
            Some("1.0.0")
        );
        assert_eq!(model.properties.get("lib.version").unwrap(), "2.3.4");
        assert_eq!(model.managed.len(), 1);
        assert_eq!(model.dependencies.len(), 3);
        assert_eq!(model.dependencies[0].exclusions.len(), 1);
        assert!(model.dependencies[1].scope.as_deref() == Some("test"));
        assert!(model.dependencies[2].optional);
    }

    #[test]
    fn interpolation_uses_properties_and_project_fields() {
        let model = parse_model(POM).unwrap();
        assert_eq!(interpolate("${lib.version}", &model), "2.3.4");
        assert_eq!(interpolate("${project.version}", &model), "1.0.0");
        assert_eq!(
            interpolate("${project.groupId}:${project.artifactId}", &model),
            "com.example:app"
        );
        assert_eq!(interpolate("${unknown}", &model), "${unknown}");
    }

    #[test]
    fn exclusions_accept_the_maven_wildcard() {
        let exclusions = vec![("*".to_string(), "leaf".to_string())];
        assert!(excluded(&exclusions, "com.example", "leaf"));
        assert!(!excluded(&exclusions, "com.example", "other"));
    }
}
