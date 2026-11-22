//! CycloneDX and SPDX inventories built from a lockfile.
//!
//! An SBOM is an inventory, not a verdict: this module reads the packages the
//! lockfile already resolved, adds the npm dependency graph when one exists,
//! and never fetches, resolves, or invents metadata. Fields the lockfile does
//! not carry (licenses, provenance, download locations) are omitted or marked
//! `NOASSERTION`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use base64::Engine as _;
use serde_json::{Value, json};
use sha2::Digest as _;

use crate::graph::DependencyGraph;
use crate::lockfile::LockContents;
use crate::model::Ecosystem;

/// A checksum parsed from npm's `integrity` field, in the shape both SBOM
/// formats accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    /// `SHA-512` for CycloneDX; SPDX strips the hyphen.
    pub algorithm: &'static str,
    pub hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub purl: Option<String>,
    pub bom_ref: String,
    pub checksums: Vec<Checksum>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub name: String,
    pub version: String,
    pub purl: String,
}

#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub components: Vec<Component>,
    /// Index pairs into `components`.
    pub edges: Vec<(usize, usize)>,
    pub roots: Vec<usize>,
    pub project: Option<Project>,
    /// Lockfile entries that could not be audited. Disclosed, never guessed.
    pub skipped: Vec<(String, String)>,
    pub notes: Vec<String>,
}

/// Percent-encode one PURL path segment. Unreserved characters stay readable.
fn encode(segment: &str) -> String {
    let mut out = String::new();
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A Package URL when the ecosystem has a standard type. JSR has none this
/// project is willing to guess, so it gets an internal `bom-ref` instead.
pub fn purl(ecosystem: Ecosystem, name: &str, version: &str) -> Option<String> {
    let encoded_version = encode(version);
    match ecosystem {
        Ecosystem::Npm => {
            if let Some((scope, package)) = name.split_once('/')
                && scope.starts_with('@')
            {
                return Some(format!(
                    "pkg:npm/{}/{}@{encoded_version}",
                    encode(scope),
                    encode(package)
                ));
            }
            Some(format!("pkg:npm/{}@{encoded_version}", encode(name)))
        }
        Ecosystem::Pypi => {
            let normalized = name.to_ascii_lowercase().replace(['_', '.'], "-");
            Some(format!(
                "pkg:pypi/{}@{encoded_version}",
                encode(&normalized)
            ))
        }
        Ecosystem::CratesIo => Some(format!("pkg:cargo/{}@{encoded_version}", encode(name))),
        Ecosystem::Go => Some(format!(
            "pkg:golang/{}@{encoded_version}",
            name.split('/').map(encode).collect::<Vec<_>>().join("/")
        )),
        Ecosystem::RubyGems => Some(format!("pkg:gem/{}@{encoded_version}", encode(name))),
        Ecosystem::NuGet => Some(format!("pkg:nuget/{}@{encoded_version}", encode(name))),
        Ecosystem::Maven => {
            let (group, artifact) = name.split_once(':')?;
            Some(format!(
                "pkg:maven/{}/{}@{encoded_version}",
                encode(group),
                encode(artifact)
            ))
        }
        Ecosystem::Composer => {
            let (vendor, package) = name.split_once('/')?;
            Some(format!(
                "pkg:composer/{}/{}@{encoded_version}",
                encode(vendor),
                encode(package)
            ))
        }
        Ecosystem::Jsr => None,
    }
}

fn internal_ref(ecosystem: Ecosystem, name: &str, version: &str) -> String {
    format!(
        "dep-vet:{}/{}@{}",
        ecosystem.cli_name(),
        encode(name),
        encode(version)
    )
}

pub fn component(ecosystem: Ecosystem, name: &str, version: &str) -> Component {
    let purl = purl(ecosystem, name, version);
    Component {
        ecosystem,
        name: name.to_string(),
        version: version.to_string(),
        bom_ref: purl
            .clone()
            .unwrap_or_else(|| internal_ref(ecosystem, name, version)),
        purl,
        checksums: Vec::new(),
    }
}

/// Build the inventory. `graph` is populated for npm lockfiles only; when it
/// is absent, components are still listed but no relationships are claimed.
pub fn inventory(
    ecosystem: Ecosystem,
    contents: &LockContents,
    graph: Option<&DependencyGraph>,
    project: Option<(String, String)>,
    checksums: &HashMap<(String, String), Vec<Checksum>>,
) -> Inventory {
    let mut components: BTreeMap<(String, String, String), Component> = BTreeMap::new();
    let mut add = |ecosystem: Ecosystem, name: &str, version: &str| {
        let key = (
            ecosystem.cli_name().to_string(),
            name.to_string(),
            version.to_string(),
        );
        components.entry(key).or_insert_with(|| {
            let mut item = component(ecosystem, name, version);
            if ecosystem == Ecosystem::Npm
                && let Some(found) = checksums.get(&(name.to_string(), version.to_string()))
            {
                item.checksums = found.clone();
            }
            item
        });
    };
    for package in &contents.packages {
        add(ecosystem, &package.name, &package.version);
    }
    for package in &contents.jsr {
        add(Ecosystem::Jsr, &package.name, &package.version);
    }
    let components: Vec<Component> = components.into_values().collect();
    let index: HashMap<(&str, &str), usize> = components
        .iter()
        .enumerate()
        .map(|(position, item)| ((item.name.as_str(), item.version.as_str()), position))
        .collect();

    let mut edges = BTreeSet::new();
    let mut roots = BTreeSet::new();
    if let Some(graph) = graph {
        for edge in &graph.edges {
            let from = graph
                .nodes
                .iter()
                .find(|node| node.path == edge.from)
                .and_then(|node| index.get(&(node.name.as_str(), node.version.as_str())));
            let to = graph
                .nodes
                .iter()
                .find(|node| node.path == edge.to)
                .and_then(|node| index.get(&(node.name.as_str(), node.version.as_str())));
            if let (Some(from), Some(to)) = (from, to)
                && from != to
            {
                edges.insert((*from, *to));
            }
        }
        for root in &graph.roots {
            if let Some(node) = graph.nodes.iter().find(|node| &node.path == root)
                && let Some(position) = index.get(&(node.name.as_str(), node.version.as_str()))
            {
                roots.insert(*position);
            }
        }
    }

    Inventory {
        components,
        edges: edges.into_iter().collect(),
        roots: roots.into_iter().collect(),
        project: project.and_then(|(name, version)| {
            Some(Project {
                purl: purl(Ecosystem::Npm, &name, &version)?,
                name,
                version,
            })
        }),
        skipped: contents.skipped.clone(),
        notes: contents.notes.clone(),
    }
}

/// Parse npm's `sha512-...` integrity strings into hex checksums. Invalid or
/// unsupported entries are skipped; no checksum is invented.
pub fn npm_checksums(body: &str) -> HashMap<(String, String), Vec<Checksum>> {
    let Ok(document) = serde_json::from_str::<Value>(body) else {
        return HashMap::new();
    };
    let Some(packages) = document.get("packages").and_then(Value::as_object) else {
        return HashMap::new();
    };
    let mut out: HashMap<(String, String), Vec<Checksum>> = HashMap::new();
    for (path, entry) in packages {
        let Some(version) = entry.get("version").and_then(Value::as_str) else {
            continue;
        };
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .or_else(|| path.rsplit("node_modules/").next())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let Some(integrity) = entry.get("integrity").and_then(Value::as_str) else {
            continue;
        };
        let checksums = out
            .entry((name.to_string(), version.to_string()))
            .or_default();
        for token in integrity.split_whitespace() {
            let Some((algorithm, encoded)) = token.split_once('-') else {
                continue;
            };
            let algorithm = match algorithm {
                "sha512" => "SHA-512",
                "sha384" => "SHA-384",
                "sha256" => "SHA-256",
                "sha1" => "SHA-1",
                _ => continue,
            };
            let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
                continue;
            };
            let hex = to_hex(&bytes);
            if !checksums
                .iter()
                .any(|checksum| checksum.algorithm == algorithm && checksum.hex == hex)
            {
                checksums.push(Checksum { algorithm, hex });
            }
        }
    }
    out
}

/// The project name and version npm records in the lockfile, when present.
pub fn npm_project(body: &str) -> Option<(String, String)> {
    let document = serde_json::from_str::<Value>(body).ok()?;
    let root = document
        .get("packages")
        .and_then(|packages| packages.get(""));
    let name = root
        .and_then(|root| root.get("name"))
        .and_then(Value::as_str)
        .or_else(|| document.get("name").and_then(Value::as_str))?;
    let version = root
        .and_then(|root| root.get("version"))
        .and_then(Value::as_str)
        .or_else(|| document.get("version").and_then(Value::as_str))?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn tool_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn metadata_properties(inventory: &Inventory) -> Vec<Value> {
    let mut properties = Vec::new();
    for (entry, reason) in &inventory.skipped {
        properties.push(json!({
            "name": "dep-vet:skipped",
            "value": format!("{entry}: {reason}"),
        }));
    }
    for note in &inventory.notes {
        properties.push(json!({
            "name": "dep-vet:note",
            "value": note,
        }));
    }
    properties
}

pub fn cyclonedx(
    inventory: &Inventory,
    lockfile: &str,
    now: i64,
) -> Result<String, serde_json::Error> {
    let components: Vec<Value> = inventory
        .components
        .iter()
        .map(|item| {
            let mut component = json!({
                "type": "library",
                "bom-ref": item.bom_ref,
                "name": item.name,
                "version": item.version,
            });
            if let Some(purl) = &item.purl {
                component["purl"] = json!(purl);
            }
            if !item.checksums.is_empty() {
                component["hashes"] = Value::Array(
                    item.checksums
                        .iter()
                        .map(|checksum| {
                            json!({
                                "alg": checksum.algorithm,
                                "content": checksum.hex,
                            })
                        })
                        .collect(),
                );
            }
            component
        })
        .collect();

    let mut depends: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (from, to) in &inventory.edges {
        depends.entry(*from).or_default().push(*to);
    }
    let mut dependencies: Vec<Value> = Vec::new();
    if inventory.project.is_some() {
        dependencies.push(json!({
            "ref": "dep-vet:project",
            "dependsOn": inventory
                .roots
                .iter()
                .map(|root| inventory.components[*root].bom_ref.clone())
                .collect::<Vec<_>>(),
        }));
    }
    for (position, item) in inventory.components.iter().enumerate() {
        let Some(children) = depends.get(&position) else {
            continue;
        };
        dependencies.push(json!({
            "ref": item.bom_ref,
            "dependsOn": children
                .iter()
                .map(|child| inventory.components[*child].bom_ref.clone())
                .collect::<Vec<_>>(),
        }));
    }

    let mut metadata = json!({
        "timestamp": crate::date::format_timestamp(now),
        "tools": [{
            "vendor": "dep-vet",
            "name": "dep-vet",
            "version": tool_version(),
        }],
    });
    if let Some(project) = &inventory.project {
        metadata["component"] = json!({
            "type": "application",
            "bom-ref": "dep-vet:project",
            "name": project.name,
            "version": project.version,
            "purl": project.purl,
        });
    }
    let mut properties = vec![json!({
        "name": "dep-vet:lockfile",
        "value": lockfile,
    })];
    properties.extend(metadata_properties(inventory));
    metadata["properties"] = Value::Array(properties);

    let document = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
    });
    serde_json::to_string_pretty(&document)
}

pub fn spdx(inventory: &Inventory, lockfile: &str, now: i64) -> Result<String, serde_json::Error> {
    let timestamp = crate::date::format_timestamp(now);
    let creator = format!("Tool: dep-vet-{}", tool_version());

    let mut namespace = sha2::Sha256::new();
    namespace.update(lockfile.as_bytes());
    for item in &inventory.components {
        namespace.update(
            format!(
                "{}:{}@{};",
                item.ecosystem.cli_name(),
                item.name,
                item.version
            )
            .as_bytes(),
        );
    }
    let namespace = to_hex(&namespace.finalize());

    let mut packages = Vec::new();
    let mut ids: Vec<String> = Vec::new();
    if let Some(project) = &inventory.project {
        packages.push(json!({
            "SPDXID": "SPDXRef-Project",
            "name": project.name,
            "versionInfo": project.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": project.purl,
            }],
        }));
    }
    for (position, item) in inventory.components.iter().enumerate() {
        let id = format!("SPDXRef-Package-{}", position + 1);
        ids.push(id.clone());
        let mut package = json!({
            "SPDXID": id,
            "name": item.name,
            "versionInfo": item.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        });
        if let Some(purl) = &item.purl {
            package["externalRefs"] = json!([{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }]);
        }
        if !item.checksums.is_empty() {
            package["checksums"] = Value::Array(
                item.checksums
                    .iter()
                    .map(|checksum| {
                        json!({
                            "algorithm": checksum.algorithm.replace('-', ""),
                            "checksumValue": checksum.hex,
                        })
                    })
                    .collect(),
            );
        }
        packages.push(package);
    }

    let mut relationships = Vec::new();
    if inventory.project.is_some() {
        relationships.push(json!({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Project",
        }));
        for root in &inventory.roots {
            relationships.push(json!({
                "spdxElementId": "SPDXRef-Project",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": ids[*root],
            }));
        }
    }
    for (from, to) in &inventory.edges {
        relationships.push(json!({
            "spdxElementId": ids[*from],
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": ids[*to],
        }));
    }

    let mut annotations = Vec::new();
    for (entry, reason) in &inventory.skipped {
        annotations.push(json!({
            "annotationDate": timestamp,
            "annotationType": "OTHER",
            "annotator": creator,
            "comment": format!("not included: {entry}: {reason}"),
        }));
    }
    for note in &inventory.notes {
        annotations.push(json!({
            "annotationDate": timestamp,
            "annotationType": "OTHER",
            "annotator": creator,
            "comment": format!("note: {note}"),
        }));
    }

    let mut document = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("dep-vet SBOM for {lockfile}"),
        "documentNamespace": format!(
            "https://github.com/nassih-yassine/Dep-Vet/sbom/{namespace}"
        ),
        "creationInfo": {
            "created": timestamp,
            "creators": [creator],
        },
        "packages": packages,
        "relationships": relationships,
    });
    if !annotations.is_empty() {
        document["annotations"] = Value::Array(annotations);
    }
    serde_json::to_string_pretty(&document)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purls_follow_each_ecosystems_rules() {
        assert_eq!(
            purl(Ecosystem::Npm, "@scope/pkg", "1.0.0").as_deref(),
            Some("pkg:npm/%40scope/pkg@1.0.0")
        );
        assert_eq!(
            purl(Ecosystem::Npm, "express", "5.1.0").as_deref(),
            Some("pkg:npm/express@5.1.0")
        );
        assert_eq!(
            purl(Ecosystem::Pypi, "My_Package", "2.0").as_deref(),
            Some("pkg:pypi/my-package@2.0")
        );
        assert_eq!(
            purl(Ecosystem::CratesIo, "serde", "1.0.0").as_deref(),
            Some("pkg:cargo/serde@1.0.0")
        );
        assert_eq!(
            purl(Ecosystem::Go, "github.com/gin-gonic/gin", "v1.9.1").as_deref(),
            Some("pkg:golang/github.com/gin-gonic/gin@v1.9.1")
        );
        assert_eq!(
            purl(Ecosystem::RubyGems, "rack", "3.0.0").as_deref(),
            Some("pkg:gem/rack@3.0.0")
        );
        assert_eq!(
            purl(Ecosystem::NuGet, "Newtonsoft.Json", "13.0.3").as_deref(),
            Some("pkg:nuget/Newtonsoft.Json@13.0.3")
        );
        assert_eq!(
            purl(Ecosystem::Maven, "org.example:lib", "1.2.3").as_deref(),
            Some("pkg:maven/org.example/lib@1.2.3")
        );
        assert_eq!(
            purl(Ecosystem::Composer, "vendor/pkg", "1.0.0").as_deref(),
            Some("pkg:composer/vendor/pkg@1.0.0")
        );
        assert_eq!(purl(Ecosystem::Jsr, "@std/assert", "1.0.0"), None);
        assert_eq!(purl(Ecosystem::Maven, "no-colon", "1.0"), None);
    }

    #[test]
    fn npm_integrity_becomes_hex_checksums() {
        // sha512 of the empty string, base64 encoded.
        let body = r#"{"packages":{
          "node_modules/a":{"version":"1.0.0","integrity":"sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="}
        }}"#;
        let hashes = npm_checksums(body);
        let checksums = hashes.get(&("a".to_string(), "1.0.0".to_string())).unwrap();
        assert_eq!(checksums[0].algorithm, "SHA-512");
        assert!(checksums[0].hex.starts_with("cf83e135"), "{checksums:?}");
        assert!(checksums[0].hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn inventory_dedupes_and_links_the_npm_graph() {
        let contents = LockContents {
            packages: vec![
                crate::lockfile::LockedPackage {
                    name: "a".to_string(),
                    version: "1.0.0".to_string(),
                },
                crate::lockfile::LockedPackage {
                    name: "b".to_string(),
                    version: "2.0.0".to_string(),
                },
                crate::lockfile::LockedPackage {
                    name: "a".to_string(),
                    version: "1.0.0".to_string(),
                },
            ],
            jsr: Vec::new(),
            skipped: Vec::new(),
            notes: Vec::new(),
        };
        let graph = crate::graph::npm_from_package_lock(
            r#"{"lockfileVersion":3,"packages":{
              "":{"dependencies":{"a":"1"}},
              "node_modules/a":{"version":"1.0.0","dependencies":{"b":"2"}},
              "node_modules/b":{"version":"2.0.0"}
            }}"#,
        )
        .unwrap();
        let inventory = inventory(
            Ecosystem::Npm,
            &contents,
            Some(&graph),
            Some(("app".to_string(), "1.0.0".to_string())),
            &HashMap::new(),
        );
        assert_eq!(inventory.components.len(), 2);
        assert_eq!(inventory.edges.len(), 1);
        assert_eq!(inventory.roots, vec![0]);
        assert_eq!(inventory.project.unwrap().purl, "pkg:npm/app@1.0.0");
    }

    #[test]
    fn both_formats_name_only_metadata_the_lockfile_has() {
        let contents = LockContents {
            packages: vec![crate::lockfile::LockedPackage {
                name: "a".to_string(),
                version: "1.0.0".to_string(),
            }],
            jsr: Vec::new(),
            skipped: vec![("git-dep".to_string(), "not in a registry".to_string())],
            notes: Vec::new(),
        };
        let inventory = inventory(
            Ecosystem::Npm,
            &contents,
            None,
            Some(("app".to_string(), "1.0.0".to_string())),
            &HashMap::new(),
        );
        let cyclone = cyclonedx(&inventory, "package-lock.json", 0).unwrap();
        let value: Value = serde_json::from_str(&cyclone).unwrap();
        assert_eq!(value["bomFormat"], "CycloneDX");
        assert_eq!(value["components"][0]["purl"], "pkg:npm/a@1.0.0");
        assert!(
            value["metadata"]["properties"]
                .as_array()
                .unwrap()
                .iter()
                .any(|property| property["name"] == "dep-vet:skipped"),
            "{value}"
        );

        let spdx = spdx(&inventory, "package-lock.json", 0).unwrap();
        let value: Value = serde_json::from_str(&spdx).unwrap();
        assert_eq!(value["spdxVersion"], "SPDX-2.3");
        assert_eq!(value["creationInfo"]["created"], "1970-01-01T00:00:00Z");
        assert!(
            value["annotations"][0]["comment"]
                .as_str()
                .unwrap()
                .contains("git-dep"),
            "{value}"
        );
        assert_eq!(value["packages"][1]["name"], "a");
        assert_eq!(value["relationships"][0]["relationshipType"], "DESCRIBES");
    }
}
