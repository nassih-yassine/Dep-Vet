//! PEP 691 "simple" index JSON, which most private Python indexes speak.
//!
//! Warehouse's JSON API (`/pypi/{name}/json`) is not part of the packaging
//! specs and mirrors often omit it, so a routed name is read from the simple
//! index instead. What that document cannot answer (maintainers, license,
//! repository) stays `None` and is reported as not checked.

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleIndex {
    pub name: Option<String>,
    /// Release order as the index lists it, newest last.
    pub versions: Vec<String>,
    pub files: Vec<SimpleFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleFile {
    pub filename: String,
    pub url: String,
    pub yanked: bool,
    /// Unix seconds, when the index publishes PEP 700 `upload-time`.
    pub upload_time: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct Document {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    files: Vec<FileEntry>,
}

#[derive(Debug, Deserialize)]
struct FileEntry {
    filename: String,
    url: String,
    /// PEP 691 allows `false` or a non-empty reason string.
    #[serde(default)]
    yanked: Yanked,
    #[serde(rename = "upload-time", default)]
    upload_time: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
enum Yanked {
    #[default]
    No,
    Flag(bool),
    Reason(String),
}

impl Yanked {
    fn is_yanked(&self) -> bool {
        match self {
            Self::No => false,
            Self::Flag(value) => *value,
            Self::Reason(reason) => !reason.trim().is_empty(),
        }
    }
}

/// Parses the JSON representation. HTML is not guessed at: a document that
/// does not declare PEP 691 is an error the caller reports, not a scan of
/// anchor text whose version semantics we cannot verify.
pub fn parse(body: &str) -> Result<SimpleIndex, String> {
    let document: Document =
        serde_json::from_str(body).map_err(|error| format!("simple index json: {error}"))?;
    Ok(SimpleIndex {
        name: document.name,
        versions: document.versions,
        files: document
            .files
            .into_iter()
            .map(|file| SimpleFile {
                filename: file.filename,
                url: file.url,
                yanked: file.yanked.is_yanked(),
                upload_time: file
                    .upload_time
                    .as_deref()
                    .and_then(crate::date::parse_timestamp),
            })
            .collect(),
    })
}

impl SimpleIndex {
    /// The newest version the index lists. PEP 691 defines `versions` in
    /// release order, so the last entry is the newest; no version comparison
    /// is attempted here because PEP 440 ordering is a different problem.
    pub fn newest(&self) -> Option<&str> {
        self.versions.last().map(String::as_str)
    }

    /// Files that belong to `version`. The index is per project, so a filename
    /// starts with the normalised project name and the version, and the next
    /// character is a separator.
    pub fn files_for(&self, project: &str, version: &str) -> Vec<&SimpleFile> {
        // Only the distribution name folds: folding the version would make
        // `1.0` match `1.0.0`. Filenames use `_` where the project name has
        // `-`, so both spellings are tried.
        let folded = fold(project);
        let prefixes = [
            format!("{folded}-{version}"),
            format!("{}-{version}", folded.replace('-', "_")),
        ]
        .map(|prefix| prefix.to_ascii_lowercase());
        self.files
            .iter()
            .filter(|file| {
                let filename = file.filename.to_ascii_lowercase();
                prefixes
                    .iter()
                    .any(|prefix| filename.strip_prefix(prefix).is_some_and(archive_suffix))
            })
            .collect()
    }

    /// True when every file for the version is a source archive, so installing
    /// it runs a build backend.
    pub fn sdist_only(files: &[&SimpleFile]) -> bool {
        !files.is_empty() && files.iter().all(|file| !file.filename.ends_with(".whl"))
    }

    /// True when the index marks every file for the version as yanked.
    pub fn all_yanked(files: &[&SimpleFile]) -> bool {
        !files.is_empty() && files.iter().all(|file| file.yanked)
    }

    /// Oldest upload time across every file: when the project was first seen.
    pub fn first_upload(&self) -> Option<i64> {
        self.files.iter().filter_map(|file| file.upload_time).min()
    }
}

/// What may follow the version in a release filename. A bare `.` is not
/// enough: it would let `1.0` match `1.0.0`.
fn archive_suffix(rest: &str) -> bool {
    rest.starts_with('-')
        || [".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".whl", ".tgz"]
            .iter()
            .any(|extension| rest.starts_with(extension))
}

/// PEP 503 folding: lowercase, runs of `-`, `_`, `.` become one `-`. Filenames
/// use `_` where a distribution name has `-`, so both sides are folded.
pub(crate) fn fold(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut separator = false;
    for character in value.to_ascii_lowercase().chars() {
        if matches!(character, '-' | '_' | '.') {
            if !separator {
                out.push('-');
                separator = true;
            }
        } else {
            out.push(character);
            separator = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "meta": {"api-version": "1.1"},
        "name": "demo-pkg",
        "versions": ["0.9.0", "1.0.0", "2.0.0"],
        "files": [
            {"filename": "demo_pkg-0.9.0-py3-none-any.whl", "url": "https://index/0.whl",
             "upload-time": "2024-01-01T00:00:00Z"},
            {"filename": "demo_pkg-1.0.0.tar.gz", "url": "https://index/1.tar.gz",
             "upload-time": "2025-01-01T00:00:00Z"},
            {"filename": "demo_pkg-2.0.0.tar.gz", "url": "https://index/2.tar.gz",
             "yanked": "broken sdist", "upload-time": "2025-06-01T00:00:00Z"}
        ]
    }"#;

    #[test]
    fn parses_versions_files_and_yank_state() {
        let index = parse(SAMPLE).unwrap();
        assert_eq!(index.newest(), Some("2.0.0"));
        assert_eq!(index.versions.len(), 3);
        let files = index.files_for("demo-pkg", "2.0.0");
        assert_eq!(files.len(), 1);
        assert!(files[0].yanked, "a reason string is a yank");
        assert!(SimpleIndex::all_yanked(&files));
        assert!(files[0].upload_time.is_some());
    }

    #[test]
    fn separators_fold_so_underscore_filenames_match() {
        let index = parse(SAMPLE).unwrap();
        assert_eq!(index.files_for("demo_pkg", "1.0.0").len(), 1);
        assert_eq!(index.files_for("Demo.Pkg", "1.0.0").len(), 1);
    }

    #[test]
    fn a_version_prefix_does_not_swallow_a_longer_version() {
        let index = parse(SAMPLE).unwrap();
        assert!(index.files_for("demo-pkg", "1.0").is_empty());
        assert_eq!(index.files_for("demo-pkg", "1.0.0").len(), 1);
    }

    #[test]
    fn sdist_only_is_true_only_when_no_wheel_exists() {
        let index = parse(SAMPLE).unwrap();
        let sdist = index.files_for("demo-pkg", "1.0.0");
        assert!(SimpleIndex::sdist_only(&sdist));
        let wheel = index.files_for("demo-pkg", "0.9.0");
        assert!(!SimpleIndex::sdist_only(&wheel));
    }

    #[test]
    fn the_first_upload_is_the_oldest_file_time() {
        let index = parse(SAMPLE).unwrap();
        assert_eq!(
            index.first_upload(),
            crate::date::parse_timestamp("2024-01-01T00:00:00Z")
        );
    }

    #[test]
    fn an_html_document_is_an_error_not_a_guess() {
        assert!(parse("<html><body><a href='x'>x</a></body></html>").is_err());
    }
}
