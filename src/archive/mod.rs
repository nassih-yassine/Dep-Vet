//! Safe, bounded extraction for release archives.
//!
//! Extracted files stay in memory: nothing is written to disk, so a hostile
//! path cannot escape anywhere. Path checks still run so symlinks, absolute
//! paths, and `..` are reported as skipped rather than silently ignored.

pub mod extract;

pub use extract::{ArchiveError, ArchiveKind, Extracted, ExtractedFile, extract};

/// Hard caps. Every archive reader must stop when one is reached.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_compressed: u64,
    pub max_total: u64,
    pub max_entries: usize,
    pub max_file: u64,
    pub max_path: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_compressed: 25 * 1024 * 1024,
            max_total: 100 * 1024 * 1024,
            max_entries: 10_000,
            max_file: 5 * 1024 * 1024,
            max_path: 1_024,
        }
    }
}

/// A relative, normalised path, or `None` when the entry must be skipped.
pub fn safe_path(entry: &str, max_path: usize) -> Option<String> {
    let normalised = entry.replace('\\', "/");
    let trimmed = normalised.strip_prefix("./").unwrap_or(&normalised);
    if trimmed.is_empty() || trimmed.len() > max_path || trimmed.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in trimmed.split('/') {
        match part {
            "" | "." => continue,
            ".." => return None,
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_and_absolute_paths() {
        assert_eq!(safe_path("../x", 1024), None);
        assert_eq!(safe_path("a/../../b", 1024), None);
        assert_eq!(safe_path("/etc/passwd", 1024), None);
        assert_eq!(safe_path("a//b", 1024), Some("a/b".to_string()));
        assert_eq!(safe_path("./ok.js", 1024), Some("ok.js".to_string()));
        assert_eq!(safe_path("a\\b.js", 1024), Some("a/b.js".to_string()));
        assert_eq!(safe_path(".", 1024), None);
        assert_eq!(safe_path(&"x".repeat(2000), 1024), None);
    }

    #[test]
    fn default_limits_match_the_documented_values() {
        let limits = Limits::default();
        assert_eq!(limits.max_compressed, 25 * 1024 * 1024);
        assert_eq!(limits.max_total, 100 * 1024 * 1024);
        assert_eq!(limits.max_entries, 10_000);
        assert_eq!(limits.max_file, 5 * 1024 * 1024);
    }
}
