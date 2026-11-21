//! Extraction from tar.gz, tar, zip, and gem archives. Everything stays in
//! memory and every reader is bounded by `Limits`.

use std::io::{Cursor, Read};

use flate2::read::GzDecoder;

use super::{Limits, safe_path};

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("archive is larger than the {} byte limit", .0.max_compressed)]
    TooLarge(Limits),
    #[error("archive could not be read: {0}")]
    Read(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    TarGz,
    Zip,
    Gem,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedFile {
    pub path: String,
    pub text: String,
}

#[derive(Debug, Default)]
pub struct Extracted {
    pub files: Vec<ExtractedFile>,
    pub entries: usize,
    pub skipped_binary: usize,
    pub skipped_unsafe: usize,
    /// Paths of entries that looked binary; kept for diffs, capped.
    pub binaries: Vec<String>,
    /// A NuGet `.signature.p7s` entry exists. Presence only, never verified.
    pub signature_file: bool,
    /// Paths skipped for exceeding the per-file or total size cap, capped at
    /// 50 so a hostile archive cannot make the report huge.
    pub oversize_files: Vec<String>,
    /// More entries existed than the entry cap allowed.
    pub entries_over_cap: bool,
    /// The total uncompressed budget ran out before the archive ended.
    pub total_over_cap: bool,
    /// Any of the above happened. Kept for callers that only ask "truncated?".
    pub truncated: bool,
}

/// Remember a skipped path without letting a hostile archive grow the report.
fn record_skipped(out: &mut Extracted, path: String) {
    out.truncated = true;
    if out.oversize_files.len() < 50 {
        out.oversize_files.push(path);
    }
}

pub fn extract(kind: ArchiveKind, bytes: &[u8], limits: Limits) -> Result<Extracted, ArchiveError> {
    if bytes.len() as u64 > limits.max_compressed {
        return Err(ArchiveError::TooLarge(limits));
    }
    let mut out = Extracted::default();
    match kind {
        ArchiveKind::TarGz => {
            let decoder = GzDecoder::new(bytes);
            read_tar(decoder, limits, &mut out)?;
        }
        ArchiveKind::Zip => read_zip(bytes, limits, &mut out)?,
        ArchiveKind::Gem => {
            // A .gem is a tar containing metadata.gz and data.tar.gz.
            let mut outer = tar::Archive::new(Cursor::new(bytes));
            for entry in outer
                .entries()
                .map_err(|error| ArchiveError::Read(error.to_string()))?
            {
                let mut entry = entry.map_err(|error| ArchiveError::Read(error.to_string()))?;
                let path = entry
                    .path()
                    .map_err(|error| ArchiveError::Read(error.to_string()))?
                    .to_string_lossy()
                    .to_string();
                if path == "data.tar.gz" {
                    let mut inner = Vec::new();
                    entry
                        .read_to_end(&mut inner)
                        .map_err(|error| ArchiveError::Read(error.to_string()))?;
                    read_tar(GzDecoder::new(Cursor::new(inner)), limits, &mut out)?;
                }
                out.entries += 1;
            }
        }
    }
    Ok(out)
}

fn read_tar<R: Read>(reader: R, limits: Limits, out: &mut Extracted) -> Result<(), ArchiveError> {
    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|error| ArchiveError::Read(error.to_string()))?;

    for entry in entries {
        if out.entries >= limits.max_entries {
            out.truncated = true;
            out.entries_over_cap = true;
            break;
        }
        let mut entry = entry.map_err(|error| ArchiveError::Read(error.to_string()))?;
        out.entries += 1;

        if !entry.header().entry_type().is_file() {
            out.skipped_unsafe += 1;
            continue;
        }
        let path = match entry.path() {
            Ok(path) => path.to_string_lossy().to_string(),
            Err(_) => {
                out.skipped_unsafe += 1;
                continue;
            }
        };
        let Some(path) = safe_path(&path, limits.max_path) else {
            out.skipped_unsafe += 1;
            continue;
        };
        let declared = entry.size();
        if declared > limits.max_file {
            record_skipped(out, path);
            continue;
        }
        read_text(&mut entry, path, limits, out)?;
    }
    Ok(())
}

fn read_zip(bytes: &[u8], limits: Limits, out: &mut Extracted) -> Result<(), ArchiveError> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| ArchiveError::Read(error.to_string()))?;

    for index in 0..zip.len() {
        if out.entries >= limits.max_entries {
            out.truncated = true;
            out.entries_over_cap = true;
            break;
        }
        let mut file = zip
            .by_index(index)
            .map_err(|error| ArchiveError::Read(error.to_string()))?;
        out.entries += 1;
        if file.is_dir() {
            out.skipped_unsafe += 1;
            continue;
        }
        let name = match file.name() {
            Ok(name) => name.to_string(),
            Err(_) => {
                out.skipped_unsafe += 1;
                continue;
            }
        };
        let Some(path) = safe_path(&name, limits.max_path) else {
            out.skipped_unsafe += 1;
            continue;
        };
        if file.size() > limits.max_file {
            record_skipped(out, path);
            continue;
        }
        read_text(&mut file, path, limits, out)?;
    }
    Ok(())
}

fn read_text(
    reader: &mut impl Read,
    path: String,
    limits: Limits,
    out: &mut Extracted,
) -> Result<(), ArchiveError> {
    // Read one byte past the file cap so an over-large file is detected
    // without trusting the header.
    let remaining = limits.max_total.saturating_sub(
        out.files
            .iter()
            .map(|file| file.text.len() as u64)
            .sum::<u64>(),
    );
    if remaining == 0 {
        out.total_over_cap = true;
        record_skipped(out, path);
        return Ok(());
    }
    let budget = limits.max_file.saturating_add(1).min(remaining);
    let mut buffer = Vec::new();
    reader
        .take(budget)
        .read_to_end(&mut buffer)
        .map_err(|error| ArchiveError::Read(error.to_string()))?;
    if buffer.len() as u64 > limits.max_file {
        record_skipped(out, path);
        return Ok(());
    }
    if path
        .rsplit('/')
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case(".signature.p7s"))
    {
        out.signature_file = true;
    }
    if buffer.contains(&0) {
        out.skipped_binary += 1;
        if out.binaries.len() < 200 {
            out.binaries.push(path);
        }
        return Ok(());
    }
    match String::from_utf8(buffer) {
        Ok(text) => out.files.push(ExtractedFile { path, text }),
        Err(_) => {
            out.skipped_binary += 1;
            if out.binaries.len() < 200 {
                out.binaries.push(path);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tar_gz(files: &[(&str, &[u8])], symlink: Option<&str>) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (path, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            if path.contains("..") {
                // tar's safe API refuses traversal, which is the point; forge
                // the raw header so extraction is tested against a hostile file.
                let name = path.as_bytes();
                header.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name);
            } else {
                header.set_path(path).unwrap();
            }
            header.set_cksum();
            builder.append(&header, *bytes).unwrap();
        }
        if let Some(target) = symlink {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_path("link").unwrap();
            header.set_link_name(target).unwrap();
            header.set_cksum();
            builder.append(&header, &[][..]).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn a_nuget_signature_entry_is_noted_without_being_verified() {
        let unsigned = zip_bytes(&[("lib/net8.0/a.dll", b"text")]);
        assert!(
            !extract(ArchiveKind::Zip, &unsigned, Limits::default())
                .unwrap()
                .signature_file
        );

        let signed = zip_bytes(&[
            ("lib/net8.0/a.dll", b"text"),
            (".signature.p7s", b"\x00\x01signature"),
        ]);
        assert!(
            extract(ArchiveKind::Zip, &signed, Limits::default())
                .unwrap()
                .signature_file
        );
    }

    fn zip_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (path, bytes) in files {
            writer.start_file(*path, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn reads_tar_gz_files() {
        let bytes = tar_gz(&[("src/index.js", b"eval('1')\n")], None);
        let out = extract(ArchiveKind::TarGz, &bytes, Limits::default()).unwrap();
        assert_eq!(out.files.len(), 1);
        assert_eq!(out.files[0].path, "src/index.js");
        assert!(out.files[0].text.contains("eval"));
    }

    #[test]
    fn reads_zip_files() {
        let bytes = zip_bytes(&[("pkg/index.js", b"const a = 1;\n")]);
        let out = extract(ArchiveKind::Zip, &bytes, Limits::default()).unwrap();
        assert_eq!(out.files.len(), 1);
        assert_eq!(out.files[0].path, "pkg/index.js");
    }

    #[test]
    fn traversal_and_symlinks_are_skipped() {
        let bytes = tar_gz(&[("../evil.sh", b"#!/bin/sh\n")], Some("/etc/passwd"));
        let out = extract(ArchiveKind::TarGz, &bytes, Limits::default()).unwrap();
        assert!(out.files.is_empty());
        assert!(out.skipped_unsafe >= 2, "{out:?}");
    }

    #[test]
    fn binary_files_are_counted_not_decoded() {
        let bytes = tar_gz(&[("bin/blob", &[0, 1, 2, 3])], None);
        let out = extract(ArchiveKind::TarGz, &bytes, Limits::default()).unwrap();
        assert!(out.files.is_empty());
        assert_eq!(out.skipped_binary, 1);
    }

    #[test]
    fn entry_and_size_caps_stop_the_reader() {
        let bytes = tar_gz(&[("a.js", b"aa"), ("b.js", b"bb"), ("c.js", b"cc")], None);
        let limits = Limits {
            max_entries: 2,
            ..Limits::default()
        };
        let out = extract(ArchiveKind::TarGz, &bytes, limits).unwrap();
        assert!(out.truncated);
        assert_eq!(out.entries, 2);

        let limits = Limits {
            max_file: 1,
            ..Limits::default()
        };
        let out = extract(ArchiveKind::TarGz, &bytes, limits).unwrap();
        assert!(out.truncated);
        assert!(out.files.is_empty());
    }

    #[test]
    fn an_oversize_scannable_file_records_why_it_was_skipped() {
        let big = vec![b'a'; 6 * 1024 * 1024];
        let bytes = tar_gz(&[("big.js", &big)], None);
        let out = extract(ArchiveKind::TarGz, &bytes, Limits::default()).unwrap();
        assert!(out.truncated);
        assert!(out.files.is_empty());
        assert!(
            out.oversize_files.iter().any(|path| path == "big.js"),
            "{:?}",
            out.oversize_files
        );
    }

    #[test]
    fn entries_past_the_cap_say_the_archive_was_not_read_to_the_end() {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for index in 0..10_001 {
            let body = b"x";
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            let name = if index == 10_000 {
                "payload.js".to_string()
            } else {
                format!("f{index}.txt")
            };
            header.set_path(&name).unwrap();
            header.set_cksum();
            builder.append(&header, body.as_slice()).unwrap();
        }
        let bytes = builder.into_inner().unwrap().finish().unwrap();
        let out = extract(ArchiveKind::TarGz, &bytes, Limits::default()).unwrap();
        assert!(out.entries_over_cap);
        assert!(out.truncated);
        assert!(
            out.files.iter().all(|file| file.path != "payload.js"),
            "the entry past the cap must not be scanned"
        );

        // The finding is what the user sees: a skipped scannable payload.
        let report = crate::inspect::build_report(
            crate::model::Ecosystem::Npm,
            &crate::model::PackageSpec {
                name: "pkg".to_string(),
                version: Some("1.0.0".to_string()),
            },
            crate::inspect::Prepared {
                url: "https://example.test/a.tgz".to_string(),
                kind: ArchiveKind::TarGz,
                integrity: crate::inspect::Integrity::Verified,
                extracted: out,
                bytes: 1,
                provenance: None,
            },
            &[],
        );
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule == "archive-partially-scanned")
            .expect("missing partial-scan finding");
        assert_eq!(finding.severity, crate::model::Severity::Warn);
    }

    #[test]
    fn oversized_archive_is_refused_before_reading() {
        let limits = Limits {
            max_compressed: 2,
            ..Limits::default()
        };
        assert!(matches!(
            extract(ArchiveKind::TarGz, b"abc", limits),
            Err(ArchiveError::TooLarge(_))
        ));
    }

    #[test]
    fn gem_data_archive_is_read() {
        let inner = tar_gz(&[("lib/rack.rb", b"eval('x')\n")], None);
        let mut builder = tar::Builder::new(Vec::new());
        for (path, bytes) in [("metadata.gz", &b"meta"[..]), ("data.tar.gz", &inner[..])] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_path(path).unwrap();
            header.set_cksum();
            builder.append(&header, bytes).unwrap();
        }
        let bytes = builder.into_inner().unwrap();
        let out = extract(ArchiveKind::Gem, &bytes, Limits::default()).unwrap();
        assert_eq!(out.files.len(), 1);
        assert_eq!(out.files[0].path, "lib/rack.rb");
    }
}
