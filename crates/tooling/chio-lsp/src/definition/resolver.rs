//! URN resolution helpers for the go-to-definition provider.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use tower_lsp::lsp_types::{Location, Position, Range, Url};

use crate::position::{byte_to_utf16_column, utf16_to_byte_offset};

/// Upper bound on the bytes read from a followed manifest. A manifest
/// that exceeds it is treated as unreadable.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Extract the URN spanning `position` in `text`. Returns `None` if
/// the cursor is not on a `urn:chio:*` token.
///
/// `position.character` is a UTF-16 code-unit count per the LSP
/// spec; the helper translates it to a UTF-8 byte index inside the
/// target line so multibyte characters (for example accented Latin or
/// CJK) cannot drive `&line[start..end]` into a non-boundary slice.
#[must_use]
pub fn extract_urn_at_position(text: &str, position: Position) -> Option<String> {
    let line = text.split('\n').nth(position.line as usize)?;
    let column = utf16_to_byte_offset(line, position.character);

    fn is_urn_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '.' | '_')
    }

    // Walk backward over scalar values so the boundary stays valid for
    // multibyte characters. URN bytes are all ASCII, so the byte-level
    // peek inside the loop only fires on ASCII bytes; that keeps the
    // step size correct.
    let bytes = line.as_bytes();
    let mut start = column;
    while start > 0 {
        let prev_byte = bytes[start - 1];
        if !prev_byte.is_ascii() {
            break;
        }
        if !is_urn_char(prev_byte as char) {
            break;
        }
        start -= 1;
    }
    let mut end = column;
    while end < line.len() {
        let next_byte = bytes[end];
        if !next_byte.is_ascii() {
            break;
        }
        if !is_urn_char(next_byte as char) {
            break;
        }
        end += 1;
    }
    if start == end {
        return None;
    }
    let token = &line[start..end];
    if token.starts_with("urn:chio:") {
        Some(token.to_string())
    } else {
        None
    }
}

/// Resolve a URN to its definition. Tries the on-disk manifest first
/// (if reachable), then the first occurrence of the URN in `text`.
#[must_use]
pub fn resolve(uri: &Url, text: &str, urn: &str) -> Option<Location> {
    if let Some(manifest_path) = manifest_path_in(text) {
        if let Some(loc) = locate_in_file(uri, &manifest_path, urn) {
            return Some(loc);
        }
    }
    locate_in_text(uri, text, urn).map(|range| Location {
        uri: uri.clone(),
        range,
    })
}

/// Read the top-level `manifest:` key from a chio.yaml-shaped
/// document. Returns `None` if absent or if the value is not a scalar
/// string.
fn manifest_path_in(text: &str) -> Option<PathBuf> {
    for line in text.split('\n') {
        if !line.starts_with([' ', '-', '\t']) {
            if let Some((key, value)) = line.split_once(':') {
                if key.trim() == "manifest" {
                    let v = value.trim().trim_matches('"').trim_matches('\'');
                    if v.is_empty() {
                        return None;
                    }
                    return Some(PathBuf::from(v));
                }
            }
        }
    }
    None
}

/// Locate the first occurrence of `urn` in the file at `manifest_path`
/// resolved relative to the directory of the document URI.
///
/// The on-disk read is fail-closed scoped:
///
/// - Absolute paths are rejected. A hostile `chio.yaml` opened in the
///   editor cannot point the LSP server at `/etc/passwd`.
/// - Paths that escape the document directory (`..` traversal, symlink
///   indirection) are rejected after canonicalisation.
/// - Only filenames matching the manifest naming pattern
///   (`*.chio-manifest.yaml` / `*.chio-manifest.yml` / `chio-manifest.yaml`)
///   are followed. The LSP server does not behave like a generic file
///   reader.
/// - The target must be a regular file and is read through a
///   [`MAX_MANIFEST_BYTES`] bound; FIFOs, directories and oversize
///   files yield `None`.
fn locate_in_file(doc_uri: &Url, manifest_path: &Path, urn: &str) -> Option<Location> {
    let doc_dir = doc_uri.to_file_path().ok()?.parent()?.to_path_buf();
    let resolved = scoped_manifest_path(&doc_dir, manifest_path)?;
    let body = read_bounded_manifest(&resolved)?;
    let range = locate_in_text(doc_uri, &body, urn)?;
    let target = Url::from_file_path(&resolved).ok()?;
    Some(Location { uri: target, range })
}

/// Read a regular file of at most [`MAX_MANIFEST_BYTES`] as UTF-8.
/// The path is checked before it is opened so a FIFO cannot block the
/// open, and the opened handle is checked again.
fn read_bounded_manifest(path: &Path) -> Option<String> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Resolve `manifest_path` against `doc_dir`, rejecting absolute paths
/// and escapes outside the document directory. Returns `None` for any
/// rejected path so the caller fails closed.
fn scoped_manifest_path(doc_dir: &Path, manifest_path: &Path) -> Option<PathBuf> {
    if manifest_path.as_os_str().is_empty() || manifest_path.is_absolute() {
        return None;
    }
    if !manifest_filename_is_allowed(manifest_path) {
        return None;
    }
    if path_contains_parent_component(manifest_path) {
        return None;
    }
    let joined = doc_dir.join(manifest_path);
    let canonical_doc_dir = std::fs::canonicalize(doc_dir).ok()?;
    let canonical_target = std::fs::canonicalize(&joined).ok()?;
    if !canonical_target.starts_with(&canonical_doc_dir) {
        return None;
    }
    Some(canonical_target)
}

fn path_contains_parent_component(path: &Path) -> bool {
    use std::path::Component;
    path.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::Prefix(_) | Component::RootDir
        )
    })
}

fn manifest_filename_is_allowed(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name.contains('\0') {
        return false;
    }
    name.ends_with(".chio-manifest.yaml")
        || name.ends_with(".chio-manifest.yml")
        || name == "chio-manifest.yaml"
        || name == "chio-manifest.yml"
}

fn locate_in_text(_uri: &Url, text: &str, urn: &str) -> Option<Range> {
    for (idx, line) in text.split('\n').enumerate() {
        if let Some(byte_col) = line.find(urn) {
            // LSP `Range` columns are UTF-16 code units, not bytes.
            // Translate so editors highlight the correct span when the
            // line contains non-ASCII text before the URN.
            let start_col = byte_to_utf16_column(line, byte_col);
            let end_col = byte_to_utf16_column(line, byte_col + urn.len());
            let start = Position::new(idx as u32, start_col);
            let end = Position::new(idx as u32, end_col);
            return Some(Range::new(start, end));
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn extract_urn_returns_full_token() {
        let text = "scopes:\n  - urn:chio:scope:tool.read\n";
        let pos = Position::new(1, 12);
        let urn = extract_urn_at_position(text, pos).expect("urn");
        assert_eq!(urn, "urn:chio:scope:tool.read");
    }

    #[test]
    fn locate_in_text_returns_first_match() {
        let text = "scopes:\n  - urn:chio:scope:tool.read\n  - urn:chio:scope:tool.read\n";
        let uri = Url::parse("file:///proj/chio.yaml").unwrap();
        let range = locate_in_text(&uri, text, "urn:chio:scope:tool.read").expect("range");
        assert_eq!(range.start.line, 1);
    }

    #[test]
    fn manifest_path_in_returns_relative_path() {
        let text = "version: 1\nmanifest: ./manifest.chio-manifest.yaml\n";
        let p = manifest_path_in(text).expect("manifest");
        assert_eq!(p, PathBuf::from("./manifest.chio-manifest.yaml"));
    }

    #[test]
    fn manifest_path_in_skips_indented_keys() {
        let text = "version: 1\nnested:\n  manifest: should-be-ignored\n";
        assert!(manifest_path_in(text).is_none());
    }

    #[test]
    fn extract_urn_handles_non_ascii_prefix() {
        // 'café ' adds a multibyte char before the URN; the URN must
        // round-trip intact regardless of the leading non-ASCII run
        // (UTF-16 columns, not byte offsets).
        let text = "scopes: # café\n  - urn:chio:scope:tool.read\n";
        // UTF-16 column of 't' in 'tool.read' on line 1: bytes
        // "  - urn:chio:scope:" -> all ASCII, so column == byte index.
        let pos = Position::new(1, 22);
        let urn = extract_urn_at_position(text, pos).expect("urn extracted");
        assert_eq!(urn, "urn:chio:scope:tool.read");
    }

    #[test]
    fn scoped_manifest_rejects_absolute_path() {
        let doc_dir = Path::new("/tmp");
        let abs = PathBuf::from("/etc/passwd");
        assert!(scoped_manifest_path(doc_dir, &abs).is_none());
    }

    #[test]
    fn scoped_manifest_rejects_parent_traversal() {
        let doc_dir = Path::new("/tmp");
        let traversal = PathBuf::from("../../etc/passwd.chio-manifest.yaml");
        assert!(scoped_manifest_path(doc_dir, &traversal).is_none());
    }

    #[test]
    fn scoped_manifest_rejects_non_manifest_filename() {
        let doc_dir = Path::new("/tmp");
        // Even a sibling-only path is rejected if the filename is not
        // recognised as a Chio manifest.
        let bad = PathBuf::from("notes.txt");
        assert!(scoped_manifest_path(doc_dir, &bad).is_none());
    }

    #[test]
    fn scoped_manifest_rejects_empty_path() {
        let doc_dir = Path::new("/tmp");
        assert!(scoped_manifest_path(doc_dir, &PathBuf::new()).is_none());
    }

    #[test]
    fn manifest_filename_allows_known_patterns() {
        assert!(manifest_filename_is_allowed(Path::new(
            "tools.chio-manifest.yaml"
        )));
        assert!(manifest_filename_is_allowed(Path::new("chio-manifest.yml")));
        assert!(!manifest_filename_is_allowed(Path::new("manifest.yaml")));
        assert!(!manifest_filename_is_allowed(Path::new("/etc/passwd")));
    }

    #[test]
    fn scoped_manifest_accepts_sibling_manifest() {
        let tmp = std::env::temp_dir().join("chio-lsp-resolver-scope-test");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let manifest = tmp.join("tools.chio-manifest.yaml");
        std::fs::write(&manifest, "version: 1\n").expect("write");

        let resolved = scoped_manifest_path(&tmp, Path::new("tools.chio-manifest.yaml"))
            .expect("sibling manifest is in scope");
        // canonicalisation should strip the relative prefix and stay
        // inside the document directory.
        let canonical_tmp = std::fs::canonicalize(&tmp).expect("canonical tmp");
        assert!(resolved.starts_with(&canonical_tmp));

        let _ = std::fs::remove_file(&manifest);
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn locate_in_text_emits_utf16_columns_for_non_ascii_prefix() {
        // 'café ' is 5 chars / 6 bytes. The URN starts at byte 6 but
        // UTF-16 column 5, so the start column must be reported as 5.
        let text = "café urn:chio:scope:tool.read\n";
        let uri = Url::parse("file:///proj/chio.yaml").unwrap();
        let range = locate_in_text(&uri, text, "urn:chio:scope:tool.read").expect("range");
        assert_eq!(range.start.character, 5);
        // 'urn:chio:scope:tool.read' is 24 ASCII chars, so end column
        // is 5 + 24 = 29 in UTF-16 units.
        assert_eq!(range.end.character, 29);
    }

    const URN: &str = "urn:chio:scope:tool.read";

    fn doc_uri(dir: &Path) -> Url {
        Url::from_file_path(dir.join("chio.yaml")).unwrap()
    }

    fn canonical_tmp() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        (tmp, dir)
    }

    #[test]
    fn locate_in_file_reads_regular_manifest() {
        let (_tmp, dir) = canonical_tmp();
        std::fs::write(dir.join("a.chio-manifest.yaml"), format!("x:\n  - {URN}\n")).unwrap();
        let loc = locate_in_file(&doc_uri(&dir), Path::new("a.chio-manifest.yaml"), URN).unwrap();
        assert_eq!(loc.range.start.line, 1);
        assert_eq!(
            loc.uri,
            Url::from_file_path(dir.join("a.chio-manifest.yaml")).unwrap()
        );
    }

    #[test]
    fn locate_in_file_accepts_manifest_at_exact_bound() {
        let (_tmp, dir) = canonical_tmp();
        let line = format!("{URN}\n");
        let mut body = line.clone();
        body.push_str(&" ".repeat(MAX_MANIFEST_BYTES as usize - line.len()));
        assert_eq!(body.len() as u64, MAX_MANIFEST_BYTES);
        std::fs::write(dir.join("a.chio-manifest.yaml"), body).unwrap();
        let loc = locate_in_file(&doc_uri(&dir), Path::new("a.chio-manifest.yaml"), URN).unwrap();
        assert_eq!(loc.range.start.line, 0);
    }

    #[test]
    fn locate_in_file_rejects_oversize_manifest() {
        let (_tmp, dir) = canonical_tmp();
        let line = format!("{URN}\n");
        let mut body = line.clone();
        body.push_str(&" ".repeat(MAX_MANIFEST_BYTES as usize + 1 - line.len()));
        assert_eq!(body.len() as u64, MAX_MANIFEST_BYTES + 1);
        std::fs::write(dir.join("a.chio-manifest.yaml"), body).unwrap();
        assert_eq!(
            locate_in_file(&doc_uri(&dir), Path::new("a.chio-manifest.yaml"), URN),
            None
        );
    }

    #[test]
    fn locate_in_file_rejects_directory_named_like_manifest() {
        let (_tmp, dir) = canonical_tmp();
        std::fs::create_dir(dir.join("a.chio-manifest.yaml")).unwrap();
        assert_eq!(
            locate_in_file(&doc_uri(&dir), Path::new("a.chio-manifest.yaml"), URN),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn locate_in_file_rejects_fifo_without_blocking() {
        let (_tmp, dir) = canonical_tmp();
        let fifo = dir.join("a.chio-manifest.yaml");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            locate_in_file(&doc_uri(&dir), Path::new("a.chio-manifest.yaml"), URN),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn locate_in_file_rejects_symlink_escaping_document_dir() {
        let (_tmp, dir) = canonical_tmp();
        let (_outside_tmp, outside) = canonical_tmp();
        std::fs::write(outside.join("real.chio-manifest.yaml"), format!("{URN}\n")).unwrap();
        let doc_dir = dir.join("docs");
        std::fs::create_dir(&doc_dir).unwrap();
        std::os::unix::fs::symlink(
            outside.join("real.chio-manifest.yaml"),
            doc_dir.join("link.chio-manifest.yaml"),
        )
        .unwrap();
        assert_eq!(
            locate_in_file(
                &doc_uri(&doc_dir),
                Path::new("link.chio-manifest.yaml"),
                URN
            ),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn locate_in_file_follows_symlink_to_canonical_path_inside_document_dir() {
        let (_tmp, dir) = canonical_tmp();
        std::fs::write(dir.join("real.chio-manifest.yaml"), format!("{URN}\n")).unwrap();
        std::os::unix::fs::symlink(
            dir.join("real.chio-manifest.yaml"),
            dir.join("link.chio-manifest.yaml"),
        )
        .unwrap();
        let loc =
            locate_in_file(&doc_uri(&dir), Path::new("link.chio-manifest.yaml"), URN).unwrap();
        assert_eq!(
            loc.uri,
            Url::from_file_path(dir.join("real.chio-manifest.yaml")).unwrap()
        );
    }
}
