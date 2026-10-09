//! SQLite path and URI classification shared by the stores.

use std::path::{Path, PathBuf};

/// Whether a SQLite path opens a database that lives only in memory for the life
/// of the process. rusqlite enables URI filenames, so the bare `:memory:`
/// sentinel, `file::memory:`, and any `file:...?mode=memory` URI all open a
/// non-durable database that loses its contents on restart and must not be
/// mistaken for a durable store. Durability gates use this to refuse an in-memory
/// path where they would otherwise advertise durable persistence.
#[must_use]
pub fn is_in_memory_sqlite_path(path: &str) -> bool {
    if path.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    let Some(rest) = path.strip_prefix("file:") else {
        return false;
    };
    // SQLite URI fragments do not participate in either the filename or the
    // query. Strip them before interpreting the durability-sensitive parts.
    let rest = rest.split_once('#').map_or(rest, |(uri, _)| uri);
    // SQLite terminates a percent-decoded filename or URI parameter at NUL.
    // Classify any such URI as non-durable so qualified stores reject it
    // before SQLite can silently open a temporary or in-memory database.
    if percent_decode_sqlite_uri(rest).contains('\0') {
        return true;
    }
    let (name, query) = match rest.split_once('?') {
        Some((name, query)) => (name, Some(query)),
        None => (rest, None),
    };
    let decoded_name = percent_decode_sqlite_uri(name);
    if decoded_name.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    query.is_some_and(|query| {
        percent_decode_sqlite_uri(query)
            .split('&')
            .filter_map(|parameter| parameter.split_once('='))
            .any(|(key, value)| {
                (key.eq_ignore_ascii_case("mode") && value.eq_ignore_ascii_case("memory"))
                    || (key.eq_ignore_ascii_case("vfs") && value.eq_ignore_ascii_case("memdb"))
            })
    })
}

#[allow(
    clippy::indexing_slicing,
    reason = "The loop bounds index by the byte length and checks the complete percent-encoded triplet before reading its suffix."
)]
pub fn percent_decode_sqlite_uri(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_nibble(bytes[index + 1]), hex_nibble(bytes[index + 2]))
            {
                decoded.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

#[allow(
    clippy::indexing_slicing,
    reason = "The loop bounds index by the byte length and checks the complete percent-encoded triplet before reading its suffix."
)]
pub fn percent_decode_sqlite_uri_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push(
                hex_nibble(high)?
                    .checked_mul(16)?
                    .checked_add(hex_nibble(low)?)?,
            );
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

pub fn sqlite_uri_has_nonlocal_authority(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("file://") else {
        return false;
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let Some(authority) = percent_decode_sqlite_uri_component(&rest[..authority_end]) else {
        return true;
    };
    !authority.is_empty() && !authority.eq_ignore_ascii_case("localhost")
}

pub fn sqlite_uri_disables_locking(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("file:") else {
        return false;
    };
    let rest = rest.split_once('#').map_or(rest, |(uri, _)| uri);
    let Some((_, query)) = rest.split_once('?') else {
        return false;
    };
    query.split('&').any(|pair| {
        let (key, value) = pair.split_once('=').map_or((pair, ""), |parts| parts);
        let Some(key) = percent_decode_sqlite_uri_component(key) else {
            return true;
        };
        let Some(value) = percent_decode_sqlite_uri_component(value) else {
            return true;
        };
        key.eq_ignore_ascii_case("nolock")
            || (key.eq_ignore_ascii_case("vfs") && value.eq_ignore_ascii_case("unix-none"))
    })
}

pub fn sqlite_uri_is_read_only(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("file:") else {
        return false;
    };
    let rest = rest.split_once('#').map_or(rest, |(uri, _)| uri);
    let Some((_, query)) = rest.split_once('?') else {
        return false;
    };
    query.split('&').any(|pair| {
        let (key, value) = pair.split_once('=').map_or((pair, ""), |parts| parts);
        let (Some(key), Some(value)) = (
            percent_decode_sqlite_uri_component(key),
            percent_decode_sqlite_uri_component(value),
        ) else {
            return true;
        };
        (key.eq_ignore_ascii_case("mode") && value.eq_ignore_ascii_case("ro"))
            || (key.eq_ignore_ascii_case("immutable")
                && !matches!(
                    value.to_ascii_lowercase().as_str(),
                    "0" | "off" | "false" | "no"
                ))
    })
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The directory that must exist before SQLite opens `path`, or `None` when
/// there is nothing to create.
///
/// rusqlite accepts `file:` URIs whose query string (`?mode=rwc`) and optional
/// `//authority` are not part of the on-disk filename. Treating such a URI as a
/// plain [`Path`] makes `parent()` resolve to a bogus directory (for example
/// `file:/var/lib/chio`) and skips creating the real one, so SQLite then fails
/// to open the database. This strips the `file:` scheme, any authority, and the
/// query so callers create the directory that actually backs the database. An
/// in-memory database (`:memory:`, `file:...?mode=memory`) has no backing
/// directory and returns `None`.
#[must_use]
pub fn sqlite_parent_dir_to_create(path: &Path) -> Option<PathBuf> {
    let Some(text) = path.to_str() else {
        // A non-UTF8 path cannot be a `file:` URI, so use it verbatim.
        return non_empty_parent(path);
    };
    if is_in_memory_sqlite_path(text) {
        return None;
    }
    non_empty_parent(&sqlite_filesystem_path(text))
}

/// The parent of `path`, unless it is empty (a bare filename with no directory
/// component), in which case there is nothing to create.
fn non_empty_parent(path: &Path) -> Option<PathBuf> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
}

/// The filesystem path a rusqlite path points at, resolving a `file:` URI to
/// its on-disk filename by stripping the scheme, any `//authority`, and the
/// `?query`. A plain path (no `file:` scheme) is returned unchanged.
#[must_use]
pub fn sqlite_filesystem_path(text: &str) -> PathBuf {
    let Some(rest) = text.strip_prefix("file:") else {
        return PathBuf::from(text);
    };
    // Drop the URI query (`?mode=rwc`, `?cache=shared`); it is not part of the
    // filename.
    let without_query = rest.split_once('?').map_or(rest, |(name, _query)| name);
    // `file://authority/path` places the filesystem path after the authority;
    // `file:/path` and `file:path` have no authority. Strip a leading `//` and
    // the authority up to the next `/`.
    let filesystem = match without_query.strip_prefix("//") {
        Some(after_authority_marker) => match after_authority_marker.find('/') {
            Some(path_start) => &after_authority_marker[path_start..],
            None => "",
        },
        None => without_query,
    };
    PathBuf::from(filesystem)
}

#[cfg(test)]
mod tests {
    use super::{
        is_in_memory_sqlite_path, sqlite_parent_dir_to_create, sqlite_uri_has_nonlocal_authority,
    };
    use std::path::{Path, PathBuf};

    #[test]
    fn resolves_parent_dir_from_file_uris_and_plain_paths() {
        // A `file:` URI with a query resolves to the real filesystem parent, not
        // a `file:`-prefixed directory folded out of the raw string.
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new(
                "file:/var/lib/chio/receipts.db.revocations?mode=rwc"
            )),
            Some(PathBuf::from("/var/lib/chio"))
        );
        // A `file://` URI with an empty authority drops the `//`.
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new("file:///var/lib/chio/db?cache=shared")),
            Some(PathBuf::from("/var/lib/chio"))
        );
        // A plain filesystem path keeps its parent unchanged.
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new("/var/lib/chio/receipts.db")),
            Some(PathBuf::from("/var/lib/chio"))
        );
        // A bare filename has no directory component to create.
        assert_eq!(sqlite_parent_dir_to_create(Path::new("receipts.db")), None);
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new("file:receipts.db?mode=rwc")),
            None
        );
        // In-memory databases have no backing directory.
        assert_eq!(sqlite_parent_dir_to_create(Path::new(":memory:")), None);
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new("file:receipts.db?mode=memory")),
            None
        );
    }

    #[test]
    fn classifies_in_memory_sqlite_paths() {
        for path in [
            ":memory:",
            ":MEMORY:",
            "file::memory:",
            "file:receipts.db?mode=memory",
            "file:receipts.db?cache=shared&mode=memory",
            "file:pool?vfs=memdb",
            "file:pool?mode%3Dmemory",
            "file:pool?mode=%6demory",
            "file:%3Amemory%3A",
            "file:%00",
            "file::memory:%00",
            "file:pool?mode=memory%00",
        ] {
            assert!(
                is_in_memory_sqlite_path(path),
                "{path} must classify as in-memory"
            );
        }
    }

    #[test]
    fn classifies_durable_sqlite_paths() {
        for path in [
            "receipts.db",
            "/var/lib/chio/receipts.db",
            "file:/var/lib/chio/receipts.db?mode=rwc",
            "file:receipts.db",
            "memory-notes.db",
        ] {
            assert!(
                !is_in_memory_sqlite_path(path),
                "{path} must classify as durable"
            );
        }
    }

    #[test]
    fn classifies_sqlite_uri_authorities() {
        for path in [
            "receipts.db",
            "file:/var/lib/chio/receipts.db",
            "file:///var/lib/chio/receipts.db",
            "file://localhost/var/lib/chio/receipts.db",
            "file://LOCALHOST/var/lib/chio/receipts.db",
            "file://%6cocalhost/var/lib/chio/receipts.db",
        ] {
            assert!(!sqlite_uri_has_nonlocal_authority(path), "{path}");
        }
        for path in [
            "file://remote-host/var/lib/chio/receipts.db",
            "file://%72emote-host/var/lib/chio/receipts.db",
            "file://localhost%00/var/lib/chio/receipts.db",
            "file://%zz/var/lib/chio/receipts.db",
        ] {
            assert!(sqlite_uri_has_nonlocal_authority(path), "{path}");
        }
    }
}
