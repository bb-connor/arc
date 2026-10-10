//! Reclamation of abandoned snapshot files before the receipt store opens.
//!
//! Opening the receipt store writes: every open commits its schema stamp. On a
//! data filesystem filled by snapshot files that owners abandoned when they
//! died, that open can fail before the snapshot service, which reclaims too,
//! ever starts. The owner of both calls this first, with the path it is about
//! to open.
//!
//! One attempt does bounded work (at most 256 directory entries read and 16
//! snapshot directories examined) and takes the snapshot parent lock with a
//! non-blocking lock; the filesystem calls themselves block as the filesystem
//! does. It creates no snapshot parent, does not retry and never opens or
//! writes the receipt database. Later attempts, by this process or by the
//! next one after a restart, resume where this one stopped. On a
//! copy-on-write filesystem the cursor update can itself need space; that
//! attempt is then refused after what it reclaimed has been freed.

use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// Reclaim one bounded window of snapshot files abandoned by owners that died,
/// in the data directory of the receipt database at `receipt_db_path`, before
/// that database is opened.
///
/// Best effort: it never fails and never changes what opening the store then
/// returns; what it could not do is logged. A database SQLite holds in memory,
/// or a temporary one, has no data directory, and a SQLite URI this does not
/// resolve exactly (a remote authority, a VFS, an escaped NUL or malformed
/// escape, an access mode SQLite rejects, non-UTF-8 text) is left alone.
pub fn reclaim_abandoned_snapshots(receipt_db_path: &Path) {
    #[cfg(target_os = "linux")]
    {
        match data_directory(receipt_db_path) {
            Location::Directory(directory) => {
                if let Err(error) =
                    crate::receipt_query_snapshot_backing::reclaim_abandoned(Some(&directory))
                {
                    tracing::warn!(
                        %error,
                        "receipt query snapshot reclamation before the receipt store opened did not run"
                    );
                }
            }
            Location::Unsupported => tracing::warn!(
                "receipt query snapshot reclamation before the receipt store opened skipped a \
                 database path it does not resolve"
            ),
            Location::NoFile | Location::Absent => {}
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = receipt_db_path;
}

/// Where the snapshot files of a receipt database live.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum Location {
    /// The directory of the database file, as SQLite resolves it.
    Directory(PathBuf),
    /// Neither the database nor its directory exists yet.
    Absent,
    /// SQLite backs the database by no file: it is held in memory, or it is
    /// a temporary database.
    NoFile,
    /// A form this does not resolve exactly; nothing is touched.
    Unsupported,
}

/// The directory SQLite will report for the database at `configured`: the
/// database file resolved through every link when it exists, otherwise its
/// existing parent resolved. Nothing is created.
#[cfg(target_os = "linux")]
fn data_directory(configured: &Path) -> Location {
    let file = match database_file(configured) {
        Ok(Some(file)) => file,
        Ok(None) => return Location::NoFile,
        Err(Unsupported) => return Location::Unsupported,
    };
    match std::fs::canonicalize(&file) {
        Ok(resolved) if resolved.is_dir() => Location::Unsupported,
        Ok(resolved) => resolved
            .parent()
            .map_or(Location::Unsupported, |directory| {
                Location::Directory(directory.to_path_buf())
            }),
        // A dangling link: SQLite would create its target, which this does
        // not resolve.
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && std::fs::symlink_metadata(&file).is_ok() =>
        {
            Location::Unsupported
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = file
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            match std::fs::canonicalize(parent) {
                Ok(directory) if directory.is_dir() => Location::Directory(directory),
                Ok(_) => Location::Unsupported,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Location::Absent,
                Err(_) => Location::Unsupported,
            }
        }
        Err(_) => Location::Unsupported,
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct Unsupported;

/// The file SQLite opens for `configured`, or `None` when no file backs it,
/// following SQLite's own exact rules. rusqlite opens with URI filenames
/// enabled, so a name that starts with `file:` is a URI; any other name is a
/// plain path, `#` and `?` included. SQLite compares the `:memory:` name and
/// the URI keys and values it acts on exactly, after decoding escapes.
#[cfg(target_os = "linux")]
fn database_file(configured: &Path) -> Result<Option<PathBuf>, Unsupported> {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let bytes = configured.as_os_str().as_bytes();
    if !bytes.starts_with(b"file:") {
        // An empty name is a temporary database.
        let no_file = bytes.is_empty() || bytes == b":memory:";
        return Ok((!no_file).then(|| configured.to_path_buf()));
    }
    let uri = std::str::from_utf8(bytes).map_err(|_| Unsupported)?;
    let rest = uri.strip_prefix("file:").ok_or(Unsupported)?;
    // `file://authority/path`: SQLite reads the authority up to the next `/`
    // and accepts only an empty one or exactly `localhost`.
    let rest = match rest.strip_prefix("//") {
        Some(after) => {
            let end = after.find('/').unwrap_or(after.len());
            let (authority, path) = (after.get(..end), after.get(end..));
            match (authority, path) {
                (Some("" | "localhost"), Some(path)) => path,
                _ => return Err(Unsupported),
            }
        }
        None => rest,
    };
    // A fragment is not part of a URI; the query follows the filename.
    let rest = rest.split_once('#').map_or(rest, |(uri, _)| uri);
    let (name, query) = match rest.split_once('?') {
        Some((name, query)) => (name, Some(query)),
        None => (rest, None),
    };
    let in_memory = match query {
        Some(query) => query_selects_memory(query)?,
        None => false,
    };
    let decoded = percent_decode(name).ok_or(Unsupported)?;
    if decoded.contains(&0) {
        return Err(Unsupported);
    }
    if in_memory || decoded.is_empty() || decoded == b":memory:" {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(OsString::from_vec(decoded))))
}

/// Whether a URI query makes SQLite hold the database in memory. A VFS, a
/// repeated or rejected access mode, or an undecodable parameter is refused.
#[cfg(target_os = "linux")]
fn query_selects_memory(query: &str) -> Result<bool, Unsupported> {
    let mut mode = None;
    for parameter in query.split('&') {
        let (key, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        let key = percent_decode(key).ok_or(Unsupported)?;
        let value = percent_decode(value).ok_or(Unsupported)?;
        if key.contains(&0) || value.contains(&0) {
            return Err(Unsupported);
        }
        match key.as_slice() {
            b"vfs" => return Err(Unsupported),
            b"mode" if mode.is_some() => return Err(Unsupported),
            b"mode" => match value.as_slice() {
                b"ro" | b"rw" | b"rwc" | b"memory" => mode = Some(value),
                _ => return Err(Unsupported),
            },
            _ => {}
        }
    }
    Ok(mode.is_some_and(|mode| mode == b"memory"))
}

/// Decode `%HH` escapes in a URI filename as SQLite does, into bytes, since
/// the decoded name need not be UTF-8. `None` for a malformed escape, which
/// this does not resolve.
#[cfg(target_os = "linux")]
fn percent_decode(text: &str) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = hex(bytes.next()?)?;
            let low = hex(bytes.next()?)?;
            decoded.push((high << 4) | low);
        } else {
            decoded.push(byte);
        }
    }
    Some(decoded)
}

#[cfg(target_os = "linux")]
const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "preopen/tests.rs"]
mod tests;
