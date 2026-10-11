//! Decode the accepted URI subset once, then pass only a filesystem path to SQLite.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use chio_kernel::AuthorityStoreError;

use super::refused;

pub(super) struct AuthorityPath {
    pub(super) filesystem: PathBuf,
    pub(super) create: bool,
}

pub(super) fn parse(path: &Path) -> Result<AuthorityPath, AuthorityStoreError> {
    let (filesystem, create) = match path.to_str().and_then(|text| text.strip_prefix("file:")) {
        Some(uri) => parse_uri(uri)?,
        None => (path.to_path_buf(), true),
    };
    let bytes = filesystem.as_os_str().as_bytes();
    if bytes.is_empty()
        || bytes.contains(&0)
        || filesystem
            .to_str()
            .is_some_and(|text| text.eq_ignore_ascii_case(":memory:"))
        || bytes
            .split(|byte| *byte == b'/')
            .any(|component| component == b"." || component == b"..")
        || filesystem.file_name().is_none()
    {
        return Err(refused(
            "requires a nonempty filesystem path without dot traversal",
        ));
    }
    let filesystem = if filesystem.is_absolute() {
        filesystem
    } else {
        std::env::current_dir()?.join(filesystem)
    };
    Ok(AuthorityPath { filesystem, create })
}

fn parse_uri(uri: &str) -> Result<(PathBuf, bool), AuthorityStoreError> {
    if uri.contains('#') {
        return Err(refused("SQLite URI fragments are unsupported"));
    }
    let (filename, query) = uri
        .split_once('?')
        .map_or((uri, None), |(filename, query)| (filename, Some(query)));
    let filename = match filename.strip_prefix("//") {
        Some(authority_path) => {
            let (authority, path) = authority_path
                .split_once('/')
                .ok_or_else(|| refused("SQLite URI has no local filename"))?;
            let authority = decode(authority)?;
            if !authority.is_empty() && !authority.eq_ignore_ascii_case("localhost") {
                return Err(refused("SQLite URI authority must be empty or localhost"));
            }
            format!("/{path}")
        }
        None => filename.to_owned(),
    };
    let filename = PathBuf::from(decode(&filename)?);
    let mut create = true;
    let mut mode_seen = false;
    let mut cache_seen = false;
    if let Some(query) = query {
        for parameter in query.split('&') {
            let (key, value) = parameter
                .split_once('=')
                .ok_or_else(|| refused("SQLite URI parameter must have a value"))?;
            let key = decode(key)?;
            let value = decode(value)?;
            match (key.as_str(), value.as_str()) {
                ("mode", "rw" | "rwc") if !mode_seen => {
                    mode_seen = true;
                    create = value == "rwc";
                }
                ("cache", "private") if !cache_seen => cache_seen = true,
                _ => {
                    return Err(refused(
                        "SQLite URI has a duplicate or unsupported parameter",
                    ))
                }
            }
        }
    }
    Ok((filename, create))
}

fn decode(encoded: &str) -> Result<String, AuthorityStoreError> {
    let decoded = crate::percent_decode_sqlite_uri_component(encoded)
        .ok_or_else(|| refused("SQLite URI has invalid percent encoding or UTF-8"))?;
    if decoded.contains('\0') {
        return Err(refused("SQLite URI contains NUL"));
    }
    Ok(decoded)
}
