//! Bounded, no-follow reads of bundle files and their strict decoding.
//!
//! Every path is relative to the bundle root, has only normal components and
//! is opened without following a symbolic link at any component. File data
//! stays untrusted until the envelope and digests are checked.

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use chio_core_types::canonical::UntrustedJsonText;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::BundleVerifyError;

/// Largest single file a bundle may carry.
pub const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
/// Largest sum of listed file lengths.
pub const MAX_PACKAGE_BYTES: u64 = 256 * 1024 * 1024;

/// A relative path with only normal components.
pub fn safe_relative_path(relative_path: &str) -> Result<PathBuf, BundleVerifyError> {
    let path = Path::new(relative_path);
    if path.is_absolute() {
        return Err(BundleVerifyError::file(format!(
            "evidence package manifest path must be relative: {relative_path}"
        )));
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(BundleVerifyError::file(format!(
                    "evidence package manifest path escapes the package root: {relative_path}"
                )));
            }
        }
    }
    Ok(path.to_path_buf())
}

#[cfg(unix)]
fn open_file(root: &Path, relative: &Path) -> Result<fs::File, std::io::Error> {
    use rustix::fs::{open, openat, Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let mut directory = open(root, flags | OFlags::DIRECTORY, Mode::empty())?;
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "non-canonical evidence path",
            ));
        };
        let is_directory = components.peek().is_some();
        let next = openat(
            &directory,
            name,
            flags
                | if is_directory {
                    OFlags::DIRECTORY
                } else {
                    OFlags::empty()
                },
            Mode::empty(),
        )?;
        if !is_directory {
            return Ok(fs::File::from(next));
        }
        directory = next;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "empty evidence path",
    ))
}

#[cfg(not(unix))]
fn open_file(root: &Path, relative: &Path) -> Result<fs::File, std::io::Error> {
    let mut path = root.to_owned();
    for component in relative.components() {
        path.push(component);
        if fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "evidence paths cannot be symbolic links",
            ));
        }
    }
    fs::File::open(path)
}

/// Read one bundle file, refusing links, non-regular files and files over
/// [`MAX_FILE_BYTES`].
pub fn read_bytes(root: &Path, name: &str) -> Result<Vec<u8>, BundleVerifyError> {
    let relative = safe_relative_path(name)?;
    let file = open_file(root, &relative)
        .map_err(|error| BundleVerifyError::file(format!("cannot open {name}: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| BundleVerifyError::file(format!("cannot stat {name}: {error}")))?;
    if !metadata.is_file() {
        return Err(BundleVerifyError::file(format!(
            "evidence input must be a regular file: {name}"
        )));
    }
    let mut bytes = Vec::new();
    let bound = u64::try_from(MAX_FILE_BYTES)
        .ok()
        .and_then(|bound| bound.checked_add(1))
        .unwrap_or(u64::MAX);
    file.take(bound)
        .read_to_end(&mut bytes)
        .map_err(|error| BundleVerifyError::file(format!("cannot read {name}: {error}")))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(BundleVerifyError::file(format!(
            "evidence file exceeds byte limit: {name}"
        )));
    }
    Ok(bytes)
}

/// Decode `bytes` as `T`, refusing input the typed form would drop or
/// rewrite (unknown members at any level, explicit nulls for omitted
/// members), through the shared lossless decoder.
pub fn decode_strict<T>(what: &str, bytes: &[u8]) -> Result<T, BundleVerifyError>
where
    T: DeserializeOwned + Serialize,
{
    let text = UntrustedJsonText::from_wire(bytes, MAX_FILE_BYTES)
        .map_err(|error| BundleVerifyError::signed_json(what, error))?;
    let value: serde_json::Value = text
        .decode_signed()
        .map_err(|error| BundleVerifyError::signed_json(what, error))?;
    chio_security_types::strict_serde::lossless(value, serde_json::from_value::<T>, |typed: &T| {
        serde_json::to_value(typed)
    })
    .map_err(|error| {
        BundleVerifyError::schema(format!("{what} does not match its schema: {error}"))
    })
}

/// Read and strictly decode one JSON file.
pub fn read_json<T>(root: &Path, name: &str) -> Result<T, BundleVerifyError>
where
    T: DeserializeOwned + Serialize,
{
    decode_strict(name, &read_bytes(root, name)?)
}

/// Read and strictly decode one NDJSON file; blank lines are skipped.
pub fn read_ndjson<T>(root: &Path, name: &str) -> Result<Vec<T>, BundleVerifyError>
where
    T: DeserializeOwned + Serialize,
{
    let bytes = read_bytes(root, name)?;
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        BundleVerifyError::schema(format!("{name} is not valid UTF-8: {error}"))
    })?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| decode_strict(name, line.as_bytes()))
        .collect()
}
