//! Records every body a signer signs through the wrapper, for schema generation.
//!
//! Compiled only with the `wrapper-capture` feature, which no manifest
//! enables (`scripts/check-wrapper-capture-scope.py`); the capture harness
//! `scripts/capture-wrapper-bodies.sh` turns it on for one test run. Building
//! a wrapper stages its body; turning that wrapper into a signing input
//! records it, so a wrapper built only to verify records nothing. Nothing
//! is recorded unless `CHIO_WRAPPER_CAPTURE_DIR` is set and non-empty and the
//! process is a cargo test binary. Each body lands once at
//! `<dir>/<escaped schema id>/<sha256 of body>.json`; a failed write is
//! reported on stderr and never changes the wrapper result.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::string::String;
use std::sync::{Mutex, MutexGuard};
use std::vec::Vec;

use sha2::{Digest, Sha256};

/// Environment variable naming the capture directory.
pub const CAPTURE_DIR_ENV: &str = "CHIO_WRAPPER_CAPTURE_DIR";

/// Staged bodies kept before the oldest are dropped; a wrapper is signed
/// right after it is built, so the bound only sheds verify-only wrappers.
const MAX_STAGED: usize = 4096;

type Staged = BTreeMap<[u8; super::SIGNING_WRAPPER_LEN], (String, Vec<u8>)>;

static STAGED: Mutex<Staged> = Mutex::new(BTreeMap::new());

fn staged() -> MutexGuard<'static, Staged> {
    match STAGED.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(super) fn stage(wrapper: &[u8; super::SIGNING_WRAPPER_LEN], schema_id: &str, canonical_body: &[u8]) {
    if std::env::var_os(CAPTURE_DIR_ENV).is_none_or(|dir| dir.is_empty()) {
        return;
    }
    let mut staged = staged();
    if staged.len() >= MAX_STAGED {
        staged.clear();
    }
    staged.insert(*wrapper, (schema_id.into(), canonical_body.to_vec()));
}

pub(super) fn commit(wrapper: &[u8; super::SIGNING_WRAPPER_LEN]) {
    let entry = staged().remove(wrapper);
    if let Some((schema_id, canonical_body)) = entry {
        record(&schema_id, &canonical_body);
    }
}

#[allow(
    clippy::print_stderr,
    reason = "The capture harness reads failures from the test run output; the wrapper result never depends on them."
)]
fn record(schema_id: &str, canonical_body: &[u8]) {
    let Some(dir) = std::env::var_os(CAPTURE_DIR_ENV).filter(|dir| !dir.is_empty()) else {
        return;
    };
    if !running_as_cargo_test_binary() {
        std::eprintln!("wrapper-capture: {schema_id}: not a cargo test binary, nothing recorded");
        return;
    }
    if let Err(error) = write_capture(Path::new(&dir), schema_id, canonical_body) {
        std::eprintln!("wrapper-capture: {schema_id}: {error}");
    }
}

/// Cargo places test binaries in `<target>/<profile>/deps/`; binaries a
/// release or install produces live elsewhere and never record.
fn running_as_cargo_test_binary() -> bool {
    std::env::current_exe().is_ok_and(|exe| {
        exe.parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "deps")
    })
}

/// Maps a schema id to one path segment: bytes outside `[a-z0-9._-]`
/// become `%XX`, so distinct ids never share a directory.
fn escape_schema_id(schema_id: &str) -> String {
    let mut out = String::with_capacity(schema_id.len());
    for byte in schema_id.bytes() {
        if byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        {
            out.push(char::from(byte));
        } else {
            out.push_str(&std::format!("%{byte:02X}"));
        }
    }
    if out.starts_with('.') {
        out.replace_range(0..1, "%2E");
    }
    out
}

fn write_capture(dir: &Path, schema_id: &str, canonical_body: &[u8]) -> std::io::Result<PathBuf> {
    let digest = hex::encode(Sha256::digest(canonical_body));
    let id_dir = dir.join(escape_schema_id(schema_id));
    fs::create_dir_all(&id_dir)?;
    let target = id_dir.join(std::format!("{digest}.json"));
    if target.exists() {
        return Ok(target);
    }
    let staging = id_dir.join(std::format!(".{digest}.{}.tmp", std::process::id()));
    {
        let mut file = fs::File::create(&staging)?;
        file.write_all(canonical_body)?;
        file.sync_all()?;
    }
    fs::rename(&staging, &target)?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_tests_run_as_cargo_test_binaries() {
        assert!(running_as_cargo_test_binary());
    }

    #[test]
    fn escaping_keeps_plain_ids_and_separates_others() {
        assert_eq!(escape_schema_id("chio.work-offer.v1"), "chio.work-offer.v1");
        assert_eq!(
            escape_schema_id("chio.replay.report/v1"),
            "chio.replay.report%2Fv1"
        );
        assert_eq!(escape_schema_id("../x"), "%2E.%2Fx");
        assert_ne!(escape_schema_id("chio.A.v1"), escape_schema_id("chio.a.v1"));
    }

    #[test]
    fn capture_writes_each_body_once_under_its_id() -> std::io::Result<()> {
        let root =
            std::env::temp_dir().join(std::format!("chio-wrapper-capture-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let first = write_capture(&root, "chio.work-offer.v1", br#"{"a":1}"#)?;
        let again = write_capture(&root, "chio.work-offer.v1", br#"{"a":1}"#)?;
        let other = write_capture(&root, "chio.work-offer.v1", br#"{"a":2}"#)?;
        assert_eq!(first, again);
        assert_ne!(first, other);
        assert_eq!(fs::read(&first)?, br#"{"a":1}"#);
        let mut names: std::vec::Vec<_> = fs::read_dir(root.join("chio.work-offer.v1"))?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<_>>()?;
        names.sort();
        assert_eq!(names.len(), 2, "{names:?}");
        fs::remove_dir_all(&root)?;
        Ok(())
    }
}
