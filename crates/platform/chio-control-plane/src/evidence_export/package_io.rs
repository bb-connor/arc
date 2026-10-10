//! Bounded package reads. File data remains untrusted until envelope verification.

use super::*;
use std::io::Read;

pub(super) const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const REQUIRED_FILES: &[&str] = &[
    "query.json",
    "receipts.ndjson",
    "child-receipts.ndjson",
    "checkpoints.ndjson",
    "checkpoint-publications.ndjson",
    "checkpoint-witnesses.ndjson",
    "checkpoint-consistency-proofs.ndjson",
    "checkpoint-equivocations.ndjson",
    "capability-lineage.ndjson",
    "inclusion-proofs.ndjson",
    "uncheckpointed-receipts.ndjson",
    "retention.json",
    "README.txt",
];

pub(super) fn verify_inventory(manifest: &EvidenceExportManifest) -> Result<(), CliError> {
    let mut expected: BTreeSet<&str> = REQUIRED_FILES.iter().copied().collect();
    if let Some(policy) = &manifest.policy {
        expected.insert("policy/metadata.json");
        if !policy.source_path.starts_with("policy/source.") {
            return Err(CliError::attest_error(
                "unsupported evidence policy attachment path".to_owned(),
            ));
        }
        expected.insert(&policy.source_path);
    }
    if manifest.federation_policy.is_some() {
        expected.insert(federation_policy_relative_path());
    }
    let actual: BTreeSet<&str> = manifest
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    if actual != expected || actual.len() != manifest.files.len() {
        return Err(CliError::attest_error(
            "evidence manifest must declare every package file exactly once".to_owned(),
        ));
    }
    let mut total = 0_u64;
    for file in &manifest.files {
        safe_relative_path(&file.path)?;
        total = total
            .checked_add(file.bytes)
            .ok_or_else(|| CliError::attest_error("evidence package size overflow".to_owned()))?;
        if file.bytes > crate::integer::count(MAX_FILE_BYTES) || total > 256 * 1024 * 1024 {
            return Err(CliError::attest_error(
                "evidence package exceeds file or total byte limit".to_owned(),
            ));
        }
    }
    Ok(())
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

pub(super) fn read_bytes(root: &Path, name: &str) -> Result<Vec<u8>, CliError> {
    let relative = safe_relative_path(name)?;
    let file = open_file(root, &relative)?;
    if !file.metadata()?.is_file() {
        return Err(CliError::attest_error(
            "evidence input must be a regular file".to_owned(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(crate::integer::count(MAX_FILE_BYTES + 1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(CliError::attest_error(
            "evidence file exceeds byte limit".to_owned(),
        ));
    }
    Ok(bytes)
}
