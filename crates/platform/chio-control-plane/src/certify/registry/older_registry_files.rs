//! Certification registry files written without a revocation reserve: pretty
//! JSON from the earlier unbounded saver, and compact JSON from the bounded
//! saver. A revocation of such a file persists exactly when the rewritten file
//! fits the read cap; a write that adds an entry to a file over its reserve is
//! refused.

use std::fs;
use std::sync::OnceLock;

use super::test_fixtures::{artifact, published_entry, Fallible, CHECKED_AT};
use super::*;
use crate::signed_input::MAX_SIGNED_FILE_BYTES;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PUBLISHED_AT: u64 = CHECKED_AT + 120;
const BULK_PAD: usize = 16 * 1024;
const REASON_BYTES: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OlderFile {
    /// Pretty JSON exactly at the read cap.
    PrettyAtCap,
    /// Compact JSON exactly at the read cap.
    CompactAtCap,
    /// Compact JSON with room for one more small entry and no reserve.
    CompactWithSlack,
}

const OLDER_FILES: [OlderFile; 3] = [
    OlderFile::PrettyAtCap,
    OlderFile::CompactAtCap,
    OlderFile::CompactWithSlack,
];

fn bulk_entry(index: usize) -> Fallible<CertificationRegistryEntry> {
    published_entry(
        artifact(&format!("tool-server-older-{index:06}"), BULK_PAD)?,
        PUBLISHED_AT,
    )
}

/// Enough distinct published entries to fill a compact file to the read cap.
fn bulk_entries() -> Fallible<&'static [CertificationRegistryEntry]> {
    static BULK: OnceLock<Result<Vec<CertificationRegistryEntry>, String>> = OnceLock::new();
    BULK.get_or_init(|| {
        (|| -> Fallible<Vec<CertificationRegistryEntry>> {
            let first = bulk_entry(0)?;
            let per_entry = serde_json::to_vec(&first)?.len();
            (0..MAX_SIGNED_FILE_BYTES / per_entry + 2)
                .map(bulk_entry)
                .collect()
        })()
        .map_err(|error| error.to_string())
    })
    .as_deref()
    .map_err(|error| error.clone().into())
}

/// `count` bulk entries plus one entry whose artifact carries `pad` extra
/// ASCII bytes.
fn older_registry(count: usize, pad: usize) -> Fallible<CertificationRegistry> {
    let mut registry = CertificationRegistry::default();
    for entry in bulk_entries()?.iter().take(count) {
        registry
            .artifacts
            .insert(entry.artifact_id.clone(), entry.clone());
    }
    let padded = published_entry(artifact("tool-server-older-pad", pad)?, PUBLISHED_AT)?;
    registry
        .artifacts
        .insert(padded.artifact_id.clone(), padded);
    Ok(registry)
}

/// The bulk count and pad whose encoding is exactly `target` bytes.
fn fill(
    target: usize,
    encode: fn(&CertificationRegistry) -> serde_json::Result<Vec<u8>>,
) -> Fallible<(usize, usize)> {
    let base = encode(&older_registry(0, 0)?)?.len();
    let per_entry = encode(&older_registry(1, 0)?)?.len() - base;
    let count = (target - base) / per_entry;
    Ok((count, target - (base + count * per_entry)))
}

fn fresh_entry() -> Fallible<CertificationRegistryEntry> {
    published_entry(artifact("tool-server-older-fresh", 0)?, PUBLISHED_AT + 2)
}

/// Bytes the fresh entry adds to a non-empty registry, plus room for two
/// revocations.
fn slack() -> Fallible<usize> {
    let mut registry = older_registry(0, 0)?;
    let before = serde_json::to_vec(&registry)?.len();
    let entry = fresh_entry()?;
    registry.artifacts.insert(entry.artifact_id.clone(), entry);
    Ok(serde_json::to_vec(&registry)?.len() - before + 512)
}

/// Writes an older file of `shape` at `path` the way its saver did.
fn write_older_file(shape: OlderFile, path: &Path) -> TestResult {
    let target = match shape {
        OlderFile::PrettyAtCap | OlderFile::CompactAtCap => MAX_SIGNED_FILE_BYTES,
        OlderFile::CompactWithSlack => MAX_SIGNED_FILE_BYTES - slack()?,
    };
    if shape == OlderFile::PrettyAtCap {
        let (count, pad) = fill(target, serde_json::to_vec_pretty::<CertificationRegistry>)?;
        fs::write(
            path,
            serde_json::to_vec_pretty(&older_registry(count, pad)?)?,
        )?;
    } else {
        let (count, pad) = fill(target, serde_json::to_vec::<CertificationRegistry>)?;
        crate::signed_input::write_bounded_json(path, &older_registry(count, pad)?)?;
    }
    assert_eq!(
        fs::metadata(path)?.len(),
        u64::try_from(target)?,
        "{shape:?}"
    );
    Ok(())
}

fn status_on_disk(path: &Path, artifact_id: &str) -> Fallible<Option<CertificationRegistryState>> {
    Ok(CertificationRegistry::load(path)?
        .get(artifact_id)
        .map(|entry| entry.status))
}

#[test]
fn older_files_persist_a_revocation_exactly_when_the_rewrite_fits_the_read_cap() -> TestResult {
    let reason = "r".repeat(REASON_BYTES);
    for shape in OLDER_FILES {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("certifications.json");
        write_older_file(shape, &path)?;
        let mut registry = CertificationRegistry::load(&path)?;
        let ids: Vec<String> = registry.artifacts.keys().take(16).cloned().collect();
        let mut persisted = Vec::new();
        let mut refused = None;
        let mut growth = 0;
        for artifact_id in ids {
            let before = fs::read(&path)?;
            let size_before = serde_json::to_vec(&registry)?.len();
            registry.revoke(&artifact_id, Some(&reason), Some(PUBLISHED_AT + 1))?;
            let size_after = serde_json::to_vec(&registry)?.len();
            growth = size_after - size_before;
            let fits = size_after <= MAX_SIGNED_FILE_BYTES;
            match registry.save(&path) {
                Ok(()) => {
                    assert!(fits, "{shape:?}: a file past the read cap was written");
                    persisted.push(artifact_id);
                    if shape == OlderFile::PrettyAtCap && persisted.len() == 3 {
                        break;
                    }
                }
                Err(error) => {
                    assert!(
                        !fits,
                        "{shape:?}: revocation {} fits the read cap but was refused: {error}",
                        persisted.len() + 1
                    );
                    let message = error.to_string();
                    assert!(
                        message.contains(&format!("{MAX_SIGNED_FILE_BYTES} byte limit"))
                            && message.contains("the existing file was left unchanged"),
                        "{error}"
                    );
                    assert_eq!(fs::read(&path)?, before);
                    assert_eq!(
                        status_on_disk(&path, &artifact_id)?,
                        Some(CertificationRegistryState::Active)
                    );
                    refused = Some(artifact_id);
                    break;
                }
            }
        }
        println!(
            "certification {shape:?}: {} revocations persisted, next refused: {}",
            persisted.len(),
            refused.is_some()
        );
        let reloaded = CertificationRegistry::load(&path)?;
        for artifact_id in &persisted {
            assert_eq!(
                reloaded.get(artifact_id).map(|entry| entry.status),
                Some(CertificationRegistryState::Revoked)
            );
        }
        let expected = match shape {
            OlderFile::PrettyAtCap => (3, false),
            OlderFile::CompactAtCap => (0, true),
            OlderFile::CompactWithSlack => (slack()? / growth, true),
        };
        assert_eq!((persisted.len(), refused.is_some()), expected, "{shape:?}");
    }
    Ok(())
}

fn outcome(result: Result<(), CliError>) -> Fallible<&'static str> {
    match result {
        Ok(()) => Ok("admitted"),
        Err(error)
            if error
                .to_string()
                .contains("registry file is over its revocation reserve") =>
        {
            Ok("refused: file over its revocation reserve")
        }
        Err(error)
            if error
                .to_string()
                .contains("bytes are kept for revoking its records") =>
        {
            Ok("refused: revocation reserve")
        }
        Err(error) if error.to_string().contains("byte limit; the existing file") => {
            Ok("refused: read cap")
        }
        Err(error) => Err(error.into()),
    }
}

#[test]
fn older_files_refuse_a_publish_past_the_revocation_reserve() -> TestResult {
    let mut outcomes = Vec::new();
    for shape in OLDER_FILES {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("certifications.json");
        write_older_file(shape, &path)?;
        let before = fs::read(&path)?;
        let mut registry = CertificationRegistry::load(&path)?;
        println!(
            "certification {shape:?}: {} entries, compact {} bytes",
            registry.artifacts.len(),
            serde_json::to_vec(&registry)?.len()
        );
        let entry = fresh_entry()?;
        let artifact_id = entry.artifact_id.clone();
        registry.artifacts.insert(artifact_id.clone(), entry);
        let result = outcome(registry.save(&path))?;
        println!("certification {shape:?}: publish {result}");
        if result != "admitted" {
            assert_eq!(fs::read(&path)?, before);
            assert_eq!(status_on_disk(&path, &artifact_id)?, None);
        }
        outcomes.push((shape, result));
    }
    // Pretty JSON spends more bytes per entry on indentation than an entry's
    // revocation headroom, so that file, once compacted, is within its reserve
    // and keeps admitting entries; the compact files are over theirs.
    assert_eq!(
        outcomes,
        vec![
            (OlderFile::PrettyAtCap, "admitted"),
            (
                OlderFile::CompactAtCap,
                "refused: file over its revocation reserve"
            ),
            (
                OlderFile::CompactWithSlack,
                "refused: file over its revocation reserve"
            ),
        ]
    );
    Ok(())
}
