//! Passport status registry files written without a revocation reserve: pretty
//! JSON from the earlier unbounded saver, and compact JSON from the bounded
//! saver. A revocation of such a file persists exactly when the rewritten file
//! fits the read cap; a write that adds a record to it is refused.

use super::test_fixtures::{passport_issued_at, Fallible};
use super::*;
use crate::signed_input::MAX_SIGNED_FILE_BYTES;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ISSUED_AT: u64 = 1_720_000_000;
const PUBLISHED_AT: u64 = ISSUED_AT + 60;
const BULK_SUBJECT_SEED: u8 = 91;
const FRESH_SUBJECT_SEED: u8 = 92;
/// Room for four revocations with a `REASON_BYTES` reason, and for one more
/// record when no reserve is kept.
const SLACK: usize = 1_024;
const REASON_BYTES: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OlderFile {
    /// Pretty JSON exactly at the read cap.
    PrettyAtCap,
    /// Compact JSON exactly at the read cap.
    CompactAtCap,
    /// Compact JSON `SLACK` bytes below the read cap.
    CompactWithSlack,
}

const OLDER_FILES: [OlderFile; 3] = [
    OlderFile::PrettyAtCap,
    OlderFile::CompactAtCap,
    OlderFile::CompactWithSlack,
];

/// `count` active records cloned from one published record, the first with
/// `pad` extra ASCII bytes in its resolve URL.
fn older_registry(
    template: &PassportLifecycleRecord,
    count: usize,
    pad: usize,
) -> PassportStatusRegistry {
    let mut registry = PassportStatusRegistry::default();
    for index in 0..count {
        let mut record = template.clone();
        record.passport_id = format!("{index:064x}");
        if index == 0 {
            record.distribution.resolve_urls = vec![format!(
                "https://status.example.test/older/{}",
                "p".repeat(pad)
            )];
        }
        registry
            .passports
            .insert(record.passport_id.clone(), record);
    }
    registry
}

fn template() -> Fallible<PassportLifecycleRecord> {
    let mut seed = PassportStatusRegistry::default();
    Ok(seed.publish(
        &passport_issued_at(BULK_SUBJECT_SEED, ISSUED_AT)?,
        PUBLISHED_AT,
        PassportStatusDistribution {
            resolve_urls: vec!["https://status.example.test/older/".to_string()],
            cache_ttl_secs: Some(300),
        },
    )?)
}

/// The record count and pad whose encoding is exactly `target` bytes.
fn fill(
    template: &PassportLifecycleRecord,
    target: usize,
    encode: fn(&PassportStatusRegistry) -> serde_json::Result<Vec<u8>>,
) -> Fallible<(usize, usize)> {
    let one = encode(&older_registry(template, 1, 0))?.len();
    let per_record = encode(&older_registry(template, 2, 0))?.len() - one;
    let count = (target - one) / per_record + 1;
    let pad = target - (one + (count - 1) * per_record);
    Ok((count, pad))
}

/// Writes an older file of `shape` at `path` the way its saver did.
fn write_older_file(shape: OlderFile, path: &Path) -> TestResult {
    let template = template()?;
    let target = match shape {
        OlderFile::PrettyAtCap | OlderFile::CompactAtCap => MAX_SIGNED_FILE_BYTES,
        OlderFile::CompactWithSlack => MAX_SIGNED_FILE_BYTES - SLACK,
    };
    if shape == OlderFile::PrettyAtCap {
        let (count, pad) = fill(
            &template,
            target,
            serde_json::to_vec_pretty::<PassportStatusRegistry>,
        )?;
        fs::write(
            path,
            serde_json::to_vec_pretty(&older_registry(&template, count, pad))?,
        )?;
    } else {
        let (count, pad) = fill(
            &template,
            target,
            serde_json::to_vec::<PassportStatusRegistry>,
        )?;
        crate::signed_input::write_bounded_json(path, &older_registry(&template, count, pad))?;
    }
    assert_eq!(
        fs::metadata(path)?.len(),
        u64::try_from(target)?,
        "{shape:?}"
    );
    Ok(())
}

fn status_on_disk(path: &Path, passport_id: &str) -> Fallible<Option<PassportLifecycleState>> {
    Ok(PassportStatusRegistry::load(path)?
        .get(passport_id)
        .map(|record| record.status))
}

#[test]
fn older_files_persist_a_revocation_exactly_when_the_rewrite_fits_the_read_cap() -> TestResult {
    let reason = "r".repeat(REASON_BYTES);
    for shape in OLDER_FILES {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("passport-statuses.json");
        write_older_file(shape, &path)?;
        let mut registry = PassportStatusRegistry::load(&path)?;
        let ids: Vec<String> = registry.passports.keys().take(8).cloned().collect();
        let mut persisted = Vec::new();
        let mut refused = None;
        for passport_id in ids {
            let before = fs::read(&path)?;
            registry.revoke(&passport_id, Some(&reason), Some(PUBLISHED_AT + 1))?;
            let fits = serde_json::to_vec(&registry)?.len() <= MAX_SIGNED_FILE_BYTES;
            match registry.save(&path) {
                Ok(()) => {
                    assert!(fits, "{shape:?}: a file past the read cap was written");
                    persisted.push(passport_id);
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
                        status_on_disk(&path, &passport_id)?,
                        Some(PassportLifecycleState::Active)
                    );
                    refused = Some(passport_id);
                    break;
                }
            }
        }
        println!(
            "passport {shape:?}: {} revocations persisted, next refused: {}",
            persisted.len(),
            refused.is_some()
        );
        let reloaded = PassportStatusRegistry::load(&path)?;
        for passport_id in &persisted {
            assert_eq!(
                reloaded.get(passport_id).map(|record| record.status),
                Some(PassportLifecycleState::Revoked)
            );
        }
        let expected = match shape {
            OlderFile::PrettyAtCap => (3, false),
            OlderFile::CompactAtCap => (0, true),
            OlderFile::CompactWithSlack => (4, true),
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
fn older_files_refuse_a_publish_that_adds_a_record() -> TestResult {
    let mut outcomes = Vec::new();
    for shape in OLDER_FILES {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("passport-statuses.json");
        write_older_file(shape, &path)?;
        let before = fs::read(&path)?;
        let mut registry = PassportStatusRegistry::load(&path)?;
        let record = registry.publish(
            &passport_issued_at(FRESH_SUBJECT_SEED, ISSUED_AT)?,
            PUBLISHED_AT + 2,
            PassportStatusDistribution::default(),
        )?;
        let result = outcome(registry.save(&path))?;
        println!("passport {shape:?}: publish {result}");
        if result != "admitted" {
            assert_eq!(fs::read(&path)?, before);
            assert_eq!(status_on_disk(&path, &record.passport_id)?, None);
        }
        outcomes.push((shape, result));
    }
    assert_eq!(
        outcomes,
        vec![
            (
                OlderFile::PrettyAtCap,
                "refused: file over its revocation reserve"
            ),
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

#[test]
fn older_file_writes_compare_against_the_file_they_replace_now() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    write_older_file(OlderFile::CompactWithSlack, &path)?;
    let mut stale = PassportStatusRegistry::load(&path)?;

    // Another writer replaces the file with a registry of one record.
    let mut current = PassportStatusRegistry::default();
    current.publish(
        &passport_issued_at(FRESH_SUBJECT_SEED, ISSUED_AT)?,
        PUBLISHED_AT + 2,
        PassportStatusDistribution::default(),
    )?;
    current.save(&path)?;
    let before = fs::read(&path)?;

    let passport_id = stale.passports.keys().next().cloned().ok_or("one record")?;
    stale.revoke(
        &passport_id,
        Some(&"r".repeat(REASON_BYTES)),
        Some(PUBLISHED_AT + 1),
    )?;
    assert_eq!(
        outcome(stale.save(&path))?,
        "refused: revocation reserve",
        "a registry over its reserve may not replace one within it"
    );
    assert_eq!(fs::read(&path)?, before);
    Ok(())
}
