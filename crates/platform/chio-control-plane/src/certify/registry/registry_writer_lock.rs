//! The certification registry has one writer at a time: an update that
//! overlaps a dispute, publish or revocation is refused as busy instead of
//! replacing a newer file with an older copy.

use std::sync::{Arc, Barrier};

use super::test_fixtures::{artifact, published_entry, CHECKED_AT};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PUBLISHED_AT: u64 = CHECKED_AT + 60;

fn status(path: &Path, artifact_id: &str) -> Result<Option<CertificationRegistryState>, CliError> {
    Ok(CertificationRegistry::load(path)?
        .get(artifact_id)
        .map(|entry| entry.status))
}

fn revoke(
    path: &Path,
    artifact_id: &str,
) -> Result<CertificationRegistryEntry, RegistryUpdateError> {
    CertificationRegistry::update(path, |registry| {
        registry.revoke(artifact_id, Some("compromised"), Some(PUBLISHED_AT + 5))
    })
}

#[test]
fn updates_overlapping_a_dispute_or_a_revocation_are_busy_and_the_revocation_holds() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("certifications.json");
    let entry = published_entry(artifact("tool-server-writer-lock", 0)?, PUBLISHED_AT)?;
    let artifact_id = entry.artifact_id.clone();
    CertificationRegistry::update(&path, |registry| {
        registry.artifacts.insert(artifact_id.clone(), entry);
        Ok(())
    })?;

    // A dispute in progress holds the registry; the revocation is busy and
    // persists when retried after it.
    let inside = Arc::new(Barrier::new(2));
    let attempted = Arc::new(Barrier::new(2));
    let disputer = {
        let (path, artifact_id) = (path.clone(), artifact_id.clone());
        let (inside, attempted) = (Arc::clone(&inside), Arc::clone(&attempted));
        std::thread::spawn(move || {
            CertificationRegistry::update(&path, |registry| {
                inside.wait();
                attempted.wait();
                registry.dispute(
                    &artifact_id,
                    &CertificationDisputeRequest {
                        state: CertificationDisputeState::Open,
                        note: Some("under review".to_string()),
                        updated_at: Some(PUBLISHED_AT + 2),
                    },
                )
            })
            .map_err(|error| error.to_string())
        })
    };
    inside.wait();
    let before = std::fs::read(&path)?;
    let overlapping = revoke(&path, &artifact_id);
    assert!(
        matches!(overlapping, Err(RegistryUpdateError::Busy)),
        "{overlapping:?}"
    );
    assert_eq!(std::fs::read(&path)?, before);
    attempted.wait();
    disputer.join().map_err(|_| "disputer panicked")??;
    revoke(&path, &artifact_id)?;

    // A publish overlapping a later write is busy too, and its retry keeps
    // the revocation.
    let fresh = published_entry(
        artifact("tool-server-writer-lock-fresh", 0)?,
        PUBLISHED_AT + 9,
    )?;
    let fresh_id = fresh.artifact_id.clone();
    let inside = Arc::new(Barrier::new(2));
    let attempted = Arc::new(Barrier::new(2));
    let revoker = {
        let (path, artifact_id) = (path.clone(), artifact_id.clone());
        let (inside, attempted) = (Arc::clone(&inside), Arc::clone(&attempted));
        std::thread::spawn(move || {
            CertificationRegistry::update(&path, |registry| {
                inside.wait();
                attempted.wait();
                registry.revoke(&artifact_id, Some("confirmed"), Some(PUBLISHED_AT + 8))
            })
            .map_err(|error| error.to_string())
        })
    };
    inside.wait();
    let publish = |path: &Path, fresh: CertificationRegistryEntry| {
        CertificationRegistry::update(path, |registry| {
            registry.artifacts.insert(fresh.artifact_id.clone(), fresh);
            Ok(())
        })
    };
    assert!(matches!(
        publish(&path, fresh.clone()),
        Err(RegistryUpdateError::Busy)
    ));
    attempted.wait();
    revoker.join().map_err(|_| "revoker panicked")??;
    publish(&path, fresh)?;

    let reopened = CertificationRegistry::load(&path)?;
    let revoked = reopened.get(&artifact_id).ok_or("entry kept")?;
    assert_eq!(revoked.status, CertificationRegistryState::Revoked);
    assert_eq!(revoked.revoked_reason.as_deref(), Some("confirmed"));
    assert_eq!(
        revoked.dispute.as_ref().map(|dispute| dispute.state),
        Some(CertificationDisputeState::Open)
    );
    assert_eq!(
        status(&path, &fresh_id)?,
        Some(CertificationRegistryState::Active)
    );
    Ok(())
}
