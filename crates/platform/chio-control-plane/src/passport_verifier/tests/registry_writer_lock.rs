//! The passport status registry has one writer at a time: an overlapping
//! update is refused as busy instead of replacing a newer file with an older
//! copy.

use std::sync::{Arc, Barrier};

use super::test_fixtures::{passport_issued_at, Fallible};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ISSUED_AT: u64 = 1_730_000_000;
const PUBLISHED_AT: u64 = ISSUED_AT + 60;

/// A registry at `path` holding one published record, whose id is returned.
fn one_published(path: &Path) -> Fallible<String> {
    let passport = passport_issued_at(111, ISSUED_AT)?;
    let record = PassportStatusRegistry::update(path, |registry| {
        registry.publish(
            &passport,
            PUBLISHED_AT,
            PassportStatusDistribution::default(),
        )
    })?;
    Ok(record.passport_id)
}

fn revoke(path: &Path, passport_id: &str) -> Result<PassportLifecycleRecord, RegistryUpdateError> {
    PassportStatusRegistry::update(path, |registry| {
        registry.revoke(passport_id, Some("compromised"), Some(PUBLISHED_AT + 5))
    })
}

fn status(path: &Path, passport_id: &str) -> Fallible<Option<PassportLifecycleState>> {
    Ok(PassportStatusRegistry::load(path)?
        .get(passport_id)
        .map(|record| record.status))
}

#[test]
fn an_update_overlapping_a_publish_is_busy_and_the_revocation_persists_on_retry() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let passport_id = one_published(&path)?;
    let fresh = passport_issued_at(112, ISSUED_AT)?;
    let inside = Arc::new(Barrier::new(2));
    let attempted = Arc::new(Barrier::new(2));
    let publisher = {
        let (path, inside, attempted) = (path.clone(), Arc::clone(&inside), Arc::clone(&attempted));
        std::thread::spawn(move || {
            PassportStatusRegistry::update(&path, |registry| {
                inside.wait();
                attempted.wait();
                registry.publish(
                    &fresh,
                    PUBLISHED_AT + 10,
                    PassportStatusDistribution::default(),
                )
            })
            .map(|record| record.passport_id)
            .map_err(|error| error.to_string())
        })
    };
    inside.wait();
    let before = fs::read(&path)?;
    let overlapping = revoke(&path, &passport_id);
    assert!(
        matches!(overlapping, Err(RegistryUpdateError::Busy)),
        "{overlapping:?}"
    );
    assert_eq!(fs::read(&path)?, before);
    attempted.wait();
    let published = publisher.join().map_err(|_| "publisher panicked")??;

    revoke(&path, &passport_id)?;
    assert_eq!(
        status(&path, &passport_id)?,
        Some(PassportLifecycleState::Revoked)
    );
    assert_eq!(
        status(&path, &published)?,
        Some(PassportLifecycleState::Active)
    );
    Ok(())
}

#[test]
fn a_publish_overlapping_a_revocation_is_busy_and_never_reverts_it() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let passport_id = one_published(&path)?;
    let inside = Arc::new(Barrier::new(2));
    let attempted = Arc::new(Barrier::new(2));
    let revoker = {
        let (path, passport_id) = (path.clone(), passport_id.clone());
        let (inside, attempted) = (Arc::clone(&inside), Arc::clone(&attempted));
        std::thread::spawn(move || {
            PassportStatusRegistry::update(&path, |registry| {
                inside.wait();
                attempted.wait();
                registry.revoke(&passport_id, Some("compromised"), Some(PUBLISHED_AT + 5))
            })
            .map_err(|error| error.to_string())
        })
    };
    inside.wait();
    let fresh = passport_issued_at(113, ISSUED_AT)?;
    let publish = |path: &Path| {
        PassportStatusRegistry::update(path, |registry| {
            registry.publish(
                &fresh,
                PUBLISHED_AT + 10,
                PassportStatusDistribution::default(),
            )
        })
    };
    assert!(matches!(publish(&path), Err(RegistryUpdateError::Busy)));
    attempted.wait();
    revoker.join().map_err(|_| "revoker panicked")??;

    let published = publish(&path)?;
    assert_eq!(
        status(&path, &passport_id)?,
        Some(PassportLifecycleState::Revoked)
    );
    assert_eq!(
        status(&path, &published.passport_id)?,
        Some(PassportLifecycleState::Active)
    );
    Ok(())
}
