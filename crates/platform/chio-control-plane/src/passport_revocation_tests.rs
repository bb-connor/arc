use std::path::Path;

use chio_credentials::{
    passport_credential_digests, present_agent_passport, AgentPassport, PassportLifecycleRecord,
    PassportLifecycleState, PassportPresentationOptions, PassportStatusDistribution,
};
use chio_revocation_oracle::{
    credential_revocation_key, passport_revocation_key, PassportRevocationLeaf,
    PassportRevocationLeafKind, SqliteRevocationOracle,
};

use super::{check_passport_revocation, passport_revocation_oracle_path, revoke_passport_status};
use crate::passport_verifier::test_fixtures::passport_from_issuers;
use crate::passport_verifier::{PassportStatusRegistry, RegistryUpdateError};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

const ISSUED_AT: u64 = 1_710_000_000;
const PUBLISHED_AT: u64 = ISSUED_AT + 10;
const REVOKED_AT: u64 = PUBLISHED_AT + 20;
const NOW: u64 = PUBLISHED_AT + 60;

fn passport() -> Fallible<AgentPassport> {
    passport_from_issuers(3, &[4, 5], ISSUED_AT)
}

fn publish(path: &Path, passport: &AgentPassport) -> Fallible<PassportLifecycleRecord> {
    Ok(PassportStatusRegistry::update(path, |registry| {
        registry.publish(passport, PUBLISHED_AT, PassportStatusDistribution::default())
    })?)
}

fn oracle_leaves(path: &Path) -> Fallible<Vec<PassportRevocationLeaf>> {
    let oracle = SqliteRevocationOracle::open(&passport_revocation_oracle_path(path)?)?;
    Ok(oracle
        .leaves_after(0, 64)?
        .iter()
        .map(PassportRevocationLeaf::from_oracle_leaf)
        .collect::<Result<Vec<_>, _>>()?)
}

#[test]
fn a_published_record_carries_one_digest_per_credential() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("passport-statuses.json");
    let passport = passport()?;
    let record = publish(&path, &passport)?;
    assert_eq!(record.credential_digests.len(), 2);
    assert_eq!(
        record.credential_digests,
        passport_credential_digests(&passport)?
    );
    assert_eq!(
        PassportStatusRegistry::load(&path)?
            .get(&record.passport_id)
            .map(|loaded| loaded.credential_digests.clone()),
        Some(record.credential_digests)
    );
    Ok(())
}

#[test]
fn a_revocation_writes_the_passport_leaf_and_one_credential_leaf_per_digest() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("passport-statuses.json");
    let record = publish(&path, &passport()?)?;

    let revoked = revoke_passport_status(
        &path,
        &record.passport_id,
        Some("compromised"),
        Some(REVOKED_AT),
        NOW,
    )?;
    assert_eq!(revoked.status, PassportLifecycleState::Revoked);
    assert_eq!(
        passport_revocation_oracle_path(&path)?,
        dir.path()
            .join("passport-statuses.json.revocations.sqlite3")
    );
    let mut expected = vec![PassportRevocationLeaf {
        seq: 1,
        kind: PassportRevocationLeafKind::Passport,
        subject: record.passport_id.clone(),
    }];
    for (seq, digest) in (2..).zip(&record.credential_digests) {
        expected.push(PassportRevocationLeaf {
            seq,
            kind: PassportRevocationLeafKind::Credential,
            subject: digest.clone(),
        });
    }
    assert_eq!(oracle_leaves(&path)?, expected);

    let resolution = PassportStatusRegistry::load(&path)?.resolve_at(&record.passport_id, NOW);
    assert_eq!(resolution.state, PassportLifecycleState::Revoked);
    check_passport_revocation(&path, &resolution, &record.credential_digests)?;

    let again = revoke_passport_status(
        &path,
        &record.passport_id,
        Some("compromised"),
        Some(REVOKED_AT),
        NOW,
    )?;
    assert_eq!(again.status, PassportLifecycleState::Revoked);
    assert_eq!(oracle_leaves(&path)?, expected);
    Ok(())
}

#[test]
fn a_filtered_view_of_a_revoked_passport_is_refused_by_the_local_oracle() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("passport-statuses.json");
    let passport = passport()?;
    let record = publish(&path, &passport)?;
    revoke_passport_status(&path, &record.passport_id, None, Some(REVOKED_AT), NOW)?;

    let kept = passport
        .credentials
        .first()
        .map(|credential| credential.unsigned.issuer.clone())
        .ok_or("a passport carries a credential")?;
    let filtered = present_agent_passport(
        &passport,
        &PassportPresentationOptions {
            issuer_allowlist: [kept].into_iter().collect(),
            max_credentials: None,
        },
    )?;
    let resolution = PassportStatusRegistry::load(&path)?.resolve_for_passport(&filtered, NOW)?;
    assert_eq!(resolution.state, PassportLifecycleState::NotFound);
    assert_ne!(resolution.passport_id, record.passport_id);

    let error = check_passport_revocation(
        &path,
        &resolution,
        &passport_credential_digests(&filtered)?,
    )
    .err()
    .ok_or("a revoked credential must refuse the filtered view")?;
    assert!(
        error
            .to_string()
            .contains("is revoked in the passport revocation oracle"),
        "{error}"
    );
    Ok(())
}

#[test]
fn an_active_resolution_is_refused_once_the_oracle_holds_the_revocation() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("passport-statuses.json");
    let record = publish(&path, &passport()?)?;
    let active = PassportStatusRegistry::load(&path)?.resolve_at(&record.passport_id, NOW);
    assert_eq!(active.state, PassportLifecycleState::Active);
    check_passport_revocation(&path, &active, &record.credential_digests)?;

    let oracle = SqliteRevocationOracle::open(&passport_revocation_oracle_path(&path)?)?;
    oracle.revoke(passport_revocation_key(&record.passport_id), REVOKED_AT)?;
    let error = check_passport_revocation(&path, &active, &record.credential_digests)
        .err()
        .ok_or("an oracle revocation must refuse the active resolution")?;
    assert!(error.to_string().contains(&format!(
        "passport `{}` is revoked in the passport revocation oracle",
        record.passport_id
    )));
    Ok(())
}

#[test]
fn an_active_resolution_is_refused_once_one_of_its_credentials_is_revoked() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("passport-statuses.json");
    let record = publish(&path, &passport()?)?;
    let active = PassportStatusRegistry::load(&path)?.resolve_at(&record.passport_id, NOW);
    let digest = record
        .credential_digests
        .last()
        .ok_or("a record carries a digest")?;
    SqliteRevocationOracle::open(&passport_revocation_oracle_path(&path)?)?
        .revoke(credential_revocation_key(digest), REVOKED_AT)?;
    let error = check_passport_revocation(&path, &active, &record.credential_digests)
        .err()
        .ok_or("a revoked credential must refuse the active resolution")?;
    assert!(
        error.to_string().contains(&format!(
            "credential `{digest}` of passport `{}` is revoked in the passport revocation oracle",
            record.passport_id
        )),
        "{error}"
    );
    Ok(())
}

#[test]
fn a_revocation_dated_after_now_is_refused_before_the_oracle_is_written() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("passport-statuses.json");
    let record = publish(&path, &passport()?)?;

    let refused = revoke_passport_status(&path, &record.passport_id, None, Some(NOW + 1), NOW)
        .err()
        .ok_or("a future revocation must be refused")?;
    assert!(
        matches!(refused, RegistryUpdateError::Refused(_)),
        "{refused}"
    );
    assert!(refused.to_string().contains("after the current time"), "{refused}");
    assert!(oracle_leaves(&path)?.is_empty());
    assert_eq!(
        PassportStatusRegistry::load(&path)?
            .resolve_at(&record.passport_id, NOW)
            .state,
        PassportLifecycleState::Active
    );

    let defaulted = revoke_passport_status(&path, &record.passport_id, None, None, NOW)?;
    assert_eq!(defaulted.revoked_at, Some(NOW));
    Ok(())
}

#[test]
fn a_revocation_before_publication_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("passport-statuses.json");
    let record = publish(&path, &passport()?)?;

    let refused = revoke_passport_status(
        &path,
        &record.passport_id,
        None,
        Some(PUBLISHED_AT - 1),
        NOW,
    )
    .err()
    .ok_or("a revocation before publication must be refused")?;
    assert!(
        matches!(refused, RegistryUpdateError::Refused(_)),
        "{refused}"
    );
    assert!(oracle_leaves(&path)?.is_empty());
    assert_eq!(
        PassportStatusRegistry::load(&path)?
            .resolve_at(&record.passport_id, NOW)
            .state,
        PassportLifecycleState::Active
    );
    Ok(())
}

#[test]
fn an_unreadable_oracle_refuses_resolution() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("passport-statuses.json");
    let record = publish(&path, &passport()?)?;
    std::fs::create_dir(passport_revocation_oracle_path(&path)?)?;
    let active = PassportStatusRegistry::load(&path)?.resolve_at(&record.passport_id, NOW);

    let error = check_passport_revocation(&path, &active, &record.credential_digests)
        .err()
        .ok_or("an unreadable oracle must refuse")?;
    assert!(error
        .to_string()
        .contains("passport revocation oracle unavailable"));
    let refused = revoke_passport_status(&path, &record.passport_id, None, Some(REVOKED_AT), NOW)
        .err()
        .ok_or("an unreadable oracle must refuse the revocation")?;
    assert!(
        matches!(refused, RegistryUpdateError::Refused(_)),
        "{refused}"
    );
    assert!(refused
        .to_string()
        .contains("passport revocation oracle unavailable"));
    assert_eq!(
        PassportStatusRegistry::load(&path)?
            .resolve_at(&record.passport_id, NOW)
            .state,
        PassportLifecycleState::Active
    );
    Ok(())
}
