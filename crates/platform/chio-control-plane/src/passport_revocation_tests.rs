use std::path::Path;

use chio_core::Keypair;
use chio_credentials::{
    PassportLifecycleRecord, PassportLifecycleState, PassportStatusDistribution,
};
use chio_revocation_oracle::{passport_revocation_key, SqliteRevocationOracle};

use super::{check_passport_revocation, passport_revocation_oracle_path, revoke_passport_status};
use crate::passport_verifier::{PassportStatusRegistry, RegistryUpdateError};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PASSPORT: &str = "sha256:passport-revocation-oracle";

fn did(seed: u8) -> Result<String, Box<dyn std::error::Error>> {
    Ok(
        chio_did::DidChio::from_public_key(Keypair::from_seed(&[seed; 32]).public_key())?
            .to_string(),
    )
}

fn seed_registry(path: &Path) -> TestResult {
    let record = PassportLifecycleRecord {
        passport_id: PASSPORT.to_owned(),
        subject: did(3)?,
        issuers: vec![did(4)?],
        issuer_count: 1,
        published_at: 1_000,
        updated_at: 1_000,
        status: PassportLifecycleState::Active,
        superseded_by: None,
        revoked_at: None,
        revoked_reason: None,
        distribution: PassportStatusDistribution::default(),
        valid_until: "2099-01-01T00:00:00Z".to_owned(),
    };
    PassportStatusRegistry::update(path, |registry| {
        registry.passports.insert(PASSPORT.to_owned(), record);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn a_revocation_is_recorded_in_the_oracle_and_the_registry() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("passport-statuses.json");
    seed_registry(&path)?;

    let record = revoke_passport_status(&path, PASSPORT, Some("compromised"), Some(2_000))?;
    assert_eq!(record.status, PassportLifecycleState::Revoked);
    assert_eq!(
        passport_revocation_oracle_path(&path)?,
        dir.path()
            .join("passport-statuses.json.revocations.sqlite3")
    );
    let oracle = SqliteRevocationOracle::open(&passport_revocation_oracle_path(&path)?)?;
    assert!(oracle.is_revoked(&passport_revocation_key(PASSPORT))?);

    let resolution = PassportStatusRegistry::load(&path)?.resolve_at(PASSPORT, 3_000);
    assert_eq!(resolution.state, PassportLifecycleState::Revoked);
    check_passport_revocation(&path, &resolution)?;

    let again = revoke_passport_status(&path, PASSPORT, Some("compromised"), Some(2_000))?;
    assert_eq!(again.status, PassportLifecycleState::Revoked);
    assert_eq!(oracle.current_epoch_root()?.leaf_count, 1);
    Ok(())
}

#[test]
fn an_active_resolution_is_refused_once_the_oracle_holds_the_revocation() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("passport-statuses.json");
    seed_registry(&path)?;
    let active = PassportStatusRegistry::load(&path)?.resolve_at(PASSPORT, 3_000);
    assert_eq!(active.state, PassportLifecycleState::Active);
    check_passport_revocation(&path, &active)?;

    SqliteRevocationOracle::open(&passport_revocation_oracle_path(&path)?)?
        .revoke(passport_revocation_key(PASSPORT), 2_000)?;

    let error = check_passport_revocation(&path, &active)
        .err()
        .ok_or("an oracle revocation must refuse the active resolution")?;
    assert!(error.to_string().contains(&format!(
        "passport `{PASSPORT}` is revoked in the passport revocation oracle"
    )));
    Ok(())
}

#[test]
fn an_unreadable_oracle_refuses_resolution() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("passport-statuses.json");
    seed_registry(&path)?;
    std::fs::create_dir(passport_revocation_oracle_path(&path)?)?;
    let active = PassportStatusRegistry::load(&path)?.resolve_at(PASSPORT, 3_000);

    let error = check_passport_revocation(&path, &active)
        .err()
        .ok_or("an unreadable oracle must refuse")?;
    assert!(error
        .to_string()
        .contains("passport revocation oracle unavailable"));
    let refused = revoke_passport_status(&path, PASSPORT, None, Some(2_000))
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
            .resolve_at(PASSPORT, 3_000)
            .state,
        PassportLifecycleState::Active
    );
    Ok(())
}
