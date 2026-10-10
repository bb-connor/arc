use std::error::Error;
use std::sync::{Arc, Barrier};
use std::thread;

use chio_core::Keypair;
use chio_security_types::ports::{Digest32, PortErrorKind, RecordId};
use chio_security_types::{
    EnterpriseMigrationCasOutcome, EnterpriseMigrationControl, EnterpriseMigrationKey,
    EnterpriseMigrationMinimumHead, EnterpriseMigrationRegisterOutcome,
    EnterpriseMigrationScopeKind, EnterpriseMigrationStage, EnterpriseMigrationState,
    EnterpriseMigrationStateStore, EnterpriseMigrationTransition,
    EnterpriseMigrationTransitionBody, EnterpriseRuntimeBindingError,
    ENTERPRISE_MIGRATION_TRANSITION_SIGNATURE_DOMAIN,
};
use chio_store_sqlite::{
    enterprise_migration_transition_digest, sign_enterprise_migration_transition,
    SqliteEnterpriseMigrationOpenPolicy, SqliteEnterpriseMigrationStateStore,
    SqliteEnterpriseMigrationStateStoreError,
};
use rusqlite::{params, Connection};

type TestResult = Result<(), Box<dyn Error>>;

fn test_path(
    directory: &tempfile::TempDir,
    file_name: &str,
) -> Result<std::path::PathBuf, std::io::Error> {
    Ok(std::fs::canonicalize(directory.path())?.join(file_name))
}

fn migration_key() -> Result<EnterpriseMigrationKey, Box<dyn Error>> {
    Ok(EnterpriseMigrationKey {
        deployment_id: RecordId::new("production.us-east-1")?,
        scope_kind: EnterpriseMigrationScopeKind::Provider,
        scope_id: RecordId::new("provider.payments")?,
        control: EnterpriseMigrationControl::BrokerCredentialCustody,
    })
}

const fn digest(byte: u8) -> Digest32 {
    Digest32::new([byte; 32])
}

fn signer() -> Keypair {
    Keypair::from_seed(&[0x51; 32])
}

fn policy(
    signer: &Keypair,
    minimum_heads: Vec<EnterpriseMigrationMinimumHead>,
) -> Result<SqliteEnterpriseMigrationOpenPolicy, SqliteEnterpriseMigrationStateStoreError> {
    SqliteEnterpriseMigrationOpenPolicy::new(vec![signer.public_key()], minimum_heads)
}

fn genesis(
    key: EnterpriseMigrationKey,
    signer: &Keypair,
) -> Result<EnterpriseMigrationTransition, Box<dyn Error>> {
    let body = EnterpriseMigrationTransitionBody::genesis(
        key,
        digest(1),
        digest(2),
        digest(3),
        digest(4),
        100,
        signer.public_key().to_hex(),
    )?;
    Ok(sign_enterprise_migration_transition(body, signer)?)
}

fn promotion(
    prior: &EnterpriseMigrationState,
    signer: &Keypair,
    seed: u8,
    trusted_at_unix_ms: u64,
) -> Result<EnterpriseMigrationTransition, Box<dyn Error>> {
    let body = EnterpriseMigrationTransitionBody::promotion(
        prior,
        digest(seed),
        digest(seed.wrapping_add(1)),
        digest(seed.wrapping_add(2)),
        digest(seed.wrapping_add(3)),
        trusted_at_unix_ms,
        signer.public_key().to_hex(),
    )?;
    Ok(sign_enterprise_migration_transition(body, signer)?)
}

fn register(
    store: &SqliteEnterpriseMigrationStateStore,
    transition: &EnterpriseMigrationTransition,
) -> Result<EnterpriseMigrationState, Box<dyn Error>> {
    match store.register(transition)? {
        EnterpriseMigrationRegisterOutcome::Registered(state) => Ok(state),
        EnterpriseMigrationRegisterOutcome::Existing(_)
        | EnterpriseMigrationRegisterOutcome::Conflict(_) => {
            Err("first registration did not append genesis".into())
        }
    }
}

fn promote(
    store: &SqliteEnterpriseMigrationStateStore,
    transition: &EnterpriseMigrationTransition,
) -> Result<EnterpriseMigrationState, Box<dyn Error>> {
    match store.compare_and_promote(transition)? {
        EnterpriseMigrationCasOutcome::Promoted(state) => Ok(state),
        EnterpriseMigrationCasOutcome::Conflict(_) => {
            Err("fresh promotion lost its compare-and-swap".into())
        }
    }
}

#[test]
fn signed_hash_linked_chain_survives_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let key = migration_key()?;
    let signer = signer();
    let store = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;

    let genesis = genesis(key.clone(), &signer)?;
    let disabled = register(&store, &genesis)?;
    assert_eq!(disabled.stage, EnterpriseMigrationStage::Disabled);
    assert_eq!(disabled.generation, disabled.stage.generation());
    assert_eq!(
        disabled.transition_digest,
        enterprise_migration_transition_digest(&genesis)?
    );

    let shadow_transition = promotion(&disabled, &signer, 10, 200)?;
    let shadow = promote(&store, &shadow_transition)?;
    assert_eq!(shadow.prior_head_digest, Some(disabled.transition_digest));
    assert_eq!(shadow.generation, shadow.stage.generation());

    let enforced_transition = promotion(&shadow, &signer, 20, 300)?;
    let enforced = promote(&store, &enforced_transition)?;
    assert!(enforced.stage.operational_failure_must_deny());
    drop(store);

    let anchor = enforced.minimum_head();
    let reopened =
        SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, vec![anchor])?)?;
    let persisted = reopened
        .load(&key)?
        .ok_or("registered migration state was absent after reopen")?;
    assert_eq!(persisted, enforced);
    assert_eq!(
        persisted.runtime_binding(EnterpriseMigrationStage::Enforced, digest(20)),
        Ok(())
    );
    Ok(())
}

#[test]
fn runtime_binding_rejects_downgrade_advance_and_posture_rebinding() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let signer = signer();
    let store = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;
    let disabled = register(&store, &genesis(migration_key()?, &signer)?)?;
    let shadow = promote(&store, &promotion(&disabled, &signer, 10, 200)?)?;

    assert_eq!(
        shadow.runtime_binding(EnterpriseMigrationStage::Disabled, digest(10)),
        Err(EnterpriseRuntimeBindingError::DowngradeAttempt)
    );
    assert_eq!(
        shadow.runtime_binding(EnterpriseMigrationStage::Enforced, digest(10)),
        Err(EnterpriseRuntimeBindingError::UncommittedAdvance)
    );
    assert_eq!(
        shadow.runtime_binding(EnterpriseMigrationStage::Shadow, digest(99)),
        Err(EnterpriseRuntimeBindingError::ConfigurationMismatch)
    );
    Ok(())
}

#[test]
fn duplicate_generation_is_classified_without_replace() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let signer = signer();
    let key = migration_key()?;
    let store = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;
    let first = genesis(key.clone(), &signer)?;
    let disabled = register(&store, &first)?;

    let duplicate = store.register(&first)?;
    assert!(matches!(
        duplicate,
        EnterpriseMigrationRegisterOutcome::Existing(_)
    ));

    let conflicting_body = EnterpriseMigrationTransitionBody::genesis(
        key,
        digest(40),
        digest(41),
        digest(42),
        digest(43),
        101,
        signer.public_key().to_hex(),
    )?;
    let conflicting = sign_enterprise_migration_transition(conflicting_body, &signer)?;
    assert!(matches!(
        store.register(&conflicting)?,
        EnterpriseMigrationRegisterOutcome::Conflict(_)
    ));
    assert_eq!(
        store.load(&disabled.key)?.ok_or("genesis disappeared")?,
        disabled
    );
    Ok(())
}

#[test]
fn valid_signature_from_untrusted_signer_is_rejected() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let trusted = signer();
    let untrusted = Keypair::from_seed(&[0x72; 32]);
    let store = SqliteEnterpriseMigrationStateStore::open(&path, policy(&trusted, Vec::new())?)?;
    let transition = genesis(migration_key()?, &untrusted)?;
    let error = store
        .register(&transition)
        .err()
        .ok_or("untrusted transition signer was accepted")?;
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    Ok(())
}

#[test]
fn two_connections_race_one_promotion_and_one_conflict() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let signer = signer();
    let first = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;
    let disabled = register(&first, &genesis(migration_key()?, &signer)?)?;
    let second = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;
    let left_transition = promotion(&disabled, &signer, 10, 200)?;
    let right_transition = promotion(&disabled, &signer, 30, 201)?;
    let barrier = Arc::new(Barrier::new(2));
    let left_barrier = Arc::clone(&barrier);
    let right_barrier = Arc::clone(&barrier);

    let left = thread::spawn(move || {
        left_barrier.wait();
        first.compare_and_promote(&left_transition)
    });
    let right = thread::spawn(move || {
        right_barrier.wait();
        second.compare_and_promote(&right_transition)
    });
    let left = left
        .join()
        .map_err(|_| "left race participant panicked")??;
    let right = right
        .join()
        .map_err(|_| "right race participant panicked")??;
    let left_counts = match left {
        EnterpriseMigrationCasOutcome::Promoted(_) => (1, 0),
        EnterpriseMigrationCasOutcome::Conflict(_) => (0, 1),
    };
    let right_counts = match right {
        EnterpriseMigrationCasOutcome::Promoted(_) => (1, 0),
        EnterpriseMigrationCasOutcome::Conflict(_) => (0, 1),
    };
    assert_eq!(left_counts.0 + right_counts.0, 1);
    assert_eq!(left_counts.1 + right_counts.1, 1);
    Ok(())
}

#[test]
fn raw_sql_cannot_skip_update_or_delete() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let signer = signer();
    let key = migration_key()?;
    let store = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;
    let disabled = register(&store, &genesis(key.clone(), &signer)?)?;

    let connection = Connection::open(&path)?;
    assert!(connection
        .execute(
            "UPDATE enterprise_migration_transitions SET posture_digest = ?1",
            params![digest(90).as_bytes().as_slice()],
        )
        .is_err());
    assert!(connection
        .execute("DELETE FROM enterprise_migration_transitions", [])
        .is_err());
    let skipped = connection.execute(
        r#"
        INSERT INTO enterprise_migration_transitions (
            deployment_id, scope_kind, scope_id, control, signature_domain,
            schema_version, generation, from_stage, to_stage, prior_head_digest,
            posture_digest, evidence_digest, authorization_digest, intent_digest,
            trusted_at_unix_ms, signer_public_key, signature, transition_digest
        ) VALUES (?1, 'provider', ?2, 'broker_credential_custody', ?3,
                  1, 2, 1, 2, ?4, ?5, ?6, ?7, ?8, 300, ?9, ?10, ?11)
        "#,
        params![
            key.deployment_id.as_str(),
            key.scope_id.as_str(),
            ENTERPRISE_MIGRATION_TRANSITION_SIGNATURE_DOMAIN,
            disabled.transition_digest.as_bytes().as_slice(),
            digest(50).as_bytes().as_slice(),
            digest(51).as_bytes().as_slice(),
            digest(52).as_bytes().as_slice(),
            digest(53).as_bytes().as_slice(),
            signer.public_key().to_hex(),
            "00".repeat(64),
            digest(54).as_bytes().as_slice(),
        ],
    );
    assert!(skipped.is_err());

    let current = store.load(&key)?.ok_or("genesis disappeared")?;
    assert_eq!(current, disabled);
    Ok(())
}

#[test]
fn load_rejects_raw_append_with_invalid_signature() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let signer = signer();
    let key = migration_key()?;
    let store = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;
    let disabled = register(&store, &genesis(key.clone(), &signer)?)?;

    let connection = Connection::open(&path)?;
    connection.execute(
        r#"
        INSERT INTO enterprise_migration_transitions (
            deployment_id, scope_kind, scope_id, control, signature_domain,
            schema_version, generation, from_stage, to_stage, prior_head_digest,
            posture_digest, evidence_digest, authorization_digest, intent_digest,
            trusted_at_unix_ms, signer_public_key, signature, transition_digest
        ) VALUES (?1, 'provider', ?2, 'broker_credential_custody', ?3,
                  1, 1, 0, 1, ?4, ?5, ?6, ?7, ?8, 200, ?9, ?10, ?11)
        "#,
        params![
            key.deployment_id.as_str(),
            key.scope_id.as_str(),
            ENTERPRISE_MIGRATION_TRANSITION_SIGNATURE_DOMAIN,
            disabled.transition_digest.as_bytes().as_slice(),
            digest(60).as_bytes().as_slice(),
            digest(61).as_bytes().as_slice(),
            digest(62).as_bytes().as_slice(),
            digest(63).as_bytes().as_slice(),
            signer.public_key().to_hex(),
            "00".repeat(64),
            digest(64).as_bytes().as_slice(),
        ],
    )?;
    let error = store
        .load(&key)
        .err()
        .ok_or("invalid raw signature unexpectedly verified")?;
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    Ok(())
}

#[test]
fn independently_anchored_head_rejects_valid_restored_prefix() -> TestResult {
    let directory = tempfile::tempdir()?;
    let prefix_path = test_path(&directory, "prefix.sqlite3")?;
    let current_path = test_path(&directory, "current.sqlite3")?;
    let signer = signer();
    let key = migration_key()?;
    let genesis = genesis(key.clone(), &signer)?;

    let prefix =
        SqliteEnterpriseMigrationStateStore::open(&prefix_path, policy(&signer, Vec::new())?)?;
    register(&prefix, &genesis)?;
    drop(prefix);

    let current =
        SqliteEnterpriseMigrationStateStore::open(&current_path, policy(&signer, Vec::new())?)?;
    let disabled = register(&current, &genesis)?;
    let shadow = promote(&current, &promotion(&disabled, &signer, 10, 200)?)?;
    drop(current);

    let anchor = shadow.minimum_head();
    let reopened =
        SqliteEnterpriseMigrationStateStore::open(&prefix_path, policy(&signer, vec![anchor])?);
    assert!(matches!(
        reopened,
        Err(SqliteEnterpriseMigrationStateStoreError::Integrity)
    ));
    Ok(())
}

#[test]
fn schema_trigger_removal_is_detected_before_load() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let signer = signer();
    let key = migration_key()?;
    let store = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;
    register(&store, &genesis(key.clone(), &signer)?)?;

    let connection = Connection::open(&path)?;
    connection.execute_batch("DROP TRIGGER enterprise_migration_transitions_no_delete")?;
    let error = store
        .load(&key)
        .err()
        .ok_or("load ignored a removed authority trigger")?;
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    drop(store);
    drop(connection);
    assert!(matches!(
        SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?),
        Err(SqliteEnterpriseMigrationStateStoreError::Integrity)
    ));
    Ok(())
}

#[test]
fn legacy_mutable_row_authority_is_rejected() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TABLE enterprise_migration_state (deployment_id TEXT PRIMARY KEY)",
    )?;
    drop(connection);

    let signer = signer();
    assert!(matches!(
        SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?),
        Err(SqliteEnterpriseMigrationStateStoreError::Integrity)
    ));
    Ok(())
}

#[test]
fn volatile_and_relative_paths_are_rejected() -> TestResult {
    let signer = signer();
    assert!(matches!(
        SqliteEnterpriseMigrationOpenPolicy::new(Vec::new(), Vec::new()),
        Err(SqliteEnterpriseMigrationStateStoreError::MissingTrustedSigner)
    ));
    assert!(matches!(
        SqliteEnterpriseMigrationStateStore::open(":memory:", policy(&signer, Vec::new())?),
        Err(SqliteEnterpriseMigrationStateStoreError::VolatilePath)
    ));
    assert!(matches!(
        SqliteEnterpriseMigrationStateStore::open(
            "file:enterprise-migration.sqlite3?mode=memory",
            policy(&signer, Vec::new())?
        ),
        Err(SqliteEnterpriseMigrationStateStoreError::VolatilePath)
    ));
    assert!(matches!(
        SqliteEnterpriseMigrationStateStore::open(
            "enterprise-migration.sqlite3",
            policy(&signer, Vec::new())?
        ),
        Err(SqliteEnterpriseMigrationStateStoreError::VolatilePath)
    ));

    let directory = tempfile::tempdir()?;
    let missing_path = test_path(&directory, "missing-anchored.sqlite3")?;
    let missing_anchor = EnterpriseMigrationMinimumHead {
        key: migration_key()?,
        minimum_generation: 0,
        transition_digest: digest(99),
    };
    assert!(matches!(
        SqliteEnterpriseMigrationStateStore::open(
            &missing_path,
            policy(&signer, vec![missing_anchor])?
        ),
        Err(SqliteEnterpriseMigrationStateStoreError::Integrity)
    ));
    assert!(!missing_path.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_hardlink_and_live_path_replacement_are_rejected() -> TestResult {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let signer = signer();
    let base = std::fs::canonicalize(directory.path())?;
    let real_directory = base.join("real");
    std::fs::create_dir(&real_directory)?;
    let linked_directory = base.join("linked");
    symlink(&real_directory, &linked_directory)?;
    assert!(matches!(
        SqliteEnterpriseMigrationStateStore::open(
            linked_directory.join("migration.sqlite3"),
            policy(&signer, Vec::new())?
        ),
        Err(SqliteEnterpriseMigrationStateStoreError::UnsafePath)
    ));

    let hardlink_path = base.join("hardlink.sqlite3");
    let store =
        SqliteEnterpriseMigrationStateStore::open(&hardlink_path, policy(&signer, Vec::new())?)?;
    drop(store);
    std::fs::hard_link(&hardlink_path, base.join("second-link.sqlite3"))?;
    assert!(matches!(
        SqliteEnterpriseMigrationStateStore::open(&hardlink_path, policy(&signer, Vec::new())?),
        Err(SqliteEnterpriseMigrationStateStoreError::HardLinkedPath)
    ));

    let live_path = base.join("live.sqlite3");
    let live = SqliteEnterpriseMigrationStateStore::open(&live_path, policy(&signer, Vec::new())?)?;
    let key = migration_key()?;
    register(&live, &genesis(key.clone(), &signer)?)?;
    std::fs::rename(&live_path, base.join("displaced.sqlite3"))?;
    std::fs::copy(&hardlink_path, &live_path)?;
    let error = live
        .load(&key)
        .err()
        .ok_or("live store ignored replacement of its database path")?;
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    Ok(())
}
