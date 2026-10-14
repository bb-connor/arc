use std::error::Error;
use std::sync::{Arc, Barrier};
use std::thread;

use chio_core::Keypair;
use chio_security_types::ports::{Digest32, PortErrorKind, RecordId};
use chio_security_types::{
    EnterpriseMigrationControl, EnterpriseMigrationHead, EnterpriseMigrationKey,
    EnterpriseMigrationRegisterOutcome, EnterpriseMigrationRuntimeBinding,
    EnterpriseMigrationRuntimeError, EnterpriseMigrationScopeKind, EnterpriseMigrationState,
    EnterpriseMigrationStateStore, EnterpriseMigrationTransition,
    EnterpriseMigrationTransitionBody, ENTERPRISE_MIGRATION_TRANSITION_SIGNATURE_DOMAIN,
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
    heads: Vec<EnterpriseMigrationHead>,
) -> Result<SqliteEnterpriseMigrationOpenPolicy, SqliteEnterpriseMigrationStateStoreError> {
    SqliteEnterpriseMigrationOpenPolicy::new(vec![signer.public_key()], heads)
}

fn registration(
    key: EnterpriseMigrationKey,
    signer: &Keypair,
    seed: u8,
) -> Result<EnterpriseMigrationTransition, Box<dyn Error>> {
    let body = EnterpriseMigrationTransitionBody::enforced(
        key,
        digest(seed),
        digest(seed.wrapping_add(1)),
        digest(seed.wrapping_add(2)),
        digest(seed.wrapping_add(3)),
        100,
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
            Err("first registration did not append the enforced registration".into())
        }
    }
}

fn insert_raw_row(
    connection: &Connection,
    key: &EnterpriseMigrationKey,
    signer: &Keypair,
    seed: u8,
) -> rusqlite::Result<usize> {
    connection.execute(
        r#"
        INSERT INTO enterprise_migration_transitions (
            deployment_id, scope_kind, scope_id, control, signature_domain,
            schema_version, posture_digest, evidence_digest, authorization_digest,
            intent_digest, trusted_at_unix_ms, signer_public_key, signature,
            transition_digest
        ) VALUES (?1, 'provider', ?2, 'broker_credential_custody', ?3,
                  1, ?4, ?5, ?6, ?7, 200, ?8, ?9, ?10)
        "#,
        params![
            key.deployment_id.as_str(),
            key.scope_id.as_str(),
            ENTERPRISE_MIGRATION_TRANSITION_SIGNATURE_DOMAIN,
            digest(seed).as_bytes().as_slice(),
            digest(seed.wrapping_add(1)).as_bytes().as_slice(),
            digest(seed.wrapping_add(2)).as_bytes().as_slice(),
            digest(seed.wrapping_add(3)).as_bytes().as_slice(),
            signer.public_key().to_hex(),
            "00".repeat(64),
            digest(seed.wrapping_add(4)).as_bytes().as_slice(),
        ],
    )
}

#[test]
fn enforced_registration_survives_reopen_under_its_head() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let key = migration_key()?;
    let signer = signer();
    let store = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;

    let transition = registration(key.clone(), &signer, 1)?;
    let enforced = register(&store, &transition)?;
    assert_eq!(
        enforced.transition_digest,
        enterprise_migration_transition_digest(&transition)?
    );
    drop(store);

    let reopened =
        SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, vec![enforced.head()])?)?;
    let persisted = reopened
        .load(&key)?
        .ok_or("registered migration state was absent after reopen")?;
    assert_eq!(persisted, enforced);
    Ok(())
}

#[test]
fn runtime_binding_rejects_posture_rebinding_and_state_replacement() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let signer = signer();
    let key = migration_key()?;
    let store: Arc<dyn EnterpriseMigrationStateStore> = Arc::new(
        SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?,
    );
    let transition = registration(key.clone(), &signer, 1)?;
    store.register(&transition)?;

    assert_eq!(
        EnterpriseMigrationRuntimeBinding::load(&store, &key, digest(99))
            .err()
            .ok_or("a different posture bound")?,
        EnterpriseMigrationRuntimeError::PostureMismatch
    );
    let binding = EnterpriseMigrationRuntimeBinding::load(&store, &key, digest(1))?;
    binding.revalidate()?;

    let other_key = EnterpriseMigrationKey {
        scope_id: RecordId::new("provider.other")?,
        ..key
    };
    assert_eq!(
        EnterpriseMigrationRuntimeBinding::load(&store, &other_key, digest(1))
            .err()
            .ok_or("an unregistered key bound")?,
        EnterpriseMigrationRuntimeError::Unregistered
    );
    Ok(())
}

#[test]
fn duplicate_registration_is_classified_without_replace() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let signer = signer();
    let key = migration_key()?;
    let store = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;
    let first = registration(key.clone(), &signer, 1)?;
    let enforced = register(&store, &first)?;

    assert!(matches!(
        store.register(&first)?,
        EnterpriseMigrationRegisterOutcome::Existing(_)
    ));
    let conflicting = registration(key, &signer, 40)?;
    assert!(matches!(
        store.register(&conflicting)?,
        EnterpriseMigrationRegisterOutcome::Conflict(_)
    ));
    assert_eq!(
        store
            .load(&enforced.key)?
            .ok_or("registration disappeared")?,
        enforced
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
    let transition = registration(migration_key()?, &untrusted, 1)?;
    let error = store
        .register(&transition)
        .err()
        .ok_or("untrusted transition signer was accepted")?;
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    Ok(())
}

#[test]
fn two_connections_race_one_registration_and_one_conflict() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let signer = signer();
    let key = migration_key()?;
    let first = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;
    let second = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;
    let left_transition = registration(key.clone(), &signer, 10)?;
    let right_transition = registration(key, &signer, 30)?;
    let barrier = Arc::new(Barrier::new(2));
    let left_barrier = Arc::clone(&barrier);
    let right_barrier = Arc::clone(&barrier);

    let left = thread::spawn(move || {
        left_barrier.wait();
        first.register(&left_transition)
    });
    let right = thread::spawn(move || {
        right_barrier.wait();
        second.register(&right_transition)
    });
    let left = left
        .join()
        .map_err(|_| "left race participant panicked")??;
    let right = right
        .join()
        .map_err(|_| "right race participant panicked")??;
    let registered = [&left, &right]
        .iter()
        .filter(|outcome| matches!(outcome, EnterpriseMigrationRegisterOutcome::Registered(_)))
        .count();
    let conflicts = [&left, &right]
        .iter()
        .filter(|outcome| matches!(outcome, EnterpriseMigrationRegisterOutcome::Conflict(_)))
        .count();
    assert_eq!((registered, conflicts), (1, 1));
    Ok(())
}

#[test]
fn raw_sql_cannot_update_delete_or_add_a_second_registration() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let signer = signer();
    let key = migration_key()?;
    let store = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;
    let enforced = register(&store, &registration(key.clone(), &signer, 1)?)?;

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
    assert!(insert_raw_row(&connection, &key, &signer, 50).is_err());

    assert_eq!(
        store.load(&key)?.ok_or("registration disappeared")?,
        enforced
    );
    Ok(())
}

#[test]
fn load_rejects_raw_row_with_invalid_signature() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let signer = signer();
    let key = migration_key()?;
    let store = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;

    let connection = Connection::open(&path)?;
    insert_raw_row(&connection, &key, &signer, 60)?;
    let error = store
        .load(&key)
        .err()
        .ok_or("invalid raw signature unexpectedly verified")?;
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    Ok(())
}

#[test]
fn independently_anchored_head_rejects_another_valid_registration() -> TestResult {
    let directory = tempfile::tempdir()?;
    let restored_path = test_path(&directory, "restored.sqlite3")?;
    let current_path = test_path(&directory, "current.sqlite3")?;
    let signer = signer();
    let key = migration_key()?;

    let restored =
        SqliteEnterpriseMigrationStateStore::open(&restored_path, policy(&signer, Vec::new())?)?;
    register(&restored, &registration(key.clone(), &signer, 1)?)?;
    drop(restored);

    let current =
        SqliteEnterpriseMigrationStateStore::open(&current_path, policy(&signer, Vec::new())?)?;
    let enforced = register(&current, &registration(key, &signer, 10)?)?;
    drop(current);

    let reopened = SqliteEnterpriseMigrationStateStore::open(
        &restored_path,
        policy(&signer, vec![enforced.head()])?,
    );
    assert!(matches!(
        reopened,
        Err(SqliteEnterpriseMigrationStateStoreError::Integrity)
    ));
    Ok(())
}

#[test]
fn staged_transition_table_is_rejected() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TABLE enterprise_migration_transitions (\
             deployment_id TEXT NOT NULL, generation INTEGER NOT NULL, \
             to_stage INTEGER NOT NULL, PRIMARY KEY (deployment_id, generation)) STRICT",
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
fn schema_trigger_removal_is_detected_before_load() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = test_path(&directory, "enterprise-migration.sqlite3")?;
    let signer = signer();
    let key = migration_key()?;
    let store = SqliteEnterpriseMigrationStateStore::open(&path, policy(&signer, Vec::new())?)?;
    register(&store, &registration(key.clone(), &signer, 1)?)?;

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
fn retired_mutable_row_table_is_rejected() -> TestResult {
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
    let missing_anchor = EnterpriseMigrationHead {
        key: migration_key()?,
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
    register(&live, &registration(key.clone(), &signer, 1)?)?;
    std::fs::rename(&live_path, base.join("displaced.sqlite3"))?;
    std::fs::copy(&hardlink_path, &live_path)?;
    let error = live
        .load(&key)
        .err()
        .ok_or("live store ignored replacement of its database path")?;
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    Ok(())
}
