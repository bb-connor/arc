//! Revocation entries: deterministic ids, the stored catalog, and the global
//! commit chain kind that makes every entry restore-evident.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use chio_core::root_authority::{
    RevocationEntry, RevocationReason, RevocationTarget, RevocationTargetKind, Sha256Digest,
};
use chio_kernel::{RevocationStore, RevocationStoreError};
use rusqlite::{ffi, params, Connection, ErrorCode};

use super::{commit_mutation, SqliteRevocationStore};
use crate::serving_owner::{ProvisionedAuthority, SqliteServingOwnerError};
use crate::SqliteAuthorityStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const FIXED_REVOKED_AT: i64 = 1_792_234_800;

fn standalone(
) -> Result<(tempfile::TempDir, PathBuf, SqliteRevocationStore), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("revocations.db");
    let store = SqliteRevocationStore::open(&path)?;
    Ok((directory, path, store))
}

fn is_check_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(
            ffi::Error {
                code: ErrorCode::ConstraintViolation,
                extended_code: ffi::SQLITE_CONSTRAINT_CHECK,
            },
            _,
        )
    )
}

/// Commit one entry that names no capability, the way `revoke` commits: one
/// IMMEDIATE transaction, then the anchor sync.
fn record_unmatched_entry(
    store: &SqliteRevocationStore,
    target: &RevocationTarget,
) -> Result<(), RevocationStoreError> {
    let mut connection = store.connection()?;
    let transaction = store.begin_write(&mut connection)?;
    let (_, created) = store.record_revocation_entry(
        &transaction,
        target,
        FIXED_REVOKED_AT,
        RevocationReason::PolicyWithdrawn,
    )?;
    assert!(created, "the fixture target was already recorded");
    commit_mutation(store, transaction)?;
    if let Some(owner) = store.serving_owner.as_ref() {
        owner
            .sync_authority_anchor(&connection)
            .map_err(super::map_serving_owner_error)?;
    }
    Ok(())
}

fn rule_target() -> RevocationTarget {
    RevocationTarget::root_policy_rule("rule-fixture-1").expect("rule target")
}

fn reopen_serving(
    database: &Path,
    lock_root: &Path,
) -> Result<SqliteAuthorityStore, SqliteServingOwnerError> {
    SqliteAuthorityStore::open_serving_with_clock(
        database,
        lock_root,
        chio_test_support::clock::clock(),
    )
}

fn global_commits(
    database: &Path,
    projection_kind: &str,
) -> Result<Vec<(String, i64)>, rusqlite::Error> {
    let connection = Connection::open(database)?;
    let mut statement = connection.prepare(
        r#"
        SELECT projection_key, projection_sequence FROM authority_global_commits
        WHERE projection_kind = ?1 ORDER BY commit_sequence
        "#,
    )?;
    let rows = statement
        .query_map(params![projection_kind], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[test]
fn entry_ids_are_pinned_for_every_kind() -> TestResult {
    let pinned = [
        (
            RevocationTarget::capability("cap-fixture-1")?,
            "rev_9381c386951ff33d55040e8c800dc291d1f0344ae9f3a17d8fa7db722508adc8",
        ),
        (
            RevocationTarget::root_policy_rule("rule-fixture-1")?,
            "rev_7ce5fb5ee0bdd9f010497d335717f470897e89e6baca2419e1f9f072435a918d",
        ),
        (
            RevocationTarget::subject_tag(Sha256Digest::from_bytes([0x11; 32])),
            "rev_f8171fd98a477e7ffeb6749c46fc866add9cea7150e1fa52a1d46b1de9992f30",
        ),
        (
            RevocationTarget::tenant_tag(Sha256Digest::from_bytes([0x22; 32])),
            "rev_f371a93ba9f71ba9f4028991ca86d854f40ba252de25c46f929b4a49dad3d0ed",
        ),
        (
            RevocationTarget::replay_key(Sha256Digest::from_bytes([0x33; 32])),
            "rev_2c61bc4439fc093f379756475a05967f37fb94ad2edc1e3e40bb71ce048889b1",
        ),
    ];
    for (target, id) in pinned {
        assert_eq!(target.id().as_str(), id, "{:?}", target.kind());
    }
    Ok(())
}

#[test]
fn kind_is_part_of_the_id() -> TestResult {
    let capability = RevocationTarget::capability("cap-fixture-1")?;
    let rule = RevocationTarget::root_policy_rule("cap-fixture-1")?;
    assert_eq!(
        rule.id().as_str(),
        "rev_3a9b59c965d3ced107d9dd6c113e427affd5e4ff89932755c410454870257876"
    );
    assert_ne!(capability.id(), rule.id());
    Ok(())
}

#[test]
fn capability_revocation_records_and_names_one_entry() -> TestResult {
    let (_directory, _path, store) = standalone()?;
    assert!(store.revoke("cap-fixture-1")?);
    assert!(!store.revoke("cap-fixture-1")?);
    let target = RevocationTarget::capability("cap-fixture-1")?;
    assert_eq!(store.revocation_entry("cap-fixture-1")?, Some(target.id()));
    assert_eq!(store.revocation_entry("cap-fixture-2")?, None);
    let (page, head) = store.list_revocation_entries_after(0, 10, None)?;
    assert_eq!((page.len(), head), (1, 1));
    assert_eq!(page[0].0, 1);
    assert_eq!(page[0].1.entry_id, target.id());
    assert_eq!(page[0].1.target()?, target);
    assert_eq!(page[0].1.reason, RevocationReason::OperatorRequest);
    let (after_head, head) = store.list_revocation_entries_after(1, 10, None)?;
    assert_eq!((after_head, head), (Vec::new(), 1));
    let (other_kind, _) =
        store.list_revocation_entries_after(0, 10, Some(RevocationTargetKind::RootPolicyRule))?;
    assert_eq!(other_kind, Vec::new());
    Ok(())
}

#[test]
fn a_newer_replicated_revocation_keeps_the_first_entry() -> TestResult {
    let (_directory, _path, store) = standalone()?;
    let record = |revoked_at| chio_kernel::RevocationRecord {
        capability_id: "cap-replicated".to_string(),
        revoked_at,
    };
    assert!(store.upsert_revocation_if_newer(&record(FIXED_REVOKED_AT))?);
    assert!(store.upsert_revocation_if_newer(&record(FIXED_REVOKED_AT + 60))?);
    let (page, head) = store.list_revocation_entries_after(0, 10, None)?;
    assert_eq!(head, 1);
    assert_eq!(
        page,
        vec![(
            1,
            RevocationEntry::new(
                &RevocationTarget::capability("cap-replicated")?,
                1_792_234_800,
                RevocationReason::OperatorRequest,
            )?
        )]
    );
    Ok(())
}

#[test]
fn revoked_row_without_entry_refuses_open() -> TestResult {
    let (_directory, path, store) = standalone()?;
    assert!(store.revoke("cap-fixture-1")?);
    drop(store);
    let connection = Connection::open(&path)?;
    connection.execute_batch("PRAGMA foreign_keys = OFF;")?;
    connection.execute("DELETE FROM revocation_entries", [])?;
    drop(connection);

    let error = SqliteRevocationStore::open(&path)
        .err()
        .ok_or("a projection row without its entry opened")?;
    assert_eq!(
        error.to_string(),
        "revocation store synchronization error: sqlite foreign key violation in `revoked_capabilities` row 1"
    );
    Ok(())
}

#[test]
fn table_refuses_non_hex_tag_values_and_unknown_reasons() -> TestResult {
    let (_directory, path, store) = standalone()?;
    drop(store);
    let connection = Connection::open(&path)?;
    let insert = |entry_id: &str, kind: &str, value: &str, reason: &str| {
        connection.execute(
            r#"
            INSERT INTO revocation_entries (
                entry_id, target_kind, target_value, revoked_at, reason
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![entry_id, kind, value, FIXED_REVOKED_AT, reason],
        )
    };
    let entry_id = format!("rev_{}", "a".repeat(64));
    let upper_hex = "A".repeat(64);
    let short_hex = "a".repeat(63);
    for (kind, value, reason) in [
        ("anchor_subject", upper_hex.as_str(), "principal_offboarded"),
        ("tenant_tag", short_hex.as_str(), "tenant_offboarded"),
        ("replay_key", "not-a-digest", "credential_compromise"),
        ("capability_id", "cap-fixture-1", "because"),
        ("operator_note", "cap-fixture-1", "operator_request"),
    ] {
        let error = insert(&entry_id, kind, value, reason)
            .err()
            .ok_or("the catalog accepted an invalid entry")?;
        assert!(
            is_check_violation(&error),
            "{kind} {value} {reason}: {error}"
        );
    }
    for invalid_id in [
        "cap_".to_string() + &"a".repeat(64),
        "rev_".to_string() + &"A".repeat(64),
    ] {
        let error = insert(
            &invalid_id,
            "capability_id",
            "cap-fixture-1",
            "operator_request",
        )
        .err()
        .ok_or("the catalog accepted an invalid entry id")?;
        assert!(is_check_violation(&error), "{invalid_id}: {error}");
    }
    Ok(())
}

fn catalog(path: &Path) -> Result<Vec<(String, String, Option<String>)>, rusqlite::Error> {
    let connection = Connection::open(path)?;
    let mut statement =
        connection.prepare("SELECT type, name, sql FROM sqlite_schema ORDER BY type, name")?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[test]
fn a_catalog_missing_projection_tables_refuses_open_without_repair() -> TestResult {
    for (dropped, refusal) in [
        (
            "DROP TABLE revocation_entries;",
            "revocation store synchronization error: schema catalog differs from its canonical definition",
        ),
        (
            "DROP TABLE revoked_capabilities; DROP TABLE revocation_entries;",
            "sqlite error: no such table: revoked_capabilities",
        ),
    ] {
        let (_directory, path, store) = standalone()?;
        assert!(store.revoke("cap-fixture-1")?);
        drop(store);
        Connection::open(&path)?.execute_batch(&format!("PRAGMA foreign_keys = OFF; {dropped}"))?;
        let before = catalog(&path)?;
        assert!(
            before
                .iter()
                .any(|(_, name, _)| name == "revocation_delta_log"),
            "the rest of the revocation state is retained"
        );

        let error = SqliteRevocationStore::open(&path)
            .err()
            .ok_or("a catalog missing projection tables opened")?;
        assert_eq!(error.to_string(), refusal, "{dropped}");
        assert_eq!(
            catalog(&path)?,
            before,
            "{dropped}: the refused catalog is not repaired"
        );
    }
    Ok(())
}

#[test]
fn a_serving_catalog_missing_projection_tables_refuses_open_without_repair() -> TestResult {
    let fixture = ProvisionedAuthority::open();
    drop(fixture.authority);
    Connection::open(&fixture.database)?.execute_batch(
        "PRAGMA foreign_keys = OFF; DROP TABLE revoked_capabilities; DROP TABLE revocation_entries;",
    )?;
    let before = catalog(&fixture.database)?;

    let error = reopen_serving(&fixture.database, &fixture.lock_root)
        .err()
        .ok_or("a serving catalog missing projection tables opened")?;
    assert_eq!(
        error.to_string(),
        "invalid sqlite authority store: sqlite error: no such table: revoked_capabilities"
    );
    assert_eq!(
        catalog(&fixture.database)?,
        before,
        "the refused catalog is not repaired"
    );
    Ok(())
}

#[test]
fn a_reassigned_revocation_entry_refuses_serving_reopen() -> TestResult {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.revocation_store();
    assert!(store.revoke("cap-a")?);
    assert!(store.revoke("cap-b")?);
    drop(store);
    drop(fixture.authority);

    let reopened = reopen_serving(&fixture.database, &fixture.lock_root)?;
    let revocations = reopened.revocation_store();
    assert_eq!(
        revocations.revocation_entry("cap-a")?,
        Some(RevocationTarget::capability("cap-a")?.id())
    );
    assert_eq!(
        revocations.revocation_entry("cap-b")?,
        Some(RevocationTarget::capability("cap-b")?.id())
    );
    drop(revocations);
    drop(reopened);

    Connection::open(&fixture.database)?.execute(
        "UPDATE revoked_capabilities SET revocation_entry_id = ?1 WHERE capability_id = 'cap-a'",
        params![RevocationTarget::capability("cap-b")?.id().as_str()],
    )?;
    let error = reopen_serving(&fixture.database, &fixture.lock_root)
        .err()
        .ok_or("a reassigned revocation entry reopened")?;
    assert_eq!(
        error.to_string(),
        "invalid sqlite authority store: global authority commit lost its exact revocation projection"
    );
    Ok(())
}

#[test]
fn every_entry_advances_the_global_commit_chain() -> TestResult {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.revocation_store();
    assert!(store.revoke("cap-fixture-1")?);
    record_unmatched_entry(&store, &rule_target())?;

    let capability_entry = RevocationTarget::capability("cap-fixture-1")?.id();
    assert_eq!(
        global_commits(&fixture.database, "revocation_entry")?,
        vec![
            (capability_entry.as_str().to_string(), 1),
            (rule_target().id().as_str().to_string(), 2),
        ]
    );
    let connection = Connection::open(&fixture.database)?;
    let (entry_commit, row_commit): (i64, i64) = connection.query_row(
        r#"
        SELECT
            (SELECT commit_sequence FROM authority_global_commits
             WHERE projection_kind = 'revocation_entry' AND projection_key = ?1),
            (SELECT commit_sequence FROM authority_global_commits
             WHERE projection_kind = 'revocation' AND projection_key = 'cap-fixture-1')
        "#,
        params![capability_entry.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(row_commit, entry_commit + 1);
    drop(connection);
    drop(store);
    drop(fixture.authority);

    let reopened = reopen_serving(&fixture.database, &fixture.lock_root)?;
    let (page, head) = reopened
        .revocation_store()
        .list_revocation_entries_after(0, 10, None)?;
    assert_eq!(head, 2);
    assert_eq!(page[1].1.entry_id, rule_target().id());
    Ok(())
}

#[test]
fn restored_snapshot_missing_an_entry_refuses_open() -> TestResult {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.revocation_store();
    let snapshot = fixture.database.with_file_name("before-entry.db");
    store
        .connection()?
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    fs::copy(&fixture.database, &snapshot)?;
    record_unmatched_entry(&store, &rule_target())?;
    drop(store);
    drop(fixture.authority);

    restore_in_place(&fixture.database, &snapshot)?;
    let error = reopen_serving(&fixture.database, &fixture.lock_root)
        .err()
        .ok_or("a snapshot missing an entry reopened")?;
    assert_eq!(
        error.to_string(),
        "invalid sqlite authority store: authority database is behind its rollback anchor"
    );
    Ok(())
}

#[test]
fn deleting_an_entry_commit_fails_coverage() -> TestResult {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.revocation_store();
    record_unmatched_entry(&store, &rule_target())?;
    drop(store);
    drop(fixture.authority);

    let connection = Connection::open(&fixture.database)?;
    let guard: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name = 'authority_global_commits_no_delete'",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch(
        r#"
        DROP TRIGGER authority_global_commits_no_delete;
        DELETE FROM authority_global_commits
        WHERE projection_kind = 'revocation_entry';
        UPDATE authority_global_commit_meta SET
            head_sequence = (SELECT MAX(commit_sequence) FROM authority_global_commits),
            head_chain_digest = (
                SELECT chain_digest FROM authority_global_commits
                ORDER BY commit_sequence DESC LIMIT 1
            )
        WHERE singleton = 1;
        "#,
    )?;
    connection.execute_batch(&guard)?;
    drop(connection);

    let error = reopen_serving(&fixture.database, &fixture.lock_root)
        .err()
        .ok_or("a database missing an entry commit reopened")?;
    assert_eq!(
        error.to_string(),
        "invalid sqlite authority store: revocation entry projection coverage is not exact"
    );
    Ok(())
}

#[test]
fn an_extra_entry_commit_fails_validation() -> TestResult {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.revocation_store();
    record_unmatched_entry(&store, &rule_target())?;
    {
        let mut connection = store.connection()?;
        let transaction = store.begin_write(&mut connection)?;
        let owner = store.serving_owner.as_ref().ok_or("joint store")?;
        owner.append_global_commit(
            &transaction,
            "revocation_entry_record",
            "revocation_entry",
            rule_target().id().as_str(),
            1,
        )?;
        commit_mutation(&store, transaction)?;
        owner.sync_authority_anchor(&connection)?;
    }
    drop(store);
    drop(fixture.authority);

    let error = reopen_serving(&fixture.database, &fixture.lock_root)
        .err()
        .ok_or("a database with a second commit for one entry reopened")?;
    assert_eq!(
        error.to_string(),
        "invalid sqlite authority store: revocation entry projection coverage is not exact"
    );
    Ok(())
}

#[test]
fn an_entry_commit_without_its_entry_fails_validation() -> TestResult {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.revocation_store();
    record_unmatched_entry(&store, &rule_target())?;
    drop(store);
    drop(fixture.authority);

    Connection::open(&fixture.database)?.execute(
        "DELETE FROM revocation_entries WHERE entry_id = ?1",
        params![rule_target().id().as_str()],
    )?;
    let error = reopen_serving(&fixture.database, &fixture.lock_root)
        .err()
        .ok_or("a database missing an entry reopened")?;
    assert_eq!(
        error.to_string(),
        "invalid sqlite authority store: revocation entry projection reference is absent"
    );
    Ok(())
}

#[test]
fn an_altered_entry_reason_fails_its_reference_digest() -> TestResult {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.revocation_store();
    assert!(store.revoke("cap-fixture-1")?);
    drop(store);
    drop(fixture.authority);

    Connection::open(&fixture.database)?.execute(
        "UPDATE revocation_entries SET reason = 'incident_response'",
        [],
    )?;
    let error = reopen_serving(&fixture.database, &fixture.lock_root)
        .err()
        .ok_or("a database with an altered entry reopened")?;
    assert_eq!(
        error.to_string(),
        "invalid sqlite authority store: global authority commit lost its exact projection reference"
    );
    Ok(())
}

#[test]
fn anchor_sync_failure_after_entry_commit_reports_outcome_unknown() -> TestResult {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.revocation_store();
    let anchor = serving_anchor(&fixture.lock_root)?;
    {
        let connection = store.connection()?;
        let unsecured = anchor.clone();
        connection.create_scalar_function(
            "chio_test_unsecure_anchor",
            0,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_INNOCUOUS,
            move |_| {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&unsecured, fs::Permissions::from_mode(0o640))
                    .map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))?;
                Ok(1_i64)
            },
        )?;
        connection.execute_batch(
            r#"
            CREATE TEMP TRIGGER chio_test_unsecure_anchor_after_entry
            AFTER INSERT ON main.revocation_entries
            BEGIN
                SELECT chio_test_unsecure_anchor();
            END;
            "#,
        )?;
    }

    let error = store
        .revoke("cap-fixture-1")
        .err()
        .ok_or("revoke reported success without an anchor")?;
    assert!(
        matches!(
            &error,
            RevocationStoreError::OutcomeUnknown(detail)
                if detail == "invalid sqlite authority store: serving rollback anchor inode is insecure"
        ),
        "{error}"
    );
    let durable = Connection::open(&fixture.database)?.query_row(
        r#"
        SELECT
            (SELECT COUNT(*) FROM revocation_entries),
            (SELECT COUNT(*) FROM authority_global_commits
             WHERE projection_kind = 'revocation_entry')
        "#,
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    assert_eq!(durable, (1, 1), "the entry and its commit landed together");
    Ok(())
}

#[test]
fn a_refused_capability_row_rolls_back_its_entry_and_commit() -> TestResult {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.revocation_store();
    store.connection()?.execute_batch(
        r#"
        CREATE TEMP TRIGGER chio_test_refuse_revoked_row
        BEFORE INSERT ON main.revoked_capabilities
        BEGIN
            SELECT RAISE(ABORT, 'revoked row refused');
        END;
        "#,
    )?;

    let error = store
        .revoke("cap-fixture-1")
        .err()
        .ok_or("revoke succeeded past a refused row")?;
    assert!(
        matches!(
            &error,
            RevocationStoreError::Sqlite(rusqlite::Error::SqliteFailure(
                ffi::Error {
                    code: ErrorCode::ConstraintViolation,
                    ..
                },
                Some(message),
            )) if message == "revoked row refused"
        ),
        "{error}"
    );
    let written = Connection::open(&fixture.database)?.query_row(
        r#"
        SELECT
            (SELECT COUNT(*) FROM revocation_entries),
            (SELECT COUNT(*) FROM authority_global_commits
             WHERE projection_kind = 'revocation_entry')
        "#,
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    assert_eq!(written, (0, 0));

    store
        .connection()?
        .execute_batch("DROP TRIGGER temp.chio_test_refuse_revoked_row;")?;
    assert!(store.revoke("cap-fixture-1")?);
    assert_eq!(
        global_commits(&fixture.database, "revocation_entry")?,
        vec![(
            RevocationTarget::capability("cap-fixture-1")?
                .id()
                .as_str()
                .to_string(),
            1
        )]
    );
    Ok(())
}

fn serving_anchor(lock_root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    for entry in fs::read_dir(lock_root)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "lock")
        {
            return Ok(path);
        }
    }
    Err("no serving anchor in the lock root".into())
}

fn restore_in_place(database: &Path, snapshot: &Path) -> std::io::Result<()> {
    let mut input = File::open(snapshot)?;
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(database)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", database.display()));
        if sidecar.exists() {
            fs::remove_file(sidecar)?;
        }
    }
    Ok(())
}
