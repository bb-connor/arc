//! The protected writer against an actual provisioned authority store.

use std::path::PathBuf;

use chio_kernel::admission_operation::AdmissionOperationStoreError;
use rusqlite::Connection;
use tempfile::TempDir;

use crate::SqliteAuthorityStore;

use super::super::super::SqliteAdmissionOperationStore;
use super::super::{verify_global_coverage, verify_local_history};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SCOPE: &str = "abababababababababababababababababababababababababababababababab";
const OTHER_SCOPE: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

struct Provisioned {
    _temp: TempDir,
    database: PathBuf,
    authority: SqliteAuthorityStore,
}

fn provisioned() -> Result<Provisioned, Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    crate::test_authority::secure_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = crate::test_authority::open_serving(&database, &lock_root)?;
    Ok(Provisioned {
        _temp: temp,
        database,
        authority,
    })
}

fn command<'a>(key: &'a str, payload: &'static [u8]) -> ProtectedWrite<'a> {
    ProtectedWrite {
        key,
        scope: SCOPE,
        kind: ProtectedRecordKind::Command,
        payload,
    }
}

/// Run `body` in one fenced owning transaction and commit it.
fn committed<T>(
    store: &SqliteAdmissionOperationStore,
    fence: &chio_core::StoreMutationFence,
    body: impl FnOnce(&Transaction<'_>) -> Result<T, AdmissionOperationStoreError>,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    let value = body(&tx)?;
    store.commit_write(tx)?;
    store.sync_after_write(&connection)?;
    Ok(value)
}

/// Run `body` in one fenced owning transaction and roll it back.
fn rolled_back<T>(
    store: &SqliteAdmissionOperationStore,
    fence: &chio_core::StoreMutationFence,
    body: impl FnOnce(&Transaction<'_>) -> T,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    let value = body(&tx);
    tx.rollback()?;
    Ok(value)
}

fn counts(database: &std::path::Path) -> Result<(i64, i64, i64), Box<dyn std::error::Error>> {
    let raw = Connection::open(database)?;
    Ok(raw.query_row(
        "SELECT (SELECT count(*) FROM admission_operation_recovery_records),
                (SELECT count(*) FROM admission_operation_recovery_events),
                (SELECT count(*) FROM authority_global_commits WHERE projection_kind = 'recovery')",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

#[test]
fn fresh_and_rotated_records_extend_both_chains_exactly() -> TestResult {
    let store = provisioned()?;
    let owner = store.authority.admission_operation_store();
    let fence = store.authority.mutation_fence();
    let first = committed(&owner, &fence, |tx| {
        persist_protected_record(
            tx,
            &owner.serving_owner,
            &command("command:a", b"{\"n\":1}"),
        )
    })?;
    assert_eq!(first, 1);
    let second = committed(&owner, &fence, |tx| {
        persist_protected_record(
            tx,
            &owner.serving_owner,
            &command("command:a", b"{\"n\":2}"),
        )
    })?;
    assert_eq!(second, 2);
    assert_eq!(counts(&store.database)?, (1, 2, 2));
    let raw = Connection::open(&store.database)?;
    verify_local_history(&raw)?;
    verify_global_coverage(&raw)?;
    let (version, payload): (i64, Vec<u8>) = raw.query_row(
        "SELECT version, payload FROM admission_operation_recovery_records
         WHERE record_key = 'command:a'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!((version, payload.as_slice()), (2, b"{\"n\":2}".as_slice()));
    let mutation_kinds: Vec<String> = raw
        .prepare(
            "SELECT mutation_kind FROM authority_global_commits
             WHERE projection_kind = 'recovery' ORDER BY commit_sequence",
        )?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    assert_eq!(
        mutation_kinds,
        [RECOVERY_MUTATION_KIND, RECOVERY_MUTATION_KIND]
    );
    Ok(())
}

#[test]
fn changed_scope_or_kind_refuses_without_writing() -> TestResult {
    let store = provisioned()?;
    let owner = store.authority.admission_operation_store();
    let fence = store.authority.mutation_fence();
    committed(&owner, &fence, |tx| {
        persist_protected_record(tx, &owner.serving_owner, &command("command:a", b"{}"))
    })?;
    for write in [
        ProtectedWrite {
            scope: OTHER_SCOPE,
            ..command("command:a", b"{\"n\":2}")
        },
        ProtectedWrite {
            kind: ProtectedRecordKind::Deployment,
            ..command("command:a", b"{\"n\":2}")
        },
    ] {
        assert_eq!(
            rolled_back(&owner, &fence, |tx| {
                persist_protected_record(tx, &owner.serving_owner, &write)
            })?,
            Err(invariant("protected record ownership changed"))
        );
    }
    assert_eq!(counts(&store.database)?, (1, 1, 1));
    Ok(())
}

#[test]
fn malformed_writes_refuse_before_any_row() -> TestResult {
    let store = provisioned()?;
    let owner = store.authority.admission_operation_store();
    let fence = store.authority.mutation_fence();
    let oversized = vec![b'1'; MAX_RECORD_PAYLOAD_BYTES + 1];
    let long_key = "k".repeat(513);
    let cases: [(ProtectedWrite<'_>, &str); 6] = [
        (
            ProtectedWrite {
                scope: "AB",
                ..command("command:a", b"{}")
            },
            "recovery record identity is not canonical",
        ),
        (command("command:a", b""), "recovery record quota exhausted"),
        (
            ProtectedWrite {
                payload: &oversized,
                ..command("command:a", b"{}")
            },
            "recovery record quota exhausted",
        ),
        (
            command("command:a", b"{ \"n\": 1 }"),
            "recovery record payload is not canonical JSON",
        ),
        (
            command(&long_key, b"{}"),
            "recovery record key exceeds its bound",
        ),
        (command("", b"{}"), "recovery record key exceeds its bound"),
    ];
    for (write, expected) in cases {
        assert_eq!(
            rolled_back(&owner, &fence, |tx| {
                persist_protected_record(tx, &owner.serving_owner, &write)
            })?,
            Err(invariant(expected))
        );
    }
    assert_eq!(counts(&store.database)?, (0, 0, 0));
    Ok(())
}

#[test]
fn encoding_refuses_values_above_the_record_bound() {
    assert_eq!(
        encode_protected(&"x".repeat(MAX_RECORD_PAYLOAD_BYTES)),
        Err(invariant("recovery resource exhausted"))
    );
    assert_eq!(
        encode_protected(&"x".repeat(MAX_RECORD_PAYLOAD_BYTES - 2)).map(|bytes| bytes.len()),
        Ok(MAX_RECORD_PAYLOAD_BYTES)
    );
}

#[test]
fn raw_replacement_is_refused_while_the_writer_rotates() -> TestResult {
    let store = provisioned()?;
    let owner = store.authority.admission_operation_store();
    let fence = store.authority.mutation_fence();
    committed(&owner, &fence, |tx| {
        persist_protected_record(tx, &owner.serving_owner, &command("command:a", b"{}"))
    })?;
    let raw = Connection::open(&store.database)?;
    let replaced = raw.execute(
        "INSERT INTO admission_operation_recovery_records
         (record_key, scope_key, kind, version, payload)
         VALUES ('command:a', ?1, 'command', 2, X'7B7D')",
        [SCOPE],
    );
    assert!(matches!(
        replaced,
        Err(rusqlite::Error::SqliteFailure(_, Some(message)))
            if message == "recovery ownership cannot be replaced"
    ));
    drop(raw);
    assert_eq!(
        committed(&owner, &fence, |tx| {
            persist_protected_record(tx, &owner.serving_owner, &command("command:a", b"[]"))
        })?,
        2
    );
    assert_eq!(counts(&store.database)?, (1, 2, 2));
    Ok(())
}

#[test]
fn absence_with_retained_history_refuses_a_fresh_insert() -> TestResult {
    let store = provisioned()?;
    let owner = store.authority.admission_operation_store();
    let fence = store.authority.mutation_fence();
    committed(&owner, &fence, |tx| {
        persist_protected_record(tx, &owner.serving_owner, &command("command:a", b"{}"))
    })?;
    delete_projection_through_owner(&owner, &fence, "command:a")?;
    assert_eq!(
        rolled_back(&owner, &fence, |tx| {
            persist_protected_record(tx, &owner.serving_owner, &command("command:a", b"{}"))
        })?,
        Err(invariant(
            "recovery record disappeared with retained history"
        ))
    );
    assert_eq!(counts(&store.database)?, (0, 1, 1));
    Ok(())
}

#[test]
fn source_reads_require_the_latest_head_of_both_chains() -> TestResult {
    let store = provisioned()?;
    let owner = store.authority.admission_operation_store();
    let fence = store.authority.mutation_fence();
    committed(&owner, &fence, |tx| {
        persist_protected_record(tx, &owner.serving_owner, &command("command:a", b"{}"))
    })?;
    let loaded = |tx: &Transaction<'_>| -> Result<ProtectedRecord, AdmissionOperationStoreError> {
        load_record(tx, "command:a")?.ok_or(AdmissionOperationStoreError::NotFound)
    };
    rolled_back(&owner, &fence, |tx| {
        require_latest_projection_head(tx, &loaded(tx)?)
    })??;
    assert_eq!(
        rolled_back(&owner, &fence, |tx| {
            owner
                .serving_owner
                .append_global_commit(tx, RECOVERY_MUTATION_KIND, "recovery", "command:a", 1)
                .map_err(crate::admission_operation_store::map_owner_error)?;
            require_latest_projection_head(tx, &loaded(tx)?)
        })?,
        Err(invariant("historical deployment lost its global reference"))
    );
    assert_eq!(
        rolled_back(&owner, &fence, |tx| {
            let stale = loaded(tx)?;
            persist_protected_record(tx, &owner.serving_owner, &command("command:a", b"[]"))?;
            require_latest_projection_head(tx, &stale)
        })?,
        Err(invariant(
            "protected source projection is not its latest head"
        ))
    );
    assert_eq!(counts(&store.database)?, (1, 1, 1));
    Ok(())
}

#[test]
fn first_version_retention_names_the_exact_first_write() -> TestResult {
    let store = provisioned()?;
    let owner = store.authority.admission_operation_store();
    let fence = store.authority.mutation_fence();
    committed(&owner, &fence, |tx| {
        persist_protected_record(
            tx,
            &owner.serving_owner,
            &command("command:a", b"{\"n\":1}"),
        )?;
        persist_protected_record(
            tx,
            &owner.serving_owner,
            &command("command:a", b"{\"n\":2}"),
        )
    })?;
    rolled_back(
        &owner,
        &fence,
        |tx| -> Result<(), AdmissionOperationStoreError> {
            assert!(first_version_retains(
                tx,
                &command("command:a", b"{\"n\":1}")
            )?);
            assert!(!first_version_retains(
                tx,
                &command("command:a", b"{\"n\":2}")
            )?);
            assert!(!first_version_retains(
                tx,
                &command("command:b", b"{\"n\":1}")
            )?);
            Ok(())
        },
    )??;
    Ok(())
}

/// Apply `tamper` to the global commit catalog with its immutability and
/// deletion guards deliberately removed, then restore both guards.
fn tamper_global_commits(database: &std::path::Path, tamper: &str) -> TestResult {
    let raw = Connection::open(database)?;
    let mut guards = Vec::new();
    for name in [
        "authority_global_commits_immutable",
        "authority_global_commits_no_delete",
    ] {
        let sql: String = raw.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
            [name],
            |row| row.get(0),
        )?;
        raw.execute_batch(&format!("DROP TRIGGER {name};"))?;
        guards.push(sql);
    }
    raw.execute_batch(tamper)?;
    for sql in &guards {
        raw.execute_batch(sql)?;
    }
    Ok(())
}

#[test]
fn latest_head_refuses_tampered_global_commit_metadata() -> TestResult {
    for (tamper, expected) in [
        (
            "UPDATE authority_global_commits SET mutation_kind = 'stop_epoch'
             WHERE projection_kind = 'recovery' AND projection_key = 'command:a';",
            "recovery global commit mutation kind differs",
        ),
        (
            "UPDATE authority_global_commits SET commit_sequence = 9007199254740992
             WHERE projection_kind = 'recovery' AND projection_key = 'command:a';",
            "recovery global commit sequence is out of range",
        ),
        (
            "INSERT INTO authority_global_commits
             (commit_sequence, mutation_kind, projection_kind, projection_key,
              projection_sequence, projection_reference_digest, authority_projection_digest,
              previous_chain_digest, chain_digest, store_uuid, store_lease_id,
              store_owner_epoch)
             SELECT (SELECT max(commit_sequence) + 1 FROM authority_global_commits),
                    mutation_kind, projection_kind, projection_key, 'corrupt',
                    projection_reference_digest, authority_projection_digest,
                    previous_chain_digest, chain_digest, store_uuid, store_lease_id,
                    store_owner_epoch
             FROM authority_global_commits
             WHERE projection_kind = 'recovery' AND projection_key = 'command:a';",
            "recovery latest global projection sequence is out of range",
        ),
    ] {
        let store = provisioned()?;
        let owner = store.authority.admission_operation_store();
        let fence = store.authority.mutation_fence();
        committed(&owner, &fence, |tx| {
            persist_protected_record(tx, &owner.serving_owner, &command("command:a", b"{}"))
        })?;
        let raw = Connection::open(&store.database)?;
        let record = load_record(&raw, "command:a")?.ok_or("published record")?;
        require_latest_projection_head(&raw, &record)?;
        drop(raw);
        let (records, events, _) = counts(&store.database)?;
        tamper_global_commits(&store.database, tamper)?;
        let raw = Connection::open(&store.database)?;
        let record = load_record(&raw, "command:a")?.ok_or("published record")?;
        assert_eq!(
            require_latest_projection_head(&raw, &record),
            Err(invariant(expected)),
            "{expected}"
        );
        let (after_records, after_events, _) = counts(&store.database)?;
        assert_eq!((after_records, after_events), (records, events));
    }
    Ok(())
}

#[test]
fn workflow_owned_records_refuse_the_generic_writer() -> TestResult {
    use super::super::digest::{event_digest, record_digest, EventDigestInput, RecordDigestInput};
    use super::super::record::NativeIdentity;

    let store = provisioned()?;
    let owner = store.authority.admission_operation_store();
    let fence = store.authority.mutation_fence();
    committed(&owner, &fence, |tx| {
        let native = NativeIdentity {
            namespace: OTHER_SCOPE.to_owned(),
            request: "request:native".to_owned(),
        };
        tx.execute(
            "INSERT INTO main.admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload, native_namespace, native_request)
             VALUES ('workflow:native', ?1, 'workflow', 1, X'7B7D', ?2, ?3)",
            params![SCOPE, native.namespace, native.request],
        )
        .map_err(sqlite_error)?;
        let (sequence, previous, floor) = chain_head(tx)?;
        let observed = crate::admission_operation_store::schema::observe_authority_time(
            tx,
            &owner.serving_owner,
        )?;
        let record = record_digest(&RecordDigestInput {
            key: "workflow:native",
            scope: SCOPE,
            kind: RecordKind::Workflow,
            version: 1,
            payload: b"{}",
            native: Some(&native),
        })?;
        let event = event_digest(&EventDigestInput {
            sequence,
            key: "workflow:native",
            version: 1,
            record_digest: &record,
            previous_digest: &previous,
            observed_at: observed.max(floor),
        })?;
        tx.execute(
            "INSERT INTO main.admission_operation_recovery_events
             (sequence, record_key, record_version, record_digest, previous_digest,
              event_digest, observed_at)
             VALUES (?1, 'workflow:native', 1, ?2, ?3, ?4, ?5)",
            params![
                sqlite_i64(sequence, "sequence")?,
                record,
                previous,
                event,
                sqlite_i64(observed.max(floor), "observed")?
            ],
        )
        .map_err(sqlite_error)?;
        owner
            .serving_owner
            .append_global_commit(tx, RECOVERY_MUTATION_KIND, "recovery", "workflow:native", 1)
            .map_err(crate::admission_operation_store::map_owner_error)
    })?;
    let before = counts(&store.database)?;
    assert_eq!(before, (1, 1, 1));
    for kind in [
        ProtectedRecordKind::Command,
        ProtectedRecordKind::Deployment,
    ] {
        assert_eq!(
            rolled_back(&owner, &fence, |tx| {
                persist_protected_record(
                    tx,
                    &owner.serving_owner,
                    &ProtectedWrite {
                        kind,
                        ..command("workflow:native", b"[]")
                    },
                )
            })?,
            Err(invariant("protected record ownership changed"))
        );
    }
    assert_eq!(counts(&store.database)?, before);
    let raw = Connection::open(&store.database)?;
    verify_local_history(&raw)?;
    verify_global_coverage(&raw)?;
    Ok(())
}

/// Corrupt one projection while retaining owner custody and the exact catalog.
fn delete_projection_through_owner(
    store: &SqliteAdmissionOperationStore,
    fence: &chio_core::StoreMutationFence,
    key: &str,
) -> TestResult {
    let mut connection = store.connection()?;
    connection.execute_batch("PRAGMA foreign_keys = OFF;")?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    let guard: String = tx.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger'
         AND name = 'admission_operation_recovery_records_no_delete'",
        [],
        |row| row.get(0),
    )?;
    tx.execute_batch("DROP TRIGGER admission_operation_recovery_records_no_delete;")?;
    tx.execute(
        "DELETE FROM main.admission_operation_recovery_records WHERE record_key = ?1",
        [key],
    )?;
    tx.execute_batch(&guard)?;
    store.commit_write(tx)?;
    store.sync_after_write(&connection)?;
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    assert_eq!(
        connection.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))?,
        1
    );
    Ok(())
}
