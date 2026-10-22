//! The recovery catalog inside an actual provisioned authority store: created
//! once with the admission schema, verified locally at every open, and covered
//! by the global commit chain. Refused opens leave the database unchanged.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};
use tempfile::TempDir;

use crate::{SqliteAuthorityStore, SqliteServingOwnerError};

use super::super::super::SqliteAdmissionOperationStore;
use super::super::digest::{event_digest, record_digest, EventDigestInput, RecordDigestInput};
use super::super::global_coverage::RECOVERY_MUTATION_KIND;
use super::super::{
    projection_reference, verify_global_coverage, verify_local_history, RecordKind, GENESIS_DIGEST,
};
use super::fixture::{TestResult, SCOPE};

type Catalog = Vec<(String, String, String, Option<String>)>;

struct Provisioned {
    _temp: TempDir,
    database: PathBuf,
    lock_root: PathBuf,
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
    Ok(Provisioned {
        _temp: temp,
        database,
        lock_root,
    })
}

fn open(store: &Provisioned) -> Result<SqliteAuthorityStore, SqliteServingOwnerError> {
    crate::test_authority::open_serving(&store.database, &store.lock_root)
}

fn catalog(database: &Path) -> Result<Catalog, Box<dyn std::error::Error>> {
    let connection = Connection::open(database)?;
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name, tbl_name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Recovery rows and recovery global commits in stored order; an absent table
/// is recorded as absent.
fn recovery_state(database: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let connection = Connection::open(database)?;
    let mut state = Vec::new();
    for (table, query) in [
        (
            "admission_operation_recovery_records",
            "SELECT record_key || ':' || version FROM admission_operation_recovery_records
             ORDER BY record_key",
        ),
        (
            "admission_operation_recovery_events",
            "SELECT sequence || ':' || record_key || ':' || event_digest
             FROM admission_operation_recovery_events ORDER BY sequence",
        ),
        (
            "authority_global_commits",
            "SELECT commit_sequence || ':' || projection_key || ':' || chain_digest
             FROM authority_global_commits WHERE projection_kind = 'recovery'
             ORDER BY commit_sequence",
        ),
    ] {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )?;
        if !present {
            state.push(format!("{table} absent"));
            continue;
        }
        let mut statement = connection.prepare(query)?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            state.push(row?);
        }
    }
    Ok(state)
}

/// Write version 1 of each command record and its next event through the
/// store's owned write path, then append the recovery global commits of the
/// records named by `commits`, in that order. Returns each event digest.
fn publish(
    authority: &SqliteAuthorityStore,
    keys: &[&str],
    commits: &[usize],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let store: SqliteAdmissionOperationStore = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let mut connection = store.connection()?;
    let transaction = store.begin_write(&mut connection, Some(&fence))?;
    let mut digests = Vec::new();
    for key in keys {
        let head: Option<(i64, String)> = transaction
            .query_row(
                "SELECT sequence, event_digest FROM admission_operation_recovery_events
                 ORDER BY sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (sequence, previous) = head.map_or((1, GENESIS_DIGEST.to_owned()), |(last, digest)| {
            (last + 1, digest)
        });
        let sequence = u64::try_from(sequence)?;
        let record = record_digest(&RecordDigestInput {
            key,
            scope: SCOPE,
            kind: RecordKind::Command,
            version: 1,
            payload: b"{}",
            native: None,
        })?;
        let event = event_digest(&EventDigestInput {
            sequence,
            key,
            version: 1,
            record_digest: &record,
            previous_digest: &previous,
            observed_at: sequence,
        })?;
        transaction.execute(
            "INSERT INTO admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload)
             VALUES (?1, ?2, 'command', 1, ?3)",
            params![key, SCOPE, b"{}".as_slice()],
        )?;
        transaction.execute(
            "INSERT INTO admission_operation_recovery_events
             (sequence, record_key, record_version, record_digest, previous_digest,
              event_digest, observed_at)
             VALUES (?1, ?2, 1, ?3, ?4, ?5, ?1)",
            params![i64::try_from(sequence)?, key, record, previous, event],
        )?;
        digests.push(event);
    }
    for index in commits {
        let key = keys
            .get(*index)
            .ok_or("commit names an unpublished record")?;
        store.serving_owner.append_global_commit(
            &transaction,
            RECOVERY_MUTATION_KIND,
            "recovery",
            key,
            1,
        )?;
    }
    store.commit_write(transaction)?;
    store.sync_after_write(&connection)?;
    Ok(digests)
}

fn assert_open_refused(store: &Provisioned, expected: &str) -> TestResult {
    let catalog_before = catalog(&store.database)?;
    let state_before = recovery_state(&store.database)?;
    match open(store) {
        Err(SqliteServingOwnerError::Invalid(message)) => assert_eq!(message, expected),
        Err(other) => return Err(format!("expected {expected:?}, got {other:?}").into()),
        Ok(_) => return Err(format!("expected {expected:?}, but the store opened").into()),
    }
    assert_eq!(catalog(&store.database)?, catalog_before);
    assert_eq!(recovery_state(&store.database)?, state_before);
    Ok(())
}

#[test]
fn fresh_store_creates_the_recovery_catalog_and_reopens_unchanged() -> TestResult {
    let store = provisioned()?;
    let authority = open(&store)?;
    let raw = Connection::open(&store.database)?;
    for (kind, name) in [
        ("table", "admission_operation_recovery_records"),
        ("table", "admission_operation_recovery_events"),
        ("trigger", "admission_operation_recovery_records_no_delete"),
        ("trigger", "admission_operation_recovery_records_no_replace"),
        ("trigger", "admission_operation_recovery_history_insert"),
        ("trigger", "admission_operation_recovery_history_immutable"),
        ("table", "admission_operation_recovery_deferrals"),
    ] {
        let present: bool = raw.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = ?1 AND name = ?2)",
            [kind, name],
            |row| row.get(0),
        )?;
        assert!(present, "{kind} {name} is absent");
    }
    let records_sql: String = raw.query_row(
        "SELECT sql FROM sqlite_schema WHERE name = 'admission_operation_recovery_records'",
        [],
        |row| row.get(0),
    )?;
    assert!(records_sql.ends_with(") WITHOUT ROWID"));
    verify_local_history(&raw)?;
    verify_global_coverage(&raw)?;
    assert_eq!(recovery_state(&store.database)?, Vec::<String>::new());
    drop(raw);
    drop(authority);
    let catalog_before = catalog(&store.database)?;
    drop(open(&store)?);
    assert_eq!(catalog(&store.database)?, catalog_before);
    Ok(())
}

#[test]
fn published_records_reopen_with_exact_global_coverage() -> TestResult {
    let store = provisioned()?;
    let authority = open(&store)?;
    let digests = publish(&authority, &["command:a", "command:b"], &[0, 1])?;
    drop(authority);
    let state = recovery_state(&store.database)?;
    assert_eq!(state.len(), 6);
    drop(open(&store)?);
    assert_eq!(recovery_state(&store.database)?, state);
    let raw = Connection::open(&store.database)?;
    verify_local_history(&raw)?;
    verify_global_coverage(&raw)?;
    for (key, digest) in ["command:a", "command:b"].into_iter().zip(&digests) {
        assert_eq!(projection_reference(&raw, key, 1)?, *digest);
    }
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
fn omitted_or_misbound_recovery_catalog_objects_refuse_without_rewriting() -> TestResult {
    for tamper in [
        "DROP TABLE admission_operation_recovery_events;",
        "DROP INDEX admission_operation_recovery_scope;",
        "DROP TRIGGER admission_operation_recovery_records_no_delete;",
        "DROP TRIGGER admission_operation_recovery_records_no_replace;",
        "DROP TRIGGER admission_operation_recovery_history_insert;",
        "DROP TRIGGER admission_operation_recovery_history_immutable;",
        "DROP TRIGGER admission_operation_recovery_history_immutable;
         CREATE TRIGGER admission_operation_recovery_history_immutable
         BEFORE UPDATE ON admission_operation_recovery_events
         BEGIN
             SELECT RAISE(ABORT, 'historical deployment is immutable');
         END;",
        "DROP TRIGGER admission_operation_recovery_records_no_delete;
         CREATE TRIGGER admission_operation_recovery_records_no_delete
         BEFORE DELETE ON admission_operation_recovery_events
         BEGIN
             SELECT RAISE(ABORT, 'recovery ownership cannot be deleted');
         END;",
    ] {
        let store = provisioned()?;
        Connection::open(&store.database)?.execute_batch(tamper)?;
        assert_open_refused(
            &store,
            "admission operation invariant failed: \
             admission operation schema differs from the canonical definition",
        )?;
    }
    Ok(())
}

#[test]
fn orphan_local_recovery_rows_refuse_at_open_without_rewriting() -> TestResult {
    let store = provisioned()?;
    Connection::open(&store.database)?.execute(
        "INSERT INTO admission_operation_recovery_records
         (record_key, scope_key, kind, version, payload)
         VALUES ('command:orphan', ?1, 'command', 1, ?2)",
        params![SCOPE, b"{}".as_slice()],
    )?;
    assert_open_refused(
        &store,
        "admission operation invariant failed: recovery record history coverage is incomplete",
    )?;

    let store = provisioned()?;
    let record = record_digest(&RecordDigestInput {
        key: "command:gone",
        scope: SCOPE,
        kind: RecordKind::Command,
        version: 1,
        payload: b"{}",
        native: None,
    })?;
    let event = event_digest(&EventDigestInput {
        sequence: 1,
        key: "command:gone",
        version: 1,
        record_digest: &record,
        previous_digest: GENESIS_DIGEST,
        observed_at: 1,
    })?;
    let raw = Connection::open(&store.database)?;
    raw.execute_batch("PRAGMA foreign_keys = OFF;")?;
    raw.execute(
        "INSERT INTO admission_operation_recovery_events
         (sequence, record_key, record_version, record_digest, previous_digest,
          event_digest, observed_at)
         VALUES (1, 'command:gone', 1, ?1, ?2, ?3, 1)",
        params![record, GENESIS_DIGEST, event],
    )?;
    drop(raw);
    let catalog_before = catalog(&store.database)?;
    let state_before = recovery_state(&store.database)?;
    assert!(matches!(open(&store),
        Err(SqliteServingOwnerError::BudgetSchema(chio_kernel::BudgetStoreError::Invariant(message)))
            if message == "sqlite foreign key violation in `admission_operation_recovery_events` row 1"));
    assert_eq!(catalog(&store.database)?, catalog_before);
    assert_eq!(recovery_state(&store.database)?, state_before);
    Ok(())
}

#[test]
fn recovery_commit_without_its_local_event_refuses_at_open_without_rewriting() -> TestResult {
    let store = provisioned()?;
    let authority = open(&store)?;
    publish(&authority, &["command:a"], &[0])?;
    drop(authority);
    let raw = Connection::open(&store.database)?;
    raw.execute_batch("PRAGMA foreign_keys = OFF;")?;
    let mut guards = Vec::new();
    for name in [
        "admission_operation_recovery_records_no_delete",
        "admission_operation_recovery_event_no_delete",
    ] {
        let sql: String = raw.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
            [name],
            |row| row.get(0),
        )?;
        raw.execute_batch(&format!("DROP TRIGGER {name};"))?;
        guards.push(sql);
    }
    raw.execute_batch(
        "DELETE FROM admission_operation_recovery_events;
         DELETE FROM admission_operation_recovery_records;",
    )?;
    for sql in &guards {
        raw.execute_batch(sql)?;
    }
    drop(raw);
    assert_open_refused(&store, "recovery record projection reference is absent")
}

#[test]
fn incomplete_duplicate_or_reordered_recovery_coverage_refuses_at_open() -> TestResult {
    for (keys, commits, expected) in [
        (
            &["command:a"][..],
            &[][..],
            "recovery event lacks its global commit",
        ),
        (
            &["command:a"][..],
            &[0, 0][..],
            "recovery event has duplicate global commits",
        ),
        (
            &["command:a", "command:b"][..],
            &[1, 0][..],
            "recovery global commit order regressed",
        ),
    ] {
        let store = provisioned()?;
        let authority = open(&store)?;
        publish(&authority, keys, commits)?;
        drop(authority);
        assert_open_refused(
            &store,
            &format!("admission operation invariant failed: {expected}"),
        )?;
    }
    Ok(())
}

#[test]
fn global_catalog_without_the_recovery_kind_refuses_at_open() -> TestResult {
    let store = provisioned()?;
    let raw = Connection::open(&store.database)?;
    let sql: String = raw.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'authority_global_commits'",
        [],
        |row| row.get(0),
    )?;
    let open = sql
        .find("projection_kind IN (")
        .ok_or("projection kind CHECK is missing")?
        + "projection_kind IN (".len();
    let close = open
        + sql[open..]
            .find(')')
            .ok_or("projection kind CHECK is unterminated")?;
    let kinds: Vec<&str> = sql[open..close].split(", ").collect();
    let retained: Vec<&str> = kinds
        .iter()
        .copied()
        .filter(|kind| *kind != "'recovery'")
        .collect();
    assert_eq!(retained.len() + 1, kinds.len());
    let stripped = format!("{}{}{}", &sql[..open], retained.join(", "), &sql[close..]);
    raw.execute_batch("PRAGMA writable_schema = ON;")?;
    let changed = raw.execute(
        "UPDATE sqlite_schema SET sql = ?1
         WHERE type = 'table' AND name = 'authority_global_commits'",
        [&stripped],
    )?;
    raw.execute_batch("PRAGMA writable_schema = OFF;")?;
    drop(raw);
    assert_eq!(changed, 1);
    assert_open_refused(&store, "global authority commit schema is not canonical")
}
