use super::*;
use chio_kernel::admission_operation::{
    AdmissionRecoveryDeferralV1, AdmissionRecoveryDeferralWrite, AdmissionRecoveryFailureKind,
    AdmissionRecoveryPhase,
};

fn table_rows(connection: &Connection, table: &str) -> AnchoredTestResult<Vec<Vec<Value>>> {
    let mut primary_key =
        connection.prepare("SELECT name FROM pragma_table_info(?1) WHERE pk > 0 ORDER BY pk")?;
    let columns = primary_key
        .query_map([table], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if columns.is_empty() {
        return Err("migration fixture table has no declared primary key".into());
    }
    let order = columns
        .iter()
        .map(|column| format!("\"{}\"", column.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(", ");
    let mut statement = connection.prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))?;
    let count = statement.column_count();
    let rows = statement
        .query_map([], |row| {
            (0..count)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[test]
fn native_journal_migration_v35_preserves_populated_recovery_and_native_bytes() -> AnchoredTestResult
{
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, request) = mutations::request("migration-native")?;
    let (native_operation, native_lease) =
        mutations::setup(&fixture, "migration-native", &context)?;
    fixture.store.join_security_participant_flow(
        &native_operation,
        &native_lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "migration-deferral",
        "migration-capability",
    );
    let now = now_ms();
    fixture.store.begin(&operation, &fixture.fence, now)?;
    let lease = claim(&fixture, &operation, "migration-deferral", now);
    let deferral = AdmissionRecoveryDeferralV1::after_failure(
        &operation,
        None,
        AdmissionRecoveryPhase::Inspection,
        AdmissionRecoveryFailureKind::ParticipantUnavailable,
        AdmissionDigest::try_new("diagnostic", sha256_hex(b"checkpoint migration"))?,
        now,
    )?;
    let status = fixture
        .store
        .defer_recovery(AdmissionRecoveryDeferralWrite {
            operation: &operation,
            lease: &lease,
            expected: None,
            deferral: &deferral,
            fence: &fixture.fence,
            trusted_now_unix_ms: now,
        })?;
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let connection = Connection::open(&database)?;
    crate::admission_operation_store::tests::schema::remove_empty_checkpoint_catalog(&connection)?;
    connection.execute_batch("UPDATE chio_store_schema_versions SET version = 35 WHERE store_key = 'admission_operation'")?;
    let tables = [
        "admission_operations",
        "admission_operation_commits",
        "admission_operation_recovery_deferrals",
        "security_participant_state_mutations",
        "security_participant_state_initializations",
        "authority_global_commits",
    ];
    let before = tables
        .iter()
        .map(|table| table_rows(&connection, table))
        .collect::<AnchoredTestResult<Vec<_>>>()?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    assert_eq!(connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",[],|row|row.get::<_,i32>(0))?,36);
    for (table, rows) in tables.iter().zip(before) {
        assert_eq!(table_rows(&connection, table)?, rows, "preserved {table}");
    }
    drop(connection);
    let authority = crate::test_authority::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    assert_eq!(
        store.load_recovery_status(
            operation.binding().operation_id(),
            &authority.mutation_fence(),
            now_ms()
        )?,
        Some(status)
    );
    assert_eq!(
        store.load_security_participant_state(
            initialized.security_authority_id(),
            &authority.mutation_fence(),
            now_ms()
        )?,
        Some(initialized.clone())
    );
    store.checkpoint_security_participant_history(
        &initialized,
        &authority.mutation_fence(),
        now_ms(),
    )?;
    Ok(())
}

#[test]
fn native_journal_migration_v35_rejects_partial_checkpoint_catalog_without_repair(
) -> AnchoredTestResult {
    for future in [
        "CREATE TABLE security_participant_checkpoint_alias(value TEXT)",
        "CREATE VIEW SECURITY_PARTICIPANT_CHECKPOINT_EVENTS AS SELECT 1",
        "CREATE TABLE security_participant_checkpoint_rows(value BLOB)",
    ] {
        let Fixture {
            _temp,
            database,
            lock_root,
            authority,
            store,
            ..
        } = fixture();
        drop(store);
        drop(authority);
        let connection = Connection::open(&database)?;
        crate::admission_operation_store::tests::schema::remove_empty_checkpoint_catalog(
            &connection,
        )?;
        connection.execute_batch("UPDATE chio_store_schema_versions SET version = 35 WHERE store_key = 'admission_operation'")?;
        connection.execute_batch(future)?;
        let before = table_rows(&connection, "authority_global_commits")?;
        assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
        assert_eq!(connection.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",[],|row|row.get::<_,i32>(0))?,35);
        assert_eq!(table_rows(&connection, "authority_global_commits")?, before);
    }
    Ok(())
}

#[test]
fn native_journal_migration_v35_rejects_existing_checkpoint_evidence_without_repair(
) -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let connection = Connection::open(&database)?;
    let before = table_rows(&connection, "security_participant_checkpoint_events")?;
    connection.execute_batch("UPDATE chio_store_schema_versions SET version = 35 WHERE store_key = 'admission_operation'")?;
    assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
    assert_eq!(
        table_rows(&connection, "security_participant_checkpoint_events")?,
        before
    );
    Ok(())
}

#[test]
fn native_journal_migration_immutable_checkpoint_history_is_enforced() -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    fixture.store.checkpoint_security_participant_history(
        &initialized,
        &fixture.fence,
        now_ms(),
    )?;
    let connection = fixture.store.connection()?;
    for table in [
        "security_participant_checkpoint_events",
        "security_participant_checkpoint_rows",
    ] {
        let before = table_rows(&connection, table)?;
        assert!(connection
            .execute(&format!("DELETE FROM {table}"), [])
            .is_err());
        assert!(connection
            .execute(
                &format!("UPDATE {table} SET security_authority_id = security_authority_id"),
                []
            )
            .is_err());
        assert!(connection
            .execute(
                &format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
                []
            )
            .is_err());
        assert_eq!(table_rows(&connection, table)?, before);
    }
    Ok(())
}
