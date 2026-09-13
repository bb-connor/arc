use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn legacy_schema() -> Result<Connection, rusqlite::Error> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(&migration_v20::predecessor_schema())?;
    connection.execute_batch(include_str!("../../../admission_operation_nonce.sql"))?;
    connection.execute_batch(include_str!(
        "../../../admission_operation_nonce_preflight.sql"
    ))?;
    Ok(connection)
}

#[test]
fn canonical_v18_accepts_only_a_new_empty_runtime_namespace() -> TestResult {
    let connection = legacy_schema()?;
    verify_pre_migration_schema(&connection, 18)?;
    connection.execute_batch(&migration_v21::predecessor_schema())?;
    verify_admission_operation_schema(&connection, 19)?;
    assert!(matches!(
        verify_pre_migration_schema(&connection, 18),
        Err(AdmissionOperationStoreError::Invariant(message))
            if message.contains("unqualified runtime replay namespace")
    ));
    Ok(())
}

#[test]
fn v18_damaged_old_schema_is_rejected_without_repair() -> TestResult {
    let connection = legacy_schema()?;
    connection.execute_batch("DROP TRIGGER admission_operation_tool_requests_immutable")?;
    let before = admission_operation_schema_catalog(&connection)?;
    assert!(matches!(
        verify_pre_migration_schema(&connection, 18),
        Err(AdmissionOperationStoreError::Invariant(message))
            if message.contains("schema differs from the canonical definition")
    ));
    assert_eq!(admission_operation_schema_catalog(&connection)?, before);
    Ok(())
}

#[test]
fn every_pre_v19_version_rejects_case_insensitive_partial_namespace() -> TestResult {
    for version in [0, 1, 16, 17, 18] {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("CREATE TABLE RUNTIME_REPLAY_LEGACY_TOMBSTONES(value INTEGER)")?;
        let before = admission_operation_schema_catalog(&connection)?;
        assert!(matches!(
            verify_pre_migration_schema(&connection, version),
            Err(AdmissionOperationStoreError::Invariant(message))
                if message.contains("unqualified runtime replay namespace")
        ));
        assert_eq!(admission_operation_schema_catalog(&connection)?, before);
    }
    Ok(())
}

#[test]
fn current_catalog_does_not_recreate_a_missing_runtime_barrier() -> TestResult {
    let connection = legacy_schema()?;
    connection.execute_batch(RUNTIME_REPLAY_MIGRATION_SCHEMA)?;
    connection.execute_batch("DROP TRIGGER runtime_replay_legacy_tombstones_no_delete")?;
    let before = admission_operation_schema_catalog(&connection)?;
    assert!(verify_admission_operation_schema(&connection, 19).is_err());
    assert_eq!(admission_operation_schema_catalog(&connection)?, before);
    Ok(())
}

#[test]
fn runtime_replay_tables_reject_hidden_rowid_replacement() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch("PRAGMA foreign_keys = OFF; PRAGMA recursive_triggers = OFF;")?;
    connection.execute_batch(RUNTIME_REPLAY_MIGRATION_SCHEMA)?;
    let digest = "0".repeat(64);
    for (table, columns, values) in [
        (
            "runtime_replay_migration_expectations",
            "runtime_authority_id, source_id, expectation_id, destination_store_uuid, canonical_source, inventory_sha256, expectation_digest",
            format!("'runtime', 'source', 'expectation', 'destination', X'01', '{digest}', '{digest}'"),
        ),
        (
            "runtime_replay_migration_events",
            "runtime_authority_id, sequence, mutation_kind, expectation_digest, inventory_sha256, event_digest, observed_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch",
            format!("'runtime', 1, 'expect_runtime_replay_source', '{digest}', '{digest}', '{digest}', 1, 'destination', 'lease', 1"),
        ),
        (
            "runtime_replay_legacy_tombstones",
            "runtime_authority_id, participant_kind, resource_id, source_id, expectation_id, historical_admission_id",
            "'runtime', 'destructive_lease', 'resource', 'source', 'expectation', 'admission'".into(),
        ),
    ] {
        connection.execute(&format!("INSERT INTO {table} ({columns}) VALUES ({values})"), [])?;
        let before = physical_rows(&connection, table)?;
        // Every declared key differs, so the uniqueness guards alone would not
        // stop REPLACE from deleting the old row through an implicit rowid.
        let replacement = values
            .replace("'runtime'", "'other-runtime'")
            .replace("'source'", "'other-source'")
            .replace("'expectation'", "'other-expectation'");
        for hidden_key in ["rowid", "_rowid_", "oid"] {
            let error = connection
                .execute(
                    &format!(
                        "INSERT OR REPLACE INTO {table} ({hidden_key}, {columns}) VALUES (1, {replacement})"
                    ),
                    [],
                )
                .err()
                .ok_or("implicit rowid replacement unexpectedly succeeded")?;
            assert!(
                error.to_string().contains(&format!("no column named {hidden_key}")),
                "{table}: {error}"
            );
            assert_eq!(physical_rows(&connection, table)?, before);
        }
    }
    Ok(())
}

fn physical_rows(
    connection: &Connection,
    table: &str,
) -> rusqlite::Result<Vec<Vec<rusqlite::types::Value>>> {
    let mut statement = connection.prepare(&format!("SELECT * FROM {table}"))?;
    let columns = statement.column_count();
    let rows = statement.query_map([], |row| {
        (0..columns).map(|column| row.get(column)).collect()
    })?;
    rows.collect()
}
