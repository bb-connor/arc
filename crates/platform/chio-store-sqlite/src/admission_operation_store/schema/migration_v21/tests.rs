use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn predecessor() -> rusqlite::Result<Connection> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(&migration_v23::predecessor_admission_schema())?;
    connection.execute_batch(include_str!("../../../admission_operation_nonce.sql"))?;
    connection.execute_batch(include_str!(
        "../../../admission_operation_nonce_preflight.sql"
    ))?;
    connection.execute_batch(RUNTIME_PARTICIPANT_SCHEMA)?;
    connection.execute_batch(&predecessor_schema())?;
    Ok(connection)
}

#[test]
fn v20_catalog_migration_changes_only_activation_constraints() -> TestResult {
    assert_eq!(
        RUNTIME_REPLAY_MIGRATION_SCHEMA.matches(ACTIVE_KIND).count(),
        1
    );
    assert_eq!(
        RUNTIME_REPLAY_MIGRATION_SCHEMA
            .matches(ACTIVE_TRANSITION)
            .count(),
        1
    );
    assert_eq!(
        RUNTIME_REPLAY_MIGRATION_SCHEMA
            .matches("sequence BETWEEN 1 AND 3")
            .count(),
        1
    );
    let mut connection = predecessor()?;
    verify_admission_operation_schema(&connection, 20)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    migration_v17::preserving_parent_names(&mut connection, |connection| {
        let transaction = connection.transaction().map_err(sqlite_error)?;
        verify_pre_migration_schema(&transaction, 20)?;
        migrate_activation_event(&transaction)?;
        verify_admission_operation_schema(&transaction, 21)?;
        transaction.commit().map_err(sqlite_error)
    })?;
    assert!(connection.pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))?);
    assert!(
        !connection.pragma_query_value(None, "legacy_alter_table", |row| row.get::<_, bool>(0))?
    );
    Ok(())
}

#[test]
fn v20_damaged_catalog_is_not_repaired_for_activation() -> TestResult {
    for ddl in [
        "DROP TRIGGER runtime_replay_migration_events_no_delete",
        "DROP TRIGGER runtime_replay_claim_episodes_no_update",
        "DROP TRIGGER admission_operation_commits_no_delete",
    ] {
        let mut connection = predecessor()?;
        connection.execute_batch(ddl)?;
        let before = admission_operation_schema_catalog(&connection)?;
        let transaction = connection.transaction()?;
        assert!(
            verify_pre_migration_schema(&transaction, 20).is_err(),
            "{ddl}"
        );
        transaction.rollback()?;
        assert_eq!(admission_operation_schema_catalog(&connection)?, before);
    }
    Ok(())
}

#[test]
fn activation_shaped_predecessor_is_rejected_without_adopting_its_rows() -> TestResult {
    let mut connection = predecessor()?;
    connection.execute_batch(
        "DROP TABLE runtime_replay_migration_events;
         CREATE TABLE runtime_replay_migration_events(sequence INTEGER, mutation_kind TEXT);
         INSERT INTO runtime_replay_migration_events VALUES(3, 'activate_runtime_replay_source');",
    )?;
    let before = admission_operation_schema_catalog(&connection)?;
    let transaction = connection.transaction()?;
    assert!(verify_pre_migration_schema(&transaction, 20).is_err());
    transaction.rollback()?;
    assert_eq!(admission_operation_schema_catalog(&connection)?, before);
    Ok(())
}
