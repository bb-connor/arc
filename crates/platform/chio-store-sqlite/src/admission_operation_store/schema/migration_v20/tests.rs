use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn predecessor() -> Result<Connection, rusqlite::Error> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(&predecessor_schema())?;
    connection.execute_batch(include_str!("../../../admission_operation_nonce.sql"))?;
    connection.execute_batch(include_str!(
        "../../../admission_operation_nonce_preflight.sql"
    ))?;
    connection.execute_batch(&migration_v21::predecessor_schema())?;
    Ok(connection)
}

#[test]
fn v19_catalog_upgrade_is_exact_and_preserves_connection_settings() -> TestResult {
    assert_eq!(ADMISSION_OPERATION_SCHEMA.matches(CLAIM_KINDS).count(), 1);
    assert_eq!(ADMISSION_OPERATION_SCHEMA.matches(CLAIM_CONTEXT).count(), 1);
    let mut connection = predecessor()?;
    verify_pre_migration_schema(&connection, 19)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    migration_v17::preserving_parent_names(&mut connection, |connection| {
        let transaction = connection.transaction().map_err(sqlite_error)?;
        migrate_commit_kinds(&transaction)?;
        transaction
            .execute_batch(RUNTIME_PARTICIPANT_SCHEMA)
            .map_err(sqlite_error)?;
        verify_admission_operation_schema(&transaction, 20)?;
        transaction.commit().map_err(sqlite_error)
    })?;
    assert!(connection.pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))?);
    assert!(
        !connection.pragma_query_value(None, "legacy_alter_table", |row| row.get::<_, bool>(0))?
    );
    Ok(())
}

#[test]
fn v19_damage_and_partial_claim_namespace_are_not_repaired() -> TestResult {
    for ddl in [
        "DROP TRIGGER admission_operation_commits_no_delete",
        "DROP TRIGGER runtime_replay_legacy_tombstones_no_delete",
        "CREATE TABLE RUNTIME_REPLAY_CLAIM_EPISODES(value INTEGER)",
    ] {
        let connection = predecessor()?;
        connection.execute_batch(ddl)?;
        let before = admission_operation_schema_catalog(&connection)?;
        assert!(verify_pre_migration_schema(&connection, 19).is_err());
        assert_eq!(admission_operation_schema_catalog(&connection)?, before);
    }
    Ok(())
}

#[test]
fn older_versions_cannot_adopt_claim_tables() -> TestResult {
    for version in [0, 1, 16, 17, 18, 19] {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(RUNTIME_PARTICIPANT_SCHEMA)?;
        assert!(verify_pre_migration_schema(&connection, version).is_err());
    }
    Ok(())
}

#[test]
fn claim_rows_reject_replacement_mutation_and_unbounded_fields() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch("PRAGMA foreign_keys = OFF; PRAGMA recursive_triggers = OFF")?;
    connection.execute_batch(RUNTIME_PARTICIPANT_SCHEMA)?;
    let digest = "a".repeat(64);
    let insert = "INSERT INTO runtime_replay_claim_episodes
        (operation_id, episode_id, runtime_authority_id, ledger_digest, claim_digest, claim_json, operation_json)
        VALUES (?1, ?2, 'runtime', ?3, ?3, ?4, X'01')";
    for (operation, episode, hash, body) in [
        (
            "o".repeat(513),
            "episode".into(),
            digest.clone(),
            vec![1_u8],
        ),
        ("operation".into(), "e".repeat(513), digest.clone(), vec![1]),
        (
            "operation".into(),
            "episode".into(),
            "A".repeat(64),
            vec![1],
        ),
        (
            "operation".into(),
            "episode".into(),
            digest.clone(),
            vec![1; 16385],
        ),
    ] {
        assert!(connection
            .execute(insert, params![operation, episode, hash, body])
            .is_err());
    }
    connection.execute(insert, params!["operation", "episode", digest, vec![1_u8]])?;
    for sql in [
        "UPDATE runtime_replay_claim_episodes SET episode_id = 'different'",
        "DELETE FROM runtime_replay_claim_episodes",
        "INSERT OR REPLACE INTO runtime_replay_claim_episodes SELECT * FROM runtime_replay_claim_episodes",
        "INSERT OR REPLACE INTO runtime_replay_claim_episodes(rowid) VALUES(1)",
    ] {
        assert!(connection.execute(sql, []).is_err(), "{sql}");
    }
    Ok(())
}
