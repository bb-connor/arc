use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

#[test]
fn canonical_catalog_does_not_recreate_a_missing_source_guard() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(&admission_operation_schema_sql()?)?;
    verify_admission_operation_schema(&connection)?;
    connection.execute_batch("DROP TRIGGER runtime_source_qualifications_no_delete")?;
    let before = admission_operation_schema_catalog(&connection)?;
    assert!(verify_admission_operation_schema(&connection).is_err());
    assert_eq!(admission_operation_schema_catalog(&connection)?, before);
    Ok(())
}

#[test]
fn runtime_source_rejects_hidden_rowid_replacement() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch("PRAGMA foreign_keys = OFF; PRAGMA recursive_triggers = OFF;")?;
    connection.execute_batch(RUNTIME_SOURCE_SCHEMA)?;
    let digest = "0".repeat(64);
    let table = "runtime_source_qualifications";
    let columns = "runtime_authority_id, source_id, qualification_id, destination_store_uuid, canonical_source, observed_at_unix_ms, store_lease_id, store_owner_epoch, record_digest";
    let values =
        format!("'runtime', 'source', '{digest}', 'destination', X'01', 1, 'lease', 1, '{digest}'");
    connection.execute(
        &format!("INSERT INTO {table} ({columns}) VALUES ({values})"),
        [],
    )?;
    let before = physical_rows(&connection, table)?;
    let replacement = values
        .replace("'runtime'", "'other-runtime'")
        .replace("'source'", "'other-source'")
        .replace(&digest, &"1".repeat(64));
    for hidden_key in ["rowid", "_rowid_", "oid"] {
        let error = connection.execute(
            &format!("INSERT OR REPLACE INTO {table} ({hidden_key}, {columns}) VALUES (1, {replacement})"), [],
        ).err().ok_or("implicit rowid replacement unexpectedly succeeded")?;
        assert_eq!(
            error.to_string(),
            format!("table {table} has no column named {hidden_key}")
        );
        assert_eq!(physical_rows(&connection, table)?, before);
    }
    for sql in [
        "UPDATE runtime_source_qualifications SET source_id = 'different'",
        "DELETE FROM runtime_source_qualifications",
        "INSERT OR REPLACE INTO runtime_source_qualifications SELECT * FROM runtime_source_qualifications",
    ] {
        let error = connection.execute(sql, []).err().ok_or("source qualification changed")?;
        assert_eq!(error.to_string(), "runtime source qualification is immutable");
        assert_eq!(physical_rows(&connection, table)?, before);
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

#[test]
fn commit_observed_clock_is_required() -> TestResult {
    let catalog = Connection::open_in_memory()?;
    catalog.execute_batch(&admission_operation_schema_sql()?)?;
    let sql: String = catalog.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'admission_operation_commits'",
        [],
        |row| row.get(0),
    )?;
    let definition = crate::text_bounds_tests::column_definition(&sql, "observed_at_unix_ms")
        .ok_or("observed_at_unix_ms is not defined")?;
    let probe = Connection::open_in_memory()?;
    probe.execute_batch(&format!("CREATE TABLE probe ({definition});"))?;
    assert_eq!(probe.execute("INSERT INTO probe VALUES (1)", [])?, 1);
    let error = probe
        .execute("INSERT INTO probe VALUES (NULL)", [])
        .err()
        .ok_or("a commit without an observed clock was stored")?;
    assert_eq!(
        error.to_string(),
        "NOT NULL constraint failed: probe.observed_at_unix_ms"
    );
    Ok(())
}
