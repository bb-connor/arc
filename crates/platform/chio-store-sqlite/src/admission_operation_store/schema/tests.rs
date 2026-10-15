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
fn canonical_catalog_does_not_recreate_a_missing_runtime_barrier() -> TestResult {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(&admission_operation_schema_sql()?)?;
    verify_admission_operation_schema(&connection)?;
    connection.execute_batch("DROP TRIGGER runtime_replay_legacy_tombstones_no_delete")?;
    let before = admission_operation_schema_catalog(&connection)?;
    assert!(verify_admission_operation_schema(&connection).is_err());
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

const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PADDING: usize = 1 << 20;

enum Probe {
    Text(String),
    Blob(Vec<u8>),
}

fn table_items(table_sql: &str) -> Vec<String> {
    let Some(open) = table_sql.find('(') else {
        return Vec::new();
    };
    let mut depth = 0usize;
    let mut quoted = false;
    let mut start = open + 1;
    let mut items = Vec::new();
    for (offset, ch) in table_sql[open..].char_indices() {
        let index = open + offset;
        match ch {
            '\'' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => {
                depth -= 1;
                if depth == 0 {
                    items.push(table_sql[start..index].trim().to_owned());
                    break;
                }
            }
            ',' if !quoted && depth == 1 => {
                items.push(table_sql[start..index].trim().to_owned());
                start = index + 1;
            }
            _ => {}
        }
    }
    items
}

fn bounded_columns(catalog: &Connection) -> rusqlite::Result<Vec<(String, String, String, bool)>> {
    let mut statement = catalog.prepare(
        "SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND sql IS NOT NULL ORDER BY name",
    )?;
    let tables = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut columns = Vec::new();
    for (table, sql) in tables {
        let strict = sql.trim_end().ends_with("STRICT") || sql.contains(") STRICT");
        for item in table_items(&sql) {
            let mut words = item.split_whitespace();
            let (Some(name), Some(kind)) = (words.next(), words.next()) else {
                continue;
            };
            if matches!(kind, "TEXT" | "BLOB") && item.contains(&format!("length({name})")) {
                columns.push((table.clone(), name.to_owned(), item.clone(), strict));
            }
        }
    }
    Ok(columns)
}

fn is_bound_refusal(result: &rusqlite::Result<usize>) -> bool {
    matches!(
        result,
        Err(rusqlite::Error::SqliteFailure(error, Some(_)))
            if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_CHECK
                || error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_DATATYPE
    )
}

fn probe_table(definition: &str, strict: bool, encoding: &str) -> rusqlite::Result<Connection> {
    let probe = Connection::open_in_memory()?;
    let suffix = if strict { " STRICT" } else { "" };
    probe.execute_batch(&format!(
        "PRAGMA encoding = '{encoding}'; PRAGMA foreign_keys = OFF;\n         CREATE TABLE probe ({definition}){suffix};"
    ))?;
    Ok(probe)
}

fn accepted(definition: &str, strict: bool) -> rusqlite::Result<Option<Probe>> {
    let probe = probe_table(definition, strict, "UTF-8")?;
    let texts = [
        HEX64.to_owned(),
        "a".to_owned(),
        "1".to_owned(),
        "operation".to_owned(),
        "0".repeat(64),
    ];
    for text in texts {
        if probe
            .execute("INSERT INTO probe VALUES (?1)", [&text])
            .is_ok()
        {
            return Ok(Some(Probe::Text(text)));
        }
    }
    for len in [1, 16, 32, 64] {
        if probe
            .execute("INSERT INTO probe VALUES (?1)", [vec![1_u8; len]])
            .is_ok()
        {
            return Ok(Some(Probe::Blob(vec![1; len])));
        }
    }
    Ok(None)
}

#[test]
fn bounded_admission_columns_refuse_nul_and_malformed_text() -> TestResult {
    let catalog = Connection::open_in_memory()?;
    catalog.execute_batch(&admission_operation_schema_sql()?)?;
    let columns = bounded_columns(&catalog)?;
    assert!(columns.len() > 150, "{} bounded columns", columns.len());
    let mut unprobed = Vec::new();
    for (table, column, definition, strict) in &columns {
        let label = format!("{table}.{column}");
        let Some(valid) = accepted(definition, *strict)? else {
            unprobed.push(label);
            continue;
        };
        for encoding in ["UTF-8", "UTF-16le"] {
            let probe = probe_table(definition, *strict, encoding)?;
            match &valid {
                Probe::Text(text) => {
                    assert_eq!(
                        probe.execute("INSERT INTO probe VALUES (?1)", [text])?,
                        1,
                        "{label}"
                    );
                    let padded = format!("{text}\0{}", "a".repeat(PADDING));
                    let refused = probe.execute("INSERT INTO probe VALUES (?1)", [&padded]);
                    assert!(
                        is_bound_refusal(&refused),
                        "{label} {encoding}: {refused:?}"
                    );
                    let mut in_width = text[..text.len() - 1].to_owned();
                    in_width.push('\0');
                    let refused = probe.execute("INSERT INTO probe VALUES (?1)", [&in_width]);
                    assert!(
                        is_bound_refusal(&refused),
                        "{label} {encoding}: {refused:?}"
                    );
                    if encoding == "UTF-8" {
                        let mut malformed = text.as_bytes().to_vec();
                        malformed.extend(std::iter::repeat_n(0x80_u8, PADDING));
                        let refused = probe
                            .execute("INSERT INTO probe VALUES (CAST(?1 AS TEXT))", [malformed]);
                        assert!(is_bound_refusal(&refused), "{label} malformed: {refused:?}");
                    }
                }
                Probe::Blob(bytes) => {
                    assert_eq!(
                        probe.execute("INSERT INTO probe VALUES (?1)", [bytes])?,
                        1,
                        "{label}"
                    );
                    let as_text = format!("{}\0{}", "a".repeat(bytes.len()), "a".repeat(PADDING));
                    let refused = probe.execute("INSERT INTO probe VALUES (?1)", [&as_text]);
                    assert!(
                        is_bound_refusal(&refused),
                        "{label} {encoding}: {refused:?}"
                    );
                }
            }
        }
    }
    assert!(
        unprobed.is_empty(),
        "no accepted probe value for {unprobed:?}"
    );
    Ok(())
}

#[test]
fn every_bounded_admission_text_column_carries_the_nul_guard() -> TestResult {
    let catalog = Connection::open_in_memory()?;
    catalog.execute_batch(&admission_operation_schema_sql()?)?;
    let mut statement = catalog
        .prepare("SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND sql IS NOT NULL")?;
    let tables = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (table, sql) in tables {
        assert!(
            !sql.contains("length(CAST("),
            "{table} bounds bytes in the database encoding"
        );
        for item in table_items(&sql) {
            let mut words = item.split_whitespace();
            let (Some(name), Some("TEXT")) = (words.next(), words.next()) else {
                continue;
            };
            if sql.contains(&format!("length({name})")) {
                assert!(
                    sql.contains(&format!("instr({name}, char(0)) = 0")),
                    "{table}.{name} is length-bounded without a NUL guard"
                );
            }
        }
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
    let definition = table_items(&sql)
        .into_iter()
        .find(|item| item.starts_with("observed_at_unix_ms "))
        .ok_or("observed_at_unix_ms is not defined")?;
    let probe = probe_table(&definition, false, "UTF-8")?;
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
