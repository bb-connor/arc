use super::*;

#[test]
fn another_authority_cannot_supply_a_use_identity_or_outcome_predecessor() -> AnchoredTestResult {
    let fixture = fixture();
    let first = imported(&fixture, "first")?;
    imported(&fixture, "second")?;
    hydrate(&fixture, &first)?;
    let mut connection = fixture.store.connection()?;
    let tx = connection.transaction()?;
    let copy = |source_table: &str, predicate: &str| -> rusqlite::Result<usize> {
        let table = native::schema::TABLES
            .iter()
            .find(|table| table.source == source_table)
            .ok_or(rusqlite::Error::InvalidQuery)?;
        let columns = crate::security_state::retained_security_columns(table.source)
            .map_err(|_| rusqlite::Error::InvalidQuery)?
            .into_iter()
            .map(|column| format!("\"{column}\""))
            .collect::<Vec<_>>()
            .join(",");
        tx.execute(&format!("INSERT INTO {} (security_authority_id,{columns}) SELECT 'second',{columns} FROM {} WHERE security_authority_id = 'first' AND ({predicate})", table.native, table.native), [])
    };
    let outbox = "security_declassification_receipt_outbox";
    let pending = "phase = 'consumption' AND grant_id = 'pending'";
    let missing_use = copy(outbox, pending).expect_err("another authority cannot supply a use");
    assert!(missing_use
        .to_string()
        .contains("native evidence use binding"));
    assert_eq!(copy("security_declassification_uses", "1 = 1")?, 2);
    let missing_identity =
        copy(outbox, pending).expect_err("another authority cannot supply an identity");
    assert!(missing_identity.to_string().contains("FOREIGN KEY"));
    assert_eq!(
        copy("security_declassification_evidence_identity", "1 = 1")?,
        5
    );
    let missing_predecessor = copy(outbox, "phase = 'outcome'")
        .expect_err("another authority cannot supply a predecessor");
    assert!(missing_predecessor
        .to_string()
        .contains("native evidence predecessor"));
    assert_eq!(copy(outbox, pending)?, 1);
    tx.rollback()?;
    native::verify_coverage(&connection)?;
    Ok(())
}

#[test]
fn restoring_private_database_before_hydration_cannot_erase_the_anchored_initialization(
) -> AnchoredTestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let backup = fixture._temp.path().join("before-native.db");
    fixture.store.connection()?.execute(
        "VACUUM INTO ?1",
        [backup.to_str().ok_or("non-UTF8 fixture path")?],
    )?;
    hydrate(&fixture, &source)?;
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
    // Only this disposable test database is restored; its independent anchor
    // retains the acknowledged native initialization.
    fs::copy(&backup, &database)?;
    assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
    Ok(())
}

#[test]
fn all_inactive_rows_and_initialization_are_immutable_even_without_recursive_triggers(
) -> AnchoredTestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    hydrate(&fixture, &source)?;
    let connection = fixture.store.connection()?;
    connection.execute_batch("PRAGMA recursive_triggers = OFF")?;
    for table in native::schema::TABLES
        .iter()
        .map(|table| table.native)
        .chain(["security_participant_state_initializations"])
    {
        let count: i64 =
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        assert!(count > 0, "fixture must exercise {table}");
        for mutation in [
            format!("UPDATE {table} SET security_authority_id = security_authority_id"),
            format!("DELETE FROM {table}"),
            format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
            format!("INSERT OR IGNORE INTO {table} SELECT * FROM {table}"),
        ] {
            assert!(connection.execute_batch(&mutation).is_err(), "{mutation}");
        }
    }
    native::verify_all(&connection)?;
    native::verify_coverage(&connection)?;
    Ok(())
}

#[test]
fn actual_native_tampering_is_detected_with_canonical_catalog_restored() -> AnchoredTestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    hydrate(&fixture, &source)?;
    let mut connection = fixture.store.connection()?;
    for mutation in [
        "UPDATE security_participant_state_flow_sequences SET last_generation = last_generation + 1",
        "DELETE FROM security_participant_state_egress_fences",
        "UPDATE security_participant_state_initializations SET fingerprint_digest = printf('%064d', 0)",
        "UPDATE security_participant_state_initializations SET store_lease_id = 'wrong-owner'",
        "UPDATE security_participant_state_initializations SET store_lease_id = printf('%02000d', 0)",
    ] {
        let tx = connection.transaction()?;
        let mut statement = tx.prepare("SELECT name FROM sqlite_schema WHERE type = 'trigger' AND name GLOB 'security_participant_state*'")?;
        let triggers = statement.query_map([], |row| row.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        for trigger in triggers { tx.execute_batch(&format!("DROP TRIGGER {trigger}"))?; }
        tx.execute_batch(mutation)?;
        tx.execute_batch(&native::schema::sql()?)?;
        assert!(native::verify_all(&tx).is_err(), "{mutation}");
        tx.rollback()?;
    }
    native::verify_all(&connection)?;
    Ok(())
}

#[test]
fn orphan_native_rows_and_global_reference_mismatch_are_not_accepted() -> AnchoredTestResult {
    let fixture = fixture();
    let first = imported(&fixture, "first")?;
    imported(&fixture, "second")?;
    let mut connection = fixture.store.connection()?;
    {
        let tx = connection.transaction()?;
        tx.execute_batch(
            "INSERT INTO security_participant_state_flow_sequences VALUES ('second', 'orphan', 1)",
        )?;
        assert!(native::verify_all(&tx).is_err());
    }
    drop(connection);
    hydrate(&fixture, &first)?;
    let mut connection = fixture.store.connection()?;
    for mutation in [
        "UPDATE authority_global_commits SET projection_key = 'second' WHERE projection_kind = 'security_participant_state'",
        "UPDATE authority_global_commits SET mutation_kind = 'wrong' WHERE projection_kind = 'security_participant_state'",
        "UPDATE authority_global_commits SET projection_sequence = 2 WHERE projection_kind = 'security_participant_state'",
        "UPDATE authority_global_commits SET projection_reference_digest = printf('%064d', 0) WHERE projection_kind = 'security_participant_state'",
    ] {
        let tx = connection.transaction()?;
        tx.execute_batch("DROP TRIGGER authority_global_commits_immutable")?;
        tx.execute_batch(mutation)?;
        assert!(native::verify_coverage(&tx).is_err(), "{mutation}");
    }
    Ok(())
}
