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
    // Preserve SQLite's no-symlink policy when temporary paths use an alias.
    let backup = fs::canonicalize(fixture._temp.path())?.join("before-native.db");
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
        let triggers = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        for trigger in triggers {
            tx.execute_batch(&format!("DROP TRIGGER {trigger}"))?;
        }
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

#[test]
fn warm_current_initialization_guard_requires_its_exact_selected_reference() -> AnchoredTestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let initialized = hydrate(&fixture, &source)?;
    let binding = initialized.admission_binding()?;
    let mut connection = fixture.store.connection()?;
    // The legitimate hydrated binding passes the warm guard before any tamper.
    native::verify_current_recovery_initialization(&connection, &binding)?;
    for mutation in [
        "UPDATE security_participant_state_initializations SET fingerprint_digest = printf('%064d', 0)",
        "UPDATE security_participant_state_initializations SET expectation_id = printf('%064d', 0)",
        "UPDATE security_participant_state_initializations SET store_lease_id = 'wrong-owner'",
    ] {
        let tx = connection.transaction()?;
        let mut statement = tx.prepare("SELECT name FROM sqlite_schema WHERE type = 'trigger' AND name GLOB 'security_participant_state*'")?;
        let triggers = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        for trigger in triggers {
            tx.execute_batch(&format!("DROP TRIGGER {trigger}"))?;
        }
        tx.execute_batch(mutation)?;
        tx.execute_batch(&native::schema::sql()?)?;
        let result = native::verify_current_recovery_initialization(&tx, &binding);
        assert!(
            matches!(&result, Err(AdmissionOperationStoreError::Invariant(detail))
                if detail == "native security state: current native initialization binding differs"),
            "{mutation}: {result:?}"
        );
        tx.rollback()?;
        native::verify_current_recovery_initialization(&connection, &binding)?;
    }
    for mutation in [
        "UPDATE authority_global_commits SET projection_reference_digest = printf('%064d', 0) WHERE projection_kind = 'security_participant_state' AND projection_sequence = 1",
        "UPDATE authority_global_commits SET store_lease_id = 'wrong-owner' WHERE projection_kind = 'security_participant_state' AND projection_sequence = 1",
    ] {
        let tx = connection.transaction()?;
        tx.execute_batch("DROP TRIGGER authority_global_commits_immutable")?;
        tx.execute_batch(mutation)?;
        let result = native::verify_current_recovery_initialization(&tx, &binding);
        assert!(
            matches!(&result, Err(AdmissionOperationStoreError::Invariant(detail))
                if detail == "native security state: current native initialization lost its immutable source"),
            "{mutation}: {result:?}"
        );
        tx.rollback()?;
        native::verify_current_recovery_initialization(&connection, &binding)?;
    }
    // Every disposable tamper rolled back, so the legitimate binding still
    // passes and the complete historical-state checks remain unchanged.
    native::verify_current_recovery_initialization(&connection, &binding)?;
    native::verify_all(&connection)?;
    native::verify_coverage(&connection)?;
    Ok(())
}

/// Commit one damage through the serving owner's own connection with foreign
/// keys and every native trigger lifted, then restore the exact catalog and
/// foreign-key enforcement before any read. That connection leaves
/// `data_version` unchanged, so only the warm read's own checks can refuse.
fn commit_native_damage(fixture: &Fixture, damage: &str) -> AnchoredTestResult {
    let mut connection = fixture.store.connection()?;
    // SQLite ignores `foreign_keys` inside a transaction.
    connection.pragma_update(None, "foreign_keys", false)?;
    let tx = connection.transaction()?;
    let mut statement = tx.prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'trigger'
         AND name GLOB 'security_participant_state*'",
    )?;
    let triggers = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for trigger in triggers {
        tx.execute_batch(&format!("DROP TRIGGER {trigger}"))?;
    }
    tx.execute_batch(damage)?;
    tx.execute_batch(&native::schema::sql()?)?;
    tx.commit()?;
    connection.pragma_update(None, "foreign_keys", true)?;
    Ok(())
}

/// The serving connection's read-only footprint: its accumulated change
/// counter and the global commit count. A fail-closed refusal that writes
/// nothing and appends no history leaves both exactly unchanged.
fn footprint(fixture: &Fixture) -> AnchoredTestResult<(u64, i64)> {
    let connection = fixture.store.connection()?;
    Ok((
        connection.total_changes(),
        connection.query_row("SELECT COUNT(*) FROM authority_global_commits", [], |row| {
            row.get(0)
        })?,
    ))
}

#[test]
fn warm_reads_refuse_a_missing_initialization_that_history_names() -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    imported(&fixture, "pending")?;
    // An authority no native commit names is genuinely uninitialized.
    assert_eq!(
        fixture.store.load_security_participant_state(
            &identifier("security_authority_id", "pending"),
            &fixture.fence,
            now_ms()
        )?,
        None
    );
    commit_native_damage(
        &fixture,
        "DELETE FROM security_participant_state_initializations
         WHERE security_authority_id = 'source'",
    )?;
    let refused = fixture.store.load_security_participant_state(
        initialized.security_authority_id(),
        &fixture.fence,
        now_ms(),
    );
    // Deleting the initialization row orphans its imported-scope-index child,
    // a WITHOUT ROWID table whose `PRAGMA foreign_key_check` row identity is
    // NULL. The serving owner's entry gate detects that foreign-key damage
    // first and fails the whole owner closed, so this warm read never reaches
    // its later lost-row guard. The NULL identity is reported truthfully
    // rather than decoded into an opaque sqlite error or defaulted.
    assert!(
        matches!(&refused, Err(AdmissionOperationStoreError::Invariant(detail))
            if detail == "invalid sqlite authority store: sqlite foreign key violation in `security_participant_state_imported_scope_index` row NULL (WITHOUT ROWID table)"),
        "{refused:?}"
    );
    // The first refusal permanently poisons the serving owner. The later
    // observation is refused by that exact poisoned fence, without
    // revalidating the damage or running the lost-row guard.
    let (_, request) = super::mutations::request("native-join")?;
    let observed = fixture.store.observe_security_participant_flow(
        &initialized.admission_binding()?,
        &request.key,
        &fixture.fence,
        now_ms(),
    );
    assert!(
        matches!(&observed, Err(AdmissionOperationStoreError::OutcomeUnknown(detail))
            if detail == "sqlite authority owner is poisoned after an outcome-unknown anchor sync"),
        "{observed:?}"
    );
    Ok(())
}

#[test]
fn warm_history_readback_requires_the_returned_records_exact_commit() -> AnchoredTestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, request) = super::mutations::request("native-join")?;
    let (operation, lease) = super::mutations::setup(&fixture, "native-operation", &context)?;
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    let operation_id = operation.binding().operation_id();
    let history = fixture
        .store
        .load_security_participant_flow_join(operation_id, &fixture.fence, now_ms())?
        .ok_or("committed join readback")?;
    assert_eq!(
        history.initialization_digest(),
        initialized.initialization_digest()
    );
    // A later operation moves the global head past the join's own commit.
    super::mutations::setup(&fixture, "later-operation", &context)?;
    {
        let mut connection = fixture.store.connection()?;
        let tx = connection.transaction()?;
        let guard: String = tx.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger'
             AND name = 'authority_global_commits_immutable'",
            [],
            |row| row.get(0),
        )?;
        tx.execute_batch("DROP TRIGGER authority_global_commits_immutable")?;
        tx.execute_batch(
            "UPDATE authority_global_commits SET projection_reference_digest = printf('%064d', 0)
             WHERE projection_kind = 'security_participant_state' AND projection_sequence = 2",
        )?;
        tx.execute_batch(&guard)?;
        tx.commit()?;
    }
    let refused =
        fixture
            .store
            .load_security_participant_flow_join(operation_id, &fixture.fence, now_ms());
    assert!(
        matches!(&refused, Err(AdmissionOperationStoreError::Invariant(detail))
            if detail == "native security state: native mutation lacks its exact global commit"),
        "{refused:?}"
    );
    Ok(())
}

#[test]
fn warm_reads_stay_on_requested_state_while_open_keeps_full_history() -> AnchoredTestResult {
    let fixture = fixture();
    let source = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let other = hydrate(&fixture, &imported(&fixture, "other")?)?;
    let (context, request) = super::mutations::request("other-join")?;
    let (operation, lease, _) = super::mutations::setup_selected_at(
        &fixture,
        "other-operation",
        &context,
        now_ms(),
        Some(other.admission_binding()?),
    )?;
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &other,
        &context,
        &request,
        now_ms(),
    )?;
    // Before any damage, a bounded warm read of the requested source
    // authority returns its own legitimately anchored state. The unrelated
    // other authority's genuine anchored join does not pull this read off the
    // requested state, and the synced writer commits already advanced the
    // owner's watermark, so the full validating fallback never runs.
    let validations = fixture.authority.anchor_full_validations_for_test();
    assert_eq!(
        fixture.store.load_security_participant_state(
            source.security_authority_id(),
            &fixture.fence,
            now_ms()
        )?,
        Some(source.clone())
    );
    assert_eq!(
        fixture.authority.anchor_full_validations_for_test(),
        validations
    );
    // Damage the other authority's retained join through the serving owner's
    // own connection, keeping its row checksum canonical. Its global commit and
    // the rollback anchor stay intact, so the only unexplained delta left for
    // the owner's entry gate is this unauthorized same-connection mutation.
    let bytes: Vec<u8> = fixture.store.connection()?.query_row(
        "SELECT canonical_record FROM security_participant_state_mutations
         WHERE security_authority_id = 'other'",
        [],
        |row| row.get(0),
    )?;
    let mut record: serde_json::Value = serde_json::from_slice(&bytes)?;
    record["previous"] = "0".repeat(64).into();
    let bytes = chio_core::canonical_json_bytes(&record)?;
    let mut digest_input = b"chio.native-security-mutation.commit.v1\0".to_vec();
    digest_input.extend_from_slice(&bytes);
    commit_native_damage(
        &fixture,
        &format!(
            "UPDATE security_participant_state_mutations
             SET canonical_record = X'{}', mutation_digest = '{}'
             WHERE security_authority_id = 'other'",
            hex::encode(&bytes),
            sha256_hex(&digest_input)
        ),
    )?;
    // The warm read no longer stays on the requested authority: the
    // unexplained same-connection delta forces the owner's entry gate to
    // authenticate the full store before any read or write, and the corrupted
    // join family makes that authentication fail. The refusal is read-only:
    // no SQLite writes and no new global history.
    let before = footprint(&fixture)?;
    let refused = fixture.store.load_security_participant_state(
        source.security_authority_id(),
        &fixture.fence,
        now_ms(),
    );
    assert!(
        matches!(&refused, Err(AdmissionOperationStoreError::Invariant(detail))
            if detail == "invalid sqlite authority store: admission operation invariant failed: native security state: native join family is out of global order"),
        "{refused:?}"
    );
    assert_eq!(footprint(&fixture)?, before);
    // The gate ran the full authentication exactly once before refusing, and
    // the poisoned owner stays fail-closed on every later read without
    // revalidating and without laundering the corruption into the watermark.
    assert_eq!(
        fixture.authority.anchor_full_validations_for_test(),
        validations + 1
    );
    assert!(fixture
        .store
        .load_security_participant_state(source.security_authority_id(), &fixture.fence, now_ms())
        .is_err());
    assert_eq!(
        fixture.authority.anchor_full_validations_for_test(),
        validations + 1
    );
    // Full history remains authenticated cold, by the API and at open.
    assert!(native::verify_coverage(&*fixture.store.connection()?).is_err());
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
    assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
    Ok(())
}
