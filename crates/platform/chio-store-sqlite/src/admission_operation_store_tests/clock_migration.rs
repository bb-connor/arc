use super::*;

#[test]
fn v16_upgrade_preserves_old_hashes_and_anchors_then_appends_v2() -> AnchoredTestResult {
    let fixture = fixture();
    let now = now_ms() / 1_000 * 1_000;
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(now / 1_000, std::iter::empty());
    let legacy = legacy_clock::LegacyClock::enter();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "legacy-clock",
        "legacy-cap",
    );
    fixture.store.begin(&operation, &fixture.fence, now)?;
    drop(legacy);
    let old_head = {
        let connection = fixture.store.connection()?;
        let expected = sha256_hex(&canonical_json_bytes(&serde_json::json!({
            "format": "chio.admission-operation-commit-chain.v1",
            "previous_chain_digest": GENESIS_CHAIN_DIGEST,
            "commit_sequence": 1,
            "operation_id": operation.binding().operation_id().as_str(),
            "operation_version": 1,
            "mutation_kind": "begin",
            "operation_digest": sha256_hex(&encode_operation(&operation)?),
            "recovery_claim_digest": null,
            "store_uuid": fixture.fence.store_uuid,
            "store_lease_id": fixture.fence.lease_id,
            "store_owner_epoch": fixture.fence.owner_epoch,
            "recorded_at_unix_ms": now,
        }))?);
        let head = load_admission_commit_head(&connection)?;
        assert_eq!(
            head.chain_digest, expected,
            "independently encoded v1 payload"
        );
        head
    };
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
    super::runtime_replay::remove_empty_v19_runtime_tables(&connection)?;
    connection.execute_batch(
        "ALTER TABLE admission_operation_commits DROP COLUMN observed_at_unix_ms;
         UPDATE chio_store_schema_versions SET version = 16 WHERE store_key = 'admission_operation';"
    )?;
    drop(connection);
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    {
        let connection = store.connection()?;
        assert_eq!(load_admission_commit_head(&connection)?, old_head);
        let observed: Option<i64> = connection.query_row(
            "SELECT observed_at_unix_ms FROM admission_operation_commits WHERE commit_sequence = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(observed, None);
    }
    assert_eq!(
        store.load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    let fence = authority.mutation_fence();
    let new = prepared_operation(
        &fence,
        AdmissionOperationKind::ToolDispatch,
        "new-clock",
        "new-cap",
    );
    {
        let _lagging = chio_kernel::scope_fixed_runtime_for_current_thread(
            now / 1_000 - 1,
            std::iter::empty(),
        );
        assert!(matches!(store.begin(&new, &fence, now),
            Err(AdmissionOperationStoreError::Invariant(message)) if message.contains("authority time regressed")));
    }
    store.begin(&new, &fence, now - 1)?;
    let connection = store.connection()?;
    let current = verify_admission_commit_chain(&connection)?;
    verify_admission_commit_suffix(&connection, &old_head, &current)?;
    verify_admission_operation_invariants(&connection)?;
    assert_eq!(current.head_sequence, 2);
    assert_eq!(current.trusted_time_high_water_unix_ms, now);
    Ok(())
}

#[test]
fn observed_clock_is_authenticated_and_cannot_be_removed_or_forged() -> AnchoredTestResult {
    for replacement in ["NULL", "observed_at_unix_ms + 1"] {
        let fixture = fixture();
        let operation = prepared_operation(
            &fixture.fence,
            AdmissionOperationKind::ToolDispatch,
            "tamper-clock",
            "tamper-cap",
        );
        fixture.store.begin(&operation, &fixture.fence, now_ms())?;
        let connection = fixture.store.connection()?;
        connection.execute_batch("DROP TRIGGER admission_operation_commits_immutable;")?;
        connection.execute_batch(&format!(
            "UPDATE admission_operation_commits SET observed_at_unix_ms = {replacement};"
        ))?;
        assert!(verify_admission_commit_chain(&connection).is_err());
    }
    Ok(())
}

#[test]
fn current_version_cannot_silently_regenerate_a_missing_observation_column() -> AnchoredTestResult {
    let fixture = fixture();
    let mut connection = fixture.store.connection()?;
    connection.execute_batch(
        "ALTER TABLE admission_operation_commits DROP COLUMN observed_at_unix_ms;",
    )?;
    assert!(initialize_admission_operation_schema(&mut connection).is_err());
    Ok(())
}

#[test]
fn failed_upgrade_rolls_back_and_restores_foreign_key_enforcement() -> AnchoredTestResult {
    let fixture = fixture();
    let mut connection = fixture.store.connection()?;
    super::runtime_replay::remove_empty_v19_runtime_tables(&connection)?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA legacy_alter_table = OFF;
         ALTER TABLE admission_operation_commits DROP COLUMN observed_at_unix_ms;
         DROP TRIGGER admission_operation_commits_immutable;
         UPDATE chio_store_schema_versions SET version = 16 WHERE store_key = 'admission_operation';"
    )?;
    assert!(initialize_admission_operation_schema(&mut connection).is_err());
    assert!(connection.pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))?);
    assert!(
        !connection.pragma_query_value(None, "legacy_alter_table", |row| row.get::<_, bool>(0))?
    );
    let version: i32 = connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(version, 16);
    let exact_lease_survives: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'admission_operation_commits_exact_lease')", [], |row| row.get(0))?;
    assert!(
        exact_lease_survives,
        "a failed rebuild must roll back its earlier DDL"
    );
    Ok(())
}
