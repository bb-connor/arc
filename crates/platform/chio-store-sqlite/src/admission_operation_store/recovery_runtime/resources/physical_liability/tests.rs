use super::*;

fn physical_fixture() -> Result<(tempfile::TempDir, Connection), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let connection = Connection::open(directory.path().join("physical-liability.sqlite"))?;
    connection.execute_batch(
        "PRAGMA page_size=4096; PRAGMA journal_mode=WAL;
         PRAGMA cache_spill=OFF; PRAGMA wal_autocheckpoint=0;",
    )?;
    let model = crate::admission_operation_store::schema::current_command_catalog_model_for_test()?;
    let mut catalog = model.prepare(
        "SELECT sql FROM main.sqlite_schema WHERE sql IS NOT NULL AND tbl_name IN (
            'admission_operation_recovery_records','admission_operation_recovery_events',
            'authority_global_commits','authority_global_commit_meta')
         ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END,name",
    )?;
    let definitions = catalog.query_map([], |row| row.get::<_, String>(0))?;
    for definition in definitions {
        connection.execute_batch(&definition?)?;
    }
    // This fixture measures the compiled current physical SQL geometry. It grants no serving owner,
    // native admission, source capability, or execution allowance.
    connection.execute_batch(crate::serving_owner::compiled_global_commit_schema())?;
    Ok((directory, connection))
}

#[test]
fn protected_command_price_covers_actual_sqlite_wal_frames(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, mut connection) = physical_fixture()?;
    let scope = "d".repeat(64);
    let key = format!("native-influence-phase:{scope}:physical-output");
    let mut plan = ProtectedCommandLiabilityPlan::new();
    plan.add_new_command(&connection, &key, &scope, 16384)?;
    let price = price_protected_command_liability(&connection, &plan)?;
    assert_eq!(price.recovery_appends(), 1);
    assert_eq!(price.global_appends(), 1);
    assert!(price.wal_bytes() > 16384);
    assert!(price.disk_bytes() >= price.wal_bytes());
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    let before = wal_pressure(&connection, false)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let payload = canonical_json_bytes(&serde_json::json!({
        "retained": "r".repeat(16384 - b"{\"retained\":\"\"}".len())
    }))?;
    assert_eq!(payload.len(), 16384);
    let digest = "0".repeat(64);
    transaction.execute(
        "INSERT INTO admission_operation_recovery_records
            (record_key,scope_key,kind,version,payload)
         VALUES(?1,?2,'command',1,?3)",
        params![key, scope, payload],
    )?;
    transaction.execute(
        "INSERT INTO admission_operation_recovery_events VALUES(1,?1,1,?2,?2,?2,1)",
        params![key, digest],
    )?;
    transaction.execute(
        "INSERT INTO authority_global_commits VALUES
            (1,'recovery_transition','recovery',?1,1,?2,?2,?2,?2,
             '00000000-0000-7000-8000-000000000001',
             '00000000-0000-7000-8000-000000000002',1)",
        params![key, digest],
    )?;
    transaction.execute(
        "UPDATE authority_global_commit_meta SET head_sequence=1,head_chain_digest=?1
         WHERE singleton=1",
        [digest],
    )?;
    transaction.commit()?;
    let written = wal_pressure(&connection, false)? - before;
    assert!(
        written > 16384,
        "actual WAL includes indexes and both histories"
    );
    assert!(
        written <= price.wal_bytes(),
        "actual {written} bytes exceed the prepaid physical price {}",
        price.wal_bytes()
    );
    Ok(())
}

#[test]
fn protected_command_price_refuses_quoted_catalog_changes() -> Result<(), Box<dyn std::error::Error>>
{
    let (_directory, connection) = physical_fixture()?;
    let scope = "c".repeat(64);
    let mut plan = ProtectedCommandLiabilityPlan::new();
    plan.add_new_command(&connection, "physical-command:catalog", &scope, 16384)?;
    let baseline = price_protected_command_liability(&connection, &plan)?;
    assert!(baseline.wal_bytes() > 0);
    let original: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name='admission_operation_recovery_event_no_update'",
        [],
        |row| row.get(0),
    )?;
    let changed = original.replace(
        "'recovery history is immutable'",
        "'recovery  history is immutable'",
    );
    assert_ne!(changed, original);
    connection.execute_batch("DROP TRIGGER admission_operation_recovery_event_no_update")?;
    connection.execute_batch(&changed)?;
    assert!(
        price_protected_command_liability(&connection, &plan).is_err(),
        "physical command pricing accepted changed quoted trigger bytes"
    );
    Ok(())
}

#[test]
fn current_command_index_families_refuse_unpriced_writes() -> Result<(), Box<dyn std::error::Error>>
{
    let (_directory, connection) = physical_fixture()?;
    let scope = "b".repeat(64);
    let mut supported = ProtectedCommandLiabilityPlan::new();
    supported.add_new_command(
        &connection,
        &format!("native-influence-phase:{scope}:unpriced-index-control"),
        &scope,
        16384,
    )?;
    assert!(price_protected_command_liability(&connection, &supported)?.wal_bytes() > 0);
    for (name, key) in [
        (
            "admission_operation_recovery_command_alias",
            format!("command-alias:{scope}:current-index-control"),
        ),
        (
            "admission_operation_recovery_first_report",
            format!("command:{scope}:current-index-control"),
        ),
        (
            "admission_operation_recovery_reference_capacity",
            format!("knowledge-reference-capacity:{scope}"),
        ),
        (
            "idx_recovery_knowledge_journal_chunk_authority",
            format!("knowledge-encoding-chunk:{scope}:{}:0000", "c".repeat(64)),
        ),
    ] {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type='index' AND name=?1)",
            [name],
            |row| row.get(0),
        )?;
        assert!(present, "the compiled current command index is present");
        let mut plan = ProtectedCommandLiabilityPlan::new();
        plan.add_new_command(&connection, &key, &scope, 16384)?;
        let error = price_protected_command_liability(&connection, &plan)
            .err()
            .ok_or("an unpriced current command index received a physical quote")?;
        assert!(error
            .to_string()
            .contains("current command partial index writer is not priced"));
    }
    Ok(())
}

#[test]
fn protected_command_price_refuses_unpriced_temporary_triggers(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, connection) = physical_fixture()?;
    let scope = "a".repeat(64);
    let mut plan = ProtectedCommandLiabilityPlan::new();
    plan.add_new_command(
        &connection,
        "physical-command:temporary-trigger",
        &scope,
        16384,
    )?;
    assert!(price_protected_command_liability(&connection, &plan)?.wal_bytes() > 0);
    connection.execute_batch(
        "CREATE TABLE physical_command_unpriced_bytes(payload BLOB);
         CREATE TEMP TRIGGER unpriced_physical_command_write
         AFTER INSERT ON main.admission_operation_recovery_records
         BEGIN INSERT INTO physical_command_unpriced_bytes(payload)
           VALUES(zeroblob(8388608)); END;",
    )?;
    // The actual TEMP trigger writes the main database. Roll back this control
    // so the priced command remains pristine and no orphan history survives.
    connection.execute_batch("SAVEPOINT temporary_trigger_control")?;
    connection.execute(
        "INSERT INTO main.admission_operation_recovery_records
            (record_key,scope_key,kind,version,payload)
         VALUES('physical-command:temporary-trigger-control',?1,'command',1,x'7b7d')",
        [&scope],
    )?;
    let written: i64 = connection.query_row(
        "SELECT sum(length(payload)) FROM main.physical_command_unpriced_bytes",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(written, 8388608);
    connection.execute_batch(
        "ROLLBACK TO temporary_trigger_control; RELEASE temporary_trigger_control;",
    )?;
    assert!(
        price_protected_command_liability(&connection, &plan).is_err(),
        "physical command pricing accepted an unpriced temporary trigger"
    );
    Ok(())
}

#[test]
fn progress_preservation_refuses_temporary_global_head_shadow(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, connection) = physical_fixture()?;
    connection.execute(
        "UPDATE main.authority_global_commit_meta SET head_sequence=?1 WHERE singleton=1",
        [9007199254740990_i64],
    )?;
    let current = PhysicalLiabilityData {
        global_appends: 2,
        ..PhysicalLiabilityData::zero()
    };
    let other = PhysicalLiabilityData::zero();
    assert!(require_progress_preserving_liability(&connection, &other, &current).is_err());
    connection.execute_batch(
        "CREATE TEMP TABLE authority_global_commit_meta(
            singleton INTEGER PRIMARY KEY,head_sequence INTEGER);
         INSERT INTO temp.authority_global_commit_meta VALUES(1,0);",
    )?;
    assert!(
        require_progress_preserving_liability(&connection, &other, &current).is_err(),
        "temporary metadata shadow concealed the actual global head"
    );
    Ok(())
}

#[test]
fn physical_amounts_preserve_every_family_tail_and_reject_overflow(
) -> Result<(), Box<dyn std::error::Error>> {
    let native = PhysicalLiabilityData {
        wal_bytes: 40 * MIB,
        disk_bytes: 80 * MIB,
        recovery_appends: 14,
        global_appends: 16,
    };
    let confined = PhysicalLiabilityData {
        wal_bytes: 8 * MIB,
        disk_bytes: 16 * MIB,
        recovery_appends: 4,
        global_appends: 4,
    };
    let combined = native.checked_add(&confined)?;
    assert_eq!(combined.wal_bytes(), 48 * MIB);
    assert_eq!(combined.disk_bytes(), 96 * MIB);
    assert_eq!(combined.recovery_appends(), 18);
    assert_eq!(combined.global_appends(), 20);
    assert_eq!(combined.checked_sub(&confined)?, native);
    assert!(native.checked_sub(&combined).is_err());
    assert!(combined
        .checked_add(&PhysicalLiabilityData {
            wal_bytes: u64::MAX,
            ..PhysicalLiabilityData::zero()
        })
        .is_err());
    Ok(())
}

#[test]
fn physical_amounts_refuse_invalid_operands_before_balancing_totals() {
    let invalid_disk_tail = PhysicalLiabilityData {
        wal_bytes: 2,
        disk_bytes: 1,
        ..PhysicalLiabilityData::zero()
    };
    let additional_disk = PhysicalLiabilityData {
        disk_bytes: 1,
        ..PhysicalLiabilityData::zero()
    };
    assert!(
        invalid_disk_tail.checked_add(&additional_disk).is_err(),
        "a valid sum normalized an invalid retained WAL and disk operand"
    );
    assert!(
        additional_disk.checked_add(&invalid_disk_tail).is_err(),
        "a valid sum normalized an invalid added WAL and disk operand"
    );
    assert!(
        invalid_disk_tail.checked_sub(&invalid_disk_tail).is_err(),
        "subtracting the same invalid retained tail concealed its malformed bounds"
    );
    for invalid_history_tail in [
        PhysicalLiabilityData {
            recovery_appends: MAX_TRUSTED_UNIX_MS + 1,
            ..PhysicalLiabilityData::zero()
        },
        PhysicalLiabilityData {
            global_appends: MAX_TRUSTED_UNIX_MS + 1,
            ..PhysicalLiabilityData::zero()
        },
    ] {
        assert!(
            invalid_history_tail
                .checked_sub(&invalid_history_tail)
                .is_err(),
            "subtracting invalid history bounds minted a valid zero tail"
        );
    }
}

#[test]
fn funded_progress_cannot_spend_other_owed_event_sequences(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, connection) = physical_fixture()?;
    let scope = "e".repeat(64);
    connection.execute(
        "INSERT INTO admission_operation_recovery_records
            (record_key,scope_key,kind,version,payload)
         VALUES('native-influence-phase:retained',?1,'command',1,x'7b7d')",
        [&scope],
    )?;
    let max_safe = 9007199254740991_i64;
    let digest = "0".repeat(64);
    connection.execute(
        "INSERT INTO admission_operation_recovery_events VALUES(?1,
            'native-influence-phase:retained',1,?2,?2,?2,1)",
        params![max_safe - 3, digest],
    )?;
    connection.execute(
        "UPDATE authority_global_commit_meta SET head_sequence=?1 WHERE singleton=1",
        [max_safe - 3],
    )?;
    let other_owed = PhysicalLiabilityData {
        recovery_appends: 2,
        global_appends: 2,
        ..PhysicalLiabilityData::zero()
    };
    let current_write = PhysicalLiabilityData {
        recovery_appends: 1,
        global_appends: 1,
        ..PhysicalLiabilityData::zero()
    };
    require_progress_preserving_liability(&connection, &other_owed, &current_write)?;
    connection.execute(
        "UPDATE authority_global_commit_meta SET head_sequence=?1 WHERE singleton=1",
        [max_safe - 2],
    )?;
    assert!(
        require_progress_preserving_liability(&connection, &other_owed, &current_write).is_err()
    );
    Ok(())
}
