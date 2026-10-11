//! Metadata-only predecessor qualification on isolated, genuinely completed calls.
use super::*;

fn v3_catalog(connection: &Connection) -> Result<(), Box<dyn Error>> {
    connection.execute_batch(
        "DROP INDEX tool_outcomes_raw_digest_owners;
        DROP INDEX tool_outcomes_resolved_digest_owners;
        DROP INDEX post_return_evaluations_resolved_digest_owners;
        DROP TRIGGER tool_outcome_blobs_compaction_requires_terminal;",
    )?;
    connection.execute_batch(include_str!(
        "../../../../chio-store-sqlite/src/tool_outcome_store.sql"
    ))?;
    connection.execute(
        "UPDATE chio_store_schema_versions SET version=3 WHERE store_key='tool_outcome'",
        [],
    )?;
    Ok(())
}

#[test]
fn durable_payload_maintenance_verified_v3_migration_preserves_identity_and_cold_replay(
) -> TestResult {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let directory = private_tempdir()?;
    let database = directory.path().join("qualified-v3.db");
    let runtime =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let calls = Arc::new(AtomicU64::new(0));
    let kernel = configured_kernel(&runtime, calls.clone())?;
    let request = request_with_credentials(&kernel, &runtime.kernel_keypair(), "qualified-v3")?;
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let metadata = receipt_operation(&response.receipt)?;
    let authority = runtime.local_authority_store().ok_or("missing authority")?;
    let outcome = authority
        .tool_outcome_store()
        .lookup_by_operation(&metadata.operation_id)?
        .ok_or("missing outcome")?;
    let fence = authority.mutation_fence();
    let key = runtime.kernel_keypair().public_key();
    let operation = authority
        .admission_operation_store()
        .load_by_operation_id(&metadata.operation_id)?
        .ok_or("missing operation")?;
    drop(authority);
    drop(kernel);
    drop(runtime);
    {
        let connection = Connection::open(&database)?;
        v3_catalog(&connection)?;
    }
    let migrated =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let authority = migrated
        .local_authority_store()
        .ok_or("missing migrated authority")?;
    assert_eq!(authority.mutation_fence().store_uuid, fence.store_uuid);
    assert!(authority.mutation_fence().owner_epoch > fence.owner_epoch);
    assert_eq!(migrated.kernel_keypair().public_key(), key);
    assert_eq!(
        authority
            .admission_operation_store()
            .load_by_operation_id(&metadata.operation_id)?,
        Some(operation)
    );
    assert_eq!(
        authority
            .tool_outcome_store()
            .lookup_by_operation(&metadata.operation_id)?,
        Some(outcome.clone())
    );
    assert_eq!(
        canonical_json_bytes(
            &authority
                .admission_operation_store()
                .load_chio_receipt(&response.receipt.id)?
                .ok_or("missing receipt")?
        )?,
        canonical_json_bytes(&response.receipt)?
    );
    let connection = Connection::open_with_flags(&database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let version: i64 = connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key='tool_outcome'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(version, 4);
    drop(connection);
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    migrated.start_terminal_payload_maintenance(test_maintenance_config())?;
    wait_for_health(&migrated, |health| health.compacted == 1)?;
    assert!(!raw_payload_present(
        &database,
        outcome.raw_output_digest().as_str()
    )?);
    migrated.shutdown_terminal_payload_maintenance()?;
    drop(authority);
    drop(migrated);
    let reopened =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let recovered = configured_kernel(&reopened, calls.clone())?;
    let replay = recovered.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.output, response.output);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn durable_payload_maintenance_refuses_damaged_v3_current_and_future_catalogs() -> TestResult {
    for profile in ["v3", "current", "future"] {
        let directory = private_tempdir()?;
        let database = directory.path().join(format!("{profile}.db"));
        let runtime =
            DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
        drop(runtime);
        let expected_version;
        {
            let connection = Connection::open(&database)?;
            match profile {
                "v3" => {
                    v3_catalog(&connection)?;
                    connection.execute_batch("DROP TRIGGER tool_outcome_blobs_immutable")?;
                    expected_version = 3;
                }
                "current" => {
                    connection.execute_batch("DROP INDEX tool_outcomes_raw_digest_owners")?;
                    expected_version = 4;
                }
                _ => {
                    connection.execute("UPDATE chio_store_schema_versions SET version=5 WHERE store_key='tool_outcome'",[])?;
                    expected_version = 5;
                }
            }
        }
        let error =
            DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())
                .err()
                .ok_or("damaged or future catalog must fail closed")?;
        assert!(
            matches!(&error, CliError::SqliteServingOwner(_)),
            "actual catalog refusal: {error:?}"
        );
        let connection = Connection::open_with_flags(&database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let version: i64 = connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key='tool_outcome'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            version, expected_version,
            "refusal must not stamp/migrate damaged source"
        );
    }
    Ok(())
}
