use super::*;

fn migrate(fixture: NonceFixture) -> TestResult<NonceFixture> {
    fixture.fixture.store.connection()?.execute_batch(
        "DROP TABLE admission_execution_nonce_issuances;
         UPDATE chio_store_schema_versions SET version = 14 WHERE store_key = 'admission_operation';",
    )?;
    lifecycle::reopen(fixture)
}

#[test]
fn durable_nonce_issuance_v14_ready_cannot_gain_fresh_capture_authority() -> TestResult {
    let mut fixture = migrate(domain::historical_ready(true, false)?)?;
    assert!(load(&fixture)?.is_none());
    let command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        Vec::new(),
        AdmissionOperationState::CapturePending,
    )?;
    let error = fixture
        .fixture
        .store
        .begin_execution_nonce_capture(&command, now_ms())
        .expect_err("unissued historical nonce gained fresh capture authority");
    assert!(
        error.to_string().contains("requires durable issuance"),
        "{error}"
    );
    assert_eq!(lifecycle::state(&fixture)?, ("authorized".into(), 0, 0));
    lifecycle::release(&fixture)?;
    fixture
        .fixture
        .store
        .commit_terminal_projection(&lifecycle::projection(&fixture)?)?;
    fixture = lifecycle::reopen(fixture)?;
    assert_eq!(
        fixture.operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(load(&fixture)?.is_none());
    assert_eq!(lifecycle::state(&fixture)?, ("reversed".into(), 1, 0));
    Ok(())
}

fn historical_pending() -> TestResult<NonceFixture> {
    let mut fixture = domain::historical_ready(true, false)?;
    let command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        Vec::new(),
        AdmissionOperationState::CapturePending,
    )?;
    let at = now_ms();
    let pending = fixture
        .operation
        .apply_command(&command, at)?
        .into_operation();
    let bytes = canonical_json_bytes(&pending.to_persisted())?;
    let digest = sha256_hex(&canonical_json_bytes(&serde_json::json!({
        "schema": "chio.admission-execution-nonce-capture-preparation.v1",
        "reservation_digest": sha256_hex(fixture.reservation.canonical_bytes()),
        "operation_digest": sha256_hex(&bytes),
        "recorded_at_unix_ms": at,
    }))?);
    {
        let store = &fixture.fixture.store;
        let mut connection = store.connection()?;
        let transaction = store.begin_write(&mut connection, Some(&fixture.fixture.fence))?;
        crate::admission_operation_store::participant::advance_participant_bound_operation_tx(
            &transaction,
            &store.serving_owner,
            &fixture.operation,
            command.recovery_lease(),
            &pending,
            &digest,
            at,
        )?;
        transaction.execute(
            "INSERT INTO admission_execution_nonce_transitions
                (operation_id, kind, operation_json, recorded_at_unix_ms, participant_digest)
             VALUES (?1, 'capture_pending', ?2, ?3, ?4)",
            params![
                pending.binding().operation_id().as_str(),
                bytes,
                i64::try_from(at)?,
                digest
            ],
        )?;
        store.commit_write(transaction)?;
        store.sync_after_write(&connection)?;
    }
    fixture.operation = pending;
    Ok(fixture)
}

#[test]
fn durable_nonce_issuance_v14_pending_capture_rolls_back_and_can_cancel() -> TestResult {
    let mut fixture = migrate(historical_pending()?)?;
    let command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        Vec::new(),
        AdmissionOperationState::CapturePending,
    )?;
    let error = fixture
        .fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &fixture.operation,
            command.recovery_lease(),
            lifecycle::capture_request(&fixture),
            &fixture.fixture.fence,
            now_ms(),
        )
        .expect_err("unissued historical nonce captured quota");
    assert!(
        error.to_string().contains("requires durable issuance"),
        "{error}"
    );
    assert_eq!(lifecycle::state(&fixture)?, ("authorized".into(), 1, 0));
    lifecycle::release(&fixture)?;
    fixture
        .fixture
        .store
        .commit_terminal_projection(&lifecycle::projection(&fixture)?)?;
    fixture = lifecycle::reopen(fixture)?;
    assert_eq!(
        fixture.operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(load(&fixture)?.is_none());
    assert_eq!(lifecycle::state(&fixture)?, ("reversed".into(), 2, 0));
    Ok(())
}
