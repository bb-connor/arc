use super::*;

fn historical_issuance() -> TestResult<NonceFixture> {
    let mut fixture = unowned_prepared_nonce_fixture(None)?;
    let command = issue_command(&fixture)?;
    let at = now_ms();
    let issued = fixture
        .operation
        .apply_command(&command, at)?
        .into_operation();
    let snapshot = canonical_json_bytes(&issued.to_persisted())?;
    let artifact = fixture.reservation.canonical_bytes();
    let digest = sha256_hex(&canonical_json_bytes(&serde_json::json!({
        "schema": "chio.admission-execution-nonce-issuance-commit.v1",
        "issuance_digest": sha256_hex(artifact), "operation_digest": sha256_hex(&snapshot),
        "issued_at_unix_ms": at,
    }))?);
    {
        // Reconstruct the v15 writer and its genuine shared authority commit.
        // Never ask the fresh v16 port to fabricate migration history.
        let store = &fixture.fixture.store;
        let mut connection = store.connection()?;
        let transaction = store.begin_write(&mut connection, Some(&fixture.fixture.fence))?;
        crate::admission_operation_store::participant::advance_participant_bound_operation_tx(
            &transaction,
            &store.serving_owner,
            &fixture.operation,
            command.recovery_lease(),
            &issued,
            &digest,
            at,
        )?;
        transaction.execute(
            "INSERT INTO admission_execution_nonce_issuances
             (operation_id, nonce_id, issuer, issuance_json, operation_json, issued_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                issued.binding().operation_id().as_str(),
                fixture.reservation.nonce_id().as_str(),
                fixture.key.public_key().to_hex(),
                artifact,
                snapshot,
                i64::try_from(at)?
            ],
        )?;
        store.commit_write(transaction)?;
        store.sync_after_write(&connection)?;
    }
    fixture.operation = issued;
    Ok(fixture)
}

fn migrate(fixture: NonceFixture) -> TestResult<NonceFixture> {
    fixture.fixture.store.connection()?.execute_batch(
        "DROP TABLE admission_nonce_preflight_holds;
         UPDATE chio_store_schema_versions SET version = 15 WHERE store_key = 'admission_operation';",
    )?;
    lifecycle::reopen(fixture)
}

#[test]
fn durable_nonce_preflight_v15_issuance_is_history_not_fresh_authority() -> TestResult {
    let fixture = migrate(historical_issuance()?)?;
    let retained = fixture
        .fixture
        .store
        .load_execution_nonce_issuance(
            fixture.operation.binding().operation_id(),
            &fixture.fixture.fence,
            now_ms(),
        )?
        .ok_or("lost old issuance")?;
    assert_eq!(
        retained.canonical_bytes(),
        fixture.reservation.canonical_bytes()
    );
    let error = fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(
            &issue_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )
        .expect_err("unowned old issuance cannot be freshly retried");
    assert!(
        error.to_string().contains("operation-owned preflight"),
        "{error}"
    );
    let fixture = unowned_prepared_nonce_fixture(None)?;
    let error = fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(
            &issue_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )
        .expect_err("new issuance cannot omit preflight");
    assert!(
        error.to_string().contains("operation-owned preflight"),
        "{error}"
    );
    Ok(())
}

#[test]
fn durable_nonce_preflight_v15_ready_cannot_reserve_or_prepare_capture() -> TestResult {
    let fixture = migrate(domain::historical_ready_from(
        historical_issuance()?,
        true,
        false,
    )?)?;
    let error = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(
            &reserve_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )
        .expect_err("v15 reservation retry cannot gain preflight authority");
    assert!(
        error.to_string().contains("operation-owned preflight"),
        "{error}"
    );
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
        .expect_err("v15 capture preparation cannot gain preflight authority");
    assert!(
        error.to_string().contains("operation-owned preflight"),
        "{error}"
    );
    assert_eq!(quota(&fixture)?, (1, 0));
    Ok(())
}

#[test]
fn durable_nonce_preflight_v15_pending_capture_rolls_back_and_can_cancel() -> TestResult {
    let fixture = domain::historical_ready_from(historical_issuance()?, true, false)?;
    let mut fixture = migrate(issuance::recovery::historical_pending_from(fixture)?)?;
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
        .expect_err("v15 capture must not consume quota");
    assert!(
        error.to_string().contains("operation-owned preflight"),
        "{error}"
    );
    assert_eq!(quota(&fixture)?, (1, 0));
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
    assert!(fixture
        .operation
        .execution_nonce_preflight_digest()
        .is_none());
    assert_eq!(quota(&fixture)?, (0, 0));
    Ok(())
}
