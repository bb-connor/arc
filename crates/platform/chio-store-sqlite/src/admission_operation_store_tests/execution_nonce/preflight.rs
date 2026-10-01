use super::*;
use chio_kernel::admission_operation::{
    AdmissionNoncePreflightHoldDisposition, AdmissionNoncePreflightIdentityV1,
};
use chio_kernel::budget_store::{BudgetCaptureHoldRequest, BudgetReverseHoldRequest};
use chio_kernel::BudgetStore;

#[path = "preflight/approval.rs"]
mod approval;
#[path = "preflight/qualification.rs"]
mod qualification;
#[path = "preflight/recovery.rs"]
mod recovery;

pub(super) fn own_and_clean(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    key: &Keypair,
) -> TestResult<AdmissionOperationV1> {
    let identity = AdmissionNoncePreflightIdentityV1::for_operation(operation, 0)?;
    let mut request = lifecycle::budget_request(fixture, operation);
    request
        .admission_binding
        .as_mut()
        .ok_or("binding")?
        .operation_id = identity.budget_operation_id().as_str().into();
    request.hold_id = Some(identity.hold_id().as_str().into());
    request.event_id = Some(identity.authorization_event_id().as_str().into());
    let command = nonce_command(
        &fixture.store,
        &fixture.fence,
        operation,
        key,
        Vec::new(),
        AdmissionOperationState::Prepared,
    )?;
    let (decision, operation) = fixture.store.authorize_execution_nonce_preflight(
        operation,
        command.recovery_lease(),
        request.clone(),
        now_ms(),
    )?;
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    fixture
        .authority
        .budget_store()
        .reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: request.capability_id,
            grant_index: request.grant_index,
            reversed_exposure_units: 0,
            hold_id: request.hold_id,
            event_id: Some(format!("{}:reverse", identity.hold_id().as_str())),
            expected_cumulative_approval_state: None,
            authority: request.authority,
        })?;
    Ok(operation)
}

fn identity(fixture: &NonceFixture) -> TestResult<AdmissionNoncePreflightIdentityV1> {
    Ok(AdmissionNoncePreflightIdentityV1::for_operation(
        &fixture.operation,
        0,
    )?)
}

fn request(fixture: &NonceFixture) -> TestResult<BudgetAuthorizeHoldRequest> {
    let identity = identity(fixture)?;
    let mut request = lifecycle::budget_request(&fixture.fixture, &fixture.operation);
    request
        .admission_binding
        .as_mut()
        .ok_or("binding")?
        .operation_id = identity.budget_operation_id().as_str().into();
    request.hold_id = Some(identity.hold_id().as_str().into());
    request.event_id = Some(identity.authorization_event_id().as_str().into());
    Ok(request)
}

fn lease(fixture: &NonceFixture) -> TestResult<AdmissionRecoveryLease> {
    Ok(nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        Vec::new(),
        AdmissionOperationState::Prepared,
    )?
    .recovery_lease()
    .clone())
}

fn authorize(fixture: &mut NonceFixture) -> TestResult {
    let (decision, operation) = fixture.fixture.store.authorize_execution_nonce_preflight(
        &fixture.operation,
        &lease(fixture)?,
        request(fixture)?,
        now_ms(),
    )?;
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    fixture.operation = operation;
    Ok(())
}

fn issue_command(fixture: &NonceFixture) -> TestResult<AdmissionOperationCommand> {
    nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        vec![AdmissionAttachment::ExecutionNonceIssuanceDigest(
            AdmissionDigest::try_new(
                "issuance",
                sha256_hex(fixture.reservation.canonical_bytes()),
            )?,
        )],
        AdmissionOperationState::Prepared,
    )
}

fn reverse(fixture: &NonceFixture, exposure: u64) -> TestResult {
    let request = request(fixture)?;
    fixture
        .fixture
        .authority
        .budget_store()
        .reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: request.capability_id,
            grant_index: request.grant_index,
            reversed_exposure_units: exposure,
            hold_id: request.hold_id,
            event_id: Some(format!("{}:reverse", identity(fixture)?.hold_id().as_str())),
            expected_cumulative_approval_state: None,
            authority: request.authority,
        })?;
    Ok(())
}

fn quota(fixture: &NonceFixture) -> TestResult<(u32, u32)> {
    let usage = fixture
        .fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&chio_kernel::budget_store::BudgetQuotaKey::grant(
            fixture.operation.binding().capability_id().as_str(),
            0,
        ))?
        .ok_or("missing grant quota")?;
    Ok((usage.reserved_invocations, usage.captured_invocations))
}

#[test]
fn durable_nonce_preflight_owns_and_reverses_a_distinct_physical_hold() -> TestResult {
    let mut fixture = unowned_prepared_nonce_fixture(None)?;
    let binding = fixture.operation.binding().clone();
    authorize(&mut fixture)?;
    assert_eq!(fixture.operation.binding(), &binding);
    assert_eq!(fixture.operation.state(), AdmissionOperationState::Prepared);
    assert!(fixture.operation.budget_hold_id().is_none());
    assert!(fixture
        .operation
        .execution_nonce_preflight_digest()
        .is_some());
    assert_eq!(quota(&fixture)?, (1, 0));
    let error = fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(
            &issue_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )
        .expect_err("live preflight must prevent issuance");
    assert!(
        error.to_string().contains("physical preflight reversal"),
        "{error}"
    );
    reverse(&fixture, 0)?;
    assert_eq!(quota(&fixture)?, (0, 0));
    fixture = advance_nonce_fixture(fixture, true, None, true)?;
    assert_eq!(fixture.operation.binding(), &binding);
    assert_eq!(quota(&fixture)?, (1, 0));
    assert_eq!(
        fixture
            .operation
            .budget_hold_id()
            .map(AdmissionIdentifier::as_str),
        Some("nonce-hold")
    );
    let connection = Connection::open(&fixture.fixture.database)?;
    let (holds, operations): (u32, u32) = connection.query_row(
        "SELECT COUNT(*), COUNT(DISTINCT operation_id) FROM budget_authorization_holds",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!((holds, operations), (2, 2));
    let index: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE name = 'idx_budget_holds_operation'",
        [],
        |row| row.get(0),
    )?;
    assert!(index.contains("ON budget_authorization_holds(operation_id)"));
    fixture.operation = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(
            &reserve_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )?
        .into_operation();
    let command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        Vec::new(),
        AdmissionOperationState::CapturePending,
    )?;
    fixture.operation = fixture
        .fixture
        .store
        .begin_execution_nonce_capture(&command, now_ms())?
        .into_operation();
    let command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        Vec::new(),
        AdmissionOperationState::CapturePending,
    )?;
    fixture.operation = fixture
        .fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &fixture.operation,
            command.recovery_lease(),
            lifecycle::capture_request(&fixture),
            &fixture.fixture.fence,
            now_ms(),
        )?
        .1;
    assert_eq!(quota(&fixture)?, (0, 1));
    fixture = lifecycle::reopen(fixture)?;
    assert_eq!(
        fixture.operation.state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(quota(&fixture)?, (0, 1));
    Ok(())
}

#[test]
fn durable_nonce_preflight_cannot_capture_invocations_or_money() -> TestResult {
    let mut fixture = unowned_prepared_nonce_fixture(None)?;
    let mut request = request(&fixture)?;
    request.requested_exposure_units = 5;
    request.max_cost_per_invocation = Some(5);
    request.max_total_cost_units = Some(5);
    fixture.operation = fixture
        .fixture
        .store
        .authorize_execution_nonce_preflight(
            &fixture.operation,
            &lease(&fixture)?,
            request.clone(),
            now_ms(),
        )?
        .1;
    let budget = fixture.fixture.authority.budget_store();
    let mut capture = lifecycle::capture_request(&fixture);
    capture.hold_id = identity(&fixture)?.hold_id().as_str().into();
    let error = budget
        .capture_invocation_reservations(capture)
        .expect_err("preflight invocation capture");
    assert!(
        error
            .to_string()
            .contains("preflight holds cannot be captured"),
        "{error}"
    );
    let error = budget
        .capture_budget_hold(BudgetCaptureHoldRequest {
            capability_id: request.capability_id,
            grant_index: request.grant_index,
            hold_id: request.hold_id,
            event_id: Some("preflight-spend".into()),
            exposed_cost_units: 5,
            realized_spend_units: 5,
            authority: request.authority,
        })
        .expect_err("preflight monetary capture");
    assert!(
        error
            .to_string()
            .contains("preflight holds cannot be captured"),
        "{error}"
    );
    assert_eq!(quota(&fixture)?, (1, 0));
    reverse(&fixture, 5)?;
    assert_eq!(quota(&fixture)?, (0, 0));
    Ok(())
}
