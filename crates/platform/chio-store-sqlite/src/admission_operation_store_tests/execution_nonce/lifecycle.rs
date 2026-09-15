use super::*;
use chio_kernel::admission_operation::verified_released_pre_dispatch_compensation_projection_for_test;
use chio_kernel::budget_store::BudgetReverseHoldRequest;
use chio_kernel::BudgetStore;

#[path = "lifecycle/approval.rs"]
mod approval;
#[path = "lifecycle/recovery.rs"]
mod recovery;
pub(super) use approval::reserve_approvals;
pub(super) use recovery::reopen;

pub(super) fn budget_request(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
) -> BudgetAuthorizeHoldRequest {
    BudgetAuthorizeHoldRequest {
        capability_id: operation.binding().capability_id().as_str().into(),
        grant_index: 0,
        max_invocations: Some(1),
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: Some(BudgetAdmissionBinding {
            operation_id: operation.binding().operation_id().as_str().into(),
            revocation_set: CanonicalRevocationSet::canonicalize(vec![operation
                .binding()
                .capability_id()
                .as_str()
                .into()])
            .expect("revocation set"),
            authorization_artifact_digests: vec![operation
                .to_persisted()
                .binding
                .authorization_capability_hash
                .as_str()
                .into()],
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: 0,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        hold_id: Some("nonce-hold".into()),
        event_id: Some("nonce-authorize".into()),
        authority: Some(authority(fixture)),
    }
}

fn authority(fixture: &Fixture) -> BudgetEventAuthority {
    BudgetEventAuthority {
        authority_id: fixture.fence.store_uuid.clone(),
        lease_id: fixture.fence.lease_id.clone(),
        lease_epoch: fixture.fence.owner_epoch,
    }
}

fn ready() -> TestResult<NonceFixture> {
    let mut fixture = nonce_fixture_with_budget(true)?;
    let command = reserve_command(&fixture)?;
    fixture.operation = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(&command, &fixture.reservation, now_ms())?
        .into_operation();
    Ok(fixture)
}

fn command(fixture: &NonceFixture) -> TestResult<AdmissionOperationCommand> {
    nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        Vec::new(),
        AdmissionOperationState::CapturePending,
    )
}

fn prepare(fixture: &mut NonceFixture) -> TestResult {
    fixture.operation = fixture
        .fixture
        .store
        .begin_execution_nonce_capture(&command(fixture)?, now_ms())?
        .into_operation();
    Ok(())
}

pub(super) fn capture_request(fixture: &NonceFixture) -> BudgetCaptureInvocationRequest {
    BudgetCaptureInvocationRequest {
        capability_id: fixture.operation.binding().capability_id().as_str().into(),
        grant_index: 0,
        hold_id: "nonce-hold".into(),
        event_id: "nonce-capture".into(),
        trusted_time: None,
        authority: Some(authority(&fixture.fixture)),
    }
}

fn capture(fixture: &mut NonceFixture) -> TestResult {
    fixture.operation = fixture
        .fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &fixture.operation,
            command(fixture)?.recovery_lease(),
            capture_request(fixture),
            &fixture.fixture.fence,
            now_ms(),
        )?
        .1;
    Ok(())
}

pub(super) fn release(fixture: &NonceFixture) -> TestResult {
    fixture
        .fixture
        .authority
        .budget_store()
        .reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: fixture.operation.binding().capability_id().as_str().into(),
            grant_index: 0,
            reversed_exposure_units: 0,
            hold_id: Some("nonce-hold".into()),
            event_id: Some("nonce-reverse".into()),
            expected_cumulative_approval_state: None,
            authority: Some(authority(&fixture.fixture)),
        })?;
    Ok(())
}

pub(super) fn projection(fixture: &NonceFixture) -> TestResult<AdmissionTerminalProjection> {
    let command = command(fixture)?;
    let lease = command.recovery_lease();
    Ok(
        verified_released_pre_dispatch_compensation_projection_for_test(
            &fixture.operation,
            AdmissionProjectionContext {
                operation_id: fixture.operation.binding().operation_id().clone(),
                request_id: fixture.operation.binding().request_id().clone(),
                expected_operation_version: fixture.operation.version(),
                trusted_time_unix_ms: now_ms(),
                coordinator_lease_id: lease.coordinator_lease_id().clone(),
                coordinator_lease_epoch: lease.coordinator_lease_epoch(),
                store_fence: fixture.fixture.fence.clone(),
            },
            serde_json::json!({"policy":"nonce-lifecycle-test-release"}),
        )?,
    )
}

pub(super) fn state(fixture: &NonceFixture) -> TestResult<(String, i64, i64)> {
    Ok(fixture.fixture.store.connection()?.query_row(
        "SELECT invocation_state, (SELECT COUNT(*) FROM admission_execution_nonce_transitions),
                (SELECT COUNT(*) FROM budget_mutation_events WHERE event_id = 'nonce-capture')
         FROM budget_authorization_holds WHERE hold_id = 'nonce-hold'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

#[test]
fn durable_nonce_lifecycle_commits_with_real_capture_and_blocks_split_capture() -> TestResult {
    let mut fixture = ready()?;
    assert!(fixture
        .fixture
        .authority
        .budget_store()
        .capture_invocation_reservations(capture_request(&fixture))
        .is_err());
    assert_eq!(state(&fixture)?, ("authorized".into(), 0, 0));
    prepare(&mut fixture)?;
    let replay = command(&fixture)?;
    assert!(matches!(
        fixture
            .fixture
            .store
            .begin_execution_nonce_capture(&replay, now_ms())?,
        AdmissionCommandResult::Idempotent(_)
    ));
    assert!(fixture
        .fixture
        .authority
        .budget_store()
        .capture_invocation_reservations(capture_request(&fixture))
        .is_err());
    let pending = fixture.operation.clone();
    let capture_command = command(&fixture)?;
    let captured_at = now_ms();
    fixture.operation = fixture
        .fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &pending,
            capture_command.recovery_lease(),
            capture_request(&fixture),
            &fixture.fixture.fence,
            captured_at,
        )?
        .1;
    let (decision, replayed) = fixture
        .fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &pending,
            capture_command.recovery_lease(),
            capture_request(&fixture),
            &fixture.fixture.fence,
            captured_at,
        )?;
    assert!(matches!(
        decision,
        chio_kernel::budget_store::BudgetInvocationCaptureDecision::AlreadyCaptured(_)
    ));
    assert_eq!(replayed, fixture.operation);
    let wire: serde_json::Value = serde_json::from_slice(fixture.reservation.canonical_bytes())?;
    let expires = wire["signed_nonce"]["nonce"]["expires_at"]
        .as_u64()
        .ok_or("nonce expiry")?
        * 1_000;
    for retry_at in [captured_at + 1, expires] {
        let (decision, replayed) = fixture
            .fixture
            .store
            .capture_invocation_and_commit_dispatch(
                &pending,
                capture_command.recovery_lease(),
                capture_request(&fixture),
                &fixture.fixture.fence,
                retry_at,
            )?;
        assert!(matches!(
            decision,
            chio_kernel::budget_store::BudgetInvocationCaptureDecision::AlreadyCaptured(_)
        ));
        assert_eq!(replayed, fixture.operation);
    }
    let committed_at: i64 = fixture.fixture.store.connection()?.query_row(
        "SELECT recorded_at_unix_ms FROM admission_execution_nonce_transitions
         WHERE operation_id = ?1 AND kind = 'committed'",
        [fixture.operation.binding().operation_id().as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(committed_at, i64::try_from(captured_at)?);
    let mut substituted = capture_request(&fixture);
    substituted.event_id = "substituted-capture".into();
    assert!(fixture
        .fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &pending,
            capture_command.recovery_lease(),
            substituted,
            &fixture.fixture.fence,
            captured_at,
        )
        .is_err());
    assert_eq!(
        fixture.operation.state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(state(&fixture)?, ("captured".into(), 2, 1));
    assert!(release(&fixture).is_err());
    assert!(fixture
        .fixture
        .authority
        .budget_store()
        .capture_invocation_reservations(capture_request(&fixture))
        .is_err());
    assert_eq!(
        fixture
            .fixture
            .store
            .load_by_operation_id(fixture.operation.binding().operation_id())?,
        Some(fixture.operation.clone())
    );
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_preparation_requires_physical_budget_evidence() -> TestResult {
    let mut fixture = nonce_fixture()?;
    fixture.operation = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(
            &reserve_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )?
        .into_operation();
    let error = fixture
        .fixture
        .store
        .begin_execution_nonce_capture(&command(&fixture)?, now_ms())
        .expect_err("metadata is not a budget hold");
    assert!(
        error.to_string().contains("physical composite hold"),
        "{error}"
    );
    assert_eq!(
        fixture
            .fixture
            .store
            .load_by_operation_id(fixture.operation.binding().operation_id())?,
        Some(fixture.operation.clone())
    );
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_preparation_rolls_back_each_sql_cutpoint() -> TestResult {
    for (table, mutation) in [
        ("admission_operations", "UPDATE"),
        ("admission_operation_commits", "INSERT"),
        ("admission_execution_nonce_transitions", "INSERT"),
    ] {
        let fixture = ready()?;
        let command = command(&fixture)?;
        fixture.fixture.store.connection()?.execute_batch(&format!(
            "CREATE TEMP TRIGGER fail_nonce_preparation BEFORE {mutation} ON {table}
             BEGIN SELECT RAISE(ABORT, 'injected nonce preparation failure'); END;"
        ))?;
        let error = fixture
            .fixture
            .store
            .begin_execution_nonce_capture(&command, now_ms())
            .expect_err("cutpoint");
        assert!(
            error
                .to_string()
                .contains("injected nonce preparation failure"),
            "{error}"
        );
        assert_eq!(state(&fixture)?, ("authorized".into(), 0, 0));
        assert_eq!(
            fixture
                .fixture
                .store
                .load_by_operation_id(fixture.operation.binding().operation_id())?,
            Some(fixture.operation.clone())
        );
    }
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_capture_rolls_back_nonce_budget_and_dispatch_together() -> TestResult {
    for table in [
        "admission_execution_nonce_transitions",
        "admission_operation_commits",
        "budget_mutation_events",
    ] {
        let mut fixture = ready()?;
        prepare(&mut fixture)?;
        let command = command(&fixture)?;
        fixture.fixture.store.connection()?.execute_batch(&format!(
            "CREATE TEMP TRIGGER fail_nonce_capture BEFORE INSERT ON {table}
             BEGIN SELECT RAISE(ABORT, 'injected nonce capture failure'); END;"
        ))?;
        let error = fixture
            .fixture
            .store
            .capture_invocation_and_commit_dispatch(
                &fixture.operation,
                command.recovery_lease(),
                capture_request(&fixture),
                &fixture.fixture.fence,
                now_ms(),
            )
            .expect_err("capture cutpoint");
        assert!(
            error.to_string().contains("injected nonce capture failure"),
            "{error}"
        );
        assert_eq!(state(&fixture)?, ("authorized".into(), 1, 0));
        assert_eq!(
            fixture
                .fixture
                .store
                .load_by_operation_id(fixture.operation.binding().operation_id())?,
            Some(fixture.operation.clone())
        );
        fixture
            .fixture
            .store
            .connection()?
            .execute_batch("DROP TRIGGER fail_nonce_capture")?;
        capture(&mut fixture)?;
        assert_eq!(state(&fixture)?, ("captured".into(), 2, 1));
    }
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_cancellation_requires_release_and_retains_tombstones() -> TestResult {
    for prepared in [false, true] {
        let mut fixture = ready()?;
        if prepared {
            prepare(&mut fixture)?;
        }
        let error = fixture
            .fixture
            .store
            .commit_terminal_projection(&projection(&fixture)?)
            .expect_err("unreleased budget");
        assert!(
            error.to_string().contains("physical budget disposition"),
            "{error}"
        );
        assert_eq!(
            state(&fixture)?,
            ("authorized".into(), i64::from(prepared), 0)
        );
        release(&fixture)?;
        let projection = projection(&fixture)?;
        let terminal = fixture
            .fixture
            .store
            .commit_terminal_projection(&projection)?;
        assert_eq!(
            terminal.state,
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        assert_eq!(
            fixture
                .fixture
                .store
                .commit_terminal_projection(&projection)?,
            terminal
        );
        assert_eq!(
            state(&fixture)?,
            ("reversed".into(), 1 + i64::from(prepared), 0)
        );
        assert!(fixture
            .fixture
            .store
            .load_execution_nonce_reservation(
                fixture.operation.binding().operation_id(),
                &fixture.fixture.fence,
                now_ms(),
            )?
            .is_some());
        assert!(fixture
            .fixture
            .authority
            .budget_store()
            .capture_invocation_reservations(capture_request(&fixture))
            .is_err());
    }
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_cancellation_and_terminal_projection_roll_back_together() -> TestResult {
    for table in [
        "admission_execution_nonce_transitions",
        "admission_operation_terminal_projections",
        "admission_operation_commits",
    ] {
        let mut fixture = ready()?;
        prepare(&mut fixture)?;
        release(&fixture)?;
        let projection = projection(&fixture)?;
        fixture.fixture.store.connection()?.execute_batch(&format!(
            "CREATE TEMP TRIGGER fail_nonce_cancel BEFORE INSERT ON {table}
             BEGIN SELECT RAISE(ABORT, 'injected nonce cancellation failure'); END;"
        ))?;
        let error = fixture
            .fixture
            .store
            .commit_terminal_projection(&projection)
            .expect_err("cancel cutpoint");
        assert!(
            error
                .to_string()
                .contains("injected nonce cancellation failure"),
            "{error}"
        );
        assert_eq!(state(&fixture)?, ("reversed".into(), 1, 0));
        assert_eq!(
            fixture
                .fixture
                .store
                .load_by_operation_id(fixture.operation.binding().operation_id())?,
            Some(fixture.operation.clone())
        );
        fixture
            .fixture
            .store
            .connection()?
            .execute_batch("DROP TRIGGER fail_nonce_cancel")?;
        fixture
            .fixture
            .store
            .commit_terminal_projection(&projection)?;
        assert_eq!(state(&fixture)?, ("reversed".into(), 2, 0));
    }
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_generic_cas_cannot_fake_postdispatch_participants() -> TestResult {
    use chio_kernel::tool_outcome::{test_support::returned_value, ToolOutcomeStore};

    let mut fixture = ready()?;
    prepare(&mut fixture)?;
    capture(&mut fixture)?;
    let command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        vec![AdmissionAttachment::ToolOutcomeId(digest("outcome", 'e'))],
        AdmissionOperationState::Finalizing,
    )?;
    assert!(
        fixture
            .fixture
            .store
            .compare_and_swap(&command, now_ms())
            .is_err(),
        "generic CAS attached a tool outcome without its physical participant"
    );
    assert_eq!(
        fixture
            .fixture
            .store
            .load_by_operation_id(fixture.operation.binding().operation_id())?,
        Some(fixture.operation.clone())
    );
    assert_eq!(state(&fixture)?, ("captured".into(), 2, 1));
    let (blob, outcome) = returned_value(
        &fixture.operation,
        fixture.fixture.fence.clone(),
        now_ms(),
        serde_json::json!({"completed": true}),
        None,
    )?;
    let (stored, finalizing) = fixture
        .fixture
        .authority
        .tool_outcome_store()
        .record_tool_returned(
            &fixture.operation,
            command.recovery_lease(),
            &blob,
            &outcome,
            &fixture.fixture.fence,
            now_ms(),
        )?
        .into_parts();
    assert_eq!(stored, outcome);
    assert_eq!(finalizing.state(), AdmissionOperationState::Finalizing);
    assert_eq!(finalizing.tool_outcome_id(), Some(outcome.outcome_id()));
    assert_eq!(
        fixture
            .fixture
            .store
            .load_by_operation_id(fixture.operation.binding().operation_id())?,
        Some(finalizing)
    );
    assert_eq!(state(&fixture)?, ("captured".into(), 2, 1));
    Ok(())
}
