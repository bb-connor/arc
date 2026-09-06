//! Real kernel strict-nonce preflight and execution against the SQLite admission store.
#[path = "execution_nonce_kernel_lifecycle/support.rs"]
mod support;

use chio_core::receipt::decision::Decision;
use chio_core::session::OperationTerminalState;
use chio_kernel::execution_nonce::SignedExecutionNonce;
use chio_kernel::{ToolCallRequest, ToolCallResponse, Verdict};
use std::sync::atomic::Ordering;
use support::*;

fn preflight(runtime: &Runtime, request: &ToolCallRequest) -> TestResult<SignedExecutionNonce> {
    let response = runtime.kernel.evaluate_tool_call_blocking(request)?;
    assert_preflight(&response)?;
    Ok(*response.execution_nonce.ok_or("preflight nonce")?)
}

fn assert_preflight(response: &ToolCallResponse) -> TestResult {
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(response.output.is_none());
    assert!(matches!(
        &response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert!(matches!(
        response.receipt.decision.as_ref(),
        Some(Decision::Incomplete { reason }) if reason.contains("execution nonce preflight")
    ));
    let nonce = response
        .execution_nonce
        .as_deref()
        .ok_or("preflight nonce")?;
    assert_eq!(nonce.nonce.schema, "chio.execution_nonce.v2");
    assert!(nonce.reserved_hold_id().is_none());
    Ok(())
}

fn execute(
    runtime: &Runtime,
    request: &ToolCallRequest,
    nonce: &SignedExecutionNonce,
) -> TestResult<ToolCallResponse> {
    let mut execution = request.clone();
    execution.execution_nonce = Some(nonce.clone());
    Ok(runtime.kernel.evaluate_tool_call_blocking(&execution)?)
}

fn assert_state(fixture: &Fixture, request: &ToolCallRequest, state: &str) -> TestResult<String> {
    let (operation_id, actual) =
        operation_state(fixture, &request.request_id)?.ok_or("retained operation")?;
    assert_eq!(actual, state);
    Ok(operation_id)
}

#[test]
fn strict_preflight_issues_durable_nonce_then_executes_once() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "preflight-execute")?;

    let nonce = preflight(&runtime, &request)?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_state(&fixture, &request, "prepared")?;
    assert_eq!(count_rows(&fixture, "admission_nonce_preflight_holds")?, 1);
    assert_eq!(
        count_rows(&fixture, "admission_execution_nonce_issuances")?,
        1
    );
    assert_eq!(
        count_rows(&fixture, "admission_execution_nonce_reservations")?,
        0
    );
    assert_eq!(
        grant_quota(&runtime, &request)?,
        (0, 0),
        "the preflight hold is reversed before issuance"
    );

    let executed = execute(&runtime, &request, &nonce)?;
    assert_eq!(executed.verdict, Verdict::Allow, "{:?}", executed.reason);
    assert!(executed.output.is_some());
    assert!(executed.execution_nonce.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_state(&fixture, &request, "completed")?;
    assert_eq!(
        count_rows(&fixture, "admission_execution_nonce_reservations")?,
        1
    );
    assert_eq!(count_rows(&fixture, "budget_authorization_holds")?, 2);
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));

    let replay = execute(&runtime, &request, &nonce)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(replay.receipt.id, executed.receipt.id);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);

    let fresh = fixture.request(&runtime, "second-request")?;
    let error = runtime
        .kernel
        .evaluate_tool_call_blocking(&fresh)
        .map(|response| response.verdict)?;
    assert_eq!(error, Verdict::Allow, "a new request preflights again");
    let stale = execute(&runtime, &fresh, &nonce)?;
    assert_eq!(stale.verdict, Verdict::Deny);
    assert!(stale
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("does not match its retained issuance")));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn preflight_replay_redelivers_the_retained_nonce_without_a_second_hold() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "preflight-replay")?;
    let first = preflight(&runtime, &request)?;
    let second = preflight(&runtime, &request)?;
    assert_eq!(first, second);
    assert_eq!(count_rows(&fixture, "admission_nonce_preflight_holds")?, 1);
    assert_eq!(count_rows(&fixture, "budget_authorization_holds")?, 1);
    assert_eq!(
        count_rows(&fixture, "admission_execution_nonce_issuances")?,
        1
    );
    assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
    let executed = execute(&runtime, &request, &second)?;
    assert_eq!(executed.verdict, Verdict::Allow, "{:?}", executed.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn execution_rejects_foreign_nonces_without_touching_the_operation() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "foreign-nonce")?;
    let other = fixture.request(&runtime, "other-request")?;
    let nonce = preflight(&runtime, &request)?;
    let foreign = preflight(&runtime, &other)?;

    for presented in [
        foreign.clone(),
        {
            let mut tampered = nonce.clone();
            tampered.nonce.expires_at += 1;
            tampered
        },
        {
            let mut resigned = nonce.clone();
            resigned.signature = foreign.signature.clone();
            resigned
        },
    ] {
        let denied = execute(&runtime, &request, &presented)?;
        assert_eq!(denied.verdict, Verdict::Deny, "{:?}", denied.reason);
        assert!(denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("does not match its retained issuance")));
    }
    let mut missing = request.clone();
    missing.request_id = "never-preflighted".into();
    missing.execution_nonce = Some(nonce.clone());
    let denied = runtime.kernel.evaluate_tool_call_blocking(&missing)?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("was never issued for this request")));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_state(&fixture, &request, "prepared")?;

    let executed = execute(&runtime, &request, &nonce)?;
    assert_eq!(executed.verdict, Verdict::Allow, "{:?}", executed.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn restart_between_preflight_and_execution_keeps_the_issuance() -> TestResult {
    let fixture = Fixture::new()?;
    let nonce;
    let request;
    {
        let runtime = fixture.open()?;
        request = fixture.request(&runtime, "restart-request")?;
        nonce = preflight(&runtime, &request)?;
        drop(runtime);
    }
    let runtime = fixture.open()?;
    assert_state(&fixture, &request, "prepared")?;
    assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
    let executed = execute(&runtime, &request, &nonce)?;
    assert_eq!(executed.verdict, Verdict::Allow, "{:?}", executed.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_state(&fixture, &request, "completed")?;
    drop(runtime);

    let runtime = fixture.open()?;
    let replay = execute(&runtime, &request, &nonce)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(replay.receipt.id, executed.receipt.id);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn expired_issuance_denies_execution_and_is_compensated_by_startup_recovery() -> TestResult {
    let fixture = Fixture::with_nonce_ttl(1)?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "expired-request")?;
    let nonce = preflight(&runtime, &request)?;
    std::thread::sleep(std::time::Duration::from_millis(2_100));

    let denied = execute(&runtime, &request, &nonce)?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("execution nonce expired")));
    let replay = runtime.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.verdict, Verdict::Deny, "{:?}", replay.reason);
    assert!(replay
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("retained execution nonce expired")));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_state(&fixture, &request, "prepared")?;
    drop(runtime);

    let runtime = fixture.open()?;
    assert_state(&fixture, &request, "compensated_before_dispatch")?;
    assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
    assert_eq!(
        count_rows(&fixture, "admission_execution_nonce_issuances")?,
        1,
        "expired issuance remains history"
    );
    let late = execute(&runtime, &request, &nonce)?;
    assert_eq!(late.verdict, Verdict::Deny);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn live_issuance_survives_startup_recovery_until_it_expires() -> TestResult {
    let fixture = Fixture::with_nonce_ttl(2)?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "live-recovery")?;
    let nonce = preflight(&runtime, &request)?;
    drop(runtime);

    let runtime = fixture.open()?;
    assert_state(&fixture, &request, "prepared")?;
    std::thread::sleep(std::time::Duration::from_millis(3_100));
    assert_eq!(runtime.kernel.reconcile_recoverable_admissions()?, 1);
    assert_state(&fixture, &request, "compensated_before_dispatch")?;
    let denied = execute(&runtime, &request, &nonce)?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn unconfirmed_preflight_cleanup_is_compensated_by_startup_recovery() -> TestResult {
    let fixture = Fixture::new()?;
    // The serving owner refuses outside schema changes once it opens, so the
    // cutpoint is installed on the provisioned database before the kernel starts.
    execute_sql(&fixture, &rollback_cutpoint("1"))?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "cleanup-cutpoint")?;
    let denied = runtime.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("cleanup could not be confirmed")),
        "{:?}",
        denied.reason
    );
    assert!(denied.execution_nonce.is_none());
    assert_state(&fixture, &request, "prepared")?;
    assert_eq!(count_rows(&fixture, "admission_nonce_preflight_holds")?, 1);
    assert_eq!(
        grant_quota(&runtime, &request)?,
        (1, 0),
        "the preflight hold stays reserved until the deterministic cleanup replays"
    );
    assert_eq!(
        count_rows(&fixture, "admission_execution_nonce_issuances")?,
        0
    );
    drop(runtime);
    execute_sql(&fixture, "DROP TRIGGER preflight_rollback_cutpoint")?;

    let runtime = fixture.open()?;
    assert_state(&fixture, &request, "compensated_before_dispatch")?;
    assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let replay = runtime.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.verdict, Verdict::Deny, "{:?}", replay.reason);
    Ok(())
}

#[test]
fn unconfirmed_preflight_cleanup_replays_on_the_next_preflight() -> TestResult {
    let fixture = Fixture::new()?;
    // The cutpoint only fires while this is the sole retained operation, so a
    // second request lifts it without touching the database from outside.
    execute_sql(&fixture, &rollback_cutpoint("1"))?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "cleanup-retry")?;
    let denied = runtime.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(denied.verdict, Verdict::Deny, "{:?}", denied.reason);
    assert_eq!(grant_quota(&runtime, &request)?, (1, 0));

    let other = fixture.request(&runtime, "cleanup-other")?;
    preflight(&runtime, &other)?;
    let nonce = preflight(&runtime, &request)?;
    assert_eq!(count_rows(&fixture, "admission_nonce_preflight_holds")?, 2);
    assert_eq!(count_rows(&fixture, "budget_authorization_holds")?, 2);
    assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
    let executed = execute(&runtime, &request, &nonce)?;
    assert_eq!(executed.verdict, Verdict::Allow, "{:?}", executed.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

fn rollback_cutpoint(operation_count: &str) -> String {
    format!(
        "CREATE TRIGGER preflight_rollback_cutpoint BEFORE INSERT ON budget_mutation_events
         WHEN NEW.event_id LIKE 'nonce-preflight-authorize:%:rollback:%'
         AND (SELECT COUNT(*) FROM admission_operations) = {operation_count}
         BEGIN SELECT RAISE(ABORT, 'injected preflight rollback cutpoint'); END;"
    )
}

#[test]
fn budget_exhaustion_at_execution_compensates_without_dispatch() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let first = fixture.request(&runtime, "exhaust-first")?;
    let mut second = first.clone();
    second.request_id = "exhaust-second".into();
    let first_nonce = preflight(&runtime, &first)?;
    let second_nonce = preflight(&runtime, &second)?;
    assert_eq!(grant_quota(&runtime, &first)?, (0, 0));

    let executed = execute(&runtime, &first, &first_nonce)?;
    assert_eq!(executed.verdict, Verdict::Allow, "{:?}", executed.reason);
    let denied = execute(&runtime, &second, &second_nonce)?;
    assert_eq!(denied.verdict, Verdict::Deny, "{:?}", denied.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_state(&fixture, &second, "compensated_before_dispatch")?;
    assert_eq!(grant_quota(&runtime, &first)?, (0, 1));
    let retry = execute(&runtime, &second, &second_nonce)?;
    assert_eq!(retry.verdict, Verdict::Deny);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn cumulative_approval_grants_deny_strict_nonce_preflight() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let request = fixture.request_with_constraints(
        &runtime,
        "cumulative-request",
        vec![Fixture::cumulative_constraint()],
    )?;
    let denied = runtime.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("does not compose with cumulative approval")));
    assert!(operation_state(&fixture, &request.request_id)?.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn session_flow_preflights_and_executes_with_the_same_participant() -> TestResult {
    use chio_core::session::{OperationContext, RequestId, SessionOperation, ToolCallOperation};
    use chio_kernel::SessionOperationResponse;

    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "session-request")?;
    let session_id = runtime
        .kernel
        .open_session(request.agent_id.clone(), vec![request.capability.clone()])?;
    runtime.kernel.activate_session(&session_id)?;
    let context = OperationContext::new(
        session_id,
        RequestId::new(request.request_id.clone()),
        request.agent_id.clone(),
    );
    let operation = |nonce: Option<&SignedExecutionNonce>| -> TestResult<SessionOperation> {
        Ok(SessionOperation::ToolCall(Box::new(ToolCallOperation {
            capability: request.capability.clone(),
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            arguments: request.arguments.clone(),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: nonce.map(serde_json::to_value).transpose()?,
            model_metadata: None,
            extra_metadata: None,
        })))
    };
    let tool_call = |response: SessionOperationResponse| -> TestResult<ToolCallResponse> {
        match response {
            SessionOperationResponse::ToolCall(response) => Ok(response),
            _ => Err("tool call response missing".into()),
        }
    };

    let preflight = tool_call(
        runtime
            .kernel
            .evaluate_session_operation(&context, &operation(None)?)?,
    )?;
    assert_preflight(&preflight)?;
    let nonce = *preflight.execution_nonce.ok_or("session preflight nonce")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_state(&fixture, &request, "prepared")?;
    assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
    {
        let session = runtime
            .kernel
            .session(&context.session_id)
            .ok_or("session missing")?;
        let pending = session
            .inflight()
            .get(&context.request_id)
            .ok_or("pending request missing")?;
        assert_eq!(
            pending.pending_execution_nonce_id.as_deref(),
            Some(nonce.nonce_id())
        );
    }

    let executed = tool_call(
        runtime
            .kernel
            .evaluate_session_operation(&context, &operation(Some(&nonce))?)?,
    )?;
    assert_eq!(executed.verdict, Verdict::Allow, "{:?}", executed.reason);
    assert!(executed.output.is_some());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_state(&fixture, &request, "completed")?;
    let session = runtime
        .kernel
        .session(&context.session_id)
        .ok_or("session missing")?;
    assert!(session.inflight().is_empty());
    assert_eq!(
        session.terminal().get(&context.request_id),
        Some(OperationTerminalState::Completed)
    );
    Ok(())
}

#[test]
fn reserve_for_caller_authorization_denies_durable_nonce_operations() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "reserve-for-caller")?;
    let denied = runtime
        .kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("reserve-for-caller")),
        "{:?}",
        denied.reason
    );
    assert!(denied.execution_nonce.is_none());
    assert_state(&fixture, &request, "compensated_before_dispatch")?;
    assert_eq!(count_rows(&fixture, "budget_authorization_holds")?, 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn opt_in_nonces_deny_under_durable_admission() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.require_nonce = false;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "opt-in-request")?;
    let denied = runtime.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("require strict issuance")));
    assert!(operation_state(&fixture, &request.request_id)?.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
