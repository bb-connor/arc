//! Real kernel reservations for tools a caller executes elsewhere, reconciled
//! against the SQLite admission store.

#[path = "execution_nonce_kernel_lifecycle/support.rs"]
mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use chio_core::session::OperationTerminalState;
use chio_kernel::execution_nonce::SignedExecutionNonce;
use chio_kernel::{CallerExecutionReport, ToolCallRequest, ToolCallResponse, Verdict};
use support::*;

fn preflight(runtime: &Runtime, request: &ToolCallRequest) -> TestResult<SignedExecutionNonce> {
    let response = runtime.kernel.evaluate_tool_call_blocking(request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    Ok(*response.execution_nonce.ok_or("preflight nonce")?)
}

fn with_nonce(request: &ToolCallRequest, nonce: &SignedExecutionNonce) -> ToolCallRequest {
    let mut execution = request.clone();
    execution.execution_nonce = Some(nonce.clone());
    execution
}

/// Preflights and reserves; returns the request with its reserved nonce.
fn reserve(fixture: &Fixture, runtime: &Runtime, id: &str) -> TestResult<ToolCallRequest> {
    let request = fixture.request(runtime, id)?;
    let nonce = preflight(runtime, &request)?;
    let execution = with_nonce(&request, &nonce);
    let reserved = runtime
        .kernel
        .reserve_caller_execution_blocking(&execution)?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
    assert!(matches!(
        &reserved.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    let metadata = reserved
        .receipt
        .metadata
        .as_ref()
        .ok_or("reserve metadata")?;
    assert_eq!(
        metadata["execution_nonce"]["hold_disposition"],
        serde_json::json!("reserved")
    );
    assert_eq!(
        metadata["execution_nonce"]["tool_dispatched"],
        serde_json::json!(false)
    );
    let delivered = reserved.execution_nonce.ok_or("reserved nonce")?;
    assert_eq!(delivered.nonce.nonce_id, nonce.nonce.nonce_id);
    assert_state(fixture, &execution, "ready_to_dispatch")?;
    assert_eq!(grant_quota(runtime, &execution)?, (1, 0));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(execution)
}

fn report() -> CallerExecutionReport {
    CallerExecutionReport {
        output: serde_json::json!({ "caller_reported": true }),
        realized_cost: None,
    }
}

fn reconcile(runtime: &Runtime, execution: &ToolCallRequest) -> TestResult<ToolCallResponse> {
    let nonce = execution.execution_nonce.as_ref().ok_or("reserved nonce")?;
    Ok(runtime
        .kernel
        .reconcile_caller_execution_blocking(nonce, &execution.arguments, report())?)
}

fn assert_state(fixture: &Fixture, request: &ToolCallRequest, state: &str) -> TestResult {
    let (_, actual) = operation_state(fixture, &request.request_id)?.ok_or("retained operation")?;
    assert_eq!(actual, state);
    Ok(())
}

fn canonical<T: serde::Serialize>(value: &T) -> TestResult<Vec<u8>> {
    Ok(chio_core::canonical::canonical_json_bytes(value)?)
}

#[test]
fn caller_reservation_holds_the_budget_until_the_report_settles() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let execution = reserve(&fixture, &runtime, "caller-settles")?;

    let settled = reconcile(&runtime, &execution)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_eq!(settled.terminal_state, OperationTerminalState::Completed);
    assert_state(&fixture, &execution, "completed")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (0, 1));
    assert_eq!(
        fixture.invocations.load(Ordering::SeqCst),
        0,
        "the kernel never dispatched to its own server"
    );

    let replay = reconcile(&runtime, &execution)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(canonical(&settled.receipt)?, canonical(&replay.receipt)?);
    assert_eq!(grant_quota(&runtime, &execution)?, (0, 1));
    Ok(())
}

#[test]
fn a_report_for_other_arguments_is_refused_and_keeps_the_reservation() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let execution = reserve(&fixture, &runtime, "caller-other-arguments")?;
    let nonce = execution.execution_nonce.as_ref().ok_or("reserved nonce")?;
    let refused = runtime.kernel.reconcile_caller_execution_blocking(
        nonce,
        &serde_json::json!({ "not": "the reserved call" }),
        report(),
    );
    assert!(
        refused
            .as_ref()
            .is_err_and(|error| error.to_string().contains("do not match the reserved call")),
        "{refused:?}"
    );
    assert_state(&fixture, &execution, "ready_to_dispatch")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (1, 0));
    let settled = reconcile(&runtime, &execution)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_state(&fixture, &execution, "completed")?;
    Ok(())
}

#[test]
fn a_nonce_of_an_unreserved_operation_cannot_reconcile() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let _reserved = reserve(&fixture, &runtime, "caller-reserved")?;
    let other = fixture.request(&runtime, "caller-unreserved")?;
    let other_nonce = preflight(&runtime, &other)?;
    let refused = runtime.kernel.reconcile_caller_execution_blocking(
        &other_nonce,
        &other.arguments,
        report(),
    );
    assert!(
        refused.as_ref().is_err_and(|error| error
            .to_string()
            .contains("not reserved for caller execution")),
        "{refused:?}"
    );
    assert_state(&fixture, &other, "prepared")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn kernel_dispatch_cannot_resume_a_caller_reservation() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let execution = reserve(&fixture, &runtime, "caller-not-kernel")?;
    let denied = runtime.kernel.evaluate_tool_call_blocking(&execution)?;
    assert_eq!(denied.verdict, Verdict::Deny, "{:?}", denied.reason);
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("provider attempt does not match")),
        "{:?}",
        denied.reason
    );
    assert_state(&fixture, &execution, "ready_to_dispatch")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (1, 0));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn restart_keeps_a_live_caller_reservation() -> TestResult {
    let fixture = Fixture::new()?;
    let execution = {
        let runtime = fixture.open()?;
        reserve(&fixture, &runtime, "caller-restart")?
    };
    let runtime = fixture.open_with_reconcile(false)?;
    assert_eq!(runtime.kernel.reconcile_recoverable_admissions()?, 0);
    assert_state(&fixture, &execution, "ready_to_dispatch")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (1, 0));
    let settled = reconcile(&runtime, &execution)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_state(&fixture, &execution, "completed")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn an_expired_caller_reservation_is_compensated_by_startup_recovery() -> TestResult {
    let fixture = Fixture::with_nonce_ttl(2)?;
    let execution = {
        let runtime = fixture.open()?;
        reserve(&fixture, &runtime, "caller-expired")?
    };
    std::thread::sleep(Duration::from_secs(3));
    let runtime = fixture.open_with_reconcile(false)?;
    assert_eq!(runtime.kernel.reconcile_recoverable_admissions()?, 1);
    assert_state(&fixture, &execution, "compensated_before_dispatch")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (0, 0));
    runtime.kernel.reconcile_durable_admission_startup()?;
    let late = reconcile(&runtime, &execution)?;
    assert_eq!(late.verdict, Verdict::Deny, "{:?}", late.reason);
    assert_state(&fixture, &execution, "compensated_before_dispatch")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn a_second_reservation_is_bounded_by_the_shared_budget() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let first = reserve(&fixture, &runtime, "caller-budget-first")?;
    let mut second = first.clone();
    second.request_id = "caller-budget-second".into();
    second.execution_nonce = None;
    // The open reservation already counts against the shared grant, so the
    // second request cannot even preflight while the caller holds it.
    let denied = runtime.kernel.evaluate_tool_call_blocking(&second)?;
    assert_eq!(denied.verdict, Verdict::Deny, "{:?}", denied.reason);
    assert!(denied.execution_nonce.is_none());
    assert_state(&fixture, &first, "ready_to_dispatch")?;
    assert_eq!(grant_quota(&runtime, &first)?, (1, 0));
    let settled = reconcile(&runtime, &first)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_eq!(grant_quota(&runtime, &first)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
