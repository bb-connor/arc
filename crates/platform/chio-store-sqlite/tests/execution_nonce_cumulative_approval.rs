//! Real kernel strict-nonce preflight composed with cumulative approval
//! against the SQLite admission store.

#[path = "threshold_kernel_lifecycle/support.rs"]
mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use chio_core::crypto::Keypair;
use chio_core::session::OperationTerminalState;
use chio_kernel::execution_nonce::SignedExecutionNonce;
use chio_kernel::threshold_approval::ThresholdApprovalCollectorState;
use chio_kernel::{ToolCallRequest, ToolCallResponse, Verdict};
use support::*;

fn nonce_fixture(nonce_ttl_secs: u64) -> TestResult<Fixture> {
    let mut fixture = Fixture::new()?;
    fixture.nonce_ttl_secs = Some(nonce_ttl_secs);
    Ok(fixture)
}

fn preflight(runtime: &Runtime, request: &ToolCallRequest) -> TestResult<SignedExecutionNonce> {
    let response = runtime.kernel.evaluate_tool_call_blocking(request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(matches!(
        &response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert!(
        response
            .receipt
            .metadata
            .as_ref()
            .is_none_or(|metadata| metadata.get("threshold_approval").is_none()),
        "a preflight never mints a proposal"
    );
    Ok(*response.execution_nonce.ok_or("preflight nonce")?)
}

fn with_nonce(request: &ToolCallRequest, nonce: &SignedExecutionNonce) -> ToolCallRequest {
    let mut execution = request.clone();
    execution.execution_nonce = Some(nonce.clone());
    execution
}

fn assert_state(fixture: &Fixture, request: &ToolCallRequest, state: &str) -> TestResult {
    assert_eq!(
        operation_state(fixture, &request.request_id)?.as_deref(),
        Some(state)
    );
    Ok(())
}

/// Preflights, then parks the execution for approval; returns the request
/// with its nonce and the pending proposal.
fn park_for_approval(
    fixture: &Fixture,
    runtime: &Runtime,
    id: &str,
) -> TestResult<(
    ToolCallRequest,
    chio_core::capability::governance::ThresholdApprovalProposal,
)> {
    let request = fixture.request(runtime, id)?;
    let nonce = preflight(runtime, &request)?;
    assert_state(fixture, &request, "prepared")?;
    let execution = with_nonce(&request, &nonce);
    let proposal = pending(runtime, &execution)?;
    assert_state(fixture, &request, "approval_required")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok((execution, proposal))
}

fn approve(
    fixture: &Fixture,
    runtime: &Runtime,
    execution: &mut ToolCallRequest,
    proposal: &chio_core::capability::governance::ThresholdApprovalProposal,
) -> TestResult {
    let collector = fixture.collector(runtime, true)?;
    collector.create_proposal(proposal.clone(), now())?;
    collector.submit_token(
        &proposal.body.proposal_id,
        fixture.vote(proposal, &fixture.reviewer)?,
        now(),
    )?;
    let delivered = collector.deliver(&proposal.body.proposal_id, now())?;
    execution.threshold_approval_proposal = Some(delivered.proposal);
    execution.approval_tokens = delivered.tokens;
    Ok(())
}

fn evaluate(runtime: &Runtime, request: &ToolCallRequest) -> TestResult<ToolCallResponse> {
    Ok(runtime.kernel.evaluate_tool_call_blocking(request)?)
}

#[test]
fn execution_with_the_nonce_parks_for_approval_and_a_second_preflight_denies() -> TestResult {
    let fixture = nonce_fixture(30)?;
    let runtime = fixture.open()?;
    let (execution, _proposal) = park_for_approval(&fixture, &runtime, "park")?;

    let mut replayed_preflight = execution.clone();
    replayed_preflight.execution_nonce = None;
    let denied = evaluate(&runtime, &replayed_preflight)?;
    assert_eq!(denied.verdict, Verdict::Deny, "{:?}", denied.reason);
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("cannot replay an operation in state")),
        "{:?}",
        denied.reason
    );
    drop(runtime);

    let runtime = fixture.open()?;
    assert_state(&fixture, &execution, "approval_required")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    drop(runtime);
    Ok(())
}

#[test]
fn approved_retry_with_the_bound_nonce_executes_once_and_replays() -> TestResult {
    let fixture = nonce_fixture(30)?;
    let runtime = fixture.open()?;
    let (mut execution, proposal) = park_for_approval(&fixture, &runtime, "approve")?;
    approve(&fixture, &runtime, &mut execution, &proposal)?;

    let first = evaluate(&runtime, &execution)?;
    assert_eq!(first.verdict, Verdict::Allow, "{:?}", first.reason);
    assert_state(&fixture, &execution, "completed")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);

    let replay = evaluate(&runtime, &execution)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(canonical(&first.receipt)?, canonical(&replay.receipt)?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    drop(runtime);

    let runtime = fixture.open()?;
    let replay = evaluate(&runtime, &execution)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(canonical(&first.receipt)?, canonical(&replay.receipt)?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn approved_retry_after_the_issuance_lifetime_still_executes() -> TestResult {
    let fixture = nonce_fixture(3)?;
    let runtime = fixture.open()?;
    let (mut execution, proposal) = park_for_approval(&fixture, &runtime, "late-approval")?;
    std::thread::sleep(Duration::from_secs(4));
    approve(&fixture, &runtime, &mut execution, &proposal)?;

    let approved = evaluate(&runtime, &execution)?;
    assert_eq!(
        approved.verdict,
        Verdict::Allow,
        "the bound nonce is governed by the approval window: {:?}",
        approved.reason
    );
    assert_state(&fixture, &execution, "completed")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn unbound_issuance_still_expires_before_execution() -> TestResult {
    let fixture = nonce_fixture(1)?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "expired-before-binding")?;
    let nonce = preflight(&runtime, &request)?;
    std::thread::sleep(Duration::from_secs(2));
    let denied = evaluate(&runtime, &with_nonce(&request, &nonce))?;
    assert_eq!(denied.verdict, Verdict::Deny, "{:?}", denied.reason);
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("execution nonce expired")),
        "{:?}",
        denied.reason
    );
    assert_state(&fixture, &request, "prepared")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn foreign_tokens_keep_the_operation_parked() -> TestResult {
    let fixture = nonce_fixture(30)?;
    let runtime = fixture.open()?;
    let (mut execution, proposal) = park_for_approval(&fixture, &runtime, "foreign-tokens")?;
    execution.threshold_approval_proposal = Some(proposal.clone());
    execution.approval_tokens = vec![fixture.vote(&proposal, &Keypair::generate())?];

    let denied = evaluate(&runtime, &execution)?;
    assert_ne!(denied.verdict, Verdict::Allow, "{:?}", denied.reason);
    assert_state(&fixture, &execution, "approval_required")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);

    let collector = fixture.collector(&runtime, true)?;
    let registered = collector.create_proposal(proposal.clone(), now())?;
    assert_eq!(
        registered.state,
        ThresholdApprovalCollectorState::Collecting
    );
    Ok(())
}

#[test]
fn expired_parked_operation_is_retired_by_startup_recovery() -> TestResult {
    let fixture = nonce_fixture(30)?;
    fixture.set_proposal_timeout(2)?;
    let runtime = fixture.open()?;
    let (execution, _) = park_for_approval(&fixture, &runtime, "retire-at-startup")?;
    assert_eq!(open_holds(&fixture)?, 1);
    drop(runtime);
    std::thread::sleep(Duration::from_secs(3));

    let runtime = fixture.open_with_policy(&fixture.policy_hash, false)?;
    assert_state(&fixture, &execution, "approval_required")?;
    assert_eq!(runtime.kernel.reconcile_recoverable_admissions()?, 1);
    assert_state(&fixture, &execution, "compensated_before_dispatch")?;
    assert_eq!(open_holds(&fixture)?, 0);
    assert_eq!(runtime.kernel.reconcile_recoverable_admissions()?, 0);
    runtime.kernel.reconcile_durable_admission_startup()?;

    let denied = evaluate(&runtime, &execution)?;
    assert_eq!(denied.verdict, Verdict::Deny, "{:?}", denied.reason);
    assert_state(&fixture, &execution, "compensated_before_dispatch")?;
    let (_, _) = park_for_approval(&fixture, &runtime, "after-retirement")?;
    assert_eq!(open_holds(&fixture)?, 1);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn expired_retry_retires_the_parked_operation_in_process() -> TestResult {
    let fixture = nonce_fixture(30)?;
    fixture.set_proposal_timeout(2)?;
    let runtime = fixture.open()?;
    let (execution, _) = park_for_approval(&fixture, &runtime, "retire-on-retry")?;
    assert_eq!(open_holds(&fixture)?, 1);
    std::thread::sleep(Duration::from_secs(3));

    let denied = evaluate(&runtime, &execution)?;
    assert_eq!(denied.verdict, Verdict::Deny, "{:?}", denied.reason);
    assert_state(&fixture, &execution, "compensated_before_dispatch")?;
    assert_eq!(open_holds(&fixture)?, 0);
    let replay = evaluate(&runtime, &execution)?;
    assert_eq!(replay.verdict, Verdict::Deny, "{:?}", replay.reason);
    assert_state(&fixture, &execution, "compensated_before_dispatch")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn live_parked_operation_survives_startup_recovery() -> TestResult {
    let fixture = nonce_fixture(30)?;
    let runtime = fixture.open()?;
    let (mut execution, proposal) = park_for_approval(&fixture, &runtime, "survive-restart")?;
    drop(runtime);

    let runtime = fixture.open_with_policy(&fixture.policy_hash, false)?;
    assert_eq!(runtime.kernel.reconcile_recoverable_admissions()?, 0);
    assert_state(&fixture, &execution, "approval_required")?;
    assert_eq!(open_holds(&fixture)?, 1);
    runtime.kernel.reconcile_durable_admission_startup()?;
    approve(&fixture, &runtime, &mut execution, &proposal)?;
    let approved = evaluate(&runtime, &execution)?;
    assert_eq!(approved.verdict, Verdict::Allow, "{:?}", approved.reason);
    assert_state(&fixture, &execution, "completed")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
