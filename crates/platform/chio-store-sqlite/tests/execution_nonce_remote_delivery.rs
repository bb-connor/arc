//! Real kernel strict-nonce delivery to a tool server behind a loopback socket.

#[path = "execution_nonce_kernel_lifecycle/loopback.rs"]
mod loopback;
#[path = "execution_nonce_kernel_lifecycle/support.rs"]
mod support;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use chio_core::session::OperationTerminalState;
use chio_kernel::execution_nonce::SignedExecutionNonce;
use chio_kernel::{
    BlockingToolServerAdapter, ToolCallRequest, ToolCallResponse, ToolServerConnection, Verdict,
};
use loopback::{Behavior, LoopbackClient, LoopbackServer};
use support::*;

fn remote_fixture() -> TestResult<(Fixture, Arc<LoopbackServer>)> {
    let mut fixture = Fixture::new()?;
    let server = LoopbackServer::start(fixture.invocations.clone())?;
    let address = server.address();
    fixture.tool_server = Some(Box::new(move || {
        BlockingToolServerAdapter::new(Arc::new(LoopbackClient::new(address)))
            .map(|adapter| Box::new(adapter) as Box<dyn ToolServerConnection>)
    }));
    Ok((fixture, server))
}

fn preflight(runtime: &Runtime, request: &ToolCallRequest) -> TestResult<SignedExecutionNonce> {
    let response = runtime.kernel.evaluate_tool_call_blocking(request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(matches!(
        &response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    Ok(*response.execution_nonce.ok_or("preflight nonce")?)
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

fn reason_contains(response: &ToolCallResponse, needle: &str) -> bool {
    response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains(needle))
}

#[test]
fn remote_delivery_carries_the_operation_identity() -> TestResult {
    let (fixture, server) = remote_fixture()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "remote-identity")?;
    let nonce = preflight(&runtime, &request)?;
    assert!(server.requests()?.is_empty(), "a preflight never delivers");

    let executed = execute(&runtime, &request, &nonce)?;
    assert_eq!(executed.verdict, Verdict::Allow, "{:?}", executed.reason);
    assert!(executed.output.is_some());
    let operation_id = assert_state(&fixture, &request, "completed")?;
    let requests = server.requests()?;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["idempotency_key"], operation_id);
    assert_eq!(requests[0]["attempt_id"], format!("attempt:{operation_id}"));
    assert_eq!(requests[0]["request_id"], request.request_id);
    assert_eq!(requests[0]["tool"], TOOL_NAME);
    assert_eq!(requests[0]["arguments"], request.arguments);

    let replay = execute(&runtime, &request, &nonce)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(replay.receipt.id, executed.receipt.id);
    assert_eq!(
        fixture.invocations.load(Ordering::SeqCst),
        1,
        "a replay redelivers the receipt, not the request"
    );
    Ok(())
}

#[test]
fn unreachable_tool_server_is_compensated_before_dispatch() -> TestResult {
    let (fixture, server) = remote_fixture()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "remote-unreachable")?;
    let nonce = preflight(&runtime, &request)?;
    server.stop();

    let denied = execute(&runtime, &request, &nonce)?;
    assert_eq!(denied.verdict, Verdict::Deny, "{:?}", denied.reason);
    assert!(
        reason_contains(&denied, "could not prepare delivery"),
        "{:?}",
        denied.reason
    );
    assert_state(&fixture, &request, "compensated_before_dispatch")?;
    assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);

    let stale = execute(&runtime, &request, &nonce)?;
    assert_eq!(stale.verdict, Verdict::Deny, "{:?}", stale.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);

    server.restart()?;
    let retry = fixture.request(&runtime, "remote-unreachable-retry")?;
    let nonce = preflight(&runtime, &retry)?;
    let executed = execute(&runtime, &retry, &nonce)?;
    assert_eq!(executed.verdict, Verdict::Allow, "{:?}", executed.reason);
    assert_state(&fixture, &retry, "completed")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn transport_failure_after_delivery_is_outcome_unknown() -> TestResult {
    let (fixture, server) = remote_fixture()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "remote-closed")?;
    let nonce = preflight(&runtime, &request)?;
    server.set_behavior(Behavior::CloseAfterRead)?;

    let response = execute(&runtime, &request, &nonce)?;
    assert!(response.output.is_none(), "{response:?}");
    assert!(
        matches!(
            &response.terminal_state,
            OperationTerminalState::Incomplete { .. }
        ),
        "{:?}",
        response.terminal_state
    );
    assert_state(&fixture, &request, "outcome_unknown_after_dispatch")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        grant_quota(&runtime, &request)?,
        (0, 1),
        "the captured invocation is never reversed after delivery"
    );

    server.set_behavior(Behavior::Respond)?;
    let replay = execute(&runtime, &request, &nonce)?;
    assert_eq!(replay.verdict, Verdict::Deny, "{:?}", replay.reason);
    assert!(
        reason_contains(&replay, "outcome_unknown_after_dispatch")
            || reason_contains(&replay, "OutcomeUnknownAfterDispatch"),
        "{:?}",
        replay.reason
    );
    drop(runtime);

    let restarted = fixture.open()?;
    let replay = execute(&restarted, &request, &nonce)?;
    assert_eq!(replay.verdict, Verdict::Deny, "{:?}", replay.reason);
    assert_state(&fixture, &request, "outcome_unknown_after_dispatch")?;
    assert_eq!(
        fixture.invocations.load(Ordering::SeqCst),
        1,
        "nothing redelivers an ambiguous dispatch"
    );
    Ok(())
}

#[test]
fn late_response_after_the_transport_deadline_is_outcome_unknown() -> TestResult {
    let (fixture, server) = remote_fixture()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "remote-late")?;
    let nonce = preflight(&runtime, &request)?;
    server.set_behavior(Behavior::DelayResponse(Duration::from_secs(3)))?;

    let response = execute(&runtime, &request, &nonce)?;
    assert!(response.output.is_none(), "{response:?}");
    assert_state(&fixture, &request, "outcome_unknown_after_dispatch")?;
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));

    std::thread::sleep(Duration::from_secs(3));
    let replay = execute(&runtime, &request, &nonce)?;
    assert_eq!(replay.verdict, Verdict::Deny, "{:?}", replay.reason);
    assert_eq!(
        fixture.invocations.load(Ordering::SeqCst),
        1,
        "the late answer is discarded and never redelivered"
    );
    Ok(())
}
