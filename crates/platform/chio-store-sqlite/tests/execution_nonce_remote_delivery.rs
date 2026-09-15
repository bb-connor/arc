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
    BlockingToolServerAdapter, DurableFinalizationCutpoint, ToolCallRequest, ToolCallResponse,
    ToolServerConnection, Verdict,
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

/// A crash inside the execution request. The parent provisions the store,
/// runs the preflight, releases the serving owner and starts a child that
/// executes the same request through the same loopback server; the child
/// aborts its own process at a transport boundary or at a durable commit
/// inside finalization, and the parent reopens the authority as the next
/// process would.
#[cfg(unix)]
mod crash_cutpoints {
    use super::*;
    use loopback::AbortPoint;
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::Command;

    /// Where the child kills itself: on the transport, or after a durable
    /// commit inside the kernel's finalization of the returned call.
    #[derive(Clone, Copy)]
    enum CrashPoint {
        Transport(AbortPoint),
        Finalization(DurableFinalizationCutpoint),
    }

    impl CrashPoint {
        const FINALIZATION_PREFIX: &'static str = "finalization:";

        fn parse(name: &str) -> Option<Self> {
            match name.strip_prefix(Self::FINALIZATION_PREFIX) {
                Some(cutpoint) => {
                    DurableFinalizationCutpoint::parse(cutpoint).map(Self::Finalization)
                }
                None => AbortPoint::parse(name).map(Self::Transport),
            }
        }

        fn name(self) -> String {
            match self {
                Self::Transport(point) => point.name().to_owned(),
                Self::Finalization(cutpoint) => {
                    format!("{}{}", Self::FINALIZATION_PREFIX, cutpoint.name())
                }
            }
        }
    }

    const CHILD_ENV: &str = "CHIO_REMOTE_DELIVERY_CHILD";
    const DIRECTORY_ENV: &str = "CHIO_REMOTE_DELIVERY_DIRECTORY";
    const SIGNER_ENV: &str = "CHIO_REMOTE_DELIVERY_SIGNER_SEED";
    const AGENT_ENV: &str = "CHIO_REMOTE_DELIVERY_AGENT_SEED";
    const SERVER_ENV: &str = "CHIO_REMOTE_DELIVERY_SERVER";
    const REQUEST_FILE: &str = "execution-request.json";

    /// Runs the execution request in this process when the parent asked for
    /// it; the process aborts at the requested point.
    fn run_child_role() -> TestResult<bool> {
        let Ok(point) = std::env::var(CHILD_ENV) else {
            return Ok(false);
        };
        let crash_at = CrashPoint::parse(&point).ok_or("crash point")?;
        let directory = PathBuf::from(std::env::var(DIRECTORY_ENV)?);
        let mut fixture = Fixture::attach(
            directory.clone(),
            &std::env::var(SIGNER_ENV)?,
            &std::env::var(AGENT_ENV)?,
        )?;
        let address: std::net::SocketAddr = std::env::var(SERVER_ENV)?.parse()?;
        let abort_at = match crash_at {
            CrashPoint::Transport(point) => Some(point),
            CrashPoint::Finalization(cutpoint) => {
                fixture.finalization_cutpoint = Some(cutpoint);
                None
            }
        };
        fixture.tool_server = Some(Box::new(move || {
            let client = match abort_at {
                Some(point) => LoopbackClient::aborting_at(address, point),
                None => LoopbackClient::new(address),
            };
            BlockingToolServerAdapter::new(Arc::new(client))
                .map(|adapter| Box::new(adapter) as Box<dyn ToolServerConnection>)
        }));
        let request: ToolCallRequest =
            serde_json::from_slice(&std::fs::read(directory.join(REQUEST_FILE))?)?;
        let runtime = fixture.open()?;
        let response = runtime.kernel.evaluate_tool_call_blocking(&request)?;
        Err(format!("the child returned instead of aborting: {response:?}").into())
    }

    /// Preflights in the parent, executes in a child that aborts at `point`,
    /// and returns the fixture, server and request for the parent to assert
    /// against after reopening.
    fn crash_execution(
        test_name: &str,
        request_id: &str,
        point: CrashPoint,
    ) -> TestResult<(Fixture, Arc<LoopbackServer>, ToolCallRequest)> {
        let (fixture, server) = remote_fixture()?;
        let request = {
            let runtime = fixture.open()?;
            let request = fixture.request(&runtime, request_id)?;
            let nonce = preflight(&runtime, &request)?;
            let mut execution = request.clone();
            execution.execution_nonce = Some(nonce);
            execution
        };
        std::fs::write(
            fixture.directory.path().join(REQUEST_FILE),
            serde_json::to_vec(&request)?,
        )?;
        let output = Command::new(std::env::current_exe()?)
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, point.name())
            .env(DIRECTORY_ENV, fixture.directory.path())
            .env(SIGNER_ENV, fixture.signer.seed_hex())
            .env(AGENT_ENV, fixture.agent.seed_hex())
            .env(SERVER_ENV, server.address().to_string())
            .output()?;
        assert_eq!(
            output.status.signal(),
            Some(libc::SIGABRT),
            "the child must die at the cutpoint: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok((fixture, server, request))
    }

    #[test]
    fn crash_before_delivery_is_compensated_by_the_next_process() -> TestResult {
        if run_child_role()? {
            return Ok(());
        }
        let (fixture, server, request) = crash_execution(
            "crash_cutpoints::crash_before_delivery_is_compensated_by_the_next_process",
            "crash-before-delivery",
            CrashPoint::Transport(AbortPoint::BeforeDelivery),
        )?;
        assert!(server.requests()?.is_empty(), "nothing reached the server");
        let runtime = fixture.open()?;
        assert_state(&fixture, &request, "compensated_before_dispatch")?;
        assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
        let stale = execute(
            &runtime,
            &request,
            request.execution_nonce.as_ref().ok_or("nonce")?,
        )?;
        assert_eq!(stale.verdict, Verdict::Deny, "{:?}", stale.reason);
        let retry = fixture.request(&runtime, "crash-before-delivery-retry")?;
        let nonce = preflight(&runtime, &retry)?;
        let executed = execute(&runtime, &retry, &nonce)?;
        assert_eq!(executed.verdict, Verdict::Allow, "{:?}", executed.reason);
        assert_eq!(server.requests()?.len(), 1);
        Ok(())
    }

    #[test]
    fn crash_after_delivery_is_outcome_unknown_and_never_redelivered() -> TestResult {
        if run_child_role()? {
            return Ok(());
        }
        let (fixture, server, request) = crash_execution(
            "crash_cutpoints::crash_after_delivery_is_outcome_unknown_and_never_redelivered",
            "crash-after-delivery",
            CrashPoint::Transport(AbortPoint::AfterDelivery),
        )?;
        assert_eq!(
            server.requests()?.len(),
            1,
            "the request reached the server"
        );
        assert_state(&fixture, &request, "dispatch_committed")?;
        let runtime = fixture.open()?;
        assert_state(&fixture, &request, "outcome_unknown_after_dispatch")?;
        assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
        let replay = execute(
            &runtime,
            &request,
            request.execution_nonce.as_ref().ok_or("nonce")?,
        )?;
        assert_eq!(replay.verdict, Verdict::Deny, "{:?}", replay.reason);
        assert_eq!(server.requests()?.len(), 1, "no redelivery after the crash");
        Ok(())
    }

    #[test]
    fn crash_after_the_response_is_outcome_unknown_and_never_redelivered() -> TestResult {
        if run_child_role()? {
            return Ok(());
        }
        let (fixture, server, request) = crash_execution(
            "crash_cutpoints::crash_after_the_response_is_outcome_unknown_and_never_redelivered",
            "crash-after-response",
            CrashPoint::Transport(AbortPoint::AfterResponse),
        )?;
        assert_eq!(server.requests()?.len(), 1);
        assert_state(&fixture, &request, "dispatch_committed")?;
        let runtime = fixture.open()?;
        assert_state(&fixture, &request, "outcome_unknown_after_dispatch")?;
        assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
        let replay = execute(
            &runtime,
            &request,
            request.execution_nonce.as_ref().ok_or("nonce")?,
        )?;
        assert_eq!(replay.verdict, Verdict::Deny, "{:?}", replay.reason);
        assert_eq!(
            server.requests()?.len(),
            1,
            "a lost known-good outcome is never re-executed"
        );
        Ok(())
    }

    /// Rows in the receipt log. Read while no runtime holds the log open.
    fn receipt_log_len(fixture: &Fixture) -> TestResult<i64> {
        let connection = rusqlite::Connection::open_with_flags(
            fixture.directory.path().join("receipts.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        Ok(
            connection.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
                row.get(0)
            })?,
        )
    }

    /// Executes in a child that dies at `cutpoint`, then proves the next
    /// process finishes the retained return: the recovery sweep alone moves the
    /// operation to completed, the replay answers from that terminal, the
    /// receipt reaches the log, and the server never sees a second delivery.
    fn crash_inside_finalization_is_finished_by_the_next_process(
        test_name: &str,
        request_id: &str,
        cutpoint: DurableFinalizationCutpoint,
    ) -> TestResult {
        let (fixture, server, request) =
            crash_execution(test_name, request_id, CrashPoint::Finalization(cutpoint))?;
        assert_eq!(
            server.requests()?.len(),
            1,
            "the request reached the server"
        );
        assert_state(&fixture, &request, "finalizing")?;
        assert_eq!(
            receipt_log_len(&fixture)?,
            1,
            "only the preflight receipt was logged"
        );
        let runtime = fixture.open_with_reconcile(false)?;
        assert_state(&fixture, &request, "finalizing")?;
        assert_eq!(runtime.kernel.reconcile_recoverable_admissions()?, 1);
        assert_state(&fixture, &request, "completed")?;
        assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
        let replay = execute(
            &runtime,
            &request,
            request.execution_nonce.as_ref().ok_or("nonce")?,
        )?;
        assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
        assert_eq!(replay.terminal_state, OperationTerminalState::Completed);
        assert_eq!(
            server.requests()?.len(),
            1,
            "a recorded return is finished, never re-executed"
        );
        drop(runtime);
        assert_eq!(
            receipt_log_len(&fixture)?,
            2,
            "the completed receipt reached the log"
        );
        Ok(())
    }

    #[test]
    fn crash_after_the_return_is_recorded_is_finished_by_the_next_process() -> TestResult {
        if run_child_role()? {
            return Ok(());
        }
        crash_inside_finalization_is_finished_by_the_next_process(
            "crash_cutpoints::crash_after_the_return_is_recorded_is_finished_by_the_next_process",
            "crash-after-return-recorded",
            DurableFinalizationCutpoint::ToolReturnRecorded,
        )
    }

    #[test]
    fn crash_after_the_evaluation_begins_is_finished_by_the_next_process() -> TestResult {
        if run_child_role()? {
            return Ok(());
        }
        crash_inside_finalization_is_finished_by_the_next_process(
            "crash_cutpoints::crash_after_the_evaluation_begins_is_finished_by_the_next_process",
            "crash-after-evaluation-begun",
            DurableFinalizationCutpoint::PostReturnEvaluationBegun,
        )
    }

    #[test]
    fn crash_after_the_evaluation_resolves_is_finished_by_the_next_process() -> TestResult {
        if run_child_role()? {
            return Ok(());
        }
        crash_inside_finalization_is_finished_by_the_next_process(
            "crash_cutpoints::crash_after_the_evaluation_resolves_is_finished_by_the_next_process",
            "crash-after-evaluation-resolved",
            DurableFinalizationCutpoint::PostReturnResolved,
        )
    }

    #[test]
    fn crash_after_the_terminal_projection_replays_the_completed_receipt() -> TestResult {
        if run_child_role()? {
            return Ok(());
        }
        let (fixture, server, request) = crash_execution(
            "crash_cutpoints::crash_after_the_terminal_projection_replays_the_completed_receipt",
            "crash-after-terminal-projection",
            CrashPoint::Finalization(DurableFinalizationCutpoint::TerminalProjected),
        )?;
        assert_eq!(server.requests()?.len(), 1);
        assert_state(&fixture, &request, "completed")?;
        assert_eq!(
            receipt_log_len(&fixture)?,
            1,
            "the projected receipt never reached the log"
        );
        let runtime = fixture.open_with_reconcile(false)?;
        assert_eq!(
            runtime.kernel.reconcile_recoverable_admissions()?,
            0,
            "a projected terminal needs no operation recovery"
        );
        assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
        let replay = execute(
            &runtime,
            &request,
            request.execution_nonce.as_ref().ok_or("nonce")?,
        )?;
        assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
        assert_eq!(replay.terminal_state, OperationTerminalState::Completed);
        assert_eq!(server.requests()?.len(), 1);
        drop(runtime);
        assert_eq!(
            receipt_log_len(&fixture)?,
            2,
            "the next process materializes the projected receipt"
        );
        Ok(())
    }
}
