//! Real kernel reservations for tools a caller executes elsewhere, reconciled
//! against the SQLite admission store.

#[path = "execution_nonce_kernel_lifecycle/support.rs"]
mod support;

#[path = "execution_nonce_caller_execution/delegated_share.rs"]
mod delegated_share;

#[path = "execution_nonce_caller_execution/external_delivery.rs"]
mod external_delivery;

#[path = "execution_nonce_caller_execution/dispatch_context.rs"]
mod dispatch_context;

#[path = "execution_nonce_caller_execution/authenticated.rs"]
mod authenticated;

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

fn caller_fixture() -> TestResult<Fixture> {
    caller_fixture_with_nonce_ttl(30)
}

fn caller_fixture_with_nonce_ttl(ttl: u64) -> TestResult<Fixture> {
    let mut fixture = Fixture::with_nonce_ttl(ttl)?;
    let key = chio_core::crypto::Keypair::generate();
    fixture.caller_executor = Some(chio_kernel::caller_delivery::CallerExecutorIdentityV1 {
        executor_id: chio_kernel::admission_operation::AdmissionIdentifier::try_new(
            "executor_id",
            "caller-reservation-test-executor",
        )?,
        public_key: key.public_key(),
        key_epoch: 1,
    });
    fixture.caller_executor_key = Some(key);
    Ok(fixture)
}

fn reconcile(
    fixture: &Fixture,
    runtime: &Runtime,
    execution: &ToolCallRequest,
) -> TestResult<ToolCallResponse> {
    let nonce = execution.execution_nonce.as_ref().ok_or("reserved nonce")?;
    let authorization = match runtime
        .kernel
        .start_caller_execution_blocking(nonce, &execution.arguments)?
    {
        chio_kernel::CallerStartResponse::Authorized(authorization) => authorization,
        chio_kernel::CallerStartResponse::Denied(response) => return Ok(*response),
    };
    let path = fixture.directory.path().join("caller-ledger.sqlite3");
    let executor = fixture
        .caller_executor
        .clone()
        .ok_or("configured caller executor")?;
    let clock = chio_test_support::clock::clock();
    let ledger = if path.exists() {
        chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger::open_with_clock(
            &path, executor, clock,
        )?
    } else {
        chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger::provision_with_clock(
            &path, executor, 64, clock,
        )?
    };
    let signed = ledger.execute_once(
        &authorization,
        &fixture.signer.public_key(),
        &authorization.authorization.invocation,
        fixture
            .caller_executor_key
            .as_ref()
            .ok_or("caller executor key")?,
        || Ok(report()),
    )?;
    Ok(runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &signed)?)
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
    let fixture = caller_fixture()?;
    let runtime = fixture.open()?;
    let execution = reserve(&fixture, &runtime, "caller-settles")?;

    let settled = reconcile(&fixture, &runtime, &execution)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_eq!(settled.terminal_state, OperationTerminalState::Completed);
    assert_state(&fixture, &execution, "completed")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (0, 1));
    assert_eq!(
        fixture.invocations.load(Ordering::SeqCst),
        0,
        "the kernel never dispatched to its own server"
    );

    let replay = reconcile(&fixture, &runtime, &execution)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(canonical(&settled.receipt)?, canonical(&replay.receipt)?);
    assert_eq!(grant_quota(&runtime, &execution)?, (0, 1));
    Ok(())
}

#[test]
fn a_start_for_other_arguments_is_refused_and_keeps_the_reservation() -> TestResult {
    let fixture = caller_fixture()?;
    let runtime = fixture.open()?;
    let execution = reserve(&fixture, &runtime, "caller-other-arguments")?;
    let nonce = execution.execution_nonce.as_ref().ok_or("reserved nonce")?;
    let refused = runtime
        .kernel
        .start_caller_execution_blocking(nonce, &serde_json::json!({ "not": "the reserved call" }))
        .map(|_| ());
    assert!(
        matches!(&refused, Err(chio_kernel::KernelError::DurableAdmission(reason))
            if reason == "caller start arguments differ from the original request"),
        "{refused:?}"
    );
    assert_state(&fixture, &execution, "ready_to_dispatch")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (1, 0));
    let settled = reconcile(&fixture, &runtime, &execution)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_state(&fixture, &execution, "completed")?;
    Ok(())
}

#[test]
fn a_nonce_of_an_unreserved_operation_cannot_start() -> TestResult {
    let fixture = caller_fixture()?;
    let runtime = fixture.open()?;
    let _reserved = reserve(&fixture, &runtime, "caller-reserved")?;
    let other = fixture.request(&runtime, "caller-unreserved")?;
    let other_nonce = preflight(&runtime, &other)?;
    let refused = runtime
        .kernel
        .start_caller_execution_blocking(&other_nonce, &other.arguments)
        .map(|_| ());
    assert!(
        matches!(
            &refused,
            Err(chio_kernel::KernelError::DurableAdmission(reason))
                if reason == "caller start original nonce is absent"
        ),
        "{refused:?}"
    );
    assert_state(&fixture, &other, "prepared")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn kernel_dispatch_cannot_resume_a_caller_reservation() -> TestResult {
    let fixture = caller_fixture()?;
    let runtime = fixture.open()?;
    let execution = reserve(&fixture, &runtime, "caller-not-kernel")?;
    let receipts = runtime.kernel.receipt_log().len();
    let denied = runtime.kernel.evaluate_tool_call_blocking(&execution);
    assert!(
        matches!(&denied, Err(chio_kernel::KernelError::DurableAdmission(reason))
            if reason == "retained provider attempt does not match this dispatch"),
        "{denied:?}"
    );
    assert_eq!(runtime.kernel.receipt_log().len(), receipts);
    assert_state(&fixture, &execution, "ready_to_dispatch")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (1, 0));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn restart_keeps_a_live_caller_reservation() -> TestResult {
    let fixture = caller_fixture()?;
    let execution = {
        let runtime = fixture.open()?;
        reserve(&fixture, &runtime, "caller-restart")?
    };
    let runtime = fixture.open_with_reconcile(false)?;
    use chio_kernel::admission_operation::AdmissionOperationStore;
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;
    assert!(
        runtime
            .authority
            .admission_operation_store()
            .list_recoverable(now, 1)?
            .is_empty(),
        "live caller reservations must not occupy the bounded recovery page"
    );
    assert_eq!(runtime.kernel.reconcile_recoverable_admissions()?, 0);
    assert_state(&fixture, &execution, "ready_to_dispatch")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (1, 0));
    let settled = reconcile(&fixture, &runtime, &execution)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_state(&fixture, &execution, "completed")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn an_expired_caller_reservation_is_compensated_by_startup_recovery() -> TestResult {
    let fixture = caller_fixture_with_nonce_ttl(2)?;
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
    let late = runtime
        .kernel
        .start_caller_execution_blocking(
            execution.execution_nonce.as_ref().ok_or("reserved nonce")?,
            &execution.arguments,
        )
        .map(|_| ());
    assert!(
        matches!(&late, Err(chio_kernel::KernelError::DurableAdmission(reason))
        if reason == "caller start requires a ready original reservation"),
        "{late:?}"
    );
    assert_state(&fixture, &execution, "compensated_before_dispatch")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn a_second_reservation_is_bounded_by_the_shared_budget() -> TestResult {
    let fixture = caller_fixture()?;
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
    let settled = reconcile(&fixture, &runtime, &first)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_eq!(grant_quota(&runtime, &first)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[cfg(feature = "pq")]
#[path = "execution_nonce_caller_execution/signing_identity.rs"]
mod signing_identity;
