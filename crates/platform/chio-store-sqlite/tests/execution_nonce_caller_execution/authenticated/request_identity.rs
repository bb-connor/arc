use super::*;
use chio_core::capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_kernel::admission_operation::AdmissionOperationState;
use chio_kernel::{BudgetStore, CallerExecutionCheckpoint, ToolCallResponse, ToolInvocationCost};
use std::sync::{atomic::AtomicBool, mpsc, Arc, Mutex};

fn monetary_request(fixture: &Fixture, runtime: &Runtime, id: &str) -> TestResult<ToolCallRequest> {
    let mut request = fixture.request(runtime, id)?;
    request.capability = runtime.kernel.issue_capability(
        &fixture.agent.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: SERVER_ID.into(),
                tool_name: TOOL_NAME.into(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: Some(2),
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 40,
                    currency: "USD".into(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 150,
                    currency: "USD".into(),
                }),
                dpop_required: None,
            }],
            ..Default::default()
        },
        600,
    )?;
    let reserved = runtime.kernel.reserve_caller_execution_blocking(&request)?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
    request.execution_nonce = Some(*reserved.execution_nonce.ok_or("reserved nonce")?);
    Ok(request)
}

#[derive(Debug, PartialEq, Eq)]
struct ReservationSnapshot {
    operation: Vec<u8>,
    issuance: Vec<u8>,
    reservation: Vec<u8>,
    rows: [i64; 4],
}

fn snapshot(fixture: &Fixture, request: &ToolCallRequest) -> TestResult<ReservationSnapshot> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture.database(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (operation, issuance, reservation) = connection.query_row(
        "SELECT operation.operation_json, issuance.issuance_json, reservation.reservation_json
         FROM admission_operations AS operation
         JOIN admission_execution_nonce_issuances AS issuance USING (operation_id)
         JOIN admission_execution_nonce_reservations AS reservation USING (operation_id)
         WHERE operation.request_id = ?1",
        [&request.request_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    Ok(ReservationSnapshot {
        operation,
        issuance,
        reservation,
        rows: [
            count_rows(fixture, "budget_authorization_holds")?,
            count_rows(fixture, "admission_nonce_preflight_holds")?,
            count_rows(fixture, "admission_execution_nonce_issuances")?,
            count_rows(fixture, "admission_execution_nonce_reservations")?,
        ],
    })
}

fn assert_unstarted(fixture: &Fixture, runtime: &Runtime, request: &ToolCallRequest) -> TestResult {
    assert_state(fixture, request, "ready_to_dispatch")?;
    assert_eq!(grant_quota(runtime, request)?, (1, 0));
    let usage = runtime
        .authority
        .budget_store()
        .get_usage(&request.capability.id, 0)?
        .ok_or("original grant usage")?;
    assert_eq!(
        (usage.total_cost_exposed, usage.total_cost_realized_spend),
        (40, 0)
    );
    let payments = rusqlite::Connection::open_with_flags(
        fixture.directory.path().join("local-payments.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let payment_count: i64 = payments.query_row(
        "SELECT count(*) FROM chio_finding_operator_payments",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(payment_count, 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

fn assert_denied(response: &ToolCallResponse, reason: &str) -> TestResult {
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some(reason));
    assert!(response.execution_nonce.is_none());
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    Ok(())
}

fn settle_original(
    fixture: &Fixture,
    runtime: &Runtime,
    key: &Keypair,
    request: &ToolCallRequest,
) -> TestResult {
    let authorization = start(runtime, request)?;
    let effects = std::sync::atomic::AtomicUsize::new(0);
    let report = ledger(fixture)?.execute_once(
        &authorization,
        &fixture.signer.public_key(),
        &authorization.authorization.invocation,
        key,
        || {
            effects.fetch_add(1, Ordering::SeqCst);
            Ok(CallerExecutionReport {
                output: serde_json::json!({"original": true}),
                realized_cost: Some(ToolInvocationCost {
                    units: 40,
                    currency: "USD".into(),
                    breakdown: None,
                }),
            })
        },
    )?;
    let response = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(response.receipt.verify_signature()?);
    assert_state(fixture, request, "completed")?;
    assert_eq!(grant_quota(runtime, request)?, (0, 1));
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let payments = rusqlite::Connection::open_with_flags(
        fixture.directory.path().join("local-payments.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let payment: (i64, String, i64) = payments.query_row(
        "SELECT count(*), min(state), sum(amount_units) FROM chio_finding_operator_payments",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(payment, (1, "captured".into(), 40));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn retained_request_identity_refuses_substitution_before_payment_across_restart() -> TestResult {
    let (mut fixture, key) = fixture()?;
    fixture.local_payment_rail = true;
    let (original, initial) = {
        let runtime = fixture.open()?;
        let original = monetary_request(&fixture, &runtime, "retained-caller-identity")?;
        assert_unstarted(&fixture, &runtime, &original)?;
        let initial = snapshot(&fixture, &original)?;
        assert_eq!(initial.rows, [2, 1, 1, 1]);
        (original, initial)
    };
    for _ in 0..2 {
        let runtime = fixture.open()?;
        assert_eq!(snapshot(&fixture, &original)?, initial);
        let (operation_id, _) =
            operation_state(&fixture, &original.request_id)?.ok_or("original operation")?;
        for different_subject in [false, true] {
            let subject = if different_subject {
                Keypair::generate().public_key()
            } else {
                fixture.agent.public_key()
            };
            let mut substituted = original.clone();
            substituted.capability = runtime.kernel.issue_capability(
                &subject,
                original.capability.scope.clone(),
                600,
            )?;
            substituted.agent_id = subject.to_hex();
            let response = runtime
                .kernel
                .reserve_caller_execution_blocking(&substituted)?;
            assert_denied(&response, &format!(
                "durable admission failed: request id conflicts with retained operation {operation_id}"
            ))?;
            assert!(runtime
                .authority
                .budget_store()
                .get_usage(&substituted.capability.id, 0)?
                .is_none());
            assert_eq!(grant_quota(&runtime, &substituted)?, (0, 0));
            assert_eq!(snapshot(&fixture, &original)?, initial);
            assert_unstarted(&fixture, &runtime, &original)?;
        }
        let mut no_nonce = original.clone();
        no_nonce.execution_nonce = None;
        let denied = runtime
            .kernel
            .reserve_caller_execution_blocking(&no_nonce)?;
        assert_denied(&denied,
            "durable admission failed: execution nonce preflight cannot replay an operation in state ReadyToDispatch")?;
        for changed_identity in [false, true] {
            let mut forged = original.clone();
            let nonce = forged.execution_nonce.as_mut().ok_or("original nonce")?;
            if changed_identity {
                nonce.nonce.nonce_id = "unissued-caller-nonce".into();
            } else {
                nonce.signature = fixture.agent.sign(b"invalid caller nonce signature");
            }
            let denied = runtime.kernel.reserve_caller_execution_blocking(&forged)?;
            assert_denied(&denied,
                "durable admission failed: presented execution nonce does not match its retained issuance")?;
            assert_eq!(snapshot(&fixture, &original)?, initial);
            assert_unstarted(&fixture, &runtime, &original)?;
        }
    }
    let runtime = fixture.open()?;
    assert_eq!(snapshot(&fixture, &original)?, initial);
    settle_original(&fixture, &runtime, &key, &original)
}

#[test]
fn concurrent_original_nonce_retry_preserves_one_reservation_without_payment() -> TestResult {
    let (mut fixture, key) = fixture()?;
    fixture.local_payment_rail = true;
    let mut runtime = fixture.open()?;
    let request = monetary_request(&fixture, &runtime, "concurrent-caller-retry")?;
    let initial = snapshot(&fixture, &request)?;
    assert_eq!(initial.rows, [2, 1, 1, 1]);
    let (arrived_tx, arrived_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let armed = AtomicBool::new(true);
    let request_id = request.request_id.clone();
    Arc::get_mut(&mut runtime.kernel)
        .ok_or("exclusive kernel")?
        .install_caller_execution_checkpoint_hook(Arc::new(move |checkpoint, operation| {
            if checkpoint != CallerExecutionCheckpoint::BeforeShareAdmission
                || operation.state() != AdmissionOperationState::ReadyToDispatch
                || operation.binding().request_id().as_str() != request_id
                || !armed.swap(false, Ordering::SeqCst)
            {
                return;
            }
            assert!(arrived_tx.send(()).is_ok(), "retry observer disconnected");
            let receiver = match release_rx.lock() {
                Ok(receiver) => receiver,
                Err(error) => panic!("retry gate poisoned: {error}"),
            };
            assert!(
                receiver.recv_timeout(Duration::from_secs(30)).is_ok(),
                "retry gate not released"
            );
        }));
    let (winner, duplicate) = std::thread::scope(|scope| -> TestResult<_> {
        let worker = scope.spawn(|| runtime.kernel.reserve_caller_execution_blocking(&request));
        let duplicate = match arrived_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(()) => runtime
                .kernel
                .reserve_caller_execution_blocking(&request)
                .map_err(Box::<dyn std::error::Error>::from),
            Err(error) => Err(Box::<dyn std::error::Error>::from(error)),
        };
        let released = release_tx.send(());
        let winner = worker.join().map_err(|_| "reservation retry panicked")?;
        released?;
        Ok((winner?, duplicate?))
    })?;
    assert_denied(
        &duplicate,
        "durable admission failed: operation already has a live evaluation or recovery owner",
    )?;
    assert_eq!(winner.verdict, Verdict::Allow, "{:?}", winner.reason);
    assert_eq!(
        winner.execution_nonce.as_deref(),
        request.execution_nonce.as_ref()
    );
    assert_eq!(snapshot(&fixture, &request)?, initial);
    assert_unstarted(&fixture, &runtime, &request)?;
    settle_original(&fixture, &runtime, &key, &request)
}
