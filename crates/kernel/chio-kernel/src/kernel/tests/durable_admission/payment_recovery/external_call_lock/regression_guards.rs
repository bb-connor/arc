//! A rail call made without the fence mutation lock stays exactly-once: a
//! live duplicate defers instead of calling the rail, and a worker whose
//! claim expired or was superseded during the call cannot record its result.

use super::*;
use crate::admission_operation::AdmissionRecoveryError;

type Outcome = Result<(Verdict, String), KernelError>;

fn gate_captures(kernel: &mut ChioKernel, calls: &Arc<RailCalls>) -> Arc<Gate> {
    let gate = Arc::new(Gate::default());
    kernel.set_payment_adapter(Box::new(GatedRail {
        inner: RecoveryRail {
            prepaid: false,
            calls: calls.clone(),
        },
        gate: gate.clone(),
        gated: GatedCall::Capture,
    }));
    gate
}

fn start_operation_a(
    kernel: Arc<ChioKernel>,
    request: &ToolCallRequest,
) -> mpsc::Receiver<Outcome> {
    let request = request.clone();
    run_operation_a(move || {
        kernel
            .evaluate_tool_call_blocking(&request)
            .map(|response| (response.verdict, response.receipt.id))
    })
}

/// Fails instead of hanging when a concurrent step blocks behind operation A.
fn concurrently<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Box<dyn std::error::Error>> {
    run_operation_a(work)
        .recv_timeout(SETTLE_BOUND)
        .map_err(|_| "a concurrent admission step blocked while operation A was parked".into())
}

fn captures(calls: &RailCalls) -> Result<Vec<(String, u64)>, Box<dyn std::error::Error>> {
    Ok(calls.captures.lock().map_err(|_| "capture lock")?.clone())
}

fn entered(gate: &Gate) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(gate.state.lock().map_err(poisoned)?.entered.clone())
}

fn has_receipt(store: &TestAdmissionOperationStore) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .receipt
        .is_some())
}

fn is_fenced(error: &KernelError) -> bool {
    matches!(error, KernelError::AdmissionRecovery(failure)
        if matches!(failure.as_ref(), AdmissionRecoveryError::Store(AdmissionOperationStoreError::Fenced)))
}

#[test]
fn parked_capture_defers_a_live_duplicate_and_a_concurrent_tick() -> TestResult {
    let (mut kernel, request, store, invocations, calls) =
        payment_fixture("external-call-lock-duplicate", false);
    isolated_fence(&mut kernel, &store, "duplicate")?;
    let gate = gate_captures(&mut kernel, &calls);
    let _open = OpenOnDrop(gate.clone());
    let kernel = Arc::new(kernel);
    let finished = start_operation_a(kernel.clone(), &request);
    wait_for_entry(&gate, &finished)?;
    let parked = store.operation();
    let operation_id = parked.binding().operation_id().as_str().to_owned();
    let settling = store.payment_journal().ok_or("settling journal")?;

    let tick = kernel.clone();
    assert_eq!(
        concurrently(move || tick
            .reconcile_recoverable_admissions_batch(256)
            .map_err(|error| error.to_string()))??,
        0
    );
    let duplicate = kernel.clone();
    let duplicate_request = request.clone();
    let refusal = concurrently(move || duplicate.evaluate_tool_call_blocking(&duplicate_request))?
        .expect_err("the live finalization owns its terminal receipt");
    assert_eq!(
        refusal.to_string(),
        "durable admission failed: operation already has a live evaluation or recovery owner"
    );
    assert_eq!(store.operation(), parked);
    assert_eq!(store.payment_journal(), Some(settling));
    assert_eq!(entered(&gate)?, [operation_id.as_str()]);
    assert_eq!(gate.parked()?, 1);
    assert!(captures(&calls)?.is_empty());

    gate.open();
    let (verdict, receipt_id) = finished.recv_timeout(SETTLE_BOUND)??;
    assert_eq!(verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(captures(&calls)?, [(operation_id.clone(), 10)]);
    assert_eq!(kernel.reconcile_recoverable_admissions_batch(256)?, 0);
    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.receipt.id, receipt_id);
    assert_eq!(captures(&calls)?, [(operation_id, 10)]);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn capture_outliving_its_claim_fails_closed_and_the_next_tick_completes() -> TestResult {
    let (mut kernel, request, store, invocations, calls) =
        payment_fixture("external-call-lock-expiry", false);
    isolated_fence(&mut kernel, &store, "expiry")?;
    let gate = gate_captures(&mut kernel, &calls);
    let _open = OpenOnDrop(gate.clone());
    let kernel = Arc::new(kernel);
    let finished = start_operation_a(kernel.clone(), &request);
    wait_for_entry(&gate, &finished)?;
    let parked = store.operation();
    let operation_id = parked.binding().operation_id().as_str().to_owned();
    let settling = store.payment_journal().ok_or("settling journal")?;
    assert_eq!(settling.state, PaymentJournalState::Settling);
    let claim = store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .claim
        .clone()
        .ok_or("operation A's recovery claim")?;
    let _expired =
        chio_test_support::clock::scope_unix_secs(claim.expires_at_unix_ms() / 1_000 + 1);

    // The expired claim no longer keeps the sweep away; the live token does.
    let tick = kernel.clone();
    assert_eq!(
        concurrently(move || tick
            .reconcile_recoverable_admissions_batch(256)
            .map_err(|error| error.to_string()))??,
        0
    );
    assert_eq!(entered(&gate)?, [operation_id.as_str()]);
    assert!(captures(&calls)?.is_empty());

    gate.open();
    let error = finished
        .recv_timeout(SETTLE_BOUND)?
        .err()
        .ok_or("an expired claim recorded its rail capture")?;
    assert!(is_fenced(&error), "{error:?}");
    assert_eq!(store.operation(), parked);
    assert_eq!(store.payment_journal(), Some(settling));
    assert!(!has_receipt(&store)?);
    assert_eq!(captures(&calls)?, [(operation_id.clone(), 10)]);

    assert_eq!(kernel.reconcile_recoverable_admissions_batch(256)?, 1);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    let journal = store.payment_journal().ok_or("settled journal")?;
    assert_eq!(
        (journal.state, journal.settle_amount_units),
        (PaymentJournalState::Settled, Some(10))
    );
    assert!(has_receipt(&store)?);
    assert_eq!(
        captures(&calls)?,
        [(operation_id.clone(), 10), (operation_id, 10)]
    );
    assert_eq!(kernel.reconcile_recoverable_admissions_batch(256)?, 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn capture_across_owner_rotation_is_fenced_without_recording() -> TestResult {
    let (mut kernel, request, store, _, calls) =
        payment_fixture("external-call-lock-rotation", false);
    let fence = isolated_fence(&mut kernel, &store, "rotation")?;
    let gate = gate_captures(&mut kernel, &calls);
    let _open = OpenOnDrop(gate.clone());
    let finished = start_operation_a(Arc::new(kernel), &request);
    wait_for_entry(&gate, &finished)?;
    let parked = store.operation();
    let operation_id = parked.binding().operation_id().as_str().to_owned();
    let settling = store.payment_journal().ok_or("settling journal")?;
    assert_eq!(settling.state, PaymentJournalState::Settling);

    store.rotate_fence(rotated(&fence));
    gate.open();
    let error = finished
        .recv_timeout(SETTLE_BOUND)?
        .err()
        .ok_or("a superseded owner recorded its rail capture")?;
    assert!(is_fenced(&error), "{error:?}");
    assert_eq!(store.operation(), parked);
    assert_eq!(store.payment_journal(), Some(settling));
    assert!(!has_receipt(&store)?);
    assert_eq!(captures(&calls)?, [(operation_id, 10)]);
    Ok(())
}

#[test]
fn release_across_owner_rotation_is_fenced_without_recording() -> TestResult {
    let (mut kernel, request, store, invocations, calls) =
        payment_fixture("external-call-lock-release-rotation", false);
    let fence = isolated_fence(&mut kernel, &store, "release-rotation")?;
    let gate = Arc::new(Gate::default());
    let _open = OpenOnDrop(gate.clone());
    kernel.set_payment_adapter(Box::new(GatedRail {
        inner: RecoveryRail {
            prepaid: false,
            calls: calls.clone(),
        },
        gate: gate.clone(),
        gated: GatedCall::Release,
    }));
    authorize_without_dispatch(&kernel, &request)?;
    let operation = store.operation();
    let operation_id = operation.binding().operation_id().as_str().to_owned();
    let compensated = operation.clone();
    let finished = run_operation_a(move || {
        kernel.compensate_durable_admission_before_dispatch(
            &compensated,
            serde_json::json!({"authority": "external-call-lock"}),
            current_unix_timestamp_ms(),
            None,
        )
    });
    wait_for_entry(&gate, &finished)?;
    let releasing = store.payment_journal().ok_or("releasing journal")?;
    assert_eq!(
        (releasing.state, releasing.settle_action),
        (
            PaymentJournalState::Settling,
            Some(PaymentSettleAction::Release)
        )
    );

    store.rotate_fence(rotated(&fence));
    gate.open();
    let error = finished
        .recv_timeout(SETTLE_BOUND)?
        .err()
        .ok_or("a superseded owner recorded its rail release")?;
    assert!(is_fenced(&error), "{error:?}");
    assert_eq!(store.operation(), operation);
    assert_eq!(store.payment_journal(), Some(releasing));
    assert_eq!(
        calls
            .releases
            .lock()
            .map_err(|_| "release lock")?
            .as_slice(),
        [operation_id]
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

fn rotated(fence: &StoreMutationFence) -> StoreMutationFence {
    StoreMutationFence {
        lease_id: "external-call-lock-rotated-lease".into(),
        owner_epoch: fence.owner_epoch + 1,
        ..fence.clone()
    }
}
