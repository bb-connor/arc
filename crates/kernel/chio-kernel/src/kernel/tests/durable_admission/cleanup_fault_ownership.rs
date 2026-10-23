//! A failed cleanup reports the fault without taking the operation's terminal.

use super::*;
use chio_core::receipt::kinds::{BoundaryClass, ObservationOutcome, ReceiptKind};
use std::sync::{Arc, Condvar, Mutex};
use tokio::sync::Notify;

struct GuardGate {
    entered: Arc<Notify>,
    released: Arc<(Mutex<bool>, Condvar)>,
}

impl GuardGate {
    fn install(kernel: &mut ChioKernel) -> Self {
        kernel.config.deadlines.always_offload_guards = true;
        let gate = Self {
            entered: Arc::new(Notify::new()),
            released: Arc::new((Mutex::new(false), Condvar::new())),
        };
        kernel.add_guard(Box::new(ParkingGuard {
            entered: gate.entered.clone(),
            released: gate.released.clone(),
        }));
        gate
    }
}

impl Drop for GuardGate {
    fn drop(&mut self) {
        *self
            .released
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = true;
        self.released.1.notify_all();
    }
}

struct ParkingGuard {
    entered: Arc<Notify>,
    released: Arc<(Mutex<bool>, Condvar)>,
}

impl Guard for ParkingGuard {
    fn name(&self) -> &str {
        "cleanup-fault-ownership-gate"
    }

    fn evaluate(&self, _: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        self.entered.notify_one();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut released = self
            .released
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        while !*released {
            let (next, timeout) = self
                .released
                .1
                .wait_timeout(
                    released,
                    deadline.saturating_duration_since(std::time::Instant::now()),
                )
                .unwrap_or_else(|error| error.into_inner());
            released = next;
            if timeout.timed_out() && !*released {
                return Err(KernelError::GuardDenied(
                    "cleanup ownership guard exceeded its five-second bound".into(),
                ));
            }
        }
        Ok(GuardDecision::allow())
    }
}

async fn drop_at_guard(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    gate: &GuardGate,
    store: &TestAdmissionOperationStore,
    fail_compensation: bool,
) -> AdmissionOperationV1 {
    let mut evaluation = Box::pin(kernel.evaluate_tool_call(request));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            result = &mut evaluation => panic!("evaluation completed before the guard: {result:?}"),
            () = gate.entered.notified() => {}
        }
    })
    .await
    .expect("public evaluation reached the offloaded guard");
    let original = store.operation();
    assert_eq!(
        original.state(),
        AdmissionOperationState::BrokerAttemptRegistered
    );
    if fail_compensation {
        store.fail_next_terminal_projection();
    }
    drop(evaluation);
    original
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleanup_fault_observation_preserves_the_original_terminal_owner() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("cleanup-fault-observation-owner");
    let gate = GuardGate::install(&mut kernel);
    let original = drop_at_guard(&kernel, &request, &gate, &store, true).await;
    drop(gate);
    assert_eq!(store.operation(), original);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let log = kernel.receipt_log();
    assert_eq!(
        log.len(),
        1,
        "the cleanup fault must remain signed evidence"
    );
    let report = log.get(0).expect("cleanup report");
    assert!(report.verify_integrity_embedded_key().expect("report signature"));
    assert_eq!(report.receipt_kind, ReceiptKind::TraceObservation);
    assert_eq!(report.boundary_class, BoundaryClass::DetectOnly);
    assert_eq!(
        report.observation_outcome,
        Some(ObservationOutcome::Observed)
    );
    assert_eq!(
        report.decision, None,
        "the live operation owns its execution decision"
    );
    let metadata = report.metadata.as_ref().expect("fault metadata");
    assert_eq!(metadata.pointer("/chio_runtime/identity_disposition"), None);
    assert_eq!(
        metadata["receipt_context"]["request_id"],
        request.request_id
    );
    assert_eq!(
        metadata["receipt_context"]["request_namespace_digest"],
        original.binding().request_namespace_digest().as_str()
    );
    assert!(metadata["chio_runtime"]["pre_dispatch_cleanup_faults"]
        .as_array()
        .expect("cleanup fault list")
        .iter()
        .any(|fault| fault["step"] == "durable_admission_compensation"
            && fault["hold_ids"].as_array().is_some_and(|ids| ids
                .iter()
                .any(|id| id == original.binding().operation_id().as_str()))));

    let response = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("original owner resumes");
    assert_eq!(response.verdict, Verdict::Allow, "{response:?}");
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    let receipts = kernel.receipt_log();
    assert_eq!(receipts.len(), 2);
    assert_eq!(
        serde_json::to_value(receipts.get(0).expect("retained observation")).unwrap(),
        serde_json::to_value(report).unwrap(),
    );
    assert_eq!(
        serde_json::to_value(receipts.get(1).expect("actual terminal")).unwrap(),
        serde_json::to_value(&response.receipt).unwrap(),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirmed_cleanup_replays_its_original_cancellation_receipt() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("cleanup-fault-confirmed-control");
    let gate = GuardGate::install(&mut kernel);
    drop_at_guard(&kernel, &request, &gate, &store, false).await;
    drop(gate);
    let terminal = store.operation();
    assert_eq!(
        terminal.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let original = store
        .state
        .lock()
        .expect("admission state")
        .receipt
        .clone()
        .expect("committed cancellation receipt");
    assert!(original.verify_integrity_embedded_key().expect("cancellation signature"));
    let replay = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("replay original cancellation");
    assert_same_receipt(&replay.receipt, &original);
    assert!(replay.output.is_none());
    assert_eq!(store.operation(), terminal);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(kernel.receipt_log().len(), 1);
    let second_replay = kernel
        .evaluate_tool_call(&request)
        .await
        .expect("repeat original cancellation");
    assert_same_receipt(&second_replay.receipt, &original);
    assert_eq!(kernel.receipt_log().len(), 1);
}
