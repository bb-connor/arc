use super::concurrency::{Acknowledgements, GatedStore};
use super::*;
use crate::kernel::tests::dispatch_credentials::PausingRevocationReadStore;
use std::sync::{mpsc, Condvar};
use std::time::Duration;

#[derive(Default)]
struct PublicationTrace(Mutex<Vec<RuntimeTraceEvent>>);

impl RuntimeTraceObserver for PublicationTrace {
    fn observe(&self, event: RuntimeTraceEvent) {
        self.0.lock().unwrap().push(event);
    }
}

fn allowed_publication(kernel: &ChioKernel) -> (ToolCallRequest, ChioReceipt, String) {
    let capability = make_capability(
        kernel,
        &make_keypair(),
        make_scope(vec![make_grant("durable-revoke", "write")]),
        300,
    );
    let request = make_request("durable-revoke", &capability, "write", "durable-revoke");
    let output = ToolCallOutput::Value(serde_json::json!({"status": "completed"}));
    let content = receipt_content_for_output(Some(&output), None).unwrap();
    let receipt = kernel
        .build_and_sign_receipt(ReceiptParams {
            request_id: Some(&request.request_id),
            capability_id: &capability.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Allow,
            action: ToolCallAction::from_parameters(request.arguments.clone()).unwrap(),
            content_hash: content.content_hash,
            canonical_content: content.canonical_content,
            metadata: content.metadata,
            timestamp: current_unix_timestamp(),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })
        .unwrap();
    (request, receipt, capability.id)
}

#[test]
fn durable_recheck_and_acknowledgement_precede_concurrent_revocation() {
    let mut kernel = make_kernel(make_config());
    let (request, receipt, capability_id) = allowed_publication(&kernel);
    let trace = Arc::new(PublicationTrace::default());
    kernel.set_runtime_trace_observer(trace.clone());
    let (read_tx, read_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    kernel.set_revocation_store_handle(Arc::new(PausingRevocationReadStore {
        revoked: AtomicBool::new(false),
        pause_next_read: AtomicBool::new(true),
        read_observed: read_tx,
        release_read: Mutex::new(release_rx),
    }));
    let (entered_tx, entered_rx) = mpsc::channel();
    let acknowledgements = Arc::new(Acknowledgements {
        released: Mutex::new(false),
        wake: Condvar::new(),
    });
    let committed = Arc::new(Mutex::new(Vec::new()));
    kernel
        .set_receipt_store(Box::new(GatedStore {
            entered: entered_tx,
            acknowledgements: acknowledgements.clone(),
            committed: committed.clone(),
        }))
        .unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let (read, started, before_recheck, released, entered, before_ack, record, revoke) =
        std::thread::scope(|scope| {
            let record =
                scope.spawn(|| kernel.record_chio_receipt_with_federation(&request, &receipt));
            let read = read_rx.recv_timeout(Duration::from_secs(2));
            let revoke = scope.spawn(|| {
                started_tx.send(()).unwrap();
                let result = kernel.revoke_capability(&capability_id);
                done_tx.send(()).unwrap();
                result
            });
            let started = started_rx.recv_timeout(Duration::from_secs(2));
            let before_recheck = done_rx.recv_timeout(Duration::from_millis(100));
            let released = release_tx.send(());
            let entered = entered_rx.recv_timeout(Duration::from_secs(2));
            let before_ack = done_rx.recv_timeout(Duration::from_millis(100));
            acknowledgements.release();
            (
                read,
                started,
                before_recheck,
                released,
                entered,
                before_ack,
                record.join(),
                revoke.join(),
            )
        });
    read.unwrap();
    started.unwrap();
    assert_eq!(before_recheck, Err(mpsc::RecvTimeoutError::Timeout));
    released.unwrap();
    assert_eq!(entered.unwrap(), receipt.id);
    assert_eq!(before_ack, Err(mpsc::RecvTimeoutError::Timeout));
    record.unwrap().unwrap();
    revoke.unwrap().unwrap();
    assert_eq!(committed.lock().unwrap().len(), 1);
    assert_eq!(kernel.receipt_log().receipts()[0].id, receipt.id);
    let events = trace.0.lock().unwrap();
    let order: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            RuntimeTraceEvent::ReceiptAppended {
                source_sequence, ..
            } => Some(("receipt", *source_sequence)),
            RuntimeTraceEvent::RevocationCommitted {
                source_sequence, ..
            } => Some(("revoke", *source_sequence)),
            _ => None,
        })
        .collect();
    assert_eq!(order.len(), 2);
    let receipt_sequence = order.iter().find(|(kind, _)| *kind == "receipt").unwrap().1;
    let revoke_sequence = order.iter().find(|(kind, _)| *kind == "revoke").unwrap().1;
    assert!(revoke_sequence > receipt_sequence);
}

#[test]
fn durable_revocation_before_recheck_refuses_without_appending() {
    let mut kernel = make_kernel(make_config());
    let (request, receipt, capability_id) = allowed_publication(&kernel);
    let journal = Arc::new(Mutex::new(Journal::default()));
    kernel
        .set_receipt_store(Box::new(PublicationStore {
            mode: AppendMode::Acknowledged,
            journal: journal.clone(),
        }))
        .unwrap();
    kernel.revoke_capability(&capability_id).unwrap();
    assert!(matches!(
        kernel.record_chio_receipt_with_federation(&request, &receipt),
        Err(KernelError::CapabilityRevoked(id)) if id == capability_id
    ));
    assert!(journal.lock().unwrap().committed.is_empty());
    assert!(kernel.receipt_log().is_empty());
}
