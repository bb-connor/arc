use super::*;
use crate::kernel::effect_obligation::recovery::{
    PendingPostEffectEvidence, PendingPostEffectRecord,
};
use crate::receipt_store::RetainedReceiptCommitment;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

#[derive(Default)]
struct StoreState {
    receipts: Mutex<Vec<ChioReceipt>>,
    append_calls: AtomicU64,
    barrier_open: AtomicBool,
    panic_after_append: AtomicBool,
}

struct RecoverableStore(Arc<StoreState>);

impl ReceiptStore for RecoverableStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.0.append_calls.fetch_add(1, Ordering::SeqCst);
        self.0.receipts.lock().unwrap().push(receipt.clone());
        assert!(
            !self.0.panic_after_append.swap(false, Ordering::SeqCst),
            "append callback panic"
        );
        Err(ReceiptStoreError::Timeout {
            operation: "lost append acknowledgement".into(),
            timeout_ms: 1,
        })
    }

    fn append_child_receipt(&self, _: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        unreachable!("no child receipts in this fixture")
    }

    fn flush_receipt_writes(&self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        if self.0.barrier_open.load(Ordering::SeqCst) {
            Ok(ReceiptFlushReport::default())
        } else {
            Err(ReceiptStoreError::Timeout {
                operation: "controlled writer barrier".into(),
                timeout_ms: 1,
            })
        }
    }

    fn load_chio_receipt(&self, id: &str) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok(self
            .0
            .receipts
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .cloned())
    }

    fn load_retained_chio_receipt_commitment(
        &self,
        id: &str,
    ) -> Result<Option<RetainedReceiptCommitment>, ReceiptStoreError> {
        self.load_chio_receipt(id)?
            .map(|receipt| {
                Ok(RetainedReceiptCommitment {
                    entry_seq: 1,
                    receipt_id: receipt.id.clone(),
                    receipt_sha256: chio_core::crypto::sha256_hex(
                        &chio_core::canonical::canonical_json_bytes(&receipt)?,
                    ),
                    kernel_key: receipt.kernel_key,
                })
            })
            .transpose()
    }
}

fn fixture() -> (ChioKernel, ChioReceipt, Arc<StoreState>) {
    let mut kernel = make_kernel(make_config());
    let state = Arc::new(StoreState::default());
    kernel
        .set_receipt_store(Box::new(RecoverableStore(Arc::clone(&state))))
        .unwrap();
    let capability = make_capability(
        &kernel,
        &make_keypair(),
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    let request = make_request("retained-evidence", &capability, "read_file", "srv-a");
    let receipt = kernel
        .prepare_deny_response_with_metadata(
            &request,
            "post-effect fixture",
            current_unix_timestamp(),
            None,
            None,
        )
        .unwrap()
        .receipt()
        .clone();
    (kernel, receipt, state)
}

fn retain(kernel: &ChioKernel, receipt: ChioReceipt) {
    let mut slot = kernel
        .acquire_post_effect_evidence_slot(NonZeroUsize::new(1).unwrap())
        .unwrap();
    slot.reserve_bytes(
        chio_core::canonical::canonical_json_bytes(&receipt)
            .unwrap()
            .len(),
    )
    .unwrap();
    kernel.buffer_post_effect_evidence(
        slot,
        PendingPostEffectRecord {
            evidence: PendingPostEffectEvidence::Signed { receipt },
            child_receipts: Vec::new(),
            unknown_child: None,
        },
    );
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "evidence recovery made no progress"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn unknown_append_recovers_while_idle_without_a_competing_receipt() {
    let (kernel, receipt, state) = fixture();
    let id = receipt.id.clone();
    retain(&kernel, receipt);
    wait_until(|| state.append_calls.load(Ordering::SeqCst) == 1);
    assert!(matches!(
        kernel.ensure_post_effect_evidence_latch_clear(),
        Err(KernelError::PostEffectEvidencePending { buffered: 1 })
    ));
    assert!(kernel
        .acquire_post_effect_evidence_slot(NonZeroUsize::new(1).unwrap())
        .is_err());
    state.barrier_open.store(true, Ordering::SeqCst);
    wait_until(|| kernel.ensure_post_effect_evidence_latch_clear().is_ok());
    assert_eq!(state.append_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.receipts.lock().unwrap().len(), 1);
    assert_eq!(kernel.receipt_log().get(0).unwrap().id, id);
}

#[test]
fn retained_evidence_outlives_kernel_teardown_and_releases_host_capacity() {
    let host = Arc::new(PostEffectEvidenceBudget::new(NonZeroUsize::new(1).unwrap()).unwrap());
    let (mut kernel, receipt, state) = fixture();
    kernel
        .set_post_effect_evidence_budget(Arc::clone(&host))
        .unwrap();
    let mut other = make_kernel(make_config());
    other.set_post_effect_evidence_budget(host).unwrap();
    retain(&kernel, receipt);
    wait_until(|| state.append_calls.load(Ordering::SeqCst) == 1);
    assert!(other
        .acquire_post_effect_evidence_slot(NonZeroUsize::new(1).unwrap())
        .is_err());
    drop(kernel);
    assert!(other
        .acquire_post_effect_evidence_slot(NonZeroUsize::new(1).unwrap())
        .is_err());
    state.barrier_open.store(true, Ordering::SeqCst);
    wait_until(|| {
        other
            .acquire_post_effect_evidence_slot(NonZeroUsize::new(1).unwrap())
            .is_ok()
    });
    assert_eq!(state.append_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn receipt_store_replacement_cannot_abandon_retained_evidence() {
    let (mut kernel, receipt, state) = fixture();
    retain(&kernel, receipt);
    let replacement = Arc::new(StoreState::default());
    assert!(kernel
        .set_receipt_store(Box::new(RecoverableStore(Arc::clone(&replacement))))
        .is_err());
    state.barrier_open.store(true, Ordering::SeqCst);
    wait_until(|| kernel.ensure_post_effect_evidence_latch_clear().is_ok());
    assert_eq!(replacement.append_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn an_outstanding_slot_can_handoff_after_kernel_teardown() {
    let (kernel, receipt, state) = fixture();
    let slot = kernel
        .acquire_post_effect_evidence_slot(NonZeroUsize::new(1).unwrap())
        .unwrap();
    drop(kernel);
    // The slot is an outstanding producer even while the recovery queue is empty.
    state.barrier_open.store(true, Ordering::SeqCst);
    slot.buffer(PendingPostEffectRecord {
        evidence: PendingPostEffectEvidence::Signed { receipt },
        child_receipts: Vec::new(),
        unknown_child: None,
    });
    wait_until(|| state.append_calls.load(Ordering::SeqCst) == 1);
    assert_eq!(state.receipts.lock().unwrap().len(), 1);
}

struct RecordingTrace(Arc<Mutex<Vec<u64>>>);

impl RuntimeTraceObserver for RecordingTrace {
    fn observe(&self, event: RuntimeTraceEvent) {
        if let RuntimeTraceEvent::ReceiptAppended {
            source_sequence, ..
        } = event
        {
            self.0.lock().unwrap().push(source_sequence);
        }
    }
}

#[test]
fn changing_observers_preserves_the_retained_evidence_sequence_epoch() {
    let (mut kernel, receipt, state) = fixture();
    let old = Arc::new(Mutex::new(Vec::new()));
    let new = Arc::new(Mutex::new(Vec::new()));
    kernel.set_runtime_trace_observer(Arc::new(RecordingTrace(Arc::clone(&old))));
    kernel.runtime_trace_sequence.store(7, Ordering::SeqCst);
    retain(&kernel, receipt);
    wait_until(|| state.append_calls.load(Ordering::SeqCst) == 1);
    kernel.set_runtime_trace_observer(Arc::new(RecordingTrace(Arc::clone(&new))));
    state.barrier_open.store(true, Ordering::SeqCst);
    wait_until(|| kernel.ensure_post_effect_evidence_latch_clear().is_ok());
    assert_eq!(*old.lock().unwrap(), vec![8]);
    assert!(new.lock().unwrap().is_empty());
    assert_eq!(kernel.runtime_trace_sequence.load(Ordering::SeqCst), 0);
}

#[test]
fn append_callback_panic_retains_identity_without_poisoning_kernel_locks() {
    let (kernel, receipt, state) = fixture();
    state.panic_after_append.store(true, Ordering::SeqCst);
    state.barrier_open.store(true, Ordering::SeqCst);
    retain(&kernel, receipt);
    wait_until(|| kernel.ensure_post_effect_evidence_latch_clear().is_ok());
    assert_eq!(state.append_calls.load(Ordering::SeqCst), 1);
    assert_eq!(kernel.receipt_log().len(), 1);
    assert!(kernel.receipt_store_write_lock.lock().is_ok());
    assert!(kernel.runtime_trace_transition_lock.lock().is_ok());
}
