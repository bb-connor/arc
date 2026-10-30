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
    children: Mutex<Vec<ChildRequestReceipt>>,
    child_append_calls: AtomicU64,
    append_calls: AtomicU64,
    barrier_open: AtomicBool,
    panic_after_append: AtomicBool,
}

struct RecoverableStore(Arc<StoreState>);

impl ReceiptStore for RecoverableStore {
    fn opening_status(
        &self,
        _receipt_id: &str,
    ) -> Result<crate::receipt_store::OpeningStatus, crate::receipt_store::ReceiptStoreError> {
        Ok(crate::receipt_store::OpeningStatus::Unknown)
    }
    fn read_openings(
        &self,
        _receipt_id: &str,
        _scope: &crate::receipt_store::OpeningReadScope,
    ) -> Result<crate::receipt_store::OpeningState, crate::receipt_store::ReceiptStoreError> {
        Ok(crate::receipt_store::OpeningState::Unknown)
    }
    fn erase_openings(
        &self,
        _receipt_id: &str,
        _erased_at: u64,
    ) -> Result<(), crate::receipt_store::ReceiptStoreError> {
        Err(crate::receipt_store::ReceiptStoreError::Unsupported(
            "test double holds no receipt openings".to_string(),
        ))
    }
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

    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        self.0.child_append_calls.fetch_add(1, Ordering::SeqCst);
        self.0.children.lock().unwrap().push(receipt.clone());
        Err(ReceiptStoreError::Timeout {
            operation: "lost child acknowledgement".into(),
            timeout_ms: 1,
        })
    }

    fn load_retained_child_receipt(
        &self,
        id: &str,
    ) -> Result<Option<ChildRequestReceipt>, ReceiptStoreError> {
        Ok(self
            .0
            .children
            .lock()
            .unwrap()
            .iter()
            .find(|child| child.id == id)
            .cloned())
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
                        &chio_core::canonical::canonical_json_bytes(&receipt)
                            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?,
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
            &Denial::new(crate::ClientDenialCode::Denied, "post-effect fixture"),
            current_unix_timestamp(),
            None,
            RefusalReceiptMetadata::new(None, IdentityDisposition::Terminal),
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

pub(super) fn wait_for_post_effect_evidence(kernel: &ChioKernel) {
    wait_until(|| kernel.ensure_post_effect_evidence_latch_clear().is_ok());
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
    assert!(matches!(
        kernel.acquire_post_effect_evidence_slot(NonZeroUsize::new(1).unwrap()),
        Err(KernelError::PostEffectEvidencePending { buffered: 1 })
    ));
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
    assert!(matches!(
        other.acquire_post_effect_evidence_slot(NonZeroUsize::new(1).unwrap()),
        Err(KernelError::PostEffectEvidenceCapacity)
    ));
    drop(kernel);
    assert!(matches!(
        other.acquire_post_effect_evidence_slot(NonZeroUsize::new(1).unwrap()),
        Err(KernelError::PostEffectEvidenceCapacity)
    ));
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
    assert!(matches!(
        kernel.set_receipt_store(Box::new(RecoverableStore(Arc::clone(&replacement)))),
        Err(KernelError::Internal(reason))
            if reason == "cannot replace resources while post-effect evidence is retained"
    ));
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
    assert!(kernel.publication_sync.receipts.write().is_ok());
    assert!(kernel.publication_sync.fence.write().is_ok());
}

#[test]
fn unknown_child_acknowledgement_recovers_its_mirror_without_a_parent_terminal() {
    let (kernel, _, state) = fixture();
    let child = ChildRequestReceipt::sign(
        crate::ChildRequestReceiptBody {
            id: "retained-child".into(),
            timestamp: current_unix_timestamp(),
            session_id: SessionId::new("retained-session"),
            parent_request_id: RequestId::new("retained-parent"),
            request_id: RequestId::new("retained-child-request"),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: chio_core::crypto::sha256_hex(b"child outcome"),
            policy_hash: kernel.policy_hash().to_string(),
            metadata: None,
            kernel_key: kernel.config.keypair.public_key(),
        },
        &kernel.config.keypair,
    )
    .unwrap();
    let bytes = chio_core::canonical::canonical_json_bytes(&child)
        .unwrap()
        .len();
    let slot = kernel
        .acquire_post_effect_evidence_slot(NonZeroUsize::new(bytes).unwrap())
        .unwrap();
    slot.buffer(PendingPostEffectRecord {
        evidence: PendingPostEffectEvidence::ChildrenOnly,
        child_receipts: vec![
            crate::kernel::effect_obligation::recovery::PendingChildReceipt::Signed(child.clone()),
        ],
        unknown_child: None,
    });
    wait_until(|| state.child_append_calls.load(Ordering::SeqCst) == 1);
    assert!(kernel.child_receipt_log().is_empty());
    state.barrier_open.store(true, Ordering::SeqCst);
    wait_until(|| kernel.ensure_post_effect_evidence_latch_clear().is_ok());
    assert_eq!(state.child_append_calls.load(Ordering::SeqCst), 1);
    assert_eq!(kernel.child_receipt_log().get(0).unwrap().id, child.id);
    assert_eq!(kernel.child_receipt_log().len(), 1);
    assert!(kernel.receipt_log().is_empty());
}

fn retain_unsigned(kernel: &ChioKernel, receipt: ChioReceipt) {
    use crate::kernel::effect_obligation::recovery::PreparedFaultReceipt;
    let content = b"null".to_vec();
    assert_eq!(
        receipt.content_hash,
        chio_core::crypto::sha256_hex(&content)
    );
    let body = receipt.body();
    let bytes = chio_core::canonical::canonical_json_bytes(&body)
        .unwrap()
        .len()
        + content.len();
    let slot = kernel
        .acquire_post_effect_evidence_slot(NonZeroUsize::new(bytes).unwrap())
        .unwrap();
    slot.buffer(PendingPostEffectRecord {
        evidence: PendingPostEffectEvidence::Unsigned {
            fault: PreparedFaultReceipt {
                body,
                canonical_content: content,
            },
        },
        child_receipts: Vec::new(),
        unknown_child: None,
    });
}

struct RecoveringClock {
    reading: chio_security_types::clock::ClockReading,
    ready: AtomicBool,
    reads: AtomicU64,
}

impl chio_security_types::clock::Clock for RecoveringClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.ready.load(Ordering::SeqCst) {
            Ok(self.reading)
        } else {
            Err(chio_security_types::clock::ClockError::Unavailable)
        }
    }
}

#[test]
fn unavailable_clock_retains_unsigned_fault_until_idle_recovery() {
    let (mut kernel, receipt, state) = fixture();
    let clock = Arc::new(RecoveringClock {
        reading: kernel.authority_clock_reading().unwrap(),
        ready: AtomicBool::new(false),
        reads: AtomicU64::new(0),
    });
    kernel.clock = clock.clone();
    state.barrier_open.store(true, Ordering::SeqCst);
    retain_unsigned(&kernel, receipt);
    wait_until(|| clock.reads.load(Ordering::SeqCst) > 0);
    assert_eq!(state.append_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        kernel.ensure_post_effect_evidence_latch_clear(),
        Err(KernelError::PostEffectEvidencePending { buffered: 1 })
    ));
    clock.ready.store(true, Ordering::SeqCst);
    wait_until(|| kernel.ensure_post_effect_evidence_latch_clear().is_ok());
    assert_eq!(state.append_calls.load(Ordering::SeqCst), 1);
    assert!(kernel
        .receipt_log()
        .get(0)
        .unwrap()
        .verify_signature()
        .unwrap());
}

struct RecoveringSigner {
    backend: Arc<dyn chio_core::crypto::SigningBackend>,
    ready: AtomicBool,
    calls: AtomicU64,
}

impl chio_core::crypto::SigningBackend for RecoveringSigner {
    fn public_key(&self) -> chio_core::error::Result<PublicKey> {
        self.backend.public_key()
    }
    fn sign_bytes(&self, bytes: &[u8]) -> Result<chio_core::Signature, chio_core::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.ready.load(Ordering::SeqCst) {
            self.backend.sign_bytes(bytes)
        } else {
            Err(chio_core::Error::InvalidSignature(
                "signing temporarily unavailable".into(),
            ))
        }
    }
}

#[test]
fn unavailable_signer_retains_unsigned_fault_until_idle_recovery() {
    let (mut kernel, receipt, state) = fixture();
    let signer = Arc::new(RecoveringSigner {
        backend: Arc::clone(&kernel.signing_authority.backend),
        ready: AtomicBool::new(false),
        calls: AtomicU64::new(0),
    });
    kernel.signing_authority.backend = signer.clone();
    state.barrier_open.store(true, Ordering::SeqCst);
    retain_unsigned(&kernel, receipt);
    wait_until(|| signer.calls.load(Ordering::SeqCst) > 0);
    assert_eq!(state.append_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        kernel.ensure_post_effect_evidence_latch_clear(),
        Err(KernelError::PostEffectEvidencePending { buffered: 1 })
    ));
    signer.ready.store(true, Ordering::SeqCst);
    wait_until(|| kernel.ensure_post_effect_evidence_latch_clear().is_ok());
    assert_eq!(state.append_calls.load(Ordering::SeqCst), 1);
    assert!(kernel
        .receipt_log()
        .get(0)
        .unwrap()
        .verify_signature()
        .unwrap());
}

#[test]
fn unsigned_child_survives_clock_outage_and_kernel_teardown() {
    use crate::kernel::effect_obligation::recovery::PendingChildReceipt;
    let (mut kernel, _, state) = fixture();
    let clock = Arc::new(RecoveringClock {
        reading: kernel.authority_clock_reading().unwrap(),
        ready: AtomicBool::new(false),
        reads: AtomicU64::new(0),
    });
    kernel.clock = clock.clone();
    let body = crate::ChildRequestReceiptBody {
        id: "unsigned-retained-child".into(),
        timestamp: 0,
        session_id: SessionId::new("retained-session"),
        parent_request_id: RequestId::new("retained-parent"),
        request_id: RequestId::new("retained-child-request"),
        operation_kind: OperationKind::CreateMessage,
        terminal_state: OperationTerminalState::Completed,
        outcome_hash: chio_core::crypto::sha256_hex(b"completed child outcome"),
        policy_hash: kernel.policy_hash().to_string(),
        metadata: None,
        kernel_key: kernel.config.keypair.public_key(),
    };
    let encoded = chio_core::canonical::canonical_json_bytes(&body)
        .unwrap()
        .len();
    let slot = kernel
        .acquire_post_effect_evidence_slot(NonZeroUsize::new(encoded + 256).unwrap())
        .unwrap();
    slot.buffer(PendingPostEffectRecord {
        evidence: PendingPostEffectEvidence::ChildrenOnly,
        child_receipts: vec![PendingChildReceipt::Unsigned(body.clone())],
        unknown_child: None,
    });
    wait_until(|| clock.reads.load(Ordering::SeqCst) > 0);
    assert_eq!(state.child_append_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        kernel.ensure_post_effect_evidence_latch_clear(),
        Err(KernelError::PostEffectEvidencePending { buffered: 1 })
    ));
    let child_log = Arc::clone(&kernel.child_receipt_log);
    drop(kernel);
    state.barrier_open.store(true, Ordering::SeqCst);
    clock.ready.store(true, Ordering::SeqCst);
    wait_until(|| child_log.lock().unwrap().len() == 1);
    let child = child_log.lock().unwrap().get(0).unwrap().clone();
    assert_eq!(child.id, body.id);
    assert_eq!(child.outcome_hash, body.outcome_hash);
    assert_eq!(child.terminal_state, OperationTerminalState::Completed);
    assert!(child.timestamp > 0);
    assert!(child.verify_signature().unwrap());
    assert_eq!(state.child_append_calls.load(Ordering::SeqCst), 1);
    assert!(state.receipts.lock().unwrap().is_empty());
}

struct LockInspectingSigner {
    backend: Arc<dyn chio_core::crypto::SigningBackend>,
    kernel: Mutex<std::sync::Weak<ChioKernel>>,
    lock_held: AtomicBool,
}

impl chio_core::crypto::SigningBackend for LockInspectingSigner {
    fn public_key(&self) -> chio_core::error::Result<PublicKey> {
        if let Some(kernel) = self.kernel.lock().unwrap().upgrade() {
            self.lock_held.store(
                kernel.post_effect_evidence.try_lock().is_err(),
                Ordering::SeqCst,
            );
        }
        self.backend.public_key()
    }
    fn sign_bytes(&self, bytes: &[u8]) -> Result<chio_core::Signature, chio_core::Error> {
        self.backend.sign_bytes(bytes)
    }
}

#[test]
fn evidence_resource_selection_does_not_hold_control_lock_during_signer_callback() {
    let (mut kernel, _, _) = fixture();
    let signer = Arc::new(LockInspectingSigner {
        backend: Arc::clone(&kernel.signing_authority.backend),
        kernel: Mutex::new(std::sync::Weak::new()),
        lock_held: AtomicBool::new(false),
    });
    kernel.signing_authority.backend = signer.clone();
    let kernel = Arc::new(kernel);
    *signer.kernel.lock().unwrap() = Arc::downgrade(&kernel);
    let slot = kernel
        .acquire_post_effect_evidence_slot(NonZeroUsize::new(1).unwrap())
        .unwrap();
    assert!(!signer.lock_held.load(Ordering::SeqCst));
    drop(slot);
}

struct OncePanickingClock {
    panics: AtomicBool,
    reading: chio_security_types::clock::ClockReading,
}
impl chio_security_types::clock::Clock for OncePanickingClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        assert!(
            !self.panics.swap(false, Ordering::SeqCst),
            "transient clock callback panic"
        );
        Ok(self.reading)
    }
}

#[test]
fn clock_callback_panic_does_not_poison_recovery_authority_fence() {
    let (mut kernel, receipt, state) = fixture();
    kernel.clock = Arc::new(OncePanickingClock {
        panics: AtomicBool::new(true),
        reading: kernel.authority_clock_reading().unwrap(),
    });
    state.barrier_open.store(true, Ordering::SeqCst);
    retain_unsigned(&kernel, receipt);
    wait_until(|| kernel.ensure_post_effect_evidence_latch_clear().is_ok());
    assert!(kernel.read_authority_time().is_ok());
    assert_eq!(state.append_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn awaiting_retained_evidence_reports_a_failed_flush_then_returns_after_persistence() {
    let (kernel, receipt, state) = fixture();
    let id = receipt.id.clone();
    retain(&kernel, receipt);
    assert!(matches!(
        kernel.await_post_effect_evidence(),
        Err(KernelError::PostEffectEvidencePending { buffered: 1 })
    ));
    state.barrier_open.store(true, Ordering::SeqCst);
    let mut outcome = kernel.await_post_effect_evidence();
    while matches!(outcome, Err(KernelError::PostEffectEvidencePending { .. })) {
        outcome = kernel.await_post_effect_evidence();
    }
    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(kernel.ensure_post_effect_evidence_latch_clear().is_ok());
    assert_eq!(kernel.receipt_log().get(0).unwrap().id, id);
}
