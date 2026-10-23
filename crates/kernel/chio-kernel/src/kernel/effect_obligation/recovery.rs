//! Retained evidence has one owner until persistence is authoritative.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use chio_core::crypto::{sha256_hex, SigningBackend};
use chio_core::receipt::signing::ReceiptSigningHandle;
use chio_core::PublicKey;
use chio_security_types::clock::Clock;
use tokio::sync::OwnedSemaphorePermit;

use super::evidence::{EvidencePool, EvidenceSlot};
use crate::kernel::{ChildReceiptLog, ReceiptLog, RuntimeTraceEvent, RuntimeTraceObserver};
use crate::receipt_store::{PendingSettlementObservation, ReceiptStore};
use crate::{
    ChildRequestReceipt, ChildRequestReceiptBody, ChioReceipt, ChioReceiptBody, KernelError,
};

const RETRY_MIN: Duration = Duration::from_millis(20);
const RETRY_MAX: Duration = Duration::from_secs(5);

pub(in crate::kernel) struct PreparedFaultReceipt {
    pub body: ChioReceiptBody,
    pub canonical_content: Vec<u8>,
}

pub(in crate::kernel) enum PendingPostEffectEvidence {
    ChildrenOnly,
    Unsigned {
        fault: PreparedFaultReceipt,
    },
    Signed {
        receipt: ChioReceipt,
    },
    Unknown {
        receipt_id: String,
        receipt_sha256: String,
        kernel_key: PublicKey,
        fault: PreparedFaultReceipt,
    },
}

pub(in crate::kernel) struct UnknownChildAppend {
    pub receipt_id: String,
    pub receipt_sha256: String,
    pub kernel_key: PublicKey,
}

pub(in crate::kernel) enum PendingChildReceipt {
    Unsigned(ChildRequestReceiptBody),
    Signed(ChildRequestReceipt),
}

pub(in crate::kernel) struct PendingPostEffectRecord {
    pub evidence: PendingPostEffectEvidence,
    pub child_receipts: Vec<PendingChildReceipt>,
    pub unknown_child: Option<UnknownChildAppend>,
}

struct ReceiptIdentity {
    id: String,
    sha256: String,
    key: PublicKey,
}

struct BufferedRecord {
    evidence: PendingPostEffectEvidence,
    children: VecDeque<PendingChildReceipt>,
    unknown_child: Option<UnknownChildAppend>,
    submitted: Option<ReceiptIdentity>,
    _kernel: OwnedSemaphorePermit,
    _host: OwnedSemaphorePermit,
    _kernel_bytes: OwnedSemaphorePermit,
    _host_bytes: OwnedSemaphorePermit,
}

pub(super) struct EvidenceQueue {
    records: Mutex<VecDeque<BufferedRecord>>,
    wake: Condvar,
    settled: Condvar,
    pending: AtomicUsize,
    failed_attempts: AtomicU64,
    producers: AtomicUsize,
    stopping: AtomicBool,
    worker_exited: AtomicBool,
}

pub(super) struct EvidenceProducer {
    pub(super) queue: Arc<EvidenceQueue>,
}

impl Drop for EvidenceProducer {
    fn drop(&mut self) {
        let _records = self
            .queue
            .records
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.queue.producers.fetch_sub(1, Ordering::AcqRel);
        self.queue.wake.notify_all();
    }
}

impl EvidenceQueue {
    fn request_stop(&self) {
        // Serialize the predicate change with the worker's atomic wait entry.
        let _records = self
            .records
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.stopping.store(true, Ordering::Release);
        self.wake.notify_all();
    }

    pub(super) fn register_producer(self: Arc<Self>) -> EvidenceProducer {
        self.producers.fetch_add(1, Ordering::AcqRel);
        EvidenceProducer { queue: self }
    }

    #[cfg(test)]
    pub(super) fn empty_for_test() -> Arc<Self> {
        Arc::new(Self {
            records: Mutex::new(VecDeque::new()),
            wake: Condvar::new(),
            settled: Condvar::new(),
            pending: AtomicUsize::new(0),
            failed_attempts: AtomicU64::new(0),
            producers: AtomicUsize::new(0),
            stopping: AtomicBool::new(false),
            worker_exited: AtomicBool::new(false),
        })
    }

    pub(super) fn buffer(
        &self,
        pending: PendingPostEffectRecord,
        kernel: OwnedSemaphorePermit,
        host: OwnedSemaphorePermit,
        kernel_bytes: OwnedSemaphorePermit,
        host_bytes: OwnedSemaphorePermit,
    ) {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Every producer acquired a slot before dispatch. Its record fits in
        // the capacity reserved when this worker was created.
        self.pending.fetch_add(1, Ordering::Release);
        records.push_back(BufferedRecord {
            evidence: pending.evidence,
            children: pending.child_receipts.into(),
            unknown_child: pending.unknown_child,
            submitted: None,
            _kernel: kernel,
            _host: host,
            _kernel_bytes: kernel_bytes,
            _host_bytes: host_bytes,
        });
        self.wake.notify_one();
    }

    fn pending(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }

    /// Wake every drain waiter after a flush attempt settles or the worker
    /// exits. The records lock orders the notification after the state change.
    fn notify_settled(&self) {
        let _records = self
            .records
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.settled.notify_all();
    }

    /// Block until every retained record is persisted. A failed flush attempt
    /// or a stopped worker returns at once; recovery keeps retrying.
    pub(super) fn await_drained(&self) -> Result<(), KernelError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| KernelError::Internal("post-effect evidence queue poisoned".into()))?;
        let failures = self.failed_attempts.load(Ordering::Acquire);
        loop {
            let buffered = self.pending();
            if buffered == 0 {
                return Ok(());
            }
            if self.failed_attempts.load(Ordering::Acquire) != failures {
                return Err(KernelError::PostEffectEvidencePending { buffered });
            }
            if self.worker_exited.load(Ordering::Acquire) {
                return Err(KernelError::Internal(
                    "post-effect evidence worker stopped".into(),
                ));
            }
            records = self
                .settled
                .wait(records)
                .map_err(|_| KernelError::Internal("post-effect evidence queue poisoned".into()))?;
        }
    }
}

/// Marks worker exit, including an unwind, for drain waiters.
struct WorkerExit(Arc<EvidenceQueue>);

impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.worker_exited.store(true, Ordering::Release);
        self.0.notify_settled();
    }
}

pub(super) struct EvidenceRecoveryResources {
    pub clock: Arc<dyn Clock>,
    pub signer: Arc<dyn SigningBackend>,
    pub child_keypair: Arc<chio_core::Keypair>,
    pub signing_identity: crate::tool_outcome::FrozenReceiptSigningIdentityV1,
    pub store: Option<Arc<dyn ReceiptStore>>,
    pub log: Arc<Mutex<ReceiptLog>>,
    pub child_log: Arc<Mutex<ChildReceiptLog>>,
    pub publication_sync: Arc<crate::kernel::publication_sync::PublicationSync>,
    pub trace_sequence: Arc<AtomicU64>,
    pub trace_observer: Option<Arc<dyn RuntimeTraceObserver>>,
    pub append_budget: Duration,
    pub settlement_observation: bool,
}

pub(in crate::kernel) struct EvidenceRecovery {
    pool: EvidencePool,
    queue: Arc<EvidenceQueue>,
    worker: Option<JoinHandle<()>>,
    resources: Arc<EvidenceRecoveryResources>,
}

impl EvidenceRecovery {
    pub(super) fn new(
        pool: EvidencePool,
        capacity: usize,
        resources: EvidenceRecoveryResources,
    ) -> Result<Self, KernelError> {
        let mut records = VecDeque::new();
        records.try_reserve_exact(capacity).map_err(|_| {
            KernelError::Internal("cannot reserve post-effect evidence buffer".into())
        })?;
        let queue = Arc::new(EvidenceQueue {
            records: Mutex::new(records),
            wake: Condvar::new(),
            settled: Condvar::new(),
            pending: AtomicUsize::new(0),
            failed_attempts: AtomicU64::new(0),
            producers: AtomicUsize::new(0),
            stopping: AtomicBool::new(false),
            worker_exited: AtomicBool::new(false),
        });
        let worker_queue = Arc::clone(&queue);
        let resources = Arc::new(resources);
        let worker_resources = Arc::clone(&resources);
        let worker = std::thread::Builder::new()
            .name("chio-effect-evidence".into())
            .spawn(move || recover(worker_queue, worker_resources))
            .map_err(|error| {
                KernelError::Internal(format!("evidence worker unavailable: {error}"))
            })?;
        Ok(Self {
            pool,
            queue,
            worker: Some(worker),
            resources,
        })
    }

    pub(super) fn matches_resources(&self, next: &EvidenceRecoveryResources) -> bool {
        fn same<T: ?Sized>(left: &Option<Arc<T>>, right: &Option<Arc<T>>) -> bool {
            match (left, right) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
        }
        Arc::ptr_eq(&self.resources.signer, &next.signer)
            && self.resources.child_keypair.public_key() == next.child_keypair.public_key()
            && self.resources.signing_identity == next.signing_identity
            && Arc::ptr_eq(&self.resources.trace_sequence, &next.trace_sequence)
            && same(&self.resources.store, &next.store)
            && same(&self.resources.trace_observer, &next.trace_observer)
            && self.resources.append_budget == next.append_budget
            && self.resources.settlement_observation == next.settlement_observation
    }

    pub(super) fn queue(&self) -> Arc<EvidenceQueue> {
        Arc::clone(&self.queue)
    }

    pub(super) fn is_idle(&self) -> bool {
        self.queue.pending() == 0 && self.pool.is_idle()
    }

    pub(in crate::kernel) fn acquire(
        &self,
        bytes: std::num::NonZeroUsize,
    ) -> Result<EvidenceSlot, KernelError> {
        let records = self
            .queue
            .records
            .lock()
            .map_err(|_| KernelError::Internal("post-effect evidence queue poisoned".into()))?;
        self.ensure_clear()?;
        let slot = self.pool.acquire(Arc::clone(&self.queue), bytes);
        drop(records);
        slot
    }

    pub(in crate::kernel) fn acquire_for_dispatched_child(
        &self,
        bytes: std::num::NonZeroUsize,
    ) -> Result<EvidenceSlot, KernelError> {
        let records = self
            .queue
            .records
            .lock()
            .map_err(|_| KernelError::Internal("post-effect evidence queue poisoned".into()))?;
        self.ensure_worker_running()?;
        let slot = self.pool.acquire(Arc::clone(&self.queue), bytes);
        drop(records);
        slot
    }

    pub(in crate::kernel) fn ensure_clear(&self) -> Result<(), KernelError> {
        if self.queue.pending() != 0 {
            return Err(KernelError::PostEffectEvidencePending {
                buffered: self.queue.pending(),
            });
        }
        self.ensure_worker_running()
    }

    // A panic outside the per-record retry boundary ends automatic recovery.
    // Dispatch stays closed and retained records remain unresolved in memory;
    // process exit loses that memory evidence.
    fn ensure_worker_running(&self) -> Result<(), KernelError> {
        if self.worker.as_ref().is_none_or(JoinHandle::is_finished) {
            return Err(KernelError::Internal(
                "post-effect evidence worker stopped".into(),
            ));
        }
        Ok(())
    }
}

impl Drop for EvidenceRecovery {
    fn drop(&mut self) {
        self.queue.request_stop();
        // Pending evidence outlives kernel teardown. The worker owns its
        // resources and exits only after the retained queue drains. A failed
        // store therefore keeps its bounded host permits charged.
        if let Some(worker) = self.worker.take().filter(JoinHandle::is_finished) {
            let _ = worker.join();
        }
    }
}

fn recover(queue: Arc<EvidenceQueue>, resources: Arc<EvidenceRecoveryResources>) {
    let _exit = WorkerExit(Arc::clone(&queue));
    let mut retry = RETRY_MIN;
    loop {
        let mut records = queue
            .records
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        while records.is_empty()
            && (!queue.stopping.load(Ordering::Acquire)
                || queue.producers.load(Ordering::Acquire) != 0)
        {
            records = queue
                .wake
                .wait(records)
                .unwrap_or_else(|error| error.into_inner());
        }
        if queue.stopping.load(Ordering::Acquire)
            && records.is_empty()
            && queue.producers.load(Ordering::Acquire) == 0
        {
            return;
        }
        let Some(mut record) = records.pop_front() else {
            continue;
        };
        drop(records);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            resources.flush(&mut record)
        }));
        if matches!(result, Ok(Ok(()))) {
            queue.pending.fetch_sub(1, Ordering::AcqRel);
            drop(record);
            queue.notify_settled();
            retry = RETRY_MIN;
            continue;
        }
        let mut records = queue
            .records
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        records.push_back(record);
        queue.failed_attempts.fetch_add(1, Ordering::AcqRel);
        queue.settled.notify_all();
        let _waiting = queue
            .wake
            .wait_timeout_while(records, retry, |_| true)
            .unwrap_or_else(|error| error.into_inner());
        retry = retry.saturating_mul(2).min(RETRY_MAX);
    }
}

impl EvidenceRecoveryResources {
    fn flush(&self, record: &mut BufferedRecord) -> Result<(), KernelError> {
        let trace = self.publication_sync.fence(self.store.is_none(), false)?;
        let writes = self.publication_sync.receipts(true)?;
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.flush_locked(record)))
                .map_err(|_| {
                    KernelError::Internal("post-effect evidence callback panicked".into())
                })?;
        drop(writes);
        drop(trace);
        if let Some((receipt, sequence)) = result? {
            self.observe(receipt, sequence);
        }
        Ok(())
    }

    fn flush_locked(
        &self,
        record: &mut BufferedRecord,
    ) -> Result<Option<(ChioReceipt, Option<u64>)>, KernelError> {
        self.flush_children(record)?;
        if matches!(record.evidence, PendingPostEffectEvidence::ChildrenOnly) {
            return Ok(None);
        }
        if let Some(identity) = record.submitted.as_ref() {
            if let Some(receipt) = self.resolve_submitted(identity)? {
                let sequence = self.project(&receipt)?;
                return Ok(Some((receipt, sequence)));
            }
            record.submitted = None;
        }
        if let PendingPostEffectEvidence::Unknown {
            receipt_id,
            receipt_sha256,
            kernel_key,
            ..
        } = &record.evidence
        {
            if let Some(receipt) = self.resolve_submitted(&ReceiptIdentity {
                id: receipt_id.clone(),
                sha256: receipt_sha256.clone(),
                key: kernel_key.clone(),
            })? {
                let sequence = self.project(&receipt)?;
                return Ok(Some((receipt, sequence)));
            }
        }
        let receipt = match &record.evidence {
            PendingPostEffectEvidence::ChildrenOnly => return Ok(None),
            PendingPostEffectEvidence::Signed { receipt } => receipt.clone(),
            PendingPostEffectEvidence::Unsigned { fault }
            | PendingPostEffectEvidence::Unknown { fault, .. } => {
                self.signing_identity
                    .validate()
                    .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
                if &fault.body.kernel_key != self.signing_identity.public_key() {
                    return Err(KernelError::ReceiptSigningFailed(
                        "fault receipt does not name the retained signing identity".into(),
                    ));
                }
                let mut body = fault.body.clone();
                body.timestamp = self.clock.read()?.unix_millis().as_secs();
                chio_kernel_core::sign_receipt_with_handle(
                    body,
                    self.signer.as_ref(),
                    ReceiptSigningHandle::from_content_preimage(fault.canonical_content.clone()),
                )
                .map_err(|error| KernelError::ReceiptSigningFailed(format!("{error:?}")))?
            }
        };
        if receipt.kernel_key != *self.signing_identity.public_key()
            || !receipt
                .verify_signature_with_floor(self.signing_identity.crypto_floor())
                .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?
        {
            return Err(KernelError::ReceiptSigningFailed(
                "retained fault receipt violates its admitted signing policy".into(),
            ));
        }
        let canonical = chio_core::canonical::canonical_json_bytes(&receipt)
            .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
        let observation = if self.store.is_some() && self.settlement_observation {
            Some(PendingSettlementObservation {
                next_visible_at_ms: self.clock.read()?.unix_millis().get(),
            })
        } else {
            None
        };
        let identity = ReceiptIdentity {
            id: receipt.id.clone(),
            sha256: sha256_hex(&canonical),
            key: receipt.kernel_key.clone(),
        };
        // Keep the exact signed fault across an ambiguous append. A retry may
        // reuse it only after a completed barrier proves it absent.
        record.evidence = PendingPostEffectEvidence::Signed {
            receipt: receipt.clone(),
        };
        if let Some(store) = self.store.as_ref() {
            record.submitted = Some(identity);
            if let Some(observation) = observation {
                store.append_chio_receipt_with_pending_observation_and_timeout(
                    &receipt,
                    &observation,
                    self.append_budget,
                )?;
            } else {
                store.append_chio_receipt_with_timeout(&receipt, self.append_budget)?;
            }
        }
        let sequence = self.project(&receipt)?;
        Ok(Some((receipt, sequence)))
    }

    fn resolve_submitted(
        &self,
        expected: &ReceiptIdentity,
    ) -> Result<Option<ChioReceipt>, KernelError> {
        let store = self.store.as_ref().ok_or_else(|| {
            KernelError::Internal("unknown append has no authoritative receipt store".into())
        })?;
        store.flush_receipt_writes_with_timeout(self.append_budget)?;
        let receipt = store.load_retained_chio_receipt(&expected.id)?;
        let commitment = store.load_retained_chio_receipt_commitment(&expected.id)?;
        match (receipt, commitment) {
            (None, None) => Ok(None),
            (Some(receipt), Some(commitment)) => {
                let canonical = chio_core::canonical::canonical_json_bytes(&receipt)
                    .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
                if receipt.id != expected.id
                    || receipt.kernel_key != expected.key
                    || sha256_hex(&canonical) != expected.sha256
                    || commitment.receipt_id != expected.id
                    || commitment.receipt_sha256 != expected.sha256
                    || commitment.kernel_key != expected.key
                {
                    return Err(KernelError::Internal(
                        "retained receipt conflicts with submitted evidence".into(),
                    ));
                }
                Ok(Some(receipt))
            }
            _ => Err(KernelError::Internal(
                "retained receipt and commitment disagree".into(),
            )),
        }
    }

    fn flush_children(&self, record: &mut BufferedRecord) -> Result<(), KernelError> {
        while let Some(pending) = record.children.front_mut() {
            if let PendingChildReceipt::Unsigned(body) = pending {
                if record.unknown_child.is_some() {
                    return Err(KernelError::Internal(
                        "unknown child append lacks its signed evidence".into(),
                    ));
                }
                let mut body = body.clone();
                body.timestamp = self.clock.read()?.unix_millis().as_secs();
                let receipt = ChildRequestReceipt::sign(body, &self.child_keypair)
                    .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
                *pending = PendingChildReceipt::Signed(receipt);
            }
            let PendingChildReceipt::Signed(child) = pending else {
                return Err(KernelError::Internal(
                    "child evidence remains unsigned".into(),
                ));
            };
            if let Some(unknown) = record.unknown_child.as_ref() {
                if unknown.receipt_id != child.id {
                    return Err(KernelError::Internal(
                        "unknown child append does not match retained queue".into(),
                    ));
                }
                let store = self.store.as_ref().ok_or_else(|| {
                    KernelError::Internal("unknown child append has no receipt store".into())
                })?;
                store.flush_receipt_writes_with_timeout(self.append_budget)?;
                if let Some(existing) = store.load_retained_child_receipt(&child.id)? {
                    let canonical = chio_core::canonical::canonical_json_bytes(&existing)
                        .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
                    if existing.id != unknown.receipt_id
                        || existing.kernel_key != unknown.kernel_key
                        || sha256_hex(&canonical) != unknown.receipt_sha256
                    {
                        return Err(KernelError::Internal(
                            "retained child receipt conflicts with submitted evidence".into(),
                        ));
                    }
                    self.project_child(&existing)?;
                    record.unknown_child = None;
                    record.children.pop_front();
                    continue;
                }
                // This lookup covers complete retained history and follows a
                // completed write barrier. Unsupported stores never reach here.
                record.unknown_child = None;
            }
            if let Some(store) = self.store.as_ref() {
                let canonical = chio_core::canonical::canonical_json_bytes(child)
                    .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
                record.unknown_child = Some(UnknownChildAppend {
                    receipt_id: child.id.clone(),
                    receipt_sha256: sha256_hex(&canonical),
                    kernel_key: child.kernel_key.clone(),
                });
                store.append_child_receipt_with_timeout(child, self.append_budget)?;
            }
            // Keep submission identity through projection. A projection error
            // must not turn a committed child into a fresh append attempt.
            self.project_child(child)?;
            record.unknown_child = None;
            record.children.pop_front();
        }
        if record.unknown_child.is_some() {
            return Err(KernelError::Internal(
                "unknown child append is missing retained evidence".into(),
            ));
        }
        Ok(())
    }

    fn project_child(&self, receipt: &ChildRequestReceipt) -> Result<(), KernelError> {
        let mut log = self
            .child_log
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(existing) = log.iter().find(|existing| existing.id == receipt.id) {
            let expected = chio_core::canonical::canonical_json_bytes(receipt)
                .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
            let actual = chio_core::canonical::canonical_json_bytes(existing)
                .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
            if actual != expected {
                return Err(KernelError::Internal(
                    "local child receipt conflicts with durable evidence".into(),
                ));
            }
            return Ok(());
        }
        log.append(receipt.clone());
        Ok(())
    }

    fn project(&self, receipt: &ChioReceipt) -> Result<Option<u64>, KernelError> {
        let _projection = self.publication_sync.projection()?;
        let mut log = self.log.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(existing) = log.iter().find(|existing| existing.id == receipt.id) {
            let expected = chio_core::canonical::canonical_json_bytes(receipt)
                .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
            let actual = chio_core::canonical::canonical_json_bytes(existing)
                .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
            if actual != expected {
                return Err(KernelError::Internal(
                    "local receipt conflicts with durable evidence".into(),
                ));
            }
            return Ok(None);
        }
        log.append(receipt.clone());
        if self.trace_observer.is_none() {
            return Ok(None);
        }
        // Trace exhaustion cannot erase a committed terminal receipt.
        Ok(self
            .trace_sequence
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .ok()
            .map(|n| n + 1))
    }

    fn observe(&self, receipt: ChioReceipt, sequence: Option<u64>) {
        if let (Some(observer), Some(source_sequence)) = (&self.trace_observer, sequence) {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                observer.observe(RuntimeTraceEvent::ReceiptAppended {
                    source_sequence,
                    receipt: Box::new(receipt),
                });
            }));
            if result.is_err() {
                tracing::warn!(
                    source_sequence,
                    audit_fault = "post_effect_receipt_trace_observer_panicked",
                    "receipt committed but trace observer failed"
                );
            }
        }
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn shutdown_cannot_notify_before_the_worker_releases_its_wait_guard() {
        let queue = EvidenceQueue::empty_for_test();
        let records = queue.records.lock().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (stopped_tx, stopped_rx) = mpsc::channel();
        let stopping_queue = Arc::clone(&queue);
        let stopper = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            stopping_queue.request_stop();
            stopped_tx.send(()).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let early_stop = stopped_rx.recv_timeout(Duration::from_millis(100)).is_ok();
        drop(records);
        if !early_stop {
            stopped_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        stopper.join().unwrap();
        assert!(
            !early_stop,
            "shutdown notified before the worker could atomically enter its wait"
        );
        assert!(queue.stopping.load(Ordering::Acquire));
    }
}
