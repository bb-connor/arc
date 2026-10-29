use super::*;

#[path = "receipt_publication/concurrency.rs"]
mod concurrency;
#[path = "receipt_publication/durable.rs"]
mod durable;
#[path = "receipt_publication/ordering.rs"]
mod ordering;

#[derive(Clone, Copy)]
enum AppendMode {
    Acknowledged,
    CommittedThenTimeout,
    CommittedThenPanic,
    QueuedThenTimeout,
}

#[derive(Default)]
struct Journal {
    committed: Vec<ChioReceipt>,
    queued: Vec<ChioReceipt>,
}

struct PublicationStore {
    mode: AppendMode,
    journal: Arc<Mutex<Journal>>,
}

impl ReceiptStore for PublicationStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        let mut journal = self.journal.lock().unwrap();
        match self.mode {
            AppendMode::Acknowledged => {
                journal.committed.push(receipt.clone());
                return Ok(());
            }
            AppendMode::CommittedThenTimeout => journal.committed.push(receipt.clone()),
            AppendMode::CommittedThenPanic => {
                journal.committed.push(receipt.clone());
                drop(journal);
                panic!("append committed before callback panic");
            }
            AppendMode::QueuedThenTimeout => journal.queued.push(receipt.clone()),
        }
        Err(ReceiptStoreError::Timeout {
            operation: "append_chio_receipt".to_owned(),
            timeout_ms: 1,
        })
    }

    fn append_child_receipt(&self, _: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        unreachable!("this fixture has no children")
    }

    fn load_chio_receipt(&self, id: &str) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok(self
            .journal
            .lock()
            .unwrap()
            .committed
            .iter()
            .find(|r| r.id == id)
            .cloned())
    }

    fn flush_receipt_writes(&self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        let mut journal = self.journal.lock().unwrap();
        let queued = std::mem::take(&mut journal.queued);
        journal.committed.extend(queued);
        Ok(ReceiptFlushReport::default())
    }
}

fn signed_receipt() -> ChioReceipt {
    let kernel = make_kernel(make_config());
    let capability = make_capability(
        &kernel,
        &make_keypair(),
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    let request = make_request("publication-test", &capability, "read_file", "srv-a");
    kernel
        .build_deny_response_with_metadata(
            &request,
            &Denial::new(crate::ClientDenialCode::Denied, "publication fixture"),
            current_unix_timestamp(),
            None,
            RefusalReceiptMetadata::new(None, IdentityDisposition::Reusable),
        )
        .unwrap()
        .receipt
}

fn fixture(mode: AppendMode) -> (ChioKernel, Arc<Mutex<Journal>>) {
    let mut kernel = make_kernel(make_config());
    let journal = Arc::new(Mutex::new(Journal::default()));
    kernel
        .set_receipt_store(Box::new(PublicationStore {
            mode,
            journal: Arc::clone(&journal),
        }))
        .unwrap();
    (kernel, journal)
}

#[test]
fn committed_timeout_reports_original_receipt_as_unresolved() {
    let receipt = signed_receipt();
    let (kernel, journal) = fixture(AppendMode::CommittedThenTimeout);
    let error = kernel.record_chio_receipt(&receipt).unwrap_err();
    assert_eq!(journal.lock().unwrap().committed.len(), 1);
    let report = error.report();
    assert_eq!(report.code, "CHIO-KERNEL-RECEIPT-APPEND-OUTCOME-UNKNOWN");
    assert_eq!(report.context["receipt_id"], receipt.id);
}

#[test]
fn queued_timeout_cannot_be_treated_as_a_refused_append() {
    let receipt = signed_receipt();
    let (kernel, journal) = fixture(AppendMode::QueuedThenTimeout);
    let error = kernel.record_chio_receipt(&receipt).unwrap_err();
    assert!(journal.lock().unwrap().committed.is_empty());
    assert_eq!(journal.lock().unwrap().queued.len(), 1);
    kernel
        .with_receipt_store(|store| Ok(store.flush_receipt_writes()?))
        .unwrap();
    assert_eq!(journal.lock().unwrap().committed.len(), 1);
    assert_eq!(journal.lock().unwrap().committed[0].id, receipt.id);
    let report = error.report();
    assert_eq!(report.code, "CHIO-KERNEL-RECEIPT-APPEND-OUTCOME-UNKNOWN");
    assert_eq!(report.context["receipt_id"], receipt.id);
}

struct TraceObserver;
impl RuntimeTraceObserver for TraceObserver {
    fn observe(&self, _: RuntimeTraceEvent) {}
}

#[test]
fn trace_failure_after_append_reports_committed_receipt() {
    let receipt = signed_receipt();
    let (mut kernel, journal) = fixture(AppendMode::Acknowledged);
    kernel.set_runtime_trace_observer(Arc::new(TraceObserver));
    kernel
        .runtime_trace_sequence
        .store(u64::MAX, Ordering::SeqCst);
    let error = kernel.record_chio_receipt(&receipt).unwrap_err();
    assert_eq!(journal.lock().unwrap().committed.len(), 1);
    assert_eq!(kernel.receipt_log().len(), 1);
    let report = error.report();
    assert_eq!(report.code, "CHIO-KERNEL-DELIVERY-FAILED-AFTER-RECEIPT");
    assert_eq!(report.context["receipt_id"], receipt.id);
    assert_eq!(report.context["step"], "trace");
}

#[test]
fn acknowledged_append_records_one_receipt() {
    let receipt = signed_receipt();
    let (kernel, journal) = fixture(AppendMode::Acknowledged);
    kernel.record_chio_receipt(&receipt).unwrap();
    assert_eq!(journal.lock().unwrap().committed.len(), 1);
    assert_eq!(kernel.receipt_log().len(), 1);
}

#[test]
fn producer_append_panic_preserves_unknown_identity_and_recovery_locks() {
    let receipt = signed_receipt();
    let (kernel, journal) = fixture(AppendMode::CommittedThenPanic);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        kernel.record_chio_receipt(&receipt)
    }));
    assert_eq!(journal.lock().unwrap().committed.len(), 1);
    assert!(
        kernel.publication_sync.receipts.try_write().is_ok(),
        "producer poisoned receipt write lock"
    );
    assert!(
        kernel.publication_sync.fence.try_write().is_ok(),
        "producer poisoned trace transition lock"
    );
    let error = result
        .expect("append panic must become an unknown publication result")
        .unwrap_err();
    assert_eq!(
        error.report().code,
        "CHIO-KERNEL-RECEIPT-APPEND-OUTCOME-UNKNOWN"
    );
    assert_eq!(error.report().context["receipt_id"], receipt.id);
}
