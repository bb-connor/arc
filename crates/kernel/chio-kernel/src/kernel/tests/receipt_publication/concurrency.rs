use super::*;
use std::sync::{mpsc, Condvar};
use std::time::Duration;

pub(super) struct Acknowledgements {
    pub(super) released: Mutex<bool>,
    pub(super) wake: Condvar,
}

impl Acknowledgements {
    pub(super) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}

pub(super) struct GatedStore {
    pub(super) entered: mpsc::Sender<String>,
    pub(super) acknowledgements: Arc<Acknowledgements>,
    pub(super) committed: Arc<Mutex<Vec<ChioReceipt>>>,
}

impl ReceiptStore for GatedStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.entered.send(receipt.id.clone()).unwrap();
        let (released, _) = self
            .acknowledgements
            .wake
            .wait_timeout_while(
                self.acknowledgements.released.lock().unwrap(),
                Duration::from_secs(10),
                |released| !*released,
            )
            .unwrap();
        if !*released {
            return Err(ReceiptStoreError::Timeout {
                operation: "append_chio_receipt".to_owned(),
                timeout_ms: 10_000,
            });
        }
        self.committed.lock().unwrap().push(receipt.clone());
        Ok(())
    }

    fn append_child_receipt(&self, _: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        unreachable!()
    }
}

#[test]
fn concurrent_terminal_receipts_reach_store_before_acknowledgement() {
    let first = signed_receipt();
    let second = signed_receipt();
    assert_ne!(first.id, second.id);
    let (entered_tx, entered_rx) = mpsc::channel();
    let acknowledgements = Arc::new(Acknowledgements {
        released: Mutex::new(false),
        wake: Condvar::new(),
    });
    let committed = Arc::new(Mutex::new(Vec::new()));
    let mut kernel = make_kernel(make_config());
    kernel
        .set_receipt_store(Box::new(GatedStore {
            entered: entered_tx,
            acknowledgements: Arc::clone(&acknowledgements),
            committed: Arc::clone(&committed),
        }))
        .unwrap();
    let (first_entry, second_entry, first_result, second_result) = std::thread::scope(|scope| {
        let first_worker = scope.spawn(|| kernel.record_chio_receipt(&first));
        let first_entry = entered_rx.recv_timeout(Duration::from_secs(2));
        let second_worker = scope.spawn(|| kernel.record_chio_receipt(&second));
        let second_entry = entered_rx.recv_timeout(Duration::from_secs(2));
        acknowledgements.release();
        (
            first_entry,
            second_entry,
            first_worker.join(),
            second_worker.join(),
        )
    });
    assert_eq!(first_entry.unwrap(), first.id);
    assert_eq!(
        second_entry.expect("second receipt must enter before the first acknowledgement"),
        second.id
    );
    first_result.unwrap().unwrap();
    second_result.unwrap().unwrap();
    assert_eq!(committed.lock().unwrap().len(), 2);
    assert_eq!(kernel.receipt_log().len(), 2);
}

#[test]
fn revocation_admission_progresses_while_receipt_acknowledgement_waits() {
    let receipt = signed_receipt();
    let (entered_tx, entered_rx) = mpsc::channel();
    let acknowledgements = Arc::new(Acknowledgements {
        released: Mutex::new(false),
        wake: Condvar::new(),
    });
    let mut kernel = make_kernel(make_config());
    let capability = make_capability(
        &kernel,
        &make_keypair(),
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    let request = make_request("concurrent-admission", &capability, "read_file", "srv-a");
    kernel
        .set_receipt_store(Box::new(GatedStore {
            entered: entered_tx,
            acknowledgements: Arc::clone(&acknowledgements),
            committed: Arc::new(Mutex::new(Vec::new())),
        }))
        .unwrap();
    let (completed_tx, completed_rx) = mpsc::channel();
    let (entry, admission_before_ack, publication, admission) = std::thread::scope(|scope| {
        let publication = scope.spawn(|| kernel.record_chio_receipt(&receipt));
        let entry = entered_rx.recv_timeout(Duration::from_secs(2));
        let admission = scope.spawn(|| {
            let result = kernel.check_tool_call_revocation_admission(&request);
            completed_tx.send(()).unwrap();
            result
        });
        let admission_before_ack = completed_rx.recv_timeout(Duration::from_secs(2));
        acknowledgements.release();
        (
            entry,
            admission_before_ack,
            publication.join(),
            admission.join(),
        )
    });
    assert_eq!(entry.unwrap(), receipt.id);
    admission_before_ack.expect("admission must finish before receipt acknowledgement");
    publication.unwrap().unwrap();
    admission.unwrap().unwrap();
    assert_eq!(kernel.receipt_log().len(), 1);
}

#[test]
fn revocation_waits_for_receipt_acknowledgement() {
    let receipt = signed_receipt();
    let (entered_tx, entered_rx) = mpsc::channel();
    let acknowledgements = Arc::new(Acknowledgements {
        released: Mutex::new(false),
        wake: Condvar::new(),
    });
    let mut kernel = make_kernel(make_config());
    let capability = make_capability(
        &kernel,
        &make_keypair(),
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    kernel
        .set_receipt_store(Box::new(GatedStore {
            entered: entered_tx,
            acknowledgements: Arc::clone(&acknowledgements),
            committed: Arc::new(Mutex::new(Vec::new())),
        }))
        .unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let (entry, started, early, publication, revocation) = std::thread::scope(|scope| {
        let publication = scope.spawn(|| kernel.record_chio_receipt(&receipt));
        let entry = entered_rx.recv_timeout(Duration::from_secs(2));
        let revocation = scope.spawn(|| {
            started_tx.send(()).unwrap();
            let result = kernel.revoke_capability(&capability.id);
            done_tx.send(()).unwrap();
            result
        });
        let started = started_rx.recv_timeout(Duration::from_secs(2));
        let early = done_rx.recv_timeout(Duration::from_millis(100));
        acknowledgements.release();
        (entry, started, early, publication.join(), revocation.join())
    });
    assert_eq!(entry.unwrap(), receipt.id);
    started.unwrap();
    assert_eq!(early, Err(mpsc::RecvTimeoutError::Timeout));
    publication.unwrap().unwrap();
    revocation.unwrap().unwrap();
    assert_eq!(kernel.receipt_log().len(), 1);
}

#[test]
fn receipt_barrier_refuses_admission_reentry_and_allows_an_independent_kernel() {
    let kernel = make_kernel(make_config());
    let independent = make_kernel(make_config());
    let capability = make_capability(
        &kernel,
        &make_keypair(),
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    let request = make_request("barrier-admission", &capability, "read_file", "srv-a");
    let barrier = kernel.publication_sync.receipts(false).unwrap();
    assert!(matches!(
        kernel.check_tool_call_revocation_admission(&request),
        Err(KernelError::Internal(message)) if message == "receipt publication lock order violation"
    ));
    independent
        .check_tool_call_revocation_admission(&request)
        .unwrap();
    drop(barrier);
    kernel
        .check_tool_call_revocation_admission(&request)
        .unwrap();
}

#[test]
fn publication_refuses_recursive_publication_and_releases_tracking_on_unwind() {
    let kernel = make_kernel(make_config());
    let guard = kernel.lock_receipt_publication(false).unwrap();
    assert!(matches!(
        kernel.lock_receipt_publication(false),
        Err(KernelError::Internal(message)) if message == "receipt publication lock order violation"
    ));
    drop(guard);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = kernel.publication_sync.fence(true, true).unwrap();
        panic!("publication scope unwind");
    }));
    let payload = panicked.unwrap_err();
    assert_eq!(
        payload.downcast_ref::<&str>().copied(),
        Some("publication scope unwind")
    );
    kernel.lock_receipt_publication(false).unwrap();
}
