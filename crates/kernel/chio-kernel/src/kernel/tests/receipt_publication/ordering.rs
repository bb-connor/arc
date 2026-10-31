use super::*;
use std::sync::{mpsc, Barrier, Condvar};
use std::time::Duration;

struct RetainedStore {
    receipts: Arc<Mutex<Vec<ChioReceipt>>>,
    reads: mpsc::Sender<String>,
}

impl ReceiptStore for RetainedStore {
    no_receipt_openings!();
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.receipts.lock().unwrap().push(receipt.clone());
        Ok(())
    }

    fn append_child_receipt(&self, _: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        unreachable!()
    }

    fn load_chio_receipt(&self, id: &str) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        self.reads.send(id.to_owned()).unwrap();
        Ok(self
            .receipts
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .cloned())
    }
}

#[cfg(feature = "finding-market")]
#[test]
fn retained_replay_waits_until_acknowledged_publication_projects() {
    let receipt = signed_receipt();
    let mut kernel = make_kernel(make_config());
    let (read_tx, read_rx) = mpsc::channel();
    let receipts = Arc::new(Mutex::new(Vec::new()));
    kernel
        .set_receipt_store(Box::new(RetainedStore {
            receipts: Arc::clone(&receipts),
            reads: read_tx,
        }))
        .unwrap();
    let publication = kernel.lock_receipt_publication(false).unwrap();
    let committed = kernel
        .append_terminal_receipt_during_trace_transition(&receipt, &publication, false, false)
        .unwrap_or_else(|_| panic!("durable publication must acknowledge"));
    assert_eq!(receipts.lock().unwrap().len(), 1);
    assert_eq!(kernel.receipt_log().len(), 0);
    let (started_tx, started_rx) = mpsc::channel();
    let (started, early_read, replay, committed) = std::thread::scope(|scope| {
        let replay = scope.spawn(|| {
            started_tx.send(()).unwrap();
            kernel.record_chio_receipt_without_settlement_once(&receipt)
        });
        let started = started_rx.recv_timeout(Duration::from_secs(2));
        let early_read = read_rx.recv_timeout(Duration::from_millis(100));
        let committed = kernel.project_acknowledged_receipt_during_trace_transition(
            &receipt,
            committed,
            &publication,
        );
        drop(publication);
        (started, early_read, replay.join(), committed)
    });
    started.unwrap();
    assert_eq!(early_read, Err(mpsc::RecvTimeoutError::Timeout));
    replay.unwrap().unwrap();
    kernel
        .finish_record_chio_receipt(&receipt, committed)
        .unwrap();
    assert_eq!(
        read_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        receipt.id
    );
    assert_eq!(receipts.lock().unwrap().len(), 1);
    assert_eq!(kernel.receipt_log().len(), 1);
    let mut conflict = receipt.clone();
    conflict.timestamp += 1;
    assert!(matches!(
        kernel.record_chio_receipt_without_settlement_once(&conflict),
        Err(KernelError::DurableAdmission(message))
            if message == format!("receipt projection {} conflicts with retained durable history", receipt.id)
    ));
    assert_eq!(receipts.lock().unwrap().len(), 1);
    assert_eq!(kernel.receipt_log().len(), 1);
}

#[derive(Default)]
struct OrderedTrace(Mutex<Vec<(u64, String)>>);

impl RuntimeTraceObserver for OrderedTrace {
    fn observe(&self, event: RuntimeTraceEvent) {
        if let RuntimeTraceEvent::ReceiptAppended {
            source_sequence,
            receipt,
        } = event
        {
            self.0.lock().unwrap().push((source_sequence, receipt.id));
        }
    }
}

#[test]
fn concurrent_ephemeral_receipts_preserve_mirror_and_trace_order() {
    let mut kernel = make_kernel(make_config());
    let trace = Arc::new(OrderedTrace::default());
    kernel.set_runtime_trace_observer(trace.clone());
    let receipts: Vec<_> = (0..8).map(|_| signed_receipt()).collect();
    let start = Barrier::new(receipts.len() + 1);
    let results = std::thread::scope(|scope| {
        let kernel = &kernel;
        let start = &start;
        let workers: Vec<_> = receipts
            .iter()
            .map(|receipt| {
                scope.spawn(move || {
                    start.wait();
                    kernel.record_chio_receipt(receipt)
                })
            })
            .collect();
        start.wait();
        workers
            .into_iter()
            .map(|worker| worker.join())
            .collect::<Vec<_>>()
    });
    for result in results {
        result.unwrap().unwrap();
    }
    let mirrored: Vec<_> = kernel
        .receipt_log()
        .iter()
        .map(|receipt| receipt.id.clone())
        .collect();
    let mut observed = trace.0.lock().unwrap().clone();
    observed.sort_by_key(|(sequence, _)| *sequence);
    assert_eq!(observed.len(), 8);
    assert_eq!(
        observed
            .iter()
            .map(|(sequence, _)| *sequence)
            .collect::<Vec<_>>(),
        (1..=8).collect::<Vec<_>>()
    );
    assert_eq!(
        observed.into_iter().map(|(_, id)| id).collect::<Vec<_>>(),
        mirrored
    );
}

#[test]
fn concurrent_durable_receipts_preserve_mirror_and_trace_order() {
    use super::concurrency::{Acknowledgements, GatedStore};
    let mut kernel = make_kernel(make_config());
    let trace = Arc::new(OrderedTrace::default());
    kernel.set_runtime_trace_observer(trace.clone());
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
    let receipts: Vec<_> = (0..8).map(|_| signed_receipt()).collect();
    let (entered, results) = std::thread::scope(|scope| {
        let kernel = &kernel;
        let workers: Vec<_> = receipts
            .iter()
            .map(|receipt| scope.spawn(move || kernel.record_chio_receipt(receipt)))
            .collect();
        let mut entered = Vec::new();
        for _ in 0..receipts.len() {
            match entered_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(id) => entered.push(id),
                Err(_) => break,
            }
        }
        acknowledgements.release();
        (
            entered,
            workers
                .into_iter()
                .map(|worker| worker.join())
                .collect::<Vec<_>>(),
        )
    });
    assert_eq!(
        entered.len(),
        8,
        "all durable appends enter before acknowledgement"
    );
    for result in results {
        result.unwrap().unwrap();
    }
    assert_eq!(committed.lock().unwrap().len(), 8);
    let mirrored: Vec<_> = kernel
        .receipt_log()
        .iter()
        .map(|receipt| receipt.id.clone())
        .collect();
    let mut observed = trace.0.lock().unwrap().clone();
    observed.sort_by_key(|(sequence, _)| *sequence);
    assert_eq!(observed.len(), 8);
    assert_eq!(
        observed
            .iter()
            .map(|(sequence, _)| *sequence)
            .collect::<Vec<_>>(),
        (1..=8).collect::<Vec<_>>()
    );
    assert_eq!(
        observed.into_iter().map(|(_, id)| id).collect::<Vec<_>>(),
        mirrored
    );
}

struct CallbackStore(Box<dyn Fn() + Send + Sync>);

impl ReceiptStore for CallbackStore {
    no_receipt_openings!();
    fn append_chio_receipt(&self, _: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        (self.0)();
        Ok(())
    }

    fn append_child_receipt(&self, _: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        unreachable!()
    }
}

#[test]
fn receipt_callback_refuses_same_kernel_admission_without_blocking_an_independent_kernel() {
    let mut kernel = make_kernel(make_config());
    let independent = make_kernel(make_config());
    let capability = make_capability(
        &kernel,
        &make_keypair(),
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    let request = make_request("receipt-callback", &capability, "read_file", "srv-a");
    let owner = Arc::new(Mutex::new(std::sync::Weak::<ChioKernel>::new()));
    let callback_owner = Arc::clone(&owner);
    kernel.set_receipt_store(Box::new(CallbackStore(Box::new(move || {
        let kernel = callback_owner.lock().unwrap().upgrade().unwrap();
        assert!(matches!(
            kernel.check_tool_call_revocation_admission(&request),
            Err(KernelError::Internal(message)) if message == "receipt publication lock order violation"
        ));
        independent.check_tool_call_revocation_admission(&request).unwrap();
    })))).unwrap();
    let kernel = Arc::new(kernel);
    *owner.lock().unwrap() = Arc::downgrade(&kernel);
    kernel.record_chio_receipt(&signed_receipt()).unwrap();
    assert_eq!(kernel.receipt_log().len(), 1);
}
