use super::*;
use crate::security::adapters::{DeclassificationReceiptOutboxDrainer, NativeSecurityReceiptSink};
use crate::security::scheduler_worker::{
    DeclassificationOutboxHealth, ProductionDeclassificationReceiptOutbox, ResponseWorkerTickError,
};
use chio_security_types::ports::{
    DeclassificationEvidenceAckRequest, DeclassificationEvidenceRecord, ErrorCode,
    DECLASSIFICATION_EVIDENCE_INITIAL_RETRY_MS,
};
use std::path::Path;

type CommittedDispatch = Result<
    Option<Box<dyn chio_security_kernel::FlowDispatchOutcomeRecorder>>,
    chio_flow::FlowDenial,
>;

const DISPATCH_AT_UNIX_MS: u64 = 150_000;
const FIRST_DRAIN_AT_UNIX_MS: u64 = 150_100;
const RESTART_AT_UNIX_MS: u64 = 150_200;

/// Admits real receipts while open and fails every sink call as transient
/// while closed.
struct GatedReceipts {
    inner: Arc<NativeSecurityReceiptSink>,
    closed: AtomicBool,
}

impl SecurityReceiptSink for GatedReceipts {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        self.inner.ensure_receipts_ready()
    }

    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        if self.closed.load(Ordering::Acquire) {
            return Err(PortError::unavailable());
        }
        self.inner.sign_and_append(request)
    }
}

impl ExactSecurityReceiptSink for GatedReceipts {
    fn load_exact(&self, evidence_id: &OpaqueReceiptRef) -> PortResult<Option<ExactReceiptRecord>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(PortError::unavailable());
        }
        self.inner.load_exact(evidence_id)
    }
}

fn security_store(path: &Path) -> Arc<SqliteSecurityStateStore> {
    Arc::new(
        open_declassification_test_store(path)
            .unwrap_or_else(|error| panic!("declassification store: {error:?}")),
    )
}

fn native_receipts(path: &Path) -> Arc<NativeSecurityReceiptSink> {
    let store = chio_store_sqlite::SqliteReceiptStore::open(path)
        .unwrap_or_else(|error| panic!("receipt store: {error}"));
    Arc::new(NativeSecurityReceiptSink::new(
        Arc::new(store),
        Arc::new(chio_core::Ed25519Backend::new(Keypair::from_seed(
            &[79; 32],
        ))),
    ))
}

fn production_outbox(
    store: &Arc<SqliteSecurityStateStore>,
    receipts: Arc<dyn ExactSecurityReceiptSink>,
    now_unix_ms: u64,
) -> ProductionDeclassificationReceiptOutbox {
    let evidence_store: Arc<dyn DeclassificationEvidenceCommitStore> = store.clone();
    let drainer = DeclassificationReceiptOutboxDrainer::new_with_clock(
        Arc::clone(&evidence_store),
        receipts,
        Arc::new(FixedClock(now_unix_ms)),
    )
    .unwrap_or_else(|error| panic!("declassification drainer: {error}"));
    ProductionDeclassificationReceiptOutbox::new(evidence_store, Arc::new(drainer))
}

fn commit_declassified_dispatch(
    store: &Arc<SqliteSecurityStateStore>,
    receipts: Arc<dyn ExactSecurityReceiptSink>,
    authority_seed: u8,
) -> CommittedDispatch {
    let authority = Keypair::from_seed(&[authority_seed; 32]);
    let purpose =
        DeclassificationPurpose::new("support").unwrap_or_else(|error| panic!("purpose: {error}"));
    let config = declassifying_evidence_flow_config(
        &authority,
        store.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
        receipts,
    );
    let resolver = PersistentFlowResolver::new(
        declassification_registry(&purpose),
        Arc::new(FakeFlowStore::new(flow_snapshot(7))),
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(AdvancingClock::new(DISPATCH_AT_UNIX_MS)),
        config,
    );
    let key = flow_key();
    let context = SecurityInvocationContextV1::new(
        key.tenant_id,
        key.session_id,
        key.principal_id,
        key.isolation_epoch_id,
        key.lineage_id,
        7,
    )
    .with_flow_state_generation(7);
    let request = declassifying_flow_request(&authority, &purpose);
    resolver.commit_dispatch(
        &FlowPreInvocationInput {
            security_context: &context,
            request: &request,
        },
        RecordId::new("restart-revalidation-dispatch")
            .unwrap_or_else(|error| panic!("dispatch: {error}")),
    )
}

fn evidence(
    store: &SqliteSecurityStateStore,
    phase: DeclassificationEvidencePhase,
) -> DeclassificationEvidenceRecord {
    store
        .load_declassification_evidence(&DeclassificationEvidenceQuery {
            tenant_id: TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}")),
            grant_id: GrantId::new("grant-a").unwrap_or_else(|error| panic!("grant: {error}")),
            phase,
        })
        .unwrap_or_else(|error| panic!("load evidence: {error:?}"))
        .unwrap_or_else(|| panic!("evidence missing"))
}

fn assert_retry_backoff(record: &DeclassificationEvidenceRecord, error_code: &str) {
    assert!(!record.acknowledged);
    assert_eq!(record.attempts, 1);
    assert_eq!(
        record.next_attempt_at_unix_ms,
        FIRST_DRAIN_AT_UNIX_MS + DECLASSIFICATION_EVIDENCE_INITIAL_RETRY_MS
    );
    assert!(record.next_attempt_at_unix_ms > RESTART_AT_UNIX_MS);
    assert_eq!(
        record.last_error_code.as_ref().map(ErrorCode::as_str),
        Some(error_code)
    );
}

fn is_integrity_failure(error: &ResponseWorkerTickError) -> bool {
    matches!(
        error,
        ResponseWorkerTickError::DeclassificationOutbox(source)
            if source.kind() == PortErrorKind::IntegrityFailure
    )
}

#[test]
fn a_retried_predecessor_mismatch_keeps_restarted_readiness_closed() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let state_path = directory.path().join("declassification.sqlite");
    let receipts_path = directory.path().join("receipts.sqlite");
    let outcome_id = {
        let store = security_store(&state_path);
        assert!(matches!(
            commit_declassified_dispatch(&store, Arc::new(RejectingSecurityReceipts), 81),
            Err(chio_flow::FlowDenial::DeclassificationStoreFailure)
        ));
        // The consumption is acknowledged under a hash that is not the record
        // the exact sink will hold for it.
        let consumption = evidence(&store, DeclassificationEvidencePhase::Consumption);
        store
            .acknowledge_declassification_evidence(&DeclassificationEvidenceAckRequest {
                tenant_id: consumption.tenant_id.clone(),
                grant_id: consumption.grant_id.clone(),
                phase: consumption.phase,
                evidence_id: consumption.receipt.evidence_id.clone(),
                body_hash: consumption.receipt.body_hash,
                transition_id: consumption.receipt.transition_id.clone(),
                durable_sink_record_hash: Digest32::new([7; 32]),
                verified_at_unix_ms: FIRST_DRAIN_AT_UNIX_MS,
            })
            .unwrap_or_else(|error| panic!("acknowledge consumption: {error:?}"));

        let receipts = native_receipts(&receipts_path);
        let outbox = production_outbox(&store, receipts.clone(), FIRST_DRAIN_AT_UNIX_MS);
        match outbox.reconcile_and_drain_startup() {
            Err(error) => assert!(is_integrity_failure(&error), "{error}"),
            Ok(report) => panic!("a predecessor mismatch drained: {report:?}"),
        }
        let outcome = evidence(&store, DeclassificationEvidencePhase::Outcome);
        assert_retry_backoff(&outcome, "store.integrity_failure");
        assert!(receipts
            .load_exact(&consumption.receipt.evidence_id)
            .unwrap_or_else(|error| panic!("load consumption receipt: {error}"))
            .is_some_and(|exact| exact.durable_record_hash != Digest32::new([7; 32])));
        outcome.receipt.evidence_id
    };

    // Restart before the retry is due: nothing in memory survives.
    let store = security_store(&state_path);
    let receipts = native_receipts(&receipts_path);
    let outbox = production_outbox(&store, receipts.clone(), RESTART_AT_UNIX_MS);
    let startup = outbox.reconcile_and_drain_startup();
    let readiness = outbox.ensure_ready();
    assert!(
        startup.as_ref().is_err_and(is_integrity_failure)
            && readiness.as_ref().is_err_and(is_integrity_failure),
        "restart reopened a retried predecessor mismatch: startup {startup:?}, readiness \
         {readiness:?}"
    );
    assert!(matches!(
        outbox.health(),
        DeclassificationOutboxHealth::Failed {
            pending_receipts: Some(1),
            ..
        }
    ));
    // Revalidation is read-only: the retry is untouched and the outcome was
    // never appended.
    assert_retry_backoff(
        &evidence(&store, DeclassificationEvidencePhase::Outcome),
        "store.integrity_failure",
    );
    assert_eq!(
        receipts
            .load_exact(&outcome_id)
            .unwrap_or_else(|error| panic!("load outcome receipt: {error}")),
        None
    );
}

#[test]
fn a_retried_transient_failure_restarts_as_pending_work() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let state_path = directory.path().join("declassification.sqlite");
    let receipts_path = directory.path().join("receipts.sqlite");
    {
        let store = security_store(&state_path);
        let receipts = Arc::new(GatedReceipts {
            inner: native_receipts(&receipts_path),
            closed: AtomicBool::new(false),
        });
        let mut recorder = commit_declassified_dispatch(&store, receipts.clone(), 82)
            .unwrap_or_else(|error| panic!("commit dispatch: {error}"))
            .unwrap_or_else(|| panic!("outcome recorder missing"));
        receipts.closed.store(true, Ordering::Release);
        assert!(matches!(
            recorder.record(DeclassificationDispatchOutcome::Released),
            Err(chio_flow::FlowDenial::DeclassificationStoreFailure)
        ));
        assert!(evidence(&store, DeclassificationEvidencePhase::Consumption).acknowledged);

        let outbox = production_outbox(&store, receipts, FIRST_DRAIN_AT_UNIX_MS);
        let report = outbox
            .reconcile_and_drain_startup()
            .unwrap_or_else(|error| panic!("transient startup drain: {error}"));
        assert_eq!((report.acknowledged, report.deferred), (0, 1));
        assert_retry_backoff(
            &evidence(&store, DeclassificationEvidencePhase::Outcome),
            "store.unavailable",
        );
    }

    let store = security_store(&state_path);
    let receipts = native_receipts(&receipts_path);
    let outbox = production_outbox(&store, receipts.clone(), RESTART_AT_UNIX_MS);
    let report = outbox
        .reconcile_and_drain_startup()
        .unwrap_or_else(|error| panic!("restart with transient backoff: {error}"));
    assert_eq!((report.remaining, report.remaining_due), (1, 0));
    assert_eq!(
        outbox.health(),
        DeclassificationOutboxHealth::Pending { receipts: 1 }
    );
    outbox
        .ensure_ready()
        .unwrap_or_else(|error| panic!("readiness during transient backoff: {error}"));

    let due = production_outbox(
        &store,
        receipts,
        FIRST_DRAIN_AT_UNIX_MS + DECLASSIFICATION_EVIDENCE_INITIAL_RETRY_MS,
    );
    let delivered = due
        .reconcile_and_drain_startup()
        .unwrap_or_else(|error| panic!("delivery once due: {error}"));
    assert_eq!((delivered.acknowledged, delivered.remaining), (1, 0));
    assert_eq!(due.health(), DeclassificationOutboxHealth::Ready);
}
