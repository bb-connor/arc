use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::{canonical_json_bytes, CanonicalBytes};
use chio_core::capability::{scope::ChioScope, token::CapabilityToken};
use chio_core::crypto::{sha256_hex, Keypair, Signature};
use chio_core::receipt::{
    body::ChioReceipt, crypto_floor::ReceiptCryptoFloor, decision::Decision,
    economics::FinancialReceiptMetadata, economics::SettlementStatus,
    governance::GovernedTransactionReceiptMetadata, lineage::ChildRequestReceipt,
    metadata::ReceiptAttributionMetadata,
};
use chio_core::session::{
    OperationTerminalState, RequestLineageMode, RequestLineageRecord, SessionAnchorReference,
};
use chio_kernel::checkpoint::{KernelCheckpoint, KernelCheckpointBody};
use chio_kernel::cost_attribution::{
    CostAttributionChainHop, CostAttributionQuery, CostAttributionReceiptRow,
    CostAttributionReport, CostAttributionSummary, LeafCostAttributionRow, RootCostAttributionRow,
    MAX_COST_ATTRIBUTION_LIMIT,
};
use chio_kernel::dpop::DPOP_SCHEMA;
use chio_kernel::operator_report::{
    AuthorizationContextReport, AuthorizationContextRow, AuthorizationContextSenderConstraint,
    AuthorizationContextSummary, BehavioralFeedGovernedActionSummary,
    BehavioralFeedMeteredBillingRow, BehavioralFeedMeteredBillingSummary, BehavioralFeedQuery,
    BehavioralFeedReceiptRow, BehavioralFeedReceiptSelection, BehavioralFeedSettlementSummary,
    ChioOAuthAuthorizationDiscoveryMetadata, ChioOAuthAuthorizationExampleMapping,
    ChioOAuthAuthorizationMetadataReport, ChioOAuthAuthorizationProfile,
    ChioOAuthAuthorizationReviewPack, ChioOAuthAuthorizationReviewPackRecord,
    ChioOAuthAuthorizationReviewPackSummary, ChioOAuthAuthorizationSupportBoundary,
    ComplianceReport, EconomicCompletionFlowReport, EconomicCompletionFlowSummary,
    EconomicReceiptMeteringProjection, EconomicReceiptProjectionReport,
    EconomicReceiptProjectionRow, EconomicReceiptProjectionSummary,
    EconomicReceiptSettlementProjection, GovernedAuthorizationCommerceDetail,
    GovernedAuthorizationDetail, GovernedAuthorizationMeteredBillingDetail,
    GovernedAuthorizationTransactionContext, MeteredBillingEvidenceRecord,
    MeteredBillingReconciliationReport, MeteredBillingReconciliationRow,
    MeteredBillingReconciliationState, MeteredBillingReconciliationSummary, OperatorReportQuery,
    SettlementReconciliationReport, SettlementReconciliationRow, SettlementReconciliationState,
    SettlementReconciliationSummary, SharedEvidenceQuery, SharedEvidenceReferenceReport,
    SharedEvidenceReferenceRow, SharedEvidenceReferenceSummary,
    CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE, CHIO_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA,
    CHIO_OAUTH_AUTHORIZATION_METADATA_SCHEMA, CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE,
    CHIO_OAUTH_AUTHORIZATION_REVIEW_PACK_SCHEMA, CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE,
    CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP, ECONOMIC_COMPLETION_FLOW_SCHEMA,
};
use chio_kernel::receipt_analytics::{
    AgentAnalyticsRow, AnalyticsTimeBucket, ReceiptAnalyticsMetrics, ReceiptAnalyticsQuery,
    ReceiptAnalyticsResponse, TimeAnalyticsRow, ToolAnalyticsRow, MAX_ANALYTICS_GROUP_LIMIT,
};
use chio_kernel::receipt_query::{
    ReceiptQuery, ReceiptQueryResult, ReceiptReadBoundary, ReceiptReadContext, MAX_QUERY_LIMIT,
};
use chio_kernel::receipt_store::{ReceiptLineageStatementLink, ReceiptLineageVerification};
use chio_kernel::{
    AuthorizationReceiptConsumption, CapabilitySnapshot, CreditBondDisposition,
    CreditBondLifecycleState, CreditBondListQuery, CreditBondListReport, CreditBondListSummary,
    CreditBondRow, CreditFacilityDisposition, CreditFacilityLifecycleState,
    CreditFacilityListQuery, CreditFacilityListReport, CreditFacilityListSummary,
    CreditFacilityRow, CreditLossLifecycleEventKind, CreditLossLifecycleListQuery,
    CreditLossLifecycleListReport, CreditLossLifecycleListSummary, CreditLossLifecycleRow,
    EvidenceChildReceiptScope, EvidenceExportQuery, ExposureLedgerQuery,
    FederatedEvidenceShareImport, FederatedEvidenceShareSummary, LiabilityAutoBindDisposition,
    LiabilityClaimPayoutReconciliationState, LiabilityClaimResponseDisposition,
    LiabilityClaimSettlementReconciliationState, LiabilityClaimWorkflowQuery,
    LiabilityClaimWorkflowReport, LiabilityClaimWorkflowRow, LiabilityClaimWorkflowSummary,
    LiabilityMarketWorkflowQuery, LiabilityMarketWorkflowReport, LiabilityMarketWorkflowRow,
    LiabilityMarketWorkflowSummary, LiabilityProviderLifecycleState, LiabilityProviderListQuery,
    LiabilityProviderListReport, LiabilityProviderListSummary, LiabilityProviderResolutionQuery,
    LiabilityProviderResolutionReport, LiabilityProviderRow, LiabilityQuoteDisposition,
    ReceiptCheckpointCreateReport, ReceiptCheckpointRange, ReceiptCheckpointStatusReport,
    ReceiptFlushReport, ReceiptStore, ReceiptStoreError, ReceiptStoreHealthReport,
    ReceiptWalCheckpointReport, ReceiptWriterCounters, RetentionConfig, SignedCreditBond,
    SignedCreditFacility, SignedCreditLossLifecycle, SignedLiabilityAutoBindDecision,
    SignedLiabilityBoundCoverage, SignedLiabilityClaimAdjudication, SignedLiabilityClaimDispute,
    SignedLiabilityClaimPackage, SignedLiabilityClaimPayoutInstruction,
    SignedLiabilityClaimPayoutReceipt, SignedLiabilityClaimResponse,
    SignedLiabilityClaimSettlementInstruction, SignedLiabilityClaimSettlementReceipt,
    SignedLiabilityPlacement, SignedLiabilityPricingAuthority, SignedLiabilityProvider,
    SignedLiabilityQuoteRequest, SignedLiabilityQuoteResponse, SignedUnderwritingDecision,
    StoredChildReceipt, StoredToolReceipt, UnderwritingAppealCreateRequest,
    UnderwritingAppealRecord, UnderwritingAppealResolution, UnderwritingAppealResolveRequest,
    UnderwritingAppealStatus, UnderwritingDecisionLifecycleState, UnderwritingDecisionListReport,
    UnderwritingDecisionOutcome, UnderwritingDecisionQuery, UnderwritingDecisionRow,
    UnderwritingDecisionSummary, CREDIT_BOND_LIST_REPORT_SCHEMA,
    CREDIT_FACILITY_LIST_REPORT_SCHEMA, CREDIT_LOSS_LIFECYCLE_LIST_REPORT_SCHEMA,
    LIABILITY_CLAIM_WORKFLOW_REPORT_SCHEMA, LIABILITY_MARKET_WORKFLOW_REPORT_SCHEMA,
    LIABILITY_PROVIDER_LIST_REPORT_SCHEMA, LIABILITY_PROVIDER_RESOLUTION_REPORT_SCHEMA,
};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension};

pub struct SqliteReceiptStore {
    pub(crate) pool: Pool<SqliteConnectionManager>,
    receipt_commit_actor: ReceiptCommitActor,
    /// Multi-tenant receipt isolation: when true, tenant-
    /// scoped queries exclude the pre-multitenant NULL-tagged set. When
    /// false, queries with `tenant_filter = Some(id)` return rows where
    /// `tenant_id = id OR tenant_id IS NULL`, which keeps pre-multitenant
    /// (NULL-tagged) receipts visible during explicit compatibility mode.
    pub(crate) strict_tenant_isolation: std::sync::atomic::AtomicBool,
    /// RFC-0006 staged-rollout flag: read-only after open.
    pub(crate) incremental_verification: bool,
}

type FederatedShareSubjectCorpus = (
    FederatedEvidenceShareSummary,
    Vec<StoredToolReceipt>,
    Vec<CapabilitySnapshot>,
);
pub(crate) type SqliteStoreConnection = PooledConnection<SqliteConnectionManager>;

const RECEIPT_GROUP_COMMIT_MAX_BATCH: usize = 64;
const RECEIPT_GROUP_COMMIT_FLUSH_DELAY: Duration = Duration::from_micros(500);
const RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY: usize = RECEIPT_GROUP_COMMIT_MAX_BATCH * 16;

struct ReceiptCommitActor {
    sender: mpsc::SyncSender<ReceiptCommitCommand>,
    health: Arc<ReceiptCommitWriterHealth>,
}

#[derive(Default)]
struct ReceiptCommitWriterHealth {
    accepted_total: AtomicU64,
    committed_total: AtomicU64,
    failed_total: AtomicU64,
    saturated_total: AtomicU64,
    inflight: AtomicU64,
    last_commit_unix_ms: AtomicU64,
    last_error: Mutex<Option<String>>,
    // Verified-head snapshot, written only by the actor thread; read by
    // flush_report / receipt_store_health / kernel counters (RFC-0006).
    head_checkpoint_seq: AtomicU64,
    head_checkpointed_entry_seq: AtomicU64,
    head_claim_log_count: AtomicU64,
    head_claim_log_max_seq: AtomicU64,
}

impl ReceiptCommitWriterHealth {
    fn store_head_snapshot(&self, head: &VerifiedHead) {
        self.head_checkpoint_seq
            .store(head.checkpoint_seq(), Ordering::SeqCst);
        self.head_checkpointed_entry_seq
            .store(head.checkpointed_entry_seq(), Ordering::SeqCst);
        self.head_claim_log_count
            .store(head.claim_log_count, Ordering::SeqCst);
        self.head_claim_log_max_seq
            .store(head.claim_log_max_seq, Ordering::SeqCst);
    }
}

struct ReceiptCommitRequest {
    receipt: ChioReceipt,
    raw_json: String,
    /// When true, `ensure_receipt_lineage_statement_for_receipt_id_tx` runs
    /// inside the same batch transaction as the receipt insert (trait-append
    /// paths). Canonical inherent paths keep `false` (today's behavior).
    ensure_lineage: bool,
    response: mpsc::SyncSender<Result<u64, ReceiptStoreError>>,
}

type WriterClosure =
    Box<dyn FnOnce(Result<&mut SqliteStoreConnection, ReceiptStoreError>) + Send + 'static>;

enum ReceiptCommitCommand {
    Append(Box<ReceiptCommitRequest>),
    Flush(mpsc::SyncSender<Result<(), ReceiptStoreError>>),
    /// Generic single-writer job. Runs on the writer connection after any
    /// in-flight append batch has committed. The closure receives `Err` when
    /// the actor cannot provide a healthy writer connection (fail-closed).
    Write(WriterClosure),
    /// Rerun the full verification on the writer connection and, on success,
    /// adopt the fresh head (clears a poisoned head). Audit-repair path.
    ReseedHead(mpsc::SyncSender<Result<(), ReceiptStoreError>>),
    /// Install (or replace) the background checkpoint signer on the actor
    /// thread. Delivered over the command channel: no shared state, no lock.
    InstallSigner(BackgroundCheckpointSigner),
}

impl ReceiptCommitActor {
    fn start(pool: Pool<SqliteConnectionManager>, incremental_verification: bool) -> Self {
        let (sender, receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let actor_health = Arc::clone(&health);
        thread::spawn(move || {
            receipt_commit_actor_loop(pool, receiver, actor_health, incremental_verification)
        });
        Self { sender, health }
    }

    fn append(
        &self,
        receipt: ChioReceipt,
        raw_json: String,
        ensure_lineage: bool,
    ) -> Result<u64, ReceiptStoreError> {
        let (response, result) = mpsc::sync_channel(1);
        let command = ReceiptCommitCommand::Append(Box::new(ReceiptCommitRequest {
            receipt,
            raw_json,
            ensure_lineage,
            response,
        }));
        // Increment `inflight` BEFORE handing the command to the worker. If we
        // wait until after `try_send`, the worker can dequeue, commit, and run
        // `atomic_saturating_sub(&health.inflight, n)` (see
        // `commit_receipt_batch`) before this thread observes the send result.
        // That race saturates `inflight` to 0 and leaks the increment, leaving
        // `health.writer.inflight` permanently misreporting drained writes.
        // The worker decrements unconditionally on dequeue, so the pre-send
        // increment pairs correctly. Any failure of `try_send` undoes the
        // speculative increment before returning.
        self.health.inflight.fetch_add(1, Ordering::SeqCst);
        match self.sender.try_send(command) {
            Ok(()) => {
                self.health.accepted_total.fetch_add(1, Ordering::SeqCst);
            }
            Err(mpsc::TrySendError::Full(_)) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                return Err(receipt_actor_unavailable_error());
            }
        }
        match result.recv() {
            Ok(result) => result,
            Err(_) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                Err(receipt_actor_unavailable_error())
            }
        }
    }

    fn flush(&self) -> Result<(), ReceiptStoreError> {
        self.flush_with_receiver(|receiver| {
            receiver
                .recv()
                .map_err(|_| receipt_actor_unavailable_error())?
        })
    }

    fn flush_with_timeout(&self, timeout: Duration) -> Result<(), ReceiptStoreError> {
        self.flush_with_receiver(|receiver| match receiver.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(receipt_actor_flush_timeout_error(timeout)),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(receipt_actor_unavailable_error()),
        })
    }

    fn flush_with_receiver(
        &self,
        receive: impl FnOnce(
            mpsc::Receiver<Result<(), ReceiptStoreError>>,
        ) -> Result<(), ReceiptStoreError>,
    ) -> Result<(), ReceiptStoreError> {
        let (response, result) = mpsc::sync_channel(1);
        match self.sender.try_send(ReceiptCommitCommand::Flush(response)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                self.health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return Err(receipt_actor_unavailable_error());
            }
        }
        receive(result)
    }

    fn writer_counters(&self) -> ReceiptWriterCounters {
        let last_commit_unix_ms = match self.health.last_commit_unix_ms.load(Ordering::SeqCst) {
            0 => None,
            value => Some(value),
        };
        let last_error = self
            .health
            .last_error
            .lock()
            .map(|error| error.clone())
            .unwrap_or_else(|_| Some("receipt commit writer health lock poisoned".to_string()));
        ReceiptWriterCounters {
            accepted_total: self.health.accepted_total.load(Ordering::SeqCst),
            committed_total: self.health.committed_total.load(Ordering::SeqCst),
            failed_total: self.health.failed_total.load(Ordering::SeqCst),
            saturated_total: self.health.saturated_total.load(Ordering::SeqCst),
            inflight: self.health.inflight.load(Ordering::SeqCst),
            last_commit_unix_ms,
            last_error,
        }
    }
}

/// Cloneable handle for running arbitrary write transactions on the single
/// writer connection. Closures MUST NOT call back into `SqliteReceiptStore`
/// methods that enqueue writer commands (that would deadlock the actor on
/// itself); they receive the writer connection directly instead.
pub(crate) struct WriterHandle {
    sender: mpsc::SyncSender<ReceiptCommitCommand>,
    health: Arc<ReceiptCommitWriterHealth>,
}

impl WriterHandle {
    /// Run one write job on the single writer connection and return its
    /// typed result. Fail-closed on saturation or a dead writer.
    pub(crate) fn run_write<T, F>(&self, job: F) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        let (response, result) = mpsc::sync_channel(1);
        let boxed: WriterClosure = Box::new(move |connection| {
            let outcome = match connection {
                // Panic isolation (RFC-0006 whole-store-death fix): `job` is
                // one of ~30 rerouted write families (lineage, liability,
                // underwriting, reconciliation, capability, federated, IOU,
                // checkpoint, reseed) now running on the single writer
                // thread. `AssertUnwindSafe` is sound here because the
                // writer actor re-acquires a fresh connection from the pool
                // for every command (see `handle_non_append_command`); a
                // caught panic fails only THIS job (fail-closed) and no
                // state from the panicking closure is reused afterward.
                Ok(connection) => {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(connection)))
                        .unwrap_or_else(|payload| Err(receipt_writer_job_panic_error(&payload)))
                }
                Err(error) => Err(error),
            };
            let _ = response.send(outcome);
        });
        // Pre-send increment: same race-avoidance invariant as
        // `ReceiptCommitActor::append` (see the comment at the `inflight`
        // increment in `append`). The actor decrements unconditionally on
        // dequeue; any send failure undoes the speculative increment.
        self.health.inflight.fetch_add(1, Ordering::SeqCst);
        match self.sender.try_send(ReceiptCommitCommand::Write(boxed)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                return Err(receipt_actor_unavailable_error());
            }
        }
        match result.recv() {
            Ok(outcome) => outcome,
            Err(_) => Err(receipt_actor_unavailable_error()),
        }
    }
}

fn receipt_commit_channel() -> (
    mpsc::SyncSender<ReceiptCommitCommand>,
    mpsc::Receiver<ReceiptCommitCommand>,
) {
    mpsc::sync_channel(RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY)
}

fn receipt_actor_unavailable_error() -> ReceiptStoreError {
    ReceiptStoreError::Pool("sqlite receipt commit actor is unavailable".to_string())
}

fn receipt_actor_saturated_error() -> ReceiptStoreError {
    ReceiptStoreError::Pool("sqlite receipt commit queue saturated".to_string())
}

fn receipt_actor_flush_timeout_error(timeout: Duration) -> ReceiptStoreError {
    ReceiptStoreError::Timeout {
        operation: "sqlite receipt commit flush".to_string(),
        timeout_ms: timeout.as_millis().min(u128::from(u64::MAX)) as u64,
    }
}

/// Last verified position of the writer connection's view of the receipt
/// chain, owned exclusively by the commit-actor thread (RFC-0006).
enum WriterHeadState {
    // Boxed: `VerifiedHead` embeds an `Option<KernelCheckpoint>`, which makes
    // this variant far larger than `Poisoned(String)` (clippy::large_enum_variant).
    Verified(Box<VerifiedHead>),
    /// Seeding or resync failed: every write is rejected with Conflict until
    /// `chio receipt audit --repair` reseeds (fail-closed, RFC-0006).
    Poisoned(String),
}

fn poisoned_head_error(message: &str) -> ReceiptStoreError {
    ReceiptStoreError::Conflict(format!(
        "receipt store verified head is unavailable ({message}); run `chio receipt audit --repair`"
    ))
}

fn receipt_commit_actor_loop(
    pool: Pool<SqliteConnectionManager>,
    receiver: mpsc::Receiver<ReceiptCommitCommand>,
    health: Arc<ReceiptCommitWriterHealth>,
    incremental_verification: bool,
) {
    let mut head_state = match pool
        .get()
        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
        .and_then(|connection| {
            if incremental_verification {
                seed_verified_head(&connection)
            } else {
                seed_head_snapshot(&connection)
            }
        }) {
        Ok(head) => {
            health.store_head_snapshot(&head);
            WriterHeadState::Verified(Box::new(head))
        }
        Err(error) => {
            if let Ok(mut last_error) = health.last_error.lock() {
                *last_error = Some(error.to_string());
            }
            WriterHeadState::Poisoned(error.to_string())
        }
    };

    let mut pending_flush_error: Option<ReceiptStoreError> = None;
    let mut checkpoint_signer: Option<BackgroundCheckpointSigner> = None;
    while let Ok(command) = receiver.recv() {
        match command {
            ReceiptCommitCommand::Append(request) => {
                let mut requests = vec![*request];
                let mut flushes = Vec::new();
                let mut deferred: Option<ReceiptCommitCommand> = None;
                while requests.len() < RECEIPT_GROUP_COMMIT_MAX_BATCH {
                    match receiver.recv_timeout(RECEIPT_GROUP_COMMIT_FLUSH_DELAY) {
                        Ok(ReceiptCommitCommand::Append(request)) => requests.push(*request),
                        Ok(ReceiptCommitCommand::Flush(response)) => {
                            flushes.push(response);
                            break;
                        }
                        Ok(other) => {
                            // Non-append commands (Write, InstallSigner,
                            // ReseedHead) execute strictly after the batch
                            // they interrupted commits.
                            deferred = Some(other);
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => break,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                // Panic isolation (RFC-0006 whole-store-death fix):
                // `commit_receipt_batch` runs on the single writer thread. A
                // panic anywhere inside it (the append transaction, the
                // lineage fold) must fail THIS batch, not kill the thread.
                // Clone the response channels before handing `requests` /
                // `flushes` to the panicking call: if it unwinds, those
                // values are dropped mid-function and the only way left to
                // answer every caller is through these pre-cloned senders.
                let request_responses: Vec<_> = requests
                    .iter()
                    .map(|request| request.response.clone())
                    .collect();
                let flush_responses = flushes.clone();
                pending_flush_error =
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        commit_receipt_batch(
                            &pool,
                            &mut head_state,
                            incremental_verification,
                            requests,
                            flushes,
                            &health,
                        )
                    })) {
                        Ok(flush_error) => flush_error,
                        Err(payload) => Some(fan_out_batch_panic_error(
                            &health,
                            request_responses,
                            flush_responses,
                            receipt_writer_job_panic_error(&payload),
                        )),
                    };
                // Checkpoint construction runs AFTER the batch commits and
                // AFTER commit_receipt_batch has already sent every caller's
                // response, so ADR-0013 durability latency is not extended
                // by checkpoint building. A build failure is recorded but
                // does not fail the already-durable appends (fail-closed via
                // `last_error`, not via poisoning the head).
                if pending_flush_error.is_none() {
                    if let WriterHeadState::Verified(head) = &mut head_state {
                        build_due_checkpoints_and_record(&pool, head, &checkpoint_signer, &health);
                    }
                }
                if let Some(command) = deferred {
                    handle_non_append_command(
                        &pool,
                        &mut head_state,
                        incremental_verification,
                        &health,
                        &mut checkpoint_signer,
                        command,
                    );
                }
            }
            ReceiptCommitCommand::Flush(response) => {
                let result = match &pending_flush_error {
                    Some(error) => Err(receipt_store_error_snapshot(error)),
                    None => Ok(()),
                };
                let _ = response.send(result);
            }
            other => handle_non_append_command(
                &pool,
                &mut head_state,
                incremental_verification,
                &health,
                &mut checkpoint_signer,
                other,
            ),
        }
    }
}

fn handle_non_append_command(
    pool: &Pool<SqliteConnectionManager>,
    head_state: &mut WriterHeadState,
    incremental_verification: bool,
    health: &ReceiptCommitWriterHealth,
    checkpoint_signer: &mut Option<BackgroundCheckpointSigner>,
    command: ReceiptCommitCommand,
) {
    match command {
        ReceiptCommitCommand::Write(job) => {
            // Unconditional decrement pairs with the pre-send increment in
            // `WriterHandle::run_write`.
            atomic_saturating_sub(&health.inflight, 1);
            let mut connection = match pool.get() {
                Ok(connection) => connection,
                Err(error) => {
                    job(Err(ReceiptStoreError::Pool(error.to_string())));
                    return;
                }
            };
            match head_state {
                WriterHeadState::Poisoned(message) => {
                    job(Err(poisoned_head_error(message)));
                }
                WriterHeadState::Verified(head) => {
                    // Pre-check (fail-closed): same predecessor check the
                    // append path runs, so writer-routed appends (child
                    // receipts, consuming auth) are equally protected.
                    let pre_check = if incremental_verification {
                        verify_head_against_latest_checkpoint(&connection, head)
                    } else {
                        verify_latest_checkpoint_integrity(&connection)
                    };
                    if let Err(error) = pre_check {
                        job(Err(error));
                        return;
                    }
                    job(Ok(&mut connection));
                    // Post-resync: absorb whatever the closure committed
                    // (claim-log rows via projection triggers, checkpoint
                    // rows via the manual path) so the next append's
                    // cross-check cannot false-Conflict.
                    if let Err(error) = resync_head_after_write(&connection, head) {
                        if let Ok(mut last_error) = health.last_error.lock() {
                            *last_error = Some(error.to_string());
                        }
                        *head_state = WriterHeadState::Poisoned(error.to_string());
                        return;
                    }
                    health.store_head_snapshot(head);
                    // Writer-routed appends (child receipts, consuming auth)
                    // can cross the threshold too; no pending_flush_error
                    // guard here since a Write job is not part of a batch.
                    // The writer pool holds exactly one connection
                    // (DEFAULT_WRITER_POOL_MAX_SIZE = 1): drop this one
                    // before build_due_checkpoints_and_record acquires its
                    // own, or `pool.get()` would block on itself.
                    drop(connection);
                    build_due_checkpoints_and_record(pool, head, checkpoint_signer, health);
                }
            }
        }
        ReceiptCommitCommand::InstallSigner(signer) => {
            *checkpoint_signer = Some(signer);
        }
        ReceiptCommitCommand::ReseedHead(response) => {
            let outcome = pool
                .get()
                .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
                .and_then(|connection| {
                    if incremental_verification {
                        seed_verified_head(&connection)
                    } else {
                        seed_head_snapshot(&connection)
                    }
                });
            let result = match outcome {
                Ok(head) => {
                    health.store_head_snapshot(&head);
                    if let Ok(mut last_error) = health.last_error.lock() {
                        *last_error = None;
                    }
                    *head_state = WriterHeadState::Verified(Box::new(head));
                    Ok(())
                }
                Err(error) => {
                    if let Ok(mut last_error) = health.last_error.lock() {
                        *last_error = Some(error.to_string());
                    }
                    *head_state = WriterHeadState::Poisoned(error.to_string());
                    Err(error)
                }
            };
            let _ = response.send(result);
        }
        // Append/Flush are handled by the main loop; reaching here is
        // impossible by construction but must stay fail-safe.
        ReceiptCommitCommand::Append(request) => {
            let _ = request
                .response
                .send(Err(receipt_actor_unavailable_error()));
        }
        ReceiptCommitCommand::Flush(response) => {
            let _ = response.send(Err(receipt_actor_unavailable_error()));
        }
    }
}

/// Build every checkpoint the head owes and, on success, refresh the health
/// head snapshot; on failure, record the error without poisoning the head or
/// failing the append/write that triggered it (checkpoint construction never
/// blocks an already-durable commit, RFC-0006 stage 4).
fn build_due_checkpoints_and_record(
    pool: &Pool<SqliteConnectionManager>,
    head: &mut VerifiedHead,
    checkpoint_signer: &Option<BackgroundCheckpointSigner>,
    health: &ReceiptCommitWriterHealth,
) {
    let Some(signer) = checkpoint_signer.as_ref() else {
        return;
    };
    // Panic isolation (RFC-0006 whole-store-death fix): a panic mid-build
    // (Merkle build, Ed25519 sign, serde) must not kill the writer thread.
    // `head.latest_checkpoint` is only ever assigned AFTER the per-checkpoint
    // transaction commits (see `maybe_build_checkpoint`), so a panic
    // anywhere before that leaves `head` exactly as it was; a caught panic
    // is therefore handled identically to a non-panicking `Err`: record
    // `last_error`, leave the head untouched, keep the thread alive.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        build_due_checkpoints(pool, head, signer)
    }))
    .unwrap_or_else(|payload| Err(receipt_writer_job_panic_error(&payload)));
    match result {
        Ok(()) => health.store_head_snapshot(head),
        Err(error) => {
            if let Ok(mut last_error) = health.last_error.lock() {
                *last_error = Some(error.to_string());
            }
        }
    }
}

fn build_due_checkpoints(
    pool: &Pool<SqliteConnectionManager>,
    head: &mut VerifiedHead,
    signer: &BackgroundCheckpointSigner,
) -> Result<(), ReceiptStoreError> {
    if signer.max_batch == 0 {
        return Ok(()); // ADR-0008: batch_size 0 disables checkpointing
    }
    let mut connection = pool
        .get()
        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))?;
    maybe_build_checkpoint(&mut connection, head, signer)
}

/// Build every checkpoint the head owes: count-based ADR-0008 trigger, range
/// derived from the cached head (NOT next_checkpoint_range_for_connection,
/// which runs a full chain verify), O(b) work per checkpoint.
fn maybe_build_checkpoint(
    connection: &mut SqliteStoreConnection,
    head: &mut VerifiedHead,
    signer: &BackgroundCheckpointSigner,
) -> Result<(), ReceiptStoreError> {
    if signer.max_batch == 0 {
        return Ok(());
    }
    while head
        .claim_log_max_seq
        .saturating_sub(head.checkpointed_entry_seq())
        >= signer.max_batch
    {
        let start_seq = head.checkpointed_entry_seq().saturating_add(1);
        let end_seq = start_seq.saturating_add(signer.max_batch - 1);
        ensure_claim_log_range_contiguous(connection, start_seq, end_seq, "checkpoint range")?;
        let receipt_bytes = load_claim_tree_canonical_bytes_range(connection, start_seq, end_seq)?
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint_seq = head
            .checkpoint_seq()
            .checked_add(1)
            .ok_or_else(|| ReceiptStoreError::Conflict("checkpoint_seq overflow".to_string()))?;
        // O(b) Merkle build; predecessor digest comes from the cached head.
        let checkpoint = chio_kernel::build_checkpoint_with_previous(
            checkpoint_seq,
            start_seq,
            end_seq,
            &receipt_bytes,
            &signer.keypair,
            head.latest_checkpoint.as_ref(),
        )
        .map_err(checkpoint_error_to_receipt_store)?;
        #[cfg(test)]
        if test_hooks::panic_during_checkpoint_build(signer.max_batch) {
            panic!("injected test panic during background checkpoint build");
        }
        ensure_checkpoint_transparency_guards(connection)?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        insert_checkpoint_incremental_tx(&tx, head.latest_checkpoint.as_ref(), &checkpoint)?;
        tx.commit()?;
        head.latest_checkpoint = Some(checkpoint);
    }
    Ok(())
}

/// RFC-0006 head-resync rule: one indexed delta aggregate plus one
/// latest-checkpoint row read after every Write closure.
fn resync_head_after_write(
    connection: &Connection,
    head: &mut VerifiedHead,
) -> Result<(), ReceiptStoreError> {
    let (delta_count, post_max) =
        claim_log_delta_count_and_max_seq(connection, head.claim_log_max_seq)?;
    head.claim_log_count = head.claim_log_count.saturating_add(delta_count);
    head.claim_log_max_seq = post_max;
    verify_head_against_latest_checkpoint(connection, head)
}

fn commit_receipt_batch(
    pool: &Pool<SqliteConnectionManager>,
    head_state: &mut WriterHeadState,
    incremental_verification: bool,
    requests: Vec<ReceiptCommitRequest>,
    flushes: Vec<mpsc::SyncSender<Result<(), ReceiptStoreError>>>,
    health: &ReceiptCommitWriterHealth,
) -> Option<ReceiptStoreError> {
    let results = match head_state {
        WriterHeadState::Verified(head) => {
            let results = append_receipt_batch(pool, head, incremental_verification, &requests);
            health.store_head_snapshot(head);
            results
        }
        WriterHeadState::Poisoned(message) => {
            receipt_batch_error_results(requests.len(), poisoned_head_error(message))
        }
    };
    let flush_error = results
        .iter()
        .find_map(|result| result.as_ref().err().map(receipt_store_error_snapshot));
    let committed = results.iter().filter(|result| result.is_ok()).count() as u64;
    let failed = results.iter().filter(|result| result.is_err()).count() as u64;
    if committed > 0 {
        health
            .committed_total
            .fetch_add(committed, Ordering::SeqCst);
        health
            .last_commit_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
    }
    if failed > 0 {
        health.failed_total.fetch_add(failed, Ordering::SeqCst);
    }
    atomic_saturating_sub(&health.inflight, results.len() as u64);
    if let Ok(mut last_error) = health.last_error.lock() {
        *last_error = flush_error.as_ref().map(ToString::to_string);
    }
    for (request, result) in requests.into_iter().zip(results) {
        let _ = request.response.send(result);
    }
    for response in flushes {
        let result = match &flush_error {
            Some(error) => Err(receipt_store_error_snapshot(error)),
            None => Ok(()),
        };
        let _ = response.send(result);
    }
    flush_error
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn atomic_saturating_sub(value: &AtomicU64, amount: u64) {
    let mut current = value.load(Ordering::SeqCst);
    loop {
        let next = current.saturating_sub(amount);
        match value.compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

/// Background checkpoint signer, installed once by the kernel after `open`
/// and before serving (RFC-0006 stage 4). `max_batch = 0` disables
/// checkpointing (ADR-0008 semantics).
#[derive(Clone)]
pub struct BackgroundCheckpointSigner {
    pub keypair: Arc<Keypair>,
    pub max_batch: u64,
}

/// Last verified position of the receipt chain. Owned exclusively by the
/// commit-actor thread; never shared, never locked (RFC-0006).
#[derive(Clone, Debug, Default)]
pub(crate) struct VerifiedHead {
    /// The newest checkpoint the actor has verified, already parsed and
    /// signature-checked once. `None` before the first checkpoint.
    latest_checkpoint: Option<KernelCheckpoint>,
    /// Row count of `claim_receipt_log_entries` as last verified.
    claim_log_count: u64,
    /// MAX(entry_seq) of `claim_receipt_log_entries` as last verified.
    claim_log_max_seq: u64,
}

impl VerifiedHead {
    pub(crate) fn checkpoint_seq(&self) -> u64 {
        self.latest_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.checkpoint_seq)
    }

    pub(crate) fn checkpointed_entry_seq(&self) -> u64 {
        self.latest_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq)
    }
}

/// Writer-actor head snapshot exposed to `flush_report` and diagnostics
/// (RFC-0006). Values are read from the health struct's atomics, written
/// only by the actor thread.
pub(crate) struct WriterHeadSnapshot {
    pub(crate) checkpoint_seq: u64,
    pub(crate) checkpointed_entry_seq: u64,
    // Read only by tests (`incremental_append_updates_the_head_and_stays_correct`,
    // `writer_routed_inserts_do_not_false_conflict_the_next_append`): they
    // cross-check the actor-maintained head against a full re-verification.
    // `flush_report` does not need the claim-log counters today.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) claim_log_count: u64,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) claim_log_max_seq: u64,
}

/// Seed the verified head by running the existing FULL verification exactly
/// once (the startup path for the O(N) check; also the audit-repair path).
fn seed_verified_head(connection: &Connection) -> Result<VerifiedHead, ReceiptStoreError> {
    validate_claim_receipt_log_entries(connection)?;
    let latest_checkpoint = verify_checkpoint_chain_integrity(connection)?;
    let (claim_log_count, claim_log_max_seq) = claim_log_delta_count_and_max_seq(connection, 0)?;
    Ok(VerifiedHead {
        latest_checkpoint,
        claim_log_count,
        claim_log_max_seq,
    })
}

/// Cheap head snapshot for `incremental_verification = false` stores: the
/// full per-append verification still runs on that path, so seeding only
/// parses the single latest checkpoint row (one signature check) plus two
/// aggregates. This keeps a suspect database openable for A/B verification.
fn seed_head_snapshot(connection: &Connection) -> Result<VerifiedHead, ReceiptStoreError> {
    let latest_checkpoint = load_latest_persisted_checkpoint_row(connection)?
        .map(parse_persisted_checkpoint_row)
        .transpose()?;
    let (claim_log_count, claim_log_max_seq) = claim_log_delta_count_and_max_seq(connection, 0)?;
    Ok(VerifiedHead {
        latest_checkpoint,
        claim_log_count,
        claim_log_max_seq,
    })
}

/// COUNT/MAX over `entry_seq > floor_entry_seq`: an indexed range scan over
/// the delta only (O(b)). An unscoped COUNT(*) would rescan the whole index
/// and reintroduce O(N). Returns `(delta_count, max_entry_seq)` where the max
/// falls back to `floor_entry_seq` for an empty delta.
fn claim_log_delta_count_and_max_seq(
    connection: &Connection,
    floor_entry_seq: u64,
) -> Result<(u64, u64), ReceiptStoreError> {
    let floor = sqlite_i64(floor_entry_seq, "claim log delta floor entry_seq")?;
    let (count, max_seq) = connection.query_row(
        "SELECT COUNT(*), COALESCE(MAX(entry_seq), ?1) FROM claim_receipt_log_entries WHERE entry_seq > ?1",
        params![floor],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    Ok((
        sqlite_u64(count, "claim log delta count")?,
        sqlite_u64(max_seq, "claim log delta max entry_seq")?,
    ))
}

/// O(1) predecessor check: the persisted latest checkpoint must still match
/// the verified head (one indexed row read + RFC 8785 canonical body digest
/// compare). When the persisted chain has moved FORWARD, verify only the new
/// checkpoints (bounded catch-up); every other divergence is a fail-closed
/// `Conflict` pointing at `chio receipt audit`.
fn verify_head_against_latest_checkpoint(
    connection: &Connection,
    head: &mut VerifiedHead,
) -> Result<(), ReceiptStoreError> {
    let persisted = load_latest_persisted_checkpoint_row(connection)?;
    let cached_seq = head.checkpoint_seq();
    match persisted {
        None if head.latest_checkpoint.is_none() => Ok(()),
        None => Err(ReceiptStoreError::Conflict(
            "latest checkpoint disappeared behind the verified head; run `chio receipt audit`"
                .to_string(),
        )),
        Some(row) if row.checkpoint_seq < cached_seq => Err(ReceiptStoreError::Conflict(format!(
            "checkpoint chain regressed from verified head {cached_seq} to {}; run `chio receipt audit`",
            row.checkpoint_seq
        ))),
        Some(row) if row.checkpoint_seq == cached_seq => {
            let Some(cached) = head.latest_checkpoint.as_ref() else {
                return Err(ReceiptStoreError::Conflict(
                    "checkpoint presence diverged from verified head; run `chio receipt audit`"
                        .to_string(),
                ));
            };
            // Body-only deserialize: parse_persisted_checkpoint_row would run
            // chio_kernel::checkpoint::validate_checkpoint and re-verify the
            // signature, putting one Ed25519 verify back on every append. The
            // cached head was signature-checked at seed time.
            let persisted_body: KernelCheckpointBody = serde_json::from_str(&row.statement_json)?;
            let persisted_digest = chio_kernel::checkpoint::checkpoint_body_sha256(&persisted_body)
                .map_err(checkpoint_error_to_receipt_store)?;
            let cached_digest = chio_kernel::checkpoint::checkpoint_body_sha256(&cached.body)
                .map_err(checkpoint_error_to_receipt_store)?;
            if persisted_digest == cached_digest {
                Ok(())
            } else {
                Err(ReceiptStoreError::Conflict(
                    "latest checkpoint diverged from verified head; run `chio receipt audit`"
                        .to_string(),
                ))
            }
        }
        Some(row) => catch_up_verified_head_to(connection, head, row.checkpoint_seq),
    }
}

/// Verify and adopt checkpoints `head.checkpoint_seq()+1 ..= latest_seq`.
/// O(new checkpoints): each row is parsed (one signature check), predecessor-
/// linked to the cached head, and range-checked against the claim log. Used
/// when another writer instance (second kernel on the same file, operator
/// CLI) legitimately extended the chain.
fn catch_up_verified_head_to(
    connection: &Connection,
    head: &mut VerifiedHead,
    latest_seq: u64,
) -> Result<(), ReceiptStoreError> {
    let mut cursor = head.checkpoint_seq();
    while cursor < latest_seq {
        let next_seq = cursor.saturating_add(1);
        let Some(row) = load_persisted_checkpoint_row(connection, next_seq)? else {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint chain gap at {next_seq} behind latest {latest_seq}; run `chio receipt audit`"
            )));
        };
        let checkpoint = parse_persisted_checkpoint_row(row)?;
        match head.latest_checkpoint.as_ref() {
            Some(predecessor) => {
                chio_kernel::checkpoint::validate_checkpoint_predecessor(predecessor, &checkpoint)
                    .map_err(checkpoint_error_to_receipt_store)?;
            }
            None => validate_checkpoint_base(&checkpoint)?,
        }
        validate_checkpoint_against_claim_log(connection, &checkpoint)?;
        head.latest_checkpoint = Some(checkpoint);
        cursor = next_seq;
    }
    Ok(())
}

fn append_receipt_batch(
    pool: &Pool<SqliteConnectionManager>,
    head: &mut VerifiedHead,
    incremental_verification: bool,
    requests: &[ReceiptCommitRequest],
) -> Vec<Result<u64, ReceiptStoreError>> {
    let mut connection = match pool.get() {
        Ok(connection) => connection,
        Err(error) => {
            return receipt_batch_error_results(
                requests.len(),
                ReceiptStoreError::Pool(error.to_string()),
            );
        }
    };
    if let Err(error) = ensure_checkpoint_transparency_guards(&connection) {
        return receipt_batch_error_results(requests.len(), error);
    }
    if incremental_verification {
        // O(1) predecessor check (+ bounded catch-up), not a chain rebuild.
        if let Err(error) = verify_head_against_latest_checkpoint(&connection, head) {
            return receipt_batch_error_results(requests.len(), error);
        }
    } else if let Err(error) = validate_claim_receipt_log_entries(&connection) {
        return receipt_batch_error_results(requests.len(), error);
    }
    let tx = match connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(error) => {
            return receipt_batch_error_results(requests.len(), ReceiptStoreError::Sqlite(error));
        }
    };
    if !incremental_verification {
        if let Err(error) = verify_latest_checkpoint_integrity(&tx) {
            return receipt_batch_error_results(requests.len(), error);
        }
    }
    // Baseline inside the IMMEDIATE tx: rows another store instance committed
    // since our last look are adopted as pre-existing, so the cross-check
    // below measures exactly what THIS batch inserted.
    let (pre_delta, baseline_max) =
        match claim_log_delta_count_and_max_seq(&tx, head.claim_log_max_seq) {
            Ok(pair) => pair,
            Err(error) => return receipt_batch_error_results(requests.len(), error),
        };
    let mut results = Vec::with_capacity(requests.len());
    for request in requests {
        #[cfg(test)]
        if test_hooks::panic_during_append_batch(&request.receipt.content_hash) {
            panic!("injected test panic during append batch");
        }
        match append_chio_receipt_tx(&tx, &request.receipt, &request.raw_json) {
            Ok(seq) => {
                if request.ensure_lineage {
                    #[cfg(test)]
                    if test_hooks::fail_between_receipt_and_lineage() {
                        return receipt_batch_error_results(
                            requests.len(),
                            ReceiptStoreError::Conflict(
                                "injected failure between receipt insert and lineage insert"
                                    .to_string(),
                            ),
                        );
                    }
                    if let Err(error) =
                        ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &request.receipt.id)
                    {
                        return receipt_batch_error_results(requests.len(), error);
                    }
                }
                results.push(Ok(seq));
            }
            Err(error) => return receipt_batch_error_results(requests.len(), error),
        }
    }
    // Idempotent duplicates return the existing entry_seq without adding a
    // projection row (append_chio_receipt_tx: ON CONFLICT(receipt_id) DO
    // NOTHING at receipt_store.rs:972, byte-identical duplicate branch at
    // :992-1011). Only entry_seqs beyond the baseline count as new rows.
    let inserted = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .filter(|seq| **seq > baseline_max)
        .count() as u64;
    // O(b) projection cross-check over the delta only: the claim-log
    // projection triggers (bootstrap/open.rs:676 tool, :711 child) must have
    // advanced the projection by exactly the rows this batch inserted.
    let (delta_count, post_max) = match claim_log_delta_count_and_max_seq(&tx, baseline_max) {
        Ok(pair) => pair,
        Err(error) => return receipt_batch_error_results(requests.len(), error),
    };
    if delta_count != inserted || post_max < baseline_max {
        return receipt_batch_error_results(
            requests.len(),
            ReceiptStoreError::Conflict(
                "claim receipt log projection drift on append; run `chio receipt audit`"
                    .to_string(),
            ),
        );
    }
    match tx.commit() {
        Ok(()) => {
            head.claim_log_count = head
                .claim_log_count
                .saturating_add(pre_delta)
                .saturating_add(delta_count);
            head.claim_log_max_seq = post_max.max(baseline_max);
            results
        }
        Err(error) => receipt_batch_error_results(requests.len(), ReceiptStoreError::Sqlite(error)),
    }
}

fn receipt_batch_error_results(
    count: usize,
    error: ReceiptStoreError,
) -> Vec<Result<u64, ReceiptStoreError>> {
    let snapshot = receipt_store_error_snapshot(&error);
    let mut original = Some(error);
    (0..count)
        .map(|_| {
            Err(original
                .take()
                .unwrap_or_else(|| receipt_store_error_snapshot(&snapshot)))
        })
        .collect()
}

fn receipt_store_error_snapshot(error: &ReceiptStoreError) -> ReceiptStoreError {
    match error {
        ReceiptStoreError::Sqlite(error) => {
            ReceiptStoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(
                std::io::Error::other(error.to_string()),
            )))
        }
        ReceiptStoreError::Pool(message) => ReceiptStoreError::Pool(message.clone()),
        ReceiptStoreError::Timeout {
            operation,
            timeout_ms,
        } => ReceiptStoreError::Timeout {
            operation: operation.clone(),
            timeout_ms: *timeout_ms,
        },
        ReceiptStoreError::Json(error) => ReceiptStoreError::Json(serde_json::Error::io(
            std::io::Error::other(error.to_string()),
        )),
        ReceiptStoreError::Io(error) => {
            ReceiptStoreError::Io(std::io::Error::new(error.kind(), error.to_string()))
        }
        ReceiptStoreError::CryptoDecode(message) => {
            ReceiptStoreError::CryptoDecode(message.clone())
        }
        ReceiptStoreError::Canonical(message) => ReceiptStoreError::Canonical(message.clone()),
        ReceiptStoreError::InvalidOutcome(message) => {
            ReceiptStoreError::InvalidOutcome(message.clone())
        }
        ReceiptStoreError::ReadBoundary(message) => {
            ReceiptStoreError::ReadBoundary(message.clone())
        }
        ReceiptStoreError::Conflict(message) => ReceiptStoreError::Conflict(message.clone()),
        ReceiptStoreError::NotFound(message) => ReceiptStoreError::NotFound(message.clone()),
    }
}

/// Convert a caught panic payload into a typed, fail-closed error. Panic
/// payloads are almost always `&'static str` (a `panic!("literal")`) or
/// `String` (a formatted `panic!("{}", ..)`); anything else degrades to a
/// generic message rather than unwrapping (house rule: no unwrap/expect in
/// non-test code).
fn receipt_writer_job_panic_error(payload: &(dyn std::any::Any + Send)) -> ReceiptStoreError {
    let message = payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string());
    ReceiptStoreError::Canonical(format!("receipt writer job panicked: {message}"))
}

/// Panic isolation (RFC-0006 whole-store-death fix): `commit_receipt_batch`
/// runs on the single writer thread, so a panic anywhere inside it (append
/// transaction, lineage fold) must not kill that thread. By the time this
/// runs, `requests` and `flushes` have already been moved into the
/// panicking call and dropped during unwind, so the pre-cloned response
/// senders are the only way left to answer every caller in the batch. This
/// mirrors `receipt_batch_error_results`'s uniform fan-out and the health
/// bookkeeping `commit_receipt_batch` would otherwise have performed itself.
fn fan_out_batch_panic_error(
    health: &ReceiptCommitWriterHealth,
    request_responses: Vec<mpsc::SyncSender<Result<u64, ReceiptStoreError>>>,
    flush_responses: Vec<mpsc::SyncSender<Result<(), ReceiptStoreError>>>,
    error: ReceiptStoreError,
) -> ReceiptStoreError {
    let batch_len = request_responses.len() as u64;
    health.failed_total.fetch_add(batch_len, Ordering::SeqCst);
    atomic_saturating_sub(&health.inflight, batch_len);
    if let Ok(mut last_error) = health.last_error.lock() {
        *last_error = Some(error.to_string());
    }
    for response in request_responses {
        let _ = response.send(Err(receipt_store_error_snapshot(&error)));
    }
    for response in flush_responses {
        let _ = response.send(Err(receipt_store_error_snapshot(&error)));
    }
    error
}

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// When set, `append_receipt_batch` fails the batch between the receipt
    /// insert and the lineage ensure, proving the fold is one transaction.
    pub(crate) static FAIL_BETWEEN_RECEIPT_AND_LINEAGE: AtomicBool = AtomicBool::new(false);

    pub(crate) fn fail_between_receipt_and_lineage() -> bool {
        FAIL_BETWEEN_RECEIPT_AND_LINEAGE.load(Ordering::SeqCst)
    }

    /// When set, `maybe_build_checkpoint` panics after computing the
    /// checkpoint body but before opening its write transaction, proving the
    /// background-checkpoint catch_unwind wrap keeps the writer actor alive
    /// and leaves `head.latest_checkpoint` unadvanced. Tests run in parallel
    /// within this binary and this flag is process-global, so the panic is
    /// additionally gated on `PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH`
    /// (a `max_batch` value no other test in this crate uses): a test whose
    /// signer does not use that exact batch size never panics, even if the
    /// flag happens to be `true` while it runs.
    pub(crate) static PANIC_DURING_CHECKPOINT_BUILD: AtomicBool = AtomicBool::new(false);

    pub(crate) const PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH: u64 = 5;

    pub(crate) fn panic_during_checkpoint_build(max_batch: u64) -> bool {
        max_batch == PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH
            && PANIC_DURING_CHECKPOINT_BUILD.load(Ordering::SeqCst)
    }

    /// When set, `append_receipt_batch` panics before inserting the next
    /// request in the batch, proving the append-batch catch_unwind wrap in
    /// `receipt_commit_actor_loop` keeps the writer actor alive and fans out
    /// a typed error to every request in the interrupted batch. Gated on a
    /// `content_hash` marker for the same cross-test isolation reason as
    /// `PANIC_DURING_CHECKPOINT_BUILD` above (this flag is process-global,
    /// and other tests append receipts concurrently in the same binary).
    /// `content_hash`, not `receipt.id`, is the marker: `ChioReceipt::sign`
    /// always overwrites `id` with a content-derived hash
    /// (`prepare_receipt_body_for_signing`), so a caller-chosen `id` string
    /// does not survive signing, but a caller-chosen `content_hash` does.
    pub(crate) static PANIC_DURING_APPEND_BATCH: AtomicBool = AtomicBool::new(false);

    pub(crate) const PANIC_DURING_APPEND_BATCH_MARKER_RECEIPT_ID: &str =
        "rcpt-test-hook-panic-during-append-batch";

    /// `sample_receipt_with_id(id)` sets `content_hash: format!("content-{id}")`;
    /// this must match that pattern for `PANIC_DURING_APPEND_BATCH_MARKER_RECEIPT_ID`.
    pub(crate) const PANIC_DURING_APPEND_BATCH_MARKER_CONTENT_HASH: &str =
        "content-rcpt-test-hook-panic-during-append-batch";

    pub(crate) fn panic_during_append_batch(content_hash: &str) -> bool {
        content_hash == PANIC_DURING_APPEND_BATCH_MARKER_CONTENT_HASH
            && PANIC_DURING_APPEND_BATCH.load(Ordering::SeqCst)
    }
}

#[path = "receipt_store/bootstrap.rs"]
mod bootstrap;
#[path = "receipt_store/evidence_retention.rs"]
mod evidence_retention;
#[path = "receipt_store/liability_claims.rs"]
mod liability_claims;
#[path = "receipt_store/liability_market.rs"]
mod liability_market;
#[path = "receipt_store/reports.rs"]
mod reports;
#[path = "receipt_store/support.rs"]
mod support;
#[cfg(test)]
#[path = "receipt_store/tests.rs"]
mod tests;
#[path = "receipt_store/underwriting_credit.rs"]
mod underwriting_credit;

use support::*;
pub(crate) use support::{decode_verified_child_receipt, decode_verified_chio_receipt, sqlite_u64};

impl SqliteReceiptStore {
    /// Reader-pool connection. READS ONLY: every write transaction must go
    /// through `writer_handle().run_write` (single-writer discipline,
    /// RFC-0006). The reader pool is asserted read-only by
    /// `reader_pool_never_begins_a_write_transaction` in tests.
    pub(crate) fn connection(&self) -> Result<SqliteStoreConnection, ReceiptStoreError> {
        self.pool
            .get()
            .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
    }

    pub(crate) fn writer_handle(&self) -> WriterHandle {
        WriterHandle {
            sender: self.receipt_commit_actor.sender.clone(),
            health: Arc::clone(&self.receipt_commit_actor.health),
        }
    }

    /// Multi-tenant receipt isolation: toggle strict-isolation
    /// mode on tenant-scoped queries.
    ///
    /// When `strict = true`, a `tenant_filter = Some(id)` query returns
    /// ONLY rows whose `tenant_id = id`. Pre-multitenant receipts with
    /// `tenant_id IS NULL` are excluded.
    ///
    /// When `strict = false`, the same query also includes rows where
    /// `tenant_id IS NULL` -- the pre-multitenant "public" fallback
    /// set -- so pre-multitenant (NULL-tagged) receipts remain visible during
    /// an explicit compatibility window.
    ///
    /// A `tenant_filter = None` admin / compat query always returns
    /// every row regardless of this setting.
    pub fn with_strict_tenant_isolation(&self, strict: bool) {
        self.strict_tenant_isolation
            .store(strict, std::sync::atomic::Ordering::SeqCst);
    }

    /// Read the current strict-tenant-isolation setting.
    #[must_use]
    pub fn strict_tenant_isolation_enabled(&self) -> bool {
        self.strict_tenant_isolation
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Read-only after open (RFC-0006 staged-rollout flag).
    #[must_use]
    pub fn incremental_verification_enabled(&self) -> bool {
        self.incremental_verification
    }

    pub(crate) fn writer_head_snapshot(&self) -> WriterHeadSnapshot {
        let health = &self.receipt_commit_actor.health;
        WriterHeadSnapshot {
            checkpoint_seq: health.head_checkpoint_seq.load(Ordering::SeqCst),
            checkpointed_entry_seq: health.head_checkpointed_entry_seq.load(Ordering::SeqCst),
            claim_log_count: health.head_claim_log_count.load(Ordering::SeqCst),
            claim_log_max_seq: health.head_claim_log_max_seq.load(Ordering::SeqCst),
        }
    }

    pub fn append_chio_receipt_canonical(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_canonical_returning_seq(canonical)
            .map(|_| ())
    }

    pub fn append_chio_receipt_canonical_bytes(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_canonical(canonical)
    }

    pub fn append_chio_receipt_canonical_returning_seq(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<u64, ReceiptStoreError> {
        let receipt = decode_canonical_chio_receipt(canonical.as_ref())?;
        let raw_json = canonical_receipt_json(canonical.as_ref())?;
        self.append_verified_chio_receipt_record(&receipt, raw_json, false)
    }

    pub fn append_chio_receipt_canonical_bytes_returning_seq(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<u64, ReceiptStoreError> {
        self.append_chio_receipt_canonical_returning_seq(canonical)
    }

    fn append_verified_chio_receipt_record(
        &self,
        receipt: &ChioReceipt,
        raw_json: &str,
        ensure_lineage: bool,
    ) -> Result<u64, ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        self.receipt_commit_actor
            .append(receipt.clone(), raw_json.to_string(), ensure_lineage)
    }

    pub fn append_chio_receipt_consuming_authorization(
        &self,
        receipt: &ChioReceipt,
        consumption: &AuthorizationReceiptConsumption,
    ) -> Result<(), ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        if receipt.id != consumption.consumer_receipt_id {
            return Err(ReceiptStoreError::Conflict(
                "authorization consumption consumer receipt id does not match appended receipt"
                    .to_string(),
            ));
        }
        if receipt.tenant_id.as_deref() != consumption.tenant_id.as_deref() {
            return Err(ReceiptStoreError::Conflict(
                "authorization consumption tenant id does not match appended receipt".to_string(),
            ));
        }
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        let raw_json = canonical_json_bytes(receipt)
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
        let raw_json = std::str::from_utf8(raw_json.as_slice()).map_err(|error| {
            ReceiptStoreError::Canonical(format!("canonical receipt bytes are not UTF-8: {error}"))
        })?;
        let raw_json = raw_json.to_string();
        let receipt = receipt.clone();
        let consumption = consumption.clone();
        self.writer_handle().run_write(move |connection| {
            ensure_checkpoint_transparency_guards(connection)?;
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            consume_authorization_receipt_tx(&tx, &consumption)?;
            append_chio_receipt_tx(&tx, &receipt, &raw_json)?;
            ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt.id)?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn flush_receipt_writes(&self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        self.receipt_commit_actor.flush()?;
        let wal_checkpoint = Some(self.wal_checkpoint_passive()?);
        self.flush_report(wal_checkpoint)
    }

    /// Rerun the one-time full verification on the writer connection and
    /// adopt the resulting head. This is the `chio receipt audit --repair`
    /// entry point; it is also safe to call on a healthy store.
    pub fn reseed_verified_head(&self) -> Result<(), ReceiptStoreError> {
        let (response, result) = mpsc::sync_channel(1);
        match self
            .receipt_commit_actor
            .sender
            .try_send(ReceiptCommitCommand::ReseedHead(response))
        {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => return Err(receipt_actor_saturated_error()),
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return Err(receipt_actor_unavailable_error());
            }
        }
        result
            .recv()
            .map_err(|_| receipt_actor_unavailable_error())?
    }

    /// Install the background checkpoint signer. Idempotent per store (a
    /// second call replaces the signer). Until called, the store appends
    /// without producing checkpoints.
    pub fn enable_background_checkpoints(
        &self,
        signer: BackgroundCheckpointSigner,
    ) -> Result<(), ReceiptStoreError> {
        match self
            .receipt_commit_actor
            .sender
            .try_send(ReceiptCommitCommand::InstallSigner(signer))
        {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => Err(receipt_actor_saturated_error()),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(receipt_actor_unavailable_error()),
        }
    }

    pub fn flush_receipt_writes_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        self.receipt_commit_actor.flush_with_timeout(timeout)?;
        let wal_checkpoint = Some(self.wal_checkpoint_passive()?);
        self.flush_report(wal_checkpoint)
    }

    pub fn receipt_store_health(&self) -> Result<ReceiptStoreHealthReport, ReceiptStoreError> {
        self.validate_claim_receipt_log_projection_current()?;
        let status = self.receipt_checkpoint_status(Some(1))?;
        if status.latest_committed_entry_seq > status.latest_checkpointed_entry_seq {
            let connection = self.connection()?;
            let start_seq = status.latest_checkpointed_entry_seq + 1;
            load_claim_tree_canonical_bytes_range(
                &connection,
                start_seq,
                status.latest_committed_entry_seq,
            )?;
        }
        let healthy = status.healthy
            && self
                .receipt_commit_actor
                .writer_counters()
                .last_error
                .is_none();
        let (uncheckpointed_start_seq, uncheckpointed_end_seq) = uncheckpointed_range(
            status.latest_checkpointed_entry_seq,
            status.latest_committed_entry_seq,
        );
        Ok(ReceiptStoreHealthReport {
            healthy,
            writer: self.receipt_commit_actor.writer_counters(),
            latest_committed_entry_seq: status.latest_committed_entry_seq,
            latest_checkpoint_seq: status.latest_checkpoint_seq,
            latest_checkpointed_entry_seq: status.latest_checkpointed_entry_seq,
            uncheckpointed_start_seq,
            uncheckpointed_end_seq,
            checkpoint_error: status.checkpoint_error,
            db_size_bytes: self.db_size_bytes().ok(),
        })
    }

    pub fn latest_committed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        latest_claim_log_entry_seq(&connection)
    }

    pub fn latest_checkpointed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        latest_checkpointed_entry_seq(&connection)
    }

    pub fn next_checkpoint_range(
        &self,
        max_batch: u64,
    ) -> Result<Option<ReceiptCheckpointRange>, ReceiptStoreError> {
        let connection = self.connection()?;
        next_checkpoint_range_for_connection(&connection, max_batch)
    }

    pub fn receipt_checkpoint_status(
        &self,
        max_batch: Option<u64>,
    ) -> Result<ReceiptCheckpointStatusReport, ReceiptStoreError> {
        self.validate_claim_receipt_log_projection_current()?;
        let connection = self.connection()?;
        let latest_committed_entry_seq = latest_claim_log_entry_seq(&connection)?;
        match verify_checkpoint_chain_integrity(&connection) {
            Ok(latest) => {
                let latest_checkpoint_seq = latest
                    .as_ref()
                    .map(|checkpoint| checkpoint.body.checkpoint_seq);
                let latest_checkpointed_entry_seq = latest
                    .as_ref()
                    .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
                if latest_committed_entry_seq > latest_checkpointed_entry_seq {
                    let start_seq = latest_checkpointed_entry_seq + 1;
                    if let Err(error) = ensure_claim_log_range_contiguous(
                        &connection,
                        start_seq,
                        latest_committed_entry_seq,
                        "uncheckpointed range",
                    ) {
                        return Ok(ReceiptCheckpointStatusReport {
                            healthy: false,
                            latest_committed_entry_seq,
                            latest_checkpoint_seq,
                            latest_checkpointed_entry_seq,
                            next_range: None,
                            checkpoint_error: Some(error.to_string()),
                        });
                    }
                }
                let next_range = match max_batch {
                    Some(max_batch) => {
                        next_checkpoint_range_for_connection(&connection, max_batch)?
                    }
                    None => None,
                };
                Ok(ReceiptCheckpointStatusReport {
                    healthy: true,
                    latest_committed_entry_seq,
                    latest_checkpoint_seq,
                    latest_checkpointed_entry_seq,
                    next_range,
                    checkpoint_error: None,
                })
            }
            Err(error) => Ok(ReceiptCheckpointStatusReport {
                healthy: false,
                latest_committed_entry_seq,
                latest_checkpoint_seq: None,
                latest_checkpointed_entry_seq: 0,
                next_range: None,
                checkpoint_error: Some(error.to_string()),
            }),
        }
    }

    pub fn create_next_receipt_checkpoint(
        &self,
        max_batch: u64,
        keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        let keypair = keypair.clone();
        self.writer_handle().run_write(move |connection| {
            validate_claim_receipt_log_entries(connection)?;
            create_next_receipt_checkpoint_atomic(connection, max_batch, &keypair)
        })
    }

    fn flush_report(
        &self,
        wal_checkpoint: Option<ReceiptWalCheckpointReport>,
    ) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        let head = self.writer_head_snapshot();
        let latest_committed_entry_seq = self.latest_committed_entry_seq()?;
        let latest_checkpoint_seq = (head.checkpoint_seq > 0).then_some(head.checkpoint_seq);
        let latest_checkpointed_entry_seq = head.checkpointed_entry_seq;
        let (uncheckpointed_start_seq, uncheckpointed_end_seq) =
            uncheckpointed_range(latest_checkpointed_entry_seq, latest_committed_entry_seq);
        Ok(ReceiptFlushReport {
            writer: self.receipt_commit_actor.writer_counters(),
            latest_committed_entry_seq,
            latest_checkpoint_seq,
            latest_checkpointed_entry_seq,
            uncheckpointed_start_seq,
            uncheckpointed_end_seq,
            wal_checkpoint,
            db_size_bytes: self.db_size_bytes().ok(),
        })
    }

    fn validate_claim_receipt_log_projection_current(&self) -> Result<(), ReceiptStoreError> {
        let connection = self.connection()?;
        validate_claim_receipt_log_entries(&connection)
    }

    fn wal_checkpoint_passive(&self) -> Result<ReceiptWalCheckpointReport, ReceiptStoreError> {
        let connection = self.connection()?;
        let (busy, log_frames, checkpointed_frames) =
            connection.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
        Ok(ReceiptWalCheckpointReport {
            busy: sqlite_u64(busy, "wal checkpoint busy")?,
            log_frames: wal_checkpoint_frame_count(log_frames, "wal checkpoint log frames")?,
            checkpointed_frames: wal_checkpoint_frame_count(
                checkpointed_frames,
                "wal checkpointed frames",
            )?,
        })
    }
}

/// `PRAGMA wal_checkpoint` reports -1 for the log/checkpointed frame columns
/// when there is nothing to checkpoint (an already-empty WAL). Under
/// concurrent `flush_receipt_writes()` callers this is routine: one caller's
/// PASSIVE checkpoint truncates the WAL, and a second caller racing right
/// behind it observes the now-empty WAL and gets -1/-1 from SQLite even
/// though `busy` is 0 (success). That is success-with-nothing-to-do, not an
/// error, so it is normalized to 0 rather than rejected by `sqlite_u64`.
fn wal_checkpoint_frame_count(value: i64, field: &str) -> Result<u64, ReceiptStoreError> {
    if value == -1 {
        return Ok(0);
    }
    sqlite_u64(value, field)
}

fn uncheckpointed_range(checkpointed: u64, committed: u64) -> (Option<u64>, Option<u64>) {
    if committed > checkpointed {
        (Some(checkpointed + 1), Some(committed))
    } else {
        (None, None)
    }
}

fn latest_claim_log_entry_seq(connection: &Connection) -> Result<u64, ReceiptStoreError> {
    connection
        .query_row(
            "SELECT COALESCE(MAX(entry_seq), 0) FROM claim_receipt_log_entries",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(ReceiptStoreError::from)
        .and_then(|value| sqlite_u64(value, "latest claim receipt log entry_seq"))
}

fn latest_checkpointed_entry_seq(connection: &Connection) -> Result<u64, ReceiptStoreError> {
    verify_checkpoint_chain_integrity(connection)
        .map(|latest| latest.map_or(0, |checkpoint| checkpoint.body.batch_end_seq))
}

fn next_checkpoint_range_for_connection(
    connection: &Connection,
    max_batch: u64,
) -> Result<Option<ReceiptCheckpointRange>, ReceiptStoreError> {
    if max_batch == 0 {
        return Err(ReceiptStoreError::Conflict(
            "checkpoint max_batch must be greater than zero".to_string(),
        ));
    }
    let latest_committed = latest_claim_log_entry_seq(connection)?;
    let latest_checkpointed = latest_checkpointed_entry_seq(connection)?;
    if latest_committed <= latest_checkpointed {
        return Ok(None);
    }
    let start_seq = latest_checkpointed + 1;
    let end_seq = latest_committed.min(start_seq.saturating_add(max_batch - 1));
    ensure_claim_log_range_contiguous(connection, start_seq, end_seq, "checkpoint range")?;
    Ok(Some(ReceiptCheckpointRange { start_seq, end_seq }))
}

fn ensure_claim_log_range_contiguous(
    connection: &Connection,
    start_seq: u64,
    end_seq: u64,
    context: &str,
) -> Result<(), ReceiptStoreError> {
    if end_seq < start_seq {
        return Err(ReceiptStoreError::Conflict(format!(
            "claim receipt log {context} end {end_seq} is before start {start_seq}"
        )));
    }
    let (count, min_seq, max_seq) = connection.query_row(
        r#"
        SELECT COUNT(*), MIN(entry_seq), MAX(entry_seq)
        FROM claim_receipt_log_entries
        WHERE entry_seq >= ?1 AND entry_seq <= ?2
        "#,
        params![
            sqlite_i64(start_seq, "claim log range start_seq")?,
            sqlite_i64(end_seq, "claim log range end_seq")?,
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        },
    )?;
    let expected = end_seq - start_seq + 1;
    let count = sqlite_u64(count, "claim receipt log range count")?;
    let min_seq = min_seq
        .map(|value| sqlite_u64(value, "claim receipt log range min_seq"))
        .transpose()?;
    let max_seq = max_seq
        .map(|value| sqlite_u64(value, "claim receipt log range max_seq"))
        .transpose()?;
    if count != expected || min_seq != Some(start_seq) || max_seq != Some(end_seq) {
        return Err(ReceiptStoreError::Conflict(format!(
            "claim receipt log has a gap in {context} {start_seq}..={end_seq}"
        )));
    }
    Ok(())
}

fn claim_log_entry_seq_for_source_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt_kind: &str,
    source_seq: u64,
) -> Result<u64, ReceiptStoreError> {
    let source_seq_i64 = sqlite_i64(source_seq, "claim receipt source_seq")?;
    let (entry_seq, log_receipt_id, log_raw_json, source_receipt_id, source_raw_json) =
        match receipt_kind {
            "tool_receipt" => tx.query_row(
                r#"
                SELECT l.entry_seq, l.receipt_id, l.raw_json, r.receipt_id, r.raw_json
                FROM claim_receipt_log_entries l
                JOIN chio_tool_receipts r ON r.seq = l.source_seq
                WHERE l.receipt_kind = ?1 AND l.source_seq = ?2
                "#,
                params![receipt_kind, source_seq_i64],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            ),
            "child_receipt" => tx.query_row(
                r#"
                SELECT l.entry_seq, l.receipt_id, l.raw_json, r.receipt_id, r.raw_json
                FROM claim_receipt_log_entries l
                JOIN chio_child_receipts r ON r.seq = l.source_seq
                WHERE l.receipt_kind = ?1 AND l.source_seq = ?2
                "#,
                params![receipt_kind, source_seq_i64],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            ),
            other => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "unsupported claim receipt log kind `{other}`"
                )));
            }
        }
        .optional()?
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(format!(
                "claim receipt log entry missing for {receipt_kind} source seq {source_seq}"
            ))
        })?;
    if log_receipt_id != source_receipt_id || log_raw_json != source_raw_json {
        return Err(ReceiptStoreError::Conflict(format!(
            "claim receipt log entry for {receipt_kind} source seq {source_seq} diverges from source row"
        )));
    }
    sqlite_positive_u64(entry_seq, "claim receipt log entry_seq")
}

fn append_chio_receipt_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt: &ChioReceipt,
    raw_json: &str,
) -> Result<u64, ReceiptStoreError> {
    let attribution = extract_receipt_attribution(receipt);
    let mut subject_key = attribution.subject_key;
    let mut issuer_key = attribution.issuer_key;
    if subject_key.is_none() || issuer_key.is_none() {
        if let Some((lineage_subject_key, lineage_issuer_key)) = tx
            .query_row(
                "SELECT subject_key, issuer_key FROM capability_lineage WHERE capability_id = ?1",
                params![receipt.capability_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                    ))
                },
            )
            .optional()?
        {
            if subject_key.is_none() {
                subject_key = lineage_subject_key;
            }
            if issuer_key.is_none() {
                issuer_key = lineage_issuer_key;
            }
        }
    }
    let source_seq = tx
        .query_row(
            r#"
        INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, subject_key, issuer_key, grant_index, tool_server, tool_name, decision_kind, policy_hash, content_hash, tenant_id, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(receipt_id) DO NOTHING RETURNING seq
        "#,
            params![
                receipt.id.as_str(),
                sqlite_i64(receipt.timestamp, "receipt timestamp")?,
                receipt.capability_id.as_str(),
                subject_key,
                issuer_key,
                attribution.grant_index.map(i64::from),
                receipt.tool_server.as_str(),
                receipt.tool_name.as_str(),
                receipt_decision_kind(receipt),
                receipt.policy_hash.as_str(),
                receipt.content_hash.as_str(),
                receipt.tenant_id.as_deref(),
                raw_json,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(source_seq) = source_seq else {
        let (existing_source_seq, existing_raw_json) = tx.query_row(
            "SELECT seq, raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
            params![receipt.id.as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;
        let existing_source_seq =
            sqlite_positive_u64(existing_source_seq, "tool receipt source_seq")?;
        if existing_raw_json != raw_json {
            return Err(ReceiptStoreError::Conflict(format!(
                "tool receipt `{}` already exists with different content",
                receipt.id
            )));
        }
        decode_verified_chio_receipt(
            &existing_raw_json,
            "persisted duplicate tool receipt",
            Some(existing_source_seq),
        )?;
        return claim_log_entry_seq_for_source_tx(tx, "tool_receipt", existing_source_seq);
    };
    let source_seq = sqlite_positive_u64(source_seq, "tool receipt source_seq")?;
    claim_log_entry_seq_for_source_tx(tx, "tool_receipt", source_seq)
}

fn consume_authorization_receipt_tx(
    tx: &rusqlite::Transaction<'_>,
    consumption: &AuthorizationReceiptConsumption,
) -> Result<(), ReceiptStoreError> {
    if consumption.authorization_receipt_id.trim().is_empty()
        || consumption.consumer_receipt_id.trim().is_empty()
        || consumption.request_id.trim().is_empty()
        || consumption.session_id.trim().is_empty()
        || consumption.tool_call_id.trim().is_empty()
        || consumption.parameter_hash.trim().is_empty()
    {
        return Err(ReceiptStoreError::Conflict(
            "authorization receipt consumption requires non-empty binding fields".to_string(),
        ));
    }
    // Tenant id may be `None` for non-enterprise / single-tenant deployments,
    // but if it is `Some(_)` it must not be an empty / whitespace-only string.
    if matches!(&consumption.tenant_id, Some(tenant) if tenant.trim().is_empty()) {
        return Err(ReceiptStoreError::Conflict(
            "authorization receipt consumption tenant id must not be empty when present"
                .to_string(),
        ));
    }
    let consumed_at = sqlite_i64(
        consumption.consumed_at_unix_ms,
        "authorization receipt consumed_at_unix_ms",
    )?;
    let authorization_tenant = tx
        .query_row(
            "SELECT tenant_id FROM chio_tool_receipts WHERE receipt_id = ?1",
            params![consumption.authorization_receipt_id.as_str()],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .ok_or_else(|| {
            ReceiptStoreError::NotFound(format!(
                "authorization receipt {} was not found",
                consumption.authorization_receipt_id
            ))
        })?;
    if authorization_tenant.as_deref() != consumption.tenant_id.as_deref() {
        return Err(ReceiptStoreError::Conflict(
            "authorization receipt tenant id does not match consumption tenant".to_string(),
        ));
    }
    match tx.execute(
        r#"
        INSERT INTO chio_authorization_receipt_consumptions (
            authorization_receipt_id,
            consumer_receipt_id,
            request_id,
            session_id,
            tool_call_id,
            tenant_id,
            parameter_hash,
            consumed_at_unix_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
        params![
            consumption.authorization_receipt_id.as_str(),
            consumption.consumer_receipt_id.as_str(),
            consumption.request_id.as_str(),
            consumption.session_id.as_str(),
            consumption.tool_call_id.as_str(),
            consumption.tenant_id.as_deref(),
            consumption.parameter_hash.as_str(),
            consumed_at,
        ],
    ) {
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::ConstraintViolation)
            ) =>
        {
            Err(ReceiptStoreError::Conflict(
                "authorization receipt already consumed".to_string(),
            ))
        }
        Err(error) => Err(ReceiptStoreError::Sqlite(error)),
    }
}

fn decode_canonical_chio_receipt(
    canonical: &CanonicalBytes,
) -> Result<ChioReceipt, ReceiptStoreError> {
    let receipt: ChioReceipt =
        serde_json::from_slice(canonical.as_bytes()).map_err(ReceiptStoreError::from)?;
    let expected = canonical_json_bytes(&receipt)
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    if expected.as_slice() != canonical.as_bytes() {
        return Err(ReceiptStoreError::Canonical(
            "canonical receipt bytes do not match ChioReceipt serialization".to_string(),
        ));
    }
    Ok(receipt)
}

fn canonical_receipt_json(canonical: &CanonicalBytes) -> Result<&str, ReceiptStoreError> {
    std::str::from_utf8(canonical.as_bytes()).map_err(|error| {
        ReceiptStoreError::Canonical(format!("canonical receipt bytes are not UTF-8: {error}"))
    })
}

#[cfg(test)]
mod receipt_commit_actor_tests {
    use super::*;

    fn actor_test_receipt() -> Result<ChioReceipt, ReceiptStoreError> {
        let keypair = chio_core::crypto::Keypair::generate();
        ChioReceipt::sign(
            chio_core::receipt::body::ChioReceiptBody {
                id: "rcpt-actor-test".to_string(),
                timestamp: 1,
                capability_id: "cap-actor".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: chio_core::receipt::decision::ToolCallAction::from_parameters(
                    serde_json::json!({}),
                )
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?,
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "content".to_string(),
                policy_hash: "policy".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .map_err(|error| ReceiptStoreError::CryptoDecode(error.to_string()))
    }

    #[test]
    fn receipt_commit_actor_channel_has_fixed_capacity() -> Result<(), Box<dyn std::error::Error>> {
        let (sender, _receiver) = receipt_commit_channel();
        for _ in 0..RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY {
            let (response, _result) = mpsc::sync_channel(1);
            sender.try_send(ReceiptCommitCommand::Flush(response))?;
        }

        let (response, _result) = mpsc::sync_channel(1);
        match sender.try_send(ReceiptCommitCommand::Flush(response)) {
            Err(mpsc::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(_)) => {
                Err("commit actor channel disconnected unexpectedly".into())
            }
            Ok(()) => Err("commit actor channel accepted beyond fixed capacity".into()),
        }
    }

    #[test]
    fn receipt_commit_actor_append_fails_closed_when_queue_is_full(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        for _ in 0..RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY {
            let (response, _result) = mpsc::sync_channel(1);
            sender.try_send(ReceiptCommitCommand::Flush(response))?;
        }
        let actor = ReceiptCommitActor { sender, health };

        let error = actor.append(actor_test_receipt()?, "{}".to_string(), false);

        assert!(error
            .err()
            .ok_or("expected queue saturation error")?
            .to_string()
            .contains("sqlite receipt commit queue saturated"));
        Ok(())
    }

    #[test]
    fn receipt_commit_actor_flush_honors_timeout() -> Result<(), Box<dyn std::error::Error>> {
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let actor = ReceiptCommitActor { sender, health };

        let error = actor.flush_with_timeout(Duration::from_millis(1));

        match error.err().ok_or("expected flush timeout error")? {
            ReceiptStoreError::Timeout {
                operation,
                timeout_ms,
            } => {
                assert_eq!(operation, "sqlite receipt commit flush");
                assert_eq!(timeout_ms, 1);
            }
            other => {
                return Err(
                    std::io::Error::other(format!("expected timeout error, got {other}")).into(),
                );
            }
        }
        Ok(())
    }

    #[test]
    fn run_write_executes_jobs_serially_on_the_writer_thread(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "chio-run-write-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let store = SqliteReceiptStore::open(&path)?;
        let writer = store.writer_handle();

        let first_thread = writer.run_write(|_connection| Ok(std::thread::current().id()))?;
        let second_thread = writer.run_write(|_connection| Ok(std::thread::current().id()))?;

        assert_eq!(
            first_thread, second_thread,
            "all write jobs must run on the single writer thread"
        );
        assert_ne!(
            first_thread,
            std::thread::current().id(),
            "write jobs must not run on the caller thread"
        );

        // The closure really gets a usable writer connection.
        let journal_mode = writer.run_write(|connection| {
            connection
                .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .map_err(ReceiptStoreError::from)
        })?;
        assert!(journal_mode.eq_ignore_ascii_case("wal"));

        // Inflight accounting drains back to zero after the jobs complete.
        assert_eq!(
            store
                .receipt_commit_actor
                .health
                .inflight
                .load(Ordering::SeqCst),
            0
        );

        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn run_write_fails_closed_when_queue_is_full() -> Result<(), Box<dyn std::error::Error>> {
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        for _ in 0..RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY {
            let (response, _result) = mpsc::sync_channel(1);
            sender.try_send(ReceiptCommitCommand::Flush(response))?;
        }
        let handle = WriterHandle {
            sender,
            health: Arc::clone(&health),
        };

        let error = handle.run_write(|_connection| Ok(()));

        assert!(error
            .err()
            .ok_or("expected queue saturation error")?
            .to_string()
            .contains("sqlite receipt commit queue saturated"));
        assert_eq!(
            health.inflight.load(Ordering::SeqCst),
            0,
            "speculative inflight increment must be undone on saturation"
        );
        assert_eq!(health.saturated_total.load(Ordering::SeqCst), 1);
        Ok(())
    }
}
