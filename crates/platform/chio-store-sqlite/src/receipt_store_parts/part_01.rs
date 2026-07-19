use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::{canonical_json_bytes, CanonicalBytes};
use chio_core::capability::{scope::ChioScope, token::CapabilityToken};
use chio_core::crypto::{sha256_hex, Keypair, Signature, SigningBackend};
use chio_core::receipt::security::ActiveDefenseReceiptBody;
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
    FederatedEvidenceShareImport, FederatedEvidenceShareSummary, IndexedSecurityEvidenceStore,
    LiabilityAutoBindDisposition, LiabilityClaimPayoutReconciliationState,
    LiabilityClaimResponseDisposition, LiabilityClaimSettlementReconciliationState,
    LiabilityClaimWorkflowQuery, LiabilityClaimWorkflowReport, LiabilityClaimWorkflowRow,
    LiabilityClaimWorkflowSummary, LiabilityMarketWorkflowQuery, LiabilityMarketWorkflowReport,
    LiabilityMarketWorkflowRow, LiabilityMarketWorkflowSummary, LiabilityProviderLifecycleState,
    LiabilityProviderListQuery, LiabilityProviderListReport, LiabilityProviderListSummary,
    LiabilityProviderResolutionQuery, LiabilityProviderResolutionReport, LiabilityProviderRow,
    LiabilityQuoteDisposition, ReceiptCheckpointCreateReport, ReceiptCheckpointRange,
    ReceiptCheckpointStatusReport, ReceiptFlushReport, ReceiptStore, ReceiptStoreError,
    ReceiptStoreHealthReport, ReceiptWalCheckpointReport, ReceiptWriterCounters, RetentionConfig,
    SignedCreditBond, SignedCreditFacility, SignedCreditLossLifecycle,
    SignedLiabilityAutoBindDecision, SignedLiabilityBoundCoverage,
    SignedLiabilityClaimAdjudication, SignedLiabilityClaimDispute, SignedLiabilityClaimPackage,
    SignedLiabilityClaimPayoutInstruction, SignedLiabilityClaimPayoutReceipt,
    SignedLiabilityClaimResponse, SignedLiabilityClaimSettlementInstruction,
    SignedLiabilityClaimSettlementReceipt, SignedLiabilityPlacement,
    SignedLiabilityPricingAuthority, SignedLiabilityProvider, SignedLiabilityQuoteRequest,
    SignedLiabilityQuoteResponse, SignedUnderwritingDecision, StoredChildReceipt,
    StoredToolReceipt, UnderwritingAppealCreateRequest, UnderwritingAppealRecord,
    UnderwritingAppealResolution, UnderwritingAppealResolveRequest, UnderwritingAppealStatus,
    UnderwritingDecisionLifecycleState, UnderwritingDecisionListReport,
    UnderwritingDecisionOutcome, UnderwritingDecisionQuery, UnderwritingDecisionRow,
    UnderwritingDecisionSummary, CREDIT_BOND_LIST_REPORT_SCHEMA,
    CREDIT_FACILITY_LIST_REPORT_SCHEMA, CREDIT_LOSS_LIFECYCLE_LIST_REPORT_SCHEMA,
    LIABILITY_CLAIM_WORKFLOW_REPORT_SCHEMA, LIABILITY_MARKET_WORKFLOW_REPORT_SCHEMA,
    LIABILITY_PROVIDER_LIST_REPORT_SCHEMA, LIABILITY_PROVIDER_RESOLUTION_REPORT_SCHEMA,
};
use chio_security_types::ports::OpaqueReceiptRef;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension};

struct ReceiptDatabaseIdentityFile {
    file: File,
    parent: File,
    path: PathBuf,
    identity: chio_core::Hash,
}

impl ReceiptDatabaseIdentityFile {
    fn open(path: &Path, create_if_missing: bool) -> Result<Self, ReceiptStoreError> {
        let path = resolve_receipt_database_path(path)?;
        let parent = open_trusted_receipt_database_parent(&path)?;
        #[cfg(unix)]
        let file = open_receipt_database_file_at(&parent, &path, create_if_missing);
        #[cfg(not(unix))]
        let file = {
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create(create_if_missing)
                .truncate(false);
            options.open(&path)
        };
        let file = file.map_err(|error| {
            if !create_if_missing && error.kind() == std::io::ErrorKind::NotFound {
                ReceiptStoreError::NotFound(format!(
                    "receipt database {} does not exist",
                    path.display()
                ))
            } else {
                ReceiptStoreError::Io(error)
            }
        })?;
        let identity = receipt_database_identity(&file, &path)?;
        let opened = Self {
            file,
            parent,
            path,
            identity,
        };
        opened.validate()?;
        Ok(opened)
    }

    fn validate_path_binding(&self, path: &Path) -> Result<(), ReceiptStoreError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let current_parent = open_trusted_receipt_database_parent(path)?;
            let retained_parent = self.parent.metadata()?;
            let current_parent = current_parent.metadata()?;
            if retained_parent.dev() != current_parent.dev()
                || retained_parent.ino() != current_parent.ino()
            {
                return Err(ReceiptStoreError::Conflict(
                    "receipt database parent changed after its descriptor was retained".to_string(),
                ));
            }
        }
        let path_metadata = fs::symlink_metadata(path)?;
        let file_metadata = self.file.metadata()?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.file_type().is_file()
            || !file_metadata.file_type().is_file()
        {
            return Err(ReceiptStoreError::Conflict(
                "receipt database descriptor must remain bound to a regular file".to_string(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            if path_metadata.dev() != file_metadata.dev()
                || path_metadata.ino() != file_metadata.ino()
                || file_metadata.nlink() != 1
            {
                return Err(ReceiptStoreError::Conflict(
                    "receipt database descriptor identity changed or is hard-linked".to_string(),
                ));
            }
            validate_trusted_receipt_database_file(&self.file, &file_metadata)?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ReceiptStoreError> {
        self.validate_path_binding(&self.path)
    }

    #[must_use]
    fn identity(&self) -> chio_core::Hash {
        self.identity
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn reject_volatile_receipt_database_path(path: &Path) -> Result<(), ReceiptStoreError> {
    let path_text = path.to_string_lossy();
    if path_text == ":memory:" || path_text.to_ascii_lowercase().starts_with("file:") {
        return Err(ReceiptStoreError::Conflict(
            "receipt storage must be backed by a durable filesystem path".to_string(),
        ));
    }
    if !path.is_absolute() {
        return Err(ReceiptStoreError::Conflict(
            "receipt database path must be absolute".to_string(),
        ));
    }
    Ok(())
}

fn resolve_receipt_database_path(path: &Path) -> Result<PathBuf, ReceiptStoreError> {
    reject_volatile_receipt_database_path(path)?;
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(ReceiptStoreError::Conflict(
            "receipt database path must not contain dot components".to_string(),
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(
                "receipt database path must have a parent directory".to_string(),
            )
        })?;
    let file_name = path.file_name().ok_or_else(|| {
        ReceiptStoreError::Conflict("receipt database path has no file name".to_string())
    })?;
    let resolved_parent = fs::canonicalize(parent)?;
    Ok(resolved_parent.join(file_name))
}

fn open_trusted_receipt_database_parent(path: &Path) -> Result<File, ReceiptStoreError> {
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(
                "receipt database path must have a parent directory".to_string(),
            )
        })?;
    #[cfg(unix)]
    {
        open_trusted_receipt_unix_directory_chain(parent_path)
    }
    #[cfg(not(unix))]
    {
        let path_metadata = fs::symlink_metadata(parent_path)?;
        let parent = std::fs::OpenOptions::new().read(true).open(parent_path)?;
        let descriptor_metadata = parent.metadata()?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.file_type().is_dir()
            || !descriptor_metadata.file_type().is_dir()
        {
            return Err(ReceiptStoreError::Conflict(
                "receipt database parent must be a stable directory".to_string(),
            ));
        }
        Ok(parent)
    }
}

#[cfg(unix)]
fn open_trusted_receipt_unix_directory_chain(
    parent_path: &Path,
) -> Result<File, ReceiptStoreError> {
    let mut names = Vec::new();
    for component in parent_path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => names.push(name.to_os_string()),
            std::path::Component::Prefix(_) => {
                return Err(ReceiptStoreError::Conflict(
                    "receipt database path has an unsupported prefix".to_string(),
                ));
            }
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err(ReceiptStoreError::Conflict(
                    "receipt database path must not contain dot components".to_string(),
                ));
            }
        }
    }

    let effective_uid = rustix::process::geteuid().as_raw();
    let root = rustix::fs::open(
        "/",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| ReceiptStoreError::Io(error.into()))?;
    let mut directory = File::from(root);
    validate_trusted_receipt_parent_security(&directory, effective_uid, !names.is_empty())?;
    let name_count = names.len();
    for (index, name) in names.into_iter().enumerate() {
        let descriptor = rustix::fs::openat(
            &directory,
            &name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| ReceiptStoreError::Io(error.into()))?;
        let next = File::from(descriptor);
        let metadata = next.metadata()?;
        if !metadata.file_type().is_dir() {
            return Err(ReceiptStoreError::Conflict(
                "receipt database ancestor is not a directory".to_string(),
            ));
        }
        validate_trusted_receipt_parent_security(&next, effective_uid, index + 1 != name_count)?;
        directory = next;
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_receipt_database_file_at(
    parent: &File,
    path: &Path,
    create_if_missing: bool,
) -> std::io::Result<File> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "receipt database path has no file name",
        )
    })?;
    let mut flags =
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    if create_if_missing {
        flags |= rustix::fs::OFlags::CREATE;
    }
    rustix::fs::openat(
        parent,
        file_name,
        flags,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map(File::from)
    .map_err(Into::into)
}

#[cfg(unix)]
fn validate_trusted_receipt_parent_security(
    directory: &File,
    effective_uid: u32,
    allow_sticky_write: bool,
) -> Result<(), ReceiptStoreError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = directory.metadata()?;
    let trusted_owner = metadata.uid() == effective_uid || metadata.uid() == 0;
    let group_or_world_writable = metadata.mode() & 0o022 != 0;
    let sticky = metadata.mode() & 0o1000 != 0;
    if !trusted_owner
        || (group_or_world_writable && !(allow_sticky_write && sticky))
        || receipt_file_grants_extended_acl_authority(directory)?
    {
        return Err(ReceiptStoreError::Conflict(
            "receipt database parent must have trusted ownership and grant no untrusted write authority"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_receipt_database_file(
    file: &File,
    metadata: &fs::Metadata,
) -> Result<(), ReceiptStoreError> {
    use std::os::unix::fs::MetadataExt;

    let effective_uid = rustix::process::geteuid().as_raw();
    if (metadata.uid() != effective_uid && metadata.uid() != 0)
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || receipt_file_grants_extended_acl_authority(file)?
    {
        return Err(ReceiptStoreError::Conflict(
            "receipt database file must have trusted ownership, mode 0600 or stricter, no authority-granting ACL, and one hard link"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn receipt_file_grants_extended_acl_authority(file: &File) -> Result<bool, ReceiptStoreError> {
    for attribute in ["system.posix_acl_access", "system.posix_acl_default"] {
        let mut value = Vec::<u8>::with_capacity(1);
        match rustix::fs::fgetxattr(file, attribute, &mut value) {
            Ok(_) | Err(rustix::io::Errno::RANGE) => return Ok(true),
            Err(error) if error == rustix::io::Errno::NODATA => {}
            Err(error) if error == rustix::io::Errno::NOTSUP => {}
            Err(error) => return Err(ReceiptStoreError::Io(error.into())),
        }
    }
    Ok(false)
}

#[cfg(target_vendor = "apple")]
fn receipt_file_grants_extended_acl_authority(file: &File) -> Result<bool, ReceiptStoreError> {
    chio_keyring::darwin_descriptor_grants_extended_acl_authority(file).map_err(|error| {
        ReceiptStoreError::Conflict(format!("receipt database ACL inspection failed: {error}"))
    })
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn receipt_file_grants_extended_acl_authority(_file: &File) -> Result<bool, ReceiptStoreError> {
    Err(ReceiptStoreError::Conflict(
        "receipt database ACL inspection is unsupported on this platform".to_string(),
    ))
}

fn receipt_database_identity(
    file: &File,
    _path: &Path,
) -> Result<chio_core::Hash, ReceiptStoreError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(ReceiptStoreError::Conflict(
            "receipt database must be a durable regular file".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use serde::Serialize;
        use std::os::unix::fs::MetadataExt;

        #[derive(Serialize)]
        struct StorageIdentity {
            schema: &'static str,
            device: u64,
            inode: u64,
        }
        let canonical = canonical_json_bytes(&StorageIdentity {
            schema: "chio.receipt-store.storage-identity.v1",
            device: metadata.dev(),
            inode: metadata.ino(),
        })
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
        Ok(chio_core::sha256(&canonical))
    }
    #[cfg(not(unix))]
    {
        use serde::Serialize;

        #[derive(Serialize)]
        struct StorageIdentity<'a> {
            schema: &'static str,
            canonical_path: &'a Path,
        }
        let canonical_path = fs::canonicalize(_path)?;
        let canonical = canonical_json_bytes(&StorageIdentity {
            schema: "chio.receipt-store.storage-identity.v1",
            canonical_path: &canonical_path,
        })
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
        Ok(chio_core::sha256(&canonical))
    }
}

pub struct SqliteReceiptStore {
    pub(crate) pool: Pool<SqliteConnectionManager>,
    receipt_commit_actor: ReceiptCommitActor,
    database_identity: chio_core::Hash,
    database_identity_file: Arc<ReceiptDatabaseIdentityFile>,
    /// Multi-tenant receipt isolation: when true, tenant-
    /// scoped queries exclude the pre-multitenant NULL-tagged set. When
    /// false, queries with `tenant_filter = Some(id)` return rows where
    /// `tenant_id = id OR tenant_id IS NULL`, which keeps pre-multitenant
    /// (NULL-tagged) receipts visible during explicit compatibility mode.
    pub(crate) strict_tenant_isolation: std::sync::atomic::AtomicBool,
    /// Staged-rollout flag: read-only after open.
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
    database_identity_file: Option<Arc<ReceiptDatabaseIdentityFile>>,
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
    // flush_report / receipt_store_health / kernel counters.
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
    /// paths). Canonical inherent paths pass `false`.
    ensure_lineage: bool,
    response: mpsc::SyncSender<Result<u64, ReceiptStoreError>>,
}

/// Deferred response sender for a `Write` job. The
/// actor invokes it AFTER `resync_head_after_write` so a committed write whose
/// head resync then fails returns the resync error instead of a stale `Ok`.
/// Called with `Ok(())` when resync succeeded (or never ran) to send the job's
/// own outcome, or `Err(resync_error)` to override a committed job's `Ok` with
/// the resync failure.
///
/// Returns `true` when the job's FINAL outcome (after any resync override) was
/// `Ok`, so the actor can reconcile `committed_total` / `failed_total` for
/// writer-routed receipts. This responder is the
/// only place that knows the resync-adjusted outcome, so it reports the signal
/// out of band (the actual `Result` still travels to the caller's channel).
type WriterResponder = Box<dyn FnOnce(Result<(), ReceiptStoreError>) -> bool + Send + 'static>;

/// A single-writer job. Runs the caller's closure on the writer connection and
/// returns a [`WriterResponder`] so the ACTOR controls when the caller's result
/// is sent: the response is withheld until the post-write head resync outcome
/// is known.
type WriterClosure = Box<
    dyn FnOnce(Result<&mut SqliteStoreConnection, ReceiptStoreError>) -> WriterResponder
        + Send
        + 'static,
>;

enum ReceiptCommitCommand {
    Append(Box<ReceiptCommitRequest>),
    Flush(mpsc::SyncSender<Result<(), ReceiptStoreError>>),
    /// Generic single-writer job. Runs on the writer connection after any
    /// in-flight append batch has committed. The closure receives `Err` when
    /// the actor cannot provide a healthy writer connection (fail-closed).
    ///
    /// `appends_receipts` is true for jobs that insert tool/child receipt rows
    /// (child receipts, authorization-consuming appends), which populate
    /// `claim_receipt_log_entries` via the projection triggers. On a
    /// non-incremental (full-verification) store, the pre-write check runs the
    /// full claim-log validation for these. Metadata-only Write jobs leave it
    /// false and skip the O(N) scan.
    Write {
        job: WriterClosure,
        appends_receipts: bool,
    },
    /// Rerun the full verification on the writer connection and, on success,
    /// adopt the fresh head (clears a poisoned head). Audit-repair path.
    ReseedHead(mpsc::SyncSender<Result<(), ReceiptStoreError>>),
    /// Install (or replace) the background checkpoint signer on the actor
    /// thread. Delivered over the command channel: no shared state, no lock.
    InstallSigner(BackgroundCheckpointSigner),
}

impl ReceiptCommitActor {
    fn start(
        pool: Pool<SqliteConnectionManager>,
        incremental_verification: bool,
        database_identity_file: Arc<ReceiptDatabaseIdentityFile>,
    ) -> Self {
        let (sender, receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let actor_health = Arc::clone(&health);
        thread::spawn(move || {
            receipt_commit_actor_loop(pool, receiver, actor_health, incremental_verification)
        });
        Self {
            sender,
            health,
            database_identity_file: Some(database_identity_file),
        }
    }

    fn append(
        &self,
        receipt: ChioReceipt,
        raw_json: String,
        ensure_lineage: bool,
    ) -> Result<u64, ReceiptStoreError> {
        if let Some(database_identity_file) = self.database_identity_file.as_ref() {
            database_identity_file.validate()?;
        }
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
        if let Some(database_identity_file) = self.database_identity_file.as_ref() {
            database_identity_file.validate()?;
        }
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
    database_identity_file: Option<Arc<ReceiptDatabaseIdentityFile>>,
}

impl WriterHandle {
    /// Run one write job on the single writer connection and return its
    /// typed result. Fail-closed on saturation or a dead writer. Use for
    /// metadata-only writes (capability, liability, underwriting, IOU,
    /// session anchors) that do not insert receipt rows.
    pub(crate) fn run_write<T, F>(&self, job: F) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        self.run_write_kind(job, false)
    }

    /// Run one receipt-appending write job (child receipts,
    /// authorization-consuming appends). These insert `claim_receipt_log_entries`
    /// rows via the projection triggers, so the non-incremental fallback
    /// pre-check runs the full claim-log validation (fail-closed).
    pub(crate) fn run_write_receipt<T, F>(&self, job: F) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        self.run_write_kind(job, true)
    }

    fn run_write_kind<T, F>(&self, job: F, appends_receipts: bool) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        if let Some(database_identity_file) = self.database_identity_file.as_ref() {
            database_identity_file.validate()?;
        }
        let (response, result) = mpsc::sync_channel(1);
        let boxed: WriterClosure = Box::new(move |connection| {
            let outcome = match connection {
                // Panic isolation: `job` is one of the many rerouted write
                // families (lineage, liability,
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
            // Defer the send: the actor calls this
            // responder with the post-write head resync outcome. A resync
            // failure overrides a committed job's `Ok` with the resync error; a
            // job that already failed keeps its own error.
            let responder: WriterResponder =
                Box::new(move |resync: Result<(), ReceiptStoreError>| {
                    let final_outcome = match (outcome, resync) {
                        (job_outcome, Ok(())) => job_outcome,
                        (Err(job_error), Err(_)) => Err(job_error),
                        (Ok(_), Err(resync_error)) => Err(resync_error),
                    };
                    // Report the resync-adjusted outcome to the actor so it can
                    // reconcile committed/failed for this writer-routed job,
                    // then send the caller's result.
                    let committed = final_outcome.is_ok();
                    let _ = response.send(final_outcome);
                    committed
                });
            responder
        });
        // Pre-send increment: same race-avoidance invariant as
        // `ReceiptCommitActor::append` (see the comment at the `inflight`
        // increment in `append`). The actor decrements unconditionally on
        // dequeue; any send failure undoes the speculative increment.
        self.health.inflight.fetch_add(1, Ordering::SeqCst);
        match self.sender.try_send(ReceiptCommitCommand::Write {
            job: boxed,
            appends_receipts,
        }) {
            Ok(()) => {
                // Count writer-routed writes in health. A successful enqueue
                // mirrors the Append path's
                // `accepted_total` bump (see `append`): child receipts and
                // authorization-consuming receipts now go through
                // `run_write_receipt`, so without this a store dominated by
                // writer-routed receipts would advance the log while
                // `receipt_store_health().writer.accepted_total` stayed at zero.
                // O(1), fail-closed unchanged (a Full/Disconnected send still
                // returns before counting).
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
            Ok(outcome) => outcome,
            Err(_) => {
                // Accepted-then-lost: the actor took the command but exited
                // before delivering a response (actor death; job panics are
                // caught and answered above). The job-completion decrement (the
                // `WriterInflightGuard` in the actor's `Write` arm) may never
                // have run - the command could have been
                // lost while still queued, before the arm was entered - so undo
                // the speculative pre-send increment and record the failure,
                // mirroring the append path's recv-Err handling, so
                // writer.inflight does not report a permanently-stuck write. If
                // the actor instead died mid-arm and the guard already fired,
                // `atomic_saturating_sub` keeps this compensating release from
                // underflowing.
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                Err(receipt_actor_unavailable_error())
            }
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
/// chain, owned exclusively by the commit-actor thread.
enum WriterHeadState {
    // Boxed: `VerifiedHead` embeds an `Option<KernelCheckpoint>`, which makes
    // this variant far larger than `Poisoned(String)` (clippy::large_enum_variant).
    Verified(Box<VerifiedHead>),
    /// Seeding or resync failed: every write is rejected with Conflict until
    /// `chio receipt audit --repair` reseeds (fail-closed).
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
                // Panic isolation: `commit_receipt_batch` runs on the single
                // writer thread. A
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
                // The co-drained Flush waiters are NOT passed into
                // `commit_receipt_batch`; they are released below, AFTER the
                // checkpoint build, so a flush is a genuine checkpoint
                // barrier. Keeping them in the loop lets the
                // success and panic paths fan them out at one point, and
                // because they are not moved into the panicking call they
                // survive an unwind untouched.
                pending_flush_error =
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        commit_receipt_batch(
                            &pool,
                            &mut head_state,
                            incremental_verification,
                            requests,
                            &health,
                        )
                    })) {
                        Ok(flush_error) => flush_error,
                        Err(payload) => Some(fan_out_batch_panic_error(
                            &health,
                            request_responses,
                            receipt_writer_job_panic_error(&payload),
                        )),
                    };
                // Checkpoint construction runs AFTER commit_receipt_batch has
                // already sent every APPEND durability response, so ADR-0013
                // append latency is not extended by checkpoint building; but it
                // runs BEFORE the co-drained Flush waiters are released, so a
                // flush cannot return until the owed checkpoints for the drained
                // appends are built (the flush-as-checkpoint barrier). A
                // build failure is recorded via `last_error` and does not poison
                // the head, and is surfaced to the co-drained Flush waiters of
                // THIS batch via `flush_barrier_error`. It is deliberately NOT
                // written back into `pending_flush_error`: that keeps the build
                // error scoped to this batch's barrier and preserves the
                // established contract of a later STANDALONE flush (which
                // reflects append durability; background-build health is already
                // surfaced through `last_error`/`receipt_store_health`).
                let mut flush_barrier_error = pending_flush_error
                    .as_ref()
                    .map(receipt_store_error_snapshot);
                if pending_flush_error.is_none() {
                    if let WriterHeadState::Verified(head) = &mut head_state {
                        if let Some(error) = build_due_checkpoints_and_record(
                            &pool,
                            head,
                            &checkpoint_signer,
                            &health,
                        ) {
                            flush_barrier_error = Some(error);
                        }
                    }
                }
                // Release the co-drained Flush waiters now that owed checkpoints
                // are built (the checkpoint barrier). An append error or a
                // checkpoint-build failure reaches them as an Err; otherwise Ok.
                for response in flushes {
                    let result = match &flush_barrier_error {
                        Some(error) => Err(receipt_store_error_snapshot(error)),
                        None => Ok(()),
                    };
                    let _ = response.send(result);
                }
                if let Some(command) = deferred {
                    handle_non_append_command(
                        &pool,
                        &mut head_state,
                        incremental_verification,
                        &health,
                        &mut checkpoint_signer,
                        &mut pending_flush_error,
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
                &mut pending_flush_error,
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
    pending_flush_error: &mut Option<ReceiptStoreError>,
    command: ReceiptCommitCommand,
) {
    match command {
        ReceiptCommitCommand::Write {
            job,
            appends_receipts,
        } => {
            // Hold the writer `inflight` count for the DURATION of this Write
            // job rather than releasing it immediately on dequeue, so a health
            // poll during a slow or stuck liability/checkpoint write reports
            // `inflight > 0`. The pre-send increment in
            // `WriterHandle::run_write_kind` is adopted by this RAII guard.
            //
            // The guard is released (`drop`) IMMEDIATELY BEFORE each
            // `respond(...)` on every exit path, so a caller that observes its
            // own response never sees itself still counted inflight. This
            // mirrors the Append path, which decrements in `commit_receipt_batch`
            // BEFORE fanning out its responses. The decrement stays deferred
            // until each respond, so inflight remains up through the job body and
            // the head resync (the response itself is deferred until then). The
            // guard's Drop still backstops any exit that panics before a respond
            // runs; `atomic_saturating_sub` keeps a rare overlap with the
            // caller's recv-Err compensation (actor-thread death) from
            // underflowing.
            let inflight_guard = WriterInflightGuard::new(&health.inflight);
            let mut connection = match pool.get() {
                Ok(connection) => connection,
                Err(error) => {
                    // No write ran (no connection), so there is no resync to
                    // gate on: send the pool error now (`Ok(())` = nothing to
                    // override). Count the failed outcome.
                    let respond = job(Err(ReceiptStoreError::Pool(error.to_string())));
                    // Decrement before the response reaches the caller.
                    drop(inflight_guard);
                    record_write_job_outcome(health, respond(Ok(())));
                    return;
                }
            };
            match head_state {
                WriterHeadState::Poisoned(message) => {
                    let respond = job(Err(poisoned_head_error(message)));
                    // Decrement before the response reaches the caller.
                    drop(inflight_guard);
                    record_write_job_outcome(health, respond(Ok(())));
                }
                WriterHeadState::Verified(head) => {
                    // Pre-check (fail-closed): same predecessor check the
                    // append path runs, so writer-routed appends (child
                    // receipts, consuming auth) are equally protected. On the
                    // non-incremental (full-verification) fallback, a
                    // receipt-appending job also runs the full claim-log
                    // validation, so uncheckpointed projection drift is caught
                    // before the
                    // write commits. Metadata-only Write jobs skip the O(N)
                    // scan.
                    let pre_check = if incremental_verification {
                        // Verify the checkpoint head, THEN validate the adopted
                        // claim-log delta before the job commits: a
                        // receipt-appending writer job must reject a
                        // stale/invalid baseline BEFORE its durable insert, the
                        // same way the append path does, not durably write and
                        // only poison the head in the post-write resync.
                        match verify_head_against_latest_checkpoint(&connection, head) {
                            Ok(()) => validate_writer_adopted_claim_log_baseline(
                                &connection,
                                head,
                                appends_receipts,
                            ),
                            Err(error) => Err(error),
                        }
                    } else {
                        verify_latest_checkpoint_integrity(&connection).and_then(|()| {
                            if appends_receipts {
                                validate_claim_receipt_log_entries(&connection)
                            } else {
                                Ok(())
                            }
                        })
                    };
                    if let Err(error) = pre_check {
                        let respond = job(Err(error));
                        // Decrement before the response reaches the caller.
                        drop(inflight_guard);
                        record_write_job_outcome(health, respond(Ok(())));
                        return;
                    }
                    // Capture the head's checkpoint position BEFORE the job
                    // runs: a writer-routed recovery
                    // (`create_next_receipt_checkpoint`) that creates/adopts the
                    // missing checkpoint advances this during the resync below.
                    let pre_checkpoint_seq = head.checkpoint_seq();
                    // Run the job but DEFER its response: the caller must not
                    // observe `Ok` until
                    // `resync_head_after_write` confirms the head. A committed
                    // write whose resync then fails receives the resync error,
                    // not a stale `Ok`.
                    let respond = job(Ok(&mut connection));
                    // Post-resync: absorb whatever the closure committed
                    // (claim-log rows via projection triggers, checkpoint
                    // rows via the manual path) so the next append's
                    // cross-check cannot false-Conflict.
                    match resync_head_after_write(&connection, head) {
                        Ok(()) => {
                            // Reconcile committed/failed for this writer-routed
                            // job using the responder's resync-adjusted outcome
                            // signal. Decrement before the response reaches the
                            // caller; the post-response catch-up build below
                            // reads no inflight state.
                            drop(inflight_guard);
                            record_write_job_outcome(health, respond(Ok(())));
                            health.store_head_snapshot(head);
                            // Clear a stale checkpoint error after a manual
                            // recovery: a writer-routed
                            // op such as `create_next_receipt_checkpoint` can
                            // build/adopt the missing checkpoint inside the job,
                            // advancing the head's checkpoint seq during the resync
                            // above. `build_due_checkpoints_and_record` below then
                            // finds nothing due (`Ok(false)`) and would leave a
                            // prior background-build `last_error` in place, so
                            // `receipt_store_health` keeps reporting the store
                            // unhealthy after the repair. Clear it here when the
                            // checkpoint chain actually advanced (clear only on
                            // an actual advance, never on an idle refresh); a
                            // real later build failure re-sets it below.
                            if head.checkpoint_seq() > pre_checkpoint_seq {
                                if let Ok(mut last_error) = health.last_error.lock() {
                                    *last_error = None;
                                }
                            }
                            // Writer-routed appends (child receipts, consuming
                            // auth) can cross the threshold too; no
                            // pending_flush_error guard here since a Write job is
                            // not part of a batch. The writer pool holds exactly
                            // one connection (DEFAULT_WRITER_POOL_MAX_SIZE = 1):
                            // drop this one before build_due_checkpoints_and_record
                            // acquires its own, or `pool.get()` would block on
                            // itself.
                            drop(connection);
                            // Gate the catch-up build on a full-verified head,
                            // mirroring the InstallSigner defer. On a
                            // non-incremental (suspect)
                            // store `seed_head_snapshot` leaves the head
                            // UNVALIDATED; only a receipt-appending Write reran the
                            // full claim-log validation in the pre-check above, so
                            // a metadata-only `run_write` did NOT. Building here
                            // would checkpoint unaudited claim-log rows before the
                            // deferred full validation ever runs (fail-closed
                            // violation). Build only when the head is genuinely
                            // verified: incremental mode (seed_verified_head +
                            // per-append verify) OR a receipt-appending job that
                            // just ran the full validation.
                            if incremental_verification || appends_receipts {
                                build_due_checkpoints_and_record(
                                    pool,
                                    head,
                                    checkpoint_signer,
                                    health,
                                );
                            }
                        }
                        Err(error) => {
                            if let Ok(mut last_error) = health.last_error.lock() {
                                *last_error = Some(error.to_string());
                            }
                            let poison_message = error.to_string();
                            // Surface the resync failure to the caller: a write
                            // that returned `Ok` from its closure must NOT report
                            // success when the head is now poisoned. Count the
                            // failed outcome. Decrement before the response
                            // reaches the caller.
                            drop(inflight_guard);
                            record_write_job_outcome(health, respond(Err(error)));
                            *head_state = WriterHeadState::Poisoned(poison_message);
                        }
                    }
                }
            }
        }
        ReceiptCommitCommand::InstallSigner(signer) => {
            *checkpoint_signer = Some(signer);
            // Install-time catch-up. The store can
            // open on a DB that already has >= max_batch uncheckpointed
            // claim-log entries (a crash between the durable append response and
            // the background build, or enabling checkpointing on an existing
            // store). Without building here, the owed checkpoint waits for some
            // future Append/Write, so a quiet restarted store stays
            // uncheckpointed indefinitely despite checkpointing being enabled.
            // Run the existing bounded builder now so any already-owed
            // checkpoints (head.claim_log_max_seq - checkpointed_entry_seq >=
            // max_batch) are built at install time (O(b) per checkpoint, loops
            // until caught up; NOT a full verify). Fail-closed:
            // build_due_checkpoints_and_record records last_error and never
            // panics the actor.
            //
            // Deferred-seed gate: only build at
            // install when the head has actually been VALIDATED. With
            // `incremental_verification = false` the actor seeds via
            // `seed_head_snapshot`, which INTENTIONALLY skips the full claim-log
            // + checkpoint-chain audit (deferred to the next append/verify), so
            // the seeded head is `Verified` but UNVALIDATED. Building catch-up
            // checkpoints over that range would checkpoint unaudited data (a
            // fail-closed violation), so defer it in that mode: the next
            // receipt-appending append/Write runs the deferred full validation
            // and THEN builds the owed checkpoints. In the normal incremental
            // mode the seeded head is genuinely verified, so the owed
            // checkpoints still build here.
            if incremental_verification {
                if let WriterHeadState::Verified(head) = head_state {
                    build_due_checkpoints_and_record(pool, head, checkpoint_signer, health);
                }
            }
        }
        ReceiptCommitCommand::ReseedHead(response) => {
            let outcome = pool
                .get()
                .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
                .and_then(|connection| {
                    // Reseed always runs the FULL verification. This is the
                    // `chio receipt audit --repair`
                    // recovery path: it clears a poisoned head and must establish
                    // a genuinely CLEAN, fully-verified head, so it runs
                    // `seed_verified_head` (full claim-log validation +
                    // checkpoint-chain audit) regardless of the hot-path
                    // `incremental_verification` mode. Using the cheap
                    // `seed_head_snapshot` here would let `--repair` clear
                    // `last_error` and mark the head `Verified` while the on-disk
                    // log is still corrupt (repair theater). This is the recovery
                    // path, not per-append, so it is a recovery-path cost. NOTE
                    // the deliberate difference from the InstallSigner catch-up:
                    // that path DEFERS in
                    // `incremental_verification = false` because `seed_head_snapshot`
                    // leaves the head UNVALIDATED; reseed full-verifies, so it does
                    // not defer.
                    seed_verified_head(&connection)
                });
            let result = match outcome {
                Ok(head) => {
                    health.store_head_snapshot(&head);
                    if let Ok(mut last_error) = health.last_error.lock() {
                        *last_error = None;
                    }
                    // Clear the actor loop's stale flush error: a prior append
                    // poisoned the head and set
                    // `pending_flush_error`, but this reseed has just revalidated
                    // the DB and replaced the head. Without clearing it, a
                    // subsequent STANDALONE `flush_receipt_writes()` (no queued
                    // writes) would keep returning the stale append error even
                    // though the store recovered. Fail-closed is unaffected: a
                    // real later batch failure re-sets `pending_flush_error`.
                    *pending_flush_error = None;
                    *head_state = WriterHeadState::Verified(Box::new(head));
                    // Build owed checkpoints after a successful reseed. If the
                    // background signer was installed
                    // while the head was poisoned, its install-time catch-up
                    // was skipped, so a quiet store with >= max_batch
                    // uncheckpointed claim-log entries would stay uncheckpointed
                    // until some future write. Run the SAME bounded builder now.
                    // Unlike the InstallSigner catch-up (which gates on
                    // `incremental_verification` because its deferred seed is
                    // unvalidated), this is unconditional: the reseed just
                    // full-verified the head, so building over that range never
                    // checkpoints unaudited data. Bounded (O(b) per owed
                    // checkpoint), a recovery-path build (not per-append).
                    // No-op when no signer is present. Fail-closed:
                    // `build_due_checkpoints_and_record` records `last_error` on a
                    // build failure and never re-poisons the freshly verified head.
                    if let WriterHeadState::Verified(head) = head_state {
                        build_due_checkpoints_and_record(pool, head, checkpoint_signer, health);
                    }
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
/// blocks an already-durable commit). Returns the recorded
/// error (if any) so a flush-as-checkpoint-barrier caller can surface it to its
/// co-drained flush waiters; the durable append/write path ignores the return
/// and stays fail-closed via `last_error`.
fn build_due_checkpoints_and_record(
    pool: &Pool<SqliteConnectionManager>,
    head: &mut VerifiedHead,
    checkpoint_signer: &Option<BackgroundCheckpointSigner>,
    health: &ReceiptCommitWriterHealth,
) -> Option<ReceiptStoreError> {
    let signer = checkpoint_signer.as_ref()?;
    // Panic isolation: a panic mid-build
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
        Ok(built) => {
            health.store_head_snapshot(head);
            // Recovery signal: a prior background
            // checkpoint build may have set `last_error`. A later SUCCESSFUL
            // build is reached here through a writer-routed op (a `Write` job
            // crossing the threshold), which does NOT run the append batch's
            // `last_error` reset, so without this the store keeps reporting
            // unhealthy after it has recovered. Clear the stale error only on an
            // ACTUAL build (`built`), never on a no-op due-check, so a genuinely
            // current error is not masked by an idle refresh.
            if built {
                if let Ok(mut last_error) = health.last_error.lock() {
                    *last_error = None;
                }
            }
            None
        }
        Err(error) => {
            if let Ok(mut last_error) = health.last_error.lock() {
                *last_error = Some(error.to_string());
            }
            Some(error)
        }
    }
}

fn build_due_checkpoints(
    pool: &Pool<SqliteConnectionManager>,
    head: &mut VerifiedHead,
    signer: &BackgroundCheckpointSigner,
) -> Result<bool, ReceiptStoreError> {
    if signer.max_batch == 0 {
        return Ok(false); // ADR-0008: batch_size 0 disables checkpointing
    }
    let mut connection = pool
        .get()
        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))?;
    // Shared-file freshness: on a shared receipt DB
    // another writer can commit a checkpoint AFTER this actor's append
    // pre-check but BEFORE its batch tx. `append_receipt_batch` then adopts that
    // writer's claim-log rows via the baseline delta yet leaves
    // `head.latest_checkpoint` stale, so building from the stale position would
    // try to rebuild an already-committed checkpoint and fail with "already
    // exists with different content" (the clock-skew case the idempotent-
    // identical guard does not cover). Refresh the head against the latest
    // persisted checkpoint first so that checkpoint is ADOPTED, not rebuilt.
    // This is an O(1) latest-row read + digest adopt (plus bounded catch-up),
    // NOT a full chain verify, so the incremental hot path stays flat per
    // append.
    verify_head_against_latest_checkpoint(&connection, head)?;
    maybe_build_checkpoint(&mut connection, head, signer)
}

/// Build every checkpoint the head owes: count-based ADR-0008 trigger, range
/// derived from the cached head (NOT next_checkpoint_range_for_connection,
/// which runs a full chain verify), O(b) work per checkpoint.
fn maybe_build_checkpoint(
    connection: &mut SqliteStoreConnection,
    head: &mut VerifiedHead,
    signer: &BackgroundCheckpointSigner,
) -> Result<bool, ReceiptStoreError> {
    if signer.max_batch == 0 {
        return Ok(false);
    }
    let mut built = false;
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
        let checkpoint = chio_kernel::build_checkpoint_with_backend(
            checkpoint_seq,
            start_seq,
            end_seq,
            &receipt_bytes,
            signer.backend.as_ref(),
            head.latest_checkpoint.as_ref(),
        )
        .map_err(checkpoint_error_to_receipt_store)?;
        #[cfg(test)]
        if test_hooks::panic_during_checkpoint_build(signer.max_batch) {
            panic!("injected test panic during background checkpoint build");
        }
        #[cfg(test)]
        if test_hooks::fail_checkpoint_build(signer.max_batch) {
            return Err(ReceiptStoreError::Conflict(
                "injected test checkpoint build failure".to_string(),
            ));
        }
        ensure_checkpoint_transparency_guards(connection)?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // The insert returns the checkpoint now persisted at this seq: either
        // the one we just built, or a concurrently committed winner (clock-skew
        // sibling) it validated and adopted. Catch the cached head up to THAT
        // checkpoint so a later verify_head_against_latest_checkpoint does not
        // see our discarded byte-different build diverge from the persisted row.
        let adopted =
            insert_checkpoint_incremental_tx(&tx, head.latest_checkpoint.as_ref(), &checkpoint)?;
        tx.commit()?;
        head.latest_checkpoint = Some(adopted);
        built = true;
    }
    Ok(built)
}

/// Head-resync rule: one indexed delta aggregate plus one
/// latest-checkpoint row read after every Write closure.
fn resync_head_after_write(
    connection: &Connection,
    head: &mut VerifiedHead,
) -> Result<(), ReceiptStoreError> {
    let pre_resync_max = head.claim_log_max_seq;
    let (delta_count, post_max) = claim_log_delta_count_and_max_seq(connection, pre_resync_max)?;
    // Validate the ADOPTED resync delta before advancing the head. A Write
    // closure can commit claim_receipt_log_entries rows
    // past this actor's head (another shared-DB writer, or a receipt-appending
    // Write job), and this resync absorbs them via COUNT/MAX. Without
    // validating them, an orphan/divergent row would be trusted and later
    // appends would skip it as already-verified, so a background checkpoint
    // could cover an unaudited entry. Re-validate JUST the
    // (pre_resync_max, post_max] delta against the source receipt tables
    // (O(delta)); the full-log validator is NOT called. Single-writer common
    // case: no other writer, empty delta, no-op. Fail-closed: an
    // orphan/divergent delta returns the error, which the Write arm turns into
    // a poisoned head.
    if delta_count > 0 {
        validate_adopted_claim_log_delta(connection, pre_resync_max, post_max)?;
    }
    head.claim_log_count = head.claim_log_count.saturating_add(delta_count);
    head.claim_log_max_seq = post_max;
    verify_head_against_latest_checkpoint(connection, head)
}

fn commit_receipt_batch(
    pool: &Pool<SqliteConnectionManager>,
    head_state: &mut WriterHeadState,
    incremental_verification: bool,
    requests: Vec<ReceiptCommitRequest>,
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
    // APPEND durability responses fan out here (ADR-0013): a durable append
    // response is never delayed by checkpoint construction. The co-drained
    // Flush waiters are released by the caller AFTER the checkpoint build, so a
    // flush is a genuine checkpoint barrier.
    for (request, result) in requests.into_iter().zip(results) {
        let _ = request.response.send(result);
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

/// Holds the writer `inflight` count for the DURATION of a writer-routed `Write`
/// job. The pre-send increment in `WriterHandle::run_write_kind` is ADOPTED by
/// this guard, so `receipt_store_health` reports `inflight > 0` while a slow or
/// stuck writer-routed op (pool acquire, pre-check, closure, resync) is actually
/// running. The `Write` arm releases it (`drop`) IMMEDIATELY BEFORE each
/// `respond(...)`, so a caller that observes its own response never sees itself
/// still counted inflight, mirroring the Append path, which decrements in
/// `commit_receipt_batch` BEFORE fanning out its results. Still Drop-based, so
/// any exit that panics before a respond runs releases exactly once; a release
/// overlap with the caller's recv-Err compensation under actor-thread death
/// saturates at zero via `atomic_saturating_sub` rather than underflowing.
struct WriterInflightGuard<'a> {
    inflight: &'a AtomicU64,
}

impl<'a> WriterInflightGuard<'a> {
    fn new(inflight: &'a AtomicU64) -> Self {
        Self { inflight }
    }
}

impl Drop for WriterInflightGuard<'_> {
    fn drop(&mut self) {
        atomic_saturating_sub(self.inflight, 1);
    }
}

/// Reconcile a writer-routed `Write` job's health counters. Child receipts
/// and authorization-consuming appends run through
/// `WriterHandle::run_write_receipt`, and metadata-only writes through
/// `run_write`; both are `accepted_total`-counted at enqueue, but their
/// success/failure OUTCOME was never folded into `committed_total` /
/// `failed_total`, so accepted / committed / failed did not reconcile and a
/// store dominated by writer-routed receipts undercounted commits. The actor
/// calls this exactly once per `Write` with the responder's resync-adjusted
/// signal (O(1) per write). A committed outcome also refreshes
/// `last_commit_unix_ms`, mirroring the Append path (`commit_receipt_batch`).
fn record_write_job_outcome(health: &ReceiptCommitWriterHealth, committed: bool) {
    if committed {
        health.committed_total.fetch_add(1, Ordering::SeqCst);
        health
            .last_commit_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
    } else {
        health.failed_total.fetch_add(1, Ordering::SeqCst);
    }
}

/// Background checkpoint signer, installed once by the kernel after `open`
/// and before serving. `max_batch = 0` disables
/// checkpointing (ADR-0008 semantics).
#[derive(Clone)]
pub struct BackgroundCheckpointSigner {
    pub backend: Arc<dyn SigningBackend>,
    pub max_batch: u64,
}

/// Last verified position of the receipt chain. Owned exclusively by the
/// commit-actor thread; never shared, never locked.
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
