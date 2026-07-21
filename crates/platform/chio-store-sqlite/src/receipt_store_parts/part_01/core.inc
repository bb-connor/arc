use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
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
use chio_supervisor::{HealthLevel, SupervisedOutcome, SupervisedThread, SupervisorConfig};
pub(crate) use bootstrap::open::ReceiptConnectionManager;
use r2d2::{Pool, PooledConnection};
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
            let file_name = path.file_name().ok_or_else(|| {
                ReceiptStoreError::Conflict("receipt database path has no file name".to_string())
            })?;
            crate::durable_sqlite::validate_existing_sqlite_sidecars_at(
                &self.parent,
                file_name,
            )
            .map_err(|error| {
                ReceiptStoreError::Conflict(format!(
                    "receipt database has an unsafe SQLite sidecar: {error}"
                ))
            })?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ReceiptStoreError> {
        self.validate_path_binding(&self.path)
    }

    fn validate_live_connection(&self, connection: &Connection) -> Result<(), ReceiptStoreError> {
        self.validate()?;
        chio_keyring::validate_sqlite_main_database_live_path_binding(connection).map_err(
            |error| {
                ReceiptStoreError::Conflict(format!(
                    "live SQLite connection is not bound to the retained receipt database file: {error}"
                ))
            },
        )?;
        self.validate()
    }

    #[must_use]
    fn identity(&self) -> chio_core::Hash {
        self.identity
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

/// One external SQLite connection bound to a live receipt-store identity.
///
/// Callers must obtain the connection through [`Self::validated_connection`]
/// for every operation. That gate rechecks the retained parent descriptor,
/// directory entry, file descriptor, and SQLite main-file handle before the
/// caller can read or write co-located tables.
pub struct SqliteReceiptBoundConnection {
    connection: Connection,
    database_identity_file: Arc<ReceiptDatabaseIdentityFile>,
}

impl SqliteReceiptBoundConnection {
    pub fn validated_connection(&self) -> Result<&Connection, ReceiptStoreError> {
        self.database_identity_file
            .validate_live_connection(&self.connection)?;
        Ok(&self.connection)
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
    validate_trusted_receipt_parent_security(&directory, effective_uid, names.is_empty())?;
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
        validate_trusted_receipt_parent_security(&next, effective_uid, index + 1 == name_count)?;
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
    final_authority_directory: bool,
) -> Result<(), ReceiptStoreError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = directory.metadata()?;
    let trusted_owner = metadata.uid() == effective_uid || metadata.uid() == 0;
    let group_or_world_writable = metadata.mode() & 0o022 != 0;
    let sticky = metadata.mode() & 0o1000 != 0;
    let unsafe_ancestor_write =
        !final_authority_directory && group_or_world_writable && !sticky;
    let final_directory_not_private =
        final_authority_directory && metadata.mode() & 0o777 != 0o700;
    if !trusted_owner
        || unsafe_ancestor_write
        || final_directory_not_private
        || receipt_file_grants_extended_acl_authority(directory)?
    {
        return Err(ReceiptStoreError::Conflict(
            "receipt database ancestors must have trusted ownership and no untrusted write \
             authority; the final authority directory must have mode 0700 and no \
             authority-granting ACL"
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
    pub(crate) pool: Pool<ReceiptConnectionManager>,
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
    /// Sidecar advisory locks coordinating sibling writer instances on the
    /// database file.
    writer_lifetime_lock: Option<WriterLifetimeLock>,
    /// Fresh per-open identity stamped on dispatch intents owned by this
    /// process instance.
    pub(crate) instance_token: String,
}

type FederatedShareSubjectCorpus = (
    FederatedEvidenceShareSummary,
    Vec<StoredToolReceipt>,
    Vec<CapabilitySnapshot>,
);
pub(crate) type SqliteStoreConnection = PooledConnection<ReceiptConnectionManager>;

const RECEIPT_GROUP_COMMIT_MAX_BATCH: usize = 64;
const RECEIPT_GROUP_COMMIT_FLUSH_DELAY: Duration = Duration::from_micros(500);
const RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY: usize = RECEIPT_GROUP_COMMIT_MAX_BATCH * 16;

/// Bound on the dispatch-intent reconciliation resolution write: applying
/// dead-letter, monetary-reconciled, and replay-release outcomes to the rows
/// this pass claimed. This runs off the request path (boot attach, or the
/// background recovery worker's cadence), so it can afford the same order of
/// magnitude as the hot-path receipt append budget without a request ever
/// observing it; the bound exists so a wedged-but-alive writer cannot hang
/// the pass indefinitely while it holds the sidecar reconcile probe mutex
/// (and, when the batch includes unattributed rows, the writer-lifetime mark
/// converted to exclusive), which would otherwise block sibling `open()`s and
/// make `DispatchIntentRecoveryHandle::drop` (which joins the worker thread)
/// hang kernel shutdown with it.
const DISPATCH_INTENT_RECONCILE_RESOLUTION_BUDGET: Duration = Duration::from_secs(5);

struct ReceiptCommitActor {
    sender: mpsc::SyncSender<ReceiptCommitCommand>,
    health: Arc<ReceiptCommitWriterHealth>,
    /// Retains the writer thread's join handle and its supervised health flag. The
    /// flag is TCB-critical: any writer death or degradation trips it, and the kernel
    /// pre-dispatch gate reads it to fail closed before a tool executes.
    writer: SupervisedThread,
    database_identity_file: Option<Arc<ReceiptDatabaseIdentityFile>>,
}

struct ReceiptCommitWriterHealth {
    /// Serializes command publication with the consuming close transition.
    /// Commands that acquire this gate before close are ordered before its
    /// flush barrier; later publications fail without entering the channel.
    send_gate: Mutex<()>,
    closing: AtomicBool,
    accepted_total: AtomicU64,
    committed_total: AtomicU64,
    failed_total: AtomicU64,
    /// Cumulative bounded waits that elapsed before the caller observed a
    /// terminal command response. This is observational, not terminal: the
    /// actor still records exactly one committed or failed outcome later.
    timeout_total: AtomicU64,
    saturated_total: AtomicU64,
    /// Serializes every speculative writer reservation and release so the
    /// `inflight` count and its backlog-start anchor change as one state
    /// transition. The atomics remain lock-free mirrors for health readers.
    inflight_transition: Mutex<()>,
    inflight: AtomicU64,
    /// Timeout-observed commands whose actor-owned lease is still live. This
    /// gives the liveness gate an immediate, self-clearing wedge signal without
    /// overloading `failed_total` or a global error string.
    timed_out_inflight: AtomicU64,
    /// Commands currently sitting in the commit-actor channel, not yet pulled
    /// for processing. Incremented before every send and decremented when the
    /// actor pulls a command, so it tracks true channel occupancy rather than
    /// `inflight`, which stays elevated through the commit of a drained batch.
    /// The saturation gate reads this: a drained but still-committing batch must
    /// not read as a full channel when the next send would in fact succeed.
    queue_depth: AtomicU64,
    last_commit_unix_ms: AtomicU64,
    /// Wall-clock (unix-ms) of the first accepted append, set once (0 = unset).
    /// Retained for operator display of when this writer first did work.
    first_accept_unix_ms: AtomicU64,
    /// Wall-clock (unix-ms) at which the CURRENT writer reservation backlog
    /// began (0 = no backlog). The transition lock makes this move with
    /// `inflight`: a rejected reservation cannot erase the anchor while another
    /// command remains active, and the next reservation after a full drain gets
    /// a fresh anchor.
    backlog_started_unix_ms: AtomicU64,
    last_error: Mutex<Option<String>>,
    // Last background-retention rotation failure, set by the kernel maintenance
    // worker via `record_retention_rotation_outcome` and cleared on the next
    // successful rotation. Surfaced by `receipt_store_health` so a silently
    // failing background retention task is observable rather than healthy.
    retention_error: Mutex<Option<String>>,
    // Verified-head snapshot, written only by the actor thread; read by
    // flush_report / receipt_store_health / kernel counters.
    head_checkpoint_seq: AtomicU64,
    head_checkpointed_entry_seq: AtomicU64,
    head_claim_log_count: AtomicU64,
    head_claim_log_max_seq: AtomicU64,
    // Mirror of the actor thread's `WriterHeadState` poison bit. The head lives
    // only on the actor thread, so a poisoned head (every append rejected with a
    // Conflict) is invisible to the supervised thread flag: the writer thread is
    // still alive. Publishing it here lets `writer_serving_closed` deny at the
    // pre-dispatch gate, so a tool is never executed against a store that cannot
    // persist its receipt.
    head_poisoned: AtomicBool,
}

impl Default for ReceiptCommitWriterHealth {
    fn default() -> Self {
        Self {
            send_gate: Mutex::new(()),
            closing: AtomicBool::new(false),
            accepted_total: AtomicU64::new(0),
            committed_total: AtomicU64::new(0),
            failed_total: AtomicU64::new(0),
            timeout_total: AtomicU64::new(0),
            saturated_total: AtomicU64::new(0),
            inflight_transition: Mutex::new(()),
            inflight: AtomicU64::new(0),
            timed_out_inflight: AtomicU64::new(0),
            queue_depth: AtomicU64::new(0),
            last_commit_unix_ms: AtomicU64::new(0),
            first_accept_unix_ms: AtomicU64::new(0),
            backlog_started_unix_ms: AtomicU64::new(0),
            last_error: Mutex::new(None),
            retention_error: Mutex::new(None),
            head_checkpoint_seq: AtomicU64::new(0),
            head_checkpointed_entry_seq: AtomicU64::new(0),
            head_claim_log_count: AtomicU64::new(0),
            head_claim_log_max_seq: AtomicU64::new(0),
            // Fail closed until the actor thread seeds a verified head. The head
            // is seeded asynchronously after construction, so starting open would
            // let a corrupt or still-attaching store pass the pre-dispatch gate
            // and run a tool before the first append could reject. The seed path
            // clears this the moment it succeeds.
            head_poisoned: AtomicBool::new(true),
        }
    }
}

impl ReceiptCommitWriterHealth {
    /// Record the first accepted receipt for operator display. Backlog timing is
    /// established by `reserve_inflight` before a command is published to the
    /// actor, including maintenance commands that do not count as receipts.
    fn note_accept(&self) {
        let now = current_unix_ms();
        let _ =
            self.first_accept_unix_ms
                .compare_exchange(0, now, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// Reserve one command before `try_send`. The reservation itself is
    /// conservatively visible as backlog: a producer descheduled between this
    /// call and `try_send` must not mask already accepted work that reserved
    /// behind it. Serializing the 0-to-1 count transition with the anchor store
    /// prevents a later reservation from publishing `inflight > 0` without a
    /// stall-clock origin.
    fn reserve_inflight(&self) -> u64 {
        let _transition = match self.inflight_transition.lock() {
            Ok(transition) => transition,
            Err(poisoned) => poisoned.into_inner(),
        };
        let previous_inflight = self.inflight.load(Ordering::SeqCst);
        if previous_inflight == 0 {
            self.backlog_started_unix_ms
                .store(current_unix_ms(), Ordering::SeqCst);
        }
        self.inflight
            .store(previous_inflight.saturating_add(1), Ordering::SeqCst);
        previous_inflight
    }

    /// Release one command reservation. Publish the 1-to-0 count transition
    /// before clearing the anchor while holding the same transition lock used
    /// by reservation. A concurrent fresh reservation therefore cannot have its
    /// new anchor erased by the prior backlog's final release.
    fn release_inflight(&self) {
        let _transition = match self.inflight_transition.lock() {
            Ok(transition) => transition,
            Err(poisoned) => poisoned.into_inner(),
        };
        let current = self.inflight.load(Ordering::SeqCst);
        let next = current.saturating_sub(1);
        self.inflight.store(next, Ordering::SeqCst);
        if next == 0 {
            self.backlog_started_unix_ms.store(0, Ordering::SeqCst);
        }
    }

    /// Record successful progress by a rotation or retention repair without
    /// changing receipt accepted/committed totals. When maintenance commands
    /// queue back-to-back, `inflight` never reaches zero and the backlog anchor
    /// remains the first command's start; advancing the shared writer-progress
    /// timestamp prevents a completed command from making its successor look
    /// stalled immediately.
    fn note_maintenance_success(&self) {
        self.last_commit_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
    }

    /// Record that the commit actor has disconnected so the liveness classifier
    /// reports the writer `Dead`. The classifier keys the dead verdict on the
    /// "unavailable" marker in `last_error`, so an actor observed gone at enqueue
    /// time must set it: otherwise the next liveness sample can still read
    /// `Healthy` and admit a tool side effect whose receipt can never be
    /// persisted.
    fn note_writer_unavailable(&self) {
        if let Ok(mut last_error) = self.last_error.lock() {
            *last_error = Some("sqlite receipt commit actor is unavailable".to_string());
        }
    }

    /// Count a command as occupying a channel slot. Called before every
    /// `try_send`; a rejected send undoes it with `note_channel_send_rejected`,
    /// and the actor calls `note_channel_dequeue` once when it pulls the
    /// command. Incrementing before the send (not after) keeps the actor from
    /// dequeuing and decrementing before this increment lands, which would leak
    /// the count, mirroring the `inflight` accounting.
    fn note_channel_send(&self) {
        self.queue_depth.fetch_add(1, Ordering::SeqCst);
    }

    fn note_channel_send_rejected(&self) {
        atomic_saturating_sub(&self.queue_depth, 1);
    }

    fn note_channel_dequeue(&self) {
        atomic_saturating_sub(&self.queue_depth, 1);
    }

    /// Publish whether the writer head is poisoned. Written only by the actor
    /// thread at every head-state transition (seed, post-write resync, reseed)
    /// and read by `writer_serving_closed` from other threads.
    fn set_head_poisoned(&self, poisoned: bool) {
        self.head_poisoned.store(poisoned, Ordering::SeqCst);
    }

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

/// A resync-adjusted `Write` response prepared for terminal publication. The
/// actor records `committed`, publishes command-specific health state, and
/// releases the command lease before invoking `send`. Splitting preparation
/// from delivery prevents the caller from observing a response before terminal
/// accounting becomes visible.
struct PreparedWriterResponse {
    committed: bool,
    send: Box<dyn FnOnce() + Send + 'static>,
}

/// Deferred response preparer for a `Write` job. The actor invokes it after
/// `resync_head_after_write`, allowing a resync error to override a committed
/// job's `Ok`. It computes the final outcome without delivering it; delivery is
/// retained in [`PreparedWriterResponse::send`] until health and lease state are
/// terminally published.
type WriterResponder =
    Box<dyn FnOnce(Result<(), ReceiptStoreError>) -> PreparedWriterResponse + Send + 'static>;

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
    Append {
        request: Box<ReceiptCommitRequest>,
        inflight: WriterInflightLease,
    },
    Flush {
        response: mpsc::SyncSender<Result<(), ReceiptStoreError>>,
        inflight: WriterInflightLease,
    },
    /// Drain-complete termination used by callers that own a temporary
    /// receipt authority and must not remove its directory while the writer
    /// still retains SQLite handles.
    Shutdown {
        response: mpsc::SyncSender<()>,
    },
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
        inflight: WriterInflightLease,
    },
    /// Rerun the full verification on the writer connection and, on success,
    /// adopt the fresh head (clears a poisoned head). Audit-repair path.
    ReseedHead {
        response: mpsc::SyncSender<Result<(), ReceiptStoreError>>,
        inflight: WriterInflightLease,
    },
    /// Install (or replace) the background checkpoint signer on the actor
    /// thread. Delivered over the command channel: no shared state, no lock.
    InstallSigner {
        signer: BackgroundCheckpointSigner,
        inflight: WriterInflightLease,
    },
    /// Run a checkpoint-aligned co-archive-and-delete on the writer connection.
    /// Serialized with appends by the single writer; drains any in-flight
    /// append batch first. Returns the number of tool-receipt rows archived.
    Rotate {
        config: Box<RetentionConfig>,
        response: mpsc::SyncSender<Result<u64, ReceiptStoreError>>,
        inflight: WriterInflightLease,
    },
    /// Recover a store whose claim-log rows survived a source-row delete:
    /// remove the orphaned projection rows. Runs unconditionally regardless of
    /// head state, like `ReseedHead`
    /// (the entire point is to repair a poisoned head), and on success
    /// reseeds the head so the same store instance is appendable again
    /// without requiring a fresh open. Returns the number of rows removed.
    RetentionRepair {
        archive_path: String,
        response: mpsc::SyncSender<Result<u64, ReceiptStoreError>>,
        inflight: WriterInflightLease,
    },
}

impl ReceiptCommitActor {
    fn start(
        pool: Pool<ReceiptConnectionManager>,
        incremental_verification: bool,
        database_identity_file: Arc<ReceiptDatabaseIdentityFile>,
    ) -> Self {
        let (sender, receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let actor_health = Arc::clone(&health);
        let config = SupervisorConfig {
            name: "chio-receipt-writer",
            // Durable receipt persistence is on the money path: a degraded writer must
            // fail evaluations closed rather than execute tools without a receipt.
            tcb_critical: true,
            // Any writer fault is immediately operator-visible on this surface.
            trip_after: 1,
            max_restarts: 5,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
        };
        // The loop body borrows the receiver so it survives a restart with the same
        // still-open channel; the caller's sender stays valid across restarts. The
        // pool and health handle are cheap to clone (an Arc bump each) per attempt.
        let writer = SupervisedThread::spawn(config, move |_shutdown| {
            receipt_commit_actor_loop(
                pool.clone(),
                &receiver,
                Arc::clone(&actor_health),
                incremental_verification,
            );
            // The loop returns only once every command sender has dropped: an orderly
            // store shutdown, not a fault. Do not restart or trip the flag.
            SupervisedOutcome::Shutdown
        });
        Self {
            sender,
            health,
            writer,
            database_identity_file: Some(database_identity_file),
        }
    }

    /// Typed error for a commit writer that is no longer serving, carrying the
    /// supervisor's restart count and last recorded reason so the condition is
    /// inspectable rather than an opaque pool-error string.
    fn writer_dead_error(&self) -> ReceiptStoreError {
        let snapshot = self.writer.health().snapshot();
        ReceiptStoreError::WriterDead {
            restarts: snapshot.restart_total,
            last_error: snapshot
                .reason
                .unwrap_or_else(|| "receipt commit writer channel disconnected".to_string()),
        }
    }

    fn shutdown(self) -> Result<(), ReceiptStoreError> {
        let Self {
            sender,
            health,
            writer,
            database_identity_file,
        } = self;
        let (response, acknowledged) = mpsc::sync_channel(1);
        health.note_channel_send();
        let sent = sender
            .send(ReceiptCommitCommand::Shutdown { response })
            .is_ok();
        if !sent {
            health.note_channel_send_rejected();
            health.note_writer_unavailable();
        }
        drop(sender);
        drop(database_identity_file);
        let acknowledged = sent && acknowledged.recv().is_ok();
        let _ = writer.shutdown();
        if acknowledged {
            Ok(())
        } else {
            Err(receipt_actor_unavailable_error())
        }
    }

    /// True when durable persistence can no longer be trusted, so the kernel
    /// pre-dispatch gate must fail closed. This is either the supervised writer
    /// thread leaving the healthy state, or a poisoned verified head: the thread
    /// is alive but every append is rejected with a Conflict until an operator
    /// reseeds, which the thread flag alone cannot see.
    fn writer_serving_closed(&self) -> bool {
        self.writer.health().is_serving_closed() || self.health.head_poisoned.load(Ordering::SeqCst)
    }

    /// The supervised writer's severity and cumulative restart count, for the
    /// health report.
    fn writer_health_summary(&self) -> (HealthLevel, u64) {
        let snapshot = self.writer.health().snapshot();
        (snapshot.level, snapshot.restart_total)
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
        let (inflight, inflight_release, _previous_inflight) =
            WriterInflightLease::acquire(&self.health);
        let command = ReceiptCommitCommand::Append {
            request: Box::new(ReceiptCommitRequest {
                receipt,
                raw_json,
                ensure_lineage,
                response,
            }),
            inflight,
        };
        // Increment `inflight` BEFORE handing the command to the worker. If we
        // wait until after `try_send`, the worker can dequeue and commit before
        // this thread observes the send result. The command carries the paired
        // lease and releases it after the batch outcome is durable. A rejected
        // send or disconnected response uses the caller's shared release handle;
        // the release-once bit prevents either path from stealing another
        // command's count.
        self.health.note_channel_send();
        match self.sender.try_send(command) {
            Ok(()) => {
                self.health.accepted_total.fetch_add(1, Ordering::SeqCst);
                self.health.note_accept();
            }
            Err(mpsc::TrySendError::Full(_)) => {
                inflight_release.release();
                self.health.note_channel_send_rejected();
                self.health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                inflight_release.release();
                self.health.note_channel_send_rejected();
                self.health.note_writer_unavailable();
                return Err(self.writer_dead_error());
            }
        }
        match result.recv() {
            Ok(result) => result,
            Err(_) => {
                inflight_release.release();
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                self.health.note_writer_unavailable();
                Err(self.writer_dead_error())
            }
        }
    }

    /// Bounded variant of `append`: identical up to the response wait, which is
    /// capped at `timeout`. On expiry it does NOT decrement `inflight`. The
    /// `try_send` succeeded, so the command is still queued or running on the
    /// worker, which owns `inflight` and decrements it exactly once when it
    /// drains the batch. Decrementing here too would double-count a slow-but-live
    /// append and, under concurrency, could drive `inflight` to zero while work
    /// is still queued, making writer health look drained before the actor
    /// catches up. The timeout still fails this caller loudly and records a
    /// non-terminal timeout observation; a genuinely wedged writer keeps its
    /// actor-owned lease and `timed_out_inflight` elevated until the command
    /// eventually terminates.
    fn append_with_timeout(
        &self,
        receipt: ChioReceipt,
        raw_json: String,
        ensure_lineage: bool,
        timeout: Duration,
    ) -> Result<u64, ReceiptStoreError> {
        if let Some(database_identity_file) = self.database_identity_file.as_ref() {
            database_identity_file.validate()?;
        }
        let (response, result) = mpsc::sync_channel(1);
        let (inflight, inflight_release, _previous_inflight) =
            WriterInflightLease::acquire(&self.health);
        let command = ReceiptCommitCommand::Append {
            request: Box::new(ReceiptCommitRequest {
                receipt,
                raw_json,
                ensure_lineage,
                response,
            }),
            inflight,
        };
        self.health.note_channel_send();
        match self.sender.try_send(command) {
            Ok(()) => {
                self.health.accepted_total.fetch_add(1, Ordering::SeqCst);
                self.health.note_accept();
            }
            Err(mpsc::TrySendError::Full(_)) => {
                inflight_release.release();
                self.health.note_channel_send_rejected();
                self.health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                inflight_release.release();
                self.health.note_channel_send_rejected();
                self.health.note_writer_unavailable();
                return Err(receipt_actor_unavailable_error());
            }
        }
        match result.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                inflight_release.note_timeout();
                Err(receipt_actor_append_timeout_error(timeout))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                inflight_release.release();
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut last_error) = self.health.last_error.lock() {
                    *last_error = Some("sqlite receipt commit actor is unavailable".to_string());
                }
                Err(receipt_actor_unavailable_error())
            }
        }
    }

    fn flush(&self) -> Result<(), ReceiptStoreError> {
        let EnqueuedWriterJob {
            result,
            inflight_release,
        } = self.enqueue_flush()?;
        match result.recv() {
            Ok(outcome) => outcome,
            Err(_) => {
                inflight_release.release();
                self.health.note_writer_unavailable();
                Err(self.writer_dead_error())
            }
        }
    }

    fn flush_for_shutdown(&self) -> Result<(), ReceiptStoreError> {
        let send_gate = match self.health.send_gate.lock() {
            Ok(gate) => gate,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.health.closing.store(true, Ordering::SeqCst);
        let enqueued = self.enqueue_flush();
        drop(send_gate);
        let EnqueuedWriterJob {
            result,
            inflight_release,
        } = enqueued?;
        match result.recv() {
            Ok(outcome) => outcome,
            Err(_) => {
                inflight_release.release();
                self.health.note_writer_unavailable();
                Err(self.writer_dead_error())
            }
        }
    }

    fn flush_with_timeout(&self, timeout: Duration) -> Result<(), ReceiptStoreError> {
        let EnqueuedWriterJob {
            result,
            inflight_release,
        } = self.enqueue_flush()?;
        match result.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                inflight_release.note_timeout();
                Err(receipt_actor_flush_timeout_error(timeout))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                inflight_release.release();
                self.health.note_writer_unavailable();
                Err(self.writer_dead_error())
            }
        }
    }

    fn enqueue_flush(&self) -> Result<EnqueuedWriterJob<()>, ReceiptStoreError> {
        if let Some(database_identity_file) = self.database_identity_file.as_ref() {
            database_identity_file.validate()?;
        }
        let (response, result) = mpsc::sync_channel(1);
        let (inflight, inflight_release, _previous_inflight) =
            WriterInflightLease::acquire(&self.health);
        self.health.note_channel_send();
        match self.sender.try_send(ReceiptCommitCommand::Flush {
            response,
            inflight,
        }) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                inflight_release.release();
                self.health.note_channel_send_rejected();
                self.health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                inflight_release.release();
                self.health.note_channel_send_rejected();
                self.health.note_writer_unavailable();
                return Err(self.writer_dead_error());
            }
        }
        Ok(EnqueuedWriterJob {
            result,
            inflight_release,
        })
    }

    /// Wall-clock (unix-ms) at which the current unserviced backlog began, or
    /// `None` when no backlog has started. The liveness classifier anchors its
    /// stall clock here so idle-then-fresh work is not mistaken for a wedge.
    fn backlog_started_unix_ms(&self) -> Option<u64> {
        match self.health.backlog_started_unix_ms.load(Ordering::SeqCst) {
            0 => None,
            value => Some(value),
        }
    }

    fn writer_counters(&self) -> ReceiptWriterCounters {
        let last_commit_unix_ms = match self.health.last_commit_unix_ms.load(Ordering::SeqCst) {
            0 => None,
            value => Some(value),
        };
        let first_accept_unix_ms = match self.health.first_accept_unix_ms.load(Ordering::SeqCst) {
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
            timeout_total: self.health.timeout_total.load(Ordering::SeqCst),
            saturated_total: self.health.saturated_total.load(Ordering::SeqCst),
            inflight: self.health.inflight.load(Ordering::SeqCst),
            // Load after `inflight`: lease release clears this marker before
            // decrementing inflight, which avoids a snapshot that reports an
            // active timeout marker with no command still live.
            timed_out_inflight: self.health.timed_out_inflight.load(Ordering::SeqCst),
            queue_depth: self.health.queue_depth.load(Ordering::SeqCst),
            last_commit_unix_ms,
            first_accept_unix_ms,
            last_error,
        }
    }
}

struct EnqueuedWriterJob<T> {
    result: mpsc::Receiver<Result<T, ReceiptStoreError>>,
    inflight_release: WriterInflightReleaseHandle,
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

    /// Bounded variant of [`run_write_receipt`]: identical up to the response
    /// wait, which is capped at `timeout`. On expiry it fails this caller loudly
    /// without decrementing `inflight` (the actor still owns the queued job and
    /// decrements it exactly once when it drains). A genuinely wedged writer
    /// therefore keeps `inflight` elevated, which is the signal the liveness
    /// probe reads, and this caller does not pin the kernel-wide receipt write
    /// lock waiting on it.
    pub(crate) fn run_write_receipt_with_timeout<T, F>(
        &self,
        job: F,
        timeout: Duration,
    ) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        self.run_write_kind_with_timeout(job, true, timeout)
    }

    /// Bounded variant of [`run_write`]: a metadata-only write (capability
    /// lineage, session anchors) whose response wait is capped at `timeout`.
    /// Fail-closed and inflight-preserving on expiry exactly like
    /// [`run_write_receipt_with_timeout`], so a hot-path metadata write cannot
    /// hang the caller on a wedged writer.
    pub(crate) fn run_write_with_timeout<T, F>(
        &self,
        job: F,
        timeout: Duration,
    ) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        self.run_write_kind_with_timeout(job, false, timeout)
    }

    /// Bounded metadata write whose queued job must NOT take effect once the
    /// caller has timed out. On expiry the shared `abandoned` marker is set
    /// BEFORE reporting the timeout; a cooperating job (see
    /// `dispatch_intent_insert_job_unless_abandoned`) rechecks the marker
    /// inside its transaction and refuses to commit once marked. A job that
    /// finished in the instant between the deadline expiring and the marker
    /// landing already answered, so that answer is returned instead of a
    /// timeout for a write that committed.
    pub(crate) fn run_write_abandoning_on_timeout<T, F>(
        &self,
        job: F,
        timeout: Duration,
        abandoned: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        let EnqueuedWriterJob {
            result,
            inflight_release,
        } = self.enqueue_write_job(job, false)?;
        match result.recv_timeout(timeout) {
            Ok(outcome) => outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                abandoned.store(true, Ordering::SeqCst);
                if let Ok(outcome) = result.try_recv() {
                    return outcome;
                }
                inflight_release.note_timeout();
                Err(receipt_actor_write_timeout_error(timeout))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                inflight_release.release();
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut last_error) = self.health.last_error.lock() {
                    *last_error = Some("sqlite receipt commit actor is unavailable".to_string());
                }
                Err(receipt_actor_unavailable_error())
            }
        }
    }

    /// Enqueue one metadata write job without waiting for its outcome. For
    /// compensating work whose result the caller cannot act on anyway: the
    /// job still runs in FIFO order on the single writer with full health
    /// accounting, but the caller spends no wall-clock on its response. The
    /// only error surfaced is a refused enqueue (saturated or dead writer).
    pub(crate) fn run_write_detached<F>(&self, job: F) -> Result<(), ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<(), ReceiptStoreError> + Send + 'static,
    {
        // Dropping the receiver detaches the response; the writer actor
        // tolerates a gone caller and still reconciles committed/failed for
        // the job when it drains.
        self.enqueue_write_job(job, false).map(drop)
    }

    fn run_write_kind_with_timeout<T, F>(
        &self,
        job: F,
        appends_receipts: bool,
        timeout: Duration,
    ) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        let EnqueuedWriterJob {
            result,
            inflight_release,
        } = self.enqueue_write_job(job, appends_receipts)?;
        match result.recv_timeout(timeout) {
            Ok(outcome) => outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                inflight_release.note_timeout();
                Err(receipt_actor_write_timeout_error(timeout))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                inflight_release.release();
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                // Record the writer death so the next liveness sample reports the
                // writer Dead. The classifier keys the Dead verdict on the
                // "unavailable" marker, so without setting it a disconnected
                // writer with `inflight` compensated and `failed_total` matching
                // `accepted_total` would sample as Healthy and admit a tool side
                // effect before receipt persistence fails.
                if let Ok(mut last_error) = self.health.last_error.lock() {
                    *last_error = Some("sqlite receipt commit actor is unavailable".to_string());
                }
                Err(receipt_actor_unavailable_error())
            }
        }
    }

    fn run_write_kind<T, F>(&self, job: F, appends_receipts: bool) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        let EnqueuedWriterJob {
            result,
            inflight_release,
        } = self.enqueue_write_job(job, appends_receipts)?;
        match result.recv() {
            Ok(outcome) => outcome,
            Err(_) => {
                // Accepted-then-lost: invoke this command's shared release
                // handle. The
                // queued/actor lease may already have released during channel
                // teardown or unwind; the per-command release bit makes this
                // exact-once without consuming another command's count.
                inflight_release.release();
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                // Record the writer death so the next liveness sample reports the
                // writer Dead rather than Healthy (see the bounded-write arm).
                if let Ok(mut last_error) = self.health.last_error.lock() {
                    *last_error = Some("sqlite receipt commit actor is unavailable".to_string());
                }
                Err(receipt_actor_unavailable_error())
            }
        }
    }

    /// Box a write job, speculatively account it as in-flight, and enqueue it on
    /// the commit actor. Returns the response receiver and its shared inflight
    /// release handle on a successful enqueue; the caller decides how long to
    /// wait. A `Full`/`Disconnected` send invokes the handle before returning.
    fn enqueue_write_job<T, F>(
        &self,
        job: F,
        appends_receipts: bool,
    ) -> Result<EnqueuedWriterJob<T>, ReceiptStoreError>
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
                    // Return a prepared response instead of sending here. The
                    // actor publishes the resync-adjusted terminal counters and
                    // releases this command's lease before delivery.
                    let committed = final_outcome.is_ok();
                    PreparedWriterResponse {
                        committed,
                        send: Box::new(move || {
                            let _ = response.send(final_outcome);
                        }),
                    }
                });
            responder
        });
        let _send_gate = match self.health.send_gate.lock() {
            Ok(gate) => gate,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.health.closing.load(Ordering::SeqCst) {
            return Err(receipt_actor_closing_error());
        }
        // Pre-send increment: same race-avoidance invariant as
        // `ReceiptCommitActor::append` (see the comment at the `inflight`
        // increment in `append`). The actor adopts the increment through the
        // closure and head resync; any send failure undoes it here.
        let (inflight, inflight_release, _previous_inflight) =
            WriterInflightLease::acquire(&self.health);
        self.health.note_channel_send();
        match self.sender.try_send(ReceiptCommitCommand::Write {
            job: boxed,
            appends_receipts,
            inflight,
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
                self.health.note_accept();
            }
            Err(mpsc::TrySendError::Full(_)) => {
                inflight_release.release();
                self.health.note_channel_send_rejected();
                self.health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                inflight_release.release();
                self.health.note_channel_send_rejected();
                self.health.note_writer_unavailable();
                return Err(receipt_actor_unavailable_error());
            }
        }
        Ok(EnqueuedWriterJob {
            result,
            inflight_release,
        })
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

fn receipt_actor_closing_error() -> ReceiptStoreError {
    ReceiptStoreError::Pool("sqlite receipt commit actor is closing".to_string())
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

fn receipt_actor_append_timeout_error(timeout: Duration) -> ReceiptStoreError {
    ReceiptStoreError::Timeout {
        operation: "sqlite receipt commit append".to_string(),
        timeout_ms: timeout.as_millis().min(u128::from(u64::MAX)) as u64,
    }
}

fn receipt_actor_write_timeout_error(timeout: Duration) -> ReceiptStoreError {
    ReceiptStoreError::Timeout {
        operation: "sqlite receipt commit write".to_string(),
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

include!("../part_01_writer_actor.inc");
