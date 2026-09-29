mod capability_set_suspension;
#[cfg(test)]
mod deadline_tests;
mod declassification;
mod flow_state;
mod issuance_freeze;
mod native_declassification;
mod native_egress;
mod response_simulation;
pub(crate) use native_declassification::NativeDeclassificationOutcome;
mod native_mutation;
mod participant_source;
mod scoped_sql;
mod transaction;
use crate::encrypted_blob::SqliteEncryptedBlobStore;
use crate::store_connection::StoreConnection;
use chio_core::canonical::canonical_json_bytes;
use chio_core::hashing::sha256;
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::security::{
    validate_response_snapshot_lifecycle, ActiveDefenseReceiptBody,
};
use chio_core::SignedSecurityEvent;
pub use chio_security_types::clock::{Clock, SystemClock};
use chio_security_types::ports::{
    containment_installed_version_hash, containment_overlay_version_hash,
    containment_session_target, declassification_retain_until_unix_ms,
    declassification_retry_deadline_unix_ms, derive_declassification_event_id,
    derive_declassification_transition_id, predict_containment_overlay_apply,
    predict_containment_overlay_remove, predict_session_throttle_apply,
    predict_session_throttle_remove, session_throttle_installed_version_hash,
    session_throttle_version_hash, session_throttle_window_identity,
    validate_attested_finding_batch_body, validate_containment_overlay_snapshot,
    validate_session_throttle_snapshot, ActionId, AdvisorySecurityEvent, AttestedFindingBatchBody,
    AttestedFindingBatchKey, AttestedFindingBatchPublication, AttestedFindingBatchStore,
    AttestedFindingResponseAdmissionState, AttestedFindingResponseCompletionOutcome,
    AttestedFindingResponseCompletionState, AttestedFindingResponseOutboxHealth,
    AttestedFindingResponseOutboxKey, AttestedFindingResponseOutboxRecord,
    AttestedFindingResponseOutboxStore, AttestedFindingResponseOutboxTransition,
    AttestedFindingResponsePlanBody, AttestedFindingResponsePlanPublication,
    AttestedFindingResponsePlanningState, AutomaticResponseDispatchFenceOutcome,
    AutomaticResponseDispatchFenceRecord, AutomaticResponseDispatchFenceRequest, CanonicalBody,
    CapabilitySetSuspensionStore, CommittedEgressFence, ContainmentOverlayCommand,
    ContainmentOverlayStore, CorrelationCasRequest, CorrelationDeleteRequest,
    CorrelationEventAdmission, CorrelationEventAdmissionRequest, CorrelationEventIndexRequest,
    CorrelationIngressStore, CorrelationOutcomeCommitRequest, CorrelationOutcomeKey,
    CorrelationOutcomePublication, CorrelationOutcomeStatus, CorrelationPartial,
    CorrelationPartitionKey, CorrelationScan, CreateOutcome, DeclassificationCompactionCandidate,
    DeclassificationCompactionQuery, DeclassificationCompactionRequest, DeclassificationConsume,
    DeclassificationConsumptionEvidenceCommit, DeclassificationEvidenceAckRequest,
    DeclassificationEvidenceCommitStore, DeclassificationEvidencePendingQuery,
    DeclassificationEvidencePhase, DeclassificationEvidenceQuery, DeclassificationEvidenceRecord,
    DeclassificationEvidenceRetryRequest, DeclassificationEvidenceTombstone,
    DeclassificationOutcomeEvidenceCommit, DeclassificationTransitionBinding,
    DeclassificationUseQuery, DeclassificationUseRecord, DeclassificationUseState, DestinationId,
    Digest32, EffectExecutionStatus, EffectId, EffectOperation, EffectRequest, EffectResult,
    EffectResultQuery, EgressDeniedDestinations, EgressDestinationQuery, EgressDestinationSet,
    EgressFence, EgressFenceCommit, EgressFenceRequest, EgressRestrictionApplyRequest,
    EgressRestrictionCommand, EgressRestrictionContribution, EgressRestrictionContributions,
    EgressRestrictionDecision, EgressRestrictionEffectIds, EgressRestrictionRemoveRequest,
    EgressRestrictionSessionKey, EgressRestrictionSnapshot, EgressRestrictionStore, ErrorCode,
    EventAppend, EventId, EventPartitionScan, FlowJoinRequest, FlowStateKey, FlowStateSnapshot,
    FlowStateStore, GrantId, IsolationEpochEvidenceVerifierPort, IsolationEpochTransition,
    IsolationVerificationRecord, IssuanceFreezeStore, LeaseOwnerId, LineageFence,
    LineageFenceRelease, LineageFenceRenewal, LineageFenceRequest, LineageFenceStore,
    LineageFenceTakeover, OpaqueReceiptRef, OverlayApplyRequest, OverlayContribution,
    OverlayContributions, OverlayRemoveRequest, OverlaySnapshot, PortError, PortResult,
    PreparedActiveResponseDispatchBinding, ProducerId, ProducerTrustClass, ReceiptAppendRequest,
    RecordId, ResponseCasRequest, ResponseDispatchApproval, ResponseDispatchAuthorization,
    ResponseDispatchAuthorizationBody, ResponseDispatchCommitMode, ResponseDispatchCommitOutcome,
    ResponseDispatchCommitRequest, ResponseDispatchKey, ResponseDispatchLease,
    ResponseDispatchLoadOutcome, ResponseDispatchRecord, ResponseDispatchRecoveryOutcome,
    ResponseDispatchRecoveryRequest, ResponseDispatchStore, ResponseEffectCasRequest,
    ResponseEffectKey, ResponseEffectRecord, ResponsePlanKey, ResponsePlanRecord,
    ResponseReceiptCursor, ResponseReceiptCursorCasRequest, ResponseScheduledMutationCasRequest,
    ResponseSchedulerStore, ResponseStore, RuleId, ScheduledWork, SchedulerClaimRequest,
    SchedulerHealthAckRequest, SchedulerLeaseReleaseRequest, SchedulerLeaseRenewRequest,
    SchedulerRetryRequest, SchedulerRetryState, SchedulerWorkKey, SecurityEventStore,
    SecurityEventVerificationRecord, SessionThrottleApplyRequest, SessionThrottleCommand,
    SessionThrottleConsumeRequest, SessionThrottleContribution, SessionThrottleContributions,
    SessionThrottleDecision, SessionThrottleKey, SessionThrottleLimits,
    SessionThrottleRemoveRequest, SessionThrottleSnapshot, SessionThrottleStore,
    SessionThrottleWindowUsage, SessionThrottleWindowUsages, TenantId, TenantScopedId,
    UnverifiedEventBatch, UnverifiedSecurityEvent, VerifiedEventBatch,
    ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION, LINEAGE_FENCE_RENEWAL_MARGIN_MS,
    MAX_ATTESTED_FINDING_RESPONSE_OUTBOX_SCAN, MAX_DECLASSIFICATION_EVIDENCE_BATCH,
    PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
    RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
};
use chio_security_types::{
    InformationLabel, ResponseApprovalRequirement, ResponseEffectKind, ResponseMutationRecord,
    ResponseSnapshot, ResponseState, ResponseTarget, ResponseTransitionCause,
    RESPONSE_STATE_SCHEMA_VERSION,
};
pub(crate) use declassification::{
    verify_native_declassification_state, verify_native_pending_declassification,
};
use flow_state::load_flow_snapshot;
pub(crate) use flow_state::{
    observe_native_flow_state, resolve_native_input_join, resolve_native_label_join,
    verify_native_flow_state,
};
pub(crate) use native_egress::{NativeEgressCommand, NativeEgressResult};
pub(crate) use native_mutation::{
    deny_native_mutations, is_native_flow_join_table, join_native_flow,
    join_native_nonce_preflight, join_native_output, mutate_native_egress, NativeRowChange,
};
#[cfg(all(test, unix))]
pub(crate) use participant_source::seeded_security_history;
pub(crate) use participant_source::{
    decode_retained_security_row, encode_retained_security_values, retained_security_columns,
    RetainedSecuritySourceRows, TableHasher,
};
pub use participant_source::{
    SecurityParticipantSourceBinding, SecurityParticipantSourceError,
    SecurityParticipantSourceSeal, SecurityParticipantSourceSnapshot,
    SqliteSecurityParticipantSource,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::{Arc, MutexGuard};
use std::time::Duration;
use transaction::{trusted_time_in_transaction, SecurityStateWriteTransaction};

pub struct SqliteSecurityStateStore {
    connection: StoreConnection,
    isolation_epoch_verifier: Arc<dyn IsolationEpochEvidenceVerifierPort>,
    clock: Arc<dyn Clock>,
    #[cfg(unix)]
    database_path: PathBuf,
    #[cfg(unix)]
    database_identity: SecurityStateDatabaseFileIdentity,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SecurityStateDatabaseFileIdentity {
    device: u64,
    inode: u64,
}

/// Store-bound proof that the caller retains the exclusive lifecycle-owner
/// lease for this exact security-state database file.
#[cfg(unix)]
#[derive(Debug)]
pub struct SecurityStateLifecycleOwnerProof {
    locked_database_file: File,
    database_identity: SecurityStateDatabaseFileIdentity,
    #[cfg(target_os = "macos")]
    locked_lifecycle_file: File,
    #[cfg(target_os = "macos")]
    lifecycle_lock_identity: SecurityStateDatabaseFileIdentity,
}

/// Exact durable contribution counts that must reach zero before the
/// production active-defense services can be unpublished.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ActiveDefenseOverlayInventory {
    pub containment_contributions: u64,
    pub session_throttle_contributions: u64,
    pub capability_suspension_contributions: u64,
    pub issuance_freeze_contributions: u64,
    pub egress_restriction_contributions: u64,
}

impl ActiveDefenseOverlayInventory {
    #[must_use]
    pub const fn has_active_contributions(self) -> bool {
        self.containment_contributions != 0
            || self.session_throttle_contributions != 0
            || self.capability_suspension_contributions != 0
            || self.issuance_freeze_contributions != 0
            || self.egress_restriction_contributions != 0
    }
}

struct DenyIsolationEpochEvidence;

impl IsolationEpochEvidenceVerifierPort for DenyIsolationEpochEvidence {
    fn verify(&self, _: &IsolationEpochTransition) -> PortResult<IsolationVerificationRecord> {
        Err(PortError::invalid_data())
    }
}

impl SqliteSecurityStateStore {
    pub fn open(path: impl AsRef<Path>) -> PortResult<Self> {
        Self::open_with_dependencies(
            path,
            Arc::new(DenyIsolationEpochEvidence),
            Arc::new(SystemClock),
        )
    }

    pub fn open_with_isolation_epoch_verifier(
        path: impl AsRef<Path>,
        isolation_epoch_verifier: Arc<dyn IsolationEpochEvidenceVerifierPort>,
    ) -> PortResult<Self> {
        Self::open_with_dependencies(path, isolation_epoch_verifier, Arc::new(SystemClock))
    }

    pub fn open_with_trusted_clock(
        path: impl AsRef<Path>,
        clock: Arc<dyn Clock>,
    ) -> PortResult<Self> {
        Self::open_with_dependencies(path, Arc::new(DenyIsolationEpochEvidence), clock)
    }

    fn open_with_dependencies(
        path: impl AsRef<Path>,
        isolation_epoch_verifier: Arc<dyn IsolationEpochEvidenceVerifierPort>,
        clock: Arc<dyn Clock>,
    ) -> PortResult<Self> {
        let path = path.as_ref();
        let path_text = path.as_os_str().to_string_lossy();
        if path.as_os_str().is_empty()
            || path == Path::new(":memory:")
            || path_text.to_ascii_lowercase().starts_with("file:")
            || path_text.contains('?')
            || path_text.contains('#')
        {
            return Err(PortError::invalid_data());
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|_| PortError::unavailable())?;
            }
        }
        let connection = Connection::open(path).map_err(sqlite_error)?;
        participant_source::ensure_legacy_writable(&connection)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(sqlite_error)?;
        migrate(&connection)?;
        SqliteEncryptedBlobStore::open(path).map_err(|_| PortError::unavailable())?;
        #[cfg(unix)]
        let database_path = absolute_database_path(path)?;
        #[cfg(unix)]
        let database_identity = security_state_database_path_identity(&database_path)?;
        Ok(Self {
            connection: StoreConnection::transaction_only("security_state", connection),
            isolation_epoch_verifier,
            clock,
            #[cfg(unix)]
            database_path,
            #[cfg(unix)]
            database_identity,
        })
    }

    /// Bind a retained, exclusively locked descriptor to this store's exact
    /// opened main-database identity. The returned proof retains the lock.
    #[cfg(unix)]
    pub fn security_state_lifecycle_owner_proof(
        &self,
        locked_database_file: File,
        #[cfg(target_os = "macos")] locked_lifecycle_file: File,
    ) -> PortResult<SecurityStateLifecycleOwnerProof> {
        validate_security_state_database_binding(
            &self.database_path,
            self.database_identity,
            &locked_database_file,
        )?;
        #[cfg(not(target_os = "macos"))]
        rustix::fs::flock(
            &locked_database_file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|_| PortError::conflict())?;
        #[cfg(target_os = "macos")]
        let lifecycle_lock_path = security_state_lifecycle_lock_path(&self.database_path)?;
        #[cfg(target_os = "macos")]
        let lifecycle_lock_identity = security_state_database_path_identity(&lifecycle_lock_path)?;
        #[cfg(target_os = "macos")]
        validate_security_state_database_binding(
            &lifecycle_lock_path,
            lifecycle_lock_identity,
            &locked_lifecycle_file,
        )?;
        #[cfg(target_os = "macos")]
        rustix::fs::flock(
            &locked_lifecycle_file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|_| PortError::conflict())?;
        let proof = SecurityStateLifecycleOwnerProof {
            locked_database_file,
            database_identity: self.database_identity,
            #[cfg(target_os = "macos")]
            locked_lifecycle_file,
            #[cfg(target_os = "macos")]
            lifecycle_lock_identity,
        };
        self.validate_security_state_lifecycle_owner_proof(&proof)?;
        Ok(proof)
    }

    #[cfg(unix)]
    fn validate_security_state_lifecycle_owner_proof(
        &self,
        proof: &SecurityStateLifecycleOwnerProof,
    ) -> PortResult<()> {
        if proof.database_identity != self.database_identity {
            return Err(PortError::conflict());
        }
        #[cfg(not(target_os = "macos"))]
        rustix::fs::flock(
            &proof.locked_database_file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|_| PortError::conflict())?;
        validate_security_state_database_binding(
            &self.database_path,
            self.database_identity,
            &proof.locked_database_file,
        )?;
        #[cfg(target_os = "macos")]
        {
            let lifecycle_lock_path = security_state_lifecycle_lock_path(&self.database_path)?;
            let current_lock_identity =
                security_state_database_path_identity(&lifecycle_lock_path)?;
            if proof.lifecycle_lock_identity != current_lock_identity {
                return Err(PortError::conflict());
            }
            rustix::fs::flock(
                &proof.locked_lifecycle_file,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            )
            .map_err(|_| PortError::conflict())?;
            validate_security_state_database_binding(
                &lifecycle_lock_path,
                proof.lifecycle_lock_identity,
                &proof.locked_lifecycle_file,
            )?;
        }
        Ok(())
    }

    /// Reset process-owned declassification lifecycle flags only while the
    /// caller retains a store-bound exclusive lifecycle-owner proof.
    #[cfg(unix)]
    pub fn reset_declassification_lifecycle_for_owner_takeover(
        &self,
        proof: &SecurityStateLifecycleOwnerProof,
    ) -> PortResult<()> {
        self.validate_security_state_lifecycle_owner_proof(proof)?;

        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        declassification::reset_legacy_lifecycle(&transaction)?;
        self.validate_security_state_lifecycle_owner_proof(proof)?;
        transaction.commit().map_err(sqlite_error)?;
        self.validate_security_state_lifecycle_owner_proof(proof)
    }

    fn connection(&self) -> PortResult<MutexGuard<'_, Connection>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| PortError::unavailable())?;
        participant_source::ensure_legacy_writable(&connection)?;
        Ok(connection)
    }

    /// Sample time only after both the connection lock and SQLite snapshot are
    /// acquired. BEGIN DEFERRED alone does not establish a read snapshot; the
    /// retirement check performs that first read before consulting the clock.
    /// Mutation callers use BEGIN IMMEDIATE so a write-lock wait cannot consume
    /// the lifetime of a permission checked before this boundary.
    fn trusted_now_in_transaction(&self, transaction: &Transaction<'_>) -> PortResult<u64> {
        trusted_time_in_transaction(transaction, self.clock.as_ref())
    }

    /// Validate every durable restrictive overlay family and return one
    /// point-in-time contribution inventory. Expired rows remain active for
    /// lifecycle purposes until the durable scheduler removes them.
    pub fn active_defense_overlay_inventory(&self) -> PortResult<ActiveDefenseOverlayInventory> {
        <Self as ContainmentOverlayStore>::ensure_containment_overlays_ready(self)?;
        <Self as SessionThrottleStore>::ensure_session_throttles_ready(self)?;
        <Self as CapabilitySetSuspensionStore>::ensure_capability_set_suspensions_ready(self)?;
        <Self as IssuanceFreezeStore>::ensure_issuance_freezes_ready(self)?;
        <Self as EgressRestrictionStore>::ensure_egress_restrictions_ready(self)?;

        let connection = self.connection()?;
        let quick_check: String = connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        if quick_check != "ok" {
            return Err(PortError::integrity_failure());
        }
        let mut foreign_key_check = connection
            .prepare("PRAGMA foreign_key_check")
            .map_err(sqlite_error)?;
        if foreign_key_check
            .query([])
            .map_err(sqlite_error)?
            .next()
            .map_err(sqlite_error)?
            .is_some()
        {
            return Err(PortError::integrity_failure());
        }
        drop(foreign_key_check);

        let counts: (i64, i64, i64, i64, i64) = connection
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM security_effect_contributions),
                    (SELECT COUNT(*) FROM security_session_throttle_effects),
                    (SELECT COUNT(*) FROM security_capability_set_suspension_effects),
                    (SELECT COUNT(*) FROM security_issuance_freeze_effects),
                    (SELECT COUNT(*) FROM security_egress_restriction_effects)
                "#,
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .map_err(sqlite_error)?;
        Ok(ActiveDefenseOverlayInventory {
            containment_contributions: from_i64(counts.0)?,
            session_throttle_contributions: from_i64(counts.1)?,
            capability_suspension_contributions: from_i64(counts.2)?,
            issuance_freeze_contributions: from_i64(counts.3)?,
            egress_restriction_contributions: from_i64(counts.4)?,
        })
    }
}

#[cfg(unix)]
fn absolute_database_path(path: &Path) -> PortResult<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|directory| directory.join(path))
        .map_err(|_| PortError::unavailable())
}

#[cfg(target_os = "macos")]
fn security_state_lifecycle_lock_path(path: &Path) -> PortResult<PathBuf> {
    let file_name = path.file_name().ok_or_else(PortError::invalid_data)?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lifecycle.lock");
    Ok(path.with_file_name(lock_name))
}

#[cfg(unix)]
fn security_state_database_path_identity(
    path: &Path,
) -> PortResult<SecurityStateDatabaseFileIdentity> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PortError::unavailable())?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() || metadata.nlink() != 1
    {
        return Err(PortError::invalid_data());
    }
    Ok(SecurityStateDatabaseFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn validate_security_state_database_binding(
    path: &Path,
    expected_identity: SecurityStateDatabaseFileIdentity,
    file: &File,
) -> PortResult<()> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| PortError::conflict())?;
    let file_metadata = file.metadata().map_err(|_| PortError::conflict())?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || !file_metadata.file_type().is_file()
        || path_metadata.nlink() != 1
        || file_metadata.nlink() != 1
        || path_metadata.dev() != expected_identity.device
        || path_metadata.ino() != expected_identity.inode
        || file_metadata.dev() != expected_identity.device
        || file_metadata.ino() != expected_identity.inode
    {
        return Err(PortError::conflict());
    }
    Ok(())
}

mod codec;
use codec::{
    body_hash, canonical_request_hash, decode_digest, decode_label, encode_label, from_i64,
    normalize_sql, schema_object_definition_is_exact, schema_version_error, sqlite_error,
    table_definition_is_exact, to_i64, validate_canonical_json_body,
    validate_encrypted_blob_reference,
};

mod containment;
use containment::{load_overlay_snapshot, StoredEffectCommandProjection};

mod correlation;
use correlation::{
    compare_and_swap_correlation_in_transaction, index_partition_event_in_transaction,
    insert_correlation_outcome_record, load_correlation_outcome_record, load_correlation_partial,
    load_correlation_partition_generation, validate_correlation_outcome_publication,
    validate_correlation_outcome_storage_binding,
};

mod correlation_schema;
use correlation_schema::{
    ensure_attested_finding_batch_tenant_keys, table_has_foreign_key_violation,
    upgrade_correlation_ingress_pending_index, validate_attested_finding_batch_tenant_keys,
    validate_correlation_durable_schema,
};

mod declassification_codec;
use declassification_codec::{
    declassification_evidence_matches, declassification_evidence_row, declassification_phase_name,
    declassification_state_name, decode_declassification_binding,
    decode_declassification_evidence_row, decode_declassification_receipt,
    encode_declassification_binding, parse_declassification_state,
    validate_declassification_consumption_evidence, validate_declassification_outcome_evidence,
    DeclassificationEvidenceCommit,
};
#[cfg(test)]
use declassification_codec::{
    load_declassification_evidence_record, load_declassification_use_record,
};

mod declassification_schema;
use declassification_schema::{
    prepare_declassification_schema_migration, validate_declassification_evidence_integrity,
    validate_declassification_evidence_schema, DECLASSIFICATION_READINESS_CURSOR,
};

mod dispatch;
use dispatch::load_response_dispatch;

mod egress_restriction;
use egress_restriction::{
    effect_request_matches_query, empty_egress_restriction_snapshot,
    load_egress_restriction_snapshot,
};

mod events;
use events::{
    append_verified_in_transaction, load_event_identity, parse_trust_class,
    scan_verified_partition, EVENT_EVIDENCE_HASH_DOMAIN, MAX_EVENT_SCAN_RESULTS,
    RECEIPT_EVENT_EVIDENCE_HASH_DOMAIN,
};

mod finding_batches;
use finding_batches::{
    load_attested_finding_batch_record, validate_attested_response_execution_dispatch,
};

mod lineage_fence;

mod response_journal;
use response_journal::{
    decode_response_snapshot, load_response_plan, response_mutation_scheduler_fence,
};

mod response_outbox;

mod response_schema;
use response_schema::{
    attested_finding_response_outbox_is_one_to_one, ensure_attested_finding_response_outbox_schema,
    ensure_lineage_fence_binding_columns, ensure_response_dispatch_commit_mode_column,
    ensure_response_effect_generation_column, ensure_scheduler_lease_body_hash_column,
    ensure_scheduler_retry_health_columns, ATTESTED_FINDING_RESPONSE_OUTBOX_CANONICAL_DDL,
    ATTESTED_FINDING_RESPONSE_OUTBOX_DELETE_TRIGGER_DDL,
    ATTESTED_FINDING_RESPONSE_OUTBOX_DUE_INDEX_DDL,
    ATTESTED_FINDING_RESPONSE_OUTBOX_IMMUTABLE_TRIGGER_DDL,
};

mod scheduler;
use scheduler::{
    load_scheduler_claim, load_scheduler_lease, load_scheduler_retry, load_valid_scheduler_lease,
    next_scheduler_fencing_token, scheduler_lease_body_hash, validate_scheduler_fence,
    validate_scheduler_lease_binding, MAX_CLOCK_SKEW_MS, MAX_SCHEDULER_CLAIMS,
};

mod schema;
use schema::{migrate, SECURITY_STATE_STORE_SUPPORTED_SCHEMA_VERSION};

mod session_throttle;
use session_throttle::load_session_throttle_snapshot;

mod transition_journal;
use transition_journal::{check_transition_replay, record_transition, transition_status};
