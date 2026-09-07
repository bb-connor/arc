#[cfg(feature = "std")]
fn issuance_freeze_domain_hash(domain: &[u8], commitment: &impl Serialize) -> PortResult<Digest32> {
    use sha2::{Digest as _, Sha256};

    let mut value = serde_json::to_value(commitment).map_err(|_| PortError::integrity_failure())?;
    sort_json_object_keys(&mut value);
    let canonical = serde_json::to_vec(&value).map_err(|_| PortError::integrity_failure())?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(Digest32::new(hasher.finalize().into()))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRestrictionSessionKey {
    pub tenant_id: TenantId,
    pub session_id: SessionId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRestrictionContribution {
    pub effect_id: EffectId,
    pub destinations: EgressDestinationSet,
    pub contribution_hash: Digest32,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRestrictionCommand {
    pub request: EffectRequest,
    pub result: EffectResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRestrictionApplyRequest {
    pub key: EgressRestrictionSessionKey,
    pub action_id: ActionId,
    pub contribution: EgressRestrictionContribution,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: EgressRestrictionCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRestrictionRemoveRequest {
    pub key: EgressRestrictionSessionKey,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: EgressRestrictionCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRestrictionSnapshot {
    pub key: EgressRestrictionSessionKey,
    pub generation: u64,
    pub contributions: EgressRestrictionContributions,
    pub denied_destinations: EgressDeniedDestinations,
    pub highest_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressDestinationQuery {
    pub key: EgressRestrictionSessionKey,
    pub destination_id: DestinationId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRestrictionDecision {
    pub key: EgressRestrictionSessionKey,
    pub destination_id: DestinationId,
    pub denied: bool,
    pub active_effect_ids: EgressRestrictionEffectIds,
    pub generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlastRadiusQueryBounds {
    pub max_depth: u32,
    pub max_nodes: u32,
    pub max_edges: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalLineageNodeKind {
    Capability,
    Receipt,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalLineageEdgeKind {
    CapabilityDelegation,
    CapabilityReceipt,
    ReceiptLineage,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CausalLineageNode {
    pub tenant_id: TenantId,
    pub node_id: RecordId,
    pub kind: CausalLineageNodeKind,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CausalLineageEdge {
    pub tenant_id: TenantId,
    pub parent_id: RecordId,
    pub child_id: RecordId,
    pub kind: CausalLineageEdgeKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CausalLineageCommitMetadata {
    pub source_lineage_version: u64,
    pub observed_commit_index: u64,
    pub authoritative_commit_index: u64,
    pub completeness_watermark: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CausalLineageSnapshotRequest {
    pub tenant_id: TenantId,
    pub seed_ids: BlastRadiusSeeds,
    pub query_bounds: BlastRadiusQueryBounds,
    pub fence_action_id: Option<ActionId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CausalLineageSnapshot {
    pub tenant_id: TenantId,
    pub metadata: CausalLineageCommitMetadata,
    pub nodes: CausalLineageNodes,
    pub edges: CausalLineageEdges,
    pub depth_truncated: bool,
    pub nodes_truncated: bool,
    pub edges_truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CausalLineageCommitRequest {
    pub tenant_id: TenantId,
    pub metadata: CausalLineageCommitMetadata,
    pub nodes: CausalLineageNodes,
    pub edges: CausalLineageEdges,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlastRadiusSnapshotMetadata {
    pub query_bounds: BlastRadiusQueryBounds,
    pub source_lineage_version: u64,
    pub commit_index: u64,
    pub authoritative_commit_index: u64,
    pub completeness_watermark: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadiusIncompleteReason {
    InvalidQueryBounds,
    LineageStoreFailure,
    CrossTenantSnapshot,
    TruncatedSnapshot,
    InvalidLineageMetadata,
    ReplicaLag,
    MissingCompletenessWatermark,
    UnreportedTruncation,
    CrossTenantNode,
    ConflictingNode,
    MissingSeed,
    CrossTenantEdge,
    CorruptEdge,
    DepthTruncated,
    UnreachableNode,
    CycleCorruption,
    AffectedSetInvalid,
    HashFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlastRadiusRequest {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub seed_ids: BlastRadiusSeeds,
    pub query_bounds: BlastRadiusQueryBounds,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "completeness")]
pub enum BlastRadiusResult {
    Exact {
        metadata: BlastRadiusSnapshotMetadata,
        sorted_affected_ids: RecordIdSet,
        affected_set_hash: Digest32,
        graph_slice_hash: Digest32,
    },
    Incomplete {
        metadata: BlastRadiusSnapshotMetadata,
        reason: BlastRadiusIncompleteReason,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlastRadiusFenceAcquisition {
    pub request: BlastRadiusRequest,
    pub approved_result: BlastRadiusResult,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CausalLineageFenceRequest {
    pub fence: LineageFenceRequest,
    pub frozen_affected_ids: RecordIdSet,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineageFenceRequest {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub expected_commit_index: u64,
    pub expected_affected_set_hash: Digest32,
    pub scheduler_lease_owner_id: LeaseOwnerId,
    pub scheduler_fencing_token: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineageFence {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub commit_index: u64,
    pub affected_set_hash: Digest32,
    pub fencing_token: u64,
    pub scheduler_lease_owner_id: LeaseOwnerId,
    pub scheduler_fencing_token: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineageFenceRelease {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub fencing_token: u64,
    pub scheduler_lease_owner_id: LeaseOwnerId,
    pub scheduler_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineageFenceRenewal {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub fencing_token: u64,
    pub scheduler_lease_owner_id: LeaseOwnerId,
    pub scheduler_fencing_token: u64,
    pub expected_expires_at_unix_ms: u64,
    pub renewed_expires_at_unix_ms: u64,
}

/// Monotonic handoff of a live external lineage fence to a newly claimed
/// response-scheduler lease.
///
/// Both scheduler bindings and the external fencing token are compare-and-swap
/// inputs. A successful handoff advances both fencing domains, preventing the
/// prior worker from renewing or releasing the successor lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineageFenceTakeover {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub expected_fencing_token: u64,
    pub expected_scheduler_lease_owner_id: LeaseOwnerId,
    pub expected_scheduler_fencing_token: u64,
    pub expected_expires_at_unix_ms: u64,
    pub successor_scheduler_lease_owner_id: LeaseOwnerId,
    pub successor_scheduler_fencing_token: u64,
    pub successor_expires_at_unix_ms: u64,
}

/// Atomic local projection of one successful external fence renewal or
/// scheduler takeover.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeFenceMaintenanceRequest {
    pub key: IssuanceFreezeKey,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub expected_external_fence: LineageFence,
    pub maintained_external_fence: LineageFence,
    pub scheduler_work: ScheduledWork,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineageFenceMaintenanceRequest {
    pub plan: crate::ResponsePlan,
    /// Exact installed freeze effects that still own an external fence.
    ///
    /// The response scheduler derives this set from the durable effect
    /// journal. Restored effects are excluded so maintenance cannot recreate
    /// a fence after removal completed.
    pub effect_ids: Vec<EffectId>,
    pub scheduler_work: ScheduledWork,
    pub observed_at_unix_ms: u64,
    pub renewed_expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintainedLineageFence {
    pub effect_id: EffectId,
    pub fence: LineageFence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineageFenceMaintenanceOutcome {
    pub maintained: Vec<MaintainedLineageFence>,
    /// Exact selected freeze effects whose already-durable removal command was
    /// completed instead of renewed. These entries never represent a fence.
    pub completed_releases: Vec<EffectId>,
}

pub const OPAQUE_APPROVAL_ADMISSION_ARTIFACT_SCHEMA_VERSION: u8 = 1;

/// Portable descriptor for native admission material retained by a trusted
/// composition adapter.
///
/// `artifact_ref` and `artifact_digest` identify the authenticated artifact
/// bundle. The native capability, proposal, token set, and kernel request stay
/// opaque to active-defense crates.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueApprovalAdmissionArtifactBody {
    pub schema_version: u8,
    pub artifact_ref: AdmissionArtifactRef,
    pub artifact_digest: Digest32,
}

/// Fixed canonical envelope for an opaque admission artifact descriptor.
///
/// The canonical bytes and domain-separated digest let the active-defense
/// coordinator reject descriptor substitution without parsing or verifying
/// native authorization material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueApprovalAdmissionArtifact {
    pub body: OpaqueApprovalAdmissionArtifactBody,
    pub canonical_body: CanonicalBody,
    pub canonical_digest: Digest32,
}

/// Structurally bound input to the trusted governed-approval adapter.
///
/// This type contains no approval decision. Cryptographic verification,
/// threshold evaluation, replay reservation, and dispatch coordination remain
/// exclusively behind [`ApprovalVerifierPort`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedApprovalRequest {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub policy_hash: Digest32,
    pub approval_policy_id: RecordId,
    pub operator_capability_digest: Digest32,
    pub proposal_digest: Digest32,
    pub proposal_expires_at_unix_ms: u64,
    pub governed_intent_hash: Digest32,
    pub plan_expires_at_unix_ms: u64,
    pub admission_artifact: OpaqueApprovalAdmissionArtifact,
}

/// Governed preparation returned only by the trusted approval authority.
///
/// Reusing `PreparedActiveResponseDispatchBinding` makes the kernel-owned
/// admission operation and approval replay reservation the sole dispatch
/// authority. The complete request is retained for exact crash reconstruction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedApprovalReservation {
    pub request: GovernedApprovalRequest,
    pub prepared_dispatch_binding: PreparedActiveResponseDispatchBinding,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedApprovalReservationMutation {
    pub reservation: GovernedApprovalReservation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOperation {
    Apply,
    Remove,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRequest {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub effect_id: EffectId,
    pub effect_kind: ResponseEffectKind,
    pub target: ResponseTarget,
    pub plan_expires_at_unix_ms: u64,
    pub operation: EffectOperation,
    pub idempotency_key: RecordId,
    pub expected_version_hash: Digest32,
    pub scheduler_lease_owner_id: LeaseOwnerId,
    pub scheduler_fencing_token: u64,
    pub canonical_contribution: CanonicalBody,
    pub contribution_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectResult {
    pub effect_id: EffectId,
    pub resulting_version_hash: Digest32,
    pub applied: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectResultQuery {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub effect_id: EffectId,
    pub effect_kind: ResponseEffectKind,
    pub target: ResponseTarget,
    pub plan_expires_at_unix_ms: u64,
    pub operation: EffectOperation,
    pub idempotency_key: RecordId,
    pub expected_version_hash: Digest32,
    pub contribution_hash: Digest32,
    pub scheduler_lease_owner_id: LeaseOwnerId,
    pub scheduler_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", deny_unknown_fields)]
pub enum EffectExecutionStatus {
    NotExecuted,
    Completed { result: EffectResult },
    Failed { error_code: ErrorCode },
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptAppendRequest {
    pub tenant_id: TenantId,
    pub evidence_type: RecordId,
    pub evidence_id: OpaqueReceiptRef,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
    pub transition_id: RecordId,
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactReceiptRecord {
    pub receipt: ReceiptAppendRequest,
    pub durable_record_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAlert {
    pub tenant_id: TenantId,
    pub event_id: RecordId,
    pub idempotency_key: RecordId,
    pub occurred_at_unix_ms: u64,
    pub alert_type: RecordId,
    pub finding_id_hash: Digest32,
    pub action_id_hash: Option<Digest32>,
    pub evidence_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlertDeliveryQuery {
    pub alert: SecurityAlert,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", deny_unknown_fields)]
pub enum AlertDeliveryStatus {
    Pending {
        attempts: u32,
        next_attempt_at_unix_ms: u64,
    },
    Delivered {
        attempts: u32,
        delivered_at_unix_ms: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerHealthPageRequest {
    pub event_id: RecordId,
    pub idempotency_key: RecordId,
    pub occurred_at_unix_ms: u64,
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub first_failure_at_unix_ms: u64,
    pub attempts: u32,
    pub scheduler_fencing_token: u64,
    pub error_code: ErrorCode,
    pub alert: SecurityAlert,
}

#[cfg(feature = "std")]
pub trait IsolationEpochEvidenceVerifierPort: Send + Sync {
    fn verify(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<VerifiedIsolationEvidence>;
}

#[cfg(feature = "std")]
pub trait FlowStateStore: Send + Sync {
    fn load(&self, key: &FlowStateKey) -> PortResult<Option<FlowStateSnapshot>>;
    fn join(&self, request: &FlowJoinRequest) -> PortResult<FlowStateSnapshot>;
    fn open_isolation_epoch(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<FlowStateSnapshot>;
    fn acquire_egress_fence(&self, request: &EgressFenceRequest) -> PortResult<EgressFence>;
    fn validate_egress_fence(&self, fence: &EgressFence) -> PortResult<()>;
    fn commit_egress_fence(
        &self,
        commitment: &EgressFenceCommit,
    ) -> PortResult<CommittedEgressFence>;
}

#[cfg(feature = "std")]
pub trait ClassificationPort: Send + Sync {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult>;
}

#[cfg(feature = "std")]
pub trait TripwireDetectorPort: Send + Sync {
    fn detect(&self, input: &TripwireInput) -> PortResult<TripwireDecision>;
}

#[cfg(feature = "std")]
pub trait DeclassificationUseStore: Send + Sync {
    fn consume(
        &self,
        request: &DeclassificationConsumeRequest,
    ) -> PortResult<DeclassificationConsume>;
    fn record_outcome(&self, request: &DeclassificationOutcomeRequest) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait DeclassificationEvidenceCommitStore: Send + Sync {
    fn ensure_declassification_evidence_ready(&self) -> PortResult<()>;
    fn declassification_evidence_readiness_cursor(&self) -> PortResult<RecordId>;
    fn begin_declassification_reconciliation(&self) -> PortResult<()>;
    fn end_declassification_reconciliation(&self) -> PortResult<()>;
    fn seal_declassification_live_dispatch(&self) -> PortResult<()>;
    fn commit_declassification_consumption_evidence(
        &self,
        request: &DeclassificationConsumptionEvidenceCommit,
    ) -> PortResult<DeclassificationConsume>;
    fn commit_declassification_outcome_evidence(
        &self,
        request: &DeclassificationOutcomeEvidenceCommit,
    ) -> PortResult<()>;
    fn load_declassification_use(
        &self,
        query: &DeclassificationUseQuery,
    ) -> PortResult<Option<DeclassificationUseRecord>>;
    fn load_declassification_evidence(
        &self,
        query: &DeclassificationEvidenceQuery,
    ) -> PortResult<Option<DeclassificationEvidenceRecord>>;
    fn load_pending_declassification_evidence(
        &self,
        query: &DeclassificationEvidencePendingQuery,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>>;
    fn load_pending_declassification_evidence_batch(
        &self,
        now_unix_ms: u64,
        max_records: u32,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>>;
    fn load_stranded_declassification_consumptions_batch(
        &self,
        max_records: u32,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>>;
    fn acknowledge_declassification_evidence(
        &self,
        request: &DeclassificationEvidenceAckRequest,
    ) -> PortResult<()>;
    fn record_declassification_evidence_retry(
        &self,
        request: &DeclassificationEvidenceRetryRequest,
    ) -> PortResult<DeclassificationEvidenceRecord>;
    fn count_pending_declassification_evidence(&self) -> PortResult<u64>;
    fn count_stranded_declassification_consumptions(&self) -> PortResult<u64>;
    fn load_declassification_compaction_candidates(
        &self,
        query: &DeclassificationCompactionQuery,
    ) -> PortResult<Vec<DeclassificationCompactionCandidate>>;
    fn compact_declassification_evidence(
        &self,
        request: &DeclassificationCompactionRequest,
    ) -> PortResult<DeclassificationEvidenceTombstone>;
}

#[cfg(feature = "std")]
pub trait SecurityEventVerifierPort: Send + Sync {
    fn verify(&self, event: &UnverifiedSecurityEvent) -> PortResult<VerifiedSecurityEvent>;
}

#[cfg(feature = "std")]
pub trait SecurityEventStore: Send + Sync {
    fn admit_verified_correlation_event(
        &self,
        request: &CorrelationEventAdmissionRequest,
    ) -> PortResult<CorrelationEventAdmission>;
    fn append_verified(&self, event: &VerifiedSecurityEvent) -> PortResult<EventAppend>;
    fn append_advisory(&self, event: &AdvisorySecurityEvent) -> PortResult<EventAppend>;
    fn index_partition_event(&self, request: &CorrelationEventIndexRequest) -> PortResult<()>;
    fn scan_partition(&self, scan: &EventPartitionScan) -> PortResult<CorrelationScan>;
    fn load_correlation(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<CorrelationPartial>>;
    /// Returns the greatest event time durably indexed for this partition.
    /// Correlators use this as the authoritative max-seen source even before
    /// the next partition-state transition commits.
    fn load_correlation_max_seen_event_time(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<u64>>;
    fn compare_and_swap_correlation(
        &self,
        request: &CorrelationCasRequest,
    ) -> PortResult<CorrelationPartial>;
    fn commit_correlation_outcome(
        &self,
        request: &CorrelationOutcomeCommitRequest,
    ) -> PortResult<CorrelationPartial>;
    /// Publishes the final event-specific journal when an already committed
    /// partition transition covered this indexed event.
    fn commit_correlation_outcome_only(
        &self,
        outcome: &CorrelationOutcomePublication,
    ) -> PortResult<CreateOutcome>;
    fn load_correlation_outcome(
        &self,
        key: &CorrelationOutcomeKey,
    ) -> PortResult<Option<CorrelationOutcomePublication>>;
    fn delete_correlation(&self, request: &CorrelationDeleteRequest) -> PortResult<()>;
}

/// Durable handoff between authenticated event ingress and temporal
/// correlation.
///
/// Implementations must append `verified` and retain the exact unverified
/// envelope in one transaction. Acknowledgements are permanent tombstones:
/// replaying the same authenticated envelope after acknowledgement must not
/// make it pending again, while any identity rebinding must fail closed.
#[cfg(feature = "std")]
pub trait CorrelationIngressStore: Send + Sync {
    fn ensure_correlation_ingress_ready(&self) -> PortResult<()>;
    fn enqueue_verified_correlation_event(
        &self,
        event: &UnverifiedSecurityEvent,
        verified: &VerifiedSecurityEvent,
    ) -> PortResult<EventAppend>;
    fn load_pending_correlation_events(
        &self,
        max_results: u32,
    ) -> PortResult<UnverifiedEventBatch>;
    fn validate_pending_correlation_event(
        &self,
        event: &UnverifiedSecurityEvent,
        verified: &VerifiedSecurityEvent,
    ) -> PortResult<()>;
    fn acknowledge_correlated_event(&self, event: &UnverifiedSecurityEvent) -> PortResult<()>;
    fn count_pending_correlation_events(&self) -> PortResult<u64>;
}

/// Crash-atomic publication ledger between authoritative correlation evidence
/// and the policy-specific response planning pipeline.
#[cfg(feature = "std")]
pub trait AttestedFindingBatchStore: Send + Sync {
    fn ensure_attested_finding_batches_ready(&self) -> PortResult<()>;
    fn publish_attested_finding_batch(
        &self,
        publication: &AttestedFindingBatchPublication,
    ) -> PortResult<CreateOutcome>;
    fn load_attested_finding_batch(
        &self,
        key: &AttestedFindingBatchKey,
    ) -> PortResult<Option<AttestedFindingBatchPublication>>;
}

#[cfg(feature = "std")]
pub trait SealedDecoyRegistryStore: Send + Sync {
    fn load_by_id(&self, id: &DecoyArtifactLookup) -> PortResult<Option<SealedDecoyRecord>>;
    fn load_by_marker(&self, lookup: &SealedMarkerLookup) -> PortResult<Option<SealedDecoyRecord>>;
    fn load_by_public_ref(
        &self,
        lookup: &SealedPublicRefLookup,
    ) -> PortResult<Option<SealedDecoyRecord>>;
    fn compare_and_swap(&self, request: &SealedDecoyCasRequest) -> PortResult<SealedDecoyRecord>;
    fn scan(&self, scan: &DecoyScan) -> PortResult<SealedDecoyPage>;
}

#[cfg(feature = "std")]
pub trait WatermarkSequenceStore: Send + Sync {
    fn reserve(
        &self,
        request: &WatermarkSequenceReservation,
    ) -> PortResult<WatermarkSequenceReservationResult>;
}

#[cfg(feature = "std")]
pub trait WatermarkObservationStore: Send + Sync {
    fn record_first(
        &self,
        observation: &WatermarkObservation,
    ) -> PortResult<WatermarkObservationResult>;
}

#[cfg(feature = "std")]
pub trait ResponseStore: Send + Sync {
    fn load_plan(&self, key: &ResponsePlanKey) -> PortResult<Option<ResponsePlanRecord>>;
    fn create(&self, record: &ResponsePlanRecord) -> PortResult<CreateOutcome>;
    fn compare_and_swap(&self, request: &ResponseCasRequest) -> PortResult<ResponsePlanRecord>;
    fn load_effect(&self, key: &ResponseEffectKey) -> PortResult<Option<ResponseEffectRecord>>;
    fn persist_effect(&self, record: &ResponseEffectRecord) -> PortResult<CreateOutcome>;
    fn compare_and_swap_effect(
        &self,
        request: &ResponseEffectCasRequest,
    ) -> PortResult<ResponseEffectRecord>;
    fn load_receipt_cursor(
        &self,
        _key: &ResponsePlanKey,
    ) -> PortResult<Option<ResponseReceiptCursor>> {
        Err(PortError::unavailable())
    }
    fn initialize_receipt_cursor(
        &self,
        _cursor: &ResponseReceiptCursor,
    ) -> PortResult<CreateOutcome> {
        Err(PortError::unavailable())
    }
    fn compare_and_swap_receipt_cursor(
        &self,
        _request: &ResponseReceiptCursorCasRequest,
    ) -> PortResult<ResponseReceiptCursor> {
        Err(PortError::unavailable())
    }
    fn claim_due(&self, request: &SchedulerClaimRequest) -> PortResult<Vec<ScheduledWork>>;
}

#[cfg(feature = "std")]
pub trait ResponseSchedulerStore: ResponseStore {
    fn load_retry(&self, key: &SchedulerWorkKey) -> PortResult<Option<SchedulerRetryState>>;
    fn validate_lease(&self, work: &ScheduledWork) -> PortResult<()>;
    /// Compare the exact live scheduler lease and exact current response, then
    /// commit one fully validated appended mutation in the same transaction.
    fn compare_and_swap_scheduled_mutation(
        &self,
        request: &ResponseScheduledMutationCasRequest,
    ) -> PortResult<ResponsePlanRecord>;
    fn validate_lease_identity(
        &self,
        _tenant_id: &TenantId,
        _action_id: &ActionId,
        _lease_owner_id: &LeaseOwnerId,
        _fencing_token: u64,
    ) -> PortResult<()> {
        Err(PortError::unavailable())
    }
    fn renew_lease(&self, request: &SchedulerLeaseRenewRequest) -> PortResult<ScheduledWork>;
    fn record_retry(&self, request: &SchedulerRetryRequest) -> PortResult<SchedulerRetryState>;
    fn acknowledge_health_event(
        &self,
        request: &SchedulerHealthAckRequest,
    ) -> PortResult<SchedulerRetryState>;
    fn release_lease(&self, request: &SchedulerLeaseReleaseRequest) -> PortResult<()>;
}

/// Atomically admits an already-authorized response into durable execution.
///
/// A successful commit persists the immutable authorization, the response in
/// `Applying`, and its first scheduler lease in one commit domain. Implementors
/// must treat the dispatch key as an idempotency key and reject every binding
/// mismatch on retry or load.
#[cfg(feature = "std")]
pub trait ResponseDispatchStore: ResponseSchedulerStore {
    fn ensure_dispatch_ready(&self) -> PortResult<()>;

    /// Load the exact scheduler lease currently guarding a committed dispatch.
    /// Recovery callers use this as an optimistic fencing snapshot; the
    /// subsequent recovery mutation must compare the token atomically.
    fn load_dispatch_work(&self, _key: &SchedulerWorkKey) -> PortResult<Option<ScheduledWork>> {
        Err(PortError::unavailable())
    }

    /// Atomically close one exact automatic dispatch while it is still absent.
    ///
    /// Implementations must serialize this mutation with `commit_dispatch` in
    /// the same durable authority. A successful fence prevents every later
    /// dispatch for both the retained dispatch ID and its tenant-scoped action.
    fn fence_uncommitted_automatic_dispatch(
        &self,
        _request: &AutomaticResponseDispatchFenceRequest,
    ) -> PortResult<AutomaticResponseDispatchFenceOutcome> {
        Err(PortError::unavailable())
    }

    fn commit_dispatch(
        &self,
        request: &ResponseDispatchCommitRequest,
    ) -> PortResult<ResponseDispatchCommitOutcome>;

    fn load_dispatch(&self, key: &ResponseDispatchKey) -> PortResult<ResponseDispatchLoadOutcome>;

    /// Recover only against the exact nonzero fencing token observed by the
    /// caller. Implementations must reject missing or stale tokens and must
    /// never return a live lease owned by a different worker.
    fn recover_dispatch_work(
        &self,
        request: &ResponseDispatchRecoveryRequest,
    ) -> PortResult<ResponseDispatchRecoveryOutcome>;
}

#[cfg(feature = "std")]
pub trait SchedulerHealthPort: Send + Sync {
    fn ensure_scheduler_health_ready(&self) -> PortResult<()>;
    fn page_once(&self, request: &SchedulerHealthPageRequest) -> PortResult<AlertDeliveryStatus>;
    fn load_delivery(&self, query: &AlertDeliveryQuery) -> PortResult<Option<AlertDeliveryStatus>>;
}

#[cfg(feature = "std")]
pub trait ContainmentOverlayStore: Send + Sync {
    fn ensure_containment_overlays_ready(&self) -> PortResult<()>;
    fn apply_contribution(&self, request: &OverlayApplyRequest) -> PortResult<OverlaySnapshot>;
    fn remove_contribution(&self, request: &OverlayRemoveRequest) -> PortResult<OverlaySnapshot>;
    fn load_effective(&self, target: &TenantScopedId) -> PortResult<Option<OverlaySnapshot>>;
    fn load_containment_overlay_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus>;
}

#[cfg(feature = "std")]
pub trait SessionThrottleStore: Send + Sync {
    fn ensure_session_throttles_ready(&self) -> PortResult<()>;
    fn apply_session_throttle(
        &self,
        request: &SessionThrottleApplyRequest,
    ) -> PortResult<SessionThrottleSnapshot>;
    fn remove_session_throttle(
        &self,
        request: &SessionThrottleRemoveRequest,
    ) -> PortResult<SessionThrottleSnapshot>;
    fn load_session_throttles(
        &self,
        key: &SessionThrottleKey,
    ) -> PortResult<Option<SessionThrottleSnapshot>>;
    fn consume_session_invocation(
        &self,
        request: &SessionThrottleConsumeRequest,
    ) -> PortResult<SessionThrottleDecision>;
    fn load_session_throttle_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus>;
}

#[cfg(feature = "std")]
pub trait CapabilitySetSuspensionStore: Send + Sync {
    fn ensure_capability_set_suspensions_ready(&self) -> PortResult<()>;
    fn apply_capability_set_suspension(
        &self,
        request: &CapabilitySetSuspensionApplyRequest,
    ) -> PortResult<CapabilitySetSuspensionSnapshot>;
    fn remove_capability_set_suspension(
        &self,
        request: &CapabilitySetSuspensionRemoveRequest,
    ) -> PortResult<CapabilitySetSuspensionSnapshot>;
    fn load_capability_set_suspensions(
        &self,
        key: &CapabilitySetSuspensionKey,
    ) -> PortResult<Option<CapabilitySetSuspensionSnapshot>>;
    fn evaluate_capability_suspension(
        &self,
        query: &CapabilitySuspensionQuery,
    ) -> PortResult<CapabilitySuspensionDecision>;
    fn load_capability_set_suspension_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus>;
}

#[cfg(feature = "std")]
pub trait IssuanceFreezeStore: Send + Sync {
    fn ensure_issuance_freezes_ready(&self) -> PortResult<()>;
    fn apply_issuance_freeze(
        &self,
        request: &IssuanceFreezeApplyRequest,
    ) -> PortResult<IssuanceFreezeSnapshot>;
    fn prepare_issuance_freeze_remove(
        &self,
        request: &IssuanceFreezeRemoveRequest,
    ) -> PortResult<IssuanceFreezeContribution>;
    fn complete_issuance_freeze_remove(
        &self,
        request: &IssuanceFreezeRemoveRequest,
    ) -> PortResult<IssuanceFreezeSnapshot>;
    fn load_issuance_freezes(
        &self,
        key: &IssuanceFreezeKey,
    ) -> PortResult<Option<IssuanceFreezeSnapshot>>;
    fn evaluate_issuance_freeze(
        &self,
        query: &IssuanceFreezeAdmissionQuery,
    ) -> PortResult<IssuanceFreezeAdmissionDecision>;
    fn load_issuance_freeze_operation(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<IssuanceFreezeOperationStatus>;
    fn load_pending_issuance_freeze_release(
        &self,
        _key: &IssuanceFreezeKey,
        _action_id: &ActionId,
        _effect_id: &EffectId,
    ) -> PortResult<Option<IssuanceFreezePendingRelease>> {
        Err(PortError::unavailable())
    }
    fn load_completed_issuance_freeze_release(
        &self,
        _key: &IssuanceFreezeKey,
        _action_id: &ActionId,
        _effect_id: &EffectId,
        _plan_hash: Digest32,
    ) -> PortResult<Option<IssuanceFreezeCommand>> {
        Err(PortError::unavailable())
    }
    fn maintain_issuance_freeze_fence(
        &self,
        _request: &IssuanceFreezeFenceMaintenanceRequest,
    ) -> PortResult<IssuanceFreezeSnapshot> {
        Err(PortError::unavailable())
    }
}

#[cfg(feature = "std")]
pub trait EgressRestrictionStore: Send + Sync {
    fn ensure_egress_restrictions_ready(&self) -> PortResult<()>;
    fn apply_egress_restriction(
        &self,
        request: &EgressRestrictionApplyRequest,
    ) -> PortResult<EgressRestrictionSnapshot>;
    fn remove_egress_restriction(
        &self,
        request: &EgressRestrictionRemoveRequest,
    ) -> PortResult<EgressRestrictionSnapshot>;
    fn load_egress_restrictions(
        &self,
        key: &EgressRestrictionSessionKey,
    ) -> PortResult<Option<EgressRestrictionSnapshot>>;
    fn evaluate_destination(
        &self,
        query: &EgressDestinationQuery,
    ) -> PortResult<EgressRestrictionDecision>;
    fn load_egress_restriction_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus>;
}

#[cfg(feature = "std")]
pub trait BlastRadiusPort: Send + Sync {
    fn ensure_blast_radius_ready(&self) -> PortResult<()>;
    fn resolve(&self, request: &BlastRadiusRequest) -> PortResult<BlastRadiusResult>;
    fn acquire_fence(
        &self,
        acquisition: &BlastRadiusFenceAcquisition,
        expected: &LineageFenceRequest,
    ) -> PortResult<LineageFence>;
    fn query_fence(&self, expected: &LineageFenceRequest) -> PortResult<Option<LineageFence>>;
    fn renew_fence(&self, renewal: &LineageFenceRenewal) -> PortResult<LineageFence>;
    fn takeover_fence(&self, _takeover: &LineageFenceTakeover) -> PortResult<LineageFence> {
        Err(PortError::unavailable())
    }
    fn release_fence(&self, release: &LineageFenceRelease) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait CausalLineageStore: Send + Sync {
    fn ensure_causal_lineage_ready(&self) -> PortResult<()>;
    fn load_causal_snapshot(
        &self,
        request: &CausalLineageSnapshotRequest,
    ) -> PortResult<CausalLineageSnapshot>;
}

#[cfg(feature = "std")]
pub trait CausalLineageCommitStore: CausalLineageStore {
    fn commit_causal_lineage(&self, request: &CausalLineageCommitRequest) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait LineageFenceStore: Send + Sync {
    fn acquire(&self, request: &LineageFenceRequest) -> PortResult<LineageFence>;
    fn query(&self, action: &TenantScopedId) -> PortResult<Option<LineageFence>>;
    fn renew(&self, renewal: &LineageFenceRenewal) -> PortResult<LineageFence>;
    fn takeover(&self, _takeover: &LineageFenceTakeover) -> PortResult<LineageFence> {
        Err(PortError::unavailable())
    }
    fn release(&self, release: &LineageFenceRelease) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait CausalLineageFenceStore: LineageFenceStore {
    fn ensure_causal_lineage_fences_ready(&self) -> PortResult<()>;
    fn acquire_causal_fence(&self, request: &CausalLineageFenceRequest)
        -> PortResult<LineageFence>;
}

#[cfg(feature = "std")]
pub trait ApprovalVerifierPort: Send + Sync {
    /// Verify native authorization and reserve replay state in the one trusted
    /// admission authority.
    ///
    /// The implementation must compare the complete portable request with its
    /// scoped expected request, reload the native artifact bundle by the exact
    /// opaque reference, and verify that bundle against `artifact_digest`.
    /// Caller-built descriptors are never approval authority by themselves.
    fn verify_and_reserve(
        &self,
        request: &GovernedApprovalRequest,
    ) -> PortResult<GovernedApprovalReservation>;

    /// Reconstruct the exact pre-dispatch authority after a crash.
    ///
    /// `Ok(None)` means the trusted authority has no reusable pre-dispatch
    /// preparation. A malformed or rebound preparation is an error, not a
    /// missing reservation.
    fn reconstruct(
        &self,
        request: &GovernedApprovalRequest,
        retained: &GovernedApprovalReservation,
    ) -> PortResult<Option<GovernedApprovalReservation>>;

    fn commit(&self, mutation: &GovernedApprovalReservationMutation) -> PortResult<()>;
    fn cancel(&self, mutation: &GovernedApprovalReservationMutation) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait EffectPort: Send + Sync {
    fn ensure_effects_ready(&self) -> PortResult<()>;
    fn execute(&self, request: &EffectRequest) -> PortResult<EffectResult>;
    fn load_result(&self, query: &EffectResultQuery) -> PortResult<EffectExecutionStatus>;
    fn maintain_lineage_fences(
        &self,
        _request: &LineageFenceMaintenanceRequest,
    ) -> PortResult<LineageFenceMaintenanceOutcome> {
        Err(PortError::unavailable())
    }
}

#[cfg(feature = "std")]
pub trait SecurityReceiptSink: Send + Sync {
    fn ensure_receipts_ready(&self) -> PortResult<()>;
    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef>;
}

/// Receipt sink contract required by durable state machines. A successful
/// append is not authoritative until `load_exact` returns the identical
/// logical append request from durable signed storage.
#[cfg(feature = "std")]
pub trait ExactSecurityReceiptSink: SecurityReceiptSink {
    fn load_exact(&self, evidence_id: &OpaqueReceiptRef) -> PortResult<Option<ExactReceiptRecord>>;
}

#[cfg(feature = "std")]
pub trait SecurityAlertPort: Send + Sync {
    fn ensure_alerts_ready(&self) -> PortResult<()>;
    fn page(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus>;
    fn load_delivery(&self, query: &AlertDeliveryQuery) -> PortResult<Option<AlertDeliveryStatus>>;
}
