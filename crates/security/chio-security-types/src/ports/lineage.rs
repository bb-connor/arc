use super::*;

pub const LINEAGE_FENCE_MAX_LEASE_MS: u64 = 60_000;
pub const LINEAGE_FENCE_RENEWAL_MARGIN_MS: u64 = 20_000;
pub type BlastRadiusSeeds = BoundedVec<RecordId, 256>;
pub type CausalLineageNodes = BoundedVec<CausalLineageNode, 4_096>;
pub type CausalLineageEdges = BoundedVec<CausalLineageEdge, 8_192>;

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
