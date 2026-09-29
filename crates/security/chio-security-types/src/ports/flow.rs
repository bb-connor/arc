use super::InformationLabel;
use super::Deserialize;
use super::Serialize;
use super::Digest32;
use super::TenantId;
use super::RecordId;
use super::LineageId;
use super::SessionId;
use super::IsolationEpochId;
use super::RequestId;
use super::OpaqueReceiptRef;
use super::PortResult;


#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantScopedId {
    pub tenant_id: TenantId,
    pub id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowStateKey {
    pub tenant_id: TenantId,
    pub principal_id: crate::PrincipalId,
    pub lineage_id: LineageId,
    pub session_id: SessionId,
    pub isolation_epoch_id: IsolationEpochId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowStateSnapshot {
    pub key: FlowStateKey,
    pub principal_label: InformationLabel,
    pub lineage_label: InformationLabel,
    pub session_label: InformationLabel,
    pub context_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowJoinRequest {
    pub key: FlowStateKey,
    pub principal_join: InformationLabel,
    pub lineage_join: InformationLabel,
    pub session_join: InformationLabel,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationEpochTransition {
    pub tenant_id: TenantId,
    pub principal_id: crate::PrincipalId,
    pub lineage_id: LineageId,
    pub previous_isolation_epoch_id: IsolationEpochId,
    pub new_isolation_epoch_id: IsolationEpochId,
    pub new_session_id: SessionId,
    pub verification_evidence_hash: Digest32,
    pub transition_id: RecordId,
    pub effective_at_unix_ms: u64,
}

/// A record returned by the installed isolation-evidence verifier.
/// Flow-state mutation invokes that verifier itself; request deserialization
/// cannot supply this record as authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationVerificationRecord {
    pub verifier_id: RecordId,
    pub receipt_ref: OpaqueReceiptRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressFenceRequest {
    pub key: FlowStateKey,
    pub request_id: RequestId,
    pub request_hash: Digest32,
    pub expected_context_generation: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressFence {
    pub fence_id: RecordId,
    pub key: FlowStateKey,
    pub request_id: RequestId,
    pub request_hash: Digest32,
    pub context_generation: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressFenceCommit {
    pub fence: EgressFence,
    pub dispatch_commitment_id: RecordId,
    pub committed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedEgressFence {
    pub fence_id: RecordId,
    pub request_id: RequestId,
    pub request_hash: Digest32,
    pub context_generation: u64,
    pub dispatch_commitment_id: RecordId,
    pub committed_at_unix_ms: u64,
}

#[cfg(feature = "std")]
/// Verify durable isolation evidence bound to the complete transition. This is
/// an attestation of isolation/destruction, not a transient authorization lookup.
/// Stores may invoke the port outside database locks, then independently recheck
/// current state before committing. Implementations must not rely on a store
/// transaction remaining locked while this method runs.
pub trait IsolationEpochEvidenceVerifierPort: Send + Sync {
    fn verify(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<IsolationVerificationRecord>;
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
