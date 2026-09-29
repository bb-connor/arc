use super::{
    ActionId, AdmissionArtifactRef, CanonicalBody, Deserialize, Digest32, PortResult,
    PreparedActiveResponseDispatchBinding, RecordId, Serialize, TenantId,
};

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
