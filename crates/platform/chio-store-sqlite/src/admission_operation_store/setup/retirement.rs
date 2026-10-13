//! Explicit local retirement binds completed historical custody to a live owner.
use super::*;
use chio_core::{Keypair, Signature};
use chio_kernel::admission_operation::RequestNamespaceDigest;

/// Local operator signing data. This observation grants no execution authority
/// and is independently verified by the native owner before any mutation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSetupRetirementBodyV1 {
    pub domain_version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub selection_digest: CanonicalPayloadDigest,
    pub workflow_id: WorkflowId,
    pub operation_id: OperationId,
    pub request_namespace: RequestNamespaceDigest,
    pub original_request: AdmissionIdentifier,
    pub serving_fence: StoreMutationFence,
}

/// A local operator signature over exact retirement data, never a readiness
/// claim or an agent-facing protocol command.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSetupRetirementAuthorizationV1 {
    body: NativeSetupRetirementBodyV1,
    operator: PublicKey,
    signature: Signature,
}

impl NativeSetupRetirementAuthorizationV1 {
    pub fn sign(
        body: NativeSetupRetirementBodyV1,
        operator: &Keypair,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let signing_digest = digest(RecoveryDigestDomain::SetupRetirement, &body)?;
        Ok(Self {
            body,
            operator: operator.public_key(),
            signature: operator.sign(&signing_digest),
        })
    }

    pub fn body(&self) -> &NativeSetupRetirementBodyV1 {
        &self.body
    }

    pub fn operator(&self) -> &PublicKey {
        &self.operator
    }

    pub fn verify_signature(&self) -> Result<bool, AdmissionOperationStoreError> {
        let signing_digest = digest(RecoveryDigestDomain::SetupRetirement, &self.body)?;
        Ok(self.operator.verify(&signing_digest, &self.signature))
    }
}

impl core::fmt::Debug for NativeSetupRetirementBodyV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NativeSetupRetirementBodyV1([redacted])")
    }
}

impl core::fmt::Debug for NativeSetupRetirementAuthorizationV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NativeSetupRetirementAuthorizationV1([redacted])")
    }
}

impl SqliteAdmissionOperationStore {
    /// Administrative, effect-free retirement is unavailable until exact
    /// historical native custody and consumed-origin fencing are implemented.
    pub fn retire_legacy_setup(
        &self,
        _actor: &AuthenticatedRecoveryActor,
        _authorization: &NativeSetupRetirementAuthorizationV1,
        _fence: &StoreMutationFence,
        _now: u64,
    ) -> Result<NativeSetupRetirementBodyV1, AdmissionOperationStoreError> {
        Err(refused("explicit legacy setup retirement unavailable"))
    }
}
