use crate::admission_operation::{AdmissionOperationBindingV1, NativeSecurityAuthorityBindingV1};
use crate::{SecurityInvocationContext, ToolCallRequest};
use chio_core_types::recovery::{
    RecoveryGrantBodyV2, SignedAuthorityCoverageAttestationV1, SignedRecoveryGrantV2,
};
use chio_core_types::PublicKey;
use chio_security_types::flow::{InformationLabel, PrincipalId};
use chio_security_types::ports::{FlowStateKey, FlowStateSnapshot};
use chio_security_types::recovery::*;
use serde::{Deserialize, Serialize};

pub const MAX_RECOVERY_WORKFLOWS: usize = 64;
pub const MAX_RECOVERY_COMMANDS: usize = 4096;
pub const MAX_RECOVERY_RECORD_BYTES: usize = 262_144;
pub const MAX_RECOVERY_REVIEW_MS: u64 = 900_000;
pub const MAX_RECOVERY_GRANT_SECONDS: u64 = 60;

/// Only recovery commands distinguish semantic conflicts. Native store errors
/// remain unchanged and cannot acquire new execution/closure meanings.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryCommandPortError {
    #[error("recovery command conflicted")]
    Conflict,
    #[error("recovery original is not eligible")]
    OriginRefused,
    #[error("recovery process journal is busy")]
    Busy,
    #[error(transparent)]
    Store(#[from] crate::admission_operation::AdmissionOperationStoreError),
}

/// Public bounded categories preserve command replay semantics without exposing
/// native error text or turning a stale mutation into a transport outage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecoveryCommandError {
    #[error("recovery authority refused")]
    AuthorityDenied,
    #[error("recovery command conflicted")]
    Conflict,
    #[error("recovery original is not eligible")]
    OriginRefused,
    #[error("recovery process journal is busy")]
    Busy,
    #[error("recovery mediation is required")]
    MediationRequired,
    #[error("recovery authority is unavailable; retain the command identity")]
    Unavailable,
}

/// An operator-selected identity is independent of a rotating caller token.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryActorAssignment {
    pub subject: PublicKey,
    pub principal: PrincipalId,
    pub permissions: BoundedList<RecoveryPermission, 16>,
    pub preview_clearance: InformationLabel,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPermission {
    Create,
    Inspect,
    Select,
    Approve,
    Resume,
    Cancel,
    Report,
    Settle,
    KnowledgeRead,
    KnowledgeWrite,
    KnowledgeAdopt,
    KnowledgeAdmin,
    ConfinedLaunch,
    ConfinedReturn,
    ConfinedCancel,
    Maintain,
    InspectExplanationGraph,
}
impl RecoveryPermission {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Inspect => "inspect",
            Self::Select => "select",
            Self::Approve => "approve",
            Self::Resume => "resume",
            Self::Cancel => "cancel",
            Self::Report => "report",
            Self::Settle => "settle",
            Self::KnowledgeRead => "knowledge.read",
            Self::KnowledgeWrite => "knowledge.write",
            Self::KnowledgeAdopt => "knowledge.adopt",
            Self::KnowledgeAdmin => "knowledge.admin",
            Self::ConfinedLaunch => "confined.launch",
            Self::ConfinedReturn => "confined.return",
            Self::ConfinedCancel => "confined.cancel",
            Self::Maintain => "maintain",
            Self::InspectExplanationGraph => "explanation.inspect",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCoverageAssignment {
    pub issuer_id: IssuerId,
    pub principal: PrincipalId,
    pub key: PublicKey,
    pub obligations: NonEmptyBoundedList<AuthorityObligationV1, MAX_RECOVERY_OBLIGATIONS>,
}

/// The trusted operator selects the setup root before installing a deployment.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSetupPolicyV1 {
    pub operator_root: PublicKey,
}

/// Only trusted host setup installs this profile. Incoming commands cannot
/// select roots, widen powers, change a provider or disable native participants.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDeploymentV1 {
    pub scope: RecoveryScopeV1,
    pub native_authority: NativeSecurityAuthorityBindingV1,
    pub security_context: SecurityInvocationContext,
    pub server_id: RecordName,
    pub tool_name: RecordName,
    pub recipient: chio_security_types::ports::DestinationId,
    pub purpose: chio_security_types::flow::DeclassificationPurpose,
    pub target_label: InformationLabel,
    pub policy_digest: PolicyDigest,
    pub contract_digest: ContractDigest,
    pub authority_scope: AuthorityScopeDigest,
    pub attachment_profile: RecoveryAttachmentProfile,
    pub aggregate_issuer: PublicKey,
    pub aggregate_issuer_id: RecordName,
    pub actors: NonEmptyBoundedList<RecoveryActorAssignment, 64>,
    pub coverage: NonEmptyBoundedList<RecoveryCoverageAssignment, MAX_RECOVERY_OBLIGATIONS>,
    pub effect_cardinality: SafeInteger,
    pub effect_contract: RecoveryEffectContractV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_policy: Option<NativeSetupPolicyV1>,
}
pub type RecordName = chio_security_types::ports::RecordId;

/// The kernel derives the complete original binding with its existing hash
/// implementation. Neither an argument digest nor a local negative lookup
/// replaces this identity.
pub struct RecoveryNativeIdentity {
    pub(crate) binding: AdmissionOperationBindingV1,
}

/// Only a current result-classification refusal may become withheld custody.
/// Store, capture and immutable-evidence errors keep their original error type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecoveryResultClassificationError {
    #[error("current recovery result classifier is unavailable")]
    Unavailable,
    #[error("current recovery result classification refused")]
    Refused,
}
impl RecoveryNativeIdentity {
    pub fn binding(&self) -> &AdmissionOperationBindingV1 {
        &self.binding
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApprovalSubmissionV1 {
    pub intent: ApprovalIntentV1,
    pub coverage: NonEmptyBoundedList<
        SignedAuthorityCoverageAttestationV1,
        MAX_RECOVERY_APPROVAL_ATTESTATIONS,
    >,
}

/// Authenticated protected history retains the original wider codec. Reading
/// these bytes does not recertify them as a fresh approval or capture permit.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRetainedApprovalV1 {
    pub intent: ApprovalIntentV1,
    pub coverage:
        NonEmptyBoundedList<SignedAuthorityCoverageAttestationV1, MAX_RECOVERY_OBLIGATIONS>,
}
impl TryFrom<RecoveryApprovalSubmissionV1> for RecoveryRetainedApprovalV1 {
    type Error = ContractError;

    fn try_from(submission: RecoveryApprovalSubmissionV1) -> Result<Self, Self::Error> {
        Ok(Self {
            intent: submission.intent,
            coverage: NonEmptyBoundedList::new(submission.coverage.as_slice().to_vec())?,
        })
    }
}

/// Protected exact caller custody remains separate from native history, which
/// intentionally omits one-shot credentials. These bytes are never public status.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedRequestEnvelopeV1 {
    pub action_intent: IntentDigest,
    pub authorization_requirements: AuthorizationRequirementsDigest,
    pub request: ProtectedText<65536>,
    pub process_request_digest: ProcessRequestDigest,
    pub process_binding_digest: ProcessCallBindingDigest,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAdmissionIntentV1 {
    pub intent: AdmissionIntentRef,
    pub native_binding: crate::admission_operation::PersistedAdmissionOperationBindingV1,
    pub native_operation_id: OperationId,
    pub process_request_digest: ProcessRequestDigest,
    pub process_binding_digest: ProcessCallBindingDigest,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryWorkflowRecordV1 {
    pub scope: RecoveryScopeV1,
    /// Missing only in retained legacy history, never eligible for new capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<RecoveryOriginV1>,
    pub workflow_id: WorkflowId,
    pub step_id: StepId,
    pub continuation_id: ContinuationId,
    pub revision: SafeInteger,
    pub control: WorkflowControlV1,
    pub seed: ToolCallRequest,
    pub creation_seed: ProtectedText<32768>,
    pub deployment_digest: DeploymentDigest,
    pub created_by: PrincipalId,
    pub effect_cardinality: SafeInteger,
    pub action: Option<ActionIntentV1>,
    pub process_reservation: Option<ProtectedText<4096>>,
    pub selected: bool,
    pub review: Option<ApprovalIntentV1>,
    pub approval: Option<RecoveryRetainedApprovalV1>,
    pub issuance: Option<RecoveryGrantBodyV2>,
    pub signed_grant: Option<SignedRecoveryGrantV2>,
    pub envelope: Option<FinalizedRequestEnvelopeV1>,
    pub admission: Option<RecoveryAdmissionIntentV1>,
    pub admission_closed: bool,
    pub native_link: Option<OperationId>,
    pub captured: bool,
    /// Required immutable deployment custody on new captures. Absence denotes
    /// legacy captured history, never permission to substitute current roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_deployment: Option<RecoveryCapturedDeploymentRefV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub historical_hold: Option<RecoveryHistoricalHoldV1>,
    pub effect: EffectObservationV1,
    pub release: ReleaseDispositionV1,
    pub original_flow: Option<FlowStateSnapshot>,
    pub reported_decision: Option<RecoveryReportedDecision>,
    pub provider_finality: Option<chio_core_types::recovery::SignedRecoveryProviderFinalityV1>,
    pub provider_lookups: SafeInteger,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCapturedDeploymentRefV1 {
    pub deployment_digest: DeploymentDigest,
    pub record_version: SafeInteger,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryHistoricalHoldReasonV1 {
    LegacyDeploymentUnavailable,
    FrozenOutputVerifierUnavailable,
    FrozenSigningCustodyUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryHistoricalHoldV1 {
    pub operation: OperationRef,
    pub reason: RecoveryHistoricalHoldReasonV1,
}

/// Only the native store's authenticated captured-custody lookup selects this
/// result. It grants no dispatch, capture, output or new actor authority.
pub enum RecoveryCapturedDeploymentV1 {
    Verified(Box<RecoveryDeploymentV1>),
    LegacyUnavailable,
    Quarantined,
}

/// A current classification selected by the kernel for one exact completed
/// result. SDK decoding and public labels cannot construct this release basis.
pub struct RecoveryResultReleaseBasis {
    pub(crate) deployment_digest: DeploymentDigest,
    pub(crate) operation_id: crate::admission_operation::AdmissionOperationId,
    pub(crate) request_binding_hash: crate::admission_operation::AdmissionDigest,
    pub(crate) operation_version: u64,
    pub(crate) classified_output: InformationLabel,
}
impl RecoveryResultReleaseBasis {
    pub fn deployment_digest(&self) -> DeploymentDigest {
        self.deployment_digest
    }
    pub fn operation_id(&self) -> &crate::admission_operation::AdmissionOperationId {
        &self.operation_id
    }
    pub fn request_binding_hash(&self) -> &crate::admission_operation::AdmissionDigest {
        &self.request_binding_hash
    }
    pub fn operation_version(&self) -> u64 {
        self.operation_version
    }
    pub fn classified_output(&self) -> &InformationLabel {
        &self.classified_output
    }
}

/// Borrow one authenticated resolved payload for current classification. This
/// read-only context cannot construct capture, join or release authority.
pub struct RecoveryResultClassificationContext<'a> {
    pub(crate) operation: &'a crate::admission_operation::AdmissionOperationV1,
    pub(crate) request: &'a ToolCallRequest,
    pub(crate) security_context: &'a SecurityInvocationContext,
    pub(crate) output: &'a crate::ToolCallOutput,
}
impl RecoveryResultClassificationContext<'_> {
    pub fn operation(&self) -> &crate::admission_operation::AdmissionOperationV1 {
        self.operation
    }
    pub fn request(&self) -> &ToolCallRequest {
        self.request
    }
    pub fn security_context(&self) -> &SecurityInvocationContext {
        self.security_context
    }
    pub fn output(&self) -> &crate::ToolCallOutput {
        self.output
    }
}
impl core::fmt::Debug for RecoveryResultClassificationContext<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryResultClassificationContext([redacted])")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryVerificationContextV1 {
    pub action: ActionIntentV1,
    pub approval: RecoveryRetainedApprovalV1,
    pub grant: SignedRecoveryGrantV2,
    pub deployment: RecoveryDeploymentV1,
    pub original_flow: FlowStateSnapshot,
}

/// Public response contains opaque references and bounded state only. Exact
/// preview and result release are distinct, freshly authorized operations.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCommandResponseV1 {
    pub command_id: CommandId,
    pub workflow_id: WorkflowId,
    pub revision: SafeInteger,
    pub control: WorkflowControlV1,
    pub effect: EffectObservationV1,
    pub release: ReleaseDispositionV1,
}

macro_rules! redacted {
    ($($ty:ty),+ $(,)?) => {$(impl core::fmt::Debug for $ty {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { f.write_str(concat!(stringify!($ty), "([redacted])")) }
    })+};
}
redacted!(
    RecoveryActorAssignment,
    RecoveryCoverageAssignment,
    RecoveryDeploymentV1,
    RecoveryNativeIdentity,
    RecoveryApprovalSubmissionV1,
    RecoveryRetainedApprovalV1,
    FinalizedRequestEnvelopeV1,
    RecoveryAdmissionIntentV1,
    RecoveryWorkflowRecordV1,
    RecoveryVerificationContextV1,
    RecoveryCapturedDeploymentV1,
    RecoveryResultReleaseBasis
);

pub fn recovery_flow_key(context: &SecurityInvocationContext) -> FlowStateKey {
    let context = context.as_v1();
    FlowStateKey {
        tenant_id: context.tenant_id().clone(),
        principal_id: context.principal_id().clone(),
        lineage_id: context.lineage_root_id().clone(),
        session_id: context.session_id().clone(),
        isolation_epoch_id: context.isolation_epoch_id().clone(),
    }
}

pub fn recovery_review_digest(
    action: &ActionIntentV1,
    request: &ToolCallRequest,
) -> Result<ReviewDigest, crate::KernelError> {
    let bytes = request
        .recovery_review_projection()
        .canonical_action_preview(action)
        .map_err(|_| crate::KernelError::DurableAdmission("recovery preview refused".into()))?;
    Ok(ReviewDigest::from_bytes(
        *chio_core_types::recovery::RecoveryDigestDomain::Preview
            .digest(&bytes)
            .as_bytes(),
    ))
}

/// Identity data checked against the actual process journal by its owning port.
/// Deserializing it never creates dispatch or reservation authority.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryProcessReservationV1 {
    pub runtime_id: String,
    pub process_id: String,
    pub continuation_id: ContinuationId,
    pub operation_key: String,
    pub request_id: String,
    pub capability_digest: String,
    pub unsigned_intent: IntentDigest,
    pub server_id: String,
    pub host_binding: String,
}
redacted!(RecoveryProcessReservationV1);

/// One immutable native recovery sink contract. The operator selects the HTTPS resource and
/// observation key; neither tool arguments nor SDK commands may retarget it.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEffectContractV1 {
    pub schema: RecoveryEffectContractSchema,
    pub provider: RecoveryEffectProviderId,
    pub account: RecoveryEffectAccountId,
    pub resource: ProtectedText<2048>,
    pub observation_key: PublicKey,
    pub max_response_bytes: SafeInteger,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryEffectContractSchema {
    #[serde(rename = "chio.recovery.support-issue-effect.v1")]
    V1,
}
redacted!(RecoveryEffectContractV1);

pub fn recovery_authority_scope_digest(
    profile: &RecoveryDeploymentV1,
) -> Result<AuthorityScopeDigest, crate::KernelError> {
    // Zero only this self-referential digest. Every operator-selected field,
    // including keys, coverage and the pinned sink, remains in the preimage.
    let mut unsigned = profile.clone();
    unsigned.authority_scope = AuthorityScopeDigest::from_bytes([0; 32]);
    Ok(AuthorityScopeDigest::from_bytes(super::recovery_digest(
        chio_core_types::recovery::RecoveryDigestDomain::AuthorityScope,
        &unsigned,
    )?))
}

/// One bounded read-only observation, selected under current settlement control.
/// It is affine and cannot be constructed or deserialized by an SDK.
/// One bounded original-operation observation selected by the native owner.
///
/// ```compile_fail
/// use chio_kernel::recovery::RecoveryProviderLookup;
/// fn duplicate(lookup: &RecoveryProviderLookup) {
///     let _: RecoveryProviderLookup = Clone::clone(lookup);
/// }
/// ```
///
/// ```compile_fail
/// use chio_kernel::recovery::RecoveryProviderLookup;
/// let _: Result<RecoveryProviderLookup, _> = serde_json::from_str("{}");
/// ```
pub struct RecoveryProviderLookup {
    pub(crate) workflow: RecoveryWorkflowRecordV1,
    pub(crate) deployment: RecoveryDeploymentV1,
    pub(crate) captured_deployment: RecoveryDeploymentV1,
    pub(crate) expires_at_unix_ms: u64,
    pub(crate) request_budget: Option<super::RecoveryProviderLookupBudget>,
}
impl RecoveryProviderLookup {
    pub fn workflow(&self) -> &RecoveryWorkflowRecordV1 {
        &self.workflow
    }
    pub fn deployment(&self) -> &RecoveryDeploymentV1 {
        &self.deployment
    }
    /// Exact original provider route and contract, separate from current
    /// authorization of the observation key selected by deployment().
    pub fn captured_deployment(&self) -> &RecoveryDeploymentV1 {
        &self.captured_deployment
    }
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
    pub const fn request_budget(&self) -> Option<super::RecoveryProviderLookupBudget> {
        self.request_budget
    }
}
redacted!(RecoveryProviderLookup);

/// Full, exact, freshly authorized review content. A display may not abbreviate
/// this document and claim its digest covers the omitted information.
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReviewDocumentV1 {
    pub intent: ApprovalIntentV1,
    pub canonical_preview: ProtectedText<32768>,
}
redacted!(RecoveryReviewDocumentV1);
