use std::sync::Arc;

use chio_appraisal::VerifiedRuntimeAttestationRecord;
use chio_core::receipt::metadata::GuardEvidence;
use dashmap::DashMap;

use crate::budget_store::{BudgetAdmissionOperationBinding, BudgetCommitMetadata};
use crate::*;

mod active_response_admission;
mod active_response_artifact;
mod active_response_committed_recovery;
mod active_response_coordinator;
mod active_response_executor;
mod active_response_operation_binding;
mod active_response_policy;
mod active_response_proof;
mod admission_cleanup;
mod admission_coordinator;
mod admission_terminal_receipt;
mod agent_economy_admission_coordinator;
mod approval_cleanup;
mod budget_sweep;
mod caller_reservation_handoff;
mod credential_reservation;
mod dispatch_intent;
mod error;
mod kernel_drop_guard;
mod kernel_scopes;
mod kernel_struct;
mod ordinary_admission;
mod payment_reconcile;
mod security_runtime;
mod verified_treaty;

pub use active_response_admission::{
    ActiveResponseAuthorizationRequest, ActiveResponseFindingAuthority,
    ActiveResponseFindingAuthorityError, ActiveResponseSubmissionProof,
    ActiveResponseSubmissionProofBody, ActiveResponseSubmissionProofError,
    AuthoritativeCorrelatedFindingEvidence, VerifiedActiveResponseBindings,
    ACTIVE_RESPONSE_SUBMISSION_SCHEMA,
};
#[cfg(test)]
pub use active_response_artifact::ActiveResponseArtifactAuthorityAttestationInput;
pub use active_response_artifact::{
    active_response_admission_artifact_payload_digest,
    active_response_artifact_authority_signing_bytes, active_response_submission_proof_digest,
    ActiveResponseArtifactAuthorityAttestation, ActiveResponseArtifactAuthorityAttestationBody,
    ActiveResponseArtifactAuthorityAttestationError,
    ACTIVE_RESPONSE_ADMISSION_ARTIFACT_PAYLOAD_SCHEMA,
    ACTIVE_RESPONSE_ARTIFACT_AUTHORITY_ATTESTATION_SCHEMA,
};
pub use active_response_committed_recovery::{
    DispatchCommittedActiveResponseResume, PreDispatchActiveResponseReconstruction,
};
pub use active_response_coordinator::{
    ActiveResponseAdmissionRequest, AutomaticActiveResponsePermit,
    GovernedActiveResponseReservation, PreparedActiveResponseAdmission,
};
pub(crate) use active_response_executor::ActiveResponseExecutionRequestParts;
pub use active_response_executor::{
    derive_active_response_dispatch_id, ActiveResponseCommittedDispatch,
    ActiveResponseDispatchIdError, ActiveResponseEffectEvidence, ActiveResponseExecutionApproval,
    ActiveResponseExecutionEvidence, ActiveResponseExecutionEvidenceParts,
    ActiveResponseExecutionOutcome, ActiveResponseExecutionRequest,
    ActiveResponseExecutorAuthority, ActiveResponseExecutorAuthorityIdentity,
    ActiveResponseExecutorError, ActiveResponseExecutorIdentityError,
    ActiveResponseFailedEffectEvidence, ActiveResponseFailureEvidence,
    ActiveResponseReceiptProofSource, AutomaticActiveResponseDispatchFenceOutcome,
};
pub use active_response_policy::{
    ActiveResponsePolicyRequest, ActiveResponsePolicyResolutionError, ActiveResponseRequirement,
    ActiveResponseRequirementResolver,
};
pub use budget_sweep::{
    BudgetHoldSweepHandle, DEFAULT_HOLD_EXPIRY_HORIZON_SECS, DEFAULT_HOLD_SWEEP_INTERVAL_SECS,
};
pub use caller_reservation_handoff::{
    CallerReservationAuthorizationOutcome, CallerReservationReplayProbe,
};
pub use construction::KernelBuildError;
pub use dispatch_intent::DefaultDispatchIntentReconciler;
pub use error::{
    HotPathStage, KernelError, OverloadResource, ReplayClockDirection, StructuredErrorReport,
};
pub use kernel_struct::{
    ChioKernel, HotPathDeadlineConfig, HybridSigningConfig, KernelConfig, MemoryBudgetConfig,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_SIZE_BYTES, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES, DEFAULT_RECEIPT_APPEND_BUDGET_MS,
    DEFAULT_RECEIPT_WRITER_POLL_MS, DEFAULT_RECEIPT_WRITER_STALL_MS, DEFAULT_RETENTION_DAYS,
    DEFAULT_RUNTIME_ADMISSION_READINESS_TIMEOUT_MS, MIN_RECEIPT_APPEND_BUDGET_MS,
};
pub use payment_reconcile::{
    MonetaryDispatchIntentReconciler, PaymentReconcileOutcome, PaymentReconcileReport,
};
pub use security_runtime::{GovernedSecurityRuntimePublication, GovernedSecurityRuntimeStatus};
pub use verified_treaty::{
    FederationTreatyAdmissionBinding, FederationTreatyVerification,
    VerifiedFederationTreatyMaterial,
};

pub(crate) use agent_economy_admission_coordinator::{
    AgentEconomyDurableToolAdmission, AgentEconomyDurableToolReturnInput,
};
use caller_reservation_handoff::{
    CallerReservationCaptureOutcome, PrepareCallerReservationHandoff,
};
pub(crate) use kernel_drop_guard::{PostAdmissionDropGuard, PostAdmissionReceiptContext};
pub(crate) use kernel_scopes::{
    current_receipt_evaluation_scope_key, current_scoped_receipt_federation_admission,
    current_scoped_receipt_tenant_id, extract_tenant_id_from_auth_context,
    scope_receipt_federation_admission, scope_receipt_tenant_id, ReceiptFederationAdmission,
    ScopedKernelDispatchIntent, ScopedKernelReceiptFederationAdmission,
    ScopedKernelReceiptTenantId, RECEIPT_EVALUATION_SCOPE_KEY,
};
pub(crate) use kernel_struct::{
    capability_crypto_floor, receipt_crypto_floor, ReservedSiblingShare, RestartReservedHoldGate,
};
pub(crate) use ordinary_admission::OrdinaryAdmissionMutation;

pub type AgentId = String;

/// A string-typed capability identifier.
pub type CapabilityId = String;

/// A string-typed server identifier.
pub type ServerId = String;

const MANIFEST_SECURITY_METADATA_KEY: &str = "chio_manifest_security_v1";
const PROTOCOL_ADMISSION_METADATA_KEY: &str = "protocol_admission";
const BUDGET_AUTHORITY_METADATA_KEY: &str = "budget_authority";
const BUDGET_DENIAL_AUTHORITY_METADATA_KEY: &str = "budget_denial_authority";
const FINANCIAL_METADATA_KEY: &str = "financial";
const GOVERNED_TRANSACTION_METADATA_KEY: &str = "governed_transaction";

const RESERVED_RECEIPT_METADATA_KEYS: [&str; 6] = [
    MANIFEST_SECURITY_METADATA_KEY,
    PROTOCOL_ADMISSION_METADATA_KEY,
    BUDGET_AUTHORITY_METADATA_KEY,
    BUDGET_DENIAL_AUTHORITY_METADATA_KEY,
    FINANCIAL_METADATA_KEY,
    GOVERNED_TRANSACTION_METADATA_KEY,
];

fn reserved_receipt_metadata_key(metadata: Option<&serde_json::Value>) -> Option<&'static str> {
    let object = metadata.and_then(serde_json::Value::as_object)?;
    RESERVED_RECEIPT_METADATA_KEYS
        .iter()
        .copied()
        .find(|key| object.contains_key(*key))
}

fn strip_reserved_receipt_metadata(metadata: &mut Option<serde_json::Value>) {
    let Some(object) = metadata.as_mut().and_then(serde_json::Value::as_object_mut) else {
        return;
    };
    for key in RESERVED_RECEIPT_METADATA_KEYS {
        object.remove(key);
    }
}

fn strip_reserved_economic_receipt_metadata(metadata: &mut Option<serde_json::Value>) {
    let Some(object) = metadata.as_mut().and_then(serde_json::Value::as_object_mut) else {
        return;
    };
    object.remove(FINANCIAL_METADATA_KEY);
    object.remove(GOVERNED_TRANSACTION_METADATA_KEY);
}

fn reject_reserved_receipt_metadata(
    metadata: Option<&serde_json::Value>,
) -> Result<(), KernelError> {
    let Some(key) = reserved_receipt_metadata_key(metadata) else {
        return Ok(());
    };
    let purpose = match key {
        MANIFEST_SECURITY_METADATA_KEY => "registry-validated kernel entrypoints",
        PROTOCOL_ADMISSION_METADATA_KEY => "kernel-derived admission receipts",
        BUDGET_AUTHORITY_METADATA_KEY | BUDGET_DENIAL_AUTHORITY_METADATA_KEY => {
            "kernel-derived budget receipts"
        }
        FINANCIAL_METADATA_KEY | GOVERNED_TRANSACTION_METADATA_KEY => {
            "kernel-derived economic receipts"
        }
        _ => "kernel-derived receipts",
    };
    Err(KernelError::InvalidReceiptMetadata(format!(
        "{key} is reserved for {purpose}"
    )))
}

pub(crate) fn validate_payment_adapter_identifier(
    identifier: &str,
    field_name: &'static str,
) -> Result<(), PaymentError> {
    if identifier.is_empty()
        || identifier.trim() != identifier
        || identifier.chars().any(char::is_control)
    {
        return Err(PaymentError::RailError(format!(
            "payment adapter returned an invalid {field_name}; outcome unknown"
        )));
    }
    Ok(())
}

fn registry_validated_manifest_security_metadata(
    request: &ToolCallRequest,
    registry: &chio_manifest::VerifiedManifestRegistry,
    security: &chio_manifest::BridgeSecurityMetadata,
    metadata: Option<serde_json::Value>,
) -> Result<serde_json::Value, KernelError> {
    reject_reserved_receipt_metadata(metadata.as_ref())?;
    registry
        .validate_invocation_arguments(
            &request.server_id,
            &request.tool_name,
            security,
            &request.arguments,
        )
        .map_err(|error| KernelError::InvalidReceiptMetadata(error.to_string()))?;
    security
        .merge_into_kernel_metadata(metadata)
        .map_err(|error| KernelError::InvalidReceiptMetadata(error.to_string()))
}

/// Fail-closed authority consulted immediately before capability issuance or
/// delegation becomes visible to the governed runtime.
///
/// The portable query binds the trusted tenant, lineage root, operation, and
/// parent capability. Implementations perform the durable local admission
/// check. The receipt store performs the final causal-fence check in the same
/// transaction that records a previously unseen capability, closing the race
/// between this preflight and lineage mutation.
pub trait CapabilityIssuanceAdmissionAuthority: Send + Sync {
    fn ensure_ready(&self) -> chio_security_types::ports::PortResult<()>;

    fn authorize(
        &self,
        query: &chio_security_types::ports::IssuanceFreezeAdmissionQuery,
    ) -> chio_security_types::ports::PortResult<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedGovernedPayeeBinding {
    beneficiary_id: String,
    settlement_destination_ref: String,
    payee_binding_digest: String,
    economic_intent_digest: String,
    pre_action_authority_digest: String,
    credit_facility_bind: Option<chio_credit::obligation::VerifiedCreditFacilityBindV1>,
}

impl VerifiedGovernedPayeeBinding {
    pub(in crate::kernel) fn new(
        beneficiary_id: String,
        settlement_destination_ref: String,
        economic_intent_digest: String,
        pre_action_authority_digest: String,
    ) -> Result<Self, chio_credit::obligation::ObligationError> {
        let payee_binding_digest = chio_credit::obligation::derive_obligation_payee_binding_digest(
            &beneficiary_id,
            &settlement_destination_ref,
        )?;
        Ok(Self {
            beneficiary_id,
            settlement_destination_ref,
            payee_binding_digest,
            economic_intent_digest,
            pre_action_authority_digest,
            credit_facility_bind: None,
        })
    }

    #[must_use]
    pub(crate) fn with_credit_facility_bind(
        mut self,
        credit_facility_bind: chio_credit::obligation::VerifiedCreditFacilityBindV1,
    ) -> Self {
        self.credit_facility_bind = Some(credit_facility_bind);
        self
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        beneficiary_id: &str,
        settlement_destination_ref: &str,
        economic_intent_digest: &str,
        pre_action_authority_digest: &str,
    ) -> Result<Self, chio_credit::obligation::ObligationError> {
        Self::new(
            beneficiary_id.to_owned(),
            settlement_destination_ref.to_owned(),
            economic_intent_digest.to_owned(),
            pre_action_authority_digest.to_owned(),
        )
    }

    #[must_use]
    pub(crate) fn beneficiary_id(&self) -> &str {
        &self.beneficiary_id
    }

    #[must_use]
    pub(crate) fn settlement_destination_ref(&self) -> &str {
        &self.settlement_destination_ref
    }

    #[must_use]
    pub(crate) fn payee_binding_digest(&self) -> &str {
        &self.payee_binding_digest
    }

    #[must_use]
    pub(crate) fn economic_intent_digest(&self) -> &str {
        &self.economic_intent_digest
    }

    #[must_use]
    pub(crate) fn pre_action_authority_digest(&self) -> &str {
        &self.pre_action_authority_digest
    }

    #[must_use]
    pub(crate) const fn credit_facility_bind(
        &self,
    ) -> Option<&chio_credit::obligation::VerifiedCreditFacilityBindV1> {
        self.credit_facility_bind.as_ref()
    }

    #[must_use]
    pub(crate) const fn is_credit_facility(&self) -> bool {
        self.credit_facility_bind.is_some()
    }
}

/// Authoritative security identity and isolation state supplied by a trusted
/// runtime boundary. Tool-call request fields are not a source for this data.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "version", content = "context", rename_all = "snake_case")]
pub enum SecurityInvocationContext {
    /// Version 1 of the authoritative invocation context.
    V1(SecurityInvocationContextV1),
}

/// Version 1 fields carried by [`SecurityInvocationContext`].
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityInvocationContextV1 {
    tenant_id: chio_security_types::ports::TenantId,
    session_id: chio_security_types::ports::SessionId,
    principal_id: chio_security_types::PrincipalId,
    isolation_epoch_id: chio_security_types::ports::IsolationEpochId,
    lineage_root_id: chio_security_types::ports::LineageId,
    /// Immutable isolation-incarnation generation covered by a capability's
    /// signed security binding.
    context_generation: u64,
    /// Mutable durable flow-state generation observed for this dispatch. This
    /// is deliberately not part of capability binding validation.
    flow_state_generation: Option<u64>,
}

impl SecurityInvocationContextV1 {
    #[must_use]
    pub const fn new(
        tenant_id: chio_security_types::ports::TenantId,
        session_id: chio_security_types::ports::SessionId,
        principal_id: chio_security_types::PrincipalId,
        isolation_epoch_id: chio_security_types::ports::IsolationEpochId,
        lineage_root_id: chio_security_types::ports::LineageId,
        context_generation: u64,
    ) -> Self {
        Self {
            tenant_id,
            session_id,
            principal_id,
            isolation_epoch_id,
            lineage_root_id,
            context_generation,
            flow_state_generation: None,
        }
    }

    /// Attach the mutable durable flow-state generation observed by the
    /// authoritative context resolver for this dispatch.
    #[must_use]
    pub const fn with_flow_state_generation(mut self, flow_state_generation: u64) -> Self {
        self.flow_state_generation = Some(flow_state_generation);
        self
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &chio_security_types::ports::TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &chio_security_types::ports::SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn principal_id(&self) -> &chio_security_types::PrincipalId {
        &self.principal_id
    }

    #[must_use]
    pub const fn isolation_epoch_id(&self) -> &chio_security_types::ports::IsolationEpochId {
        &self.isolation_epoch_id
    }

    #[must_use]
    pub const fn lineage_root_id(&self) -> &chio_security_types::ports::LineageId {
        &self.lineage_root_id
    }

    #[must_use]
    pub const fn context_generation(&self) -> u64 {
        self.context_generation
    }

    /// Return the mutable flow-state generation, when a durable flow authority
    /// supplied one. This value must never be used as a capability caveat.
    #[must_use]
    pub const fn flow_state_generation(&self) -> Option<u64> {
        self.flow_state_generation
    }
}

impl SecurityInvocationContext {
    /// Stable numeric version for the current context shape.
    pub const V1_VERSION: u16 = 1;

    #[must_use]
    pub const fn v1(context: SecurityInvocationContextV1) -> Self {
        Self::V1(context)
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        match self {
            Self::V1(_) => Self::V1_VERSION,
        }
    }

    #[must_use]
    pub const fn as_v1(&self) -> &SecurityInvocationContextV1 {
        match self {
            Self::V1(context) => context,
        }
    }
}

/// Trusted host authority that resolves authoritative identity, isolation,
/// lineage, and generation state for one tool dispatch.
///
/// Implementations must use host-owned session and capability state. Tool
/// request fields are not an authority for any value in the returned context.
pub trait SecurityInvocationContextAuthority: Send + Sync {
    fn resolve_security_invocation_context(
        &self,
        context: &chio_core::session::OperationContext,
        operation: &chio_core::session::ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError>;
}

/// Controls whether authoritative security state and a pre-dispatch hook are
/// required before the kernel may enter a tool connector.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SecurityPreDispatchPolicy {
    /// Preserve compatibility for hosts that have not installed the security
    /// pre-dispatch integration. When both a hook and context are present, the
    /// hook still runs and its rejection remains fail-closed.
    #[default]
    Optional,
    /// Require both authoritative security context and an installed hook for
    /// every tool dispatch.
    Enforce,
}

/// Canonical, authoritative input committed immediately before tool dispatch.
pub struct SecurityPreDispatchContext<'a> {
    /// The validated tool-call request.
    pub request: &'a ToolCallRequest,
    /// RFC 8785 canonical JSON bytes for the complete request.
    pub canonical_request: &'a [u8],
    /// Identity and isolation state supplied by the trusted runtime boundary.
    pub security_context: &'a SecurityInvocationContext,
    /// Deterministic identifier bound to the canonical request and every
    /// authoritative context field.
    pub dispatch_commitment_id: &'a chio_security_types::ports::RecordId,
}

/// Durable terminal state for a security mutation consumed immediately before
/// connector entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityDispatchOutcome {
    /// The connector completed successfully.
    Released,
    /// Connector entry was never reached, so non-delivery is proven.
    DispatchFailed,
    /// Connector entry occurred, but delivery or side effects cannot be
    /// determined from the observed terminal path.
    OutcomeUnknownAfterDispatch,
}

/// Authority that durably records one terminal outcome for a consumed
/// pre-dispatch security mutation.
pub trait SecurityDispatchOutcomeRecorder: Send {
    fn record(&mut self, outcome: SecurityDispatchOutcome) -> Result<(), KernelError>;
}

/// One-shot owner for the terminal state of a consumed pre-dispatch security
/// mutation. Explicit completion propagates persistence errors. Dropping an
/// unfinished handle records proven non-delivery before connector entry or an
/// unknown outcome after connector entry, on a best-effort basis without
/// panicking.
pub struct SecurityDispatchOutcomeHandle {
    request_id: String,
    dispatch_commitment_id: chio_security_types::ports::RecordId,
    recorder: Option<Box<dyn SecurityDispatchOutcomeRecorder>>,
    drop_outcome: SecurityDispatchOutcome,
}

impl SecurityDispatchOutcomeHandle {
    #[must_use]
    pub fn new(
        context: &SecurityPreDispatchContext<'_>,
        recorder: Box<dyn SecurityDispatchOutcomeRecorder>,
    ) -> Self {
        Self {
            request_id: context.request.request_id.clone(),
            dispatch_commitment_id: context.dispatch_commitment_id.clone(),
            recorder: Some(recorder),
            drop_outcome: SecurityDispatchOutcome::DispatchFailed,
        }
    }

    /// Change the drop fallback once connector entry is imminent. From this
    /// point cancellation or unwind cannot prove that delivery did not occur.
    pub(crate) fn mark_dispatch_started(&mut self) {
        self.drop_outcome = SecurityDispatchOutcome::OutcomeUnknownAfterDispatch;
    }

    pub fn record_released(self) -> Result<(), KernelError> {
        self.record(SecurityDispatchOutcome::Released)
    }

    pub fn record_dispatch_failed(self) -> Result<(), KernelError> {
        self.record(SecurityDispatchOutcome::DispatchFailed)
    }

    pub fn record_outcome_unknown_after_dispatch(self) -> Result<(), KernelError> {
        self.record(SecurityDispatchOutcome::OutcomeUnknownAfterDispatch)
    }

    fn record(mut self, outcome: SecurityDispatchOutcome) -> Result<(), KernelError> {
        let mut recorder = self.recorder.take().ok_or_else(|| {
            KernelError::Internal(
                "security dispatch outcome handle was already completed".to_string(),
            )
        })?;
        recorder.record(outcome)
    }
}

impl Drop for SecurityDispatchOutcomeHandle {
    fn drop(&mut self) {
        let Some(mut recorder) = self.recorder.take() else {
            return;
        };
        if recorder.record(self.drop_outcome).is_err() {
            tracing::warn!(
                request_id = %self.request_id,
                dispatch_commitment_id = %self.dispatch_commitment_id.as_str(),
                audit_fault = "security_dispatch_outcome_unrecorded",
                outcome = ?self.drop_outcome,
                "failed to record dropped security dispatch outcome"
            );
        }
    }
}

/// Request-scoped production authority retained from the final pre-dispatch
/// fence through the kernel's final response handoff. Dropping a permit on an
/// error or cancelled future releases its authority without authorizing output.
pub trait SecurityRequestLifecyclePermit: Send {
    /// Linearize the final response release against the retained runtime
    /// authority. A failure denies the response after every output hook and
    /// durable admission transition has completed.
    fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError>;
}

/// Last-moment security hook invoked after all admission checks and before the
/// kernel enters a tool connector.
pub trait SecurityPreDispatchHook: Send + Sync {
    fn name(&self) -> &str;

    fn acquire_request_lifecycle(
        &self,
        _context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, KernelError> {
        Ok(None)
    }

    fn commit(
        &self,
        context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError>;
}

pub(crate) struct SecurityPreDispatchCommit {
    pub(crate) dispatch_outcome: Option<SecurityDispatchOutcomeHandle>,
    pub(crate) request_lifecycle: Option<Box<dyn SecurityRequestLifecyclePermit>>,
}

pub(crate) struct SecurityPreDispatchDenial {
    pub(crate) reason: &'static str,
    pub(crate) evidence: GuardEvidence,
}

/// Deny reason surfaced by every evaluate path when the emergency kill
/// switch is engaged. Exposed as `pub` so HTTP adapters and SDKs can
/// pattern-match on the exact string without drifting.
pub const EMERGENCY_STOP_DENY_REASON: &str = "kernel emergency stop active";

/// Context passed to optional runtime admission hooks after capability,
/// request matching, governed-admission, and guard checks pass, but before
/// dispatch and federation co-signing side effects.
pub struct RuntimeAdmissionContext<'a> {
    pub request: &'a ToolCallRequest,
    pub extra_metadata: Option<&'a serde_json::Value>,
    pub now_unix_secs: u64,
    pub now_unix_ms: u64,
    pub matched_grant_index: Option<usize>,
    pub local_kernel_id: String,
    /// Present when runtime admission participates in a durable admission
    /// operation. Exact retries carry the same pair.
    pub admission_operation_id: Option<&'a str>,
    pub admission_request_binding_hash: Option<&'a str>,
}

/// Non-consuming context for the final runtime-admission check immediately
/// before payment authorization, nonce consumption, and tool dispatch.
pub struct RuntimeAdmissionRevalidationContext<'a> {
    pub request: &'a ToolCallRequest,
    pub admission_metadata: Option<&'a serde_json::Value>,
    pub now_unix_secs: u64,
    pub now_unix_ms: u64,
    pub matched_grant_index: Option<usize>,
    pub local_kernel_id: String,
}

/// Opaque identifier for one in-flight runtime-admission readiness poll.
/// Concurrent evaluations receive distinct tokens even when request IDs are
/// equal, so unregistering one wait cannot remove another wait's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuntimeAdmissionReadinessToken(u64);

impl RuntimeAdmissionReadinessToken {
    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Decision returned by a runtime admission hook.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeAdmissionDecision {
    pub allowed: bool,
    pub reason: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub(crate) verified_treaty_material: Option<VerifiedFederationTreatyMaterial>,
}

impl RuntimeAdmissionDecision {
    #[must_use]
    pub fn has_verified_treaty_material(&self) -> bool {
        self.verified_treaty_material.is_some()
    }

    #[must_use]
    pub fn allow(metadata: Option<serde_json::Value>) -> Self {
        Self {
            allowed: true,
            reason: None,
            metadata,
            verified_treaty_material: None,
        }
    }

    #[must_use]
    pub fn allow_with_verified_treaty_material(
        metadata: Option<serde_json::Value>,
        verified_treaty_material: VerifiedFederationTreatyMaterial,
    ) -> Self {
        Self {
            allowed: true,
            reason: None,
            metadata,
            verified_treaty_material: Some(verified_treaty_material),
        }
    }

    #[must_use]
    pub fn deny(reason: impl Into<String>, metadata: Option<serde_json::Value>) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.into()),
            metadata,
            verified_treaty_material: None,
        }
    }
}

/// Optional pre-dispatch admission hook for product-specific runtime gates.
pub trait RuntimeAdmissionHook: Send + Sync {
    fn name(&self) -> &str;

    /// Evaluate ordinary admission. Implementations may reserve runtime state;
    /// callers must release any reservation identified by returned metadata
    /// when dispatch does not begin.
    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError>;

    /// Evaluate a threshold operation before its `Prepared` row is persisted.
    ///
    /// This boundary must be observationally pure: implementations must not
    /// consume replay state, acquire a lease, or perform any other authoritative
    /// mutation. The default rejects because `evaluate` is allowed to reserve
    /// state and therefore cannot safely be reused across the pre-persistence
    /// crash window. A hook may opt in only by implementing this method with a
    /// pure verification path.
    fn evaluate_before_operation_persist(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Err(KernelError::Internal(format!(
            "runtime admission hook \"{}\" does not support pure pre-persist evaluation",
            self.name()
        )))
    }

    fn poll_ready_before_dispatch(
        &self,
        _request: &ToolCallRequest,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        std::task::Poll::Ready(())
    }

    fn poll_ready_before_dispatch_with_token(
        &self,
        request: &ToolCallRequest,
        _token: RuntimeAdmissionReadinessToken,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        self.poll_ready_before_dispatch(request, cx)
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        false
    }

    fn revalidate_before_dispatch(
        &self,
        _context: &RuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    fn unregister_ready_before_dispatch(
        &self,
        _request: &ToolCallRequest,
        _token: RuntimeAdmissionReadinessToken,
    ) {
    }

    fn release_reserved(&self, _metadata: &serde_json::Value) -> Result<(), KernelError> {
        Ok(())
    }

    fn release_reserved_for_operation(
        &self,
        _operation_id: &str,
        _request_binding_hash: &str,
        metadata: &serde_json::Value,
    ) -> Result<(), KernelError> {
        self.release_reserved(metadata)
    }
}

#[derive(Debug)]
pub(crate) struct ReceiptContent {
    pub(crate) content_hash: String,
    pub(crate) metadata: Option<serde_json::Value>,
    /// The exact byte preimage `content_hash` was computed over, carried so the
    /// signing boundary can independently recompute the hash and refuse to sign
    /// on mismatch (WYSIWYS). For value outputs this is the RFC 8785
    /// canonical JSON; for streams the concatenated per-chunk digest preimage;
    /// for the empty output the literal `null` canonicalization.
    pub(crate) canonical_content: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ValidatedGovernedCallChainProof {
    upstream_proof: Option<chio_core::capability::governance::GovernedUpstreamCallChainProof>,
    continuation_token_id: Option<String>,
    session_anchor_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ValidatedGovernedAdmission {
    call_chain_proof: Option<ValidatedGovernedCallChainProof>,
    verified_runtime_attestation: Option<VerifiedRuntimeAttestationRecord>,
    verified_payee_binding: Option<VerifiedGovernedPayeeBinding>,
    verified_governed_approval:
        Option<crate::threshold_approval::VerifiedGovernedApprovalAdmission>,
}

#[derive(Debug, Clone)]
pub(crate) enum LocalReceiptArtifact {
    Tool(Box<chio_core::receipt::body::ChioReceipt>),
    Child(Box<chio_core::receipt::lineage::ChildRequestReceipt>),
}

impl LocalReceiptArtifact {
    fn verify_signature_with_floor(
        &self,
        floor: chio_core::receipt::crypto_floor::ReceiptCryptoFloor,
    ) -> Result<bool, KernelError> {
        match self {
            Self::Tool(receipt) => receipt.verify_signature_with_floor(floor).map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "governed call_chain parent receipt failed signature verification: {error}"
                ))
            }),
            Self::Child(receipt) => receipt.verify_signature_with_floor(floor).map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "governed call_chain parent receipt failed signature verification: {error}"
                ))
            }),
        }
    }

    fn artifact_hash(&self) -> Result<String, KernelError> {
        let canonical = match self {
            Self::Tool(receipt) => canonical_json_bytes(receipt),
            Self::Child(receipt) => canonical_json_bytes(receipt),
        }
        .map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "failed to hash governed call_chain parent receipt: {error}"
            ))
        })?;
        Ok(sha256_hex(&canonical))
    }

    fn session_anchor_reference(&self) -> Option<chio_core::session::SessionAnchorReference> {
        let metadata = match self {
            Self::Tool(receipt) => receipt.metadata.as_ref(),
            Self::Child(receipt) => receipt.metadata.as_ref(),
        };
        extract_session_anchor_reference_from_metadata(metadata)
    }
}

/// Bridge a sync caller to the async tool-server dispatch path.
///
/// Calling `futures::executor::block_on` from inside a current-thread
/// Tokio runtime parks the very thread that the runtime needs to drive
/// its reactor / timer wheel, and any tool-server future that awaits
/// Tokio I/O deadlocks silently. Tokio refuses
/// to nest `block_on` calls precisely because of this, but
/// `futures::executor::block_on` is a different executor that does not
/// see the surrounding runtime, so the deadlock manifests as a hung
/// tool call rather than a typed error.
///
/// Three cases are distinguished:
///   1. Multi-thread runtime active: use `block_in_place` so Tokio can
///      move the blocking work off the runtime threads. This is the
///      supported path.
///   2. Current-thread runtime active: refuse fail-closed with
///      [`KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime`].
///      Sync callers are expected to move the host to a multi-thread runtime
///      or call an async-native kernel entrypoint instead of this bridge.
///   3. No runtime active: drive the future with a non-tokio executor.
///      No surrounding runtime exists to deadlock; tool-server impls
///      that need Tokio I/O fail when they try to spawn
///      tasks, which is the correct, observable failure mode.
fn block_on_async_tool_dispatch<F, T>(future: F) -> Result<T, KernelError>
where
    F: std::future::Future<Output = Result<T, KernelError>>,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| handle.block_on(future))
        }
        Ok(_handle) => {
            // Current-thread runtime active. Bridging here would deadlock
            // any tool-server future that awaits Tokio I/O because we
            // would park the runtime's only worker thread. Surface a
            // typed error so the caller sees the architectural
            // incompatibility instead of a silent hang.
            Err(KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime)
        }
        Err(_) => {
            // No Tokio runtime active. The future cannot collide with a
            // surrounding reactor; the non-tokio executor is the safe
            // bridge. This is the path the in-process, compute-only
            // tool servers used in unit tests rely on.
            futures::executor::block_on(future)
        }
    }
}

fn extract_session_anchor_reference_from_metadata(
    metadata: Option<&serde_json::Value>,
) -> Option<chio_core::session::SessionAnchorReference> {
    let metadata = metadata?;
    let candidates = [
        metadata
            .get("governed_transaction")
            .and_then(|value| value.get("call_chain")),
        metadata.get("lineageReferences"),
    ];

    for candidate in candidates.into_iter().flatten() {
        let Some(session_anchor_id) = candidate
            .get("sessionAnchorId")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        let Some(session_anchor_hash) = candidate
            .get("sessionAnchorHash")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        return Some(chio_core::session::SessionAnchorReference::new(
            session_anchor_id,
            session_anchor_hash,
        ));
    }

    None
}

/// A policy guard that the kernel evaluates before forwarding a tool call.
///
/// A guard is a pluggable policy check, adapted for the Chio tool-call
/// context. Each guard inspects the request and returns a verdict.
#[derive(Debug, Clone)]
pub struct GuardDecision {
    pub verdict: Verdict,
    pub evidence: Vec<GuardEvidence>,
}

impl GuardDecision {
    #[must_use]
    pub fn allow() -> Self {
        Self {
            verdict: Verdict::Allow,
            evidence: Vec::new(),
        }
    }

    #[must_use]
    pub fn allow_with_evidence(evidence: Vec<GuardEvidence>) -> Self {
        Self {
            verdict: Verdict::Allow,
            evidence,
        }
    }

    #[must_use]
    pub fn deny(evidence: Vec<GuardEvidence>) -> Self {
        Self {
            verdict: Verdict::Deny,
            evidence,
        }
    }

    #[must_use]
    pub fn pending_approval(evidence: Vec<GuardEvidence>) -> Self {
        Self {
            verdict: Verdict::PendingApproval,
            evidence,
        }
    }

    #[must_use]
    pub fn from_verdict(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allow => Self::allow(),
            Verdict::Deny => Self::deny(Vec::new()),
            Verdict::PendingApproval => Self::pending_approval(Vec::new()),
        }
    }
}

impl PartialEq<Verdict> for GuardDecision {
    fn eq(&self, other: &Verdict) -> bool {
        self.verdict == *other
    }
}

impl PartialEq<GuardDecision> for Verdict {
    fn eq(&self, other: &GuardDecision) -> bool {
        *self == other.verdict
    }
}

pub trait Guard: Send + Sync {
    /// Human-readable guard name (e.g., "forbidden-path").
    fn name(&self) -> &str;

    /// Evaluate the guard against a tool call request.
    ///
    /// Returns an allow or deny decision with optional evidence, or `Err` on
    /// internal failure (which the kernel treats as deny).
    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError>;

    /// Return true when mutable guard state must be checked immediately before
    /// dispatch even if runtime readiness never suspended.
    fn requires_dispatch_revalidation(&self) -> bool {
        false
    }

    /// Run the opt-in immediate dispatch check. Composite guards should
    /// override this method and apply it recursively to their children.
    fn revalidate_required_before_dispatch(&self, ctx: &GuardContext) -> Result<(), KernelError> {
        if self.requires_dispatch_revalidation() {
            self.revalidate_before_dispatch(ctx)
        } else {
            Ok(())
        }
    }

    /// Revalidate mutable guard state without consuming a second quota,
    /// approval, or rate-limit token.
    fn revalidate_before_dispatch(&self, _ctx: &GuardContext) -> Result<(), KernelError> {
        Ok(())
    }
}

/// Context passed to guards during evaluation.
pub struct GuardContext<'a> {
    /// The tool call request being evaluated.
    pub request: &'a ToolCallRequest,
    /// The verified capability scope.
    pub scope: &'a ChioScope,
    /// The agent making the request.
    pub agent_id: &'a AgentId,
    /// The target server.
    pub server_id: &'a ServerId,
    /// Session-scoped enforceable filesystem roots, when the request is being
    /// evaluated through the supported session-backed runtime path.
    pub session_filesystem_roots: Option<&'a [String]>,
    /// Index of the matched grant in the capability's scope, populated by
    /// check_and_increment_budget before guards run.
    pub matched_grant_index: Option<usize>,
    /// Trusted identity and isolation state, when the caller possesses it.
    /// Security enforcement adapters deny a missing value in enforce mode.
    pub security_context: Option<&'a SecurityInvocationContext>,
}

impl<'a> GuardContext<'a> {
    #[must_use]
    pub fn new(request: &'a ToolCallRequest, scope: &'a ChioScope) -> Self {
        Self {
            request,
            scope,
            agent_id: &request.agent_id,
            server_id: &request.server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
            security_context: None,
        }
    }

    #[must_use]
    pub const fn with_session_filesystem_roots(
        mut self,
        session_filesystem_roots: Option<&'a [String]>,
    ) -> Self {
        self.session_filesystem_roots = session_filesystem_roots;
        self
    }

    #[must_use]
    pub const fn with_matched_grant_index(mut self, matched_grant_index: Option<usize>) -> Self {
        self.matched_grant_index = matched_grant_index;
        self
    }

    #[must_use]
    pub const fn with_security_context(
        mut self,
        security_context: Option<&'a SecurityInvocationContext>,
    ) -> Self {
        self.security_context = security_context;
        self
    }

    #[must_use]
    pub const fn security_context(&self) -> Option<&'a SecurityInvocationContext> {
        self.security_context
    }
}

/// Trait representing a resource provider.
pub trait ResourceProvider: Send + Sync {
    /// List the resources this provider exposes.
    fn list_resources(&self) -> Vec<ResourceDefinition>;

    /// List parameterized resource templates.
    fn list_resource_templates(&self) -> Vec<ResourceTemplateDefinition> {
        vec![]
    }

    /// Read a resource by URI. Returns `Ok(None)` when the provider does not own the URI.
    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError>;

    /// Return completions for a resource template or URI reference.
    fn complete_resource_argument(
        &self,
        _uri: &str,
        _argument_name: &str,
        _value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        Ok(None)
    }
}

/// Trait representing a prompt provider.
pub trait PromptProvider: Send + Sync {
    /// List available prompts.
    fn list_prompts(&self) -> Vec<PromptDefinition>;

    /// Retrieve a prompt by name. Returns `Ok(None)` when the provider does not own the prompt.
    fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, KernelError>;

    /// Return completions for a prompt argument.
    fn complete_prompt_argument(
        &self,
        _name: &str,
        _argument_name: &str,
        _value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        Ok(None)
    }
}

/// Default capacity for a process-local receipt mirror when constructed without
/// an explicit budget (tests / benches). The kernel construction path threads
/// the configured `MemoryBudgetConfig::receipt_mirror_capacity` instead.
const DEFAULT_RECEIPT_MIRROR_CAPACITY: usize = 4096;

/// Opaque boundary captured before a transport invokes a kernel entrypoint.
///
/// Error handling uses the boundary to distinguish a deny receipt appended by
/// the current invocation from receipts attached to an older reuse of the same
/// request identifier.
#[derive(Clone, Debug)]
pub struct TransportReceiptObservation {
    request_id: String,
    observed_receipt_ids: Vec<String>,
}

/// In-memory bounded ring of signed receipts. Process-local inspection mirror;
/// a durable receipt store is authoritative for id lookups.
///
/// `Clone` yields a read-only snapshot (used by the `receipt_log()` accessor).
#[derive(Clone)]
pub struct ReceiptLog {
    ring: chio_bounded::Ring<ChioReceipt>,
}

impl ReceiptLog {
    pub fn new() -> Self {
        Self::with_capacity(
            DEFAULT_RECEIPT_MIRROR_CAPACITY,
            chio_bounded::SizeGauge::new(),
        )
    }

    pub fn with_capacity(capacity: usize, gauge: chio_bounded::SizeGauge) -> Self {
        Self {
            ring: chio_bounded::Ring::with_capacity(capacity, gauge),
        }
    }

    pub fn append(&mut self, receipt: ChioReceipt) {
        // Evicted receipts are already durably persisted (the store write in
        // record_chio_receipt precedes this mirror append) or ephemeral by
        // policy, so dropping the evicted item is safe. Caveat: for an
        // append-only/remote store that does NOT implement point lookups, this
        // mirror is the only lookup source, so eviction here
        // makes an older receipt unresolvable and parent-receipt call-chain
        // validation fails closed. Such deployments must implement
        // ReceiptStore::load_chio_receipt (see has_local_receipt_id).
        let _evicted = self.ring.push(receipt);
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ChioReceipt> {
        self.ring.iter()
    }

    /// Cloned snapshot of the mirror (process-local inspection). Bounded by the
    /// ring capacity.
    pub fn receipts(&self) -> Vec<ChioReceipt> {
        self.ring.iter().cloned().collect()
    }

    pub fn get(&self, index: usize) -> Option<&ChioReceipt> {
        self.ring.iter().nth(index)
    }
}

impl Default for ReceiptLog {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory bounded ring of signed child-request receipts.
#[derive(Clone)]
pub struct ChildReceiptLog {
    ring: chio_bounded::Ring<ChildRequestReceipt>,
}

impl ChildReceiptLog {
    pub fn new() -> Self {
        Self::with_capacity(
            DEFAULT_RECEIPT_MIRROR_CAPACITY,
            chio_bounded::SizeGauge::new(),
        )
    }

    pub fn with_capacity(capacity: usize, gauge: chio_bounded::SizeGauge) -> Self {
        Self {
            ring: chio_bounded::Ring::with_capacity(capacity, gauge),
        }
    }

    pub fn append(&mut self, receipt: ChildRequestReceipt) {
        let _evicted = self.ring.push(receipt);
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ChildRequestReceipt> {
        self.ring.iter()
    }

    /// Cloned snapshot of the mirror (process-local inspection). Bounded by the
    /// ring capacity.
    pub fn receipts(&self) -> Vec<ChildRequestReceipt> {
        self.ring.iter().cloned().collect()
    }

    pub fn get(&self, index: usize) -> Option<&ChildRequestReceipt> {
        self.ring.iter().nth(index)
    }
}

impl Default for ChildReceiptLog {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MatchingGrant<'a> {
    pub(crate) index: usize,
    pub(crate) grant: &'a ToolGrant,
    pub(crate) specificity: (u8, u8, usize),
}

/// Result of a monetary budget charge attempt.
///
/// Carries the accounting info needed to populate FinancialReceiptMetadata.
#[derive(Clone)]
pub(crate) struct BudgetChargeResult {
    grant_index: usize,
    cost_charged: u64,
    currency: String,
    budget_total: u64,
    /// Running committed cost after this charge (used to compute budget_remaining).
    new_committed_cost_units: u64,
    budget_hold_id: String,
    authorize_metadata: BudgetCommitMetadata,
    admission_operation: Option<BudgetAdmissionOperationBinding>,
}

pub(crate) struct PostDispatchCleanupFailure {
    step: &'static str,
    reason: String,
    attempted_release_event_id: String,
    hold_ids: Vec<String>,
}

impl PostDispatchCleanupFailure {
    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }
}

impl BudgetChargeResult {
    fn reverse_event_id(&self) -> String {
        format!("{}:reverse", self.budget_hold_id)
    }

    fn release_event_id(&self) -> String {
        format!("{}:release", self.budget_hold_id)
    }

    fn reconcile_event_id(&self) -> String {
        format!("{}:reconcile", self.budget_hold_id)
    }
}

pub(crate) enum PreExecutionBudgetMutation {
    None,
    #[cfg_attr(not(test), allow(dead_code))]
    Invocation {
        grant_index: usize,
    },
    #[cfg_attr(not(test), allow(dead_code))]
    Charge(Box<BudgetChargeResult>),
    Admission(Box<OrdinaryAdmissionMutation>),
}

impl PreExecutionBudgetMutation {
    fn charge_result(&self) -> Option<&BudgetChargeResult> {
        match self {
            Self::Charge(charge) => Some(charge),
            Self::Admission(admission) => admission.charge_result(),
            Self::None | Self::Invocation { .. } => None,
        }
    }

    pub(super) fn ordinary_admission(&self) -> Option<&OrdinaryAdmissionMutation> {
        match self {
            Self::Admission(admission) => Some(admission.as_ref()),
            Self::None | Self::Invocation { .. } | Self::Charge(_) => None,
        }
    }

    pub(super) fn admission_operation_binding(&self) -> Option<&BudgetAdmissionOperationBinding> {
        match self {
            Self::Admission(admission) => Some(admission.admission_operation()),
            Self::Charge(charge) => charge.admission_operation.as_ref(),
            Self::None | Self::Invocation { .. } => None,
        }
    }
}

struct SessionNestedFlowBridge<'a, C> {
    sessions: &'a DashMap<SessionId, Arc<Session>>,
    child_receipts: &'a mut Vec<ChildRequestReceipt>,
    nested_interaction_observed: &'a std::sync::atomic::AtomicBool,
    parent_context: &'a OperationContext,
    allow_sampling: bool,
    allow_sampling_tool_use: bool,
    allow_elicitation: bool,
    policy_hash: &'a str,
    authority_signing_backend: &'a dyn chio_core::crypto::SigningBackend,
    client: &'a mut C,
}

impl<C> SessionNestedFlowBridge<'_, C> {
    fn mark_nested_interaction_observed(&self) {
        self.nested_interaction_observed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn ensure_parent_not_cancelled(&self) -> Result<(), KernelError> {
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        let request_id = &self.parent_context.request_id;
        let Some(parent) = session.inflight().get(request_id) else {
            return Err(KernelError::RequestCancelled {
                request_id: request_id.clone(),
                reason: "parent session request completed during nested dispatch".to_string(),
            });
        };
        if parent.cancellation_requested {
            return Err(KernelError::RequestCancelled {
                request_id: request_id.clone(),
                reason: parent.cancellation_reason.unwrap_or_else(|| {
                    "parent session request cancelled during nested dispatch".to_string()
                }),
            });
        }
        Ok(())
    }

    fn latch_matching_cancellation<T>(
        &mut self,
        result: &Result<T, KernelError>,
        child_request_id: Option<&RequestId>,
    ) -> Result<(), KernelError> {
        let Err(KernelError::RequestCancelled { request_id, reason }) = result else {
            return Ok(());
        };
        if request_id != &self.parent_context.request_id
            && child_request_id.is_none_or(|child_request_id| request_id != child_request_id)
        {
            return Ok(());
        }
        session_from_map(self.sessions, &self.parent_context.session_id)?
            .request_cancellation_with_reason(request_id, reason)?;
        Ok(())
    }

    fn complete_child_request_with_receipt<T: serde::Serialize>(
        &mut self,
        child_context: &OperationContext,
        operation_kind: OperationKind,
        result: &Result<T, KernelError>,
    ) -> Result<(), KernelError> {
        let terminal_state = child_terminal_state(&child_context.request_id, result);
        complete_session_request_with_terminal_state_in_sessions(
            self.sessions,
            &child_context.session_id,
            &child_context.request_id,
            terminal_state.clone(),
        )?;

        let receipt = build_child_request_receipt(
            self.policy_hash,
            self.authority_signing_backend,
            child_context,
            operation_kind,
            terminal_state,
            child_outcome_payload(result)?,
        )?;
        self.child_receipts.push(receipt);
        Ok(())
    }
}

impl<C> Drop for SessionNestedFlowBridge<'_, C> {
    fn drop(&mut self) {
        if let Some(session) = self.sessions.get(&self.parent_context.session_id) {
            session.mark_request_dispatch_finished(&self.parent_context.request_id);
        }
    }
}

impl<C: NestedFlowClient> NestedFlowBridge for SessionNestedFlowBridge<'_, C> {
    fn parent_request_id(&self) -> &RequestId {
        &self.parent_context.request_id
    }

    fn poll_parent_cancellation(&mut self) -> Result<(), KernelError> {
        self.ensure_parent_not_cancelled()?;
        let result = self.client.poll_parent_cancellation(self.parent_context);
        self.latch_matching_cancellation(&result, None)?;
        result
    }

    fn list_roots(&mut self) -> Result<Vec<RootDefinition>, KernelError> {
        self.ensure_parent_not_cancelled()?;
        self.mark_nested_interaction_observed();
        let (child_context, _start) = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            nested_child_request_id(&self.parent_context.request_id, "roots"),
            OperationKind::ListRoots,
            None,
            false,
        )?;

        let result = (|| {
            let session = session_from_map(self.sessions, &child_context.session_id)?;
            session.validate_context(&child_context)?;
            session.ensure_operation_allowed(OperationKind::ListRoots)?;
            if !session.peer_capabilities().supports_roots {
                return Err(KernelError::RootsNotNegotiated);
            }

            let roots = self
                .client
                .list_roots(self.parent_context, &child_context)?;
            session_from_map(self.sessions, &child_context.session_id)?
                .replace_roots(roots.clone());
            Ok(roots)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::ListRoots,
            &result,
        )?;

        result
    }

    fn create_message(
        &mut self,
        operation: CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        self.ensure_parent_not_cancelled()?;
        self.mark_nested_interaction_observed();
        let (child_context, _start) = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            nested_child_request_id(&self.parent_context.request_id, "sample"),
            OperationKind::CreateMessage,
            None,
            true,
        )?;

        let result = (|| {
            validate_sampling_request_in_sessions(
                self.sessions,
                self.allow_sampling,
                self.allow_sampling_tool_use,
                &child_context,
                &operation,
            )?;
            self.client
                .create_message(self.parent_context, &child_context, &operation)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::CreateMessage,
            &result,
        )?;

        result
    }

    fn create_elicitation(
        &mut self,
        operation: CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        self.ensure_parent_not_cancelled()?;
        self.mark_nested_interaction_observed();
        let (child_context, _start) = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            nested_child_request_id(&self.parent_context.request_id, "elicit"),
            OperationKind::CreateElicitation,
            None,
            true,
        )?;

        let result = (|| {
            validate_elicitation_request_in_sessions(
                self.sessions,
                self.allow_elicitation,
                &child_context,
                &operation,
            )?;
            self.client
                .create_elicitation(self.parent_context, &child_context, &operation)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::CreateElicitation,
            &result,
        )?;

        result
    }

    fn notify_elicitation_completed(&mut self, elicitation_id: &str) -> Result<(), KernelError> {
        self.ensure_parent_not_cancelled()?;
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        self.mark_nested_interaction_observed();
        let result = self
            .client
            .notify_elicitation_completed(self.parent_context, elicitation_id);
        self.latch_matching_cancellation(&result, None)?;
        result
    }

    fn notify_resource_updated(&mut self, uri: &str) -> Result<(), KernelError> {
        self.ensure_parent_not_cancelled()?;
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        if !session.is_resource_subscribed(uri) {
            return Ok(());
        }

        self.mark_nested_interaction_observed();
        let result = self
            .client
            .notify_resource_updated(self.parent_context, uri);
        self.latch_matching_cancellation(&result, None)?;
        result
    }

    fn notify_resources_list_changed(&mut self) -> Result<(), KernelError> {
        self.ensure_parent_not_cancelled()?;
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        self.mark_nested_interaction_observed();
        let result = self
            .client
            .notify_resources_list_changed(self.parent_context);
        self.latch_matching_cancellation(&result, None)?;
        result
    }
}

/// Extract a guard name from a `GuardDenied` error message shaped like
/// `guard "<name>" denied the request` or `guard "<name>" error ...`.
///
/// Plan evaluation surfaces the offending guard in the per-step verdict
/// so callers can target a specific guard when replanning. Parsing the
/// name out of the canonical string is sufficient here; the structured
/// denial payload is a tool-call response type and
/// is not shared with plan evaluation.
fn extract_guard_name(message: &str) -> Option<String> {
    let start_marker = "guard \"";
    let start = message.find(start_marker)? + start_marker.len();
    let rest = &message[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn scope_from_capability_snapshot(
    snapshot: &crate::capability_lineage::CapabilitySnapshot,
) -> Result<ChioScope, KernelError> {
    serde_json::from_str(&snapshot.grants_json).map_err(|error| {
        KernelError::Internal(format!(
            "invalid capability snapshot scope for {}: {error}",
            snapshot.capability_id
        ))
    })
}

fn validate_delegation_scope_step(
    parent_capability_id: &str,
    child_capability_id: &str,
    parent_scope: &ChioScope,
    child_scope: &ChioScope,
    child_expires_at: u64,
    link: &chio_core::capability::attenuation::DelegationLink,
) -> Result<(), KernelError> {
    validate_delegatable_subset(
        parent_capability_id,
        child_capability_id,
        parent_scope,
        child_scope,
    )?;
    validate_declared_attenuations(child_capability_id, child_scope, child_expires_at, link)?;
    Ok(())
}

fn validate_delegatable_subset(
    parent_capability_id: &str,
    child_capability_id: &str,
    parent_scope: &ChioScope,
    child_scope: &ChioScope,
) -> Result<(), KernelError> {
    for child_grant in &child_scope.grants {
        let allowed = parent_scope.grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !allowed {
            return Err(KernelError::DelegationInvalid(format!(
                "parent capability {} does not authorize delegated tool grant {}/{} on child capability {}",
                parent_capability_id,
                child_grant.server_id,
                child_grant.tool_name,
                child_capability_id
            )));
        }
    }

    for child_grant in &child_scope.resource_grants {
        let allowed = parent_scope.resource_grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !allowed {
            return Err(KernelError::DelegationInvalid(format!(
                "parent capability {} does not authorize delegated resource grant {} on child capability {}",
                parent_capability_id, child_grant.uri_pattern, child_capability_id
            )));
        }
    }

    for child_grant in &child_scope.prompt_grants {
        let allowed = parent_scope.prompt_grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !allowed {
            return Err(KernelError::DelegationInvalid(format!(
                "parent capability {} does not authorize delegated prompt grant {} on child capability {}",
                parent_capability_id, child_grant.prompt_name, child_capability_id
            )));
        }
    }

    Ok(())
}

fn validate_declared_attenuations(
    child_capability_id: &str,
    child_scope: &ChioScope,
    child_expires_at: u64,
    link: &chio_core::capability::attenuation::DelegationLink,
) -> Result<(), KernelError> {
    for attenuation in &link.attenuations {
        match attenuation {
            chio_core::capability::attenuation::Attenuation::RemoveTool {
                server_id,
                tool_name,
            } => {
                if child_scope
                    .grants
                    .iter()
                    .any(|grant| tool_grant_covers_target(grant, server_id, tool_name))
                {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} still grants removed tool {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
            chio_core::capability::attenuation::Attenuation::RemoveOperation {
                server_id,
                tool_name,
                operation,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && grant.operations.contains(operation)
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} still grants removed operation {:?} on {}/{}",
                        child_capability_id, operation, server_id, tool_name
                    )));
                }
            }
            chio_core::capability::attenuation::Attenuation::AddConstraint {
                server_id,
                tool_name,
                constraint,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && !grant.constraints.contains(constraint)
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} is missing declared constraint on {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
            chio_core::capability::attenuation::Attenuation::ReduceBudget {
                server_id,
                tool_name,
                max_invocations,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && grant
                            .max_invocations
                            .is_none_or(|value| value > *max_invocations)
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} exceeds declared invocation budget on {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
            chio_core::capability::attenuation::Attenuation::ShortenExpiry { new_expires_at } => {
                if child_expires_at > *new_expires_at {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} expires after declared shortened expiry {}",
                        child_capability_id, new_expires_at
                    )));
                }
            }
            chio_core::capability::attenuation::Attenuation::ReduceCostPerInvocation {
                server_id,
                tool_name,
                max_cost_per_invocation,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && grant.max_cost_per_invocation.as_ref().is_none_or(|value| {
                            value.currency != max_cost_per_invocation.currency
                                || value.units > max_cost_per_invocation.units
                        })
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} exceeds declared per-invocation cost ceiling on {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
            chio_core::capability::attenuation::Attenuation::ReduceTotalCost {
                server_id,
                tool_name,
                max_total_cost,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && grant.max_total_cost.as_ref().is_none_or(|value| {
                            value.currency != max_total_cost.currency
                                || value.units > max_total_cost.units
                        })
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} exceeds declared total-cost ceiling on {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
        }
    }

    Ok(())
}

fn tool_grant_covers_target(grant: &ToolGrant, server_id: &str, tool_name: &str) -> bool {
    (grant.server_id == "*" || grant.server_id == server_id)
        && (grant.tool_name == "*" || grant.tool_name == tool_name)
}

/// Parameters for building a receipt.
pub(crate) struct ReceiptParams<'a> {
    request_id: Option<&'a str>,
    capability_id: &'a str,
    tool_name: &'a str,
    server_id: &'a str,
    decision: Decision,
    action: ToolCallAction,
    content_hash: String,
    /// Byte preimage `content_hash` was computed over. The signing boundary
    /// recomputes `sha256_hex(canonical_content)` and refuses to sign when it
    /// disagrees with `content_hash` (WYSIWYS). Always sourced from
    /// the matching [`ReceiptContent::canonical_content`].
    canonical_content: Vec<u8>,
    metadata: Option<serde_json::Value>,
    timestamp: u64,
    /// Strength of kernel mediation for this evaluation. Defaults to
    /// `Mediated` (the safest baseline) when integration adapters do not
    /// override it.
    trust_level: chio_core::receipt::kinds::TrustLevel,
    /// Multi-tenant receipt isolation: explicit tenant tag for
    /// this receipt. `None` in virtually every call site -- the evaluate
    /// path plumbs the resolved tenant through
    /// [`scope_receipt_tenant_id`] so `build_and_sign_receipt` can pick it
    /// up without adding a parameter to every builder signature.
    ///
    /// MUST be derived from session / auth context, not caller-provided
    /// request fields (see `STRUCTURAL-SECURITY-FIXES.md` section 6).
    tenant_id: Option<String>,
}

pub(crate) fn current_unix_timestamp() -> u64 {
    if let Some(now) = fixed_runtime_unix_secs_for_current_thread() {
        return now;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn current_unix_timestamp_ms() -> u64 {
    if let Some(now) = fixed_runtime_unix_secs_for_current_thread() {
        return now.saturating_mul(1000);
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(feature = "delegation")]
#[path = "delegation.rs"]
pub(crate) mod delegation;
// Kernel construction and configuration surface. Holds the constructor,
// session/store accessors, and the `set_*` / `with_*` / `register_*`
// configuration setters.
#[path = "construction.rs"]
mod construction;
// Tool-call and plan evaluation path, including the long-form evaluation
// cores.
mod evaluation;
// Capability and budget validation.
#[path = "validation.rs"]
mod validation;
// Reconcile-by-nonce and reserved-hold TTL primitives (mediated spend path).
#[path = "reconciliation.rs"]
mod reconciliation;
// Governed-admission validation and call-chain receipt evidence.
#[path = "governed_validation.rs"]
mod governed_validation;
// Guard evaluation, runtime admission, and tool dispatch.
#[path = "dispatch.rs"]
mod dispatch;
#[path = "evaluator.rs"]
pub mod evaluator;
mod responses;
#[path = "session_ops.rs"]
mod session_ops;
// Settlement observer slot. Wires `chio-settle::SettlementHook` into
// the post-dispatch surface so finalized receipts can be routed through
// the existing `chio-settle/ops.rs` pipeline. The observer is strictly
// post-signing: hook failures never block the dispatch path.
#[path = "settlement_observer.rs"]
pub mod settlement_observer;
// Mpsc-backed signing task. Owns a clone of the kernel signing keypair and
// pulls signing requests from a bounded `tokio::sync::mpsc` channel so receipt
// signing leaves the synchronous critical path.
#[path = "signing_task.rs"]
pub(crate) mod signing_task;
// Receipt-writer liveness watchdog. Publishes the latest verdict the
// pre-dispatch readiness gate reads.
#[path = "receipt_writer_watchdog.rs"]
mod receipt_writer_watchdog;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
