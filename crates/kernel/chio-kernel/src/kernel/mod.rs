mod active_response_simulation;
pub use active_response_simulation::{
    ActiveResponseSimulationRequest, VerifiedResponseSimulationAuthorization,
};
use std::sync::Arc;

use chio_appraisal::VerifiedRuntimeAttestationRecord;
use chio_core::receipt::metadata::GuardEvidence;
use dashmap::DashMap;

use crate::budget_store::BudgetCommitMetadata;
use crate::*;

mod active_response_admission;
mod active_response_artifact;
mod active_response_committed_recovery;
mod active_response_coordinator;
mod active_response_dispatch;
mod active_response_executor;
pub use active_response_dispatch::{prepare_response_dispatch, ResponseDispatchPreparationRequest};
mod active_response_operation_binding;
mod active_response_policy;
mod active_response_proof;
mod admission_cleanup;
#[path = "admission_coordinator.rs"]
mod admission_coordinator;
mod admission_terminal_receipt;
mod approval_cleanup;
mod credential_reservation;
mod effect_obligation;
pub use effect_obligation::evidence::PostEffectEvidenceBudget;
mod error;
mod guard_invocation_attempt;
pub(crate) use guard_invocation_attempt::GuardInvocationAttempt;
mod kernel_drop_guard;
mod nested_flow_bridge;
use nested_flow_bridge::SessionNestedFlowBridge;
mod kernel_scopes;
mod kernel_struct;
mod nonce_admission;
mod output_guard;
mod publication_sync;
mod receipt_identity;
use receipt_identity::{IdentityDisposition, RefusalReceiptMetadata};
mod rejection_metadata;
mod security_dispatch;
mod security_runtime;
mod signing_authority;
mod threshold_issuance;
mod verified_treaty;

pub use active_response_admission::{
    ActiveResponseAuthorizationRequest, ActiveResponseFindingAuthority,
    ActiveResponseFindingAuthorityError, ActiveResponseSubmissionProof,
    ActiveResponseSubmissionProofBody, ActiveResponseSubmissionProofError,
    AuthoritativeCorrelatedFindingEvidence, VerifiedActiveResponseBindings,
    ACTIVE_RESPONSE_SUBMISSION_SCHEMA,
};
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
    bind_active_response_dispatch_id_to_artifact, derive_active_response_dispatch_id,
    ActiveResponseCommittedDispatch, ActiveResponseDispatchIdError, ActiveResponseEffectEvidence,
    ActiveResponseExecutionApproval, ActiveResponseExecutionEvidence,
    ActiveResponseExecutionEvidenceParts, ActiveResponseExecutionOrigin,
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

pub use construction::KernelBuildError;
pub use error::{
    HotPathStage, KernelError, OverloadResource, ReceiptDeliveryStep, ReplayClockDirection,
    SettlementRuntimeConfigError, StructuredErrorReport,
};
pub use evaluation::{CallerExecutionReport, CallerStartCredentials, CallerStartResponse};
pub use kernel_struct::{
    ChioKernel, HotPathDeadlineConfig, HybridSigningConfig, KernelConfig, MemoryBudgetConfig,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_SIZE_BYTES, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES, DEFAULT_RECEIPT_APPEND_BUDGET_MS,
    DEFAULT_RECEIPT_WRITER_POLL_MS, DEFAULT_RECEIPT_WRITER_STALL_MS, DEFAULT_RETENTION_DAYS,
    DEFAULT_RUNTIME_ADMISSION_READINESS_TIMEOUT_MS, MIN_RECEIPT_APPEND_BUDGET_MS,
};
pub(crate) use security_dispatch::SecurityRequestLifecycleHandle;
pub use security_runtime::{GovernedSecurityRuntimePublication, GovernedSecurityRuntimeStatus};
pub use verified_treaty::{
    FederationTreatyAdmissionBinding, FederationTreatyVerification,
    VerifiedFederationTreatyMaterial,
};

#[cfg(feature = "admission-test-support")]
pub use admission_coordinator::DurableFinalizationCutpointHook;
#[cfg(feature = "admission-test-support")]
pub use admission_coordinator::NativeSecurityCaptureCheckpointHook;
pub use admission_coordinator::NativeSecurityDispatchCaptureAuthority;
#[cfg(feature = "admission-test-support")]
pub use admission_coordinator::NativeSecurityEgressCheckpointHook;
pub use admission_coordinator::NativeSecurityOutputJoinAuthority;
pub use admission_coordinator::{
    AcquiredNativeSecurityEgress, DurableFinalizationCutpoint, NativeSecurityFlowJoinAuthority,
    NativeSecurityNoncePreflightJoinAuthority, PreparedNativeSecurityEgress,
    RuntimeParticipantClaimAuthority,
};
#[cfg(feature = "admission-test-support")]
pub use admission_coordinator::{CallerExecutionCheckpoint, CallerExecutionCheckpointHook};
pub(crate) use admission_coordinator::{
    DurableAdmissionRuntime, DurableDispatchCommitError, DurableToolAdmission,
    DurableToolReturnContextInput, DurableToolReturnInput,
};
pub use credential_reservation::VerifiedNativeDispatchCredentials;
pub(crate) use kernel_drop_guard::{PostAdmissionDropGuard, PostAdmissionReceiptContext};
#[cfg(test)]
pub(crate) use kernel_scopes::RECEIPT_EVALUATION_SCOPE_KEY;
pub(crate) use kernel_scopes::{
    current_receipt_evaluation_scope_key, current_scoped_receipt_federation_admission,
    current_scoped_receipt_tenant_id, extract_tenant_id_from_auth_context,
    scope_async_receipt_context, scope_receipt_federation_admission, scope_receipt_tenant_id,
    ReceiptFederationAdmission, ScopedKernelReceiptFederationAdmission,
    ScopedKernelReceiptTenantId,
};
pub(crate) use kernel_struct::{
    capability_crypto_floor, receipt_crypto_floor, ReservedSiblingShare, RestartReservedHoldGate,
};

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
const CALLER_DELIVERY_METADATA_KEY: &str = "caller_delivery";
const RUNTIME_ADMISSION_METADATA_KEY: &str = "chio_runtime";

use chio_core::receipt::metadata::RESERVED_RECEIPT_METADATA_KEYS;

/// Refusal reason for runtime-admission hook metadata that is present but not
/// a JSON object; such metadata would displace every later kernel block.
const NON_OBJECT_HOOK_METADATA_REFUSAL: &str =
    "runtime admission hook metadata must be a JSON object";

/// Hook output may name only `chio_runtime` among the reserved keys. The kernel
/// writes `runtime_admission` itself, only on its own error paths and never
/// from hook output, so a hook can never supply it.
fn is_hook_forbidden_metadata_key(key: &str) -> bool {
    key != RUNTIME_ADMISSION_METADATA_KEY && RESERVED_RECEIPT_METADATA_KEYS.contains(&key)
}

/// The first reserved key a runtime-admission hook may not write, if its
/// metadata names one.
fn reserved_hook_metadata_key(metadata: Option<&serde_json::Value>) -> Option<&'static str> {
    let object = metadata.and_then(serde_json::Value::as_object)?;
    RESERVED_RECEIPT_METADATA_KEYS
        .iter()
        .copied()
        .find(|key| object.contains_key(*key) && is_hook_forbidden_metadata_key(key))
}

fn reserved_receipt_metadata_key(metadata: Option<&serde_json::Value>) -> Option<&'static str> {
    let object = metadata.and_then(serde_json::Value::as_object)?;
    RESERVED_RECEIPT_METADATA_KEYS
        .iter()
        .copied()
        .find(|key| object.contains_key(*key))
}

/// Attempt-scoped launch evidence must be well formed: a native launch names
/// one launch receipt, and a worker profile names one container launch record
/// and its launch attempt.
fn validate_attempt_launch_metadata(
    metadata: Option<&serde_json::Value>,
) -> Result<(), KernelError> {
    let Some(metadata) = metadata else {
        return Ok(());
    };
    if metadata
        .get("native_launch")
        .is_some_and(|launch| !crate::admission_operation::is_native_launch(launch))
    {
        return Err(KernelError::InvalidReceiptMetadata(
            "native_launch must name one launch receipt id and sha256".into(),
        ));
    }
    if metadata
        .get("chio_process")
        .and_then(|process| process.get("worker_profile"))
        .is_some_and(|profile| !crate::admission_operation::is_worker_profile(profile))
    {
        return Err(KernelError::InvalidReceiptMetadata(
            "chio_process.worker_profile must name one container launch record and attempt".into(),
        ));
    }
    Ok(())
}

fn validate_caller_receipt_metadata(
    metadata: Option<&serde_json::Value>,
) -> Result<(), KernelError> {
    if metadata.is_some_and(|value| !value.is_object()) {
        return Err(KernelError::InvalidReceiptMetadata(
            "receipt metadata must be a JSON object".into(),
        ));
    }
    crate::receipt_support::validate_caller_provenance_metadata(metadata)?;
    validate_attempt_launch_metadata(metadata)?;
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
        RUNTIME_ADMISSION_METADATA_KEY => "kernel-derived runtime admission reservations",
        _ => "kernel-derived receipts",
    };
    Err(KernelError::InvalidReceiptMetadata(format!(
        "{key} is reserved for {purpose}"
    )))
}

fn registry_validated_manifest_security_metadata(
    request: &ToolCallRequest,
    registry: &chio_manifest::VerifiedManifestRegistry,
    security: &chio_manifest::BridgeSecurityMetadata,
    metadata: Option<serde_json::Value>,
) -> Result<serde_json::Value, KernelError> {
    validate_caller_receipt_metadata(metadata.as_ref())?;
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
pub trait CapabilityIssuanceAdmissionAuthority: Send + Sync {
    fn ensure_ready(&self) -> chio_security_types::ports::PortResult<()>;

    fn authorize(
        &self,
        query: &chio_security_types::ports::IssuanceFreezeAdmissionQuery,
    ) -> chio_security_types::ports::PortResult<()>;
}

/// Authoritative security identity and isolation state supplied by a trusted
/// runtime boundary. Tool-call request fields are not a source for this data.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "version", content = "context", rename_all = "snake_case")]
pub enum SecurityInvocationContext {
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
    context_generation: u64,
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

    /// Attach mutable durable flow-state generation observed by the trusted
    /// context resolver. This is not part of capability binding validation.
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

    #[must_use]
    pub const fn flow_state_generation(&self) -> Option<u64> {
        self.flow_state_generation
    }
}

impl SecurityInvocationContext {
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

/// Trusted host authority for identity, isolation, lineage, and generation
/// state used by one tool dispatch.
pub trait SecurityInvocationContextAuthority: Send + Sync {
    fn resolve_security_invocation_context(
        &self,
        context: &chio_core::session::OperationContext,
        operation: &chio_core::session::ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError>;
}

/// Controls whether security state and a final pre-dispatch hook are required.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SecurityPreDispatchPolicy {
    #[default]
    Optional,
    Enforce,
}

/// Canonical, authoritative input committed immediately before tool dispatch.
pub struct SecurityPreDispatchContext<'a> {
    pub request: &'a ToolCallRequest,
    pub canonical_request: &'a [u8],
    pub security_context: &'a SecurityInvocationContext,
    pub dispatch_commitment_id: &'a chio_security_types::ports::RecordId,
}

/// Trusted preparation input before budget capture. Unlike the dispatch
/// context this contains no commitment or permission to enter a connector.
pub struct NativeSecurityAdmissionContext<'a> {
    pub request: &'a ToolCallRequest,
    pub security_context: &'a SecurityInvocationContext,
}

/// Durable terminal state for a security mutation consumed immediately before
/// connector entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityDispatchOutcome {
    Released,
    DispatchFailed,
    OutcomeUnknownAfterDispatch,
}

pub trait SecurityDispatchOutcomeRecorder: Send {
    fn record(&mut self, outcome: SecurityDispatchOutcome) -> Result<(), KernelError>;
}

/// One-shot owner for the terminal state of a consumed pre-dispatch mutation.
pub struct SecurityDispatchOutcomeHandle {
    request_id: String,
    dispatch_commitment_id: chio_security_types::ports::RecordId,
    recorder: Option<Box<dyn SecurityDispatchOutcomeRecorder>>,
    drop_outcome: SecurityDispatchOutcome,
}

pub trait SecurityRequestLifecyclePermit: Send {
    fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError>;

    /// Inspect the exact resolved output before durable release is acknowledged.
    /// The context is borrowed from the original finalization, not reconstructed
    /// from a receipt. Existing output-independent owners retain their contract.
    /// An owner requiring output must override this method and reject the
    /// context-free method; non-durable callers cannot supply this context.
    fn ensure_final_release_with_output(
        self: Box<Self>,
        _context: &crate::tool_outcome::DurableSecurityReleaseContext<'_>,
    ) -> Result<(), KernelError> {
        self.ensure_final_release()
    }
}

/// Last-moment security hook invoked before the kernel enters a connector.
pub trait SecurityPreDispatchHook: Send + Sync {
    fn name(&self) -> &str;

    /// Explicit trusted-host opt-in. This declaration alone grants no custody:
    /// the native callback must complete the kernel's original capture handoff.
    fn supports_native_dispatch(&self) -> bool {
        false
    }

    fn commit_native_dispatch(
        &self,
        _authority: &mut NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        Err(KernelError::DurableAdmission(
            "native security dispatch lifecycle is unsupported".into(),
        ))
    }

    /// Non-consuming native authority selection from trusted host
    /// configuration, never agent metadata. Returning data grants no mutation
    /// authority. Native profiles require enforced security and trusted context;
    /// the selection must remain stable through admission and recovery.
    fn native_authority_binding(
        &self,
    ) -> Result<Option<crate::admission_operation::NativeSecurityAuthorityBindingV1>, KernelError>
    {
        Ok(None)
    }

    /// Prepare exactly one monotone join through the kernel-owned handle. Only
    /// hooks selecting native authority are called here. The default rejects
    /// unsupported native custody; successful return without a recorded join
    /// also denies admission. This is not native lifecycle activation.
    fn prepare_native_admission(
        &self,
        _context: &NativeSecurityAdmissionContext<'_>,
        _authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        Err(KernelError::DurableAdmission(
            "native security admission preparation is unsupported".into(),
        ))
    }

    /// Separate strict-nonce preflight custody. Dispatch-only hooks fail closed;
    /// a preflight journal never satisfies the dispatch input-join contract.
    fn prepare_native_nonce_preflight(
        &self,
        _context: &NativeSecurityAdmissionContext<'_>,
        _authority: &NativeSecurityNoncePreflightJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        Err(KernelError::DurableAdmission(
            "native security nonce preflight preparation is unsupported".into(),
        ))
    }

    /// Classify the actual guarded output using the original finalization's
    /// operation-scoped writer. The kernel requires one confirmed monotone join;
    /// returning success without it, or suppressing its error, denies release.
    /// This callback neither replaces the live lifecycle owner nor grants release.
    fn prepare_native_output(
        &self,
        _context: &crate::tool_outcome::DurableSecurityReleaseContext<'_>,
        _authority: &NativeSecurityOutputJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        Err(KernelError::DurableAdmission(
            "native security output preparation is unsupported".into(),
        ))
    }

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
    pub(crate) request_lifecycle: Option<SecurityRequestLifecycleHandle>,
}

pub(crate) struct SecurityPreDispatchDenial {
    pub(crate) reason: &'static str,
    pub(crate) evidence: GuardEvidence,
}

/// Deny reason surfaced by every evaluate path when the emergency kill
/// switch is engaged. Exposed as `pub` so HTTP adapters and SDKs can
/// pattern-match on the exact string without drifting.
pub const EMERGENCY_STOP_DENY_REASON: &str = "kernel emergency stop active";

mod runtime_admission;
pub use runtime_admission::{
    RuntimeAdmissionContext, RuntimeAdmissionDecision, RuntimeAdmissionHook,
    RuntimeAdmissionReadinessToken, RuntimeAdmissionRevalidationContext,
};

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
    approval_reservation: Option<VerifiedApprovalReservation>,
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedApprovalReservation {
    pub(crate) threshold_proposal_hash: String,
    pub(crate) approval_set_hash: String,
    pub(crate) threshold_replay: Option<ThresholdApprovalReplayReservationV1>,
}

#[derive(Debug)]
pub(crate) struct VerifiedThresholdApprovalSet {
    pub(crate) body: chio_core::capability::governance::ApprovalSetBody,
    pub(crate) replay: ThresholdApprovalReplayReservationV1,
}

pub(crate) fn run_payment_adapter_operation<T>(
    operation_name: &'static str,
    operation: impl FnOnce() -> Result<T, PaymentError>,
) -> Result<T, PaymentError> {
    // A rail call blocks its thread. A multi-thread runtime worker hands its
    // other tasks off first; a current-thread runtime cannot, so it and
    // callers outside any runtime call the adapter directly.
    let blocking = || match tokio::runtime::Handle::try_current() {
        Ok(handle)
            if matches!(
                handle.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::MultiThread
            ) =>
        {
            tokio::task::block_in_place(operation)
        }
        _ => operation(),
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(blocking)) {
        Ok(result) => result,
        Err(_) => Err(PaymentError::RailError(format!(
            "payment adapter {operation_name} panicked; outcome unknown"
        ))),
    }
}

pub(crate) fn validate_payment_adapter_identifier(
    identifier: &str,
    field_name: &'static str,
) -> Result<(), PaymentError> {
    if identifier.is_empty() || identifier.trim() != identifier {
        return Err(PaymentError::RailError(format!(
            "payment adapter returned an invalid {field_name}; outcome unknown"
        )));
    }
    Ok(())
}

pub(crate) enum BudgetAdmissionOutcome {
    Authorized {
        grant_index: usize,
        mutation: Box<PreExecutionBudgetMutation>,
    },
    PendingApproval {
        grant_index: usize,
        proposal: Box<chio_core::capability::governance::ThresholdApprovalProposal>,
    },
}

#[cfg(test)]
impl BudgetAdmissionOutcome {
    pub(crate) fn into_authorized(
        self,
    ) -> Result<(usize, PreExecutionBudgetMutation), KernelError> {
        match self {
            Self::Authorized {
                grant_index,
                mutation,
            } => Ok((grant_index, *mutation)),
            Self::PendingApproval { .. } => Err(KernelError::Internal(
                "budget admission remained pending approval".to_owned(),
            )),
        }
    }
}

pub(crate) struct GovernedValidationContext<'a> {
    parent_context: Option<&'a OperationContext>,
    now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedGovernedPayeeBinding {
    beneficiary_id: String,
    settlement_destination_ref: String,
    payee_binding_digest: String,
    economic_intent_digest: String,
    pre_action_authority_digest: String,
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
        })
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

/// Whether `error` is [`block_on_async_tool_dispatch`] refusing the calling
/// thread's current-thread runtime. That refusal returns before the bridged
/// evaluation is polled, so nothing was admitted or dispatched. The bridge
/// only polls on a thread where it does not refuse, so the same variant raised
/// from inside an evaluation that ran never matches on the calling thread.
fn is_unpolled_sync_bridge_refusal(error: &KernelError) -> bool {
    matches!(
        error,
        KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime
    ) && tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread)
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

    /// Name the authenticated Finding status feed that must authorize a
    /// governed memory write. The kernel checks this against the delivery
    /// receipt before invoking the tool so a write cannot enter a quarantine
    /// domain whose resolver will later reject it.
    fn required_finding_status_feed_id(
        &self,
        _ctx: &GuardContext,
    ) -> Result<Option<String>, KernelError> {
        Ok(None)
    }

    /// Validate the exact output after the tool returns and before it can be
    /// released or committed as a durable tool return. Stateful guards use
    /// this seam to bind an admission decision to the value actually read.
    fn validate_output_before_release(
        &self,
        _ctx: &GuardContext,
        _output: &ToolServerOutput,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    /// Return true when output validation binds the exact released value and
    /// therefore must run after every configured output transform.
    fn requires_exact_released_output(&self, _ctx: &GuardContext) -> bool {
        false
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
    /// Trusted identity and isolation state, when supplied by the host.
    pub security_context: Option<&'a SecurityInvocationContext>,
    /// Kernel-owned admission identity. Public construction grants no attempt authority.
    invocation_attempt_id: Option<&'a str>,
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
            invocation_attempt_id: None,
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

    /// Identity selected once by the kernel for this evaluation's guard passes.
    /// A retained operation or acquired session claim may preserve it across retries.
    #[must_use]
    pub const fn invocation_attempt_id(&self) -> Option<&'a str> {
        self.invocation_attempt_id
    }

    pub(crate) const fn with_invocation_attempt_id(mut self, identity: &'a str) -> Self {
        self.invocation_attempt_id = Some(identity);
        self
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
pub(crate) struct BudgetChargeResult {
    cleanup_custody: crate::budget_store::BudgetHoldCleanupCustody,
    grant_index: usize,
    cost_charged: u64,
    currency: String,
    budget_total: Option<u64>,
    /// Running committed cost after this charge (used to compute budget_remaining).
    new_committed_cost_units: u64,
    budget_hold_id: String,
    authorize_metadata: BudgetCommitMetadata,
    invocation_capture: Option<Box<crate::budget_store::BudgetHoldMutationDecision>>,
}

impl BudgetChargeResult {
    /// The rail/store hold id for the monetary budget charge, so a cleanup
    /// fault can name the stuck budget hold that needs manual recovery.
    fn reverse_event_id(&self) -> String {
        let authorize_event_id = self
            .authorize_metadata
            .event_id
            .as_deref()
            .unwrap_or(&self.budget_hold_id);
        let authorize_commit_index = self.authorize_metadata.budget_commit_index.unwrap_or(0);
        format!("{authorize_event_id}:rollback:{authorize_commit_index}")
    }

    fn capture_invocation_event_id(&self) -> String {
        let authorize_commit_index = self.authorize_metadata.budget_commit_index.unwrap_or(0);
        format!(
            "{}:capture-invocation:{authorize_commit_index}",
            self.budget_hold_id
        )
    }

    fn cancel_captured_before_dispatch_event_id(&self) -> String {
        self.reverse_event_id()
    }

    fn reconcile_event_id(&self) -> String {
        format!("{}:reconcile", self.budget_hold_id)
    }
}

pub(crate) enum PreExecutionBudgetMutation {
    None,
    Invocation { grant_index: usize },
    InvocationHold(BudgetChargeResult),
    Charge(BudgetChargeResult),
}

impl PreExecutionBudgetMutation {
    fn charge_result(&self) -> Option<&BudgetChargeResult> {
        match self {
            Self::Charge(charge) => Some(charge),
            Self::None | Self::Invocation { .. } | Self::InvocationHold(_) => None,
        }
    }

    fn durable_hold_result(&self) -> Option<&BudgetChargeResult> {
        match self {
            Self::Charge(charge) | Self::InvocationHold(charge) => Some(charge),
            Self::None | Self::Invocation { .. } => None,
        }
    }

    fn durable_hold_result_mut(&mut self) -> Option<&mut BudgetChargeResult> {
        match self {
            Self::Charge(charge) | Self::InvocationHold(charge) => Some(charge),
            Self::Invocation { .. } | Self::None => None,
        }
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
    snapshot: &chio_core::receipt::evidence::CapabilitySnapshot,
) -> Result<ChioScope, KernelError> {
    chio_core::canonical::UntrustedJsonText::from_wire(
        snapshot.grants_json.as_bytes(),
        64 * 1024 * 1024,
    )
    .and_then(|input| input.decode_signed())
    .map_err(crate::KernelError::from)
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

#[cfg(test)]
pub(crate) fn current_unix_timestamp() -> u64 {
    chio_test_support::clock::unix_seconds()
}
#[cfg(test)]
pub(crate) fn current_unix_timestamp_ms() -> u64 {
    chio_test_support::clock::unix_millis()
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
pub(crate) use dispatch::derive_security_dispatch_commitment_id;
// Purchase-marked admission checks for delivery-committed reveals.
#[path = "delivery_contract.rs"]
pub(crate) mod delivery_contract;
#[cfg(not(feature = "finding-market"))]
#[path = "market_disabled.rs"]
mod market_disabled;
#[cfg(feature = "finding-market")]
#[path = "purchase_gate.rs"]
mod purchase_gate;
#[cfg(all(test, feature = "finding-market"))]
pub(crate) use purchase_gate::validate_finding_pool_receipt_authority;
#[cfg(feature = "finding-market")]
mod recovery_gate;
mod responses;
#[path = "session_ops.rs"]
mod session_ops;
pub use session_ops::{
    NestedToolCallProofs, ProtocolRefusalReason, ProtocolRefusalSummary, ProtocolRequestDigest,
    ProtocolRequestDigestSource,
};
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

#[cfg(feature = "admission-test-support")]
pub use active_response_executor::test_support as active_response_test_support;

mod clock;

mod financial_accounting;
use financial_accounting::financial_budget_remaining;
