use chio_core::receipt::body::ChioReceipt;
use chio_core::{canonical_json_bytes, sha256_hex, PublicKey};
use chio_security_types::ports::{
    ActionId, Digest32, EffectId, ErrorCode, OpaqueReceiptRef,
    PreparedActiveResponseDispatchBinding, RecordId, ResponseDispatchAuthorization,
    ResponsePlanRecord, TenantId,
};
use chio_security_types::ResponsePlan;
use serde::Serialize;
use std::sync::{Arc, Mutex};

const ACTIVE_RESPONSE_EXECUTOR_AUTHORITY_SCHEMA: &str =
    "chio.active-response-executor-authority.v1";
const ACTIVE_RESPONSE_EXECUTOR_AUTHORITY_DOMAIN: &[u8] =
    b"chio.active-response-executor-authority.v1\0";
const ACTIVE_RESPONSE_DISPATCH_SCHEMA: &str = "chio.active-response-dispatch.v1";
const ACTIVE_RESPONSE_DISPATCH_DOMAIN: &[u8] = b"chio.active-response-dispatch.v1\0";

/// Durable identity of the one executor authority trusted for active response.
///
/// The control plane owns the generation. Reopening the same authority after a
/// process restart must reuse its durable generation. Replacing its routing,
/// security configuration, or subject must durably increment the generation
/// before installing the replacement in a kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveResponseExecutorAuthorityIdentity {
    subject: PublicKey,
    generation: u64,
    authority_id: String,
}

impl ActiveResponseExecutorAuthorityIdentity {
    pub fn new(
        subject: PublicKey,
        generation: u64,
    ) -> Result<Self, ActiveResponseExecutorIdentityError> {
        if generation == 0 {
            return Err(ActiveResponseExecutorIdentityError::ZeroGeneration);
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct IdentityBody<'a> {
            executor_subject: &'a PublicKey,
            generation: u64,
            schema: &'static str,
        }

        let canonical = canonical_json_bytes(&IdentityBody {
            executor_subject: &subject,
            generation,
            schema: ACTIVE_RESPONSE_EXECUTOR_AUTHORITY_SCHEMA,
        })
        .map_err(|error| {
            ActiveResponseExecutorIdentityError::Canonicalization(error.to_string())
        })?;
        let mut preimage =
            Vec::with_capacity(ACTIVE_RESPONSE_EXECUTOR_AUTHORITY_DOMAIN.len() + canonical.len());
        preimage.extend_from_slice(ACTIVE_RESPONSE_EXECUTOR_AUTHORITY_DOMAIN);
        preimage.extend_from_slice(&canonical);
        Ok(Self {
            subject,
            generation,
            authority_id: sha256_hex(&preimage),
        })
    }

    #[must_use]
    pub const fn subject(&self) -> &PublicKey {
        &self.subject
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ActiveResponseExecutorIdentityError {
    #[error("active-response executor authority generation must be nonzero")]
    ZeroGeneration,
    #[error("active-response executor authority identity is not canonical: {0}")]
    Canonicalization(String),
}

/// Approval evidence bound to one exact executor request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActiveResponseExecutionApproval {
    Automatic,
    Governed {
        admission_operation_id: String,
        admission_operation_version: u64,
        approval_set_hash: String,
    },
}

/// Failure to derive the one canonical dispatch identifier for an active response.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ActiveResponseDispatchIdError {
    /// The stable authorization timestamp is outside the response plan lifetime.
    #[error("active-response dispatch authorization time is outside the plan window")]
    AuthorizationTimeOutsidePlan,
    /// The dispatch commitment body could not be canonically serialized.
    #[error("active-response dispatch canonicalization failed: {0}")]
    Canonicalization(String),
    /// The derived digest could not be represented as a durable record identifier.
    #[error("active-response dispatch identifier is invalid: {0}")]
    InvalidIdentifier(String),
}

/// Derive the canonical dispatch identifier shared by the kernel and durable executor.
pub fn derive_active_response_dispatch_id(
    response_plan: &ResponsePlan,
    executor_authority: &ActiveResponseExecutorAuthorityIdentity,
    authorization_capability_hash: &str,
    governed_intent_hash: &str,
    policy_decision_hash: &str,
    authorized_at_unix_ms: u64,
    approval: &ActiveResponseExecutionApproval,
) -> Result<RecordId, ActiveResponseDispatchIdError> {
    if authorized_at_unix_ms < response_plan.created_at_unix_ms
        || authorized_at_unix_ms >= response_plan.expires_at_unix_ms
    {
        return Err(ActiveResponseDispatchIdError::AuthorizationTimeOutsidePlan);
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct DispatchBody<'a> {
        schema: &'static str,
        tenant_id: &'a TenantId,
        action_id: &'a ActionId,
        plan_hash: &'a Digest32,
        executor_authority_id: &'a str,
        executor_authority_generation: u64,
        authorization_capability_hash: &'a str,
        governed_intent_hash: &'a str,
        policy_decision_hash: &'a str,
        authorized_at_unix_ms: u64,
        approval_mode: &'static str,
        admission_operation_id: Option<&'a str>,
        admission_operation_version: Option<u64>,
        approval_set_hash: Option<&'a str>,
    }

    let (approval_mode, admission_operation_id, admission_operation_version, approval_set_hash) =
        match approval {
            ActiveResponseExecutionApproval::Automatic => ("automatic", None, None, None),
            ActiveResponseExecutionApproval::Governed {
                admission_operation_id,
                admission_operation_version,
                approval_set_hash,
            } => (
                "governed",
                Some(admission_operation_id.as_str()),
                Some(*admission_operation_version),
                Some(approval_set_hash.as_str()),
            ),
        };
    let canonical = canonical_json_bytes(&DispatchBody {
        schema: ACTIVE_RESPONSE_DISPATCH_SCHEMA,
        tenant_id: &response_plan.tenant_id,
        action_id: &response_plan.action_id,
        plan_hash: &response_plan.plan_hash,
        executor_authority_id: executor_authority.authority_id(),
        executor_authority_generation: executor_authority.generation(),
        authorization_capability_hash,
        governed_intent_hash,
        policy_decision_hash,
        authorized_at_unix_ms,
        approval_mode,
        admission_operation_id,
        admission_operation_version,
        approval_set_hash,
    })
    .map_err(|error| ActiveResponseDispatchIdError::Canonicalization(error.to_string()))?;
    let mut preimage = Vec::with_capacity(ACTIVE_RESPONSE_DISPATCH_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(ACTIVE_RESPONSE_DISPATCH_DOMAIN);
    preimage.extend_from_slice(&canonical);
    RecordId::new(format!(
        "active_response_dispatch_{}",
        sha256_hex(&preimage)
    ))
    .map_err(|error| ActiveResponseDispatchIdError::InvalidIdentifier(error.to_string()))
}

/// Closed durable result of one committed active-response dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveResponseExecutionOutcome {
    Activated,
    FailedBeforeAnyEffect,
    RolledBackAfterPartial,
}

/// Durable resolution of an automatic dispatch's pre-commit fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutomaticActiveResponseDispatchFenceOutcome {
    /// The exact dispatch identity can no longer cross the commit boundary.
    Fenced,
    /// The exact dispatch crossed the commit boundary before the fence.
    DispatchCommitted,
}

/// Immutable kernel-built request accepted by the trusted executor authority.
#[derive(Clone, Debug)]
pub struct ActiveResponseExecutionRequest {
    response_plan: ResponsePlan,
    dispatch_id: RecordId,
    executor_authority: ActiveResponseExecutorAuthorityIdentity,
    request_id: String,
    plan_body_hash: String,
    authorization_capability_hash: String,
    governed_intent_hash: String,
    policy_decision_hash: String,
    approval: ActiveResponseExecutionApproval,
    authorized_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    dispatch_committed_resume: bool,
}

pub(crate) struct ActiveResponseExecutionRequestParts {
    pub(crate) response_plan: ResponsePlan,
    pub(crate) dispatch_id: RecordId,
    pub(crate) executor_authority: ActiveResponseExecutorAuthorityIdentity,
    pub(crate) request_id: String,
    pub(crate) plan_body_hash: String,
    pub(crate) authorization_capability_hash: String,
    pub(crate) governed_intent_hash: String,
    pub(crate) policy_decision_hash: String,
    pub(crate) approval: ActiveResponseExecutionApproval,
    pub(crate) authorized_at_unix_ms: u64,
    pub(crate) expires_at_unix_ms: u64,
    pub(crate) dispatch_committed_resume: bool,
}

impl ActiveResponseExecutionRequest {
    pub(super) fn new(parts: ActiveResponseExecutionRequestParts) -> Self {
        let ActiveResponseExecutionRequestParts {
            response_plan,
            dispatch_id,
            executor_authority,
            request_id,
            plan_body_hash,
            authorization_capability_hash,
            governed_intent_hash,
            policy_decision_hash,
            approval,
            authorized_at_unix_ms,
            expires_at_unix_ms,
            dispatch_committed_resume,
        } = parts;
        Self {
            response_plan,
            dispatch_id,
            executor_authority,
            request_id,
            plan_body_hash,
            authorization_capability_hash,
            governed_intent_hash,
            policy_decision_hash,
            approval,
            authorized_at_unix_ms,
            expires_at_unix_ms,
            dispatch_committed_resume,
        }
    }

    #[must_use]
    pub const fn response_plan(&self) -> &ResponsePlan {
        &self.response_plan
    }

    #[must_use]
    pub const fn dispatch_id(&self) -> &RecordId {
        &self.dispatch_id
    }

    #[must_use]
    pub const fn executor_authority(&self) -> &ActiveResponseExecutorAuthorityIdentity {
        &self.executor_authority
    }

    #[must_use]
    pub const fn executor_subject(&self) -> &PublicKey {
        self.executor_authority.subject()
    }

    #[must_use]
    pub const fn executor_authority_generation(&self) -> u64 {
        self.executor_authority.generation()
    }

    #[must_use]
    pub fn executor_authority_id(&self) -> &str {
        self.executor_authority.authority_id()
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn plan_body_hash(&self) -> &str {
        &self.plan_body_hash
    }

    #[must_use]
    pub fn authorization_capability_hash(&self) -> &str {
        &self.authorization_capability_hash
    }

    #[must_use]
    pub fn governed_intent_hash(&self) -> &str {
        &self.governed_intent_hash
    }

    #[must_use]
    pub fn policy_decision_hash(&self) -> &str {
        &self.policy_decision_hash
    }

    #[must_use]
    pub const fn approval(&self) -> &ActiveResponseExecutionApproval {
        &self.approval
    }

    #[must_use]
    pub const fn authorized_at_unix_ms(&self) -> u64 {
        self.authorized_at_unix_ms
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    #[must_use]
    pub const fn dispatch_committed_resume(&self) -> bool {
        self.dispatch_committed_resume
    }
}

/// Exact durable evidence for one applied effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveResponseEffectEvidence {
    effect_id: EffectId,
    transition_id: RecordId,
    generation: u64,
    resulting_version_hash: Digest32,
}

impl ActiveResponseEffectEvidence {
    #[must_use]
    pub const fn new(
        effect_id: EffectId,
        transition_id: RecordId,
        generation: u64,
        resulting_version_hash: Digest32,
    ) -> Self {
        Self {
            effect_id,
            transition_id,
            generation,
            resulting_version_hash,
        }
    }

    #[must_use]
    pub const fn effect_id(&self) -> &EffectId {
        &self.effect_id
    }

    #[must_use]
    pub const fn transition_id(&self) -> &RecordId {
        &self.transition_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn resulting_version_hash(&self) -> &Digest32 {
        &self.resulting_version_hash
    }
}

/// Exact durable transition for the one effect rejected during application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveResponseFailedEffectEvidence {
    effect_id: EffectId,
    transition_id: RecordId,
    generation: u64,
}

impl ActiveResponseFailedEffectEvidence {
    #[must_use]
    pub const fn new(effect_id: EffectId, transition_id: RecordId, generation: u64) -> Self {
        Self {
            effect_id,
            transition_id,
            generation,
        }
    }

    #[must_use]
    pub const fn effect_id(&self) -> &EffectId {
        &self.effect_id
    }

    #[must_use]
    pub const fn transition_id(&self) -> &RecordId {
        &self.transition_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Structured terminal failure bound to an active-response execution proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveResponseFailureEvidence {
    error_code: ErrorCode,
    failed_effect: Option<ActiveResponseFailedEffectEvidence>,
}

impl ActiveResponseFailureEvidence {
    #[must_use]
    pub const fn new(
        error_code: ErrorCode,
        failed_effect: Option<ActiveResponseFailedEffectEvidence>,
    ) -> Self {
        Self {
            error_code,
            failed_effect,
        }
    }

    #[must_use]
    pub const fn error_code(&self) -> &ErrorCode {
        &self.error_code
    }

    #[must_use]
    pub const fn failed_effect(&self) -> Option<&ActiveResponseFailedEffectEvidence> {
        self.failed_effect.as_ref()
    }
}

/// Verifiable durable proof of one exact closed active-response outcome.
#[derive(Clone, Debug)]
pub struct ActiveResponseExecutionEvidence {
    outcome: ActiveResponseExecutionOutcome,
    dispatch_id: RecordId,
    tenant_id: TenantId,
    action_id: ActionId,
    plan_hash: Digest32,
    executor_authority_generation: u64,
    response_generation: u64,
    response_transition_id: RecordId,
    response_body_hash: Digest32,
    response_record: ResponsePlanRecord,
    dispatch_authorization: ResponseDispatchAuthorization,
    proof_evidence_id: OpaqueReceiptRef,
    proof_body_hash: Digest32,
    completion_receipt: ChioReceipt,
    effects: Vec<ActiveResponseEffectEvidence>,
    failure: Option<ActiveResponseFailureEvidence>,
    recovered: bool,
}

pub struct ActiveResponseExecutionEvidenceParts {
    pub outcome: ActiveResponseExecutionOutcome,
    pub dispatch_id: RecordId,
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub executor_authority_generation: u64,
    pub response_generation: u64,
    pub response_transition_id: RecordId,
    pub response_body_hash: Digest32,
    pub response_record: ResponsePlanRecord,
    pub dispatch_authorization: ResponseDispatchAuthorization,
    pub proof_evidence_id: OpaqueReceiptRef,
    pub proof_body_hash: Digest32,
    pub completion_receipt: ChioReceipt,
    pub effects: Vec<ActiveResponseEffectEvidence>,
    pub failure: Option<ActiveResponseFailureEvidence>,
    pub recovered: bool,
}

impl ActiveResponseExecutionEvidence {
    #[must_use]
    pub fn new(parts: ActiveResponseExecutionEvidenceParts) -> Self {
        let ActiveResponseExecutionEvidenceParts {
            outcome,
            dispatch_id,
            tenant_id,
            action_id,
            plan_hash,
            executor_authority_generation,
            response_generation,
            response_transition_id,
            response_body_hash,
            response_record,
            dispatch_authorization,
            proof_evidence_id,
            proof_body_hash,
            completion_receipt,
            effects,
            failure,
            recovered,
        } = parts;
        Self {
            outcome,
            dispatch_id,
            tenant_id,
            action_id,
            plan_hash,
            executor_authority_generation,
            response_generation,
            response_transition_id,
            response_body_hash,
            response_record,
            dispatch_authorization,
            proof_evidence_id,
            proof_body_hash,
            completion_receipt,
            effects,
            failure,
            recovered,
        }
    }

    #[must_use]
    pub const fn outcome(&self) -> ActiveResponseExecutionOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn dispatch_id(&self) -> &RecordId {
        &self.dispatch_id
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    #[must_use]
    pub const fn plan_hash(&self) -> &Digest32 {
        &self.plan_hash
    }

    #[must_use]
    pub const fn executor_authority_generation(&self) -> u64 {
        self.executor_authority_generation
    }

    #[must_use]
    pub const fn response_generation(&self) -> u64 {
        self.response_generation
    }

    #[must_use]
    pub const fn response_transition_id(&self) -> &RecordId {
        &self.response_transition_id
    }

    #[must_use]
    pub const fn response_body_hash(&self) -> &Digest32 {
        &self.response_body_hash
    }

    #[must_use]
    pub const fn response_record(&self) -> &ResponsePlanRecord {
        &self.response_record
    }

    #[must_use]
    pub const fn dispatch_authorization(&self) -> &ResponseDispatchAuthorization {
        &self.dispatch_authorization
    }

    #[must_use]
    pub const fn proof_evidence_id(&self) -> &OpaqueReceiptRef {
        &self.proof_evidence_id
    }

    #[must_use]
    pub const fn proof_body_hash(&self) -> &Digest32 {
        &self.proof_body_hash
    }

    #[must_use]
    pub const fn completion_receipt(&self) -> &ChioReceipt {
        &self.completion_receipt
    }

    #[must_use]
    pub fn effects(&self) -> &[ActiveResponseEffectEvidence] {
        &self.effects
    }

    #[must_use]
    pub const fn failure(&self) -> Option<&ActiveResponseFailureEvidence> {
        self.failure.as_ref()
    }

    #[must_use]
    pub const fn recovered(&self) -> bool {
        self.recovered
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ActiveResponseExecutorError {
    #[error("active-response executor is not ready: {0}")]
    NotReady(String),
    #[error("active-response dispatch was rejected before commit: {0}")]
    RejectedBeforeCommit(String),
    #[error("active-response dispatch outcome is unknown: {0}")]
    OutcomeUnknown(String),
}

/// Exact immutable executor record proving that one active-response dispatch
/// crossed the durable commit boundary.
///
/// The kernel treats this as untrusted readback until it has independently
/// checked the canonical authorization, committed response record, response
/// plan, dispatch identity, and installed executor identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveResponseCommittedDispatch {
    response_plan: ResponsePlan,
    authorization: ResponseDispatchAuthorization,
    committed_response_record: ResponsePlanRecord,
}

impl ActiveResponseCommittedDispatch {
    #[must_use]
    pub const fn new(
        response_plan: ResponsePlan,
        authorization: ResponseDispatchAuthorization,
        committed_response_record: ResponsePlanRecord,
    ) -> Self {
        Self {
            response_plan,
            authorization,
            committed_response_record,
        }
    }

    #[must_use]
    pub const fn response_plan(&self) -> &ResponsePlan {
        &self.response_plan
    }

    #[must_use]
    pub const fn authorization(&self) -> &ResponseDispatchAuthorization {
        &self.authorization
    }

    #[must_use]
    pub const fn committed_response_record(&self) -> &ResponsePlanRecord {
        &self.committed_response_record
    }
}

/// Signed active-defense receipt readback used to prove durable execution.
pub trait ActiveResponseReceiptProofSource: Send + Sync {
    /// Check that signed receipt readback is available before dispatch.
    fn ensure_active_response_receipt_proofs_ready(
        &self,
    ) -> Result<(), ActiveResponseExecutorError>;

    /// Load the exact signed receipt persisted under a deterministic evidence ID.
    fn load_signed_active_response_receipt(
        &self,
        evidence_id: &OpaqueReceiptRef,
    ) -> Result<Option<ChioReceipt>, ActiveResponseExecutorError>;
}

/// Callable trusted boundary for durable active-response execution.
pub trait ActiveResponseExecutorAuthority: Send + Sync {
    /// Return the live durable authority identity.
    fn identity(&self) -> ActiveResponseExecutorAuthorityIdentity;

    /// Verify that dispatch, effects, receipts, and recovery are live.
    fn ensure_ready(&self) -> Result<(), ActiveResponseExecutorError>;

    /// Load the exact immutable authorization and response record retained at
    /// the durable commit boundary for one tenant-scoped dispatch identifier.
    ///
    /// This lookup must not re-evaluate current policy, capability revocation,
    /// submission authority, or approval-authority state. A missing record is
    /// distinct from an unavailable or invalid durable store.
    fn load_committed_active_response_dispatch(
        &self,
        _tenant_id: &TenantId,
        _dispatch_id: &RecordId,
    ) -> Result<Option<ActiveResponseCommittedDispatch>, ActiveResponseExecutorError> {
        Err(ActiveResponseExecutorError::NotReady(
            "active-response committed-dispatch readback is unavailable".to_string(),
        ))
    }

    /// Atomically close one exact automatic dispatch against future commit.
    ///
    /// The durable executor store must serialize this operation with the
    /// irreversible dispatch commit. Exact retries are idempotent. A different
    /// dispatch identity for the same tenant-scoped action must fail closed.
    fn fence_uncommitted_automatic_dispatch(
        &self,
        _response_plan: &ResponsePlan,
        _binding: &PreparedActiveResponseDispatchBinding,
    ) -> Result<AutomaticActiveResponseDispatchFenceOutcome, ActiveResponseExecutorError> {
        Err(ActiveResponseExecutorError::NotReady(
            "automatic active-response dispatch fencing is unavailable".to_string(),
        ))
    }

    /// Apply or recover the exact deterministic dispatch.
    ///
    /// Success means the response is durably activated, failed before any
    /// effect applied, or rolled back after a partial application. Applied
    /// effects carry exact transition evidence. Unknown outcomes remain
    /// retryable using the same dispatch identifier.
    fn execute_active_response(
        &self,
        request: &ActiveResponseExecutionRequest,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError>;
}

pub(super) struct InstalledActiveResponseExecutor {
    pub(super) authority: Arc<dyn ActiveResponseExecutorAuthority>,
    pub(super) identity: ActiveResponseExecutorAuthorityIdentity,
    pub(super) dispatch_gate: Mutex<()>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_identity_has_fixed_generation_separated_vectors() {
        let subject =
            PublicKey::from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .expect("RFC 8032 public key");
        assert_eq!(
            ActiveResponseExecutorAuthorityIdentity::new(subject.clone(), 7)
                .expect("generation 7 identity")
                .authority_id(),
            "ab8f35c98df1da3ae8b7fd4aea8119a46305a55a4aa0f6dce353e0e3d3445ae1"
        );
        assert_eq!(
            ActiveResponseExecutorAuthorityIdentity::new(subject, 8)
                .expect("generation 8 identity")
                .authority_id(),
            "a97b3a38306d9b90bbfccb944ffc80b36ffb6634b4c5f5e39cf9c7e241e663c5"
        );
    }

    #[test]
    fn authority_identity_rejects_zero_generation() {
        assert!(matches!(
            ActiveResponseExecutorAuthorityIdentity::new(
                PublicKey::from_hex(
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                )
                .expect("RFC 8032 public key"),
                0,
            ),
            Err(ActiveResponseExecutorIdentityError::ZeroGeneration)
        ));
    }
}
