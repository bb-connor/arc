use std::collections::BTreeSet;

use chio_core::capability::governance::{
    GovernedResponseEffect, GovernedResponsePlanIntentBody, GovernedTransactionIntent,
    CHIO_ACTIVE_RESPONSE_SERVER_ID,
};
use chio_core::capability::scope::Operation;
use chio_core::capability::token::CapabilityToken;
use chio_core::receipt::security::{ActiveDefenseReceiptBody, CorrelatedFindingReceiptBody};
use chio_core::{canonical_json_bytes, Hash, PublicKey, Signature, SigningBackend};
use chio_security_types::ports::{ActionId, Digest32, OpaqueReceiptRef, RecordId};
use chio_security_types::{
    ResponseApprovalRequirement, ResponseEffectKind, ResponsePlanAuthorizationBody, ResponseTarget,
};
use serde::{Deserialize, Serialize};

use super::{current_unix_timestamp_ms, ChioKernel, KernelCryptoFloor, KernelError};

const AFFECTED_SET_HASH_DOMAIN: &[u8] = b"chio.response-affected-set.v1\0";
pub const ACTIVE_RESPONSE_SUBMISSION_SCHEMA: &str = "chio.active-response-submission.v1";
const ACTIVE_RESPONSE_SUBMISSION_SIGNATURE_DOMAIN: &[u8] = b"chio.active-response-submission.v1\0";

/// Canonical statement signed by the authenticated response-plan submitter.
///
/// The proof binds the complete compact plan and governed intent before the
/// kernel uses the submitter identity for approval separation. Policy code may
/// transport the proof, but it cannot substitute an unsigned public key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveResponseSubmissionProofBody {
    pub schema: String,
    pub action_id: ActionId,
    pub tenant_id: chio_security_types::ports::TenantId,
    pub plan_body_hash: String,
    pub governed_intent_hash: String,
    pub submitter: PublicKey,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl ActiveResponseSubmissionProofBody {
    pub fn new(
        action_id: ActionId,
        tenant_id: chio_security_types::ports::TenantId,
        plan_body_hash: String,
        governed_intent_hash: String,
        submitter: PublicKey,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, ActiveResponseSubmissionProofError> {
        let body = Self {
            schema: ACTIVE_RESPONSE_SUBMISSION_SCHEMA.to_string(),
            action_id,
            tenant_id,
            plan_body_hash,
            governed_intent_hash,
            submitter,
            issued_at_unix_ms,
            expires_at_unix_ms,
        };
        body.validate()?;
        Ok(body)
    }

    fn validate(&self) -> Result<(), ActiveResponseSubmissionProofError> {
        if self.schema != ACTIVE_RESPONSE_SUBMISSION_SCHEMA {
            return Err(ActiveResponseSubmissionProofError::Invalid(
                "submission proof schema is unsupported".to_string(),
            ));
        }
        validate_submission_digest(&self.plan_body_hash, "plan body")?;
        validate_submission_digest(&self.governed_intent_hash, "governed intent")?;
        if self.issued_at_unix_ms == 0 || self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(ActiveResponseSubmissionProofError::Invalid(
                "submission proof validity window is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

/// Signed authentication of the principal that submitted one exact plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveResponseSubmissionProof {
    pub body: ActiveResponseSubmissionProofBody,
    pub signature: Signature,
}

impl ActiveResponseSubmissionProof {
    pub fn sign_with_backend(
        body: ActiveResponseSubmissionProofBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self, ActiveResponseSubmissionProofError> {
        body.validate()?;
        let expected_submitter = body.submitter.clone();
        let signing_bytes = active_response_submission_signing_bytes(&body)?;
        let outcome = backend
            .sign_bytes_for_identity(&expected_submitter, &signing_bytes)
            .map_err(|error| ActiveResponseSubmissionProofError::Signing(error.to_string()))?;
        let expected_algorithm = expected_submitter.algorithm();
        if outcome.public_key != expected_submitter
            || outcome.algorithm != expected_algorithm
            || outcome.signature.algorithm() != expected_algorithm
            || !expected_submitter.verify(&signing_bytes, &outcome.signature)
        {
            return Err(ActiveResponseSubmissionProofError::Signing(
                "backend returned an invalid submitter identity or signature".to_string(),
            ));
        }
        Ok(Self {
            body,
            signature: outcome.signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool, ActiveResponseSubmissionProofError> {
        self.body.validate()?;
        if self.signature.algorithm() != self.body.submitter.algorithm() {
            return Ok(false);
        }
        Ok(self.body.submitter.verify(
            &active_response_submission_signing_bytes(&self.body)?,
            &self.signature,
        ))
    }
}

fn active_response_submission_signing_bytes(
    body: &ActiveResponseSubmissionProofBody,
) -> Result<Vec<u8>, ActiveResponseSubmissionProofError> {
    let canonical = canonical_json_bytes(body)
        .map_err(|error| ActiveResponseSubmissionProofError::Invalid(error.to_string()))?;
    let mut signing_bytes =
        Vec::with_capacity(ACTIVE_RESPONSE_SUBMISSION_SIGNATURE_DOMAIN.len() + canonical.len());
    signing_bytes.extend_from_slice(ACTIVE_RESPONSE_SUBMISSION_SIGNATURE_DOMAIN);
    signing_bytes.extend_from_slice(&canonical);
    Ok(signing_bytes)
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ActiveResponseSubmissionProofError {
    #[error("active-response submission proof is invalid: {0}")]
    Invalid(String),
    #[error("active-response submission proof signing failed: {0}")]
    Signing(String),
}

fn validate_submission_digest(
    digest: &str,
    label: &str,
) -> Result<(), ActiveResponseSubmissionProofError> {
    let parsed = Hash::from_hex(digest).map_err(|_| {
        ActiveResponseSubmissionProofError::Invalid(format!(
            "submission {label} hash is not a 32-byte hexadecimal digest"
        ))
    })?;
    if parsed.to_hex() != digest || parsed.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(ActiveResponseSubmissionProofError::Invalid(format!(
            "submission {label} hash is zero or not canonical lowercase hexadecimal"
        )));
    }
    Ok(())
}

/// Validated correlated-finding evidence returned by the trusted authority.
///
/// Construction is intentionally named for its trust precondition. A caller
/// must first verify the signed Chio receipt through an authoritative durable
/// evidence-id index. This type then revalidates the closed native body and
/// its deterministic evidence ID before the kernel accepts it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritativeCorrelatedFindingEvidence {
    evidence_id: OpaqueReceiptRef,
    body: CorrelatedFindingReceiptBody,
}

impl AuthoritativeCorrelatedFindingEvidence {
    pub fn from_verified_signed_receipt(
        evidence_id: OpaqueReceiptRef,
        body: CorrelatedFindingReceiptBody,
    ) -> Result<Self, ActiveResponseFindingAuthorityError> {
        let closed = ActiveDefenseReceiptBody::CorrelatedFinding(body.clone());
        closed.validate().map_err(|error| {
            ActiveResponseFindingAuthorityError::Integrity(format!(
                "correlated-finding body is invalid: {error}"
            ))
        })?;
        let expected_id = closed.evidence_id().map_err(|error| {
            ActiveResponseFindingAuthorityError::Integrity(format!(
                "correlated-finding evidence ID derivation failed: {error}"
            ))
        })?;
        if evidence_id != expected_id {
            return Err(ActiveResponseFindingAuthorityError::Integrity(
                "correlated-finding evidence ID does not match the signed body".to_string(),
            ));
        }
        Ok(Self { evidence_id, body })
    }

    #[must_use]
    pub const fn evidence_id(&self) -> &OpaqueReceiptRef {
        &self.evidence_id
    }

    #[must_use]
    pub const fn body(&self) -> &CorrelatedFindingReceiptBody {
        &self.body
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ActiveResponseFindingAuthorityError {
    #[error("correlated-finding authority is unavailable: {0}")]
    Unavailable(String),
    #[error("correlated-finding authority integrity failure: {0}")]
    Integrity(String),
}

/// Authoritative signed correlated-finding lookup for active response.
///
/// Implementations must resolve the logical active-defense evidence ID through
/// a durable evidence-id-to-signed-receipt index, verify the Chio receipt
/// signature and closed native body, and never trust caller-supplied metadata
/// or cast a finding ID into a receipt ID.
pub trait ActiveResponseFindingAuthority: Send + Sync {
    fn ensure_ready(&self) -> Result<(), ActiveResponseFindingAuthorityError>;

    fn load_correlated_finding(
        &self,
        evidence_id: &OpaqueReceiptRef,
    ) -> Result<Option<AuthoritativeCorrelatedFindingEvidence>, ActiveResponseFindingAuthorityError>;
}

/// Complete immutable input to pure active-response authorization verification.
///
/// This request does not carry approval tokens and does not reserve replay,
/// budget, or dispatch state. The later mutating coordinator must separately
/// enforce negotiated rollout before it can commit an active response.
#[derive(Clone, Debug)]
pub struct ActiveResponseAuthorizationRequest {
    operator_capability: CapabilityToken,
    plan_body: ResponsePlanAuthorizationBody,
    governed_intent: GovernedTransactionIntent,
    submission_proof: ActiveResponseSubmissionProof,
}

impl ActiveResponseAuthorizationRequest {
    pub fn new(
        operator_capability: CapabilityToken,
        plan_body: ResponsePlanAuthorizationBody,
        governed_intent: GovernedTransactionIntent,
        submission_proof: ActiveResponseSubmissionProof,
    ) -> Result<Self, KernelError> {
        if governed_intent.as_active_response_plan().is_none() {
            return Err(denied(
                "request must carry a governed active-response plan intent",
            ));
        }
        if !submission_proof
            .verify_signature()
            .map_err(|error| denied(&error.to_string()))?
        {
            return Err(denied(
                "active-response submission proof signature is invalid",
            ));
        }
        Ok(Self {
            operator_capability,
            plan_body,
            governed_intent,
            submission_proof,
        })
    }

    #[must_use]
    pub const fn operator_capability(&self) -> &CapabilityToken {
        &self.operator_capability
    }

    #[must_use]
    pub const fn plan_body(&self) -> &ResponsePlanAuthorizationBody {
        &self.plan_body
    }

    #[must_use]
    pub const fn governed_intent(&self) -> &GovernedTransactionIntent {
        &self.governed_intent
    }

    #[must_use]
    pub const fn authenticated_submitter(&self) -> &PublicKey {
        &self.submission_proof.body.submitter
    }

    #[must_use]
    pub const fn submission_proof(&self) -> &ActiveResponseSubmissionProof {
        &self.submission_proof
    }
}

/// Immutable authorization facts re-derived and verified by the kernel.
///
/// This value is not executable authorization. No declared approval
/// requirement is executable until a composition-owned
/// `ActiveResponseRequirementResolver` validates the effect class and eligible
/// time-to-live. The mutating coordinator must then obtain any required
/// approvals before dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedActiveResponseBindings {
    plan_body: ResponsePlanAuthorizationBody,
    request_id: String,
    authorization_capability_id: String,
    authorization_capability_hash: String,
    governed_intent_hash: String,
    plan_body_hash: String,
    declared_approval_requirement: ResponseApprovalRequirement,
    executor_subject: PublicKey,
    authenticated_submitter: PublicKey,
    ordered_effects: Vec<GovernedResponseEffect>,
    trigger_finding_occurred_at_unix_ms: u64,
    operator_capability_expires_at: u64,
    governed_operation_expires_at: u64,
}

impl VerifiedActiveResponseBindings {
    #[must_use]
    pub const fn plan_body(&self) -> &ResponsePlanAuthorizationBody {
        &self.plan_body
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn authorization_capability_id(&self) -> &str {
        &self.authorization_capability_id
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
    pub fn plan_body_hash(&self) -> &str {
        &self.plan_body_hash
    }

    /// Return the approval requirement declared by the submitted plan.
    ///
    /// This declaration is not a policy eligibility decision and does not make
    /// an automatic plan executable.
    #[must_use]
    pub const fn declared_approval_requirement(&self) -> &ResponseApprovalRequirement {
        &self.declared_approval_requirement
    }

    /// Return the governance policy identifier declared by the submitted plan.
    ///
    /// The coordinator must still resolve and enforce that policy.
    #[must_use]
    pub fn policy_id(&self) -> Option<&RecordId> {
        match &self.declared_approval_requirement {
            ResponseApprovalRequirement::Automatic => None,
            ResponseApprovalRequirement::Governed { policy_id } => Some(policy_id),
        }
    }

    #[must_use]
    pub const fn executor_subject(&self) -> &PublicKey {
        &self.executor_subject
    }

    #[must_use]
    pub const fn authenticated_submitter(&self) -> &PublicKey {
        &self.authenticated_submitter
    }

    #[must_use]
    pub fn ordered_effects(&self) -> &[GovernedResponseEffect] {
        &self.ordered_effects
    }

    #[must_use]
    pub const fn trigger_finding_occurred_at_unix_ms(&self) -> u64 {
        self.trigger_finding_occurred_at_unix_ms
    }

    #[must_use]
    pub const fn operator_capability_expires_at(&self) -> u64 {
        self.operator_capability_expires_at
    }

    #[must_use]
    pub const fn governed_operation_expires_at(&self) -> u64 {
        self.governed_operation_expires_at
    }
}

impl ChioKernel {
    /// Install the authoritative signed-finding lookup while response
    /// negotiation is disabled.
    pub fn set_active_response_finding_authority(
        &mut self,
        authority: std::sync::Arc<dyn ActiveResponseFindingAuthority>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        self.require_active_response_deactivated_for_authority_change()?;
        authority.ensure_ready().map_err(|error| {
            KernelError::Internal(format!(
                "active-response finding authority is not ready: {error}"
            ))
        })?;
        self.active_response_finding_authority = Some(authority);
        Ok(())
    }

    /// Remove the finding authority and immediately disable negotiation.
    pub fn clear_active_response_finding_authority(&mut self) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.active_response_finding_authority = None;
        self.governed_active_response_plans_enabled = false;
    }

    pub(super) fn ensure_active_response_finding_authority_ready(&self) -> Result<(), KernelError> {
        self.active_response_finding_authority
            .as_deref()
            .ok_or_else(|| {
                KernelError::Internal(
                    "active-response finding authority is not installed".to_string(),
                )
            })?
            .ensure_ready()
            .map_err(|error| {
                KernelError::Internal(format!(
                    "active-response finding authority is not ready: {error}"
                ))
            })
    }

    /// Verify all immutable and current-state bindings for an active response.
    ///
    /// This method performs no admission mutation. In particular, it does not
    /// activate the negotiated feature, reserve approval members, admit a
    /// capability budget, or commit dispatch. The mutating coordinator owns
    /// those rollout and exactly-once obligations.
    pub fn verify_active_response_authorization(
        &self,
        request: &ActiveResponseAuthorizationRequest,
    ) -> Result<VerifiedActiveResponseBindings, KernelError> {
        let now_unix_ms = current_unix_timestamp_ms();
        self.verify_active_response_authorization_at(request, now_unix_ms)
    }

    pub(super) fn verify_active_response_authorization_at(
        &self,
        request: &ActiveResponseAuthorizationRequest,
        now_unix_ms: u64,
    ) -> Result<VerifiedActiveResponseBindings, KernelError> {
        let now = now_unix_ms / 1_000;
        let capability = request.operator_capability();

        self.verify_capability_full_pre_admit(capability, None, now)
            .map_err(|reason| {
                denied(&format!(
                    "operator capability verification failed: {reason}"
                ))
            })?;
        self.check_revocation(capability)?;
        if !capability.delegation_chain.is_empty() {
            return Err(denied(
                "delegated operator capabilities are unsupported because active-response admission has no sibling-budget participant",
            ));
        }
        self.validate_delegation_admission(capability)?;

        if capability.aggregate_invocation_budget.is_some() {
            return Err(denied(
                "aggregate invocation budgets are unsupported because active-response admission has no quota participant",
            ));
        }
        if capability.budget_share_bps.is_some() {
            return Err(denied(
                "delegation budget shares are unsupported because pure active-response authorization has no sibling-sum admission participant",
            ));
        }

        let plan = request.plan_body();
        validate_plan_shape(plan, now_unix_ms)?;
        let trigger_finding_occurred_at_unix_ms =
            self.verify_active_response_finding_binding(plan)?;
        let active_policy_hash = active_policy_digest(&self.config.policy_hash)?;
        if plan.policy_hash != active_policy_hash {
            return Err(denied(
                "compact response plan policy hash does not match the active kernel policy",
            ));
        }
        let governed = request
            .governed_intent()
            .as_active_response_plan()
            .ok_or_else(|| denied("governed intent is not an active-response plan"))?;
        governed.validate().map_err(|error| {
            denied(&format!(
                "governed active-response plan is invalid: {error}"
            ))
        })?;

        let capability_hash = crate::threshold_approval::authorization_capability_hash(capability)
            .map_err(|error| denied(&error.to_string()))?;
        validate_capability_bindings(plan, governed, capability, &capability_hash, now_unix_ms)?;

        let canonical_plan_value = serde_json::to_value(plan).map_err(|error| {
            denied(&format!(
                "compact response-plan serialization failed: {error}"
            ))
        })?;
        let canonical_plan_bytes =
            canonical_json_bytes(&canonical_plan_value).map_err(|error| {
                denied(&format!(
                    "compact response-plan canonicalization failed: {error}"
                ))
            })?;
        let governed_plan_bytes =
            canonical_json_bytes(governed.canonical_plan_body()).map_err(|error| {
                denied(&format!(
                    "governed response-plan canonicalization failed: {error}"
                ))
            })?;
        if canonical_plan_bytes != governed_plan_bytes {
            return Err(denied(
                "governed canonical plan body does not equal the typed compact response plan",
            ));
        }
        let plan_body_hash = GovernedResponsePlanIntentBody::compute_plan_body_hash(
            &canonical_plan_value,
        )
        .map_err(|error| {
            denied(&format!(
                "compact response-plan body exceeds governance bounds or cannot be hashed: {error}"
            ))
        })?;
        if governed.plan_body_hash_value() != plan_body_hash {
            return Err(denied(
                "governed plan-body hash does not match the typed compact response plan",
            ));
        }

        validate_duplicate_bindings(plan, governed, &plan_body_hash)?;
        let ordered_effects = project_containment_effects(plan)?;
        validate_declared_automatic_effects(plan, &ordered_effects)?;
        if governed.ordered_effects() != ordered_effects.as_slice() {
            return Err(denied(
                "governed ordered effects do not equal the first-occurrence containment projection",
            ));
        }
        validate_exact_effect_grants(capability, &ordered_effects)?;

        let governed_intent_hash = request.governed_intent().binding_hash().map_err(|error| {
            denied(&format!(
                "governed active-response intent hashing failed: {error}"
            ))
        })?;
        validate_active_response_submission(
            request.submission_proof(),
            plan,
            &plan_body_hash,
            &governed_intent_hash,
            now_unix_ms,
            self.capability_crypto_floor,
        )?;

        Ok(VerifiedActiveResponseBindings {
            plan_body: plan.clone(),
            request_id: plan.action_id.as_str().to_string(),
            authorization_capability_id: capability.id.clone(),
            authorization_capability_hash: capability_hash,
            governed_intent_hash,
            plan_body_hash,
            declared_approval_requirement: plan.approval_requirement.clone(),
            executor_subject: capability.subject.clone(),
            authenticated_submitter: request.authenticated_submitter().clone(),
            ordered_effects,
            trigger_finding_occurred_at_unix_ms,
            operator_capability_expires_at: capability.expires_at,
            governed_operation_expires_at: governed.expires_at(),
        })
    }

    fn verify_active_response_finding_binding(
        &self,
        plan: &ResponsePlanAuthorizationBody,
    ) -> Result<u64, KernelError> {
        let authority = self
            .active_response_finding_authority
            .as_deref()
            .ok_or_else(|| denied("correlated-finding authority is not installed"))?;
        authority
            .ensure_ready()
            .map_err(|error| denied(&error.to_string()))?;
        let evidence = authority
            .load_correlated_finding(&plan.trigger_finding_receipt_id)
            .map_err(|error| denied(&error.to_string()))?
            .ok_or_else(|| denied("trigger correlated-finding receipt is missing"))?;
        let closed = ActiveDefenseReceiptBody::CorrelatedFinding(evidence.body().clone());
        closed.validate().map_err(|error| {
            denied(&format!(
                "trigger correlated-finding receipt body is invalid: {error}"
            ))
        })?;
        let derived_evidence_id = closed.evidence_id().map_err(|error| {
            denied(&format!(
                "trigger correlated-finding evidence ID derivation failed: {error}"
            ))
        })?;
        let finding = evidence.body();
        plan.created_at_unix_ms
            .checked_sub(finding.header.occurred_at_unix_ms)
            .ok_or_else(|| denied("trigger correlated finding was signed after plan creation"))?;
        if evidence.evidence_id() != &plan.trigger_finding_receipt_id
            || derived_evidence_id != plan.trigger_finding_receipt_id
            || finding.header.tenant_id != plan.tenant_id
            || finding.finding_id != plan.trigger_finding_id
            || finding.finding_hash != plan.trigger_finding_hash
            || finding.policy.policy_version != plan.policy_version
            || finding.policy.policy_hash != plan.policy_hash
        {
            return Err(denied(
                "trigger correlated-finding authority does not exactly match the response plan",
            ));
        }
        Ok(finding.header.occurred_at_unix_ms)
    }
}

fn validate_active_response_submission(
    proof: &ActiveResponseSubmissionProof,
    plan: &ResponsePlanAuthorizationBody,
    plan_body_hash: &str,
    governed_intent_hash: &str,
    now_unix_ms: u64,
    crypto_floor: KernelCryptoFloor,
) -> Result<(), KernelError> {
    let body = &proof.body;
    let plan_submitter = parse_canonical_public_key(plan.submitter.as_str(), "submitter")?;
    if body.action_id != plan.action_id
        || body.tenant_id != plan.tenant_id
        || body.plan_body_hash != plan_body_hash
        || body.governed_intent_hash != governed_intent_hash
        || body.submitter != plan_submitter
    {
        return Err(denied(
            "signed submission proof does not exactly match the active-response plan and governed intent",
        ));
    }
    if body.issued_at_unix_ms < plan.created_at_unix_ms
        || body.issued_at_unix_ms > now_unix_ms
        || now_unix_ms >= body.expires_at_unix_ms
        || body.expires_at_unix_ms > plan.expires_at_unix_ms
    {
        return Err(denied(
            "signed submission proof is outside the plan or current validity window",
        ));
    }
    if !crypto_floor
        .allowed_signing_algorithms()
        .contains(&proof.signature.algorithm())
    {
        return Err(denied(
            "signed submission proof algorithm is below the kernel crypto floor",
        ));
    }
    if !proof
        .verify_signature()
        .map_err(|error| denied(&error.to_string()))?
    {
        return Err(denied(
            "signed submission proof signature verification failed",
        ));
    }
    Ok(())
}

fn active_policy_digest(policy_hash: &str) -> Result<Digest32, KernelError> {
    let hash = Hash::from_hex(policy_hash)
        .map_err(|_| denied("active kernel policy hash is not a 32-byte hexadecimal digest"))?;
    if hash.to_hex() != policy_hash {
        return Err(denied(
            "active kernel policy hash is not canonical lowercase hexadecimal",
        ));
    }
    Ok(Digest32::new(*hash.as_bytes()))
}

fn validate_plan_shape(
    plan: &ResponsePlanAuthorizationBody,
    now_unix_ms: u64,
) -> Result<(), KernelError> {
    if plan.effects.is_empty() {
        return Err(denied("compact response plan has no effects"));
    }
    if plan.ttl_ms == 0
        || plan
            .created_at_unix_ms
            .checked_add(plan.ttl_ms)
            .is_none_or(|expires_at| expires_at != plan.expires_at_unix_ms)
    {
        return Err(denied("compact response plan has an invalid time range"));
    }
    if plan.created_at_unix_ms > now_unix_ms || now_unix_ms >= plan.expires_at_unix_ms {
        return Err(denied("compact response plan is not currently valid"));
    }
    if plan.operator_capability.expires_at_unix_ms < plan.expires_at_unix_ms {
        return Err(denied(
            "operator capability expires before the compact response plan",
        ));
    }

    let expected_affected_set_hash = affected_set_hash(plan)?;
    if plan.affected_set_hash != expected_affected_set_hash {
        return Err(denied(
            "compact response plan affected-set hash does not match its exact affected IDs",
        ));
    }

    let mut effect_ids = BTreeSet::new();
    let mut lineage_scoped = false;
    for (index, effect) in plan.effects.as_slice().iter().enumerate() {
        if usize::from(effect.ordinal) != index {
            return Err(denied("compact response plan effect ordinal is invalid"));
        }
        if !effect.kind.accepts_target(&effect.target) {
            return Err(denied(
                "compact response plan effect target does not match its kind",
            ));
        }
        if let ResponseTarget::Tenant { tenant_id } = &effect.target {
            if tenant_id != &plan.tenant_id {
                return Err(denied("compact response plan crosses a tenant boundary"));
            }
        }
        if let ResponseTarget::CapabilitySet { affected_set_hash } = &effect.target {
            if affected_set_hash != &plan.affected_set_hash {
                return Err(denied(
                    "capability-set response target does not match the exact affected set",
                ));
            }
        }
        if !effect_ids.insert(effect.effect_id.as_str()) {
            return Err(denied(
                "compact response plan contains a duplicate effect ID",
            ));
        }
        lineage_scoped |= matches!(
            effect.kind,
            ResponseEffectKind::SuspendCapabilitySet | ResponseEffectKind::FreezeIssuance
        );
    }
    if lineage_scoped
        && plan
            .effects
            .as_slice()
            .first()
            .is_none_or(|effect| effect.kind != ResponseEffectKind::FreezeIssuance)
    {
        return Err(denied(
            "lineage-scoped response plan does not begin with an issuance fence",
        ));
    }
    Ok(())
}

fn validate_capability_bindings(
    plan: &ResponsePlanAuthorizationBody,
    governed: &GovernedResponsePlanIntentBody,
    capability: &CapabilityToken,
    capability_hash: &str,
    now_unix_ms: u64,
) -> Result<(), KernelError> {
    let capability_issued_at_ms = capability
        .issued_at
        .checked_mul(1_000)
        .ok_or_else(|| denied("operator capability issuance time overflows milliseconds"))?;
    let capability_expires_at_ms = capability
        .expires_at
        .checked_mul(1_000)
        .ok_or_else(|| denied("operator capability expiry overflows milliseconds"))?;
    if plan.created_at_unix_ms < capability_issued_at_ms {
        return Err(denied(
            "compact response plan predates the operator capability",
        ));
    }
    if now_unix_ms >= capability_expires_at_ms {
        return Err(denied("operator capability is expired"));
    }
    if plan.operator_capability.capability_id.as_str() != capability.id
        || governed.operator_capability_id() != capability.id
    {
        return Err(denied(
            "operator capability ID binding does not match the verified capability",
        ));
    }
    let portable_capability_hash =
        Hash::from_bytes(*plan.operator_capability.capability_digest.as_bytes()).to_hex();
    if portable_capability_hash != capability_hash
        || governed.operator_capability_hash() != capability_hash
    {
        return Err(denied(
            "operator capability digest binding does not match the verified capability",
        ));
    }
    if plan.operator_capability.expires_at_unix_ms != capability_expires_at_ms
        || governed.operator_capability_expires_at() != capability.expires_at
    {
        return Err(denied(
            "operator capability expiry binding does not match the verified capability",
        ));
    }
    if plan.expires_at_unix_ms > capability_expires_at_ms
        || governed.expires_at() != plan.expires_at_unix_ms / 1_000
        || now_unix_ms / 1_000 >= governed.expires_at()
    {
        return Err(denied(
            "governed plan expiry does not match the safe millisecond-to-second projection",
        ));
    }
    if governed.plan_id() != plan.action_id.as_str() {
        return Err(denied(
            "governed plan ID does not match the response action ID",
        ));
    }

    let executor = parse_canonical_public_key(
        plan.operator_capability.executor_subject.as_str(),
        "executor subject",
    )?;
    if executor != capability.subject || governed.executor_subject() != &capability.subject {
        return Err(denied(
            "executor subject does not match the verified operator capability subject",
        ));
    }
    Ok(())
}

fn validate_duplicate_bindings(
    plan: &ResponsePlanAuthorizationBody,
    governed: &GovernedResponsePlanIntentBody,
    plan_body_hash: &str,
) -> Result<(), KernelError> {
    let affected_set_hash = Hash::from_bytes(*plan.affected_set_hash.as_bytes()).to_hex();
    let expected_target = serde_json::json!({ "affectedSetHash": affected_set_hash });
    if governed.target_binding() != &expected_target {
        return Err(denied(
            "governed target binding does not match the exact affected set",
        ));
    }
    let expected_rollback = serde_json::json!({ "responsePlanHash": plan_body_hash });
    if governed.rollback_binding() != &expected_rollback {
        return Err(denied(
            "governed rollback binding does not match the response-plan hash",
        ));
    }
    Ok(())
}

fn project_containment_effects(
    plan: &ResponsePlanAuthorizationBody,
) -> Result<Vec<GovernedResponseEffect>, KernelError> {
    let mut ordered = Vec::new();
    for effect in plan.effects.as_slice() {
        let logical = match effect.kind {
            ResponseEffectKind::EscalateAlert => None,
            ResponseEffectKind::ThrottleSession => Some(GovernedResponseEffect::ThrottleSession),
            ResponseEffectKind::RestrictEgress => Some(GovernedResponseEffect::RestrictEgress),
            ResponseEffectKind::SuspendSession => Some(GovernedResponseEffect::SuspendSession),
            ResponseEffectKind::SuspendCapabilitySet => {
                Some(GovernedResponseEffect::SuspendCapabilitySet)
            }
            ResponseEffectKind::FreezeIssuance => Some(GovernedResponseEffect::FreezeIssuance),
        };
        if let Some(logical) = logical {
            if !ordered.contains(&logical) {
                ordered.push(logical);
            }
        }
    }
    if ordered.is_empty() {
        return Err(denied(
            "governed active-response plan contains no containment effect",
        ));
    }
    Ok(ordered)
}

fn validate_declared_automatic_effects(
    plan: &ResponsePlanAuthorizationBody,
    ordered_effects: &[GovernedResponseEffect],
) -> Result<(), KernelError> {
    if matches!(
        &plan.approval_requirement,
        ResponseApprovalRequirement::Automatic
    ) && ordered_effects.iter().any(|effect| {
        !matches!(
            effect,
            GovernedResponseEffect::ThrottleSession | GovernedResponseEffect::RestrictEgress
        )
    }) {
        return Err(denied(
            "automatic approval cannot be declared for a heavy containment effect",
        ));
    }
    Ok(())
}

fn validate_exact_effect_grants(
    capability: &CapabilityToken,
    ordered_effects: &[GovernedResponseEffect],
) -> Result<(), KernelError> {
    for effect in ordered_effects {
        let covered = capability.scope.grants.iter().any(|grant| {
            grant.server_id == CHIO_ACTIVE_RESPONSE_SERVER_ID
                && grant.tool_name == effect.tool_name()
                && grant.operations.contains(&Operation::Invoke)
                && grant.constraints.is_empty()
                && grant.max_invocations.is_none()
                && grant.max_cost_per_invocation.is_none()
                && grant.max_total_cost.is_none()
                && grant.dpop_required.is_none()
        });
        if !covered {
            return Err(denied(&format!(
                "verified capability lacks an exact unconditional Invoke grant for {} on {}",
                effect.tool_name(),
                CHIO_ACTIVE_RESPONSE_SERVER_ID
            )));
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct AffectedSetCommitment<'a> {
    tenant_id: &'a str,
    affected_ids: &'a [RecordId],
}

fn affected_set_hash(plan: &ResponsePlanAuthorizationBody) -> Result<Digest32, KernelError> {
    let canonical = canonical_json_bytes(&AffectedSetCommitment {
        tenant_id: plan.tenant_id.as_str(),
        affected_ids: plan.affected_ids.as_slice(),
    })
    .map_err(|error| {
        denied(&format!(
            "affected-set commitment canonicalization failed: {error}"
        ))
    })?;
    let mut preimage = Vec::with_capacity(AFFECTED_SET_HASH_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(AFFECTED_SET_HASH_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(Digest32::new(*chio_core::sha256(&preimage).as_bytes()))
}

fn parse_canonical_public_key(value: &str, label: &str) -> Result<PublicKey, KernelError> {
    let key = PublicKey::from_hex(value)
        .map_err(|error| denied(&format!("{label} is not a valid public key: {error}")))?;
    if key.to_hex() != value {
        return Err(denied(&format!("{label} is not canonically encoded")));
    }
    Ok(key)
}

fn denied(reason: &str) -> KernelError {
    KernelError::GovernedTransactionDenied(format!(
        "active-response authorization denied: {reason}"
    ))
}
