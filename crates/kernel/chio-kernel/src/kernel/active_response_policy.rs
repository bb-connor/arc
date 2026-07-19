use std::sync::Arc;

use chio_core::capability::features::{
    GOVERNED_ACTIVE_RESPONSE_PLAN, THRESHOLD_GOVERNED_APPROVALS,
};
use chio_core::capability::governance::GovernedResponseEffect;
use chio_core::{canonical_json_bytes, sha256_hex, PublicKey};
use chio_security_types::ports::{Digest32, RecordId, RecordIdSet, TenantId};
use chio_security_types::{
    ResponseApprovalRequirement, ResponsePlanAuthorizationBody, ResponsePlanAuthorizationEffect,
    ResponseTarget,
};
use serde::Serialize;

use super::active_response_admission::VerifiedActiveResponseBindings;
use super::active_response_executor::{
    ActiveResponseExecutorAuthority, ActiveResponseExecutorAuthorityIdentity,
    InstalledActiveResponseExecutor,
};
use super::{current_unix_timestamp, ChioKernel, KernelError};

const ACTIVE_RESPONSE_POLICY_DECISION_SCHEMA: &str = "chio.active-response-policy-decision.v1";
const ACTIVE_RESPONSE_POLICY_DECISION_DOMAIN: &[u8] = b"chio.active-response-policy-decision.v1\0";
pub const MAX_ACTIVE_RESPONSE_FINDING_AGE_MS: u64 = 86_400_000;

/// Immutable, kernel-derived input to the active-response policy authority.
///
/// The capability subject is cryptographically bound to the verified operator
/// capability. It is not proof that the live effect executor authenticated as
/// that subject. The dispatch coordinator must establish that separate binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveResponsePolicyRequest {
    plan_body: ResponsePlanAuthorizationBody,
    ordered_effects: Vec<GovernedResponseEffect>,
    operator_capability_subject: PublicKey,
}

impl ActiveResponsePolicyRequest {
    fn from_verified(bindings: &VerifiedActiveResponseBindings) -> Self {
        Self {
            plan_body: bindings.plan_body().clone(),
            ordered_effects: bindings.ordered_effects().to_vec(),
            operator_capability_subject: bindings.executor_subject().clone(),
        }
    }

    #[must_use]
    pub fn policy_version(&self) -> &RecordId {
        &self.plan_body.policy_version
    }

    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.plan_body.tenant_id
    }

    #[must_use]
    pub fn trigger_finding_id(&self) -> &RecordId {
        &self.plan_body.trigger_finding_id
    }

    #[must_use]
    pub fn affected_ids(&self) -> &RecordIdSet {
        &self.plan_body.affected_ids
    }

    #[must_use]
    pub const fn affected_set_hash(&self) -> &Digest32 {
        &self.plan_body.affected_set_hash
    }

    #[must_use]
    pub fn exact_effects(&self) -> &[ResponsePlanAuthorizationEffect] {
        self.plan_body.effects.as_slice()
    }

    #[must_use]
    pub fn ordered_effects(&self) -> &[GovernedResponseEffect] {
        &self.ordered_effects
    }

    #[must_use]
    pub const fn ttl_ms(&self) -> u64 {
        self.plan_body.ttl_ms
    }

    #[must_use]
    pub const fn created_at_unix_ms(&self) -> u64 {
        self.plan_body.created_at_unix_ms
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.plan_body.expires_at_unix_ms
    }

    #[must_use]
    pub const fn declared_approval_requirement(&self) -> &ResponseApprovalRequirement {
        &self.plan_body.approval_requirement
    }

    #[must_use]
    pub const fn operator_capability_subject(&self) -> &PublicKey {
        &self.operator_capability_subject
    }

    #[must_use]
    pub fn target_at(&self, index: usize) -> Option<&ResponseTarget> {
        self.plan_body
            .effects
            .as_slice()
            .get(index)
            .map(|effect| &effect.target)
    }
}

/// Policy-authority output for one exact active-response request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveResponseRequirement {
    policy_hash: String,
    policy_version: RecordId,
    approval_requirement: ResponseApprovalRequirement,
    automatic_ttl_ceiling_ms: Option<u64>,
    max_finding_age_ms: u64,
}

impl ActiveResponseRequirement {
    #[must_use]
    pub const fn automatic(
        policy_hash: String,
        policy_version: RecordId,
        max_ttl_ms: u64,
        max_finding_age_ms: u64,
    ) -> Self {
        Self {
            policy_hash,
            policy_version,
            approval_requirement: ResponseApprovalRequirement::Automatic,
            automatic_ttl_ceiling_ms: Some(max_ttl_ms),
            max_finding_age_ms,
        }
    }

    #[must_use]
    pub const fn governed(
        policy_hash: String,
        policy_version: RecordId,
        policy_id: RecordId,
        max_finding_age_ms: u64,
    ) -> Self {
        Self {
            policy_hash,
            policy_version,
            approval_requirement: ResponseApprovalRequirement::Governed { policy_id },
            automatic_ttl_ceiling_ms: None,
            max_finding_age_ms,
        }
    }

    #[must_use]
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    #[must_use]
    pub const fn policy_version(&self) -> &RecordId {
        &self.policy_version
    }

    #[must_use]
    pub const fn approval_requirement(&self) -> &ResponseApprovalRequirement {
        &self.approval_requirement
    }

    #[must_use]
    pub const fn automatic_ttl_ceiling_ms(&self) -> Option<u64> {
        self.automatic_ttl_ceiling_ms
    }

    #[must_use]
    pub const fn max_finding_age_ms(&self) -> u64 {
        self.max_finding_age_ms
    }
}

/// Failure returned by the installed active-response policy authority.
#[derive(Debug, thiserror::Error)]
pub enum ActiveResponsePolicyResolutionError {
    #[error("active-response policy is stale: expected {expected}, received {received}")]
    StalePolicy { expected: String, received: String },

    #[error("active-response policy is unavailable: {0}")]
    Unavailable(String),

    #[error("active-response policy rejected the request: {0}")]
    Invalid(String),
}

/// Trusted, deterministic authority for effect class and TTL policy.
pub trait ActiveResponseRequirementResolver: Send + Sync {
    fn resolve_active_response_requirement(
        &self,
        request: &ActiveResponsePolicyRequest,
        policy_hash: &str,
    ) -> Result<ActiveResponseRequirement, ActiveResponsePolicyResolutionError>;
}

impl<F> ActiveResponseRequirementResolver for F
where
    F: Fn(
            &ActiveResponsePolicyRequest,
            &str,
        ) -> Result<ActiveResponseRequirement, ActiveResponsePolicyResolutionError>
        + Send
        + Sync,
{
    fn resolve_active_response_requirement(
        &self,
        request: &ActiveResponsePolicyRequest,
        policy_hash: &str,
    ) -> Result<ActiveResponseRequirement, ActiveResponsePolicyResolutionError> {
        self(request, policy_hash)
    }
}

/// Kernel-checked policy result bound to the exact compact plan hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedActiveResponseRequirement {
    policy_hash: String,
    approval_requirement: ResponseApprovalRequirement,
    policy_decision_hash: String,
    executor_authority: ActiveResponseExecutorAuthorityIdentity,
}

impl VerifiedActiveResponseRequirement {
    #[must_use]
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    #[must_use]
    pub const fn approval_requirement(&self) -> &ResponseApprovalRequirement {
        &self.approval_requirement
    }

    #[must_use]
    pub fn policy_decision_hash(&self) -> &str {
        &self.policy_decision_hash
    }

    #[must_use]
    pub const fn executor_authority(&self) -> &ActiveResponseExecutorAuthorityIdentity {
        &self.executor_authority
    }
}

impl ChioKernel {
    /// Install the policy authority while active-response negotiation is off.
    pub fn set_active_response_requirement_resolver(
        &mut self,
        resolver: Arc<dyn ActiveResponseRequirementResolver>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        self.require_active_response_deactivated_for_authority_change()?;
        self.active_response_requirement_resolver = Some(resolver);
        Ok(())
    }

    /// Remove the policy authority and immediately disable negotiation.
    pub fn clear_active_response_requirement_resolver(&mut self) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.active_response_requirement_resolver = None;
        self.governed_active_response_plans_enabled = false;
    }

    /// Install the durable, callable control-plane authority that executes plans.
    pub fn set_active_response_executor_authority(
        &mut self,
        authority: Arc<dyn ActiveResponseExecutorAuthority>,
    ) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        self.require_active_response_deactivated_for_authority_change()?;
        if let Some(installed) = self.active_response_executor.as_ref() {
            let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "active-response executor rotation requires the durable operation store"
                        .to_string(),
                )
            })?;
            let incomplete = operation_store
                .count_unresolved_by_authority(
                    crate::admission_operation::AdmissionOperationKind::GovernedActiveResponse,
                    installed.identity.authority_id(),
                )
                .map_err(|error| {
                    KernelError::Internal(format!(
                        "active-response executor rotation audit failed: {error}"
                    ))
                })?;
            if incomplete != 0 {
                return Err(KernelError::Internal(format!(
                    "active-response executor rotation would strand {incomplete} incomplete admission operations"
                )));
            }
        }
        authority.ensure_ready().map_err(|error| {
            KernelError::Internal(format!(
                "active-response executor authority is not ready: {error}"
            ))
        })?;
        let identity = authority.identity();
        if identity.generation() <= self.active_response_executor_generation_floor {
            return Err(KernelError::Internal(
                "active-response executor authority generation must increase on replacement"
                    .to_string(),
            ));
        }
        self.active_response_executor_generation_floor = identity.generation();
        self.active_response_executor = Some(InstalledActiveResponseExecutor {
            authority,
            identity,
            dispatch_gate: std::sync::Mutex::new(()),
        });
        Ok(())
    }

    /// Remove the executor authority and immediately disable negotiation.
    pub fn clear_active_response_executor_authority(&mut self) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.active_response_executor = None;
        self.governed_active_response_plans_enabled = false;
    }

    /// Disable active-response negotiation before replacing policy authority.
    pub fn deactivate_governed_active_response_plans(&mut self) {
        if self.has_atomic_security_runtime_publication() {
            return;
        }
        self.governed_active_response_plans_enabled = false;
    }

    /// Negotiate active-response plan support only with an installed resolver.
    pub fn enable_governed_active_response_plans(&mut self) -> Result<(), KernelError> {
        self.require_no_atomic_security_runtime_publication()?;
        if self.active_response_requirement_resolver.is_none() {
            return Err(KernelError::Internal(
                "active-response requirement resolver is not installed".to_string(),
            ));
        }
        let executor_identity = self.active_response_executor_identity()?;
        self.ensure_active_response_finding_authority_ready()?;
        self.ensure_active_response_submission_authority_configured()?;
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        self.recover_nonterminal_admission_kind_with_authorities(
            operation_store.as_ref(),
            self.budget_store.as_ref(),
            self.approval_store.as_deref(),
            crate::admission_operation::AdmissionOperationKind::GovernedActiveResponse,
            executor_identity.authority_id(),
        )?;
        self.governed_active_response_plans_enabled = true;
        Ok(())
    }

    pub(super) fn active_response_runtime_ready(&self) -> bool {
        self.governed_active_response_plans_enabled
            && self.active_response_requirement_resolver.is_some()
            && self
                .ensure_active_response_finding_authority_ready()
                .is_ok()
            && self
                .ensure_active_response_submission_authority_configured()
                .is_ok()
            && self.active_response_executor_identity().is_ok()
    }

    pub(super) fn active_response_executor_identity(
        &self,
    ) -> Result<ActiveResponseExecutorAuthorityIdentity, KernelError> {
        let installed = self.active_response_executor.as_ref().ok_or_else(|| {
            KernelError::Internal("active-response executor authority is not installed".to_string())
        })?;
        installed.authority.ensure_ready().map_err(|error| {
            KernelError::Internal(format!(
                "active-response executor authority is not ready: {error}"
            ))
        })?;
        let live_identity = installed.authority.identity();
        if live_identity != installed.identity {
            return Err(KernelError::Internal(
                "active-response executor authority identity changed after installation"
                    .to_string(),
            ));
        }
        Ok(live_identity)
    }

    pub(super) fn require_active_response_deactivated_for_authority_change(
        &self,
    ) -> Result<(), KernelError> {
        if self.governed_active_response_plans_enabled {
            return Err(KernelError::Internal(
                "active-response plan support must be explicitly deactivated before policy authority replacement"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Resolve policy from kernel-verified plan bindings without dispatching.
    pub(crate) fn resolve_active_response_requirement(
        &self,
        bindings: &VerifiedActiveResponseBindings,
    ) -> Result<VerifiedActiveResponseRequirement, KernelError> {
        let negotiated = self
            .capability_negotiation_for_remote(None, current_unix_timestamp())
            .map_err(active_response_policy_denied)?;
        if !negotiated.supports(GOVERNED_ACTIVE_RESPONSE_PLAN) {
            return Err(active_response_policy_denied(
                "governed active-response plans were not negotiated",
            ));
        }

        let resolver = self
            .active_response_requirement_resolver
            .as_deref()
            .ok_or_else(|| {
                active_response_policy_denied(
                    "active-response requirement resolver is not configured",
                )
            })?;
        let executor_authority = self
            .active_response_executor_identity()
            .map_err(|error| active_response_policy_denied(error.to_string()))?;
        if executor_authority.subject() != bindings.executor_subject() {
            return Err(active_response_policy_denied(
                "operator capability subject does not match the configured active-response executor",
            ));
        }
        let request = ActiveResponsePolicyRequest::from_verified(bindings);
        let requirement = resolver
            .resolve_active_response_requirement(&request, &self.config.policy_hash)
            .map_err(|error| active_response_policy_denied(error.to_string()))?;

        if requirement.policy_hash() != self.config.policy_hash {
            return Err(active_response_policy_denied(
                "resolved policy hash does not match the active kernel policy",
            ));
        }
        if requirement.policy_version() != request.policy_version() {
            return Err(active_response_policy_denied(
                "resolved policy version does not match the verified response plan",
            ));
        }
        if requirement.approval_requirement() != request.declared_approval_requirement() {
            return Err(active_response_policy_denied(
                "resolved approval requirement does not match the verified response plan",
            ));
        }
        if requirement.max_finding_age_ms() == 0
            || requirement.max_finding_age_ms() > MAX_ACTIVE_RESPONSE_FINDING_AGE_MS
        {
            return Err(active_response_policy_denied(
                "resolved maximum finding age is zero or exceeds the kernel bound",
            ));
        }
        let finding_age_ms = request
            .created_at_unix_ms()
            .checked_sub(bindings.trigger_finding_occurred_at_unix_ms())
            .ok_or_else(|| {
                active_response_policy_denied(
                    "trigger correlated finding was signed after plan creation",
                )
            })?;
        if finding_age_ms > requirement.max_finding_age_ms() {
            return Err(active_response_policy_denied(
                "trigger correlated finding exceeds the resolved freshness ceiling",
            ));
        }

        match requirement.approval_requirement() {
            ResponseApprovalRequirement::Automatic => {
                let ceiling = requirement.automatic_ttl_ceiling_ms().ok_or_else(|| {
                    active_response_policy_denied(
                        "automatic policy resolution omitted its TTL ceiling",
                    )
                })?;
                if ceiling == 0 || request.ttl_ms() > ceiling {
                    return Err(active_response_policy_denied(
                        "automatic response TTL exceeds the resolved policy ceiling",
                    ));
                }
            }
            ResponseApprovalRequirement::Governed { .. } => {
                if requirement.automatic_ttl_ceiling_ms().is_some() {
                    return Err(active_response_policy_denied(
                        "governed policy resolution carried an automatic TTL ceiling",
                    ));
                }
            }
        }

        let threshold_required = matches!(
            requirement.approval_requirement(),
            ResponseApprovalRequirement::Governed { .. }
        );
        if threshold_required && !negotiated.supports(THRESHOLD_GOVERNED_APPROVALS) {
            return Err(active_response_policy_denied(
                "threshold governed approvals were not negotiated",
            ));
        }

        let policy_decision_hash = active_response_policy_decision_hash(
            bindings,
            &requirement,
            threshold_required,
            &executor_authority,
        )?;
        Ok(VerifiedActiveResponseRequirement {
            policy_hash: requirement.policy_hash,
            approval_requirement: requirement.approval_requirement,
            policy_decision_hash,
            executor_authority,
        })
    }
}

fn active_response_policy_decision_hash(
    bindings: &VerifiedActiveResponseBindings,
    requirement: &ActiveResponseRequirement,
    threshold_required: bool,
    executor_authority: &ActiveResponseExecutorAuthorityIdentity,
) -> Result<String, KernelError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PolicyDecisionBody<'a> {
        schema: &'static str,
        plan_body_hash: &'a str,
        policy_hash: &'a str,
        policy_version: &'a RecordId,
        approval_requirement: &'a ResponseApprovalRequirement,
        automatic_ttl_ceiling_ms: Option<u64>,
        max_finding_age_ms: u64,
        operator_capability_subject: &'a PublicKey,
        executor_authority_id: &'a str,
        executor_authority_generation: u64,
        governed_active_response_plan: bool,
        threshold_governed_approvals: bool,
    }

    let canonical = canonical_json_bytes(&PolicyDecisionBody {
        schema: ACTIVE_RESPONSE_POLICY_DECISION_SCHEMA,
        plan_body_hash: bindings.plan_body_hash(),
        policy_hash: requirement.policy_hash(),
        policy_version: requirement.policy_version(),
        approval_requirement: requirement.approval_requirement(),
        automatic_ttl_ceiling_ms: requirement.automatic_ttl_ceiling_ms(),
        max_finding_age_ms: requirement.max_finding_age_ms(),
        operator_capability_subject: bindings.executor_subject(),
        executor_authority_id: executor_authority.authority_id(),
        executor_authority_generation: executor_authority.generation(),
        governed_active_response_plan: true,
        threshold_governed_approvals: threshold_required,
    })
    .map_err(|error| {
        active_response_policy_denied(format!(
            "active-response policy decision canonicalization failed: {error}"
        ))
    })?;
    let mut preimage =
        Vec::with_capacity(ACTIVE_RESPONSE_POLICY_DECISION_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(ACTIVE_RESPONSE_POLICY_DECISION_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn active_response_policy_denied(reason: impl Into<String>) -> KernelError {
    KernelError::GovernedTransactionDenied(format!(
        "active-response policy denied: {}",
        reason.into()
    ))
}
