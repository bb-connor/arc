// Adapted from Clawdstrike concepts; see docs/security/clawdstrike-active-defense-provenance.md.
use crate::ports::{
    ActionId, BoundedVec, CanonicalBody, Digest32, EffectId, ErrorCode, LeaseOwnerId, LineageId,
    OpaqueReceiptRef, RecordId, RecordIdSet, ResponseDispatchApproval, SessionId, TenantId,
    RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
};
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

pub const RESPONSE_STATE_SCHEMA_VERSION: u8 = 1;
pub const MAX_RESPONSE_EFFECTS: usize = 64;
pub const MAX_RESPONSE_MUTATIONS: usize = 1_024;

pub type PlannedResponseEffects = BoundedVec<PlannedResponseEffect, MAX_RESPONSE_EFFECTS>;
pub type ResponsePlanAuthorizationEffects =
    BoundedVec<ResponsePlanAuthorizationEffect, MAX_RESPONSE_EFFECTS>;
pub type ResponseMutationLog = BoundedVec<ResponseMutationRecord, MAX_RESPONSE_MUTATIONS>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseState {
    Planned,
    AwaitingApproval,
    Applying,
    Active,
    ApplyPartial,
    Expiring,
    RollingBack,
    RollbackPartial,
    Cancelled,
    Expired,
    Failed,
    Lifted,
}

impl ResponseState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Applying => "applying",
            Self::Active => "active",
            Self::ApplyPartial => "apply_partial",
            Self::Expiring => "expiring",
            Self::RollingBack => "rolling_back",
            Self::RollbackPartial => "rollback_partial",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Failed => "failed",
            Self::Lifted => "lifted",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::Expired | Self::Failed | Self::Lifted
        )
    }
}

#[must_use]
pub const fn is_legal_response_transition(from: ResponseState, to: ResponseState) -> bool {
    matches!(
        (from, to),
        (ResponseState::Planned, ResponseState::AwaitingApproval)
            | (ResponseState::Planned, ResponseState::Applying)
            | (ResponseState::Planned, ResponseState::Cancelled)
            | (ResponseState::Planned, ResponseState::Expired)
            | (ResponseState::Planned, ResponseState::Failed)
            | (ResponseState::AwaitingApproval, ResponseState::Applying)
            | (ResponseState::AwaitingApproval, ResponseState::Cancelled)
            | (ResponseState::AwaitingApproval, ResponseState::Expired)
            | (ResponseState::AwaitingApproval, ResponseState::Failed)
            | (ResponseState::Applying, ResponseState::Applying)
            | (ResponseState::Applying, ResponseState::Active)
            | (ResponseState::Applying, ResponseState::ApplyPartial)
            | (ResponseState::Applying, ResponseState::Failed)
            | (ResponseState::ApplyPartial, ResponseState::RollingBack)
            | (ResponseState::Active, ResponseState::Expiring)
            | (ResponseState::Active, ResponseState::RollingBack)
            | (ResponseState::Expiring, ResponseState::RollingBack)
            | (ResponseState::RollingBack, ResponseState::Lifted)
            | (ResponseState::RollingBack, ResponseState::RollbackPartial)
            | (ResponseState::RollbackPartial, ResponseState::RollingBack)
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseEffectKind {
    EscalateAlert,
    ThrottleSession,
    RestrictEgress,
    SuspendSession,
    SuspendCapabilitySet,
    FreezeIssuance,
}

impl ResponseEffectKind {
    #[must_use]
    pub const fn is_reversible(self) -> bool {
        !matches!(self, Self::EscalateAlert)
    }

    #[must_use]
    pub const fn accepts_target(self, target: &ResponseTarget) -> bool {
        matches!(
            (self, target),
            (Self::EscalateAlert, ResponseTarget::Tenant { .. })
                | (
                    Self::ThrottleSession | Self::RestrictEgress | Self::SuspendSession,
                    ResponseTarget::Session { .. }
                )
                | (
                    Self::SuspendCapabilitySet,
                    ResponseTarget::CapabilitySet { .. }
                )
                | (Self::FreezeIssuance, ResponseTarget::Lineage { .. })
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "target_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseTarget {
    Tenant { tenant_id: TenantId },
    Session { session_id: SessionId },
    Lineage { lineage_id: LineageId },
    CapabilitySet { affected_set_hash: Digest32 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "approval_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseApprovalRequirement {
    Automatic,
    Governed { policy_id: RecordId },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorCapabilityBinding {
    pub capability_id: RecordId,
    pub capability_digest: Digest32,
    pub expires_at_unix_ms: u64,
    pub executor_subject: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectSpec {
    pub kind: ResponseEffectKind,
    pub target: ResponseTarget,
    pub canonical_contribution: CanonicalBody,
    pub contribution_hash: Digest32,
    pub observed_base_version_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedResponseEffect {
    pub effect_id: EffectId,
    pub ordinal: u16,
    pub kind: ResponseEffectKind,
    pub target: ResponseTarget,
    pub canonical_contribution: CanonicalBody,
    pub contribution_hash: Digest32,
    pub observed_base_version_hash: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponsePlanInput {
    pub action_id: ActionId,
    pub trigger_finding_id: RecordId,
    pub trigger_finding_hash: Digest32,
    pub trigger_finding_receipt_id: OpaqueReceiptRef,
    pub tenant_id: TenantId,
    pub policy_version: RecordId,
    pub policy_hash: Digest32,
    pub affected_ids: Vec<RecordId>,
    pub effects: Vec<ResponseEffectSpec>,
    pub ttl_ms: u64,
    pub created_at_unix_ms: u64,
    pub operator_capability: OperatorCapabilityBinding,
    pub approval_requirement: ResponseApprovalRequirement,
    pub submitter: RecordId,
    pub reason_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlan {
    pub action_id: ActionId,
    pub trigger_finding_id: RecordId,
    pub trigger_finding_hash: Digest32,
    pub trigger_finding_receipt_id: OpaqueReceiptRef,
    pub tenant_id: TenantId,
    pub policy_version: RecordId,
    pub policy_hash: Digest32,
    pub affected_ids: RecordIdSet,
    pub affected_set_hash: Digest32,
    pub effects: PlannedResponseEffects,
    pub ttl_ms: u64,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub operator_capability: OperatorCapabilityBinding,
    pub approval_requirement: ResponseApprovalRequirement,
    pub submitter: RecordId,
    pub reason_hash: Digest32,
    pub plan_hash: Digest32,
}

/// Compact effect commitment used by response authorization.
///
/// `contribution_hash` commits to the canonical contribution retained in the
/// executable plan. The raw contribution is deliberately excluded from the
/// governed authorization body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlanAuthorizationEffect {
    pub effect_id: EffectId,
    pub ordinal: u16,
    pub kind: ResponseEffectKind,
    pub target: ResponseTarget,
    pub contribution_hash: Digest32,
    pub observed_base_version_hash: Digest32,
}

/// Complete compact response-plan commitment used by authorization.
///
/// The resulting body deliberately excludes `plan_hash` so the hash cannot
/// become part of its own preimage. Every executable contribution remains
/// bound by its validated canonical hash and derived effect identifier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlanAuthorizationBody {
    pub action_id: ActionId,
    pub trigger_finding_id: RecordId,
    pub trigger_finding_hash: Digest32,
    pub trigger_finding_receipt_id: OpaqueReceiptRef,
    pub tenant_id: TenantId,
    pub policy_version: RecordId,
    pub policy_hash: Digest32,
    pub affected_ids: RecordIdSet,
    pub affected_set_hash: Digest32,
    pub effects: ResponsePlanAuthorizationEffects,
    pub ttl_ms: u64,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub operator_capability: OperatorCapabilityBinding,
    pub approval_requirement: ResponseApprovalRequirement,
    pub submitter: RecordId,
    pub reason_hash: Digest32,
}

impl ResponsePlan {
    #[must_use]
    pub fn authorization_body(&self) -> ResponsePlanAuthorizationBody {
        ResponsePlanAuthorizationBody {
            action_id: self.action_id.clone(),
            trigger_finding_id: self.trigger_finding_id.clone(),
            trigger_finding_hash: self.trigger_finding_hash,
            trigger_finding_receipt_id: self.trigger_finding_receipt_id.clone(),
            tenant_id: self.tenant_id.clone(),
            policy_version: self.policy_version.clone(),
            policy_hash: self.policy_hash,
            affected_ids: self.affected_ids.clone(),
            affected_set_hash: self.affected_set_hash,
            effects: self
                .effects
                .map_ref(|effect| ResponsePlanAuthorizationEffect {
                    effect_id: effect.effect_id.clone(),
                    ordinal: effect.ordinal,
                    kind: effect.kind,
                    target: effect.target.clone(),
                    contribution_hash: effect.contribution_hash,
                    observed_base_version_hash: effect.observed_base_version_hash,
                }),
            ttl_ms: self.ttl_ms,
            created_at_unix_ms: self.created_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            operator_capability: self.operator_capability.clone(),
            approval_requirement: self.approval_requirement.clone(),
            submitter: self.submitter.clone(),
            reason_hash: self.reason_hash,
        }
    }

    pub fn validate_shape(&self) -> Result<(), ResponseShapeError> {
        if self.effects.is_empty() {
            return Err(ResponseShapeError::EmptyEffects);
        }
        if digest_is_zero(&self.trigger_finding_hash) {
            return Err(ResponseShapeError::InvalidFindingHash);
        }
        if digest_is_zero(&self.policy_hash) {
            return Err(ResponseShapeError::InvalidPolicyHash);
        }
        if digest_is_zero(&self.affected_set_hash) {
            return Err(ResponseShapeError::InvalidAffectedSetHash);
        }
        if digest_is_zero(&self.operator_capability.capability_digest) {
            return Err(ResponseShapeError::InvalidOperatorCapabilityHash);
        }
        if digest_is_zero(&self.reason_hash) {
            return Err(ResponseShapeError::InvalidReasonHash);
        }
        if digest_is_zero(&self.plan_hash) {
            return Err(ResponseShapeError::InvalidPlanHash);
        }
        if self.ttl_ms == 0
            || self
                .created_at_unix_ms
                .checked_add(self.ttl_ms)
                .is_none_or(|expiry| expiry != self.expires_at_unix_ms)
        {
            return Err(ResponseShapeError::InvalidTimeRange);
        }
        if self.operator_capability.expires_at_unix_ms < self.expires_at_unix_ms {
            return Err(ResponseShapeError::CapabilityExpiresBeforePlan);
        }
        let mut effect_ids = Vec::with_capacity(self.effects.len());
        let mut lineage_scoped = false;
        for (index, effect) in self.effects.as_slice().iter().enumerate() {
            if usize::from(effect.ordinal) != index {
                return Err(ResponseShapeError::InvalidEffectOrdinal);
            }
            if !effect.kind.accepts_target(&effect.target) {
                return Err(ResponseShapeError::InvalidEffectTarget);
            }
            if digest_is_zero(&effect.contribution_hash) {
                return Err(ResponseShapeError::InvalidContributionHash);
            }
            if digest_is_zero(&effect.observed_base_version_hash) {
                return Err(ResponseShapeError::InvalidObservedBaseVersionHash);
            }
            if matches!(
                &effect.target,
                ResponseTarget::CapabilitySet { affected_set_hash }
                    if digest_is_zero(affected_set_hash)
            ) {
                return Err(ResponseShapeError::InvalidTargetAffectedSetHash);
            }
            if let ResponseTarget::Tenant { tenant_id } = &effect.target {
                if tenant_id != &self.tenant_id {
                    return Err(ResponseShapeError::CrossTenantTarget);
                }
            }
            lineage_scoped |= matches!(
                effect.kind,
                ResponseEffectKind::SuspendCapabilitySet | ResponseEffectKind::FreezeIssuance
            );
            effect_ids.push(effect.effect_id.as_str());
        }
        effect_ids.sort_unstable();
        if effect_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ResponseShapeError::DuplicateEffectId);
        }
        if lineage_scoped
            && self
                .effects
                .as_slice()
                .first()
                .is_none_or(|effect| effect.kind != ResponseEffectKind::FreezeIssuance)
        {
            return Err(ResponseShapeError::MissingIssuanceFence);
        }
        Ok(())
    }

    #[must_use]
    pub fn effect(&self, effect_id: &EffectId) -> Option<&PlannedResponseEffect> {
        self.effects
            .as_slice()
            .iter()
            .find(|effect| &effect.effect_id == effect_id)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseTransitionCause {
    ApprovalRequested,
    ApprovalSatisfied,
    ApplyStarted,
    ApplyCompleted,
    ApplyingLeaseRenewed,
    ApplyingLeaseExpired,
    PlanExpired,
    OperatorCancelled,
    RollbackCompleted,
    RollbackFailed,
    RollbackRequested,
    RollbackRetry,
    ValidationFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseRequestedRecord {
    pub transition_id: RecordId,
    pub generation: u64,
    pub prior_receipt_id: OpaqueReceiptRef,
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseTransitionRecord {
    pub transition_id: RecordId,
    pub generation: u64,
    pub from_state: ResponseState,
    pub to_state: ResponseState,
    pub cause: ResponseTransitionCause,
    pub applying_lease_expires_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_lease_owner_id: Option<LeaseOwnerId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_fencing_token: Option<u64>,
    pub prior_receipt_id: OpaqueReceiptRef,
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectRequestedRecord {
    pub transition_id: RecordId,
    pub generation: u64,
    pub effect_id: EffectId,
    pub effect_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_lease_owner_id: Option<LeaseOwnerId>,
    pub scheduler_fencing_token: u64,
    pub prior_receipt_id: OpaqueReceiptRef,
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectAppliedRecord {
    pub transition_id: RecordId,
    pub generation: u64,
    pub effect_id: EffectId,
    pub effect_generation: u64,
    pub resulting_version_hash: Digest32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_lease_owner_id: Option<LeaseOwnerId>,
    pub scheduler_fencing_token: u64,
    pub effect_transition_id: Option<RecordId>,
    pub prior_receipt_id: OpaqueReceiptRef,
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectFailedRecord {
    pub transition_id: RecordId,
    pub generation: u64,
    pub effect_id: EffectId,
    pub effect_generation: u64,
    pub error_code: ErrorCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_lease_owner_id: Option<LeaseOwnerId>,
    pub scheduler_fencing_token: u64,
    pub effect_transition_id: Option<RecordId>,
    pub prior_receipt_id: OpaqueReceiptRef,
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", deny_unknown_fields)]
pub enum ResponseRollbackOutcome {
    Requested,
    Restored { resulting_version_hash: Digest32 },
    Failed { error_code: ErrorCode },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseRollbackRecord {
    pub transition_id: RecordId,
    pub generation: u64,
    pub effect_id: EffectId,
    pub effect_generation: u64,
    pub outcome: ResponseRollbackOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_lease_owner_id: Option<LeaseOwnerId>,
    pub scheduler_fencing_token: u64,
    pub effect_transition_id: Option<RecordId>,
    pub prior_receipt_id: OpaqueReceiptRef,
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseFailureRecord {
    pub transition_id: RecordId,
    pub generation: u64,
    pub from_state: ResponseState,
    pub to_state: ResponseState,
    pub error_code: ErrorCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_lease_owner_id: Option<LeaseOwnerId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_fencing_token: Option<u64>,
    pub prior_receipt_id: OpaqueReceiptRef,
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseFinalRecord {
    pub transition_id: RecordId,
    pub generation: u64,
    pub from_state: ResponseState,
    pub final_state: ResponseState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_lease_owner_id: Option<LeaseOwnerId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_fencing_token: Option<u64>,
    pub prior_receipt_id: OpaqueReceiptRef,
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "record_type",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ResponseMutationRecord {
    Requested(ResponseRequestedRecord),
    Transition(ResponseTransitionRecord),
    EffectRequested(ResponseEffectRequestedRecord),
    EffectApplied(ResponseEffectAppliedRecord),
    EffectFailed(ResponseEffectFailedRecord),
    Rollback(ResponseRollbackRecord),
    Failed(ResponseFailureRecord),
    Final(ResponseFinalRecord),
}

/// Immutable authorization binding persisted into every executor-admitted
/// response snapshot before the dispatch crosses its commit boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseExecutionDispatchBinding {
    pub schema_version: u8,
    pub tenant_id: TenantId,
    pub dispatch_id: RecordId,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub executor_authority_id: RecordId,
    pub executor_authority_generation: u64,
    pub authorization_capability_hash: Digest32,
    pub governed_intent_hash: Digest32,
    pub policy_decision_hash: Digest32,
    pub approval: ResponseDispatchApproval,
    pub authorized_at_unix_ms: u64,
}

impl ResponseExecutionDispatchBinding {
    pub fn validate_for_response(
        &self,
        tenant_id: &TenantId,
        action_id: &ActionId,
        plan_hash: &Digest32,
        plan_expires_at_unix_ms: u64,
    ) -> Result<(), ResponseExecutionDispatchBindingError> {
        if self.schema_version != RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION {
            return Err(ResponseExecutionDispatchBindingError::Invalid(
                "unsupported schema version",
            ));
        }
        if &self.tenant_id != tenant_id
            || &self.action_id != action_id
            || &self.plan_hash != plan_hash
        {
            return Err(ResponseExecutionDispatchBindingError::Invalid(
                "response identity mismatch",
            ));
        }
        if self.executor_authority_generation == 0
            || self.authorized_at_unix_ms == 0
            || self.authorized_at_unix_ms >= plan_expires_at_unix_ms
            || record_id_is_zero_sentinel(&self.dispatch_id)
            || record_id_is_zero_sentinel(&self.executor_authority_id)
        {
            return Err(ResponseExecutionDispatchBindingError::Invalid(
                "authority generation or authorization time is invalid",
            ));
        }
        if digest_is_zero(&self.plan_hash)
            || digest_is_zero(&self.authorization_capability_hash)
            || digest_is_zero(&self.governed_intent_hash)
            || digest_is_zero(&self.policy_decision_hash)
        {
            return Err(ResponseExecutionDispatchBindingError::Invalid(
                "dispatch binding contains a zero digest",
            ));
        }
        if matches!(
            &self.approval,
            ResponseDispatchApproval::Governed {
                admission_operation_version: 0,
                ..
            }
        ) || matches!(
            &self.approval,
            ResponseDispatchApproval::Governed {
                approval_set_hash,
                ..
            } if digest_is_zero(approval_set_hash)
        ) || matches!(
            &self.approval,
            ResponseDispatchApproval::Governed {
                admission_operation_id,
                ..
            } if record_id_is_zero_sentinel(admission_operation_id)
        ) {
            return Err(ResponseExecutionDispatchBindingError::Invalid(
                "governed approval binding is invalid",
            ));
        }
        Ok(())
    }

    pub fn validate_for_plan(
        &self,
        plan: &ResponsePlan,
    ) -> Result<(), ResponseExecutionDispatchBindingError> {
        self.validate_for_response(
            &plan.tenant_id,
            &plan.action_id,
            &plan.plan_hash,
            plan.expires_at_unix_ms,
        )?;
        if self.authorized_at_unix_ms < plan.created_at_unix_ms
            || self.authorization_capability_hash != plan.operator_capability.capability_digest
        {
            return Err(ResponseExecutionDispatchBindingError::Invalid(
                "dispatch authorization does not match the response plan",
            ));
        }
        let approval_matches = matches!(
            (&plan.approval_requirement, &self.approval),
            (
                ResponseApprovalRequirement::Automatic,
                ResponseDispatchApproval::Automatic
            ) | (
                ResponseApprovalRequirement::Governed { .. },
                ResponseDispatchApproval::Governed { .. }
            )
        );
        if !approval_matches {
            return Err(ResponseExecutionDispatchBindingError::Invalid(
                "dispatch approval mode does not match the response plan",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseExecutionDispatchBindingError {
    Invalid(&'static str),
}

impl fmt::Display for ResponseExecutionDispatchBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => {
                write!(formatter, "invalid response dispatch binding: {reason}")
            }
        }
    }
}

impl core::error::Error for ResponseExecutionDispatchBindingError {}

impl ResponseMutationRecord {
    #[must_use]
    pub const fn transition_id(&self) -> &RecordId {
        match self {
            Self::Requested(record) => &record.transition_id,
            Self::Transition(record) => &record.transition_id,
            Self::EffectRequested(record) => &record.transition_id,
            Self::EffectApplied(record) => &record.transition_id,
            Self::EffectFailed(record) => &record.transition_id,
            Self::Rollback(record) => &record.transition_id,
            Self::Failed(record) => &record.transition_id,
            Self::Final(record) => &record.transition_id,
        }
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        match self {
            Self::Requested(record) => record.generation,
            Self::Transition(record) => record.generation,
            Self::EffectRequested(record) => record.generation,
            Self::EffectApplied(record) => record.generation,
            Self::EffectFailed(record) => record.generation,
            Self::Rollback(record) => record.generation,
            Self::Failed(record) => record.generation,
            Self::Final(record) => record.generation,
        }
    }

    #[must_use]
    pub const fn occurred_at_unix_ms(&self) -> u64 {
        match self {
            Self::Requested(record) => record.occurred_at_unix_ms,
            Self::Transition(record) => record.occurred_at_unix_ms,
            Self::EffectRequested(record) => record.occurred_at_unix_ms,
            Self::EffectApplied(record) => record.occurred_at_unix_ms,
            Self::EffectFailed(record) => record.occurred_at_unix_ms,
            Self::Rollback(record) => record.occurred_at_unix_ms,
            Self::Failed(record) => record.occurred_at_unix_ms,
            Self::Final(record) => record.occurred_at_unix_ms,
        }
    }

    #[must_use]
    pub const fn prior_receipt_id(&self) -> &OpaqueReceiptRef {
        match self {
            Self::Requested(record) => &record.prior_receipt_id,
            Self::Transition(record) => &record.prior_receipt_id,
            Self::EffectRequested(record) => &record.prior_receipt_id,
            Self::EffectApplied(record) => &record.prior_receipt_id,
            Self::EffectFailed(record) => &record.prior_receipt_id,
            Self::Rollback(record) => &record.prior_receipt_id,
            Self::Failed(record) => &record.prior_receipt_id,
            Self::Final(record) => &record.prior_receipt_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseEffectProgress {
    Planned,
    Requested,
    Applied,
    ApplyFailed,
    RollbackRequested,
    Restored,
    RollbackFailed,
}

/// Portable completion state for one response effect.
///
/// Receipt validation and durable snapshot validation both reduce their
/// richer effect records to this closed vocabulary before accepting a
/// terminal apply result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseCompletionEffectState {
    Planned,
    Requested,
    Applied,
    ApplyFailed(ErrorCode),
    Unresolved,
}

/// Validate the effect shape shared by response snapshots and completion
/// receipts.
///
/// ApplyPartial deliberately permits every effect to be Applied. That state
/// represents a lease expiry after the external effects committed but before
/// the response reached Active. It also permits an authoritative NotExecuted
/// failure with no applied effects so the response can enter rollback and
/// prove that no restriction remains. Failed deliberately permits every
/// effect to remain Planned for a failure before the first effect request.
#[must_use]
pub fn response_completion_effect_shape_is_valid(
    final_state: ResponseState,
    error_code: Option<&ErrorCode>,
    effects: &[ResponseCompletionEffectState],
) -> bool {
    if effects.is_empty() {
        return false;
    }
    let applied = effects
        .iter()
        .filter(|effect| matches!(effect, ResponseCompletionEffectState::Applied))
        .count();
    let planned = effects
        .iter()
        .filter(|effect| matches!(effect, ResponseCompletionEffectState::Planned))
        .count();
    let failed = effects
        .iter()
        .filter_map(|effect| match effect {
            ResponseCompletionEffectState::ApplyFailed(error) => Some(error),
            _ => None,
        })
        .collect::<Vec<_>>();
    let resolved = effects.iter().all(|effect| {
        matches!(
            effect,
            ResponseCompletionEffectState::Planned
                | ResponseCompletionEffectState::Applied
                | ResponseCompletionEffectState::ApplyFailed(_)
        )
    });
    let failure_matches = failed
        .first()
        .is_none_or(|effect_error| error_code == Some(*effect_error));
    match final_state {
        ResponseState::Active => error_code.is_none() && applied == effects.len(),
        ResponseState::ApplyPartial => {
            (error_code.is_some()
                && applied > 0
                && resolved
                && failed.len() <= 1
                && failure_matches)
                || (error_code
                    .is_some_and(|error| error.as_str() == "response.effect_not_executed")
                    && applied == 0
                    && failed.len() == 1
                    && planned + failed.len() == effects.len()
                    && failure_matches)
        }
        ResponseState::Failed => {
            error_code.is_some()
                && resolved
                && failure_matches
                && (planned == effects.len()
                    || (failed.len() == 1 && planned + failed.len() == effects.len()))
        }
        _ => false,
    }
}

/// Exact durable effect transition associated with one terminal apply failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseFailedEffectEvidence {
    effect_id: EffectId,
    transition_id: RecordId,
    generation: u64,
}

impl ResponseFailedEffectEvidence {
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

/// Exact terminal error and optional authoritative failed-effect transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseTerminalFailureEvidence {
    error_code: ErrorCode,
    failed_effect: Option<ResponseFailedEffectEvidence>,
}

impl ResponseTerminalFailureEvidence {
    #[must_use]
    pub const fn error_code(&self) -> &ErrorCode {
        &self.error_code
    }

    #[must_use]
    pub const fn failed_effect(&self) -> Option<&ResponseFailedEffectEvidence> {
        self.failed_effect.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSnapshot {
    pub schema_version: u8,
    pub plan: ResponsePlan,
    pub execution_dispatch: Option<ResponseExecutionDispatchBinding>,
    pub dispatch_authorization_hash: Option<Digest32>,
    pub state: ResponseState,
    pub generation: u64,
    pub applying_lease_expires_at_unix_ms: Option<u64>,
    pub due_at_unix_ms: Option<u64>,
    pub operator_page_required: bool,
    pub mutations: ResponseMutationLog,
}

impl ResponseSnapshot {
    #[must_use]
    pub fn effect_progress(&self, effect_id: &EffectId) -> Option<ResponseEffectProgress> {
        self.plan.effect(effect_id)?;
        let mut progress = ResponseEffectProgress::Planned;
        for mutation in self.mutations.as_slice() {
            progress = match mutation {
                ResponseMutationRecord::EffectRequested(record)
                    if &record.effect_id == effect_id =>
                {
                    ResponseEffectProgress::Requested
                }
                ResponseMutationRecord::EffectApplied(record) if &record.effect_id == effect_id => {
                    ResponseEffectProgress::Applied
                }
                ResponseMutationRecord::EffectFailed(record) if &record.effect_id == effect_id => {
                    ResponseEffectProgress::ApplyFailed
                }
                ResponseMutationRecord::Rollback(record) if &record.effect_id == effect_id => {
                    match record.outcome {
                        ResponseRollbackOutcome::Requested => {
                            ResponseEffectProgress::RollbackRequested
                        }
                        ResponseRollbackOutcome::Restored { .. } => {
                            ResponseEffectProgress::Restored
                        }
                        ResponseRollbackOutcome::Failed { .. } => {
                            ResponseEffectProgress::RollbackFailed
                        }
                    }
                }
                _ => progress,
            };
        }
        Some(progress)
    }

    #[must_use]
    pub fn any_effect_applied(&self) -> bool {
        self.mutations
            .as_slice()
            .iter()
            .any(|mutation| matches!(mutation, ResponseMutationRecord::EffectApplied(_)))
    }

    #[must_use]
    pub fn terminal_failure_effects_are_exact(&self, error_code: &ErrorCode) -> bool {
        self.exact_terminal_failure_effect(error_code).is_some()
    }

    /// Validate the only truthful effect shapes for a terminal partial apply.
    #[must_use]
    pub fn terminal_apply_partial_effects_are_exact(&self, error_code: &ErrorCode) -> bool {
        let effect_states = self.completion_effect_states();
        if !response_completion_effect_shape_is_valid(
            ResponseState::ApplyPartial,
            Some(error_code),
            &effect_states,
        ) {
            return false;
        }
        let failed_progress_count = effect_states
            .iter()
            .filter(|effect| matches!(effect, ResponseCompletionEffectState::ApplyFailed(_)))
            .count();
        let mutations = self.mutations.as_slice();
        let failures = mutations
            .iter()
            .filter_map(|mutation| match mutation {
                ResponseMutationRecord::EffectFailed(failed) => Some(failed),
                _ => None,
            })
            .collect::<Vec<_>>();
        if failures.len() != failed_progress_count {
            return false;
        }
        let terminal_matches = |terminal: &ResponseFailureRecord| {
            self.state == ResponseState::ApplyPartial
                && terminal.to_state == ResponseState::ApplyPartial
                && terminal.generation == self.generation
                && terminal.error_code == *error_code
        };
        let Some(failed) = failures.first().copied() else {
            return match mutations.last() {
                Some(ResponseMutationRecord::Failed(terminal)) => terminal_matches(terminal),
                _ => true,
            };
        };
        if failed.error_code != *error_code
            || self.effect_progress(&failed.effect_id) != Some(ResponseEffectProgress::ApplyFailed)
        {
            return false;
        }
        let immediately_prior = match mutations.last() {
            Some(ResponseMutationRecord::Failed(terminal)) if terminal_matches(terminal) => {
                mutations
                    .len()
                    .checked_sub(2)
                    .and_then(|index| mutations.get(index))
            }
            Some(ResponseMutationRecord::EffectFailed(_))
                if self.state == ResponseState::Applying =>
            {
                mutations.last()
            }
            _ => return false,
        };
        matches!(
            immediately_prior,
            Some(ResponseMutationRecord::EffectFailed(prior)) if prior == failed
        )
    }

    /// Extract the exact terminal failure from a closed response snapshot.
    ///
    /// A pre-effect failure exposes only its terminal error. An authoritative
    /// apply rejection additionally exposes the effect ID, the durable effect
    /// CAS transition ID, and its positive generation. Any ambiguous history
    /// is rejected rather than reduced to a best-effort summary.
    #[must_use]
    pub fn terminal_failure_evidence(&self) -> Option<ResponseTerminalFailureEvidence> {
        let mutations = self.mutations.as_slice();
        let ResponseMutationRecord::Failed(failure) = mutations.last()? else {
            return None;
        };
        if self.state != ResponseState::Failed
            || failure.to_state != ResponseState::Failed
            || failure.generation != self.generation
        {
            return None;
        }
        let failed_effect = match self.exact_terminal_failure_effect(&failure.error_code)? {
            Some(failed) => {
                let transition_id = failed.effect_transition_id.clone()?;
                let generation = failed.effect_generation.checked_sub(1)?;
                if generation == 0 {
                    return None;
                }
                Some(ResponseFailedEffectEvidence {
                    effect_id: failed.effect_id.clone(),
                    transition_id,
                    generation,
                })
            }
            None => None,
        };
        Some(ResponseTerminalFailureEvidence {
            error_code: failure.error_code.clone(),
            failed_effect,
        })
    }

    fn exact_terminal_failure_effect(
        &self,
        error_code: &ErrorCode,
    ) -> Option<Option<&ResponseEffectFailedRecord>> {
        let effect_states = self.completion_effect_states();
        if !response_completion_effect_shape_is_valid(
            ResponseState::Failed,
            Some(error_code),
            &effect_states,
        ) {
            return None;
        }
        let all_planned = effect_states
            .iter()
            .all(|effect| *effect == ResponseCompletionEffectState::Planned);
        let mutations = self.mutations.as_slice();
        if all_planned {
            let terminal_matches = match mutations.last() {
                Some(ResponseMutationRecord::Failed(terminal)) => {
                    self.state == ResponseState::Failed
                        && terminal.to_state == ResponseState::Failed
                        && terminal.generation == self.generation
                        && terminal.error_code == *error_code
                }
                _ => true,
            };
            return (terminal_matches
                && !mutations
                    .iter()
                    .any(|mutation| matches!(mutation, ResponseMutationRecord::EffectFailed(_))))
            .then_some(None);
        }
        let failed_count = self
            .plan
            .effects
            .as_slice()
            .iter()
            .filter(|effect| {
                self.effect_progress(&effect.effect_id) == Some(ResponseEffectProgress::ApplyFailed)
            })
            .count();
        if failed_count != 1
            || self.plan.effects.as_slice().iter().any(|effect| {
                !matches!(
                    self.effect_progress(&effect.effect_id),
                    Some(ResponseEffectProgress::Planned | ResponseEffectProgress::ApplyFailed)
                )
            })
        {
            return None;
        }
        let mut failures = mutations.iter().filter_map(|mutation| match mutation {
            ResponseMutationRecord::EffectFailed(failed) => Some(failed),
            _ => None,
        });
        let failed = failures.next()?;
        if failures.next().is_some()
            || failed.error_code != *error_code
            || self.effect_progress(&failed.effect_id) != Some(ResponseEffectProgress::ApplyFailed)
        {
            return None;
        }
        let immediately_prior = match mutations.last() {
            Some(ResponseMutationRecord::Failed(terminal))
                if self.state == ResponseState::Failed
                    && terminal.to_state == ResponseState::Failed
                    && terminal.generation == self.generation
                    && terminal.error_code == *error_code =>
            {
                mutations
                    .len()
                    .checked_sub(2)
                    .and_then(|index| mutations.get(index))
            }
            Some(ResponseMutationRecord::EffectFailed(_))
                if self.state == ResponseState::Applying =>
            {
                mutations.last()
            }
            _ => return None,
        };
        matches!(
            immediately_prior,
            Some(ResponseMutationRecord::EffectFailed(prior)) if prior == failed
        )
        .then_some(Some(failed))
    }

    #[must_use]
    pub fn all_applied_reversible_effects_restored(&self) -> bool {
        self.plan.effects.as_slice().iter().all(|effect| {
            !effect.kind.is_reversible()
                || !self.effect_was_applied(&effect.effect_id)
                || self.effect_progress(&effect.effect_id) == Some(ResponseEffectProgress::Restored)
        })
    }

    #[must_use]
    pub fn has_rollback_failure(&self) -> bool {
        self.plan.effects.as_slice().iter().any(|effect| {
            self.effect_progress(&effect.effect_id) == Some(ResponseEffectProgress::RollbackFailed)
        })
    }

    fn effect_was_applied(&self, effect_id: &EffectId) -> bool {
        self.mutations.as_slice().iter().any(|mutation| {
            matches!(
                mutation,
                ResponseMutationRecord::EffectApplied(record) if &record.effect_id == effect_id
            )
        })
    }

    fn completion_effect_states(&self) -> Vec<ResponseCompletionEffectState> {
        self.plan
            .effects
            .as_slice()
            .iter()
            .map(|effect| match self.effect_progress(&effect.effect_id) {
                Some(ResponseEffectProgress::Planned) => ResponseCompletionEffectState::Planned,
                Some(ResponseEffectProgress::Requested) => ResponseCompletionEffectState::Requested,
                Some(ResponseEffectProgress::Applied) => ResponseCompletionEffectState::Applied,
                Some(ResponseEffectProgress::ApplyFailed) => self
                    .mutations
                    .as_slice()
                    .iter()
                    .rev()
                    .find_map(|mutation| match mutation {
                        ResponseMutationRecord::EffectFailed(failed)
                            if failed.effect_id == effect.effect_id =>
                        {
                            Some(ResponseCompletionEffectState::ApplyFailed(
                                failed.error_code.clone(),
                            ))
                        }
                        _ => None,
                    })
                    .unwrap_or(ResponseCompletionEffectState::Unresolved),
                Some(
                    ResponseEffectProgress::RollbackRequested
                    | ResponseEffectProgress::Restored
                    | ResponseEffectProgress::RollbackFailed,
                )
                | None => ResponseCompletionEffectState::Unresolved,
            })
            .collect()
    }
}

/// Compute the maximum number of response mutations that a valid execution
/// can still require after the current snapshot.
///
/// The bound is derived from durable effect progress instead of a fixed tail
/// allowance. It reserves every already-issued outcome, activation and expiry
/// transitions, and a conservative rollback path in which every reversible
/// effect fails its first removal attempt and succeeds on one complete retry
/// pass. All arithmetic is checked so a malformed snapshot cannot wrap the
/// admission calculation.
#[must_use]
pub fn response_required_mutation_suffix(snapshot: &ResponseSnapshot) -> Option<usize> {
    match snapshot.state {
        ResponseState::Planned => {
            let admission = match snapshot.plan.approval_requirement {
                ResponseApprovalRequirement::Automatic => 1_usize,
                ResponseApprovalRequirement::Governed { .. } => 2_usize,
            };
            admission.checked_add(fresh_applying_suffix(snapshot)?)
        }
        ResponseState::AwaitingApproval => 1_usize.checked_add(fresh_applying_suffix(snapshot)?),
        ResponseState::Applying => applying_suffix(snapshot),
        ResponseState::Active => {
            2_usize.checked_add(fresh_rollback_suffix(reversible_effect_count(snapshot)?)?)
        }
        ResponseState::ApplyPartial | ResponseState::Expiring => 1_usize.checked_add(
            fresh_rollback_suffix(applied_reversible_effect_count(snapshot)?)?,
        ),
        ResponseState::RollingBack => rolling_back_suffix(snapshot),
        ResponseState::RollbackPartial => rollback_partial_suffix(snapshot),
        ResponseState::Cancelled
        | ResponseState::Expired
        | ResponseState::Failed
        | ResponseState::Lifted => Some(0),
    }
}

/// Whether the current mutation log and its complete checked suffix fit in the
/// protocol bound. An effect request is admitted only when this remains true;
/// therefore the corresponding in-flight result can always be appended.
#[must_use]
pub fn response_snapshot_has_mutation_capacity(snapshot: &ResponseSnapshot) -> bool {
    response_required_mutation_suffix(snapshot).is_some_and(|suffix| {
        snapshot
            .mutations
            .len()
            .checked_add(suffix)
            .is_some_and(|required| required <= MAX_RESPONSE_MUTATIONS)
    })
}

fn fresh_applying_suffix(snapshot: &ResponseSnapshot) -> Option<usize> {
    let apply = snapshot.plan.effects.len().checked_mul(2)?;
    apply
        .checked_add(1)?
        .checked_add(2)?
        .checked_add(fresh_rollback_suffix(reversible_effect_count(snapshot)?)?)
}

fn applying_suffix(snapshot: &ResponseSnapshot) -> Option<usize> {
    let apply_failed = snapshot.plan.effects.as_slice().iter().any(|effect| {
        snapshot.effect_progress(&effect.effect_id) == Some(ResponseEffectProgress::ApplyFailed)
    });
    if apply_failed {
        let applied = snapshot.plan.effects.as_slice().iter().filter(|effect| {
            snapshot.effect_progress(&effect.effect_id) == Some(ResponseEffectProgress::Applied)
        });
        let any_applied = applied.clone().next().is_some();
        if !any_applied {
            return Some(1);
        }
        let reversible = applied.filter(|effect| effect.kind.is_reversible()).count();
        return 2_usize.checked_add(fresh_rollback_suffix(reversible)?);
    }

    let mut apply_mutations = 0_usize;
    let mut reversible_after_apply = 0_usize;
    for effect in snapshot.plan.effects.as_slice() {
        match snapshot.effect_progress(&effect.effect_id)? {
            ResponseEffectProgress::Planned => {
                apply_mutations = apply_mutations.checked_add(2)?;
                reversible_after_apply =
                    reversible_after_apply.checked_add(usize::from(effect.kind.is_reversible()))?;
            }
            ResponseEffectProgress::Requested => {
                apply_mutations = apply_mutations.checked_add(1)?;
                reversible_after_apply =
                    reversible_after_apply.checked_add(usize::from(effect.kind.is_reversible()))?;
            }
            ResponseEffectProgress::Applied => {
                reversible_after_apply =
                    reversible_after_apply.checked_add(usize::from(effect.kind.is_reversible()))?;
            }
            ResponseEffectProgress::ApplyFailed
            | ResponseEffectProgress::RollbackRequested
            | ResponseEffectProgress::Restored
            | ResponseEffectProgress::RollbackFailed => return None,
        }
    }
    apply_mutations
        .checked_add(1)?
        .checked_add(2)?
        .checked_add(fresh_rollback_suffix(reversible_after_apply)?)
}

fn fresh_rollback_suffix(reversible_effects: usize) -> Option<usize> {
    let effect_mutations = reversible_effects.checked_mul(4)?;
    let failure_retry_transitions = usize::from(reversible_effects > 0).checked_mul(2)?;
    effect_mutations
        .checked_add(failure_retry_transitions)?
        .checked_add(1)
}

fn rolling_back_suffix(snapshot: &ResponseSnapshot) -> Option<usize> {
    rollback_in_progress_suffix(snapshot, false)
}

fn rollback_partial_suffix(snapshot: &ResponseSnapshot) -> Option<usize> {
    1_usize.checked_add(rollback_in_progress_suffix(snapshot, true)?)
}

fn rollback_in_progress_suffix(
    snapshot: &ResponseSnapshot,
    retry_transition_already_reserved: bool,
) -> Option<usize> {
    let latest_retry_index = snapshot
        .mutations
        .as_slice()
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, mutation)| match mutation {
            ResponseMutationRecord::Transition(record)
                if record.from_state == ResponseState::RollbackPartial
                    && record.to_state == ResponseState::RollingBack =>
            {
                Some(index)
            }
            _ => None,
        });
    let latest_failure_index = snapshot
        .mutations
        .as_slice()
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, mutation)| match mutation {
            ResponseMutationRecord::Rollback(ResponseRollbackRecord {
                outcome: ResponseRollbackOutcome::Failed { .. },
                ..
            }) => Some(index),
            _ => None,
        });
    let mut effect_mutations = 0_usize;
    let mut first_failure_cycle_needed = latest_failure_index
        .is_some_and(|failure| latest_retry_index.is_none_or(|retry| failure > retry))
        && !retry_transition_already_reserved;

    for effect in snapshot
        .plan
        .effects
        .as_slice()
        .iter()
        .filter(|effect| effect.kind.is_reversible())
    {
        let failures = snapshot
            .mutations
            .as_slice()
            .iter()
            .filter(|mutation| {
                matches!(
                    mutation,
                    ResponseMutationRecord::Rollback(ResponseRollbackRecord {
                        effect_id,
                        outcome: ResponseRollbackOutcome::Failed { .. },
                        ..
                    }) if effect_id == &effect.effect_id
                )
            })
            .count();
        let remaining = match snapshot.effect_progress(&effect.effect_id)? {
            ResponseEffectProgress::Applied if failures == 0 => {
                first_failure_cycle_needed = true;
                4
            }
            ResponseEffectProgress::Applied => 2,
            ResponseEffectProgress::RollbackRequested if failures == 0 => {
                first_failure_cycle_needed = true;
                3
            }
            ResponseEffectProgress::RollbackRequested => 1,
            ResponseEffectProgress::RollbackFailed => 2,
            ResponseEffectProgress::Restored
            | ResponseEffectProgress::Planned
            | ResponseEffectProgress::Requested
            | ResponseEffectProgress::ApplyFailed => 0,
        };
        effect_mutations = effect_mutations.checked_add(remaining)?;
    }

    let extra_failure_cycle = usize::from(first_failure_cycle_needed).checked_mul(2)?;
    effect_mutations
        .checked_add(extra_failure_cycle)?
        .checked_add(1)
}

fn reversible_effect_count(snapshot: &ResponseSnapshot) -> Option<usize> {
    snapshot
        .plan
        .effects
        .as_slice()
        .iter()
        .try_fold(0_usize, |count, effect| {
            count.checked_add(usize::from(effect.kind.is_reversible()))
        })
}

fn applied_reversible_effect_count(snapshot: &ResponseSnapshot) -> Option<usize> {
    snapshot
        .plan
        .effects
        .as_slice()
        .iter()
        .try_fold(0_usize, |count, effect| {
            let applied = effect.kind.is_reversible()
                && snapshot.effect_progress(&effect.effect_id)
                    == Some(ResponseEffectProgress::Applied);
            count.checked_add(usize::from(applied))
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseShapeError {
    InvalidAffectedSetHash,
    CapabilityExpiresBeforePlan,
    CrossTenantTarget,
    DuplicateEffectId,
    EmptyEffects,
    InvalidEffectOrdinal,
    InvalidEffectTarget,
    InvalidFindingHash,
    InvalidContributionHash,
    InvalidObservedBaseVersionHash,
    InvalidOperatorCapabilityHash,
    InvalidPlanHash,
    InvalidPolicyHash,
    InvalidReasonHash,
    InvalidTargetAffectedSetHash,
    InvalidTimeRange,
    MissingIssuanceFence,
}

impl fmt::Display for ResponseShapeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidAffectedSetHash => "response plan affected-set hash is zero",
            Self::CapabilityExpiresBeforePlan => "operator capability expires before the plan",
            Self::CrossTenantTarget => "response target crosses the plan tenant",
            Self::DuplicateEffectId => "response plan contains a duplicate effect id",
            Self::EmptyEffects => "response plan contains no effects",
            Self::InvalidEffectOrdinal => "response effect ordinal is not canonical",
            Self::InvalidEffectTarget => "response effect target does not match its operation",
            Self::InvalidFindingHash => "response plan finding hash is zero",
            Self::InvalidContributionHash => "response effect contribution hash is zero",
            Self::InvalidObservedBaseVersionHash => {
                "response effect observed base version hash is zero"
            }
            Self::InvalidOperatorCapabilityHash => "response plan operator capability hash is zero",
            Self::InvalidPlanHash => "response plan hash is zero",
            Self::InvalidPolicyHash => "response plan policy hash is zero",
            Self::InvalidReasonHash => "response plan reason hash is zero",
            Self::InvalidTargetAffectedSetHash => "response capability-set target hash is zero",
            Self::InvalidTimeRange => "response plan time range is invalid",
            Self::MissingIssuanceFence => "lineage response does not begin with an issuance fence",
        };
        formatter.write_str(message)
    }
}

impl core::error::Error for ResponseShapeError {}

fn digest_is_zero(digest: &Digest32) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

fn record_id_is_zero_sentinel(record_id: &RecordId) -> bool {
    let value = record_id.as_str();
    value.char_indices().any(|(index, character)| {
        if character != '0'
            || (index > 0 && !matches!(value.as_bytes()[index - 1], b'_' | b'-' | b':'))
        {
            return false;
        }
        let candidate = &value[index..];
        candidate.bytes().filter(|byte| *byte == b'0').count() >= 32
            && candidate
                .bytes()
                .all(|byte| matches!(byte, b'0' | b'_' | b'-' | b':'))
    })
}
