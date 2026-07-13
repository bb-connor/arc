use crate::ports::{
    ActionId, BoundedVec, CanonicalBody, Digest32, EffectId, ErrorCode, LineageId, RecordId,
    RecordIdSet, SessionId, TenantId,
};
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

pub const RESPONSE_STATE_SCHEMA_VERSION: u8 = 1;
pub const MAX_RESPONSE_EFFECTS: usize = 64;
pub const MAX_RESPONSE_MUTATIONS: usize = 1_024;

pub type PlannedResponseEffects = BoundedVec<PlannedResponseEffect, MAX_RESPONSE_EFFECTS>;
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
    pub tenant_id: TenantId,
    pub policy_version: RecordId,
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
    pub tenant_id: TenantId,
    pub policy_version: RecordId,
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

/// Complete canonical response-plan commitment used by authorization.
///
/// The resulting body deliberately excludes `plan_hash` so the hash cannot
/// become part of its own preimage. Every field that can change execution,
/// rollback, approval, or attribution remains present.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlanAuthorizationBody {
    pub action_id: ActionId,
    pub trigger_finding_id: RecordId,
    pub tenant_id: TenantId,
    pub policy_version: RecordId,
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
}

impl ResponsePlan {
    #[must_use]
    pub fn authorization_body(&self) -> ResponsePlanAuthorizationBody {
        ResponsePlanAuthorizationBody {
            action_id: self.action_id.clone(),
            trigger_finding_id: self.trigger_finding_id.clone(),
            tenant_id: self.tenant_id.clone(),
            policy_version: self.policy_version.clone(),
            affected_ids: self.affected_ids.clone(),
            affected_set_hash: self.affected_set_hash,
            effects: self.effects.clone(),
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
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectRequestedRecord {
    pub transition_id: RecordId,
    pub generation: u64,
    pub effect_id: EffectId,
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectAppliedRecord {
    pub transition_id: RecordId,
    pub generation: u64,
    pub effect_id: EffectId,
    pub resulting_version_hash: Digest32,
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectFailedRecord {
    pub transition_id: RecordId,
    pub generation: u64,
    pub effect_id: EffectId,
    pub error_code: ErrorCode,
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
    pub outcome: ResponseRollbackOutcome,
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
    pub occurred_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseFinalRecord {
    pub transition_id: RecordId,
    pub generation: u64,
    pub from_state: ResponseState,
    pub final_state: ResponseState,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSnapshot {
    pub schema_version: u8,
    pub plan: ResponsePlan,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseShapeError {
    CapabilityExpiresBeforePlan,
    CrossTenantTarget,
    DuplicateEffectId,
    EmptyEffects,
    InvalidEffectOrdinal,
    InvalidEffectTarget,
    InvalidTimeRange,
    MissingIssuanceFence,
}

impl fmt::Display for ResponseShapeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::CapabilityExpiresBeforePlan => "operator capability expires before the plan",
            Self::CrossTenantTarget => "response target crosses the plan tenant",
            Self::DuplicateEffectId => "response plan contains a duplicate effect id",
            Self::EmptyEffects => "response plan contains no effects",
            Self::InvalidEffectOrdinal => "response effect ordinal is not canonical",
            Self::InvalidEffectTarget => "response effect target does not match its operation",
            Self::InvalidTimeRange => "response plan time range is invalid",
            Self::MissingIssuanceFence => "lineage response does not begin with an issuance fence",
        };
        formatter.write_str(message)
    }
}

impl core::error::Error for ResponseShapeError {}
