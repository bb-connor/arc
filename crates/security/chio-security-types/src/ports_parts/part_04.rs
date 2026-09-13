pub const ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION: u8 = 1;
pub const PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION: u8 = 1;
pub const MAX_ATTESTED_FINDING_RESPONSE_OUTBOX_SCAN: u32 = 4_096;
pub const ATTESTED_FINDING_RESPONSE_INITIAL_RETRY_MS: u64 = 1_000;
pub const ATTESTED_FINDING_RESPONSE_MAX_RETRY_MS: u64 = 3_600_000;
pub const ATTESTED_FINDING_RESPONSE_MAX_ATTEMPTS: u64 = 1_000_000;

/// Exact durable recovery descriptor for one kernel-prepared active response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedActiveResponseDispatchBinding {
    pub schema_version: u8,
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub dispatch_id: RecordId,
    pub executor_authority_id: RecordId,
    pub executor_authority_generation: u64,
    pub authorized_at_unix_ms: u64,
    pub authorization_capability_hash: Digest32,
    pub governed_intent_hash: Digest32,
    pub policy_decision_hash: Digest32,
    pub approval: ResponseDispatchApproval,
}

impl PreparedActiveResponseDispatchBinding {
    pub fn validate_for_plan(
        &self,
        plan: &crate::ResponsePlan,
    ) -> Result<(), PreparedActiveResponseDispatchBindingError> {
        if self.schema_version != PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION
            || plan.validate_shape().is_err()
            || self.tenant_id != plan.tenant_id
            || self.action_id != plan.action_id
            || self.plan_hash != plan.plan_hash
            || self.authorization_capability_hash
                != plan.operator_capability.capability_digest
            || validate_nonzero_id(self.tenant_id.as_str()).is_err()
            || validate_nonzero_id(self.action_id.as_str()).is_err()
            || validate_nonzero_id(self.dispatch_id.as_str()).is_err()
            || validate_nonzero_id(self.executor_authority_id.as_str()).is_err()
            || self.executor_authority_generation == 0
            || self.authorized_at_unix_ms == 0
            || self.authorized_at_unix_ms < plan.created_at_unix_ms
            || self.authorized_at_unix_ms >= plan.expires_at_unix_ms
            || self.plan_hash.is_zero()
            || self.authorization_capability_hash.is_zero()
            || self.governed_intent_hash.is_zero()
            || self.policy_decision_hash.is_zero()
        {
            return Err(PreparedActiveResponseDispatchBindingError);
        }
        match (&plan.approval_requirement, &self.approval) {
            (
                crate::ResponseApprovalRequirement::Automatic,
                ResponseDispatchApproval::Automatic,
            ) => Ok(()),
            (
                crate::ResponseApprovalRequirement::Governed { .. },
                ResponseDispatchApproval::Governed {
                    admission_operation_id,
                    admission_operation_version,
                    approval_set_hash,
                },
            ) if validate_nonzero_id(admission_operation_id.as_str()).is_ok()
                && *admission_operation_version != 0
                && !approval_set_hash.is_zero() =>
            {
                Ok(())
            }
            _ => Err(PreparedActiveResponseDispatchBindingError),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedActiveResponseDispatchBindingError;

impl fmt::Display for PreparedActiveResponseDispatchBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("prepared active-response dispatch binding is invalid")
    }
}

impl core::error::Error for PreparedActiveResponseDispatchBindingError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestedFindingResponsePlanningState {
    Pending,
    Planned,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestedFindingResponseAdmissionState {
    Pending,
    Prepared,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestedFindingResponseCompletionState {
    NotStarted,
    Pending,
    OutcomeUnknownAfterDispatch,
    Completed,
}

/// Closed, signed outcome of one admitted active-response dispatch.
///
/// A rollback that is incomplete is not a member of this enum. Its outcome is
/// still unknown and recovery must retain the restrictive retry state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestedFindingResponseCompletionOutcome {
    Activated,
    FailedBeforeEffect,
    RolledBackAfterPartial,
}

/// Immutable, canonical recovery input for one policy-planned active response.
///
/// The policy-issued artifact reference is opaque. Recovery must resolve it
/// through the same authenticated policy authority and the returned artifacts
/// must still pass complete kernel verification against `response_plan`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedFindingResponsePlanBody {
    pub schema_version: u8,
    pub batch_id: RecordId,
    pub ordinal: u32,
    pub binding: AttestedFindingBatchBinding,
    pub response_plan: crate::ResponsePlan,
    pub admission_artifact_ref: AdmissionArtifactRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedFindingResponsePlanPublication {
    pub body: AttestedFindingResponsePlanBody,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedFindingResponseOutboxKey {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
}

/// Durable response-planning outbox state.
///
/// A prepared admission always records the one kernel-derived execution
/// dispatch identity. Completion can advance only after execution evidence
/// returns the exact same identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedFindingResponseOutboxRecord {
    pub batch_id: RecordId,
    pub ordinal: u32,
    pub binding: AttestedFindingBatchBinding,
    pub publication: Option<AttestedFindingResponsePlanPublication>,
    pub planning_state: AttestedFindingResponsePlanningState,
    pub admission_state: AttestedFindingResponseAdmissionState,
    pub completion_state: AttestedFindingResponseCompletionState,
    pub execution_dispatch_id: Option<RecordId>,
    pub prepared_dispatch_binding: Option<PreparedActiveResponseDispatchBinding>,
    pub admission_artifact_digest: Option<Digest32>,
    pub completion_outcome: Option<AttestedFindingResponseCompletionOutcome>,
    pub completion_evidence_id: Option<OpaqueReceiptRef>,
    pub completion_evidence_body_hash: Option<Digest32>,
    pub attempts: u64,
    pub next_attempt_at_unix_ms: u64,
    pub last_error_code: Option<ErrorCode>,
}

impl AttestedFindingResponseOutboxRecord {
    #[must_use]
    pub fn key(&self) -> AttestedFindingResponseOutboxKey {
        AttestedFindingResponseOutboxKey {
            tenant_id: self.binding.tenant_id.clone(),
            action_id: self.binding.action_id.clone(),
        }
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.planning_state, AttestedFindingResponsePlanningState::Failed)
            || matches!(
                self.admission_state,
                AttestedFindingResponseAdmissionState::Rejected
                    | AttestedFindingResponseAdmissionState::Expired
            )
            || matches!(
                self.completion_state,
                AttestedFindingResponseCompletionState::Completed
            )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttestedFindingResponseOutboxTransition {
    BeginAttempt { next_attempt_at_unix_ms: u64 },
    RetryableFailure {
        next_attempt_at_unix_ms: u64,
        error_code: ErrorCode,
        outcome_unknown_after_dispatch: bool,
    },
    PlanningFailed { error_code: ErrorCode },
    AdmissionRejected { error_code: ErrorCode },
    ExpiredBeforeAdmission,
    ExpiredAfterPreparedNeverCommitted,
    AdmissionArtifactsBound { artifact_digest: Digest32 },
    AdmissionPrepared {
        prepared_dispatch_binding: Box<PreparedActiveResponseDispatchBinding>,
    },
    Completed {
        execution_dispatch_id: RecordId,
        outcome: AttestedFindingResponseCompletionOutcome,
        evidence_id: OpaqueReceiptRef,
        evidence_body_hash: Digest32,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AttestedFindingResponseOutboxHealth {
    pub planning_pending: u64,
    pub admission_pending: u64,
    pub artifact_binding_pending: u64,
    pub completion_pending: u64,
    pub outcome_unknown_after_dispatch: u64,
    pub terminal_failed: u64,
    pub terminal_expired: u64,
    pub terminal_activated: u64,
    pub terminal_failed_before_effect: u64,
    pub terminal_rolled_back_after_partial: u64,
}

/// Crash-recovery ledger between durable finding publication and the kernel's
/// idempotent active-response coordinator.
#[cfg(feature = "std")]
pub trait AttestedFindingResponseOutboxStore: Send + Sync {
    fn ensure_attested_finding_response_outbox_ready(&self) -> PortResult<()>;

    fn publish_attested_finding_response_plan(
        &self,
        publication: &AttestedFindingResponsePlanPublication,
    ) -> PortResult<CreateOutcome>;

    fn load_attested_finding_response_outbox(
        &self,
        key: &AttestedFindingResponseOutboxKey,
    ) -> PortResult<Option<AttestedFindingResponseOutboxRecord>>;

    fn scan_unplanned_attested_finding_responses(
        &self,
        now_unix_ms: u64,
        max_records: u32,
    ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>>;

    fn scan_incomplete_attested_finding_responses(
        &self,
        now_unix_ms: u64,
        max_records: u32,
    ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>>;

    fn transition_attested_finding_response_outbox(
        &self,
        current: &AttestedFindingResponseOutboxRecord,
        transition: AttestedFindingResponseOutboxTransition,
    ) -> PortResult<AttestedFindingResponseOutboxRecord>;

    fn attested_finding_response_outbox_health(
        &self,
    ) -> PortResult<AttestedFindingResponseOutboxHealth>;
}
