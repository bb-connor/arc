#[cfg(feature = "std")]
use super::ResponseSchedulerStore;
use super::{
    ActionId, Box, CanonicalBody, Deserialize, Digest32, LeaseOwnerId, PortError, PortResult,
    PreparedActiveResponseDispatchBinding, RecordId, ResponsePlanRecord, ScheduledWork,
    SchedulerWorkKey, Serialize, TenantId,
};

pub const RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchKey {
    pub tenant_id: TenantId,
    pub dispatch_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "approval_mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseDispatchApproval {
    Automatic,
    Governed {
        admission_operation_id: RecordId,
        admission_operation_version: u64,
        approval_set_hash: Digest32,
    },
}

/// Canonical immutable authorization for one deterministic response dispatch.
///
/// `response_body_hash` binds the complete `Applying` response record. The
/// governed intent is present for both approval modes because automatic
/// response still executes the exact protocol-owned response intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchAuthorizationBody {
    pub schema_version: u8,
    pub key: ResponseDispatchKey,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub response_body_hash: Digest32,
    pub authorization_capability_hash: Digest32,
    pub governed_intent_hash: Digest32,
    pub policy_decision_hash: Digest32,
    pub executor_authority_id: RecordId,
    pub executor_authority_generation: u64,
    pub approval: ResponseDispatchApproval,
    pub authorized_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchAuthorization {
    pub body: ResponseDispatchAuthorizationBody,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchLease {
    pub lease_owner_id: LeaseOwnerId,
    pub lease_expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchRecoveryRequest {
    pub key: ResponseDispatchKey,
    pub action_id: ActionId,
    pub recovery_id: RecordId,
    pub lease_owner_id: LeaseOwnerId,
    /// Exact fencing token observed before the atomic recovery attempt.
    /// Stores reject `None` so an unfenced legacy request fails closed.
    pub expected_fencing_token: Option<u64>,
    pub now_unix_ms: u64,
    pub lease_expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "work")]
pub enum ResponseDispatchRecoveryOutcome {
    LiveLease(ScheduledWork),
    Takeover(ScheduledWork),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchCommitRequest {
    pub mode: ResponseDispatchCommitMode,
    pub authorization: ResponseDispatchAuthorization,
    pub response_plan: ResponsePlanRecord,
    pub initial_lease: ResponseDispatchLease,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseDispatchCommitMode {
    Fresh,
    GovernedCommittedResume,
    GovernedCommittedExpiredResume,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchRecord {
    pub authorization: ResponseDispatchAuthorization,
    pub response_plan: ResponsePlanRecord,
    pub initial_work: ScheduledWork,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "record")]
pub enum ResponseDispatchCommitOutcome {
    Committed(ResponseDispatchRecord),
    Existing(ResponseDispatchRecord),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "record")]
pub enum ResponseDispatchLoadOutcome {
    Found(Box<ResponseDispatchRecord>),
    Missing,
}

/// Exact automatic dispatch identity durably closed before executor commit.
///
/// The complete prepared binding is retained so a retry can distinguish the
/// same termination from a conflicting dispatch identity. The response plan is
/// supplied for validation only and is not part of the mutable store state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticResponseDispatchFenceRequest {
    pub response_plan: crate::ResponsePlan,
    pub prepared_dispatch_binding: PreparedActiveResponseDispatchBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticResponseDispatchFenceRecord {
    pub prepared_dispatch_binding: PreparedActiveResponseDispatchBinding,
    pub binding_hash: Digest32,
    pub fenced_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "record")]
pub enum AutomaticResponseDispatchFenceOutcome {
    Fenced(AutomaticResponseDispatchFenceRecord),
    ExistingFence(AutomaticResponseDispatchFenceRecord),
    Committed(Box<ResponseDispatchRecord>),
}

/// Atomically admits an already-authorized response into durable execution.
///
/// A successful commit persists the immutable authorization, the response in
/// `Applying`, and its first scheduler lease in one commit domain. Implementors
/// must treat the dispatch key as an idempotency key and reject every binding
/// mismatch on retry or load.
#[cfg(feature = "std")]
pub trait ResponseDispatchStore: ResponseSchedulerStore {
    fn ensure_dispatch_ready(&self) -> PortResult<()>;

    /// Load the exact scheduler lease currently guarding a committed dispatch.
    /// Recovery callers use this as an optimistic fencing snapshot; the
    /// subsequent recovery mutation must compare the token atomically.
    fn load_dispatch_work(&self, _key: &SchedulerWorkKey) -> PortResult<Option<ScheduledWork>> {
        Err(PortError::unavailable())
    }

    /// Atomically close one exact automatic dispatch while it is still absent.
    ///
    /// Implementations must serialize this mutation with `commit_dispatch` in
    /// the same durable authority. A successful fence prevents every later
    /// dispatch for both the retained dispatch ID and its tenant-scoped action.
    fn fence_uncommitted_automatic_dispatch(
        &self,
        _request: &AutomaticResponseDispatchFenceRequest,
    ) -> PortResult<AutomaticResponseDispatchFenceOutcome> {
        Err(PortError::unavailable())
    }

    fn commit_dispatch(
        &self,
        request: &ResponseDispatchCommitRequest,
    ) -> PortResult<ResponseDispatchCommitOutcome>;

    fn load_dispatch(&self, key: &ResponseDispatchKey) -> PortResult<ResponseDispatchLoadOutcome>;

    /// Recover only against the exact nonzero fencing token observed by the
    /// caller. Implementations must reject missing or stale tokens and must
    /// never return a live lease owned by a different worker.
    fn recover_dispatch_work(
        &self,
        request: &ResponseDispatchRecoveryRequest,
    ) -> PortResult<ResponseDispatchRecoveryOutcome>;
}
