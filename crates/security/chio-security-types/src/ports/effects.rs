use super::ResponseEffectKind;
use super::ResponseTarget;
use super::Deserialize;
use super::Serialize;
use super::Digest32;
use super::CanonicalBody;
use super::TenantId;
use super::RecordId;
use super::ActionId;
use super::EffectId;
use super::LeaseOwnerId;
use super::ErrorCode;
use super::PortError;
use super::PortResult;
use super::LineageFenceMaintenanceRequest;
use super::LineageFenceMaintenanceOutcome;


#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOperation {
    Apply,
    Remove,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRequest {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub effect_id: EffectId,
    pub effect_kind: ResponseEffectKind,
    pub target: ResponseTarget,
    pub plan_expires_at_unix_ms: u64,
    pub operation: EffectOperation,
    pub idempotency_key: RecordId,
    pub expected_version_hash: Digest32,
    pub scheduler_lease_owner_id: LeaseOwnerId,
    pub scheduler_fencing_token: u64,
    pub canonical_contribution: CanonicalBody,
    pub contribution_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectResult {
    pub effect_id: EffectId,
    pub resulting_version_hash: Digest32,
    pub applied: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectResultQuery {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub effect_id: EffectId,
    pub effect_kind: ResponseEffectKind,
    pub target: ResponseTarget,
    pub plan_expires_at_unix_ms: u64,
    pub operation: EffectOperation,
    pub idempotency_key: RecordId,
    pub expected_version_hash: Digest32,
    pub contribution_hash: Digest32,
    pub scheduler_lease_owner_id: LeaseOwnerId,
    pub scheduler_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", deny_unknown_fields)]
pub enum EffectExecutionStatus {
    NotExecuted,
    Completed { result: EffectResult },
    Failed { error_code: ErrorCode },
    Unknown,
}

#[cfg(feature = "std")]
pub trait EffectPort: Send + Sync {
    fn ensure_effects_ready(&self) -> PortResult<()>;
    fn execute(&self, request: &EffectRequest) -> PortResult<EffectResult>;
    fn load_result(&self, query: &EffectResultQuery) -> PortResult<EffectExecutionStatus>;
    fn maintain_lineage_fences(
        &self,
        _request: &LineageFenceMaintenanceRequest,
    ) -> PortResult<LineageFenceMaintenanceOutcome> {
        Err(PortError::unavailable())
    }
}
