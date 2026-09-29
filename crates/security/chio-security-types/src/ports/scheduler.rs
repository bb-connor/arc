#[cfg(feature = "std")]
use super::ResponseStore;
use super::{
    ActionId, AlertDeliveryQuery, AlertDeliveryStatus, Deserialize, ErrorCode, LeaseOwnerId,
    PortError, PortResult, RecordId, ResponsePlanRecord, ResponseScheduledMutationCasRequest,
    SecurityAlert, Serialize, TenantId,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerClaimRequest {
    pub tenant_id: TenantId,
    pub claim_id: RecordId,
    pub lease_owner_id: LeaseOwnerId,
    pub now_unix_ms: u64,
    pub lease_expires_at_unix_ms: u64,
    pub max_claims: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledWork {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub lease_owner_id: LeaseOwnerId,
    pub lease_expires_at_unix_ms: u64,
    pub fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerWorkKey {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerRetryState {
    pub key: SchedulerWorkKey,
    pub attempts: u32,
    pub last_error: ErrorCode,
    pub first_failure_at_unix_ms: u64,
    pub not_before_unix_ms: u64,
    pub health_event_id: Option<RecordId>,
    pub health_event_delivered: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerLeaseRenewRequest {
    pub work: ScheduledWork,
    pub now_unix_ms: u64,
    pub lease_expires_at_unix_ms: u64,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerRetryRequest {
    pub work: ScheduledWork,
    pub expected_attempts: u32,
    pub error_code: ErrorCode,
    pub first_failure_at_unix_ms: u64,
    pub now_unix_ms: u64,
    pub not_before_unix_ms: u64,
    pub health_event_id: Option<RecordId>,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerHealthAckRequest {
    pub key: SchedulerWorkKey,
    pub event_id: RecordId,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerLeaseReleaseRequest {
    pub work: ScheduledWork,
    pub clear_retry_state: bool,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerHealthPageRequest {
    pub event_id: RecordId,
    pub idempotency_key: RecordId,
    pub occurred_at_unix_ms: u64,
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub first_failure_at_unix_ms: u64,
    pub attempts: u32,
    pub scheduler_fencing_token: u64,
    pub error_code: ErrorCode,
    pub alert: SecurityAlert,
}

#[cfg(feature = "std")]
pub trait ResponseSchedulerStore: ResponseStore {
    fn load_retry(&self, key: &SchedulerWorkKey) -> PortResult<Option<SchedulerRetryState>>;
    fn validate_lease(&self, work: &ScheduledWork) -> PortResult<()>;
    /// Compare the exact live scheduler lease and exact current response, then
    /// commit one fully validated appended mutation in the same transaction.
    fn compare_and_swap_scheduled_mutation(
        &self,
        request: &ResponseScheduledMutationCasRequest,
    ) -> PortResult<ResponsePlanRecord>;
    fn validate_lease_identity(
        &self,
        _tenant_id: &TenantId,
        _action_id: &ActionId,
        _lease_owner_id: &LeaseOwnerId,
        _fencing_token: u64,
    ) -> PortResult<()> {
        Err(PortError::unavailable())
    }
    fn renew_lease(&self, request: &SchedulerLeaseRenewRequest) -> PortResult<ScheduledWork>;
    fn record_retry(&self, request: &SchedulerRetryRequest) -> PortResult<SchedulerRetryState>;
    fn acknowledge_health_event(
        &self,
        request: &SchedulerHealthAckRequest,
    ) -> PortResult<SchedulerRetryState>;
    fn release_lease(&self, request: &SchedulerLeaseReleaseRequest) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait SchedulerHealthPort: Send + Sync {
    fn ensure_scheduler_health_ready(&self) -> PortResult<()>;
    fn page_once(&self, request: &SchedulerHealthPageRequest) -> PortResult<AlertDeliveryStatus>;
    fn load_delivery(&self, query: &AlertDeliveryQuery) -> PortResult<Option<AlertDeliveryStatus>>;
}
