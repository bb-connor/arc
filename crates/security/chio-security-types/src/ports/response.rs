use super::{
    ActionId, CanonicalBody, CreateOutcome, Deserialize, Digest32, EffectId, LeaseOwnerId,
    OpaqueReceiptRef, PortError, PortResult, RecordId, ScheduledWork, SchedulerClaimRequest,
    Serialize, TenantId, Vec,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlanRecord {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub generation: u64,
    pub state: RecordId,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
    pub due_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlanKey {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
}

/// Durable cursor for the last response evidence receipt whose authoritative
/// store append has been verified.
///
/// Business-state and effect CAS records commit the next receipt's exact body
/// inputs and predecessor before append. Only this separate cursor advances
/// after append succeeds or an append-ack-loss retry reloads and verifies the
/// exact signed receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseReceiptCursor {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub generation: u64,
    pub current_evidence_id: OpaqueReceiptRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseReceiptCursorCasRequest {
    pub cursor: ResponseReceiptCursor,
    pub expected_generation: u64,
    pub expected_evidence_id: OpaqueReceiptRef,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseCasRequest {
    pub record: ResponsePlanRecord,
    pub expected_generation: u64,
    pub transition_id: RecordId,
}

/// Atomically commits one scheduler-owned response mutation under one exact
/// live scheduler lease.
///
/// The store compares the complete `current` record, validates the complete
/// `candidate` lifecycle, and requires the candidate to append exactly one
/// mutation whose identifier is `transition_id`. Every field of `work`, both
/// canonical bodies, both body hashes, and both generations are part of the
/// idempotency binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseScheduledMutationCasRequest {
    pub work: ScheduledWork,
    pub current: ResponsePlanRecord,
    pub candidate: ResponsePlanRecord,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectRecord {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub generation: u64,
    pub scheduler_lease_owner_id: LeaseOwnerId,
    pub scheduler_fencing_token: u64,
    pub state: RecordId,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
    pub encrypted_rollback_ref: Option<RecordId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectKey {
    pub tenant_id: TenantId,
    pub effect_id: EffectId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectCasRequest {
    pub record: ResponseEffectRecord,
    pub expected_generation: u64,
    pub transition_id: RecordId,
}

#[cfg(feature = "std")]
pub trait ResponseStore: Send + Sync {
    fn load_plan(&self, key: &ResponsePlanKey) -> PortResult<Option<ResponsePlanRecord>>;
    fn create(&self, record: &ResponsePlanRecord) -> PortResult<CreateOutcome>;
    fn compare_and_swap(&self, request: &ResponseCasRequest) -> PortResult<ResponsePlanRecord>;
    fn load_effect(&self, key: &ResponseEffectKey) -> PortResult<Option<ResponseEffectRecord>>;
    fn persist_effect(&self, record: &ResponseEffectRecord) -> PortResult<CreateOutcome>;
    fn compare_and_swap_effect(
        &self,
        request: &ResponseEffectCasRequest,
    ) -> PortResult<ResponseEffectRecord>;
    fn load_receipt_cursor(
        &self,
        _key: &ResponsePlanKey,
    ) -> PortResult<Option<ResponseReceiptCursor>> {
        Err(PortError::unavailable())
    }
    fn initialize_receipt_cursor(
        &self,
        _cursor: &ResponseReceiptCursor,
    ) -> PortResult<CreateOutcome> {
        Err(PortError::unavailable())
    }
    fn compare_and_swap_receipt_cursor(
        &self,
        _request: &ResponseReceiptCursorCasRequest,
    ) -> PortResult<ResponseReceiptCursor> {
        Err(PortError::unavailable())
    }
    fn claim_due(&self, request: &SchedulerClaimRequest) -> PortResult<Vec<ScheduledWork>>;
}
