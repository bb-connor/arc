//! Security admission operations: the durable record of one tool dispatch or
//! governed active response, its cleanup actions, the store port and the
//! in-memory store.

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::sha256_hex;
pub use chio_core_types::StoreMutationFence;
use serde::{Deserialize, Serialize};

mod error;
pub use error::AdmissionOperationError;
mod request_binding;
pub use request_binding::{AdmissionRequestBindingInput, AdmissionRequestBindingParts};

mod ids;
mod in_memory;
mod recovery_pages;
mod store;
mod validation;
pub use ids::{derive_cleanup_action_id, derive_operation_id};
pub use in_memory::InMemoryAdmissionOperationStore;
pub use store::{AdmissionOperationStore, AdmissionOperationStoreProfile};
use validation::{
    valid_state_transition, validate_cleanup_claim, validate_cleanup_payload, validate_digest,
    validate_identifier, validate_kind_participants, validate_last_error, validate_optional_digest,
    validate_optional_identifier, validate_state_dispatch_pair,
};

pub const ADMISSION_OPERATION_SCHEMA: &str = "chio.security-admission-operation.v1";
const ADMISSION_OPERATION_DOMAIN: &[u8] = b"chio.security-admission-operation.v1\0";
const ADMISSION_REQUEST_BINDING_DOMAIN: &[u8] = b"chio.security-admission-request-binding.v1\0";
const ADMISSION_CLEANUP_ACTION_DOMAIN: &[u8] = b"chio.security-admission-cleanup-action.v1\0";
const MAX_ADMISSION_IDENTIFIER_BYTES: usize = 512;
const MAX_ADMISSION_ERROR_BYTES: usize = 4_096;
// A complete cleanup snapshot can contain every verified quota and the full
// bounded revocation set. Keep the journal bound finite, but large enough for
// the maximum protocol-valid authority input.
pub(crate) const MAX_ADMISSION_CLEANUP_PAYLOAD_BYTES: usize = 256 * 1_024;
pub const MAX_APPROVAL_TOKEN_DIGESTS_PER_OPERATION: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayReservationState {
    Reserved,
    Committed,
    Cancelled,
}

impl ReplayReservationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Committed => "committed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "reserved" => Some(Self::Reserved),
            "committed" => Some(Self::Committed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionOperationKind {
    ToolDispatch,
    GovernedActiveResponse,
}

impl AdmissionOperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolDispatch => "tool_dispatch",
            Self::GovernedActiveResponse => "governed_active_response",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "tool_dispatch" => Some(Self::ToolDispatch),
            "governed_active_response" => Some(Self::GovernedActiveResponse),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionOperationState {
    Prepared,
    BrokerAttemptRegistered,
    BudgetAuthorized,
    DelegatedBudgetReserved,
    PaymentAuthorized,
    ApprovalReserved,
    ReadyToDispatch,
    CapturePending,
    CallerReservationCapturePending,
    CompensationPending,
    DispatchCommitted,
    CallerReserved,
    Completed,
    CompensatedBeforeDispatch,
    OutcomeUnknownAfterDispatch,
}

impl AdmissionOperationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::BrokerAttemptRegistered => "broker_attempt_registered",
            Self::BudgetAuthorized => "budget_authorized",
            Self::DelegatedBudgetReserved => "delegated_budget_reserved",
            Self::PaymentAuthorized => "payment_authorized",
            Self::ApprovalReserved => "approval_reserved",
            Self::ReadyToDispatch => "ready_to_dispatch",
            Self::CapturePending => "capture_pending",
            Self::CallerReservationCapturePending => "caller_reservation_capture_pending",
            Self::CompensationPending => "compensation_pending",
            Self::DispatchCommitted => "dispatch_committed",
            Self::CallerReserved => "caller_reserved",
            Self::Completed => "completed",
            Self::CompensatedBeforeDispatch => "compensated_before_dispatch",
            Self::OutcomeUnknownAfterDispatch => "outcome_unknown_after_dispatch",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "prepared" => Some(Self::Prepared),
            "broker_attempt_registered" => Some(Self::BrokerAttemptRegistered),
            "budget_authorized" => Some(Self::BudgetAuthorized),
            "delegated_budget_reserved" => Some(Self::DelegatedBudgetReserved),
            "payment_authorized" => Some(Self::PaymentAuthorized),
            "approval_reserved" => Some(Self::ApprovalReserved),
            "ready_to_dispatch" => Some(Self::ReadyToDispatch),
            "capture_pending" => Some(Self::CapturePending),
            "caller_reservation_capture_pending" => Some(Self::CallerReservationCapturePending),
            "compensation_pending" => Some(Self::CompensationPending),
            "dispatch_committed" => Some(Self::DispatchCommitted),
            "caller_reserved" => Some(Self::CallerReserved),
            "completed" => Some(Self::Completed),
            "compensated_before_dispatch" => Some(Self::CompensatedBeforeDispatch),
            "outcome_unknown_after_dispatch" => Some(Self::OutcomeUnknownAfterDispatch),
            _ => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::CompensatedBeforeDispatch | Self::OutcomeUnknownAfterDispatch
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDispatchState {
    NotStarted,
    Committed,
    EffectCompleted,
    OutcomeUnknown,
}

impl AdmissionDispatchState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Committed => "committed",
            Self::EffectCompleted => "effect_completed",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "not_started" => Some(Self::NotStarted),
            "committed" => Some(Self::Committed),
            "effect_completed" => Some(Self::EffectCompleted),
            "outcome_unknown" => Some(Self::OutcomeUnknown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAdmissionOperation {
    pub kind: AdmissionOperationKind,
    pub coordinator_authority_id: String,
    pub request_id: String,
    pub capability_id: String,
    pub authorization_capability_hash: String,
    pub request_binding_hash: String,
    pub policy_hash: String,
    pub broker_attempt_id: Option<String>,
    pub budget_hold_id: Option<String>,
    pub approval_set_hash: Option<String>,
    pub execution_nonce_id: Option<String>,
    pub coordinator_lease_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionOperation {
    kind: AdmissionOperationKind,
    operation_id: String,
    coordinator_authority_id: String,
    request_id: String,
    capability_id: String,
    authorization_capability_hash: String,
    request_binding_hash: String,
    policy_hash: String,
    broker_attempt_id: Option<String>,
    budget_hold_id: Option<String>,
    approval_set_hash: Option<String>,
    execution_nonce_id: Option<String>,
    state: AdmissionOperationState,
    dispatch_state: AdmissionDispatchState,
    coordinator_lease_epoch: u64,
    version: u64,
    last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedAdmissionOperation {
    pub kind: AdmissionOperationKind,
    pub operation_id: String,
    pub coordinator_authority_id: String,
    pub request_id: String,
    pub capability_id: String,
    pub authorization_capability_hash: String,
    pub request_binding_hash: String,
    pub policy_hash: String,
    pub broker_attempt_id: Option<String>,
    pub budget_hold_id: Option<String>,
    pub approval_set_hash: Option<String>,
    pub execution_nonce_id: Option<String>,
    pub state: AdmissionOperationState,
    pub dispatch_state: AdmissionDispatchState,
    pub coordinator_lease_epoch: u64,
    pub version: u64,
    pub last_error: Option<String>,
}

impl AdmissionOperation {
    pub fn prepared(input: PreparedAdmissionOperation) -> Result<Self, AdmissionOperationError> {
        validate_identifier(&input.coordinator_authority_id, "coordinator_authority_id")?;
        validate_identifier(&input.request_id, "request_id")?;
        validate_identifier(&input.capability_id, "capability_id")?;
        validate_digest(
            &input.authorization_capability_hash,
            "authorization_capability_hash",
        )?;
        validate_digest(&input.request_binding_hash, "request_binding_hash")?;
        validate_digest(&input.policy_hash, "policy_hash")?;
        validate_optional_identifier(input.broker_attempt_id.as_deref(), "broker_attempt_id")?;
        validate_optional_identifier(input.budget_hold_id.as_deref(), "budget_hold_id")?;
        validate_optional_digest(input.approval_set_hash.as_deref(), "approval_set_hash")?;
        validate_optional_identifier(input.execution_nonce_id.as_deref(), "execution_nonce_id")?;
        validate_kind_participants(
            input.kind,
            input.broker_attempt_id.as_deref(),
            input.budget_hold_id.as_deref(),
            input.execution_nonce_id.as_deref(),
            AdmissionOperationState::Prepared,
        )?;
        let operation_id = derive_operation_id(
            input.kind,
            &input.coordinator_authority_id,
            &input.request_id,
            &input.capability_id,
            &input.authorization_capability_hash,
            &input.request_binding_hash,
        )?;
        Ok(Self {
            kind: input.kind,
            operation_id,
            coordinator_authority_id: input.coordinator_authority_id,
            request_id: input.request_id,
            capability_id: input.capability_id,
            authorization_capability_hash: input.authorization_capability_hash,
            request_binding_hash: input.request_binding_hash,
            policy_hash: input.policy_hash,
            broker_attempt_id: input.broker_attempt_id,
            budget_hold_id: input.budget_hold_id,
            approval_set_hash: input.approval_set_hash,
            execution_nonce_id: input.execution_nonce_id,
            state: AdmissionOperationState::Prepared,
            dispatch_state: AdmissionDispatchState::NotStarted,
            coordinator_lease_epoch: input.coordinator_lease_epoch,
            version: 0,
            last_error: None,
        })
    }

    pub fn from_persisted_parts(
        persisted: PersistedAdmissionOperation,
    ) -> Result<Self, AdmissionOperationError> {
        let PersistedAdmissionOperation {
            kind,
            operation_id,
            coordinator_authority_id,
            request_id,
            capability_id,
            authorization_capability_hash,
            request_binding_hash,
            policy_hash,
            broker_attempt_id,
            budget_hold_id,
            approval_set_hash,
            execution_nonce_id,
            state,
            dispatch_state,
            coordinator_lease_epoch,
            version,
            last_error,
        } = persisted;
        let expected_id = derive_operation_id(
            kind,
            &coordinator_authority_id,
            &request_id,
            &capability_id,
            &authorization_capability_hash,
            &request_binding_hash,
        )?;
        if operation_id != expected_id {
            return Err(AdmissionOperationError::Invalid(
                "persisted operation_id does not match its identity fields".to_string(),
            ));
        }
        validate_digest(&policy_hash, "policy_hash")?;
        validate_optional_identifier(broker_attempt_id.as_deref(), "broker_attempt_id")?;
        validate_optional_identifier(budget_hold_id.as_deref(), "budget_hold_id")?;
        validate_optional_digest(approval_set_hash.as_deref(), "approval_set_hash")?;
        validate_optional_identifier(execution_nonce_id.as_deref(), "execution_nonce_id")?;
        validate_last_error(last_error.as_deref())?;
        validate_state_dispatch_pair(state, dispatch_state)?;
        validate_kind_participants(
            kind,
            broker_attempt_id.as_deref(),
            budget_hold_id.as_deref(),
            execution_nonce_id.as_deref(),
            state,
        )?;
        Ok(Self {
            kind,
            operation_id,
            coordinator_authority_id,
            request_id,
            capability_id,
            authorization_capability_hash,
            request_binding_hash,
            policy_hash,
            broker_attempt_id,
            budget_hold_id,
            approval_set_hash,
            execution_nonce_id,
            state,
            dispatch_state,
            coordinator_lease_epoch,
            version,
            last_error,
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn kind(&self) -> AdmissionOperationKind {
        self.kind
    }

    pub fn state(&self) -> AdmissionOperationState {
        self.state
    }

    pub fn dispatch_state(&self) -> AdmissionDispatchState {
        self.dispatch_state
    }

    pub fn coordinator_lease_epoch(&self) -> u64 {
        self.coordinator_lease_epoch
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn coordinator_authority_id(&self) -> &str {
        &self.coordinator_authority_id
    }

    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub fn authorization_capability_hash(&self) -> &str {
        &self.authorization_capability_hash
    }

    pub fn request_binding_hash(&self) -> &str {
        &self.request_binding_hash
    }

    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    pub fn broker_attempt_id(&self) -> Option<&str> {
        self.broker_attempt_id.as_deref()
    }

    pub fn budget_hold_id(&self) -> Option<&str> {
        self.budget_hold_id.as_deref()
    }

    pub fn approval_set_hash(&self) -> Option<&str> {
        self.approval_set_hash.as_deref()
    }

    pub fn execution_nonce_id(&self) -> Option<&str> {
        self.execution_nonce_id.as_deref()
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Compare immutable operation identity and participant bindings across recovery.
    pub fn has_same_prepared_binding(&self, prepared: &Self) -> bool {
        self.kind == prepared.kind
            && self.operation_id == prepared.operation_id
            && self.coordinator_authority_id == prepared.coordinator_authority_id
            && self.request_id == prepared.request_id
            && self.capability_id == prepared.capability_id
            && self.authorization_capability_hash == prepared.authorization_capability_hash
            && self.request_binding_hash == prepared.request_binding_hash
            && self.policy_hash == prepared.policy_hash
            && self.broker_attempt_id == prepared.broker_attempt_id
            && self.budget_hold_id == prepared.budget_hold_id
            && self.approval_set_hash == prepared.approval_set_hash
            && self.execution_nonce_id == prepared.execution_nonce_id
    }

    pub fn transition_checked(
        &self,
        next_state: AdmissionOperationState,
        next_dispatch_state: AdmissionDispatchState,
        coordinator_lease_epoch: u64,
        last_error: Option<String>,
    ) -> Result<Self, AdmissionOperationError> {
        if self.state.is_terminal() {
            return Err(AdmissionOperationError::Invalid(format!(
                "terminal admission operation in `{}` is immutable",
                self.state.as_str()
            )));
        }
        if coordinator_lease_epoch < self.coordinator_lease_epoch {
            return Err(AdmissionOperationError::Invalid(
                "coordinator lease epoch regressed".to_string(),
            ));
        }
        let lease_only = next_state == self.state
            && next_dispatch_state == self.dispatch_state
            && coordinator_lease_epoch > self.coordinator_lease_epoch;
        if !lease_only && !valid_state_transition(self.state, next_state, self.kind) {
            return Err(AdmissionOperationError::Invalid(format!(
                "invalid admission state transition from `{}` to `{}`",
                self.state.as_str(),
                next_state.as_str()
            )));
        }
        validate_state_dispatch_pair(next_state, next_dispatch_state)?;
        validate_last_error(last_error.as_deref())?;
        let version = self.version.checked_add(1).ok_or_else(|| {
            AdmissionOperationError::Overflow("version overflowed u64".to_string())
        })?;
        let mut next = self.clone();
        next.state = next_state;
        next.dispatch_state = next_dispatch_state;
        next.coordinator_lease_epoch = coordinator_lease_epoch;
        next.version = version;
        next.last_error = last_error;
        Ok(next)
    }

    /// Fence every coordinator that observed the prior lease epoch while
    /// preserving the durable saga state for recovery inspection.
    pub fn claim_recovery_checked(&self) -> Result<Self, AdmissionOperationError> {
        if self.state.is_terminal() {
            return Err(AdmissionOperationError::Invalid(
                "terminal admission operation cannot be claimed for recovery".to_string(),
            ));
        }
        let coordinator_lease_epoch =
            self.coordinator_lease_epoch.checked_add(1).ok_or_else(|| {
                AdmissionOperationError::Overflow(
                    "admission coordinator lease epoch overflowed u64".to_string(),
                )
            })?;
        let version = self.version.checked_add(1).ok_or_else(|| {
            AdmissionOperationError::Overflow(
                "admission operation version overflowed u64".to_string(),
            )
        })?;
        let mut claimed = self.clone();
        claimed.coordinator_lease_epoch = coordinator_lease_epoch;
        claimed.version = version;
        Ok(claimed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionOperationCreateOutcome {
    Created(AdmissionOperation),
    Existing(AdmissionOperation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionOperationCasOutcome {
    Applied(AdmissionOperation),
    Conflict(AdmissionOperation),
    Missing,
}

#[derive(Debug)]
pub struct AdmissionOperationCompareAndSwap<'a> {
    pub operation_id: &'a str,
    pub expected_version: u64,
    pub coordinator_lease_epoch: u64,
    pub next_state: AdmissionOperationState,
    pub next_dispatch_state: AdmissionDispatchState,
    pub next_coordinator_lease_epoch: u64,
    pub last_error: Option<String>,
}

/// A durable participant action owned by one admission operation. Most kinds
/// describe pre-dispatch effects that must be undone after compensation;
/// `TerminalReceipt` is the forward-only outbox that makes terminal receipt
/// persistence recoverable.
///
/// One operation can own at most one action of each kind. The action payload is
/// canonical JSON whose schema is owned by the participant adapter. Keeping the
/// journal generic lets new operation-owned participants join the saga without
/// another admission-operation table migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionCleanupActionKind {
    Budget,
    Payment,
    DelegatedBudget,
    Approval,
    ExecutionNonce,
    Broker,
    CallerReservationHandoffIntent,
    CallerReservationHandoff,
    TerminalReceipt,
}

impl AdmissionCleanupActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Budget => "budget",
            Self::Payment => "payment",
            Self::DelegatedBudget => "delegated_budget",
            Self::Approval => "approval",
            Self::ExecutionNonce => "execution_nonce",
            Self::Broker => "broker",
            Self::CallerReservationHandoffIntent => "caller_reservation_handoff_intent",
            Self::CallerReservationHandoff => "caller_reservation_handoff",
            Self::TerminalReceipt => "terminal_receipt",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "budget" => Some(Self::Budget),
            "payment" => Some(Self::Payment),
            "delegated_budget" => Some(Self::DelegatedBudget),
            "approval" => Some(Self::Approval),
            "execution_nonce" => Some(Self::ExecutionNonce),
            "broker" => Some(Self::Broker),
            "caller_reservation_handoff_intent" => Some(Self::CallerReservationHandoffIntent),
            "caller_reservation_handoff" => Some(Self::CallerReservationHandoff),
            "terminal_receipt" => Some(Self::TerminalReceipt),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionCleanupActionState {
    Pending,
    Claimed,
    Completed,
}

impl AdmissionCleanupActionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimed => "claimed",
            Self::Completed => "completed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "claimed" => Some(Self::Claimed),
            "completed" => Some(Self::Completed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCleanupAction {
    action_id: String,
    operation_id: String,
    request_binding_hash: String,
    kind: AdmissionCleanupActionKind,
    payload_json: String,
    payload_hash: String,
    state: AdmissionCleanupActionState,
    claim_token: Option<String>,
    claim_deadline_unix_ms: Option<u64>,
    version: u64,
    last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedAdmissionCleanupAction {
    pub action_id: String,
    pub operation_id: String,
    pub request_binding_hash: String,
    pub kind: AdmissionCleanupActionKind,
    pub payload_json: String,
    pub payload_hash: String,
    pub state: AdmissionCleanupActionState,
    pub claim_token: Option<String>,
    pub claim_deadline_unix_ms: Option<u64>,
    pub version: u64,
    pub last_error: Option<String>,
}

impl AdmissionCleanupAction {
    pub fn pending<T: Serialize>(
        operation: &AdmissionOperation,
        kind: AdmissionCleanupActionKind,
        payload: &T,
    ) -> Result<Self, AdmissionOperationError> {
        let payload_bytes = canonical_json_bytes(payload).map_err(|error| {
            AdmissionOperationError::Invalid(format!(
                "failed to canonicalize admission cleanup payload: {error}"
            ))
        })?;
        if payload_bytes.is_empty() || payload_bytes.len() > MAX_ADMISSION_CLEANUP_PAYLOAD_BYTES {
            return Err(AdmissionOperationError::Invalid(format!(
                "admission cleanup payload must be between 1 and {MAX_ADMISSION_CLEANUP_PAYLOAD_BYTES} bytes"
            )));
        }
        let payload_json = String::from_utf8(payload_bytes).map_err(|_| {
            AdmissionOperationError::Invalid(
                "admission cleanup payload is not canonical UTF-8 JSON".to_string(),
            )
        })?;
        let payload_hash = sha256_hex(payload_json.as_bytes());
        let action_id = derive_cleanup_action_id(
            operation.operation_id(),
            operation.request_binding_hash(),
            kind,
            &payload_hash,
        )?;
        Ok(Self {
            action_id,
            operation_id: operation.operation_id().to_string(),
            request_binding_hash: operation.request_binding_hash().to_string(),
            kind,
            payload_json,
            payload_hash,
            state: AdmissionCleanupActionState::Pending,
            claim_token: None,
            claim_deadline_unix_ms: None,
            version: 0,
            last_error: None,
        })
    }

    pub fn from_persisted_parts(
        persisted: PersistedAdmissionCleanupAction,
    ) -> Result<Self, AdmissionOperationError> {
        let PersistedAdmissionCleanupAction {
            action_id,
            operation_id,
            request_binding_hash,
            kind,
            payload_json,
            payload_hash,
            state,
            claim_token,
            claim_deadline_unix_ms,
            version,
            last_error,
        } = persisted;
        validate_digest(&operation_id, "cleanup operation_id")?;
        validate_digest(&request_binding_hash, "cleanup request_binding_hash")?;
        validate_cleanup_payload(&payload_json, &payload_hash)?;
        let expected_action_id =
            derive_cleanup_action_id(&operation_id, &request_binding_hash, kind, &payload_hash)?;
        if action_id != expected_action_id {
            return Err(AdmissionOperationError::Invalid(
                "persisted cleanup action_id does not match its immutable binding".to_string(),
            ));
        }
        validate_last_error(last_error.as_deref())?;
        validate_cleanup_claim(state, claim_token.as_deref(), claim_deadline_unix_ms)?;
        Ok(Self {
            action_id,
            operation_id,
            request_binding_hash,
            kind,
            payload_json,
            payload_hash,
            state,
            claim_token,
            claim_deadline_unix_ms,
            version,
            last_error,
        })
    }

    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn request_binding_hash(&self) -> &str {
        &self.request_binding_hash
    }

    pub fn kind(&self) -> AdmissionCleanupActionKind {
        self.kind
    }

    pub fn payload_json(&self) -> &str {
        &self.payload_json
    }

    pub fn payload_hash(&self) -> &str {
        &self.payload_hash
    }

    pub fn state(&self) -> AdmissionCleanupActionState {
        self.state
    }

    pub fn claim_token(&self) -> Option<&str> {
        self.claim_token.as_deref()
    }

    pub fn claim_deadline_unix_ms(&self) -> Option<u64> {
        self.claim_deadline_unix_ms
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn claim_checked(
        &self,
        claim_token: String,
        now_unix_ms: u64,
        claim_deadline_unix_ms: u64,
    ) -> Result<Self, AdmissionOperationError> {
        validate_identifier(&claim_token, "cleanup claim_token")?;
        if claim_deadline_unix_ms <= now_unix_ms {
            return Err(AdmissionOperationError::Invalid(
                "cleanup claim deadline must be later than now".to_string(),
            ));
        }
        if self.state == AdmissionCleanupActionState::Completed {
            return Err(AdmissionOperationError::Invalid(
                "completed cleanup action cannot be claimed".to_string(),
            ));
        }
        let version = self.version.checked_add(1).ok_or_else(|| {
            AdmissionOperationError::Overflow("cleanup action version overflowed u64".to_string())
        })?;
        let mut next = self.clone();
        next.state = AdmissionCleanupActionState::Claimed;
        next.claim_token = Some(claim_token);
        next.claim_deadline_unix_ms = Some(claim_deadline_unix_ms);
        next.version = version;
        next.last_error = None;
        Ok(next)
    }

    pub fn acknowledge_checked(&self) -> Result<Self, AdmissionOperationError> {
        if self.state != AdmissionCleanupActionState::Claimed {
            return Err(AdmissionOperationError::Invalid(
                "only a claimed cleanup action can be acknowledged".to_string(),
            ));
        }
        let version = self.version.checked_add(1).ok_or_else(|| {
            AdmissionOperationError::Overflow("cleanup action version overflowed u64".to_string())
        })?;
        let mut next = self.clone();
        next.state = AdmissionCleanupActionState::Completed;
        next.claim_token = None;
        next.claim_deadline_unix_ms = None;
        next.version = version;
        next.last_error = None;
        Ok(next)
    }

    pub fn abandon_checked(&self, last_error: String) -> Result<Self, AdmissionOperationError> {
        if self.state != AdmissionCleanupActionState::Claimed {
            return Err(AdmissionOperationError::Invalid(
                "only a claimed cleanup action can be abandoned".to_string(),
            ));
        }
        validate_last_error(Some(&last_error))?;
        let version = self.version.checked_add(1).ok_or_else(|| {
            AdmissionOperationError::Overflow("cleanup action version overflowed u64".to_string())
        })?;
        let mut next = self.clone();
        next.state = AdmissionCleanupActionState::Pending;
        next.claim_token = None;
        next.claim_deadline_unix_ms = None;
        next.version = version;
        next.last_error = Some(last_error);
        Ok(next)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionCleanupActionCreateOutcome {
    Created(AdmissionCleanupAction),
    Existing(AdmissionCleanupAction),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionCleanupActionClaimOutcome {
    Claimed(AdmissionCleanupAction),
    Busy(AdmissionCleanupAction),
    Completed(AdmissionCleanupAction),
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionCleanupActionCasOutcome {
    Applied(AdmissionCleanupAction),
    Conflict(AdmissionCleanupAction),
    Missing,
}

#[cfg(test)]
mod review_tests;

#[cfg(test)]
mod tests;
