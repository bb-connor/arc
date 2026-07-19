use std::collections::HashMap;
use std::sync::Mutex;

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::sha256_hex;
use serde::{Deserialize, Serialize};

pub const ADMISSION_OPERATION_SCHEMA: &str = "chio.admission-operation.v1";
const ADMISSION_OPERATION_DOMAIN: &[u8] = b"chio.admission-operation.v1\0";
const ADMISSION_REQUEST_BINDING_DOMAIN: &[u8] = b"chio.admission-request-binding.v1\0";
const ADMISSION_CLEANUP_ACTION_DOMAIN: &[u8] = b"chio.admission-cleanup-action.v1\0";
const MAX_ADMISSION_IDENTIFIER_BYTES: usize = 512;
const MAX_ADMISSION_ERROR_BYTES: usize = 4_096;
// A complete cleanup snapshot can contain every verified quota and the full
// bounded revocation set. Keep the journal bound finite, but large enough for
// the maximum protocol-valid authority input.
const MAX_ADMISSION_CLEANUP_PAYLOAD_BYTES: usize = 256 * 1_024;
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

#[derive(Debug, thiserror::Error)]
pub enum AdmissionOperationError {
    #[error("invalid admission operation: {0}")]
    Invalid(String),

    #[error("admission operation arithmetic overflow: {0}")]
    Overflow(String),

    #[error("admission operation storage unavailable: {0}")]
    Unavailable(String),
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
    CompensationPending,
    DispatchCommitted,
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
            Self::CompensationPending => "compensation_pending",
            Self::DispatchCommitted => "dispatch_committed",
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
            "compensation_pending" => Some(Self::CompensationPending),
            "dispatch_committed" => Some(Self::DispatchCommitted),
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
pub struct AdmissionRequestBindingInput {
    action_hash: String,
    policy_hash: String,
    governed_intent_hash: Option<String>,
    threshold_proposal_hash: Option<String>,
    verified_approval_set_hash: Option<String>,
    approval_token_digests: Vec<String>,
    budget_hold_reference: Option<String>,
    supplemental_authorization_reference: Option<String>,
    supplemental_authorization_digest: Option<String>,
    execution_nonce_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRequestBindingParts {
    pub action_hash: String,
    pub policy_hash: String,
    pub governed_intent_hash: Option<String>,
    pub threshold_proposal_hash: Option<String>,
    pub verified_approval_set_hash: Option<String>,
    pub approval_token_digests: Vec<String>,
    pub budget_hold_reference: Option<String>,
    pub supplemental_authorization_reference: Option<String>,
    pub supplemental_authorization_digest: Option<String>,
    pub execution_nonce_reference: Option<String>,
}

impl AdmissionRequestBindingInput {
    pub fn new(parts: AdmissionRequestBindingParts) -> Result<Self, AdmissionOperationError> {
        let AdmissionRequestBindingParts {
            action_hash,
            policy_hash,
            governed_intent_hash,
            threshold_proposal_hash,
            verified_approval_set_hash,
            approval_token_digests,
            budget_hold_reference,
            supplemental_authorization_reference,
            supplemental_authorization_digest,
            execution_nonce_reference,
        } = parts;
        validate_digest(&action_hash, "action_hash")?;
        validate_digest(&policy_hash, "policy_hash")?;
        validate_optional_digest(governed_intent_hash.as_deref(), "governed_intent_hash")?;
        validate_optional_digest(
            threshold_proposal_hash.as_deref(),
            "threshold_proposal_hash",
        )?;
        validate_optional_digest(
            verified_approval_set_hash.as_deref(),
            "verified_approval_set_hash",
        )?;
        if approval_token_digests.len() > MAX_APPROVAL_TOKEN_DIGESTS_PER_OPERATION {
            return Err(AdmissionOperationError::Invalid(format!(
                "approval token digest count exceeds {MAX_APPROVAL_TOKEN_DIGESTS_PER_OPERATION}"
            )));
        }
        for digest in &approval_token_digests {
            validate_digest(digest, "approval_token_digest")?;
        }
        if approval_token_digests
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(AdmissionOperationError::Invalid(
                "approval token digests must be strictly sorted".to_string(),
            ));
        }
        validate_optional_identifier(budget_hold_reference.as_deref(), "budget_hold_reference")?;
        validate_optional_identifier(
            supplemental_authorization_reference.as_deref(),
            "supplemental_authorization_reference",
        )?;
        validate_optional_digest(
            supplemental_authorization_digest.as_deref(),
            "supplemental_authorization_digest",
        )?;
        if supplemental_authorization_reference.is_some()
            != supplemental_authorization_digest.is_some()
        {
            return Err(AdmissionOperationError::Invalid(
                "supplemental authorization reference and digest must be supplied together"
                    .to_string(),
            ));
        }
        validate_optional_identifier(
            execution_nonce_reference.as_deref(),
            "execution_nonce_reference",
        )?;
        Ok(Self {
            action_hash,
            policy_hash,
            governed_intent_hash,
            threshold_proposal_hash,
            verified_approval_set_hash,
            approval_token_digests,
            budget_hold_reference,
            supplemental_authorization_reference,
            supplemental_authorization_digest,
            execution_nonce_reference,
        })
    }

    pub(crate) fn from_unordered_approval_token_digests(
        mut parts: AdmissionRequestBindingParts,
    ) -> Result<Self, AdmissionOperationError> {
        parts.approval_token_digests.sort_unstable();
        Self::new(parts)
    }

    pub fn approval_token_digests(&self) -> &[String] {
        &self.approval_token_digests
    }

    pub fn derive_hash(&self) -> Result<String, AdmissionOperationError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct BindingBody<'a> {
            action_hash: &'a str,
            policy_hash: &'a str,
            governed_intent_hash: Option<&'a str>,
            threshold_proposal_hash: Option<&'a str>,
            verified_approval_set_hash: Option<&'a str>,
            approval_token_digests: &'a [String],
            budget_hold_reference: Option<&'a str>,
            supplemental_authorization_reference: Option<&'a str>,
            supplemental_authorization_digest: Option<&'a str>,
            execution_nonce_reference: Option<&'a str>,
        }

        let canonical = canonical_json_bytes(&BindingBody {
            action_hash: &self.action_hash,
            policy_hash: &self.policy_hash,
            governed_intent_hash: self.governed_intent_hash.as_deref(),
            threshold_proposal_hash: self.threshold_proposal_hash.as_deref(),
            verified_approval_set_hash: self.verified_approval_set_hash.as_deref(),
            approval_token_digests: &self.approval_token_digests,
            budget_hold_reference: self.budget_hold_reference.as_deref(),
            supplemental_authorization_reference: self
                .supplemental_authorization_reference
                .as_deref(),
            supplemental_authorization_digest: self.supplemental_authorization_digest.as_deref(),
            execution_nonce_reference: self.execution_nonce_reference.as_deref(),
        })
        .map_err(|error| {
            AdmissionOperationError::Invalid(format!(
                "failed to canonicalize admission request binding: {error}"
            ))
        })?;
        let mut bytes =
            Vec::with_capacity(ADMISSION_REQUEST_BINDING_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(ADMISSION_REQUEST_BINDING_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(sha256_hex(&bytes))
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
        if matches!(
            self.state,
            AdmissionOperationState::Completed | AdmissionOperationState::CompensatedBeforeDispatch
        ) {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionOperationStoreProfile {
    EphemeralLocal,
    SingleNodeDurable,
    SharedLinearizable,
}

impl AdmissionOperationStoreProfile {
    pub fn supports_dispatch_workers(self, dispatch_worker_count: usize) -> bool {
        match self {
            Self::EphemeralLocal => false,
            Self::SingleNodeDurable => dispatch_worker_count == 1,
            Self::SharedLinearizable => dispatch_worker_count > 0,
        }
    }
}

pub trait AdmissionOperationStore: Send + Sync {
    fn authority_profile(&self) -> AdmissionOperationStoreProfile {
        AdmissionOperationStoreProfile::EphemeralLocal
    }

    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError>;

    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError>;

    /// Return a bounded, deterministic inventory of operations that still
    /// require recovery or reconciliation.
    fn list_unresolved(
        &self,
        kind: Option<AdmissionOperationKind>,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.list_unresolved(kind, limit);
        }
        Err(AdmissionOperationError::Unavailable(
            "unresolved admission operation inventory is unavailable".to_string(),
        ))
    }

    /// Atomically increment the operation lease epoch without changing saga
    /// state. Every later state transition must present the returned epoch.
    fn claim_recovery(
        &self,
        operation_id: &str,
        expected_version: u64,
        expected_coordinator_lease_epoch: u64,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.claim_recovery(
                operation_id,
                expected_version,
                expected_coordinator_lease_epoch,
            );
        }
        Err(AdmissionOperationError::Unavailable(
            "admission recovery claims are unavailable".to_string(),
        ))
    }

    /// Count operations that still require their original authority.
    ///
    /// An unknown post-dispatch outcome is terminal for admission mutation but
    /// remains unresolved for authority rotation and reconciliation.
    fn count_unresolved_by_authority(
        &self,
        kind: AdmissionOperationKind,
        coordinator_authority_id: &str,
    ) -> Result<u64, AdmissionOperationError>;

    /// Count every nonterminal, non-compensated operation of one kind. This is
    /// the cold-restart authority-rotation gate when the prior coordinator
    /// identity is not available in process memory.
    fn count_unresolved(
        &self,
        kind: AdmissionOperationKind,
    ) -> Result<u64, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.count_unresolved(kind);
        }
        Err(AdmissionOperationError::Unavailable(
            "unresolved admission operation inventory is unavailable".to_string(),
        ))
    }

    fn compare_and_swap(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError>;

    /// Atomically persist one state transition and its exact forward-only
    /// journal action. Terminal receipt finalization uses this so a terminal
    /// operation can never become durable without a recoverable signed receipt.
    fn compare_and_swap_with_cleanup_action(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
        action: AdmissionCleanupAction,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.compare_and_swap_with_cleanup_action(request, action);
        }
        Err(AdmissionOperationError::Unavailable(
            "atomic admission transition with journal action is unavailable".to_string(),
        ))
    }

    /// Optional forwarding target for store decorators used by observability
    /// and fault-injection layers. Durable concrete stores should implement the
    /// cleanup methods directly. A decorator can forward the complete journal
    /// contract by returning its wrapped store here.
    fn cleanup_journal_delegate(&self) -> Option<&dyn AdmissionOperationStore> {
        None
    }

    fn create_cleanup_action(
        &self,
        action: AdmissionCleanupAction,
    ) -> Result<AdmissionCleanupActionCreateOutcome, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.create_cleanup_action(action);
        }
        Err(AdmissionOperationError::Unavailable(
            "admission cleanup journal is unavailable".to_string(),
        ))
    }

    fn load_cleanup_actions(
        &self,
        operation_id: &str,
    ) -> Result<Vec<AdmissionCleanupAction>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.load_cleanup_actions(operation_id);
        }
        Err(AdmissionOperationError::Unavailable(
            "admission cleanup journal is unavailable".to_string(),
        ))
    }

    /// Return compensation-pending or compensated operations with unfinished
    /// cleanup, oldest first.
    /// The caller supplies a hard bound so startup recovery never scans an
    /// unbounded journal in one pass.
    fn list_compensated_with_pending_cleanup(
        &self,
        kind: Option<AdmissionOperationKind>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.list_compensated_with_pending_cleanup(kind, limit);
        }
        Err(AdmissionOperationError::Unavailable(
            "admission cleanup journal is unavailable".to_string(),
        ))
    }

    fn list_operations_with_pending_cleanup_action(
        &self,
        operation_kind: AdmissionOperationKind,
        action_kind: AdmissionCleanupActionKind,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.list_operations_with_pending_cleanup_action(
                operation_kind,
                action_kind,
                limit,
            );
        }
        Err(AdmissionOperationError::Unavailable(
            "pending admission journal inventory is unavailable".to_string(),
        ))
    }

    fn claim_cleanup_action(
        &self,
        action_id: &str,
        claim_token: &str,
        now_unix_ms: u64,
        claim_deadline_unix_ms: u64,
    ) -> Result<AdmissionCleanupActionClaimOutcome, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.claim_cleanup_action(
                action_id,
                claim_token,
                now_unix_ms,
                claim_deadline_unix_ms,
            );
        }
        Err(AdmissionOperationError::Unavailable(
            "admission cleanup journal is unavailable".to_string(),
        ))
    }

    fn acknowledge_cleanup_action(
        &self,
        action_id: &str,
        expected_version: u64,
        claim_token: &str,
    ) -> Result<AdmissionCleanupActionCasOutcome, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.acknowledge_cleanup_action(action_id, expected_version, claim_token);
        }
        Err(AdmissionOperationError::Unavailable(
            "admission cleanup journal is unavailable".to_string(),
        ))
    }

    fn abandon_cleanup_action(
        &self,
        action_id: &str,
        expected_version: u64,
        claim_token: &str,
        last_error: String,
    ) -> Result<AdmissionCleanupActionCasOutcome, AdmissionOperationError> {
        if let Some(delegate) = self.cleanup_journal_delegate() {
            return delegate.abandon_cleanup_action(
                action_id,
                expected_version,
                claim_token,
                last_error,
            );
        }
        Err(AdmissionOperationError::Unavailable(
            "admission cleanup journal is unavailable".to_string(),
        ))
    }
}

#[derive(Default)]
pub struct InMemoryAdmissionOperationStore {
    state: Mutex<InMemoryAdmissionOperationState>,
}

#[derive(Default)]
struct InMemoryAdmissionOperationState {
    operations: HashMap<String, AdmissionOperation>,
    cleanup_actions: HashMap<String, AdmissionCleanupAction>,
}

impl InMemoryAdmissionOperationStore {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn inject_legacy_operation_without_outbox_for_test(
        &self,
        operation: AdmissionOperation,
    ) -> Result<(), AdmissionOperationError> {
        self.lock()?
            .operations
            .insert(operation.operation_id().to_string(), operation);
        Ok(())
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, InMemoryAdmissionOperationState>, AdmissionOperationError>
    {
        self.state.lock().map_err(|_| {
            AdmissionOperationError::Unavailable(
                "in-memory admission operation lock poisoned".to_string(),
            )
        })
    }
}
