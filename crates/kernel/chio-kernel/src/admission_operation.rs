use std::collections::HashMap;
use std::sync::Mutex;

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::sha256_hex;
use serde::{Deserialize, Serialize};

pub const ADMISSION_OPERATION_SCHEMA: &str = "chio.admission-operation.v1";
const ADMISSION_OPERATION_DOMAIN: &[u8] = b"chio.admission-operation.v1\0";
const ADMISSION_REQUEST_BINDING_DOMAIN: &[u8] = b"chio.admission-request-binding.v1\0";
const MAX_ADMISSION_IDENTIFIER_BYTES: usize = 512;
const MAX_ADMISSION_ERROR_BYTES: usize = 4_096;
pub const MAX_APPROVAL_TOKEN_DIGESTS_PER_OPERATION: usize = 64;

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
    ApprovalReserved,
    ReadyToDispatch,
    CapturePending,
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
            Self::ApprovalReserved => "approval_reserved",
            Self::ReadyToDispatch => "ready_to_dispatch",
            Self::CapturePending => "capture_pending",
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
            "approval_reserved" => Some(Self::ApprovalReserved),
            "ready_to_dispatch" => Some(Self::ReadyToDispatch),
            "capture_pending" => Some(Self::CapturePending),
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
    governed_intent_hash: Option<String>,
    threshold_proposal_hash: Option<String>,
    verified_approval_set_hash: Option<String>,
    approval_token_digests: Vec<String>,
    supplemental_authorization_reference: Option<String>,
    execution_nonce_reference: Option<String>,
}

impl AdmissionRequestBindingInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_hash: String,
        governed_intent_hash: Option<String>,
        threshold_proposal_hash: Option<String>,
        verified_approval_set_hash: Option<String>,
        mut approval_token_digests: Vec<String>,
        supplemental_authorization_reference: Option<String>,
        execution_nonce_reference: Option<String>,
    ) -> Result<Self, AdmissionOperationError> {
        validate_digest(&action_hash, "action_hash")?;
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
        approval_token_digests.sort_unstable();
        if approval_token_digests
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(AdmissionOperationError::Invalid(
                "approval token digests contain a duplicate".to_string(),
            ));
        }
        validate_optional_identifier(
            supplemental_authorization_reference.as_deref(),
            "supplemental_authorization_reference",
        )?;
        validate_optional_identifier(
            execution_nonce_reference.as_deref(),
            "execution_nonce_reference",
        )?;
        Ok(Self {
            action_hash,
            governed_intent_hash,
            threshold_proposal_hash,
            verified_approval_set_hash,
            approval_token_digests,
            supplemental_authorization_reference,
            execution_nonce_reference,
        })
    }

    pub fn approval_token_digests(&self) -> &[String] {
        &self.approval_token_digests
    }

    pub fn derive_hash(&self) -> Result<String, AdmissionOperationError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct BindingBody<'a> {
            action_hash: &'a str,
            governed_intent_hash: Option<&'a str>,
            threshold_proposal_hash: Option<&'a str>,
            verified_approval_set_hash: Option<&'a str>,
            approval_token_digests: &'a [String],
            supplemental_authorization_reference: Option<&'a str>,
            execution_nonce_reference: Option<&'a str>,
        }

        let canonical = canonical_json_bytes(&BindingBody {
            action_hash: &self.action_hash,
            governed_intent_hash: self.governed_intent_hash.as_deref(),
            threshold_proposal_hash: self.threshold_proposal_hash.as_deref(),
            verified_approval_set_hash: self.verified_approval_set_hash.as_deref(),
            approval_token_digests: &self.approval_token_digests,
            supplemental_authorization_reference: self
                .supplemental_authorization_reference
                .as_deref(),
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
        if input.kind == AdmissionOperationKind::GovernedActiveResponse
            && (input.broker_attempt_id.is_some()
                || input.budget_hold_id.is_some()
                || input.execution_nonce_id.is_some())
        {
            return Err(AdmissionOperationError::Invalid(
                "governed active response cannot bind budget, broker, or nonce participants"
                    .to_string(),
            ));
        }
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

    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted_parts(
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
    ) -> Result<Self, AdmissionOperationError> {
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

    fn transition(
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

pub trait AdmissionOperationStore: Send + Sync {
    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError>;

    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError>;

    #[allow(clippy::too_many_arguments)]
    fn compare_and_swap(
        &self,
        operation_id: &str,
        expected_version: u64,
        coordinator_lease_epoch: u64,
        next_state: AdmissionOperationState,
        next_dispatch_state: AdmissionDispatchState,
        next_coordinator_lease_epoch: u64,
        last_error: Option<String>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError>;
}

#[derive(Default)]
pub struct InMemoryAdmissionOperationStore {
    operations: Mutex<HashMap<String, AdmissionOperation>>,
}

impl InMemoryAdmissionOperationStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, HashMap<String, AdmissionOperation>>,
        AdmissionOperationError,
    > {
        self.operations.lock().map_err(|_| {
            AdmissionOperationError::Unavailable(
                "in-memory admission operation lock poisoned".to_string(),
            )
        })
    }
}

impl AdmissionOperationStore for InMemoryAdmissionOperationStore {
    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError> {
        if operation.state != AdmissionOperationState::Prepared
            || operation.dispatch_state != AdmissionDispatchState::NotStarted
            || operation.version != 0
        {
            return Err(AdmissionOperationError::Invalid(
                "new admission operation is not Prepared at version zero".to_string(),
            ));
        }
        let mut operations = self.lock()?;
        if let Some(existing) = operations.get(operation.operation_id()) {
            if existing != &operation {
                return Err(AdmissionOperationError::Invalid(
                    "operation_id is already bound to different input".to_string(),
                ));
            }
            return Ok(AdmissionOperationCreateOutcome::Existing(existing.clone()));
        }
        operations.insert(operation.operation_id.clone(), operation.clone());
        Ok(AdmissionOperationCreateOutcome::Created(operation))
    }

    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        validate_identifier(operation_id, "operation_id")?;
        Ok(self.lock()?.get(operation_id).cloned())
    }

    fn compare_and_swap(
        &self,
        operation_id: &str,
        expected_version: u64,
        coordinator_lease_epoch: u64,
        next_state: AdmissionOperationState,
        next_dispatch_state: AdmissionDispatchState,
        next_coordinator_lease_epoch: u64,
        last_error: Option<String>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        validate_identifier(operation_id, "operation_id")?;
        let mut operations = self.lock()?;
        let Some(current) = operations.get(operation_id).cloned() else {
            return Ok(AdmissionOperationCasOutcome::Missing);
        };
        if current.version != expected_version
            || current.coordinator_lease_epoch != coordinator_lease_epoch
        {
            return Ok(AdmissionOperationCasOutcome::Conflict(current));
        }
        let next = current.transition(
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        )?;
        operations.insert(operation_id.to_string(), next.clone());
        Ok(AdmissionOperationCasOutcome::Applied(next))
    }
}

pub fn derive_operation_id(
    kind: AdmissionOperationKind,
    coordinator_authority_id: &str,
    request_id: &str,
    capability_id: &str,
    authorization_capability_hash: &str,
    request_binding_hash: &str,
) -> Result<String, AdmissionOperationError> {
    validate_identifier(coordinator_authority_id, "coordinator_authority_id")?;
    validate_identifier(request_id, "request_id")?;
    validate_identifier(capability_id, "capability_id")?;
    validate_digest(
        authorization_capability_hash,
        "authorization_capability_hash",
    )?;
    validate_digest(request_binding_hash, "request_binding_hash")?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OperationIdentity<'a> {
        kind: AdmissionOperationKind,
        coordinator_authority_id: &'a str,
        request_id: &'a str,
        capability_id: &'a str,
        authorization_capability_hash: &'a str,
        request_binding_hash: &'a str,
    }
    let canonical = canonical_json_bytes(&OperationIdentity {
        kind,
        coordinator_authority_id,
        request_id,
        capability_id,
        authorization_capability_hash,
        request_binding_hash,
    })
    .map_err(|error| {
        AdmissionOperationError::Invalid(format!(
            "failed to canonicalize admission operation identity: {error}"
        ))
    })?;
    let mut bytes = Vec::with_capacity(ADMISSION_OPERATION_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(ADMISSION_OPERATION_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_hex(&bytes))
}

fn valid_state_transition(
    current: AdmissionOperationState,
    next: AdmissionOperationState,
    kind: AdmissionOperationKind,
) -> bool {
    use AdmissionOperationState as State;
    if current.is_terminal() {
        return false;
    }
    if next == State::CompensatedBeforeDispatch {
        return !matches!(current, State::DispatchCommitted);
    }
    match (current, next) {
        (State::Prepared, State::BrokerAttemptRegistered) => {
            kind == AdmissionOperationKind::ToolDispatch
        }
        (State::Prepared, State::BudgetAuthorized)
        | (State::BrokerAttemptRegistered, State::BudgetAuthorized) => {
            kind == AdmissionOperationKind::ToolDispatch
        }
        (State::Prepared, State::ApprovalReserved) => {
            kind == AdmissionOperationKind::GovernedActiveResponse
        }
        (State::BudgetAuthorized, State::ApprovalReserved)
        | (State::BudgetAuthorized, State::ReadyToDispatch)
        | (State::ApprovalReserved, State::ReadyToDispatch)
        | (State::ReadyToDispatch, State::CapturePending) => {
            kind == AdmissionOperationKind::ToolDispatch
        }
        (State::ApprovalReserved, State::DispatchCommitted) => {
            kind == AdmissionOperationKind::GovernedActiveResponse
        }
        (State::CapturePending, State::DispatchCommitted)
        | (State::DispatchCommitted, State::Completed)
        | (State::DispatchCommitted, State::OutcomeUnknownAfterDispatch) => true,
        _ => false,
    }
}

fn validate_state_dispatch_pair(
    state: AdmissionOperationState,
    dispatch_state: AdmissionDispatchState,
) -> Result<(), AdmissionOperationError> {
    let valid = match state {
        AdmissionOperationState::Prepared
        | AdmissionOperationState::BrokerAttemptRegistered
        | AdmissionOperationState::BudgetAuthorized
        | AdmissionOperationState::ApprovalReserved
        | AdmissionOperationState::ReadyToDispatch
        | AdmissionOperationState::CapturePending
        | AdmissionOperationState::CompensatedBeforeDispatch => {
            dispatch_state == AdmissionDispatchState::NotStarted
        }
        AdmissionOperationState::DispatchCommitted => {
            dispatch_state == AdmissionDispatchState::Committed
        }
        AdmissionOperationState::Completed => {
            dispatch_state == AdmissionDispatchState::EffectCompleted
        }
        AdmissionOperationState::OutcomeUnknownAfterDispatch => {
            dispatch_state == AdmissionDispatchState::OutcomeUnknown
        }
    };
    if valid {
        Ok(())
    } else {
        Err(AdmissionOperationError::Invalid(
            "admission state and dispatch state are inconsistent".to_string(),
        ))
    }
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), AdmissionOperationError> {
    if value.is_empty()
        || value.len() > MAX_ADMISSION_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte == 0)
    {
        return Err(AdmissionOperationError::Invalid(format!(
            "{label} is empty, oversized, or contains NUL"
        )));
    }
    Ok(())
}

fn validate_optional_identifier(
    value: Option<&str>,
    label: &'static str,
) -> Result<(), AdmissionOperationError> {
    value.map_or(Ok(()), |value| validate_identifier(value, label))
}

fn validate_digest(value: &str, label: &'static str) -> Result<(), AdmissionOperationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AdmissionOperationError::Invalid(format!(
            "{label} must be lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

fn validate_optional_digest(
    value: Option<&str>,
    label: &'static str,
) -> Result<(), AdmissionOperationError> {
    value.map_or(Ok(()), |value| validate_digest(value, label))
}

fn validate_last_error(value: Option<&str>) -> Result<(), AdmissionOperationError> {
    if value.is_some_and(|value| {
        value.is_empty()
            || value.len() > MAX_ADMISSION_ERROR_BYTES
            || value.bytes().any(|byte| byte == 0)
    }) {
        return Err(AdmissionOperationError::Invalid(
            "last_error is empty, oversized, or contains NUL".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepared(kind: AdmissionOperationKind) -> AdmissionOperation {
        AdmissionOperation::prepared(PreparedAdmissionOperation {
            kind,
            coordinator_authority_id: "coordinator-1".to_string(),
            request_id: "request-1".to_string(),
            capability_id: "capability-1".to_string(),
            authorization_capability_hash: "11".repeat(32),
            request_binding_hash: "22".repeat(32),
            policy_hash: "33".repeat(32),
            broker_attempt_id: (kind == AdmissionOperationKind::ToolDispatch)
                .then(|| "attempt-1".to_string()),
            budget_hold_id: (kind == AdmissionOperationKind::ToolDispatch)
                .then(|| "hold-1".to_string()),
            approval_set_hash: Some("44".repeat(32)),
            execution_nonce_id: (kind == AdmissionOperationKind::ToolDispatch)
                .then(|| "nonce-1".to_string()),
            coordinator_lease_epoch: 7,
        })
        .unwrap()
    }

    #[test]
    fn operation_id_is_fixed_and_identity_bound() {
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        assert_eq!(
            operation.operation_id(),
            "abb08f11721ae2dc1e0c5956c319971108ee2a6d0918f6dcacd162857fd2baf4"
        );
        assert_eq!(operation, prepared(AdmissionOperationKind::ToolDispatch));

        let mut changed = prepared(AdmissionOperationKind::ToolDispatch);
        changed.request_id = "request-2".to_string();
        assert_ne!(
            operation.operation_id(),
            derive_operation_id(
                changed.kind,
                &changed.coordinator_authority_id,
                &changed.request_id,
                &changed.capability_id,
                &changed.authorization_capability_hash,
                &changed.request_binding_hash,
            )
            .unwrap()
        );
    }

    #[test]
    fn approval_membership_order_cannot_change_request_binding() {
        let left = AdmissionRequestBindingInput::new(
            "11".repeat(32),
            None,
            Some("22".repeat(32)),
            Some("33".repeat(32)),
            vec!["55".repeat(32), "44".repeat(32)],
            Some("supplemental-1".to_string()),
            Some("nonce-1".to_string()),
        )
        .unwrap();
        let right = AdmissionRequestBindingInput::new(
            "11".repeat(32),
            None,
            Some("22".repeat(32)),
            Some("33".repeat(32)),
            vec!["44".repeat(32), "55".repeat(32)],
            Some("supplemental-1".to_string()),
            Some("nonce-1".to_string()),
        )
        .unwrap();
        assert_eq!(
            left.approval_token_digests(),
            right.approval_token_digests()
        );
        assert_eq!(left.derive_hash().unwrap(), right.derive_hash().unwrap());
        assert!(AdmissionRequestBindingInput::new(
            "11".repeat(32),
            None,
            None,
            None,
            vec!["44".repeat(32), "44".repeat(32)],
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn compare_and_swap_is_versioned_and_lease_fenced() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        let id = operation.operation_id().to_string();
        assert!(matches!(
            store.create_prepared(operation).unwrap(),
            AdmissionOperationCreateOutcome::Created(_)
        ));

        let applied = store
            .compare_and_swap(
                &id,
                0,
                7,
                AdmissionOperationState::BrokerAttemptRegistered,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .unwrap();
        let AdmissionOperationCasOutcome::Applied(applied) = applied else {
            panic!("first transition should apply");
        };
        assert_eq!(applied.version(), 1);

        assert!(matches!(
            store
                .compare_and_swap(
                    &id,
                    0,
                    7,
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(_)
        ));
        assert!(matches!(
            store
                .compare_and_swap(
                    &id,
                    1,
                    6,
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(_)
        ));
    }

    #[test]
    fn dispatch_commit_precedes_effect_terminal_states() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        let id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        let mut version = 0;
        for state in [
            AdmissionOperationState::BrokerAttemptRegistered,
            AdmissionOperationState::BudgetAuthorized,
            AdmissionOperationState::ApprovalReserved,
            AdmissionOperationState::ReadyToDispatch,
            AdmissionOperationState::CapturePending,
        ] {
            let AdmissionOperationCasOutcome::Applied(applied) = store
                .compare_and_swap(
                    &id,
                    version,
                    7,
                    state,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                )
                .unwrap()
            else {
                panic!("transition should apply");
            };
            version = applied.version();
        }
        assert!(store
            .compare_and_swap(
                &id,
                version,
                7,
                AdmissionOperationState::Completed,
                AdmissionDispatchState::EffectCompleted,
                7,
                None,
            )
            .is_err());
        let AdmissionOperationCasOutcome::Applied(committed) = store
            .compare_and_swap(
                &id,
                version,
                7,
                AdmissionOperationState::DispatchCommitted,
                AdmissionDispatchState::Committed,
                7,
                None,
            )
            .unwrap()
        else {
            panic!("dispatch commit should apply");
        };
        assert!(matches!(
            store
                .compare_and_swap(
                    &id,
                    committed.version(),
                    7,
                    AdmissionOperationState::Completed,
                    AdmissionDispatchState::EffectCompleted,
                    7,
                    None,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
    }

    #[test]
    fn approval_only_flow_omits_budget_and_dispatches_after_reservation() {
        let operation = prepared(AdmissionOperationKind::GovernedActiveResponse);
        assert!(operation.budget_hold_id().is_none());
        assert!(operation.execution_nonce_id().is_none());
        let store = InMemoryAdmissionOperationStore::new();
        let id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        let AdmissionOperationCasOutcome::Applied(reserved) = store
            .compare_and_swap(
                &id,
                0,
                7,
                AdmissionOperationState::ApprovalReserved,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .unwrap()
        else {
            panic!("approval reservation should apply");
        };
        assert!(matches!(
            store
                .compare_and_swap(
                    &id,
                    reserved.version(),
                    7,
                    AdmissionOperationState::DispatchCommitted,
                    AdmissionDispatchState::Committed,
                    7,
                    None,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
    }
}
