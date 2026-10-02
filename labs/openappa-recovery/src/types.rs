use chio_core_types::PublicKey;
use chio_security_types::flow::{DeclassificationPurpose, ToolFlowDeclaration};
use chio_security_types::ports::{
    CanonicalBody, DestinationId, Digest32, FlowStateSnapshot, RecordId,
};
use chio_security_types::InformationLabel;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

#[derive(Clone, Debug, Serialize)]
pub struct DisclosureIntent {
    pub operation_id: RecordId,
    pub capability_id: RecordId,
    pub agent_id: RecordId,
    pub tool_name: RecordId,
    pub destination: DestinationId,
    pub purpose: DeclassificationPurpose,
    pub canonical_request: CanonicalBody,
    pub payload_label: InformationLabel,
}

/// Supplied by a trusted host in this lab. Production must resolve it from kernel state.
#[derive(Clone, Debug, Serialize)]
pub struct HostSnapshot {
    pub operation_id: RecordId,
    pub flow: FlowStateSnapshot,
    pub input_floor: InformationLabel,
    pub policy_clearances: Vec<InformationLabel>,
    pub manifest: ToolFlowDeclaration,
    pub policy_digest: Digest32,
    pub contract_digest: Digest32,
    pub revocation_generation: u64,
    pub budget_generation: u64,
    pub capability_revoked: bool,
    pub budget_remaining: u64,
    pub operation_state: OperationState,
    pub policy_purposes: BTreeSet<DeclassificationPurpose>,
    pub trusted_authorities: BTreeMap<RecordId, PublicKey>,
    /// Passage of time does not change an offer's basis; expiry is checked separately.
    #[serde(skip)]
    pub now_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    BeforeAdmission,
    DeniedBeforeDispatch,
    Pending,
    OutcomeUnknown,
    Complete,
}

/// Private fields prevent accidental construction through the public Rust API.
/// No signature or approval authority is implied by this prototype object.
#[derive(Clone, Debug, Serialize)]
pub struct DisclosureOffer {
    pub(crate) basis_digest: Digest32,
    pub(crate) expires_at_unix_ms: u64,
    pub(crate) action: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PlanningDecision {
    FlowCheckPassed,
    ContinuationRequired {
        denied_operation_id: RecordId,
    },
    WaitForOutcome {
        operation_id: RecordId,
    },
    Denied {
        reason: String,
        offers: Vec<DisclosureOffer>,
    },
    Refused {
        reason: String,
    },
    Reconcile {
        operation_id: RecordId,
    },
    RecoverOutcome {
        operation_id: RecordId,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub enum RecoveryError {
    OperationBindingMismatch,
    FrozenDeniedOperation,
    OutcomePending,
    StaleOffer,
    OfferExpired,
    CapabilityRevoked,
    BudgetUnavailable,
    UnknownOutcome,
    AlreadyCompleted,
    ClockMovedBackward,
    Grant(chio_flow::DeclassificationError),
    Flow(chio_flow::FlowDenial),
    Representation(String),
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RecoveryError {}

pub(crate) fn representation(error: impl fmt::Display) -> RecoveryError {
    RecoveryError::Representation(error.to_string())
}
