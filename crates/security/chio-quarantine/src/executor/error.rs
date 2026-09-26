//! Errors the response executor returns.

use chio_security_types::ports::PortError;
use thiserror::Error;

use crate::state_machine::StateMachineError;

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("response execution requires a completed approval")]
    ApprovalRequired,
    #[error("response execution retry attempt overflowed")]
    AttemptOverflow,
    #[error("response execution alert failed: {0}")]
    Alert(PortError),
    #[error("response execution canonicalization failed")]
    Canonical,
    #[error("response effect outcome is unknown")]
    EffectOutcomeUnknown,
    #[error("response effect mutation returned without an authoritative result: {0}")]
    EffectMutation(PortError),
    #[error("response effect result query failed: {0}")]
    EffectQuery(PortError),
    #[error("response effect result is invalid")]
    InvalidEffectResult,
    #[error("response effect generation overflowed")]
    GenerationOverflow,
    #[error("response effect journal is invalid")]
    InvalidEffectJournal,
    #[error("active response execution evidence is invalid or incomplete")]
    InvalidActiveEvidence,
    #[error("response execution receipt failed: {0}")]
    Receipt(PortError),
    #[error("response execution receipt lineage does not match durable state")]
    ReceiptLineageMismatch,
    #[error("response execution lease is stale")]
    StaleLease,
    #[error("response execution store failed: {0}")]
    Store(PortError),
    #[error("response state machine failed: {0}")]
    StateMachine(#[from] StateMachineError),
    #[error("scheduled work does not match the response plan")]
    WorkMismatch,
}
