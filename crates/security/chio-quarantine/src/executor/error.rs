//! Errors the response executor returns.

use chio_security_types::ports::{CollectionError, PortError};
use chio_security_types::ResponseExecutionDispatchBindingError;
use thiserror::Error;

use crate::state_machine::{CanonicalFailure, StateMachineError};

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("response execution requires a completed approval")]
    ApprovalRequired,
    #[error("response execution retry attempt overflowed")]
    AttemptOverflow,
    #[error("response execution alert failed: {0}")]
    Alert(PortError),
    #[error("response execution canonicalization failed: {0}")]
    Canonical(#[from] CanonicalFailure),
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
    #[error("response generation does not fit the index width")]
    GenerationWidth(#[source] core::num::TryFromIntError),
    #[error("response effect journal is invalid")]
    InvalidEffectJournal,
    #[error("response effect journal does not decode")]
    EffectJournalDecode(#[source] serde_json::Error),
    #[error("response effect journal could not be re-encoded canonically")]
    EffectJournalEncoding(#[source] chio_core_types::Error),
    #[error("active response execution evidence is invalid or incomplete")]
    InvalidActiveEvidence,
    #[error("active response evidence mutation log exceeds its bound")]
    ActiveEvidenceMutationBound(#[source] CollectionError),
    #[error("active response evidence could not be canonically encoded")]
    ActiveEvidenceEncoding(#[source] chio_core_types::Error),
    #[error("active response evidence dispatch binding is invalid")]
    ActiveEvidenceBinding(#[source] ResponseExecutionDispatchBindingError),
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
