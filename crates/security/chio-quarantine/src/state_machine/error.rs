//! Errors the response state machine returns.
//!
//! Each variant is a category the callers match on. A category that several
//! rules can produce carries a payload naming the rule, so a rejection stays
//! distinguishable in a test, a receipt and an operator log. Inner causes
//! travel as sources rather than being flattened into the category.

use chio_security_types::ports::PortError;
use chio_security_types::{DispatchRejection, ResponseShapeError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateMachineError {
    #[error("response canonicalization failed")]
    Canonical,
    #[error("response effect application is incomplete")]
    IncompleteApplication,
    #[error("response effect lifecycle transition is invalid")]
    InvalidEffectLifecycle,
    #[error("response failure record is invalid")]
    InvalidFailureRecord,
    #[error("response plan is invalid")]
    InvalidPlan,
    #[error(transparent)]
    InvalidDispatch(#[from] DispatchRejection),
    #[error("response state record is invalid")]
    InvalidRecord,
    #[error("response transition timing is invalid")]
    InvalidTiming,
    #[error("response state transition is not permitted")]
    InvalidTransition,
    #[error("response mutation limit exceeded")]
    MutationLimit,
    #[error("response is not due")]
    NotDue,
    #[error("response generation overflow")]
    GenerationOverflow,
    #[error("response generation is stale")]
    StaleGeneration,
    #[error("response effect is unknown")]
    UnknownEffect,
    #[error("response still has unrestored reversible effects")]
    UnrestoredEffects,
    #[error("response plan shape is invalid: {0}")]
    Shape(#[from] ResponseShapeError),
    #[error("response store failed: {0}")]
    Store(#[from] PortError),
}
