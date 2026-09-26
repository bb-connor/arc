//! Errors the response state machine returns.

use chio_security_types::ports::PortError;
use chio_security_types::ResponseShapeError;
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
    #[error("response dispatch authorization is invalid")]
    InvalidDispatch,
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
