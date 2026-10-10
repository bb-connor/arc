//! Errors the response state machine returns.
//!
//! Each variant is a category the callers match on. A category that several
//! rules can produce carries a payload naming the rule, so a rejection stays
//! distinguishable in a test, a receipt and an operator log. Inner causes
//! travel as sources rather than being flattened into the category.

use chio_security_types::ports::{
    BodyError, CollectionError, IdError, PortError, RecordIdSetError,
};
use chio_security_types::{DispatchRejection, ResponseShapeError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateMachineError {
    #[error("response canonicalization failed: {0}")]
    Canonical(#[from] CanonicalFailure),
    #[error("response effect application is incomplete")]
    IncompleteApplication,
    #[error("response effect lifecycle transition is invalid")]
    InvalidEffectLifecycle,
    #[error("response failure record is invalid")]
    InvalidFailureRecord,
    #[error("response plan is invalid: {0}")]
    InvalidPlan(#[from] PlanDefect),
    #[error(transparent)]
    InvalidDispatch(#[from] DispatchRejection),
    #[error("response state record is invalid: {0}")]
    InvalidRecord(#[from] RecordDefect),
    #[error("response transition timing is invalid")]
    InvalidTiming,
    #[error("response state transition is not permitted")]
    InvalidTransition,
    #[error("response mutation log is full")]
    MutationLimit(#[source] CollectionError),
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

/// The step of canonical encoding that failed. Every step is named so a
/// receipt can say which representation could not be produced.
#[derive(Debug, Error)]
pub enum CanonicalFailure {
    #[error("canonical JSON encoding failed")]
    Encoding(#[source] chio_core_types::Error),
    #[error("canonical body exceeds its bound")]
    Body(#[source] BodyError),
    #[error("derived identifier is not a valid record id")]
    Identifier(#[source] IdError),
    #[error("JSON value conversion failed")]
    Value(#[source] serde_json::Error),
    #[error("native receipt derivation failed")]
    Receipt(#[source] chio_core_types::Error),
}

/// The rule a response plan failed. One variant per rule; the payload is the
/// value the rule compared or the cause it uncovered.
#[derive(Debug, Error)]
pub enum PlanDefect {
    #[error("plan carries no effects")]
    NoEffects,
    #[error("plan carries {count} effects; the bound is {bound}")]
    TooManyEffects { count: usize, bound: usize },
    #[error("plan ttl is zero")]
    ZeroTtl,
    #[error("plan expiry overflows the millisecond clock")]
    ExpiryOverflow,
    #[error("affected ids do not form a bounded, strictly sorted set")]
    AffectedIds(#[source] RecordIdSetError),
    #[error("affected set hash could not be derived")]
    AffectedSetHash(#[source] PortError),
    #[error("affected set hash does not match the affected ids")]
    AffectedSetHashMismatch,
    #[error("effect index does not fit the ordinal width")]
    EffectOrdinalOverflow(#[source] core::num::TryFromIntError),
    #[error("planned effects exceed the effect bound")]
    EffectBound(#[source] CollectionError),
    #[error("effect contribution is not JSON")]
    ContributionNotJson(#[source] serde_json::Error),
    #[error("effect contribution is not in canonical form")]
    ContributionNotCanonical,
    #[error("effect contribution does not match its hash")]
    ContributionHashMismatch,
    #[error("effect id does not match its derivation")]
    EffectIdMismatch,
    #[error("issuance freeze contribution does not decode")]
    FreezeContribution(#[source] serde_json::Error),
    #[error("issuance freeze effect does not target a lineage")]
    FreezeTargetNotLineage,
    #[error("issuance freeze acquisition is not an exact blast radius")]
    FreezeAcquisitionNotExact,
    #[error("issuance freeze {0:?} does not match the plan it fences")]
    FreezeBindingMismatch(FreezeBindingField),
    #[error("plan body hash could not be derived")]
    PlanBodyHash(#[source] chio_core_types::Error),
    #[error("plan body hash is not a 32-byte hex digest")]
    PlanBodyHashEncoding(#[source] hex::FromHexError),
    #[error("plan hash does not match the plan body")]
    PlanHashMismatch,
}

/// The field of an issuance freeze that must agree with the plan it fences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreezeBindingField {
    Lineage,
    Tenant,
    Action,
    AffectedIds,
    AffectedSetHash,
}

/// The rule a durable response record failed. One variant per rule.
#[derive(Debug, Error)]
pub enum RecordDefect {
    #[error("record body does not decode as a response snapshot")]
    Decode(#[source] serde_json::Error),
    #[error("record body is not the canonical encoding of its snapshot")]
    NotCanonical,
    #[error("record body hash does not match its body")]
    BodyHashMismatch,
    #[error("record tenant does not match its snapshot")]
    TenantMismatch,
    #[error("record action does not match its snapshot")]
    ActionMismatch,
    #[error("record generation does not match its snapshot")]
    GenerationMismatch,
    #[error("record state does not match its snapshot")]
    StateMismatch,
    #[error("record due time does not match its snapshot")]
    DueAtMismatch,
    #[error("snapshot lifecycle is invalid")]
    Lifecycle(#[source] chio_core_types::Error),
    #[error("mutation log is empty")]
    EmptyMutationLog,
    #[error("mutation generation zero has no predecessor")]
    ZeroMutationGeneration,
    #[error("applying snapshot carries no lease expiry")]
    MissingApplyingLease,
}
