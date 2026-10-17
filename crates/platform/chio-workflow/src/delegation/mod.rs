//! Dynamic work allocation under one resource owner's authority.
//!
//! This module defines the D1 records, signing domains and transition rules.
//! It reserves ceilings, not funds. Its signed records are evidence, never
//! native invocation authority. Production allocation state lives in the
//! serving authority's qualified store,
//! `chio_store_sqlite::delegation_store::SqliteDelegationStore`, which applies
//! these rules inside its fenced transactions. Only trusted configuration may
//! create a root or supply receiver enrollment. Native kernels still validate
//! capabilities, account actual costs and own replay. Dispatched allocations
//! are never released, even on a timeout.

pub mod transition;
mod types;

pub use types::*;

#[derive(Debug, thiserror::Error)]
pub enum DelegationError {
    #[error("invalid work contract: {0}")]
    Invalid(String),
    #[error("delegation signature verification failed")]
    Signature,
    #[error("holder or receiver is not authorized")]
    Authority,
    #[error("delegation exceeds its ancestor or offer bounds")]
    Bounds,
    #[error("allocation or dispatch identity conflicts with durable state")]
    Conflict,
    #[error("work allocation or offer expired")]
    Expired,
    #[error("result does not meet the agreed acceptance predicate")]
    Rejected,
}

pub type Result<T> = std::result::Result<T, DelegationError>;
