//! Experimental dynamic work allocation under one resource owner's authority.
//!
//! This module reserves ceilings, not funds. Its signed records are evidence,
//! never native invocation authority. The owner must protect the SQLite database
//! and clock and qualify receiving hosts, including all their observable channels.
//! Only trusted configuration may call `create_root` or supply receiver enrollment.
//! Native kernels still validate capabilities, account actual costs and own replay.
//! Dispatched allocations are never released by this API, even on a timeout.

mod store;
mod types;

pub use store::DelegationStore;
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
    #[error("delegation store is unavailable")]
    Unavailable,
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, DelegationError>;
