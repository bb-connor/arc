//! Replay corpus helpers for TEE capture graduation.
//!
//! The bless pipeline records redacted frames, deduplicates them by the
//! canonical JSON hash of `invocation`, then re-redacts payload bytes under
//! the current default redactor set before writing fixtures.

#![forbid(unsafe_code)]

pub mod dedupe;
pub mod reredact;

pub use dedupe::{dedupe_last_wins, invocation_hash, DedupedFrame};
pub use reredact::{reredact_default, ReredactedPayload};

/// Errors surfaced by replay corpus normalization helpers.
#[derive(Debug, thiserror::Error)]
pub enum ReplayCorpusError {
    /// Canonical JSON serialization or hashing failed.
    #[error("canonical invocation hash failed: {0}")]
    Canonical(#[from] chio_core::Error),
    /// The default redactor failed closed.
    #[error("default redactor failed: {0}")]
    Redact(#[from] chio_tee::RedactError),
}

/// Crate-local result alias.
pub type Result<T> = std::result::Result<T, ReplayCorpusError>;
