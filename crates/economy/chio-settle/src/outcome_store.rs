use thiserror::Error;

use crate::hook::{SettlementFailureReason, SettlementSkipReason};
use crate::retry::RetryPolicy;

/// Normalized outcome accepted by durable settlement routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementRoutingInput {
    /// The hook durably accepted the observation.
    Accepted,
    /// The observation legitimately requires no settlement work.
    Skipped { reason: SettlementSkipReason },
    /// The observation may succeed when replayed.
    Retryable { reason: SettlementFailureReason },
    /// The observation must terminate without replay.
    Permanent { reason: SettlementFailureReason },
}

/// Lease and row version required to commit a settlement transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementAttemptClaim {
    /// Receipt bound to the claimed row.
    pub receipt_id: String,
    /// Version incremented when the claim was acquired.
    pub row_version: u64,
    /// Unpredictable token required by the outcome CAS.
    pub lease_token: String,
    /// Exclusive lease deadline in milliseconds.
    pub lease_until_ms: u64,
}

/// Result of atomically recording a claimed settlement outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementRoute {
    /// The claimed row was removed without further work.
    NoAction,
    /// The claimed row was rescheduled for retry.
    RetryScheduled {
        /// Persisted attempt number for the next invocation.
        attempt: u32,
        /// Earliest visibility time in milliseconds.
        next_visible_at_ms: u64,
    },
    /// The failure was committed as terminal.
    DeadLettered {
        /// Total hook invocations represented by the dead letter.
        attempts: u32,
    },
}

/// Bounded class for settlement routing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementRouteErrorClass {
    /// Persistence backend failure.
    Backend,
    /// Lease, version, or terminal-state conflict.
    Conflict,
    /// Invalid or overflowing durable data.
    InvalidRecord,
}

/// Failure returned by the durable settlement router.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SettlementRouteError {
    #[error("settlement routing backend failure: {detail}")]
    Backend { detail: String },
    #[error("settlement routing conflict: {detail}")]
    Conflict { detail: String },
    #[error("invalid settlement routing record: {detail}")]
    InvalidRecord { detail: String },
}

impl SettlementRouteError {
    /// Return the stable class suitable for bounded telemetry.
    #[must_use]
    pub const fn class(&self) -> SettlementRouteErrorClass {
        match self {
            Self::Backend { .. } => SettlementRouteErrorClass::Backend,
            Self::Conflict { .. } => SettlementRouteErrorClass::Conflict,
            Self::InvalidRecord { .. } => SettlementRouteErrorClass::InvalidRecord,
        }
    }
}

/// Atomic leased store for settlement outcomes.
pub trait SettlementOutcomeStore: Send + Sync {
    /// Claim one due row by receipt id, or return `None` when a live lease owns it.
    fn claim_receipt(
        &self,
        receipt_id: &str,
        worker_id: &str,
        now_ms: u64,
        lease_ms: u64,
    ) -> Result<Option<SettlementAttemptClaim>, SettlementRouteError>;

    /// Claim a bounded due batch using the same lease and version rules.
    fn claim_due(
        &self,
        worker_id: &str,
        now_ms: u64,
        lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<SettlementAttemptClaim>, SettlementRouteError>;

    /// Atomically commit an outcome for an exact, unexpired claim.
    fn record_claimed_outcome(
        &self,
        claim: &SettlementAttemptClaim,
        finalized_at: u64,
        outcome: &SettlementRoutingInput,
        policy: RetryPolicy,
        observed_at_ms: u64,
    ) -> Result<SettlementRoute, SettlementRouteError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_store_error_classes_are_bounded() {
        let cases = [
            (
                SettlementRouteError::Backend {
                    detail: "db unavailable".to_string(),
                },
                SettlementRouteErrorClass::Backend,
            ),
            (
                SettlementRouteError::Conflict {
                    detail: "stale lease".to_string(),
                },
                SettlementRouteErrorClass::Conflict,
            ),
            (
                SettlementRouteError::InvalidRecord {
                    detail: "negative counter".to_string(),
                },
                SettlementRouteErrorClass::InvalidRecord,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.class(), expected);
        }
    }

    #[test]
    fn outcome_store_trait_is_object_safe() {
        fn accepts_trait_object(_store: &dyn SettlementOutcomeStore) {}

        let _ = accepts_trait_object;
    }
}
