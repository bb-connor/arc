//! Kernel-facing seam for the durable settlement retry/dead-letter sink.
//!
//! The kernel holds an optional `Arc<dyn SettlementRetryStore>`. When one is
//! installed, the settlement routing consumer persists a bounded attempt
//! envelope for retryable outcomes and dead-letters terminal failures. When
//! absent, unresolved outcomes still fail loud (a warning plus a metric),
//! never silently dropped.

/// A persisted settlement-retry attempt row keyed by receipt id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleAttemptRecord {
    /// Receipt whose settlement outcome is pending resolution.
    pub receipt_id: String,
    /// Unix seconds at which the receipt was finalized.
    pub finalized_at: u64,
    /// Attempts consumed so far.
    pub attempts: u32,
    /// Unix seconds before which the driver must not retry this row.
    pub next_visible_at: u64,
    /// Most recent classification reason, for operators.
    pub last_reason: Option<String>,
}

/// Fenced ownership of one durable settlement retry row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleAttemptLease {
    /// Retry row held by this claim.
    pub record: SettleAttemptRecord,
    /// Opaque driver token participating in the ownership fence.
    pub claim_token: String,
    /// Unix seconds at which another driver may reclaim this row.
    pub claim_deadline_unix_secs: u64,
    /// Monotonic storage version participating in the ownership fence.
    pub version: u64,
}

/// Typed, fail-closed errors from the retry sink.
#[derive(Debug, thiserror::Error)]
pub enum SettlementRetryError {
    /// Connection, SQLite, or serialization failure.
    #[error("settlement retry backend error: {0}")]
    Backend(String),
    /// A divergent row already exists for the same key.
    #[error("settlement retry conflict: {0}")]
    Conflict(String),
}

/// Durable sink the settlement routing consumer writes to. Implemented over
/// SQLite in `chio-store-sqlite`.
pub trait SettlementRetryStore: Send + Sync {
    /// Whether retry, dead-letter, and clear outcomes survive process failure.
    fn supports_durable_settlement_retry(&self) -> bool {
        false
    }

    /// Immutable identity of the durable commit domain. Observer wiring
    /// requires this to match the receipt outbox store.
    fn durable_storage_identity(&self) -> Result<Option<chio_core::Hash>, SettlementRetryError> {
        Ok(None)
    }

    /// Load the attempt row for a receipt, if one exists.
    fn load_attempt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<SettleAttemptRecord>, SettlementRetryError>;

    /// Insert the first attempt, accept an exact replay, or advance a pending
    /// row by exactly one attempt. Stale, divergent, and claimed writes fail.
    fn upsert_attempt(&self, record: &SettleAttemptRecord) -> Result<(), SettlementRetryError>;

    /// Insert the initial observer attempt exactly once. A replay of the same
    /// receipt and finalized timestamp returns `Ok(false)` without changing
    /// attempts or backoff. A timestamp mismatch is a conflict.
    fn insert_observer_attempt_if_absent(
        &self,
        _record: &SettleAttemptRecord,
    ) -> Result<bool, SettlementRetryError> {
        Err(SettlementRetryError::Backend(
            "atomic settlement observer attempt insertion is unsupported".to_string(),
        ))
    }

    /// Remove the attempt row for a receipt. Removing an absent row is a no-op.
    fn clear_attempt(&self, receipt_id: &str) -> Result<(), SettlementRetryError>;

    /// Persist a dead-letter record. Returns `Ok(true)` for a new row,
    /// `Ok(false)` for a byte-identical replay, and `Err(Conflict)` when a
    /// divergent row already exists for the receipt.
    fn insert_dead_letter(
        &self,
        record: &chio_settle::DeadLetterRecord,
    ) -> Result<bool, SettlementRetryError>;

    /// Atomically claim the earliest eligible row by `(finalized_at, receipt_id)`.
    /// `next_visible_at <= now` defines eligibility but never reorders eligible
    /// receipts. A live claim on that earliest row blocks every sibling; expired
    /// leases are reclaimable. Claiming increments the row's fencing version in
    /// the same transaction. The bounded result is currently at most one row so
    /// strict global order survives independent drivers.
    fn claim_due_attempts(
        &self,
        _now_unix_secs: u64,
        _claim_deadline_unix_secs: u64,
        _claim_token: &str,
        _limit: usize,
    ) -> Result<Vec<SettleAttemptLease>, SettlementRetryError> {
        Err(SettlementRetryError::Backend(
            "atomic settlement retry claiming is unsupported".to_string(),
        ))
    }

    /// Release a claimed row back to pending with its next monotonic attempt and
    /// visibility. Returns false when the supplied lease lost its fence or has
    /// expired according to the store's trusted clock.
    fn reschedule_claimed_attempt(
        &self,
        _lease: &SettleAttemptLease,
        _next: &SettleAttemptRecord,
    ) -> Result<bool, SettlementRetryError> {
        Err(SettlementRetryError::Backend(
            "fenced settlement retry rescheduling is unsupported".to_string(),
        ))
    }

    /// Delete a successfully reconciled or skipped claimed row. Returns false
    /// when the supplied lease lost its fence or has expired according to the
    /// store's trusted clock.
    fn complete_claimed_attempt(
        &self,
        _lease: &SettleAttemptLease,
    ) -> Result<bool, SettlementRetryError> {
        Err(SettlementRetryError::Backend(
            "fenced settlement retry completion is unsupported".to_string(),
        ))
    }

    /// Atomically insert an exact dead letter for the next attempt and delete
    /// its claimed retry row. A divergent existing dead letter or nonmonotonic
    /// attempt count is a conflict and leaves the retry row claimed. Returns
    /// false when the supplied lease lost its fence or has expired according to
    /// the store's trusted clock.
    fn dead_letter_claimed_attempt(
        &self,
        _lease: &SettleAttemptLease,
        _record: &chio_settle::DeadLetterRecord,
    ) -> Result<bool, SettlementRetryError> {
        Err(SettlementRetryError::Backend(
            "fenced settlement retry dead-lettering is unsupported".to_string(),
        ))
    }

    /// Unclaimed or lease-expired attempt rows whose `next_visible_at` has
    /// passed, ordered by `(finalized_at, receipt_id)`. Drivers must use
    /// `claim_due_attempts`; this read-only inventory is diagnostic and does not
    /// grant ownership.
    fn due_attempts(
        &self,
        now_unix_secs: u64,
        limit: usize,
    ) -> Result<Vec<SettleAttemptRecord>, SettlementRetryError>;
}
