//! Single-use replay store and chain-id parsing for the C2 (BAC-541)
//! [`crate::payments::VerifiedApproval`] witness.
//!
//! These are the durable seams the exported `verify_governed_approval` path
//! depends on. They live in a sibling module so the witness verification gate
//! in `payments.rs` stays focused on the per-property fail-closed checks while
//! the replay bookkeeping and CAIP-2 chain parsing carry their own tests.
//!
//! The replay store mirrors the kernel's `approval_replay_store`
//! (`chio-kernel::dpop::DpopNonceStore::check_and_insert`): an approval token
//! is single-use, keyed on `(request_id, governed_intent_hash)`, so a second
//! presentation of the same approval is rejected before any lane settles.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::SettlementError;

/// Outcome of [`ApprovalReplayStore::record_if_fresh`].
///
/// Mirrors the kernel replay store's boolean freshness contract: a token
/// presented for the first time is [`ApprovalReplayOutcome::Fresh`]; any
/// later presentation of the same `(request_id, intent_hash)` pair is
/// [`ApprovalReplayOutcome::Replayed`] and settlement MUST fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalReplayOutcome {
    /// The `(request_id, intent_hash)` pair was not present and has now been
    /// recorded.
    Fresh,
    /// The pair was already present. Settlement MUST fail closed.
    Replayed,
}

/// Default hard capacity for retained governed-approval witnesses.
///
/// A misbehaving caller can present an unbounded stream of distinct
/// approvals. The store fails closed once this many entries are retained and
/// relies on the explicit [`ApprovalReplayStore::gc_expired`] path to reopen
/// capacity. Sized to match [`crate::payments::DEFAULT_MAX_EIP3009_NONCE_ENTRIES`].
pub const DEFAULT_MAX_APPROVAL_REPLAY_ENTRIES: usize = 65_536;

/// Single-use replay store for verified governed approvals.
///
/// This is the trust-boundary surface the exported witness path consults
/// BEFORE issuing a [`crate::payments::VerifiedApproval`]. It is keyed on the
/// approval's `(request_id, governed_intent_hash)` pair, mirroring the kernel
/// `approval_replay_store` so the settlement layer enforces the same
/// single-use guarantee the kernel does on its own path: an approval token
/// authorizes exactly one settlement.
///
/// Implementations are `Send + Sync` so callers can hold them behind an
/// `Arc<dyn ApprovalReplayStore>` and share one across settlement workers.
/// `record_if_fresh` is the only mutating entry point and MUST be atomic with
/// respect to concurrent calls, so two parallel presentations of the same
/// approval cannot both observe [`ApprovalReplayOutcome::Fresh`]. The record
/// path never prunes; [`ApprovalReplayStore::gc_expired`] is the only entry
/// point that drops entries, so replay decisions stay decoupled from the wall
/// clock.
pub trait ApprovalReplayStore: Send + Sync {
    /// Record `(request_id, intent_hash)` for replay detection.
    ///
    /// `retain_until_unix_seconds` is the time the entry stays GC-able until
    /// (typically the approval token's `expires_at`). Atomicity: two
    /// concurrent calls with the same key cannot both observe
    /// [`ApprovalReplayOutcome::Fresh`].
    fn record_if_fresh(
        &self,
        request_id: &str,
        intent_hash: &str,
        retain_until_unix_seconds: u64,
    ) -> Result<ApprovalReplayOutcome, SettlementError>;

    /// Sweep entries whose retention bound is below `now_unix_seconds`.
    ///
    /// Returns the number of records pruned. Advisory: failing to run it
    /// never causes a false [`ApprovalReplayOutcome::Fresh`].
    fn gc_expired(&self, now_unix_seconds: u64) -> Result<usize, SettlementError>;

    /// Number of currently retained entries. Used by tests and metrics.
    fn len(&self) -> Result<usize, SettlementError>;

    /// True if no entries are retained.
    fn is_empty(&self) -> Result<bool, SettlementError> {
        Ok(self.len()? == 0)
    }
}

/// Internal map keyed on `(request_id, intent_hash)` whose value is the
/// Unix-seconds retention bound past which the entry is GC-able.
type ApprovalReplayMap = HashMap<(String, String), u64>;

/// Process-local single-use approval replay store.
///
/// Backed by `Mutex<ApprovalReplayMap>`. ON BY DEFAULT for the exported
/// witness path and suitable for single-process deployments; durable
/// deployments back the [`ApprovalReplayStore`] trait with the same SQLite
/// seam the EIP-3009 nonce store uses.
pub struct InMemoryApprovalReplayStore {
    inner: Mutex<ApprovalReplayMap>,
    max_entries: usize,
}

impl Default for InMemoryApprovalReplayStore {
    fn default() -> Self {
        Self::with_max_entries(DEFAULT_MAX_APPROVAL_REPLAY_ENTRIES)
    }
}

impl InMemoryApprovalReplayStore {
    /// Build a fresh store with the default hard capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a fresh store with a custom hard capacity.
    #[must_use]
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ApprovalReplayMap>, SettlementError> {
        self.inner.lock().map_err(|err| {
            SettlementError::InvalidBinding(format!("approval replay store mutex poisoned: {err}"))
        })
    }
}

impl ApprovalReplayStore for InMemoryApprovalReplayStore {
    fn record_if_fresh(
        &self,
        request_id: &str,
        intent_hash: &str,
        retain_until_unix_seconds: u64,
    ) -> Result<ApprovalReplayOutcome, SettlementError> {
        let key = (request_id.to_string(), intent_hash.to_string());
        let mut guard = self.lock()?;

        // Fail-closed: any present entry, even past its retention bound, is
        // treated as a replay. `gc_expired` is the ONLY entry point that
        // drops entries; the record path never prunes so replay decisions
        // stay decoupled from the wall clock.
        if guard.contains_key(&key) {
            return Ok(ApprovalReplayOutcome::Replayed);
        }
        if guard.len() >= self.max_entries {
            return Err(SettlementError::InvalidBinding(format!(
                "approval replay store capacity exceeded: {} retained entries (max {})",
                guard.len(),
                self.max_entries
            )));
        }
        guard.insert(key, retain_until_unix_seconds);
        Ok(ApprovalReplayOutcome::Fresh)
    }

    fn gc_expired(&self, now_unix_seconds: u64) -> Result<usize, SettlementError> {
        let mut guard = self.lock()?;
        let before = guard.len();
        guard.retain(|_, retain_until| *retain_until >= now_unix_seconds);
        Ok(before - guard.len())
    }

    fn len(&self) -> Result<usize, SettlementError> {
        Ok(self.lock()?.len())
    }
}

/// Parse the numeric EIP-155 chain id from a CAIP-2 dispatch `chain_id`
/// string (for example `"eip155:8453"` -> `8453`).
///
/// The dispatch carries the namespaced string while the approval binding
/// carries the bare numeric chain id, so the verifier derives the numeric
/// chain id from the dispatch itself rather than trusting a caller-supplied
/// value. Fails closed on a missing `eip155:` namespace, a non-numeric
/// reference, or surrounding whitespace so a malformed chain string cannot be
/// coerced into a chain the approval did not authorize.
pub fn parse_eip155_chain_id(dispatch_chain_id: &str) -> Result<u64, SettlementError> {
    if dispatch_chain_id.trim() != dispatch_chain_id {
        return Err(SettlementError::InvalidDispatch(format!(
            "dispatch chain id {dispatch_chain_id:?} must not contain surrounding whitespace"
        )));
    }
    let reference = dispatch_chain_id.strip_prefix("eip155:").ok_or_else(|| {
        SettlementError::InvalidDispatch(format!(
            "dispatch chain id {dispatch_chain_id:?} is not an eip155 namespace"
        ))
    })?;
    reference.parse::<u64>().map_err(|error| {
        SettlementError::InvalidDispatch(format!(
            "dispatch chain id {dispatch_chain_id:?} carries a non-numeric eip155 reference: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        parse_eip155_chain_id, ApprovalReplayOutcome, ApprovalReplayStore,
        InMemoryApprovalReplayStore,
    };

    use chio_test_support::prelude::*;

    #[test]
    fn replay_store_records_a_fresh_pair_once() {
        let store = InMemoryApprovalReplayStore::new();
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 0).test_unwrap(),
            ApprovalReplayOutcome::Fresh
        );
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 0).test_unwrap(),
            ApprovalReplayOutcome::Replayed,
            "a second presentation of the same (request, intent) must replay"
        );
    }

    #[test]
    fn replay_store_distinguishes_distinct_pairs() {
        let store = InMemoryApprovalReplayStore::new();
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 0).test_unwrap(),
            ApprovalReplayOutcome::Fresh
        );
        // Same intent hash, different request id: a distinct approval.
        assert_eq!(
            store.record_if_fresh("req-2", "hash-1", 0).test_unwrap(),
            ApprovalReplayOutcome::Fresh
        );
        // Same request id, different intent hash: also distinct.
        assert_eq!(
            store.record_if_fresh("req-1", "hash-2", 0).test_unwrap(),
            ApprovalReplayOutcome::Fresh
        );
    }

    #[test]
    fn replay_store_never_prunes_on_the_record_path() {
        // A present entry past its retention bound is still a replay; only
        // `gc_expired` drops entries.
        let store = InMemoryApprovalReplayStore::new();
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 10).test_unwrap(),
            ApprovalReplayOutcome::Fresh
        );
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 10).test_unwrap(),
            ApprovalReplayOutcome::Replayed,
            "the record path must never prune, even past the retention bound"
        );
        // After GC the entry is gone and a fresh presentation is allowed.
        assert_eq!(store.gc_expired(11).test_unwrap(), 1);
        assert!(store.is_empty().test_unwrap());
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 20).test_unwrap(),
            ApprovalReplayOutcome::Fresh
        );
    }

    #[test]
    fn replay_store_fails_closed_at_capacity() {
        let store = InMemoryApprovalReplayStore::with_max_entries(1);
        assert_eq!(
            store.record_if_fresh("req-1", "hash-1", 0).test_unwrap(),
            ApprovalReplayOutcome::Fresh
        );
        let error = store
            .record_if_fresh("req-2", "hash-2", 0)
            .test_unwrap_err();
        assert!(
            error.to_string().contains("capacity exceeded"),
            "got: {error}"
        );
    }

    #[test]
    fn parses_eip155_chain_id() {
        assert_eq!(parse_eip155_chain_id("eip155:8453").test_unwrap(), 8453);
        assert_eq!(parse_eip155_chain_id("eip155:1").test_unwrap(), 1);
    }

    #[test]
    fn rejects_non_eip155_namespace() {
        let error =
            parse_eip155_chain_id("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp").test_unwrap_err();
        assert!(
            error.to_string().contains("not an eip155 namespace"),
            "got: {error}"
        );
    }

    #[test]
    fn rejects_non_numeric_reference() {
        let error = parse_eip155_chain_id("eip155:base").test_unwrap_err();
        assert!(error.to_string().contains("non-numeric"), "got: {error}");
    }

    #[test]
    fn rejects_surrounding_whitespace() {
        let error = parse_eip155_chain_id(" eip155:8453").test_unwrap_err();
        assert!(
            error.to_string().contains("surrounding whitespace"),
            "got: {error}"
        );
    }
}
