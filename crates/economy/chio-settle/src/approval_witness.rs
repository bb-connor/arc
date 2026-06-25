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

use chio_core::capability::governance::GovernedTransactionIntent;
use serde::Deserialize;

use crate::SettlementError;

/// Reserved key inside [`GovernedTransactionIntent::context`] that commits the
/// concrete settlement economics (chain / payee / token / amount) the approver
/// signed over.
///
/// A `GovernedTransactionIntent` carries no discrete chain / payee / token
/// fields, so without this the witness layer would have to trust a
/// caller-supplied chain / payee / token that the signed intent never bound:
/// a captured approval could then be redirected to a different chain, payee, or
/// token contract. Folding these values into the intent's `context` means
/// `intent.binding_hash()` (the canonical-JSON sha256 the approval token
/// commits to) covers them, so the verifier can DERIVE the settlement identity
/// from what the approver actually signed and reject any caller-supplied
/// binding that disagrees.
pub const CHIO_SETTLEMENT_BINDING_CONTEXT_KEY: &str = "chioSettlementBinding";

/// The concrete settlement economics committed by a [`GovernedTransactionIntent`]
/// via [`CHIO_SETTLEMENT_BINDING_CONTEXT_KEY`].
///
/// Because the intent's `binding_hash()` covers `context`, every field here is
/// part of what the approval token's signature commits to. The witness gate
/// asserts the caller-resolved settlement binding against these values so the
/// witness chain / payee / token / amount are the SIGNED ones, not
/// caller-chosen.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentSettlementBinding {
    /// EIP-155 chain id the approver signed the spend on.
    pub chain_id: u64,
    /// Payee address the approver signed (case-insensitive hex / checksum).
    pub payee_address: String,
    /// Amount in token minor units the approver signed.
    pub amount_minor_units: u128,
    /// Token / currency symbol the approver signed (for example `"USDC"`).
    pub token_symbol: String,
    /// Optional token contract address the approver signed. When present it is
    /// asserted against the caller binding's contract so a captured approval
    /// cannot be redirected to a different token contract on the same chain.
    #[serde(default)]
    pub token_contract: Option<String>,
}

/// Parse the [`IntentSettlementBinding`] committed by an intent, if any.
///
/// Returns `Ok(None)` when the intent carries no `context` object or no
/// settlement-binding key (such an intent must then rely on `max_amount` for
/// its monetary bound, enforced by the witness gate). Returns an error when the
/// key IS present but malformed, so a corrupt commitment fails closed rather
/// than being silently ignored.
pub fn parse_intent_settlement_binding(
    intent: &GovernedTransactionIntent,
) -> Result<Option<IntentSettlementBinding>, SettlementError> {
    let Some(context) = intent.context.as_ref() else {
        return Ok(None);
    };
    let Some(object) = context.as_object() else {
        return Ok(None);
    };
    let Some(value) = object.get(CHIO_SETTLEMENT_BINDING_CONTEXT_KEY) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let parsed: IntentSettlementBinding =
        serde_json::from_value(value.clone()).map_err(|error| {
            SettlementError::Verification(format!(
                "governed intent carries a malformed {CHIO_SETTLEMENT_BINDING_CONTEXT_KEY} \
                 settlement commitment: {error}"
            ))
        })?;
    Ok(Some(parsed))
}

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
        parse_eip155_chain_id, parse_intent_settlement_binding, ApprovalReplayOutcome,
        ApprovalReplayStore, InMemoryApprovalReplayStore, IntentSettlementBinding,
        CHIO_SETTLEMENT_BINDING_CONTEXT_KEY,
    };

    use chio_core::capability::governance::GovernedTransactionIntent;
    use chio_test_support::prelude::*;
    use serde_json::json;

    /// A minimal intent with the given `context` (or none).
    fn intent_with_context(context: Option<serde_json::Value>) -> GovernedTransactionIntent {
        GovernedTransactionIntent {
            id: "intent-1".to_string(),
            server_id: "settlement-server".to_string(),
            tool_name: "transfer_funds".to_string(),
            purpose: "settlement-binding parse test".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context,
        }
    }

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

    #[test]
    fn parses_a_committed_settlement_binding() {
        let intent = intent_with_context(Some(json!({
            CHIO_SETTLEMENT_BINDING_CONTEXT_KEY: {
                "chain_id": 8453,
                "payee_address": "0x2222222222222222222222222222222222222222",
                "amount_minor_units": 150,
                "token_symbol": "USDC",
                "token_contract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            }
        })));
        let parsed = parse_intent_settlement_binding(&intent)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(
            parsed,
            IntentSettlementBinding {
                chain_id: 8453,
                payee_address: "0x2222222222222222222222222222222222222222".to_string(),
                amount_minor_units: 150,
                token_symbol: "USDC".to_string(),
                token_contract: Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".to_string()),
            }
        );
    }

    #[test]
    fn returns_none_when_no_settlement_binding_is_committed() {
        // No context at all.
        assert!(parse_intent_settlement_binding(&intent_with_context(None))
            .test_unwrap()
            .is_none());
        // A context object without the reserved key.
        let other = intent_with_context(Some(json!({ "unrelated": true })));
        assert!(parse_intent_settlement_binding(&other)
            .test_unwrap()
            .is_none());
        // An explicit null under the key.
        let null_key =
            intent_with_context(Some(json!({ CHIO_SETTLEMENT_BINDING_CONTEXT_KEY: null })));
        assert!(parse_intent_settlement_binding(&null_key)
            .test_unwrap()
            .is_none());
    }

    #[test]
    fn rejects_a_malformed_settlement_binding() {
        // The key IS present but the value is missing required fields: this
        // must fail closed, not be silently ignored.
        let intent = intent_with_context(Some(json!({
            CHIO_SETTLEMENT_BINDING_CONTEXT_KEY: { "chain_id": 8453 }
        })));
        let error = parse_intent_settlement_binding(&intent).test_unwrap_err();
        assert!(
            error.to_string().contains("malformed"),
            "a malformed settlement commitment must fail closed, got: {error}"
        );
    }
}
