// Verdict re-derive for `chio replay` (drives exit code 10).
//
// This file is included into `main.rs` via `include!` (matching the
// pattern used by `cli/replay.rs`, `cli/replay/reader.rs`,
// `cli/replay/verify.rs`, and `cli/replay/merkle.rs`). It provides
// [`rederive_verdict`], the comparator that, for each receipt yielded
// by the replay log reader, runs the current kernel evaluator over the
// receipt's input and compares the freshly-produced decision against
// the receipt's stored decision.
//
// ## Status: comparator wired, live eval deferred to T5/T6
//
// This ticket (M04.P4.T4) lands the public surface the dispatch layer
// will call:
//
// - [`VerdictError`] enumerates the three terminal failure shapes
//   (drift, missing decision, kernel evaluation failure).
// - [`VerdictOutcome`] is the per-receipt structured diff the JSON
//   report (T5) renders.
// - [`EXIT_VERDICT_DRIFT`] pins the canonical exit code (`10`) so the
//   dispatch layer cannot drift silently from the spec.
// - [`compare_verdicts`] is the pure comparator that owns the
//   stored-vs-current diff: it is what the unit tests pin and what T5
//   wires once it can produce a `current_decision` from the live
//   kernel.
//
// [`rederive_verdict`] currently runs an "identity re-derive": it
// extracts the stored decision from the receipt and compares it
// against itself. This always reports `drift == false` because the
// chio-kernel evaluator is invoked from a parallel control flow
// (capability tokens, guard registry, tool-server dispatch) that the
// receipt alone does not carry: T5 lands the receipt -> kernel-input
// reconstruction, T6 wires the live evaluator. Until then, the
// comparator surface is exercised end-to-end by the unit tests, and
// the dispatch layer can already map a drift outcome to exit 10.
//
// Reference: `.planning/trajectory/04-deterministic-replay.md` Phase 4
// task 4 ("Implement verdict re-derive against current build (drives
// exit code 10)") and the canonical exit-code registry in the same
// document.

/// Canonical exit code emitted when any receipt's stored decision
/// disagrees with the decision the current build would produce for
/// the same input. Pinned by the canonical exit-code registry in
/// `.planning/trajectory/04-deterministic-replay.md` Phase 4.
pub const EXIT_VERDICT_DRIFT: i32 = 10;

/// Errors returned by [`rederive_verdict`] for a single receipt.
///
/// `Drift` is the headline failure shape: stored and current decisions
/// disagree. `MissingDecision` means the receipt was structurally
/// parseable but did not carry a decision the comparator can extract
/// (a malformed-receipt rejection that is distinct from the JSON
/// parse failure surfaced by [`super::verify_receipt`]).
/// `EvalFailed` is reserved for the live evaluator: T5/T6 will return
/// this when the kernel call itself errors before producing a
/// decision.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerdictError {
    /// Stored verdict disagrees with the verdict the current build
    /// would produce.
    #[error("verdict drift on receipt {receipt_id:?}: stored={stored:?}, current={current:?}")]
    Drift {
        receipt_id: String,
        stored: String,
        current: String,
    },
    /// Receipt parseable but did not carry a decision label.
    #[error("missing decision in receipt {receipt_id:?}")]
    MissingDecision { receipt_id: String },
    /// Live kernel evaluation returned an error (reserved for T5/T6).
    #[error("kernel evaluation failed for receipt {receipt_id:?}: {detail}")]
    EvalFailed { receipt_id: String, detail: String },
}

/// Per-receipt structured diff returned by [`rederive_verdict`].
///
/// `drift == false` is the success case: stored and current decision
/// labels are byte-equal. `drift == true` accompanies a returned
/// `Err(VerdictError::Drift { .. })` for the consumer that wants the
/// structured shape rather than the formatted message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictOutcome {
    /// Receipt's UUIDv7-style identifier, copied for attribution.
    pub receipt_id: String,
    /// Stored decision label (e.g. `"allow"`, `"deny"`, `"cancelled"`,
    /// `"incomplete"`).
    pub stored_decision: String,
    /// Decision label the current build would produce for the same
    /// input. Equals `stored_decision` until T5/T6 wires the live
    /// kernel.
    pub current_decision: String,
    /// `true` when stored and current decisions disagree.
    pub drift: bool,
}

/// Stable string label for a [`Decision`].
///
/// Matches the `#[serde(tag = "verdict", rename_all = "snake_case")]`
/// representation on `chio_core::receipt::Decision` so the labels the
/// comparator exposes are byte-identical to the receipt wire format.
fn decision_label(decision: &chio_core::receipt::Decision) -> &'static str {
    match decision {
        chio_core::receipt::Decision::Allow => "allow",
        chio_core::receipt::Decision::Deny { .. } => "deny",
        chio_core::receipt::Decision::Cancelled { .. } => "cancelled",
        chio_core::receipt::Decision::Incomplete { .. } => "incomplete",
    }
}

/// Pure comparator: build a [`VerdictOutcome`] (or the [`VerdictError::Drift`]
/// equivalent) from a receipt id and the stored / current decision
/// labels.
///
/// This is the function the unit tests pin and the function T5 will
/// call once it can produce a `current_decision` from the live
/// kernel. Splitting it out from [`rederive_verdict`] lets the drift
/// path be exercised with synthesised inputs without re-deriving a
/// real `ChioReceipt`.
pub fn compare_verdicts(
    receipt_id: &str,
    stored: &str,
    current: &str,
) -> Result<VerdictOutcome, VerdictError> {
    if stored == current {
        Ok(VerdictOutcome {
            receipt_id: receipt_id.to_string(),
            stored_decision: stored.to_string(),
            current_decision: current.to_string(),
            drift: false,
        })
    } else {
        Err(VerdictError::Drift {
            receipt_id: receipt_id.to_string(),
            stored: stored.to_string(),
            current: current.to_string(),
        })
    }
}

/// Re-derive the verdict for a single receipt against the current
/// build.
///
/// For T4 this runs an "identity re-derive" (see module-level docs).
/// The function still validates that the receipt carries a usable
/// receipt id and decision label so the dispatch layer can rely on
/// the `MissingDecision` shape for fail-closed handling once T5/T6
/// wires the live evaluator.
///
/// Errors:
///
/// - [`VerdictError::Drift`] when stored and current labels disagree.
///   `drift == true` on the structured outcome is also surfaced inside
///   the error so callers can render either shape.
/// - [`VerdictError::MissingDecision`] when the receipt's `id` field
///   is empty (a malformed-receipt rejection that the comparator
///   refuses to attribute).
/// - [`VerdictError::EvalFailed`] is reserved for the live kernel
///   path and will be returned by T5/T6 once the evaluator is wired.
pub fn rederive_verdict(
    receipt: &chio_core::receipt::ChioReceipt,
) -> Result<VerdictOutcome, VerdictError> {
    if receipt.id.is_empty() {
        return Err(VerdictError::MissingDecision {
            receipt_id: receipt.id.clone(),
        });
    }
    let stored = decision_label(&receipt.decision);
    // T5/T6 will replace this with a live kernel evaluation against a
    // request reconstructed from the receipt. Until then the
    // comparator runs against the stored decision so the surface is
    // exercised end-to-end.
    let current = stored;
    compare_verdicts(&receipt.id, stored, current)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_verdict_tests {
    use super::*;
    use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
    use chio_core::Keypair;
    use serde_json::json;

    fn body_with_decision(kp: &Keypair, id: &str, decision: Decision) -> ChioReceiptBody {
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-test".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read_file".to_string(),
            action: ToolCallAction {
                parameters: json!({}),
                parameter_hash: "0".repeat(64),
            },
            decision,
            content_hash: "0".repeat(64),
            policy_hash: "0".repeat(64),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
        }
    }

    fn signed_receipt_with(id: &str, decision: Decision) -> ChioReceipt {
        let kp = Keypair::generate();
        let body = body_with_decision(&kp, id, decision);
        ChioReceipt::sign(body, &kp).unwrap()
    }

    #[test]
    fn exit_verdict_drift_constant_is_ten() {
        // Pinned by the canonical exit-code registry in M04 Phase 4
        // task 4. If the registry ever shifts, this test trips first
        // so the dispatch layer cannot drift silently.
        assert_eq!(EXIT_VERDICT_DRIFT, 10);
    }

    #[test]
    fn rederive_matching_verdict_returns_no_drift() {
        let receipt = signed_receipt_with("rcpt-allow-0001", Decision::Allow);
        let outcome = rederive_verdict(&receipt).unwrap();
        assert_eq!(outcome.receipt_id, "rcpt-allow-0001");
        assert_eq!(outcome.stored_decision, "allow");
        assert_eq!(outcome.current_decision, "allow");
        assert!(!outcome.drift, "identity re-derive must not report drift");
    }

    #[test]
    fn rederive_deny_receipt_yields_deny_label() {
        let receipt = signed_receipt_with(
            "rcpt-deny-0001",
            Decision::Deny {
                reason: "quota exhausted".to_string(),
                guard: "budget".to_string(),
            },
        );
        let outcome = rederive_verdict(&receipt).unwrap();
        assert_eq!(outcome.stored_decision, "deny");
        assert_eq!(outcome.current_decision, "deny");
        assert!(!outcome.drift);
    }

    #[test]
    fn rederive_cancelled_receipt_yields_cancelled_label() {
        let receipt = signed_receipt_with(
            "rcpt-cancel-0001",
            Decision::Cancelled {
                reason: "client disconnect".to_string(),
            },
        );
        let outcome = rederive_verdict(&receipt).unwrap();
        assert_eq!(outcome.stored_decision, "cancelled");
    }

    #[test]
    fn rederive_incomplete_receipt_yields_incomplete_label() {
        let receipt = signed_receipt_with(
            "rcpt-incomplete-0001",
            Decision::Incomplete {
                reason: "timeout".to_string(),
            },
        );
        let outcome = rederive_verdict(&receipt).unwrap();
        assert_eq!(outcome.stored_decision, "incomplete");
    }

    #[test]
    fn rederive_rejects_receipt_with_empty_id() {
        // A receipt parseable as JSON but missing the `id` field
        // collapses into the MissingDecision shape, which the dispatch
        // layer maps separately from drift.
        let receipt = signed_receipt_with("", Decision::Allow);
        let err = rederive_verdict(&receipt).unwrap_err();
        match err {
            VerdictError::MissingDecision { receipt_id } => {
                assert_eq!(receipt_id, "");
            }
            other => panic!("expected MissingDecision, got {other:?}"),
        }
    }

    #[test]
    fn compare_verdicts_detects_allow_to_deny_drift() {
        let err = compare_verdicts("rcpt-drift-0001", "allow", "deny").unwrap_err();
        match err {
            VerdictError::Drift {
                receipt_id,
                stored,
                current,
            } => {
                assert_eq!(receipt_id, "rcpt-drift-0001");
                assert_eq!(stored, "allow");
                assert_eq!(current, "deny");
            }
            other => panic!("expected Drift, got {other:?}"),
        }
    }

    #[test]
    fn compare_verdicts_detects_deny_to_allow_drift() {
        // Symmetry: drift in the deny -> allow direction is just as
        // fatal as allow -> deny. Both must trip the same shape.
        let err = compare_verdicts("rcpt-drift-0002", "deny", "allow").unwrap_err();
        assert!(matches!(err, VerdictError::Drift { .. }));
    }

    #[test]
    fn compare_verdicts_matching_labels_succeeds() {
        let outcome = compare_verdicts("rcpt-ok-0001", "allow", "allow").unwrap();
        assert!(!outcome.drift);
        assert_eq!(outcome.stored_decision, "allow");
        assert_eq!(outcome.current_decision, "allow");
    }

    #[test]
    fn drift_error_message_includes_both_decisions() {
        // The dispatch layer formats this via Display when emitting a
        // human-readable replay summary; pin the shape so the JSON
        // report (T5) and the summary stay aligned.
        let err = VerdictError::Drift {
            receipt_id: "rcpt-x".to_string(),
            stored: "allow".to_string(),
            current: "deny".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("rcpt-x"), "message must attribute receipt: {msg}");
        assert!(msg.contains("allow"), "message must show stored: {msg}");
        assert!(msg.contains("deny"), "message must show current: {msg}");
    }

    #[test]
    fn missing_decision_error_message_attributes_receipt() {
        let err = VerdictError::MissingDecision {
            receipt_id: "rcpt-malformed".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("rcpt-malformed"), "message: {msg}");
    }

    #[test]
    fn eval_failed_error_carries_detail() {
        let err = VerdictError::EvalFailed {
            receipt_id: "rcpt-y".to_string(),
            detail: "kernel panic in guard registry".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("rcpt-y"));
        assert!(msg.contains("kernel panic in guard registry"));
    }

    #[test]
    fn outcome_clone_and_eq_round_trip() {
        // PartialEq + Clone are part of the stable surface that T5
        // relies on for emitting the JSON report; pin the shape so
        // refactors cannot silently drop the derives.
        let a = VerdictOutcome {
            receipt_id: "r".to_string(),
            stored_decision: "allow".to_string(),
            current_decision: "allow".to_string(),
            drift: false,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
