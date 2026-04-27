// Receipt signature re-verifier for `chio replay`.
//
// This file is included into `main.rs` via `include!` (matching the
// pattern used by `cli/replay.rs` and `cli/replay/reader.rs`). It
// provides [`verify_receipt`], a thin wrapper over
// [`chio_core::receipt::ChioReceipt::verify_signature`], that returns a
// [`VerifyOutcome`] describing whether the embedded signature
// re-verifies against the receipt's `kernel_key`.
//
// The replay command calls this once per receipt yielded by the log
// reader. Per the canonical exit-code registry (M04 Phase 4 task 3 of
// `.planning/trajectory/04-deterministic-replay.md`):
//
// - `ok == true`  -> contributes nothing to the exit verdict.
// - `ok == false` -> drives exit code `20` (bad signature) once any
//   downstream divergence reporter (M04.P4.T4 / T5) wires the verdict
//   bus. T3 owns the per-receipt result; the orchestration is layered
//   on top by later tickets.
//
// `VerifyOutcome::error` carries a human-readable note for the malformed
// JSON / missing-fields case so the JSON report (T5) can surface
// failures without re-walking the receipt.
//
// Reference: `.planning/trajectory/04-deterministic-replay.md` Phase 4
// task 3 ("Implement signature re-verify and incremental Merkle root
// recompute") and the "chio replay subcommand surface" section.

/// Canonical exit code emitted when any receipt fails signature
/// re-verification. Surfaced as a constant so the dispatch layer (T4)
/// can map a `VerifyOutcome { ok: false, .. }` to the documented exit
/// without hard-coding the magic number twice.
pub const EXIT_BAD_SIGNATURE: i32 = 20;

/// Per-receipt outcome from [`verify_receipt`].
///
/// Three terminal shapes:
///
/// - `ok == true` and `error.is_none()`: the receipt deserialized
///   successfully and its signature verified against the embedded
///   `kernel_key`.
/// - `ok == false` and `error.is_some()`: the receipt was structurally
///   parseable but either failed signature verification (`error =
///   "signature mismatch"`) or hit a kernel-side verifier error
///   (`error = <error.to_string()>`). The signer key is still surfaced
///   when present so the divergence report (T5) can attribute the
///   failure.
/// - `ok == false` and `signer_key_hex == ""`: the input was not a
///   well-formed `ChioReceipt`. `error` carries the deserialization
///   failure text. This shape contributes to the malformed-JSON exit
///   (`30`) at the dispatch layer rather than to bad-signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOutcome {
    /// Whether the embedded signature verified against the embedded
    /// `kernel_key`. `false` means signature mismatch, kernel-side
    /// verifier error, or that the receipt could not be parsed in the
    /// first place; consult `error` and `signer_key_hex` to disambiguate.
    pub ok: bool,
    /// Lowercase hex of the receipt's `kernel_key`. Empty when the input
    /// could not be parsed as a `ChioReceipt`.
    pub signer_key_hex: String,
    /// Human-readable failure detail. `None` only when `ok == true`.
    pub error: Option<String>,
}

/// Re-verify the embedded signature on a single receipt.
///
/// `value` is a `serde_json::Value` previously yielded by the replay
/// log reader. The function deserializes it into a
/// [`chio_core::receipt::ChioReceipt`], extracts the kernel key for
/// attribution, and calls
/// [`ChioReceipt::verify_signature`](chio_core::receipt::ChioReceipt::verify_signature).
///
/// The function never returns a `Result`: every failure mode is captured
/// inside the [`VerifyOutcome`] so callers can drive exit-code policy
/// off the outcome shape rather than bubbling errors. This matches the
/// "fail-closed but never panic mid-stream" invariant the replay
/// command relies on for stable JSON-report output.
pub fn verify_receipt(value: &serde_json::Value) -> VerifyOutcome {
    let receipt: chio_core::receipt::ChioReceipt = match serde_json::from_value(value.clone()) {
        Ok(r) => r,
        Err(error) => {
            return VerifyOutcome {
                ok: false,
                signer_key_hex: String::new(),
                error: Some(format!("malformed receipt JSON: {error}")),
            };
        }
    };

    let signer_key_hex = receipt.kernel_key.to_hex();

    match receipt.verify_signature() {
        Ok(true) => VerifyOutcome {
            ok: true,
            signer_key_hex,
            error: None,
        },
        Ok(false) => VerifyOutcome {
            ok: false,
            signer_key_hex,
            error: Some("signature mismatch".to_string()),
        },
        Err(error) => VerifyOutcome {
            ok: false,
            signer_key_hex,
            error: Some(format!("verifier error: {error}")),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_verify_tests {
    use super::*;
    use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
    use chio_core::Keypair;
    use serde_json::json;

    fn sample_body(kp: &Keypair) -> ChioReceiptBody {
        ChioReceiptBody {
            id: "rcpt-test-0001".to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-test".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read_file".to_string(),
            action: ToolCallAction {
                parameters: json!({}),
                parameter_hash: "0".repeat(64),
            },
            decision: Decision::Allow,
            content_hash: "0".repeat(64),
            policy_hash: "0".repeat(64),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
        }
    }

    fn signed_receipt() -> ChioReceipt {
        let kp = Keypair::generate();
        let body = sample_body(&kp);
        ChioReceipt::sign(body, &kp).unwrap()
    }

    #[test]
    fn verify_receipt_accepts_good_signature() {
        let receipt = signed_receipt();
        let value = serde_json::to_value(&receipt).unwrap();

        let outcome = verify_receipt(&value);
        assert!(outcome.ok, "good signature must verify: {outcome:?}");
        assert!(outcome.error.is_none(), "no error for good signature");
        assert_eq!(outcome.signer_key_hex.len(), 64, "ed25519 key is 32 bytes");
    }

    #[test]
    fn verify_receipt_rejects_tampered_signature() {
        let receipt = signed_receipt();
        let mut value = serde_json::to_value(&receipt).unwrap();
        // Flip a byte in the canonical content_hash so the signed body
        // no longer matches the signature. The kernel_key field is left
        // untouched so the function can still attribute the failure.
        value["content_hash"] = json!("ff".repeat(32));

        let outcome = verify_receipt(&value);
        assert!(!outcome.ok, "tampered receipt must not verify");
        assert!(outcome.error.is_some(), "bad signature carries an error note");
        assert_eq!(
            outcome.signer_key_hex.len(),
            64,
            "signer key still attributed on bad signature",
        );
    }

    #[test]
    fn verify_receipt_rejects_malformed_json() {
        // A bare object with none of the required ChioReceipt fields.
        // serde_json::from_value should fail before any signature check.
        let value = json!({"id": "no-signature-here"});

        let outcome = verify_receipt(&value);
        assert!(!outcome.ok, "malformed JSON must not verify");
        assert_eq!(
            outcome.signer_key_hex, "",
            "signer_key_hex empty when receipt cannot be parsed",
        );
        let error = outcome.error.expect("malformed JSON carries an error");
        assert!(
            error.contains("malformed receipt JSON"),
            "error must explain the parse failure, got: {error}",
        );
    }

    #[test]
    fn exit_bad_signature_constant_is_twenty() {
        // Pinned by the canonical exit-code registry in M04 Phase 4 task
        // 3. If the registry ever shifts, this test trips first so the
        // dispatch layer (T4) cannot drift silently.
        assert_eq!(EXIT_BAD_SIGNATURE, 20);
    }
}
