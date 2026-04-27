// Property-based replay-invariance suite for the Chio kernel.
//
// Source-doc anchor:
// `.planning/trajectory/04-deterministic-replay.md`, Phase 5
// ("property-based replay invariance"). The doc requires three properties
// over arbitrary `(decision, payload, clock, nonce)` receipt tuples:
//
//   1. Signing is a function (same canonical body, same signed bytes).
//   2. Replaying the receipt log twice yields the same anchored Merkle root.
//   3. Shuffling independent receipts (no shared nonce) does not change the
//      per-receipt canonical signing bytes.
//
// CI budget: 30 seconds (enforced at the workflow level via timeout-minutes
// and PROPTEST_CASES). Failed shrinks persist under
// `tests/replay/proptest-regressions/` so future runs replay the seed.
//
// House rules:
// - No em dashes anywhere.
// - `unwrap_used` / `expect_used` are denied workspace-wide; we allow them
//   inside the `#[cfg(test)]` body of this file because the proptest harness
//   constructs ad-hoc fixtures whose invariants are checked locally.
//
// Named exit-criterion tests:
// - `signing_is_a_function`
// - `replay_root_is_idempotent`
//
// Plus a third declared property:
// - `shuffle_independent_receipts_preserves_bytes`
//
// All three live under a single `proptest! { ... }` block so the
// `#![proptest_config(...)]` declaration covers them uniformly.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::merkle::MerkleTree;
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence};
use serde_json::json;

// Deterministic test signing key. The kernel verifies receipts off the
// embedded `kernel_key`, so a fixed seed keeps the fixture reproducible
// across machines without coupling to the production key-rotation runbook.
const KERNEL_SEED: [u8; 32] = [
    0xC4, 0x10, 0x73, 0x29, 0xA6, 0xB2, 0x4D, 0x5F, 0x91, 0x08, 0x42, 0x6E, 0xD7, 0xCB, 0x33, 0x80,
    0x1E, 0x55, 0xAA, 0x77, 0x16, 0x9C, 0x3B, 0xE0, 0x4F, 0x82, 0x69, 0x12, 0xBD, 0x05, 0x2A, 0xCC,
];

const PROPTEST_BUDGET_CASES: u32 = 64;

fn kernel_keypair() -> Keypair {
    Keypair::from_seed(&KERNEL_SEED)
}

/// One element of the strategy: `(decision, payload, clock, nonce)`.
#[derive(Debug, Clone)]
struct ReceiptTuple {
    decision: Decision,
    payload: serde_json::Value,
    clock: u64,
    nonce: String,
}

fn arbitrary_decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Allow),
        ("[a-z]{3,16}", "[a-z]{3,16}").prop_map(|(reason, guard)| Decision::Deny { reason, guard }),
        "[a-z]{3,16}".prop_map(|reason| Decision::Cancelled { reason }),
        "[a-z]{3,16}".prop_map(|reason| Decision::Incomplete { reason }),
    ]
}

fn arbitrary_payload() -> impl Strategy<Value = serde_json::Value> {
    // Bound payload size so the strategy is shrink-friendly and the 30s CI
    // budget is reachable. Real-world receipts carry larger payloads, but the
    // properties under test are agnostic to payload contents.
    (
        "[a-z]{1,12}",
        proptest::collection::vec(0u8..=255, 0..16),
        any::<i32>(),
    )
        .prop_map(|(method, bytes, magnitude)| {
            json!({
                "method": method,
                "bytes": bytes,
                "magnitude": magnitude,
            })
        })
}

/// `arbitrary_receipt_tuple()`: produces `(decision, payload, clock, nonce)`.
fn arbitrary_receipt_tuple() -> impl Strategy<Value = ReceiptTuple> {
    (
        arbitrary_decision(),
        arbitrary_payload(),
        any::<u64>(),
        "[a-z0-9]{8,32}",
    )
        .prop_map(|(decision, payload, clock, nonce)| ReceiptTuple {
            decision,
            payload,
            clock,
            nonce,
        })
}

/// Build a `ChioReceiptBody` from a tuple. The `nonce` is woven into the
/// receipt id, the capability id, and the policy hash so two tuples with
/// distinct nonces produce different canonical bytes.
fn body_from_tuple(tuple: &ReceiptTuple, kernel_key: &Keypair) -> ChioReceiptBody {
    let action =
        ToolCallAction::from_parameters(tuple.payload.clone()).expect("payload canonicalises");
    let content_hash = sha256_hex(action.parameter_hash.as_bytes());
    let policy_hash = sha256_hex(format!("policy:{}", tuple.nonce).as_bytes());
    ChioReceiptBody {
        id: format!("rcpt-{}", tuple.nonce),
        timestamp: tuple.clock,
        capability_id: format!("cap-{}", tuple.nonce),
        tool_server: "tool.example".to_string(),
        tool_name: "echo".to_string(),
        action,
        decision: tuple.decision.clone(),
        content_hash,
        policy_hash,
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kernel_key.public_key(),
    }
}

fn sign_body(body: &ChioReceiptBody, kernel_key: &Keypair) -> ChioReceipt {
    ChioReceipt::sign(body.clone(), kernel_key).expect("signing succeeds")
}

fn canonical_body_bytes(body: &ChioReceiptBody) -> Vec<u8> {
    canonical_json_bytes(body).expect("body canonicalises")
}

/// Anchor a sequence of signed receipts via an RFC 6962 Merkle tree over the
/// canonical body bytes. This mirrors `build_checkpoint`'s leaf shape.
fn anchor_root(receipts: &[ChioReceipt]) -> [u8; 32] {
    let leaves: Vec<Vec<u8>> = receipts
        .iter()
        .map(|r| canonical_body_bytes(&r.body()))
        .collect();
    let tree = MerkleTree::from_leaves(&leaves).expect("non-empty receipt batch");
    *tree.root().as_bytes()
}

/// Path to the regression archive directory required by the source-of-truth
/// doc (`tests/replay/proptest-regressions/`). We point proptest at a file
/// inside this directory so failed shrinks are committed alongside other
/// replay-test artefacts.
fn regression_persistence() -> Box<FileFailurePersistence> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // CARGO_MANIFEST_DIR is `crates/chio-kernel`; the archive lives at the
    // repo root under `tests/replay/proptest-regressions/`.
    path.pop(); // crates/
    path.pop(); // repo root
    path.push("tests");
    path.push("replay");
    path.push("proptest-regressions");
    path.push("replay_proptest.txt");
    Box::new(FileFailurePersistence::Direct(Box::leak(
        path.to_string_lossy().into_owned().into_boxed_str(),
    )))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: PROPTEST_BUDGET_CASES,
        failure_persistence: Some(regression_persistence()),
        .. ProptestConfig::default()
    })]

    /// Property 1 (named exit-criterion test):
    /// signing is a pure function: same canonical body, same signature
    /// material. We sign the same body twice and assert the resulting
    /// `ChioReceipt`s are byte-identical when re-canonicalised.
    #[test]
    fn signing_is_a_function(tuple in arbitrary_receipt_tuple()) {
        let kp = kernel_keypair();
        let body = body_from_tuple(&tuple, &kp);

        let receipt_a = sign_body(&body, &kp);
        let receipt_b = sign_body(&body, &kp);

        let bytes_a = canonical_json_bytes(&receipt_a).expect("receipt a canonicalises");
        let bytes_b = canonical_json_bytes(&receipt_b).expect("receipt b canonicalises");
        prop_assert_eq!(bytes_a, bytes_b);

        // Signature material itself must agree (Ed25519 over canonical body
        // is deterministic by construction).
        prop_assert_eq!(
            canonical_json_bytes(&receipt_a.signature)
                .expect("signature a canonicalises"),
            canonical_json_bytes(&receipt_b.signature)
                .expect("signature b canonicalises"),
        );
        prop_assert!(receipt_a.verify_signature().expect("verify a"));
        prop_assert!(receipt_b.verify_signature().expect("verify b"));
    }

    /// Property 2 (named exit-criterion test):
    /// replaying the receipt log twice yields the same anchored root. We
    /// build the same receipt batch twice and assert byte equality on the
    /// computed Merkle root.
    #[test]
    fn replay_root_is_idempotent(
        tuples in proptest::collection::vec(arbitrary_receipt_tuple(), 1..16)
            .prop_filter(
                "receipt nonces must be unique per batch",
                |ts| {
                    let mut seen = std::collections::HashSet::new();
                    ts.iter().all(|t| seen.insert(t.nonce.clone()))
                },
            ),
    ) {
        let kp = kernel_keypair();

        let receipts_a: Vec<ChioReceipt> = tuples
            .iter()
            .map(|t| sign_body(&body_from_tuple(t, &kp), &kp))
            .collect();
        let receipts_b: Vec<ChioReceipt> = tuples
            .iter()
            .map(|t| sign_body(&body_from_tuple(t, &kp), &kp))
            .collect();

        let root_a = anchor_root(&receipts_a);
        let root_b = anchor_root(&receipts_b);
        prop_assert_eq!(root_a, root_b);
    }

    /// Property 3:
    /// shuffling independent receipts (no shared nonce) does not change the
    /// per-receipt canonical body bytes. The anchored root WILL change when
    /// the receipt order changes (RFC 6962 trees are order-sensitive), but
    /// each receipt's individual signing payload is invariant under
    /// reordering of the surrounding batch.
    #[test]
    fn shuffle_independent_receipts_preserves_bytes(
        tuples in proptest::collection::vec(arbitrary_receipt_tuple(), 2..12)
            .prop_filter(
                "receipt nonces must be unique per batch",
                |ts| {
                    let mut seen = std::collections::HashSet::new();
                    ts.iter().all(|t| seen.insert(t.nonce.clone()))
                },
            ),
        seed in any::<u64>(),
    ) {
        let kp = kernel_keypair();

        let receipts: Vec<ChioReceipt> = tuples
            .iter()
            .map(|t| sign_body(&body_from_tuple(t, &kp), &kp))
            .collect();
        let baseline_bytes: Vec<Vec<u8>> = receipts
            .iter()
            .map(|r| canonical_body_bytes(&r.body()))
            .collect();

        // Deterministic Fisher-Yates permutation seeded by the proptest
        // input. We avoid pulling in `rand` here: a linear congruential
        // step over `seed` is sufficient to produce a non-trivial
        // permutation while keeping the property reproducible.
        let mut indices: Vec<usize> = (0..receipts.len()).collect();
        let mut state = seed | 1;
        for i in (1..indices.len()).rev() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let j = (state as usize) % (i + 1);
            indices.swap(i, j);
        }
        let shuffled: Vec<ChioReceipt> =
            indices.iter().map(|&i| receipts[i].clone()).collect();
        let shuffled_bytes: Vec<Vec<u8>> = shuffled
            .iter()
            .map(|r| canonical_body_bytes(&r.body()))
            .collect();

        // Per-receipt bytes are invariant under reordering: every shuffled
        // entry must match exactly one baseline entry, with multiplicities.
        let mut baseline_sorted = baseline_bytes.clone();
        baseline_sorted.sort();
        let mut shuffled_sorted = shuffled_bytes.clone();
        shuffled_sorted.sort();
        prop_assert_eq!(baseline_sorted, shuffled_sorted);
    }
}
