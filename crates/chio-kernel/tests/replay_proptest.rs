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
// `signing_is_a_function` lives in its own `proptest! { ... }` block with a
// raised `cases` budget (`SIGNING_FUNCTION_CASES`); the other two share the
// standard `PROPTEST_BUDGET_CASES` block. Splitting the macro invocations is
// the only way to per-test-tune the case count, since `proptest!` only
// honours the `#![proptest_config(...)]` inner attribute at block scope.

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

/// Higher case count for `signing_is_a_function`. Signing is the cheapest
/// property to evaluate (one body, one keypair, no Merkle anchoring) so we
/// can afford a denser sweep without breaching the 30s CI budget.
const SIGNING_FUNCTION_CASES: u32 = 256;

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

/// Edge-case payload strategy biased toward boundary shapes that have caused
/// canonical-bytes regressions in the past: empty maps, all-zero byte vectors,
/// extreme integer magnitudes, and unicode-free single-character methods.
fn edge_case_payload() -> impl Strategy<Value = serde_json::Value> {
    prop_oneof![
        // Empty payload (no fields).
        Just(json!({})),
        // All-zero byte vector at maximum bounded size.
        Just(json!({
            "method": "z",
            "bytes": vec![0u8; 16],
            "magnitude": 0,
        })),
        // Maximum-magnitude i32 (positive and negative).
        Just(json!({
            "method": "max",
            "bytes": Vec::<u8>::new(),
            "magnitude": i32::MAX,
        })),
        Just(json!({
            "method": "min",
            "bytes": Vec::<u8>::new(),
            "magnitude": i32::MIN,
        })),
        // Single-element byte vector with the high bit set (canonical-JSON
        // numeric encoding has previously regressed on values >= 128).
        Just(json!({
            "method": "h",
            "bytes": vec![0xFFu8],
            "magnitude": 1,
        })),
    ]
}

/// `signing_edge_tuple()`: tuples that exercise boundary conditions of the
/// signing surface area. The strategy mixes random tuples with a curated set
/// of edge cases (zero clock, max-u64 clock, empty/min-length nonce,
/// max-length nonce, and the edge-case payload shapes above).
fn signing_edge_tuple() -> impl Strategy<Value = ReceiptTuple> {
    prop_oneof![
        // 60% of the budget: random tuples (the original strategy).
        6 => arbitrary_receipt_tuple(),
        // Zero clock + minimal nonce.
        1 => (arbitrary_decision(), edge_case_payload(), Just(0u64), "[a-z]{1}").prop_map(
            |(decision, payload, clock, nonce)| ReceiptTuple { decision, payload, clock, nonce },
        ),
        // Max u64 clock + maximum-length nonce.
        1 => (
            arbitrary_decision(),
            edge_case_payload(),
            Just(u64::MAX),
            "[a-z0-9]{32}",
        )
            .prop_map(|(decision, payload, clock, nonce)| ReceiptTuple {
                decision,
                payload,
                clock,
                nonce,
            }),
        // Boundary clocks: 1, i64::MAX as u64, u64::MAX - 1.
        1 => (
            arbitrary_decision(),
            arbitrary_payload(),
            prop_oneof![Just(1u64), Just(i64::MAX as u64), Just(u64::MAX - 1)],
            "[a-z0-9]{8,32}",
        )
            .prop_map(|(decision, payload, clock, nonce)| ReceiptTuple {
                decision,
                payload,
                clock,
                nonce,
            }),
        // Edge payloads paired with random clocks/nonces.
        1 => (arbitrary_decision(), edge_case_payload(), any::<u64>(), "[a-z0-9]{8,32}").prop_map(
            |(decision, payload, clock, nonce)| ReceiptTuple { decision, payload, clock, nonce },
        ),
    ]
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

// Property 1 lives in its own `proptest!` block so we can dial up the case
// count specifically for `signing_is_a_function` without slowing the other
// two properties (which build full Merkle trees per case). Signing is the
// cheapest property to evaluate, so the denser sweep stays well inside the
// 30s CI budget.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: SIGNING_FUNCTION_CASES,
        failure_persistence: Some(regression_persistence()),
        .. ProptestConfig::default()
    })]

    /// Property 1 (named exit-criterion test):
    /// signing is a pure function: same canonical body, same signed bytes.
    /// We sign the same body three times across two independently-derived
    /// keypair instances and assert byte equality across every pairing.
    /// The strategy is biased toward edge cases (boundary clocks, empty and
    /// all-zero payloads, min and max nonce lengths) on top of the random
    /// `arbitrary_receipt_tuple` baseline.
    #[test]
    fn signing_is_a_function(tuple in signing_edge_tuple()) {
        // Two keypair instances from the same seed must behave identically.
        // This catches regressions where signer state (e.g. RNG) leaks into
        // the signature bytes.
        let kp = kernel_keypair();
        let kp_twin = kernel_keypair();
        prop_assert_eq!(kp.public_key(), kp_twin.public_key());

        let body = body_from_tuple(&tuple, &kp);

        // Triple-sign across both keypair instances. Three signatures over
        // the same body must produce identical bytes; if any pair drifts,
        // signing is not a pure function of (body, key).
        let receipt_a = sign_body(&body, &kp);
        let receipt_b = sign_body(&body, &kp);
        let receipt_c = sign_body(&body, &kp_twin);

        let bytes_a = canonical_json_bytes(&receipt_a).expect("receipt a canonicalises");
        let bytes_b = canonical_json_bytes(&receipt_b).expect("receipt b canonicalises");
        let bytes_c = canonical_json_bytes(&receipt_c).expect("receipt c canonicalises");
        prop_assert_eq!(&bytes_a, &bytes_b);
        prop_assert_eq!(&bytes_a, &bytes_c);

        // Raw signature bytes must agree exactly. We compare both the
        // canonical-JSON encoding of the signature container and the
        // structural equality of the signature itself, so a bug that
        // reordered hex chars or changed the encoding would still fail.
        let sig_a = canonical_json_bytes(&receipt_a.signature)
            .expect("signature a canonicalises");
        let sig_b = canonical_json_bytes(&receipt_b.signature)
            .expect("signature b canonicalises");
        let sig_c = canonical_json_bytes(&receipt_c.signature)
            .expect("signature c canonicalises");
        prop_assert_eq!(&sig_a, &sig_b);
        prop_assert_eq!(&sig_a, &sig_c);

        // Verification must succeed for every signed copy.
        prop_assert!(receipt_a.verify_signature().expect("verify a"));
        prop_assert!(receipt_b.verify_signature().expect("verify b"));
        prop_assert!(receipt_c.verify_signature().expect("verify c"));

        // Canonical body bytes must round-trip independent of which receipt
        // we project from: the body is the input to signing and must remain
        // a fixed point.
        let body_bytes_a = canonical_body_bytes(&receipt_a.body());
        let body_bytes_b = canonical_body_bytes(&receipt_b.body());
        let body_bytes_direct = canonical_body_bytes(&body);
        prop_assert_eq!(&body_bytes_a, &body_bytes_b);
        prop_assert_eq!(&body_bytes_a, &body_bytes_direct);

        // The action's parameter hash must verify against its own canonical
        // bytes. This guards against a regression where signing accepted a
        // body with a stale `parameter_hash`.
        prop_assert!(
            receipt_a
                .body()
                .action
                .verify_hash()
                .expect("parameter hash verifies")
        );
    }
}

// Properties 2 and 3 share the standard budget: each case builds a full
// Merkle tree over a batch of receipts, so we keep the case count modest.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: PROPTEST_BUDGET_CASES,
        failure_persistence: Some(regression_persistence()),
        .. ProptestConfig::default()
    })]

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
