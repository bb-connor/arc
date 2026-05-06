//! W2.3 negative conformance test: stale witness-lane fallback.
//!
//! Threat: the public-witness lane (Rekor or OTS) goes down. The
//! verifier still holds a previously-witnessed receipt for batch B0
//! and a brand-new pending batch B1.
//!
//! Required behaviour, per `WitnessPolicy`:
//!
//! - `require_public_witness: true` and B1 is `WitnessState::Pending`
//!   -> reject (lane is required, no receipt).
//! - `require_public_witness: true` and B0 is `WitnessState::Stale`
//!   with `now - last_verified > stale_window_seconds` -> reject.
//! - `require_public_witness: true` and B0 is `WitnessState::Stale`
//!   with `now - last_verified <= stale_window_seconds` -> accept
//!   (already-witnessed receipt remains usable through a brief lane
//!   outage).
//! - `require_public_witness: false` -> accept all states (advisory
//!   mode for partner integrations that have not yet wired the lane).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_anchor::{
    build_anchor_batch, verify_anchor_batch_with_witness_policy, AnchorBatchWitness,
    AnchorBatchWitnessKind, WitnessPolicy, WitnessReceipt, WitnessState,
};
use chio_core::hashing::Hash;
use chio_core::Keypair;

fn make_batch(state: WitnessState) -> chio_anchor::AnchorBatch {
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:placeholder".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch = build_anchor_batch(
        vec![
            "ck-stale-1".to_string(),
            "ck-stale-2".to_string(),
            "ck-stale-3".to_string(),
        ],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap();
    batch.body.witness_state = state;
    chio_anchor::AnchorBatch::sign(batch.body, &kp).unwrap()
}

fn fresh_witnessed_state(batch: &chio_anchor::AnchorBatch, observed_at: i64) -> WitnessState {
    WitnessState::Witnessed {
        receipt: WitnessReceipt {
            kind: AnchorBatchWitnessKind::Rekor,
            external_uuid: "uuid-prior-witness".to_string(),
            published_at: observed_at,
            inclusion_proof: vec![1, 2, 3, 4],
            witness_root: batch.body.tree_root,
            body_hash: chio_anchor::batch_body_hash(batch).unwrap(),
        },
        observed_at,
    }
}

#[test]
fn require_public_witness_rejects_pending_batch() {
    let batch = make_batch(WitnessState::Pending);
    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60 * 60,
    };
    let err = verify_anchor_batch_with_witness_policy(&batch, &policy, 1_700_000_100)
        .expect_err("Pending batch must be rejected when require_public_witness=true");
    let msg = err.to_string();
    assert!(
        msg.contains("Pending state") || msg.contains("PendingNotAllowed"),
        "expected Pending rejection, got: {msg}"
    );
}

#[test]
fn require_public_witness_rejects_stale_outside_window() {
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:placeholder".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch = build_anchor_batch(
        vec!["ck-S-1".to_string(), "ck-S-2".to_string()],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap();
    batch.body.witness_state = WitnessState::Stale {
        last_verified: 1_700_000_000,
        error: "rekor 503".to_string(),
    };
    let signed = chio_anchor::AnchorBatch::sign(batch.body, &kp).unwrap();

    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60,
    };
    // 500 seconds > 60 second stale window
    let err = verify_anchor_batch_with_witness_policy(&signed, &policy, 1_700_000_500)
        .expect_err("stale beyond window must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("stale window exceeded") || msg.contains("StaleWindowExceeded"),
        "expected stale-window rejection, got: {msg}"
    );
}

#[test]
fn require_public_witness_accepts_already_witnessed_during_lane_outage() {
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:uuid-prior".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let unsigned = build_anchor_batch(
        vec!["ck-W-1".to_string(), "ck-W-2".to_string()],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap();

    // Build a Witnessed state that points at this batch's tree_root
    // and body_hash so the WitnessReceiptRootMismatch invariant
    // holds.
    let prior_state = fresh_witnessed_state(&unsigned, 1_700_000_010);
    let mut body = unsigned.body.clone();
    body.witness_state = prior_state;
    let signed = chio_anchor::AnchorBatch::sign(body, &kp).unwrap();

    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60 * 60,
    };
    verify_anchor_batch_with_witness_policy(&signed, &policy, 1_700_000_500)
        .expect("already-witnessed receipt must remain usable");
}

#[test]
fn advisory_mode_accepts_pending_and_stale() {
    let pending = make_batch(WitnessState::Pending);
    let stale = make_batch(WitnessState::Stale {
        last_verified: 1_700_000_000,
        error: "rekor sigstore.dev unreachable".to_string(),
    });
    let policy = WitnessPolicy {
        require_public_witness: false,
        stale_window_seconds: 60,
    };
    verify_anchor_batch_with_witness_policy(&pending, &policy, 1_700_000_500)
        .expect("advisory mode accepts pending");
    verify_anchor_batch_with_witness_policy(&stale, &policy, 1_700_000_500)
        .expect("advisory mode accepts stale");
}

#[test]
fn require_public_witness_rejects_already_witnessed_with_root_mismatch() {
    // Defence-in-depth: even when the policy is satisfied by
    // WitnessState::Witnessed, the receipt's witness_root must equal
    // the batch's tree_root. An adversary who substitutes the
    // tree_root post-witness gets caught here.
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:uuid-prior".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let unsigned = build_anchor_batch(
        vec!["ck-RM-1".to_string(), "ck-RM-2".to_string()],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap();

    let receipt = WitnessReceipt {
        kind: AnchorBatchWitnessKind::Rekor,
        external_uuid: "uuid-honest".to_string(),
        published_at: 1_700_000_010,
        inclusion_proof: vec![],
        // Adversary forges the receipt to point at a different root
        // (sha256("evil")) while the batch's actual tree_root is the
        // honest computed root.
        witness_root: chio_core::hashing::sha256(b"evil-substituted-root"),
        body_hash: chio_anchor::batch_body_hash(&unsigned).unwrap(),
    };
    let mut body = unsigned.body.clone();
    body.witness_state = WitnessState::Witnessed {
        receipt,
        observed_at: 1_700_000_010,
    };
    let signed = chio_anchor::AnchorBatch::sign(body, &kp).unwrap();

    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60 * 60,
    };
    let err = verify_anchor_batch_with_witness_policy(&signed, &policy, 1_700_000_500)
        .expect_err("witness root must match batch tree_root");
    let msg = err.to_string();
    assert!(
        msg.contains("does not match") || msg.contains("WitnessReceiptRootMismatch"),
        "expected witness-root mismatch, got: {msg}"
    );
}
