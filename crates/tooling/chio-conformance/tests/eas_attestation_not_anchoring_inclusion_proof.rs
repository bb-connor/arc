//! Negative conformance test: an external EAS/SAS attestation is not an
//! anchoring inclusion proof.
//!
//! Threat: an integrator carries an external standard (an Ethereum/Solana
//! Attestation Service record) that *asserts* a Merkle root was anchored,
//! and tries to use that attestation in place of an inclusion proof. A naive
//! verifier that "reads back" the attested root and trusts the attester
//! signature would admit settlement state that was never actually committed
//! on-chain or recomputed.
//!
//! Invariant (recompute is the SOLE proof lane): the chio-web3 readback lane
//! `verify_anchor_inclusion_proof` (the verifier-side mirror of the on-chain
//! `getRoot` / `verifyInclusionDetailed` calls) takes the committed Merkle
//! root only from the kernel-signed checkpoint statement, recomputes the
//! receipt leaf from the canonical receipt body, and re-walks the audit path
//! to that root. It never trusts a producer-asserted or witnessed value.
//!
//! This test proves three fail-closed facts:
//!
//! 1. An EAS/SAS attestation envelope is not admissible as an anchoring
//!    inclusion proof: it does not even deserialize as
//!    `chio.anchor-inclusion-proof.v1`.
//! 2. A genuine recomputing proof passes the lane (the lane is the gate).
//! 3. Splicing the attestation's asserted root into the proof fails closed
//!    at every layer: the inclusion root must equal the kernel-signed
//!    checkpoint root, and rewriting the checkpoint root to the attested
//!    value breaks the kernel signature. The attested root is never honored.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_web3::anchors::{verify_anchor_inclusion_proof, AnchorInclusionProof};
use serde_json::{json, Value};

/// A genuine inclusion proof whose committed root recomputes from the receipt
/// leaf and a kernel-signed checkpoint statement. This is the only shape the
/// readback lane admits.
const ANCHOR_INCLUSION_PROOF_FIXTURE: &str =
    include_str!("../../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json");

/// A 32-byte Merkle root an external EAS/SAS attestation merely *asserts*. It
/// is bound to no kernel-signed checkpoint commitment and no recomputing
/// audit path, so the readback lane must refuse to honor it.
const ATTESTED_ROOT: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

fn fixture_value() -> Value {
    serde_json::from_str(ANCHOR_INCLUSION_PROOF_FIXTURE).expect("anchor inclusion fixture parses")
}

/// Model of an external EAS/SAS attestation: an attester-signed statement that
/// asserts a Merkle root was anchored at a checkpoint. It carries no receipt,
/// no inclusion proof, and no kernel-signed checkpoint statement.
fn eas_sas_attestation() -> Value {
    json!({
        "schema": "eas.attestation.v1",
        "uid": "0x9c8b7a6f5e4d3c2b1a09f8e7d6c5b4a3928170615243342516071839405a6b7c",
        "schema_uid": "0x1122334455667788990011223344556677889900112233445566778899001122",
        "attester": "0x3333333333333333333333333333333333333333",
        "recipient": "0x2222222222222222222222222222222222222222",
        "ref_uid": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "time": 1_743_292_800u64,
        "expiration_time": 0u64,
        "revocable": true,
        "revoked": false,
        // The fact the attester signs over: a root it claims was anchored.
        "attested_merkle_root": ATTESTED_ROOT,
        "checkpoint_seq": 1_042u64,
        "attester_signature": "0x4444444444444444444444444444444444444444444444444444444444444444"
    })
}

#[test]
fn eas_attestation_is_not_admissible_as_anchoring_inclusion_proof() {
    // An EAS/SAS attestation envelope cannot enter the anchoring-readback
    // lane: it is not a `chio.anchor-inclusion-proof.v1` and carries none of
    // the recompute inputs (receipt, inclusion proof, signed checkpoint).
    let admitted = serde_json::from_value::<AnchorInclusionProof>(eas_sas_attestation());
    assert!(
        admitted.is_err(),
        "an EAS/SAS attestation must not deserialize as an anchoring inclusion proof"
    );
}

#[test]
fn recompute_lane_admits_only_a_genuine_recomputing_proof() {
    // Sanity: the readback lane is the gate, and it accepts a proof whose
    // committed root recomputes from the receipt leaf and signed checkpoint.
    let proof: AnchorInclusionProof =
        serde_json::from_value(fixture_value()).expect("genuine proof deserializes");
    verify_anchor_inclusion_proof(&proof).expect("genuine recomputing proof must verify");
}

#[test]
fn attested_root_at_inclusion_layer_is_rejected_fail_closed() {
    // Splice the attestation's asserted root into the inclusion claim only.
    // The lane refuses: the inclusion root must equal the kernel-signed
    // checkpoint root, so an attested root cannot be smuggled in here.
    let mut value = fixture_value();
    value["receipt_inclusion"]["merkle_root"] = json!(ATTESTED_ROOT);
    let proof: AnchorInclusionProof =
        serde_json::from_value(value).expect("spliced proof still deserializes");

    let err = verify_anchor_inclusion_proof(&proof)
        .expect_err("an attested inclusion root must fail closed");
    let message = err.to_string();
    assert!(
        message.contains("receipt inclusion merkle_root must match checkpoint statement"),
        "expected inclusion/checkpoint root-binding rejection, got: {message}"
    );
}

#[test]
fn attested_root_committed_everywhere_breaks_kernel_signature_fail_closed() {
    // Now rewrite the attested root into every committed root field, exactly
    // as a "trust the attested value" readback would. Validation's
    // root-equality checks pass, but the kernel-signed checkpoint commitment
    // no longer covers the attested root, so the recompute lane rejects it.
    let mut value = fixture_value();
    value["receipt_inclusion"]["merkle_root"] = json!(ATTESTED_ROOT);
    value["checkpoint_statement"]["merkle_root"] = json!(ATTESTED_ROOT);
    value["chain_anchor"]["anchored_merkle_root"] = json!(ATTESTED_ROOT);
    let proof: AnchorInclusionProof =
        serde_json::from_value(value).expect("spliced proof still deserializes");

    let err = verify_anchor_inclusion_proof(&proof)
        .expect_err("an attested root with no kernel-signed commitment must fail closed");
    let message = err.to_string();
    assert!(
        message.contains("checkpoint statement signature verification failed"),
        "expected kernel-signature recompute rejection, got: {message}"
    );
}
