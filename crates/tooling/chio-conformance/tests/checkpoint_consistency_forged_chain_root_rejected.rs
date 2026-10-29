//! Negative conformance test: forged checkpoint-chain consistency.
//!
//! Threat: the operator of a log (who holds the kernel signing key)
//! rewrites history and issues a successor checkpoint whose signed
//! `chain_root` has no append-only relation to the predecessor's. Every
//! metadata field of a consistency proof can be made to match the two
//! signed bodies, but the RFC 6962 consistency path cannot connect two
//! unrelated roots, so `verify_checkpoint_consistency_proof` MUST
//! return false.
//!
//! Before the chain commitment existed, the consistency record carried
//! no Merkle node hashes and a verifier recomputed it from the two
//! checkpoints alone, so exactly this rewrite verified.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::merkle::leaf_hash;
use chio_core::Keypair;
use chio_kernel::checkpoint::{build_checkpoint, build_checkpoint_with_previous};
use chio_kernel_core::evidence_verify::{
    build_checkpoint_consistency_proof, checkpoint_body_sha256, checkpoint_chain_leaf_hash,
    checkpoint_chain_root, verify_checkpoint_consistency_proof,
};

#[test]
fn checkpoint_consistency_proof_with_forged_chain_root_is_rejected() {
    let kp = Keypair::generate();
    let batch_one: Vec<Vec<u8>> = vec![b"receipt-1".to_vec(), b"receipt-2".to_vec()];
    let batch_two: Vec<Vec<u8>> = vec![b"receipt-3".to_vec(), b"receipt-4".to_vec()];

    let first = build_checkpoint(1, 1, 2, &batch_one, &kp).unwrap();
    let first_leaf = checkpoint_chain_leaf_hash(&first.body).unwrap();
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &batch_two,
        &kp,
        Some(
            &chio_kernel_core::evidence_verify::verify_integrity_embedded_key(&first)
                .expect("verified predecessor"),
        ),
        &[first_leaf],
    )
    .unwrap();
    let chain = [
        first_leaf,
        checkpoint_chain_leaf_hash(&second.body).unwrap(),
    ];

    let honest = build_checkpoint_consistency_proof(
        &first,
        &second,
        &chain,
        std::slice::from_ref(&first.body.kernel_key),
    )
    .unwrap();
    assert!(
        verify_checkpoint_consistency_proof(
            &first,
            &second,
            &honest,
            std::slice::from_ref(&first.body.kernel_key)
        )
        .unwrap(),
        "the honest chain extension must verify"
    );

    // Rewrite: the successor re-commits a chain root over fabricated
    // history and re-signs with the real kernel key.
    let fabricated_root = checkpoint_chain_root(&[leaf_hash(b"fabricated-history")]).unwrap();
    let mut rewritten = second.clone();
    rewritten.body.chain_root = Some(fabricated_root);
    rewritten.signature = kp
        .sign_wrapped(
            chio_core::receipt::checkpoint::CHECKPOINT_SCHEMA,
            &chio_core::canonical::CanonicalBytes::from_serializable(&rewritten.body).unwrap(),
        )
        .unwrap();

    let mut forged = honest.clone();
    forged.to_checkpoint_sha256 = checkpoint_body_sha256(&rewritten.body).unwrap();
    forged.to_chain_root = fabricated_root;

    assert!(
        !verify_checkpoint_consistency_proof(
            &first,
            &rewritten,
            &forged,
            std::slice::from_ref(&first.body.kernel_key)
        )
        .unwrap(),
        "a chain root with no append-only relation to the predecessor must be rejected"
    );
}
