//! Checkpoint consistency proofs across chain growth, key rotation and anchored prefixes.

use super::*;

#[test]
fn checkpoint_consistency_proof_verifies_chain_growth() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(
            &validate_checkpoint(&first, core::slice::from_ref(&first.body.kernel_key))
                .expect("verified predecessor"),
        ),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let third = build_checkpoint_with_previous(
        3,
        7,
        9,
        &make_receipt_bytes(3),
        &kp,
        Some(
            &validate_checkpoint(&second, core::slice::from_ref(&second.body.kernel_key))
                .expect("verified predecessor"),
        ),
        &chain_leaves(&[&first, &second]),
    )
    .expect("third");

    let leaves = chain_leaves(&[&first, &second, &third]);
    let proof = build_checkpoint_consistency_proof(
        &first,
        &second,
        &leaves[..2],
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect("proof");
    assert_eq!(proof.schema, CHECKPOINT_CONSISTENCY_PROOF_SCHEMA);
    assert_eq!(proof.log_id, checkpoint_log_id(&first));
    assert_eq!(proof.from_log_tree_size, 3);
    assert_eq!(proof.to_log_tree_size, 6);
    assert_eq!(proof.appended_entry_start_seq, 4);
    assert_eq!(proof.appended_entry_end_seq, 6);
    assert_eq!(Some(proof.from_chain_root), first.body.chain_root);
    assert_eq!(Some(proof.to_chain_root), second.body.chain_root);
    assert!(
        verify_checkpoint_consistency_proof(
            &first,
            &second,
            &proof,
            std::slice::from_ref(&first.body.kernel_key)
        )
        .expect("verify proof"),
        "chain-growth proof should verify"
    );

    let later = build_checkpoint_consistency_proof(
        &second,
        &third,
        &leaves,
        std::slice::from_ref(&second.body.kernel_key),
    )
    .expect("later");
    assert!(
        !later.chain_proof_hashes.is_empty(),
        "a chain extension past one leaf must carry node hashes"
    );
    assert!(
        verify_checkpoint_consistency_proof_with_anchor(
            &second,
            &third,
            &later,
            CheckpointConsistencyAnchor::ChainPrefix(&leaves[..2]),
            std::slice::from_ref(&second.body.kernel_key),
        )
        .expect("verify later"),
        "second chain-growth proof should verify against the verified prefix"
    );
    assert!(
        verify_checkpoint_consistency_proof_with_anchor(
            &second,
            &third,
            &later,
            CheckpointConsistencyAnchor::VerifiedChainRoot(
                second.body.chain_root.expect("second chain root")
            ),
            std::slice::from_ref(&second.body.kernel_key),
        )
        .expect("verify later against a pinned root"),
        "a previously verified chain root anchors the same proof"
    );
}

#[test]
fn consistency_proof_without_chain_commitments_is_refused_at_deserialization() {
    let record = serde_json::json!({
        "schema": CHECKPOINT_CONSISTENCY_PROOF_SCHEMA,
        "log_id": "local-log-0",
        "from_checkpoint_seq": 1,
        "to_checkpoint_seq": 2,
        "from_checkpoint_sha256": "00".repeat(32),
        "to_checkpoint_sha256": "11".repeat(32),
        "from_log_tree_size": 3,
        "to_log_tree_size": 6,
        "appended_entry_start_seq": 4,
        "appended_entry_end_seq": 6
    });

    let error = serde_json::from_value::<CheckpointConsistencyProof>(record)
        .expect_err("a metadata-only record must not deserialize as a consistency proof");
    assert!(
        error
            .to_string()
            .contains("missing field `from_chain_root`"),
        "unexpected error: {error}"
    );
}

#[test]
fn consistency_proof_rejects_maximum_untrusted_leaf_index_without_panicking() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(
            &validate_checkpoint(&first, core::slice::from_ref(&first.body.kernel_key))
                .expect("verified predecessor"),
        ),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let mut proof = build_checkpoint_consistency_proof(
        &first,
        &second,
        &chain_leaves(&[&first, &second]),
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect("proof");
    proof.from_leaf_inclusion.leaf_index = usize::MAX;

    assert!(
        !verify_checkpoint_consistency_proof(
            &first,
            &second,
            &proof,
            std::slice::from_ref(&first.body.kernel_key)
        )
        .expect("malformed proof is denied"),
        "an overflowing leaf index must fail closed"
    );
}

#[test]
fn transparency_preserves_post_rotation_consistency_proofs() {
    let first_key = Keypair::generate();
    let rotated_key = Keypair::generate();
    let first =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &first_key).expect("first checkpoint");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &rotated_key,
        Some(
            &validate_checkpoint(&first, core::slice::from_ref(&first.body.kernel_key))
                .expect("verified predecessor"),
        ),
        &chain_leaves(&[&first]),
    )
    .expect("rotated checkpoint");
    let third = build_checkpoint_with_previous(
        3,
        7,
        9,
        &make_receipt_bytes(3),
        &rotated_key,
        Some(
            &validate_checkpoint(&second, core::slice::from_ref(&second.body.kernel_key))
                .expect("verified predecessor"),
        ),
        &chain_leaves(&[&first, &second]),
    )
    .expect("post-rotation checkpoint");

    let transparency = build_checkpoint_transparency(
        &[first.clone(), second, third],
        &[first_key.public_key(), rotated_key.public_key()],
    )
    .expect("transparency");
    assert_eq!(transparency.consistency_proofs.len(), 1);
    assert_eq!(transparency.consistency_proofs[0].from_checkpoint_seq, 2);
    assert_eq!(transparency.consistency_proofs[0].to_checkpoint_seq, 3);
}

#[test]
fn transparency_rejects_divergent_chain_root_at_key_rotation() {
    let first_key = Keypair::generate();
    let rotated_key = Keypair::generate();
    let first =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &first_key).expect("first checkpoint");
    let mut second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &rotated_key,
        Some(
            &validate_checkpoint(&first, core::slice::from_ref(&first.body.kernel_key))
                .expect("verified predecessor"),
        ),
        &chain_leaves(&[&first]),
    )
    .expect("rotated checkpoint");
    second.body.chain_root =
        Some(checkpoint_chain_root(&[leaf_hash(b"unrelated-rotated-history")]).expect("root"));
    second.signature = sign_checkpoint_body(&rotated_key, &second.body);

    let error = build_checkpoint_transparency(
        &[first.clone(), second],
        &[first_key.public_key(), rotated_key.public_key()],
    )
    .expect_err("key rotation must not bypass the global chain commitment");
    assert!(
        error
            .to_string()
            .contains("does not extend the retained checkpoint chain"),
        "unexpected error: {error}"
    );
}

#[test]
fn checkpoint_consistency_proof_rejects_unrelated_chain_root() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(
            &validate_checkpoint(&first, core::slice::from_ref(&first.body.kernel_key))
                .expect("verified predecessor"),
        ),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let leaves = chain_leaves(&[&first, &second]);
    let honest = build_checkpoint_consistency_proof(
        &first,
        &second,
        &leaves,
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect("proof");

    // A key-holding log that rewrites history: the successor commits a
    // chain root with no append-only relation to the predecessor's, and
    // re-signs. Every metadata field can be made to match, but the Merkle
    // path cannot.
    let mut rewritten = second.clone();
    rewritten.body.chain_root =
        Some(checkpoint_chain_root(&[leaf_hash(b"rewritten-history")]).expect("root"));
    rewritten.signature = sign_checkpoint_body(&kp, &rewritten.body);

    let mut forged = honest.clone();
    forged.to_checkpoint_sha256 =
        checkpoint_body_sha256(&rewritten.body).expect("rewritten digest");
    forged.to_chain_root = rewritten.body.chain_root.expect("rewritten chain root");
    assert!(
        !verify_checkpoint_consistency_proof(
            &first,
            &rewritten,
            &forged,
            std::slice::from_ref(&first.body.kernel_key)
        )
        .expect("verify forged"),
        "a chain root with no append-only relation must not verify"
    );

    // Tampering any single field of an otherwise honest proof fails too.
    let mut tampered = honest.clone();
    tampered.to_chain_root = Hash::zero();
    assert!(
        !verify_checkpoint_consistency_proof(
            &first,
            &second,
            &tampered,
            std::slice::from_ref(&first.body.kernel_key)
        )
        .expect("verify tampered"),
        "a tampered to_chain_root must not verify"
    );
    let mut truncated = honest.clone();
    truncated.chain_proof_hashes.push(Hash::zero());
    assert!(
        !verify_checkpoint_consistency_proof(
            &first,
            &second,
            &truncated,
            std::slice::from_ref(&first.body.kernel_key)
        )
        .expect("verify extended"),
        "an extended proof path must not verify"
    );
}

#[test]
fn checkpoint_consistency_proof_requires_the_committed_chain_to_end_in_this_checkpoint() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(
            &validate_checkpoint(&first, core::slice::from_ref(&first.body.kernel_key))
                .expect("verified predecessor"),
        ),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let leaves = chain_leaves(&[&first, &second]);
    let honest = build_checkpoint_consistency_proof(
        &first,
        &second,
        &leaves,
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect("proof");

    // A key holder commits a chain whose last leaf is not its own body and
    // re-signs. The verifier recomputes from the checkpoint's true leaf, so
    // the substituted root cannot be reproduced.
    let smuggled_leaf = leaf_hash(b"not-this-checkpoint");
    let smuggled_chain =
        MerkleTree::from_hashes(vec![leaves[0], smuggled_leaf]).expect("smuggled chain");
    let mut smuggled = second.clone();
    smuggled.body.chain_root = Some(smuggled_chain.root());
    smuggled.signature = sign_checkpoint_body(&kp, &smuggled.body);
    let mut smuggled_proof = honest.clone();
    smuggled_proof.to_checkpoint_sha256 =
        checkpoint_body_sha256(&smuggled.body).expect("smuggled digest");
    smuggled_proof.to_chain_root = smuggled_chain.root();
    smuggled_proof.chain_proof_hashes = smuggled_chain.consistency_proof(1).expect("smuggled path");
    smuggled_proof.to_leaf_inclusion = smuggled_chain
        .inclusion_proof(1)
        .expect("smuggled inclusion");
    assert!(
        !verify_checkpoint_consistency_proof(
            &first,
            &smuggled,
            &smuggled_proof,
            std::slice::from_ref(&first.body.kernel_key)
        )
        .expect("verify smuggled chain"),
        "a chain whose last leaf is not this checkpoint must not verify"
    );

    let mut wrong_index = honest.clone();
    wrong_index.to_leaf_inclusion.leaf_index = 0;
    assert!(
        !verify_checkpoint_consistency_proof(
            &first,
            &second,
            &wrong_index,
            std::slice::from_ref(&first.body.kernel_key)
        )
        .expect("verify wrong index"),
        "the checkpoint leaf must be proven at the last position"
    );
}

/// A pair starting after checkpoint 1 must bind BOTH endpoints. The forged
/// chain here has correct sizes and a genuine prefix relation, and its
/// later endpoint really does commit the later body, so every other check
/// passes: only binding the earlier leaf catches that checkpoint 2's
/// signed root never contained checkpoint 2.
#[test]
fn checkpoint_consistency_proof_binds_the_earlier_endpoint_too() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(
            &validate_checkpoint(&first, core::slice::from_ref(&first.body.kernel_key))
                .expect("verified predecessor"),
        ),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let third = build_checkpoint_with_previous(
        3,
        7,
        9,
        &make_receipt_bytes(3),
        &kp,
        Some(
            &validate_checkpoint(&second, core::slice::from_ref(&second.body.kernel_key))
                .expect("verified predecessor"),
        ),
        &chain_leaves(&[&first, &second]),
    )
    .expect("third");
    let honest_leaves = chain_leaves(&[&first, &second, &third]);
    let honest = build_checkpoint_consistency_proof(
        &second,
        &third,
        &honest_leaves,
        std::slice::from_ref(&second.body.kernel_key),
    )
    .expect("honest");

    // Same sizes as the honest chain, but the second leaf is junk instead
    // of checkpoint 2's body; checkpoint 3's real leaf is still appended.
    let forged_from = vec![honest_leaves[0], leaf_hash(b"never-checkpoint-two")];
    let mut forged_to = forged_from.clone();
    forged_to.push(honest_leaves[2]);
    let forged_from_tree = MerkleTree::from_hashes(forged_from).expect("forged from tree");
    let forged_to_tree = MerkleTree::from_hashes(forged_to).expect("forged to tree");

    let mut forged_second = second.clone();
    forged_second.body.chain_root = Some(forged_from_tree.root());
    forged_second.signature = sign_checkpoint_body(&kp, &forged_second.body);
    let mut forged_third = third.clone();
    forged_third.body.previous_checkpoint_sha256 =
        Some(checkpoint_body_sha256(&forged_second.body).expect("forged second digest"));
    forged_third.body.chain_root = Some(forged_to_tree.root());
    forged_third.signature = sign_checkpoint_body(&kp, &forged_third.body);

    let forged = CheckpointConsistencyProof {
        from_checkpoint_sha256: checkpoint_body_sha256(&forged_second.body)
            .expect("forged from digest"),
        to_checkpoint_sha256: checkpoint_body_sha256(&forged_third.body).expect("forged to digest"),
        from_chain_root: forged_from_tree.root(),
        to_chain_root: forged_to_tree.root(),
        chain_proof_hashes: forged_to_tree.consistency_proof(2).expect("forged path"),
        from_leaf_inclusion: forged_from_tree
            .inclusion_proof(1)
            .expect("forged from leaf"),
        to_leaf_inclusion: forged_to_tree.inclusion_proof(2).expect("forged to leaf"),
        ..honest
    };

    // The later endpoint and the consistency path are internally valid.
    assert!(
        verify_consistency_proof(
            2,
            3,
            &forged.from_chain_root,
            &forged.to_chain_root,
            &forged.chain_proof_hashes,
        ),
        "the forged chain is genuinely prefix-related, so only leaf binding can catch it"
    );
    // Even handed the forged root as the anchor, the earlier body is not in
    // the tree that root commits.
    assert!(
        !verify_checkpoint_consistency_proof_with_anchor(
            &forged_second,
            &forged_third,
            &forged,
            CheckpointConsistencyAnchor::VerifiedChainRoot(forged_from_tree.root()),
            std::slice::from_ref(&forged_second.body.kernel_key),
        )
        .expect("verify forged mid-chain pair"),
        "an earlier root that does not commit the earlier body must not verify"
    );
}

/// The mirror of the case above: the forged earlier tree does end in
/// checkpoint 2's real leaf, so both endpoints bind and the consistency path
/// is genuine. Only the leaf below the pair is fabricated, which is invisible
/// to a verifier that never sees checkpoint 1.
#[test]
fn mid_chain_consistency_proof_requires_an_anchored_prefix() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(
            &validate_checkpoint(&first, core::slice::from_ref(&first.body.kernel_key))
                .expect("verified predecessor"),
        ),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let third = build_checkpoint_with_previous(
        3,
        7,
        9,
        &make_receipt_bytes(3),
        &kp,
        Some(
            &validate_checkpoint(&second, core::slice::from_ref(&second.body.kernel_key))
                .expect("verified predecessor"),
        ),
        &chain_leaves(&[&first, &second]),
    )
    .expect("third");
    let honest_leaves = chain_leaves(&[&first, &second, &third]);
    let honest = build_checkpoint_consistency_proof(
        &second,
        &third,
        &honest_leaves,
        std::slice::from_ref(&second.body.kernel_key),
    )
    .expect("honest");

    // Checkpoint 1's leaf is replaced by junk; checkpoints 2 and 3 keep their
    // real leaves at their own positions.
    let forged_from = vec![leaf_hash(b"never-checkpoint-one"), honest_leaves[1]];
    let mut forged_to = forged_from.clone();
    forged_to.push(honest_leaves[2]);
    let forged_from_tree = MerkleTree::from_hashes(forged_from).expect("forged from tree");
    let forged_to_tree = MerkleTree::from_hashes(forged_to).expect("forged to tree");

    let mut forged_second = second.clone();
    forged_second.body.chain_root = Some(forged_from_tree.root());
    forged_second.signature = sign_checkpoint_body(&kp, &forged_second.body);
    let mut forged_third = third.clone();
    forged_third.body.previous_checkpoint_sha256 =
        Some(checkpoint_body_sha256(&forged_second.body).expect("forged second digest"));
    forged_third.body.chain_root = Some(forged_to_tree.root());
    forged_third.signature = sign_checkpoint_body(&kp, &forged_third.body);

    let forged = CheckpointConsistencyProof {
        from_checkpoint_sha256: checkpoint_body_sha256(&forged_second.body)
            .expect("forged from digest"),
        to_checkpoint_sha256: checkpoint_body_sha256(&forged_third.body).expect("forged to digest"),
        from_chain_root: forged_from_tree.root(),
        to_chain_root: forged_to_tree.root(),
        chain_proof_hashes: forged_to_tree.consistency_proof(2).expect("forged path"),
        from_leaf_inclusion: forged_from_tree
            .inclusion_proof(1)
            .expect("forged from leaf"),
        to_leaf_inclusion: forged_to_tree.inclusion_proof(2).expect("forged to leaf"),
        ..honest.clone()
    };

    let error = verify_checkpoint_consistency_proof(
        &forged_second,
        &forged_third,
        &forged,
        std::slice::from_ref(&forged_second.body.kernel_key),
    )
    .expect_err("a mid-chain pair is not genesis-anchored");
    assert!(
        error.to_string().contains("is unanchored"),
        "unexpected error: {error}"
    );

    assert!(
        !verify_checkpoint_consistency_proof_with_anchor(
            &forged_second,
            &forged_third,
            &forged,
            CheckpointConsistencyAnchor::ChainPrefix(&honest_leaves[..2]),
            std::slice::from_ref(&forged_second.body.kernel_key),
        )
        .expect("verify forged prefix"),
        "a fabricated pre-pair history must not verify against the real prefix"
    );

    assert!(
        verify_checkpoint_consistency_proof_with_anchor(
            &second,
            &third,
            &honest,
            CheckpointConsistencyAnchor::ChainPrefix(&honest_leaves[..2]),
            std::slice::from_ref(&second.body.kernel_key),
        )
        .expect("verify honest prefix"),
        "the honest pair still verifies against the real prefix"
    );
}

#[test]
fn checkpoint_consistency_proof_requires_chain_commitment() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(
            &validate_checkpoint(&first, core::slice::from_ref(&first.body.kernel_key))
                .expect("verified predecessor"),
        ),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let leaves = chain_leaves(&[&first, &second]);
    let proof = build_checkpoint_consistency_proof(
        &first,
        &second,
        &leaves,
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect("proof");

    let mut rootless_second = second.clone();
    rootless_second.body.chain_root = None;
    rootless_second.signature = sign_checkpoint_body(&kp, &rootless_second.body);

    let error = verify_checkpoint_consistency_proof(
        &first,
        &rootless_second,
        &proof,
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect_err("a rootless endpoint cannot carry a consistency proof");
    assert!(
        error
            .to_string()
            .contains("does not extend a chain commitment from its predecessor"),
        "unexpected error: {error}"
    );
}
