//! Unit tests for checkpoint issuance, verification and transparency.

extern crate std;

use alloc::boxed::Box;
use alloc::vec;

use chio_core_types::crypto::{Keypair, PublicKey, Signature};
use chio_core_types::receipt::checkpoint::{
    CHECKPOINT_CONSISTENCY_PROOF_SCHEMA, CHECKPOINT_SCHEMA,
};
use chio_security_types::clock::UnixMillis;

use super::*;

/// Fixed issuance time for every checkpoint these tests build.
const ISSUED_AT_SECS: u64 = 1_792_234_800;

fn signing(keypair: &Keypair) -> CheckpointSigningContext<'_> {
    CheckpointSigningContext {
        keypair,
        issued_at: UnixMillis::new(ISSUED_AT_SECS * 1000),
    }
}

pub(super) fn build_checkpoint(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    keypair: &Keypair,
) -> Result<KernelCheckpoint, CheckpointError> {
    build_checkpoint_with_previous(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        receipt_canonical_bytes_batch,
        keypair,
        None,
        &[],
    )
}

pub(super) fn build_checkpoint_with_previous(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    keypair: &Keypair,
    previous_checkpoint: Option<&VerifiedCheckpoint<'_>>,
    prior_chain_leaf_hashes: &[Hash],
) -> Result<KernelCheckpoint, CheckpointError> {
    build_checkpoint_with_previous_at(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        receipt_canonical_bytes_batch,
        signing(keypair),
        previous_checkpoint,
        prior_chain_leaf_hashes,
    )
}

fn build_checkpoint_with_chain_frontier(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    keypair: &Keypair,
    previous_checkpoint: Option<&VerifiedCheckpoint<'_>>,
    prior_chain: &CheckpointChainFrontier,
) -> Result<KernelCheckpoint, CheckpointError> {
    build_checkpoint_with_chain_frontier_at(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        receipt_canonical_bytes_batch,
        signing(keypair),
        previous_checkpoint,
        prior_chain,
    )
}

#[test]
fn checkpoint_rejects_identity_key_forgery() -> Result<(), Box<dyn core::error::Error>> {
    let mut checkpoint = build_checkpoint(1, 1, 1, &[b"receipt".to_vec()], &Keypair::generate())?;
    checkpoint.body.kernel_key =
        PublicKey::from_hex("0100000000000000000000000000000000000000000000000000000000000000")?;
    checkpoint.signature = Signature::from_hex(concat!(
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000"
    ))?;
    assert!(matches!(
        verify_checkpoint_signature(&checkpoint, std::slice::from_ref(&checkpoint.body.kernel_key)),
        Err(CheckpointError::InvalidSignature)
    ));
    Ok(())
}

#[test]
fn checkpoint_signature_refuses_kernel_key_outside_trusted_set(
) -> Result<(), Box<dyn std::error::Error>> {
    let signer = Keypair::generate();
    let checkpoint = build_checkpoint(1, 1, 1, &[b"receipt".to_vec()], &signer)?;
    let foreign = [Keypair::generate().public_key()];

    assert!(matches!(
        verify_checkpoint_signature(&checkpoint, &foreign),
        Err(CheckpointError::UntrustedKernelKey)
    ));
    assert!(matches!(
        validate_checkpoint(&checkpoint, &foreign),
        Err(CheckpointError::UntrustedKernelKey)
    ));
    assert!(matches!(
        validate_checkpoint(&checkpoint, &[]),
        Err(CheckpointError::UntrustedKernelKey)
    ));
    Ok(())
}

#[test]
fn checkpoint_validates_under_trusted_kernel_key() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Keypair::generate();
    let checkpoint = build_checkpoint(1, 1, 1, &[b"receipt".to_vec()], &signer)?;
    let trusted = [Keypair::generate().public_key(), signer.public_key()];

    assert!(verify_checkpoint_signature(&checkpoint, &trusted)?);
    validate_checkpoint(&checkpoint, &trusted)?;
    Ok(())
}

fn sign_checkpoint_body(key: &Keypair, body: &KernelCheckpointBody) -> Signature {
    key.sign_wrapped(
        CHECKPOINT_SCHEMA,
        &CanonicalBytes::from_serializable(body).expect("canonical checkpoint body"),
    )
    .expect("sign checkpoint body")
}

fn make_receipt_bytes(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("{{\"receipt_id\":\"rcpt-{i:04}\",\"seq\":{i}}}").into_bytes())
        .collect()
}

fn chain_leaves(checkpoints: &[&KernelCheckpoint]) -> Vec<Hash> {
    checkpoints
        .iter()
        .map(|checkpoint| checkpoint_chain_leaf_hash(&checkpoint.body).expect("chain leaf"))
        .collect()
}

#[test]
fn build_checkpoint_100_has_tree_size_100() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(100);
    let cp = build_checkpoint(1, 1, 100, &batch, &kp).expect("build_checkpoint failed");
    assert_eq!(cp.body.tree_size, 100);
}

#[test]
fn build_checkpoint_signature_verifies() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(10);
    let cp = build_checkpoint(1, 1, 10, &batch, &kp).expect("build_checkpoint failed");
    verify_checkpoint_signature(&cp, std::slice::from_ref(&cp.body.kernel_key))
        .expect("signature should be valid");
}

#[test]
fn checkpoint_validation_refuses_unwrapped_and_foreign_id_signatures() {
    let kp = Keypair::generate();
    let mut cp = build_checkpoint(1, 1, 5, &make_receipt_bytes(5), &kp).unwrap();
    for (label, signature) in crate::wrapper_refusals::refused_signatures(&kp, &cp.body) {
        cp.signature = signature;
        assert!(
            !verify_checkpoint_signature(&cp, std::slice::from_ref(&cp.body.kernel_key)).unwrap(),
            "{label}"
        );
        assert!(
            matches!(
                validate_checkpoint(&cp, std::slice::from_ref(&cp.body.kernel_key)),
                Err(CheckpointError::InvalidSignature)
            ),
            "{label}"
        );
    }
}

#[test]
fn build_checkpoint_wrong_key_fails_verification() {
    let kp1 = Keypair::generate();
    let kp2 = Keypair::generate();
    let batch = make_receipt_bytes(5);
    let mut cp = build_checkpoint(1, 1, 5, &batch, &kp1).expect("build_checkpoint failed");
    // Replace the kernel_key with a different key -- signature no longer matches.
    cp.body.kernel_key = kp2.public_key();
    assert!(
        matches!(
            verify_checkpoint_signature(&cp, std::slice::from_ref(&cp.body.kernel_key)),
            Err(CheckpointError::InvalidSignature)
        ),
        "tampered key should fail"
    );
}

#[test]
fn build_checkpoint_single_receipt() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(1);
    let cp = build_checkpoint(1, 1, 1, &batch, &kp).expect("build_checkpoint failed");
    assert_eq!(cp.body.tree_size, 1);
    verify_checkpoint_signature(&cp, std::slice::from_ref(&cp.body.kernel_key))
        .expect("single-receipt checkpoint should have valid signature");
}

#[test]
fn build_checkpoint_rejects_receipt_count_that_disagrees_with_batch_bounds() {
    let kp = Keypair::generate();
    let error = build_checkpoint(1, 10, 12, &make_receipt_bytes(2), &kp)
        .expect_err("builder must not sign inconsistent batch bounds");

    assert!(
        error
            .to_string()
            .contains("receipt batch length 2 does not match covered entry count 3"),
        "unexpected error: {error}"
    );
}

#[test]
fn build_checkpoint_single_receipt_merkle_root_equals_leaf_hash() {
    // Degenerate case: a single-receipt batch must produce a Merkle root
    // equal to the leaf hash of that receipt's canonical bytes (per RFC 6962:
    // LeafHash(bytes) = SHA256(0x00 || bytes)).
    use chio_core_types::merkle::leaf_hash;

    let kp = Keypair::generate();
    let leaf_bytes = b"single-receipt-canonical-bytes";
    let batch = vec![leaf_bytes.to_vec()];
    let cp = build_checkpoint(1, 1, 1, &batch, &kp).expect("build_checkpoint failed");

    let expected_root = leaf_hash(leaf_bytes);
    assert_eq!(
        cp.body.merkle_root, expected_root,
        "single-receipt checkpoint merkle_root must equal leaf_hash of the receipt bytes"
    );
    assert_eq!(cp.body.tree_size, 1);
    verify_checkpoint_signature(&cp, std::slice::from_ref(&cp.body.kernel_key))
        .expect("single-receipt checkpoint signature should verify");
}

#[test]
fn builder_uses_current_checkpoint_schema() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(3);
    let cp = build_checkpoint(1, 1, 3, &batch, &kp).expect("build_checkpoint failed");
    assert_eq!(cp.body.schema, CHECKPOINT_SCHEMA);
    assert!(cp.body.previous_checkpoint_sha256.is_none());
}

#[test]
fn build_checkpoint_with_previous_sets_continuity_hash() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp)
        .expect("first checkpoint build failed");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("second checkpoint build failed");
    let expected_previous_checkpoint_sha256 =
        checkpoint_body_sha256(&first.body).expect("previous digest");

    assert_eq!(
        second.body.previous_checkpoint_sha256.as_deref(),
        Some(expected_previous_checkpoint_sha256.as_str())
    );
    assert!(
        verify_checkpoint_continuity(
            &first,
            &second,
            std::slice::from_ref(&first.body.kernel_key)
        )
        .expect("continuity verification"),
        "second checkpoint should extend the first"
    );
}

#[test]
fn build_checkpoint_with_chain_frontier_accepts_canonical_successor() -> Result<(), CheckpointError>
{
    let keypair = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &keypair)?;
    let first_leaf = checkpoint_chain_leaf_hash(&first.body)?;
    let frontier = CheckpointChainFrontier::from_leaves(&[first_leaf]);

    let second = build_checkpoint_with_chain_frontier(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &keypair,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &frontier,
    )?;

    validate_checkpoint_predecessor(
        &first,
        &second,
        std::slice::from_ref(&first.body.kernel_key),
    )?;
    assert!(second.body.chain_root.is_some());
    Ok(())
}

#[test]
fn build_checkpoint_with_chain_frontier_rejects_a_rootless_predecessor(
) -> Result<(), CheckpointError> {
    let keypair = Keypair::generate();
    let detached = build_checkpoint(2, 4, 6, &make_receipt_bytes(3), &keypair)?;
    assert_eq!(detached.body.chain_root, None);
    let frontier = CheckpointChainFrontier::from_leaves(&[
        Hash::zero(),
        checkpoint_chain_leaf_hash(&detached.body)?,
    ]);

    let result = build_checkpoint_with_chain_frontier(
        3,
        7,
        9,
        &make_receipt_bytes(3),
        &keypair,
        Some(&validate_checkpoint(&detached).expect("verified predecessor")),
        &frontier,
    );

    assert!(matches!(
        result,
        Err(CheckpointError::Continuity(message))
            if message == "predecessor 2 carries no chain commitment to extend"
    ));
    Ok(())
}

#[test]
fn build_checkpoint_with_chain_frontier_rejects_invalid_predecessor() -> Result<(), CheckpointError>
{
    let keypair = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &keypair)?;
    let first_leaf = checkpoint_chain_leaf_hash(&first.body)?;
    let frontier = CheckpointChainFrontier::from_leaves(&[first_leaf]);

    let mut invalid_signature = first.clone();
    invalid_signature.body.issued_at = invalid_signature.body.issued_at.saturating_add(1);
    assert!(matches!(
        validate_checkpoint(&invalid_signature),
        Err(CheckpointError::InvalidSignature)
    ));

    let mut invalid_body = first;
    invalid_body.body.tree_size = invalid_body.body.tree_size.saturating_add(1);
    let body_bytes = canonical_json_bytes(&invalid_body.body)
        .map_err(|error| CheckpointError::Serialization(error.to_string()))?;
    invalid_body.signature = keypair.sign(&body_bytes);
    let signed_invalid_body = verify_checkpoint_signature(&invalid_body)?;
    let result = build_checkpoint_with_chain_frontier(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &keypair,
        Some(&signed_invalid_body),
        &frontier,
    );
    assert!(matches!(
        result,
        Err(CheckpointError::Invalid(message))
            if message.contains("tree_size 4 does not match covered entry count 3")
    ));

    Ok(())
}

#[test]
fn build_checkpoint_with_chain_frontier_rejects_discontinuous_successor(
) -> Result<(), CheckpointError> {
    let keypair = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &keypair)?;
    let first_leaf = checkpoint_chain_leaf_hash(&first.body)?;
    let frontier = CheckpointChainFrontier::from_leaves(&[first_leaf]);

    let result = build_checkpoint_with_chain_frontier(
        3,
        4,
        6,
        &make_receipt_bytes(3),
        &keypair,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &frontier,
    );
    assert!(matches!(
        result,
        Err(CheckpointError::Continuity(message))
            if message.contains("checkpoint_seq 3 does not immediately follow predecessor 1")
    ));

    let result = build_checkpoint_with_chain_frontier(
        2,
        5,
        6,
        &make_receipt_bytes(2),
        &keypair,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &frontier,
    );
    assert!(matches!(
        result,
        Err(CheckpointError::Continuity(message))
            if message.contains(
                "batch_start_seq 5 does not immediately follow predecessor batch_end_seq 3"
            )
    ));

    let result = build_checkpoint_with_chain_frontier(
        2,
        3,
        3,
        &make_receipt_bytes(1),
        &keypair,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &frontier,
    );
    assert!(matches!(
        result,
        Err(CheckpointError::Continuity(message))
            if message.contains(
                "batch_start_seq 3 does not immediately follow predecessor batch_end_seq 3"
            )
    ));

    Ok(())
}

#[test]
fn build_checkpoint_with_chain_frontier_rejects_successor_overflow() -> Result<(), CheckpointError>
{
    let keypair = Keypair::generate();
    let maximum_sequence = build_checkpoint(u64::MAX, 1, 1, &make_receipt_bytes(1), &keypair)?;
    let result = build_checkpoint_with_chain_frontier(
        u64::MAX,
        2,
        2,
        &make_receipt_bytes(1),
        &keypair,
        Some(&validate_checkpoint(&maximum_sequence).expect("verified predecessor")),
        &CheckpointChainFrontier::empty(),
    );
    assert!(matches!(
        result,
        Err(CheckpointError::Continuity(message))
            if message.contains("predecessor checkpoint_seq overflowed u64")
    ));

    let maximum_batch = build_checkpoint(1, u64::MAX, u64::MAX, &make_receipt_bytes(1), &keypair)?;
    let maximum_batch_leaf = checkpoint_chain_leaf_hash(&maximum_batch.body)?;
    let frontier = CheckpointChainFrontier::from_leaves(&[maximum_batch_leaf]);
    let result = build_checkpoint_with_chain_frontier(
        2,
        u64::MAX,
        u64::MAX,
        &make_receipt_bytes(1),
        &keypair,
        Some(&validate_checkpoint(&maximum_batch).expect("verified predecessor")),
        &frontier,
    );
    assert!(matches!(
        result,
        Err(CheckpointError::Continuity(message))
            if message.contains("predecessor batch_end_seq overflowed u64")
    ));

    Ok(())
}

#[test]
fn build_checkpoint_transparency_derives_publications_and_witnesses() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("build second");

    let transparency = validate_checkpoint_transparency(
        &[first.clone(), second.clone()],
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect("summary");

    assert_eq!(transparency.publications.len(), 2);
    assert_eq!(transparency.witnesses.len(), 1);
    assert_eq!(transparency.consistency_proofs.len(), 1);
    assert!(transparency.equivocations.is_empty());
    assert_eq!(
        transparency.publications[0].log_id,
        checkpoint_log_id(&first)
    );
    assert_eq!(transparency.publications[0].log_tree_size, 3);
    assert_eq!(transparency.publications[1].entry_start_seq, 4);
    assert_eq!(transparency.publications[1].entry_end_seq, 6);
    assert_eq!(
        transparency.publications[0].checkpoint_sha256,
        checkpoint_body_sha256(&first.body).expect("first digest")
    );
    assert_eq!(transparency.witnesses[0].log_id, checkpoint_log_id(&first));
    assert_eq!(transparency.witnesses[0].checkpoint_seq, 1);
    assert_eq!(transparency.witnesses[0].witness_checkpoint_seq, 2);
    assert_eq!(transparency.consistency_proofs[0].from_log_tree_size, 3);
    assert_eq!(transparency.consistency_proofs[0].to_log_tree_size, 6);
}

#[test]
fn transparency_verifies_each_checkpoint_once_for_a_large_prefix() {
    const CHECKPOINT_COUNT: u64 = 128;

    let keypair = Keypair::generate();
    let mut frontier = CheckpointChainFrontier::empty();
    let mut checkpoints = Vec::<KernelCheckpoint>::with_capacity(CHECKPOINT_COUNT as usize);
    for checkpoint_seq in 1..=CHECKPOINT_COUNT {
        let receipt = format!("receipt-{checkpoint_seq}").into_bytes();
        let checkpoint = build_checkpoint_with_chain_frontier(
            checkpoint_seq,
            checkpoint_seq,
            checkpoint_seq,
            &[receipt],
            &keypair,
            checkpoints
                .last()
                .map(validate_checkpoint)
                .transpose()
                .expect("verified predecessor")
                .as_ref(),
            &frontier,
        )
        .expect("build checkpoint prefix");
        frontier
            .append(checkpoint_chain_leaf_hash(&checkpoint.body).expect("checkpoint chain leaf"));
        checkpoints.push(checkpoint);
    }

    let verifications_before = checkpoint_signature_verification_count_for_test();
    let inspections_before = checkpoint_equivocation_inspection_count_for_test();
    let transparency = validate_checkpoint_transparency(
        &checkpoints,
        &checkpoints
            .iter()
            .map(|checkpoint| checkpoint.body.kernel_key.clone())
            .collect::<Vec<_>>(),
    )
    .expect("validate checkpoint prefix");
    let verification_count =
        checkpoint_signature_verification_count_for_test() - verifications_before;
    let inspection_count = checkpoint_equivocation_inspection_count_for_test() - inspections_before;

    assert_eq!(transparency.publications.len(), CHECKPOINT_COUNT as usize);
    assert_eq!(transparency.witnesses.len(), CHECKPOINT_COUNT as usize - 1);
    assert_eq!(
        verification_count, CHECKPOINT_COUNT as usize,
        "transparency validation must verify each checkpoint signature exactly once"
    );
    assert_eq!(
        inspection_count, 0,
        "a clean prefix must not inspect any checkpoint pairs for equivocation"
    );

    let conflicting = build_checkpoint(1, 1, 1, &[b"conflicting-receipt".to_vec()], &keypair)
        .expect("build conflicting checkpoint");
    let inspections_before = checkpoint_equivocation_inspection_count_for_test();
    let conflict_summary = build_checkpoint_transparency(
        &[checkpoints[0].clone(), conflicting],
        std::slice::from_ref(&checkpoints[0].body.kernel_key),
    )
    .expect("derive conflicting transparency");
    let inspection_count = checkpoint_equivocation_inspection_count_for_test() - inspections_before;
    assert_eq!(inspection_count, 1, "one indexed pair must be inspected");
    assert_eq!(conflict_summary.equivocations.len(), 1);
    assert_eq!(
        conflict_summary.equivocations[0].kind,
        CheckpointEquivocationKind::ConflictingCheckpointSeq
    );

    let duplicate_checkpoints = vec![checkpoints[0].clone(); CHECKPOINT_COUNT as usize];
    let verifications_before = checkpoint_signature_verification_count_for_test();
    let inspections_before = checkpoint_equivocation_inspection_count_for_test();
    let duplicate_summary = build_checkpoint_transparency(
        &duplicate_checkpoints,
        &duplicate_checkpoints
            .iter()
            .map(|checkpoint| checkpoint.body.kernel_key.clone())
            .collect::<Vec<_>>(),
    )
    .expect("derive duplicate checkpoint transparency");
    let verification_count =
        checkpoint_signature_verification_count_for_test() - verifications_before;
    let inspection_count = checkpoint_equivocation_inspection_count_for_test() - inspections_before;
    assert_eq!(
        duplicate_summary.publications.len(),
        CHECKPOINT_COUNT as usize
    );
    assert!(duplicate_summary.equivocations.is_empty());
    assert_eq!(verification_count, CHECKPOINT_COUNT as usize);
    assert_eq!(
        inspection_count, 0,
        "identical bodies must not create quadratic candidate scans"
    );
}

#[test]
fn validate_checkpoint_transparency_rejects_duplicate_signed_checkpoints() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &make_receipt_bytes(2), &kp).expect("build first");
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &make_receipt_bytes(2),
        &kp,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("build second");

    let error = validate_checkpoint_transparency(
        &[first.clone(), first.clone(), second],
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect_err("duplicate signed checkpoints must fail closed");
    assert!(
        error
            .to_string()
            .contains("duplicate checkpoint sequence 1"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_transparency_requires_the_first_receipt_prefix() {
    let keypair = Keypair::generate();
    let checkpoint = build_checkpoint(1, 5, 5, &make_receipt_bytes(1), &keypair)
        .expect("build signed late-starting checkpoint");
    validate_checkpoint(
        &checkpoint,
        std::slice::from_ref(&checkpoint.body.kernel_key),
    )
    .expect("single-checkpoint integrity remains valid");

    let error = validate_checkpoint_transparency(
        &[checkpoint.clone()],
        std::slice::from_ref(&checkpoint.body.kernel_key),
    )
    .expect_err("transparency must reject a prefix that starts after receipt one");
    assert!(
        error
            .to_string()
            .contains("checkpoint 1 must start at receipt 1, got 5"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_rejects_zero_time_and_malformed_predecessor_digest() {
    let keypair = Keypair::generate();
    let checkpoint = build_checkpoint(1, 1, 1, &make_receipt_bytes(1), &keypair)
        .expect("build signed checkpoint");

    let mut zero_time = checkpoint.clone();
    zero_time.body.issued_at = 0;
    let error = validate_checkpoint(&zero_time, std::slice::from_ref(&zero_time.body.kernel_key))
        .expect_err("zero issued_at must fail closed");
    assert!(error
        .to_string()
        .contains("issued_at must be greater than zero"));

    let mut malformed_predecessor = checkpoint;
    malformed_predecessor.body.previous_checkpoint_sha256 = Some("not-a-digest".to_string());
    let error = validate_checkpoint(
        &malformed_predecessor,
        std::slice::from_ref(&malformed_predecessor.body.kernel_key),
    )
    .expect_err("malformed predecessor digest must fail closed");
    assert!(error
        .to_string()
        .contains("must be 64 lowercase hex characters"));
}

#[test]
fn checkpoint_body_rejects_explicit_null_options_at_deserialization() {
    let keypair = Keypair::generate();
    let checkpoint = build_checkpoint(1, 1, 1, &make_receipt_bytes(1), &keypair)
        .expect("build signed checkpoint");

    for field in ["previous_checkpoint_sha256", "chain_root"] {
        let mut document =
            serde_json::to_value(&checkpoint).expect("serialize signed checkpoint fixture");
        document["body"][field] = serde_json::Value::Null;
        let error = serde_json::from_value::<KernelCheckpoint>(document)
            .expect_err("explicit null checkpoint options must fail closed");
        assert!(
            error.to_string().contains("explicit null is not permitted"),
            "unexpected {field} error: {error}"
        );
    }
}

#[test]
fn checkpoint_log_id_preserves_historical_ed25519_hashing() {
    let kp = Keypair::generate();
    let checkpoint =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build checkpoint");

    assert_eq!(
        checkpoint_log_id(&checkpoint),
        format!("local-log-{}", sha256_hex(&kp.public_key_bytes()))
    );
}

#[test]
fn build_trust_anchored_checkpoint_publication_records_binding() {
    let kp = Keypair::generate();
    let checkpoint =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build checkpoint");
    let publication = build_trust_anchored_checkpoint_publication(
        &checkpoint,
        CheckpointPublicationTrustAnchorBinding {
            publication_identity: chio_core_types::receipt::checkpoint::CheckpointPublicationIdentity::new(
                chio_core_types::receipt::checkpoint::CheckpointPublicationIdentityKind::TransparencyService,
                "transparency.example/checkpoints/1",
            ),
            trust_anchor_identity: chio_core_types::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
                chio_core_types::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::Did,
                "did:chio:operator-root",
            ),
            trust_anchor_ref: "chio_checkpoint_witness_chain".to_string(),
            signer_cert_ref: "did:web:chio.example#checkpoint-signer".to_string(),
            publication_profile_version: "phase4-preview.v1".to_string(),
        }, std::slice::from_ref(&checkpoint.body.kernel_key),
    )
    .expect("build trust-anchored publication");

    assert_eq!(
        publication
            .trust_anchor_binding
            .as_ref()
            .expect("binding")
            .trust_anchor_ref,
        "chio_checkpoint_witness_chain"
    );
    assert_eq!(
        publication
            .trust_anchor_binding
            .as_ref()
            .expect("binding")
            .publication_identity
            .identity,
        "transparency.example/checkpoints/1"
    );
    assert_eq!(publication.log_id, checkpoint_log_id(&checkpoint));
}

#[test]
fn verify_checkpoint_transparency_records_rejects_duplicate_publication_coverage() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &make_receipt_bytes(2), &kp).expect("first checkpoint");
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &make_receipt_bytes(2),
        &kp,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("second checkpoint");
    let derived = validate_checkpoint_transparency(
        &[first.clone(), second.clone()],
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect("transparency");
    let supplied = CheckpointTransparencySummary {
        publications: vec![
            derived.publications[0].clone(),
            derived.publications[0].clone(),
        ],
        witnesses: derived.witnesses.clone(),
        consistency_proofs: derived.consistency_proofs.clone(),
        equivocations: derived.equivocations.clone(),
    };

    let error = verify_checkpoint_transparency_records(
        &[first.clone(), second],
        &supplied,
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect_err("duplicate publication coverage should fail");
    assert!(
        error
            .to_string()
            .contains("duplicate checkpoint publication record"),
        "unexpected error: {error}"
    );
}

#[test]
fn build_trust_anchored_checkpoint_publication_rejects_invalid_binding() {
    let kp = Keypair::generate();
    let checkpoint =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build checkpoint");
    let error = build_trust_anchored_checkpoint_publication(
        &checkpoint,
        CheckpointPublicationTrustAnchorBinding {
            publication_identity: chio_core_types::receipt::checkpoint::CheckpointPublicationIdentity::new(
                chio_core_types::receipt::checkpoint::CheckpointPublicationIdentityKind::TransparencyService,
                "",
            ),
            trust_anchor_identity: chio_core_types::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
                chio_core_types::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::Did,
                "did:chio:operator-root",
            ),
            trust_anchor_ref: "chio_checkpoint_witness_chain".to_string(),
            signer_cert_ref: "".to_string(),
            publication_profile_version: "phase4-preview.v1".to_string(),
        }, std::slice::from_ref(&checkpoint.body.kernel_key),
    )
    .expect_err("blank signer certificate ref must be rejected");
    assert!(error.to_string().contains("publication_identity.identity"));
}

#[test]
fn trust_anchor_binding_validation_precedes_checkpoint_validation() {
    let keypair = Keypair::generate();
    let mut checkpoint =
        build_checkpoint(1, 1, 1, &make_receipt_bytes(1), &keypair).expect("build checkpoint");
    checkpoint.body.issued_at = checkpoint.body.issued_at.saturating_add(1);

    let error = build_trust_anchored_checkpoint_publication(
        &checkpoint,
        CheckpointPublicationTrustAnchorBinding {
            publication_identity:
                chio_core_types::receipt::checkpoint::CheckpointPublicationIdentity::new(
                    chio_core_types::receipt::checkpoint::CheckpointPublicationIdentityKind::TransparencyService,
                    "",
                ),
            trust_anchor_identity:
                chio_core_types::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
                    chio_core_types::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::Did,
                    "did:chio:operator-root",
                ),
            trust_anchor_ref: "chio_checkpoint_witness_chain".to_string(),
            signer_cert_ref: "".to_string(),
            publication_profile_version: "phase4-preview.v1".to_string(),
        }, std::slice::from_ref(&checkpoint.body.kernel_key),
    )
    .expect_err("invalid binding must be rejected before the checkpoint");
    assert!(error.to_string().contains("publication_identity.identity"));
}

#[test]
fn build_trust_anchored_checkpoint_publication_rejects_mismatched_local_log_identity() {
    let kp = Keypair::generate();
    let checkpoint =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build checkpoint");
    let error = build_trust_anchored_checkpoint_publication(
        &checkpoint,
        CheckpointPublicationTrustAnchorBinding {
            publication_identity:
                chio_core_types::receipt::checkpoint::CheckpointPublicationIdentity::new(
                    chio_core_types::receipt::checkpoint::CheckpointPublicationIdentityKind::LocalLog,
                    "local-log-not-the-real-one",
                ),
            trust_anchor_identity:
                chio_core_types::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
                    chio_core_types::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::OperatorRoot,
                    "chio-operator-root",
                ),
            trust_anchor_ref: "chio_checkpoint_witness_chain".to_string(),
            signer_cert_ref: "did:web:chio.example#checkpoint-signer".to_string(),
            publication_profile_version: "phase4-preview.v1".to_string(),
        },
        std::slice::from_ref(&checkpoint.body.kernel_key),
    )
    .expect_err("mismatched local log identity must be rejected");
    assert!(error.to_string().contains("does not match log_id"));
}

#[test]
fn detect_checkpoint_equivocation_reports_conflicting_sequence() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp)
        .expect("first checkpoint");
    let conflicting = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"changed".to_vec()], &kp)
        .expect("conflicting checkpoint");

    let equivocation = detect_checkpoint_equivocation(
        &first,
        &conflicting,
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect("equivocation detection")
    .expect("expected conflict");
    assert_eq!(
        equivocation.kind,
        CheckpointEquivocationKind::ConflictingCheckpointSeq
    );
    assert_eq!(equivocation.first_checkpoint_seq, 1);
    assert_eq!(equivocation.second_checkpoint_seq, 1);
}

fn pairwise_checkpoint_equivocations(
    checkpoints: &[KernelCheckpoint],
) -> Vec<CheckpointEquivocation> {
    let mut equivocations = Vec::new();
    for (position, checkpoint) in checkpoints.iter().enumerate() {
        for conflicting in checkpoints.iter().skip(position + 1) {
            if let Some(equivocation) = detect_checkpoint_equivocation(
                checkpoint,
                conflicting,
                std::slice::from_ref(&checkpoint.body.kernel_key),
            )
            .expect("pairwise equivocation detection")
            {
                equivocations.push(equivocation);
            }
        }
    }
    equivocations.sort();
    equivocations.dedup();
    equivocations
}

#[test]
fn indexed_equivocation_matches_pairwise_orientation_and_priority() {
    let keypair = Keypair::generate();
    let with_predecessor = |mut checkpoint: KernelCheckpoint, digest: &str| {
        checkpoint.body.previous_checkpoint_sha256 = Some(digest.repeat(32));
        checkpoint.signature = sign_checkpoint_body(&keypair, &checkpoint.body);
        checkpoint
    };

    let sequence_first = with_predecessor(
        build_checkpoint(2, 1, 1, &[b"sequence-first".to_vec()], &keypair)
            .expect("build first sequence checkpoint"),
        "11",
    );
    let sequence_second = with_predecessor(
        build_checkpoint(2, 1, 1, &[b"sequence-second".to_vec()], &keypair)
            .expect("build second sequence checkpoint"),
        "22",
    );
    let tree_size_first = build_checkpoint(
        2,
        1,
        2,
        &[b"tree-first-a".to_vec(), b"tree-first-b".to_vec()],
        &keypair,
    )
    .expect("build first tree-size checkpoint");
    let tree_size_second = build_checkpoint(
        3,
        1,
        2,
        &[b"tree-second-a".to_vec(), b"tree-second-b".to_vec()],
        &keypair,
    )
    .expect("build second tree-size checkpoint");
    let predecessor_first = with_predecessor(
        build_checkpoint(2, 1, 1, &[b"predecessor-first".to_vec()], &keypair)
            .expect("build first predecessor checkpoint"),
        "33",
    );
    let predecessor_second = with_predecessor(
        build_checkpoint(3, 2, 2, &[b"predecessor-second".to_vec()], &keypair)
            .expect("build second predecessor checkpoint"),
        "33",
    );
    let overlap_first = with_predecessor(
        build_checkpoint(4, 3, 3, &[b"overlap-first".to_vec()], &keypair)
            .expect("build first overlap checkpoint"),
        "44",
    );
    let overlap_second = with_predecessor(
        build_checkpoint(4, 3, 3, &[b"overlap-second".to_vec()], &keypair)
            .expect("build second overlap checkpoint"),
        "44",
    );

    for (checkpoints, expected_kind) in [
        (
            vec![sequence_first.clone(), sequence_second.clone()],
            CheckpointEquivocationKind::ConflictingCheckpointSeq,
        ),
        (
            vec![tree_size_first, tree_size_second],
            CheckpointEquivocationKind::ConflictingLogTreeSize,
        ),
        (
            vec![predecessor_first, predecessor_second],
            CheckpointEquivocationKind::ConflictingPredecessorWitness,
        ),
        (
            vec![overlap_first, overlap_second],
            CheckpointEquivocationKind::ConflictingCheckpointSeq,
        ),
        (
            vec![
                sequence_first.clone(),
                sequence_second.clone(),
                sequence_first.clone(),
            ],
            CheckpointEquivocationKind::ConflictingCheckpointSeq,
        ),
        (
            vec![sequence_second.clone(), sequence_first, sequence_second],
            CheckpointEquivocationKind::ConflictingCheckpointSeq,
        ),
    ] {
        let expected = pairwise_checkpoint_equivocations(&checkpoints);
        let actual = build_checkpoint_transparency(
            &checkpoints,
            &checkpoints
                .iter()
                .map(|checkpoint| checkpoint.body.kernel_key.clone())
                .collect::<Vec<_>>(),
        )
        .expect("indexed transparency")
        .equivocations;
        assert_eq!(actual, expected);
        assert!(actual
            .iter()
            .all(|equivocation| equivocation.kind == expected_kind));
    }
}

#[test]
fn checkpoint_rejects_same_log_same_tree_size_fork() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let fork = build_checkpoint_with_previous(
        9,
        1,
        6,
        &[
            b"fork-one".to_vec(),
            b"fork-two".to_vec(),
            b"fork-three".to_vec(),
            b"fork-four".to_vec(),
            b"fork-five".to_vec(),
            b"fork-six".to_vec(),
        ],
        &kp,
        None,
        &[],
    )
    .expect("fork");

    let error = validate_checkpoint_transparency(
        &[first.clone(), second, fork],
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect_err("same-log same-tree-size fork should fail");
    assert!(
        error.to_string().contains("cumulative tree size 6"),
        "unexpected error: {error}"
    );
}

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
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let third = build_checkpoint_with_previous(
        3,
        7,
        9,
        &make_receipt_bytes(3),
        &kp,
        Some(&validate_checkpoint(&second).expect("verified predecessor")),
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
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
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
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("rotated checkpoint");
    let third = build_checkpoint_with_previous(
        3,
        7,
        9,
        &make_receipt_bytes(3),
        &rotated_key,
        Some(&validate_checkpoint(&second).expect("verified predecessor")),
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
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
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
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
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
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
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
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let third = build_checkpoint_with_previous(
        3,
        7,
        9,
        &make_receipt_bytes(3),
        &kp,
        Some(&validate_checkpoint(&second).expect("verified predecessor")),
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
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    let third = build_checkpoint_with_previous(
        3,
        7,
        9,
        &make_receipt_bytes(3),
        &kp,
        Some(&validate_checkpoint(&second).expect("verified predecessor")),
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
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
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

#[test]
fn validate_checkpoint_predecessor_rejects_chain_commitment_downgrade() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
    let mut second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("second");
    second.body.chain_root = None;
    second.signature = sign_checkpoint_body(&kp, &second.body);

    let error = validate_checkpoint_predecessor(
        &first,
        &second,
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect_err("downgrade should fail");
    assert!(
        error
            .to_string()
            .contains("does not extend a chain commitment from its predecessor"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_rejects_first_checkpoint_chain_root_mismatch() {
    let kp = Keypair::generate();
    let mut checkpoint =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    checkpoint.body.chain_root = Some(Hash::zero());
    checkpoint.signature = sign_checkpoint_body(&kp, &checkpoint.body);

    let error = validate_checkpoint(
        &checkpoint,
        std::slice::from_ref(&checkpoint.body.kernel_key),
    )
    .expect_err("checkpoint should be invalid");
    assert!(
        error
            .to_string()
            .contains("does not commit its own chain leaf"),
        "unexpected error: {error}"
    );
}

#[test]
fn checkpoint_body_rejects_unknown_fields() {
    let kp = Keypair::generate();
    let checkpoint = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    let mut body_value = serde_json::to_value(&checkpoint.body).expect("serialize checkpoint body");
    body_value["smuggled_field"] = serde_json::json!("payload");

    let error = serde_json::from_value::<KernelCheckpointBody>(body_value)
        .expect_err("unknown body field should be rejected");
    assert!(
        error.to_string().contains("smuggled_field"),
        "unexpected error: {error}"
    );

    let mut checkpoint_value = serde_json::to_value(&checkpoint).expect("serialize checkpoint");
    checkpoint_value["extra"] = serde_json::json!(1);
    let error = serde_json::from_value::<KernelCheckpoint>(checkpoint_value)
        .expect_err("unknown top-level field should be rejected");
    assert!(
        error.to_string().contains("extra"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_rejects_a_first_checkpoint_without_chain_root() {
    let kp = Keypair::generate();
    let mut checkpoint =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    checkpoint.body.chain_root = None;
    checkpoint.signature = sign_checkpoint_body(&kp, &checkpoint.body);

    let error = validate_checkpoint(
        &checkpoint,
        std::slice::from_ref(&checkpoint.body.kernel_key),
    )
    .expect_err("checkpoint 1 needs its chain root");
    assert_eq!(
        error.to_string(),
        "invalid checkpoint: checkpoint 1 must carry chain_root"
    );
}

#[test]
fn validate_checkpoint_rejects_retired_statement_schema() {
    let kp = Keypair::generate();
    let mut checkpoint =
        build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    checkpoint.body.schema = "chio.checkpoint_statement.v2".to_string();
    checkpoint.signature = sign_checkpoint_body(&kp, &checkpoint.body);

    let error = validate_checkpoint(
        &checkpoint,
        std::slice::from_ref(&checkpoint.body.kernel_key),
    )
    .expect_err("retired schema must be refused");
    assert_eq!(
        error.to_string(),
        "invalid checkpoint: unsupported checkpoint schema chio.checkpoint_statement.v2"
    );
}

#[test]
fn inclusion_proof_verifies_for_leaf_n() {
    let batch = make_receipt_bytes(10);
    let tree = MerkleTree::from_leaves(&batch).expect("tree build failed");
    let root = tree.root();
    let proof = build_inclusion_proof(&tree, 5, 1, 6).expect("proof failed");
    assert!(
        proof.verify(&batch[5], &root),
        "inclusion proof should verify"
    );
}

#[test]
fn inclusion_proof_tampered_bytes_fail() {
    let batch = make_receipt_bytes(10);
    let tree = MerkleTree::from_leaves(&batch).expect("tree build failed");
    let root = tree.root();
    let proof = build_inclusion_proof(&tree, 5, 1, 6).expect("proof failed");
    assert!(
        !proof.verify(b"tampered bytes that are not in the tree", &root),
        "tampered bytes should not verify"
    );
}

#[test]
fn inclusion_proof_all_100_leaves_verify() {
    let batch = make_receipt_bytes(100);
    let tree = MerkleTree::from_leaves(&batch).expect("tree build failed");
    let root = tree.root();
    for (i, leaf) in batch.iter().enumerate().take(100) {
        let proof = build_inclusion_proof(&tree, i, 1, i as u64 + 1).expect("proof failed");
        assert!(proof.verify(leaf, &root), "leaf {i} inclusion proof failed");
    }
}

#[test]
fn checkpoint_body_schema_field() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(5);
    let cp = build_checkpoint(7, 101, 105, &batch, &kp).expect("build failed");
    let json = serde_json::to_string(&cp.body).expect("serialize failed");
    assert!(
        json.contains(CHECKPOINT_SCHEMA),
        "JSON should contain schema string"
    );
}

#[test]
fn checkpoint_schema_support_is_exactly_the_current_schema() {
    assert!(is_supported_checkpoint_schema(CHECKPOINT_SCHEMA));
    assert!(!is_supported_checkpoint_schema(
        "chio.checkpoint_statement.v2"
    ));
}

#[test]
fn kernel_checkpoint_serde_roundtrip() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(5);
    let cp = build_checkpoint(1, 1, 5, &batch, &kp).expect("build failed");
    let json = serde_json::to_string(&cp).expect("serialize failed");
    let restored: KernelCheckpoint = serde_json::from_str(&json).expect("deserialize failed");
    assert_eq!(cp.body.checkpoint_seq, restored.body.checkpoint_seq);
    assert_eq!(cp.body.tree_size, restored.body.tree_size);
    assert_eq!(cp.signature.to_hex(), restored.signature.to_hex());
    // Verify signature still works after roundtrip.
    verify_checkpoint_signature(&restored, std::slice::from_ref(&restored.body.kernel_key))
        .expect("roundtripped checkpoint signature should verify");
}

#[test]
fn validate_checkpoint_rejects_zero_checkpoint_seq() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(3);
    let mut checkpoint = build_checkpoint(1, 1, 3, &batch, &kp).expect("build failed");
    checkpoint.body.checkpoint_seq = 0;

    let error = validate_checkpoint(
        &checkpoint,
        std::slice::from_ref(&checkpoint.body.kernel_key),
    )
    .expect_err("checkpoint should be invalid");
    assert!(
        error
            .to_string()
            .contains("checkpoint_seq must be greater than zero"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_rejects_tampered_signature() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(3);
    let mut checkpoint = build_checkpoint(1, 1, 3, &batch, &kp).expect("build failed");
    checkpoint.body.issued_at = checkpoint.body.issued_at.saturating_add(1);

    let error = validate_checkpoint(
        &checkpoint,
        std::slice::from_ref(&checkpoint.body.kernel_key),
    )
    .expect_err("checkpoint should be invalid");
    assert!(
        matches!(error, CheckpointError::InvalidSignature),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_rejects_tree_size_that_does_not_match_entry_range() {
    let kp = Keypair::generate();
    let batch = make_receipt_bytes(3);
    let mut checkpoint = build_checkpoint(1, 1, 3, &batch, &kp).expect("build failed");
    checkpoint.body.tree_size = 2;
    checkpoint.signature = sign_checkpoint_body(&kp, &checkpoint.body);

    let error = validate_checkpoint(
        &checkpoint,
        std::slice::from_ref(&checkpoint.body.kernel_key),
    )
    .expect_err("checkpoint should be invalid");
    assert!(
        error
            .to_string()
            .contains("tree_size 2 does not match covered entry count 3"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_predecessor_accepts_contiguous_batches() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    let second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("build failed");

    validate_checkpoint_predecessor(
        &first,
        &second,
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect("continuity should hold");
}

#[test]
fn validate_checkpoint_predecessor_rejects_batch_gap() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    let mut second = build_checkpoint(2, 5, 6, &make_receipt_bytes(2), &kp).expect("build failed");
    second.body.previous_checkpoint_sha256 =
        Some(checkpoint_body_sha256(&first.body).expect("predecessor digest"));
    second.signature = sign_checkpoint_body(&kp, &second.body);

    let error = validate_checkpoint_predecessor(
        &first,
        &second,
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect_err("continuity should fail");
    assert!(
        error.to_string().contains("does not immediately follow"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_predecessor_rejects_wrong_predecessor_digest() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    let mut second = build_checkpoint_with_previous(
        2,
        4,
        6,
        &make_receipt_bytes(3),
        &kp,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("build failed");
    second.body.previous_checkpoint_sha256 = Some("00".repeat(32));
    second.signature = sign_checkpoint_body(&kp, &second.body);

    let error = validate_checkpoint_predecessor(
        &first,
        &second,
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect_err("continuity should fail");
    assert!(
        error
            .to_string()
            .contains("does not match predecessor digest"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_predecessor_rejects_missing_predecessor_digest() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
    let second = build_checkpoint(2, 4, 6, &make_receipt_bytes(3), &kp).expect("build failed");

    let error = validate_checkpoint_predecessor(
        &first,
        &second,
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect_err("continuity should fail");
    assert!(
        error.to_string().contains("missing predecessor digest"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_transparency_rejects_predecessor_fork() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp)
        .expect("first checkpoint");
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"three".to_vec(), b"four".to_vec()],
        &kp,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("second checkpoint");
    let mut fork = build_checkpoint_with_previous(
        3,
        5,
        6,
        &[b"five".to_vec(), b"six".to_vec()],
        &kp,
        Some(&validate_checkpoint(&second).expect("verified predecessor")),
        &chain_leaves(&[&first, &second]),
    )
    .expect("fork checkpoint");
    fork.body.previous_checkpoint_sha256 =
        Some(checkpoint_body_sha256(&first.body).expect("first checkpoint digest"));
    fork.signature = sign_checkpoint_body(&kp, &fork.body);

    let error = validate_checkpoint_transparency(
        &[first.clone(), second, fork],
        std::slice::from_ref(&first.body.kernel_key),
    )
    .expect_err("forked checkpoint set should fail");
    assert!(
        error
            .to_string()
            .contains("checkpoint equivocation detected"),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_checkpoint_transparency_rejects_truncated_predecessor_chain() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp)
        .expect("first checkpoint");
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"three".to_vec(), b"four".to_vec()],
        &kp,
        Some(&validate_checkpoint(&first).expect("verified predecessor")),
        &chain_leaves(&[&first]),
    )
    .expect("second checkpoint");

    let error = validate_checkpoint_transparency(
        &[second.clone()],
        std::slice::from_ref(&second.body.kernel_key),
    )
    .expect_err("a checkpoint set with an unresolved predecessor must fail closed");
    assert!(
        error.to_string().contains("unresolved predecessor"),
        "unexpected error: {error}"
    );
}

/// The frontier must agree with a full tree build at every size, otherwise a
/// writer that extends incrementally would sign a different chain commitment
/// than a verifier that rebuilds from leaves.
#[test]
fn chain_frontier_root_matches_a_full_tree_build_at_every_size() {
    let leaves: Vec<Hash> = (0..200u32)
        .map(|i| leaf_hash(format!("chain-leaf-{i}").as_bytes()))
        .collect();

    let mut frontier = CheckpointChainFrontier::empty();
    assert_eq!(frontier.root(), None);
    assert_eq!(frontier.leaf_count(), 0);

    for size in 1..=leaves.len() {
        frontier.append(leaves[size - 1]);
        assert_eq!(frontier.leaf_count(), size as u64, "size {size}");
        assert_eq!(
            frontier.root(),
            Some(checkpoint_chain_root(&leaves[..size]).expect("full build")),
            "frontier root diverges from the full build at size {size}"
        );
        assert_eq!(
            frontier,
            CheckpointChainFrontier::from_leaves(&leaves[..size]),
            "incremental and rebuilt frontiers diverge at size {size}"
        );
    }
}

/// The per-checkpoint path must not rehash the whole chain: the frontier keeps
/// at most one subtree per set bit of the leaf count.
#[test]
fn chain_frontier_stays_logarithmic() {
    let mut frontier = CheckpointChainFrontier::empty();
    for i in 0..4096u32 {
        frontier.append(leaf_hash(format!("chain-leaf-{i}").as_bytes()));
    }
    assert_eq!(frontier.leaf_count(), 4096);
    assert_eq!(
        frontier.subtree_count_for_test(),
        (4096u64).count_ones() as usize,
        "a power-of-two chain collapses to a single perfect subtree"
    );

    frontier.append(leaf_hash(b"one-more"));
    assert_eq!(
        frontier.subtree_count_for_test(),
        (4097u64).count_ones() as usize
    );
}
