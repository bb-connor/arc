#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use chio_core::crypto::Keypair;
use chio_core::merkle::{leaf_hash, MerkleTree};
use libfuzzer_sys::fuzz_target;

const MAX_LEAVES: usize = 64;
const MAX_LEAF_BYTES: usize = 512;

#[derive(Arbitrary, Debug)]
struct MerkleCheckpointInput {
    leaves: Vec<Vec<u8>>,
    proof_index: usize,
    checkpoint_seq: u16,
    batch_start_seq: u16,
    key_seed: [u8; 32],
}

fn bounded_leaves(input: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    input
        .into_iter()
        .take(MAX_LEAVES)
        .map(|leaf| leaf.into_iter().take(MAX_LEAF_BYTES).collect())
        .collect()
}

fn leaves_from_raw(data: &[u8]) -> Vec<Vec<u8>> {
    data.split(|byte| *byte == b'\n')
        .filter(|leaf| !leaf.is_empty())
        .take(MAX_LEAVES)
        .map(|leaf| leaf.iter().copied().take(MAX_LEAF_BYTES).collect())
        .collect()
}

fn tampered_hash(hash: &chio_core::hashing::Hash) -> chio_core::hashing::Hash {
    let mut bytes = *hash.as_bytes();
    bytes[0] ^= 0xff;
    chio_core::hashing::Hash::from_bytes(bytes)
}

fn exercise_merkle(
    leaves: Vec<Vec<u8>>,
    proof_index: usize,
    checkpoint_seq: u16,
    batch_start_seq: u16,
    key_seed: [u8; 32],
) {
    if leaves.is_empty() {
        return;
    }

    let tree = match MerkleTree::from_leaves(&leaves) {
        Ok(tree) => tree,
        Err(error) => panic!("non-empty leaves should build a Merkle tree: {error}"),
    };
    assert_eq!(tree.leaf_count(), leaves.len());

    let leaf_hashes = leaves
        .iter()
        .map(|leaf| leaf_hash(leaf))
        .collect::<Vec<_>>();
    let hash_tree = match MerkleTree::from_hashes(leaf_hashes) {
        Ok(tree) => tree,
        Err(error) => panic!("non-empty leaf hashes should build a Merkle tree: {error}"),
    };
    assert_eq!(tree.root(), hash_tree.root());

    let proof_index = proof_index % leaves.len();
    let proof = match tree.inclusion_proof(proof_index) {
        Ok(proof) => proof,
        Err(error) => panic!("valid proof index should produce inclusion proof: {error}"),
    };
    assert!(proof.verify(&leaves[proof_index], &tree.root()));
    assert!(!proof.verify(&leaves[proof_index], &leaf_hash(b"wrong-root")));

    let mut wrong_leaf = leaves[proof_index].clone();
    wrong_leaf.push(0xff);
    if wrong_leaf != leaves[proof_index] {
        assert!(!proof.verify(&wrong_leaf, &tree.root()));
    }

    let keypair = Keypair::from_seed(&key_seed);
    let checkpoint_seq = u64::from(checkpoint_seq) + 1;
    let batch_start_seq = u64::from(batch_start_seq) + 1;
    let batch_end_seq = batch_start_seq + leaves.len() as u64 - 1;
    let checkpoint = match chio_kernel::build_checkpoint(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        &leaves,
        &keypair,
    ) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("valid checkpoint input should build: {error}"),
    };

    assert_eq!(checkpoint.body.tree_size, leaves.len());
    assert_eq!(checkpoint.body.merkle_root, tree.root());
    assert!(matches!(
        chio_kernel::verify_checkpoint_signature(&checkpoint),
        Ok(true)
    ));
    if let Err(error) = chio_kernel::checkpoint::validate_checkpoint(&checkpoint) {
        panic!("built checkpoint should validate: {error}");
    }

    let mut body_tampered = checkpoint.clone();
    body_tampered.body.tree_size = body_tampered.body.tree_size.saturating_add(1);
    assert!(matches!(
        chio_kernel::verify_checkpoint_signature(&body_tampered),
        Ok(false)
    ));
    assert!(chio_kernel::checkpoint::validate_checkpoint(&body_tampered).is_err());

    let mut range_tampered = checkpoint.clone();
    range_tampered.body.batch_end_seq = range_tampered.body.batch_end_seq.saturating_add(1);
    assert!(matches!(
        chio_kernel::verify_checkpoint_signature(&range_tampered),
        Ok(false)
    ));
    assert!(chio_kernel::checkpoint::validate_checkpoint(&range_tampered).is_err());

    let inclusion = match chio_kernel::build_inclusion_proof(
        &tree,
        proof_index,
        checkpoint.body.checkpoint_seq,
        batch_start_seq + proof_index as u64,
    ) {
        Ok(proof) => proof,
        Err(error) => panic!("valid checkpoint inclusion proof should build: {error}"),
    };
    assert_eq!(inclusion.merkle_root, checkpoint.body.merkle_root);
    assert!(inclusion.verify(&leaves[proof_index], &checkpoint.body.merkle_root));

    let mut tampered_inclusion = inclusion.clone();
    tampered_inclusion.merkle_root = tampered_hash(&tampered_inclusion.merkle_root);
    assert!(!tampered_inclusion.verify(&leaves[proof_index], &tampered_inclusion.merkle_root));

    let mut proof_tampered = inclusion.clone();
    if let Some(first) = proof_tampered.proof.audit_path.first_mut() {
        *first = tampered_hash(first);
        assert!(!proof_tampered.verify(&leaves[proof_index], &checkpoint.body.merkle_root));
    }
}

fn exercise_generated(input: MerkleCheckpointInput) {
    exercise_merkle(
        bounded_leaves(input.leaves),
        input.proof_index,
        input.checkpoint_seq,
        input.batch_start_seq,
        input.key_seed,
    );
}

fuzz_target!(|data: &[u8]| {
    exercise_merkle(leaves_from_raw(data), 0, 1, 1, [0x24; 32]);

    let mut unstructured = Unstructured::new(data);
    if let Ok(input) = MerkleCheckpointInput::arbitrary(&mut unstructured) {
        exercise_generated(input);
    }
});
