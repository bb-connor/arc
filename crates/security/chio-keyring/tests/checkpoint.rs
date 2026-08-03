use chio_test_support::prelude::*;

use std::collections::BTreeMap;

use chio_core_types::{sha256, Ed25519Backend, Keypair, SigningBackend};
use chio_keyring::{
    KeyLogCheckpointExpectation, LogId, SignedKeyLogCheckpoint, WitnessId, WitnessSignature,
    KEY_LOG_CHECKPOINT_SCHEMA, MAX_WITNESS_SIGNATURES,
};

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

#[test]
fn checkpoint_deserialization_rejects_oversized_witness_vectors() {
    let operator = backend(10);
    let mut checkpoint = checkpoint(&operator);
    checkpoint.witness_signatures = (0..=MAX_WITNESS_SIGNATURES)
        .map(|index| {
            WitnessSignature::sign(
                &checkpoint,
                WitnessId::new(format!("witness.{index:03}")).test_unwrap(),
                &backend(u8::try_from(index + 50).test_unwrap()),
            )
            .test_unwrap()
        })
        .collect();
    let encoded = serde_json::to_vec(&checkpoint).test_unwrap();
    assert!(SignedKeyLogCheckpoint::from_canonical_bytes(&encoded).is_err());
}

fn checkpoint(operator: &Ed25519Backend) -> SignedKeyLogCheckpoint {
    SignedKeyLogCheckpoint::sign(
        chio_keyring::KeyLogCheckpointBody {
            schema: KEY_LOG_CHECKPOINT_SCHEMA.to_string(),
            log_id: LogId::new("log.enterprise.test").test_unwrap(),
            checkpoint_sequence: 0,
            tree_size: 1,
            root_hash: sha256(b"root"),
            previous_checkpoint_hash: None,
            issued_at: 1_000,
        },
        operator,
    )
    .test_unwrap()
}

#[test]
fn checkpoint_operator_signature_and_identity_are_canonical() {
    let operator = backend(10);
    let checkpoint = checkpoint(&operator);
    let canonical = checkpoint.canonical_body_bytes().test_unwrap();
    let restored_body: chio_keyring::KeyLogCheckpointBody =
        serde_json::from_slice(&canonical).test_unwrap();

    assert_eq!(restored_body, checkpoint.body);
    checkpoint
        .verify_operator(&operator.public_key())
        .test_unwrap();
    assert!(checkpoint
        .verify_operator(&backend(11).public_key())
        .is_err());
}

#[test]
fn witness_signatures_bind_checkpoint_hash_and_require_distinct_known_quorum() {
    let operator = backend(10);
    let witness_a = backend(20);
    let witness_b = backend(21);
    let witness_c = backend(22);
    let mut checkpoint = checkpoint(&operator);
    let identity_before = checkpoint.checkpoint_hash().test_unwrap();
    checkpoint.witness_signatures = vec![
        WitnessSignature::sign(
            &checkpoint,
            WitnessId::new("witness.a").test_unwrap(),
            &witness_a,
        )
        .test_unwrap(),
        WitnessSignature::sign(
            &checkpoint,
            WitnessId::new("witness.b").test_unwrap(),
            &witness_b,
        )
        .test_unwrap(),
    ];
    let keys = BTreeMap::from([
        (
            WitnessId::new("witness.a").test_unwrap(),
            witness_a.public_key(),
        ),
        (
            WitnessId::new("witness.b").test_unwrap(),
            witness_b.public_key(),
        ),
        (
            WitnessId::new("witness.c").test_unwrap(),
            witness_c.public_key(),
        ),
    ]);

    assert_eq!(checkpoint.checkpoint_hash().test_unwrap(), identity_before);
    assert_eq!(checkpoint.verify_witnesses(&keys).test_unwrap().len(), 2);

    let mut altered_operator_envelope = checkpoint.clone();
    altered_operator_envelope.operator_signature =
        operator.sign_bytes(b"other statement").test_unwrap();
    assert!(altered_operator_envelope
        .verify_witness_signatures(&keys)
        .is_err());

    let mut insufficient = checkpoint.clone();
    insufficient.witness_signatures.pop();
    assert!(insufficient.verify_witnesses(&keys).is_err());

    checkpoint
        .witness_signatures
        .push(checkpoint.witness_signatures[0].clone());
    assert!(checkpoint.verify_witnesses(&keys).is_err());

    let mut excessive = checkpoint;
    excessive
        .witness_signatures
        .push(excessive.witness_signatures[0].clone());
    assert!(excessive.verify_witnesses(&keys).is_err());
}

#[test]
fn checkpoint_validation_rejects_root_size_sequence_and_predecessor_mismatch() {
    let operator = backend(10);
    let checkpoint = checkpoint(&operator);
    checkpoint
        .validate(KeyLogCheckpointExpectation {
            log_id: &LogId::new("log.enterprise.test").test_unwrap(),
            sequence: 0,
            tree_size: 1,
            root: &sha256(b"root"),
            previous_checkpoint_hash: None,
            last_issued_at: None,
        })
        .test_unwrap();

    assert!(checkpoint
        .validate(KeyLogCheckpointExpectation {
            log_id: &LogId::new("log.enterprise.test").test_unwrap(),
            sequence: 1,
            tree_size: 1,
            root: &sha256(b"root"),
            previous_checkpoint_hash: None,
            last_issued_at: None,
        })
        .is_err());
    assert!(checkpoint
        .validate(KeyLogCheckpointExpectation {
            log_id: &LogId::new("log.enterprise.test").test_unwrap(),
            sequence: 0,
            tree_size: 2,
            root: &sha256(b"root"),
            previous_checkpoint_hash: None,
            last_issued_at: None,
        })
        .is_err());
}
