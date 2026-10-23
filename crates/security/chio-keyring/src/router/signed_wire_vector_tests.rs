use chio_test_support::prelude::*;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chio_core_types::crypto::SigningWrapper;
use chio_core_types::{
    canonical_json_bytes, CanonicalBytes, Ed25519Backend, Hash, Keypair, SigningBackend,
};

use super::{artifact_hash, KeyringArtifactSignature, KEYRING_ARTIFACT_SIGNATURE_SCHEMA};
use crate::signing::verify_wrapped_value;
use crate::{
    derive_key_id, AnchorId, ArtifactTimeAnchorBody, ArtifactTimeAnchorKind,
    AuditServiceReadinessBody, AuditServiceReadinessProof, KeyLogPin, SignedArtifactTimeAnchor,
    WitnessId, WitnessServiceReadinessBody, WitnessServiceReadinessProof, WitnessServiceView,
    ARTIFACT_TIME_ANCHOR_SCHEMA, KEY_LOG_AUDIT_READINESS_SCHEMA, KEY_LOG_CHECKPOINT_SCHEMA,
    KEY_LOG_WITNESS_READINESS_SCHEMA,
};

const ROUTER_SEED: u8 = 17;
const ANCHOR_SEED: u8 = 34;
const WITNESS_SEED: u8 = 51;
const AUDIT_SEED: u8 = 68;
const SIGNING_EPOCH: u64 = 7;
const CONFIGURATION_BINDING: &str =
    "0xb7d64a9221007dfd5390f7df6cd5b8f3ea4f82faa1237141e35ebf161f5511a1";
const STARTED_AT: u64 = 1_700_000_000_000;

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

fn hash(hex: &str) -> Hash {
    Hash::from_hex(hex).test_unwrap()
}

fn vector_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/bindings/vectors/security/signed-wire")
}

fn line(value: &impl serde::Serialize) -> Vec<u8> {
    let mut bytes = canonical_json_bytes(value).test_unwrap();
    bytes.push(b'\n');
    bytes
}

fn pin() -> KeyLogPin {
    KeyLogPin {
        checkpoint_sequence: 4,
        tree_size: 5,
        checkpoint_hash: hash(
            "0x47320987f9a49d5b00119b960f247a956773f57543982b8bfcb6da5bb3afd9ef",
        ),
        root_hash: hash("0x4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"),
        signing_epoch: 2,
    }
}

fn witness_storage_identity() -> Hash {
    hash("0xe6a253898d7c5cf3e7c4ca7824498bd6e13b374e937ac42b5ac1fb764af1d9b6")
}

fn witness_body() -> WitnessServiceReadinessBody {
    WitnessServiceReadinessBody {
        schema: KEY_LOG_WITNESS_READINESS_SCHEMA.to_string(),
        witness_id: WitnessId::new("witness.vector.1").test_unwrap(),
        configuration_binding: hash(CONFIGURATION_BINDING),
        nonce: "witness-nonce-vector-1".to_string(),
        process_id: 4242,
        storage_identity: witness_storage_identity(),
        started_at: STARTED_AT,
        pin: Some(pin()),
        conflict_count: 0,
        gossip_observation_count: 3,
    }
}

fn witness_proof() -> WitnessServiceReadinessProof {
    WitnessServiceReadinessProof::sign(witness_body(), &backend(WITNESS_SEED)).test_unwrap()
}

fn audit_body() -> AuditServiceReadinessBody {
    let witness_id = WitnessId::new("witness.vector.1").test_unwrap();
    AuditServiceReadinessBody {
        schema: KEY_LOG_AUDIT_READINESS_SCHEMA.to_string(),
        monitor_id: "audit.vector.1".to_string(),
        configuration_binding: hash(CONFIGURATION_BINDING),
        nonce: "audit-nonce-vector-1".to_string(),
        process_id: 4343,
        storage_identity: hash(
            "0xc1681d8f87d9c6182c63c95346acef592038184455b05e0ad4de51cab528db43",
        ),
        started_at: STARTED_AT,
        last_successful_poll_at: 1_700_000_000_100,
        pin: Some(pin()),
        operator_head: pin(),
        witness_views: BTreeMap::from([(
            witness_id.clone(),
            WitnessServiceView {
                pin: Some(pin()),
                process_id: 4242,
                storage_identity: witness_storage_identity(),
                conflict_count: 0,
            },
        )]),
        witness_proofs: BTreeMap::from([(witness_id, witness_proof())]),
        conflict_count: 0,
    }
}

fn audit_proof() -> AuditServiceReadinessProof {
    AuditServiceReadinessProof::sign(audit_body(), &backend(AUDIT_SEED)).test_unwrap()
}

fn artifact_canonical() -> CanonicalBytes {
    CanonicalBytes::from_serializable(&serde_json::json!({ "artifact": "signed-wire-vector" }))
        .test_unwrap()
}

fn artifact_bytes() -> Vec<u8> {
    SigningWrapper::new(KEY_LOG_CHECKPOINT_SCHEMA, &artifact_canonical())
        .test_unwrap()
        .as_bytes()
        .to_vec()
}

fn artifact_signature() -> KeyringArtifactSignature {
    let router = backend(ROUTER_SEED);
    let public_key = router.public_key().test_unwrap();
    let outcome = router
        .sign_wrapped_for_identity(&public_key, KEY_LOG_CHECKPOINT_SCHEMA, &artifact_canonical())
        .test_unwrap();
    KeyringArtifactSignature::sign_fence(
        &router,
        &public_key,
        artifact_hash(&artifact_bytes()).test_unwrap(),
        derive_key_id(public_key.algorithm(), &public_key).test_unwrap(),
        SIGNING_EPOCH,
        outcome,
    )
    .test_unwrap()
}

fn time_anchor_body() -> ArtifactTimeAnchorBody {
    ArtifactTimeAnchorBody {
        schema: ARTIFACT_TIME_ANCHOR_SCHEMA.to_string(),
        anchor_id: AnchorId::new("anchor.vector.1").test_unwrap(),
        artifact_hash: artifact_hash(&artifact_bytes()).test_unwrap(),
        anchored_at: 1_700_000_000_123,
        anchor: ArtifactTimeAnchorKind::External {
            commitment: hash(
                "0x268bdf049e4b7ae47c4c52b10388147af455b0fba9c3b545b2f0c0d1241329cd",
            ),
        },
    }
}

fn time_anchor() -> SignedArtifactTimeAnchor {
    SignedArtifactTimeAnchor::sign(time_anchor_body(), &backend(ANCHOR_SEED)).test_unwrap()
}

fn generated_positives() -> Vec<(&'static str, Vec<u8>)> {
    let anchor = time_anchor();
    let witness = witness_proof();
    let audit = audit_proof();
    vec![
        (
            "positive/key-log-artifact-time-anchor-body-v1.json",
            line(&anchor.body),
        ),
        (
            "positive/key-log-artifact-time-anchor-envelope-v1.json",
            line(&anchor),
        ),
        (
            "positive/key-log-audit-readiness-body-v1.json",
            line(&audit.body),
        ),
        (
            "positive/key-log-audit-readiness-proof-v1.json",
            line(&audit),
        ),
        (
            "positive/key-log-witness-readiness-body-v1.json",
            line(&witness.body),
        ),
        (
            "positive/key-log-witness-readiness-proof-v1.json",
            line(&witness),
        ),
        (
            "positive/keyring-artifact-signature-v1.json",
            line(&artifact_signature()),
        ),
    ]
}

fn committed(relative: &str) -> Vec<u8> {
    std::fs::read(vector_root().join(relative)).test_unwrap()
}

fn canonical_of(relative: &str) -> Vec<u8> {
    let bytes = committed(relative);
    bytes
        .strip_suffix(b"\n")
        .test_expect("committed fixture ends with a newline")
        .to_vec()
}

#[test]
fn committed_keyring_signed_wire_positives_match_the_signing_paths() {
    for (relative, expected) in generated_positives() {
        assert!(
            committed(relative) == expected,
            "fixture tests/bindings/vectors/security/signed-wire/{relative} is out of date"
        );
    }
}

#[test]
fn committed_keyring_signed_wire_positives_verify_against_the_pinned_keys() {
    let anchor: SignedArtifactTimeAnchor = crate::from_bounded_json(&canonical_of(
        "positive/key-log-artifact-time-anchor-envelope-v1.json",
    ))
    .test_unwrap();
    let anchor_key = backend(ANCHOR_SEED).public_key().test_unwrap();
    assert_eq!(
        anchor.anchor_key_id,
        derive_key_id(anchor_key.algorithm(), &anchor_key).test_unwrap()
    );
    verify_wrapped_value(
        &anchor_key,
        ARTIFACT_TIME_ANCHOR_SCHEMA,
        &anchor.body,
        &anchor.signature,
    )
    .test_unwrap();

    let witness: WitnessServiceReadinessProof = crate::from_bounded_json(&canonical_of(
        "positive/key-log-witness-readiness-proof-v1.json",
    ))
    .test_unwrap();
    witness
        .verify(
            &WitnessId::new("witness.vector.1").test_unwrap(),
            &backend(WITNESS_SEED).public_key().test_unwrap(),
            hash(CONFIGURATION_BINDING),
            "witness-nonce-vector-1",
        )
        .test_unwrap();

    let audit: AuditServiceReadinessProof = crate::from_bounded_json(&canonical_of(
        "positive/key-log-audit-readiness-proof-v1.json",
    ))
    .test_unwrap();
    audit
        .verify(
            "audit.vector.1",
            &backend(AUDIT_SEED).public_key().test_unwrap(),
            hash(CONFIGURATION_BINDING),
            "audit-nonce-vector-1",
        )
        .test_unwrap();

    let evidence = KeyringArtifactSignature::from_canonical_bytes(&canonical_of(
        "positive/keyring-artifact-signature-v1.json",
    ))
    .test_unwrap();
    assert_eq!(evidence.schema, KEYRING_ARTIFACT_SIGNATURE_SCHEMA);
    evidence
        .verify_artifact_bytes(
            &backend(ROUTER_SEED).public_key().test_unwrap(),
            &artifact_bytes(),
        )
        .test_unwrap();
}

#[test]
#[ignore = "regenerator: rewrites the keyring rows of tests/bindings/vectors/security/signed-wire/positive"]
fn regenerate_keyring_signed_wire_positives() {
    for (relative, bytes) in generated_positives() {
        std::fs::write(vector_root().join(relative), bytes).test_unwrap();
    }
}
