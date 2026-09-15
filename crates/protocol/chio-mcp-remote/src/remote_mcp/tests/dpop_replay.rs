use super::*;
use chio_core::crypto::Keypair;
use chio_kernel::dpop::{DpopProofBody, MAX_DPOP_REPLAY_IDENTITY_PART_BYTES};
use std::time::Duration;

fn proof(key: &Keypair, nonce: String, issued_at: u64) -> DpopProof {
    DpopProof::sign(
        DpopProofBody {
            replay_authority: None,
            schema: chio_kernel::DPOP_SCHEMA.to_owned(),
            capability_id: "sender-binding".to_owned(),
            tool_server: "chio-mcp".to_owned(),
            tool_name: "POST".to_owned(),
            action_hash: sha256_hex(HTTP_DPOP_ACTION_HASH_EMPTY),
            nonce,
            issued_at,
            agent_key: key.public_key(),
        },
        key,
    )
    .unwrap()
}

fn verify(proof: &DpopProof, store: &DpopNonceStore, config: &DpopConfig) -> Result<(), String> {
    verify_sender_dpop_proof(
        proof,
        "sender-binding",
        "chio-mcp",
        "POST",
        &proof.body.agent_key,
        store,
        config,
    )
}

#[test]
fn sender_dpop_signed_retention_overrides_local_ttl_for_future_dated_proofs() {
    let key = Keypair::generate();
    let config = DpopConfig::default();
    let store = DpopNonceStore::new(8, Duration::ZERO);
    let proof = proof(
        &key,
        "sender-proof".to_owned(),
        unix_now() + config.max_clock_skew_secs,
    );
    verify(&proof, &store, &config).unwrap();
    assert!(verify(&proof, &store, &config).is_err());
    assert_eq!(store.utilization().unwrap().0, 1);
    // Characterize the former local-TTL path: the same cache configuration
    // immediately forgets local-only markers, although this proof is valid.
    let legacy = DpopNonceStore::new(8, Duration::ZERO);
    assert!(legacy
        .check_and_insert(&proof.body.nonce, "sender-binding")
        .unwrap());
    assert!(legacy
        .check_and_insert(&proof.body.nonce, "sender-binding")
        .unwrap());
}

#[test]
fn sender_dpop_rejects_oversized_keys_before_signature_verification_or_storage() {
    let key = Keypair::generate();
    let config = DpopConfig::default();
    let store = DpopNonceStore::new(8, Duration::ZERO);
    let mut proof = proof(&key, "nonce".to_owned(), unix_now());
    proof.body.nonce = "private-marker".repeat(MAX_DPOP_REPLAY_IDENTITY_PART_BYTES);
    let error = verify(&proof, &store, &config).unwrap_err();
    assert!(error.contains("4096-byte limit"));
    assert!(!error.contains("private-marker"));
    assert_eq!(store.utilization().unwrap().0, 0);
    assert_eq!(store.identity_byte_utilization().unwrap().0, 0);
}

#[test]
fn sender_dpop_byte_pressure_preserves_the_consumed_proof() {
    let key = Keypair::generate();
    let config = DpopConfig::default();
    let store = DpopNonceStore::new_with_identity_byte_capacity(8, 8, 40, Duration::ZERO);
    let first = proof(&key, "first".to_owned(), unix_now());
    verify(&first, &store, &config).unwrap();
    let second = proof(&key, "second".to_owned(), unix_now());
    assert!(verify(&second, &store, &config)
        .unwrap_err()
        .contains("byte capacity"));
    assert!(verify(&first, &store, &config)
        .unwrap_err()
        .contains("already used"));
    assert_eq!(store.utilization().unwrap().0, 1);
}

#[test]
fn sender_legacy_profile_rejects_a_durable_domain_even_when_resigned_as_v1() {
    use chio_kernel::admission_operation::{AdmissionDigest, AdmissionIdentifier};
    use chio_kernel::dpop::authority::{DpopReplayAuthorityInputV1, DpopReplayAuthorityV1, DPOP_AUTHORITY_SCHEMA};
    let key = Keypair::generate();
    let config = DpopConfig::default();
    let store = DpopNonceStore::new(8, Duration::from_secs(300));
    let mut body = proof(&key, "authority-proof".into(), unix_now()).body;
    body.replay_authority = Some(DpopReplayAuthorityV1::new(DpopReplayAuthorityInputV1 {
        destination_store_uuid: AdmissionIdentifier::try_new("destination", "018f9878-7047-7abc-8c98-120dc65700ea").unwrap(),
        dpop_authority_id: AdmissionIdentifier::try_new("authority", "configured").unwrap(),
        expectation_id: AdmissionDigest::try_new("expectation", "a".repeat(64)).unwrap(),
        proof_ttl_secs: 300, max_clock_skew_secs: 30,
    }).unwrap());
    for schema in [chio_kernel::DPOP_SCHEMA, DPOP_AUTHORITY_SCHEMA] {
        body.schema = schema.into();
        let signed = DpopProof::sign(body.clone(), &key).unwrap();
        assert!(verify(&signed, &store, &config).unwrap_err().contains("unsupported DPoP schema"));
        assert_eq!(store.utilization().unwrap().0, 0);
    }
}
