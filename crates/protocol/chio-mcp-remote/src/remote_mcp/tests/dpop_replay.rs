use super::*;
use chio_core::crypto::Keypair;
use chio_kernel::dpop::{DpopProofBody, MAX_DPOP_REPLAY_IDENTITY_PART_BYTES};
use std::time::Duration;

#[test]
fn sender_headers_retain_non_text_causes_before_replay_custody() {
    use std::error::Error;
    for (header, claims) in [
        (
            CHIO_MTLS_THUMBPRINT_HEADER,
            ChioSenderConstraintClaims {
                mtls_thumbprint_sha256: Some("thumbprint".into()),
                ..Default::default()
            },
        ),
        (
            CHIO_RUNTIME_ATTESTATION_HEADER,
            ChioSenderConstraintClaims {
                chio_attestation_sha256: Some("attestation".into()),
                ..Default::default()
            },
        ),
        (
            DPOP_HEADER,
            ChioSenderConstraintClaims {
                chio_sender_key: Some(Keypair::generate().public_key().to_hex()),
                ..Default::default()
            },
        ),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            header,
            HeaderValue::from_bytes(b"private-marker\xff").unwrap(),
        );
        let store = DpopNonceStore::new(8, Duration::from_secs(30)).unwrap();
        let error =
            SenderConstraintVerifier::new(&RemoteClock::default(), &store, &DpopConfig::default())
                .validate(
                    Some(&claims),
                    &headers,
                    Some("sender-binding"),
                    "chio-mcp",
                    "POST",
                )
                .unwrap_err();
        assert!(error
            .source()
            .unwrap()
            .is::<axum::http::header::ToStrError>());
        assert_eq!(store.utilization().unwrap().0, 0);
        assert!(!format!("{error:?} {error}").contains("private-marker"));
    }
}

#[tokio::test]
async fn sender_key_rejection_keeps_decode_source_out_of_the_wire_response() {
    let response =
        build_request_sender_constraint(Some("private-invalid-key"), None, None, None).unwrap_err();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response
        .extensions()
        .get::<Arc<chio_core::error::Error>>()
        .is_some());
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"], "invalid_request");
    assert!(!std::str::from_utf8(&body)
        .unwrap()
        .contains("private-invalid-key"));
}

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

fn verify(
    proof: &DpopProof,
    store: &DpopNonceStore,
    config: &DpopConfig,
) -> Result<(), SenderConstraintError> {
    SenderConstraintVerifier::new(&RemoteClock::default(), store, config).verify_proof(
        proof,
        "sender-binding",
        "chio-mcp",
        "POST",
        &proof.body.agent_key,
    )
}

#[test]
fn sender_dpop_signed_retention_overrides_local_ttl_for_future_dated_proofs() {
    let key = Keypair::generate();
    let config = DpopConfig::default();
    let store =
        DpopNonceStore::new(8, Duration::ZERO).expect("positive replay store test capacities");
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
    let legacy =
        DpopNonceStore::new(8, Duration::ZERO).expect("positive replay store test capacities");
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
    let store =
        DpopNonceStore::new(8, Duration::ZERO).expect("positive replay store test capacities");
    let mut proof = proof(&key, "nonce".to_owned(), unix_now());
    proof.body.nonce = "private-marker".repeat(MAX_DPOP_REPLAY_IDENTITY_PART_BYTES);
    let error = verify(&proof, &store, &config).unwrap_err();
    assert!(matches!(
        error,
        SenderConstraintError::Replay(chio_kernel::KernelError::Dpop(
            chio_kernel::dpop::DpopError::IdentityLimit
        ))
    ));
    assert!(!error.to_string().contains("private-marker"));
    assert_eq!(store.utilization().unwrap().0, 0);
    assert_eq!(store.identity_byte_utilization().unwrap().0, 0);
}

#[test]
fn sender_dpop_byte_pressure_preserves_the_consumed_proof() {
    let key = Keypair::generate();
    let config = DpopConfig::default();
    let store = DpopNonceStore::new_with_identity_byte_capacity(8, 8, 40, Duration::ZERO)
        .expect("positive replay store test capacities");
    let first = proof(&key, "first".to_owned(), unix_now());
    verify(&first, &store, &config).unwrap();
    let second = proof(&key, "second".to_owned(), unix_now());
    assert!(matches!(
        verify(&second, &store, &config),
        Err(SenderConstraintError::Replay(
            chio_kernel::KernelError::Dpop(chio_kernel::dpop::DpopError::IdentityCapacity)
        ))
    ));
    assert!(matches!(
        verify(&first, &store, &config),
        Err(crate::input::SenderConstraintError::NonceReused)
    ));
    assert_eq!(store.utilization().unwrap().0, 1);
}

#[test]
fn sender_legacy_profile_rejects_a_durable_domain_even_when_resigned_as_v1() {
    use chio_kernel::admission_operation::{AdmissionDigest, AdmissionIdentifier};
    use chio_kernel::dpop::authority::{
        DpopReplayAuthorityInputV1, DpopReplayAuthorityV1, DPOP_AUTHORITY_SCHEMA,
    };
    let key = Keypair::generate();
    let config = DpopConfig::default();
    let store = DpopNonceStore::new(8, Duration::from_secs(300))
        .expect("positive replay store test capacities");
    let mut body = proof(&key, "authority-proof".into(), unix_now()).body;
    body.replay_authority = Some(
        DpopReplayAuthorityV1::new(DpopReplayAuthorityInputV1 {
            destination_store_uuid: AdmissionIdentifier::try_new(
                "destination",
                "018f9878-7047-7abc-8c98-120dc65700ea",
            )
            .unwrap(),
            dpop_authority_id: AdmissionIdentifier::try_new("authority", "configured").unwrap(),
            expectation_id: AdmissionDigest::try_new("expectation", "a".repeat(64)).unwrap(),
            proof_ttl_secs: 300,
            max_clock_skew_secs: 30,
        })
        .unwrap(),
    );
    for schema in [chio_kernel::DPOP_SCHEMA, DPOP_AUTHORITY_SCHEMA] {
        body.schema = schema.into();
        let signed = DpopProof::sign(body.clone(), &key).unwrap();
        assert!(matches!(
            verify(&signed, &store, &config),
            Err(crate::input::SenderConstraintError::UnsupportedSchema)
        ));
        assert_eq!(store.utilization().unwrap().0, 0);
    }
}
