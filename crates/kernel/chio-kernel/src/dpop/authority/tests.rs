use super::*;
use crate::dpop::{DpopNonceStore, DpopProofBody, DPOP_SCHEMA};
use chio_core::capability::{scope::ChioScope, token::CapabilityTokenBody};
use chio_core::crypto::Keypair;
use std::time::Duration;

const NOW: u64 = 1_800_000_000;

fn authority() -> DpopReplayAuthority {
    DpopReplayAuthority::new(DpopReplayAuthorityInput {
        destination_store_uuid: AdmissionIdentifier::try_new(
            "destination",
            "018f9878-7047-7abc-8c98-120dc65700ea",
        )
        .unwrap(),
        dpop_authority_id: AdmissionIdentifier::try_new("authority", "configured-dpop").unwrap(),
        expectation_id: AdmissionDigest::try_new("expectation", "a".repeat(64)).unwrap(),
        proof_ttl_secs: 300,
        max_clock_skew_secs: 30,
    })
    .unwrap()
}

fn fixture() -> (Keypair, CapabilityToken, DpopProof) {
    let key = Keypair::generate();
    let issuer = Keypair::generate();
    let cap = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "private-capability".into(),
            issuer: issuer.public_key(),
            subject: key.public_key(),
            scope: ChioScope::default(),
            issued_at: NOW - 1,
            expires_at: NOW + 3600,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .unwrap();
    let proof = DpopProof::sign(
        DpopProofBody {
            schema: DPOP_SCHEMA.into(),
            replay_authority: authority(),
            capability_id: cap.id.clone(),
            tool_server: "server".into(),
            tool_name: "tool".into(),
            action_hash: sha256_hex(b"{}"),
            nonce: "private-nonce".into(),
            issued_at: NOW,
            agent_key: key.public_key(),
        },
        &key,
    )
    .unwrap();
    (key, cap, proof)
}

fn verify(
    proof: &DpopProof,
    cap: &CapabilityToken,
    expected: &DpopReplayAuthority,
    now: u64,
) -> Result<VerifiedDpopReplayProof, KernelError> {
    verify_dpop_proof_stateless(
        proof,
        cap,
        "server",
        "tool",
        &sha256_hex(b"{}"),
        expected,
        now,
    )
}

#[test]
fn single_profile_accepts_authority_bound_v1() {
    let (key, cap, proof) = fixture();
    let mut body = proof.body;
    body.schema = "chio.dpop_proof.v1".to_owned();
    let proof = DpopProof::sign(body, &key).unwrap();
    assert!(verify(&proof, &cap, &authority(), NOW).is_ok());
}

#[test]
fn single_profile_refuses_retired_v2_id() {
    let (key, cap, proof) = fixture();
    let mut body = proof.body;
    body.schema = "chio.dpop_proof.v2".to_owned();
    let proof = DpopProof::sign(body, &key).unwrap();
    assert!(matches!(
        verify(&proof, &cap, &authority(), NOW),
        Err(KernelError::Dpop(crate::dpop::DpopError::Schema))
    ));
}

#[test]
fn single_profile_refuses_authority_free_shape() {
    let (_, _, proof) = fixture();
    let mut value = serde_json::to_value(proof).unwrap();
    value["body"]["schema"] = serde_json::json!("chio.dpop_proof.v1");
    value["body"]
        .as_object_mut()
        .unwrap()
        .remove("replay_authority");
    let error = serde_json::from_value::<DpopProof>(value).unwrap_err();
    assert_eq!(error.to_string(), "missing field `replay_authority`");
}

fn weak_key_forgery() -> (CapabilityToken, DpopProof) {
    let (_, cap, mut proof) = fixture();
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    let weak = chio_core::crypto::PublicKey::from_bytes(&identity).unwrap();
    let issuer = Keypair::generate();
    let mut body = cap.body();
    body.issuer = issuer.public_key();
    body.subject = weak.clone();
    let cap = CapabilityToken::sign(body, &issuer).unwrap();
    assert!(cap.verify_signature().unwrap());
    proof.body.agent_key = weak;
    let mut signature = [0_u8; 64];
    signature[0] = 1;
    proof.signature = chio_core::crypto::Signature::from_bytes(&signature);
    (cap, proof)
}

#[test]
fn durable_dpop_rejects_weak_key_forgery() {
    let (cap, proof) = weak_key_forgery();
    assert!(matches!(
        verify(&proof, &cap, &authority(), NOW),
        Err(KernelError::Dpop(crate::dpop::DpopError::Signature))
    ));
}

#[test]
fn exact_authority_signature_yields_only_non_consuming_bounded_evidence() {
    let (_, cap, proof) = fixture();
    let verified = verify(&proof, &cap, &authority(), NOW).unwrap();
    assert_eq!(verified.authority(), &authority());
    assert_eq!(verified.capability_id(), cap.id);
    assert_eq!(verified.nonce(), "private-nonce");
    assert_eq!(verified.issued_at_unix_secs(), NOW);
    assert_eq!(verified.valid_through_unix_secs(), NOW + 300);
    assert_eq!(
        verified.proof_digest().as_str(),
        sha256_hex(&canonical_json_bytes(&proof).unwrap())
    );
    let debug = format!("{verified:?}");
    assert!(!debug.contains("private-nonce"));
    assert!(!debug.contains("private-capability"));
    // Stateless verification can repeat. Neither result is replay custody.
    assert!(verify(&proof, &cap, &authority(), NOW).is_ok());
}

#[test]
fn every_destination_generation_and_policy_field_is_pinned_and_signed() {
    let (key, cap, proof) = fixture();
    for field in 0..5 {
        let mut changed = authority();
        match field {
            0 => {
                changed.destination_store_uuid = AdmissionIdentifier::try_new(
                    "destination",
                    "018f9878-7047-7abc-8c98-120dc65700eb",
                )
                .unwrap()
            }
            1 => {
                changed.dpop_authority_id =
                    AdmissionIdentifier::try_new("authority", "another-authority").unwrap()
            }
            2 => {
                changed.expectation_id =
                    AdmissionDigest::try_new("expectation", "b".repeat(64)).unwrap()
            }
            3 => changed.proof_ttl_secs += 1,
            4 => changed.max_clock_skew_secs += 1,
            _ => unreachable!(),
        }
        assert!(matches!(
            verify(&proof, &cap, &changed, NOW),
            Err(KernelError::Dpop(crate::dpop::DpopError::AuthorityMismatch))
        ));
        let mut tampered = proof.clone();
        tampered.body.replay_authority = changed.clone();
        assert!(
            verify(&tampered, &cap, &changed, NOW).is_err(),
            "unsigned change {field}"
        );
        let resigned = DpopProof::sign(tampered.body, &key).unwrap();
        assert!(
            verify(&resigned, &cap, &authority(), NOW).is_err(),
            "caller cannot select domain {field}"
        );
        assert!(verify(&resigned, &cap, &changed, NOW).is_ok());
    }
}

#[test]
fn durable_freshness_preserves_inclusive_horizon_and_future_skew() {
    let (_, cap, mut proof) = fixture();
    for (now, admitted) in [
        (NOW - 31, false),
        (NOW - 30, true),
        (NOW, true),
        (NOW + 300, true),
        (NOW + 301, false),
    ] {
        assert_eq!(
            verify(&proof, &cap, &authority(), now).is_ok(),
            admitted,
            "time {now}"
        );
    }
    for issued in [u64::MAX, MAX_UNIX_SECS - 299] {
        proof.body.issued_at = issued;
        assert!(matches!(
            verify(&proof, &cap, &authority(), MAX_UNIX_SECS),
            Err(KernelError::Dpop(crate::dpop::DpopError::WindowOverflow))
        ));
    }
    proof.body.issued_at = NOW;
    let error = verify(&proof, &cap, &authority(), MAX_UNIX_SECS + 1)
        .unwrap_err()
        .to_string();
    assert!(error.contains("authority clock exceeds"), "{error}");
}

#[test]
fn common_sender_and_invocation_checks_remain_mandatory() {
    let (key, cap, proof) = fixture();
    for field in 0..5 {
        let mut body = proof.body.clone();
        match field {
            0 => body.agent_key = Keypair::generate().public_key(),
            1 => body.capability_id = "other-capability".into(),
            2 => body.tool_server = "other-server".into(),
            3 => body.tool_name = "other-tool".into(),
            4 => body.action_hash = sha256_hex(b"changed"),
            _ => unreachable!(),
        }
        assert!(verify(
            &DpopProof::sign(body, &key).unwrap(),
            &cap,
            &authority(),
            NOW
        )
        .is_err());
    }
}

#[test]
fn signed_preimage_requires_the_exact_authority_object() {
    let (_, _, proof) = fixture();
    let value = serde_json::to_value(&proof.body).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 9);
    assert_eq!(
        value["replay_authority"],
        serde_json::to_value(authority()).unwrap()
    );
    let decoded: DpopProofBody = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        canonical_json_bytes(&decoded).unwrap(),
        canonical_json_bytes(&proof.body).unwrap()
    );
    for (invalid, expected) in [
        (
            serde_json::Value::Null,
            "invalid type: null, expected struct DpopReplayAuthorityInput",
        ),
        (
            serde_json::json!({}),
            "missing field `destination_store_uuid`",
        ),
        (
            serde_json::json!(false),
            "invalid type: boolean `false`, expected struct DpopReplayAuthorityInput",
        ),
    ] {
        let mut changed = value.clone();
        changed["replay_authority"] = invalid;
        assert_eq!(
            serde_json::from_value::<DpopProofBody>(changed)
                .unwrap_err()
                .to_string(),
            expected
        );
    }
}

#[test]
fn authority_decode_rejects_noncanonical_identity_unknown_fields_and_unbounded_policy() {
    let original = serde_json::to_value(authority()).unwrap();
    for (field, value, expected) in [
        (
            "destination_store_uuid",
            serde_json::json!("018F9878-7047-7ABC-8C98-120DC65700EA"),
            "DPoP proof verification failed: durable DPoP profile: destination store UUID is not canonical",
        ),
        (
            "destination_store_uuid",
            serde_json::json!(uuid::Uuid::nil().to_string()),
            "DPoP proof verification failed: durable DPoP profile: destination store UUID is not canonical",
        ),
        (
            "expectation_id",
            serde_json::json!("not-a-digest"),
            "persisted_admission_digest must be lowercase SHA-256 hex",
        ),
        (
            "dpop_authority_id",
            serde_json::json!(" padded"),
            "persisted_admission_text must not have leading or trailing whitespace",
        ),
        (
            "proof_ttl_secs",
            serde_json::json!(0),
            "DPoP proof verification failed: durable DPoP profile: durable freshness policy exceeds its bounds",
        ),
        (
            "proof_ttl_secs",
            serde_json::json!(MAX_DURABLE_DPOP_TTL_SECS + 1),
            "DPoP proof verification failed: durable DPoP profile: durable freshness policy exceeds its bounds",
        ),
        (
            "max_clock_skew_secs",
            serde_json::json!(MAX_DURABLE_DPOP_CLOCK_SKEW_SECS + 1),
            "DPoP proof verification failed: durable DPoP profile: durable freshness policy exceeds its bounds",
        ),
        (
            "active",
            serde_json::json!(true),
            "unknown field `active`, expected one of `destination_store_uuid`, `dpop_authority_id`, `expectation_id`, `proof_ttl_secs`, `max_clock_skew_secs`",
        ),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert_eq!(
            serde_json::from_value::<DpopReplayAuthority>(changed)
                .unwrap_err()
                .to_string(),
            expected,
            "{field}"
        );
    }
    assert_eq!(
        serde_json::from_value::<DpopReplayAuthority>(original).unwrap(),
        authority()
    );
}

#[test]
fn oversized_replay_keys_fail_before_signature_or_evidence_allocation() {
    let (_, cap, mut proof) = fixture();
    proof.body.nonce = "é".repeat(crate::dpop::MAX_DPOP_REPLAY_IDENTITY_PART_BYTES / 2 + 1);
    let error = verify(&proof, &cap, &authority(), NOW)
        .unwrap_err()
        .to_string();
    assert!(error.contains("4096-byte limit"));
}

#[test]
fn invalid_system_clock_is_not_reinterpreted_as_epoch_zero() {
    use chio_security_types::clock::{Clock, ClockError, ClockReading};
    struct BeforeEpoch;
    impl Clock for BeforeEpoch {
        fn read(&self) -> Result<ClockReading, ClockError> {
            Err(ClockError::BeforeEpoch)
        }
    }
    let store = DpopNonceStore::with_clock(
        8,
        8,
        4096,
        Duration::from_secs(60),
        std::sync::Arc::new(BeforeEpoch),
    )
    .expect("positive replay store test capacities");
    assert!(matches!(
        store.check_and_insert("nonce", "cap"),
        Err(KernelError::Clock(ClockError::BeforeEpoch))
    ));
    assert_eq!(store.utilization().unwrap().0, 0);
}

#[test]
fn typescript_wire_vector_matches_rust_canonical_bytes_and_signature_verification() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/fixtures/dpop-authority-v1.json"
    )))
    .unwrap();
    let proof: DpopProof = serde_json::from_value(vector["proof"].clone()).unwrap();
    assert_eq!(
        String::from_utf8(canonical_json_bytes(&proof.body).unwrap()).unwrap(),
        vector["canonical_body"].as_str().unwrap()
    );
    assert_eq!(
        sha256_hex(&canonical_json_bytes(&proof).unwrap()),
        vector["proof_sha256"].as_str().unwrap()
    );
    let issuer = Keypair::generate();
    let cap = CapabilityToken::sign(
        CapabilityTokenBody {
            id: proof.body.capability_id.clone(),
            issuer: issuer.public_key(),
            subject: proof.body.agent_key.clone(),
            scope: ChioScope::default(),
            issued_at: NOW - 1,
            expires_at: NOW + 3600,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .unwrap();
    let verified = verify(&proof, &cap, &authority(), NOW).unwrap();
    assert_eq!(
        verified.proof_digest().as_str(),
        vector["proof_sha256"].as_str().unwrap()
    );
}

#[test]
fn proof_decode_rejects_unsigned_unknown_body_and_envelope_fields() {
    let (_, _, proof) = fixture();
    let original = serde_json::to_value(&proof).unwrap();
    let mut body_extra = original.clone();
    body_extra["body"]["activated"] = true.into();
    assert!(serde_json::from_value::<DpopProof>(body_extra).is_err());
    let mut envelope_extra = original;
    envelope_extra["dispatch_permit"] = true.into();
    assert!(serde_json::from_value::<DpopProof>(envelope_extra).is_err());
}
