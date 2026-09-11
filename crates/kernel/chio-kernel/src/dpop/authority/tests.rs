use super::*;
use crate::dpop::{DpopNonceStore, DpopProofBody, DPOP_SCHEMA};
use chio_core::capability::{scope::ChioScope, token::CapabilityTokenBody};
use chio_core::crypto::Keypair;
use std::time::{Duration, UNIX_EPOCH};

const NOW: u64 = 1_800_000_000;

fn authority() -> DpopReplayAuthorityV1 {
    DpopReplayAuthorityV1::new(DpopReplayAuthorityInputV1 {
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
            schema: DPOP_AUTHORITY_SCHEMA.into(),
            replay_authority: Some(authority()),
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
    expected: &DpopReplayAuthorityV1,
    now: u64,
) -> Result<VerifiedDpopReplayProof, KernelError> {
    verify_authority_dpop_proof_stateless(
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
fn legacy_consuming_and_preview_ports_refuse_v2_without_burning_a_nonce() {
    let (_, cap, proof) = fixture();
    let store = DpopNonceStore::new(8, Duration::from_secs(300));
    assert!(crate::dpop::verify_dpop_proof_stateless(
        &proof,
        &cap,
        "server",
        "tool",
        &sha256_hex(b"{}"),
        &DpopConfig::default()
    )
    .is_err());
    assert!(crate::dpop::verify_dpop_proof(
        &proof,
        &cap,
        "server",
        "tool",
        &sha256_hex(b"{}"),
        &store,
        &DpopConfig::default()
    )
    .is_err());
    assert_eq!(store.utilization().unwrap().0, 0);
    assert_eq!(store.identity_byte_utilization().unwrap().0, 0);
}

#[test]
fn old_proofs_and_schema_downgrades_never_enter_the_durable_domain() {
    let (key, cap, proof) = fixture();
    for retain_authority in [false, true] {
        let mut body = proof.body.clone();
        body.schema = DPOP_SCHEMA.into();
        if !retain_authority {
            body.replay_authority = None;
        }
        let legacy = DpopProof::sign(body, &key).unwrap();
        assert!(verify(&legacy, &cap, &authority(), NOW).is_err());
        if retain_authority {
            assert!(crate::dpop::verify_dpop_proof_stateless(
                &legacy,
                &cap,
                "server",
                "tool",
                &sha256_hex(b"{}"),
                &DpopConfig::default()
            )
            .is_err());
        }
    }
    let mut downgraded = proof.clone();
    downgraded.body.replay_authority = None;
    assert!(verify(&downgraded, &cap, &authority(), NOW).is_err());
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
        assert!(verify(&proof, &cap, &changed, NOW).is_err());
        let mut tampered = proof.clone();
        tampered.body.replay_authority = Some(changed.clone());
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
        let error = verify(&proof, &cap, &authority(), MAX_UNIX_SECS)
            .unwrap_err()
            .to_string();
        assert!(error.contains("validity exceeds"), "{error}");
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
fn legacy_canonical_preimage_is_unchanged_when_authority_is_absent() {
    let (key, _, proof) = fixture();
    let mut body = proof.body;
    body.schema = DPOP_SCHEMA.into();
    body.replay_authority = None;
    let signed = DpopProof::sign(body, &key).unwrap();
    let value = serde_json::to_value(&signed.body).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 8);
    assert!(value.get("replay_authority").is_none());
    let bytes = canonical_json_bytes(&signed.body).unwrap();
    assert!(key.public_key().verify(&bytes, &signed.signature));
    let decoded: DpopProofBody = serde_json::from_value(value).unwrap();
    assert!(decoded.replay_authority.is_none());
    assert_eq!(canonical_json_bytes(&decoded).unwrap(), bytes);
}

#[test]
fn authority_decode_rejects_noncanonical_identity_unknown_fields_and_unbounded_policy() {
    let original = serde_json::to_value(authority()).unwrap();
    for (field, value) in [
        (
            "destination_store_uuid",
            serde_json::json!("018F9878-7047-7ABC-8C98-120DC65700EA"),
        ),
        (
            "destination_store_uuid",
            serde_json::json!(uuid::Uuid::nil().to_string()),
        ),
        ("expectation_id", serde_json::json!("not-a-digest")),
        ("dpop_authority_id", serde_json::json!(" padded")),
        ("proof_ttl_secs", serde_json::json!(0)),
        (
            "proof_ttl_secs",
            serde_json::json!(MAX_DURABLE_DPOP_TTL_SECS + 1),
        ),
        (
            "max_clock_skew_secs",
            serde_json::json!(MAX_DURABLE_DPOP_CLOCK_SKEW_SECS + 1),
        ),
        ("active", serde_json::json!(true)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(
            serde_json::from_value::<DpopReplayAuthorityV1>(changed).is_err(),
            "{field}"
        );
    }
    assert_eq!(
        serde_json::from_value::<DpopReplayAuthorityV1>(original).unwrap(),
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
    assert!(crate::dpop::system_unix_secs(UNIX_EPOCH - Duration::from_secs(1)).is_err());
    assert_eq!(crate::dpop::system_unix_secs(UNIX_EPOCH).unwrap(), 0);
}

#[test]
fn typescript_wire_vector_matches_rust_canonical_bytes_and_signature_verification() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/fixtures/dpop-authority-v2.json"
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
