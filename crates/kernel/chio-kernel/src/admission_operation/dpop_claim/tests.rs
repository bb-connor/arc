use super::*;
use crate::dpop::authority::{invocation_binding_digest, verify_authority_dpop_proof_stateless};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::Keypair;

fn credential() -> DpopReplayCredentialV1 {
    let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/fixtures/dpop-authority-v2.json"
    )))
    .unwrap();
    let proof: crate::dpop::DpopProof = serde_json::from_value(vector["proof"].clone()).unwrap();
    let authority: DpopReplayAuthorityV1 =
        serde_json::from_value(vector["authority"].clone()).unwrap();
    let issuer = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "capability".into(),
            issuer: issuer.public_key(),
            subject: proof.body.agent_key.clone(),
            scope: Default::default(),
            issued_at: 1_799_999_999,
            expires_at: 1_800_000_600,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .unwrap();
    let verified = verify_authority_dpop_proof_stateless(
        &proof,
        &capability,
        "server",
        "tool",
        &proof.body.action_hash,
        &authority,
        1_800_000_000,
    )
    .unwrap();
    assert_eq!(
        verified.invocation_digest(),
        &invocation_binding_digest(&capability, "server", "tool", &proof.body.action_hash).unwrap()
    );
    DpopReplayCredentialV1::from_verified(verified)
}

#[test]
fn credential_roundtrip_retains_exact_commitments_without_a_reusable_signature() {
    let credential = credential();
    let value = serde_json::to_value(&credential).unwrap();
    let restored: DpopReplayCredentialV1 = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(restored, credential);
    assert!(value.get("signature").is_none());
    assert_eq!(credential.valid_through_unix_secs().unwrap(), 1_800_000_300);
    let debug = format!("{credential:?}");
    assert!(!debug.contains("nonce"));
    assert!(!debug.contains("capability"));
}

#[test]
fn credential_freshness_is_inclusive_and_uses_the_pinned_future_skew() {
    let credential = credential();
    for (time, valid) in [
        (1_799_999_969_999, false),
        (1_799_999_970_000, true),
        (1_800_000_300_999, true),
        (1_800_000_301_000, false),
        (super::super::I_JSON_MAX_SAFE_INTEGER + 1, false),
    ] {
        assert_eq!(credential.validate_at(time).is_ok(), valid, "{time}");
    }
}

#[test]
fn decoded_credential_bounds_and_unknown_fields_fail_before_custody() {
    let original = serde_json::to_value(credential()).unwrap();
    for (field, value) in [
        ("nonce", serde_json::json!("é".repeat(2049))),
        ("capabilityId", serde_json::json!("x".repeat(4097))),
        ("issuedAtUnixSecs", serde_json::json!(9_007_199_254_740_u64)),
        ("invocationDigest", serde_json::json!("bad")),
        ("activated", serde_json::json!(true)),
    ] {
        let mut candidate = original.clone();
        candidate[field] = value;
        assert!(
            serde_json::from_value::<DpopReplayCredentialV1>(candidate).is_err(),
            "{field}"
        );
    }
}
