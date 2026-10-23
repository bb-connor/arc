#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::crypto::{
    verify_wrapped_bytes, Keypair, PublicKey, Signature, SigningAlgorithm, SigningWrapper,
    SIGNING_WRAPPER_PREFIX,
};
use chio_core_types::{CanonicalBytes, Error, KNOWN_SIGNED_ARTIFACT_SCHEMAS};
use serde_json::Value;

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/bindings/vectors/signing/wrapper/v1.json"
));

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("wrapper vectors parse")
}

fn canonical(text: &str) -> CanonicalBytes {
    let value: Value = serde_json::from_str(text).expect("canonical body parses");
    let canonical = CanonicalBytes::from_value(&value).expect("canonical body canonicalizes");
    assert_eq!(canonical.as_bytes(), text.as_bytes(), "vector body is canonical");
    canonical
}

fn cases<'a>(doc: &'a Value, member: &str) -> &'a [Value] {
    doc[member].as_array().expect("case array")
}

#[test]
fn prefix_matches_the_wrapper_constant() {
    let doc = vectors();
    assert_eq!(
        doc["prefix_hex"].as_str().unwrap(),
        hex::encode(SIGNING_WRAPPER_PREFIX)
    );
}

#[test]
fn wrapper_cases_match_or_refuse_by_registration() {
    let doc = vectors();
    for case in cases(&doc, "wrapper_cases") {
        let schema_id = case["schema_id"].as_str().unwrap();
        let body = canonical(case["canonical_body"].as_str().unwrap());
        if KNOWN_SIGNED_ARTIFACT_SCHEMAS.contains(&schema_id) {
            let wrapper = SigningWrapper::new(schema_id, &body).unwrap();
            assert_eq!(
                hex::encode(wrapper.as_bytes()),
                case["wrapper_hex"].as_str().unwrap(),
                "{schema_id}"
            );
        } else {
            assert!(
                matches!(SigningWrapper::new(schema_id, &body), Err(Error::UnregisteredSchemaId(ref id)) if id == schema_id),
                "{schema_id}"
            );
        }
    }
}

#[test]
fn every_known_id_has_a_wrapper_case() {
    let doc = vectors();
    let covered: std::collections::BTreeSet<&str> = cases(&doc, "wrapper_cases")
        .iter()
        .map(|case| case["schema_id"].as_str().unwrap())
        .collect();
    let missing: Vec<&str> = KNOWN_SIGNED_ARTIFACT_SCHEMAS
        .iter()
        .copied()
        .filter(|id| !covered.contains(id))
        .collect();
    assert!(missing.is_empty(), "known ids without a wrapper case: {missing:?}");
}

fn verifiable(algorithm: &str) -> bool {
    match algorithm {
        "ed25519" => true,
        "p256" | "p384" => cfg!(feature = "fips"),
        other => panic!("unexpected vector algorithm {other}"),
    }
}

#[test]
fn signature_cases_verify_exactly_as_expected() {
    let doc = vectors();
    let mut checked = 0;
    let mut ecdsa = 0;
    for case in cases(&doc, "signature_cases") {
        let algorithm = case["algorithm"].as_str().unwrap();
        if !verifiable(algorithm) {
            continue;
        }
        if algorithm != "ed25519" {
            ecdsa += 1;
        }
        let key = PublicKey::from_hex(case["public_key"].as_str().unwrap()).unwrap();
        let signature = Signature::from_hex(case["signature"].as_str().unwrap()).unwrap();
        let body = canonical(case["canonical_body"].as_str().unwrap());
        let verdict = verify_wrapped_bytes(
            &key,
            case["verify_schema_id"].as_str().unwrap(),
            &body,
            &signature,
        );
        assert_eq!(
            verdict.is_ok(),
            case["expected_verify"].as_bool().unwrap(),
            "{}: {verdict:?}",
            case["id"]
        );
        checked += 1;
    }
    assert!(checked > 0);
    if cfg!(feature = "fips") {
        assert!(ecdsa > 0, "fips build checks the P-256 and P-384 cases");
    }
}

#[test]
fn rust_signer_reproduces_every_ed25519_positive() {
    let doc = vectors();
    let seed = hex::decode(doc["keys"]["ed25519"]["seed_hex"].as_str().unwrap()).unwrap();
    let keypair = Keypair::from_seed(&seed.try_into().unwrap());
    let mut reproduced = 0;
    for case in cases(&doc, "signature_cases") {
        if case["algorithm"] != "ed25519"
            || !case["expected_verify"].as_bool().unwrap()
            || case["public_key"].as_str() != Some(&keypair.public_key().to_hex())
        {
            continue;
        }
        let body = canonical(case["canonical_body"].as_str().unwrap());
        let signature = keypair
            .sign_wrapped(case["signed_schema_id"].as_str().unwrap(), &body)
            .unwrap();
        assert_eq!(signature.algorithm(), SigningAlgorithm::Ed25519);
        assert_eq!(signature.to_hex(), case["signature"].as_str().unwrap(), "{}", case["id"]);
        reproduced += 1;
    }
    assert!(reproduced > 0);
}
