//! Receipt and delegation-context commitments against the committed-receipt vectors.

use std::path::PathBuf;

use chio_core_types::hashing::Sha256State;
use chio_core_types::receipt::commitment::{
    commit, ClaimName, CommitmentAlg, CommitmentDomain, CommitmentError, ContentPreimage,
    ReceiptCommitment, Salt, CONTENT_COMMITMENT_DOMAIN, CONTENT_SALT_REF,
    PARAMETERS_COMMITMENT_DOMAIN, PARAMS_SALT_REF, SALT_LEN,
};
use chio_core_types::rng::{Rng, RngError};
use chio_core_types::root_authority::{SaltRef, Sha256Digest};
use chio_test_support::prelude::*;
use serde_json::Value;

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/bindings/vectors/receipt/committed/v1.json");
    serde_json::from_str(&std::fs::read_to_string(path).test_unwrap()).test_unwrap()
}

fn digest(text: &str) -> Sha256Digest {
    Sha256Digest::parse(text).test_unwrap()
}

fn salt_from_b64u(text: &str) -> Option<Salt> {
    let encoded = text.strip_prefix("b64u:")?;
    if encoded.len() != 43 {
        return None;
    }
    let mut bits = 0_u32;
    let mut width = 0_u32;
    let mut bytes = Vec::with_capacity(SALT_LEN);
    for character in encoded.bytes() {
        let sextet = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(sextet);
        width += 6;
        if width >= 8 {
            width -= 8;
            bytes.push(u8::try_from((bits >> width) & 0xff).ok()?);
        }
    }
    Some(Salt::from_bytes(bytes.try_into().ok()?))
}

fn field<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    path.iter()
        .try_fold(value, |node, key| node.get(*key))
        .test_unwrap()
}

#[test]
fn commitment_matches_layout() {
    let salt = Salt::from_bytes([0x10; SALT_LEN]);
    let mut state = Sha256State::new();
    state.update(PARAMETERS_COMMITMENT_DOMAIN);
    state.update(&[0x10; SALT_LEN]);
    state.update(b"{\"a\":1}");
    assert_eq!(
        commit(CommitmentDomain::Parameters, &salt, b"{\"a\":1}"),
        Sha256Digest::from_hash(state.finalize())
    );
    assert_ne!(
        commit(CommitmentDomain::Parameters, &salt, b"x"),
        commit(CommitmentDomain::Content, &salt, b"x")
    );
}

#[test]
fn commit_reproduces_committed_vectors() {
    let vectors = vectors();
    let domains = field(&vectors, &["commitment_domains"]);
    assert_eq!(
        field(domains, &["params"]).as_str(),
        Some("chio.receipt.parameters.v1\\0")
    );
    assert_eq!(
        field(domains, &["content"]).as_str(),
        Some("chio.receipt.content.v1\\0")
    );
    assert!(PARAMETERS_COMMITMENT_DOMAIN.ends_with(b"\0"));
    assert!(CONTENT_COMMITMENT_DOMAIN.ends_with(b"\0"));

    let cases = field(&vectors, &["cases"]).as_array().test_unwrap();
    let mut checked = 0;
    for case in cases {
        if field(case, &["expected", "disclosure_valid"]) != &Value::Bool(true) {
            continue;
        }
        let openings = field(case, &["disclosure", "openings"])
            .as_array()
            .test_unwrap();
        let parameters = field(case, &["preimages", "parameters_canonical"])
            .as_str()
            .test_unwrap()
            .as_bytes()
            .to_vec();
        let content = hex::decode(
            field(case, &["preimages", "content_preimage_hex"])
                .as_str()
                .test_unwrap(),
        )
        .test_unwrap();
        let rows = [
            (
                CommitmentDomain::Parameters,
                PARAMS_SALT_REF,
                &["receipt", "action", "parameter_commitment"][..],
                "parameters",
                parameters,
            ),
            (
                CommitmentDomain::Content,
                CONTENT_SALT_REF,
                &["receipt", "content_commitment"][..],
                "content",
                content,
            ),
        ];
        for (domain, salt_ref, commitment_path, verdict_key, preimage) in rows {
            let expected = field(case, &["expected", verdict_key])
                .as_str()
                .test_unwrap();
            let commitment: ReceiptCommitment =
                serde_json::from_value(field(case, commitment_path).clone()).test_unwrap();
            assert_eq!(commitment.alg, CommitmentAlg::Sha256Salted);
            let opening = openings
                .iter()
                .find(|opening| opening.get("salt_ref").and_then(Value::as_str) == Some(salt_ref));
            let Some(opening) = opening else {
                assert_eq!(expected, "unverifiable", "{case}");
                continue;
            };
            let salt =
                salt_from_b64u(field(opening, &["salt"]).as_str().test_unwrap()).test_unwrap();
            let opens = commitment.salt_ref.as_str() == salt_ref
                && commitment.opens_to(domain, &salt, &preimage);
            assert_eq!(opens, expected == "verified", "{}", field(case, &["id"]));
            checked += 1;
        }
    }
    assert!(checked >= 20, "checked {checked} commitments");
}

#[test]
fn delegation_commitments_reproduce_committed_vectors() {
    let vectors = vectors();
    let salts = field(&vectors, &["fixture_salts"]);
    let salt_of = |name: &str| {
        let mut bytes = [0_u8; SALT_LEN];
        hex::decode_to_slice(field(salts, &[name]).as_str().test_unwrap(), &mut bytes)
            .test_unwrap();
        Salt::from_bytes(bytes)
    };
    let domains = field(&vectors, &["commitment_domains"]);
    assert_eq!(
        field(domains, &["anchor.sub"]).as_str(),
        Some("chio.delegation-context.subject.v1\\0")
    );
    assert_eq!(
        field(domains, &["anchor.tenant"]).as_str(),
        Some("chio.delegation-context.tenant.v1\\0")
    );
    let subject = commit(
        CommitmentDomain::DelegationSubject,
        &salt_of("anchor.sub"),
        b"x",
    );
    let tenant = commit(
        CommitmentDomain::DelegationTenant,
        &salt_of("anchor.sub"),
        b"x",
    );
    assert_ne!(subject, tenant);
}

#[test]
fn claim_commitment_layout_names_the_claim() {
    let salt = Salt::from_bytes([0x21; SALT_LEN]);
    let name = ClaimName::new("client_id").test_unwrap();
    let mut state = Sha256State::new();
    state.update(b"chio.delegation-context.claim.v1\0client_id\0");
    state.update(&[0x21; SALT_LEN]);
    state.update(b"\"agent\"");
    assert_eq!(
        commit(CommitmentDomain::DelegationClaim(name), &salt, b"\"agent\""),
        Sha256Digest::from_hash(state.finalize())
    );
    for bad in ["", "client\0id", "Client", "client.id", "client id"] {
        assert_eq!(
            ClaimName::new(bad),
            Err(CommitmentError::ClaimName),
            "{bad:?}"
        );
    }
}

#[test]
fn content_preimage_forms() {
    let value = serde_json::json!({"text": "Roadmap", "lines": 42});
    assert_eq!(
        ContentPreimage::Value(&value).to_bytes().test_unwrap(),
        br#"{"lines":42,"text":"Roadmap"}"#.to_vec()
    );
    assert_eq!(
        ContentPreimage::Empty.to_bytes().test_unwrap(),
        Vec::<u8>::new()
    );
    assert_eq!(
        ContentPreimage::Stream(&[]).to_bytes().test_unwrap(),
        Vec::<u8>::new()
    );
    let chunks = [[0xab; 32], [0x01; 32]];
    let expected = format!("{}{}", "ab".repeat(32), "01".repeat(32));
    assert_eq!(
        ContentPreimage::Stream(&chunks).to_bytes().test_unwrap(),
        expected.into_bytes()
    );
}

#[test]
fn empty_output_preimage_is_zero_length() {
    let salt = Salt::from_bytes([0x11; SALT_LEN]);
    let mut state = Sha256State::new();
    state.update(CONTENT_COMMITMENT_DOMAIN);
    state.update(&[0x11; SALT_LEN]);
    let empty = ContentPreimage::Empty.to_bytes().test_unwrap();
    assert_eq!(
        commit(CommitmentDomain::Content, &salt, &empty),
        Sha256Digest::from_hash(state.finalize())
    );
}

#[test]
fn receipt_commitment_wire_form_is_strict() {
    let salt_ref = SaltRef::new(PARAMS_SALT_REF).test_unwrap();
    let salt = Salt::from_bytes([0x10; SALT_LEN]);
    let commitment =
        ReceiptCommitment::compute(CommitmentDomain::Parameters, salt_ref, &salt, b"{}");
    let encoded = serde_json::to_value(&commitment).test_unwrap();
    assert_eq!(field(&encoded, &["alg"]).as_str(), Some("sha256-salted"));
    assert_eq!(field(&encoded, &["salt_ref"]).as_str(), Some("params"));
    assert_eq!(
        serde_json::from_value::<ReceiptCommitment>(encoded.clone()).test_unwrap(),
        commitment
    );
    assert!(commitment.opens_to(CommitmentDomain::Parameters, &salt, b"{}"));
    assert!(!commitment.opens_to(CommitmentDomain::Content, &salt, b"{}"));

    let mut padded = encoded.clone();
    if let Some(object) = padded.as_object_mut() {
        object.insert("extra".to_owned(), Value::Null);
    }
    assert!(serde_json::from_value::<ReceiptCommitment>(padded).is_err());
    let mut other_alg = encoded.clone();
    if let Some(object) = other_alg.as_object_mut() {
        object.insert("alg".to_owned(), "sha256".into());
    }
    assert!(serde_json::from_value::<ReceiptCommitment>(other_alg).is_err());
    let mut bad_ref = encoded;
    if let Some(object) = bad_ref.as_object_mut() {
        object.insert("salt_ref".to_owned(), "Params".into());
    }
    assert!(serde_json::from_value::<ReceiptCommitment>(bad_ref).is_err());
    let claim_ref = SaltRef::new("anchor.claims.client_id").test_unwrap();
    assert_eq!(claim_ref.as_str(), "anchor.claims.client_id");
    assert_eq!(digest(&commitment.value.to_string()), commitment.value);
}

struct FailingRng;

impl Rng for FailingRng {
    fn fill_bytes(&self, _dest: &mut [u8]) -> Result<(), RngError> {
        Err(RngError("offline"))
    }
}

struct CountingRng;

impl Rng for CountingRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        for (index, byte) in dest.iter_mut().enumerate() {
            *byte = u8::try_from(index).map_err(|_| RngError("index"))?;
        }
        Ok(())
    }
}

#[test]
fn salt_draw_fails_closed_and_never_prints() {
    assert_eq!(Salt::draw(&FailingRng), Err(RngError("offline")));
    let salt = Salt::draw(&CountingRng).test_unwrap();
    let mut expected = [0_u8; SALT_LEN];
    for (index, byte) in expected.iter_mut().enumerate() {
        *byte = u8::try_from(index).test_unwrap();
    }
    assert_eq!(salt.as_bytes(), &expected);
    assert_eq!(format!("{salt:?}"), "Salt(..)");
    assert_eq!(salt, Salt::from_bytes(expected));
    assert_ne!(salt, Salt::from_bytes([0; SALT_LEN]));
}

#[test]
fn salt_zeroizes() {
    use zeroize::Zeroize;
    let mut salt = Salt::from_bytes([0x5a; SALT_LEN]);
    salt.zeroize();
    assert_eq!(salt.as_bytes(), &[0; SALT_LEN]);
}
