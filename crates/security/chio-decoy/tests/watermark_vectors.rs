use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_core_types::{
    canonical_json_bytes, canonical_json_bytes_from_str, Keypair, PublicKey, Signature,
};
use chio_decoy::{SignedWatermarkEnvelope, WatermarkPayload, MAX_IJSON_INTEGER};
use chio_test_support::prelude::*;
use serde::Deserialize;

const POSITIVE_VECTORS: &str =
    include_str!("../../../tooling/chio-conformance/vectors/security/watermark/v1.json");
const REJECTION_VECTORS: &str =
    include_str!("../../../tooling/chio-conformance/vectors/security/watermark/v1-rejections.json");

#[derive(Deserialize)]
struct WatermarkVectors {
    schema: String,
    signing_domain: String,
    signing_key_seed_hex: String,
    cases: Vec<WatermarkVector>,
}

#[derive(Deserialize)]
struct WatermarkVector {
    id: String,
    payload: WatermarkPayload,
    canonical_payload_json: String,
    signing_message_hex: String,
    encoded_payload: String,
    public_key_hex: String,
    signature_hex: String,
    envelope: SignedWatermarkEnvelope,
    canonical_envelope_json: String,
    token: String,
}

#[derive(Deserialize)]
struct WatermarkRejectionVectors {
    schema: String,
    cases: Vec<WatermarkRejectionVector>,
}

#[derive(Deserialize)]
struct WatermarkRejectionVector {
    id: String,
    input_payload_json: String,
    canonical_payload_json: String,
    field: String,
    value_decimal: String,
    expected_error: String,
}

#[test]
fn shared_watermark_vector_pins_rust_bytes_and_signature() {
    let vectors: WatermarkVectors =
        serde_json::from_str(POSITIVE_VECTORS).test_expect("valid positive watermark vectors");
    assert_eq!(vectors.schema, "chio.signed-watermark-vectors.v1");
    assert_eq!(vectors.signing_domain.as_bytes().last(), Some(&0));
    assert_eq!(vectors.signing_domain, "chio.signed-watermark.v1\0");
    assert_eq!(vectors.cases.len(), 1);

    let vector = vectors
        .cases
        .first()
        .test_expect("one positive watermark vector");
    assert_eq!(vector.id, "max_safe_sequence");
    assert_eq!(vector.payload.sequence, MAX_IJSON_INTEGER);
    assert!(vector.payload.issued_at_unix_ms <= MAX_IJSON_INTEGER);
    assert!(vector.payload.expires_at_unix_ms <= MAX_IJSON_INTEGER);

    let canonical_payload =
        canonical_json_bytes(&vector.payload).test_expect("canonical watermark payload");
    assert_eq!(
        canonical_payload.as_slice(),
        vector.canonical_payload_json.as_bytes()
    );
    assert!(!vector.encoded_payload.contains('='));
    assert_eq!(
        URL_SAFE_NO_PAD.encode(&canonical_payload),
        vector.encoded_payload
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(&vector.encoded_payload)
            .test_expect("decode watermark payload"),
        canonical_payload
    );

    let mut signing_message = vectors.signing_domain.as_bytes().to_vec();
    signing_message.extend_from_slice(&canonical_payload);
    assert_eq!(hex::encode(&signing_message), vector.signing_message_hex);
    let keypair = Keypair::from_seed_hex(&vectors.signing_key_seed_hex)
        .test_expect("valid fixed Ed25519 seed");
    assert_eq!(keypair.public_key().to_hex(), vector.public_key_hex);
    assert_eq!(
        keypair.sign(&signing_message).to_hex(),
        vector.signature_hex
    );

    let public_key = PublicKey::from_hex(&vector.public_key_hex).test_expect("valid public key");
    let signature = Signature::from_hex(&vector.signature_hex).test_expect("valid signature");
    assert!(public_key.verify(&signing_message, &signature));
    assert!(!public_key.verify(&canonical_payload, &signature));

    assert_eq!(vector.envelope.payload, vector.payload);
    assert_eq!(vector.envelope.encoded_payload, vector.encoded_payload);
    assert_eq!(vector.envelope.signature.to_hex(), vector.signature_hex);
    assert_eq!(vector.envelope.schema, "chio.signed-watermark-envelope.v1");
    let canonical_envelope =
        canonical_json_bytes(&vector.envelope).test_expect("canonical watermark envelope");
    assert_eq!(
        canonical_envelope.as_slice(),
        vector.canonical_envelope_json.as_bytes()
    );
    assert_eq!(
        vector
            .envelope
            .encode_token()
            .test_expect("encode watermark token"),
        vector.token
    );
    assert_eq!(
        SignedWatermarkEnvelope::decode_token(&vector.token).test_expect("decode watermark token"),
        vector.envelope
    );

    let encoded_envelope = vector
        .token
        .strip_prefix("[[chio-wm1:")
        .and_then(|value| value.strip_suffix("]]"))
        .test_expect("valid watermark wrapper");
    assert!(!encoded_envelope.contains('='));
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(encoded_envelope)
            .test_expect("decode watermark envelope"),
        canonical_envelope
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(&canonical_envelope),
        encoded_envelope
    );
}

#[test]
fn unsafe_integer_rejection_vector_is_fail_closed_in_rust() {
    let vectors: WatermarkRejectionVectors =
        serde_json::from_str(REJECTION_VECTORS).test_expect("valid watermark rejection vectors");
    assert_eq!(vectors.schema, "chio.signed-watermark-rejection-vectors.v1");
    assert_eq!(vectors.cases.len(), 1);

    let vector = vectors
        .cases
        .first()
        .test_expect("one watermark rejection vector");
    assert_eq!(vector.id, "sequence_at_two_to_53_is_unsafe");
    assert_eq!(vector.field, "sequence");
    assert_eq!(vector.expected_error, "unsafe_integer");
    assert_eq!(
        vector
            .value_decimal
            .parse::<u64>()
            .test_expect("valid rejection integer"),
        MAX_IJSON_INTEGER + 1
    );
    assert!(canonical_json_bytes_from_str(&vector.input_payload_json).is_err());

    let payload: WatermarkPayload =
        serde_json::from_str(&vector.input_payload_json).test_expect("typed unsafe payload");
    assert_eq!(payload.sequence, MAX_IJSON_INTEGER + 1);
    assert_eq!(
        canonical_json_bytes(&payload).test_expect("typed canonical payload"),
        vector.canonical_payload_json.as_bytes()
    );
    assert!(SignedWatermarkEnvelope::encode_payload(&payload).is_err());
}
