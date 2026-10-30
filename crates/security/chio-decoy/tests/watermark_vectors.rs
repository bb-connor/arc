use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_core_types::crypto::{verify_wrapped_bytes, SigningWrapper};
use chio_core_types::{
    canonical_json_bytes, canonical_json_bytes_from_str, CanonicalBytes, Keypair, PublicKey,
    Signature,
};
use chio_decoy::{SignedWatermarkEnvelope, WatermarkPayload, MAX_IJSON_INTEGER};
use chio_test_support::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const WATERMARK_ENVELOPE_SCHEMA: &str = "chio.signed-watermark-envelope.v1";

const POSITIVE_VECTORS: &str =
    include_str!("../../../tooling/chio-conformance/vectors/security/watermark/v1.json");
const REJECTION_VECTORS: &str =
    include_str!("../../../tooling/chio-conformance/vectors/security/watermark/v1-rejections.json");

const SIGNING_KEY_SEED_HEX: &str =
    "0909090909090909090909090909090909090909090909090909090909090909";

#[derive(Deserialize)]
struct WatermarkVectors {
    schema: String,
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

#[derive(Serialize)]
struct GeneratedVectors {
    schema: &'static str,
    signing_key_seed_hex: &'static str,
    cases: Vec<GeneratedVector>,
}

#[derive(Serialize)]
struct GeneratedVector {
    id: &'static str,
    description: &'static str,
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

fn max_safe_sequence_payload() -> WatermarkPayload {
    serde_json::from_value(serde_json::json!({
        "tenant_id": "tenant-alpha",
        "application_id": "app-support",
        "session_id": "session-2026-07-13-001",
        "source_receipt_id": "receipt-000042",
        "tool_id": "tool.crm.lookup",
        "sequence": MAX_IJSON_INTEGER,
        "issued_at_unix_ms": 1_783_951_200_000_u64,
        "expires_at_unix_ms": 1_783_954_800_000_u64,
        "marker_ref": "wm-marker-7f3c2a",
        "key_id": "wm-key-2026-07",
        "encoding": "base64_url_canonical_json"
    }))
    .test_expect("typed watermark payload")
}

fn generated_positive_vectors() -> String {
    let payload = max_safe_sequence_payload();
    let keypair =
        Keypair::from_seed_hex(SIGNING_KEY_SEED_HEX).test_expect("valid fixed Ed25519 seed");
    let canonical_payload = canonical_json_bytes(&payload).test_expect("canonical payload");
    let wrapper_body = CanonicalBytes::from_serializable(&payload).test_expect("wrapper body");
    let wrapper = SigningWrapper::new(WATERMARK_ENVELOPE_SCHEMA, &wrapper_body)
        .test_expect("registered watermark schema id");
    let signature = keypair
        .sign_wrapped(WATERMARK_ENVELOPE_SCHEMA, &wrapper_body)
        .test_expect("sign watermark wrapper");
    let encoded_payload =
        SignedWatermarkEnvelope::encode_payload(&payload).test_expect("encode watermark payload");
    let envelope = SignedWatermarkEnvelope {
        schema: WATERMARK_ENVELOPE_SCHEMA.to_string(),
        payload: payload.clone(),
        encoded_payload: encoded_payload.clone(),
        signature: signature.clone(),
    };
    let document = GeneratedVectors {
        schema: "chio.signed-watermark-vectors.v1",
        signing_key_seed_hex: SIGNING_KEY_SEED_HEX,
        cases: vec![GeneratedVector {
            id: "max_safe_sequence",
            description: "A signed watermark at the I-JSON safe-integer boundary pins every canonical and cryptographic byte surface.",
            canonical_payload_json: String::from_utf8(canonical_payload)
                .test_expect("canonical payload is UTF-8"),
            signing_message_hex: hex::encode(wrapper.as_bytes()),
            encoded_payload,
            public_key_hex: keypair.public_key().to_hex(),
            signature_hex: signature.to_hex(),
            canonical_envelope_json: String::from_utf8(
                canonical_json_bytes(&envelope).test_expect("canonical envelope"),
            )
            .test_expect("canonical envelope is UTF-8"),
            token: envelope.encode_token().test_expect("encode watermark token"),
            envelope,
            payload,
        }],
    };
    let mut text = serde_json::to_string_pretty(&document).test_expect("serialize vectors");
    text.push('\n');
    text
}

#[test]
#[ignore = "regenerator: rewrites the shared watermark vector from the issuer types"]
fn regenerate_watermark_vectors() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tooling/chio-conformance/vectors/security/watermark/v1.json");
    std::fs::write(path, generated_positive_vectors()).test_expect("write watermark vectors");
}

#[test]
fn committed_watermark_vectors_match_generator() {
    assert_eq!(
        POSITIVE_VECTORS,
        generated_positive_vectors(),
        "fixture crates/tooling/chio-conformance/vectors/security/watermark/v1.json is out of date"
    );
}

#[test]
fn shared_watermark_vector_pins_rust_bytes_and_signature() {
    let vectors: WatermarkVectors =
        serde_json::from_str(POSITIVE_VECTORS).test_expect("valid positive watermark vectors");
    assert_eq!(vectors.schema, "chio.signed-watermark-vectors.v1");
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

    let wrapper_body =
        CanonicalBytes::from_serializable(&vector.payload).test_expect("canonical wrapper body");
    let wrapper = SigningWrapper::new(WATERMARK_ENVELOPE_SCHEMA, &wrapper_body)
        .test_expect("registered watermark schema id");
    assert_eq!(hex::encode(wrapper.as_bytes()), vector.signing_message_hex);
    let keypair = Keypair::from_seed_hex(&vectors.signing_key_seed_hex)
        .test_expect("valid fixed Ed25519 seed");
    assert_eq!(keypair.public_key().to_hex(), vector.public_key_hex);
    assert_eq!(
        keypair
            .sign_wrapped(WATERMARK_ENVELOPE_SCHEMA, &wrapper_body)
            .test_expect("sign watermark wrapper")
            .to_hex(),
        vector.signature_hex
    );

    let public_key = PublicKey::from_hex(&vector.public_key_hex).test_expect("valid public key");
    let signature = Signature::from_hex(&vector.signature_hex).test_expect("valid signature");
    verify_wrapped_bytes(
        &public_key,
        WATERMARK_ENVELOPE_SCHEMA,
        &wrapper_body,
        &signature,
    )
    .test_expect("watermark wrapper signature verifies");
    assert!(matches!(
        verify_wrapped_bytes(
            &public_key,
            chio_core_types::CHIO_SIGNED_SECURITY_EVENT_SCHEMA,
            &wrapper_body,
            &signature,
        ),
        Err(chio_core_types::Error::SignatureRejected)
    ));

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
