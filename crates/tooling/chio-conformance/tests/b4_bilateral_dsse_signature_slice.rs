//! DSSE signature-slice regression tests.
//!
//! This fixture intentionally does NOT claim
//! strict treaty-bound bilateral invocation predicate conformance. The
//! production emitter signs a local signature-slice predicate that carries
//! `receipt_canonical_json` and omits strict-schema fields such as
//! `tool_args_hash`.
//!
//! ## What this fixture checks
//!
//! 1. **Signature-slice verifier accepts the envelope** under matching public keys.
//! 2. **Tampered payload bytes are rejected** (changes LEN(payload) and the
//!    payload bytes; PAE preimage diverges).
//! 3. **Mismatched payloadType is rejected** (payload-type is part of PAE).
//! 4. **The cosigner-routed emitter (`co_sign_with_origin`) produces
//!    an envelope that verifies** under the signature-slice verifier.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};
use chio_federation::bilateral::{co_sign_with_origin, InProcessCoSigner};
use chio_federation::bilateral_dsse::{
    pae, receipt_subject_name, sign_dsse_envelope, verify_dsse_envelope, Keyid,
    PAYLOAD_TYPE_IN_TOTO, PREDICATE_BODY_SCHEMA, PREDICATE_TYPE_BILATERAL,
};
use std::path::Path;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

fn sample_action() -> ToolCallAction {
    ToolCallAction::from_parameters(serde_json::json!({"path": "/data/b4-fixture.txt"})).unwrap()
}

fn sample_receipt(tool_host_kp: &Keypair) -> ChioReceipt {
    let body = ChioReceiptBody {
        id: "rcpt-bilateral-b4-fixture".to_string(),
        timestamp: 1_734_000_000,
        capability_id: "cap-bilateral-b4".to_string(),
        tool_server: "srv-orgb-files".to_string(),
        tool_name: "file_read".to_string(),
        action: sample_action(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: chio_core::crypto::sha256_hex(br#"{"ok":true}"#),
        policy_hash: "fed-policy-hash".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: tool_host_kp.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, tool_host_kp).unwrap()
}

const ORG_A_KERNEL_ID: &str = "kernel.org-a";
const ORG_B_KERNEL_ID: &str = "kernel.org-b";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The signature-slice verifier accepts a freshly-signed envelope when the
/// public keys match the keyids carried in the envelope's signatures array.
#[test]
fn signature_slice_verifier_accepts_freshly_signed_envelope() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();

    let statement = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
        .expect("signature-slice verifier must accept envelope under matching pinned public keys");
    assert_eq!(statement.predicate_type, PREDICATE_TYPE_BILATERAL);
    assert_eq!(statement.subject.len(), 1);
    assert_eq!(statement.subject[0].name, receipt_subject_name(&receipt.id));

    // Spec section 7 step 8 partial: the fingerprint declared in the predicate
    // matches the keyid the verifier derives from the public key.
    let want_a = Keyid::from_public_key(&kp_a.public_key());
    let want_b = Keyid::from_public_key(&kp_b.public_key());
    assert_eq!(
        statement.predicate.tool_server_a.passport_key_fingerprint, want_a,
        "predicate.tool_server_a.passport_key_fingerprint MUST equal \
         sha256(orgA_pubkey)"
    );
    assert_eq!(
        statement.predicate.tool_server_b.passport_key_fingerprint, want_b,
        "predicate.tool_server_b.passport_key_fingerprint MUST equal \
         sha256(orgB_pubkey)"
    );
}

#[test]
fn emitted_predicate_is_explicit_signature_slice_not_chio_invocation_schema() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    let statement = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
        .expect("signature-slice verifier must accept envelope");
    let predicate_json = serde_json::to_value(&statement.predicate).unwrap();

    let envelope_json = serde_json::to_value(&envelope).unwrap();
    assert!(
        envelope_json.get("schema").is_none(),
        "standard DSSE envelope wire JSON must not carry Chio schema metadata"
    );
    assert!(envelope_json.get("payloadType").is_some());
    assert!(envelope_json.get("payload").is_some());
    assert!(envelope_json.get("signatures").is_some());
    assert_eq!(statement.predicate_type, PREDICATE_TYPE_BILATERAL);
    assert_eq!(predicate_json["schema"], PREDICATE_BODY_SCHEMA);
    assert_ne!(
        statement.predicate_type, "chio.bilateral-cosign-invocation.v1",
        "signature-slice output must not claim the strict treaty-bound predicate type"
    );
    assert!(
        predicate_json.get("receipt_canonical_json").is_some(),
        "signature-slice profile carries the local receipt helper field"
    );
    assert!(
        predicate_json.get("tool_args_hash").is_none(),
        "missing strict-schema tool_args_hash is why this profile is not CHIO invocation conformance"
    );
}

#[test]
fn signature_slice_profile_is_registered_as_signed_artifact_schema() {
    assert_eq!(
        PREDICATE_BODY_SCHEMA, PREDICATE_TYPE_BILATERAL,
        "the signed artifact must have one verifier-facing profile identifier"
    );

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("crate lives under <repo>/crates/tooling/chio-conformance");
    let registry_path = repo_root.join("spec/schemas/registry.json");
    let registry_text = std::fs::read_to_string(&registry_path).expect("read schema registry");
    let registry: serde_json::Value =
        serde_json::from_str(&registry_text).expect("parse schema registry");
    let artifacts = registry["artifacts"]
        .as_array()
        .expect("registry.artifacts is an array");

    let entry = artifacts
        .iter()
        .find(|artifact| artifact["schema"] == PREDICATE_TYPE_BILATERAL)
        .expect("signature-slice profile is registered");
    assert_eq!(
        entry["artifactKind"], "bilateral_dsse_signature_slice",
        "registry entry must be verifier-facing, not a generic receipt artifact"
    );
    let schema_file = entry["schemaFile"]
        .as_str()
        .expect("schemaFile is a string");
    let schema_path = repo_root.join(schema_file);
    assert!(
        schema_path.is_file(),
        "registered schema file must exist: {}",
        schema_file
    );

    let envelope_schema_text = std::fs::read_to_string(&schema_path).expect("read envelope schema");
    let envelope_schema: serde_json::Value =
        serde_json::from_str(&envelope_schema_text).expect("parse envelope schema");
    assert_eq!(
        envelope_schema["properties"]["payloadType"]["const"],
        PAYLOAD_TYPE_IN_TOTO
    );
    assert_eq!(envelope_schema["properties"]["signatures"]["minItems"], 2);

    let payload_schema_file = entry["payloadSchemaFile"]
        .as_str()
        .expect("payloadSchemaFile is a string");
    let payload_schema_path = repo_root.join(payload_schema_file);
    assert!(
        payload_schema_path.is_file(),
        "registered payload schema file must exist: {}",
        payload_schema_file
    );

    let payload_schema_text =
        std::fs::read_to_string(&payload_schema_path).expect("read payload schema");
    let payload_schema: serde_json::Value =
        serde_json::from_str(&payload_schema_text).expect("parse payload schema");
    assert_eq!(
        payload_schema["properties"]["predicateType"]["const"],
        PREDICATE_TYPE_BILATERAL
    );
    assert_eq!(
        payload_schema["properties"]["predicate"]["properties"]["schema"]["const"],
        PREDICATE_BODY_SCHEMA
    );
}

#[test]
fn emitted_statement_validates_against_registered_signature_slice_schema() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    let statement_bytes = BASE64_STANDARD.decode(&envelope.payload).unwrap();
    let statement_json: serde_json::Value = serde_json::from_slice(&statement_bytes).unwrap();
    assert!(
        statement_json["predicate"]["receipt_canonical_json"].is_string(),
        "emitted receipt_canonical_json is a canonical JSON string, not a nested object"
    );

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("crate lives under <repo>/crates/tooling/chio-conformance");
    let schema_path = repo_root
        .join("spec/schemas/chio-wire/v1/federation/bilateral-signature-slice.schema.json");
    let schema_text = std::fs::read_to_string(&schema_path).expect("read profile schema");
    let schema: serde_json::Value =
        serde_json::from_str(&schema_text).expect("parse profile schema");
    let validator = jsonschema::validator_for(&schema).expect("compile signature-slice schema");
    let errors: Vec<String> = validator
        .iter_errors(&statement_json)
        .map(|err| err.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "emitted signature-slice Statement must validate against registered schema: {errors:?}"
    );
}

/// Tampering with the payload changes the DSSE PAE preimage that the
/// signatures cover; the verifier MUST reject.
#[test]
fn tampered_pae_bytes_rejected_by_signature_slice_verifier() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();

    // Mutate the payload by appending a base64-valid character. This
    // changes the decoded statement bytes AND the LEN(payload) value
    // baked into the PAE preimage.
    envelope.payload.push('A');

    let result = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key());
    assert!(
        result.is_err(),
        "tampered PAE bytes MUST fail signature-slice verification"
    );
}

/// Payload-type is part of the PAE preimage. A verifier that accepts a
/// swapped payload-type would let an attacker
/// reuse a signature against a differently-typed payload.
#[test]
fn mismatched_payload_type_rejected_by_signature_slice_verifier() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();

    envelope.payload_type = "application/json".to_string();

    let result = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key());
    assert!(
        result.is_err(),
        "mismatched payloadType MUST fail signature-slice verification because PAE \
         binds it into the preimage"
    );
}

#[test]
fn cosigner_routed_emitter_produces_verifying_envelope() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let cosigner = InProcessCoSigner::new(ORG_A_KERNEL_ID, kp_a.clone(), kp_b.public_key());

    let envelope = co_sign_with_origin(
        ORG_A_KERNEL_ID,
        &kp_a.public_key(),
        ORG_B_KERNEL_ID,
        &kp_b,
        &receipt,
        &cosigner,
        "file_read",
        1_734_000_000_000,
    )
    .expect("co-sign must succeed");

    let statement = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
        .expect("DSSE envelope verifies under signature-slice verifier");
    assert_eq!(statement.subject[0].name, receipt_subject_name(&receipt.id));
    assert!(
        envelope.pae_bytes().unwrap().starts_with(b"DSSEv1 "),
        "DSSE PAE preimage MUST begin with the literal 'DSSEv1 ' tag"
    );
}

/// DSSE PAE format check: the helper is deterministic and matches the
/// "DSSEv1 LEN(type) SP type SP LEN(body) SP body" wire form.
#[test]
fn pae_helper_matches_spec_format() {
    // Known vector: payloadType "application/x" (13 bytes), payload "hello"
    // (5 bytes): "DSSEv1 SP LEN(type) SP type SP
    // LEN(body) SP body".
    let bytes = pae("application/x", b"hello");
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        "DSSEv1 13 application/x 5 hello",
        "PAE helper MUST encode per DSSE v1 spec"
    );

    // Empty payload: LEN(body) is "0".
    let empty = pae(PAYLOAD_TYPE_IN_TOTO, b"");
    let expected_prefix = format!(
        "DSSEv1 {} {} 0 ",
        PAYLOAD_TYPE_IN_TOTO.len(),
        PAYLOAD_TYPE_IN_TOTO
    );
    assert_eq!(
        std::str::from_utf8(&empty).unwrap(),
        expected_prefix,
        "empty-payload PAE preserves all framing fields"
    );
}

/// Spec step substrate: the subject digest binds the receipt body
/// (canonical JSON of `ChioReceiptBody`), not the full signed
/// `ChioReceipt` wrapper. Resolving the receipt from a store (which
/// exposes the body for re-verification) and re-hashing the body must
/// reproduce this digest. Hashing the full wrapper would fold in the
/// signature bytes, which the verifier cannot reproduce from a
/// body-only re-emission.
#[test]
fn statement_subject_digest_matches_canonical_receipt_body_hash() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    let (statement, _) = envelope.decode_statement().unwrap();

    let body = receipt.body();
    let canonical_body = canonical_json_bytes(&body).unwrap();
    let want = chio_core::crypto::sha256_hex(&canonical_body);
    assert_eq!(
        statement.subject[0].digest.sha256, want,
        "subject[0].digest.sha256 MUST equal sha256(canonical_json(receipt.body())) \
         cross-impl resolution from a body-only receipt store relies on this binding."
    );

    // hashing the full signed wrapper must NOT
    // match. A wrapper-hash match would mean the body/wrapper binding
    // had regressed silently.
    let canonical_full = canonical_json_bytes(&receipt).unwrap();
    let full_digest = chio_core::crypto::sha256_hex(&canonical_full);
    assert_ne!(
        statement.subject[0].digest.sha256, full_digest,
        "subject digest MUST hash body, not full wrapper; got matching wrapper hash"
    );
}

#[test]
fn statement_subject_name_is_canonical_receipt_name_and_raw_id_is_rejected() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    let (mut statement, _) = envelope.decode_statement().unwrap();
    assert_eq!(statement.subject[0].name, receipt_subject_name(&receipt.id));

    statement.subject[0].name = receipt.id.clone();
    let new_statement_bytes = chio_core::canonical::canonical_json_bytes(&statement).unwrap();
    envelope.payload = BASE64_STANDARD.encode(&new_statement_bytes);

    let err = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
        .expect_err("raw receipt id subject must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("subject name") && msg.contains("chio-receipt:"),
        "expected canonical subject-name rejection, got: {msg}"
    );
}

/// The bilateral envelope profile pins exactly one subject. Accepting a
/// multi-subject envelope would let a signer insert a second arbitrary
/// subject; any verifier walking the full subject list (the in-toto
/// convention for membership) would then resolve a different receipt
/// than the producer signed. The empty-list case is rejected for the
/// same reason: there must be exactly one subject.
#[test]
fn dsse_envelope_with_two_subjects_is_rejected() {
    use chio_federation::bilateral_dsse::{DsseStatement, StatementSubject, SubjectDigest};

    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();

    // Decode, splice in a second subject, re-canonicalise, re-encode.
    let (mut statement, _bytes) = envelope.decode_statement().unwrap();
    statement.subject.push(StatementSubject {
        name: "rcpt-injected".to_string(),
        digest: SubjectDigest {
            sha256: "0".repeat(64),
        },
    });
    let new_statement_bytes = chio_core::canonical::canonical_json_bytes(&statement).unwrap();
    envelope.payload = BASE64_STANDARD.encode(&new_statement_bytes);

    // Signatures do not verify over the new payload, but the
    // multi-subject check fires BEFORE PAE
    // verification so the diagnostic is structural rather than
    // signature-cryptographic.
    let outcome = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key());
    let err = outcome.expect_err("multi-subject envelope must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("statement.malformed") || msg.contains("exactly 1 subject"),
        "expected multi-subject rejection diagnostic, got: {msg}"
    );

    // Suppress dead-code lint for DsseStatement field access in tests
    // that share this file.
    let _ = DsseStatement::canonical_bytes;
}
