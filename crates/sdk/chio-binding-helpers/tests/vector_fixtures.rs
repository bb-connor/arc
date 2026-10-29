use std::fs;
use std::path::{Path, PathBuf};

use chio_binding_helpers::{
    canonicalize_json_str, capability_signing_body_canonical_json, receipt_body_canonical_json,
    sha256_hex_utf8, sign_wrapped_json_ed25519, signed_manifest_body_canonical_json,
    verify_capability, verify_receipt, verify_receipt_json,
    verify_receipt_json_with_trusted_signer_hex, verify_receipt_with_trusted_signers,
    verify_signed_manifest, verify_wrapped_json, CapabilityVerification, ErrorCode,
    ManifestVerification, ReceiptVerification,
};
use chio_core::{
    capability::{
        attenuation::{DelegationLink, DelegationLinkBody},
        scope::{ChioScope, Constraint, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    },
    receipt::body::chio_receipt_id,
    receipt::body::ChioReceipt,
    receipt::body::ChioReceiptBody,
    receipt::decision::Decision,
    receipt::decision::ToolCallAction,
    receipt::kinds::BoundaryClass,
    receipt::kinds::ReceiptKind,
    receipt::kinds::RedactionMode,
    receipt::kinds::ToolOrigin,
    receipt::kinds::TrustLevel,
    receipt::metadata::GuardEvidence,
    receipt::signing::{bind_receipt_signing_nonce, ChioReceiptSigningBody},
    sha256_hex, Keypair,
};
use chio_manifest::{
    sign_manifest, LatencyHint, RequiredPermissions, SignedManifest,
    ToolDefinition as SignedManifestToolDefinition, ToolManifest as SignedToolManifest,
};
use serde_json::{json, Value};

use chio_test_support::ctx::TestUnwrap;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .test_unwrap("crate is nested under repo root")
        .to_path_buf()
}

fn canonical_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/canonical/v1.json")
}

fn receipt_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/receipt/v1.json")
}

fn capability_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/capability/v1.json")
}

fn hashing_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/hashing/v1.json")
}

fn manifest_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/manifest/v1.json")
}

fn signing_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/signing/v1.json")
}

fn pretty_json(value: &Value) -> String {
    let mut rendered = serde_json::to_string_pretty(value).test_unwrap("serialize fixture");
    rendered.push('\n');
    rendered
}

fn assert_fixture_matches(path: &Path, actual: &Value) {
    let expected = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
    let rendered = pretty_json(actual);
    assert_eq!(
        expected,
        rendered,
        "fixture {} is out of date",
        path.display()
    );
}

fn canonical_vector_fixture() -> Value {
    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "cases": [
            {
                "id": "object_key_sorting",
                "description": "Object keys are sorted lexicographically in canonical output.",
                "input_json": "{\"z\":1,\"a\":2,\"m\":3}",
                "canonical_json": "{\"a\":2,\"m\":3,\"z\":1}"
            },
            {
                "id": "nested_structures",
                "description": "Nested objects and arrays preserve structure while object keys are canonicalized.",
                "input_json": "{\"tool\":\"read\",\"params\":{\"path\":\"/tmp/demo\",\"flags\":[\"read\",\"text\"]},\"enabled\":true}",
                "canonical_json": "{\"enabled\":true,\"params\":{\"flags\":[\"read\",\"text\"],\"path\":\"/tmp/demo\"},\"tool\":\"read\"}"
            },
            {
                "id": "number_formatting",
                "description": "Numbers follow RFC 8785 / ECMAScript shortest-form rendering.",
                "input_json": "{\"whole\":1.0,\"small\":1e-7,\"big\":1e21,\"negative_zero\":-0.0}",
                "canonical_json": "{\"big\":1e+21,\"negative_zero\":0,\"small\":1e-7,\"whole\":1}"
            },
            {
                "id": "utf16_key_ordering",
                "description": "Object keys are sorted by UTF-16 code units, not UTF-8 bytes.",
                "input_json": "{\"\\ue000\":1,\"\\ud800\\udc00\":2}",
                "canonical_json": "{\"\u{10000}\":2,\"\u{e000}\":1}"
            },
            {
                "id": "string_escaping",
                "description": "Strings use minimal JSON escaping in canonical output.",
                "input_json": "{\"text\":\"line\\n\\\"quoted\\\"\\\\path\"}",
                "canonical_json": "{\"text\":\"line\\n\\\"quoted\\\"\\\\path\"}"
            }
        ]
    })
}

fn base_receipt_body(
    id: &str,
    action: ToolCallAction,
    decision: Decision,
    keypair: &Keypair,
) -> ChioReceiptBody {
    ChioReceiptBody {
        id: id.to_string(),
        timestamp: 1710000200,
        capability_id: "cap-bindings-001".to_string(),
        tool_server: "srv-files".to_string(),
        tool_name: "file_read".to_string(),
        action,
        decision: Some(decision),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: sha256_hex(br#"{"ok":true}"#),
        policy_hash: "policy-bindings-v1".to_string(),
        evidence: vec![
            GuardEvidence {
                guard_name: "ForbiddenPathGuard".to_string(),
                verdict: true,
                details: Some("path allowed".to_string()),
            },
            GuardEvidence {
                guard_name: "SecretLeakGuard".to_string(),
                verdict: true,
                details: Some("no secrets detected".to_string()),
            },
        ],
        metadata: Some(json!({
            "surface": "bindings-vectors",
            "version": 1
        })),
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    }
}

fn hashing_vector_fixture() -> Value {
    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "cases": [
            {
                "id": "empty_utf8",
                "description": "SHA-256 of the empty UTF-8 string.",
                "input_utf8": "",
                "sha256_hex": sha256_hex_utf8("")
            },
            {
                "id": "hello_utf8",
                "description": "SHA-256 of a simple ASCII string.",
                "input_utf8": "hello",
                "sha256_hex": sha256_hex_utf8("hello")
            },
            {
                "id": "unicode_utf8",
                "description": "SHA-256 operates on UTF-8 bytes for non-ASCII strings too.",
                "input_utf8": "chio 🔐",
                "sha256_hex": sha256_hex_utf8("chio 🔐")
            }
        ]
    })
}

#[allow(clippy::too_many_arguments)]
fn signing_json_case_value(
    id: &str,
    description: &str,
    schema_id: &str,
    input_json: &str,
    canonical_json: &str,
    public_key_hex: &str,
    signature_hex: &str,
    expected_verify: bool,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "schema_id": schema_id,
        "input_json": input_json,
        "canonical_json": canonical_json,
        "public_key_hex": public_key_hex,
        "signature_hex": signature_hex,
        "expected_verify": expected_verify,
    })
}

const SIGNING_VECTOR_SCHEMA_ID: &str = "chio.receipt.v1";

fn signing_vector_fixture() -> Value {
    let seed_hex = "09".repeat(32);
    let signed_json =
        sign_wrapped_json_ed25519(SIGNING_VECTOR_SCHEMA_ID, "{\"z\":1,\"a\":2}", &seed_hex)
            .test_unwrap("sign json string");

    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "signing_key_seed_hex": seed_hex,
        "json_cases": [
            signing_json_case_value(
                "valid_wrapped_json_message",
                "Signing raw JSON canonicalizes it, then signs the signing wrapper under the schema id.",
                SIGNING_VECTOR_SCHEMA_ID,
                "{\"z\":1,\"a\":2}",
                &signed_json.canonical_json,
                &signed_json.public_key_hex,
                &signed_json.signature_hex,
                true,
            ),
            signing_json_case_value(
                "tampered_wrapped_json_message",
                "Verification fails if the JSON payload changes after signing.",
                SIGNING_VECTOR_SCHEMA_ID,
                "{\"z\":2,\"a\":2}",
                &canonicalize_json_str("{\"z\":2,\"a\":2}").test_unwrap("canonicalize tampered json"),
                &signed_json.public_key_hex,
                &signed_json.signature_hex,
                false,
            ),
            signing_json_case_value(
                "substituted_schema_id",
                "Verification fails if the signature is checked under another schema id.",
                "chio.capability.v1",
                "{\"z\":1,\"a\":2}",
                &signed_json.canonical_json,
                &signed_json.public_key_hex,
                &signed_json.signature_hex,
                false,
            ),
        ],
    })
}

fn sample_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-files".to_string(),
            tool_name: "file_read".to_string(),
            operations: vec![Operation::Invoke, Operation::ReadResult],
            constraints: vec![Constraint::PathPrefix("/workspace/".to_string())],
            max_invocations: Some(3),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    }
}

fn signed_delegation_link(
    capability_id: &str,
    delegator: &Keypair,
    delegatee: &Keypair,
    timestamp: u64,
) -> DelegationLink {
    DelegationLink::sign(
        DelegationLinkBody {
            capability_id: capability_id.to_string(),
            delegator: delegator.public_key(),
            delegatee: delegatee.public_key(),
            attenuations: vec![],
            timestamp,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        delegator,
    )
    .test_unwrap("delegation link")
}

fn base_capability_body(
    id: &str,
    issuer: &Keypair,
    subject: &Keypair,
    issued_at: u64,
    expires_at: u64,
    delegation_chain: Vec<DelegationLink>,
) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: id.to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: sample_scope(),
        issued_at,
        expires_at,
        delegation_chain,
        aggregate_invocation_budget: None,
    }
}

fn capability_case_value(
    id: &str,
    description: &str,
    capability: &CapabilityToken,
    verify_at: u64,
    verification: CapabilityVerification,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "verify_at": verify_at,
        "capability": capability,
        "capability_signing_body_canonical_json": capability_signing_body_canonical_json(capability).test_unwrap("canonical capability signing body"),
        "expected": {
            "signature_valid": verification.signature_valid,
            "delegation_chain_shape_valid": verification.delegation_chain_shape_valid,
            "time_valid": verification.time_valid,
            "time_status": verification.time_status,
        }
    })
}

fn capability_cases() -> Vec<Value> {
    let issuer = Keypair::from_seed(&[11u8; 32]);
    let subject = Keypair::from_seed(&[12u8; 32]);
    let delegatee = Keypair::from_seed(&[13u8; 32]);

    let valid_delegation_link =
        signed_delegation_link("cap-bindings-valid", &issuer, &delegatee, 1710000250);
    let valid_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-valid",
            &issuer,
            &subject,
            1710000200,
            1710000800,
            vec![valid_delegation_link],
        ),
        &issuer,
    )
    .test_unwrap("valid capability");
    let valid_verify_at = 1710000400;
    let valid_verification = verify_capability(&valid_capability, valid_verify_at, Some(4))
        .test_unwrap("valid capability verification");

    let expired_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-expired",
            &issuer,
            &subject,
            1710000000,
            1710000100,
            vec![],
        ),
        &issuer,
    )
    .test_unwrap("expired capability");
    let expired_verify_at = 1710000400;
    let expired_verification = verify_capability(&expired_capability, expired_verify_at, Some(4))
        .test_unwrap("expired capability verification");

    let not_yet_valid_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-not-yet-valid",
            &issuer,
            &subject,
            1710000600,
            1710001200,
            vec![],
        ),
        &issuer,
    )
    .test_unwrap("not yet valid capability");
    let not_yet_valid_verify_at = 1710000400;
    let not_yet_valid_verification =
        verify_capability(&not_yet_valid_capability, not_yet_valid_verify_at, Some(4))
            .test_unwrap("not yet valid capability verification");

    let mut tampered_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-invalid-signature",
            &issuer,
            &subject,
            1710000200,
            1710000800,
            vec![],
        ),
        &issuer,
    )
    .test_unwrap("tampered capability");
    tampered_capability.scope.grants[0].tool_name = "file_write".to_string();
    let tampered_verify_at = 1710000400;
    let tampered_verification =
        verify_capability(&tampered_capability, tampered_verify_at, Some(4))
            .test_unwrap("tampered capability verification");

    let mut invalid_delegation_link =
        signed_delegation_link("cap-bindings-broken-chain", &issuer, &delegatee, 1710000300);
    invalid_delegation_link.timestamp = 1710000301;
    let broken_chain_capability = CapabilityToken::sign(
        base_capability_body(
            "cap-bindings-broken-chain",
            &issuer,
            &subject,
            1710000200,
            1710000800,
            vec![invalid_delegation_link],
        ),
        &issuer,
    )
    .test_unwrap("broken chain capability");
    let broken_chain_verify_at = 1710000400;
    let broken_chain_verification =
        verify_capability(&broken_chain_capability, broken_chain_verify_at, Some(4))
            .test_unwrap("broken chain capability verification");

    vec![
        capability_case_value(
            "valid_delegated_capability",
            "Capability is signed correctly, valid at the verification time, and carries a valid delegation link.",
            &valid_capability,
            valid_verify_at,
            valid_verification,
        ),
        capability_case_value(
            "expired_capability",
            "Capability signature is valid, but the token is expired at verification time.",
            &expired_capability,
            expired_verify_at,
            expired_verification,
        ),
        capability_case_value(
            "not_yet_valid_capability",
            "Capability signature is valid, but the token is not yet valid at verification time.",
            &not_yet_valid_capability,
            not_yet_valid_verify_at,
            not_yet_valid_verification,
        ),
        capability_case_value(
            "tampered_capability_signature",
            "Capability payload was modified after signing, so signature verification fails.",
            &tampered_capability,
            tampered_verify_at,
            tampered_verification,
        ),
        capability_case_value(
            "broken_delegation_chain_signature",
            "Capability was signed after embedding a delegation link whose own signature no longer matches.",
            &broken_chain_capability,
            broken_chain_verify_at,
            broken_chain_verification,
        ),
    ]
}

fn capability_vector_fixture() -> Value {
    let issuer = Keypair::from_seed(&[11u8; 32]);
    let subject = Keypair::from_seed(&[12u8; 32]);
    let delegatee = Keypair::from_seed(&[13u8; 32]);

    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "issuer_seed_hex": issuer.seed_hex(),
        "subject_seed_hex": subject.seed_hex(),
        "delegatee_seed_hex": delegatee.seed_hex(),
        "cases": capability_cases(),
    })
}

fn sample_signed_manifest(public_key: String, tool_names: &[&str]) -> SignedToolManifest {
    SignedToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "srv-bindings-demo".to_string(),
        name: "Bindings Demo".to_string(),
        description: Some("Manifest vector for bindings-core SDK fixtures".to_string()),
        version: "1.0.0".to_string(),
        tools: tool_names
            .iter()
            .map(|tool_name| SignedManifestToolDefinition {
                name: (*tool_name).to_string(),
                description: format!("Tool definition for {tool_name}"),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" }
                    },
                    "required": ["path"]
                }),
                output_schema: Some(json!({
                    "type": "object",
                    "properties": {
                        "ok": { "type": "boolean" }
                    }
                })),
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: *tool_name != "file_write",
                    destructive: *tool_name == "file_write",
                    idempotent: false,
                    requires_approval: *tool_name == "file_write",
                },
                latency_hint: Some(if *tool_name == "file_read" {
                    LatencyHint::Fast
                } else {
                    LatencyHint::Moderate
                }),
                flow: Some(chio_manifest::ToolFlowDeclaration::public_egress()),
            })
            .collect(),
        server_tools: Vec::new(),
        required_permissions: Some(RequiredPermissions {
            read_paths: Some(vec!["/workspace".to_string()]),
            write_paths: Some(vec!["/workspace/output".to_string()]),
            network_destinations: Some(vec![chio_manifest::NetworkDestination::new(
                "api.example.com",
                443,
            )
            .test_unwrap("valid network destination")]),
            environment_variables: Some(vec![chio_manifest::EnvironmentVariableName::new(
                "CHIO_ENV",
            )
            .test_unwrap("valid environment variable")]),
            native_syscall_profile: chio_manifest::NativeSyscallProfile::NativeStandardV1,
        }),
        public_key,
    }
}

fn signed_manifest_with_manual_signature(
    manifest: SignedToolManifest,
    signer: &Keypair,
) -> SignedManifest {
    let signature = signer
        .sign_wrapped(
            chio_core::signed_artifact::CHIO_TOOL_MANIFEST_SCHEMA,
            &chio_core::canonical::CanonicalBytes::from_serializable(&manifest)
                .test_unwrap("canonical manifest"),
        )
        .test_unwrap("manual manifest signature");
    SignedManifest {
        manifest,
        signature,
        signer_key: signer.public_key(),
    }
}

fn manifest_case_value(
    id: &str,
    description: &str,
    signed_manifest: &SignedManifest,
    verification: ManifestVerification,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "signed_manifest": signed_manifest,
        "manifest_body_canonical_json": signed_manifest_body_canonical_json(signed_manifest).test_unwrap("canonical manifest body"),
        "expected": {
            "structure_valid": verification.structure_valid,
            "signature_valid": verification.signature_valid,
            "embedded_public_key_valid": verification.embedded_public_key_valid,
            "embedded_public_key_matches_signer": verification.embedded_public_key_matches_signer,
        }
    })
}

fn manifest_cases() -> Vec<Value> {
    let server = Keypair::from_seed(&[21u8; 32]);
    let alternate = Keypair::from_seed(&[22u8; 32]);

    let valid_signed_manifest = sign_manifest(
        &sample_signed_manifest(server.public_key().to_hex(), &["file_read"]),
        &server,
    )
    .test_unwrap("valid signed manifest");
    let valid_verification =
        verify_signed_manifest(&valid_signed_manifest).test_unwrap("valid manifest verification");

    let mut tampered_signed_manifest = sign_manifest(
        &sample_signed_manifest(server.public_key().to_hex(), &["file_read"]),
        &server,
    )
    .test_unwrap("tampered signed manifest");
    tampered_signed_manifest.manifest.version = "1.0.1".to_string();
    let tampered_verification = verify_signed_manifest(&tampered_signed_manifest)
        .test_unwrap("tampered manifest verification");

    let mismatched_key_signed_manifest = signed_manifest_with_manual_signature(
        sample_signed_manifest(alternate.public_key().to_hex(), &["file_read"]),
        &server,
    );
    let mismatched_key_verification = verify_signed_manifest(&mismatched_key_signed_manifest)
        .test_unwrap("mismatched key manifest verification");

    let duplicate_tool_manifest =
        sample_signed_manifest(server.public_key().to_hex(), &["file_read", "file_read"]);
    let duplicate_tool_signed_manifest =
        signed_manifest_with_manual_signature(duplicate_tool_manifest, &server);
    let duplicate_tool_verification = verify_signed_manifest(&duplicate_tool_signed_manifest)
        .test_unwrap("duplicate tool manifest verification");

    let invalid_embedded_key_signed_manifest = signed_manifest_with_manual_signature(
        sample_signed_manifest("not-a-public-key".to_string(), &["file_read", "file_write"]),
        &server,
    );
    let invalid_embedded_key_verification =
        verify_signed_manifest(&invalid_embedded_key_signed_manifest)
            .test_unwrap("invalid embedded key manifest verification");

    vec![
        manifest_case_value(
            "valid_signed_manifest",
            "Signed manifest is structurally valid, signature-valid, and its embedded public key matches the signer.",
            &valid_signed_manifest,
            valid_verification,
        ),
        manifest_case_value(
            "tampered_manifest_signature",
            "Manifest payload was modified after signing, so signature verification fails while structure remains valid.",
            &tampered_signed_manifest,
            tampered_verification,
        ),
        manifest_case_value(
            "mismatched_embedded_public_key",
            "Manifest is signed correctly, but the manifest.public_key field does not match the signer key carried alongside the signature.",
            &mismatched_key_signed_manifest,
            mismatched_key_verification,
        ),
        manifest_case_value(
            "duplicate_tool_name_manifest",
            "Manifest signature is valid, but validation fails because tool names are not unique.",
            &duplicate_tool_signed_manifest,
            duplicate_tool_verification,
        ),
        manifest_case_value(
            "invalid_embedded_public_key",
            "Manifest signature is valid, but the embedded public_key field is not a parseable Ed25519 key.",
            &invalid_embedded_key_signed_manifest,
            invalid_embedded_key_verification,
        ),
    ]
}

fn manifest_vector_fixture() -> Value {
    let server = Keypair::from_seed(&[21u8; 32]);
    let alternate = Keypair::from_seed(&[22u8; 32]);

    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "server_seed_hex": server.seed_hex(),
        "alternate_seed_hex": alternate.seed_hex(),
        "cases": manifest_cases(),
    })
}

// On-disk JSON is the source of truth; the in-Rust generators cover a subset
// of cases. The #[ignore] tests below regenerate the checked-in files when run
// manually (`cargo test -- --ignored`).

#[test]
#[ignore = "on-disk canonical corpus is the source of truth; run to regenerate after editing the fixture builder"]
fn canonical_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&canonical_fixture_path(), &canonical_vector_fixture());
}

#[test]
#[ignore = "on-disk JSON is the source of truth; the in-Rust generator is a regenerator helper"]
fn hashing_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&hashing_fixture_path(), &hashing_vector_fixture());
}

fn receipt_expectation(receipt: &ChioReceipt) -> Value {
    serde_json::to_value(verify_receipt(receipt).test_unwrap("verify receipt case"))
        .test_unwrap("serialize receipt verification")
}

fn indented_pretty_json(value: &Value, indent: &str) -> String {
    serde_json::to_string_pretty(value)
        .test_unwrap("render receipt fixture fragment")
        .replace('\n', &format!("\n{indent}"))
}

fn null_observation_outcome_case(keypair: &Keypair) -> Value {
    let action = ToolCallAction::from_parameters(json!({
        "path": "/workspace/docs/roadmap.md",
        "mode": "read"
    }))
    .test_unwrap("null observation action");
    let receipt = ChioReceipt::sign(
        base_receipt_body(
            "rcpt-bindings-null-observation",
            action,
            Decision::Allow,
            keypair,
        ),
        keypair,
    )
    .test_unwrap("sign null observation receipt");
    let mut receipt_json =
        serde_json::to_value(&receipt).test_unwrap("serialize null observation receipt");
    receipt_json["observation_outcome"] = Value::Null;
    let decoded: ChioReceipt =
        serde_json::from_value(receipt_json.clone()).test_unwrap("decode null observation receipt");
    json!({
        "id": "mediated_decision_with_null_observation_outcome",
        "description": "An explicit null observation outcome is absent, so a signed mediated allow keeps its authorization label.",
        "receipt": receipt_json,
        "receipt_body_canonical_json": receipt_body_canonical_json(&decoded).test_unwrap("canonical null observation body"),
        "expected": receipt_expectation(&decoded),
    })
}

fn mediated_allow_with_trust_level_case(keypair: &Keypair, trust_level: TrustLevel) -> Value {
    let action = ToolCallAction::from_parameters(json!({
        "path": "/workspace/docs/roadmap.md",
        "mode": "read"
    }))
    .test_unwrap("trust level action");
    let mut body = base_receipt_body(
        &format!("rcpt-bindings-{}-trust", trust_level.as_str()),
        action,
        Decision::Allow,
        keypair,
    );
    body.trust_level = trust_level;
    bind_receipt_signing_nonce(&mut body);
    body.id = chio_receipt_id(&body).test_unwrap("trust level receipt id");
    let signature = keypair
        .sign_wrapped(
            chio_core::receipt::body::CHIO_RECEIPT_SCHEMA,
            &chio_core::canonical::CanonicalBytes::from_serializable(
                &ChioReceiptSigningBody::from(&body),
            )
            .test_unwrap("canonical trust level receipt body"),
        )
        .test_unwrap("sign trust level receipt body");
    let mut receipt_json = serde_json::to_value(&body).test_unwrap("serialize trust level body");
    receipt_json["signature"] =
        serde_json::to_value(&signature).test_unwrap("serialize trust level signature");
    let decoded: ChioReceipt =
        serde_json::from_value(receipt_json).test_unwrap("decode trust level receipt");
    json!({
        "id": format!("mediated_decision_with_{}_trust_level", trust_level.as_str()),
        "description": format!(
            "A mediated allow with {} trust has a valid id but is not signable and is not authorization.",
            trust_level.as_str()
        ),
        "receipt": serde_json::to_value(&decoded).test_unwrap("serialize trust level receipt"),
        "receipt_body_canonical_json": receipt_body_canonical_json(&decoded).test_unwrap("canonical trust level body"),
        "expected": receipt_expectation(&decoded),
    })
}

/// Re-signs every receipt case with the corpus key over the case's own signing
/// body and moves every occurrence of each old signature in `raw` to the new
/// one. Each case is then rejected only by the rule it names, never by a
/// signature in another format.
fn resign_corpus_receipts(mut raw: String, fixture: &Value, keypair: &Keypair) -> String {
    let corpus_key = keypair.public_key().to_hex();
    for case in fixture["cases"]
        .as_array()
        .test_unwrap("receipt cases array")
    {
        let id = case["id"].as_str().test_unwrap("receipt case id");
        assert_eq!(
            case["receipt"]["kernel_key"].as_str(),
            Some(corpus_key.as_str()),
            "receipt case {id} is not under the corpus key"
        );
        let receipt: ChioReceipt =
            serde_json::from_value(case["receipt"].clone()).test_unwrap("parse receipt case");
        let signature = keypair
            .sign_wrapped(
                chio_core::receipt::body::CHIO_RECEIPT_SCHEMA,
                &chio_core::canonical::CanonicalBytes::from_serializable(
                    &ChioReceiptSigningBody::from(&receipt.body()),
                )
                .test_unwrap("canonical receipt signing body"),
            )
            .test_unwrap("re-sign receipt");
        let old_signature = case["receipt"]["signature"]
            .as_str()
            .test_unwrap("receipt signature")
            .to_string();
        raw = raw.replace(&old_signature, &signature.to_hex());
    }
    raw
}

#[test]
#[ignore = "regenerator: rewrite each expected block of the checked-in receipt corpus in place from verify_receipt and append missing cases; run with --ignored, then `cargo xtask freeze-vectors`"]
fn refresh_receipt_vector_fixture() {
    let path = receipt_fixture_path();
    let mut raw = fs::read_to_string(&path).test_unwrap("read receipt fixture");
    let mut fixture: Value = serde_json::from_str(&raw).test_unwrap("parse receipt fixture");
    let keypair = Keypair::from_seed(&[7u8; 32]);
    assert_eq!(fixture["signing_key_seed_hex"], keypair.seed_hex());
    raw = resign_corpus_receipts(raw, &fixture, &keypair);
    fixture = serde_json::from_str(&raw).test_unwrap("parse re-signed receipt fixture");

    let cases = fixture["cases"]
        .as_array_mut()
        .test_unwrap("receipt cases array");
    let mut cursor = 0;
    for case in cases.iter_mut() {
        let receipt: ChioReceipt =
            serde_json::from_value(case["receipt"].clone()).test_unwrap("parse receipt case");
        let expected = receipt_expectation(&receipt);
        let old_block = format!(
            "\"expected\": {}",
            indented_pretty_json(&case["expected"], "      ")
        );
        let new_block = format!(
            "\"expected\": {}",
            indented_pretty_json(&expected, "      ")
        );
        let start = cursor
            + raw[cursor..]
                .find(&old_block)
                .test_unwrap("locate expected block");
        raw.replace_range(start..start + old_block.len(), &new_block);
        cursor = start + new_block.len();
        case["expected"] = expected;
    }

    let appended = [
        null_observation_outcome_case(&keypair),
        mediated_allow_with_trust_level_case(&keypair, TrustLevel::Verified),
        mediated_allow_with_trust_level_case(&keypair, TrustLevel::Advisory),
    ];
    for extra in appended {
        if cases.iter().any(|case| case["id"] == extra["id"]) {
            continue;
        }
        let close = raw.find("\n  ]").test_unwrap("locate end of receipt cases");
        raw.insert_str(
            close,
            &format!(",\n    {}", indented_pretty_json(&extra, "    ")),
        );
        cases.push(extra);
    }

    let rewritten: Value = serde_json::from_str(&raw).test_unwrap("parse rewritten fixture");
    assert_eq!(
        rewritten, fixture,
        "in-place rewrite must equal the refreshed corpus"
    );
    fs::write(&path, raw).test_unwrap("write receipt fixture");
}

#[test]
fn signing_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&signing_fixture_path(), &signing_vector_fixture());
}

#[test]
#[ignore = "regenerator: rewrite the signing vector fixture from signing_vector_fixture(); run with --ignored, then `cargo xtask freeze-vectors`"]
fn regenerate_signing_vector_fixture() {
    fs::write(
        signing_fixture_path(),
        pretty_json(&signing_vector_fixture()),
    )
    .test_unwrap("write signing vector fixture");
}

#[test]
#[ignore = "on-disk JSON is the source of truth; the in-Rust generator is a regenerator helper"]
fn capability_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&capability_fixture_path(), &capability_vector_fixture());
}

#[test]
fn manifest_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&manifest_fixture_path(), &manifest_vector_fixture());
}

#[test]
#[ignore = "regenerator: rewrite the manifest vector fixture from manifest_vector_fixture(); run with --ignored, then `cargo xtask freeze-vectors`"]
fn regenerate_manifest_vector_fixture() {
    fs::write(
        manifest_fixture_path(),
        pretty_json(&manifest_vector_fixture()),
    )
    .test_unwrap("write manifest vector fixture");
}

// Re-sign the checked-in capability corpus in place after a capability
// signing-schema change. The signed body carries the schema string, so a
// schema change invalidates every stored signature. Only capabilities whose
// own signature is meant to verify are re-signed; the intentionally tampered
// cases keep their invalid signatures (a corrupted signature stays invalid
// under any schema). Run with `--ignored`, then refreeze the manifest
// with `cargo xtask freeze-vectors`.
#[test]
#[ignore = "regenerator: re-sign capability vectors after a signing-schema change; run with --ignored"]
fn rebless_capability_vector_signatures() {
    use std::collections::{BTreeMap, HashMap};
    let path = capability_fixture_path();
    let raw = fs::read_to_string(&path).test_unwrap("read capability fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse capability fixture");

    let mut by_pub: HashMap<String, Keypair> = HashMap::new();
    for seed_field in [
        "issuer_seed_hex",
        "subject_seed_hex",
        "delegatee_seed_hex",
        "alt_seed_1_hex",
        "alt_seed_2_hex",
        "alt_seed_3_hex",
        "alt_seed_4_hex",
    ] {
        if let Some(hex) = fixture[seed_field].as_str() {
            let keypair = Keypair::from_seed_hex(hex).test_unwrap("seed hex");
            by_pub.insert(keypair.public_key().to_hex(), keypair);
        }
    }
    let keypair_for = |key: &chio_core::PublicKey| {
        let hex = key.to_hex();
        by_pub
            .get(&hex)
            .unwrap_or_else(|| panic!("no seed keypair for {hex}"))
    };

    // Links are re-signed where the case expects a valid chain shape and the
    // token where it expects a valid signature; the token signs its links.
    let mut replacements: BTreeMap<String, String> = BTreeMap::new();
    let mut kept: Vec<String> = Vec::new();
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        let mut token: CapabilityToken =
            serde_json::from_value(case["capability"].clone()).test_unwrap("parse capability");
        let resign_links = case["expected"]["delegation_chain_shape_valid"]
            .as_bool()
            .unwrap_or(false);
        let resign_token = case["expected"]["signature_valid"]
            .as_bool()
            .unwrap_or(false);
        for link in &mut token.delegation_chain {
            let old = link.signature.to_hex();
            if resign_links {
                *link = DelegationLink::sign(link.body(), keypair_for(&link.delegator))
                    .test_unwrap("re-sign delegation link");
                replacements.insert(old, link.signature.to_hex());
            } else {
                kept.push(old);
            }
        }
        let old = token.signature.to_hex();
        if resign_token {
            let resigned = CapabilityToken::sign(token.body(), keypair_for(&token.issuer))
                .test_unwrap("re-sign capability");
            replacements.insert(old, resigned.signature.to_hex());
        } else {
            kept.push(old);
        }
    }
    for old in &kept {
        assert!(
            !replacements.contains_key(old),
            "signature {old} is both re-signed and kept invalid"
        );
    }

    let mut text = raw;
    for (old, new) in &replacements {
        text = text.replace(old.as_str(), new.as_str());
    }
    fs::write(&path, text).test_unwrap("write capability fixture");
}

#[test]
fn canonical_fixture_cases_round_trip_through_public_api() {
    let fixture = canonical_vector_fixture();
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        let input = case["input_json"].as_str().test_unwrap("input_json");
        let expected = case["canonical_json"]
            .as_str()
            .test_unwrap("canonical_json");
        let actual = canonicalize_json_str(input).test_unwrap("canonicalize case");
        assert_eq!(actual, expected, "canonical case {}", case["id"]);
    }
}

#[test]
fn hashing_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus so the test exercises every case regardless of
    // whether the in-Rust generator has been updated.
    let raw = fs::read_to_string(hashing_fixture_path()).test_unwrap("read hashing fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse hashing fixture");
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        let input = case["input_utf8"].as_str().test_unwrap("input_utf8");
        let expected = case["sha256_hex"].as_str().test_unwrap("sha256_hex");
        let actual = sha256_hex_utf8(input);
        assert_eq!(actual, expected, "hashing case {}", case["id"]);
    }
}

#[test]
fn receipt_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus so the round-trip covers every case.
    let raw = fs::read_to_string(receipt_fixture_path()).test_unwrap("read receipt fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse receipt fixture");
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        let receipt: ChioReceipt =
            serde_json::from_value(case["receipt"].clone()).test_unwrap("parse receipt case");
        let expected: ReceiptVerification =
            serde_json::from_value(case["expected"].clone()).test_unwrap("parse expectation");
        let actual = verify_receipt(&receipt).test_unwrap("verify receipt case");
        let actual_value = serde_json::to_value(&actual).test_unwrap("serialize verification");
        assert_eq!(
            actual_value["trust_level"], case["receipt"]["trust_level"],
            "receipt case {}",
            case["id"]
        );
        assert_eq!(actual, expected, "receipt case {}", case["id"]);
    }
}

#[test]
fn receipt_fixture_allow_case_passes_with_trusted_signer() {
    let raw = fs::read_to_string(receipt_fixture_path()).test_unwrap("read receipt fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse receipt fixture");
    let case = fixture["cases"]
        .as_array()
        .test_unwrap("cases array")
        .iter()
        .find(|case| case["id"] == "allow_receipt")
        .test_unwrap("allow case");
    let receipt: ChioReceipt =
        serde_json::from_value(case["receipt"].clone()).test_unwrap("parse receipt case");
    let actual =
        verify_receipt_with_trusted_signers(&receipt, std::slice::from_ref(&receipt.kernel_key))
            .test_unwrap("verify receipt with trusted signer");

    assert!(actual.signature_valid);
    assert!(actual.parameter_hash_valid);
    assert!(actual.receipt_id_valid);
    assert!(actual.signer_trusted);
    assert!(actual.ok);
    assert!(actual.authorized);
}

#[test]
fn receipt_fixture_allow_case_passes_with_json_trusted_signer_hex() {
    let raw = fs::read_to_string(receipt_fixture_path()).test_unwrap("read receipt fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse receipt fixture");
    let case = fixture["cases"]
        .as_array()
        .test_unwrap("cases array")
        .iter()
        .find(|case| case["id"] == "allow_receipt")
        .test_unwrap("allow case");
    let receipt_json =
        serde_json::to_string(&case["receipt"]).test_unwrap("serialize receipt case");
    let trusted_signer_hex = vec![case["receipt"]["kernel_key"]
        .as_str()
        .test_unwrap("kernel_key")
        .to_string()];
    let actual = verify_receipt_json_with_trusted_signer_hex(&receipt_json, &trusted_signer_hex)
        .test_unwrap("verify receipt json with trusted signer hex");

    assert!(actual.signature_valid);
    assert!(actual.parameter_hash_valid);
    assert!(actual.receipt_id_valid);
    assert!(actual.signer_trusted);
    assert!(actual.ok);
    assert!(actual.authorized);
}

fn protocol_primitives_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/fixtures/protocol-primitives-v1.json")
}

fn read_json_fixture(path: &Path) -> Value {
    let raw = fs::read_to_string(path).test_unwrap("read fixture");
    serde_json::from_str(&raw).test_unwrap("parse fixture")
}

fn kernel_key_hex(receipt: &Value) -> Vec<String> {
    vec![receipt["kernel_key"]
        .as_str()
        .test_unwrap("kernel_key")
        .to_string()]
}

fn assert_receipt_json_rejected(input: &str, label: &str) {
    let trusted = kernel_key_hex(&serde_json::from_str(input).test_unwrap("input is JSON"));
    for result in [
        verify_receipt_json(input),
        verify_receipt_json_with_trusted_signer_hex(input, &trusted),
    ] {
        match result {
            Err(error) => assert_eq!(error.code(), ErrorCode::UntrustedInput, "{label}"),
            Ok(verification) => {
                panic!("duplicate keys in {label} were decoded: {verification:?}")
            }
        }
    }
}

#[test]
fn receipt_json_rejects_raw_duplicate_key_corpus_cases_at_original_bytes() {
    let corpus = read_json_fixture(&protocol_primitives_fixture_path());
    let valid = corpus["cases"]
        .as_array()
        .test_unwrap("cases array")
        .iter()
        .find(|case| case["name"] == "receipt-internal-origin")
        .test_unwrap("valid receipt case");
    assert_eq!(valid["valid"], json!(true));
    let mut rejected = Vec::new();
    for case in corpus["raw_cases"]
        .as_array()
        .test_unwrap("raw_cases array")
    {
        if case["schema_file"] != "receipt/record.schema.json" {
            continue;
        }
        let name = case["name"].as_str().test_unwrap("raw case name");
        let text = case["instance_text"]
            .as_str()
            .test_unwrap("raw case instance_text");
        let collapsed: Value = serde_json::from_str(text).test_unwrap("raw case is JSON");
        assert_eq!(collapsed, valid["instance"], "raw case {name} collapses");
        for input in [
            serde_json::to_string(&collapsed).test_unwrap("compact"),
            serde_json::to_string_pretty(&collapsed).test_unwrap("pretty"),
        ] {
            verify_receipt_json(&input).test_unwrap("valid corpus receipt decodes");
        }
        assert_receipt_json_rejected(text, name);
        rejected.push(name.to_string());
    }
    assert_eq!(
        rejected,
        ["receipt-duplicate-id", "receipt-duplicate-parameter"]
    );
}

#[test]
fn receipt_json_rejects_duplicate_keys_in_a_validly_signed_receipt() {
    let fixture = read_json_fixture(&receipt_fixture_path());
    let case = fixture["cases"]
        .as_array()
        .test_unwrap("cases array")
        .iter()
        .find(|case| case["id"] == "allow_receipt")
        .test_unwrap("allow case");
    let compact = serde_json::to_string(&case["receipt"]).test_unwrap("compact receipt");
    let verified =
        verify_receipt_json_with_trusted_signer_hex(&compact, &kernel_key_hex(&case["receipt"]))
            .test_unwrap("signed vector verifies");
    assert!(verified.ok && verified.authorized);

    for (label, anchor, inserted) in [
        (
            "nested action.parameters",
            r#""parameters":{"#,
            r#""path":"/etc/shadow","#,
        ),
        (
            "nested metadata",
            r#""metadata":{"#,
            r#""surface":"forged","#,
        ),
        ("top-level tool_name", "{", r#""tool_name":"shell_exec","#),
    ] {
        let forged = compact.replacen(anchor, &format!("{anchor}{inserted}"), 1);
        let collapsed: Value = serde_json::from_str(&forged).test_unwrap("forged is JSON");
        assert_eq!(collapsed, case["receipt"], "{label} collapses last-wins");
        assert_receipt_json_rejected(&forged, label);
    }
}

#[test]
fn receipt_json_fixture_cases_match_expected_verification() {
    let fixture = read_json_fixture(&receipt_fixture_path());
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        let expected: ReceiptVerification =
            serde_json::from_value(case["expected"].clone()).test_unwrap("parse expectation");
        for input in [
            serde_json::to_string(&case["receipt"]).test_unwrap("compact"),
            serde_json::to_string_pretty(&case["receipt"]).test_unwrap("pretty"),
        ] {
            let actual = verify_receipt_json(&input).test_unwrap("verify receipt json");
            assert_eq!(actual, expected, "receipt case {}", case["id"]);
        }
    }
}

#[test]
fn receipt_json_accepts_full_width_integers_and_nested_parameters() {
    let keypair = Keypair::from_seed(&[23u8; 32]);
    let action = ToolCallAction::from_parameters(json!({
        "limits": {"max": u64::MAX, "min": i64::MIN, "zero": 0},
        "nested": [{"path": "/workspace/a", "flags": [true, false, null]}, [1, [2, [3]]]],
        "ratio": 0.25,
        "unicode": "caf\u{e9} \u{2028}",
    }))
    .test_unwrap("full-width parameters hash");
    let mut body = base_receipt_body("rcpt-full-width", action, Decision::Allow, &keypair);
    body.timestamp = u64::MAX;
    body.metadata = Some(json!({"sequence": u64::MAX, "window": {"offset": i64::MIN}}));
    let receipt = ChioReceipt::sign(body, &keypair).test_unwrap("sign full-width receipt");
    let trusted = vec![receipt.kernel_key.to_hex()];
    for input in [
        serde_json::to_string(&receipt).test_unwrap("compact"),
        serde_json::to_string_pretty(&receipt).test_unwrap("pretty"),
    ] {
        assert!(input.contains("18446744073709551615"));
        let verification = verify_receipt_json_with_trusted_signer_hex(&input, &trusted)
            .test_unwrap("full-width receipt verifies");
        assert!(verification.ok);
        assert!(verification.signature_valid);
        assert!(verification.parameter_hash_valid);
        assert!(verification.receipt_id_valid);
    }
}

#[test]
fn signing_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus. Per-case `signing_key_seed_hex` overrides pin
    // the keypair for cases that use an alternate seed; honoring them makes the
    // round-trip exact for those cases.
    let raw = fs::read_to_string(signing_fixture_path()).test_unwrap("read signing fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse signing fixture");
    let global_seed_hex = fixture["signing_key_seed_hex"]
        .as_str()
        .test_unwrap("signing_key_seed_hex");

    for case in fixture["json_cases"]
        .as_array()
        .test_unwrap("json_cases array")
    {
        let schema_id = case["schema_id"].as_str().test_unwrap("schema_id");
        let input = case["input_json"].as_str().test_unwrap("input_json");
        let canonical_json = case["canonical_json"]
            .as_str()
            .test_unwrap("canonical_json");
        let public_key_hex = case["public_key_hex"]
            .as_str()
            .test_unwrap("public_key_hex");
        let signature_hex = case["signature_hex"].as_str().test_unwrap("signature_hex");
        let expected_verify = case["expected_verify"]
            .as_bool()
            .test_unwrap("expected_verify");
        let seed_hex = case["signing_key_seed_hex"]
            .as_str()
            .unwrap_or(global_seed_hex);

        assert_eq!(
            canonicalize_json_str(input).test_unwrap("canonicalize json case"),
            canonical_json,
            "json canonical {}",
            case["id"]
        );

        if expected_verify {
            let signed =
                sign_wrapped_json_ed25519(schema_id, input, seed_hex).test_unwrap("sign json case");
            assert_eq!(
                signed.canonical_json, canonical_json,
                "json sign {}",
                case["id"]
            );
            assert_eq!(
                signed.public_key_hex, public_key_hex,
                "json sign {}",
                case["id"]
            );
            assert_eq!(
                signed.signature_hex, signature_hex,
                "json sign {}",
                case["id"]
            );
        }

        let actual = verify_wrapped_json(schema_id, input, public_key_hex, signature_hex);
        assert_eq!(
            actual.is_ok(),
            expected_verify,
            "json verify {}",
            case["id"]
        );
        if !expected_verify {
            assert!(
                matches!(
                    actual,
                    Err(chio_binding_helpers::Error::Core(
                        chio_core::Error::SignatureRejected
                    ))
                ),
                "json verify refusal {}",
                case["id"]
            );
        }
    }
}

#[test]
fn capability_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus. The shared `expected` field is depth-agnostic so
    // cross-language consumers can compare against the same vectors. Cases with
    // depth-aware behavior carry an optional `max_delegation_depth` plus
    // `expected_with_max_delegation_depth` pair; this test asserts both branches when present.
    let raw = fs::read_to_string(capability_fixture_path()).test_unwrap("read capability fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse capability fixture");
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        let capability: CapabilityToken =
            serde_json::from_value(case["capability"].clone()).test_unwrap("parse capability case");
        assert_eq!(
            capability_signing_body_canonical_json(&capability)
                .test_unwrap("canonical capability signing body"),
            case["capability_signing_body_canonical_json"]
                .as_str()
                .test_unwrap("capability_signing_body_canonical_json"),
            "capability case {} signing body",
            case["id"]
        );
        let verify_at = case["verify_at"].as_u64().test_unwrap("verify_at");
        let expected: CapabilityVerification = serde_json::from_value(case["expected"].clone())
            .test_unwrap("parse capability expectation");

        // Depth-agnostic verification: every consumer in the cross-language
        // matrix (chio-go, chio-py, chio-ts) runs this exact assertion.
        let actual_no_depth =
            verify_capability(&capability, verify_at, None).test_unwrap("verify capability case");
        assert_eq!(
            actual_no_depth, expected,
            "capability case {} (no max depth)",
            case["id"]
        );

        // Optional depth-aware branch: only Rust currently parameterizes
        // max_delegation_depth, so we gate on the presence of the per-case
        // override fields.
        if let Some(max_depth) = case
            .get("max_delegation_depth")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
        {
            let depth_expected_value = case
                .get("expected_with_max_delegation_depth")
                .cloned()
                .unwrap_or_else(|| case["expected"].clone());
            let depth_expected: CapabilityVerification =
                serde_json::from_value(depth_expected_value)
                    .test_unwrap("parse depth-aware capability expectation");
            let actual_with_depth = verify_capability(&capability, verify_at, Some(max_depth))
                .test_unwrap("verify capability case (max depth)");
            assert_eq!(
                actual_with_depth, depth_expected,
                "capability case {} (max_delegation_depth={})",
                case["id"], max_depth
            );
        }
    }
}

#[test]
fn old_manifest_shape_under_the_current_id_is_refused_structurally() {
    let server = Keypair::from_seed(&[21u8; 32]);
    let public_key = server.public_key().to_hex();
    let old_tool = json!({
        "name": "file_read",
        "description": "Tool definition for file_read",
        "input_schema": {"type": "object"},
        "has_side_effects": false
    });
    let current_tool =
        serde_json::to_value(&sample_signed_manifest(public_key.clone(), &["file_read"]).tools[0])
            .test_unwrap("current tool definition");
    let signed = |manifest: Value| {
        let signature = server
            .sign_wrapped(
                chio_core::signed_artifact::CHIO_TOOL_MANIFEST_SCHEMA,
                &chio_core::canonical::CanonicalBytes::from_serializable(&manifest)
                    .test_unwrap("canonical old-shape manifest"),
            )
            .test_unwrap("sign old-shape manifest");
        json!({
            "manifest": manifest,
            "signature": signature,
            "signer_key": server.public_key(),
        })
        .to_string()
    };
    let cases = [
        (
            signed(json!({
                "schema": chio_manifest::TOOL_MANIFEST_SCHEMA,
                "server_id": "srv-bindings-demo",
                "name": "Bindings Demo",
                "version": "1.0.0",
                "tools": [old_tool],
                "public_key": public_key,
            })),
            "unknown field `has_side_effects`, expected one of `name`, `description`, `input_schema`, `output_schema`, `pricing`, `annotations`, `latency_hint`, `flow` at line 1 column 250",
        ),
        (
            signed(json!({
                "schema": chio_manifest::TOOL_MANIFEST_SCHEMA,
                "server_id": "srv-bindings-demo",
                "name": "Bindings Demo",
                "version": "1.0.0",
                "tools": [current_tool],
                "required_permissions": {"network_hosts": ["api.example.com"]},
                "public_key": public_key,
            })),
            "unknown field `network_hosts`, expected one of `read_paths`, `write_paths`, `network_destinations`, `environment_variables`, `native_syscall_profile` at line 1 column 176",
        ),
    ];
    for (input, expected) in cases {
        let error = match chio_binding_helpers::parse_signed_manifest_json(&input) {
            Ok(_) => panic!("old-shape manifest must be refused"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ErrorCode::Json);
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn retired_manifest_id_is_refused_as_unsupported_schema() {
    let server = Keypair::from_seed(&[21u8; 32]);
    let mut manifest = sample_signed_manifest(server.public_key().to_hex(), &["file_read"]);
    manifest.schema = "chio.manifest.v2".to_string();
    let error = match sign_manifest(&manifest, &server) {
        Ok(_) => panic!("retired manifest id must be refused"),
        Err(error) => chio_binding_helpers::Error::from(error),
    };
    assert_eq!(error.code(), ErrorCode::UnsupportedSchema);
    assert_eq!(
        error.to_string(),
        "manifest schema version is not supported: chio.manifest.v2"
    );
    let verification =
        verify_signed_manifest(&signed_manifest_with_manual_signature(manifest, &server))
            .test_unwrap("retired manifest verification");
    assert!(!verification.structure_valid);
    assert!(verification.signature_valid);
}

#[test]
#[ignore = "helper for regenerating checked-in vector fixtures during development"]
fn print_vector_fixtures_for_bootstrap() {
    println!("--- canonical fixture ---");
    println!("{}", pretty_json(&canonical_vector_fixture()));
    println!("--- hashing fixture ---");
    println!("{}", pretty_json(&hashing_vector_fixture()));
    println!("--- signing fixture ---");
    println!("{}", pretty_json(&signing_vector_fixture()));
    println!("--- capability fixture ---");
    println!("{}", pretty_json(&capability_vector_fixture()));
    println!("--- manifest fixture ---");
    println!("{}", pretty_json(&manifest_vector_fixture()));
}
