use std::fs;
use std::path::{Path, PathBuf};

use chio_binding_helpers::{
    canonicalize_json_str, sha256_hex_utf8, sign_json_str_ed25519, sign_utf8_message_ed25519,
    signed_manifest_body_canonical_json, verify_capability, verify_json_str_signature_ed25519,
    verify_receipt, verify_receipt_json_with_trusted_signer_hex,
    verify_receipt_with_trusted_signers, verify_signed_manifest, verify_utf8_message_ed25519,
    CapabilityVerification, ManifestVerification, ReceiptVerification,
};
use chio_core::{capability::token::CapabilityToken, receipt::body::ChioReceipt, Keypair};
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

fn manifest_v2_fixture_path() -> PathBuf {
    repo_root().join("tests/bindings/vectors/manifest/v2.json")
}

fn manifest_v1_fixture_path() -> PathBuf {
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

fn assert_fixture_cases_are_subset(path: &Path, actual: &Value, field: &str) {
    let expected: Value = serde_json::from_str(
        &fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display())),
    )
    .test_unwrap("parse checked-in fixture");
    let expected_cases = expected[field]
        .as_array()
        .unwrap_or_else(|| panic!("fixture {} has no {field} array", path.display()));
    for generated_case in actual[field]
        .as_array()
        .unwrap_or_else(|| panic!("generated fixture has no {field} array"))
    {
        let id = generated_case["id"]
            .as_str()
            .test_unwrap("generated case id");
        let checked_in_case = expected_cases
            .iter()
            .find(|candidate| candidate["id"] == id)
            .unwrap_or_else(|| panic!("fixture {} has no case {id}", path.display()));
        assert_eq!(checked_in_case, generated_case, "fixture case {field}/{id}");
    }
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

fn signing_utf8_case_value(
    id: &str,
    description: &str,
    input_utf8: &str,
    public_key_hex: &str,
    signature_hex: &str,
    expected_verify: bool,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "input_utf8": input_utf8,
        "public_key_hex": public_key_hex,
        "signature_hex": signature_hex,
        "expected_verify": expected_verify,
    })
}

fn signing_json_case_value(
    id: &str,
    description: &str,
    input_json: &str,
    canonical_json: &str,
    public_key_hex: &str,
    signature_hex: &str,
    expected_verify: bool,
) -> Value {
    json!({
        "id": id,
        "description": description,
        "input_json": input_json,
        "canonical_json": canonical_json,
        "public_key_hex": public_key_hex,
        "signature_hex": signature_hex,
        "expected_verify": expected_verify,
    })
}

fn signing_vector_fixture() -> Value {
    let seed_hex = "09".repeat(32);
    let signed_utf8 =
        sign_utf8_message_ed25519("hello chio", &seed_hex).test_unwrap("sign utf8 message");
    let signed_json =
        sign_json_str_ed25519("{\"z\":1,\"a\":2}", &seed_hex).test_unwrap("sign json string");

    json!({
        "version": 1,
        "generated_by": "chio-binding-helpers",
        "signing_key_seed_hex": seed_hex,
        "utf8_cases": [
            signing_utf8_case_value(
                "valid_utf8_message",
                "A UTF-8 message signs and verifies with a deterministic Ed25519 seed.",
                "hello chio",
                &signed_utf8.public_key_hex,
                &signed_utf8.signature_hex,
                true,
            ),
            signing_utf8_case_value(
                "tampered_utf8_message",
                "The same signature fails if the UTF-8 message bytes change.",
                "hello chio!",
                &signed_utf8.public_key_hex,
                &signed_utf8.signature_hex,
                false,
            ),
        ],
        "json_cases": [
            signing_json_case_value(
                "valid_canonical_json_message",
                "Signing raw JSON first canonicalizes it, then signs the canonical bytes.",
                "{\"z\":1,\"a\":2}",
                &signed_json.canonical_json,
                &signed_json.public_key_hex,
                &signed_json.signature_hex,
                true,
            ),
            signing_json_case_value(
                "tampered_canonical_json_message",
                "Verification fails if the JSON payload changes after signing.",
                "{\"z\":2,\"a\":2}",
                &canonicalize_json_str("{\"z\":2,\"a\":2}").test_unwrap("canonicalize tampered json"),
                &signed_json.public_key_hex,
                &signed_json.signature_hex,
                false,
            ),
        ],
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
    let (signature, _bytes) = signer
        .sign_canonical(&manifest)
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

#[test]
fn manifest_vector_fixture_matches_checked_in_json() {
    assert_fixture_matches(&manifest_v2_fixture_path(), &manifest_vector_fixture());
}

#[test]
fn generated_vector_fixture_subsets_match_checked_in_corpora() {
    assert_fixture_cases_are_subset(
        &canonical_fixture_path(),
        &canonical_vector_fixture(),
        "cases",
    );
    assert_fixture_cases_are_subset(&hashing_fixture_path(), &hashing_vector_fixture(), "cases");
    let signing = signing_vector_fixture();
    assert_fixture_cases_are_subset(&signing_fixture_path(), &signing, "utf8_cases");
    assert_fixture_cases_are_subset(&signing_fixture_path(), &signing, "json_cases");
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

    for case in fixture["utf8_cases"]
        .as_array()
        .test_unwrap("utf8_cases array")
    {
        let input = case["input_utf8"].as_str().test_unwrap("input_utf8");
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

        if expected_verify {
            let signed = sign_utf8_message_ed25519(input, seed_hex).test_unwrap("sign utf8 case");
            assert_eq!(
                signed.public_key_hex, public_key_hex,
                "utf8 sign {}",
                case["id"]
            );
            assert_eq!(
                signed.signature_hex, signature_hex,
                "utf8 sign {}",
                case["id"]
            );
        }

        let actual = verify_utf8_message_ed25519(input, public_key_hex, signature_hex)
            .test_unwrap("verify utf8 case");
        assert_eq!(actual, expected_verify, "utf8 verify {}", case["id"]);
    }

    for case in fixture["json_cases"]
        .as_array()
        .test_unwrap("json_cases array")
    {
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
            let signed = sign_json_str_ed25519(input, seed_hex).test_unwrap("sign json case");
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

        let actual = verify_json_str_signature_ed25519(input, public_key_hex, signature_hex)
            .test_unwrap("verify json case");
        assert_eq!(actual, expected_verify, "json verify {}", case["id"]);
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
fn manifest_fixture_cases_round_trip_through_public_api() {
    // Read the on-disk corpus as ground truth.
    let raw =
        std::fs::read_to_string(manifest_v2_fixture_path()).test_unwrap("read manifest fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse manifest fixture");
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        let signed_manifest: SignedManifest =
            serde_json::from_value(case["signed_manifest"].clone())
                .test_unwrap("parse signed manifest case");
        let expected: ManifestVerification = serde_json::from_value(case["expected"].clone())
            .test_unwrap("parse manifest expectation");
        let actual =
            verify_signed_manifest(&signed_manifest).test_unwrap("verify signed manifest case");
        assert_eq!(actual, expected, "manifest case {}", case["id"]);
    }
}

#[test]
fn legacy_manifest_fixture_is_kept_separate_from_v2() {
    let raw = fs::read_to_string(manifest_v1_fixture_path()).test_unwrap("read v1 fixture");
    let fixture: Value = serde_json::from_str(&raw).test_unwrap("parse v1 fixture");
    let mut saw_v1 = false;
    for case in fixture["cases"].as_array().test_unwrap("cases array") {
        let schema = case["signed_manifest"]["manifest"]["schema"]
            .as_str()
            .test_unwrap("manifest schema");
        assert_ne!(schema, "chio.manifest.v2");
        saw_v1 |= schema == "chio.manifest.v1";
    }
    assert!(
        saw_v1,
        "v1 corpus must retain at least one valid v1 manifest"
    );
}
