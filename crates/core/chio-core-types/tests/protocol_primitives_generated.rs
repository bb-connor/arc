#![allow(
    clippy::clone_on_copy,
    clippy::derivable_impls,
    clippy::enum_variant_names,
    clippy::expect_used,
    clippy::large_enum_variant,
    clippy::unwrap_used
)]

use std::{fs, path::PathBuf};

use chio_core_types::canonical::UntrustedJsonText;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};

#[allow(dead_code)]
#[path = "../src/_generated/chio_wire_v1.rs"]
mod generated;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

const ACTIVE_RESPONSE_SCHEMA: &str = "agent/active-response-governed-intent.schema.json";

/// Raw fixtures whose duplicate key sits inside a `serde_json::Value` member
/// (`action.parameters`, `metadata`). Plain typed serde keeps the last value
/// there, so only the signed-wire decoder rejects them.
const TYPED_SERDE_LAST_WINS: &[&str] = &["receipt-duplicate-parameter"];

/// Decoder input. `Value` has already collapsed duplicate keys last-wins; the
/// text variants hand the original bytes to typed serde or to the signed-wire
/// decoder, which rejects duplicate keys at every depth.
#[derive(Clone, Copy)]
enum Wire<'a> {
    Value(&'a Value),
    Text(&'a str),
    SignedText(&'a str),
}

fn round_trip<T>(instance: Wire<'_>) -> Result<Value, String>
where
    T: DeserializeOwned + Serialize,
{
    let parsed: T = match instance {
        Wire::Value(value) => {
            serde_json::from_value(value.clone()).map_err(|error| error.to_string())?
        }
        Wire::Text(text) => serde_json::from_str(text).map_err(|error| error.to_string())?,
        Wire::SignedText(text) => UntrustedJsonText::new(text)
            .decode_signed()
            .map_err(|error| error.code().to_string())?,
    };
    serde_json::to_value(parsed).map_err(|error| error.to_string())
}

fn generated_instance(schema_file: &str, instance: Value) -> Value {
    if schema_file == ACTIVE_RESPONSE_SCHEMA {
        json!({
            "id": "intent-1",
            "server_id": "chio.control-plane.active-response",
            "tool_name": "execute_response_plan",
            "purpose": "containment",
            "body": { "kind": "active_response_plan", "value": instance }
        })
    } else {
        instance
    }
}

fn parse_generated(schema_file: &str, instance: Wire<'_>) -> Result<Value, String> {
    match schema_file {
        "receipt/record.schema.json" => {
            round_trip::<generated::kernel_tool_call_response::ChioReceiptRecord>(instance)
        }
        "kernel/caller_dispatch_authorization.schema.json" => round_trip::<
            generated::kernel_caller_dispatch_authorization::ChioSignedCallerDispatchAuthorization,
        >(instance),
        "kernel/caller_delivery_report.schema.json" => round_trip::<
            generated::kernel_caller_delivery_report::ChioSignedCallerDeliveryReport,
        >(instance),
        "result/pending_approval.schema.json" => round_trip::<
            generated::kernel_tool_call_response::ChioKernelMessageToolCallResponseResult,
        >(instance),
        "kernel/execution_nonce.schema.json" => {
            round_trip::<generated::agent_tool_call_request::ChioSignedExecutionNonce>(instance)
        }
        "capability/token.schema.json" => {
            round_trip::<generated::agent_tool_call_request::ChioCapabilityToken>(instance)
        }
        "capability/aggregate-invocation-budget.schema.json" => round_trip::<
            generated::agent_tool_call_request::ChioAggregateInvocationBudget,
        >(instance),
        "capability/threshold-approval-proposal.schema.json" => round_trip::<
            generated::agent_tool_call_request::ChioThresholdApprovalProposal,
        >(instance),
        "capability/governed-approval-token.schema.json" => {
            round_trip::<generated::agent_tool_call_request::ChioGovernedApprovalToken>(instance)
        }
        "agent/active-response-governed-intent.schema.json" => round_trip::<
            generated::agent_tool_call_request::ChioGovernedTransactionIntent,
        >(instance),
        "kernel/combined-capture-metadata.schema.json" => round_trip::<
            generated::kernel_combined_capture_metadata::ChioCombinedAdmissionCaptureMetadata,
        >(instance),
        "capability/supplemental-authorization.schema.json" => round_trip::<
            generated::agent_tool_call_request::ChioOpaqueSupplementalAuthorization,
        >(instance),
        other => panic!("unmapped protocol-primitives fixture schema: {other}"),
    }
}

#[test]
fn generated_rust_shapes_parse_reject_and_round_trip_shared_fixtures() {
    let corpus: Value = serde_json::from_str(
        &fs::read_to_string(
            repo_root().join("tests/bindings/fixtures/protocol-primitives-v1.json"),
        )
        .expect("protocol-primitives fixture corpus exists"),
    )
    .expect("protocol-primitives fixture corpus parses");

    for case in corpus["cases"]
        .as_array()
        .expect("fixture cases are an array")
    {
        let schema_file = case["schema_file"]
            .as_str()
            .expect("fixture schema_file is a string");
        let instance = generated_instance(schema_file, case["instance"].clone());
        let result = parse_generated(schema_file, Wire::Value(&instance));
        let valid = case["valid"].as_bool().expect("fixture valid is a boolean");
        assert_eq!(
            result.is_ok(),
            valid,
            "generated Rust fixture result mismatch for {}",
            case["name"].as_str().expect("fixture name is a string")
        );
        if valid {
            assert_eq!(
                chio_core_types::canonical_json_bytes(&result.expect("valid fixture parsed"))
                    .expect("round trip canonicalizes"),
                chio_core_types::canonical_json_bytes(&instance).expect("fixture canonicalizes"),
                "generated Rust round trip changed canonical bytes for {}",
                case["name"].as_str().expect("fixture name is a string")
            );
        }
    }

    let raw_cases = corpus["raw_cases"]
        .as_array()
        .expect("raw fixture cases are an array");
    assert!(!raw_cases.is_empty(), "raw fixture cases exist");
    for case in raw_cases {
        let name = case["name"].as_str().expect("raw fixture name is a string");
        let schema_file = case["schema_file"]
            .as_str()
            .expect("raw fixture schema_file is a string");
        let text = case["instance_text"]
            .as_str()
            .expect("raw fixture instance_text is a string");
        assert_eq!(
            case["valid"],
            json!(false),
            "raw fixture {name} must reject"
        );
        assert_ne!(
            schema_file, ACTIVE_RESPONSE_SCHEMA,
            "raw fixture {name} cannot be wrapped as a generated intent"
        );
        let collapsed: Value = serde_json::from_str(text).expect("raw fixture text is JSON");
        assert!(
            parse_generated(schema_file, Wire::Value(&collapsed)).is_ok(),
            "raw fixture {name} must be valid once duplicate keys collapse last-wins"
        );
        assert!(
            parse_generated(schema_file, Wire::SignedText(text)).is_err(),
            "signed-wire decoder accepted duplicate keys in raw fixture {name}"
        );
        match (
            parse_generated(schema_file, Wire::Text(text)),
            TYPED_SERDE_LAST_WINS.contains(&name),
        ) {
            (Err(_), false) | (Ok(_), true) => {}
            (Ok(_), false) => panic!("typed serde accepted duplicate keys in raw fixture {name}"),
            (Err(error), true) => panic!(
                "typed serde now rejects raw fixture {name} ({error}); remove it from TYPED_SERDE_LAST_WINS"
            ),
        }
    }
}

mod receipt_fixture {
    use chio_core_types::canonical::CanonicalBytes;
    use chio_core_types::crypto::{sha256_hex, Keypair};
    use chio_core_types::receipt::body::{chio_receipt_id, ChioReceipt, ChioReceiptBody};
    use chio_core_types::receipt::decision::{Decision, ToolCallAction};
    use chio_core_types::receipt::kinds::{
        BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    };
    use chio_core_types::receipt::metadata::GuardEvidence;
    use chio_core_types::receipt::signing::ChioReceiptSigningBody;
    use serde::Serialize;
    use serde_json::{json, Value};

    const RECEIPT_SCHEMA_FILE: &str = "receipt/record.schema.json";
    const FIRST_UNSIGNED_CASE: &str = "    {\n      \"name\": \"caller-dispatch-authorization\"";
    const RAW_CASES_OPEN: &str = "\n  ],\n  \"raw_cases\": [\n";

    #[derive(Serialize)]
    struct Case {
        name: &'static str,
        schema_file: &'static str,
        valid: bool,
        instance: Value,
    }

    #[derive(Serialize)]
    struct RawCase {
        name: &'static str,
        schema_file: &'static str,
        valid: bool,
        instance_text: String,
    }

    fn reference_receipt() -> Value {
        let kernel = Keypair::from_seed(&[7u8; 32]);
        let mut body = ChioReceiptBody {
            id: String::new(),
            timestamp: 1710000200,
            capability_id: "cap-bindings-001".to_string(),
            tool_server: "srv-files".to_string(),
            tool_name: "file_read".to_string(),
            action: ToolCallAction::from_parameters(json!({
                "path": "/workspace/docs/roadmap.md",
                "mode": "read"
            }))
            .unwrap(),
            decision: Some(Decision::Allow),
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
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        };
        body.id = chio_receipt_id(&body).unwrap();
        let signature = kernel
            .sign_wrapped(
                chio_core_types::receipt::body::CHIO_RECEIPT_SCHEMA,
                &CanonicalBytes::from_serializable(&ChioReceiptSigningBody::from(&body)).unwrap(),
            )
            .unwrap();
        let mut receipt = serde_json::to_value(&body).unwrap();
        receipt["signature"] = serde_json::to_value(&signature).unwrap();
        receipt
    }

    fn with_origin(origin: Value) -> Value {
        let mut receipt = reference_receipt();
        receipt["tool_origin"] = origin;
        receipt
    }

    fn indented(value: &impl Serialize) -> String {
        let rendered = serde_json::to_string_pretty(value).unwrap();
        format!("    {}", rendered.replace('\n', "\n    "))
    }

    fn receipt_cases() -> Vec<Case> {
        let mut unknown_field = with_origin(json!("chio_internal"));
        unknown_field["unsigned_extension"] = json!(true);
        vec![
            Case {
                name: "receipt-internal-origin",
                schema_file: RECEIPT_SCHEMA_FILE,
                valid: true,
                instance: with_origin(json!("chio_internal")),
            },
            Case {
                name: "receipt-unknown-origin",
                schema_file: RECEIPT_SCHEMA_FILE,
                valid: false,
                instance: with_origin(json!("untrusted_future_origin")),
            },
            Case {
                name: "receipt-null-origin",
                schema_file: RECEIPT_SCHEMA_FILE,
                valid: false,
                instance: with_origin(Value::Null),
            },
            Case {
                name: "receipt-unknown-field",
                schema_file: RECEIPT_SCHEMA_FILE,
                valid: false,
                instance: unknown_field,
            },
        ]
    }

    fn raw_receipt_cases() -> Vec<RawCase> {
        let text = serde_json::to_string(&with_origin(json!("chio_internal"))).unwrap();
        let duplicate_id = format!(
            "{{\"id\":\"{}\",{}",
            "0".repeat(64),
            text.strip_prefix('{').unwrap()
        );
        let honest_parameters =
            r#""parameters":{"mode":"read","path":"/workspace/docs/roadmap.md"}"#;
        assert!(text.contains(honest_parameters));
        let duplicate_parameter = text.replace(
            honest_parameters,
            r#""parameters":{"path":"/etc/shadow","mode":"read","path":"/workspace/docs/roadmap.md"}"#,
        );
        vec![
            RawCase {
                name: "receipt-duplicate-id",
                schema_file: RECEIPT_SCHEMA_FILE,
                valid: false,
                instance_text: duplicate_id,
            },
            RawCase {
                name: "receipt-duplicate-parameter",
                schema_file: RECEIPT_SCHEMA_FILE,
                valid: false,
                instance_text: duplicate_parameter,
            },
        ]
    }

    /// Rebuilds the corpus text. Only the receipt cases carry Chio-produced
    /// signatures; every other case holds fixed placeholder signature bytes and
    /// is carried over unchanged from `committed`.
    pub fn render(committed: &str) -> String {
        let start = committed
            .find(FIRST_UNSIGNED_CASE)
            .expect("corpus lists the caller dispatch authorization case");
        let end = committed
            .find(RAW_CASES_OPEN)
            .expect("corpus lists the raw cases");
        let receipts: Vec<String> = receipt_cases().iter().map(indented).collect();
        let raws: Vec<String> = raw_receipt_cases().iter().map(indented).collect();
        format!(
            "{{\n  \"cases\": [\n{},\n{}{}{}\n  ]\n}}\n",
            receipts.join(",\n"),
            &committed[start..end],
            RAW_CASES_OPEN,
            raws.join(",\n"),
        )
    }

    pub fn reference_receipt_verifies() -> bool {
        let mut receipt = reference_receipt();
        receipt["tool_origin"] = json!("caller_executed");
        serde_json::from_value::<ChioReceipt>(receipt)
            .unwrap()
            .verify_signature()
            .unwrap()
    }
}

fn corpus_path() -> PathBuf {
    repo_root().join("tests/bindings/fixtures/protocol-primitives-v1.json")
}

#[test]
fn protocol_primitives_receipt_cases_are_current() {
    let path = corpus_path();
    let committed = fs::read_to_string(&path).unwrap();
    assert_eq!(
        committed,
        receipt_fixture::render(&committed),
        "fixture {} is out of date",
        path.display()
    );
    assert!(receipt_fixture::reference_receipt_verifies());
}

#[test]
#[ignore = "regenerator: rewrite the receipt cases of tests/bindings/fixtures/protocol-primitives-v1.json from the receipt builder; run with --ignored"]
fn regenerate_protocol_primitives_receipt_cases() {
    let path = corpus_path();
    let committed = fs::read_to_string(&path).unwrap();
    fs::write(&path, receipt_fixture::render(&committed)).unwrap();
}
