//! Real signature verification with valid receipts paired with altered wire/context fields.

use std::process::{Command, Output};

use chio_core::{
    crypto::{canonical_json_bytes, sha256_hex, Keypair},
    receipt::{
        body::{ChioReceipt, ChioReceiptBody},
        decision::{Decision, ToolCallAction},
    },
};
use serde_json::{json, Value};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    directory: tempfile::TempDir,
    key: Keypair,
    request: Value,
    context: Value,
    body: ChioReceiptBody,
    request_id: String,
}

impl Fixture {
    fn new() -> Result<Self> {
        let key = Keypair::generate();
        let request_id = format!(
            "process:{}",
            sha256_hex(&canonical_json_bytes(&json!([
                "runtime-one",
                "operator",
                "assign-one"
            ]),)?)
        );
        let body = ChioReceiptBody {
            id: "response-test".into(),
            timestamp: 1_710_000_000,
            capability_id: "operator-cap".into(),
            tool_server: "resource".into(),
            tool_name: "assign".into(),
            action: ToolCallAction::from_parameters(json!({"owner": "λ"}))?,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: sha256_hex(&canonical_json_bytes(
                &json!({"owner": "λ", "revision": 1}),
            )?),
            policy_hash: "d".repeat(64),
            evidence: Vec::new(),
            metadata: Some(json!({
                "chio_process": {"runtime_id": "runtime-one", "process_id": "operator",
                    "operation_key": "assign-one", "attempt": 1,
                    "recovery_policy": "known_outcome_only"},
                "receipt_context": {"request_id": request_id},
            })),
            trust_level: Default::default(),
            tenant_id: None,
            kernel_key: key.public_key(),
            bbs_projection_version: None,
        };
        Ok(Self {
            directory: tempfile::tempdir()?,
            key,
            body,
            request_id,
            request: json!({"operation_key": "assign-one", "server_id": "resource",
                "tool_name": "assign", "arguments": {"owner": "λ"}, "known_outcome_only": true}),
            context: json!({"runtime_id": "runtime-one", "process_id": "operator", "capability_id": "operator-cap"}),
        })
    }

    fn response(
        &self,
        verdict: &str,
        output: Value,
        reason: Value,
        terminal: Value,
    ) -> Result<Value> {
        Ok(json!({
            "request_id": self.request_id, "verdict": verdict, "output": output,
            "reason": reason, "terminal_state": terminal, "execution_nonce_json": null,
            "receipt_json": serde_json::to_string(&ChioReceipt::sign(self.body.clone(), &self.key)?)?,
        }))
    }

    fn invoke(&self, response: &Value) -> Result<Output> {
        self.invoke_text(&serde_json::to_string(response)?)
    }

    fn invoke_text(&self, response: &str) -> Result<Output> {
        let root = self.directory.path();
        std::fs::write(
            root.join("request.json"),
            serde_json::to_vec(&self.request)?,
        )?;
        std::fs::write(
            root.join("context.json"),
            serde_json::to_vec(&self.context)?,
        )?;
        std::fs::write(root.join("response.json"), response)?;
        std::fs::write(root.join("kernel.pub"), self.key.public_key().to_hex())?;
        Ok(Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["--json", "receipt", "verify-process-response", "--request"])
            .arg(root.join("request.json"))
            .arg("--context")
            .arg(root.join("context.json"))
            .arg("--response")
            .arg(root.join("response.json"))
            .arg("--trusted-kernel-pubkey")
            .arg(root.join("kernel.pub"))
            .output()?)
    }

    fn accepts(&self, response: &Value) -> Result {
        let output = self.invoke(response)?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(report["response_bound"], true);
        assert_eq!(report["unchecked_fields"], json!(["execution_nonce_json"]));
        Ok(())
    }

    fn rejects(&self, response: &Value) -> Result {
        let output = self.invoke(response)?;
        assert!(
            !output.status.success(),
            "unexpected acceptance: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        Ok(())
    }
}

#[test]
fn null_content_preserves_success_cancellation_and_preflight_output_presence() -> Result {
    let mut fixture = Fixture::new()?;
    fixture.body.content_hash = sha256_hex(b"null");
    let success = fixture.response(
        "allow",
        json!({"kind": "value", "value": null}),
        Value::Null,
        json!({"state": "completed"}),
    )?;
    fixture.accepts(&success)?;
    let mut changed = success;
    changed["output"] = Value::Null;
    fixture.rejects(&changed)?;

    fixture.body.decision = Some(Decision::Cancelled {
        reason: "stopped".into(),
    });
    let cancelled = fixture.response(
        "deny",
        Value::Null,
        json!("stopped"),
        json!({"state": "cancelled", "reason": "stopped"}),
    )?;
    fixture.accepts(&cancelled)?;
    changed = cancelled;
    changed["output"] = json!({"kind": "value", "value": null});
    fixture.rejects(&changed)?;

    fixture.body.decision = Some(Decision::Incomplete {
        reason: "unknown".into(),
    });
    let unknown = fixture.response(
        "deny",
        Value::Null,
        json!("unknown"),
        json!({"state": "incomplete", "reason": "unknown"}),
    )?;
    fixture.accepts(&unknown)?;
    changed = unknown;
    changed["output"] = json!({"kind": "value", "value": null});
    fixture.rejects(&changed)?;

    fixture.body.decision = Some(Decision::Incomplete {
        reason: "preflight".into(),
    });
    fixture.body.metadata.as_mut().ok_or("metadata")?["execution_nonce"] =
        json!({"stage": "preflight", "tool_dispatched": false});
    let preflight = fixture.response(
        "allow",
        Value::Null,
        Value::Null,
        json!({"state": "incomplete", "reason": "preflight"}),
    )?;
    fixture.accepts(&preflight)?;
    changed = preflight;
    changed["output"] = json!({"kind": "value", "value": null});
    fixture.rejects(&changed)?;
    Ok(())
}

#[test]
fn ordinary_json_spelling_is_supported_but_duplicate_keys_and_number_rounding_are_rejected(
) -> Result {
    let fixture = Fixture::new()?;
    let response = fixture.response(
        "allow",
        json!({"kind": "value", "value": {"owner": "λ", "revision": 1}}),
        Value::Null,
        json!({"state": "completed"}),
    )?;
    let text = serde_json::to_string(&response)?;
    for spelling in ["1.0", "1e0", "10e-1"] {
        let input = text.replace("\"revision\":1", &format!("\"revision\":{spelling}"));
        let output = fixture.invoke_text(&input)?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for input in [
        text.replace("\"revision\":1", "\"revision\":1.0000000000000000000001"),
        text.replace("\"revision\":1", "\"revision\":0,\"revision\":1"),
        text.replacen('{', "{\"verdict\":\"deny\",", 1),
        format!("{text}{{}}"),
        " ".repeat(16 * 1024 * 1024 + 1),
    ] {
        let output = fixture.invoke_text(&input)?;
        assert!(
            !output.status.success(),
            "unexpectedly accepted malformed response"
        );
    }
    Ok(())
}

#[test]
fn valid_signature_does_not_authorize_a_substituted_response_or_request() -> Result {
    let mut fixture = Fixture::new()?;
    let response = fixture.response(
        "allow",
        json!({"kind": "value", "value": {"owner": "λ", "revision": 1}}),
        Value::Null,
        json!({"state": "completed"}),
    )?;
    fixture.accepts(&response)?;
    for (field, replacement) in [
        (
            "output",
            json!({"kind": "value", "value": {"forged": true}}),
        ),
        ("output", Value::Null),
        (
            "output",
            json!({"kind": "value", "value": {"owner": "λ", "revision": 1}, "extra": true}),
        ),
        ("verdict", json!("deny")),
        ("verdict", json!("pending_approval")),
        ("request_id", json!("another-operation")),
        ("reason", json!("forged")),
        (
            "terminal_state",
            json!({"state": "incomplete", "reason": "forged"}),
        ),
        ("unsigned_claim", json!(true)),
    ] {
        let mut changed = response.clone();
        changed[field] = replacement;
        fixture.rejects(&changed)?;
    }
    for (field, replacement) in [
        ("operation_key", json!("another-operation")),
        ("server_id", json!("another-server")),
        ("tool_name", json!("another-tool")),
        ("arguments", json!({"owner": "other"})),
        ("known_outcome_only", json!(false)),
    ] {
        let original = fixture.request[field].clone();
        fixture.request[field] = replacement;
        fixture.rejects(&response)?;
        fixture.request[field] = original;
    }
    for field in ["runtime_id", "process_id", "capability_id"] {
        let original = fixture.context[field].clone();
        fixture.context[field] = json!("another-identity");
        fixture.rejects(&response)?;
        fixture.context[field] = original;
    }
    let original = fixture.body.metadata.clone();
    for field in [
        "runtime_id",
        "process_id",
        "operation_key",
        "recovery_policy",
    ] {
        let mut metadata = original.clone().ok_or("missing fixture metadata")?;
        metadata["chio_process"][field] = json!("other");
        fixture.body.metadata = Some(metadata);
        // This substituted receipt has a valid signature from the same pinned key.
        let mut changed = response.clone();
        changed["receipt_json"] = json!(serde_json::to_string(&ChioReceipt::sign(
            fixture.body.clone(),
            &fixture.key
        )?)?);
        fixture.rejects(&changed)?;
    }
    fixture.body.metadata = original;
    let mut changed = response;
    let receipt_text = changed["receipt_json"].as_str().ok_or("missing receipt")?;
    changed["receipt_json"] = json!(receipt_text.replacen('{', "{\"tool_name\":\"duplicate\",", 1));
    fixture.rejects(&changed)?;
    Ok(())
}

#[test]
fn binding_preserves_withheld_denials_partial_streams_and_approval_proposals() -> Result {
    let mut fixture = Fixture::new()?;
    fixture.body.decision = Some(Decision::Deny {
        reason: "withheld".into(),
        guard: "delivery".into(),
    });
    // A digest may commit hidden content or the kernel's domain-separated redaction.
    let denied = fixture.response(
        "deny",
        Value::Null,
        json!("withheld"),
        json!({"state": "completed"}),
    )?;
    fixture.accepts(&denied)?;
    let mut exposed = denied.clone();
    exposed["output"] = json!({"kind": "value", "value": {"owner": "λ", "revision": 1}});
    fixture.rejects(&exposed)?;

    let chunks = json!([{"large": u64::MAX}, {"text": "λ", "float": 1.0}]);
    let mut hashes = Vec::new();
    let mut total_bytes = 0;
    for chunk in chunks.as_array().ok_or("chunks")? {
        let bytes = canonical_json_bytes(chunk)?;
        total_bytes += bytes.len();
        hashes.push(sha256_hex(&bytes));
    }
    fixture.body.content_hash = sha256_hex(hashes.concat().as_bytes());
    fixture.body.metadata.as_mut().ok_or("metadata")?["stream"] = json!({
        "chunks_expected": 3, "chunks_received": 2, "total_bytes": total_bytes, "chunk_hashes": hashes,
    });
    fixture.body.decision = Some(Decision::Incomplete {
        reason: "stream truncated".into(),
    });
    let partial = fixture.response(
        "deny",
        json!({"kind": "stream", "chunks": chunks}),
        json!("stream truncated"),
        json!({"state": "incomplete", "reason": "stream truncated"}),
    )?;
    fixture.accepts(&partial)?;
    let mut changed = partial.clone();
    changed["output"]["chunks"][0] = json!({"large": 1});
    fixture.rejects(&changed)?;
    changed = partial.clone();
    changed["output"]["chunks"] = json!([chunks[1], chunks[0]]);
    fixture.rejects(&changed)?;
    changed = partial;
    changed["verdict"] = json!("allow");
    fixture.rejects(&changed)?;

    fixture.body.content_hash = sha256_hex(b"null");
    fixture
        .body
        .metadata
        .as_mut()
        .ok_or("metadata")?
        .as_object_mut()
        .ok_or("metadata object")?
        .remove("stream");
    for (decision, terminal) in [
        (
            Decision::Cancelled {
                reason: "stopped".into(),
            },
            json!({"state": "cancelled", "reason": "stopped"}),
        ),
        (
            Decision::Incomplete {
                reason: "stopped".into(),
            },
            json!({"state": "incomplete", "reason": "stopped"}),
        ),
    ] {
        fixture.body.decision = Some(decision);
        fixture.accepts(&fixture.response("deny", Value::Null, json!("stopped"), terminal)?)?;
    }

    fixture.body.metadata.as_mut().ok_or("metadata")?["execution_nonce"] =
        json!({"stage": "preflight", "tool_dispatched": false});
    fixture.body.decision = Some(Decision::Incomplete {
        reason: "preflight".into(),
    });
    fixture.accepts(&fixture.response(
        "allow",
        Value::Null,
        Value::Null,
        json!({"state": "incomplete", "reason": "preflight"}),
    )?)?;

    fixture.body.metadata.as_mut().ok_or("metadata")?["threshold_approval"] =
        json!({"state": "approval_required"});
    fixture.body.decision = Some(Decision::Deny {
        reason: "cumulative approval required".into(),
        guard: "kernel".into(),
    });
    fixture.body.content_hash = sha256_hex(&canonical_json_bytes(&json!({"proposal": "one"}))?);
    let pending = fixture.response(
        "pending_approval",
        json!({"kind": "value", "value": {"proposal": "one"}}),
        Value::Null,
        json!({"state": "incomplete", "reason": "approval_required"}),
    )?;
    fixture.accepts(&pending)?;
    let mut changed = pending;
    changed["output"]["value"] = json!({"proposal": "another"});
    fixture.rejects(&changed)?;
    Ok(())
}
