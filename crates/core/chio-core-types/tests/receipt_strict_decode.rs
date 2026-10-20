//! Every signed record in the receipt and child-receipt trees refuses a member
//! it would not sign, so a padded receipt cannot decode and still verify.

use chio_core_types::crypto::sha256_hex;
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::kinds::{
    BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core_types::receipt::lineage::{ChildRequestReceipt, ChildRequestReceiptBody};
use chio_core_types::receipt::metadata::{ActorRef, GuardEvidence};
use chio_core_types::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use chio_core_types::Keypair;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn signed_receipt(decision: Decision) -> TestResult<Value> {
    let kernel = Keypair::from_seed(&[5; 32]);
    let body = ChioReceiptBody {
        id: "rcpt-strict".to_string(),
        timestamp: 1_710_000_000,
        capability_id: "cap-strict".to_string(),
        tool_server: "srv".to_string(),
        tool_name: "read".to_string(),
        action: ToolCallAction::from_parameters(json!({"path": "/workspace/a"}))?,
        decision: Some(decision),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: vec![ActorRef {
            actor_id: "agent-1".to_string(),
            actor_kind: Some("agent".to_string()),
        }],
        content_hash: sha256_hex(br#"{"ok":true}"#),
        policy_hash: "deadbeefdeadbeef".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "ForbiddenPathGuard".to_string(),
            verdict: true,
            details: None,
        }],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: kernel.public_key(),
        bbs_projection_version: None,
    };
    Ok(serde_json::to_value(ChioReceipt::sign(body, &kernel)?)?)
}

fn signed_child_receipt(terminal_state: OperationTerminalState) -> TestResult<Value> {
    let kernel = Keypair::from_seed(&[6; 32]);
    let body = ChildRequestReceiptBody {
        id: "child-strict".to_string(),
        timestamp: 1_710_000_001,
        session_id: SessionId::new("sess-strict"),
        parent_request_id: RequestId::new("parent-strict"),
        request_id: RequestId::new("child-req-strict"),
        operation_kind: OperationKind::CreateMessage,
        terminal_state,
        outcome_hash: sha256_hex(br#"{"message":"sampled"}"#),
        policy_hash: "aabbccddaabbccdd".to_string(),
        metadata: None,
        kernel_key: kernel.public_key(),
    };
    Ok(serde_json::to_value(ChildRequestReceipt::sign(
        body, &kernel,
    )?)?)
}

fn refusal<T: DeserializeOwned>(value: Value) -> Option<String> {
    serde_json::from_value::<T>(value)
        .err()
        .map(|error| error.to_string())
}

fn pad(value: &Value, path: &str, record: &str) -> TestResult<Value> {
    let mut padded = value.clone();
    padded
        .pointer_mut(path)
        .and_then(Value::as_object_mut)
        .ok_or(record.to_string())?
        .insert("pad".to_string(), json!(0));
    Ok(padded)
}

#[test]
fn the_signed_receipts_decode_and_verify() -> TestResult {
    let receipt: ChioReceipt = serde_json::from_value(signed_receipt(Decision::Allow)?)?;
    assert!(receipt.verify_signature()?);
    let child: ChildRequestReceipt =
        serde_json::from_value(signed_child_receipt(OperationTerminalState::Completed)?)?;
    assert!(child.verify_signature()?);
    Ok(())
}

#[test]
fn every_receipt_record_refuses_an_unknown_member() -> TestResult {
    let receipt = signed_receipt(Decision::Deny {
        reason: "blocked".to_string(),
        guard: "ForbiddenPathGuard".to_string(),
    })?;
    for (record, path) in [
        ("ChioReceipt", ""),
        ("ToolCallAction", "/action"),
        ("Decision", "/decision"),
        ("ActorRef", "/actor_chain/0"),
        ("GuardEvidence", "/evidence/0"),
    ] {
        let error = refusal::<ChioReceipt>(pad(&receipt, path, record)?).ok_or(record)?;
        assert!(
            error.starts_with("unknown field `pad`, expected"),
            "{record}: {error}"
        );
    }
    Ok(())
}

#[test]
fn a_unit_decision_refuses_an_unknown_member() -> TestResult {
    let receipt = signed_receipt(Decision::Allow)?;
    assert_eq!(
        refusal::<ChioReceipt>(pad(&receipt, "/decision", "Decision")?).as_deref(),
        Some(chio_security_types::strict_serde::DROPPED_INPUT)
    );
    Ok(())
}

#[test]
fn a_receipt_body_refuses_an_unknown_member() -> TestResult {
    let mut body = signed_receipt(Decision::Allow)?;
    let members = body.as_object_mut().ok_or("receipt object")?;
    members.remove("signature");
    members.insert("pad".to_string(), json!(0));
    let error = refusal::<ChioReceiptBody>(body).ok_or("padded body decoded")?;
    assert!(
        error.starts_with("unknown field `pad`, expected"),
        "{error}"
    );
    Ok(())
}

#[test]
fn a_receipt_refuses_an_unsigned_schema_member() -> TestResult {
    let mut receipt = signed_receipt(Decision::Allow)?;
    receipt["schema"] = json!("chio.receipt.v1");
    let error = refusal::<ChioReceipt>(receipt).ok_or("schema member decoded")?;
    assert!(
        error.starts_with("unknown field `schema`, expected"),
        "{error}"
    );
    Ok(())
}

#[test]
fn every_child_receipt_record_refuses_an_unknown_member() -> TestResult {
    let child = signed_child_receipt(OperationTerminalState::Cancelled {
        reason: "caller cancelled".to_string(),
    })?;
    for (record, path) in [
        ("ChildRequestReceipt", ""),
        ("OperationTerminalState", "/terminal_state"),
    ] {
        let error = refusal::<ChildRequestReceipt>(pad(&child, path, record)?).ok_or(record)?;
        assert!(
            error.starts_with("unknown field `pad`, expected"),
            "{record}: {error}"
        );
    }

    let mut body = child;
    let members = body.as_object_mut().ok_or("child object")?;
    members.remove("signature");
    members.insert("pad".to_string(), json!(0));
    let error = refusal::<ChildRequestReceiptBody>(body).ok_or("padded child body decoded")?;
    assert!(
        error.starts_with("unknown field `pad`, expected"),
        "{error}"
    );
    Ok(())
}

#[test]
fn a_unit_terminal_state_refuses_an_unknown_member() -> TestResult {
    let child = signed_child_receipt(OperationTerminalState::Completed)?;
    assert_eq!(
        refusal::<ChildRequestReceipt>(pad(&child, "/terminal_state", "OperationTerminalState")?)
            .as_deref(),
        Some(chio_security_types::strict_serde::DROPPED_INPUT)
    );
    Ok(())
}

#[test]
fn the_direct_decoders_refuse_a_padded_unit_variant() {
    let decision = <Decision>::deserialize(json!({"verdict": "allow", "pad": 0}))
        .err()
        .map(|error| error.to_string());
    assert_eq!(
        decision.as_deref(),
        Some(chio_security_types::strict_serde::DROPPED_INPUT)
    );
    let state = <OperationTerminalState>::deserialize(json!({"state": "completed", "pad": 0}))
        .err()
        .map(|error| error.to_string());
    assert_eq!(
        state.as_deref(),
        Some(chio_security_types::strict_serde::DROPPED_INPUT)
    );
}
