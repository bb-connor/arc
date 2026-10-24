use crate::{validate_json_artifact_schema, ProofRoomError, PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA};

fn receipt_evidence() -> serde_json::Value {
    serde_json::json!({
        "schema": PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA,
        "receipt_id": "fixture-receipt",
        "terminal_status": "allowed_executed",
        "policy_digest": "a".repeat(64),
        "request_digest": "b".repeat(64),
        "response_digest": "c".repeat(64),
        "kernel_key": "d".repeat(64),
        "signature": "e".repeat(128),
        "capability_id": "fixture-capability",
        "guard_decision_id": "fixture-guard",
    })
}

fn check(value: &serde_json::Value) -> Result<(), ProofRoomError> {
    validate_json_artifact_schema(
        &serde_json::to_vec(value).map_err(|error| ProofRoomError::from(error.to_string()))?,
        PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA,
        "receipt evidence",
    )
}

fn assert_evidence_refusal(value: &serde_json::Value, detail: &str) {
    let Err(ProofRoomError::Validation(message)) = check(value) else {
        panic!("expected receipt evidence schema refusal");
    };
    assert_eq!(
        message,
        format!("proof-room.schema-violation: receipt evidence: {detail}")
    );
}

#[test]
fn terminal_evidence_preserves_capability_and_guard_bindings() -> Result<(), ProofRoomError> {
    check(&receipt_evidence())
}

#[test]
fn terminal_evidence_refuses_undeclared_members() {
    let mut value = receipt_evidence();
    value["extra"] = serde_json::json!(true);
    assert_evidence_refusal(
        &value,
        "Additional properties are not allowed ('extra' was unexpected)",
    );
}

#[test]
fn terminal_evidence_requires_request_digest() {
    let mut value = receipt_evidence();
    value["request_digest"] = serde_json::Value::Null;
    assert_evidence_refusal(&value, r#"null is not of type "string""#);
}

#[test]
fn terminal_evidence_refuses_non_string_guard_binding() {
    let mut value = receipt_evidence();
    value["guard_decision_id"] = serde_json::json!(7);
    assert_evidence_refusal(&value, r#"7 is not of type "string""#);
}
