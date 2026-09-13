use super::*;

fn pending_result() -> Value {
    let corpus: Value = serde_json::from_str(
        &fs::read_to_string(
            repo_root().join("tests/bindings/fixtures/protocol-primitives-v1.json"),
        )
        .unwrap(),
    )
    .unwrap();
    corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "pending-approval-result")
        .unwrap()["instance"]
        .clone()
}

#[test]
fn pending_approval_result_preserves_the_proposal_on_round_trip() {
    let instance = pending_result();
    assert_schema_accepts("result/pending_approval.schema.json", &instance);
    let parsed: ToolCallResult = serde_json::from_value(instance.clone()).unwrap();
    assert!(matches!(parsed, ToolCallResult::PendingApproval { .. }));
    assert_eq!(to_json(&parsed), instance);
}

#[test]
fn pending_approval_result_rejects_missing_unknown_and_malformed_fields() {
    let valid = pending_result();
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("proposal");
    let mut unknown = valid.clone();
    unknown["execution_allowed"] = json!(true);
    let mut wrong_status = valid.clone();
    wrong_status["status"] = json!("ok");
    let mut malformed = valid.clone();
    malformed["proposal"]["authorizing_capability_digest"] = json!(17);
    let mut rewritten = valid.clone();
    rewritten["proposal"]["unsigned_extension"] = json!(true);
    for instance in [missing, unknown, wrong_status, malformed, rewritten] {
        assert_schema_rejects("result/pending_approval.schema.json", &instance);
        assert!(serde_json::from_value::<ToolCallResult>(instance).is_err());
    }
}

#[test]
fn pending_approval_frame_rejects_execution_nonce() {
    let key = Keypair::generate();
    let mut frame = json!({
        "type": "tool_call_response", "id": "request-1",
        "result": pending_result(), "receipt": make_receipt(&key, Decision::Deny {
            guard: "kernel".into(), reason: "cumulative approval required".into(),
        }),
    });
    assert_schema_accepts("kernel/tool_call_response.schema.json", &frame);
    frame["execution_nonce"] = to_json(&make_execution_nonce(&key));
    assert_schema_rejects("kernel/tool_call_response.schema.json", &frame);
}
