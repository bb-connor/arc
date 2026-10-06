//! Nonterminal v1 custody through actual SQLite-backed approval admission.

use super::*;
use chio_core::capability::governance::ThresholdApprovalProposal;

fn call(consumer: &mut Consumer, request: &ToolCallRequest, wire: Value) -> TestResult<Value> {
    let Frontend::A2a(kernel, edge) = &mut consumer.frontend else {
        return Err("expected the A2A consumer fixture".into());
    };
    let execution = chio_a2a_edge::A2aKernelExecutionContext {
        capability: request.capability.clone(),
        agent_id: request.agent_id.clone(),
        dpop_proof: request.dpop_proof.clone(),
        execution_nonce: request.execution_nonce.clone(),
        governed_intent: request.governed_intent.clone(),
        approval_token: request.approval_token.clone(),
        approval_tokens: request.approval_tokens.clone(),
        threshold_approval_proposal: request.threshold_approval_proposal.clone(),
        supplemental_authorization: request.supplemental_authorization.clone(),
        model_metadata: request.model_metadata.clone(),
    };
    Ok(edge
        .handle_jsonrpc(&serde_json::to_vec(&wire)?, kernel, &execution)?
        .into_value()
        .ok_or("missing A2A wire response")?)
}

fn send(request: &ToolCallRequest, mode: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": "send", "method": "SendMessage",
        "params": {
            "message": {
                "messageId": request.request_id, "role": "ROLE_USER",
                "parts": [{"data": request.arguments}]
            },
            "metadata": {"chio": {"targetSkillId": TOOL}},
            "configuration": {"returnImmediately": false, "acceptedOutputModes": [mode]}
        }
    })
}

fn lookup(method: &str, id: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": method, "method": method, "params": {"id": id}})
}

#[test]
fn pending_approval_remains_observable_without_dispatch_or_new_receipts() -> TestResult {
    let fixture = Fixture::new()?.with_threshold_approval()?;
    let request = fixture.approval_request("v1-pending-observation")?;
    let mut consumer = fixture.open(Protocol::A2a)?;
    let response = call(&mut consumer, &request, send(&request, "application/json"))?;
    let task = &response["result"]["task"];
    assert_eq!(task["status"]["state"], "TASK_STATE_WORKING", "{response}");
    assert_eq!(task["metadata"]["chio"]["decision"], "pending_approval");
    let receipt: ChioReceipt = serde_json::from_value(task["metadata"]["chio"]["receipt"].clone())?;
    assert!(receipt.verify_signature()?);
    assert_eq!(receipt.kernel_key, fixture.signer.public_key());
    let proposal: ThresholdApprovalProposal =
        serde_json::from_value(task["artifacts"][0]["parts"][0]["data"]["proposal"].clone())?;
    assert!(proposal.verify_signature()?);
    assert_eq!(proposal.body.policy_authority, fixture.signer.public_key());
    assert_eq!(proposal.body.request_id, request.request_id);
    assert_eq!(proposal.body.threshold, 2);
    let id = task["id"].as_str().ok_or("pending task id")?;
    for _ in 0..3 {
        let observed = call(&mut consumer, &request, lookup("GetTask", id))?;
        assert_eq!(observed["result"], *task, "{observed}");
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    }
    let Frontend::A2a(kernel, _) = &consumer.frontend else {
        return Err("expected the A2A consumer fixture".into());
    };
    assert_eq!(kernel.receipt_log().receipts().len(), 1);
    Ok(())
}

#[test]
fn pending_approval_preserves_caller_isolation_and_text_mode_through_cancel() -> TestResult {
    let fixture = Fixture::new()?.with_threshold_approval()?;
    let request = fixture.approval_request("v1-pending-cancel")?;
    let mut consumer = fixture.open(Protocol::A2a)?;
    let response = call(&mut consumer, &request, send(&request, "text/plain"))?;
    let task = &response["result"]["task"];
    assert_eq!(task["status"]["state"], "TASK_STATE_WORKING", "{response}");
    let text = task["artifacts"][0]["parts"][0]["text"]
        .as_str()
        .ok_or("text output mode")?;
    let output: Value = serde_json::from_str(text)?;
    assert_eq!(output["status"], "pending_approval");
    let id = task["id"].as_str().ok_or("pending task id")?;
    let mut renamed = request.clone();
    renamed.agent_id = "renamed-agent".into();
    let mut different_subject = request.clone();
    let mut body = request.capability.body();
    body.subject = Keypair::generate().public_key();
    different_subject.capability = CapabilityToken::sign(body, &fixture.signer)?;
    for inaccessible in [renamed, different_subject] {
        for method in ["GetTask", "CancelTask"] {
            let refused = call(&mut consumer, &inaccessible, lookup(method, id))?;
            assert_eq!(refused["error"]["code"], -32001, "{refused}");
        }
    }
    let observed = call(&mut consumer, &request, lookup("GetTask", id))?;
    assert_eq!(observed["result"], *task, "{observed}");
    let cancelled = call(&mut consumer, &request, lookup("CancelTask", id))?;
    assert_eq!(cancelled["result"]["id"], id);
    assert_eq!(
        cancelled["result"]["status"]["state"],
        "TASK_STATE_CANCELED"
    );
    for method in ["GetTask", "CancelTask"] {
        let terminal = call(&mut consumer, &request, lookup(method, id))?;
        assert_eq!(terminal["result"], cancelled["result"], "{terminal}");
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    let Frontend::A2a(kernel, _) = &consumer.frontend else {
        return Err("expected the A2A consumer fixture".into());
    };
    assert_eq!(kernel.receipt_log().receipts().len(), 1);
    Ok(())
}
