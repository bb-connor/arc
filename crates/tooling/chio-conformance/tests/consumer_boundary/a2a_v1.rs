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
    assert_eq!(
        task["status"]["state"], "TASK_STATE_INPUT_REQUIRED",
        "{response}"
    );
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
    assert_eq!(
        task["status"]["state"], "TASK_STATE_INPUT_REQUIRED",
        "{response}"
    );
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

// Catches loss of the retained task or original authority when signed approval
// arrives after the first v1 SendMessage. Polling must stay observational.
#[test]
fn signed_approval_continuation_completes_the_original_v1_task() -> TestResult {
    let fixture = Fixture::new()?.with_threshold_approval()?;
    let request = fixture.approval_request("v1-approved-continuation")?;
    let mut consumer = fixture.open(Protocol::A2a)?;
    let pending = call(&mut consumer, &request, send(&request, "application/json"))?;
    let task = &pending["result"]["task"];
    assert_eq!(
        task["metadata"]["chio"]["decision"], "pending_approval",
        "{pending}"
    );
    let id = task["id"].as_str().ok_or("pending task id")?;
    let proposal: ThresholdApprovalProposal =
        serde_json::from_value(task["artifacts"][0]["parts"][0]["data"]["proposal"].clone())?;
    assert!(proposal.verify_signature()?);
    assert_eq!(proposal.body.request_id, request.request_id);
    let approved = fixture.approved_request(&request, proposal)?;
    let observed = call(&mut consumer, &approved, lookup("GetTask", id))?;
    assert_eq!(observed["result"], *task);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    let Frontend::A2a(kernel, _) = &consumer.frontend else {
        return Err("expected the A2A consumer fixture".into());
    };
    assert_eq!(kernel.receipt_log().receipts().len(), 1);

    let mut continuation = send(&approved, "application/json");
    continuation["params"]["message"]["taskId"] = json!(id);
    continuation["params"]["message"]["contextId"] = task["contextId"].clone();
    let completed = call(&mut consumer, &approved, continuation)?;
    assert_eq!(
        completed["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED",
        "{completed}"
    );
    assert_eq!(completed["result"]["task"]["id"], id);
    assert_eq!(completed["result"]["task"]["contextId"], task["contextId"]);
    assert_eq!(
        completed["result"]["task"]["metadata"]["chio"]["decision"],
        "allow"
    );
    let receipt: ChioReceipt =
        serde_json::from_value(completed["result"]["task"]["metadata"]["chio"]["receipt"].clone())?;
    assert!(receipt.verify_signature()?);
    assert_eq!(receipt.kernel_key, fixture.signer.public_key());
    assert_eq!(receipt.capability_id, request.capability.id);
    assert_eq!(receipt.tool_name, TOOL);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);

    // Retrying the original stable message after direct terminal delivery must
    // replay durable work, even though the bounded task slot has retired.
    let replay = call(
        &mut consumer,
        &approved,
        send(&approved, "application/json"),
    )?;
    let replay_receipt: ChioReceipt =
        serde_json::from_value(replay["result"]["task"]["metadata"]["chio"]["receipt"].clone())?;
    assert_eq!(
        chio_core::canonical_json_bytes(&receipt)?,
        chio_core::canonical_json_bytes(&replay_receipt)?
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn continuation_refuses_frozen_authority_changes_without_losing_pending_custody() -> TestResult {
    let fixture = Fixture::new()?.with_threshold_approval()?;
    let request = fixture.approval_request("v1-frozen-continuation")?;
    let mut consumer = fixture.open(Protocol::A2a)?;
    let pending = call(&mut consumer, &request, send(&request, "application/json"))?;
    let task = &pending["result"]["task"];
    let id = task["id"].as_str().ok_or("pending task id")?;
    let proposal =
        serde_json::from_value(task["artifacts"][0]["parts"][0]["data"]["proposal"].clone())?;
    let approved = fixture.approved_request(&request, proposal)?;
    let mut wire = send(&approved, "application/json");
    wire["params"]["message"]["taskId"] = json!(id);
    let mut attempts = Vec::new();
    for (pointer, value) in [
        (
            "/params/message/parts/0/data/record",
            json!("another-record"),
        ),
        ("/params/message/messageId", json!("another-work-request")),
        (
            "/params/configuration/acceptedOutputModes",
            json!(["text/plain"]),
        ),
    ] {
        let mut changed = wire.clone();
        *changed.pointer_mut(pointer).ok_or("mutation pointer")? = value;
        attempts.push((approved.clone(), changed));
    }
    let mut context = wire.clone();
    context["params"]["message"]["contextId"] = json!("another-context");
    attempts.push((approved.clone(), context));
    let mut capability = approved.clone();
    let mut body = capability.capability.body();
    body.id = "substituted-capability".into();
    capability.capability = CapabilityToken::sign(body, &fixture.signer)?;
    attempts.push((capability, wire.clone()));
    let mut intent = approved.clone();
    intent
        .governed_intent
        .as_mut()
        .ok_or("governed intent")?
        .purpose = "another-purpose".into();
    attempts.push((intent, wire.clone()));
    let mut metadata = approved.clone();
    metadata.model_metadata = Some(serde_json::from_value(json!({
        "provider": "substituted-provider", "model_id": "substituted-model"
    }))?);
    attempts.push((metadata, wire.clone()));
    for (changed, request_wire) in attempts {
        let refused = call(&mut consumer, &changed, request_wire)?;
        assert_eq!(refused["error"]["code"], -32602, "{refused}");
        let observed = call(&mut consumer, &approved, lookup("GetTask", id))?;
        assert_eq!(observed["result"], *task);
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        let Frontend::A2a(kernel, _) = &consumer.frontend else {
            return Err("expected A2A consumer".into());
        };
        assert_eq!(kernel.receipt_log().receipts().len(), 1);
    }
    let completed = call(&mut consumer, &approved, wire)?;
    assert_eq!(completed["result"]["task"]["id"], id);
    assert_eq!(
        completed["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED",
        "{completed}"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn continuation_conceals_inaccessible_tasks_and_preserves_the_original_owner() -> TestResult {
    let fixture = Fixture::new()?.with_threshold_approval()?;
    let request = fixture.approval_request("v1-owned-continuation")?;
    let mut consumer = fixture.open(Protocol::A2a)?;
    let pending = call(&mut consumer, &request, send(&request, "application/json"))?;
    let task = &pending["result"]["task"];
    let id = task["id"].as_str().ok_or("pending task id")?;
    let proposal =
        serde_json::from_value(task["artifacts"][0]["parts"][0]["data"]["proposal"].clone())?;
    let approved = fixture.approved_request(&request, proposal)?;
    let mut wire = send(&approved, "application/json");
    wire["params"]["message"]["taskId"] = json!(id);
    let mut renamed = approved.clone();
    renamed.agent_id = "renamed-owner".into();
    let mut other_subject = approved.clone();
    let mut body = other_subject.capability.body();
    body.subject = Keypair::generate().public_key();
    other_subject.capability = CapabilityToken::sign(body, &fixture.signer)?;
    for inaccessible in [renamed, other_subject] {
        let refused = call(&mut consumer, &inaccessible, wire.clone())?;
        assert_eq!(refused["error"]["code"], -32001, "{refused}");
        let mut missing = wire.clone();
        missing["params"]["message"]["taskId"] = json!("absent-task");
        let absent = call(&mut consumer, &inaccessible, missing)?;
        assert_eq!(absent["error"]["code"], refused["error"]["code"]);
        let observed = call(&mut consumer, &approved, lookup("GetTask", id))?;
        assert_eq!(observed["result"], *task);
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    }
    let completed = call(&mut consumer, &approved, wire)?;
    assert_eq!(
        completed["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED",
        "{completed}"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn signed_approval_cannot_resume_a_cancelled_v1_task() -> TestResult {
    let fixture = Fixture::new()?.with_threshold_approval()?;
    let request = fixture.approval_request("v1-cancelled-continuation")?;
    let mut consumer = fixture.open(Protocol::A2a)?;
    let pending = call(&mut consumer, &request, send(&request, "application/json"))?;
    let task = &pending["result"]["task"];
    let id = task["id"].as_str().ok_or("pending task id")?;
    let proposal =
        serde_json::from_value(task["artifacts"][0]["parts"][0]["data"]["proposal"].clone())?;
    let approved = fixture.approved_request(&request, proposal)?;
    let cancelled = call(&mut consumer, &request, lookup("CancelTask", id))?;
    assert_eq!(
        cancelled["result"]["status"]["state"],
        "TASK_STATE_CANCELED"
    );
    let mut wire = send(&approved, "application/json");
    wire["params"]["message"]["taskId"] = json!(id);
    let refused = call(&mut consumer, &approved, wire)?;
    assert_eq!(refused["error"]["code"], -32602, "{refused}");
    let observed = call(&mut consumer, &approved, lookup("GetTask", id))?;
    assert_eq!(observed["result"], cancelled["result"]);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    let Frontend::A2a(kernel, _) = &consumer.frontend else {
        return Err("expected A2A consumer".into());
    };
    assert_eq!(kernel.receipt_log().receipts().len(), 1);
    Ok(())
}
