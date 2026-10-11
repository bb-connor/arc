//! Worker-output substitution controls at the owning credential completion seam.
//! These controls do not claim an unprivileged peer can publish worker events.

use super::*;

const DEADLINE: Duration = Duration::from_secs(4);
const FORGED: &str = "unsigned-worker-projection-sentinel";

struct CapturedCall {
    fixture: HttpFixture,
    session: String,
    token: String,
    request: Value,
    pending: remote_mcp_session_credentials::CredentialCall,
    terminal: Value,
}

async fn status_call(
    fixture: &HttpFixture,
    session: &str,
) -> TestResult<remote_mcp_session_credentials::CredentialCall> {
    let request = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/admin/sessions/{session}/credential/status"))
        .header(AUTHORIZATION, "Bearer admin-fixture")
        .body(axum::body::Body::empty())?;
    let response =
        tokio::time::timeout(DEADLINE, fixture.router.clone().oneshot(request)).await??;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024).await?;
    let body: Value = serde_json::from_slice(&bytes)?;
    Ok(serde_json::from_value(body["call"].clone())?)
}

async fn capture(logical_id: &str) -> TestResult<CapturedCall> {
    let fixture = fixture()?;
    let session = initialize(&fixture).await?;
    let token = credential(&fixture, &session).await?;
    let bound = match fixture.state.sessions.lookup(&session).await {
        Some(RemoteSessionEntry::Active(bound)) => bound,
        _ => return Err("restricted worker session is not active".into()),
    };
    let mut events = bound.subscribe();
    let call = json!({"jsonrpc":"2.0","id":41,"method":"tools/call","params":{
        "name":"echo_json","arguments":{"message":"signed-original-output"},
        "_meta":{"chioRequestId":logical_id}}});
    let response = tokio::time::timeout(
        DEADLINE,
        request(
            &fixture,
            MCP_ENDPOINT_PATH,
            &token,
            Some(&session),
            &serde_json::to_vec(&call)?,
        ),
    )
    .await??;
    assert_eq!(response.status(), StatusCode::OK);
    let terminal = tokio::time::timeout(DEADLINE, async {
        loop {
            let event = events.recv().await?;
            if event.message["id"] == 41 && event.message.get("method").is_none() {
                return Ok::<_, broadcast::error::RecvError>(event.message);
            }
        }
    })
    .await??;
    // The real adapter and kernel have produced a terminal result. This body
    // has never been polled, so the credential outcome remains pending. Dropping
    // it allows a substitution control at finish_call, without dispatching twice.
    drop(response);
    let pending = status_call(&fixture, &session).await?;
    let receipt: ChioReceipt =
        serde_json::from_value(terminal["result"]["_meta"]["chioEvidence"]["receipt"].clone())?;
    assert_eq!(receipt.kernel_key, fixture.trusted_key);
    assert!(receipt.verify_signature()?);
    assert_eq!(
        receipt.content_hash,
        sha256_hex(&canonical_json_bytes(
            &terminal["result"]["_meta"]["chioEvidence"]["output"]
        )?)
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    Ok(CapturedCall {
        fixture,
        session,
        token,
        request: call,
        pending,
        terminal,
    })
}

async fn replay(captured: &CapturedCall) -> TestResult<(StatusCode, Vec<u8>)> {
    let bytes = serde_json::to_vec(&captured.request)?;
    let response = tokio::time::timeout(
        DEADLINE,
        request(
            &captured.fixture,
            MCP_ENDPOINT_PATH,
            &captured.token,
            Some(&captured.session),
            &bytes,
        ),
    )
    .await??;
    let status = response.status();
    let bytes = tokio::time::timeout(
        DEADLINE,
        axum::body::to_bytes(response.into_body(), 128 * 1024),
    )
    .await??;
    Ok((status, bytes.to_vec()))
}

fn visible_result(message: &Value) -> Value {
    json!({"content":message["result"]["content"],
        "structuredContent":message["result"]["structuredContent"],
        "isError":message["result"]["isError"]})
}

async fn cleanup(captured: &CapturedCall) -> TestResult {
    captured
        .fixture
        .state
        .sessions
        .shutdown_all_active()
        .await?;
    captured
        .fixture
        .state
        .factory
        .shutdown_shared_upstream_owner()?;
    Ok(())
}

#[tokio::test]
async fn mcp_projection_original_real_adapter_projection_is_acknowledged_and_replayed() -> TestResult
{
    let captured = capture("projection-real-adapter-positive").await?;
    let finished = remote_mcp_session_credentials::finish_call(
        &captured.fixture.state,
        &captured.pending,
        &captured.terminal,
    );
    let replayed = replay(&captured).await?;
    cleanup(&captured).await?;
    let finished = finished.map_err(|response| format!("finish returned {}", response.status()))?;
    assert_eq!(
        visible_result(&finished),
        visible_result(&captured.terminal)
    );
    assert!(finished["result"]["_meta"]["chioDelivery"]["acknowledgement"].is_string());
    assert_eq!(replayed.0, StatusCode::OK);
    let replayed: Value = serde_json::from_slice(&replayed.1)?;
    assert_eq!(
        replayed, finished,
        "replay changed the verified delivered outcome"
    );
    assert_eq!(captured.fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

async fn rejects_forged_projection(invalid_signed_evidence: bool) -> TestResult {
    let captured = capture(if invalid_signed_evidence {
        "projection-invalid-signed-evidence"
    } else {
        "projection-unchanged-signed-evidence"
    })
    .await?;
    let mut forged = captured.terminal.clone();
    forged["result"]["content"] = json!([{"type":"text","text":FORGED}]);
    forged["result"]["structuredContent"] = json!({"echo":FORGED});
    forged["result"]["isError"] = json!(true);
    if invalid_signed_evidence {
        let mut receipt: ChioReceipt =
            serde_json::from_value(forged["result"]["_meta"]["chioEvidence"]["receipt"].clone())?;
        receipt.tool_name = "unsigned-replacement-tool".into();
        assert!(!receipt.verify_signature()?);
        forged["result"]["_meta"]["chioEvidence"]["receipt"] = serde_json::to_value(receipt)?;
    } else {
        assert_eq!(
            forged["result"]["_meta"]["chioEvidence"],
            captured.terminal["result"]["_meta"]["chioEvidence"],
            "projection-only control changed signed evidence"
        );
    }
    let finished = remote_mcp_session_credentials::finish_call(
        &captured.fixture.state,
        &captured.pending,
        &forged,
    );
    let replayed = replay(&captured).await?;
    cleanup(&captured).await?;

    if let Ok(response) = finished {
        assert!(
            !visible_result(&response).to_string().contains(FORGED),
            "credential completion returned an unsigned visible tool result: {response}"
        );
        if response.get("result").is_some() {
            assert_eq!(
                visible_result(&response),
                visible_result(&captured.terminal)
            );
            assert!(
                !invalid_signed_evidence,
                "invalid receipt still authorized tool output"
            );
        }
    }
    assert!(
        !String::from_utf8_lossy(&replayed.1).contains(FORGED),
        "the signed credential-call row replayed forged worker output"
    );
    assert_eq!(captured.fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn mcp_projection_original_unchanged_receipt_cannot_authorize_tampered_visible_output(
) -> TestResult {
    rejects_forged_projection(false).await
}

#[tokio::test]
async fn mcp_projection_original_invalid_signed_evidence_cannot_deliver_or_replay_tool_output(
) -> TestResult {
    rejects_forged_projection(true).await
}

#[tokio::test]
async fn mcp_projection_original_unsigned_result_extensions_cannot_be_delivered_or_replayed(
) -> TestResult {
    let captured = capture("projection-unsigned-extension").await?;
    let mut forged = captured.terminal.clone();
    forged["result"]["annotations"] = json!({"audience":["assistant"],"instruction":FORGED});
    forged["result"]["resourceMetadata"] = json!({"uri":FORGED});
    forged["result"]["_meta"]["unsignedProjection"] = json!({"callerInstruction":FORGED});
    assert_eq!(
        forged["result"]["_meta"]["chioEvidence"],
        captured.terminal["result"]["_meta"]["chioEvidence"],
        "unsigned extension control changed signed evidence"
    );
    let finished = remote_mcp_session_credentials::finish_call(
        &captured.fixture.state,
        &captured.pending,
        &forged,
    );
    let replayed = replay(&captured).await?;
    cleanup(&captured).await?;
    if let Ok(response) = finished {
        assert!(
            !response.to_string().contains(FORGED),
            "unsigned caller-visible result extensions survived credential completion: {response}"
        );
        if response.get("result").is_some() {
            assert_eq!(
                visible_result(&response),
                visible_result(&captured.terminal)
            );
        }
    }
    assert!(
        !String::from_utf8_lossy(&replayed.1).contains(FORGED),
        "the credential-call row replayed unsigned result extensions"
    );
    assert_eq!(captured.fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn mcp_projection_control_valid_v2_nonce_is_preserved_through_delivery_and_replay(
) -> TestResult {
    use chio_kernel::admission_operation::{
        AdmissionAuthorityProfileV1, AdmissionAuthoritySelectionV1, AdmissionDigest,
        AdmissionExecutionNonceReservationV1, AdmissionOperationBindingInputV1,
        AdmissionOperationBindingV1, AdmissionOperationId, AdmissionOperationStore,
        AdmissionOperationV1, AdmissionRequestBindingV1, AuthenticatedRequestNamespace,
        RetainedToolAdmissionRequestV1,
    };

    let captured = capture("projection-valid-operation-nonce").await?;
    let runtime = captured
        .fixture
        .state
        .factory
        .durable_admission
        .as_ref()
        .ok_or("runtime")?;
    let now = captured.fixture.state.factory.config.clock.millis()?;
    let receipt: ChioReceipt = serde_json::from_value(
        captured.terminal["result"]["_meta"]["chioEvidence"]["receipt"].clone(),
    )?;
    let (store, _) = runtime
        .local_runtime_participant()
        .ok_or("local existing owner")?;
    let original_id = AdmissionOperationId::from_persisted(
        receipt.metadata.as_ref().ok_or("receipt metadata")?["admission_operation"]["operation_id"]
            .as_str()
            .ok_or("terminal operation id")?,
    )?;
    let base = store
        .load_by_operation_id(&original_id)?
        .ok_or("actual operation")?;
    let bound = match captured
        .fixture
        .state
        .sessions
        .lookup(&captured.session)
        .await
    {
        Some(RemoteSessionEntry::Active(bound)) => bound,
        _ => return Err("actual session is inactive".into()),
    };
    let capability = bound
        .issued_capabilities
        .iter()
        .find(|capability| capability.id == receipt.capability_id)
        .ok_or("actual issued capability")?
        .clone();
    assert!(capability.verify_signature()?);
    let request = chio_kernel::ToolCallRequest {
        request_id: base.binding().request_id().as_str().into(),
        capability,
        tool_name: receipt.tool_name.clone(),
        server_id: receipt.tool_server.clone(),
        agent_id: bound.agent_id.clone(),
        arguments: captured.request["params"]["arguments"].clone(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: vec![],
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    assert_eq!(request.arguments, receipt.action.parameters);
    let grant_index = usize::try_from(
        receipt.metadata.as_ref().ok_or("receipt metadata")?["attribution"]["grant_index"]
            .as_u64()
            .ok_or("actual grant index")?,
    )?;
    let grant = request
        .capability
        .scope
        .grants
        .get(grant_index)
        .ok_or("actual matching grant")?;
    let profile = AdmissionAuthorityProfileV1::new(AdmissionAuthoritySelectionV1 {
        runtime_hook_installed: false,
        swarm_admission_required: false,
        runtime_enforces_swarm_authority: false,
        runtime_requires_dispatch_revalidation: false,
        runtime: None,
        approval: None,
        dpop: None,
    })?;
    // Ordinary MCP calls deliberately retain no original-request artifact.
    // This metadata-only fixture uses the existing canonical store-test recipe
    // for the actual issued capability, caller arguments and grant selection.
    // The public binding validator checks both request commitments; no opaque
    // digest or nonce signature context is fabricated and nothing is dispatched.
    let prior_request_hash = sha256_hex(&canonical_json_bytes(&json!({
        "schema":"chio.tool-admission-request.v1", "server_id":request.server_id,
        "tool_name":request.tool_name, "agent_id":request.agent_id,
        "arguments":request.arguments, "governed_intent":request.governed_intent,
        "model_metadata":request.model_metadata,
        "federated_origin_kernel_id":request.federated_origin_kernel_id,
        "matching_grants":[{"index":grant_index,"grant":grant}], "post_return_steps":[],
    }))?);
    let immutable_request_hash = AdmissionDigest::try_new(
        "immutable_request_hash",
        sha256_hex(&canonical_json_bytes(&json!({
            "schema":"chio.tool-admission-request.v4", "prior_request_hash":prior_request_hash,
            "authority_profile":&profile,
        }))?),
    )?;
    let original = RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(
        &json!({"schema":"chio.retained-tool-admission-request.v4", "request":&request,
            "authority_profile":profile,"matching_grant_indices":[grant_index], "post_return_steps":[]}),
    )?)?;
    original.validate_request_material(&request)?;
    let binding = base.binding();
    let mut requirements = binding.participant_requirements();
    requirements.execution_nonce = true;
    let nonce_binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: binding.kind(),
        namespace: AuthenticatedRequestNamespace::for_local_system(
            binding.coordinator_authority_id().clone(),
        )?,
        request_id: binding.request_id().clone(),
        capability_id: binding.capability_id().clone(),
        authorization_capability_hash: binding.authorization_capability_hash().clone(),
        request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
            immutable_request_hash,
            binding.action_parameter_hash().clone(),
            requirements,
        )?,
        policy_hash: binding.policy_hash().clone(),
        effect_class: binding.effect_class(),
    })?;
    original.validate_binding(&nonce_binding)?;
    let operation = AdmissionOperationV1::prepare(nonce_binding, base.coordinator_lease_epoch())?;
    // This public API mints checked metadata. It neither reserves a nonce nor
    // commits a new operation, and this control dispatches no additional tool.
    let keypair = runtime.kernel_keypair();
    let issuance = AdmissionExecutionNonceReservationV1::mint_for_operation(
        &operation,
        &original,
        &keypair,
        &chio_kernel::ExecutionNonceConfig::default(),
        now,
    )?;
    issuance.require_operation_bound_profile()?;
    let signed = issuance.signed_nonce().clone();
    let mut body = receipt.body();
    let admission = &mut body.metadata.as_mut().ok_or("receipt metadata")?["admission_operation"];
    admission["operation_id"] = json!(operation.binding().operation_id().as_str());
    admission["trusted_time_unix_ms"] = json!(now);
    let timed_receipt = ChioReceipt::sign(body, &keypair)?;
    let mut message = captured.terminal.clone();
    message["result"]["_meta"]["chioEvidence"]["receipt"] = serde_json::to_value(timed_receipt)?;
    message["result"]["_meta"]["chioExecutionNonce"] = serde_json::to_value(&signed)?;
    let finished = remote_mcp_session_credentials::finish_call(
        &captured.fixture.state,
        &captured.pending,
        &message,
    );
    let replayed = replay(&captured).await?;
    cleanup(&captured).await?;
    let finished =
        finished.map_err(|response| format!("v2 finish returned {}", response.status()))?;
    assert_eq!(
        finished["result"]["_meta"]["chioExecutionNonce"],
        serde_json::to_value(&signed)?
    );
    assert_eq!(
        visible_result(&finished),
        visible_result(&captured.terminal)
    );
    assert!(finished["result"]["_meta"]["chioDelivery"]["acknowledgement"].is_string());
    assert_eq!(replayed.0, StatusCode::OK);
    assert_eq!(serde_json::from_slice::<Value>(&replayed.1)?, finished);
    assert_eq!(captured.fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}
