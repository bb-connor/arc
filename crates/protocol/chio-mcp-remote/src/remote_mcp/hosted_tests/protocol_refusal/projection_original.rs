//! Worker-output substitution controls at the owning credential completion seam.
//! These controls do not claim an unprivileged peer can publish worker events.

use super::*;
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationStore, AdmissionOperationV1,
    RetainedToolAdmissionRequestV1,
};

const DEADLINE: Duration = Duration::from_secs(4);
const FORGED: &str = "unsigned-worker-projection-sentinel";

pub(super) struct LiveDispatchGate {
    entered: tokio::sync::Notify,
    released: StdMutex<bool>,
    changed: std::sync::Condvar,
}

impl LiveDispatchGate {
    fn new() -> Self {
        Self {
            entered: tokio::sync::Notify::new(),
            released: StdMutex::new(false),
            changed: std::sync::Condvar::new(),
        }
    }

    pub(super) fn capture_before_completion(&self) -> Result<(), AdapterError> {
        self.entered.notify_one();
        let released = self
            .released
            .lock()
            .map_err(|_| AdapterError::ConnectionFailed("test dispatch gate is poisoned".into()))?;
        let (released, _) = self
            .changed
            .wait_timeout_while(released, DEADLINE, |value| !*value)
            .map_err(|_| AdapterError::ConnectionFailed("test dispatch gate is poisoned".into()))?;
        if !*released {
            return Err(AdapterError::ConnectionFailed(
                "test dispatch capture deadline".into(),
            ));
        }
        Ok(())
    }

    fn release(&self) -> TestResult {
        *self
            .released
            .lock()
            .map_err(|_| "test dispatch gate is poisoned")? = true;
        self.changed.notify_all();
        Ok(())
    }
}

struct CapturedCall {
    fixture: HttpFixture,
    session: String,
    token: String,
    request: Value,
    pending: remote_mcp_session_credentials::CredentialCall,
    terminal: Value,
    live_original: Option<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)>,
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
    capture_with_dispatch_gate(logical_id, None).await
}

async fn capture_with_dispatch_gate(
    logical_id: &str,
    gate: Option<Arc<LiveDispatchGate>>,
) -> TestResult<CapturedCall> {
    let fixture = fixture_with_dispatch_gate(gate.clone())?;
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
    let live_original = if let Some(gate) = gate.as_ref() {
        tokio::time::timeout(DEADLINE, gate.entered.notified()).await?;
        let runtime = fixture
            .state
            .factory
            .durable_admission
            .as_ref()
            .ok_or("runtime")?;
        let (store, fence) = runtime
            .local_runtime_participant()
            .ok_or("local existing owner")?;
        let selector = AdmissionIdentifier::try_new("request_id", logical_id)?;
        let retained = store.load_unambiguous_retained_tool_request(
            &selector,
            &fence,
            fixture.state.factory.config.clock.millis()?,
        );
        // Release even when the snapshot read fails, so fixture setup cannot
        // strand the real worker. The original four-second deadlines remain.
        gate.release()?;
        Some(retained?.ok_or("live fenced original request")?)
    } else {
        None
    };
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
        live_original,
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
        AdmissionExecutionNonceReservationV1, AdmissionOperationBindingInputV1,
        AdmissionOperationBindingV1, AdmissionRequestBindingV1, AuthenticatedRequestNamespace,
    };

    let captured = capture_with_dispatch_gate(
        "projection-valid-operation-nonce",
        Some(Arc::new(LiveDispatchGate::new())),
    )
    .await?;
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
    let (base, original) = captured
        .live_original
        .as_ref()
        .ok_or("captured live original request")?;
    assert_eq!(
        base.binding().operation_id().as_str(),
        receipt.metadata.as_ref().ok_or("receipt metadata")?["admission_operation"]["operation_id"]
            .as_str()
            .ok_or("terminal operation id")?,
        "preterminal snapshot belongs to a different actual dispatch"
    );
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
            binding.immutable_request_hash().clone(),
            binding.action_parameter_hash().clone(),
            requirements,
        )?,
        policy_hash: binding.policy_hash().clone(),
        effect_class: binding.effect_class(),
    })?;
    let operation = AdmissionOperationV1::prepare(nonce_binding, base.coordinator_lease_epoch())?;
    // This public API mints checked metadata. It neither reserves a nonce nor
    // commits a new operation, and this control dispatches no additional tool.
    let keypair = runtime.kernel_keypair();
    let issuance = AdmissionExecutionNonceReservationV1::mint_for_operation(
        &operation,
        original,
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
