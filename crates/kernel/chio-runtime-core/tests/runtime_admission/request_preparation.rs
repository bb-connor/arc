use super::*;

#[test]
fn kernel_hook_preserves_millisecond_admission_time() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut bundle = bundle();
    bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&bundle)?;
    store.insert_bundle(bundle)?;

    let cap = capability("cap-live-1")?;
    let mut request = ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent-live-1".to_string(),
        server_id: "vendor-ledger".to_string(),
        tool_name: "close_account".to_string(),
        purpose: "close governed vendor account".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "chioAdmission": {
                "admissionId": "adm-live-1",
                "bundleSha256": bundle_hash
            }
        })),
        body: Default::default(),
    });

    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;
    let mut expiring_profile = profile();
    expiring_profile.expires_at_unix_ms = 1_800_000_001_500;
    let hook = ChioRuntimeAdmissionHook::new(expiring_profile, store, uninstalled_binding()?)
        .with_runtime_trust_input(signed_trust, trusted)
        .with_pheromone_query_report(advisory)
        .with_runtime_pheromone_policy(signed_policy, signed_weights);
    let decision = prepare_denial(
        &hook,
        &RuntimeAdmissionContext {
            request: &request,
            extra_metadata: None,
            now_unix_secs: 1_800_000_001,
            now_unix_ms: 1_800_000_001_600,
            matched_grant_index: Some(0),
            local_kernel_id: "kernel.vendor-b".to_string(),
        },
    )?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["failure_code"], "stale_profile");
    Ok(())
}

#[test]
fn kernel_hook_denies_federated_origin_without_any_runtime_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let cap = capability("cap-live-1")?;
    let request = ToolCallRequest {
        request_id: "req-federated-no-context".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: Some("kernel.buyer".to_string()),
        declassification_grant: None,
    };

    let hook = allowing_policy_hook(store)?;
    let decision = prepare_denial(
        &hook,
        &RuntimeAdmissionContext {
            request: &request,
            extra_metadata: None,
            now_unix_secs: 1_800_000_001,
            now_unix_ms: 1_800_000_001_000,
            matched_grant_index: Some(0),
            local_kernel_id: "kernel.vendor-b".to_string(),
        },
    )?;

    assert!(!decision.allowed, "{decision:#?}");
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "missing_chio_treaty_context"
    );
    Ok(())
}

#[test]
fn kernel_hook_denies_federated_runtime_request_without_treaty_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut bundle = bundle();
    bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&bundle)?;
    store.insert_bundle(bundle)?;

    let cap = capability("cap-live-1")?;
    let mut request = ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: Some("kernel.buyer".to_string()),
        declassification_grant: None,
    };
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent-live-1".to_string(),
        server_id: "vendor-ledger".to_string(),
        tool_name: "close_account".to_string(),
        purpose: "close governed vendor account".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "chioAdmission": {
                "admissionId": "adm-live-1",
                "bundleSha256": bundle_hash
            }
        })),
        body: Default::default(),
    });

    let hook = allowing_policy_hook(store)?;
    let decision = prepare_denial(
        &hook,
        &RuntimeAdmissionContext {
            request: &request,
            extra_metadata: None,
            now_unix_secs: 1_800_000_001,
            now_unix_ms: 1_800_000_001_000,
            matched_grant_index: Some(0),
            local_kernel_id: "kernel.vendor-b".to_string(),
        },
    )?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["admission_id"], "adm-live-1");
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "missing_chio_treaty_context"
    );
    Ok(())
}

#[test]
fn kernel_hook_denies_cross_boundary_request_when_treaty_store_evidence_missing(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut bundle = bundle();
    bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&bundle)?;
    store.insert_bundle(bundle)?;

    let cap = capability("cap-live-1")?;
    let mut request = ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: Some("kernel.buyer".to_string()),
        declassification_grant: None,
    };
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent-live-1".to_string(),
        server_id: "vendor-ledger".to_string(),
        tool_name: "close_account".to_string(),
        purpose: "close governed vendor account".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "chioAdmission": {
                "admissionId": "adm-live-1",
                "bundleSha256": bundle_hash
            },
            "chioTreaty": {
                "treatyScopeId": "treaty-buyer-vendor",
                "treatyScopeSha256": "5".repeat(64),
                "ladderIntersectionId": "treaty-buyer-vendor:1800000010000",
                "ladderIntersectionSha256": "6".repeat(64),
                "actionClassId": "workflow.destructive.vendor_call"
            }
        })),
        body: Default::default(),
    });

    let hook = allowing_policy_hook(store)?;
    let decision = prepare_denial(
        &hook,
        &RuntimeAdmissionContext {
            request: &request,
            extra_metadata: None,
            now_unix_secs: 1_800_000_001,
            now_unix_ms: 1_800_000_001_000,
            matched_grant_index: Some(0),
            local_kernel_id: "kernel.vendor-b".to_string(),
        },
    )?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_missing_scope"
    );
    Ok(())
}
