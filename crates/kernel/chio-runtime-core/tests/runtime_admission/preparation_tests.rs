use crate as runtime_api;
#[path = "../support/runtime_admission.rs"]
mod fixtures;
use fixtures::*;

fn prepare_denial<S: RuntimeAdmissionStore + Send + Sync>(
    hook: &ChioRuntimeAdmissionHook<S>,
    context: &RuntimeAdmissionContext<'_>,
) -> Result<chio_kernel::RuntimeAdmissionDecision, chio_kernel::KernelError> {
    match hook.prepare_request(context)? {
        super::preparation::HookAdmissionPreparation::Immediate(decision) => {
            assert!(!decision.allowed, "expected evidence refusal");
            Ok(*decision)
        }
        super::preparation::HookAdmissionPreparation::Prepared(_) => {
            panic!("invalid evidence produced a prepared plan")
        }
    }
}

#[test]
fn treaty_runtime_hook_denies_missing_lineage_evidence_ref(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context
        .as_object_mut()
        .ok_or_else(|| io::Error::other("context object missing"))?
        .remove("receiptLineageBundle");
    let request = treaty_runtime_request(args, bundle_hash, context)?;
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
    if let Some(code) = metadata["chio_runtime"]["failure_code"].as_str() {
        emit_threat_matrix_code(code);
    }
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_missing_required_evidence"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_request_smuggled_trust_root() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context["trustRoot"] = serde_json::json!({"issuer": "caller-smuggled"});
    let request = treaty_runtime_request(args, bundle_hash, context)?;
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
    if let Some(code) = metadata["chio_runtime"]["failure_code"].as_str() {
        emit_threat_matrix_code(code);
    }
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "request_smuggled_trust_root"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_request_smuggled_dynamic_trust(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context["dynamicTrust"] = serde_json::json!({"discovery": "caller-smuggled"});
    let request = treaty_runtime_request(args, bundle_hash, context)?;
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
    if let Some(code) = metadata["chio_runtime"]["failure_code"].as_str() {
        emit_threat_matrix_code(code);
    }
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "request_smuggled_dynamic_trust"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_missing_bilateral_invocation_evidence_ref(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context
        .as_object_mut()
        .ok_or_else(|| io::Error::other("context object missing"))?
        .remove("bilateralInvocation");
    let request = treaty_runtime_request(args, bundle_hash, context)?;
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
        "chio_treaty_missing_required_evidence"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_requires_signed_bilateral_evidence_before_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;

    let mut context = treaty_runtime_context(&fixture);
    context
        .as_object_mut()
        .ok_or_else(|| io::Error::other("context object missing"))?
        .remove("bilateralDsse");
    let request = treaty_runtime_request(args, bundle_hash, context)?;
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
        "chio_treaty_missing_required_evidence"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_mismatched_continuation_hash(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let fixture = treaty_runtime_fixture()?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let mut context = treaty_runtime_context(&fixture);
    context["crossKernelContinuation"]["sha256"] = serde_json::Value::String("f".repeat(64));
    let request = treaty_runtime_request(args, bundle_hash, context)?;
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
        "chio_treaty_continuation_hash_mismatch"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_continuation_from_non_origin_source(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.continuation.source_kernel_id = "kernel.vendor-b".to_string();
    fixture.continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.continuation)?,
    );
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
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
        "chio_treaty_continuation_mismatch"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_bare_tool_continuation_audience(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.continuation.audience_tool = "close_account".to_string();
    fixture.continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.continuation)?,
    );
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
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
        "chio_treaty_continuation_mismatch"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_unverified_lineage_bundle_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.lineage_bundle.statements[0].evidence_class = "asserted".to_string();
    fixture.lineage_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.lineage_bundle)?,
    );
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
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
        "chio_lineage_bundle_unverified_edge"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_denies_stale_continuation_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.continuation.expires_at_unix_ms = 1_800_000_000_500;
    fixture.continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.continuation)?,
    );
    fixture.lineage_bundle.statements[0].continuation_sha256 = fixture.continuation_sha256.clone();
    fixture.lineage_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.lineage_bundle)?,
    );
    fixture.bilateral_invocation.continuation_sha256 = fixture.continuation_sha256.clone();
    fixture.bilateral_invocation_sha256 =
        runtime_api::bilateral_invocation_binding_sha256(&fixture.bilateral_invocation)?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = ChioRuntimeAdmissionHook::new(profile(), store, uninstalled_binding()?);
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
        "chio_treaty_continuation_stale"
    );
    Ok(())
}

#[test]
fn treaty_runtime_hook_preserves_millisecond_time_for_continuation_staleness(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("treaty-hook.sqlite3"))?;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let mut fixture = treaty_runtime_fixture()?;
    fixture.continuation.expires_at_unix_ms = 1_800_000_001_500;
    fixture.continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.continuation)?,
    );
    fixture.lineage_bundle.statements[0].continuation_sha256 = fixture.continuation_sha256.clone();
    fixture.lineage_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.lineage_bundle)?,
    );
    fixture.bilateral_invocation.continuation_sha256 = fixture.continuation_sha256.clone();
    fixture.bilateral_invocation_sha256 =
        runtime_api::bilateral_invocation_binding_sha256(&fixture.bilateral_invocation)?;
    insert_treaty_runtime_fixture(&store, &fixture)?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = ChioRuntimeAdmissionHook::new(profile(), store, uninstalled_binding()?);
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
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_continuation_stale"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_swarm_context_without_required_evidence_refs(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let cap = capability("cap-live-1")?;
    let request = ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
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
                "chioSwarm": {
                    "taskGraph": {
                        "id": "swarm-task-graph-runtime",
                        "sha256": "a".repeat(64)
                    },
                    "continuationToken": {
                        "id": "swarm-continuation-runtime",
                        "sha256": "b".repeat(64)
                    }
                }
            })),
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let hook = allowing_chio_policy_hook(store)?;
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
        "missing_chio_swarm_evidence_ref"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_stale_swarm_continuation_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(true)?;
    let graphs = retained_swarm_graphs(&swarm_bundle);

    let cap = capability("cap-live-1")?;
    let request = ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
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
                "chioSwarm": swarm_runtime_context(&swarm_bundle)?
            })),
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let hook = allowing_chio_policy_hook(store)?
        .with_swarm_witness_keys(trusted_swarm_witness_keys())
        .with_swarm_graph_source(graphs);
    let route_metadata = swarm_route_metadata();
    let decision = prepare_denial(
        &hook,
        &RuntimeAdmissionContext {
            request: &request,
            extra_metadata: Some(&route_metadata),
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
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_swarm_continuation_expired_since_storage(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let mut swarm_bundle = runtime_swarm_bundle(false)?;
    swarm_bundle.continuation_tokens[0].expires_at_unix_ms = 1_800_000_001_500;
    swarm_bundle.continuation_tokens[0].signature = sign_swarm_continuation_token(
        &swarm_bundle.continuation_tokens[0],
        &swarm_witness_keypair(),
    )?;
    let graphs = retained_swarm_graphs(&swarm_bundle);

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook = allowing_chio_policy_hook(store)?
        .with_swarm_witness_keys(trusted_swarm_witness_keys())
        .with_swarm_graph_source(graphs);
    let route_metadata = swarm_route_metadata();
    let decision = prepare_denial(
        &hook,
        &RuntimeAdmissionContext {
            request: &request,
            extra_metadata: Some(&route_metadata),
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
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_swarm_route_metadata_mismatch_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    let graphs = retained_swarm_graphs(&swarm_bundle);

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let route_metadata = serde_json::json!({
        "route": {
            "bridge": "a2a",
            "protocolTarget": "a2a://provider-b"
        }
    });
    let hook = allowing_chio_policy_hook(store)?
        .with_swarm_witness_keys(trusted_swarm_witness_keys())
        .with_swarm_graph_source(graphs);
    let decision = prepare_denial(
        &hook,
        &RuntimeAdmissionContext {
            request: &request,
            extra_metadata: Some(&route_metadata),
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
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_route_selection_as_swarm_route_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    let graphs = retained_swarm_graphs(&swarm_bundle);

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let route_metadata = serde_json::json!({
        "route_selection": {
            "bridge": "mcp",
            "protocolTarget": "mcp://provider-runtime",
            "selectedRoute": "mcp:task-child-a"
        }
    });
    let hook = allowing_chio_policy_hook(store)?
        .with_swarm_witness_keys(trusted_swarm_witness_keys())
        .with_swarm_graph_source(graphs);
    let decision = prepare_denial(
        &hook,
        &RuntimeAdmissionContext {
            request: &request,
            extra_metadata: Some(&route_metadata),
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
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_incomplete_swarm_route_metadata_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    let graphs = retained_swarm_graphs(&swarm_bundle);

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let route_metadata = serde_json::json!({
        "route": {
            "bridge": "mcp"
        }
    });
    let hook = allowing_chio_policy_hook(store)?
        .with_swarm_witness_keys(trusted_swarm_witness_keys())
        .with_swarm_graph_source(graphs);
    let decision = prepare_denial(
        &hook,
        &RuntimeAdmissionContext {
            request: &request,
            extra_metadata: Some(&route_metadata),
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
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_swarm_route_plan_not_bound_to_continuation(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    let graphs = retained_swarm_graphs(&swarm_bundle);
    let mut swarm_context = swarm_runtime_context(&swarm_bundle)?;
    swarm_context["routePlanReceipt"] = serde_json::json!({
        "id": &swarm_bundle.route_plan_receipts[1].route_plan_id,
        "sha256": canonical_test_hash(&swarm_bundle.route_plan_receipts[1])?
    });

    let request = chio_swarm_runtime_request(args, bundle_hash, swarm_context)?;
    let route_metadata = serde_json::json!({
        "route": {
            "bridge": "a2a",
            "protocolTarget": "a2a://provider-runtime",
            "selectedRoute": "a2a:task-child-b"
        }
    });
    let hook = allowing_chio_policy_hook(store)?
        .with_swarm_witness_keys(trusted_swarm_witness_keys())
        .with_swarm_graph_source(graphs);
    let decision = prepare_denial(
        &hook,
        &RuntimeAdmissionContext {
            request: &request,
            extra_metadata: Some(&route_metadata),
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
        "chio_swarm_authority_ref_mismatch"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_denies_swarm_missing_route_metadata_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    admission_bundle.destructive = false;
    admission_bundle.lease_id = None;
    admission_bundle.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(false)?;
    let graphs = retained_swarm_graphs(&swarm_bundle);

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook = allowing_chio_policy_hook(store)?
        .with_swarm_witness_keys(trusted_swarm_witness_keys())
        .with_swarm_graph_source(graphs);
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
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn sqlite_runtime_hook_denies_stale_swarm_continuation_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("swarm-hook.sqlite3"))?;
    let mut admission_bundle = bundle();
    admission_bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission_bundle.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;

    let swarm_bundle = runtime_swarm_bundle(true)?;
    let graphs = retained_swarm_graphs(&swarm_bundle);

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook = allowing_chio_policy_hook(store)?
        .with_swarm_witness_keys(trusted_swarm_witness_keys())
        .with_swarm_graph_source(graphs);
    let route_metadata = swarm_route_metadata();
    let decision = prepare_denial(
        &hook,
        &RuntimeAdmissionContext {
            request: &request,
            extra_metadata: Some(&route_metadata),
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
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[path = "preparation_faults.rs"]
mod faults;

#[test]
fn chio_native_runtime_admission_schema_emits_chio_report() -> Result<(), Box<dyn std::error::Error>>
{
    let mut profile = profile();
    profile.schema = "chio.runtime.admission-profile.v1".to_string();
    let mut bundle = bundle();
    bundle.schema = "chio.runtime.admission-bundle.v1".to_string();
    bundle.destructive = false;
    bundle.lease_id = None;
    bundle.governance_receipt_id = None;

    let store = InMemoryRuntimeAdmissionStore::new();
    store.insert_bundle(bundle.clone())?;
    let preparation = crate::admission::prepare_runtime_admission_from_bundle(
        RuntimeAdmissionInput {
            profile: &profile,
            store: &store,
            admission_id: &bundle.admission_id,
            request: &bundle.binding,
            action_class_id: None,
            runtime_trust_input: None,
            trusted_verifier_keys: &[],
            pheromone_query_report: None,
            runtime_pheromone_policy: None,
            runtime_peer_weights: None,
            now_unix_ms: 1_800_000_000_001,
        },
        store.bundle("adm-live-1")?,
    )?;
    let crate::admission::RuntimeAdmissionPreparation::Prepared(prepared) = preparation else {
        return Err("valid report inputs did not prepare".into());
    };
    let report = prepared.commit_operation_owned(&store)?;

    assert!(report.accepted);
    assert_eq!(report.schema, "chio.runtime.admission-report.v1");
    let metadata = report
        .receipt_metadata
        .get("chio_runtime")
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(metadata["admission_id"], bundle.admission_id);
    assert_eq!(metadata["accepted"], true);
    Ok(())
}

#[test]
fn signed_runtime_admission_report_detects_tampering() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    store.insert_bundle(bundle())?;
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;
    let preparation = crate::admission::prepare_runtime_admission_from_bundle(
        RuntimeAdmissionInput {
            profile: &profile(),
            store: &store,
            admission_id: "adm-live-1",
            request: &binding(),
            action_class_id: None,
            runtime_trust_input: Some(&signed_trust),
            trusted_verifier_keys: &trusted,
            pheromone_query_report: Some(&advisory),
            runtime_pheromone_policy: Some(&signed_policy),
            runtime_peer_weights: Some(&signed_weights),
            now_unix_ms: 1_800_000_001_000,
        },
        store.bundle("adm-live-1")?,
    )?;
    let crate::admission::RuntimeAdmissionPreparation::Prepared(prepared) = preparation else {
        return Err("valid report inputs did not prepare".into());
    };
    let report = prepared.commit_operation_owned(&store)?;
    let signer = Keypair::generate();
    let mut signed = sign_runtime_admission_report(report, &signer)?;
    assert!(verify_signed_runtime_admission_report(&signed)?);
    signed.body.accepted = false;
    assert!(!verify_signed_runtime_admission_report(&signed)?);
    Ok(())
}

#[test]
fn prepared_hook_rejects_treaty_dsse_policy_verdict_disagreement(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut fixture = treaty_runtime_fixture()?;
    fixture.bilateral_dsse = deny_policy_bilateral_dsse(&fixture.bilateral_dsse)?;
    fixture.bilateral_dsse_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&fixture.bilateral_dsse)?,
    );
    let mut bundle = bundle();
    bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&bundle)?;
    store.insert_bundle(bundle)?;
    store.insert_treaty_runtime_artifact(
        "treaty_scope",
        &fixture.treaty_scope.treaty_id,
        &fixture.treaty_scope,
    )?;
    store.insert_treaty_runtime_artifact(
        "ladder_intersection",
        &fixture.ladder_intersection.intersection_id,
        &fixture.ladder_intersection,
    )?;
    store.insert_treaty_runtime_artifact(
        "cross_kernel_continuation",
        &fixture.continuation.continuation_id,
        &fixture.continuation,
    )?;
    store.insert_treaty_runtime_artifact(
        "receipt_lineage_bundle",
        &fixture.lineage_bundle.bundle_id,
        &fixture.lineage_bundle,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_invocation",
        &fixture.bilateral_invocation.invocation_id,
        &fixture.bilateral_invocation,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_dsse_envelope",
        &fixture.bilateral_dsse_id,
        &fixture.bilateral_dsse,
    )?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = allowing_chio_policy_hook(store)?;
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
        "chio_treaty_unverified_required_evidence"
    );
    Ok(())
}

#[test]
fn prepared_hook_rejects_treaty_dsse_unanimous_deny() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let fixture = treaty_runtime_fixture_with_policy(unanimous_deny_policy_evaluation_summary())?;
    let mut bundle = bundle();
    bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&bundle)?;
    store.insert_bundle(bundle)?;
    store.insert_treaty_runtime_artifact(
        "treaty_scope",
        &fixture.treaty_scope.treaty_id,
        &fixture.treaty_scope,
    )?;
    store.insert_treaty_runtime_artifact(
        "ladder_intersection",
        &fixture.ladder_intersection.intersection_id,
        &fixture.ladder_intersection,
    )?;
    store.insert_treaty_runtime_artifact(
        "cross_kernel_continuation",
        &fixture.continuation.continuation_id,
        &fixture.continuation,
    )?;
    store.insert_treaty_runtime_artifact(
        "receipt_lineage_bundle",
        &fixture.lineage_bundle.bundle_id,
        &fixture.lineage_bundle,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_invocation",
        &fixture.bilateral_invocation.invocation_id,
        &fixture.bilateral_invocation,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_dsse_envelope",
        &fixture.bilateral_dsse_id,
        &fixture.bilateral_dsse,
    )?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;
    let hook = allowing_chio_policy_hook(store)?;
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
    if let Some(code) = metadata["chio_runtime"]["failure_code"].as_str() {
        emit_threat_matrix_code(code);
    }
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_policy_denied"
    );
    Ok(())
}

#[test]
fn prepared_hook_uses_configured_runtime_policy_to_deny() -> Result<(), Box<dyn std::error::Error>>
{
    let store = InMemoryRuntimeAdmissionStore::new();
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let fixture = treaty_runtime_fixture()?;
    let mut bundle = bundle();
    bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&bundle)?;
    store.insert_bundle(bundle)?;
    store.insert_treaty_runtime_artifact(
        "treaty_scope",
        &fixture.treaty_scope.treaty_id,
        &fixture.treaty_scope,
    )?;
    store.insert_treaty_runtime_artifact(
        "ladder_intersection",
        &fixture.ladder_intersection.intersection_id,
        &fixture.ladder_intersection,
    )?;
    store.insert_treaty_runtime_artifact(
        "cross_kernel_continuation",
        &fixture.continuation.continuation_id,
        &fixture.continuation,
    )?;
    store.insert_treaty_runtime_artifact(
        "receipt_lineage_bundle",
        &fixture.lineage_bundle.bundle_id,
        &fixture.lineage_bundle,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_invocation",
        &fixture.bilateral_invocation.invocation_id,
        &fixture.bilateral_invocation,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_dsse_envelope",
        &fixture.bilateral_dsse_id,
        &fixture.bilateral_dsse,
    )?;
    let request = treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&fixture))?;

    let verifier = Keypair::generate();
    let signed_trust = SignedExportEnvelope::sign(trust_body(1, None), &verifier)?;
    let weights = peer_weights();
    let mut policy_body = policy(runtime_peer_weights_sha256(&weights)?);
    policy_body.rules[0].action_class_id = fixture.bilateral_invocation.action_class_id.clone();
    let signed_policy = SignedExportEnvelope::sign(policy_body, &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let high_risk_query_report = signed_query_report(advisory(0.91), &verifier)?;
    let hook = ChioRuntimeAdmissionHook::new(profile(), store, uninstalled_binding()?)
        .with_runtime_trust_input(signed_trust, trusted_keys(&verifier))
        .with_pheromone_query_report(high_risk_query_report)
        .with_runtime_pheromone_policy(signed_policy, signed_weights);
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
        "runtime_pheromone_policy_deny"
    );
    Ok(())
}

#[path = "swarm_evolution.rs"]
mod swarm_evolution;
#[path = "swarm_preparation.rs"]
mod swarm_preparation;

#[path = "swarm_binding_preparation.rs"]
mod swarm_binding;

fn allowing_policy_hook<S>(
    store: S,
) -> Result<ChioRuntimeAdmissionHook<S>, Box<dyn std::error::Error>> {
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;
    Ok(
        ChioRuntimeAdmissionHook::new(profile(), store, uninstalled_binding()?)
            .with_runtime_trust_input(signed_trust, trusted)
            .with_pheromone_query_report(advisory)
            .with_runtime_pheromone_policy(signed_policy, signed_weights),
    )
}

fn allowing_chio_policy_hook<S>(
    store: S,
) -> Result<ChioRuntimeAdmissionHook<S>, Box<dyn std::error::Error>> {
    let mut profile = profile();
    profile.schema = "chio.runtime.admission-profile.v1".to_string();
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;
    Ok(
        ChioRuntimeAdmissionHook::new(profile, store, uninstalled_binding()?)
            .with_runtime_trust_input(signed_trust, trusted)
            .with_pheromone_query_report(advisory)
            .with_runtime_pheromone_policy(signed_policy, signed_weights),
    )
}

fn uninstalled_binding() -> Result<
    chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1,
    Box<dyn std::error::Error>,
> {
    use chio_kernel::admission_operation::{
        runtime_participant::RuntimeParticipantAuthorityBindingV1, AdmissionIdentifier,
    };
    Ok(RuntimeParticipantAuthorityBindingV1::new(
        AdmissionIdentifier::try_new("runtime_id", "uninstalled-runtime")?,
        AdmissionIdentifier::try_new("qualification_id", "a".repeat(64))?,
    ))
}

#[path = "request_preparation.rs"]
mod request_preparation;
