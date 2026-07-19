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
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;
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
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

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
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

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
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let route_metadata = swarm_route_metadata();
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

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
fn chio_runtime_hook_denies_replayed_swarm_continuation_before_dispatch(
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
    let continuation_id = swarm_bundle.continuation_tokens[0].token_id.clone();
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let route_metadata = swarm_route_metadata();
    let context = RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    };
    let first = hook.evaluate(&context)?;
    assert!(first.allowed, "{first:#?}");
    let first_metadata = first
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        first_metadata["chio_runtime"]["reserved_swarm_continuation_id"],
        continuation_id
    );

    let replay = hook.evaluate(&context)?;
    assert!(!replay.allowed);
    let replay_metadata = replay
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        replay_metadata["chio_runtime"]["failure_code"],
        "chio_swarm_continuation_replay"
    );
    Ok(())
}

#[test]
fn chio_runtime_hook_revalidates_resumable_swarm_continuation_without_replay_denial(
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

    let mut swarm_bundle = runtime_swarm_bundle(false)?;
    swarm_bundle.continuation_tokens[0].mode = SwarmContinuationMode::Resumable;
    swarm_bundle.continuation_tokens[0].signature = sign_swarm_continuation_token(
        &swarm_bundle.continuation_tokens[0],
        &swarm_witness_keypair(),
    )?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let route_metadata = swarm_route_metadata();
    let context = RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    };

    let first = hook.evaluate(&context)?;
    let second = hook.evaluate(&context)?;

    assert!(first.allowed, "{first:#?}");
    assert!(second.allowed, "{second:#?}");
    assert!(first
        .metadata
        .as_ref()
        .and_then(|metadata| metadata["chio_runtime"].get("reserved_swarm_continuation_id"))
        .is_none());
    Ok(())
}

#[test]
fn sqlite_runtime_hook_denies_replayed_swarm_continuation_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("swarm-replay.sqlite3"))?;
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
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;

    let request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    let route_metadata = swarm_route_metadata();
    let context = RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&route_metadata),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    };
    let first = hook.evaluate(&context)?;
    assert!(first.allowed, "{first:#?}");

    let replay = hook.evaluate(&context)?;
    assert!(!replay.allowed);
    let replay_metadata = replay
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        replay_metadata["chio_runtime"]["failure_code"],
        "chio_swarm_continuation_replay"
    );
    Ok(())
}

#[test]
fn kernel_hook_uses_configured_runtime_policy_to_deny() -> Result<(), Box<dyn std::error::Error>> {
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
    let hook = ChioRuntimeAdmissionHook::new(profile(), store)
        .with_runtime_trust_input(signed_trust, trusted_keys(&verifier))
        .with_pheromone_query_report(high_risk_query_report)
        .with_runtime_pheromone_policy(signed_policy, signed_weights);
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

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

#[test]
fn kernel_hook_rejects_treaty_dsse_unanimous_deny() -> Result<(), Box<dyn std::error::Error>> {
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
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "chio_treaty_policy_denied"
    );
    Ok(())
}

#[test]
fn kernel_hook_rejects_treaty_dsse_policy_verdict_disagreement(
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
    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
        admission_operation_id: None,
        admission_request_binding_hash: None,
    })?;

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

#[derive(Clone)]
struct TreatyRuntimeFixture {
    treaty_scope: TreatyScope,
    treaty_scope_sha256: String,
    ladder_intersection: chio_runtime_core::LadderIntersection,
    ladder_intersection_sha256: String,
    continuation: CrossKernelContinuation,
    continuation_sha256: String,
    lineage_bundle: ReceiptLineageBundle,
    lineage_bundle_sha256: String,
    bilateral_invocation: BilateralInvocation,
    bilateral_invocation_sha256: String,
    bilateral_dsse_id: String,
    bilateral_dsse: chio_federation::bilateral_dsse::DsseEnvelope,
    bilateral_dsse_sha256: String,
}

fn allow_policy_evaluation_summary() -> PolicyEvaluationSummary {
    PolicyEvaluationSummary {
        server_a_verdict: PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: "policy-buyer".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: None,
        },
        server_b_verdict: PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: "policy-vendor".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: None,
        },
        joint_disposition: Some("allow".to_string()),
    }
}

fn unanimous_deny_policy_evaluation_summary() -> PolicyEvaluationSummary {
    PolicyEvaluationSummary {
        server_a_verdict: PolicyVerdict {
            verdict: "deny".to_string(),
            policy_id: "policy-buyer".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: Some("high_risk".to_string()),
        },
        server_b_verdict: PolicyVerdict {
            verdict: "deny".to_string(),
            policy_id: "policy-vendor".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: Some("high_risk".to_string()),
        },
        joint_disposition: Some("deny".to_string()),
    }
}

fn treaty_runtime_fixture() -> Result<TreatyRuntimeFixture, Box<dyn std::error::Error>> {
    treaty_runtime_fixture_with_policy(allow_policy_evaluation_summary())
}

fn treaty_runtime_fixture_with_policy(
    policy_evaluation_summary: PolicyEvaluationSummary,
) -> Result<TreatyRuntimeFixture, Box<dyn std::error::Error>> {
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["bilateral_dsse", "bilateral_invocation", "receipt_lineage"],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["bilateral_dsse", "bilateral_invocation", "receipt_lineage"],
        ),
    );
    let signer_a = Keypair::generate();
    let signer_b = Keypair::generate();
    let mut treaty_scope = treaty_scope();
    treaty_scope.participant_public_keys = vec![signer_a.public_key(), signer_b.public_key()];
    treaty_scope.ladder_manifest_sha256s = vec![
        chio_runtime_core::governance_ladder_manifest_sha256(&buyer)?,
        chio_runtime_core::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let treaty_scope_sha256 = chio_runtime_core::treaty_scope_sha256(&treaty_scope)?;
    let ladder_intersection =
        compute_ladder_intersection(&treaty_scope, &[buyer, vendor], 1_800_000_001_000)?;
    let ladder_intersection_sha256 =
        chio_runtime_core::ladder_intersection_sha256(&ladder_intersection)?;
    let continuation = CrossKernelContinuation {
        schema: CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
        continuation_id: "continue-runtime-1".to_string(),
        source_kernel_id: "kernel.buyer".to_string(),
        target_kernel_id: "kernel.vendor-b".to_string(),
        parent_receipt_sha256: "1".repeat(64),
        parent_session_anchor_sha256: "2".repeat(64),
        capability_id: "cap-live-1".to_string(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        audience_tool: "vendor-ledger.close_account".to_string(),
        nonce: "nonce-runtime-1".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    };
    let continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&continuation)?,
    );
    let mut bilateral_invocation = BilateralInvocation {
        schema: CHIO_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: "invoke-runtime-1".to_string(),
        treaty_id: treaty_scope.treaty_id.clone(),
        ladder_intersection_sha256: ladder_intersection_sha256.clone(),
        continuation_sha256: continuation_sha256.clone(),
        lineage_statement_sha256: String::new(),
        action_class_id: continuation.action_class_id.clone(),
        consistency_model: "totally_ordered".to_string(),
        capability_id: continuation.capability_id.clone(),
        request_sha256: tool_args_sha256(&serde_json::json!({
            "record": "vendor-ledger-7",
            "value": "closed"
        }))?,
        outcome_sha256: "5".repeat(64),
        local_receipt_sha256: continuation.parent_receipt_sha256.clone(),
        remote_receipt_sha256: String::new(),
        signer_kernel_ids: vec!["kernel.buyer".to_string(), "kernel.vendor-b".to_string()],
    };
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: bilateral_invocation.invocation_id.clone(),
            timestamp: 1_800_000_001,
            capability_id: bilateral_invocation.capability_id.clone(),
            tool_server: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "record": "vendor-ledger-7",
                "value": "closed"
            }))?,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: "agent:chio-runtime/admission".to_string(),
                actor_kind: Some("agent".to_string()),
            }],
            content_hash: bilateral_invocation.outcome_sha256.clone(),
            policy_hash: "policy-live".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: signer_b.public_key(),
            bbs_projection_version: None,
        },
        &signer_b,
    )?;
    bilateral_invocation.remote_receipt_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&receipt)?,
    );
    let bilateral_invocation_binding_sha256 =
        chio_runtime_core::bilateral_invocation_binding_sha256(&bilateral_invocation)?;
    let lineage = ReceiptLineageStatement {
        schema: CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
        statement_id: "lineage-runtime-1".to_string(),
        parent_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
        child_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
        continuation_sha256: continuation_sha256.clone(),
        bilateral_invocation_sha256: bilateral_invocation_binding_sha256.clone(),
        evidence_class: "verified".to_string(),
        source_kernel_id: continuation.source_kernel_id.clone(),
        target_kernel_id: continuation.target_kernel_id.clone(),
    };
    let lineage_statement_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&lineage)?,
    );
    bilateral_invocation.lineage_statement_sha256 = lineage_statement_sha256;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-runtime-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage],
    };
    let lineage_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&lineage_bundle)?,
    );
    let rebound_bilateral_invocation_sha256 =
        chio_runtime_core::bilateral_invocation_binding_sha256(&bilateral_invocation)?;
    assert_eq!(
        rebound_bilateral_invocation_sha256,
        bilateral_invocation_binding_sha256
    );
    let bilateral_invocation_sha256 = bilateral_invocation_binding_sha256;
    let bilateral_dsse = sign_chio_bilateral_dsse_envelope(BilateralDsseLocalSigningInput {
        invocation: BilateralDsseInvocationInput {
            receipt: &receipt,
            org_a_kernel_id: &bilateral_invocation.signer_kernel_ids[0],
            org_b_kernel_id: &bilateral_invocation.signer_kernel_ids[1],
            tool_name: "close_account",
            timestamp_unix_ms: 1_800_000_001_000,
            extensions: BilateralPredicateExtensions {
                capability_lease_ref: Some(CapabilityLeaseRef {
                    lease_id: "lease-live-1".to_string(),
                    issuer: bilateral_invocation.signer_kernel_ids[0].clone(),
                    expires_at_unix_ms: 1_800_003_600_000,
                    scope_digest: None,
                }),
                policy_evaluation_summary: Some(policy_evaluation_summary),
                governance_receipt_ref: Some(GovernanceReceiptRef {
                    receipt_id: "gov-live-1".to_string(),
                    kernel_id: bilateral_invocation.signer_kernel_ids[1].clone(),
                    digest: HashRecord {
                        alg: "sha256".to_string(),
                        value: "d".repeat(64),
                    },
                }),
                consistency_anchor: Some("anchor-live".to_string()),
                consistency_model: Some(bilateral_invocation.consistency_model.clone()),
                cross_org_visibility: Some("treaty_only".to_string()),
                treaty_binding_ref: Some(TreatyBindingRef {
                    treaty_id: bilateral_invocation.treaty_id.clone(),
                    treaty_scope_sha256: treaty_scope_sha256.clone(),
                    ladder_intersection_sha256: ladder_intersection_sha256.clone(),
                    admission_report_sha256: "6".repeat(64),
                    continuation_sha256: continuation_sha256.clone(),
                    lineage_bundle_sha256: lineage_bundle_sha256.clone(),
                    action_class_id: bilateral_invocation.action_class_id.clone(),
                    consistency_model: bilateral_invocation.consistency_model.clone(),
                    request_sha256: bilateral_invocation.request_sha256.clone(),
                    outcome_sha256: bilateral_invocation.outcome_sha256.clone(),
                    local_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
                    remote_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
                    lease_refs: vec!["lease-live-1".to_string()],
                    governance_refs: vec!["gov-live-1".to_string()],
                    signer_kernel_ids: bilateral_invocation.signer_kernel_ids.clone(),
                }),
            },
        },
        org_a_signer: &signer_a,
        org_b_signer: &signer_b,
    })?;
    let bilateral_dsse_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&bilateral_dsse)?,
    );
    Ok(TreatyRuntimeFixture {
        treaty_scope,
        treaty_scope_sha256,
        ladder_intersection,
        ladder_intersection_sha256,
        continuation,
        continuation_sha256,
        lineage_bundle,
        lineage_bundle_sha256,
        bilateral_invocation,
        bilateral_invocation_sha256,
        bilateral_dsse_id: "bilateral-dsse-runtime-1".to_string(),
        bilateral_dsse,
        bilateral_dsse_sha256,
    })
}

fn insert_treaty_runtime_fixture(
    store: &SqliteRuntimeOrchestrationStore,
    fixture: &TreatyRuntimeFixture,
) -> Result<(), Box<dyn std::error::Error>> {
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
    Ok(())
}

fn deny_policy_bilateral_dsse(
    envelope: &DsseEnvelope,
) -> Result<DsseEnvelope, Box<dyn std::error::Error>> {
    let (mut statement, _) = envelope.decode_statement()?;
    let summary = statement
        .predicate
        .policy_evaluation_summary
        .as_mut()
        .ok_or_else(|| io::Error::other("fixture DSSE missing policy summary"))?;
    summary.server_b_verdict.verdict = "deny".to_string();
    summary.joint_disposition = Some("deny".to_string());
    Ok(DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            statement.canonical_bytes()?,
        ),
        signatures: envelope.signatures.clone(),
    })
}

fn treaty_runtime_context(fixture: &TreatyRuntimeFixture) -> serde_json::Value {
    serde_json::json!({
        "treatyScopeId": fixture.treaty_scope.treaty_id,
        "treatyScopeSha256": fixture.treaty_scope_sha256,
        "ladderIntersectionId": fixture.ladder_intersection.intersection_id,
        "ladderIntersectionSha256": fixture.ladder_intersection_sha256,
        "actionClassId": "workflow.destructive.vendor_call",
        "crossKernelContinuation": {
            "id": fixture.continuation.continuation_id,
            "sha256": fixture.continuation_sha256
        },
        "receiptLineageBundle": {
            "id": fixture.lineage_bundle.bundle_id,
            "sha256": fixture.lineage_bundle_sha256
        },
        "bilateralInvocation": {
            "id": fixture.bilateral_invocation.invocation_id,
            "sha256": fixture.bilateral_invocation_sha256
        },
        "bilateralDsse": {
            "id": fixture.bilateral_dsse_id,
            "sha256": fixture.bilateral_dsse_sha256
        }
    })
}

fn treaty_runtime_request(
    args: serde_json::Value,
    bundle_hash: String,
    treaty_context: serde_json::Value,
) -> Result<ToolCallRequest, Box<dyn std::error::Error>> {
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
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: Some("kernel.buyer".to_string()),
        declassification_grant: None,
    };
    request.governed_intent = Some(GovernedTransactionIntent::tool_invocation(
        GovernedToolInvocationIntentBody {
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
                "chioTreaty": treaty_context
            })),
        },
    ));
    Ok(request)
}

fn chio_swarm_runtime_request(
    args: serde_json::Value,
    bundle_hash: String,
    swarm_context: serde_json::Value,
) -> Result<ToolCallRequest, Box<dyn std::error::Error>> {
    let cap = capability("cap-live-1")?;
    Ok(ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent::tool_invocation(
            GovernedToolInvocationIntentBody {
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
                    "chioSwarm": swarm_context
                })),
            },
        )),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    })
}

fn swarm_runtime_context(
    bundle: &SwarmAuthorityBundle,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::json!({
        "taskGraph": {
            "id": &bundle.task_graph.graph_id,
            "sha256": canonical_test_hash(&bundle.task_graph)?
        },
        "continuationToken": {
            "id": &bundle.continuation_tokens[0].token_id,
            "sha256": canonical_test_hash(&bundle.continuation_tokens[0])?
        },
        "routePlanReceipt": {
            "id": &bundle.route_plan_receipts[0].route_plan_id,
            "sha256": canonical_test_hash(&bundle.route_plan_receipts[0])?
        },
        "delegationWitness": {
            "id": &bundle.witness_chains[0].chain_id,
            "sha256": canonical_test_hash(&bundle.witness_chains[0])?
        },
        "joinReceipt": {
            "id": &bundle.join_receipts[0].join_id,
            "sha256": canonical_test_hash(&bundle.join_receipts[0])?
        },
        "revocationEpoch": {
            "id": &bundle.revocation_epoch.epoch_id,
            "sha256": canonical_test_hash(&bundle.revocation_epoch)?
        },
        "budgetPool": {
            "id": &bundle.budget_pool.pool_id,
            "sha256": canonical_test_hash(&bundle.budget_pool)?
        }
    }))
}

fn swarm_route_metadata() -> serde_json::Value {
    serde_json::json!({
        "route": {
            "bridge": "mcp",
            "protocolTarget": "mcp://provider-runtime",
            "selectedRoute": "mcp:task-child-a"
        }
    })
}

fn runtime_swarm_bundle(
    stale_continuation: bool,
) -> Result<SwarmAuthorityBundle, Box<dyn std::error::Error>> {
    let parent_scope = runtime_swarm_scope(3);
    let child_scope = runtime_swarm_scope(1);
    let parent_scope_hash = scope_hash(&parent_scope)?;
    let child_scope_hash = scope_hash(&child_scope)?;
    let scope_subset_proof = compute_attenuation_witness(&parent_scope, &child_scope)?;
    let revocation_root = runtime_swarm_revocation_root(&[], &[])?;

    let mut task_graph = SwarmTaskGraph {
        schema: CHIO_SWARM_TASK_GRAPH_SCHEMA.to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        root_transaction_ref: "passport-runtime".to_string(),
        planner_subject: "did:chio:planner".to_string(),
        issuer: swarm_witness_issuer(),
        signature: String::new(),
        created_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        max_depth: 1,
        max_fanout: 2,
        multi_hop_witness_chains: false,
        nodes: vec![
            SwarmGraphNode {
                task_id: "task-root".to_string(),
                parent_task_id: None,
                route_plan_ref: None,
                continuation_token_ref: None,
                budget_allocation_ref: None,
                scope_hash: parent_scope_hash.clone(),
                depth: 0,
            },
            SwarmGraphNode {
                task_id: "task-child-a".to_string(),
                parent_task_id: Some("task-root".to_string()),
                route_plan_ref: Some("route-child-a".to_string()),
                continuation_token_ref: Some("continuation-child-a".to_string()),
                budget_allocation_ref: Some("budget-child-a".to_string()),
                scope_hash: child_scope_hash.clone(),
                depth: 1,
            },
            SwarmGraphNode {
                task_id: "task-child-b".to_string(),
                parent_task_id: Some("task-root".to_string()),
                route_plan_ref: Some("route-child-b".to_string()),
                continuation_token_ref: Some("continuation-child-b".to_string()),
                budget_allocation_ref: Some("budget-child-b".to_string()),
                scope_hash: child_scope_hash.clone(),
                depth: 1,
            },
        ],
        edges: vec![
            SwarmGraphEdge {
                from_task_id: "task-root".to_string(),
                to_task_id: "task-child-a".to_string(),
                edge_type: "delegates".to_string(),
            },
            SwarmGraphEdge {
                from_task_id: "task-root".to_string(),
                to_task_id: "task-child-b".to_string(),
                edge_type: "delegates".to_string(),
            },
        ],
        joins: vec![SwarmGraphJoin {
            join_id: "join-child-results".to_string(),
            parent_task_ids: vec!["task-child-a".to_string(), "task-child-b".to_string()],
            next_task_id: "task-root".to_string(),
        }],
        budget_pool_ref: "budget-pool-runtime".to_string(),
        revocation_epoch_ref: "revocation-epoch-runtime".to_string(),
        route_plan_refs: vec!["route-child-a".to_string(), "route-child-b".to_string()],
    };
    task_graph.signature = sign_swarm_task_graph(&task_graph, &swarm_witness_keypair())?;
    let graph_sha256 = canonical_test_hash(&task_graph)?;
    let mut continuation_a = runtime_swarm_continuation(
        "continuation-child-a",
        "task-child-a",
        "route-child-a",
        "budget-child-a",
        &graph_sha256,
        &revocation_root,
        stale_continuation,
    )?;
    let mut continuation_b = runtime_swarm_continuation(
        "continuation-child-b",
        "task-child-b",
        "route-child-b",
        "budget-child-b",
        &graph_sha256,
        &revocation_root,
        false,
    )?;
    task_graph.nodes[1].continuation_token_ref = Some(continuation_a.token_id.clone());
    task_graph.nodes[2].continuation_token_ref = Some(continuation_b.token_id.clone());
    task_graph.signature = sign_swarm_task_graph(&task_graph, &swarm_witness_keypair())?;
    continuation_a.graph_sha256 = canonical_test_hash(&task_graph)?;
    continuation_a.signature =
        sign_swarm_continuation_token(&continuation_a, &swarm_witness_keypair())?;
    continuation_b.graph_sha256 = canonical_test_hash(&task_graph)?;
    continuation_b.signature =
        sign_swarm_continuation_token(&continuation_b, &swarm_witness_keypair())?;

    let witness_chain_a = runtime_swarm_witness_chain(
        "witness-child-a",
        "task-child-a",
        &parent_scope_hash,
        &child_scope_hash,
        scope_subset_proof.clone(),
    )?;
    let witness_chain_b = runtime_swarm_witness_chain(
        "witness-child-b",
        "task-child-b",
        &parent_scope_hash,
        &child_scope_hash,
        scope_subset_proof,
    )?;
    continuation_a.witness_chain_ref = Some(witness_chain_a.chain_id.clone());
    continuation_a.witness_chain_sha256 = Some(canonical_test_hash(&witness_chain_a)?);
    continuation_a.signature =
        sign_swarm_continuation_token(&continuation_a, &swarm_witness_keypair())?;
    continuation_b.witness_chain_ref = Some(witness_chain_b.chain_id.clone());
    continuation_b.witness_chain_sha256 = Some(canonical_test_hash(&witness_chain_b)?);
    continuation_b.signature =
        sign_swarm_continuation_token(&continuation_b, &swarm_witness_keypair())?;

    let mut join_receipt = SwarmJoinReceipt {
        schema: CHIO_SWARM_JOIN_RECEIPT_SCHEMA.to_string(),
        join_id: "join-child-results".to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        chain_id: "swarm-chain-swarm-graph-runtime".to_string(),
        parent_set_hash: runtime_swarm_join_parent_set_hash(
            "swarm-chain-swarm-graph-runtime",
            &["receipt-child-a", "receipt-child-b"],
        )?,
        dag_ordinal: 2,
        hlc_unix_ms: 1_800_000_000_500,
        parent_task_receipts: vec![
            SwarmJoinParentReceipt {
                task_id: "task-child-a".to_string(),
                receipt_id: "receipt-child-a".to_string(),
            },
            SwarmJoinParentReceipt {
                task_id: "task-child-b".to_string(),
                receipt_id: "receipt-child-b".to_string(),
            },
        ],
        expected_parent_receipt_ids: vec![
            "receipt-child-a".to_string(),
            "receipt-child-b".to_string(),
        ],
        actual_parent_receipt_ids: vec![
            "receipt-child-a".to_string(),
            "receipt-child-b".to_string(),
        ],
        join_predicate: "all_success".to_string(),
        result_digest: sha256_hex(b"joined-child-results"),
        next_task_id: "task-root".to_string(),
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    join_receipt.signature = sign_swarm_join_receipt(&join_receipt, &swarm_witness_keypair())?;

    let mut revocation_epoch = SwarmRevocationEpoch {
        schema: CHIO_SWARM_REVOCATION_EPOCH_SCHEMA.to_string(),
        epoch_id: "revocation-epoch-runtime".to_string(),
        root_hash: revocation_root,
        issued_at_unix_ms: 1_800_000_000_000,
        valid_until_unix_ms: 1_800_003_600_000,
        revoked_subjects: Vec::new(),
        revoked_task_ids: Vec::new(),
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    revocation_epoch.signature =
        sign_swarm_revocation_epoch(&revocation_epoch, &swarm_witness_keypair())?;

    let bundle = SwarmAuthorityBundle {
        task_graph,
        continuation_tokens: vec![continuation_a, continuation_b],
        witness_chains: vec![witness_chain_a, witness_chain_b],
        join_receipts: vec![join_receipt],
        route_plan_receipts: vec![
            runtime_swarm_route_plan_receipt(
                "route-child-a",
                "task-child-a",
                "mcp",
                "mcp://provider-runtime",
                b"runtime-swarm-candidates",
            )?,
            runtime_swarm_route_plan_receipt(
                "route-child-b",
                "task-child-b",
                "a2a",
                "a2a://provider-runtime",
                b"runtime-swarm-candidates-b",
            )?,
        ],
        budget_pool: SwarmBudgetPool {
            schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.to_string(),
            pool_id: "budget-pool-runtime".to_string(),
            graph_id: "swarm-graph-runtime".to_string(),
            currency: "USD".to_string(),
            total_units: 10_000,
            allocations: vec![
                SwarmBudgetAllocation {
                    allocation_id: "budget-child-a".to_string(),
                    task_id: "task-child-a".to_string(),
                    dimension_id: "usd_minor".to_string(),
                    state: SwarmBudgetAllocationState::Active,
                    max_units: 1_000,
                    reserved_units: 0,
                    active_units: 1_000,
                    consumed_units: 0,
                    released_units: 0,
                    reversed_units: 0,
                },
                SwarmBudgetAllocation {
                    allocation_id: "budget-child-b".to_string(),
                    task_id: "task-child-b".to_string(),
                    dimension_id: "usd_minor".to_string(),
                    state: SwarmBudgetAllocationState::Active,
                    max_units: 1_000,
                    reserved_units: 0,
                    active_units: 1_000,
                    consumed_units: 0,
                    released_units: 0,
                    reversed_units: 0,
                },
            ],
        },
        revocation_epoch,
        terminal_receipts: vec![runtime_swarm_terminal_graph_receipt()?],
        now_unix_ms: 1_800_000_001_000,
    };

    if !stale_continuation {
        verify_swarm_authority_bundle(&bundle, &trusted_swarm_witness_keys()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("runtime swarm fixture invalid: {}", error.runtime_detail()),
            )
        })?;
    }

    Ok(bundle)
}

fn runtime_swarm_continuation(
    token_id: &str,
    child_task_id: &str,
    route_plan_receipt_id: &str,
    budget_allocation_id: &str,
    graph_sha256: &str,
    revocation_epoch_root_hash: &str,
    stale: bool,
) -> Result<SwarmContinuationToken, Box<dyn std::error::Error>> {
    let mut token = SwarmContinuationToken {
        schema: CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA.to_string(),
        token_id: token_id.to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        child_task_id: child_task_id.to_string(),
        parent_task_id: Some("task-root".to_string()),
        join_receipt_id: None,
        parent_receipt_ids: vec!["receipt-root".to_string()],
        graph_sha256: graph_sha256.to_string(),
        route_plan_receipt_id: route_plan_receipt_id.to_string(),
        budget_allocation_id: budget_allocation_id.to_string(),
        witness_chain_ref: None,
        witness_chain_sha256: None,
        revocation_epoch_ref: "revocation-epoch-runtime".to_string(),
        revocation_epoch_root_hash: revocation_epoch_root_hash.to_string(),
        session_anchor_ref: "session-anchor-runtime".to_string(),
        nonce: format!("nonce-{child_task_id}"),
        mode: SwarmContinuationMode::SingleUse,
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: if stale {
            1_800_000_000_999
        } else {
            1_800_003_600_000
        },
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    token.signature = sign_swarm_continuation_token(&token, &swarm_witness_keypair())?;
    Ok(token)
}

fn runtime_swarm_witness_chain(
    chain_id: &str,
    child_task_id: &str,
    parent_scope_hash: &str,
    child_scope_hash: &str,
    scope_subset_proof: chio_core_types::capability::attenuation::AttenuationWitness,
) -> Result<SwarmDelegationWitnessChain, Box<dyn std::error::Error>> {
    let mut chain = SwarmDelegationWitnessChain {
        schema: CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA.to_string(),
        chain_id: chain_id.to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        parent_task_id: "task-root".to_string(),
        child_task_id: child_task_id.to_string(),
        hops: vec![SwarmDelegationWitnessHop {
            parent_capability_digest: sha256_hex(b"parent-capability"),
            child_capability_digest: sha256_hex(child_task_id.as_bytes()),
            parent_scope_hash: parent_scope_hash.to_string(),
            child_scope_hash: child_scope_hash.to_string(),
            attenuation_rule_id: "rule-subset-tool-invocation".to_string(),
            scope_subset_proof,
            expires_at_unix_ms: 1_800_003_600_000,
            issuer: swarm_witness_issuer(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: String::new(),
        }],
    };
    chain.hops[0].witness_signature =
        sign_swarm_delegation_witness_hop(&chain, &chain.hops[0], &swarm_witness_keypair())?;
    Ok(chain)
}

fn runtime_swarm_scope(max_invocations: u32) -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: Some(max_invocations),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn swarm_witness_keypair() -> Keypair {
    Keypair::from_seed(&[31u8; 32])
}

fn trusted_swarm_witness_keys() -> Vec<PublicKey> {
    vec![swarm_witness_keypair().public_key()]
}

fn swarm_witness_issuer() -> String {
    format!("did:chio:{}", swarm_witness_keypair().public_key().to_hex())
}

fn runtime_swarm_join_parent_set_hash(
    chain_id: &str,
    receipt_ids: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut sorted_receipt_ids = receipt_ids.to_vec();
    sorted_receipt_ids.sort();
    let body = serde_json::json!({
        "chainId": chain_id,
        "parentReceiptIds": sorted_receipt_ids,
    });
    Ok(sha256_hex(&canonical_json_bytes(&body)?))
}

fn runtime_swarm_route_plan_receipt(
    route_plan_id: &str,
    task_id: &str,
    bridge_id: &str,
    protocol_target: &str,
    candidate_seed: &[u8],
) -> Result<SwarmRoutePlanReceipt, Box<dyn std::error::Error>> {
    let mut receipt = SwarmRoutePlanReceipt {
        schema: CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA.to_string(),
        route_plan_id: route_plan_id.to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        task_id: task_id.to_string(),
        selected_route: format!("{bridge_id}:{task_id}"),
        candidate_set_digest: sha256_hex(candidate_seed),
        registry_snapshot_hash: sha256_hex(b"runtime-swarm-registry"),
        bridge_id: bridge_id.to_string(),
        protocol_target: protocol_target.to_string(),
        egress_contract_id: format!("{bridge_id}:egress-contract-{task_id}"),
        egress_constraints: vec!["deny-private-network".to_string()],
        attenuation_decision: "accepted".to_string(),
        policy_digest: sha256_hex(b"swarm-route-policy"),
        expires_at_unix_ms: 1_800_003_600_000,
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    receipt.signature = sign_swarm_route_plan_receipt(&receipt, &swarm_witness_keypair())?;
    Ok(receipt)
}

fn runtime_swarm_terminal_graph_receipt(
) -> Result<SwarmTerminalGraphReceipt, Box<dyn std::error::Error>> {
    let mut receipt = SwarmTerminalGraphReceipt {
        schema: CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA.to_string(),
        receipt_id: "terminal-swarm-runtime".to_string(),
        graph_id: "swarm-graph-runtime".to_string(),
        chain_id: "swarm-chain-swarm-graph-runtime".to_string(),
        terminal_task_ids: vec!["task-root".to_string()],
        completed_task_ids: vec![
            "task-root".to_string(),
            "task-child-a".to_string(),
            "task-child-b".to_string(),
        ],
        join_receipt_ids: vec!["join-child-results".to_string()],
        route_plan_receipt_ids: vec!["route-child-a".to_string(), "route-child-b".to_string()],
        budget_pool_id: "budget-pool-runtime".to_string(),
        budget_rollups: vec![SwarmTerminalBudgetRollup {
            dimension_id: "usd_minor".to_string(),
            reserved_units: 0,
            active_units: 2_000,
            consumed_units: 0,
            released_units: 0,
            reversed_units: 0,
            total_units: 2_000,
        }],
        revocation_epoch_ref: "revocation-epoch-runtime".to_string(),
        result_digest: sha256_hex(b"joined-child-results"),
        completed_at_unix_ms: 1_800_000_000_500,
        issuer: swarm_witness_issuer(),
        signature: String::new(),
    };
    receipt.signature = sign_swarm_terminal_graph_receipt(&receipt, &swarm_witness_keypair())?;
    Ok(receipt)
}

fn canonical_test_hash<T: serde::Serialize>(
    value: &T,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

fn runtime_swarm_revocation_root(
    revoked_subjects: &[&str],
    revoked_task_ids: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut revoked_subjects = revoked_subjects.to_vec();
    let mut revoked_task_ids = revoked_task_ids.to_vec();
    revoked_subjects.sort_unstable();
    revoked_task_ids.sort_unstable();
    canonical_test_hash(&serde_json::json!({
        "revokedSubjects": revoked_subjects,
        "revokedTaskIds": revoked_task_ids,
    }))
}
