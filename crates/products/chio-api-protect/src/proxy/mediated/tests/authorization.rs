use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_authorization_rejects_non_durable_admission() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let capability =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let capability_id = capability.id.clone();
    let state = mediated_test_state_with_durable_admission(
        signer,
        MediationBudget::Configured(Arc::clone(&budget)),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        None,
        None,
        None,
    );
    let body = serde_json::json!({
        "capability": capability,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" }
    });

    let (status, response) = post_evaluate(state, &body).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response["error"],
        "chio_mediation_requires_durable_admission"
    );
    assert_eq!(
        response["message"],
        "mediated authorization requires a durable admission store"
    );
    assert!(budget.get_usage(&capability_id, 0).test_unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_authorization_reserves_hold_and_mints_non_authoritative_receipt() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let cap_id = cap.id.clone();
    let signer_pub = signer.public_key();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());

    let body = serde_json::json!({
        "capability": cap,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" }
    });
    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(json["status"], "reserved");
    assert!(
        json["execution_nonce"].is_object(),
        "authorization must mint an execution nonce object"
    );
    assert_eq!(
        json["receipt"]["decision"]["verdict"], "incomplete",
        "a reserved authorization is not a completed-spend decision"
    );

    let budget_authority = &json["receipt"]["metadata"]["budget_authority"];
    assert_eq!(budget_authority["authorize"]["exposure_units"], 100);
    assert!(
        budget_authority.get("terminal").is_none(),
        "a reserved (not reconciled) hold must carry no terminal disposition"
    );

    let receipt: ChioReceipt = serde_json::from_value(json["receipt"].clone()).unwrap();
    let nonce: SignedExecutionNonce =
        serde_json::from_value(json["execution_nonce"].clone()).unwrap();
    assert!(
        is_authoritative_spend_receipt(&receipt, &[signer_pub], &nonce).is_err(),
        "a reserved authorization receipt must not be an authoritative spend"
    );

    let usage = budget.get_usage(&cap_id, 0).unwrap();
    let usage = usage.expect("the reserved hold must be recorded in the budget store");
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        100,
        "the pre-execution hold must remain reserved (open), not reversed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_durable_reuse_guard_rejects_reused_request_id_across_capabilities() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap_a =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let cap_b =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    assert_ne!(
        cap_a.id, cap_b.id,
        "the two capabilities must carry distinct ids"
    );

    let state_before = mediated_test_state(signer.clone(), durable.clone(), Vec::new());
    let body_a = serde_json::json!({
        "capability": cap_a,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "request_id": "shared-request-id",
        "parameters": { "invoice": "inv-1" }
    });
    let (status_a, json_a) = post_evaluate(Arc::clone(&state_before), &body_a).await;
    assert_eq!(status_a, StatusCode::OK, "{json_a}");
    assert_eq!(json_a["status"], "reserved");

    let original_operation = json_a["receipt"]["metadata"]["admission_operation"]["operation_id"]
        .as_str()
        .test_unwrap()
        .to_owned();
    let original_usage = budget.get_usage(&cap_a.id, 0).test_unwrap();
    drop(state_before);
    drop(kernel);
    drop(budget);
    drop(durable);
    let durable = reopen_durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let state_after = mediated_test_state(signer, durable.clone(), Vec::new());

    let body_b = serde_json::json!({
        "capability": cap_b,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "request_id": "shared-request-id",
        "parameters": { "invoice": "inv-2" }
    });
    let (status_b, json_b) = post_evaluate(Arc::clone(&state_after), &body_b).await;
    assert_eq!(status_b, StatusCode::OK, "{json_b}");
    assert_eq!(json_b["status"], "deny");
    assert_eq!(
        json_b["receipt"]["decision"]["reason"],
        format!("durable admission failed: request id conflicts with retained operation {original_operation}")
    );
    assert_eq!(budget.get_usage(&cap_a.id, 0).test_unwrap(), original_usage);
    assert!(budget.get_usage(&cap_b.id, 0).test_unwrap().is_none());

    let body_fresh = serde_json::json!({
        "capability": cap_b,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "request_id": "fresh-request-id",
        "parameters": { "invoice": "inv-3" }
    });
    let (status_fresh, json_fresh) = post_evaluate(Arc::clone(&state_after), &body_fresh).await;
    assert_eq!(status_fresh, StatusCode::OK, "{json_fresh}");
    assert_eq!(json_fresh["status"], "reserved");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_reserved_hold_blocks_oversubscription() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
    let state = mediated_test_state(signer, durable.clone(), Vec::new());

    let body = serde_json::json!({
        "capability": cap,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" }
    });

    let (_, first) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(first["status"], "reserved");

    let (_, second) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(
        second["status"], "deny",
        "the reserved hold must block a second authorization past max_total_cost"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_revoked_capability_is_rejected() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let cap_id = cap.id.clone();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());
    state
        .revoked_capability_ids
        .lock()
        .await
        .insert(cap_id.clone());

    let body = serde_json::json!({
        "capability": cap,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" }
    });
    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_ne!(json["status"], "reserved");
    assert_eq!(json["error"], "chio_capability_revoked");

    let usage = budget.get_usage(&cap_id, 0).unwrap();
    assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
}

fn delegated_child_capability(
    issuer: &Keypair,
    delegator: &Keypair,
    subject: &Keypair,
    ancestor_id: &str,
    server: &str,
    tool: &str,
) -> CapabilityToken {
    use chio_core_types::capability::attenuation::{DelegationLink, DelegationLinkBody};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .test_unwrap()
        .as_secs();
    let grant = ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: 1000,
            currency: "USD".to_string(),
        }),
        dpop_required: None,
    };
    let scope = ChioScope {
        grants: vec![grant],
        ..ChioScope::default()
    };
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: ancestor_id.to_string(),
            delegator: delegator.public_key(),
            delegatee: subject.public_key(),
            attenuations: vec![],
            timestamp: now,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        delegator,
    )
    .test_unwrap();
    let body = CapabilityTokenBody {
        id: uuid::Uuid::now_v7().to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
        issued_at: now,
        expires_at: now + 3600,
        delegation_chain: vec![link],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, issuer).test_unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_revoked_delegation_ancestor_rejects_delegated_child() {
    let signer = Keypair::generate();
    let root = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let ancestor_id = "cap-root-revoked".to_string();
    let child =
        delegated_child_capability(&signer, &root, &agent, &ancestor_id, "cost-srv", "compute");
    let child_id = child.id.clone();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());
    state
        .revoked_capability_ids
        .lock()
        .await
        .insert(ancestor_id.clone());
    assert!(
        !state
            .revoked_capability_ids
            .lock()
            .await
            .contains(&child_id),
        "the presented leaf id must not itself be revoked"
    );

    let body = serde_json::json!({
        "capability": child,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" }
    });
    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_ne!(json["status"], "reserved");
    assert_eq!(json["error"], "chio_capability_revoked");

    let usage = budget.get_usage(&child_id, 0).unwrap();
    assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_route_honors_a_durable_only_revocation() {
    let signer = Keypair::generate();
    let root = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let child =
        delegated_child_capability(&signer, &root, &agent, "cap-root", "cost-srv", "compute");
    let child_id = child.id.clone();

    let revocations: Arc<dyn chio_kernel::RevocationStore> =
        Arc::new(chio_kernel::InMemoryRevocationStore::new());
    chio_kernel::RevocationStore::revoke(revocations.as_ref(), &child_id).test_unwrap();

    let state = mediated_test_state_core(
        signer,
        durable.clone(),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        None,
        None,
        Some(Arc::clone(&revocations)),
    );
    assert!(
        !state
            .revoked_capability_ids
            .lock()
            .await
            .contains(&child_id),
        "the in-memory release set must not carry the durable-only revocation"
    );

    let body = serde_json::json!({
        "capability": child,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" }
    });
    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["error"], "chio_capability_revoked");

    let usage = budget.get_usage(&child_id, 0).unwrap();
    assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_authorization_admits_caller_named_server_id() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "arbitrary-srv", "invoke", 100, 1000, "USD");
    let state = mediated_test_state(signer, durable.clone(), Vec::new());
    let body = serde_json::json!({
        "capability": cap,
        "tool_server": "arbitrary-srv",
        "tool_name": "invoke",
        "parameters": {}
    });
    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "reserved");
    assert!(json["execution_nonce"].is_object());
    assert_eq!(json["receipt"]["decision"]["verdict"], "incomplete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_trusts_configured_external_capability_issuers() {
    let signer = Keypair::generate();
    let external_signer = Keypair::generate();
    let agent = Keypair::generate();

    let issuer_budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let issuer = issuing_kernel(&external_signer, issuer_budget, &[]);
    let cap =
        issue_cost_bearing_capability(&issuer, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();

    let trusting_directory = tempfile::tempdir().test_unwrap();
    let trusting_authority = durable_admission_stores(trusting_directory.path());
    let trusting_state = mediated_test_state(
        signer.clone(),
        trusting_authority,
        vec![external_signer.public_key()],
    );
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": {}
    });
    let (_, json) = post_evaluate(trusting_state, &body).await;
    assert_eq!(json["status"], "reserved");
    assert!(json["execution_nonce"].is_object());

    let untrusting_directory = tempfile::tempdir().test_unwrap();
    let untrusting_authority = durable_admission_stores(untrusting_directory.path());
    let untrusting_state = mediated_test_state(signer, untrusting_authority, Vec::new());
    let (_, json) = post_evaluate(untrusting_state, &body).await;
    assert_eq!(json["status"], "deny");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_deny_leaves_committed_cost_zero() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 40, "USD");
    let cap_id = cap.id.clone();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());
    let body = serde_json::json!({ "capability": cap, "tool_server": "cost-srv",
        "tool_name": "compute", "parameters": {} });
    let (_, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(json["status"], "deny");
    assert_ne!(json["receipt"]["decision"]["verdict"], "allow");
    let usage = budget.get_usage(&cap_id, 0).unwrap();
    assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_governed_capability_requires_retained_approval() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_governed_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD", 50);
    let cap_value = serde_json::to_value(&cap).unwrap();
    let approver = signer.clone();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());

    let bare_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" }
    });
    let (_, denied) = post_evaluate(Arc::clone(&state), &bare_body).await;
    assert_eq!(
        denied["status"], "deny",
        "a governed grant without a forwarded intent must be denied"
    );

    let request_id = "req-governed-1";
    let intent = governed_intent("intent-gov-1", "cost-srv", "compute", 100, "USD");
    let approval = governed_approval_token(&approver, &agent.public_key(), &intent, request_id);
    let governed_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" },
        "request_id": request_id,
        "governed_intent": intent,
        "approval_token": approval
    });
    let (status, rejected) = post_evaluate(Arc::clone(&state), &governed_body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        rejected["message"],
        "use approval_id to redeem the retained server-built approval"
    );
    assert!(budget.get_usage(&cap.id, 0).test_unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_governed_direct_token_rejected_even_with_payment_adapter() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_governed_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD", 50);
    let cap_value = serde_json::to_value(&cap).unwrap();
    let approver = signer.clone();
    let state = mediated_test_state_core(
        signer,
        durable.clone(),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        None,
        Some(Box::new(chio_kernel::payment::SimPaymentAdapter::new())),
        None,
    );

    let request_id = "req-mustprepay-adapter";
    let intent = governed_mustprepay_intent("intent-prepay-1", "cost-srv", "compute", 100, "USD");
    let approval = governed_approval_token(&approver, &agent.public_key(), &intent, request_id);
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" },
        "request_id": request_id,
        "governed_intent": intent,
        "approval_token": approval,
    });
    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json["message"],
        "use approval_id to redeem the retained server-built approval"
    );
    assert!(budget.get_usage(&cap.id, 0).test_unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_governed_direct_token_rejected_without_payment_adapter() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_governed_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD", 50);
    let cap_id = cap.id.clone();
    let cap_value = serde_json::to_value(&cap).unwrap();
    let approver = signer.clone();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());

    let request_id = "req-mustprepay-no-adapter";
    let intent = governed_mustprepay_intent("intent-prepay-2", "cost-srv", "compute", 100, "USD");
    let approval = governed_approval_token(&approver, &agent.public_key(), &intent, request_id);
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" },
        "request_id": request_id,
        "governed_intent": intent,
        "approval_token": approval,
    });
    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json["message"],
        "use approval_id to redeem the retained server-built approval"
    );
    assert!(budget.get_usage(&cap_id, 0).test_unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_dpop_requires_operation_owned_custody() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_dpop_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());
    let params = serde_json::json!({ "invoice": "inv-1" });

    let bare_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params.clone()
    });
    let (_, denied) = post_evaluate(Arc::clone(&state), &bare_body).await;
    assert_eq!(
        denied["status"], "deny",
        "a dpop_required grant without a proof must be denied"
    );

    let proof = dpop_proof_for(&agent, &cap, "cost-srv", "compute", &params);
    let dpop_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "dpop_proof": proof
    });
    let (_, refused) = post_evaluate(Arc::clone(&state), &dpop_body).await;
    assert_eq!(refused["status"], "deny");
    assert_eq!(
        refused["receipt"]["decision"]["reason"],
        "caller execution requires authenticated start and operation-owned credential custody"
    );
    assert!(refused["execution_nonce"].is_null());
    assert!(budget.get_usage(&cap.id, 0).test_unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_reused_request_id_is_conflict() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());

    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" },
        "request_id": "fixed-req-id",
    });
    let (status, first) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["status"], "reserved");

    let (status, second) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_ne!(second["status"], "reserved");
    assert_eq!(second["error"], "chio_request_id_reused");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_authorization_requires_caller_delivery_control_token() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let cap_id = cap.id.clone();
    let state = mediated_test_state_with_control_token(signer, durable.clone(), Vec::new(), None);
    let body = serde_json::json!({
        "capability": cap,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" }
    });
    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json["error"], "chio_mediation_requires_control_token");
    assert_eq!(
        json["message"],
        "mediated authorization requires a configured sidecar-control token for signed caller delivery"
    );
    assert_ne!(json["status"], "reserved");
    assert!(
        json["execution_nonce"].is_null(),
        "a fail-closed rejection must not mint a reserved nonce"
    );

    let usage = budget.get_usage(&cap_id, 0).unwrap();
    assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_authorization_rejects_blank_reconcile_control_token() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let cap_id = cap.id.clone();
    let state = mediated_test_state_with_control_token(
        signer,
        durable.clone(),
        Vec::new(),
        Some("   ".to_string()),
    );
    let body = serde_json::json!({
        "capability": cap,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" }
    });
    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json["error"], "chio_mediation_requires_control_token");
    assert_eq!(
        json["message"],
        "mediated authorization requires a configured sidecar-control token for signed caller delivery"
    );
    assert_ne!(json["status"], "reserved");
    assert!(
        json["execution_nonce"].is_null(),
        "a fail-closed rejection must not mint a reserved nonce"
    );

    let usage = budget.get_usage(&cap_id, 0).unwrap();
    assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_durable_hold_rejects_request_id_reuse_across_restart() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();

    let before = mediated_test_state(signer.clone(), durable.clone(), Vec::new());
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" },
        "request_id": "restart-req",
    });
    let (status, authorized) = post_evaluate(Arc::clone(&before), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(authorized["status"], "reserved");

    let usage = budget.get_usage(&cap.id, 0).test_unwrap();
    drop(before);
    drop(kernel);
    drop(budget);
    drop(durable);
    let durable = reopen_durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let after = mediated_test_state(signer, durable.clone(), Vec::new());

    let (status, replay) = post_evaluate(Arc::clone(&after), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["status"], "deny");
    assert_ne!(replay["status"], "reserved");
    assert!(
        replay["execution_nonce"].is_null(),
        "no second nonce is minted against the open hold"
    );
    assert_eq!(
        replay["receipt"]["decision"]["reason"],
        "durable admission failed: execution nonce preflight cannot replay an operation in state ReadyToDispatch"
    );
    assert_eq!(budget.get_usage(&cap.id, 0).test_unwrap(), usage);

    let fresh_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-2" },
        "request_id": "restart-req-fresh",
    });
    let (status, fresh) = post_evaluate(after, &fresh_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fresh["status"], "reserved");
    assert!(fresh["execution_nonce"].is_object());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_report_preserves_spent_budget_after_settlement() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let signer_pub = signer.public_key();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());
    let params = serde_json::json!({ "invoice": "inv-1" });

    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "recon-reserve",
    });
    let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(authorized["status"], "reserved");
    let nonce_json = authorized["execution_nonce"].clone();
    assert!(nonce_json.is_object());

    let blocked_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "recon-blocked",
    });
    let (_, blocked) = post_evaluate(Arc::clone(&state), &blocked_body).await;
    assert_eq!(blocked["status"], "deny");

    let caller = CallerExecutorFixture::new();
    let report_body = caller
        .report_request(
            Arc::clone(&state),
            &nonce_json,
            &params,
            ToolInvocationCost {
                units: 100,
                currency: "USD".to_string(),
                breakdown: None,
            },
        )
        .await;
    let (status, reconciled) = post_caller_report(Arc::clone(&state), &report_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reconciled["status"], "reconciled");

    let receipt: ChioReceipt = serde_json::from_value(reconciled["receipt"].clone()).unwrap();
    let nonce: SignedExecutionNonce = serde_json::from_value(nonce_json).unwrap();
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer_pub], &nonce),
        Ok(())
    );

    let after_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "recon-after",
    });
    let (_, after) = post_evaluate(Arc::clone(&state), &after_body).await;
    assert_eq!(after["status"], "deny");
    assert_eq!(
        budget
            .get_usage(&cap.id, 0)
            .test_unwrap()
            .test_unwrap()
            .total_cost_realized_spend,
        100
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconcile_replays_retained_receipt_without_settling_again() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());
    let params = serde_json::json!({ "invoice": "inv-1" });

    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "recon-replay",
    });
    let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
    let nonce_json = authorized["execution_nonce"].clone();

    let caller = CallerExecutorFixture::new();
    let report_body = caller
        .report_request(
            Arc::clone(&state),
            &nonce_json,
            &params,
            ToolInvocationCost {
                units: 100,
                currency: "USD".to_string(),
                breakdown: None,
            },
        )
        .await;
    let (status, completed) = post_caller_report(Arc::clone(&state), &report_body).await;
    assert_eq!(status, StatusCode::OK);

    let usage = budget.get_usage(&cap.id, 0).test_unwrap();
    let (status, replay) = post_caller_report(Arc::clone(&state), &report_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["receipt"], completed["receipt"]);
    assert_eq!(budget.get_usage(&cap.id, 0).test_unwrap(), usage);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_start_rejects_argument_mismatch() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());
    let params = serde_json::json!({ "invoice": "inv-1" });

    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "recon-mismatch",
    });
    let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
    let nonce_json = authorized["execution_nonce"].clone();

    let start_body = serde_json::json!({
        "protocol": "chio.caller-delivery.v1",
        "execution_nonce": nonce_json,
        "arguments": { "invoice": "tampered" },
    });
    let usage = budget.get_usage(&cap.id, 0).test_unwrap();
    let (status, rejected) = post_json_with_bearer(
        Arc::clone(&state),
        "/v1/caller/start",
        &start_body,
        Some(MEDIATED_CONTROL_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(rejected["error"], "chio_caller_delivery_rejected");
    assert_eq!(
        rejected["message"],
        "original committed caller delivery could not be authenticated or finalized"
    );
    assert_eq!(budget.get_usage(&cap.id, 0).test_unwrap(), usage);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_configured_budget_requires_durable_admission() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let dir = std::env::temp_dir().join(format!("chio-budget-both-e2e-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("budget.sqlite");
    let config = ProtectConfig {
        transport: Default::default(),
        upstream: "http://127.0.0.1:1".to_string(),
        spec_content: Some("{}".to_string()),
        spec_sha256: None,
        allow_anonymous_reads: false,
        spec_path: None,
        listen_addr: "127.0.0.1:0".to_string(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: None,
        receipt_retention: None,
        signer_seed_file: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        approval: None,
        control_url: Some("http://127.0.0.1:1".to_string()),
        control_token: Some("token".to_string()),
        budget_db: Some(db.to_string_lossy().to_string()),
        revocation_db: None,
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };
    let configured = build_budget_store(&config, Arc::new(clock::ProxyClock::default()))
        .unwrap()
        .expect("a budget store must be built");
    let budget = configured;

    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state_with_durable_admission(
        signer,
        MediationBudget::Configured(budget.clone()),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        None,
        None,
        None,
    );
    let params = serde_json::json!({ "invoice": "inv-both" });

    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "both-configured",
    });
    let (status, authorized) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        authorized["error"],
        "chio_mediation_requires_durable_admission"
    );
    assert_eq!(
        authorized["message"],
        "mediated authorization requires a durable admission store"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_nonce_retry_preserves_capacity_and_original_custody() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let state = mediated_test_state(signer, durable, Vec::new());
    let body = serde_json::json!({
        "capability": cap,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": {},
        "request_id": "capacity-original",
    });
    let (status, reserved) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reserved["status"], "reserved");
    let usage = budget.get_usage(&cap.id, 0).test_unwrap();
    {
        let now = state.clock.signed_seconds().test_unwrap();
        let mut window = state.minted_request_ids.lock().await;
        for index in 1..MAX_LIVE_REQUEST_IDS {
            window
                .claim(&format!("capacity-{index}"), now, false)
                .test_unwrap();
        }
        assert_eq!(window.len(), MAX_LIVE_REQUEST_IDS);
    }
    let mut retry = body.clone();
    retry["execution_nonce"] = reserved["execution_nonce"].clone();
    let mut invalid = retry.clone();
    invalid["execution_nonce"]["nonce"]["nonce_id"] = serde_json::json!("forged-candidate");
    let (status, denied) = post_evaluate(Arc::clone(&state), &invalid).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(denied["status"], "deny");
    assert_eq!(
        denied["receipt"]["decision"]["reason"],
        "durable admission failed: presented execution nonce does not match its retained issuance"
    );
    assert_eq!(
        state.minted_request_ids.lock().await.len(),
        MAX_LIVE_REQUEST_IDS
    );
    assert_eq!(budget.get_usage(&cap.id, 0).test_unwrap(), usage);

    let mut fresh = body.clone();
    fresh["request_id"] = serde_json::json!("capacity-exhausted");
    let (status, rejected) = post_evaluate(Arc::clone(&state), &fresh).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rejected["error"], "chio_request_id_capacity");
    let (status, rejected) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(rejected["error"], "chio_request_id_reused");

    let (status, retried) = post_evaluate(Arc::clone(&state), &retry).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(retried["status"], "reserved");
    assert_eq!(retried["execution_nonce"], reserved["execution_nonce"]);
    assert_eq!(
        state.minted_request_ids.lock().await.len(),
        MAX_LIVE_REQUEST_IDS
    );
    assert_eq!(budget.get_usage(&cap.id, 0).test_unwrap(), usage);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_request_id_shape_rejects_before_reservation() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let state = mediated_test_state(signer, durable, Vec::new());
    let mut body = serde_json::json!({
        "capability": cap,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": {},
    });
    for request_id in [
        "".to_owned(),
        " ".to_owned(),
        "a b".to_owned(),
        "a\tb".to_owned(),
        "é".to_owned(),
        "a".repeat(129),
    ] {
        body["request_id"] = serde_json::json!(request_id);
        let (status, rejected) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(rejected["error"], "chio_request_id_invalid_shape");
        assert!(budget.get_usage(&cap.id, 0).test_unwrap().is_none());
        assert_eq!(state.minted_request_ids.lock().await.len(), 0);
    }
    body["request_id"] = serde_json::json!("a".repeat(128));
    let (status, reserved) = post_evaluate(state, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reserved["status"], "reserved");
}
