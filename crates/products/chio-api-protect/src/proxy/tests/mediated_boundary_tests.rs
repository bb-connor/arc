use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_authorization_rejects_unconfigured_supplemental_authorization() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let cap_id = cap.id.clone();
    let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
    let body = serde_json::json!({
        "capability": cap,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-supplemental" },
        "supplemental_authorization": { "signed_extension": "signed-extension" }
    });

    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json["message"]
            .as_str()
            .is_some_and(|reason| reason.contains("no supplemental verifier is configured")),
        "{json}"
    );
    let usage = budget.get_usage(&cap_id, 0).unwrap();
    assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_authorization_rejects_threshold_approval_without_policy_runtime() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let approver = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
    let approval_token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "approval-mediated".to_string(),
            approver: approver.public_key(),
            subject: agent.public_key(),
            governed_intent_hash: "a".repeat(64),
            request_id: "mediated-threshold-request".to_string(),
            threshold_proposal_hash: Some("b".repeat(64)),
            issued_at: 1,
            expires_at: 2,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )
    .unwrap();
    // The mediated product does not install a threshold requirement resolver, so
    // it rejects the advertised fields at the boundary instead of forwarding a
    // request the kernel cannot authorize.
    let body = serde_json::json!({
        "capability": cap,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "request_id": "mediated-threshold-request",
        "parameters": { "invoice": "inv-threshold" },
        "approval_tokens": [approval_token]
    });

    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json["message"]
            .as_str()
            .is_some_and(|message| message.contains("no threshold policy resolver is configured")),
        "{json}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_presented_execution_nonce_is_rejected() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" }
    });
    let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
    let minted_nonce = authorized["execution_nonce"].clone();
    assert!(minted_nonce.is_object());
    let settle_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" },
        "execution_nonce": minted_nonce
    });

    let (status, json) = post_evaluate(Arc::clone(&state), &settle_body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_ne!(json["status"], "reserved");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_governed_context_accepts_producer_numbers_but_not_signed_aliases() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let state = mediated_test_state(signer, budget, Vec::new());
    let template = serde_json::json!({
        "capability": cap, "tool_server": "cost-srv", "tool_name": "compute",
        "parameters": {},
        "governed_intent": {
            "id": "numeric-intent", "server_id": "cost-srv", "tool_name": "compute",
            "purpose": "ordinary SDK context", "context": "RAW_CONTEXT"
        }
    })
    .to_string();
    for (context, expected) in [
        (
            r#"{"learning_rate":1e-05,"confidence":0.50}"#,
            StatusCode::OK,
        ),
        (r#"{"n":1,"n":2}"#, StatusCode::BAD_REQUEST),
        (
            r#"{"callChainUpstreamProof":{"signed_number":0.50}}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            r#"{"callChainContinuation":{"signed_number":1e-05}}"#,
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(template.replace("\"RAW_CONTEXT\"", context)))
            .test_unwrap();
        let response =
            sidecar_evaluate_tool_call_mediated_handler(State(state.clone()), request).await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        assert_eq!(
            status,
            expected,
            "context {context}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
}
