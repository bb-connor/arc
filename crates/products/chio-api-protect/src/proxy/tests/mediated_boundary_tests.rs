use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_authorization_forwards_supplemental_authorization_fail_closed() {
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

    let (_, json) = post_evaluate(Arc::clone(&state), &body).await;

    assert_eq!(json["status"], "deny", "{json}");
    assert!(
        json["receipt"]["decision"]["reason"]
            .as_str()
            .is_some_and(|reason| reason
                .contains("supplemental authorization requires an installed verifier")),
        "{json}"
    );
    let usage = budget.get_usage(&cap_id, 0).unwrap();
    assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
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
    assert_ne!(json["status"], "authorized");
}
