use super::*;

#[test]
fn product_default_guards_mediation_preserves_authority_policy_identity() {
    let signer = Keypair::generate();
    let provided = chio_core_types::sha256_hex(b"authority-policy-with-configured-guards");
    for hash in [Some(provided.as_str()), None] {
        let kernel = build_mediation_kernel(
            &signer,
            Arc::new(InMemoryBudgetStore::new()),
            MediationPolicy {
                issuers: &[],
                hash,
                receipt_store: None,
            },
            Vec::new(),
            None,
            None,
            Arc::new(clock::ProxyClock::default()),
        )
        .test_unwrap();
        if let Some(hash) = hash {
            assert_eq!(kernel.policy_hash(), hash);
        } else {
            assert_eq!(kernel.policy_hash().len(), 64);
            assert_ne!(
                kernel.policy_hash(),
                chio_core_types::sha256_hex(b"chio_api_protect_mediation_v1")
            );
        }
        assert_eq!(
            kernel.guard_names(),
            ["internal-network", "agent-velocity", "advisory-pipeline"]
        );
        assert_eq!(kernel.post_invocation_hook_names(), ["output-sanitizer"]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn product_default_guards_caller_reservation_refuses_internal_target_without_nonce() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let issuer = issuing_kernel(&signer, budget.clone(), &[]);
    let capability =
        issue_invocation_capability(&issuer, &agent, "external-caller", "http_request", 10);
    let state = mediated_test_state(signer.clone(), budget, Vec::new());
    let body = serde_json::json!({"capability":capability,"tool_server":"external-caller","tool_name":"http_request","parameters":{"url":"http://169.254.169.254/latest/meta-data"}});
    let (status, reply) = post_evaluate(state.clone(), &body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["status"], "deny", "private target reserved: {reply}");
    assert!(reply["execution_nonce"].is_null());
    assert_eq!(reply["execution_authorized"], false);
    let receipt: chio_core_types::receipt::body::ChioReceipt =
        serde_json::from_value(reply["receipt"].clone()).test_unwrap();
    assert_eq!(receipt.kernel_key, signer.public_key());
    assert!(receipt.verify_signature().test_unwrap());
    assert!(matches!(
        receipt.decision,
        Some(chio_core_types::receipt::decision::Decision::Deny { .. })
    ));
    let kernel = state.mediation_kernel.as_ref().test_unwrap().lock().await;
    assert_eq!(
        kernel.guard_names(),
        ["internal-network", "agent-velocity", "advisory-pipeline"]
    );
    assert_eq!(kernel.post_invocation_hook_names(), ["output-sanitizer"]);
}
