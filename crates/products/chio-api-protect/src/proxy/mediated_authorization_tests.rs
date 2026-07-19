    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_reserves_hold_and_mints_non_authoritative_receipt() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        let signer_pub = signer.public_key();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);

        // Single-phase authorization: wire status "authorized", a minted nonce
        // object, and a non-authoritative reserved receipt. The route never
        // dispatches, never consumes a nonce, never settles a spend.
        assert_eq!(json["status"], "authorized");
        assert!(
            json["execution_nonce"].is_object(),
            "authorization must mint an execution nonce object"
        );
        assert_eq!(
            json["receipt"]["decision"]["verdict"], "incomplete",
            "a reserved authorization is not a completed-spend decision"
        );

        // The receipt records the reserved hold's authorize block with NO
        // terminal reconcile disposition: reserved, not reconciled.
        let budget_authority = &json["receipt"]["metadata"]["budget_authority"];
        assert_eq!(budget_authority["authorize"]["exposure_units"], 100);
        assert!(
            budget_authority.get("terminal").is_none(),
            "a reserved (not reconciled) hold must carry no terminal disposition"
        );

        // The receipt is rejected as an authoritative spend: the hold is
        // reserved, not reconciled.
        let receipt: ChioReceipt = serde_json::from_value(json["receipt"].clone()).unwrap();
        let nonce: SignedExecutionNonce =
            serde_json::from_value(json["execution_nonce"].clone()).unwrap();
        assert!(
            is_authoritative_spend_receipt(&receipt, &[signer_pub], &nonce).is_err(),
            "a reserved authorization receipt must not be an authoritative spend"
        );

        // The pre-execution hold is RESERVED (open), not reversed. The
        // budget store shows the worst-case exposure committed against the grant,
        // so the caller's downstream execution is backed by a real reservation.
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
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap_a =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_b =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        assert_ne!(
            cap_a.id, cap_b.id,
            "the two capabilities must carry distinct ids"
        );

        // First reservation under capability A binds request_id R to a durable
        // hold whose id embeds A.
        let state_before = mediated_test_state(signer.clone(), Arc::clone(&budget), Vec::new());
        let body_a = serde_json::json!({
            "capability": cap_a,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "request_id": "shared-request-id",
            "parameters": { "invoice": "inv-1" }
        });
        let (status_a, json_a) = post_evaluate(Arc::clone(&state_before), &body_a).await;
        assert_eq!(status_a, StatusCode::OK, "{json_a}");
        assert_eq!(json_a["status"], "authorized");

        // Simulate a restart: a fresh sidecar state (empty minted-request-id
        // window and approval replay cache) over the SAME durable budget store, so
        // only the durable prefix guard can catch a reused request_id.
        let state_after = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        // Replaying the SAME request_id under a DIFFERENT capability is rejected by
        // the durable prefix guard, even though no `budget-hold:R:{capB}:..` row
        // exists for capability B.
        let body_b = serde_json::json!({
            "capability": cap_b,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "request_id": "shared-request-id",
            "parameters": { "invoice": "inv-2" }
        });
        let (status_b, json_b) = post_evaluate(Arc::clone(&state_after), &body_b).await;
        assert_eq!(status_b, StatusCode::CONFLICT, "{json_b}");
        assert_eq!(json_b["error"], "chio_request_id_reused");

        // A fresh request_id under capability B still proceeds.
        let body_fresh = serde_json::json!({
            "capability": cap_b,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "request_id": "fresh-request-id",
            "parameters": { "invoice": "inv-3" }
        });
        let (status_fresh, json_fresh) = post_evaluate(Arc::clone(&state_after), &body_fresh).await;
        assert_eq!(status_fresh, StatusCode::OK, "{json_fresh}");
        assert_eq!(json_fresh["status"], "authorized");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_reserved_hold_blocks_oversubscription() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // max_cost_per_invocation == max_total_cost == 100: one authorization
        // reserves the entire grant budget.
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });

        // First authorization reserves the hold.
        let (_, first) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(first["status"], "authorized");

        // Because the reserved hold is NOT reversed, a second
        // authorization for the same fully-reserved grant is DENIED. Sequential
        // mediated authorizations respect max_total_cost; no over-subscription.
        let (_, second) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(
            second["status"], "deny",
            "the reserved hold must block a second authorization past max_total_cost"
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

        // Obtain a genuine minted nonce from a first authorization.
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        let minted_nonce = authorized["execution_nonce"].clone();
        assert!(minted_nonce.is_object());

        // Presenting that nonce back to /v1/evaluate is rejected
        // fail-closed. This endpoint mints nonces; it does not settle them, so
        // the sidecar never consumes the downstream nonce (which would make the
        // real tool server reject the caller as a replay).
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_revoked_capability_is_rejected() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        // Record the capability id as revoked, mirroring a prior
        // `/v1/capabilities/release`.
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
        // A revoked capability is rejected fail-closed rather than authorized.
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_ne!(json["status"], "authorized");
        assert_eq!(json["error"], "chio_capability_revoked");

        // The revoked capability never reaches the kernel, so no hold is placed.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    /// Build a well-formed capability whose single delegation-chain link names
    /// `ancestor_id` as the delegated ancestor. The leaf is signed by `issuer`
    /// and the link by `delegator`, so the token is structurally valid; the
    /// presented leaf carries a fresh, distinct id.
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
        };
        CapabilityToken::sign(body, issuer).test_unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_revoked_delegation_ancestor_rejects_delegated_child() {
        let signer = Keypair::generate();
        let root = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        // Revoke only the ROOT ancestor; the presented leaf id is never revoked,
        // so a leaf-only guard would admit this delegated child.
        let ancestor_id = "cap-root-revoked".to_string();
        let child =
            delegated_child_capability(&signer, &root, &agent, &ancestor_id, "cost-srv", "compute");
        let child_id = child.id.clone();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
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
        // A delegated child of a revoked ancestor is rejected fail-closed before
        // the kernel, exactly as a revoked leaf is.
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_ne!(json["status"], "authorized");
        assert_eq!(json["error"], "chio_capability_revoked");

        // The severed child never reserved a hold under its own id.
        let usage = budget.get_usage(&child_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_route_honors_a_durable_only_revocation() {
        // A revocation a sibling replica (or `chio trust revoke --revocation-db`)
        // records after this process boots lives in the shared durable store but
        // never in this process's in-memory release set, which is loaded once at
        // boot. The mediated money path must still reject it fail-closed, matching
        // the proxy and validate paths, or a revoked capability keeps reserving
        // budget and minting execution nonces until it expires.
        let signer = Keypair::generate();
        let root = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let child =
            delegated_child_capability(&signer, &root, &agent, "cap-root", "cost-srv", "compute");
        let child_id = child.id.clone();

        // Revoke the presented leaf id in the DURABLE store only.
        let durable: Arc<dyn chio_kernel::RevocationStore> =
            Arc::new(chio_kernel::InMemoryRevocationStore::new());
        chio_kernel::RevocationStore::revoke(durable.as_ref(), &child_id).test_unwrap();

        let state = mediated_test_state_core(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            true,
            None,
            Some(Arc::clone(&durable)),
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

        // The revoked capability never reserved a hold.
        let usage = budget.get_usage(&child_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_admits_caller_named_server_id() {
        // The operator does not pre-register tool servers; the mediated route
        // accepts whatever server id the caller names without pre-registering a
        // dispatch target, so an authorization for an arbitrary server is
        // authorized rather than denied `ToolNotRegistered` by the kernel's
        // pre-dispatch registration check.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_cost_bearing_capability(
            &kernel,
            &agent,
            "arbitrary-srv",
            "invoke",
            100,
            1000,
            "USD",
        );
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "arbitrary-srv",
            "tool_name": "invoke",
            "parameters": {}
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "authorized");
        assert!(json["execution_nonce"].is_object());
        assert_eq!(json["receipt"]["decision"]["verdict"], "incomplete");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_trusts_configured_external_capability_issuers() {
        let signer = Keypair::generate();
        let external_signer = Keypair::generate();
        let agent = Keypair::generate();

        // A capability minted by an operator-configured external issuer.
        let issuer_budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let issuer = issuing_kernel(&external_signer, issuer_budget, &[]);
        let cap =
            issue_cost_bearing_capability(&issuer, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();

        // Trusting the external issuer: the mediated route authorizes rather than
        // rejecting the capability as untrusted.
        let trusting_budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let trusting_state = mediated_test_state(
            signer.clone(),
            trusting_budget,
            vec![external_signer.public_key()],
        );
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": {}
        });
        let (_, json) = post_evaluate(trusting_state, &body).await;
        assert_eq!(json["status"], "authorized");
        assert!(json["execution_nonce"].is_object());

        // Control: without the configured issuer the same capability is denied,
        // proving the trust set is load-bearing.
        let untrusting_budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let untrusting_state = mediated_test_state(signer, untrusting_budget, Vec::new());
        let (_, json) = post_evaluate(untrusting_state, &body).await;
        assert_eq!(json["status"], "deny");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_deny_leaves_committed_cost_zero() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // max_cost_per_invocation (100) exceeds max_total_cost (40), so the
        // pre-execution hold is refused before the authorization check.
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 40, "USD");
        let cap_id = cap.id.clone();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let body = serde_json::json!({ "capability": cap, "tool_server": "cost-srv",
            "tool_name": "compute", "parameters": {} });
        let (_, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(json["status"], "deny");
        assert_ne!(json["receipt"]["decision"]["verdict"], "allow");
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_governed_capability_requires_intent_and_approval() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // The grant requires a governed intent and approval above 50 units; the
        // worst-case charge (100) crosses the threshold, so an approval token is
        // required.
        let cap = issue_governed_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD", 50);
        let cap_value = serde_json::to_value(&cap).unwrap();
        let approver = signer.clone();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        // Without a governed intent + approval token, the governed
        // grant is DENIED (the forwarded fields are load-bearing).
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

        // With a valid governed intent + approval token bound to the caller-chosen
        // request_id, the same grant is AUTHORIZED.
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
        let (_, authorized) = post_evaluate(Arc::clone(&state), &governed_body).await;
        assert_eq!(
            authorized["status"], "authorized",
            "a governed grant with a valid intent and approval must be authorized"
        );
        assert!(authorized["execution_nonce"].is_object());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_governed_mustprepay_authorizes_with_payment_adapter() {
        // An approved governed MustPrepay request authorizes only because a payment
        // adapter is installed on the mediation kernel: the kernel prepays the
        // quoted cost through the adapter before the reserve-for-caller path mints
        // a nonce.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // Worst-case charge (100) crosses the approval threshold (50), so an
        // approval token is required alongside the governed intent.
        let cap = issue_governed_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD", 50);
        let cap_value = serde_json::to_value(&cap).unwrap();
        let approver = signer.clone();
        let state = mediated_test_state_core(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            true,
            Some(Box::new(chio_kernel::SimPaymentAdapter::new())),
            None,
        );

        let request_id = "req-mustprepay-adapter";
        let intent =
            governed_mustprepay_intent("intent-prepay-1", "cost-srv", "compute", 100, "USD");
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
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["status"], "authorized",
            "a configured payment adapter must let an approved governed MustPrepay authorize"
        );
        assert!(
            json["execution_nonce"].is_object(),
            "an authorized MustPrepay reservation must mint an execution nonce"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_governed_mustprepay_denied_without_payment_adapter() {
        // The same approved governed MustPrepay request is denied fail-closed when
        // no payment adapter is configured: the kernel has no rail to prepay the
        // quote, so the prepayment gate rejects it before any reservation.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_governed_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD", 50);
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let approver = signer.clone();
        // No payment adapter is installed on the mediation kernel.
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        let request_id = "req-mustprepay-no-adapter";
        let intent =
            governed_mustprepay_intent("intent-prepay-2", "cost-srv", "compute", 100, "USD");
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
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["status"], "deny",
            "governed MustPrepay must deny fail-closed without a configured payment adapter"
        );
        assert!(
            json["execution_nonce"].is_null(),
            "a denied MustPrepay must not mint a reserved nonce"
        );

        // The governed prepayment gate denies before any reserve, so no budget is
        // committed against the grant.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_dpop_capability_requires_valid_proof() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_dpop_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        // Without a DPoP proof, a dpop_required grant is DENIED
        // fail-closed.
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

        // With a valid DPoP proof bound to the exact call, the mediation kernel's
        // installed DPoP state verifies it and the grant is AUTHORIZED.
        let proof = dpop_proof_for(&agent, &cap, "cost-srv", "compute", &params);
        let dpop_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "dpop_proof": proof
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &dpop_body).await;
        assert_eq!(
            authorized["status"], "authorized",
            "a valid DPoP proof must authorize the dpop_required grant"
        );
        assert!(authorized["execution_nonce"].is_object());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_dpop_proof_replay_is_rejected_across_requests() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // max_total (1000) far exceeds a single reservation (100), so the second
        // request cannot be denied for budget: the only reason to reject it is a
        // DPoP replay store that persists across requests. That persistence only
        // holds if a single kernel is reused for the process lifetime.
        let cap = issue_dpop_capability_with_total(
            &kernel, &agent, "cost-srv", "compute", 100, 1000, "USD",
        );
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        // A single DPoP proof, presented twice under distinct request ids.
        let proof = dpop_proof_for(&agent, &cap, "cost-srv", "compute", &params);
        let first_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "dpop-req-1",
            "dpop_proof": proof,
        });
        let (_, first) = post_evaluate(Arc::clone(&state), &first_body).await;
        assert_eq!(
            first["status"], "authorized",
            "the first presentation of a valid DPoP proof must authorize"
        );

        let second_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "dpop-req-2",
            "dpop_proof": proof,
        });
        let (_, second) = post_evaluate(Arc::clone(&state), &second_body).await;
        assert_eq!(
            second["status"], "deny",
            "replaying the DPoP proof must be rejected by the shared kernel's persistent nonce store"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_reused_request_id_is_conflict() {
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
            "parameters": { "invoice": "inv-1" },
            "request_id": "fixed-req-id",
        });
        let (status, first) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["status"], "authorized");

        // Reusing the caller-supplied request_id is rejected fail-closed with 409
        // before authorizing, so it cannot collapse into an idempotent no-op
        // reservation that defeats the over-subscription guard.
        let (status, second) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_ne!(second["status"], "authorized");
        assert_eq!(second["error"], "chio_request_id_reused");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_requires_hold_capable_budget_store() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        // hold_capable == false models a remote `--control-url` budget store whose
        // hold APIs fall back to the no-op trait defaults, so a reserved hold can
        // never be reconciled by nonce or reclaimed by the TTL reaper.
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            false,
        );
        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        // Fail-closed: the mediated route rejects rather than mint an
        // unreconcilable reserved nonce.
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"], "chio_mediation_requires_local_budget_store");
        assert_ne!(json["status"], "authorized");
        assert!(
            json["execution_nonce"].is_null(),
            "a fail-closed rejection must not mint a reserved nonce"
        );

        // No hold is placed against the grant: the route fails closed before any
        // budget interaction.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_requires_reconcile_control_token() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        // A hold-capable store but NO sidecar-control token: every /v1/reconcile
        // is rejected by the reconcile control gate, so a minted reservation could
        // only expire and forfeit budget. The evaluate route must fail closed
        // before reserving budget or minting a nonce.
        let state =
            mediated_test_state_with_control_token(signer, Arc::clone(&budget), Vec::new(), None);
        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"], "chio_mediation_requires_reconcile_token");
        assert_ne!(json["status"], "authorized");
        assert!(
            json["execution_nonce"].is_null(),
            "a fail-closed rejection must not mint a reserved nonce"
        );

        // No hold is placed against the grant: the route fails closed before any
        // budget interaction.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_rejects_blank_reconcile_control_token() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        // A whitespace-only sidecar-control token is a misconfiguration: the
        // reconcile control gate trims the presented token and rejects a blank
        // configured token, so every /v1/reconcile is refused and a minted
        // reservation could only expire and forfeit budget. The evaluate route
        // must treat a blank token as unconfigured and fail closed before
        // reserving budget or minting a nonce.
        let state = mediated_test_state_with_control_token(
            signer,
            Arc::clone(&budget),
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
        assert_eq!(json["error"], "chio_mediation_requires_reconcile_token");
        assert_ne!(json["status"], "authorized");
        assert!(
            json["execution_nonce"].is_null(),
            "a fail-closed rejection must not mint a reserved nonce"
        );

        // No hold is placed against the grant: the route fails closed before any
        // budget interaction.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_requires_hold_capable_budget_store() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let params = serde_json::json!({ "invoice": "inv-1" });

        // Mint a genuine reserved nonce on a hold-capable sidecar so the reconcile
        // body deserializes; the reconcile is then attempted against a
        // non-hold-capable sidecar.
        let hold_capable = mediated_test_state(signer.clone(), Arc::clone(&budget), Vec::new());
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-remote",
        });
        let (_, authorized) = post_evaluate(hold_capable, &body).await;
        let nonce_json = authorized["execution_nonce"].clone();
        assert!(nonce_json.is_object());

        // A remote (non-hold-capable) sidecar cannot resolve the reserved hold the
        // nonce names, so reconcile fails closed rather than attempt a settle.
        let remote = mediated_test_state_inner(
            signer,
            budget,
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            false,
        );
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        let (status, json) = post_reconcile(remote, &reconcile_body).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"], "chio_mediation_requires_local_budget_store");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_durable_hold_rejects_request_id_reuse_across_restart() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        // The durable budget store survives a restart; the ProxyState (and its
        // in-memory request-id window) is rebuilt fresh.
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();

        // Pre-restart sidecar: reserve a hold under a caller-chosen request_id. The
        // kernel derives the durable hold id from it and marks the hold reserved.
        let before = mediated_test_state(signer.clone(), Arc::clone(&budget), Vec::new());
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" },
            "request_id": "restart-req",
        });
        let (status, authorized) = post_evaluate(Arc::clone(&before), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(authorized["status"], "authorized");

        // Restart: a fresh ProxyState with an EMPTY in-memory window, sharing only
        // the durable budget store. The seeded sidecar signer survives, so the
        // rebuilt mediation kernel still trusts the capability.
        let after = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        // Reusing the same request_id must be rejected fail-closed via the DURABLE
        // check: the in-memory fast path is empty after the restart, so only the
        // open hold recorded in the budget store closes the gap. Without it the
        // reused id would collapse into an idempotent authorize that mints a second
        // nonce against the same open reservation.
        let (status, replay) = post_evaluate(Arc::clone(&after), &body).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_ne!(replay["status"], "authorized");
        assert!(
            replay["execution_nonce"].is_null(),
            "no second nonce is minted against the open hold"
        );
        assert_eq!(replay["error"], "chio_request_id_reused");

        // A fresh request_id still authorizes on the restarted sidecar: the durable
        // check rejects only a reused id that already backs an open hold.
        let fresh_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-2" },
            "request_id": "restart-req-fresh",
        });
        let (status, fresh) = post_evaluate(after, &fresh_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fresh["status"], "authorized");
        assert!(fresh["execution_nonce"].is_object());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_settles_reserved_hold_and_frees_budget() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let signer_pub = signer.public_key();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // max_per 100, max_total 150: one reservation reserves 100, a second
        // (needing 100 more -> 200 > 150) is blocked until the first frees slack.
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        // Reserve the worst-case 100 and capture the minted nonce.
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-reserve",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(authorized["status"], "authorized");
        let nonce_json = authorized["execution_nonce"].clone();
        assert!(nonce_json.is_object());

        // A second authorization is blocked while the slack is reserved.
        let blocked_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-blocked",
        });
        let (_, blocked) = post_evaluate(Arc::clone(&state), &blocked_body).await;
        assert_eq!(blocked["status"], "deny");

        // Reconcile at realized 30 (< reserved 100): settle down, free 70.
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json.clone(),
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        let (status, reconciled) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reconciled["status"], "reconciled");

        // The returned receipt is an authoritative mediated spend bound to the nonce.
        let receipt: ChioReceipt = serde_json::from_value(reconciled["receipt"].clone()).unwrap();
        let nonce: SignedExecutionNonce = serde_json::from_value(nonce_json).unwrap();
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[signer_pub], &nonce),
            Ok(())
        );

        // The freed difference admits an authorization that was blocked before.
        let after_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-after",
        });
        let (_, after) = post_evaluate(Arc::clone(&state), &after_body).await;
        assert_eq!(
            after["status"], "authorized",
            "the budget freed by reconcile must admit a new authorization"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_rejects_replayed_nonce() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
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

        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        // First reconcile settles the hold.
        let (status, _) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);

        // Replaying the same nonce is rejected fail-closed: the shared kernel's
        // nonce store already consumed it and the reserved hold is closed.
        let (status, replay) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(replay["error"], "chio_reconcile_rejected");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_rejects_argument_mismatch() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
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

        // Arguments that do not match the nonce's signed parameter binding are
        // rejected: the realized-cost claim must be tied to the exact authorized
        // call, so a forged reconcile cannot settle a different action.
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": { "invoice": "tampered" },
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        let (status, rejected) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(rejected["error"], "chio_reconcile_rejected");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaper_forfeits_expired_hold_at_worst_case() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // One reservation reserves the whole grant.
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        let reserve_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "reap-reserve",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &reserve_body).await;
        assert_eq!(authorized["status"], "authorized");

        // The whole grant is reserved: a second authorization is blocked.
        let blocked_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "reap-blocked",
        });
        let (_, blocked) = post_evaluate(Arc::clone(&state), &blocked_body).await;
        assert_eq!(blocked["status"], "deny");

        // Sweep with a far-future clock: the abandoned reserved hold is past its
        // execution-nonce TTL and is settled at its reserved worst-case.
        let settled = reap_expired_reserved_holds_once(&state, i64::MAX)
            .await
            .unwrap();
        assert_eq!(settled, 1, "the expired reserved hold must be settled");

        // Fail-closed: reaping FORFEITS the reserved worst-case to realized spend
        // (an abandoned reservation may correspond to a call that ran), so the
        // grant stays fully committed and a new authorization is still denied.
        // The reaper's job is to convert a lingering open hold into a settled
        // spend, not to free budget for the caller who never reconciled.
        let after_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "reap-after",
        });
        let (_, after) = post_evaluate(Arc::clone(&state), &after_body).await;
        assert_eq!(
            after["status"], "deny",
            "a forfeited reserved hold must keep the grant committed, not free it"
        );

        // The forfeited worst-case remains committed against the grant.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        let usage = usage.expect("the forfeited hold must remain recorded in the budget store");
        assert_eq!(
            usage.committed_cost_units().unwrap(),
            100,
            "reaping settles the reserved worst-case as realized spend (fail-closed)"
        );
    }
