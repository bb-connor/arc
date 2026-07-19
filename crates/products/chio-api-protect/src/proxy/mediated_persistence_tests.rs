    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_works_with_both_control_url_and_budget_db() {
        // With BOTH a control plane and a local budget DB configured,
        // `build_budget_store` hands mediation the hold-capable local SQLite
        // store, so `/v1/evaluate` authorizes (minting a reserved nonce) and
        // `/v1/reconcile` settles, instead of failing closed. This exercises the
        // exact store the sidecar would select from that configuration.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let dir =
            std::env::temp_dir().join(format!("chio-budget-both-e2e-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("budget.sqlite");
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: None,
            allow_ephemeral_receipts: true,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: Some("http://127.0.0.1:1".to_string()),
            control_token: Some("token".to_string()),
            budget_db: Some(db.to_string_lossy().to_string()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let configured = build_budget_store(&config)
            .unwrap()
            .expect("a budget store must be built");
        assert!(configured.hold_capable);
        let budget = configured.store;

        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            configured.hold_capable,
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
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            authorized["status"], "authorized",
            "both configured must authorize via the local hold-capable store"
        );
        let nonce_json = authorized["execution_nonce"].clone();
        assert!(nonce_json.is_object());

        // Reconcile settles the reserved hold the local store persisted.
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        let (status, reconciled) = post_reconcile(state, &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reconciled["status"], "reconciled");
    }

    /// Open a temporary receipt store backed by a fresh SQLite database.
    fn open_temp_receipt_store() -> (std::path::PathBuf, SqliteReceiptStore) {
        let dir = std::env::temp_dir().join(format!("chio-receipt-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("receipts.sqlite");
        let store = SqliteReceiptStore::open(&db.to_string_lossy()).unwrap();
        (db, store)
    }

    /// A receipt store whose `append_tool_receipt` fails deterministically: the
    /// backing `tool_receipts` table is dropped through a second connection to
    /// the same database, so every append errors.
    fn failing_receipt_store() -> SqliteReceiptStore {
        let (db, store) = open_temp_receipt_store();
        let dropper = rusqlite::Connection::open(&db).unwrap();
        dropper.execute("DROP TABLE tool_receipts", []).unwrap();
        drop(dropper);
        store
    }

    /// A payment adapter that counts each rail action, so a test can assert a
    /// captured MustPrepay prepayment is neither refunded nor re-charged. The
    /// settlement behavior is delegated to the deterministic sim adapter.
    #[derive(Clone, Default)]
    struct RecordingPaymentAdapter {
        inner: chio_kernel::SimPaymentAdapter,
        captures: Arc<std::sync::atomic::AtomicUsize>,
        releases: Arc<std::sync::atomic::AtomicUsize>,
        refunds: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl chio_kernel::PaymentAdapter for RecordingPaymentAdapter {
        fn authorize(
            &self,
            request: &chio_kernel::PaymentAuthorizeRequest,
        ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
            self.inner.authorize(request)
        }

        fn capture(
            &self,
            authorization_id: &str,
            amount_units: u64,
            currency: &str,
            reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.captures
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner
                .capture(authorization_id, amount_units, currency, reference)
        }

        fn release(
            &self,
            authorization_id: &str,
            reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.releases
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.release(authorization_id, reference)
        }

        fn refund(
            &self,
            transaction_id: &str,
            amount_units: u64,
            currency: &str,
            reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.refunds
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner
                .refund(transaction_id, amount_units, currency, reference)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_receipt_persistence_failure_returns_nonce_and_keeps_reservation() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(failing_receipt_store()),
            true,
        );
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" },
            "request_id": "persist-fail",
        });

        // The kernel Allowed (reserved) and minted a nonce, but the local receipt
        // append fails. The reservation is durable in the budget store and the caller
        // reconciles it at /v1/reconcile (which persists its own authoritative
        // receipt), so the handler returns 200 with the nonce rather than a 500 that
        // would strand a reservation the caller can never use.
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "authorized");
        assert!(
            json["execution_nonce"].is_object(),
            "a persistence failure after a successful reserve must still return the nonce"
        );

        // The reserved hold stays OPEN with its budget committed: the caller holds a
        // real reservation backing the downstream execution.
        let hold_id = format!("budget-hold:persist-fail:{cap_id}:0");
        let hold = budget.get_budget_hold(&hold_id).unwrap();
        assert!(
            hold.map(|hold| hold.disposition.is_open()).unwrap_or(false),
            "a returned reservation must keep its reserved hold open"
        );
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        let usage = usage.expect("the reserved hold must remain recorded in the budget store");
        assert_eq!(
            usage.committed_cost_units().unwrap(),
            100,
            "the returned reservation must keep its reserved budget committed"
        );

        // The request-id claim is retained: the id backs a live reservation, so a
        // reuse must still collide rather than mint a second nonce.
        assert_eq!(
            state.minted_request_ids.lock().await.len(),
            1,
            "a returned reservation must retain its request-id claim"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_receipt_persistence_success_keeps_reservation() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let (_db, receipt_store) = open_temp_receipt_store();
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(receipt_store),
            true,
        );
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" },
            "request_id": "persist-ok",
        });

        // The happy path: the receipt append succeeds, so the caller receives the
        // minted nonce and the reservation is kept for a real reconcile.
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "authorized");
        assert!(json["execution_nonce"].is_object());

        let usage = budget.get_usage(&cap_id, 0).unwrap();
        let usage = usage.expect("the reserved hold must remain recorded in the budget store");
        assert_eq!(
            usage.committed_cost_units().unwrap(),
            100,
            "a persisted authorization must keep its reserved hold"
        );
        assert_eq!(
            state.minted_request_ids.lock().await.len(),
            1,
            "a persisted authorization must retain its request-id claim"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_invocation_receipt_persistence_failure_returns_nonce_and_keeps_reservation() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(failing_receipt_store()),
            true,
        );
        let params = serde_json::json!({ "invoice": "inv-1" });
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-persist-fail",
        });

        // An invocation-only reserve debits the single invocation and mints a nonce.
        // The receipt append fails, but the caller can still present the nonce and
        // reconcile downstream, so the handler returns 200 with the nonce and keeps
        // the invocation reserved instead of a 500 that would permanently burn the
        // invocation for a caller that never received the nonce.
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "authorized");
        let nonce_json = json["execution_nonce"].clone();
        assert!(
            nonce_json.is_object(),
            "an invocation reserve whose receipt fails to persist must still return the nonce"
        );

        // The invocation stays consumed and the reserved hold stays open: the caller
        // holds the nonce that backs it.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert_eq!(
            usage.map(|usage| usage.invocation_count).unwrap_or(0),
            1,
            "the returned invocation reservation stays consumed against the grant"
        );
        let hold_id = format!("budget-hold:invoke-persist-fail:{cap_id}:0");
        let hold = budget.get_budget_hold(&hold_id).unwrap();
        assert!(
            hold.map(|hold| hold.disposition.is_open()).unwrap_or(false),
            "the returned invocation reservation must keep its reserved hold open"
        );

        // The returned nonce is usable: reconciling it downstream settles the
        // reservation and produces a `reconciled` receipt.
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 0, "currency": "USD" },
        });
        let (recon_status, reconciled) = post_reconcile(state, &reconcile_body).await;
        assert_eq!(recon_status, StatusCode::OK);
        assert_eq!(reconciled["status"], "reconciled");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_mustprepay_receipt_persistence_failure_returns_nonce_without_refund() {
        // Money-loss guard: a governed MustPrepay reserve authorizes AND captures the
        // quoted prepayment before minting the nonce. If the sidecar's local receipt
        // append then fails, tearing the reservation down would leave the captured
        // prepayment charged for a reservation the caller never received (direct
        // financial loss). The handler must return 200 with the nonce so the captured
        // prepayment backs a usable authorization, and must not refund or re-charge.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_governed_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD", 50);
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let approver = signer.clone();

        let captures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refunds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let adapter = RecordingPaymentAdapter {
            inner: chio_kernel::SimPaymentAdapter::new(),
            captures: Arc::clone(&captures),
            releases: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            refunds: Arc::clone(&refunds),
        };
        let state = mediated_test_state_core(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(failing_receipt_store()),
            true,
            Some(Box::new(adapter)),
            None,
        );

        let request_id = "req-mustprepay-persist-fail";
        let intent =
            governed_mustprepay_intent("intent-prepay-persist", "cost-srv", "compute", 100, "USD");
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
        assert_eq!(
            status,
            StatusCode::OK,
            "a captured MustPrepay reserve whose receipt fails to persist must not 500"
        );
        assert_eq!(json["status"], "authorized");
        assert!(
            json["execution_nonce"].is_object(),
            "the caller must receive the nonce the captured prepayment backs"
        );

        // The prepayment was captured exactly once and never refunded: the payer is
        // billed for the authorization the caller now holds, with no money lost to a
        // torn-down reservation.
        assert_eq!(
            captures.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the MustPrepay quote must be captured exactly once"
        );
        assert_eq!(
            refunds.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the captured prepayment must not be refunded: it backs the returned nonce"
        );

        // The reservation is intact: the reserved hold stays open.
        let hold_id = format!("budget-hold:{request_id}:{cap_id}:0");
        let hold = budget.get_budget_hold(&hold_id).unwrap();
        assert!(
            hold.map(|hold| hold.disposition.is_open()).unwrap_or(false),
            "the captured MustPrepay reservation must stay open, backing the returned nonce"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_invocation_reconcile_keeps_invocation_consumed() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        let reserve_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-reconcile",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &reserve_body).await;
        assert_eq!(authorized["status"], "authorized");
        let nonce_json = authorized["execution_nonce"].clone();

        // A legitimate reconcile settles the invocation reservation: the debited
        // invocation stays consumed (the call ran), it is not refunded.
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 0, "currency": "USD" },
        });
        let (status, reconciled) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reconciled["status"], "reconciled");

        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert_eq!(
            usage.map(|usage| usage.invocation_count).unwrap_or(0),
            1,
            "a legitimate reconcile must keep the invocation consumed, not refund it"
        );

        // The single invocation stays consumed: a later authorization is denied.
        let after_body = serde_json::json!({
            "capability": serde_json::to_value(&cap).unwrap(),
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-reconcile-after",
        });
        let (_, after) = post_evaluate(state, &after_body).await;
        assert_eq!(
            after["status"], "deny",
            "a reconciled invocation stays consumed against max_invocations"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaper_forfeits_expired_invocation_reserve() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        let reserve_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-reap",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &reserve_body).await;
        assert_eq!(authorized["status"], "authorized");

        // Sweep with a far-future clock: the abandoned invocation reservation is
        // past its execution-nonce TTL and is settled at its (zero-money)
        // worst-case, forfeiting the invocation the same way the monetary reaper
        // forfeits reserved money.
        let settled = reap_expired_reserved_holds_once(&state, i64::MAX)
            .await
            .unwrap();
        assert_eq!(
            settled, 1,
            "the expired invocation reservation must be settled"
        );

        // Fail-closed: the forfeited invocation stays consumed, so a new
        // authorization on the single-invocation grant is still denied.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert_eq!(
            usage.map(|usage| usage.invocation_count).unwrap_or(0),
            1,
            "reaping an abandoned invocation reservation forfeits it (stays consumed)"
        );
        let after_body = serde_json::json!({
            "capability": serde_json::to_value(&cap).unwrap(),
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-reap-after",
        });
        let (_, after) = post_evaluate(state, &after_body).await;
        assert_eq!(
            after["status"], "deny",
            "a forfeited invocation reservation must keep the grant committed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_open_invocation_reserve_blocks_oversubscription() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        let first_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-open-1",
        });
        let (_, first) = post_evaluate(Arc::clone(&state), &first_body).await;
        assert_eq!(first["status"], "authorized");

        // While the first invocation reservation is OPEN (debited, not yet
        // reconciled or reaped), a second reserve that would exceed
        // max_invocations is denied: an in-flight reservation still counts, so
        // there is no over-subscription.
        let second_body = serde_json::json!({
            "capability": serde_json::to_value(&cap).unwrap(),
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "invoke-open-2",
        });
        let (_, second) = post_evaluate(state, &second_body).await;
        assert_eq!(
            second["status"], "deny",
            "an open invocation reservation must block a second reserve past max_invocations"
        );
    }

    #[test]
    fn build_budget_store_local_sqlite_when_no_control_url() {
        let dir = std::env::temp_dir().join(format!("chio-budget-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("budget.sqlite");
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: None,
            allow_ephemeral_receipts: true,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: Some(db.to_string_lossy().to_string()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let configured = build_budget_store(&config).unwrap();
        let configured = configured.expect("local sqlite budget store must be built");
        assert!(
            configured.hold_capable,
            "the local sqlite budget store implements the hold APIs and must be hold-capable"
        );
    }

    #[test]
    fn build_budget_store_remote_is_not_hold_capable() {
        // A remote control-plane budget store forwards only
        // charge/reverse/reconcile and falls back to the no-op hold-API defaults,
        // so it must be flagged not hold-capable; the mediated routes then fail
        // closed rather than mint a reservation it can never reconcile or reap.
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: None,
            allow_ephemeral_receipts: true,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: Some("http://127.0.0.1:1".to_string()),
            control_token: Some("token".to_string()),
            budget_db: None,
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let configured = build_budget_store(&config).unwrap();
        let configured = configured.expect("remote budget store must be built");
        assert!(
            !configured.hold_capable,
            "the remote control-plane budget store does not implement the hold APIs"
        );
    }

    #[test]
    fn build_budget_store_prefers_local_hold_capable_when_both_configured() {
        // An operator who configures BOTH a control plane and a local budget DB
        // must get the hold-capable local SQLite store for mediation: the remote
        // store cannot persist a reserved hold, so choosing it would disable
        // mediated authorization and reconcile. Prefer the local store.
        let dir = std::env::temp_dir().join(format!("chio-budget-both-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("budget.sqlite");
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: None,
            allow_ephemeral_receipts: true,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: Some("http://127.0.0.1:1".to_string()),
            control_token: Some("token".to_string()),
            budget_db: Some(db.to_string_lossy().to_string()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let configured = build_budget_store(&config).unwrap();
        let configured = configured.expect("a budget store must be built when both are configured");
        assert!(
            configured.hold_capable,
            "with both configured, mediation must use the hold-capable local store"
        );
        // The returned store is the working local SQLite store: it answers the
        // hold-inventory query rather than a remote endpoint that is never reached.
        assert_eq!(
            configured.store.count_open_holds().unwrap(),
            0,
            "the preferred store must be the functional local hold-capable store"
        );
    }

    fn revocation_db_config(revocation_db: Option<String>) -> ProtectConfig {
        ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: None,
            allow_ephemeral_receipts: true,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: None,
            revocation_db,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        }
    }

    #[test]
    fn load_revocation_db_ids_is_empty_without_configured_store() {
        let ids = load_revocation_db_ids(&revocation_db_config(None)).unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn load_revocation_db_ids_reads_operator_revocations() {
        let dir = std::env::temp_dir().join(format!("chio-revocation-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("revocations.sqlite3");
        let db_path = db.to_string_lossy().to_string();

        // Mirror `chio trust revoke --revocation-db <path>`: an operator writes
        // the revocation to the durable store the sidecar never used to read.
        let store = chio_store_sqlite::SqliteRevocationStore::open(&db).unwrap();
        assert!(chio_kernel::RevocationStore::revoke(&store, "cap-operator-revoked").unwrap());
        drop(store);

        let ids = load_revocation_db_ids(&revocation_db_config(Some(db_path))).unwrap();
        assert!(
            ids.contains("cap-operator-revoked"),
            "durable operator revocation must be loaded into the enforced set"
        );
    }

    #[test]
    fn load_revocation_db_ids_fails_closed_on_unreadable_store() {
        let dir =
            std::env::temp_dir().join(format!("chio-revocation-bad-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("not-a-db.sqlite3");
        std::fs::write(&db, b"this is not a sqlite database").unwrap();

        let result = load_revocation_db_ids(&revocation_db_config(Some(
            db.to_string_lossy().to_string(),
        )));
        assert!(
            result.is_err(),
            "an unreadable revocation-db must fail closed rather than start with no revocations"
        );
    }

    #[test]
    fn mediation_kernel_installs_budget_store_and_strict_nonce_config() {
        let signer = Keypair::generate();
        let budget: Arc<dyn BudgetStore> =
            Arc::new(chio_kernel::budget_store::InMemoryBudgetStore::new());
        let kernel =
            build_mediation_kernel(&signer, Arc::clone(&budget), &[], Vec::new(), None).unwrap();
        // Strict nonce mode is what routes every mediated request through the
        // authorization-reserve path. DPoP verification state is installed here
        // too; the `mediated_dpop_capability_requires_valid_proof` integration
        // test exercises it end to end.
        assert!(
            kernel.execution_nonce_required(),
            "mediation kernel must always run execution-nonce strict mode"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_requires_sidecar_control_token() {
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
            "request_id": "recon-auth-gate",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(authorized["status"], "authorized");
        let nonce_json = authorized["execution_nonce"].clone();

        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });

        // The controlled agent could self-reconcile at cost zero when
        // reconcile was on the public router. Without the sidecar-control token
        // the reconcile is rejected by the trusted-caller gate before it can
        // settle the hold; the gate runs ahead of the handler, so the nonce is
        // not consumed by the rejected attempt.
        let (status, denied) =
            post_json(Arc::clone(&state), "/v1/reconcile", &reconcile_body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(denied["error"], "chio_control_forbidden");

        // Presenting the control token (the tool server's trust boundary) settles.
        let (status, reconciled) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reconciled["status"], "reconciled");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_without_configured_control_token_is_rejected() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let params = serde_json::json!({ "invoice": "inv-1" });

        // Mint a genuine reserved nonce on a control-token-bearing sidecar so the
        // reconcile body deserializes; the reconcile is then attempted against a
        // sidecar with no configured control token. Evaluate itself fails closed
        // without a control token, so the nonce must come from a configured one.
        let with_token = mediated_test_state(signer.clone(), Arc::clone(&budget), Vec::new());
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-no-token",
        });
        let (_, authorized) = post_evaluate(with_token, &body).await;
        let nonce_json = authorized["execution_nonce"].clone();
        assert!(nonce_json.is_object());

        // No sidecar-control token configured on this sidecar.
        let state = mediated_test_state_with_control_token(signer, budget, Vec::new(), None);

        // Fail-closed: with no control token configured there is no trusted
        // caller, so reconcile is rejected outright rather than left open.
        // Presenting any bearer cannot help because none is configured to match.
        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 0, "currency": "USD" },
        });
        let (status, denied) = post_reconcile(state, &reconcile_body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(denied["error"], "chio_control_forbidden");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_needs_no_tool_server_registration() {
        // The reserve-for-caller path no longer requires the target
        // tool server to be registered, so the route registers nothing. Many
        // distinct caller-arbitrary server ids each authorize, and because the
        // handler holds the kernel behind a shared (non-mut) lock it cannot
        // register a server or otherwise grow the kernel's tool-server map.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        for index in 0..8 {
            let server = format!("arbitrary-srv-{index}");
            let cap =
                issue_cost_bearing_capability(&kernel, &agent, &server, "invoke", 100, 1000, "USD");
            let body = serde_json::json!({
                "capability": cap,
                "tool_server": server,
                "tool_name": "invoke",
                "parameters": {},
                "request_id": format!("noreg-{index}"),
            });
            let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                json["status"], "authorized",
                "an arbitrary caller server id must authorize without any registration"
            );
            assert!(json["execution_nonce"].is_object());
        }
    }

    #[test]
    fn minted_request_id_window_bounds_reuse_and_expiry() {
        let mut window = MintedRequestIdWindow::new(30);
        // A fresh id is claimed; an immediate reuse inside the window is rejected.
        assert!(window.claim("req-a", 1_000));
        assert!(!window.claim("req-a", 1_000));
        assert_eq!(window.len(), 1);

        // Releasing an id (a denied/failed authorization) makes it reusable at once.
        window.release("req-a");
        assert_eq!(window.len(), 0);
        assert!(window.claim("req-a", 1_000));

        // Distinct live ids accumulate, but a later claim prunes entries whose
        // reservation TTL has lapsed, so the set stays bounded and an expired id
        // is reusable again.
        assert!(window.claim("req-b", 1_010));
        assert_eq!(window.len(), 2);
        // At 1_031, "req-a" (expires 1_030) is pruned; "req-b" (expires 1_040)
        // is still live.
        assert!(window.claim("req-c", 1_031));
        assert_eq!(window.len(), 2);
        assert!(window.claim("req-a", 1_031));
        assert_eq!(window.len(), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_denied_authorization_does_not_burn_request_id() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        // max_cost_per_invocation (100) exceeds max_total_cost (40): the
        // reservation is refused, so the authorization is denied and places no
        // durable hold.
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 40, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": {},
            "request_id": "denied-then-retry",
        });

        let (status, first) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["status"], "deny");

        // A denied authorization must not permanently burn the id.
        // Reusing it is NOT a 409 conflict; it is evaluated again (and denied
        // again), proving the claim was released.
        let (status, second) = post_evaluate(Arc::clone(&state), &body).await;
        assert_ne!(
            status,
            StatusCode::CONFLICT,
            "a denied authorization must release its request-id claim"
        );
        assert_eq!(second["status"], "deny");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reserved_hold_reaper_handle_is_retained_not_detached() {
        let signer = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let state = mediated_test_state(signer, budget, Vec::new());

        // No reaper before spawn.
        assert!(state.reaper_handle.lock().await.is_none());

        // The reaper's JoinHandle is retained on the shared state,
        // not dropped/detached, so it can be aborted on shutdown.
        spawn_reserved_hold_reaper(&state).await;
        {
            let guard = state.reaper_handle.lock().await;
            let handle = guard
                .as_ref()
                .expect("the reaper handle must be retained on the state");
            assert!(
                !handle.is_finished(),
                "the retained reaper handle must reference a live, abortable task"
            );
        }

        // The retained handle is abortable; aborting cancels the reaper task.
        let handle = state.reaper_handle.lock().await.take().unwrap();
        handle.abort();
        assert!(
            handle.await.is_err(),
            "aborting the retained handle must cancel the reaper task"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_returns_authoritative_receipt_when_persistence_fails() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let signer_pub = signer.public_key();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();

        // A working receipt store so the evaluate that mints the nonce persists.
        let (db, receipt_store) = open_temp_receipt_store();
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(receipt_store),
            true,
        );
        let params = serde_json::json!({ "invoice": "inv-1" });

        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-persist-fail",
        });
        let (status, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(authorized["status"], "authorized");
        let nonce_json = authorized["execution_nonce"].clone();
        assert!(nonce_json.is_object());

        // The reconcile consumes the nonce and settles the reserved hold
        // IRREVERSIBLY before persisting its receipt. Drop the receipt table so the
        // post-settle append fails: unlike a reversible reservation, the settled
        // spend cannot be undone, so the authoritative receipt is the only proof.
        let dropper = rusqlite::Connection::open(&db).unwrap();
        dropper.execute("DROP TABLE tool_receipts", []).unwrap();
        drop(dropper);

        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json.clone(),
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        let (status, reconciled) = post_reconcile(Arc::clone(&state), &reconcile_body).await;

        // The settlement already happened, so the caller must receive the
        // authoritative receipt rather than a 500 that discards the only proof.
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reconciled["status"], "reconciled");
        let receipt: ChioReceipt = serde_json::from_value(reconciled["receipt"].clone()).unwrap();
        let nonce: SignedExecutionNonce = serde_json::from_value(nonce_json).unwrap();
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[signer_pub], &nonce),
            Ok(()),
            "a persistence failure after settlement must still return the authoritative receipt"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_still_fails_closed_on_replayed_nonce_when_persistence_fails() {
        // The receipt-persistence carve-out is scoped to a SUCCESSFUL settle: a
        // real reconcile ERROR (here a replayed, already-consumed nonce) must still
        // fail closed, never reaching receipt persistence.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let (db, receipt_store) = open_temp_receipt_store();
        let state = mediated_test_state_inner(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(receipt_store),
            true,
        );
        let params = serde_json::json!({ "invoice": "inv-1" });

        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "recon-replay-persist-fail",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        let nonce_json = authorized["execution_nonce"].clone();

        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        // First reconcile settles the hold and consumes the nonce.
        let (status, _) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);

        // Even with receipt persistence broken, a replayed nonce is a reconcile
        // ERROR: it is rejected 4xx and never returns a receipt.
        let dropper = rusqlite::Connection::open(&db).unwrap();
        dropper.execute("DROP TABLE tool_receipts", []).unwrap();
        drop(dropper);
        let (status, replay) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(replay["error"], "chio_reconcile_rejected");
        assert!(replay.get("receipt").is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_durable_hold_rejects_request_id_reuse_after_settle() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        // The durable budget store survives a restart; the ProxyState (and its
        // in-memory request-id window) is rebuilt fresh.
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer.clone(), Arc::clone(&budget), Vec::new());
        let params = serde_json::json!({ "invoice": "inv-1" });

        // Reserve a hold under a caller-chosen request_id, then settle it: the
        // durable hold row persists but is no longer open.
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "settled-reuse",
        });
        let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(authorized["status"], "authorized");
        let nonce_json = authorized["execution_nonce"].clone();

        let reconcile_body = serde_json::json!({
            "execution_nonce": nonce_json,
            "arguments": params,
            "realized_cost": { "units": 30, "currency": "USD" },
        });
        let (status, _) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);

        // Restart: a fresh ProxyState with an EMPTY in-memory window sharing only
        // the durable budget store, so the durable reuse guard is the only defense.
        let after = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        // Reusing the settled request_id must be rejected 409: the durable hold id
        // is already spent, so passing it through would let the kernel reject the
        // duplicate hold id and turn a valid later authorization into a 500.
        let (status, replay) = post_evaluate(Arc::clone(&after), &body).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(replay["error"], "chio_request_id_reused");
        assert_ne!(replay["status"], "authorized");
        assert!(
            replay["execution_nonce"].is_null(),
            "a reused settled request_id must not mint a second nonce"
        );

        // A fresh request_id still authorizes on the restarted sidecar.
        let fresh_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-2" },
            "request_id": "settled-reuse-fresh",
        });
        let (status, fresh) = post_evaluate(after, &fresh_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fresh["status"], "authorized");
        assert!(fresh["execution_nonce"].is_object());
    }
