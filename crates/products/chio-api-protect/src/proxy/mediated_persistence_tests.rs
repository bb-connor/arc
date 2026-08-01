    #[test]
    fn revocation_preload_is_bounded_to_the_newest_acceleration_window() {
        let directory = tempfile::tempdir().test_unwrap();
        let path = directory.path().join("revocations.sqlite3");
        let store = chio_store_sqlite::SqliteRevocationStore::open(&path).test_unwrap();
        let total = REVOCATION_ACCELERATION_CACHE_MAX_IDS + 17;

        for index in 0..total {
            store
                .upsert_revocation(&chio_kernel::RevocationRecord {
                    capability_id: format!("cap-revocation-{index:04}"),
                    revoked_at: i64::try_from(index).test_unwrap(),
                })
                .test_unwrap();
        }

        let loaded = load_revocation_store_ids(&store, &path.to_string_lossy()).test_unwrap();
        assert_eq!(loaded.len(), REVOCATION_ACCELERATION_CACHE_MAX_IDS);
        let first_retained = total - REVOCATION_ACCELERATION_CACHE_MAX_IDS;
        assert!(loaded.contains(&format!("cap-revocation-{first_retained:04}")));
        assert!(loaded.contains(&format!("cap-revocation-{:04}", total - 1)));
        assert!(!loaded.contains("cap-revocation-0000"));
        assert!(
            chio_kernel::RevocationStore::is_revoked(&store, "cap-revocation-0000")
                .test_unwrap(),
            "an entry outside the cache window must remain authoritative in the live store"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_authorization_works_with_both_control_url_and_budget_db() {
        // With BOTH a control plane and a local budget DB configured, the
        // prepare/open budget path hands mediation the hold-capable local
        // SQLite store, so `/v1/evaluate` authorizes (minting a reserved nonce)
        // and `/v1/reconcile` settles. This exercises the exact store the
        // sidecar selects from that configuration.
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
            trusted_historical_receipt_signers: Vec::new(),
            control_url: Some("http://127.0.0.1:1".to_string()),
            control_token: Some("token".to_string()),
            budget_db: Some(db.to_string_lossy().to_string()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let prepared = prepare_budget_store(&config).unwrap();
        let configured = open_prepared_budget_store(prepared)
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
        let dir = chio_test_support::private_fs::private_tempdir("chio-receipt-")
            .unwrap()
            .keep();
        let db = dir.join("receipts.sqlite");
        let store = SqliteReceiptStore::open(&db.to_string_lossy()).unwrap();
        (db, store)
    }

    fn durable_operation_snapshot(
        budget_path: &str,
        request_id: &str,
    ) -> Vec<chio_kernel::AdmissionOperation> {
        let store = chio_store_sqlite::SqliteSecurityAdmissionOperationStore::open(format!(
            "{budget_path}.admission-operations"
        ))
        .unwrap();
        store
            .load_by_request_id(
                chio_kernel::AdmissionOperationKind::ToolDispatch,
                request_id,
                2,
            )
            .unwrap()
    }

    #[derive(Debug, PartialEq, Eq)]
    struct DurableNonceAuthoritySnapshot {
        consumed: Vec<(String, i64, i64)>,
        reservations: Vec<(String, String, i64, String)>,
    }

    fn durable_nonce_authority_snapshot(budget_path: &str) -> DurableNonceAuthoritySnapshot {
        let connection = rusqlite::Connection::open(format!(
            "{budget_path}.execution-nonces"
        ))
        .unwrap();
        let consumed = {
            let mut statement = connection
                .prepare(
                    "SELECT nonce_id, consumed_at, expires_at \
                     FROM chio_execution_nonces ORDER BY nonce_id",
                )
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        let reservations = {
            let mut statement = connection
                .prepare(
                    "SELECT operation_id, nonce_id, signed_expires_at, state \
                     FROM chio_execution_nonce_reservations ORDER BY operation_id",
                )
                .unwrap();
            statement
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        DurableNonceAuthoritySnapshot {
            consumed,
            reservations,
        }
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

    fn failing_http_receipt_store() -> SqliteReceiptStore {
        let (db, store) = open_temp_receipt_store();
        let dropper = rusqlite::Connection::open(&db).unwrap();
        dropper.execute("DROP TABLE http_receipts", []).unwrap();
        drop(dropper);
        store
    }

    /// A legacy HTTP receipt writer whose revoked-capabilities mirror fails,
    /// while the authoritative revocation store remains healthy.
    fn failing_revocation_mirror_store() -> SqliteReceiptStore {
        let (db, store) = open_temp_receipt_store();
        let dropper = rusqlite::Connection::open(&db).unwrap();
        dropper
            .execute("DROP TABLE revoked_capabilities", [])
            .unwrap();
        drop(dropper);
        store
    }

    struct FailingAuthoritativeRevocationStore;

    impl chio_kernel::RevocationStore for FailingAuthoritativeRevocationStore {
        fn is_revoked(
            &self,
            _capability_id: &str,
        ) -> Result<bool, chio_kernel::RevocationStoreError> {
            Ok(false)
        }

        fn revoke(
            &self,
            _capability_id: &str,
        ) -> Result<bool, chio_kernel::RevocationStoreError> {
            Err(chio_kernel::RevocationStoreError::Sync(
                "sensitive backend path /var/lib/chio/revocations.db".to_string(),
            ))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authoritative_release_failure_leaves_cache_and_legacy_mirror_unchanged() {
        let signer = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let (_, receipt_store) = open_temp_receipt_store();
        let authority: Arc<dyn chio_kernel::RevocationStore> =
            Arc::new(FailingAuthoritativeRevocationStore);
        let state = mediated_test_state_core(
            signer,
            budget,
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(receipt_store),
            true,
            None,
            Some(authority),
            None,
        );

        let (status, json) = post_json(
            Arc::clone(&state),
            "/v1/capabilities/release",
            &serde_json::json!({ "capability_id": "cap-authority-failure" }),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"], "chio_capability_release_failed");
        assert_eq!(json["message"], "capability release could not be recorded");
        assert!(!json.to_string().contains("/var/lib/chio"));
        assert!(state.revoked_capability_ids.lock().await.is_empty());
        assert!(
            state
                .receipt_store
                .as_ref()
                .unwrap()
                .lock()
                .await
                .load_revoked_capability_ids()
                .unwrap()
                .is_empty(),
            "an authoritative write failure must not commit the legacy mirror"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn representative_internal_failures_return_fixed_client_bodies() {
        let synthetic = ProtectError::ReceiptSign(
            "sensitive signing backend /var/lib/chio/signer.key".to_string(),
        );
        let response = evaluation_error_response(&synthetic);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["message"], "request evaluation failed");
        assert!(!json.to_string().contains("/var/lib/chio"));

        let signer = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let state = mediated_test_state_inner(
            signer,
            budget,
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(failing_http_receipt_store()),
            true,
        );
        let (status, json) = post_json(
            state,
            "/v1/receipts",
            &serde_json::json!({
                "job_name": "job",
                "namespace": "default",
                "job_uid": "job-1",
                "outcome": "succeeded",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"], "chio_receipt_persistence_failed");
        assert_eq!(json["message"], "failed to persist submitted sidecar receipt");
        assert!(!json.to_string().contains("no such table"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn legacy_mirror_failure_cannot_hide_an_authoritative_release() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let issuing = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let capability = issue_cost_bearing_capability(
            &issuing,
            &agent,
            "cost-srv",
            "compute",
            100,
            1000,
            "USD",
        );
        let capability_id = capability.id.clone();
        let authority: Arc<dyn chio_kernel::RevocationStore> =
            Arc::new(chio_kernel::InMemoryRevocationStore::new());
        let state = mediated_test_state_core(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(failing_revocation_mirror_store()),
            true,
            None,
            Some(Arc::clone(&authority)),
            None,
        );

        let (status, json) = post_json(
            Arc::clone(&state),
            "/v1/capabilities/release",
            &serde_json::json!({ "capability_id": capability_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert!(
            state
                .revoked_capability_ids
                .lock()
                .await
                .contains(&capability.id)
        );
        assert!(
            chio_kernel::RevocationStore::is_revoked(authority.as_ref(), &capability.id).unwrap()
        );
        assert!(
            state
                .mediation_kernel
                .as_ref()
                .unwrap()
                .lock()
                .await
                .is_capability_revoked(&capability.id)
                .unwrap()
        );

        let (evaluate_status, evaluate_json) = post_evaluate(
            state,
            &serde_json::json!({
                "capability": capability,
                "tool_server": "cost-srv",
                "tool_name": "compute",
                "parameters": { "invoice": "inv-mirror-failure" },
            }),
        )
        .await;
        assert_eq!(evaluate_status, StatusCode::FORBIDDEN);
        assert_eq!(evaluate_json["error"], "chio_capability_revoked");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn release_preserves_exact_identifier_without_cross_id_revocation() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let issuing = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let capability = issue_cost_bearing_capability(
            &issuing,
            &agent,
            "cost-srv",
            "compute",
            100,
            1000,
            "USD",
        );
        let exact_release_id = format!(" {} ", capability.id);
        let authority: Arc<dyn chio_kernel::RevocationStore> =
            Arc::new(chio_kernel::InMemoryRevocationStore::new());
        let state = mediated_test_state_core(
            signer,
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            true,
            None,
            Some(Arc::clone(&authority)),
            None,
        );

        let (status, json) = post_json(
            Arc::clone(&state),
            "/v1/capabilities/release",
            &serde_json::json!({ "capability_id": exact_release_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert!(
            chio_kernel::RevocationStore::is_revoked(authority.as_ref(), &exact_release_id)
                .unwrap()
        );
        assert!(
            !chio_kernel::RevocationStore::is_revoked(authority.as_ref(), &capability.id).unwrap()
        );

        let (evaluate_status, evaluate_json) = post_evaluate(
            state,
            &serde_json::json!({
                "capability": capability,
                "tool_server": "cost-srv",
                "tool_name": "compute",
                "parameters": { "invoice": "inv-exact-id" },
            }),
        )
        .await;
        assert_eq!(evaluate_status, StatusCode::OK, "{evaluate_json}");
        assert_eq!(evaluate_json["status"], "authorized");
    }

    /// A payment adapter that counts each rail action, so a test can assert a
    /// captured MustPrepay prepayment is neither refunded nor re-charged. The
    /// settlement behavior is delegated to the deterministic sim adapter.
    #[derive(Clone, Default)]
    struct RecordingPaymentAdapter {
        inner: chio_kernel::SimPaymentAdapter,
        rail_calls: Arc<std::sync::atomic::AtomicUsize>,
        authorizations: Arc<std::sync::atomic::AtomicUsize>,
        captures: Arc<std::sync::atomic::AtomicUsize>,
        releases: Arc<std::sync::atomic::AtomicUsize>,
        refunds: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl chio_kernel::PaymentAdapter for RecordingPaymentAdapter {
        fn rail_id(&self) -> &str {
            self.inner.rail_id()
        }

        fn supports_operation_authorization_recovery(&self) -> bool {
            self.inner.supports_operation_authorization_recovery()
        }

        fn supports_operation_payment_mutations(&self) -> bool {
            self.inner.supports_operation_payment_mutations()
        }

        fn authorize(
            &self,
            request: &chio_kernel::PaymentAuthorizeRequest,
        ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
            self.rail_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.authorizations
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.authorize(request)
        }

        fn capture(
            &self,
            authorization_id: &str,
            amount_units: u64,
            currency: &str,
            reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.rail_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            self.rail_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            self.rail_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.refunds
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner
                .refund(transaction_id, amount_units, currency, reference)
        }

        fn authorize_for_operation(
            &self,
            operation_id: &str,
            request_binding_hash: &str,
            request: &chio_kernel::PaymentAuthorizeRequest,
        ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
            self.rail_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.authorizations
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner
                .authorize_for_operation(operation_id, request_binding_hash, request)
        }

        fn lookup_authorization_for_operation(
            &self,
            operation_id: &str,
            request_binding_hash: &str,
        ) -> Result<Option<chio_kernel::PaymentAuthorization>, chio_kernel::PaymentError> {
            self.rail_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner
                .lookup_authorization_for_operation(operation_id, request_binding_hash)
        }

        fn capture_for_operation(
            &self,
            request: chio_kernel::OperationPaymentCaptureRequest<'_>,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.rail_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.captures
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.capture_for_operation(request)
        }

        fn release_for_operation(
            &self,
            operation_id: &str,
            request_binding_hash: &str,
            authorization_id: &str,
            reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.rail_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.releases
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.release_for_operation(
                operation_id,
                request_binding_hash,
                authorization_id,
                reference,
            )
        }

        fn refund_for_operation(
            &self,
            request: chio_kernel::OperationPaymentRefundRequest<'_>,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.rail_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.refunds
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.refund_for_operation(request)
        }

        fn settlement_state_for_operation(
            &self,
            operation_id: &str,
            request_binding_hash: &str,
            reference: &str,
            authorization_id: Option<&str>,
        ) -> Result<chio_kernel::RailSettlementState, chio_kernel::PaymentError> {
            self.rail_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.settlement_state_for_operation(
                operation_id,
                request_binding_hash,
                reference,
                authorization_id,
            )
        }

        fn settlement_state(
            &self,
            reference: &str,
            authorization_id: Option<&str>,
        ) -> Result<chio_kernel::RailSettlementState, chio_kernel::PaymentError> {
            self.rail_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.settlement_state(reference, authorization_id)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hold_capable_mediation_rejects_missing_durable_receipt_authority_at_startup() {
        let directory = tempfile::tempdir().unwrap();
        let budget_path = directory.path().join("budget.db");
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: None,
            allow_ephemeral_receipts: true,
            sidecar_control_token: Some(MEDIATED_CONTROL_TOKEN.to_string()),
            signer_seed_hex: Some("11".repeat(32)),
            trusted_capability_issuers: Vec::new(),
            trusted_historical_receipt_signers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: Some(budget_path.to_string_lossy().into_owned()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };

        let error = ProtectProxy::new(config)
            .run_with_observer(|_| {
                panic!("missing durable receipt authority must fail before listener bind")
            })
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("hold-capable mediation requires a durable authoritative receipt store"),
            "unexpected startup failure: {error}"
        );
        assert!(
            !budget_path.exists(),
            "receipt validation must run before the budget authority is created"
        );
        assert!(
            !std::path::Path::new(&format!(
                "{}.admission-operations",
                budget_path.to_string_lossy()
            ))
            .exists(),
            "receipt validation must run before the admission authority is created"
        );
        assert!(
            !std::path::Path::new(&format!(
                "{}.execution-nonces",
                budget_path.to_string_lossy()
            ))
            .exists(),
            "receipt validation must run before the nonce authority is created"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalid_budget_topologies_create_no_durable_authority_files() {
        for invalid_budget in ["", ":memory:", "file:budget.db?mode=rwc"] {
            let directory = tempfile::tempdir().unwrap();
            let receipt_path = directory.path().join("receipts.db");
            let budget_path = directory.path().join("budget.db");
            let configured_budget = match invalid_budget {
                "file:budget.db?mode=rwc" => {
                    format!("file:{}?mode=rwc", budget_path.to_string_lossy())
                }
                value => value.to_string(),
            };
            let config = ProtectConfig {
                upstream: "http://127.0.0.1:1".to_string(),
                spec_content: Some(
                    r#"{"openapi":"3.0.3","info":{"title":"Chio","version":"1"},"paths":{}}"#
                        .to_string(),
                ),
                spec_path: None,
                listen_addr: "127.0.0.1:0".to_string(),
                receipt_db: Some(receipt_path.to_string_lossy().into_owned()),
                allow_ephemeral_receipts: false,
                sidecar_control_token: Some(MEDIATED_CONTROL_TOKEN.to_string()),
                signer_seed_hex: Some("10".repeat(32)),
                trusted_capability_issuers: Vec::new(),
                trusted_historical_receipt_signers: Vec::new(),
                control_url: None,
                control_token: None,
                budget_db: Some(configured_budget),
                revocation_db: None,
                require_nonce: false,
                allow_advisory: false,
                upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
            };

            let error = ProtectProxy::new(config)
                .run_with_observer(|_| panic!("invalid budget topology must fail before bind"))
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("budget_db"),
                "unexpected startup failure for {invalid_budget:?}: {error}"
            );
            for path in [
                receipt_path.clone(),
                std::path::PathBuf::from(format!(
                    "{}.revocations",
                    receipt_path.to_string_lossy()
                )),
                budget_path.clone(),
                std::path::PathBuf::from(format!(
                    "{}.admission-operations",
                    budget_path.to_string_lossy()
                )),
                std::path::PathBuf::from(format!(
                    "{}.execution-nonces",
                    budget_path.to_string_lossy()
                )),
            ] {
                assert!(
                    !path.exists(),
                    "invalid budget topology {invalid_budget:?} created {}",
                    path.display()
                );
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn symlink_aliased_receipt_and_revocation_paths_fail_before_database_mutation() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let receipt_path = directory.path().join("receipts.db");
        let revocation_alias = directory.path().join("revocations-alias.db");
        symlink(&receipt_path, &revocation_alias).unwrap();
        let budget_path = directory.path().join("budget.db");
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some(
                r#"{"openapi":"3.0.3","info":{"title":"Chio","version":"1"},"paths":{}}"#
                    .to_string(),
            ),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: Some(receipt_path.to_string_lossy().into_owned()),
            allow_ephemeral_receipts: false,
            sidecar_control_token: Some(MEDIATED_CONTROL_TOKEN.to_string()),
            signer_seed_hex: Some("13".repeat(32)),
            trusted_capability_issuers: Vec::new(),
            trusted_historical_receipt_signers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: Some(budget_path.to_string_lossy().into_owned()),
            revocation_db: Some(revocation_alias.to_string_lossy().into_owned()),
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };

        let error = ProtectProxy::new(config)
            .run_with_observer(|_| panic!("aliased authority topology must fail before bind"))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("durable authority path conflict"),
            "unexpected aliased-topology failure: {error}"
        );
        for path in [
            receipt_path.clone(),
            std::path::PathBuf::from(format!("{}-wal", receipt_path.to_string_lossy())),
            std::path::PathBuf::from(format!("{}-shm", receipt_path.to_string_lossy())),
            std::path::PathBuf::from(format!(
                "{}.revocations",
                receipt_path.to_string_lossy()
            )),
            budget_path.clone(),
            std::path::PathBuf::from(format!(
                "{}.admission-operations",
                budget_path.to_string_lossy()
            )),
            std::path::PathBuf::from(format!(
                "{}.execution-nonces",
                budget_path.to_string_lossy()
            )),
        ] {
            assert!(
                !path.exists(),
                "aliased topology created or mutated durable artifact {}",
                path.display()
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hardlink_aliased_receipt_and_revocation_paths_fail_before_database_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let receipt_path = directory.path().join("receipts.db");
        let revocation_alias = directory.path().join("revocations-hardlink.db");
        std::fs::File::create(&receipt_path).unwrap();
        std::fs::hard_link(&receipt_path, &revocation_alias).unwrap();
        let budget_path = directory.path().join("budget.db");
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some(
                r#"{"openapi":"3.0.3","info":{"title":"Chio","version":"1"},"paths":{}}"#
                    .to_string(),
            ),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: Some(receipt_path.to_string_lossy().into_owned()),
            allow_ephemeral_receipts: false,
            sidecar_control_token: Some(MEDIATED_CONTROL_TOKEN.to_string()),
            signer_seed_hex: Some("16".repeat(32)),
            trusted_capability_issuers: Vec::new(),
            trusted_historical_receipt_signers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: Some(budget_path.to_string_lossy().into_owned()),
            revocation_db: Some(revocation_alias.to_string_lossy().into_owned()),
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };

        let error = ProtectProxy::new(config)
            .run_with_observer(|_| panic!("hardlink alias must fail before listener bind"))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("durable authority path conflict"),
            "unexpected hardlink-alias failure: {error}"
        );
        assert_eq!(std::fs::metadata(&receipt_path).unwrap().len(), 0);
        assert_eq!(std::fs::metadata(&revocation_alias).unwrap().len(), 0);
        for path in [
            std::path::PathBuf::from(format!("{}-wal", receipt_path.to_string_lossy())),
            std::path::PathBuf::from(format!("{}-shm", receipt_path.to_string_lossy())),
            budget_path.clone(),
            std::path::PathBuf::from(format!(
                "{}.admission-operations",
                budget_path.to_string_lossy()
            )),
            std::path::PathBuf::from(format!(
                "{}.execution-nonces",
                budget_path.to_string_lossy()
            )),
        ] {
            assert!(
                !path.exists(),
                "hardlink alias created or mutated durable artifact {}",
                path.display()
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn symlink_aliased_derived_admission_path_fails_before_database_mutation() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let receipt_path = directory.path().join("receipts.db");
        let budget_path = directory.path().join("budget.db");
        let operation_path = std::path::PathBuf::from(format!(
            "{}.admission-operations",
            budget_path.to_string_lossy()
        ));
        let nonce_path = std::path::PathBuf::from(format!(
            "{}.execution-nonces",
            budget_path.to_string_lossy()
        ));
        symlink(&receipt_path, &operation_path).unwrap();
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some(
                r#"{"openapi":"3.0.3","info":{"title":"Chio","version":"1"},"paths":{}}"#
                    .to_string(),
            ),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: Some(receipt_path.to_string_lossy().into_owned()),
            allow_ephemeral_receipts: false,
            sidecar_control_token: Some(MEDIATED_CONTROL_TOKEN.to_string()),
            signer_seed_hex: Some("15".repeat(32)),
            trusted_capability_issuers: Vec::new(),
            trusted_historical_receipt_signers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: Some(budget_path.to_string_lossy().into_owned()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };

        let error = ProtectProxy::new(config)
            .run_with_observer(|_| panic!("derived alias must fail before listener bind"))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("durable authority path conflict"),
            "unexpected derived-alias failure: {error}"
        );
        for path in [
            receipt_path.clone(),
            std::path::PathBuf::from(format!(
                "{}.revocations",
                receipt_path.to_string_lossy()
            )),
            budget_path,
            nonce_path,
        ] {
            assert!(
                !path.exists(),
                "derived alias created durable artifact {}",
                path.display()
            );
        }
        assert!(
            std::fs::symlink_metadata(&operation_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "pure topology validation must leave the fixture symlink untouched"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn durable_mediation_startup_constructs_operation_and_nonce_authorities() {
        let directory =
            chio_test_support::private_fs::private_tempdir("api-protect-startup-authorities-")
                .unwrap();
        let budget_path = directory.path().join("budget.db");
        let receipt_path = directory.path().join("receipts.db");
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some(
                r#"{"openapi":"3.0.3","info":{"title":"Chio","version":"1"},"paths":{}}"#
                    .to_string(),
            ),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: Some(receipt_path.to_string_lossy().into_owned()),
            allow_ephemeral_receipts: false,
            sidecar_control_token: Some(MEDIATED_CONTROL_TOKEN.to_string()),
            signer_seed_hex: Some("12".repeat(32)),
            trusted_capability_issuers: Vec::new(),
            trusted_historical_receipt_signers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: Some(budget_path.to_string_lossy().into_owned()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let operation_path = format!(
            "{}.admission-operations",
            budget_path.to_string_lossy()
        );
        let nonce_path = format!("{}.execution-nonces", budget_path.to_string_lossy());
        let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            ProtectProxy::new(config)
                .run_with_observer(move |address| {
                    bound_tx
                        .send(address)
                        .expect("observer receiver must remain active");
                })
                .await
        });
        let address = tokio::time::timeout(std::time::Duration::from_secs(5), bound_rx)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(address.port(), 0);
        assert!(budget_path.exists());
        assert!(receipt_path.exists());
        assert!(std::path::Path::new(&operation_path).exists());
        assert!(std::path::Path::new(&nonce_path).exists());

        let operation_store =
            chio_store_sqlite::SqliteSecurityAdmissionOperationStore::open(&operation_path).unwrap();
        assert!(operation_store
            .authority_profile()
            .supports_dispatch_workers(1));
        let nonce_store = chio_store_sqlite::SqliteExecutionNonceStore::open(&nonce_path).unwrap();
        assert!(nonce_store
            .authority_profile()
            .supports_dispatch_workers(1));

        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn configured_revocation_database_is_a_live_production_route_authority() {
        let directory =
            chio_test_support::private_fs::private_tempdir("api-protect-live-revocation-")
                .unwrap();
        let budget_path = directory.path().join("budget.db");
        let receipt_path = directory.path().join("receipts.db");
        let revocation_path = directory.path().join("operator-revocations.db");
        let signer = Keypair::from_seed(&[0x14; 32]);
        let agent = Keypair::generate();
        let issuing_budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let issuing = issuing_kernel(&signer, issuing_budget, &[]);
        let capability = issue_cost_bearing_capability(
            &issuing,
            &agent,
            "cost-srv",
            "compute",
            100,
            1000,
            "USD",
        );
        let capability_id = capability.id.clone();
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some(
                r#"{"openapi":"3.0.3","info":{"title":"Chio","version":"1"},"paths":{}}"#
                    .to_string(),
            ),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: Some(receipt_path.to_string_lossy().into_owned()),
            allow_ephemeral_receipts: false,
            sidecar_control_token: Some(MEDIATED_CONTROL_TOKEN.to_string()),
            signer_seed_hex: Some("14".repeat(32)),
            trusted_capability_issuers: Vec::new(),
            trusted_historical_receipt_signers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: Some(budget_path.to_string_lossy().into_owned()),
            revocation_db: Some(revocation_path.to_string_lossy().into_owned()),
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            ProtectProxy::new(config)
                .run_with_observer(move |address| {
                    bound_tx
                        .send(address)
                        .expect("observer receiver must remain active");
                })
                .await
        });
        let address = tokio::time::timeout(std::time::Duration::from_secs(5), bound_rx)
            .await
            .unwrap()
            .unwrap();
        let client = reqwest::Client::new();
        let request_body = |request_id: &str| {
            serde_json::json!({
                "capability": capability.clone(),
                "tool_server": "cost-srv",
                "tool_name": "compute",
                "parameters": { "invoice": "inv-live-revocation" },
                "request_id": request_id,
            })
        };
        let post = |body: serde_json::Value| {
            client
                .post(format!("http://{address}/v1/evaluate"))
                .header("content-type", "application/json")
                .body(serde_json::to_vec(&body).unwrap())
                .send()
        };

        let before = post(request_body("before-live-revocation"))
            .await
            .unwrap();
        assert_eq!(before.status(), StatusCode::OK);

        let second_handle =
            chio_store_sqlite::SqliteRevocationStore::open(&revocation_path).unwrap();
        assert!(
            chio_kernel::RevocationStore::revoke(&second_handle, &capability_id).unwrap(),
            "the external operator handle must record a new revocation"
        );

        let after = post(request_body("after-live-revocation"))
            .await
            .unwrap();
        assert_eq!(after.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = serde_json::from_slice(&after.bytes().await.unwrap()).unwrap();
        assert_eq!(body["error"], "chio_capability_revoked");

        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn changed_signer_restart_with_unresolved_operation_mutates_nothing() {
        let directory =
            chio_test_support::private_fs::private_tempdir("api-protect-signer-restart-")
                .unwrap();
        let budget_path = directory.path().join("budget.db");
        let receipt_path = directory.path().join("receipts.db");
        let operation_path = format!(
            "{}.admission-operations",
            budget_path.to_string_lossy()
        );
        let old_signer = Keypair::from_seed(&[0x11; 32]);
        let changed_seed_hex = "22".repeat(32);

        // Leave a no-payment caller reservation in the exact pre-stamp crash
        // window. Startup recovery may reverse it, but only after admission
        // ownership has been validated against every unresolved operation.
        let hold_id = "budget-hold:signer-rotation-crash:cap-legacy:0";
        let budget = chio_store_sqlite::budget_store::SqliteBudgetStore::open(&budget_path)
            .unwrap();
        let decision = budget
            .authorize_budget_hold(chio_kernel::budget_store::BudgetAuthorizeHoldRequest::legacy(
                "cap-legacy".to_string(),
                0,
                Some(1),
                7,
                Some(7),
                Some(7),
                Some(hold_id.to_string()),
                Some(format!(
                    "{hold_id}{}",
                    chio_kernel::budget_store::CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX
                )),
                None,
            ))
            .unwrap();
        assert!(matches!(
            decision,
            chio_kernel::budget_store::BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        let hold_before = budget.get_budget_hold(hold_id).unwrap().unwrap();
        let usage_before = budget.get_usage("cap-legacy", 0).unwrap().unwrap();
        drop(budget);

        // Persist an unresolved operation owned by the original signer. A valid
        // but different restart seed must fail closed on this immutable owner.
        let operation_store =
            chio_store_sqlite::SqliteSecurityAdmissionOperationStore::open(&operation_path).unwrap();
        let operation = chio_kernel::AdmissionOperation::prepared(
            chio_kernel::PreparedAdmissionOperation {
                kind: chio_kernel::AdmissionOperationKind::ToolDispatch,
                coordinator_authority_id: format!(
                    "kernel:{}",
                    old_signer.public_key().to_hex()
                ),
                request_id: "signer-rotation-unresolved".to_string(),
                capability_id: "cap-operation".to_string(),
                authorization_capability_hash: "33".repeat(32),
                request_binding_hash: "44".repeat(32),
                policy_hash: chio_core_types::sha256_hex(b"chio_api_protect_mediation_v1"),
                broker_attempt_id: None,
                budget_hold_id: Some("budget-hold:signer-rotation-operation".to_string()),
                approval_set_hash: None,
                execution_nonce_id: None,
                coordinator_lease_epoch: 1,
            },
        )
        .unwrap();
        let operation_id = operation.operation_id().to_string();
        operation_store.create_prepared(operation).unwrap();
        let operation_before = operation_store.load(&operation_id).unwrap().unwrap();
        drop(operation_store);

        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: Some(receipt_path.to_string_lossy().into_owned()),
            allow_ephemeral_receipts: false,
            sidecar_control_token: None,
            signer_seed_hex: Some(changed_seed_hex),
            trusted_capability_issuers: Vec::new(),
            trusted_historical_receipt_signers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: Some(budget_path.to_string_lossy().into_owned()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let error = ProtectProxy::new(config)
            .run_with_observer(|_| panic!("authority mismatch must fail before listener bind"))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("belongs to coordinator authority"),
            "unexpected restart failure: {error}"
        );

        let budget = chio_store_sqlite::budget_store::SqliteBudgetStore::open(&budget_path)
            .unwrap();
        assert_eq!(budget.get_budget_hold(hold_id).unwrap().unwrap(), hold_before);
        let usage_after = budget.get_usage("cap-legacy", 0).unwrap().unwrap();
        assert_eq!(usage_after.invocation_count, usage_before.invocation_count);
        assert_eq!(
            usage_after.committed_cost_units().unwrap(),
            usage_before.committed_cost_units().unwrap()
        );

        let operation_store =
            chio_store_sqlite::SqliteSecurityAdmissionOperationStore::open(&operation_path).unwrap();
        assert_eq!(
            operation_store.load(&operation_id).unwrap().unwrap(),
            operation_before,
            "failed restart must not claim or advance the old coordinator's operation"
        );
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
        let directory =
            chio_test_support::private_fs::private_tempdir("api-protect-mustprepay-failure-")
                .unwrap();
        let (budget, admission_config) =
            durable_mediation_budget_and_admission(directory.path(), None);
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_governed_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD", 50);
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let approver = signer.clone();

        let captures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refunds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let adapter = RecordingPaymentAdapter {
            inner: chio_kernel::SimPaymentAdapter::new(),
            rail_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            authorizations: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
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
            Some(admission_config),
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

    include!("mediated_persistence_tests/configuration_and_recovery.inc");
