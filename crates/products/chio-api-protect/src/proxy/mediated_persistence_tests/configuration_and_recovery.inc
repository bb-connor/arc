    #[test]
    fn prepared_budget_store_opens_local_sqlite_when_no_control_url() {
        let directory = private_test_directory();
        let dir = directory.path();
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
            control_url: None,
            control_token: None,
            budget_db: Some(db.to_string_lossy().to_string()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let prepared = prepare_budget_store(&config).unwrap();
        let configured = open_prepared_budget_store(prepared)
            .unwrap()
            .expect("local sqlite budget store must be built");
        assert!(
            configured.hold_capable,
            "the local sqlite budget store implements the hold APIs and must be hold-capable"
        );
    }

    #[test]
    fn prepared_budget_store_resolves_relative_path_once_and_retains_it() {
        let current_dir = std::env::current_dir().unwrap();
        let directory = tempfile::Builder::new()
            .prefix("chio-relative-budget-")
            .tempdir_in(&current_dir)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(
                directory.path(),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        let relative_path = directory
            .path()
            .strip_prefix(&current_dir)
            .unwrap()
            .join("budget.sqlite");
        let expected_path = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("budget.sqlite")
            .into_os_string()
            .into_string()
            .unwrap();
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
            control_url: None,
            control_token: None,
            budget_db: Some(relative_path.to_string_lossy().into_owned()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };

        let prepared = prepare_budget_store(&config).unwrap();
        let configured = open_prepared_budget_store(prepared)
            .unwrap()
            .expect("relative budget path must build a local store");
        assert_eq!(configured.resolved_path.as_deref(), Some(expected_path.as_str()));
        assert!(std::path::Path::new(&expected_path).is_file());

        let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
        let authorities = build_mediation_admission_authorities_in_directory(
            configured.resolved_path.as_deref().unwrap(),
            configured.authority_directory.as_ref().unwrap().clone(),
            approval_store,
            None,
        )
        .unwrap();
        assert!(std::path::Path::new(&format!(
            "{expected_path}.admission-operations"
        ))
        .is_file());
        assert!(std::path::Path::new(&format!(
            "{expected_path}.execution-nonces"
        ))
        .is_file());

        drop(authorities);
        drop(configured);
    }

    #[cfg(unix)]
    #[test]
    fn retained_budget_path_survives_configured_symlink_replacement() {
        use std::os::unix::fs::symlink;
        use std::os::unix::fs::PermissionsExt;

        let directory = chio_test_support::private_fs::private_tempdir(
            "api-protect-retained-budget-",
        )
        .unwrap();
        let original = directory.path().join("original.sqlite");
        let replacement = directory.path().join("replacement.sqlite");
        std::fs::File::create(&original).unwrap();
        std::fs::File::create(&replacement).unwrap();
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        let configured_link = directory.path().join("configured.sqlite");
        symlink(&original, &configured_link).unwrap();
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
            control_url: None,
            control_token: None,
            budget_db: Some(configured_link.to_string_lossy().into_owned()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };

        let prepared = prepare_budget_store(&config).unwrap();
        let configured = open_prepared_budget_store(prepared)
            .unwrap()
            .expect("symlinked budget path must build a local store");
        let original = std::fs::canonicalize(&original).unwrap();
        let original = original.into_os_string().into_string().unwrap();
        assert_eq!(configured.resolved_path.as_deref(), Some(original.as_str()));

        std::fs::remove_file(&configured_link).unwrap();
        symlink(&replacement, &configured_link).unwrap();
        let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
        let authorities = build_mediation_admission_authorities_in_directory(
            configured.resolved_path.as_deref().unwrap(),
            configured.authority_directory.as_ref().unwrap().clone(),
            approval_store,
            None,
        )
        .unwrap();

        assert!(std::path::Path::new(&format!(
            "{original}.admission-operations"
        ))
        .is_file());
        assert!(!std::path::Path::new(&format!(
            "{}.admission-operations",
            replacement.to_string_lossy()
        ))
        .exists());

        drop(authorities);
        drop(configured);
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_bound_mediation_detects_all_authority_file_substitution() {
        use std::os::unix::fs::PermissionsExt;

        fn replace_with_regular_file(path: &std::path::Path) {
            let displaced = path.with_extension(format!(
                "{}-displaced",
                uuid::Uuid::now_v7()
            ));
            std::fs::rename(path, displaced).unwrap();
            std::fs::File::create(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let directory = chio_test_support::private_fs::private_tempdir(
            "api-protect-descriptor-substitution-",
        )
        .unwrap();
        let budget_path = directory.path().join("budget.sqlite");
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
            control_url: None,
            control_token: None,
            budget_db: Some(budget_path.to_string_lossy().into_owned()),
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let prepared = prepare_budget_store(&config).unwrap();
        let configured = open_prepared_budget_store(prepared)
            .unwrap()
            .expect("local budget authority");
        let resolved_path = configured.resolved_path.as_deref().unwrap();
        let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
        let authorities = build_mediation_admission_authorities_in_directory(
            resolved_path,
            configured.authority_directory.as_ref().unwrap().clone(),
            approval_store,
            None,
        )
        .unwrap();

        replace_with_regular_file(std::path::Path::new(resolved_path));
        assert!(configured.store.count_open_holds().is_err());

        let operation_path = format!("{resolved_path}.admission-operations");
        replace_with_regular_file(std::path::Path::new(&operation_path));
        assert!(authorities.operation_store.load("missing-operation").is_err());

        let nonce_path = format!("{resolved_path}.execution-nonces");
        replace_with_regular_file(std::path::Path::new(&nonce_path));
        assert!(authorities
            .execution_nonce_store
            .reserve("substituted-nonce")
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_bound_mediation_rejects_symlinked_authority_sibling() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = private_test_directory();
        let budget_path = directory.path().join("budget.sqlite");
        let authority_directory = Arc::new(
            chio_store_sqlite::durable_sqlite::TrustedSqliteDirectory::open_for_database(
                &budget_path,
            )
            .unwrap(),
        );
        let foreign = directory.path().join("foreign.sqlite");
        std::fs::File::create(&foreign).unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(
            &foreign,
            format!("{}.admission-operations", budget_path.to_string_lossy()),
        )
        .unwrap();

        let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
        let error = build_mediation_admission_authorities_in_directory(
            &budget_path.to_string_lossy(),
            authority_directory,
            approval_store,
            None,
        )
        .err()
        .expect("symlinked authority sibling must fail closed");
        assert!(error.to_string().contains("admission-operation store"));
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_bound_mediation_requires_one_retained_sibling_parent() {
        let retained_directory = private_test_directory();
        let other_directory = private_test_directory();
        let retained_budget = retained_directory.path().join("budget.sqlite");
        let other_budget = other_directory.path().join("budget.sqlite");
        let authority_directory = Arc::new(
            chio_store_sqlite::durable_sqlite::TrustedSqliteDirectory::open_for_database(
                &retained_budget,
            )
            .unwrap(),
        );
        let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());

        let error = build_mediation_admission_authorities_in_directory(
            &other_budget.to_string_lossy(),
            authority_directory,
            approval_store,
            None,
        )
        .err()
        .expect("authority siblings under a different parent must fail closed");
        assert!(error.to_string().contains("does not match retained parent"));
        assert!(!std::path::Path::new(&format!(
            "{}.admission-operations",
            other_budget.to_string_lossy()
        ))
        .exists());
    }

    #[test]
    fn prepared_remote_budget_store_is_not_hold_capable() {
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
            trusted_historical_receipt_signers: Vec::new(),
            control_url: Some("http://127.0.0.1:1".to_string()),
            control_token: Some("token".to_string()),
            budget_db: None,
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };
        let prepared = prepare_budget_store(&config).unwrap();
        let configured = open_prepared_budget_store(prepared)
            .unwrap()
            .expect("remote budget store must be built");
        assert!(
            !configured.hold_capable,
            "the remote control-plane budget store does not implement the hold APIs"
        );
    }

    #[test]
    fn prepared_budget_store_prefers_local_hold_capable_when_both_configured() {
        // An operator who configures BOTH a control plane and a local budget DB
        // must get the hold-capable local SQLite store for mediation: the remote
        // store cannot persist a reserved hold, so choosing it would disable
        // mediated authorization and reconcile. Prefer the local store.
        let directory = private_test_directory();
        let dir = directory.path();
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
            .expect("a budget store must be built when both are configured");
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

    #[test]
    fn prepared_revocation_store_is_empty_without_a_durable_path() {
        let prepared = prepare_revocation_store(None, None).unwrap();
        let (live_store, ids) = open_prepared_revocation_store(prepared).unwrap();
        assert!(live_store.is_some());
        assert!(ids.is_empty());
    }

    #[test]
    fn prepared_revocation_store_loads_and_retains_operator_revocations() {
        let directory = private_test_directory();
        let dir = directory.path();
        let db = dir.join("revocations.sqlite3");
        let db_path = db.to_string_lossy().to_string();

        // Mirror `chio trust revoke --revocation-db <path>`: an operator writes
        // the revocation to the durable store the sidecar never used to read.
        let store = chio_store_sqlite::SqliteRevocationStore::open(&db).unwrap();
        assert!(chio_kernel::RevocationStore::revoke(&store, "cap-operator-revoked").unwrap());
        drop(store);

        let prepared = prepare_revocation_store(Some(&db_path), None).unwrap();
        let (live_store, ids) = open_prepared_revocation_store(prepared).unwrap();
        assert!(
            ids.contains("cap-operator-revoked"),
            "durable operator revocation must be loaded into the enforced set"
        );
        let live_store = live_store.unwrap();
        assert!(
            chio_kernel::RevocationStore::is_revoked(
                live_store.as_ref(),
                "cap-operator-revoked",
            )
            .unwrap(),
            "startup must retain the same live revocation authority after preload"
        );
    }

    #[test]
    fn prepared_revocation_store_fails_closed_on_unreadable_store() {
        let directory = private_test_directory();
        let dir = directory.path();
        let db = dir.join("not-a-db.sqlite3");
        std::fs::write(&db, b"this is not a sqlite database").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let db_path = db.to_string_lossy().into_owned();
        let prepared = prepare_revocation_store(Some(&db_path), None).unwrap();
        let result = open_prepared_revocation_store(prepared);
        assert!(
            result.is_err(),
            "an unreadable revocation-db must fail closed rather than start with no revocations"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_requires_sidecar_control_token() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = durable_test_budget_store();
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
        let budget: Arc<dyn BudgetStore> = durable_test_budget_store();
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
        let budget: Arc<dyn BudgetStore> = durable_test_budget_store();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_denied_authorization_retains_durable_request_id_ownership() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = durable_test_budget_store();
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

        // Fill the capability's budget with a live reservation.
        let occupying_parameters = serde_json::json!({ "invoice": "occupying" });
        let occupying_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": occupying_parameters,
            "request_id": "capacity-owner",
        });
        let (status, occupying) = post_evaluate(Arc::clone(&state), &occupying_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(occupying["status"], "authorized");
        let occupying_nonce = occupying["execution_nonce"].clone();

        // This authenticated request reaches durable operation creation, then
        // denies because the first reservation owns all available capacity.
        let denied_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "denied" },
            "request_id": "denied-owned-id",
        });
        let (status, denied) = post_evaluate(Arc::clone(&state), &denied_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(denied["status"], "deny");
        assert!(denied["receipt"].is_object());
        assert!(denied["execution_nonce"].is_null());

        // Release the occupying exposure. Capacity is now available, but the
        // denied request id still has one durable ToolDispatch owner.
        let reconcile_body = serde_json::json!({
            "execution_nonce": occupying_nonce,
            "arguments": occupying_parameters,
            "realized_cost": { "units": 0, "currency": "USD" },
        });
        let (status, reconciled) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reconciled["status"], "reconciled");

        let usages_before_retry = budget.list_usages(100, None).unwrap();
        let denied_hold_id = format!("budget-hold:denied-owned-id:{}:0", cap.id);
        let denied_hold_before_retry = budget.get_budget_hold(&denied_hold_id).unwrap();
        let tool_log_before_retry =
            serde_json::to_value(&state.tool_receipt_log.lock().await.receipts).unwrap();

        let (status, conflict) = post_evaluate(Arc::clone(&state), &denied_body).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            conflict,
            serde_json::json!({
                "error": "chio_request_id_reused",
                "message": "request_id is unavailable; choose a fresh request_id",
            }),
            "the conflict body must disclose no capability, hold, or prior verdict detail"
        );
        assert!(conflict.get("receipt").is_none());
        assert!(conflict.get("execution_nonce").is_none());
        assert_eq!(budget.list_usages(100, None).unwrap(), usages_before_retry);
        assert_eq!(
            budget.get_budget_hold(&denied_hold_id).unwrap(),
            denied_hold_before_retry
        );
        assert_eq!(
            serde_json::to_value(&state.tool_receipt_log.lock().await.receipts).unwrap(),
            tool_log_before_retry,
            "the conflict must bypass legacy receipt publication"
        );

        // A fresh id is independently evaluated against the now-available
        // capacity and can authorize.
        let fresh_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "fresh" },
            "request_id": "denied-owned-id-fresh",
        });
        let (status, fresh) = post_evaluate(state, &fresh_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fresh["status"], "authorized");
        assert!(fresh["execution_nonce"].is_object());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reserved_hold_reaper_handle_is_retained_not_detached() {
        let signer = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = durable_test_budget_store();
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
                "the retained reaper handle must reference a live, abortable worker"
            );
        }

        // The retained handle is abortable; aborting cancels the reaper worker.
        let handle = state.reaper_handle.lock().await.take().unwrap();
        handle.abort();
        assert!(
            handle.await.is_err(),
            "aborting the retained handle must cancel the reaper worker"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_returns_authoritative_receipt_when_persistence_fails() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let signer_pub = signer.public_key();
        let budget: Arc<dyn BudgetStore> = durable_test_budget_store();
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
        let budget: Arc<dyn BudgetStore> = durable_test_budget_store();
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
        assert_eq!(
            replay,
            serde_json::json!({
                "error": "chio_reconcile_rejected",
                "message": "reconcile request was rejected",
            })
        );
        assert!(replay.get("receipt").is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_durable_hold_rejects_request_id_reuse_after_settle() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let directory =
            chio_test_support::private_fs::private_tempdir("api-protect-hold-restart-").unwrap();
        let (budget, admission_config) =
            durable_mediation_budget_and_admission(directory.path(), None);
        let budget_path = admission_config.budget_path.clone();
        let approval_path = admission_config.approval_path.clone();
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state_core(
            signer.clone(),
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            true,
            None,
            None,
            Some(admission_config),
        );
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

        // Rebuild every mediation authority over the same durable databases.
        drop(state);
        drop(kernel);
        drop(budget);
        let reopened_budget: Arc<dyn BudgetStore> = Arc::new(
            chio_store_sqlite::budget_store::SqliteBudgetStore::open(&budget_path).unwrap(),
        );
        let after = mediated_test_state_core(
            signer,
            Arc::clone(&reopened_budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            true,
            None,
            None,
            Some(TestMediationAdmissionConfig {
                budget_path,
                approval_path,
                threshold_config: None,
            }),
        );

        // Reusing the settled request_id must be rejected 409: the durable hold id
        // is already spent and its operation is no longer replayable.
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_exact_retry_replays_durable_handoff_without_side_effects() {
        let signer = Keypair::from_seed(&[0x31; 32]);
        let agent = Keypair::from_seed(&[0x32; 32]);
        let other_agent = Keypair::from_seed(&[0x33; 32]);
        let directory =
            chio_test_support::private_fs::private_tempdir("api-protect-exact-retry-").unwrap();
        let (budget, admission_config) =
            durable_mediation_budget_and_admission(directory.path(), None);
        let budget_path = admission_config.budget_path.clone();
        let approval_path = admission_config.approval_path.clone();
        let issuing = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let capability = issue_governed_dpop_capability(
            &issuing,
            &agent,
            &[
                ("cost-srv", "compute"),
                ("other-srv", "compute"),
                ("cost-srv", "other-tool"),
            ],
            100,
            1_000,
            "USD",
            50,
        );
        let changed_capability = issue_governed_dpop_capability(
            &issuing,
            &agent,
            &[("cost-srv", "compute")],
            100,
            1_000,
            "USD",
            50,
        );
        let changed_agent_capability = issue_governed_dpop_capability(
            &issuing,
            &other_agent,
            &[("cost-srv", "compute")],
            100,
            1_000,
            "USD",
            50,
        );
        let request_id = "mustprepay-exact-replay";
        let parameters = serde_json::json!({ "invoice": "inv-exact-replay" });
        let intent = governed_mustprepay_intent(
            "intent-exact-replay",
            "cost-srv",
            "compute",
            100,
            "USD",
        );
        let approval =
            governed_approval_token(&signer, &agent.public_key(), &intent, request_id);
        let proof = dpop_proof_for(
            &agent,
            &capability,
            "cost-srv",
            "compute",
            &parameters,
        );
        let body = serde_json::json!({
            "capability": capability,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": parameters,
            "request_id": request_id,
            "governed_intent": intent,
            "approval_token": approval,
            "dpop_proof": proof,
        });

        let adapter = RecordingPaymentAdapter {
            inner: chio_kernel::SimPaymentAdapter::new(),
            ..RecordingPaymentAdapter::default()
        };
        let before = mediated_test_state_core(
            signer.clone(),
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(SqliteReceiptStore::open(&approval_path).unwrap()),
            true,
            Some(Box::new(adapter.clone())),
            None,
            Some(admission_config),
        );
        let (status, authorized_bytes) = post_evaluate_raw(Arc::clone(&before), &body).await;
        assert_eq!(status, StatusCode::OK);
        let authorized: serde_json::Value = serde_json::from_slice(&authorized_bytes).unwrap();
        assert_eq!(authorized["status"], "authorized");
        assert!(authorized["execution_nonce"].is_object());

        let hold_id = format!("budget-hold:{request_id}:{}:0", capability.id);
        drop(before);
        drop(issuing);
        drop(budget);

        let reopened_budget: Arc<dyn BudgetStore> = Arc::new(
            chio_store_sqlite::budget_store::SqliteBudgetStore::open(&budget_path).unwrap(),
        );
        let after = mediated_test_state_core(
            signer.clone(),
            Arc::clone(&reopened_budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            Some(SqliteReceiptStore::open(&approval_path).unwrap()),
            true,
            Some(Box::new(adapter.clone())),
            None,
            Some(TestMediationAdmissionConfig {
                budget_path: budget_path.clone(),
                approval_path: approval_path.clone(),
                threshold_config: None,
            }),
        );

        // Startup recovery may inspect the rail. Freeze every externally visible
        // mutation surface only after the restarted state is ready to serve.
        let rail_calls_before = adapter
            .rail_calls
            .load(std::sync::atomic::Ordering::SeqCst);
        let authorizations_before = adapter
            .authorizations
            .load(std::sync::atomic::Ordering::SeqCst);
        let captures_before = adapter
            .captures
            .load(std::sync::atomic::Ordering::SeqCst);
        let releases_before = adapter
            .releases
            .load(std::sync::atomic::Ordering::SeqCst);
        let refunds_before = adapter
            .refunds
            .load(std::sync::atomic::Ordering::SeqCst);
        let usages_before = reopened_budget.list_usages(100, None).unwrap();
        let hold_before = reopened_budget.get_budget_hold(&hold_id).unwrap();
        let journal_before = reopened_budget.get_payment_journal(request_id).unwrap();
        let operations_before = durable_operation_snapshot(&budget_path, request_id);
        assert_eq!(operations_before.len(), 1);
        let nonce_authority_before = durable_nonce_authority_snapshot(&budget_path);
        assert_eq!(nonce_authority_before.consumed.len(), 1);
        assert!(nonce_authority_before.reservations.is_empty());
        let authoritative_receipt_count_before =
            SqliteReceiptStore::open(&approval_path)
                .unwrap()
                .load_tool_receipts(&after.trusted_receipt_signers)
                .unwrap()
                .len();
        let tool_log_before =
            serde_json::to_value(&after.tool_receipt_log.lock().await.receipts).unwrap();
        assert_eq!(
            tool_log_before.as_array().map(|receipts| receipts.len()),
            Some(authoritative_receipt_count_before),
        );

        let (status, replayed_bytes) = post_evaluate_raw(Arc::clone(&after), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            replayed_bytes, authorized_bytes,
            "exact retry must replay the original response bytes"
        );
        assert_eq!(
            adapter
                .rail_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            rail_calls_before,
            "exact replay must not inspect or mutate the payment rail"
        );
        assert_eq!(
            reopened_budget.list_usages(100, None).unwrap(),
            usages_before,
            "exact replay must not mutate budget usage"
        );
        assert_eq!(
            reopened_budget.get_budget_hold(&hold_id).unwrap(),
            hold_before,
            "exact replay must not mutate the reserved hold"
        );
        assert_eq!(
            reopened_budget.get_payment_journal(request_id).unwrap(),
            journal_before,
            "exact replay must not mutate the payment journal"
        );
        assert_eq!(
            durable_operation_snapshot(&budget_path, request_id),
            operations_before,
            "exact replay must not mutate the admission operation"
        );
        assert_eq!(
            durable_nonce_authority_snapshot(&budget_path),
            nonce_authority_before,
            "exact replay must not mutate execution-nonce or DPoP authority"
        );
        assert_eq!(
            SqliteReceiptStore::open(&approval_path)
                .unwrap()
                .load_tool_receipts(&after.trusted_receipt_signers)
                .unwrap()
                .len(),
            authoritative_receipt_count_before,
            "exact replay must not append an authoritative receipt"
        );
        assert_eq!(
            serde_json::to_value(&after.tool_receipt_log.lock().await.receipts).unwrap(),
            tool_log_before,
            "exact replay must bypass legacy receipt publication"
        );

        let other_server_intent = governed_mustprepay_intent(
            "intent-exact-other-server",
            "other-srv",
            "compute",
            100,
            "USD",
        );
        let other_server_approval = governed_approval_token(
            &signer,
            &agent.public_key(),
            &other_server_intent,
            request_id,
        );
        let other_server_proof = dpop_proof_for(
            &agent,
            &capability,
            "other-srv",
            "compute",
            &parameters,
        );
        let other_tool_intent = governed_mustprepay_intent(
            "intent-exact-other-tool",
            "cost-srv",
            "other-tool",
            100,
            "USD",
        );
        let other_tool_approval = governed_approval_token(
            &signer,
            &agent.public_key(),
            &other_tool_intent,
            request_id,
        );
        let other_tool_proof = dpop_proof_for(
            &agent,
            &capability,
            "cost-srv",
            "other-tool",
            &parameters,
        );
        let changed_capability_proof = dpop_proof_for(
            &agent,
            &changed_capability,
            "cost-srv",
            "compute",
            &parameters,
        );
        let changed_agent_approval =
            governed_approval_token(&signer, &other_agent.public_key(), &intent, request_id);
        let changed_agent_proof = dpop_proof_for(
            &other_agent,
            &changed_agent_capability,
            "cost-srv",
            "compute",
            &parameters,
        );
        let fresh_proof = dpop_proof_for(
            &agent,
            &capability,
            "cost-srv",
            "compute",
            &parameters,
        );
        let conflicts = [
            serde_json::json!({
                "capability": capability,
                "tool_server": "other-srv",
                "tool_name": "compute",
                "parameters": parameters,
                "request_id": request_id,
                "governed_intent": other_server_intent,
                "approval_token": other_server_approval,
                "dpop_proof": other_server_proof,
            }),
            serde_json::json!({
                "capability": capability,
                "tool_server": "cost-srv",
                "tool_name": "other-tool",
                "parameters": parameters,
                "request_id": request_id,
                "governed_intent": other_tool_intent,
                "approval_token": other_tool_approval,
                "dpop_proof": other_tool_proof,
            }),
            serde_json::json!({
                "capability": changed_capability,
                "tool_server": "cost-srv",
                "tool_name": "compute",
                "parameters": parameters,
                "request_id": request_id,
                "governed_intent": intent,
                "approval_token": approval,
                "dpop_proof": changed_capability_proof,
            }),
            serde_json::json!({
                "capability": changed_agent_capability,
                "tool_server": "cost-srv",
                "tool_name": "compute",
                "parameters": parameters,
                "request_id": request_id,
                "governed_intent": intent,
                "approval_token": changed_agent_approval,
                "dpop_proof": changed_agent_proof,
            }),
            serde_json::json!({
                "capability": capability,
                "tool_server": "cost-srv",
                "tool_name": "compute",
                "parameters": parameters,
                "request_id": request_id,
                "governed_intent": intent,
                "approval_token": approval,
                "dpop_proof": fresh_proof,
            }),
        ];
        let expected_conflict = serde_json::json!({
            "error": "chio_request_id_reused",
            "message": "request_id is unavailable; choose a fresh request_id",
        });
        for changed in conflicts {
            let (status, conflict) = post_evaluate(Arc::clone(&after), &changed).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(conflict, expected_conflict);
            assert!(conflict.get("receipt").is_none());
            assert!(conflict.get("execution_nonce").is_none());
        }
        assert_eq!(
            adapter
                .rail_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            rail_calls_before
        );
        assert_eq!(
            adapter
                .authorizations
                .load(std::sync::atomic::Ordering::SeqCst),
            authorizations_before
        );
        assert_eq!(
            adapter
                .captures
                .load(std::sync::atomic::Ordering::SeqCst),
            captures_before
        );
        assert_eq!(
            adapter
                .releases
                .load(std::sync::atomic::Ordering::SeqCst),
            releases_before
        );
        assert_eq!(
            adapter
                .refunds
                .load(std::sync::atomic::Ordering::SeqCst),
            refunds_before
        );
        assert_eq!(reopened_budget.list_usages(100, None).unwrap(), usages_before);
        assert_eq!(
            reopened_budget.get_budget_hold(&hold_id).unwrap(),
            hold_before
        );
        assert_eq!(
            reopened_budget.get_payment_journal(request_id).unwrap(),
            journal_before
        );
        assert_eq!(
            serde_json::to_value(&after.tool_receipt_log.lock().await.receipts).unwrap(),
            tool_log_before,
            "request-id conflicts must bypass legacy receipt publication"
        );

        // Mutations that fail capability subject or scope authentication are
        // ordinary signed denials. They must not reveal whether the request id
        // names an existing reservation.
        let unauthenticated_agent = serde_json::json!({
            "capability": capability,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "agent_id": "not-the-capability-subject",
            "parameters": parameters,
            "request_id": request_id,
            "governed_intent": intent,
            "approval_token": approval,
            "dpop_proof": proof,
        });
        let unauthorized_server = serde_json::json!({
            "capability": capability,
            "tool_server": "unauthorized-srv",
            "tool_name": "compute",
            "parameters": parameters,
            "request_id": request_id,
            "governed_intent": intent,
            "approval_token": approval,
            "dpop_proof": dpop_proof_for(
                &agent,
                &capability,
                "unauthorized-srv",
                "compute",
                &parameters,
            ),
        });
        for unauthenticated in [unauthenticated_agent, unauthorized_server] {
            let (status, denied) = post_evaluate(Arc::clone(&after), &unauthenticated).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(denied["status"], "deny");
            assert!(denied["receipt"].is_object());
            assert!(denied["execution_nonce"].is_null());
        }
        assert_eq!(
            adapter
                .rail_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            rail_calls_before
        );
        assert_eq!(reopened_budget.list_usages(100, None).unwrap(), usages_before);
        assert_eq!(
            reopened_budget.get_budget_hold(&hold_id).unwrap(),
            hold_before
        );
        assert_eq!(
            reopened_budget.get_payment_journal(request_id).unwrap(),
            journal_before
        );

        {
            let kernel = after.mediation_kernel.as_ref().unwrap().lock().await;
            kernel.emergency_stop("exact replay test stop").unwrap();
        }
        let (status, stopped) = post_evaluate(Arc::clone(&after), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stopped["status"], "deny");
        assert!(stopped["receipt"].is_object());
        assert!(stopped["execution_nonce"].is_null());
        assert_ne!(stopped, authorized, "emergency stop must win before replay");
        {
            let kernel = after.mediation_kernel.as_ref().unwrap().lock().await;
            kernel.emergency_resume().unwrap();
        }
        let tool_log_before_resumed_replay =
            serde_json::to_value(&after.tool_receipt_log.lock().await.receipts).unwrap();
        let (status, resumed) = post_evaluate(Arc::clone(&after), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resumed, authorized);
        assert_eq!(
            serde_json::to_value(&after.tool_receipt_log.lock().await.receipts).unwrap(),
            tool_log_before_resumed_replay,
            "resumed exact replay must still bypass legacy receipt publication"
        );

        after
            .revoked_capability_ids
            .lock()
            .await
            .insert(capability.id.clone());
        let (status, revoked) = post_evaluate(Arc::clone(&after), &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(revoked["error"], "chio_capability_revoked");
        assert!(revoked.get("receipt").is_none());
        assert!(revoked.get("execution_nonce").is_none());

        assert_eq!(
            adapter
                .rail_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            rail_calls_before
        );
        assert_eq!(reopened_budget.list_usages(100, None).unwrap(), usages_before);
        assert_eq!(
            reopened_budget.get_budget_hold(&hold_id).unwrap(),
            hold_before
        );
        assert_eq!(
            reopened_budget.get_payment_journal(request_id).unwrap(),
            journal_before
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_dpop_replay_is_rejected_after_durable_state_restart() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let directory =
            chio_test_support::private_fs::private_tempdir("api-protect-dpop-restart-").unwrap();
        let (budget, admission_config) =
            durable_mediation_budget_and_admission(directory.path(), None);
        let budget_path = admission_config.budget_path.clone();
        let approval_path = admission_config.approval_path.clone();
        let issuing = issuing_kernel(&signer, Arc::clone(&budget), &[]);
        let cap = issue_dpop_capability_with_total(
            &issuing, &agent, "cost-srv", "compute", 100, 1_000, "USD",
        );
        let cap_value = serde_json::to_value(&cap).unwrap();
        let params = serde_json::json!({ "invoice": "inv-dpop-restart" });
        let proof = dpop_proof_for(&agent, &cap, "cost-srv", "compute", &params);
        let before = mediated_test_state_core(
            signer.clone(),
            Arc::clone(&budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            true,
            None,
            None,
            Some(admission_config),
        );
        let first_body = serde_json::json!({
            "capability": cap_value.clone(),
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params.clone(),
            "request_id": "dpop-restart-1",
            "dpop_proof": proof.clone(),
        });
        let (status, first) = post_evaluate(Arc::clone(&before), &first_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["status"], "authorized");
        assert!(first["execution_nonce"].is_object());

        // Rebuild every API Protect and kernel authority over the same durable
        // databases. The first reservation remains open, but the capability's
        // total budget permits another reservation so replay is the only denial.
        drop(before);
        drop(issuing);
        drop(budget);
        let reopened_budget: Arc<dyn BudgetStore> = Arc::new(
            chio_store_sqlite::budget_store::SqliteBudgetStore::open(&budget_path).unwrap(),
        );
        let after = mediated_test_state_core(
            signer,
            Arc::clone(&reopened_budget),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
            None,
            true,
            None,
            None,
            Some(TestMediationAdmissionConfig {
                budget_path,
                approval_path,
                threshold_config: None,
            }),
        );
        let replay_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": params,
            "request_id": "dpop-restart-2",
            "dpop_proof": proof,
        });
        let (status, replay) = post_evaluate(after, &replay_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay["status"], "deny");
        assert!(replay["execution_nonce"].is_null());
        assert!(replay["receipt"]["decision"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("nonce replayed")));
    }
