    #[test]
    fn auth_helpers_and_metered_billing_validation_cover_error_paths() {
        let mut headers = HeaderMap::new();
        let auth_error = bearer_token_from_headers(&headers).test_unwrap_err();
        assert_eq!(auth_error.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            auth_error
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer realm=\"chio-passport-issuance\"")
        );

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer issue-token"),
        );
        assert_eq!(
            bearer_token_from_headers(&headers).test_unwrap(),
            "issue-token"
        );
        assert!(validate_service_auth(&headers, "issue-token").is_ok());
        assert_eq!(
            validate_service_auth(&headers, "")
                .test_unwrap_err()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );

        let mut config = base_config();
        // The admin bearer header carries "issue-token"; align the configured
        // service token so the admin principal resolves and the downstream
        // tenant-token-equals-service-token collision check exercises a real
        // conflict rather than failing the bearer match first.
        config.service_token = "issue-token".to_string();
        config
            .tenant_read_tokens
            .insert("tenant-a".to_string(), "tenant-read-token".to_string());
        let admin_principal = resolve_control_read_principal(&headers, &config).test_unwrap();
        assert_eq!(admin_principal, ResolvedControlReadPrincipal::AdminService);
        config
            .tenant_read_tokens
            .insert("tenant-collision".to_string(), "issue-token".to_string());
        assert_eq!(
            resolve_control_read_principal(&headers, &config)
                .test_unwrap_err()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        config.tenant_read_tokens.remove("tenant-collision");

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer tenant-read-token"),
        );
        let tenant_principal = resolve_control_read_principal(&headers, &config).test_unwrap();
        assert_eq!(
            tenant_principal,
            ResolvedControlReadPrincipal::TenantRead {
                tenant_id: "tenant-a".to_string()
            }
        );
        assert!(validate_service_auth(&headers, "issue-token").is_err());
        assert!(tenant_principal
            .authorize_evidence_export_query(EvidenceExportQuery::admin_all())
            .is_err());
        let tenant_export = tenant_principal
            .authorize_evidence_export_query(EvidenceExportQuery::default())
            .test_unwrap();
        assert_eq!(tenant_export.tenant.as_deref(), Some("tenant-a"));
        assert_eq!(
            tenant_export.read_boundary,
            Some(ReceiptReadBoundary::TenantScoped {
                tenant: "tenant-a".to_string()
            })
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer issue-token"),
        );
        let invalid_auth = validate_service_auth(&headers, "other-token").test_unwrap_err();
        assert_eq!(invalid_auth.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            invalid_auth
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer")
        );

        let cluster_state =
            state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        let issued_at = unix_timestamp_now() as i64;
        let peer_key = deterministic_cluster_test_key("http://node-b");
        let body_digest = cluster_empty_body_digest();
        let nonce = uuid::Uuid::new_v4().to_string();
        headers = signed_cluster_test_headers(
            &peer_key,
            "http://node-b",
            "http://node-a",
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
            issued_at,
            &nonce,
            None,
            &body_digest,
        );
        let peer = validate_cluster_peer_empty_request(
            &headers,
            &cluster_state.config,
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap();
        assert_eq!(peer.node_id, "http://node-b");

        let receiver_b =
            state_with_cluster("http://node-b", &["http://node-a"], None, None, None);
        let receiver_c =
            state_with_cluster("http://node-c", &["http://node-a"], None, None, None);
        let sender_a_key = deterministic_cluster_test_key("http://node-a");
        let receiver_bound = signed_cluster_test_headers(
            &sender_a_key,
            "http://node-a",
            "http://node-b",
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
            issued_at,
            &uuid::Uuid::new_v4().to_string(),
            None,
            &body_digest,
        );
        validate_cluster_peer_empty_request(
            &receiver_bound,
            &receiver_b.config,
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap();
        assert_eq!(
            validate_cluster_peer_empty_request(
                &receiver_bound,
                &receiver_c.config,
                "GET",
                INTERNAL_CLUSTER_STATUS_PATH,
            )
            .test_unwrap_err()
            .status(),
            StatusCode::UNAUTHORIZED
        );
        clear_cluster_peer_auth_failures(&cluster_peer_auth_unverified_failure_key(
            "http://node-a",
            INTERNAL_CLUSTER_STATUS_PATH,
        ));

        let replay = validate_cluster_peer_empty_request(
            &headers,
            &cluster_state.config,
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap_err();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

        let expired_issued_at = issued_at - CLUSTER_AUTH_MAX_SKEW_SECS - 1;
        let expired_headers = signed_cluster_test_headers(
            &peer_key,
            "http://node-b",
            "http://node-a",
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
            expired_issued_at,
            &uuid::Uuid::new_v4().to_string(),
            None,
            &body_digest,
        );
        let expired_peer = validate_cluster_peer_empty_request(
            &expired_headers,
            &cluster_state.config,
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap_err();
        assert_eq!(expired_peer.status(), StatusCode::UNAUTHORIZED);
        clear_cluster_peer_auth_failures("http://node-b");

        let wrong_key_headers = signed_cluster_test_headers(
            &deterministic_cluster_test_key("http://node-c"),
            "http://node-b",
            "http://node-a",
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
            issued_at,
            &uuid::Uuid::new_v4().to_string(),
            None,
            &body_digest,
        );
        let mismatched_key = validate_cluster_peer_empty_request(
            &wrong_key_headers,
            &cluster_state.config,
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap_err();
        assert_eq!(mismatched_key.status(), StatusCode::UNAUTHORIZED);
        clear_cluster_peer_auth_failures(&cluster_peer_auth_unverified_failure_key(
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
        ));

        let unknown_headers = signed_cluster_test_headers(
            &deterministic_cluster_test_key("http://node-c"),
            "http://node-c",
            "http://node-a",
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
            issued_at,
            &uuid::Uuid::new_v4().to_string(),
            None,
            &body_digest,
        );
        let unknown_peer = validate_cluster_peer_empty_request(
            &unknown_headers,
            &cluster_state.config,
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap_err();
        assert_eq!(unknown_peer.status(), StatusCode::FORBIDDEN);

        let mut bearer_only = HeaderMap::new();
        bearer_only.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        assert_eq!(
            validate_cluster_peer_empty_request(
                &bearer_only,
                &cluster_state.config,
                "GET",
                INTERNAL_CLUSTER_STATUS_PATH,
            )
            .test_unwrap_err()
            .status(),
            StatusCode::UNAUTHORIZED
        );

        let mut duplicate_header = signed_cluster_test_headers(
            &peer_key,
            "http://node-b",
            "http://node-a",
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
            issued_at,
            &uuid::Uuid::new_v4().to_string(),
            None,
            &body_digest,
        );
        duplicate_header.append(
            CLUSTER_AUTH_METHOD_HEADER,
            HeaderValue::from_static("GET"),
        );
        assert_eq!(
            validate_cluster_peer_empty_request(
                &duplicate_header,
                &cluster_state.config,
                "GET",
                INTERNAL_CLUSTER_STATUS_PATH,
            )
            .test_unwrap_err()
            .status(),
            StatusCode::UNAUTHORIZED
        );

        for (header_name, changed_value) in [
            (CLUSTER_AUTH_METHOD_HEADER, "POST"),
            (CLUSTER_AUTH_TERM_HEADER, "9"),
            (CLUSTER_AUTH_BODY_DIGEST_HEADER, "11"),
            (CLUSTER_AUTH_NONCE_HEADER, "not-a-uuid"),
        ] {
            let mut mutated = signed_cluster_test_headers(
                &peer_key,
                "http://node-b",
                "http://node-a",
                "GET",
                INTERNAL_CLUSTER_STATUS_PATH,
                issued_at,
                &uuid::Uuid::new_v4().to_string(),
                Some(8),
                &body_digest,
            );
            mutated.insert(header_name, HeaderValue::from_str(changed_value).test_unwrap());
            assert_eq!(
                validate_cluster_peer_empty_request(
                    &mutated,
                    &cluster_state.config,
                    "GET",
                    INTERNAL_CLUSTER_STATUS_PATH,
                )
                .test_unwrap_err()
                .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        clear_cluster_peer_auth_failures(&cluster_peer_auth_unverified_failure_key(
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
        ));

        let mut changed_timestamp = signed_cluster_test_headers(
            &peer_key,
            "http://node-b",
            "http://node-a",
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
            issued_at,
            &uuid::Uuid::new_v4().to_string(),
            None,
            &body_digest,
        );
        changed_timestamp.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&issued_at.saturating_add(1).to_string()).test_unwrap(),
        );
        assert_eq!(
            validate_cluster_peer_empty_request(
                &changed_timestamp,
                &cluster_state.config,
                "GET",
                INTERNAL_CLUSTER_STATUS_PATH,
            )
            .test_unwrap_err()
            .status(),
            StatusCode::UNAUTHORIZED
        );

        let mut changed_digest = signed_cluster_test_headers(
            &peer_key,
            "http://node-b",
            "http://node-a",
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
            issued_at,
            &uuid::Uuid::new_v4().to_string(),
            None,
            &body_digest,
        );
        changed_digest.insert(
            CLUSTER_AUTH_BODY_DIGEST_HEADER,
            HeaderValue::from_str(&"11".repeat(32)).test_unwrap(),
        );
        assert_eq!(
            validate_cluster_peer_empty_request(
                &changed_digest,
                &cluster_state.config,
                "GET",
                INTERNAL_CLUSTER_STATUS_PATH,
            )
            .test_unwrap_err()
            .status(),
            StatusCode::UNAUTHORIZED
        );
        clear_cluster_peer_auth_failures(&cluster_peer_auth_unverified_failure_key(
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
        ));

        let endpoint_bound = signed_cluster_test_headers(
            &peer_key,
            "http://node-b",
            "http://node-a",
            "GET",
            INTERNAL_CLUSTER_STATUS_PATH,
            issued_at,
            &uuid::Uuid::new_v4().to_string(),
            None,
            &body_digest,
        );
        assert_eq!(
            validate_cluster_peer_empty_request(
                &endpoint_bound,
                &cluster_state.config,
                "GET",
                INTERNAL_CLUSTER_SNAPSHOT_PATH,
            )
            .test_unwrap_err()
            .status(),
            StatusCode::UNAUTHORIZED
        );

        let mut request = MeteredBillingReconciliationUpdateRequest {
            receipt_id: "receipt-1".to_string(),
            adapter_kind: "usage-adapter".to_string(),
            evidence_id: "evidence-1".to_string(),
            observed_units: 3,
            billed_cost: MonetaryAmount {
                units: 25,
                currency: "USD".to_string(),
            },
            evidence_sha256: Some("digest".to_string()),
            recorded_at: 44,
            reconciliation_state: MeteredBillingReconciliationState::Open,
            note: None,
        };
        assert!(validate_metered_billing_reconciliation_request(&request).is_ok());

        request.receipt_id.clear();
        assert_eq!(
            validate_metered_billing_reconciliation_request(&request),
            Err("receiptId must not be empty".to_string())
        );
        request.receipt_id = "receipt-1".to_string();
        request.observed_units = 0;
        assert_eq!(
            validate_metered_billing_reconciliation_request(&request),
            Err("observedUnits must be greater than zero".to_string())
        );
        request.observed_units = 3;
        request.billed_cost.currency.clear();
        assert_eq!(
            validate_metered_billing_reconciliation_request(&request),
            Err("billedCost.currency must not be empty".to_string())
        );
        request.billed_cost.currency = "USD".to_string();
        request.evidence_sha256 = Some(String::new());
        assert_eq!(
            validate_metered_billing_reconciliation_request(&request),
            Err("evidenceSha256 must not be empty when provided".to_string())
        );
    }

    #[test]
    fn trust_service_config_boundary_rejects_invalid_auth_material_and_cluster_timing() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));

        let mut blank_tenant_id = base_config();
        blank_tenant_id
            .tenant_read_tokens
            .insert(" ".to_string(), "tenant-read-token".to_string());
        assert_eq!(
            resolve_control_read_principal(&headers, &blank_tenant_id)
                .test_unwrap_err()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );

        let mut blank_tenant_token = base_config();
        blank_tenant_token
            .tenant_read_tokens
            .insert("tenant-a".to_string(), "   ".to_string());
        assert_eq!(
            resolve_control_read_principal(&headers, &blank_tenant_token)
                .test_unwrap_err()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );

        let mut zero_cluster_interval = base_config();
        zero_cluster_interval.advertise_url = Some("http://127.0.0.1:3200".to_string());
        zero_cluster_interval.peer_urls = vec!["http://127.0.0.1:3300".to_string()];
        zero_cluster_interval.cluster_sync_interval = Duration::ZERO;
        let error = build_cluster_state(&zero_cluster_interval, zero_cluster_interval.listen)
            .test_unwrap_err();
        assert!(error
            .to_string()
            .contains("cluster sync interval must be non-zero"));
    }

    #[test]
    fn cluster_snapshot_round_trip_copies_receipts_revocations_lineage_and_budgets() {
        let source_receipt_db = unique_temp_path("cluster-source-receipts", "sqlite3");
        let source_budget_db = unique_temp_path("cluster-source-budgets", "sqlite3");
        let source_revocation_db = source_budget_db.clone();
        let target_receipt_db = unique_temp_path("cluster-target-receipts", "sqlite3");
        let target_budget_db = unique_temp_path("cluster-target-budgets", "sqlite3");
        let target_revocation_db = target_budget_db.clone();

        let source_state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            Some(source_receipt_db.clone()),
            Some(source_revocation_db.clone()),
            Some(source_budget_db.clone()),
        );
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            Some(target_receipt_db.clone()),
            Some(target_revocation_db.clone()),
            Some(target_budget_db.clone()),
        );

        {
            let revocation_store = SqliteRevocationStore::open(&source_revocation_db).test_unwrap();
            revocation_store
                .upsert_revocation(&RevocationRecord {
                    capability_id: "cap-1".to_string(),
                    revoked_at: 17,
                })
                .test_unwrap();
        }
        {
            let receipt_store = SqliteReceiptStore::open(&source_receipt_db).test_unwrap();
            receipt_store
                .append_chio_receipt(&sample_tool_receipt("tool-1", "cap-1"))
                .test_unwrap();
            receipt_store
                .append_child_receipt(&sample_child_receipt("child-1", "alpha"))
                .test_unwrap();
            receipt_store
                .record_capability_snapshot(&sample_capability("cap-1"), None)
                .test_unwrap();
        }
        {
            let budget_store = SqliteBudgetStore::open(&source_budget_db).test_unwrap();
            budget_store
                .try_charge_cost_with_ids(
                    "cap-1",
                    0,
                    Some(4),
                    9,
                    Some(9),
                    Some(32),
                    Some("hold-1"),
                    Some("hold-1:authorize"),
                )
                .test_unwrap();
            budget_store
                .reduce_charge_cost_with_ids("cap-1", 0, 4, Some("hold-1"), Some("hold-1:release"))
                .test_unwrap();
        }

        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        assert_eq!(snapshot.replication.tool_seq, 1);
        assert_eq!(snapshot.replication.child_seq, 1);
        assert_eq!(snapshot.replication.lineage_seq, 1);
        assert_eq!(snapshot.replication.budget_seq, 2);
        assert_eq!(snapshot.budget_invocation_quotas.len(), 1);
        assert_eq!(
            snapshot.budget_invocation_quotas[0]
                .usage
                .quota
                .max_invocations,
            4
        );
        assert_eq!(
            snapshot.budget_invocation_quotas[0]
                .usage
                .captured_invocations_after,
            1
        );
        assert_eq!(snapshot.budget_mutation_events.len(), 2);
        assert_eq!(
            snapshot
                .budget_mutation_events
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["hold-1:authorize", "hold-1:release"]
        );
        assert_eq!(
            snapshot
                .replication
                .revocation_cursor
                .as_ref()
                .test_unwrap()
                .capability_id,
            "cap-1"
        );

        let generated_at = snapshot.generated_at;
        apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap();

        let revocations = SqliteRevocationStore::open(&target_revocation_db)
            .test_unwrap()
            .list_revocations_after(MAX_LIST_LIMIT, None, None)
            .test_unwrap();
        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].capability_id, "cap-1");

        let receipt_store = SqliteReceiptStore::open(&target_receipt_db).test_unwrap();
        assert_eq!(
            receipt_store
                .list_tool_receipts_after_seq(0, MAX_LIST_LIMIT)
                .test_unwrap()
                .len(),
            1
        );
        assert_eq!(
            receipt_store
                .list_child_receipts_after_seq(0, MAX_LIST_LIMIT)
                .test_unwrap()
                .len(),
            1
        );
        assert_eq!(
            receipt_store
                .list_capability_snapshots_after_seq(0, MAX_LIST_LIMIT)
                .test_unwrap()
                .len(),
            1
        );

        let budgets = SqliteBudgetStore::open(&target_budget_db)
            .test_unwrap()
            .list_usages_after(MAX_LIST_LIMIT, None)
            .test_unwrap();
        assert_eq!(budgets.len(), 1);
        assert_eq!(budgets[0].invocation_count, 1);
        assert_eq!(budgets[0].total_cost_exposed, 5);
        assert_eq!(budgets[0].total_cost_realized_spend, 0);
        let target_budget_store = SqliteBudgetStore::open(&target_budget_db).test_unwrap();
        let replicated_quota = target_budget_store
            .get_compatibility_invocation_quota_usage("cap-1", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(replicated_quota.usage.quota.max_invocations(), 4);
        assert_eq!(replicated_quota.usage.captured_invocations_after, 1);
        let mutation_events = target_budget_store
            .list_mutation_events(10, Some("cap-1"), Some(0))
            .test_unwrap();
        assert_eq!(
            mutation_events
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["hold-1:authorize", "hold-1:release"]
        );

        assert_eq!(peer_tool_seq(&target_state, "http://node-a"), 1);
        assert_eq!(peer_child_seq(&target_state, "http://node-a"), 1);
        assert_eq!(peer_lineage_seq(&target_state, "http://node-a"), 1);
        assert_eq!(
            peer_budget_cursor(&target_state, "http://node-a")
                .test_unwrap()
                .seq,
            2
        );
        assert_eq!(
            peer_revocation_cursor(&target_state, "http://node-a")
                .test_unwrap()
                .capability_id,
            "cap-1"
        );
        assert_eq!(
            with_peer_state(&target_state, "http://node-a", |peer| peer
                .snapshot_applied_count),
            Some(1)
        );
        assert_eq!(
            with_peer_state(&target_state, "http://node-a", |peer| peer.last_snapshot_at),
            Some(Some(generated_at))
        );
        assert!(!peer_should_force_snapshot(&target_state, "http://node-a"));
    }

    #[test]
    fn admission_managed_budget_projection_rejects_legacy_replication_writes() {
        let source_budget_db = unique_temp_path("cluster-managed-source-budget", "sqlite3");
        let managed_db = unique_temp_path("cluster-managed-target-budget", "sqlite3");
        let source_state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            None,
            Some(source_budget_db.clone()),
            Some(source_budget_db.clone()),
        );
        let managed_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            None,
            Some(managed_db.clone()),
            Some(managed_db.clone()),
        );
        SqliteBudgetStore::open(&source_budget_db)
            .test_unwrap()
            .try_charge_cost_with_ids(
                "legacy-capability",
                0,
                Some(4),
                0,
                None,
                None,
                Some("legacy-hold"),
                Some("legacy-event"),
            )
            .test_unwrap();
        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        let _authority = SqliteAdmissionCaptureAuthority::open(&managed_db).test_unwrap();

        apply_cluster_snapshot(&managed_state, "http://node-a", snapshot).test_unwrap();

        let managed_store = SqliteBudgetStore::open(&managed_db).test_unwrap();
        assert!(managed_store
            .list_usages_after(MAX_LIST_LIMIT, None)
            .test_unwrap()
            .is_empty());
        assert!(managed_store
            .list_mutation_events(MAX_LIST_LIMIT, None, None)
            .test_unwrap()
            .is_empty());
        assert!(peer_budget_cursor(&managed_state, "http://node-a").is_none());

        let client = service_runtime::client::build_cluster_peer_client(
            "http://127.0.0.1:9",
            &managed_state.config,
            "http://node-b",
        )
        .test_unwrap();
        let pulled = sync_peer_budgets(
            &managed_state,
            &client,
            "http://node-a",
            &mut PullRoundBudget::new(),
        )
        .test_unwrap();
        assert_eq!(pulled, 0);
    }

    #[test]
    fn cluster_snapshot_round_trip_preserves_denied_budget_events_without_usage_rows() {
        let source_budget_db = unique_temp_path("cluster-source-denied-budgets", "sqlite3");
        let target_budget_db = unique_temp_path("cluster-target-denied-budgets", "sqlite3");

        let source_state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            None,
            Some(source_budget_db.clone()),
            Some(source_budget_db.clone()),
        );
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            None,
            Some(target_budget_db.clone()),
            Some(target_budget_db.clone()),
        );

        {
            let budget_store = SqliteBudgetStore::open(&source_budget_db).test_unwrap();
            let allowed = budget_store
                .try_charge_cost_with_ids(
                    "cap-denied-only",
                    0,
                    Some(1),
                    25,
                    Some(50),
                    Some(10),
                    Some("cap-denied-only-hold-1"),
                    Some("cap-denied-only-hold-1:authorize"),
                )
                .test_unwrap();
            assert!(!allowed);
            assert!(budget_store
                .list_usages_after(MAX_LIST_LIMIT, None)
                .test_unwrap()
                .is_empty());
            let delta =
                collect_budget_mutation_event_views_after_seq(&budget_store, 0, MAX_LIST_LIMIT)
                    .test_unwrap();
            assert_eq!(delta.len(), 1);
            assert_eq!(delta[0].event_seq, 1);
            assert_eq!(delta[0].allowed, Some(false));
            assert_eq!(delta[0].usage_seq, None);
            assert!(collect_budget_mutation_event_views_after_seq(
                &budget_store,
                1,
                MAX_LIST_LIMIT
            )
            .test_unwrap()
            .is_empty());
        }

        let mut omitted_quota_snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        omitted_quota_snapshot.budget_invocation_quotas.clear();
        let omitted_quota_error =
            apply_cluster_snapshot(&target_state, "http://node-a", omitted_quota_snapshot)
                .test_unwrap_err();
        assert!(omitted_quota_error
            .to_string()
            .contains("omitted its immutable quota projection"));
        let target_store = SqliteBudgetStore::open(&target_budget_db).test_unwrap();
        assert_eq!(target_store.max_mutation_event_seq().test_unwrap(), 0);
        assert!(target_store
            .get_compatibility_invocation_quota_usage("cap-denied-only", 0)
            .test_unwrap()
            .is_none());
        drop(target_store);

        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        assert_eq!(snapshot.replication.budget_seq, 1);
        assert!(snapshot.budgets.is_empty());
        assert_eq!(snapshot.budget_invocation_quotas.len(), 1);
        assert_eq!(
            snapshot.budget_invocation_quotas[0]
                .usage
                .quota
                .max_invocations,
            1
        );
        assert_eq!(
            snapshot.budget_invocation_quotas[0]
                .usage
                .captured_invocations_after,
            0
        );
        assert_eq!(snapshot.budget_mutation_events.len(), 1);
        assert_eq!(
            snapshot.budget_mutation_events[0].event_id,
            "cap-denied-only-hold-1:authorize"
        );
        assert_eq!(snapshot.budget_mutation_events[0].event_seq, 1);
        assert_eq!(snapshot.budget_mutation_events[0].allowed, Some(false));
        assert_eq!(snapshot.budget_mutation_events[0].usage_seq, None);

        apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap();

        let target_store = SqliteBudgetStore::open(&target_budget_db).test_unwrap();
        assert!(target_store
            .list_usages_after(MAX_LIST_LIMIT, None)
            .test_unwrap()
            .is_empty());
        let mutation_events = target_store
            .list_mutation_events(10, Some("cap-denied-only"), Some(0))
            .test_unwrap();
        assert_eq!(mutation_events.len(), 1);
        assert_eq!(
            mutation_events[0].event_id,
            "cap-denied-only-hold-1:authorize"
        );
        assert_eq!(mutation_events[0].event_seq, 1);
        assert_eq!(mutation_events[0].allowed, Some(false));
        assert_eq!(mutation_events[0].usage_seq, None);
        let replicated_quota = target_store
            .get_compatibility_invocation_quota_usage("cap-denied-only", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(replicated_quota.usage.quota.max_invocations(), 1);
        assert_eq!(replicated_quota.usage.captured_invocations_after, 0);
        let changed_maximum = target_store
            .try_increment("cap-denied-only", 0, Some(2))
            .test_unwrap_err();
        assert!(changed_maximum.to_string().contains("different maximum"));
        drop(target_store);

        assert_eq!(
            peer_budget_cursor(&target_state, "http://node-a")
                .test_unwrap()
                .seq,
            1
        );
    }

    #[test]
    fn cluster_snapshot_range_encodes_a_huge_abandoned_run_and_the_follower_advances() {
        // The snapshot's abandoned-seq field is RANGE-ENCODED, so a rollback storm's
        // long contiguous abandoned run stays a single small (start, end) pair
        // instead of an unbounded integer list. Enumerated, a real storm's
        // millions-to-billions of seqs blow past MAX_PEER_RESPONSE_BYTES, the client
        // fails to decode cluster_snapshot(), and the force-snapshot recovery path
        // permanently stalls the peer (the snapshot backstop has no further fallback
        // like the delta path does). Range-encoded, the snapshot stays tiny AND a
        // fresh follower still learns every abandoned slot, so its contiguous ack
        // head advances across the whole run.
        let source_budget_db = unique_temp_path("cluster-source-abandoned-storm", "sqlite3");
        let target_budget_db = unique_temp_path("cluster-target-abandoned-storm", "sqlite3");

        let source_state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            None,
            Some(source_budget_db.clone()),
            Some(source_budget_db.clone()),
        );
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            None,
            Some(target_budget_db.clone()),
            Some(target_budget_db.clone()),
        );

        // The abandoned run is (2, RUN_END); boundary events sit at seq 1 and
        // RUN_END + 1, so [1..=RUN_END + 1] is contiguous once the run is recorded.
        const RUN_END: u64 = 100_000;
        let event = |seq: u64| BudgetMutationEventView {
            operation_id: None,
            request_binding_hash: None,
            event_id: format!("evt-{seq}"),
            hold_id: None,
            capability_id: "cap-storm".to_string(),
            grant_index: 0,
            kind: "authorize_exposure".to_string(),
            allowed: Some(true),
            recorded_at: seq as i64,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: 1,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: 1,
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationStateView::Absent,
            monetary_state: BudgetMonetaryHoldStateView::Exposed,
            revocation_set: None,
            total_cost_exposed_after: 1,
            total_cost_realized_spend_after: 0,
            authority: Some(BudgetMutationAuthorityView {
                authority_id: "http://node-a".to_string(),
                lease_id: "http://node-a#term-1".to_string(),
                lease_epoch: 1,
            }),
        };

        {
            let store = SqliteBudgetStore::open(&source_budget_db).test_unwrap();
            import_budget_events_with_quota_authority(&store, &[event(1), event(RUN_END + 1)]);
            // A rollback storm abandons the whole (2, RUN_END) window.
            store
                .record_abandoned_event_seq_ranges(&[(2, RUN_END)])
                .test_unwrap();
        }

        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();

        // The huge run is a SINGLE pair, not RUN_END - 1 integers.
        assert_eq!(snapshot.budget_abandoned_seq_ranges.len(), 1);
        assert_eq!(
            (
                snapshot.budget_abandoned_seq_ranges[0].start,
                snapshot.budget_abandoned_seq_ranges[0].end,
            ),
            (2, RUN_END)
        );

        // The whole range-encoded snapshot fits well under the peer-response cap.
        let encoded = serde_json::to_vec(&snapshot).test_unwrap();
        assert!(
            (encoded.len() as u64) < MAX_PEER_RESPONSE_BYTES,
            "range-encoded snapshot must fit under the peer-response cap, got {} bytes",
            encoded.len()
        );
        // The SAME run enumerated (one integer per seq) is orders of magnitude larger
        // and grows linearly with the run length; a real storm crosses the 64 MiB cap
        // and stalls recovery. Here the abandoned field ALONE dwarfs the whole ranged
        // snapshot.
        let enumerated_len = serde_json::to_vec(&(2..=RUN_END).collect::<Vec<u64>>())
            .test_unwrap()
            .len();
        assert!(
            enumerated_len > 10 * encoded.len(),
            "enumerated abandoned seqs ({enumerated_len} bytes) must dwarf the range-encoded snapshot ({} bytes)",
            encoded.len()
        );

        apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap();

        // The follower learned every abandoned slot, so its contiguous ack head
        // advances across the whole run to the tail event (no stall at the hole).
        let target_store = SqliteBudgetStore::open(&target_budget_db).test_unwrap();
        let head = target_store
            .budget_ack_heads()
            .test_unwrap()
            .into_iter()
            .find(|(origin, _)| origin == "http://node-a")
            .map(|(_, seq)| seq);
        assert_eq!(
            head,
            Some(RUN_END + 1),
            "the follower's contiguous ack head must advance across the abandoned run to the tail event"
        );

        let _ = std::fs::remove_file(&source_budget_db);
        let _ = std::fs::remove_file(&target_budget_db);
    }

    #[test]
    fn cluster_snapshot_round_trip_preserves_budget_usage_rows_without_mutation_events() {
        let source_budget_db = unique_temp_path("cluster-source-budget-usage-only", "sqlite3");
        let target_budget_db = unique_temp_path("cluster-target-budget-usage-only", "sqlite3");

        let source_state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            None,
            Some(source_budget_db.clone()),
            Some(source_budget_db.clone()),
        );
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            None,
            Some(target_budget_db.clone()),
            Some(target_budget_db.clone()),
        );

        {
            let budget_store = SqliteBudgetStore::open(&source_budget_db).test_unwrap();
            budget_store
                .upsert_usage(&chio_kernel::BudgetUsageRecord {
                    capability_id: "cap-usage-only".to_string(),
                    grant_index: 0,
                    invocation_count: 0,
                    updated_at: 1_717_171_717,
                    seq: 42,
                    total_cost_exposed: 550,
                    total_cost_realized_spend: 375,
                })
                .test_unwrap();
            assert!(budget_store
                .list_mutation_events(10, Some("cap-usage-only"), Some(0))
                .test_unwrap()
                .is_empty());
        }

        update_peer_budget_cursor(
            &target_state,
            "http://node-a",
            BudgetCursor {
                seq: 99,
                updated_at: 1_717_171_718,
                capability_id: "stale-capability".to_string(),
                grant_index: 7,
            },
        );

        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        assert_eq!(snapshot.replication.budget_seq, 0);
        assert_eq!(snapshot.budgets.len(), 1);
        assert!(snapshot.budget_invocation_quotas.is_empty());
        assert!(snapshot.budget_mutation_events.is_empty());
        assert_eq!(snapshot.budgets[0].capability_id, "cap-usage-only");
        assert_eq!(snapshot.budgets[0].seq, Some(42));

        apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap();

        let target_store = SqliteBudgetStore::open(&target_budget_db).test_unwrap();
        let usages = target_store
            .list_usages_after(MAX_LIST_LIMIT, None)
            .test_unwrap();
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].capability_id, "cap-usage-only");
        assert_eq!(usages[0].invocation_count, 0);
        assert_eq!(usages[0].seq, 42);
        assert_eq!(usages[0].total_cost_exposed, 550);
        assert_eq!(usages[0].total_cost_realized_spend, 375);
        assert!(target_store
            .list_mutation_events(10, Some("cap-usage-only"), Some(0))
            .test_unwrap()
            .is_empty());
        drop(target_store);

        assert!(
            peer_budget_cursor(&target_state, "http://node-a").is_none(),
            "usage-only snapshots should clear any stale mutation cursor"
        );
    }

    #[test]
    fn budget_cursor_from_event_uses_mutation_event_sequence() {
        let cursor = budget_cursor_from_event(&BudgetMutationEventView {
            operation_id: None,
            request_binding_hash: None,
            event_id: "evt-1".to_string(),
            hold_id: Some("hold-1".to_string()),
            capability_id: "cap-1".to_string(),
            grant_index: 2,
            kind: "authorize_exposure".to_string(),
            allowed: Some(true),
            recorded_at: 1_717_171_717,
            event_seq: 4,
            usage_seq: Some(9),
            exposure_units: 10,
            realized_spend_units: 0,
            max_invocations: Some(5),
            max_cost_per_invocation: Some(10),
            max_total_cost_units: Some(50),
            invocation_count_after: 1,
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationStateView::Absent,
            monetary_state: BudgetMonetaryHoldStateView::Exposed,
            revocation_set: None,
            total_cost_exposed_after: 10,
            total_cost_realized_spend_after: 0,
            authority: None,
        });

        assert_eq!(cursor.seq, 4);
        assert_eq!(cursor.capability_id, "cap-1");
        assert_eq!(cursor.grant_index, 2);
    }

    #[test]
    fn budget_delta_import_rejects_records_without_mutation_events() {
        // The honest leader only emits usage projections alongside the mutation
        // events they derive from. A records-only page
        // would pin the global cursor past unimported events, so it must be a
        // protocol violation (demote), NOT an accepted cursor advance.
        let budget_db = unique_temp_path("cluster-records-only-budget-delta", "sqlite3");
        let mut store = SqliteBudgetStore::open(&budget_db).test_unwrap();
        let response = BudgetDeltaResponse {
            records: vec![BudgetUsageView {
                capability_id: "cap-records-only".to_string(),
                grant_index: 0,
                invocation_count: 3,
                total_cost_exposed: 55,
                total_cost_realized_spend: 21,
                updated_at: 1_717_171_717,
                seq: Some(42),
            }],
            invocation_quotas: Vec::new(),
            mutation_events: Vec::new(),
            abandoned_seqs: Vec::new(),
        };

        let result =
            import_budget_delta_response(&mut store, &response, None, &mut PullRoundBudget::new());
        assert!(
            matches!(
                result,
                Err(PullError::Protocol(
                    PeerProtocolError::RecordsWithoutMutationEvents { record_count: 1 }
                ))
            ),
            "a records-only budget page must be rejected as a protocol violation, got {result:?}"
        );
        // Fail-closed: nothing was imported and the usage row was not created.
        assert!(store
            .get_usage("cap-records-only", 0)
            .test_unwrap()
            .is_none());
    }

    #[test]
    fn budget_delta_import_routes_oversized_page_to_snapshot_recovery() {
        // An HONEST but unpageable budget delta page (a rollback storm packs more
        // abandoned seqs into the covered range than a single page's
        // BUDGET_DELTA_MAX_RECORDS cap) must route the peer through the full snapshot
        // recovery path, NOT return a bare Transient that pins the cursor and stalls
        // the peer's whole sync forever. The signal is PullError::ForceSnapshot;
        // route_pull turns it into a force_snapshot flag
        // (see oversized_budget_delta_routes_peer_to_force_snapshot_not_wedge).
        let budget_db = unique_temp_path("cluster-oversized-budget-delta", "sqlite3");
        let mut store = SqliteBudgetStore::open(&budget_db).test_unwrap();
        let event = |seq: u64| BudgetMutationEventView {
            operation_id: None,
            request_binding_hash: None,
            event_id: format!("evt-{seq}"),
            hold_id: None,
            capability_id: "cap-storm".to_string(),
            grant_index: 0,
            kind: "authorize_exposure".to_string(),
            allowed: Some(true),
            recorded_at: seq as i64,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: 1,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: 1,
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationStateView::Absent,
            monetary_state: BudgetMonetaryHoldStateView::Exposed,
            revocation_set: None,
            total_cost_exposed_after: 1,
            total_cost_realized_spend_after: 0,
            authority: Some(BudgetMutationAuthorityView {
                authority_id: "http://origin-storm".to_string(),
                lease_id: "http://origin-storm#term-1".to_string(),
                lease_epoch: 1,
            }),
        };
        // MAX_LIST_LIMIT live events interspersed with a dense burst of abandoned
        // (rolled-back-then-retried) seqs: events + abandoned exceeds
        // BUDGET_DELTA_MAX_RECORDS for the covered range, so no smaller
        // cursor-anchored page makes forward progress.
        let live_events = MAX_LIST_LIMIT as u64;
        let abandoned_start = live_events + 1;
        let abandoned_end = BUDGET_DELTA_MAX_RECORDS as u64 + 1;
        let response = BudgetDeltaResponse {
            records: Vec::new(),
            invocation_quotas: Vec::new(),
            mutation_events: (1..=live_events).map(event).collect(),
            abandoned_seqs: (abandoned_start..=abandoned_end).collect(),
        };
        let record_count = response.mutation_events.len() + response.abandoned_seqs.len();
        assert!(
            record_count > BUDGET_DELTA_MAX_RECORDS,
            "the crafted page must exceed the record cap to exercise the oversized-page path"
        );

        let result =
            import_budget_delta_response(&mut store, &response, None, &mut PullRoundBudget::new());
        let Err(PullError::ForceSnapshot(error)) = result else {
            panic!(
                "an oversized budget page must route to snapshot recovery, not stall as Transient: {result:?}"
            );
        };
        assert!(error.to_string().contains("full snapshot recovery"));
        // Fail-closed: nothing from the unpageable window was imported as a prefix.
        assert!(store
            .list_mutation_events(10, Some("cap-storm"), Some(0))
            .test_unwrap()
            .is_empty());
    }

    #[test]
    fn oversized_budget_delta_routes_peer_to_force_snapshot_not_wedge() {
        // route_pull must turn a ForceSnapshot into a force_snapshot flag (so the
        // next sync round full-resyncs and makes forward progress) while keeping the
        // peer Healthy (honest backlog, not misbehavior), and short-circuit the
        // round. A bare Transient flags nothing, leaving the cursor pinned
        // indefinitely.
        let state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        update_peer_reachable(&state, "http://node-b");
        assert!(
            !peer_should_force_snapshot(&state, "http://node-b"),
            "a freshly reachable, already-synced peer has no pending snapshot"
        );

        // A bare Transient neither demotes nor flags a snapshot, so the cursor stays
        // pinned and the peer stalls.
        let mut records = 0u64;
        let transient = route_pull(
            &state,
            "http://node-b",
            Err(PullError::Transient(CliError::cli_other_error(
                "oversized transient",
            ))),
            &mut records,
        );
        assert!(transient.is_err(), "a Transient short-circuits the round");
        assert!(
            !peer_should_force_snapshot(&state, "http://node-b"),
            "a bare Transient does NOT trigger snapshot recovery: this is the stall"
        );

        // ForceSnapshot flags the peer for a full resync without demoting it.
        let mut records = 0u64;
        let routed = route_pull(
            &state,
            "http://node-b",
            Err(PullError::ForceSnapshot(CliError::cli_other_error(
                "budget delta response contains 401 records, maximum is 400",
            ))),
            &mut records,
        );
        assert!(
            routed.is_err(),
            "ForceSnapshot short-circuits the round before update_peer_success clears the flag"
        );
        assert!(
            peer_should_force_snapshot(&state, "http://node-b"),
            "an oversized/unpageable page must route the peer to force-snapshot recovery"
        );
        // Not demoted to Unhealthy: an honest large window is not peer misbehavior.
        assert!(
            with_peer_state(&state, "http://node-b", |peer| peer.health.is_reachable())
                .unwrap_or(false),
            "force-snapshot recovery keeps an honest peer Healthy"
        );
        assert_eq!(records, 0, "an unpageable page counts no delta records");
    }

    #[test]
    fn budget_puller_rejects_non_advancing_page() {
        let budget_db = unique_temp_path("cluster-non-advancing-budget-delta", "sqlite3");
        let mut store = SqliteBudgetStore::open(&budget_db).test_unwrap();
        // A non-empty page whose cursor does not advance past the caller's
        // current cursor is a peer protocol violation, not a continuation.
        let cursor = BudgetCursor {
            seq: 40,
            updated_at: 10,
            capability_id: "cap-x".to_string(),
            grant_index: 0,
        };
        let response = BudgetDeltaResponse {
            records: Vec::new(),
            invocation_quotas: Vec::new(),
            mutation_events: vec![BudgetMutationEventView {
                operation_id: None,
                request_binding_hash: None,
                event_id: "evt-stuck".to_string(),
                hold_id: None,
                capability_id: "cap-x".to_string(),
                grant_index: 0,
                kind: "authorize_exposure".to_string(),
                allowed: Some(true),
                recorded_at: 11,
                event_seq: 40, // equal to the cursor: does not advance
                usage_seq: Some(40),
                exposure_units: 1,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after: 1,
                invocation_counts_after: Vec::new(),
                invocation_state: BudgetInvocationReservationStateView::Absent,
                monetary_state: BudgetMonetaryHoldStateView::Exposed,
                revocation_set: None,
                total_cost_exposed_after: 1,
                total_cost_realized_spend_after: 0,
                authority: None,
            }],
            abandoned_seqs: Vec::new(),
        };
        let mut round = PullRoundBudget::new();
        let result = import_budget_delta_response(&mut store, &response, Some(cursor), &mut round);
        // event_seq 40 equals the cursor, so it is neither advancing nor
        // cursor-anchored at the expected next seq (41): a protocol violation
        // that demotes the peer. The contiguity guard now surfaces this as a
        // NonContiguousPage (expected 41, found 40).
        assert!(
            matches!(
                result,
                Err(PullError::Protocol(PeerProtocolError::NonContiguousPage {
                    expected_seq: 41,
                    found_seq: 40
                }))
            ),
            "a non-advancing non-empty budget page must be a protocol violation, got {result:?}"
        );
    }

    #[test]
    fn budget_puller_enforces_strict_global_contiguity() {
        let budget_db = unique_temp_path("cluster-budget-cursor-jump", "sqlite3");
        let mut store = SqliteBudgetStore::open(&budget_db).test_unwrap();

        // A mutation-event view at event_seq S under a single origin.
        let event = |seq: u64| BudgetMutationEventView {
            operation_id: None,
            request_binding_hash: None,
            event_id: format!("evt-{seq}"),
            hold_id: None,
            capability_id: "cap-j".to_string(),
            grant_index: 0,
            kind: "authorize_exposure".to_string(),
            allowed: Some(true),
            recorded_at: seq as i64,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: 1,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: 1,
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationStateView::Absent,
            monetary_state: BudgetMonetaryHoldStateView::Exposed,
            revocation_set: None,
            total_cost_exposed_after: 1,
            total_cost_realized_spend_after: 0,
            authority: Some(BudgetMutationAuthorityView {
                authority_id: "http://origin-j".to_string(),
                lease_id: "http://origin-j#term-1".to_string(),
                lease_epoch: 1,
            }),
        };

        // From a fresh cursor (expected next event_seq 1), a page that starts at
        // event_seq 5 is a forward cursor-jump that would skip the append-only
        // events 1..4. It must be REJECTED and the cursor must NOT advance.
        // The old max-advance-only guard (page max 6 > cursor 0) accepted this.
        let jump = BudgetDeltaResponse {
            records: Vec::new(),
            invocation_quotas: Vec::new(),
            mutation_events: vec![event(5), event(6)],
            abandoned_seqs: Vec::new(),
        };
        let result =
            import_budget_delta_response(&mut store, &jump, None, &mut PullRoundBudget::new());
        assert!(
            matches!(
                result,
                Err(PullError::Protocol(PeerProtocolError::NonContiguousPage {
                    expected_seq: 1,
                    found_seq: 5
                }))
            ),
            "a budget page that skips unreplicated events must be rejected, got {result:?}"
        );
        // Fail-closed: the skipped page was never imported as a committed prefix.
        assert!(store
            .list_mutation_events(10, Some("cap-j"), Some(0))
            .test_unwrap()
            .is_empty());

        // A cursor-anchored, gap-free page from the fresh cursor is accepted and
        // advances the cursor to the page head.
        let contiguous = BudgetDeltaResponse {
            records: vec![BudgetUsageView {
                capability_id: "cap-j".to_string(),
                grant_index: 0,
                invocation_count: 1,
                total_cost_exposed: 1,
                total_cost_realized_spend: 0,
                updated_at: 3,
                seq: Some(3),
            }],
            invocation_quotas: vec![legacy_grant_quota_view("cap-j", 0, u32::MAX, 1, 3)],
            mutation_events: vec![event(1), event(2), event(3)],
            abandoned_seqs: Vec::new(),
        };
        let outcome = import_budget_delta_response(
            &mut store,
            &contiguous,
            None,
            &mut PullRoundBudget::new(),
        )
        .test_unwrap();
        assert!(outcome.should_continue);
        assert_eq!(outcome.next_cursor.test_unwrap().seq, 3);

        // The budget cursor is a single GLOBAL event_seq. A per-origin
        // compaction floor must NOT authorize a global cursor jump: recording
        // origin-j's floor at 9 does not license a page
        // that starts at event_seq 10 from a cursor of 3, because the skipped
        // global seqs 4..9 could carry a DIFFERENT origin's unreplicated events.
        // The jump is a protocol violation regardless of any per-origin floor;
        // fail-closed recovery is a full snapshot, not a floor-authorized jump.
        store
            .record_budget_import_floors(&[
                budget_mutation_record_from_view(&event(10)).test_unwrap()
            ])
            .test_unwrap();
        assert_eq!(
            store.budget_import_floor("http://origin-j").test_unwrap(),
            9
        );
        let cursor = BudgetCursor {
            seq: 3,
            updated_at: 3,
            capability_id: "cap-j".to_string(),
            grant_index: 0,
        };
        let compacted = BudgetDeltaResponse {
            records: Vec::new(),
            invocation_quotas: Vec::new(),
            mutation_events: vec![event(10), event(11)],
            abandoned_seqs: Vec::new(),
        };
        let result = import_budget_delta_response(
            &mut store,
            &compacted,
            Some(cursor),
            &mut PullRoundBudget::new(),
        );
        assert!(
            matches!(
                result,
                Err(PullError::Protocol(PeerProtocolError::NonContiguousPage {
                    expected_seq: 4,
                    found_seq: 10
                }))
            ),
            "a per-origin floor must not license a global cursor jump, got {result:?}"
        );
        // Fail-closed: only the gap-free prefix 1..3 remains committed.
        assert_eq!(store.max_mutation_event_seq().test_unwrap(), 3);
    }

    #[test]
    fn cluster_replication_heads_reports_heads_without_materializing() {
        let budget_db = unique_temp_path("cluster-heads-budget", "sqlite3");
        let revocation_db = budget_db.clone();
        {
            let store = SqliteBudgetStore::open(&budget_db).test_unwrap();
            store
                .try_charge_cost("cap-heads", 0, Some(5), 3, None, None)
                .test_unwrap();
            let revocations = SqliteRevocationStore::open(&revocation_db).test_unwrap();
            revocations
                .upsert_revocation(&RevocationRecord {
                    capability_id: "cap-heads".to_string(),
                    revoked_at: 77,
                })
                .test_unwrap();
        }
        let state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            None,
            Some(revocation_db.clone()),
            Some(budget_db.clone()),
        );
        let heads = cluster_replication_heads(&state).test_unwrap();
        assert_eq!(heads.budget_seq, 1);
        assert_eq!(heads.tool_seq, 0);
        let cursor = heads.revocation_cursor.test_unwrap();
        assert_eq!(cursor.revoked_at, 77);
        assert_eq!(cursor.capability_id, "cap-heads");
    }

    #[test]
    fn status_advertises_contiguous_ack_heads() {
        // Wire shape: budgetAckHeads serializes as camelCase originId/eventSeq
        // when non-empty, and is omitted entirely when empty (additive,
        // backward-compatible with older peers who never witness).
        let response = ClusterStatusResponse {
            self_url: "http://node-a".to_string(),
            leader_url: None,
            role: "follower".to_string(),
            has_quorum: true,
            quorum_size: 2,
            reachable_nodes: 2,
            election_term: 1,
            authority_lease: None,
            replication: ClusterReplicationHeadsView::default(),
            peers: Vec::new(),
            budget_ack_heads: vec![BudgetOriginAck {
                origin_id: "http://origin-o".to_string(),
                event_seq: 3,
            }],
        };
        let value = serde_json::to_value(&response).test_unwrap();
        assert_eq!(value["budgetAckHeads"][0]["originId"], "http://origin-o");
        assert_eq!(value["budgetAckHeads"][0]["eventSeq"], 3);

        // Empty ack heads are omitted from the wire (skip_serializing_if).
        let empty = ClusterStatusResponse {
            budget_ack_heads: Vec::new(),
            ..response
        };
        let value = serde_json::to_value(&empty).test_unwrap();
        assert!(value.get("budgetAckHeads").is_none());
    }

    #[test]
    fn apply_cluster_snapshot_seeds_authority_term_for_late_joiner_budget_writes() {
        let source_state =
            state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        let target_state = state_with_cluster(
            "http://node-0",
            &["http://node-a", "http://node-b"],
            None,
            None,
            None,
        );

        for state in [&source_state, &target_state] {
            let cluster = state.cluster.as_ref().test_unwrap();
            let mut guard = cluster.lock().test_unwrap();
            for peer in guard.peers.values_mut() {
                peer.health = PeerHealth::Healthy;
                peer.last_contact_at = Some(unix_timestamp_now());
            }
        }

        let initial_target_consensus = cluster_consensus_view(&target_state).test_unwrap();
        assert_eq!(
            initial_target_consensus.leader_url.as_deref(),
            Some("http://node-0")
        );
        assert_eq!(initial_target_consensus.election_term, 1);

        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        assert_eq!(snapshot.election_term, 1);
        assert_eq!(
            snapshot.authority_lease.as_ref().test_unwrap().leader_url,
            "http://node-a"
        );

        apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap();

        let seeded_consensus = cluster_consensus_view(&target_state).test_unwrap();
        assert_eq!(
            seeded_consensus.leader_url.as_deref(),
            Some("http://node-0")
        );
        assert_eq!(seeded_consensus.election_term, 2);
        let seeded_lease = cluster_authority_lease_view(&target_state).test_unwrap();
        assert_eq!(seeded_lease.authority_id, "http://node-0");
        assert_eq!(seeded_lease.lease_epoch, 2);
    }

    #[test]
    fn build_cluster_state_rejects_capability_authority_without_bootstrapping_custody() {
        let state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        let authority_db_path = unique_temp_path("cluster-authority-rejected", "sqlite3");
        let mut config = state.config.clone();
        config.authority_db_path = Some(authority_db_path.clone());

        let error = build_cluster_state(&config, config.listen).test_unwrap_err();

        assert!(
            error
                .to_string()
                .contains("shared authority write and selector protocol"),
            "unexpected clustered authority error: {error}"
        );
        assert!(
            !authority_db_path.exists(),
            "rejected clustered authority configuration must not create custody"
        );
    }

    #[test]
    fn clustered_authority_mutation_boundary_fails_closed_even_without_custody() {
        let state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);

        let response = enforce_authority_mutation_fence(&state).test_unwrap_err();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response = refresh_authority_mutation_fence(&state).test_unwrap_err();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn cluster_snapshot_rejects_observational_authority_metadata_before_state_mutation() {
        let source_state =
            state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        let target_state =
            state_with_cluster("http://node-b", &["http://node-a"], None, None, None);
        let authority_db_path = unique_temp_path("cluster-observational-authority", "sqlite3");
        let authority = SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap();
        let mut snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        snapshot.authority = Some(authority_snapshot_view(
            authority.snapshot().test_unwrap(),
        ));
        let term_before = cluster_consensus_view(&target_state)
            .test_unwrap()
            .election_term;

        let error =
            apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap_err();

        assert!(
            error.to_string().contains(
                "observational capability-authority metadata into the HA admission state machine"
            ),
            "unexpected authority snapshot error: {error}"
        );
        assert_eq!(
            cluster_consensus_view(&target_state)
                .test_unwrap()
                .election_term,
            term_before
        );
        assert!(target_state.config.authority_seed_path.is_none());
        assert!(target_state.config.authority_db_path.is_none());

        let _ = std::fs::remove_file(authority_db_path);
    }
