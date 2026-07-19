    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn max_length_revocation_retry_reuses_the_original_entry_and_timestamp() {
        let cluster = ThreeNodeCluster::start("remote-revocation-response-loss").await;
        let capability_id = "r".repeat(512);
        let operation_id =
            super::super::authority_handlers::cluster_revocation_operation_id(&capability_id);
        assert!(operation_id.len() <= 512);
        let proposal = ConsensusRevocationProposal { capability_id };
        let first = invoke_admission_command(
            &cluster.states[0],
            &operation_id,
            AdmissionCommandKind::Revoke,
            &proposal,
        )
        .await
        .expect("initial revocation");
        let before = cluster.snapshots();
        let database_path = cluster.states[0]
            .config
            .revocation_db_path
            .as_deref()
            .expect("revocation database");
        let revoked_at_before: i64 = Connection::open(database_path)
            .expect("revocation connection")
            .query_row(
                "SELECT revoked_at FROM revoked_capabilities WHERE capability_id = ?1",
                params![&proposal.capability_id],
                |row| row.get(0),
            )
            .expect("persisted revocation timestamp");

        let retry = invoke_admission_command(
            &cluster.states[2],
            &operation_id,
            AdmissionCommandKind::Revoke,
            &proposal,
        )
        .await
        .expect("response-loss retry");
        assert_eq!(retry, first);
        let after = cluster.snapshots();
        for index in 0..after.len() {
            assert_eq!(after[index].entries, before[index].entries);
            assert_eq!(after[index].commit_proofs, before[index].commit_proofs);
            assert_eq!(after[index].results, before[index].results);
            assert_eq!(
                after[index].meta.last_log_index,
                before[index].meta.last_log_index
            );
            assert_eq!(
                after[index].meta.commit_index,
                before[index].meta.commit_index
            );
            assert_eq!(
                after[index].meta.last_applied,
                before[index].meta.last_applied
            );
        }
        let scoped = scoped_operation_id(AdmissionCommandKind::Revoke, &operation_id)
            .expect("scoped revocation operation");
        assert_eq!(
            after[0]
                .entries
                .iter()
                .filter(|entry| entry.operation_id == scoped)
                .count(),
            1
        );
        let revoked_at_after: i64 = Connection::open(database_path)
            .expect("revocation connection")
            .query_row(
                "SELECT revoked_at FROM revoked_capabilities WHERE capability_id = ?1",
                params![&proposal.capability_id],
                |row| row.get(0),
            )
            .expect("retried revocation timestamp");
        assert_eq!(revoked_at_after, revoked_at_before);

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn remote_revocation_and_capture_race_has_one_durable_order() {
        let cluster = ThreeNodeCluster::start("remote-revocation-capture").await;
        let capability_id = "capability-remote-order";
        let capture_operation = "operation-remote-order";
        let mut authorization_request = composite_request(
            capability_id,
            "hold-remote-order",
            "authorize-remote-order",
            1,
        );
        authorization_request.operation_id = capture_operation.to_string();
        let authorization =
            invoke_composite_authorize(cluster.states[0].clone(), authorization_request)
                .await
                .expect("authorize response");
        assert!(authorization.allowed);

        let revocation_operation = "revocation:capability-remote-order";
        let revocation = ConsensusRevocationProposal {
            capability_id: capability_id.to_string(),
        };
        let capture_request =
            combined_request(&authorization, capture_operation, "capture-remote-order");

        let (revoke_result, capture_result) = tokio::join!(
            invoke_admission_command(
                &cluster.states[1],
                revocation_operation,
                AdmissionCommandKind::Revoke,
                &revocation,
            ),
            invoke_admission_command(
                &cluster.states[2],
                capture_operation,
                AdmissionCommandKind::CombinedCapture,
                &capture_request,
            ),
        );
        revoke_result.expect("revocation response");
        let capture_result = capture_result.expect("capture response");
        let capture_response: CombinedAdmissionCaptureResponse =
            serde_json::from_str(&capture_result.response_json).expect("capture result body");

        let snapshots = cluster.snapshots();
        assert_same_committed_state(&snapshots[0], &snapshots[1]);
        assert_same_committed_state(&snapshots[1], &snapshots[2]);
        assert_eq!(snapshots[0].meta.commit_index, 3);
        assert_eq!(snapshots[0].meta.last_applied, 3);
        assert_eq!(snapshots[0].results.len(), 3);
        let revocation_key =
            scoped_operation_id(AdmissionCommandKind::Revoke, revocation_operation)
                .expect("revocation key");
        let capture_key =
            scoped_operation_id(AdmissionCommandKind::CombinedCapture, capture_operation)
                .expect("capture key");
        let revocation_index = snapshots[0]
            .entries
            .iter()
            .find(|entry| entry.operation_id == revocation_key)
            .expect("revocation entry")
            .index;
        let capture_index = snapshots[0]
            .entries
            .iter()
            .find(|entry| entry.operation_id == capture_key)
            .expect("capture entry")
            .index;
        assert_ne!(revocation_index, capture_index);

        let expected_counts = if revocation_index < capture_index {
            assert_eq!(
                capture_response.outcome,
                AdmissionCaptureOutcomeView::DeniedRevoked
            );
            assert!(capture_response.budget.is_none());
            (1_i64, 0_i64)
        } else {
            assert_eq!(
                capture_response.outcome,
                AdmissionCaptureOutcomeView::Captured
            );
            assert_eq!(
                capture_response
                    .budget
                    .as_ref()
                    .expect("captured budget")
                    .invocation_count_after,
                1
            );
            (0_i64, 1_i64)
        };
        for path in &cluster.paths {
            let counts = Connection::open(path)
                .expect("open quota database")
                .query_row(
                    r#"
                    SELECT reserved_invocations, captured_invocations
                    FROM budget_invocation_quota_usage
                    WHERE profile = 'chio.grant-invocation.v1'
                      AND owner_id = ?1
                      AND grant_index_key = 0
                    "#,
                    params![capability_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .expect("quota counts");
            assert_eq!(counts, expected_counts);
        }

        let retry = invoke_admission_command(
            &cluster.states[0],
            capture_operation,
            AdmissionCommandKind::CombinedCapture,
            &capture_request,
        )
        .await
        .expect("exact capture retry");
        assert_eq!(retry, capture_result);
        let retried_snapshots = cluster.snapshots();
        for index in 0..3 {
            assert_same_committed_state(&retried_snapshots[index], &snapshots[index]);
        }

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn remote_admission_authority_completes_every_monetary_transition() {
        let cluster = ThreeNodeCluster::start("remote-monetary-transitions").await;
        let capability_id = "capability-remote-monetary";
        let mut authorizations = Vec::new();
        for suffix in ["reverse", "release", "reconcile", "capture"] {
            let mut request = composite_request(
                capability_id,
                &format!("hold-remote-{suffix}"),
                &format!("authorize-remote-{suffix}"),
                8,
            );
            request.requested_exposure_units = 10;
            request.max_exposure_per_invocation = Some(10);
            request.max_total_exposure_units = Some(40);
            let authorization = invoke_composite_authorize(cluster.states[0].clone(), request)
                .await
                .expect("authorize monetary hold");
            assert!(authorization.allowed);
            authorizations.push(authorization);
        }

        let authority = |authorization: &CompositeBudgetAuthorizeResponse| {
            let authority = authorization
                .budget_authority
                .as_ref()
                .expect("persisted admission authority");
            BudgetMutationAuthorityView {
                authority_id: authority.authority_id.clone(),
                lease_id: authority.lease_id.clone(),
                lease_epoch: authority.lease_epoch,
            }
        };
        let missing_authority = super::super::super::budget_handlers::handle_reverse_charge_cost(
            State(cluster.states[1].clone()),
            service_headers(),
            Json(ReverseChargeCostRequest {
                operation_id: Some(authorizations[0].operation_id.clone()),
                request_binding_hash: Some(authorizations[0].request_binding_hash.clone()),
                capability_id: capability_id.to_string(),
                grant_index: 0,
                cost_units: 10,
                hold_id: Some(authorizations[0].hold_id.clone()),
                event_id: Some("reverse-remote-missing-authority".to_string()),
                budget_authority: None,
            }),
        )
        .await;
        assert_eq!(missing_authority.status(), StatusCode::BAD_REQUEST);
        let reverse = invoke_reverse_exposure(
            cluster.states[1].clone(),
            ReverseChargeCostRequest {
                operation_id: Some(authorizations[0].operation_id.clone()),
                request_binding_hash: Some(authorizations[0].request_binding_hash.clone()),
                capability_id: capability_id.to_string(),
                grant_index: 0,
                cost_units: 10,
                hold_id: Some(authorizations[0].hold_id.clone()),
                event_id: Some("reverse-remote-monetary".to_string()),
                budget_authority: Some(authority(&authorizations[0])),
            },
        )
        .await
        .expect("reverse exposure");
        assert_eq!(reverse.total_cost_exposed, Some(30));

        let invalid_release = ReduceChargeCostRequest {
            operation_id: Some(authorizations[1].operation_id.clone()),
            request_binding_hash: Some(authorizations[1].request_binding_hash.clone()),
            capability_id: capability_id.to_string(),
            grant_index: 0,
            cost_units: 11,
            exposure_units: None,
            realized_spend_units: None,
            hold_id: Some(authorizations[1].hold_id.clone()),
            event_id: Some("release-remote-conflict".to_string()),
            budget_authority: Some(authority(&authorizations[1])),
        };
        for state in [&cluster.states[2], &cluster.states[0]] {
            let response = super::super::super::budget_handlers::handle_reduce_charge_cost(
                State(state.clone()),
                service_headers(),
                Json(ReduceChargeCostRequest {
                    operation_id: invalid_release.operation_id.clone(),
                    request_binding_hash: invalid_release.request_binding_hash.clone(),
                    capability_id: invalid_release.capability_id.clone(),
                    grant_index: invalid_release.grant_index,
                    cost_units: invalid_release.cost_units,
                    exposure_units: invalid_release.exposure_units,
                    realized_spend_units: invalid_release.realized_spend_units,
                    hold_id: invalid_release.hold_id.clone(),
                    event_id: invalid_release.event_id.clone(),
                    budget_authority: invalid_release.budget_authority.clone(),
                }),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }
        let release = invoke_reduce_exposure(
            cluster.states[2].clone(),
            ReduceChargeCostRequest {
                operation_id: Some(authorizations[1].operation_id.clone()),
                request_binding_hash: Some(authorizations[1].request_binding_hash.clone()),
                capability_id: capability_id.to_string(),
                grant_index: 0,
                cost_units: 4,
                exposure_units: None,
                realized_spend_units: None,
                hold_id: Some(authorizations[1].hold_id.clone()),
                event_id: Some("release-remote-monetary".to_string()),
                budget_authority: Some(authority(&authorizations[1])),
            },
        )
        .await
        .expect("release exposure");
        assert_eq!(release.total_cost_exposed, Some(26));

        let contradictory_reconcile =
            super::super::super::budget_handlers::handle_reduce_charge_cost(
                State(cluster.states[0].clone()),
                service_headers(),
                Json(ReduceChargeCostRequest {
                    operation_id: Some(authorizations[2].operation_id.clone()),
                    request_binding_hash: Some(authorizations[2].request_binding_hash.clone()),
                    capability_id: capability_id.to_string(),
                    grant_index: 0,
                    cost_units: 4,
                    exposure_units: Some(10),
                    realized_spend_units: Some(9),
                    hold_id: Some(authorizations[2].hold_id.clone()),
                    event_id: Some("reconcile-remote-contradiction".to_string()),
                    budget_authority: Some(authority(&authorizations[2])),
                }),
            )
            .await;
        assert_eq!(contradictory_reconcile.status(), StatusCode::BAD_REQUEST);
        let reconcile = invoke_reduce_exposure(
            cluster.states[0].clone(),
            ReduceChargeCostRequest {
                operation_id: Some(authorizations[2].operation_id.clone()),
                request_binding_hash: Some(authorizations[2].request_binding_hash.clone()),
                capability_id: capability_id.to_string(),
                grant_index: 0,
                cost_units: 4,
                exposure_units: Some(10),
                realized_spend_units: Some(6),
                hold_id: Some(authorizations[2].hold_id.clone()),
                event_id: Some("reconcile-remote-monetary".to_string()),
                budget_authority: Some(authority(&authorizations[2])),
            },
        )
        .await
        .expect("reconcile exposure");
        assert_eq!(reconcile.total_cost_exposed, Some(16));
        assert_eq!(reconcile.total_cost_realized_spend, Some(6));

        let capture = invoke_capture_exposure(
            cluster.states[1].clone(),
            ReduceChargeCostRequest {
                operation_id: Some(authorizations[3].operation_id.clone()),
                request_binding_hash: Some(authorizations[3].request_binding_hash.clone()),
                capability_id: capability_id.to_string(),
                grant_index: 0,
                cost_units: 4,
                exposure_units: Some(10),
                realized_spend_units: Some(6),
                hold_id: Some(authorizations[3].hold_id.clone()),
                event_id: Some("capture-remote-monetary".to_string()),
                budget_authority: Some(authority(&authorizations[3])),
            },
        )
        .await
        .expect("capture exposure");
        assert_eq!(capture.total_cost_exposed, Some(6));
        assert_eq!(capture.total_cost_realized_spend, Some(12));
        for response in [release, reconcile, capture] {
            let commit = response.budget_commit.expect("consensus budget commit");
            assert!(commit.quorum_committed);
            assert_eq!(commit.quorum_size, 2);
            assert!(commit.commit_index >= commit.budget_seq);
        }
        let reverse_commit = reverse.budget_commit.expect("reverse consensus commit");
        assert!(reverse_commit.quorum_committed);

        let snapshots = cluster.snapshots();
        assert_same_committed_state(&snapshots[0], &snapshots[1]);
        assert_same_committed_state(&snapshots[1], &snapshots[2]);
        assert_eq!(snapshots[0].meta.commit_index, 9);
        assert_eq!(snapshots[0].meta.last_applied, 9);

        cluster.stop().await;
    }

    fn test_config(database_path: &Path) -> TrustServiceConfig {
        TrustServiceConfig {
            listen: "127.0.0.1:0".parse().expect("listen"),
            service_token: "consensus-test-token".to_string(),
            dashboard_read_token: None,
            dashboard_report_origin: None,
            dashboard_report_token: None,
            dashboard_allow_insecure_report_origin: false,
            authority_admin_token: None,
            authority_workloads: Vec::new(),
            tenant_read_tokens: BTreeMap::new(),
            receipt_db_path: None,
            revocation_db_path: Some(database_path.to_path_buf()),
            authority_seed_path: None,
            authority_db_path: None,
            authority_keyring_config_path: None,
            budget_db_path: Some(database_path.to_path_buf()),
            enterprise_providers_file: None,
            federation_policies_file: None,
            scim_lifecycle_file: None,
            verifier_policies_file: None,
            verifier_challenge_db_path: None,
            passport_statuses_file: None,
            passport_issuance_offers_file: None,
            certification_registry_file: None,
            certification_discovery_file: None,
            issuance_policy: None,
            runtime_assurance_policy: None,
            advertise_url: None,
            allow_local_peer_urls: true,
            certification_public_metadata_ttl_seconds: 300,
            peer_urls: Vec::new(),
            cluster_node_seed_path: None,
            cluster_replay_db_path: None,
            cluster_members: Vec::new(),
            cluster_sync_interval: Duration::from_millis(50),
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        }
    }

    fn revocation_set(capability_id: &str) -> CanonicalRevocationSetView {
        let ids = vec![capability_id.to_string()];
        let canonical = canonical_json_bytes(&ids).expect("canonical revocation ids");
        let mut digest_input = b"chio.revocation-set.v1\0".to_vec();
        digest_input.extend_from_slice(&canonical);
        CanonicalRevocationSetView {
            ids,
            digest: sha256_hex(&digest_input),
        }
    }

    fn composite_request(
        capability_id: &str,
        hold_id: &str,
        event_id: &str,
        max_invocations: u32,
    ) -> CompositeBudgetAuthorizeRequest {
        CompositeBudgetAuthorizeRequest {
            operation_id: format!("operation-{event_id}"),
            request_binding_hash: "44".repeat(32),
            capability_id: capability_id.to_string(),
            grant_index: 0,
            requested_exposure_units: 0,
            max_exposure_per_invocation: None,
            max_total_exposure_units: None,
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            admission_evidence: BudgetInvocationAdmissionEvidenceView {
                invocation_quotas: vec![BudgetInvocationQuotaView {
                    key: BudgetQuotaKeyView {
                        profile: BudgetQuotaProfileView::GrantInvocation,
                        owner_id: capability_id.to_string(),
                        grant_index: Some(0),
                    },
                    max_invocations,
                }],
                revocation_set: revocation_set(capability_id),
                aggregate_root_capability_id: None,
                aggregate_binding_digest: None,
                supplemental_binding: Some(BudgetSupplementalQuotaBindingView {
                    artifact_digest: "aa".repeat(32),
                    verifier_id: "consensus-test-verifier".to_string(),
                    request_binding_hash: "bb".repeat(32),
                    negotiated_features_digest: "cc".repeat(32),
                }),
            },
        }
    }

    fn commit_state_machine_command<T: Serialize>(
        store: &AdmissionConsensusStore,
        config: &TrustServiceConfig,
        operation_id: &str,
        command_kind: AdmissionCommandKind,
        command: &T,
    ) -> AdmissionConsensusResult {
        let membership = single_member();
        let election = store
            .begin_election(&membership, "https://node-a")
            .expect("state machine election");
        let command = serde_json::to_value(command).expect("command value");
        let command =
            prepare_command(config, command_kind, command, &election).expect("prepare command");
        let entry =
            AdmissionConsensusStore::build_entry(&election, operation_id, command_kind, &command)
                .expect("state machine entry");
        store
            .append_local(&election, &entry)
            .expect("state machine append");
        let proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 1,
            witness_urls: vec![election.candidate_id.clone()],
        };
        store
            .commit_local(
                &membership,
                &election,
                &proof,
                |transaction, entry, proof| {
                    apply_admission_log_entry(config, transaction, entry, proof)
                },
            )
            .expect("state machine commit")
    }

    fn authorized_hold(
        store: &AdmissionConsensusStore,
        config: &TrustServiceConfig,
        capability_id: &str,
        hold_id: &str,
        event_id: &str,
        max_invocations: u32,
    ) -> CompositeBudgetAuthorizeResponse {
        let request = composite_request(capability_id, hold_id, event_id, max_invocations);
        let result = commit_state_machine_command(
            store,
            config,
            event_id,
            AdmissionCommandKind::CompositeAuthorize,
            &request,
        );
        serde_json::from_str(&result.response_json).expect("authorize response")
    }

    fn authorized_hold_for_operation(
        store: &AdmissionConsensusStore,
        config: &TrustServiceConfig,
        capability_id: &str,
        hold_id: &str,
        event_id: &str,
        operation_id: &str,
        max_invocations: u32,
    ) -> CompositeBudgetAuthorizeResponse {
        let mut request = composite_request(capability_id, hold_id, event_id, max_invocations);
        request.operation_id = operation_id.to_string();
        let result = commit_state_machine_command(
            store,
            config,
            event_id,
            AdmissionCommandKind::CompositeAuthorize,
            &request,
        );
        serde_json::from_str(&result.response_json).expect("authorize response")
    }

    #[test]
    fn consensus_log_serializes_two_last_unit_authorizations_to_exactly_one_winner() {
        let database_path = path("last-unit");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");

        let first = authorized_hold(
            &store,
            &config,
            "capability-last-unit",
            "hold-last-unit-a",
            "event-last-unit-a",
            1,
        );
        let second = authorized_hold(
            &store,
            &config,
            "capability-last-unit",
            "hold-last-unit-b",
            "event-last-unit-b",
            1,
        );
        assert!(first.allowed);
        assert!(!second.allowed);
        assert_eq!(first.invocation_count_after, 1);
        assert_eq!(second.invocation_count_after, 1);
        assert_eq!(store.meta().expect("meta").commit_index, 2);
        assert_eq!(store.meta().expect("meta").last_applied, 2);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn changed_quota_maximum_is_rejected_before_consensus_commit() {
        let database_path = path("changed-maximum-preflight");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let authorization = authorized_hold(
            &store,
            &config,
            "capability-fixed-maximum",
            "hold-fixed-maximum-a",
            "authorize-fixed-maximum-a",
            1,
        );
        assert!(authorization.allowed);
        let election = store
            .begin_election(&single_member(), "https://node-a")
            .expect("second election");
        let changed = serde_json::to_value(composite_request(
            "capability-fixed-maximum",
            "hold-fixed-maximum-b",
            "authorize-fixed-maximum-b",
            2,
        ))
        .expect("changed command");

        assert!(prepare_command(
            &config,
            AdmissionCommandKind::CompositeAuthorize,
            changed,
            &election,
        )
        .is_err());
        assert_eq!(store.meta().expect("meta").last_log_index, 1);
        assert_eq!(store.meta().expect("meta").commit_index, 1);
        assert_eq!(store.meta().expect("meta").last_applied, 1);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn denied_composite_hold_reserves_its_hold_namespace() {
        let database_path = path("denied-hold-namespace");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let denied = authorized_hold(
            &store,
            &config,
            "capability-denied-hold",
            "hold-denied-namespace",
            "authorize-denied-namespace",
            0,
        );
        assert!(!denied.allowed);
        let election = store
            .begin_election(&single_member(), "https://node-a")
            .expect("next election");
        let reused = serde_json::to_value(composite_request(
            "capability-denied-hold",
            "hold-denied-namespace",
            "authorize-denied-namespace-reused",
            0,
        ))
        .expect("reused command");
        assert!(prepare_command(
            &config,
            AdmissionCommandKind::CompositeAuthorize,
            reused,
            &election,
        )
        .is_err());
        assert_eq!(store.meta().expect("meta").last_log_index, 1);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn single_quota_composite_authority_fences_legacy_increment() {
        let database_path = path("single-quota-fence");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let authorization = authorized_hold(
            &store,
            &config,
            "capability-single-quota-fence",
            "hold-single-quota-fence",
            "authorize-single-quota-fence",
            3,
        );
        assert!(authorization.allowed);
        let error = SqliteBudgetStore::open(&database_path)
            .expect("budget store")
            .try_increment("capability-single-quota-fence", 0, Some(3))
            .expect_err("legacy increment must be fenced");
        assert!(error
            .to_string()
            .contains("requires composite invocation admission"));
        assert_eq!(store.meta().expect("meta").last_applied, 1);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn committed_conflict_is_frozen_as_rejection_and_does_not_block_later_entries() {
        let database_path = path("committed-conflict");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let membership = single_member();
        let first_election = store
            .begin_election(&membership, "https://node-a")
            .expect("first election");
        let first_request = composite_request(
            "capability-conflict-a",
            "hold-committed-conflict",
            "authorize-committed-conflict-a",
            2,
        );
        let second_request = composite_request(
            "capability-conflict-b",
            "hold-committed-conflict",
            "authorize-committed-conflict-b",
            2,
        );
        let first_command = prepare_command(
            &config,
            AdmissionCommandKind::CompositeAuthorize,
            serde_json::to_value(first_request).expect("first command"),
            &first_election,
        )
        .expect("first command preparation");
        let second_command = prepare_command(
            &config,
            AdmissionCommandKind::CompositeAuthorize,
            serde_json::to_value(second_request).expect("second command"),
            &first_election,
        )
        .expect("second command preparation");
        let first_entry = AdmissionConsensusStore::build_entry(
            &first_election,
            "operation-committed-conflict-a",
            AdmissionCommandKind::CompositeAuthorize,
            &first_command,
        )
        .expect("first entry");
        store
            .append_local(&first_election, &first_entry)
            .expect("first append");
        let first_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: first_entry.index,
            leader_epoch: first_entry.leader_epoch,
            current_term_commit_index: first_entry.index,
            leader_id: first_election.candidate_id.clone(),
            quorum_size: 1,
            witness_urls: vec![first_election.candidate_id.clone()],
        };
        store
            .commit_local(
                &membership,
                &first_election,
                &first_proof,
                |transaction, entry, proof| {
                    apply_admission_log_entry(&config, transaction, entry, proof)
                },
            )
            .expect("first commit");

        let second_election = store
            .begin_election(&membership, "https://node-a")
            .expect("second election");
        let second_entry = AdmissionConsensusStore::build_entry(
            &second_election,
            "operation-committed-conflict-b",
            AdmissionCommandKind::CompositeAuthorize,
            &second_command,
        )
        .expect("second entry");
        store
            .append_local(&second_election, &second_entry)
            .expect("second append");
        let second_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: second_entry.index,
            leader_epoch: second_entry.leader_epoch,
            current_term_commit_index: second_entry.index,
            leader_id: second_election.candidate_id.clone(),
            quorum_size: 1,
            witness_urls: vec![second_election.candidate_id.clone()],
        };
        let rejected = store
            .commit_local(
                &membership,
                &second_election,
                &second_proof,
                |transaction, entry, proof| {
                    apply_admission_log_entry(&config, transaction, entry, proof)
                },
            )
            .expect("committed conflict result");
        assert!(rejected
            .response_json
            .contains("admissionConsensusRejection"));
        assert!(matches!(
            accepted_consensus_result(rejected.clone()),
            Err(AdmissionConsensusError::Rejected {
                status_code: 409,
                ..
            })
        ));
        assert_eq!(store.meta().expect("meta").last_applied, 2);

        let revocation = ConsensusRevocationProposal {
            capability_id: "capability-after-conflict".to_string(),
        };
        commit_state_machine_command(
            &store,
            &config,
            "revocation:capability-after-conflict",
            AdmissionCommandKind::Revoke,
            &revocation,
        );
        assert_eq!(store.meta().expect("meta").commit_index, 3);
        assert_eq!(store.meta().expect("meta").last_applied, 3);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn response_loss_and_exact_retry_return_the_same_persisted_result_without_reapply() {
        let database_path = path("response-loss");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let response = authorized_hold(
            &store,
            &config,
            "capability-response-loss",
            "hold-response-loss",
            "event-response-loss",
            2,
        );
        let original = store
            .result_for_operation("event-response-loss")
            .expect("result")
            .expect("persisted result");
        drop(store);

        let reopened = AdmissionConsensusStore::open(&database_path).expect("reopen");
        let applied = AtomicUsize::new(0);
        reopened
            .apply_committed(&mut |_, _, _| {
                applied.fetch_add(1, Ordering::SeqCst);
                Ok("{\"wrong\":true}".to_string())
            })
            .expect("replay committed");
        assert_eq!(applied.load(Ordering::SeqCst), 0);
        let retry = reopened
            .result_for_operation("event-response-loss")
            .expect("retry result")
            .expect("retry persisted result");
        assert_eq!(retry, original);
        assert_eq!(
            serde_json::from_str::<CompositeBudgetAuthorizeResponse>(&retry.response_json)
                .expect("retry response")
                .allowed,
            response.allowed
        );
        let existing = reopened
            .snapshot()
            .expect("snapshot")
            .entries
            .into_iter()
            .next()
            .expect("entry");
        let changed = serde_json::to_value(composite_request(
            "capability-response-loss",
            "hold-response-loss",
            "event-response-loss",
            3,
        ))
        .expect("changed request");
        assert!(ensure_operation_command_matches(
            &existing,
            AdmissionCommandKind::CompositeAuthorize,
            &changed,
        )
        .is_err());

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn mismatched_capture_authority_is_rejected_before_log_append() {
        let database_path = path("capture-preflight");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let authorization = authorized_hold(
            &store,
            &config,
            "capability-capture-preflight",
            "hold-capture-preflight",
            "authorize-capture-preflight",
            1,
        );
        let election = store
            .begin_election(&single_member(), "https://node-a")
            .expect("capture election");
        let mut authority = authorization
            .budget_authority
            .as_ref()
            .expect("persisted authority")
            .clone();
        authority.lease_epoch = authority
            .lease_epoch
            .checked_add(1)
            .expect("test lease epoch");
        let request = CaptureInvocationReservationsRequest {
            operation_id: authorization.operation_id.clone(),
            request_binding_hash: authorization.request_binding_hash.clone(),
            capability_id: authorization.capability_id,
            grant_index: authorization.grant_index,
            hold_id: authorization.hold_id,
            event_id: "capture-preflight".to_string(),
            budget_authority: Some(BudgetMutationAuthorityView {
                authority_id: authority.authority_id,
                lease_id: authority.lease_id,
                lease_epoch: authority.lease_epoch,
            }),
        };
        let command = serde_json::to_value(request).expect("capture command");

        assert!(prepare_command(
            &config,
            AdmissionCommandKind::CaptureInvocations,
            command,
            &election,
        )
        .is_err());
        assert_eq!(store.meta().expect("meta").last_log_index, 1);
        assert_eq!(store.meta().expect("meta").commit_index, 1);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn increment_replay_is_result_stable_and_exactly_once() {
        let database_path = path("increment-replay");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let operation_id = "increment:capability-replay:0";
        let original = commit_state_machine_command(
            &store,
            &config,
            operation_id,
            AdmissionCommandKind::IncrementInvocation,
            &TryIncrementBudgetRequest {
                capability_id: "capability-increment-replay".to_string(),
                grant_index: 0,
                max_invocations: Some(2),
            },
        );
        let projection = SqliteBudgetStore::open(&database_path).expect("increment projection");
        assert_eq!(
            projection
                .get_usage("capability-increment-replay", 0)
                .expect("increment usage")
                .expect("increment usage row")
                .invocation_count,
            1
        );
        assert_eq!(
            projection
                .list_mutation_events(10, Some("capability-increment-replay"), Some(0))
                .expect("increment mutation events")
                .len(),
            1
        );
        drop(projection);
        drop(store);

        let connection = Connection::open(&database_path).expect("database");
        connection
            .execute("DELETE FROM admission_consensus_results", [])
            .expect("delete increment result");
        connection
            .execute(
                r#"
                UPDATE admission_consensus_meta
                SET last_applied = 0, applied_state_digest = ?1
                WHERE singleton = 1
                "#,
                params![initial_applied_state_digest()],
            )
            .expect("rewind increment projection");
        drop(connection);

        let reopened = AdmissionConsensusStore::open(&database_path).expect("reopen");
        reopened
            .apply_committed(&mut |transaction, entry, proof| {
                apply_admission_log_entry(&config, transaction, entry, proof)
            })
            .expect("replay increment");
        let replayed = reopened
            .result_for_operation(operation_id)
            .expect("result")
            .expect("replayed increment result");
        assert_eq!(replayed.response_json, original.response_json);
        let replayed_projection =
            SqliteBudgetStore::open(&database_path).expect("replayed increment projection");
        assert_eq!(
            replayed_projection
                .get_usage("capability-increment-replay", 0)
                .expect("replayed increment usage")
                .expect("replayed increment usage row")
                .invocation_count,
            1
        );
        assert_eq!(
            replayed_projection
                .list_mutation_events(10, Some("capability-increment-replay"), Some(0))
                .expect("replayed increment mutation events")
                .len(),
            1
        );

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn revocation_replay_after_projection_gap_is_result_stable() {
        let database_path = path("revocation-replay");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let command = ConsensusRevocationProposal {
            capability_id: "capability-replay".to_string(),
        };
        let original = commit_state_machine_command(
            &store,
            &config,
            "revocation:capability-replay",
            AdmissionCommandKind::Revoke,
            &command,
        );
        drop(store);
        let connection = Connection::open(&database_path).expect("database");
        connection
            .execute("DELETE FROM admission_consensus_results", [])
            .expect("delete result");
        connection
            .execute(
                r#"
                UPDATE admission_consensus_meta
                SET last_applied = 0, applied_state_digest = ?1
                WHERE singleton = 1
                "#,
                params![initial_applied_state_digest()],
            )
            .expect("rewind projection");
        drop(connection);

        let reopened = AdmissionConsensusStore::open(&database_path).expect("reopen");
        reopened
            .apply_committed(&mut |transaction, entry, proof| {
                apply_admission_log_entry(&config, transaction, entry, proof)
            })
            .expect("replay");
        let replayed = reopened
            .result_for_operation("revocation:capability-replay")
            .expect("result")
            .expect("replayed result");
        assert_eq!(replayed.response_json, original.response_json);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn legacy_budget_ack_cannot_commit_an_admission_entry() {
        let database_path = path("legacy-ack");
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let election = AdmissionElection {
            term: 4,
            candidate_id: "https://node-a".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        let entry = entry(&election, "operation-legacy-ack");
        store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: election.term,
                    leader_id: election.candidate_id.clone(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(entry.clone()),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{\"ok\":true}".to_string()),
            )
            .expect("append");
        let applied = AtomicUsize::new(0);
        let rejected = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: election.term,
                    leader_id: election.candidate_id.clone(),
                    previous_log_index: entry.index,
                    previous_log_term: entry.leader_epoch,
                    entry: None,
                    leader_commit: entry.index,
                    commit_proof: Some(AdmissionCommitProof {
                        protocol_version: "ha_quorum_commit".to_string(),
                        membership_digest: membership().digest().to_string(),
                        index: entry.index,
                        leader_epoch: entry.leader_epoch,
                        current_term_commit_index: entry.index,
                        leader_id: election.candidate_id,
                        quorum_size: 2,
                        witness_urls: vec![
                            "https://node-a".to_string(),
                            "https://node-b".to_string(),
                        ],
                    }),
                },
                |_, _, _| {
                    applied.fetch_add(1, Ordering::SeqCst);
                    Ok("{\"ok\":true}".to_string())
                },
            )
            .expect("legacy commit response");
        assert!(!rejected.accepted);
        assert_eq!(store.meta().expect("meta").commit_index, 0);
        assert_eq!(applied.load(Ordering::SeqCst), 0);

        let _ = std::fs::remove_file(database_path);
    }

    fn combined_request(
        authorization: &CompositeBudgetAuthorizeResponse,
        operation_id: &str,
        event_id: &str,
    ) -> CombinedAdmissionCaptureRequest {
        assert_eq!(authorization.operation_id, operation_id);
        let authority = authorization
            .budget_authority
            .as_ref()
            .expect("authorize authority");
        CombinedAdmissionCaptureRequest {
            operation_id: operation_id.to_string(),
            request_binding_hash: authorization.request_binding_hash.clone(),
            capability_id: authorization.capability_id.clone(),
            grant_index: authorization.grant_index,
            hold_id: authorization.hold_id.clone(),
            event_id: event_id.to_string(),
            budget_authority: Some(BudgetMutationAuthorityView {
                authority_id: authority.authority_id.clone(),
                lease_id: authority.lease_id.clone(),
                lease_epoch: authority.lease_epoch,
            }),
            revocation_set: authorization.admission_evidence.revocation_set.clone(),
            bound_revocation_set_digest: authorization
                .admission_evidence
                .revocation_set
                .digest
                .clone(),
            authorization_artifact_digests: authorization
                .admission_evidence
                .supplemental_binding
                .as_ref()
                .map(|binding| vec![binding.artifact_digest.clone()])
                .unwrap_or_default(),
            aggregate_root_capability_id: authorization
                .admission_evidence
                .aggregate_root_capability_id
                .clone(),
            aggregate_root_binding_digest: authorization
                .admission_evidence
                .aggregate_binding_digest
                .clone(),
            last_observed_revocation_index: Some(0),
        }
    }

    #[test]
    fn revocation_and_combined_capture_have_one_consensus_order() {
        let revoked_first_path = path("revoked-first");
        let revoked_first_config = test_config(&revoked_first_path);
        drop(open_capture_authority(&revoked_first_config).expect("authority"));
        let revoked_first_store =
            AdmissionConsensusStore::open(&revoked_first_path).expect("consensus");
        let authorization = authorized_hold_for_operation(
            &revoked_first_store,
            &revoked_first_config,
            "capability-revoked-first",
            "hold-revoked-first",
            "authorize-revoked-first",
            "operation-revoked-first",
            1,
        );
        let revocation = ConsensusRevocationProposal {
            capability_id: authorization.capability_id.clone(),
        };
        commit_state_machine_command(
            &revoked_first_store,
            &revoked_first_config,
            "revocation:capability-revoked-first",
            AdmissionCommandKind::Revoke,
            &revocation,
        );
        let request = combined_request(
            &authorization,
            "operation-revoked-first",
            "capture-revoked-first",
        );
        let denied = commit_state_machine_command(
            &revoked_first_store,
            &revoked_first_config,
            "operation-revoked-first",
            AdmissionCommandKind::CombinedCapture,
            &request,
        );
        let denied: CombinedAdmissionCaptureResponse =
            serde_json::from_str(&denied.response_json).expect("denied response");
        assert_eq!(denied.outcome, AdmissionCaptureOutcomeView::DeniedRevoked);
        assert!(denied.budget.is_none());
        assert_eq!(
            denied.revoked_capability_ids,
            vec!["capability-revoked-first".to_string()]
        );

        let captured_first_path = path("captured-first");
        let captured_first_config = test_config(&captured_first_path);
        drop(open_capture_authority(&captured_first_config).expect("authority"));
        let captured_first_store =
            AdmissionConsensusStore::open(&captured_first_path).expect("consensus");
        let authorization = authorized_hold_for_operation(
            &captured_first_store,
            &captured_first_config,
            "capability-captured-first",
            "hold-captured-first",
            "authorize-captured-first",
            "operation-captured-first",
            1,
        );
        let request = combined_request(
            &authorization,
            "operation-captured-first",
            "capture-captured-first",
        );
        let captured = commit_state_machine_command(
            &captured_first_store,
            &captured_first_config,
            "operation-captured-first",
            AdmissionCommandKind::CombinedCapture,
            &request,
        );
        let captured_response: CombinedAdmissionCaptureResponse =
            serde_json::from_str(&captured.response_json).expect("captured response");
        assert_eq!(
            captured_response.outcome,
            AdmissionCaptureOutcomeView::Captured
        );
        assert_eq!(
            captured_response
                .budget
                .as_ref()
                .expect("captured budget")
                .invocation_count_after,
            1
        );
        let revocation = ConsensusRevocationProposal {
            capability_id: authorization.capability_id.clone(),
        };
        commit_state_machine_command(
            &captured_first_store,
            &captured_first_config,
            "revocation:capability-captured-first",
            AdmissionCommandKind::Revoke,
            &revocation,
        );
        let reopened = AdmissionConsensusStore::open(&captured_first_path).expect("reopen");
        assert_eq!(
            reopened
                .result_for_operation("operation-captured-first")
                .expect("retry result")
                .expect("persisted retry"),
            captured
        );
        let budget_store = SqliteBudgetStore::open(&captured_first_path).expect("budget store");
        assert_eq!(
            budget_store
                .get_usage("capability-captured-first", 0)
                .expect("usage")
                .expect("usage row")
                .invocation_count,
            1
        );

        let _ = std::fs::remove_file(revoked_first_path);
        let _ = std::fs::remove_file(captured_first_path);
    }

    #[test]
    fn admission_capture_replica_query_is_exact_and_non_mutating() {
        let captured_path = path("capture-point-query-captured");
        let captured_config = test_config(&captured_path);
        drop(open_capture_authority(&captured_config).expect("authority"));
        let captured_store =
            AdmissionConsensusStore::open(&captured_path).expect("consensus store");
        let authorization = authorized_hold_for_operation(
            &captured_store,
            &captured_config,
            "capability-point-query-captured",
            "hold-point-query-captured",
            "authorize-point-query-captured",
            "operation-point-query-captured",
            1,
        );
        let capture_request = combined_request(
            &authorization,
            "operation-point-query-captured",
            "capture-point-query-captured",
        );
        let point_request = AdmissionCapturePointQueryRequest {
            capture_request: capture_request.clone(),
        };
        let before_miss = captured_store.snapshot().expect("snapshot before miss");
        let miss = query_admission_capture_replica(
            &captured_config,
            &single_member(),
            "https://node-a",
            &point_request,
        )
        .expect("point-query miss");
        assert!(miss.query.capture.is_none());
        assert_eq!(
            captured_store.snapshot().expect("snapshot after miss"),
            before_miss
        );

        let scoped_capture = scoped_operation_id(
            AdmissionCommandKind::CombinedCapture,
            &capture_request.operation_id,
        )
        .expect("scoped capture operation");
        let captured = commit_state_machine_command(
            &captured_store,
            &captured_config,
            &scoped_capture,
            AdmissionCommandKind::CombinedCapture,
            &capture_request,
        );
        let after_capture = captured_store.snapshot().expect("snapshot after capture");
        let queried = query_admission_capture_replica(
            &captured_config,
            &single_member(),
            "https://node-a",
            &point_request,
        )
        .expect("completed point query");
        let queried_capture = queried.query.capture.expect("captured point-query body");
        assert_eq!(
            canonical_json_bytes(&queried_capture).expect("queried capture canonical JSON"),
            canonical_json_bytes(
                &serde_json::from_str::<CombinedAdmissionCaptureResponse>(&captured.response_json)
                    .expect("committed capture response")
            )
            .expect("committed capture canonical JSON")
        );
        assert_eq!(
            captured_store
                .snapshot()
                .expect("snapshot after point query"),
            after_capture
        );

        let mut rebound = point_request.clone();
        rebound.capture_request.request_binding_hash = "77".repeat(32);
        assert!(query_admission_capture_replica(
            &captured_config,
            &single_member(),
            "https://node-a",
            &rebound,
        )
        .is_err());

        let denied_path = path("capture-point-query-denied");
        let denied_config = test_config(&denied_path);
        drop(open_capture_authority(&denied_config).expect("authority"));
        let denied_store = AdmissionConsensusStore::open(&denied_path).expect("consensus store");
        let authorization = authorized_hold_for_operation(
            &denied_store,
            &denied_config,
            "capability-point-query-denied",
            "hold-point-query-denied",
            "authorize-point-query-denied",
            "operation-point-query-denied",
            1,
        );
        commit_state_machine_command(
            &denied_store,
            &denied_config,
            "revocation:capability-point-query-denied",
            AdmissionCommandKind::Revoke,
            &ConsensusRevocationProposal {
                capability_id: authorization.capability_id.clone(),
            },
        );
        let denied_request = combined_request(
            &authorization,
            "operation-point-query-denied",
            "capture-point-query-denied",
        );
        let scoped_denied = scoped_operation_id(
            AdmissionCommandKind::CombinedCapture,
            &denied_request.operation_id,
        )
        .expect("scoped denied operation");
        commit_state_machine_command(
            &denied_store,
            &denied_config,
            &scoped_denied,
            AdmissionCommandKind::CombinedCapture,
            &denied_request,
        );
        let denied = query_admission_capture_replica(
            &denied_config,
            &single_member(),
            "https://node-a",
            &AdmissionCapturePointQueryRequest {
                capture_request: denied_request,
            },
        )
        .expect("denied point query")
        .query
        .capture
        .expect("denied point-query body");
        assert_eq!(denied.outcome, AdmissionCaptureOutcomeView::DeniedRevoked);

        let _ = std::fs::remove_file(captured_path);
        let _ = std::fs::remove_file(denied_path);
    }
