mod cluster_and_reports_tests {
    use super::super::cluster::*;
    use super::super::report_rendering::*;
    use super::super::report_validation::*;
    use super::super::*;
    use axum::body::to_bytes;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::path::PathBuf;

    use chio_test_support::prelude::*;

    fn base_config() -> TrustServiceConfig {
        TrustServiceConfig {
            listen: "127.0.0.1:0".parse().test_unwrap(),
            service_token: "token".to_string(),
            tenant_read_tokens: BTreeMap::new(),
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
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
            cluster_sync_interval: Duration::from_millis(25),
        }
    }

    fn state_with_cluster(
        advertise_url: &str,
        peer_urls: &[&str],
        receipt_db_path: Option<PathBuf>,
        revocation_db_path: Option<PathBuf>,
        budget_db_path: Option<PathBuf>,
    ) -> TrustServiceState {
        let mut config = base_config();
        config.advertise_url = Some(advertise_url.to_string());
        config.peer_urls = peer_urls.iter().map(|value| value.to_string()).collect();
        config.receipt_db_path = receipt_db_path;
        config.revocation_db_path = revocation_db_path;
        config.budget_db_path = budget_db_path;
        let cluster = build_cluster_state(&config, config.listen).test_unwrap();
        let cluster_progress = cluster.as_ref().map(|_| Arc::new(ClusterProgress::new()));
        TrustServiceState {
            config,
            enterprise_provider_registry: None,
            verifier_policy_registry: None,
            federation_admission_rate_limiter: Arc::new(Mutex::new(
                FederationAdmissionRateLimiter::default(),
            )),
            cluster,
            cluster_progress,
        }
    }

    fn unique_temp_path(prefix: &str, extension: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.{extension}"))
    }

    fn sample_tool_receipt(id: &str, capability_id: &str) -> ChioReceipt {
        let keypair = Keypair::generate();
        let parameters = json!({"message": "cluster"});
        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp: 11,
                capability_id: capability_id.to_string(),
                tool_server: "wrapped-http-mock".to_string(),
                tool_name: "echo_json".to_string(),
                action: ToolCallAction::from_parameters(parameters).test_unwrap(),
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "content-hash".to_string(),
                policy_hash: "policy-hash".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .test_unwrap()
    }

    fn sample_child_receipt(id: &str, suffix: &str) -> ChildRequestReceipt {
        let keypair = Keypair::generate();
        ChildRequestReceipt::sign(
            chio_core::receipt::lineage::ChildRequestReceiptBody {
                id: id.to_string(),
                timestamp: 13,
                session_id: chio_core::session::SessionId::new(format!("sess-{suffix}")),
                parent_request_id: chio_core::session::RequestId::new(format!("parent-{suffix}")),
                request_id: chio_core::session::RequestId::new(format!("child-{suffix}")),
                operation_kind: chio_core::session::OperationKind::CreateMessage,
                terminal_state: OperationTerminalState::Completed,
                outcome_hash: "outcome-hash".to_string(),
                policy_hash: "policy-hash".to_string(),
                metadata: Some(json!({ "source": "cluster-test" })),
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .test_unwrap()
    }

    fn sample_capability(id: &str) -> CapabilityToken {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        CapabilityToken::sign(
            chio_core::capability::token::CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 1_000,
                expires_at: 9_000,
                delegation_chain: vec![],
            },
            &issuer,
        )
        .test_unwrap()
    }

    #[test]
    fn build_cluster_state_validates_inputs_and_normalizes_peers() {
        let mut invalid = base_config();
        invalid.advertise_url = Some("http://127.0.0.1:3200".to_string());
        invalid.peer_urls = vec!["http://127.0.0.1:3300".to_string()];
        invalid.authority_seed_path = Some(unique_temp_path("authority", "seed"));

        let error = build_cluster_state(&invalid, invalid.listen).test_unwrap_err();
        assert!(error
            .to_string()
            .contains("--authority-db instead of --authority-seed-file"));

        assert!(
            build_cluster_state(&base_config(), "127.0.0.1:0".parse().test_unwrap())
                .test_unwrap()
                .is_none()
        );

        let mut standalone_advertised = base_config();
        standalone_advertised.allow_local_peer_urls = false;
        standalone_advertised.advertise_url = Some("http://127.0.0.1:3200/".to_string());
        assert!(
            build_cluster_state(&standalone_advertised, standalone_advertised.listen)
                .test_unwrap()
                .is_none()
        );

        let mut config = base_config();
        config.advertise_url = Some("http://127.0.0.1:3200/".to_string());
        config.peer_urls = vec![
            "http://127.0.0.1:3200/".to_string(),
            " http://127.0.0.1:3300/ ".to_string(),
            "http://127.0.0.1:3300".to_string(),
        ];

        let cluster = build_cluster_state(&config, config.listen)
            .test_unwrap()
            .test_unwrap();
        let guard = cluster.lock().test_unwrap();
        assert_eq!(guard.self_url, "http://127.0.0.1:3200");
        assert_eq!(guard.peers.len(), 1);
        assert!(guard.peers.contains_key("http://127.0.0.1:3300"));
    }

    #[test]
    fn cluster_peer_url_validation_rejects_local_networks_by_default() {
        let error = normalize_cluster_config_url("http://127.0.0.1:3300", false).test_unwrap_err();
        assert!(error.to_string().contains("--allow-local-peer-urls"));

        let normalized =
            normalize_cluster_config_url(" http://127.0.0.1:3300/ ", true).test_unwrap();
        assert_eq!(normalized, "http://127.0.0.1:3300");
    }

    #[test]
    fn cluster_peer_url_validation_rejects_ambient_authority_material() {
        for peer_url in [
            "https://user:pass@control.example.test:443",
            "http://127.0.0.1:3300?token=secret",
            "http://127.0.0.1:3300#fragment",
        ] {
            let error = normalize_cluster_config_url(peer_url, true).test_unwrap_err();
            assert!(
                error.to_string().contains("cluster URL"),
                "unexpected error for peer URL `{peer_url}`: {error}",
            );
        }
    }

    #[test]
    fn compute_cluster_consensus_tracks_role_quorum_and_election_terms() {
        let mut cluster = ClusterRuntimeState {
            self_url: "http://node-a".to_string(),
            peers: HashMap::from([
                ("http://node-b".to_string(), PeerSyncState::default()),
                ("http://node-c".to_string(), PeerSyncState::default()),
            ]),
            election_term: 0,
            last_leader_url: None,
            term_started_at: None,
            lease_expires_at: None,
            lease_ttl_ms: authority_lease_ttl(Duration::from_millis(25)).as_millis() as u64,
        };

        let initial = compute_cluster_consensus_locked(&mut cluster);
        assert_eq!(initial.role, "candidate");
        assert!(!initial.has_quorum);
        assert_eq!(initial.quorum_size, 2);
        assert_eq!(initial.reachable_nodes, 1);
        assert_eq!(initial.election_term, 0);
        assert!(cluster_authority_lease_view_locked(&mut cluster, &initial).is_none());

        cluster.peers.get_mut("http://node-b").test_unwrap().health = PeerHealth::Healthy;
        cluster
            .peers
            .get_mut("http://node-b")
            .test_unwrap()
            .last_contact_at = Some(unix_timestamp_now());
        let with_quorum = compute_cluster_consensus_locked(&mut cluster);
        assert_eq!(with_quorum.role, "leader");
        assert!(with_quorum.has_quorum);
        assert_eq!(with_quorum.leader_url.as_deref(), Some("http://node-a"));
        assert_eq!(with_quorum.reachable_nodes, 2);
        assert_eq!(with_quorum.election_term, 1);
        let with_quorum_lease =
            cluster_authority_lease_view_locked(&mut cluster, &with_quorum).test_unwrap();
        assert_eq!(with_quorum_lease.lease_epoch, 1);
        assert!(with_quorum_lease.lease_id.contains("http://node-a"));
        assert!(with_quorum_lease.lease_expires_at >= unix_timestamp_now());

        cluster.peers.get_mut("http://node-c").test_unwrap().health = PeerHealth::Healthy;
        cluster
            .peers
            .get_mut("http://node-c")
            .test_unwrap()
            .last_contact_at = Some(unix_timestamp_now());
        let stable = compute_cluster_consensus_locked(&mut cluster);
        assert_eq!(stable.role, "leader");
        assert_eq!(stable.election_term, 1);
        assert_eq!(stable.reachable_nodes, 3);

        cluster.peers.get_mut("http://node-b").test_unwrap().health = PeerHealth::Unhealthy;
        cluster.peers.get_mut("http://node-c").test_unwrap().health = PeerHealth::Unhealthy;
        let lost_quorum = compute_cluster_consensus_locked(&mut cluster);
        assert_eq!(lost_quorum.role, "candidate");
        assert!(!lost_quorum.has_quorum);
        assert_eq!(lost_quorum.election_term, 2);
        assert!(cluster_authority_lease_view_locked(&mut cluster, &lost_quorum).is_none());
    }

    #[test]
    fn compute_cluster_consensus_drops_stale_peers_after_authority_lease_timeout() {
        let mut cluster = ClusterRuntimeState {
            self_url: "http://node-a".to_string(),
            peers: HashMap::from([(
                "http://node-b".to_string(),
                PeerSyncState {
                    health: PeerHealth::Healthy,
                    last_contact_at: Some(unix_timestamp_now().saturating_sub(5)),
                    ..PeerSyncState::default()
                },
            )]),
            election_term: 0,
            last_leader_url: None,
            term_started_at: None,
            lease_expires_at: None,
            lease_ttl_ms: authority_lease_ttl(Duration::from_millis(25)).as_millis() as u64,
        };

        let consensus = compute_cluster_consensus_locked(&mut cluster);
        assert!(!consensus.has_quorum);
        assert_eq!(consensus.reachable_nodes, 1);
        assert!(cluster_authority_lease_view_locked(&mut cluster, &consensus).is_none());
    }

    #[tokio::test]
    async fn leader_visibility_responses_add_cluster_metadata_and_reject_scalars() {
        let state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        update_peer_reachable(&state, "http://node-b");

        let response = json_response_with_leader_visibility(&state, json!({ "stored": true }));
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .test_unwrap();
        let body: Value = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(body["stored"], Value::Bool(true));
        assert_eq!(
            body["handledBy"],
            Value::String("http://node-a".to_string())
        );
        assert_eq!(
            body["leaderUrl"],
            Value::String("http://node-a".to_string())
        );
        assert_eq!(body["visibleAtLeader"], Value::Bool(true));
        assert_eq!(
            body["clusterAuthority"]["authorityId"],
            Value::String("http://node-a".to_string())
        );
        assert_eq!(body["clusterAuthority"]["term"], Value::from(1));
        assert_eq!(body["clusterAuthority"]["leaseValid"], Value::Bool(true));

        let scalar = json_response_with_leader_visibility(&state, "not-an-object");
        assert_eq!(scalar.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(scalar.into_body(), usize::MAX).await.test_unwrap();
        let text = String::from_utf8(body.to_vec()).test_unwrap();
        assert!(text.contains("success responses must be JSON objects"));
    }

    #[tokio::test]
    async fn budget_quorum_commit_metadata_tracks_quorum_witnesses() {
        let state = state_with_cluster(
            "http://node-a",
            &["http://node-b", "http://node-c"],
            None,
            None,
            None,
        );
        update_peer_reachable(&state, "http://node-b");
        update_peer_reachable(&state, "http://node-c");
        update_peer_budget_acks(
            &state,
            "http://node-b",
            &[BudgetOriginAck {
                origin_id: "http://node-a".to_string(),
                event_seq: 9,
            }],
        );
        update_peer_budget_acks(
            &state,
            "http://node-c",
            &[BudgetOriginAck {
                origin_id: "http://node-a".to_string(),
                event_seq: 7,
            }],
        );

        let write = BudgetWriteToken {
            origin_id: "http://node-a".to_string(),
            event_seq: 8,
            budget_term: 1,
        };
        let commit = budget_write_quorum_commit_view(&state, &write).test_unwrap();
        assert!(commit.quorum_committed);
        assert_eq!(commit.quorum_size, 2);
        assert_eq!(commit.committed_nodes, 2); // self + node-b (acked 9 >= 8)
        assert_eq!(
            commit.witness_urls,
            vec!["http://node-a".to_string(), "http://node-b".to_string()]
        );

        let response = json_response_with_leader_visibility_and_budget_commit(
            &state,
            json!({ "allowed": true }),
            Some(commit),
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .test_unwrap();
        let body: Value = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(body["budgetCommit"]["budgetSeq"], Value::from(8));
        assert_eq!(body["budgetCommit"]["commitIndex"], Value::from(8));
        assert_eq!(body["budgetCommit"]["quorumCommitted"], Value::Bool(true));
        assert_eq!(body["budgetCommit"]["committedNodes"], Value::from(2));
        assert_eq!(
            body["budgetCommit"]["authorityId"],
            Value::String("http://node-a".to_string())
        );
        assert_eq!(body["budgetCommit"]["budgetTerm"], Value::from(1));
        assert_eq!(
            body["budgetCommit"]["witnessUrls"],
            json!(["http://node-a", "http://node-b"])
        );
    }

    #[test]
    fn witness_requires_same_origin_ack() {
        let state = state_with_cluster(
            "http://node-a",
            &["http://node-b", "http://node-c"],
            None,
            None,
            None,
        );
        update_peer_reachable(&state, "http://node-b");
        update_peer_reachable(&state, "http://node-c");
        // A high ack under an UNRELATED origin must not witness the write.
        update_peer_budget_acks(
            &state,
            "http://node-b",
            &[BudgetOriginAck {
                origin_id: "http://other-origin".to_string(),
                event_seq: 999,
            }],
        );
        update_peer_budget_acks(
            &state,
            "http://node-c",
            &[BudgetOriginAck {
                origin_id: "http://other-origin".to_string(),
                event_seq: 999,
            }],
        );
        let write = BudgetWriteToken {
            origin_id: "http://node-a".to_string(),
            event_seq: 41,
            budget_term: 1,
        };
        let commit = budget_write_quorum_commit_view(&state, &write).test_unwrap();
        assert!(
            !commit.quorum_committed,
            "an ack under a different origin must not witness this write"
        );
        assert_eq!(commit.committed_nodes, 1, "only self counts");

        // Now node-b acks THIS origin at >= 41: it flips to committed.
        update_peer_budget_acks(
            &state,
            "http://node-b",
            &[BudgetOriginAck {
                origin_id: "http://node-a".to_string(),
                event_seq: 41,
            }],
        );
        let commit = budget_write_quorum_commit_view(&state, &write).test_unwrap();
        assert!(commit.quorum_committed);
        assert_eq!(commit.committed_nodes, 2);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        #[test]
        fn prop_witness_never_overclaims_durability(
            write_seq in 1u64..50,
            // The write is authored under one of TWO authorities that share the
            // single global event_seq stream: `origin-a` is the genesis authority
            // and `origin-b` is the authority-change origin whose block starts
            // mid-sequence. Each peer independently advertises a per-origin ack
            // head for each authority (or none).
            write_under_b in proptest::prelude::any::<bool>(),
            ack_b_a in proptest::prelude::prop::option::of(0u64..60),
            ack_b_b in proptest::prelude::prop::option::of(0u64..60),
            ack_c_a in proptest::prelude::prop::option::of(0u64..60),
            ack_c_b in proptest::prelude::prop::option::of(0u64..60),
        ) {
            let origin_a = "http://node-a";
            let origin_b = "http://node-b-origin";
            let state = state_with_cluster(
                "http://node-a",
                &["http://node-b", "http://node-c"],
                None,
                None,
                None,
            );
            update_peer_reachable(&state, "http://node-b");
            update_peer_reachable(&state, "http://node-c");
            let advertise = |peer: &str, ack_a: Option<u64>, ack_b: Option<u64>| {
                let mut acks = Vec::new();
                if let Some(seq) = ack_a {
                    acks.push(BudgetOriginAck { origin_id: origin_a.to_string(), event_seq: seq });
                }
                if let Some(seq) = ack_b {
                    acks.push(BudgetOriginAck { origin_id: origin_b.to_string(), event_seq: seq });
                }
                update_peer_budget_acks(&state, peer, &acks);
            };
            advertise("http://node-b", ack_b_a, ack_b_b);
            advertise("http://node-c", ack_c_a, ack_c_b);

            let write_origin = if write_under_b { origin_b } else { origin_a };
            let write = BudgetWriteToken {
                origin_id: write_origin.to_string(),
                event_seq: write_seq,
                budget_term: 1,
            };
            let commit = budget_write_quorum_commit_view(&state, &write).test_unwrap();

            // A peer witnesses iff its ack head for the WRITE's origin (not any
            // other origin) is >= write_seq. An ack under the sibling authority
            // never witnesses this write.
            let peer_ack = |ack_a: Option<u64>, ack_b: Option<u64>| {
                if write_under_b { ack_b } else { ack_a }
            };
            let peer_witnesses =
                |ack: Option<u64>| ack.is_some_and(|seq| seq >= write_seq);
            let expected_peer_witnesses =
                usize::from(peer_witnesses(peer_ack(ack_b_a, ack_b_b)))
                    + usize::from(peer_witnesses(peer_ack(ack_c_a, ack_c_b)));
            let expected_committed = 1 + expected_peer_witnesses; // self + peers
            proptest::prop_assert_eq!(commit.committed_nodes, expected_committed);
            // quorum_size for 2 peers is 2; committed only when >= 2.
            proptest::prop_assert_eq!(
                commit.quorum_committed,
                expected_committed >= commit.quorum_size
            );
            // Overclaim guard: never committed on self alone.
            if expected_peer_witnesses == 0 {
                proptest::prop_assert!(!commit.quorum_committed);
            }
        }
    }

    /// End-to-end proof of codex #965 Finding 1: budget_ack_heads (the store
    /// SQL) -> update_peer_budget_acks -> witness. Two authorities share one
    /// global event_seq stream; origin B's block starts mid-sequence (a
    /// leadership change). A peer that has durably imported the contiguous
    /// global prefix MUST witness B's write (no false time-out), and a global
    /// hole MUST cap the head so a write above the hole is NOT witnessed.
    #[test]
    fn witness_counts_authority_change_origin_and_caps_at_global_hole() {
        let origin_a = "http://origin-a";
        let origin_b = "http://origin-b";
        let event = |seq: u64, origin: &str| BudgetMutationEventView {
            event_id: format!("evt-{origin}-{seq}"),
            hold_id: None,
            capability_id: "cap-x".to_string(),
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
            total_cost_exposed_after: 1,
            total_cost_realized_spend_after: 0,
            authority: Some(BudgetMutationAuthorityView {
                authority_id: origin.to_string(),
                lease_id: format!("{origin}#term-1"),
                lease_epoch: 1,
            }),
        };
        let import = |store: &SqliteBudgetStore, events: &[BudgetMutationEventView]| {
            let records = events
                .iter()
                .map(|view| budget_mutation_record_from_view(view).test_unwrap())
                .collect::<Vec<_>>();
            store.import_snapshot_records(&[], &records).test_unwrap();
        };
        let acks_from = |heads: &[(String, u64)]| {
            heads
                .iter()
                .map(|(origin_id, event_seq)| BudgetOriginAck {
                    origin_id: origin_id.clone(),
                    event_seq: *event_seq,
                })
                .collect::<Vec<_>>()
        };

        // --- Case 1: fully-imported contiguous prefix across an authority change.
        // origin A owns global seqs 1..=3, origin B owns 4..=6 (authority change
        // at seq 4). The whole 1..=6 prefix is gap-free.
        let db1 = unique_temp_path("witness-authority-change", "sqlite3");
        {
            let store = SqliteBudgetStore::open(&db1).test_unwrap();
            let mut events = Vec::new();
            for seq in 1..=3 {
                events.push(event(seq, origin_a));
            }
            for seq in 4..=6 {
                events.push(event(seq, origin_b));
            }
            import(&store, &events);
            let heads = store.budget_ack_heads().test_unwrap();
            let b_head = heads
                .iter()
                .find(|(origin, _)| origin == origin_b)
                .map(|(_, seq)| *seq);
            // The old per-origin islands dropped B (its block starts at 4, island
            // 3 != floor 0); the global head 6 now acks B at 6.
            assert_eq!(
                b_head,
                Some(6),
                "authority-change origin B must be acked at the global head, not dropped"
            );

            let state = state_with_cluster(
                "http://node-a",
                &["http://node-b", "http://node-c"],
                None,
                None,
                None,
            );
            update_peer_reachable(&state, "http://node-b");
            update_peer_reachable(&state, "http://node-c");
            let acks = acks_from(&heads);
            update_peer_budget_acks(&state, "http://node-b", &acks);
            update_peer_budget_acks(&state, "http://node-c", &acks);
            let write = BudgetWriteToken {
                origin_id: origin_b.to_string(),
                event_seq: 4,
                budget_term: 1,
            };
            let commit = budget_write_quorum_commit_view(&state, &write).test_unwrap();
            assert!(
                commit.quorum_committed,
                "the authority-change write must witness on a fully-imported quorum (Finding 1)"
            );
            assert_eq!(commit.committed_nodes, 3);
        }
        let _ = std::fs::remove_file(&db1);

        // --- Case 2 (teeth): a global hole caps the head. origin A owns 1..=3,
        // origin B owns 5..=6, so global seq 4 is MISSING. A MAX-per-origin ack
        // head would report B = 6 and wrongly witness a write at 5; the
        // contiguous global head is 3, so B must not be acked at all.
        let db2 = unique_temp_path("witness-global-hole", "sqlite3");
        {
            let store = SqliteBudgetStore::open(&db2).test_unwrap();
            let mut events = Vec::new();
            for seq in 1..=3 {
                events.push(event(seq, origin_a));
            }
            for seq in [5u64, 6] {
                events.push(event(seq, origin_b));
            }
            import(&store, &events);
            let heads = store.budget_ack_heads().test_unwrap();
            assert!(
                heads.iter().all(|(origin, _)| origin != origin_b),
                "origin B must not be acked past the global hole at 4 (a MAX ack head would over-report)"
            );

            let state = state_with_cluster(
                "http://node-a",
                &["http://node-b", "http://node-c"],
                None,
                None,
                None,
            );
            update_peer_reachable(&state, "http://node-b");
            update_peer_reachable(&state, "http://node-c");
            let acks = acks_from(&heads);
            update_peer_budget_acks(&state, "http://node-b", &acks);
            update_peer_budget_acks(&state, "http://node-c", &acks);
            let write = BudgetWriteToken {
                origin_id: origin_b.to_string(),
                event_seq: 5,
                budget_term: 1,
            };
            let commit = budget_write_quorum_commit_view(&state, &write).test_unwrap();
            assert!(
                !commit.quorum_committed,
                "a write above a global hole must not witness (teeth: a MAX-per-origin ack head would)"
            );
            assert_eq!(
                commit.committed_nodes, 1,
                "only self counts when the global hole caps the head below the write"
            );
        }
        let _ = std::fs::remove_file(&db2);
    }

    #[test]
    fn peer_ack_regression_drops_stale_head_and_stops_witnessing() {
        // codex #965 round-2 P1: a peer that restored an older budget DB (or lost
        // a prefix) re-advertises a LOWER or empty ack set. The stored ack must
        // REGRESS (replace, not max-merge) so that data-losing peer stops being
        // counted as a witness for writes it no longer durably holds.
        let origin = "http://node-a";
        let state = state_with_cluster(
            "http://node-a",
            &["http://node-b", "http://node-c"],
            None,
            None,
            None,
        );
        update_peer_reachable(&state, "http://node-b");
        update_peer_reachable(&state, "http://node-c");
        let ack = |seq: u64| {
            vec![BudgetOriginAck {
                origin_id: origin.to_string(),
                event_seq: seq,
            }]
        };
        let write = |seq: u64| BudgetWriteToken {
            origin_id: origin.to_string(),
            event_seq: seq,
            budget_term: 1,
        };
        // Both peers ack origin at 10: a write at 8 witnesses on self + both.
        update_peer_budget_acks(&state, "http://node-b", &ack(10));
        update_peer_budget_acks(&state, "http://node-c", &ack(10));
        let commit = budget_write_quorum_commit_view(&state, &write(8)).test_unwrap();
        assert_eq!(commit.committed_nodes, 3);

        // node-b restored an older DB and re-advertises head 5: the stale 10 must
        // DROP, so a write at 8 no longer witnesses on node-b.
        update_peer_budget_acks(&state, "http://node-b", &ack(5));
        let commit = budget_write_quorum_commit_view(&state, &write(8)).test_unwrap();
        assert_eq!(
            commit.committed_nodes, 2,
            "node-b's regressed head 5 < 8 must not witness the write at 8"
        );
        // node-b still witnesses a write at 5 (5 >= 5).
        let commit = budget_write_quorum_commit_view(&state, &write(5)).test_unwrap();
        assert_eq!(commit.committed_nodes, 3);

        // An EMPTY re-advertisement drops node-b's origin entirely.
        update_peer_budget_acks(&state, "http://node-b", &[]);
        let commit = budget_write_quorum_commit_view(&state, &write(1)).test_unwrap();
        assert_eq!(
            commit.committed_nodes, 2,
            "an empty advertisement drops node-b's ack, so only self + node-c witness"
        );
    }

    #[test]
    fn commit_metadata_names_the_write_authority_not_the_current_leader() {
        // codex #965 round-2 P2: if leadership changes while a write waits, the
        // commit metadata must name the authority that AUTHORED the write, not
        // the current consensus leader (which never wrote the event).
        let state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        update_peer_reachable(&state, "http://node-b");
        let write = BudgetWriteToken {
            origin_id: "http://writer".to_string(),
            event_seq: 4,
            budget_term: 7,
        };
        let commit = budget_write_quorum_commit_view(&state, &write).test_unwrap();
        assert_eq!(
            commit.authority_id, "http://writer",
            "commit authority must be the write's origin, not the consensus leader"
        );
        assert_eq!(commit.budget_term, 7);
        assert_eq!(commit.lease_id, "http://writer#term-7");
    }

    #[test]
    fn budget_write_progress_close_fails_closed_while_clustered() {
        // codex #962: if the ClusterProgress sender is lost mid-write, a node
        // that is STILL clustered must fail closed (503) so the caller rolls back
        // the local exposure. Returning Ok(None) would render as a committed-
        // looking leader-visible write with no quorum budgetCommit (fail-open).
        // A genuinely unclustered node returns Ok(None).
        let write = BudgetWriteToken {
            origin_id: "http://node-a".to_string(),
            event_seq: 7,
            budget_term: 1,
        };
        let clustered = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        assert!(clustered.cluster.is_some(), "peers must build a cluster");
        let response = match budget_write_progress_closed_outcome(&clustered, &write) {
            Err(response) => response,
            Ok(_) => panic!("a clustered node must fail closed when the progress channel closes"),
        };
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Genuinely unclustered: the closed channel is expected, not an error.
        let mut unclustered = clustered.clone();
        unclustered.cluster = None;
        unclustered.cluster_progress = None;
        assert!(matches!(
            budget_write_progress_closed_outcome(&unclustered, &write),
            Ok(None)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writer_wait_never_wedges_sync_loop() {
        // Two peers, quorum_size 2. The writer parks on the progress watch; a
        // simulated background round records an ack and notifies, and the writer
        // observes the committed view without ever driving a sync itself.
        let state = state_with_cluster(
            "http://node-a",
            &["http://node-b", "http://node-c"],
            None,
            None,
            None,
        );
        update_peer_reachable(&state, "http://node-b");
        update_peer_reachable(&state, "http://node-c");
        let write = BudgetWriteToken {
            origin_id: "http://node-a".to_string(),
            event_seq: 5,
            budget_term: 1,
        };

        let loop_state = state.clone();
        let background = tokio::spawn(async move {
            // Simulate one background round: import the ack, then notify.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            update_peer_budget_acks(
                &loop_state,
                "http://node-b",
                &[BudgetOriginAck {
                    origin_id: "http://node-a".to_string(),
                    event_seq: 5,
                }],
            );
            if let Some(progress) = loop_state.cluster_progress.as_ref() {
                progress.notify_round_complete();
            }
        });

        let commit = wait_for_budget_write_quorum_commit(&state, write)
            .await
            .test_unwrap()
            .test_unwrap();
        assert!(commit.quorum_committed);
        background.await.test_unwrap();
    }

    #[test]
    fn peer_state_helpers_update_health_cursors_and_snapshot_thresholds() {
        let state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);

        update_peer_reachable(&state, "http://node-b");
        assert_eq!(
            with_peer_state(&state, "http://node-b", |peer| peer.health.label()),
            Some("healthy")
        );

        update_peer_sync_error(&state, "http://node-b", "lagging".to_string());
        assert_eq!(
            with_peer_state(&state, "http://node-b", |peer| peer.last_error.clone()),
            Some(Some("lagging".to_string()))
        );

        update_peer_failure(&state, "http://node-b", "offline".to_string());
        assert_eq!(
            with_peer_state(&state, "http://node-b", |peer| peer.health.label()),
            Some("unhealthy")
        );
        assert!(peer_should_force_snapshot(&state, "http://node-b"));

        update_peer_success(&state, "http://node-b");
        assert_eq!(
            with_peer_state(&state, "http://node-b", |peer| peer.health.label()),
            Some("healthy")
        );
        assert!(!peer_should_force_snapshot(&state, "http://node-b"));

        update_peer_revocation_cursor(
            &state,
            "http://node-b",
            RevocationCursor {
                revoked_at: 5,
                capability_id: "cap-1".to_string(),
            },
        );
        update_peer_budget_cursor(
            &state,
            "http://node-b",
            BudgetCursor {
                seq: 8,
                updated_at: 13,
                capability_id: "cap-1".to_string(),
                grant_index: 2,
            },
        );
        update_peer_tool_seq(&state, "http://node-b", 3);
        update_peer_child_seq(&state, "http://node-b", 4);
        update_peer_lineage_seq(&state, "http://node-b", 5);
        update_peer_delta_records(
            &state,
            "http://node-b",
            CLUSTER_SNAPSHOT_RECORD_THRESHOLD - 1,
        );
        assert_eq!(peer_tool_seq(&state, "http://node-b"), 3);
        assert_eq!(peer_child_seq(&state, "http://node-b"), 4);
        assert_eq!(peer_lineage_seq(&state, "http://node-b"), 5);
        assert_eq!(
            peer_revocation_cursor(&state, "http://node-b")
                .test_unwrap()
                .capability_id,
            "cap-1"
        );
        assert_eq!(
            peer_budget_cursor(&state, "http://node-b")
                .test_unwrap()
                .grant_index,
            2
        );
        assert!(!peer_should_force_snapshot(&state, "http://node-b"));

        update_peer_delta_records(&state, "http://node-b", 1);
        assert!(peer_should_force_snapshot(&state, "http://node-b"));

        assert!(budget_visibility_matches(true, Some(1), Some(2)));
        assert!(!budget_visibility_matches(true, None, Some(2)));
        assert!(budget_visibility_matches(false, Some(2), Some(2)));
        assert!(budget_visibility_matches(false, Some(1), None));
        assert!(!budget_visibility_matches(false, None, Some(3)));
    }

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
        let signature = cluster_peer_auth_signature(
            &cluster_state.config.service_token,
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
            issued_at,
            None,
        )
        .test_unwrap();
        headers.clear();
        headers.insert(
            CLUSTER_NODE_ID_HEADER,
            HeaderValue::from_static("http://node-b"),
        );
        headers.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&issued_at.to_string()).test_unwrap(),
        );
        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_str(&signature).test_unwrap(),
        );
        let peer = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap();
        assert_eq!(peer.node_id, "http://node-b");

        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_static("deadbeef"),
        );
        let invalid_peer = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap_err();
        assert_eq!(invalid_peer.status(), StatusCode::UNAUTHORIZED);
        clear_cluster_peer_auth_failures(&cluster_peer_auth_unverified_failure_key(
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
        ));

        let expired_issued_at = issued_at - CLUSTER_AUTH_MAX_SKEW_SECS - 1;
        let expired_signature = cluster_peer_auth_signature(
            &cluster_state.config.service_token,
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
            expired_issued_at,
            None,
        )
        .test_unwrap();
        headers.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&expired_issued_at.to_string()).test_unwrap(),
        );
        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_str(&expired_signature).test_unwrap(),
        );
        let expired_peer = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap_err();
        assert_eq!(expired_peer.status(), StatusCode::UNAUTHORIZED);
        clear_cluster_peer_auth_failures("http://node-b");

        for attempt in 0..CLUSTER_AUTH_FAILURE_BURST {
            let invalid_issued_at = issued_at + attempt as i64;
            headers.insert(
                CLUSTER_AUTH_ISSUED_AT_HEADER,
                HeaderValue::from_str(&invalid_issued_at.to_string()).test_unwrap(),
            );
            headers.insert(
                CLUSTER_AUTH_SIGNATURE_HEADER,
                HeaderValue::from_str(&format!("deadbeef-{attempt}")).test_unwrap(),
            );
            let response = validate_cluster_peer_auth(
                &headers,
                &cluster_state.config,
                INTERNAL_CLUSTER_STATUS_PATH,
            )
            .test_unwrap_err();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let limited_issued_at = issued_at + CLUSTER_AUTH_FAILURE_BURST as i64;
        headers.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&limited_issued_at.to_string()).test_unwrap(),
        );
        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_static("deadbeef-final"),
        );
        let limited_peer = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap_err();
        assert_eq!(limited_peer.status(), StatusCode::TOO_MANY_REQUESTS);
        headers.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&issued_at.to_string()).test_unwrap(),
        );
        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_str(&signature).test_unwrap(),
        );
        let peer_after_spoofed_failures = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap();
        assert_eq!(peer_after_spoofed_failures.node_id, "http://node-b");
        clear_cluster_peer_auth_failures(&cluster_peer_auth_unverified_failure_key(
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
        ));
        clear_cluster_peer_auth_failures("http://node-b");

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
        let source_revocation_db = unique_temp_path("cluster-source-revocations", "sqlite3");
        let source_budget_db = unique_temp_path("cluster-source-budgets", "sqlite3");
        let target_receipt_db = unique_temp_path("cluster-target-receipts", "sqlite3");
        let target_revocation_db = unique_temp_path("cluster-target-revocations", "sqlite3");
        let target_budget_db = unique_temp_path("cluster-target-budgets", "sqlite3");

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
        let mutation_events = SqliteBudgetStore::open(&target_budget_db)
            .test_unwrap()
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
    fn cluster_snapshot_round_trip_preserves_denied_budget_events_without_usage_rows() {
        let source_budget_db = unique_temp_path("cluster-source-denied-budgets", "sqlite3");
        let target_budget_db = unique_temp_path("cluster-target-denied-budgets", "sqlite3");

        let source_state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            None,
            None,
            Some(source_budget_db.clone()),
        );
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            None,
            None,
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

        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        assert_eq!(snapshot.replication.budget_seq, 1);
        assert!(snapshot.budgets.is_empty());
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
        drop(target_store);

        assert_eq!(
            peer_budget_cursor(&target_state, "http://node-a")
                .test_unwrap()
                .seq,
            1
        );
    }

    #[test]
    fn cluster_snapshot_round_trip_preserves_budget_usage_rows_without_mutation_events() {
        let source_budget_db = unique_temp_path("cluster-source-budget-usage-only", "sqlite3");
        let target_budget_db = unique_temp_path("cluster-target-budget-usage-only", "sqlite3");

        let source_state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            None,
            None,
            Some(source_budget_db.clone()),
        );
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            None,
            None,
            Some(target_budget_db.clone()),
        );

        {
            let budget_store = SqliteBudgetStore::open(&source_budget_db).test_unwrap();
            budget_store
                .upsert_usage(&chio_kernel::BudgetUsageRecord {
                    capability_id: "cap-usage-only".to_string(),
                    grant_index: 0,
                    invocation_count: 7,
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
        assert_eq!(usages[0].invocation_count, 7);
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
            total_cost_exposed_after: 10,
            total_cost_realized_spend_after: 0,
            authority: None,
        });

        assert_eq!(cursor.seq, 4);
        assert_eq!(cursor.capability_id, "cap-1");
        assert_eq!(cursor.grant_index, 2);
    }

    #[test]
    fn budget_delta_import_handles_records_without_mutation_events() {
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
            mutation_events: Vec::new(),
        };

        let outcome =
            import_budget_delta_response(&mut store, &response, None, &mut PullRoundBudget::new())
                .test_unwrap();
        assert_eq!(outcome.applied_count, 1);
        assert!(outcome.should_continue);
        assert_eq!(outcome.next_cursor.test_unwrap().seq, 42);

        let usage = store
            .get_usage("cap-records-only", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(usage.invocation_count, 3);
        assert_eq!(usage.seq, 42);
        assert_eq!(usage.total_cost_exposed, 55);
        assert_eq!(usage.total_cost_realized_spend, 21);
        assert!(store
            .list_mutation_events(10, Some("cap-records-only"), Some(0))
            .test_unwrap()
            .is_empty());
    }

    #[test]
    fn budget_delta_import_rejects_oversized_peer_payloads() {
        let budget_db = unique_temp_path("cluster-oversized-budget-delta", "sqlite3");
        let mut store = SqliteBudgetStore::open(&budget_db).test_unwrap();
        let response = BudgetDeltaResponse {
            records: (0..=BUDGET_DELTA_MAX_RECORDS)
                .map(|idx| BudgetUsageView {
                    capability_id: format!("cap-{idx}"),
                    grant_index: 0,
                    invocation_count: 1,
                    total_cost_exposed: 0,
                    total_cost_realized_spend: 0,
                    updated_at: 1_717_171_717,
                    seq: Some(idx as u64 + 1),
                })
                .collect(),
            mutation_events: Vec::new(),
        };

        let result =
            import_budget_delta_response(&mut store, &response, None, &mut PullRoundBudget::new());
        let Err(PullError::Transient(error)) = result else {
            panic!("oversized peer budget deltas should fail closed as a transient error");
        };
        assert!(error.to_string().contains("budget delta response contains"));
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
            mutation_events: vec![BudgetMutationEventView {
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
                total_cost_exposed_after: 1,
                total_cost_realized_spend_after: 0,
                authority: None,
            }],
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
            mutation_events: vec![event(5), event(6)],
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
            records: Vec::new(),
            mutation_events: vec![event(1), event(2), event(3)],
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
        // compaction floor must NOT authorize a global cursor jump (codex #965
        // Finding 3): recording origin-j's floor at 9 does not license a page
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
            mutation_events: vec![event(10), event(11)],
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
        let revocation_db = unique_temp_path("cluster-heads-revocation", "sqlite3");
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
    fn build_cluster_state_seeds_persisted_authority_fence_term() {
        let authority_db_path = unique_temp_path("cluster-authority-fence", "sqlite3");
        let authority = SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap();
        authority
            .seed_cluster_fence(Some("http://node-b"), 7)
            .test_unwrap();

        let mut config = base_config();
        config.advertise_url = Some("http://node-a".to_string());
        config.peer_urls = vec!["http://node-b".to_string()];
        config.authority_db_path = Some(authority_db_path.clone());

        let cluster = build_cluster_state(&config, config.listen)
            .test_unwrap()
            .test_unwrap();
        let guard = cluster.lock().test_unwrap();
        assert_eq!(guard.election_term, 7);
        assert_eq!(guard.last_leader_url.as_deref(), Some("http://node-b"));

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn build_cluster_state_discards_persisted_authority_fence_for_unknown_leader() {
        let authority_db_path =
            unique_temp_path("cluster-authority-fence-unknown-leader", "sqlite3");
        let authority = SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap();
        authority
            .seed_cluster_fence(Some("http://node-z"), 7)
            .test_unwrap();

        let mut config = base_config();
        config.advertise_url = Some("http://node-a".to_string());
        config.peer_urls = vec!["http://node-b".to_string()];
        config.authority_db_path = Some(authority_db_path.clone());

        let cluster = build_cluster_state(&config, config.listen)
            .test_unwrap()
            .test_unwrap();
        let guard = cluster.lock().test_unwrap();
        assert_eq!(guard.election_term, 7);
        assert!(
            guard.last_leader_url.is_none(),
            "unknown persisted leader should be cleared"
        );

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn build_cluster_state_discards_persisted_authority_fence_after_rotation() {
        let authority_db_path =
            unique_temp_path("cluster-authority-fence-stale-generation", "sqlite3");
        let authority = SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap();
        authority
            .seed_cluster_fence(Some("http://node-b"), 7)
            .test_unwrap();
        authority.rotate().test_unwrap();

        let mut config = base_config();
        config.advertise_url = Some("http://node-a".to_string());
        config.peer_urls = vec!["http://node-b".to_string()];
        config.authority_db_path = Some(authority_db_path.clone());

        let cluster = build_cluster_state(&config, config.listen)
            .test_unwrap()
            .test_unwrap();
        let guard = cluster.lock().test_unwrap();
        assert_eq!(guard.election_term, 0);
        assert!(guard.last_leader_url.is_none());

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn apply_cluster_snapshot_fails_when_authority_fence_persistence_fails() {
        let authority_db_path = unique_temp_path("cluster-authority-fence-dir", "d");
        std::fs::create_dir_all(&authority_db_path).test_unwrap();

        let source_state =
            state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            Some(authority_db_path.clone()),
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

        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        let error =
            apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap_err();
        let error_text = error.to_string();
        assert!(
            error_text.contains("directory") || error_text.contains("open database file"),
            "unexpected error: {error_text}"
        );

        let _ = std::fs::remove_dir_all(authority_db_path);
    }
}
