    use super::super::cluster::*;
    use super::super::report_rendering::*;
    use super::super::report_validation::*;
    use super::super::*;
    use axum::body::to_bytes;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use chio_test_support::prelude::*;

    static UNIQUE_TEMP_PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn base_config() -> TrustServiceConfig {
        TrustServiceConfig {
            listen: "127.0.0.1:0".parse().test_unwrap(),
            service_token: "token".to_string(),
            dashboard_read_token: None,
            dashboard_report_origin: None,
            dashboard_report_token: None,
            dashboard_allow_insecure_report_origin: false,
            authority_admin_token: None,
            authority_workloads: Vec::new(),
            tenant_read_tokens: BTreeMap::new(),
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            authority_keyring_config_path: None,
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
            cluster_node_seed_path: None,
            cluster_replay_db_path: None,
            cluster_members: Vec::new(),
            cluster_sync_interval: Duration::from_millis(25),
            roster_policy: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
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
        let self_key = deterministic_cluster_test_key(advertise_url);
        let seed_path = unique_temp_path("chio-cluster-node", "seed");
        crate::persist_authority_keypair(&seed_path, &self_key).test_unwrap();
        config.cluster_node_seed_path = Some(seed_path);
        let replay_db_path = unique_temp_path("chio-cluster-replay", "sqlite3");
        crate::trust_control::cluster_replay::initialize_cluster_peer_replay_ledger(&replay_db_path)
            .test_unwrap();
        config.cluster_replay_db_path = Some(replay_db_path);
        config.cluster_members = std::iter::once(advertise_url.to_string())
            .chain(peer_urls.iter().map(|value| (*value).to_string()))
            .map(|node_url| ClusterMemberIdentity {
                public_key: deterministic_cluster_test_key(&node_url).public_key(),
                node_url,
            })
            .collect();
        config.receipt_db_path = receipt_db_path;
        config.revocation_db_path = revocation_db_path;
        config.budget_db_path = budget_db_path;
        let cluster = build_cluster_state(&config, config.listen).test_unwrap();
        let cluster_progress = cluster.as_ref().map(|_| Arc::new(ClusterProgress::new()));
        let state = TrustServiceState {
            config,
            dashboard_sessions: dashboard_auth::DashboardSessionStore::production(),
            dashboard_report_bridge: None,
            authority_keyring: None,
            authority_test_backend: None,
            active_defense: service_runtime::TrustControlActiveDefenseService::disabled(),
            enterprise_provider_registry: None,
            verifier_policy_registry: None,
            federation_admission_rate_limiter: Arc::new(Mutex::new(
                FederationAdmissionRateLimiter::default(),
            )),
            authority_issuance_rotation_lock: Arc::new(Mutex::new(())),
            cluster,
            cluster_progress,
        };
        // A fresh peer starts with force_snapshot = true (it must snapshot before
        // its acks are trusted). Witness tests model
        // peers that have ALREADY completed their initial sync, so clear it here;
        // the force_snapshot exclusion itself is covered by its own test.
        for peer in peer_urls {
            update_peer_state(&state, peer, |peer| peer.force_snapshot = false);
        }
        state
    }

    fn unique_temp_path(prefix: &str, extension: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_unwrap()
            .as_nanos();
        let counter = UNIQUE_TEMP_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let process_id = std::process::id();
        std::env::temp_dir().join(format!(
            "{prefix}-{process_id}-{counter}-{nonce}.{extension}"
        ))
    }

    fn deterministic_cluster_test_key(node_url: &str) -> Keypair {
        let digest = hex::decode(sha256_hex(node_url.as_bytes())).test_unwrap();
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&digest);
        Keypair::from_seed(&seed)
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_cluster_test_headers(
        signing_key: &Keypair,
        node_url: &str,
        receiver_url: &str,
        method: &str,
        endpoint: &str,
        issued_at: i64,
        nonce: &str,
        term: Option<u64>,
        body_digest: &str,
    ) -> HeaderMap {
        let signature = cluster_peer_auth_signature(
            signing_key,
            node_url,
            receiver_url,
            method,
            endpoint,
            issued_at,
            nonce,
            term,
            body_digest,
        )
        .test_unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            CLUSTER_NODE_ID_HEADER,
            HeaderValue::from_str(node_url).test_unwrap(),
        );
        headers.insert(
            CLUSTER_AUTH_METHOD_HEADER,
            HeaderValue::from_str(method).test_unwrap(),
        );
        headers.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&issued_at.to_string()).test_unwrap(),
        );
        headers.insert(
            CLUSTER_AUTH_NONCE_HEADER,
            HeaderValue::from_str(nonce).test_unwrap(),
        );
        headers.insert(
            CLUSTER_AUTH_BODY_DIGEST_HEADER,
            HeaderValue::from_str(body_digest).test_unwrap(),
        );
        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_str(&signature).test_unwrap(),
        );
        if let Some(term) = term {
            headers.insert(
                CLUSTER_AUTH_TERM_HEADER,
                HeaderValue::from_str(&term.to_string()).test_unwrap(),
            );
        }
        headers
    }

    fn legacy_grant_quota_view(
        capability_id: &str,
        grant_index: u32,
        maximum: u32,
        captured: u32,
        seq: u64,
    ) -> BudgetInvocationQuotaUsageRecordView {
        BudgetInvocationQuotaUsageRecordView {
            usage: BudgetInvocationQuotaUsageView {
                quota: BudgetInvocationQuotaView {
                    key: BudgetQuotaKeyView {
                        profile: BudgetQuotaProfileView::GrantInvocation,
                        owner_id: capability_id.to_string(),
                        grant_index: Some(grant_index),
                    },
                    max_invocations: maximum,
                },
                reserved_invocations_after: 0,
                captured_invocations_after: captured,
            },
            updated_at: seq as i64,
            seq,
        }
    }

    fn import_budget_events_with_quota_authority(
        store: &SqliteBudgetStore,
        events: &[BudgetMutationEventView],
    ) {
        let records = events
            .iter()
            .map(|view| budget_mutation_record_from_view(view).test_unwrap())
            .collect::<Vec<_>>();
        let mut projections = BTreeMap::<(String, u32), (BudgetUsageRecord, u32)>::new();
        for event in events {
            if !matches!(
                BudgetMutationKind::parse(&event.kind),
                Some(
                    BudgetMutationKind::IncrementInvocation | BudgetMutationKind::AuthorizeExposure
                )
            ) {
                continue;
            }
            let maximum = event.max_invocations.unwrap_or(u32::MAX);
            let seq = event.usage_seq.unwrap_or(event.event_seq);
            let key = (event.capability_id.clone(), event.grant_index);
            match projections.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((
                        BudgetUsageRecord {
                            capability_id: event.capability_id.clone(),
                            grant_index: event.grant_index,
                            invocation_count: event.invocation_count_after,
                            updated_at: event.recorded_at,
                            seq,
                            total_cost_exposed: event.total_cost_exposed_after,
                            total_cost_realized_spend: event.total_cost_realized_spend_after,
                        },
                        maximum,
                    ));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let (usage, immutable_maximum) = entry.get_mut();
                    assert_eq!(
                        *immutable_maximum, maximum,
                        "test fixture cannot rebind an immutable invocation maximum"
                    );
                    if usage.seq < seq {
                        *usage = BudgetUsageRecord {
                            capability_id: event.capability_id.clone(),
                            grant_index: event.grant_index,
                            invocation_count: event.invocation_count_after,
                            updated_at: event.recorded_at,
                            seq,
                            total_cost_exposed: event.total_cost_exposed_after,
                            total_cost_realized_spend: event.total_cost_realized_spend_after,
                        };
                    }
                }
            }
        }
        let usages = projections
            .values()
            .map(|(usage, _)| usage.clone())
            .collect::<Vec<_>>();
        let quotas = projections
            .values()
            .map(|(usage, maximum)| {
                budget_invocation_quota_usage_record_from_view(&legacy_grant_quota_view(
                    &usage.capability_id,
                    usage.grant_index,
                    *maximum,
                    usage.invocation_count,
                    usage.seq,
                ))
                .test_unwrap()
            })
            .collect::<Vec<_>>();
        store
            .import_snapshot_records_with_invocation_quotas(&usages, &quotas, &records)
            .test_unwrap();
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
                aggregate_invocation_budget: None,
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
            .contains("clustered capability-authority custody and issuance are unsupported"));

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
        config.peer_urls = vec!["http://127.0.0.1:3300/".to_string()];
        let node_key = deterministic_cluster_test_key("http://127.0.0.1:3200");
        let seed_path = unique_temp_path("chio-cluster-normalization", "seed");
        crate::persist_authority_keypair(&seed_path, &node_key).test_unwrap();
        config.cluster_node_seed_path = Some(seed_path);
        let replay_path = unique_temp_path("chio-cluster-normalization-replay", "sqlite3");
        crate::trust_control::cluster_replay::initialize_cluster_peer_replay_ledger(&replay_path)
            .test_unwrap();
        config.cluster_replay_db_path = Some(replay_path);
        config.cluster_members = [
            "http://127.0.0.1:3200",
            "http://127.0.0.1:3300",
        ]
        .into_iter()
        .map(|node_url| ClusterMemberIdentity {
            public_key: deterministic_cluster_test_key(node_url).public_key(),
            node_url: node_url.to_string(),
        })
        .collect();

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

        let error = normalize_cluster_config_url(" http://127.0.0.1:3300/ ", true)
            .test_unwrap_err();
        assert!(error
            .to_string()
            .contains("whitespace or control characters"));
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

    #[test]
    fn regressed_ack_head_is_cleared_before_validation_not_witnessed_at_old_high() {
        // The per-peer sync round records a peer's freshly-advertised acks only at
        // the END (finalize_peer_sync_round). If a peer REGRESSED its ack head
        // (lost/restored its budget DB and now advertises a lower or absent head),
        // the stale-HIGH recorded value would keep witnessing for the WHOLE round,
        // so a budget write that checks the quorum view mid-round could commit
        // against a peer that already disavowed the write - an over-count.
        // `clamp_down_peer_budget_acks` applies the DECREASE/CLEAR immediately at the
        // TOP of the round (sync_peer, right after update_peer_reachable): a no-op or
        // max-merge would leave node-b witnessing seq 8; the down-clamp drops it out
        // at the old-high seq.
        let state = state_with_cluster(
            "http://node-a",
            &["http://node-b", "http://node-c"],
            None,
            None,
            None,
        );
        update_peer_reachable(&state, "http://node-b");
        update_peer_reachable(&state, "http://node-c");
        // Both peers previously imported node-a's stream up to seq 10.
        update_peer_budget_acks(
            &state,
            "http://node-b",
            &[BudgetOriginAck {
                origin_id: "http://node-a".to_string(),
                event_seq: 10,
            }],
        );
        update_peer_budget_acks(
            &state,
            "http://node-c",
            &[BudgetOriginAck {
                origin_id: "http://node-a".to_string(),
                event_seq: 10,
            }],
        );

        let write = BudgetWriteToken {
            origin_id: "http://node-a".to_string(),
            event_seq: 8,
            budget_term: 1,
        };
        // Precondition: with both peers recorded at 10, the write at seq 8 witnesses
        // on self + node-b + node-c.
        let before = budget_write_quorum_commit_view(&state, &write).test_unwrap();
        assert!(before.witness_urls.contains(&"http://node-b".to_string()));
        assert_eq!(before.committed_nodes, 3);

        // node-b REGRESSES to seq 5 (lost a suffix of node-a's stream). This is the
        // top-of-round clamp that sync_peer now applies from cluster_status.
        clamp_down_peer_budget_acks(
            &state,
            "http://node-b",
            &[BudgetOriginAck {
                origin_id: "http://node-a".to_string(),
                event_seq: 5,
            }],
        );
        // node-b no longer witnesses at seq 8 (5 < 8); the stale-high 10 is
        // gone the instant the peer disavowed it, not at the end of the round.
        let after = budget_write_quorum_commit_view(&state, &write).test_unwrap();
        assert!(
            !after.witness_urls.contains(&"http://node-b".to_string()),
            "a regressed peer must not witness at the OLD-high seq"
        );
        assert_eq!(
            after.committed_nodes, 2,
            "only self + node-c (still at 10) witness after the regression"
        );

        // An INCREASE must NOT be applied by the clamp (increases wait for
        // validation in finalize_peer_sync_round): even if node-b now advertises 20,
        // the clamp leaves it at the regressed 5, so it still does not witness seq 8.
        clamp_down_peer_budget_acks(
            &state,
            "http://node-b",
            &[BudgetOriginAck {
                origin_id: "http://node-a".to_string(),
                event_seq: 20,
            }],
        );
        let after_increase = budget_write_quorum_commit_view(&state, &write).test_unwrap();
        assert!(
            !after_increase
                .witness_urls
                .contains(&"http://node-b".to_string()),
            "the clamp must not RAISE a head on an increase (increases wait for validation)"
        );

        // A CLEAR (origin no longer advertised at all) drops the origin entirely, so
        // node-c stops witnessing it too.
        clamp_down_peer_budget_acks(&state, "http://node-c", &[]);
        let after_clear = budget_write_quorum_commit_view(&state, &write).test_unwrap();
        assert!(
            !after_clear
                .witness_urls
                .contains(&"http://node-c".to_string()),
            "a peer that no longer advertises the origin must not witness it"
        );
        assert_eq!(after_clear.committed_nodes, 1, "only self remains");
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

    /// End-to-end proof that budget_ack_heads (the store SQL) ->
    /// update_peer_budget_acks -> witness holds across an authority change. Two authorities share one
    /// global event_seq stream; origin B's block starts mid-sequence (a
    /// leadership change). A peer that has durably imported the contiguous
    /// global prefix MUST witness B's write (no false time-out), and a global
    /// hole MUST cap the head so a write above the hole is NOT witnessed.
    #[test]
    fn witness_counts_authority_change_origin_and_caps_at_global_hole() {
        let origin_a = "http://origin-a";
        let origin_b = "http://origin-b";
        let event = |seq: u64, origin: &str| BudgetMutationEventView {
            operation_id: None,
            request_binding_hash: None,
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
            import_budget_events_with_quota_authority(&store, &events);
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
                "the authority-change write must witness on a fully-imported quorum"
            );
            assert_eq!(commit.committed_nodes, 3);
        }
        let _ = std::fs::remove_file(&db1);

        // --- Case 2: a global hole caps the head. origin A owns 1..=3,
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
            import_budget_events_with_quota_authority(&store, &events);
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
                "a write above a global hole must not witness (a MAX-per-origin ack head would)"
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
        // A peer that restored an older budget DB (or lost a prefix) re-advertises
        // a LOWER or empty ack set. The stored ack must
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
        // If leadership changes while a write waits, the commit metadata must name
        // the authority that AUTHORED the write, not the current consensus leader
        // (which never wrote the event).
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
        assert!(
            !commit.quorum_committed,
            "historical witness metadata must not itself authorize a stale-term commit"
        );
    }

    #[test]
    fn force_snapshot_peer_is_excluded_from_witnesses_until_resynced() {
        // A peer demoted by a protocol error and pending a forced snapshot carries
        // stale, untrusted acks. Even after a bare
        // reachability probe flips it Healthy and it re-advertises acks, it must
        // NOT witness until the snapshot + delta re-sync clears force_snapshot.
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
        update_peer_budget_acks(&state, "http://node-b", &ack(10));
        update_peer_budget_acks(&state, "http://node-c", &ack(10));
        let write = BudgetWriteToken {
            origin_id: origin.to_string(),
            event_seq: 8,
            budget_term: 1,
        };
        let commit = budget_write_quorum_commit_view(&state, &write).test_unwrap();
        assert_eq!(commit.committed_nodes, 3);

        // node-b is Healthy (probed reachable) but still pending its forced
        // snapshot: its stale acks must not witness.
        update_peer_state(&state, "http://node-b", |peer| peer.force_snapshot = true);
        let commit = budget_write_quorum_commit_view(&state, &write).test_unwrap();
        assert_eq!(
            commit.committed_nodes, 2,
            "a force_snapshot peer must not witness until it re-syncs"
        );

        // Snapshot completed: force_snapshot cleared, node-b witnesses again.
        update_peer_state(&state, "http://node-b", |peer| peer.force_snapshot = false);
        let commit = budget_write_quorum_commit_view(&state, &write).test_unwrap();
        assert_eq!(commit.committed_nodes, 3);
    }

    #[test]
    fn peer_applying_a_snapshot_does_not_witness_at_its_old_high_ack() {
        // A peer that is force_snapshot carries a stale-high ack head that is
        // excluded from witnesses ONLY by the force_snapshot flag.
        // apply_cluster_snapshot clears force_snapshot; if it left the old ack in
        // place, any early return before finalize_peer_sync_round (an authority-sync
        // error, a puller error) would leave the peer Healthy, NOT force_snapshot,
        // and WITNESSING at an ack head this round never validated - an OVER-COUNT /
        // budget double-spend. apply_cluster_snapshot instead clears
        // budget_import_acks atomically with force_snapshot, so a peer coming out of
        // snapshot recovery witnesses NOTHING until a completed pull round's finalize
        // re-records a validated ack.
        let origin = "http://node-a";
        // A 2-node cluster (quorum 2): self + node-a is quorum, so node-a's witness
        // decision alone flips quorum_committed.
        let source_state =
            state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        let state = state_with_cluster("http://node-b", &["http://node-a"], None, None, None);

        // node-a previously validated a high ack and is now pending a forced snapshot
        // (e.g. an oversized delta window routed it to snapshot recovery).
        update_peer_reachable(&state, "http://node-a");
        update_peer_budget_acks(
            &state,
            "http://node-a",
            &[BudgetOriginAck {
                origin_id: origin.to_string(),
                event_seq: 100,
            }],
        );
        update_peer_state(&state, "http://node-a", |peer| peer.force_snapshot = true);

        let write = BudgetWriteToken {
            origin_id: origin.to_string(),
            event_seq: 100,
            budget_term: 1,
        };
        // While force_snapshot, the stale ack is already excluded (existing guard).
        assert!(
            !budget_write_quorum_commit_view(&state, &write)
                .test_unwrap()
                .quorum_committed,
            "a force_snapshot peer must not witness"
        );

        // Apply a snapshot: force_snapshot clears. If the stale ack survived, node-a
        // would now witness at 100, committing quorum on an ack this round never
        // validated; the ack map must be cleared atomically with force_snapshot.
        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        apply_cluster_snapshot(&state, "http://node-a", snapshot).test_unwrap();

        assert_eq!(
            with_peer_state(&state, "http://node-a", |peer| peer
                .budget_import_acks
                .get(origin)
                .copied()),
            Some(None),
            "snapshot recovery must clear the peer's cached witness ack"
        );
        assert!(
            !peer_should_force_snapshot(&state, "http://node-a"),
            "the snapshot cleared force_snapshot"
        );
        // The peer is Healthy and no longer force_snapshot, yet it must NOT
        // witness at its old-high ack until a validated finalize re-records one.
        let commit = budget_write_quorum_commit_view(&state, &write).test_unwrap();
        assert!(
            !commit.quorum_committed,
            "a peer coming out of snapshot recovery must not witness at its stale old-high ack head"
        );
        assert_eq!(
            commit.committed_nodes, 1,
            "only self witnesses; the just-resynced peer holds no validated ack yet"
        );
    }

    #[test]
    fn finalize_records_fresh_acks_only_when_the_peer_was_not_demoted() {
        // A peer's freshly-advertised budget acks must become countable for a quorum
        // commit ONLY after its pull round completes without demotion.
        // finalize_peer_sync_round is the SINGLE ack-record site and runs after the
        // pull round, so a peer demoted mid-round (a Protocol violation ->
        // update_peer_failure -> Unhealthy) never has its fresh, unvalidated ack
        // recorded. That closes the over-count window where an early progress wake
        // let a parked writer commit on an ack the fail-closed path then removed.
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
        let acks = vec![BudgetOriginAck {
            origin_id: origin.to_string(),
            event_seq: 9,
        }];

        // node-b was demoted during its round (route_pull -> update_peer_failure):
        // finalize must NOT record its advertised ack. Under the old code the ack
        // was recorded before the pull and an early wake could have committed on it.
        update_peer_failure(&state, "http://node-b", "protocol violation".to_string());
        finalize_peer_sync_round(&state, "http://node-b", &acks, 0);
        let recorded_b = with_peer_state(&state, "http://node-b", |peer| {
            peer.budget_import_acks.get(origin).copied()
        })
        .flatten();
        assert_eq!(
            recorded_b, None,
            "a demoted peer's fresh ack must never be recorded (over-count guard)"
        );

        // node-c finished the round Healthy: finalize records its ack, so it can
        // witness. This is the ONLY path that makes a fresh ack countable.
        finalize_peer_sync_round(&state, "http://node-c", &acks, 0);
        let recorded_c = with_peer_state(&state, "http://node-c", |peer| {
            peer.budget_import_acks.get(origin).copied()
        })
        .flatten();
        assert_eq!(
            recorded_c,
            Some(9),
            "a non-demoted, non-force-snapshot peer records its advertised ack"
        );

        // The witness set counts self + node-c only: node-b (demoted) is excluded,
        // and node-c counts solely because finalize recorded its ack post-validation.
        let write = BudgetWriteToken {
            origin_id: origin.to_string(),
            event_seq: 9,
            budget_term: 1,
        };
        let commit = budget_write_quorum_commit_view(&state, &write).test_unwrap();
        assert_eq!(
            commit.committed_nodes, 2,
            "self + node-c witness; the demoted node-b never contributes its fresh ack"
        );
        assert!(commit.witness_urls.iter().any(|url| url == "http://node-c"));
        assert!(!commit.witness_urls.iter().any(|url| url == "http://node-b"));
    }

    #[test]
    fn a_transient_budget_error_leaves_the_peer_healthy_so_revocations_still_run() {
        // The independent revocation lane in sync_peer runs unless the peer was
        // DEMOTED. A transient
        // budget-delta error (broken/slow budget endpoint) keeps the peer Healthy,
        // so peer_was_demoted stays false and revocations still replicate. A Protocol
        // violation demotes the peer, so revocations are skipped (fail-closed: an
        // untrusted peer is not pulled from).
        let state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        update_peer_reachable(&state, "http://node-b");
        assert!(!peer_was_demoted(&state, "http://node-b"));

        // Transient budget error: peer stays reachable, so the revocation lane runs.
        let mut records = 0u64;
        let _ = route_pull(
            &state,
            "http://node-b",
            Err(PullError::Transient(CliError::cli_other_error(
                "budget endpoint slow",
            ))),
            &mut records,
        );
        assert!(
            !peer_was_demoted(&state, "http://node-b"),
            "a transient budget error must not demote the peer, so revocations still replicate"
        );

        // Protocol violation: peer demoted, so the revocation lane is skipped.
        let _ = route_pull(
            &state,
            "http://node-b",
            Err(PullError::Protocol(PeerProtocolError::NonContiguousPage {
                expected_seq: 5,
                found_seq: 9,
            })),
            &mut records,
        );
        assert!(
            peer_was_demoted(&state, "http://node-b"),
            "a Protocol violation demotes the peer, so its revocations are not pulled"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clearing_force_snapshot_then_notifying_wakes_a_parked_waiter() {
        // A peer whose acks were recorded while still force_snapshot is excluded
        // from witnesses; when its snapshot CLEARS
        // force_snapshot, sync_peer must notify so the parked write re-checks and
        // counts the now-valid peer, instead of timing out while the next peer in
        // the round stalls. In a 3-node cluster (quorum 2), self + the just-cleared
        // peer is quorum.
        let state = state_with_cluster(
            "http://node-a",
            &["http://node-b", "http://node-c"],
            None,
            None,
            None,
        );
        update_peer_reachable(&state, "http://node-b");
        update_peer_reachable(&state, "http://node-c");
        // node-b advertised the quorum-making ack but is still pending its snapshot
        // (excluded); node-c never acks (simulating a slow peer in the same round).
        update_peer_state(&state, "http://node-b", |peer| peer.force_snapshot = true);
        update_peer_budget_acks(
            &state,
            "http://node-b",
            &[BudgetOriginAck {
                origin_id: "http://node-a".to_string(),
                event_seq: 5,
            }],
        );
        // While node-b is force_snapshot, quorum is NOT met (only self counts).
        let write = BudgetWriteToken {
            origin_id: "http://node-a".to_string(),
            event_seq: 5,
            budget_term: 1,
        };
        assert!(
            !budget_write_quorum_commit_view(&state, &write)
                .test_unwrap()
                .quorum_committed
        );

        let loop_state = state.clone();
        let background = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            // The snapshot completes: force_snapshot cleared, then notify (exactly
            // what sync_peer now does after apply_cluster_snapshot).
            update_peer_state(&loop_state, "http://node-b", |peer| {
                peer.force_snapshot = false
            });
            notify_cluster_progress(&loop_state);
        });

        let started = std::time::Instant::now();
        let commit = wait_for_budget_write_quorum_commit(&state, write)
            .await
            .test_unwrap()
            .test_unwrap();
        assert!(commit.quorum_committed);
        assert_eq!(commit.committed_nodes, 2, "self + the just-re-synced peer");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the waiter must wake on the post-snapshot notify, not wait out the timeout"
        );
        background.await.test_unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn notify_cluster_progress_wakes_a_parked_waiter_on_quorum() {
        // A waiter must wake as soon as the ack needed for quorum lands, not only
        // when the whole sync round finishes. In a 3-node
        // cluster (quorum 2), self + one peer is quorum: recording ONE peer's ack
        // mid-round and bumping progress must commit the parked write promptly,
        // well within the multi-second timeout, even though the other peer never
        // acked in this round.
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
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            // One peer advertises the quorum-making ack mid-round; the other stays
            // silent (simulating a slow/unreachable peer in the same round).
            update_peer_budget_acks(
                &loop_state,
                "http://node-b",
                &[BudgetOriginAck {
                    origin_id: "http://node-a".to_string(),
                    event_seq: 5,
                }],
            );
            notify_cluster_progress(&loop_state);
        });

        let started = std::time::Instant::now();
        let commit = wait_for_budget_write_quorum_commit(&state, write)
            .await
            .test_unwrap()
            .test_unwrap();
        assert!(commit.quorum_committed);
        assert_eq!(commit.committed_nodes, 2, "self + the single acking peer");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the waiter must wake on the mid-round ack, not wait out the timeout"
        );
        background.await.test_unwrap();
    }

    #[test]
    fn zero_exposure_compensation_still_reverses_the_invocation_debit() {
        let budget_path = unique_temp_path("chio-zero-exposure-compensation", "sqlite3");
        let state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            None,
            Some(budget_path.clone()),
            Some(budget_path.clone()),
        );
        let store = SqliteBudgetStore::open(&budget_path).test_unwrap();
        let authority = BudgetEventAuthority {
            authority_id: "http://node-a".to_string(),
            lease_id: "http://node-a#term-1".to_string(),
            lease_epoch: 1,
        };
        let payload = TryChargeCostRequest {
            capability_id: "cap-zero-compensation".to_string(),
            grant_index: 0,
            max_invocations: Some(1),
            cost_units: 0,
            max_cost_per_invocation: Some(0),
            max_total_cost_units: Some(10),
            hold_id: Some("hold-zero-compensation".to_string()),
            event_id: Some("hold-zero-compensation:authorize".to_string()),
        };
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                &payload.capability_id,
                payload.grant_index,
                payload.max_invocations,
                payload.cost_units,
                payload.max_cost_per_invocation,
                payload.max_total_cost_units,
                payload.hold_id.as_deref(),
                payload.event_id.as_deref(),
                Some(&authority),
            )
            .test_unwrap());
        let before = store
            .get_usage(&payload.capability_id, payload.grant_index)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(before.invocation_count, 1);
        assert_eq!(before.total_cost_exposed, 0);

        rollback_budget_authorize_exposure(
            &state,
            &payload,
            payload.event_id.as_deref().test_unwrap(),
            Some(&authority),
        )
        .test_unwrap();

        let after = store
            .get_usage(&payload.capability_id, payload.grant_index)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(after.invocation_count, 0);
        assert_eq!(after.total_cost_exposed, 0);
        assert_eq!(after.total_cost_realized_spend, 0);
        let events = store
            .list_mutation_events(10, Some(&payload.capability_id), Some(payload.grant_index))
            .test_unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].kind, BudgetMutationKind::ReverseExposure);
        assert!(events[1]
            .event_id
            .starts_with("hold-zero-compensation:authorize:rollback:"));

        let _ = std::fs::remove_file(budget_path);
    }

    #[test]
    fn budget_write_progress_close_fails_closed_while_clustered() {
        // If the ClusterProgress sender is lost mid-write, a node that is STILL
        // clustered must fail closed (503) so the caller rolls back
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

        // Detaching does not downgrade an already-authored HA write into an
        // unclustered success.
        let mut unclustered = clustered.clone();
        unclustered.cluster = None;
        unclustered.cluster_progress = None;
        assert!(budget_write_progress_closed_outcome(&unclustered, &write).is_err());

        // A write born unclustered carries the explicit empty/term-zero token and
        // is the only legitimate no-quorum success.
        let local_write = BudgetWriteToken {
            origin_id: String::new(),
            event_seq: 0,
            budget_term: 0,
        };
        assert!(matches!(
            budget_write_progress_closed_outcome(&unclustered, &local_write),
            Ok(None)
        ));
    }

    #[tokio::test]
    async fn quorum_wait_rejects_a_commit_after_authority_term_changes() {
        let state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        update_peer_reachable(&state, "http://node-b");
        update_peer_budget_acks(
            &state,
            "http://node-b",
            &[BudgetOriginAck {
                origin_id: "http://node-a".to_string(),
                event_seq: 42,
            }],
        );
        let stale_write = BudgetWriteToken {
            origin_id: "http://node-a".to_string(),
            event_seq: 42,
            budget_term: 7,
        };
        assert!(
            budget_write_quorum_commit_view(&state, &stale_write)
                .test_unwrap()
                .quorum_committed,
            "the raw witness view is intentionally independent of the live lease gate"
        );

        let response = wait_for_budget_write_quorum_commit(&state, stale_write)
            .await
            .test_expect_err("stale authority term must fail before commit acceptance");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writer_wait_never_stalls_sync_loop() {
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
