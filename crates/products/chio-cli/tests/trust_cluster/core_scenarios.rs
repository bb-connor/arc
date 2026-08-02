fn run_trust_control_cluster_proving_scenario(run_index: usize, run_total: usize) {
    println!("trust-cluster proving run {run_index}/{run_total}");

    let dir = unique_test_dir().join(format!("run-{run_index}-of-{run_total}"));
    create_private_test_dir(&dir);
    let addr_a = reserve_listen_addr();
    let addr_b = reserve_listen_addr();
    let url_a = format!("http://{addr_a}");
    let url_b = format!("http://{addr_b}");
    let expected_leader_url = std::cmp::min(url_a.clone(), url_b.clone());
    let service_token = "cluster-token";

    let receipt_db_a = dir.join("receipts-a.sqlite3");
    let revocation_db_a = dir.join("revocations-a.sqlite3");
    let authority_db = dir.join("authority.sqlite3");
    let budget_db_a = dir.join("budgets-a.sqlite3");
    let receipt_db_b = dir.join("receipts-b.sqlite3");
    let revocation_db_b = dir.join("revocations-b.sqlite3");
    let budget_db_b = dir.join("budgets-b.sqlite3");

    let mut server_a = Some(spawn_trust_service(
        addr_a,
        service_token,
        &receipt_db_a,
        &revocation_db_a,
        &authority_db,
        &budget_db_a,
        None,
        &url_a,
        std::slice::from_ref(&url_b.to_string()),
    ));
    let mut server_b = Some(spawn_trust_service(
        addr_b,
        service_token,
        &receipt_db_b,
        &revocation_db_b,
        &authority_db,
        &budget_db_b,
        None,
        &url_b,
        std::slice::from_ref(&url_a.to_string()),
    ));

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    wait_until("node A health reachable", Duration::from_secs(20), || {
        try_get_json(&client, &format!("{url_a}/health"), service_token).is_some()
    });
    wait_until("node B health reachable", Duration::from_secs(20), || {
        try_get_json(&client, &format!("{url_b}/health"), service_token).is_some()
    });
    wait_for_leader_convergence(&client, service_token, &url_a, &url_b, &expected_leader_url);

    let leader_url = expected_leader_url;
    let follower_url = if leader_url == url_a {
        url_b.clone()
    } else {
        url_a.clone()
    };

    // `ChioReceipt::sign` overwrites the supplied id with the canonical content hash
    // (`chio_receipt_id`) and folds the input string in as a signing nonce. Match
    // visibility against the stored id, not the nonce.
    let leader_tool = sample_receipt("cluster-tool-leader", "cap-tool-leader");
    let leader_tool_id = leader_tool.id.clone();
    let leader_tool_receipt = serde_json::to_value(&leader_tool).expect("tool receipt json");
    let stored_leader_tool = post_json(
        &client,
        &format!("{leader_url}/v1/receipts/tools"),
        service_token,
        &leader_tool_receipt,
    );
    assert_eq!(stored_leader_tool["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_leader_tool, &leader_url);
    assert_tool_receipt_visible(
        &client,
        &leader_url,
        service_token,
        "cap-tool-leader",
        &leader_tool_id,
    );

    let follower_tool = sample_receipt("cluster-tool-follower", "cap-tool-follower");
    let follower_tool_id = follower_tool.id.clone();
    let follower_tool_receipt = serde_json::to_value(&follower_tool).expect("tool receipt json");
    let stored_follower_tool = post_json(
        &client,
        &format!("{follower_url}/v1/receipts/tools"),
        service_token,
        &follower_tool_receipt,
    );
    assert_eq!(stored_follower_tool["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_follower_tool, &leader_url);
    assert_tool_receipt_visible(
        &client,
        &leader_url,
        service_token,
        "cap-tool-follower",
        &follower_tool_id,
    );

    wait_until("tool receipt replication", Duration::from_secs(90), || {
        try_get_json(
            &client,
            &format!("{follower_url}/v1/receipts/tools?limit=10"),
            service_token,
        )
        .and_then(|value| value["count"].as_u64())
            == Some(2)
    });

    let leader_child_receipt =
        serde_json::to_value(sample_child_receipt("cluster-child-leader", "leader"))
            .expect("child receipt json");
    let stored_leader_child = post_json(
        &client,
        &format!("{leader_url}/v1/receipts/children"),
        service_token,
        &leader_child_receipt,
    );
    assert_eq!(stored_leader_child["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_leader_child, &leader_url);
    assert_child_receipt_visible(
        &client,
        &leader_url,
        service_token,
        "child-leader",
        "cluster-child-leader",
    );

    let follower_child_receipt =
        serde_json::to_value(sample_child_receipt("cluster-child-follower", "follower"))
            .expect("child receipt json");
    let stored_follower_child = post_json(
        &client,
        &format!("{follower_url}/v1/receipts/children"),
        service_token,
        &follower_child_receipt,
    );
    assert_eq!(stored_follower_child["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_follower_child, &leader_url);
    assert_child_receipt_visible(
        &client,
        &leader_url,
        service_token,
        "child-follower",
        "cluster-child-follower",
    );

    wait_until("child receipt replication", Duration::from_secs(90), || {
        try_get_json(
            &client,
            &format!("{follower_url}/v1/receipts/children?limit=10"),
            service_token,
        )
        .and_then(|value| value["count"].as_u64())
            == Some(2)
    });

    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let child_kp = Keypair::generate();
    let root_capability = sample_capability("cluster-lineage-root", &root_kp, &issuer_kp);
    let child_capability = sample_delegated_capability(
        "cluster-lineage-child",
        &child_kp,
        &root_kp,
        &root_capability,
    );

    let stored_root_lineage = post_json(
        &client,
        &format!("{leader_url}/v1/lineage"),
        service_token,
        &json!({
            "capability": root_capability,
        }),
    );
    assert_eq!(stored_root_lineage["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_root_lineage, &leader_url);
    assert_lineage_visible(&client, &leader_url, service_token, "cluster-lineage-root");

    let stored_child_lineage = post_json(
        &client,
        &format!("{follower_url}/v1/lineage"),
        service_token,
        &json!({
            "capability": child_capability,
            "parentCapabilityId": "cluster-lineage-root",
        }),
    );
    assert_eq!(stored_child_lineage["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_child_lineage, &leader_url);
    assert_lineage_visible(&client, &leader_url, service_token, "cluster-lineage-child");

    wait_until_with_diagnostics(
        "lineage replication",
        Duration::from_secs(90),
        || {
            let Some(lineage) = try_get_json(
                &client,
                &format!("{follower_url}/v1/lineage/cluster-lineage-child/chain"),
                service_token,
            ) else {
                return false;
            };
            let Some(chain) = lineage.as_array() else {
                return false;
            };
            chain.len() == 2
                && chain[0]["capability_id"].as_str() == Some("cluster-lineage-root")
                && chain[1]["capability_id"].as_str() == Some("cluster-lineage-child")
        },
        || {
            cluster_timeout_diagnostics(
                &client,
                &leader_url,
                &follower_url,
                service_token,
                "cluster-lineage-child",
            )
        },
    );

    let revoked_leader = post_json(
        &client,
        &format!("{leader_url}/v1/revocations"),
        service_token,
        &json!({"capabilityId": "cap-revoke-leader"}),
    );
    assert_eq!(revoked_leader["revoked"].as_bool(), Some(true));
    assert_leader_visible_metadata(&revoked_leader);
    assert_revocation_visible(&client, &leader_url, service_token, "cap-revoke-leader");

    let revoked_follower = post_json(
        &client,
        &format!("{follower_url}/v1/revocations"),
        service_token,
        &json!({"capabilityId": "cap-revoke-follower"}),
    );
    assert_eq!(revoked_follower["revoked"].as_bool(), Some(true));
    assert_leader_visible_metadata(&revoked_follower);
    assert_revocation_visible(&client, &leader_url, service_token, "cap-revoke-follower");

    wait_until_with_diagnostics(
        "revocation replication",
        Duration::from_secs(120),
        || {
            let revocation_visible = |value: &Value, capability_id: &str| {
                value["revoked"].as_bool() == Some(true)
                    && value["revocations"]
                        .as_array()
                        .map(|revocations| {
                            revocations
                                .iter()
                                .any(|entry| entry["capabilityId"].as_str() == Some(capability_id))
                        })
                        .unwrap_or(false)
            };
            let Some(leader_revocation) = try_get_json(
                &client,
                &format!("{follower_url}/v1/revocations?capabilityId=cap-revoke-leader&limit=10"),
                service_token,
            ) else {
                return false;
            };
            let Some(follower_revocation) = try_get_json(
                &client,
                &format!("{follower_url}/v1/revocations?capabilityId=cap-revoke-follower&limit=10"),
                service_token,
            ) else {
                return false;
            };
            revocation_visible(&leader_revocation, "cap-revoke-leader")
                && revocation_visible(&follower_revocation, "cap-revoke-follower")
        },
        || {
            json!({
                "leaderUrl": leader_url,
                "followerUrl": follower_url,
                "leader": {
                    "health": try_get_json(&client, &format!("{leader_url}/health"), service_token),
                    "clusterStatus": try_internal_cluster_status(&client, &leader_url, service_token),
                    "capRevokeLeader": try_get_json(
                        &client,
                        &format!(
                            "{leader_url}/v1/revocations?capabilityId=cap-revoke-leader&limit=10"
                        ),
                        service_token,
                    ),
                    "capRevokeFollower": try_get_json(
                        &client,
                        &format!(
                            "{leader_url}/v1/revocations?capabilityId=cap-revoke-follower&limit=10"
                        ),
                        service_token,
                    ),
                },
                "follower": {
                    "health": try_get_json(&client, &format!("{follower_url}/health"), service_token),
                    "clusterStatus": try_internal_cluster_status(&client, &follower_url, service_token),
                    "capRevokeLeader": try_get_json(
                        &client,
                        &format!(
                            "{follower_url}/v1/revocations?capabilityId=cap-revoke-leader&limit=10"
                        ),
                        service_token,
                    ),
                    "capRevokeFollower": try_get_json(
                        &client,
                        &format!(
                            "{follower_url}/v1/revocations?capabilityId=cap-revoke-follower&limit=10"
                        ),
                        service_token,
                    ),
                },
            })
        },
    );

    let leader_budget = post_json(
        &client,
        &format!("{leader_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(leader_budget["allowed"].as_bool(), Some(true));
    assert_eq!(leader_budget["invocationCount"].as_u64(), Some(1));
    assert_budget_authority_metadata(&leader_budget, &leader_url, "ha_linearizable");
    assert_budget_commit_metadata(
        &leader_budget,
        &leader_url,
        2,
        2,
        &[leader_url.as_str(), follower_url.as_str()],
    );
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 1);

    let second_budget = post_json(
        &client,
        &format!("{follower_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(second_budget["allowed"].as_bool(), Some(true));
    assert_eq!(second_budget["invocationCount"].as_u64(), Some(2));
    assert_budget_authority_metadata(&second_budget, &leader_url, "ha_linearizable");
    assert_budget_commit_metadata(
        &second_budget,
        &leader_url,
        2,
        2,
        &[leader_url.as_str(), follower_url.as_str()],
    );
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 2);

    let rapid_budget = post_json(
        &client,
        &format!("{leader_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(rapid_budget["allowed"].as_bool(), Some(true));
    assert_eq!(rapid_budget["invocationCount"].as_u64(), Some(3));
    assert_budget_authority_metadata(&rapid_budget, &leader_url, "ha_linearizable");
    assert_budget_commit_metadata(
        &rapid_budget,
        &leader_url,
        2,
        2,
        &[leader_url.as_str(), follower_url.as_str()],
    );
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 3);

    wait_until_with_diagnostics(
        "follower budget visibility",
        Duration::from_secs(90),
        || {
            let Some(budgets) = try_get_json(
                &client,
                &format!("{follower_url}/v1/budgets?capabilityId=cap-shared&limit=10"),
                service_token,
            ) else {
                return false;
            };
            budgets["count"].as_u64() == Some(1)
                && budgets["usages"][0]["invocationCount"].as_u64() == Some(3)
        },
        || {
            cluster_timeout_diagnostics(
                &client,
                &leader_url,
                &follower_url,
                service_token,
                "cap-shared",
            )
        },
    );
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 3);
    assert_budget_invocation_count(&client, &follower_url, service_token, "cap-shared", 0, 3);
    assert_budget_totals(&client, &leader_url, service_token, "cap-shared", 0, 0, 0);
    wait_for_leader_convergence(&client, service_token, &url_a, &url_b, &leader_url);

    let authorized_budget = post_json_eventually_ok_with_diagnostics(
        &client,
        &format!("{leader_url}/v1/budgets/authorize-hold"),
        service_token,
        &composite_authorize_payload(
            "cap-shared",
            0,
            75,
            100,
            400,
            4,
            "cap-shared-hold-1",
            "cap-shared-hold-1:authorize",
        ),
        "shared budget authorize exposure reaches quorum",
        Duration::from_secs(30),
        || {
            cluster_timeout_diagnostics(
                &client,
                &leader_url,
                &follower_url,
                service_token,
                "cap-shared",
            )
        },
    );
    assert_eq!(authorized_budget["allowed"].as_bool(), Some(true));
    assert_eq!(authorized_budget["invocationCountAfter"].as_u64(), Some(4));
    assert_eq!(
        authorized_budget["authorizedExposureUnits"].as_u64(),
        Some(75)
    );
    assert_eq!(
        authorized_budget["committedCostUnitsAfter"].as_u64(),
        Some(75)
    );
    assert_budget_authority_metadata(&authorized_budget, &leader_url, "ha_linearizable");
    assert_budget_commit_metadata(
        &authorized_budget,
        &leader_url,
        2,
        2,
        &[leader_url.as_str(), follower_url.as_str()],
    );
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 4);
    assert_budget_totals(&client, &leader_url, service_token, "cap-shared", 0, 75, 0);

    let survivor_url = if leader_url == url_a {
        drop(server_a.take());
        url_b.clone()
    } else {
        drop(server_b.take());
        url_a.clone()
    };
    wait_until(
        "quorum loss after leader failure",
        Duration::from_secs(90),
        || {
            let Some(status) = try_internal_cluster_status(&client, &survivor_url, service_token)
            else {
                return false;
            };
            status["leaderUrl"].is_null()
                && status["hasQuorum"].as_bool() == Some(false)
                && status["reachableNodes"].as_u64() == Some(1)
        },
    );

    let (status, body) = post_json_status(
        &client,
        &format!("{survivor_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(status, 503);
    assert!(
        body.contains("quorum") || body.contains("leader"),
        "expected quorum failure body, got: {body}"
    );

    let budgets = get_json(
        &client,
        &format!("{survivor_url}/v1/budgets?capabilityId=cap-shared&limit=10"),
        service_token,
    );
    assert_eq!(budgets["count"].as_u64(), Some(1));
    assert_eq!(budgets["usages"][0]["invocationCount"].as_u64(), Some(4));
    assert_eq!(
        budgets["usages"][0]["totalExposureCharged"].as_u64(),
        Some(75)
    );
}

#[test]
fn trust_control_cluster_replicates_state_and_fails_closed_without_quorum() {
    let _test_lock = trust_cluster_test_lock();
    run_trust_control_cluster_proving_scenario(1, 1);
}

#[test]
fn trust_service_loads_runtime_assurance_policy_with_standalone_authority() {
    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir();
    create_private_test_dir(&dir);

    let addr = reserve_listen_addr();
    let base_url = format!("http://{addr}");
    let service_token = "runtime-assurance-token";
    let receipt_db = dir.join("receipts.sqlite3");
    let revocation_db = dir.join("revocations.sqlite3");
    let authority_db = dir.join("authority.sqlite3");
    let budget_db = dir.join("budgets.sqlite3");
    let policy_path = dir.join("runtime-assurance-policy.yaml");
    fs::write(
        &policy_path,
        r#"
hushspec: "0.1.0"
name: runtime-assurance
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
extensions:
  runtime_assurance:
    tiers:
      baseline:
        minimum_attestation_tier: none
        max_scope:
          operations: ["invoke"]
          max_invocations: 5
          max_cost_per_invocation:
            units: 50
            currency: USD
          max_total_cost:
            units: 100
            currency: USD
          max_delegation_depth: 0
          ttl_seconds: 30
      attested:
        minimum_attestation_tier: attested
        max_scope:
          operations: ["invoke"]
          max_invocations: 20
          max_cost_per_invocation:
            units: 250
            currency: USD
          max_total_cost:
            units: 1000
            currency: USD
          max_delegation_depth: 0
          ttl_seconds: 300
    trusted_verifiers:
      azure_test:
        schema: chio.runtime-attestation.azure-maa.jwt.v1
        verifier: https://maa.contoso.test/
        effective_tier: attested
        verifier_family: azure_maa
        max_evidence_age_seconds: 120
        allowed_attestation_types: [sgx]
        required_assertions:
          attestationType: sgx
"#,
    )
    .expect("write policy");

    let _server = spawn_trust_service(
        addr,
        service_token,
        &receipt_db,
        &revocation_db,
        &authority_db,
        &budget_db,
        Some(&policy_path),
        &base_url,
        &[],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");
    wait_until(
        "runtime assurance health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{base_url}/health"), service_token).is_some(),
    );
    assert_authority_generation(&client, &base_url, service_token, 1);

    let health = get_json(&client, &format!("{base_url}/health"), service_token);
    assert_eq!(
        health["federation"]["runtimeAssurancePolicyConfigured"].as_bool(),
        Some(true)
    );
}

#[test]
fn trust_control_cluster_internal_status_requires_signed_node_identity() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_internal_status_requires_signed_node_identity",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("cluster-node-identity");
    create_private_test_dir(&dir);

    let addr_a = reserve_listen_addr();
    let addr_b = reserve_listen_addr();
    let url_a = format!("http://{addr_a}");
    let url_b = format!("http://{addr_b}");
    let expected_leader_url = std::cmp::min(url_a.clone(), url_b.clone());
    let service_token = "cluster-node-identity-token";

    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        std::slice::from_ref(&url_b),
    );
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        std::slice::from_ref(&url_a),
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    wait_until(
        "node identity cluster health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_a}/health"), service_token).is_some(),
    );
    wait_until(
        "node identity peer health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_b}/health"), service_token).is_some(),
    );
    wait_for_leader_convergence(&client, service_token, &url_a, &url_b, &expected_leader_url);

    let unsigned = client
        .get(format!("{url_a}/v1/internal/cluster/status"))
        .send()
        .expect("send unsigned internal cluster status request");
    assert_eq!(unsigned.status().as_u16(), 401);

    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs() as i64;
    let invalid_signature = client
        .get(format!("{url_a}/v1/internal/cluster/status"))
        .header(CLUSTER_NODE_ID_HEADER, url_b.clone())
        .header(CLUSTER_AUTH_ISSUED_AT_HEADER, issued_at.to_string())
        .header(CLUSTER_AUTH_SIGNATURE_HEADER, "deadbeef")
        .send()
        .expect("send invalid internal cluster status request");
    assert_eq!(invalid_signature.status().as_u16(), 401);

    let status = try_internal_cluster_status(&client, &url_a, service_token)
        .expect("allowlisted signed peer request should succeed");
    assert_eq!(
        status["leaderUrl"].as_str(),
        Some(expected_leader_url.as_str())
    );
}

#[test]
fn trust_control_cluster_requires_quorum_and_heals_after_partition() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_requires_quorum_and_heals_after_partition",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("quorum-heal");
    create_private_test_dir(&dir);

    let nodes = reserve_cluster_nodes(3);
    let (addr_a, url_a) = nodes[0].clone();
    let (addr_b, url_b) = nodes[1].clone();
    let (addr_c, url_c) = nodes[2].clone();
    let urls = vec![url_a.clone(), url_b.clone(), url_c.clone()];
    let service_token = "cluster-quorum-token";
    let expected_leader_url = url_a.clone();
    let majority_urls = vec![url_a.clone(), url_b.clone()];
    let isolated_url = url_c.clone();

    let _server_a = spawn_partitionable_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        &[url_b.clone(), url_c.clone()],
    );
    let _server_b = spawn_partitionable_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        &[url_a.clone(), url_c.clone()],
    );
    let _server_c = spawn_partitionable_trust_service(
        addr_c,
        service_token,
        &dir.join("receipts-c.sqlite3"),
        &dir.join("revocations-c.sqlite3"),
        &dir.join("authority-c.sqlite3"),
        &dir.join("budgets-c.sqlite3"),
        None,
        &url_c,
        &[url_a.clone(), url_b.clone()],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    for base_url in &urls {
        wait_until(
            "cluster node health reachable",
            Duration::from_secs(20),
            || try_get_json(&client, &format!("{base_url}/health"), service_token).is_some(),
        );
    }

    wait_until_with_diagnostics(
        "three-node quorum convergence",
        Duration::from_secs(90),
        || {
            urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["quorumSize"].as_u64() == Some(2)
                    && status["reachableNodes"].as_u64() == Some(3)
            })
        },
        || cluster_status_diagnostics(&client, &urls, service_token),
    );

    let isolated_status_before_partition =
        try_internal_cluster_status(&client, &isolated_url, service_token)
            .expect("isolated node status before partition");
    let isolated_snapshot_baseline = isolated_status_before_partition["peers"]
        .as_array()
        .expect("isolated peer status array before partition")
        .iter()
        .map(|peer| {
            let peer_url = peer["peerUrl"]
                .as_str()
                .expect("isolated peer url before partition");
            let snapshot_applied_count = peer["snapshotAppliedCount"]
                .as_u64()
                .expect("isolated peer snapshot count before partition");
            (peer_url.to_string(), snapshot_applied_count)
        })
        .collect::<HashMap<_, _>>();
    assert_eq!(isolated_snapshot_baseline.len(), majority_urls.len());

    for base_url in &majority_urls {
        set_cluster_partition(
            &client,
            base_url,
            service_token,
            std::slice::from_ref(&isolated_url),
        );
    }
    set_cluster_partition(
        &client,
        &isolated_url,
        service_token,
        &[url_a.clone(), url_b.clone()],
    );

    wait_until_with_diagnostics(
        "minority partition loses quorum",
        Duration::from_secs(90),
        || {
            let majority_ok = majority_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(2)
            });
            let Some(isolated_status) =
                try_internal_cluster_status(&client, &isolated_url, service_token)
            else {
                return false;
            };
            majority_ok
                && isolated_status["leaderUrl"].is_null()
                && isolated_status["hasQuorum"].as_bool() == Some(false)
                && isolated_status["reachableNodes"].as_u64() == Some(1)
                && isolated_status["role"].as_str() == Some("candidate")
        },
        || cluster_status_diagnostics(&client, &urls, service_token),
    );

    let (status, body) = post_json_status(
        &client,
        &format!("{isolated_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-quorum-heal",
            "grantIndex": 0,
            "maxInvocations": 5
        }),
    );
    assert_eq!(status, 503);
    assert!(
        body.contains("quorum") || body.contains("leader"),
        "expected quorum failure body, got: {body}"
    );

    let majority_write = post_json(
        &client,
        &format!("{url_b}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-quorum-heal",
            "grantIndex": 0,
            "maxInvocations": 5
        }),
    );
    assert_eq!(majority_write["allowed"].as_bool(), Some(true));
    assert_budget_authority_metadata(&majority_write, &expected_leader_url, "ha_linearizable");
    assert_budget_commit_metadata(
        &majority_write,
        &expected_leader_url,
        2,
        2,
        &[url_a.as_str(), url_b.as_str()],
    );

    let isolated_budget_before_heal = get_json(
        &client,
        &format!("{isolated_url}/v1/budgets?capabilityId=cap-quorum-heal&limit=10"),
        service_token,
    );
    assert_eq!(isolated_budget_before_heal["count"].as_u64(), Some(0));
    assert_eq!(
        isolated_budget_before_heal["usages"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );

    for base_url in &urls {
        let response = set_cluster_partition(&client, base_url, service_token, &[]);
        assert_eq!(
            response["blockedPeerUrls"].as_array().map(Vec::len),
            Some(0)
        );
    }

    wait_until_with_diagnostics(
        "three-node quorum heal convergence",
        Duration::from_secs(90),
        || {
            urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(3)
            })
        },
        || cluster_status_diagnostics(&client, &urls, service_token),
    );

    wait_until_with_diagnostics(
        "healed minority catches up from snapshot",
        Duration::from_secs(90),
        || {
            let Some(budgets) = try_get_json(
                &client,
                &format!("{isolated_url}/v1/budgets?capabilityId=cap-quorum-heal&limit=10"),
                service_token,
            ) else {
                return false;
            };
            let Some(status) = try_internal_cluster_status(&client, &isolated_url, service_token)
            else {
                return false;
            };
            let exact_budget_visible = budgets["count"].as_u64() == Some(1)
                && budgets["usages"].as_array().is_some_and(|usages| {
                    usages.len() == 1
                        && usages[0]["grantIndex"].as_u64() == Some(0)
                        && usages[0]["invocationCount"].as_u64() == Some(1)
                });
            let snapshot_advanced = status["peers"].as_array().is_some_and(|peers| {
                peers.iter().any(|peer| {
                    peer["peerUrl"].as_str().is_some_and(|peer_url| {
                        isolated_snapshot_baseline
                            .get(peer_url)
                            .is_some_and(|baseline| {
                                peer["snapshotAppliedCount"]
                                    .as_u64()
                                    .is_some_and(|current| current > *baseline)
                            })
                    })
                })
            });
            exact_budget_visible && snapshot_advanced
        },
        || cluster_status_diagnostics(&client, &urls, service_token),
    );
}

#[test]
fn trust_control_cluster_rejects_stale_admission_term_after_failover_and_restart() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_rejects_stale_admission_term_after_failover_and_restart",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("authority-fence-failover");
    create_private_test_dir(&dir);

    let nodes = reserve_cluster_nodes(3);
    let (addr_a, url_a) = nodes[0].clone();
    let (addr_b, url_b) = nodes[1].clone();
    let (addr_c, url_c) = nodes[2].clone();
    let urls = vec![url_a.clone(), url_b.clone(), url_c.clone()];
    let service_token = "cluster-admission-fence-token";

    let receipts_a = dir.join("receipts-a.sqlite3");
    let revocations_a = dir.join("revocations-a.sqlite3");
    let authority_a = dir.join("authority-a.sqlite3");
    let budgets_a = dir.join("budgets-a.sqlite3");
    let receipts_b = dir.join("receipts-b.sqlite3");
    let revocations_b = dir.join("revocations-b.sqlite3");
    let authority_b = dir.join("authority-b.sqlite3");
    let budgets_b = dir.join("budgets-b.sqlite3");
    let receipts_c = dir.join("receipts-c.sqlite3");
    let revocations_c = dir.join("revocations-c.sqlite3");
    let authority_c = dir.join("authority-c.sqlite3");
    let budgets_c = dir.join("budgets-c.sqlite3");

    let mut server_a = Some(spawn_trust_service(
        addr_a,
        service_token,
        &receipts_a,
        &revocations_a,
        &authority_a,
        &budgets_a,
        None,
        &url_a,
        &[url_b.clone(), url_c.clone()],
    ));
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &receipts_b,
        &revocations_b,
        &authority_b,
        &budgets_b,
        None,
        &url_b,
        &[url_a.clone(), url_c.clone()],
    );
    let _server_c = spawn_trust_service(
        addr_c,
        service_token,
        &receipts_c,
        &revocations_c,
        &authority_c,
        &budgets_c,
        None,
        &url_c,
        &[url_a.clone(), url_b.clone()],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    for base_url in &urls {
        wait_for_node_health(
            &client,
            base_url,
            service_token,
            "admission fence node health reachable",
        );
    }

    let initial_leader = wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &urls,
        "initial admission leader convergence",
    );
    assert_eq!(initial_leader, url_a);
    let initial_status =
        wait_for_internal_cluster_status(&client, &url_b, service_token, "initial cluster status");
    let initial_term = initial_status["authorityLease"]["term"]
        .as_u64()
        .expect("initial admission lease term");

    drop(server_a.take());

    let majority_urls = vec![url_b.clone(), url_c.clone()];
    wait_until_with_diagnostics(
        "majority admission failover convergence",
        Duration::from_secs(90),
        || {
            let leader_status = try_internal_cluster_status(&client, &url_b, service_token);
            let leader_term_advanced = leader_status
                .as_ref()
                .and_then(|status| status["authorityLease"]["term"].as_u64())
                .is_some_and(|term| term > initial_term);
            majority_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(url_b.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(2)
            }) && leader_term_advanced
        },
        || cluster_status_diagnostics(&client, &majority_urls, service_token),
    );

    let failover_status = wait_for_internal_cluster_status(
        &client,
        &url_b,
        service_token,
        "failover status after leader loss",
    );
    let failover_term = failover_status["authorityLease"]["term"]
        .as_u64()
        .expect("failover admission term");
    assert!(failover_term > initial_term);

    let _restarted_a = spawn_trust_service(
        addr_a,
        service_token,
        &receipts_a,
        &revocations_a,
        &authority_a,
        &budgets_a,
        None,
        &url_a,
        &[url_b.clone(), url_c.clone()],
    );
    wait_for_node_health(
        &client,
        &url_a,
        service_token,
        "restarted stale node health reachable",
    );
    let restarted_leader = wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &urls,
        "restarted cluster reconverges after old leader returns",
    );
    let restarted_status = wait_for_internal_cluster_status(
        &client,
        &restarted_leader,
        service_token,
        "restarted cluster status",
    );
    let restarted_term = restarted_status["authorityLease"]["term"]
        .as_u64()
        .expect("restarted admission term");
    assert!(restarted_term >= failover_term);

    let primed_revocation = post_json(
        &client,
        &format!("{restarted_leader}/v1/revocations"),
        service_token,
        &json!({"capabilityId": "cap-admission-term-prime"}),
    );
    assert_eq!(primed_revocation["revoked"].as_bool(), Some(true));
    let snapshot_before = try_internal_get_json(
        &client,
        &restarted_leader,
        "/v1/internal/admission-consensus/snapshot",
    )
    .expect("load admission snapshot before stale append");
    let current_consensus_term = snapshot_before["meta"]["currentTerm"]
        .as_u64()
        .expect("current admission consensus term");
    assert!(current_consensus_term > 0);
    let stale_consensus_term = current_consensus_term - 1;
    let stale_peer_url = urls
        .iter()
        .find(|candidate| *candidate != &restarted_leader)
        .cloned()
        .expect("stale peer url");
    let stale_append = json!({
        "protocolVersion": "chio.admission-consensus.v3",
        "membershipDigest": snapshot_before["meta"]["membershipDigest"].clone(),
        "term": stale_consensus_term,
        "leaderId": stale_peer_url,
        "previousLogIndex": snapshot_before["meta"]["lastLogIndex"].clone(),
        "previousLogTerm": snapshot_before["meta"]["lastLogTerm"].clone(),
        "leaderCommit": snapshot_before["meta"]["commitIndex"].clone()
    });

    let (stale_status, stale_body) = post_internal_json_status(
        &client,
        &restarted_leader,
        service_token,
        "/v1/internal/admission-consensus/append-entries",
        &stale_peer_url,
        Some(stale_consensus_term),
        &stale_append,
    );
    assert_eq!(stale_status, 200, "stale append response: {stale_body}");
    let stale_response: Value =
        serde_json::from_str(&stale_body).expect("decode stale append response");
    assert_eq!(stale_response["accepted"].as_bool(), Some(false));
    assert_eq!(
        stale_response["rejection"].as_str(),
        Some("stale admission leader term")
    );
    let snapshot_after = try_internal_get_json(
        &client,
        &restarted_leader,
        "/v1/internal/admission-consensus/snapshot",
    )
    .expect("load admission snapshot after stale append");
    assert_eq!(snapshot_after["entries"], snapshot_before["entries"]);
    assert_eq!(snapshot_after["commitProofs"], snapshot_before["commitProofs"]);
    assert_eq!(snapshot_after["results"], snapshot_before["results"]);
    assert_eq!(
        snapshot_after["meta"]["commitIndex"],
        snapshot_before["meta"]["commitIndex"]
    );

    let forwarding_leader = wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &urls,
        "cluster leader remains stable before follower forwarding",
    );
    let forwarding_peer_url = urls
        .iter()
        .find(|candidate| *candidate != &forwarding_leader)
        .cloned()
        .expect("forwarding peer url");

    let forwarded = post_json(
        &client,
        &format!("{forwarding_peer_url}/v1/revocations"),
        service_token,
        &json!({"capabilityId": "cap-current-admission-term"}),
    );
    assert_eq!(forwarded["revoked"].as_bool(), Some(true));
    assert_leader_visible_metadata(&forwarded);
    let handled_by = forwarded["handledBy"].as_str().expect("revocation handler");
    let visible_leader = forwarded["leaderUrl"]
        .as_str()
        .expect("revocation leader");
    assert!(urls.iter().any(|url| url == handled_by));
    assert!(urls.iter().any(|url| url == visible_leader));
    assert_revocation_visible(
        &client,
        visible_leader,
        service_token,
        "cap-current-admission-term",
    );
}

#[cfg(unix)]
#[test]
fn trust_control_cluster_failed_quorum_does_not_leave_orphaned_exposure() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_failed_quorum_does_not_leave_orphaned_exposure",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("budget-quorum-commit-timeout");
    create_private_test_dir(&dir);

    let addr_a = reserve_listen_addr();
    let addr_b = reserve_listen_addr();
    let url_a = format!("http://{addr_a}");
    let url_b = format!("http://{addr_b}");
    let expected_leader_url = std::cmp::min(url_a.clone(), url_b.clone());
    let service_token = "budget-quorum-commit-timeout-token";

    let server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        std::slice::from_ref(&url_b),
    );
    let server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        std::slice::from_ref(&url_a),
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    wait_until(
        "budget quorum timeout cluster health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_a}/health"), service_token).is_some(),
    );
    wait_until(
        "budget quorum timeout peer health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_b}/health"), service_token).is_some(),
    );
    wait_for_leader_convergence(&client, service_token, &url_a, &url_b, &expected_leader_url);

    let stopped_peer = if expected_leader_url == url_a {
        &server_b.child
    } else {
        &server_a.child
    };
    send_signal(stopped_peer, "STOP");
    wait_until(
        "budget quorum loss becomes visible",
        Duration::from_secs(30),
        || {
            try_internal_cluster_status(&client, &expected_leader_url, service_token)
                .is_some_and(|status| status["hasQuorum"].as_bool() == Some(false))
        },
    );

    let (status, body) = post_json_status(
        &client,
        &format!("{expected_leader_url}/v1/budgets/authorize-hold"),
        service_token,
        &composite_authorize_payload(
            "cap-stalled-commit",
            0,
            60,
            100,
            400,
            5,
            "cap-stalled-commit-hold-1",
            "cap-stalled-commit-hold-1:authorize",
        ),
    );
    assert_eq!(status, 503);
    assert!(
        body.contains("leader-visible") || body.contains("quorum"),
        "expected explicit quorum-commit failure body, got: {body}"
    );
    wait_until(
        "failed quorum authorize rollback removes orphaned exposure",
        Duration::from_secs(10),
        || {
            let Some(budgets) = try_get_json(
                &client,
                &format!(
                    "{expected_leader_url}/v1/budgets?capabilityId=cap-stalled-commit&limit=10"
                ),
                service_token,
            ) else {
                return false;
            };
            budgets["usages"]
                .as_array()
                .is_some_and(|usages| match usages.iter().find(|usage| {
                    usage["grantIndex"].as_u64() == Some(0)
                }) {
                    None => true,
                    Some(usage) => {
                        usage["invocationCount"].as_u64() == Some(0)
                            && usage["totalExposureCharged"].as_u64() == Some(0)
                            && usage["totalRealizedSpend"].as_u64() == Some(0)
                    }
                })
        },
    );
}

#[test]
fn trust_control_cluster_replicates_denied_budget_events_without_usage_rows() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_replicates_denied_budget_events_without_usage_rows",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("denied-budget-events");
    create_private_test_dir(&dir);

    let addr_a = reserve_listen_addr();
    let addr_b = reserve_listen_addr();
    let url_a = format!("http://{addr_a}");
    let url_b = format!("http://{addr_b}");
    let expected_leader_url = std::cmp::min(url_a.clone(), url_b.clone());
    let follower_url = if expected_leader_url == url_a {
        url_b.clone()
    } else {
        url_a.clone()
    };
    let budget_db_a = dir.join("budgets-a.sqlite3");
    let budget_db_b = dir.join("budgets-b.sqlite3");
    let service_token = "denied-budget-events-token";

    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &budget_db_a,
        None,
        &url_a,
        std::slice::from_ref(&url_b),
    );
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &budget_db_b,
        None,
        &url_b,
        std::slice::from_ref(&url_a),
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    wait_until(
        "denied budget cluster health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_a}/health"), service_token).is_some(),
    );
    wait_until(
        "denied budget peer health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_b}/health"), service_token).is_some(),
    );
    wait_for_leader_convergence(&client, service_token, &url_a, &url_b, &expected_leader_url);

    let denied_budget = post_json_eventually_ok_with_diagnostics(
        &client,
        &format!("{follower_url}/v1/budgets/authorize-hold"),
        service_token,
        &composite_authorize_payload(
            "cap-denied-cluster",
            0,
            25,
            50,
            10,
            1,
            "cap-denied-cluster-hold-1",
            "cap-denied-cluster-hold-1:authorize",
        ),
        "denied budget authorize reaches leader visibility",
        Duration::from_secs(30),
        || {
            cluster_timeout_diagnostics(
                &client,
                &expected_leader_url,
                &follower_url,
                service_token,
                "cap-denied-cluster",
            )
        },
    );
    assert_eq!(denied_budget["allowed"].as_bool(), Some(false));
    assert_eq!(denied_budget["attemptedExposureUnits"].as_u64(), Some(25));
    assert!(denied_budget["authorizedExposureUnits"].is_null());
    assert_eq!(denied_budget["invocationCountAfter"].as_u64(), Some(0));
    assert_eq!(denied_budget["committedCostUnitsAfter"].as_u64(), Some(0));
    assert_eq!(denied_budget["invocationState"].as_str(), Some("denied"));
    assert_eq!(denied_budget["monetaryState"].as_str(), Some("none"));
    assert_budget_authority_metadata(&denied_budget, &expected_leader_url, "ha_linearizable");
    assert_budget_commit_metadata(
        &denied_budget,
        &expected_leader_url,
        2,
        2,
        &[expected_leader_url.as_str(), follower_url.as_str()],
    );

    let follower_budget_db = if follower_url == url_a {
        budget_db_a.clone()
    } else {
        budget_db_b.clone()
    };
    let leader_budget_db = if expected_leader_url == url_a {
        budget_db_a.clone()
    } else {
        budget_db_b.clone()
    };

    wait_until_with_diagnostics(
        "denied budget event replicates to follower",
        Duration::from_secs(30),
        || {
            let Ok(store) = SqliteBudgetStore::open(&follower_budget_db) else {
                return false;
            };
            let Ok(events) = store.list_mutation_events(10, Some("cap-denied-cluster"), Some(0))
            else {
                return false;
            };
            let Some(event) = events.first() else {
                return false;
            };
            event.event_id == "cap-denied-cluster-hold-1:authorize"
                && event.allowed == Some(false)
                && event.usage_seq.is_none()
        },
        || {
            cluster_timeout_diagnostics(
                &client,
                &expected_leader_url,
                &follower_url,
                service_token,
                "cap-denied-cluster",
            )
        },
    );

    for budget_db in [&leader_budget_db, &follower_budget_db] {
        let store = SqliteBudgetStore::open(budget_db).expect("open budget db");
        let events = store
            .list_mutation_events(10, Some("cap-denied-cluster"), Some(0))
            .expect("list denied mutation events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "cap-denied-cluster-hold-1:authorize");
        assert_eq!(events[0].allowed, Some(false));
        assert_eq!(events[0].usage_seq, None);
        assert!(events[0].event_seq >= 1);
        assert!(store
            .list_usages_after(10, Some(0))
            .expect("list denied budget usages")
            .is_empty());
    }
}

#[test]
fn trust_control_cluster_late_joiner_catches_up_from_snapshot_and_compacts() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_late_joiner_catches_up_from_snapshot_and_compacts",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("late-joiner");
    create_private_test_dir(&dir);

    let nodes = reserve_cluster_nodes(3);
    let (addr_a, url_a) = nodes[0].clone();
    let (addr_b, url_b) = nodes[1].clone();
    let (addr_c, url_c) = nodes[2].clone();
    let warm_urls = vec![url_a.clone(), url_b.clone()];
    let all_urls = vec![url_a.clone(), url_b.clone(), url_c.clone()];
    let service_token = "cluster-snapshot-token";
    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        &[url_b.clone(), url_c.clone()],
    );
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        &[url_a.clone(), url_c.clone()],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    for base_url in &warm_urls {
        wait_for_node_health(
            &client,
            base_url,
            service_token,
            "warm node health reachable",
        );
    }

    let expected_leader_url = wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &warm_urls,
        "two-node leader convergence with third node absent",
    );
    wait_until_with_diagnostics(
        "two-node quorum convergence with third node absent",
        Duration::from_secs(90),
        || {
            warm_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(2)
            })
        },
        || cluster_status_diagnostics(&client, &warm_urls, service_token),
    );

    for index in 0..10 {
        let receipt = serde_json::to_value(sample_receipt(
            &format!("snapshot-prejoin-{index}"),
            &format!("cap-prejoin-{index}"),
        ))
        .expect("serialize prejoin receipt");
        let stored = post_json(
            &client,
            &format!("{url_b}/v1/receipts/tools"),
            service_token,
            &receipt,
        );
        assert_eq!(stored["stored"].as_bool(), Some(true));
        assert_leader_visible_metadata(&stored);
    }

    wait_until_with_diagnostics(
        "warm nodes replicate prejoin receipts",
        Duration::from_secs(90),
        || {
            try_tool_receipt_count(&client, &url_a, service_token) == Some(10)
                && try_tool_receipt_count(&client, &url_b, service_token) == Some(10)
        },
        || cluster_status_diagnostics(&client, &warm_urls, service_token),
    );

    let _server_c = spawn_trust_service(
        addr_c,
        service_token,
        &dir.join("receipts-c.sqlite3"),
        &dir.join("revocations-c.sqlite3"),
        &dir.join("authority-c.sqlite3"),
        &dir.join("budgets-c.sqlite3"),
        None,
        &url_c,
        &[url_a.clone(), url_b.clone()],
    );

    wait_for_node_health(
        &client,
        &url_c,
        service_token,
        "late joiner health reachable",
    );

    wait_until_with_diagnostics(
        "late joiner snapshot catch-up",
        Duration::from_secs(90),
        || {
            let Some(status) = try_internal_cluster_status(&client, &url_c, service_token) else {
                return false;
            };
            try_tool_receipt_count(&client, &url_c, service_token) == Some(10)
                && status["hasQuorum"].as_bool() == Some(true)
                && status["peers"]
                    .as_array()
                    .expect("peer status array")
                    .iter()
                    .any(|peer| {
                        peer["snapshotAppliedCount"].as_u64().unwrap_or(0) >= 1
                            && peer["lastSnapshotAt"].as_u64().is_some()
                    })
        },
        || cluster_status_diagnostics(&client, &all_urls, service_token),
    );
    wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &all_urls,
        "three-node leader convergence after late joiner catch-up",
    );

    for index in 10..20 {
        let receipt = serde_json::to_value(sample_receipt(
            &format!("snapshot-postjoin-{index}"),
            &format!("cap-postjoin-{index}"),
        ))
        .expect("serialize postjoin receipt");
        let stored = post_json(
            &client,
            &format!("{url_b}/v1/receipts/tools"),
            service_token,
            &receipt,
        );
        assert_eq!(stored["stored"].as_bool(), Some(true));
        assert_leader_visible_metadata(&stored);
    }

    wait_until_with_diagnostics(
        "late joiner snapshot compaction after sustained deltas",
        Duration::from_secs(90),
        || {
            let Some(status) = try_internal_cluster_status(&client, &url_c, service_token) else {
                return false;
            };
            try_tool_receipt_count(&client, &url_c, service_token) == Some(20)
                && status["peers"]
                    .as_array()
                    .expect("peer status array")
                    .iter()
                    .any(|peer| {
                        peer["snapshotAppliedCount"].as_u64().unwrap_or(0) >= 2
                            && peer["forceSnapshot"].as_bool() == Some(false)
                    })
        },
        || cluster_status_diagnostics(&client, &all_urls, service_token),
    );
}
