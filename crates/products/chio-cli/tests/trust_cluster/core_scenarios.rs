fn run_trust_control_cluster_proving_scenario(run_index: usize, run_total: usize) {
    println!("trust-cluster proving run {run_index}/{run_total}");

    let dir = unique_test_dir().join(format!("run-{run_index}-of-{run_total}"));
    fs::create_dir_all(&dir).expect("create test dir");
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

    // The two processes model one logical custody backend. Public cluster
    // snapshots intentionally cannot replicate or synthesize private seed state.
    initialize_shared_cluster_authority(&authority_db);

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

    assert_authority_generation(&client, &leader_url, service_token, 1);

    let rotated_leader = post_json_eventually_ok_with_diagnostics(
        &client,
        &format!("{leader_url}/v1/authority"),
        service_token,
        &json!({}),
        "leader authority rotation after cluster convergence",
        Duration::from_secs(30),
        || cluster_status_diagnostics(&client, &[url_a.clone(), url_b.clone()], service_token),
    );
    assert_eq!(rotated_leader["generation"].as_u64(), Some(2));
    assert_expected_write_visibility_metadata(&rotated_leader, &leader_url);
    assert_authority_generation(&client, &leader_url, service_token, 2);

    let rotated_follower = post_json_eventually_ok_with_diagnostics(
        &client,
        &format!("{follower_url}/v1/authority"),
        service_token,
        &json!({}),
        "follower authority rotation after leader rotation",
        Duration::from_secs(30),
        || cluster_status_diagnostics(&client, &[url_a.clone(), url_b.clone()], service_token),
    );
    assert_eq!(rotated_follower["generation"].as_u64(), Some(3));
    assert_expected_write_visibility_metadata(&rotated_follower, &leader_url);
    assert_authority_generation(&client, &leader_url, service_token, 3);

    wait_until(
        "authority generation replication",
        Duration::from_secs(90),
        || {
            try_get_json(
                &client,
                &format!("{follower_url}/v1/authority"),
                service_token,
            )
            .and_then(|value| value["generation"].as_u64())
                == Some(3)
        },
    );

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
    let child_capability = sample_capability("cluster-lineage-child", &child_kp, &issuer_kp);

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
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "requestedExposureUnits": 75,
            "maxExposurePerInvocation": 100,
            "maxTotalExposureUnits": 400,
            "holdId": "cap-shared-hold-1",
            "eventId": "cap-shared-hold-1:authorize",
            "admissionEvidence": {
                "invocationQuotas": [{
                    "key": {
                        "profile": "chio.grant-invocation.v1",
                        "ownerId": "cap-shared",
                        "grantIndex": 0
                    },
                    "maxInvocations": 4
                }],
                "revocationSet": canonical_revocation_set_json(&["cap-shared"])
            }
        }),
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
fn trust_cluster_runtime_assurance_policy_gates_capability_issuance() {
    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");

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

    let subject = Keypair::generate();
    let subject_public_key = subject.public_key().to_hex();
    let requested_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs();
    let denied_request_nonce = sha256_hex(
        format!("runtime-assurance-denied:{requested_at}:{subject_public_key}").as_bytes(),
    );
    let allowed_request_nonce = sha256_hex(
        format!("runtime-assurance-allowed:{requested_at}:{subject_public_key}").as_bytes(),
    );
    let runtime_attestation = serde_json::to_value(
        chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test/".to_string(),
            tier: chio_core::capability::runtime_attestation::RuntimeAssuranceTier::Attested,
            issued_at: requested_at.saturating_sub(1),
            expires_at: requested_at.saturating_add(300),
            evidence_sha256: sha256_hex(b"runtime-assurance-attestation"),
            runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
            workload_identity: None,
            claims: Some(json!({
                "azureMaa": {
                    "attestationType": "sgx"
                }
            })),
        },
    )
    .expect("serialize runtime attestation");
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let denied = client
        .post(format!("{base_url}/v1/capabilities/issue"))
        .header(AUTHORIZATION, bearer(service_token))
        .json(&json!({
            "schema": "chio.capability-issuance-request.v2",
            "requestNonce": denied_request_nonce,
            "requestedAt": requested_at,
            "tenantId": "tenant-runtime-assurance",
            "lineageId": "lineage-runtime-assurance",
            "subjectPublicKey": subject_public_key,
            "scope": scope,
            "ttlSeconds": 120
        }))
        .send()
        .expect("send denied issue request");
    let denied_status = denied.status();
    let denied_body = denied.text().expect("read denied issue response");
    assert_eq!(
        denied_status.as_u16(),
        403,
        "runtime assurance denial body: {denied_body}"
    );

    let allowed = client
        .post(format!("{base_url}/v1/capabilities/issue"))
        .header(AUTHORIZATION, bearer(service_token))
        .json(&json!({
            "schema": "chio.capability-issuance-request.v2",
            "requestNonce": allowed_request_nonce,
            "requestedAt": requested_at,
            "tenantId": "tenant-runtime-assurance",
            "lineageId": "lineage-runtime-assurance",
            "subjectPublicKey": subject_public_key,
            "scope": scope,
            "ttlSeconds": 120,
            "runtimeAttestation": runtime_attestation
        }))
        .send()
        .expect("send allowed issue request");
    let allowed_status = allowed.status();
    let allowed_body = allowed.text().expect("read allowed issue response");
    assert_eq!(
        allowed_status.as_u16(),
        200,
        "runtime assurance success body: {allowed_body}"
    );
    let allowed_json: serde_json::Value =
        serde_json::from_str(&allowed_body).expect("parse allowed issue response");
    let capability: CapabilityToken =
        serde_json::from_value(allowed_json["body"]["capability"].clone())
            .expect("decode signed response capability");
    assert!(
        capability.scope.grants[0]
            .constraints
            .contains(&Constraint::MinimumRuntimeAssurance(
                chio_core::capability::runtime_attestation::RuntimeAssuranceTier::Attested
            )),
        "issued capability should retain the required runtime assurance tier"
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
    fs::create_dir_all(&dir).expect("create test dir");

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
    fs::create_dir_all(&dir).expect("create test dir");

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
    assert_expected_write_visibility_metadata(&majority_write, &expected_leader_url);

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
fn trust_control_cluster_rejects_stale_authority_term_after_failover_and_restart() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_rejects_stale_authority_term_after_failover_and_restart",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("authority-fence-failover");
    fs::create_dir_all(&dir).expect("create test dir");

    let nodes = reserve_cluster_nodes(3);
    let (addr_a, url_a) = nodes[0].clone();
    let (addr_b, url_b) = nodes[1].clone();
    let (addr_c, url_c) = nodes[2].clone();
    let urls = vec![url_a.clone(), url_b.clone(), url_c.clone()];
    let service_token = "cluster-authority-fence-token";

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
            "authority fence node health reachable",
        );
    }

    let initial_leader = wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &urls,
        "initial authority leader convergence",
    );
    assert_eq!(initial_leader, url_a);
    let initial_status =
        wait_for_internal_cluster_status(&client, &url_b, service_token, "initial cluster status");
    let initial_term = initial_status["authorityLease"]["term"]
        .as_u64()
        .expect("initial authority lease term");

    drop(server_a.take());

    let majority_urls = vec![url_b.clone(), url_c.clone()];
    wait_until_with_diagnostics(
        "majority authority failover convergence",
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
        .expect("failover authority term");
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
        .expect("restarted authority term");
    assert!(restarted_term >= failover_term);

    let generation_before = get_json(
        &client,
        &format!("{restarted_leader}/v1/authority"),
        service_token,
    )["generation"]
        .as_u64()
        .expect("generation before stale mutation");
    let stale_peer_url = urls
        .iter()
        .find(|candidate| *candidate != &restarted_leader)
        .cloned()
        .expect("stale peer url");

    let (stale_status, stale_body) = post_internal_json_status(
        &client,
        &restarted_leader,
        service_token,
        "/v1/authority",
        &stale_peer_url,
        Some(initial_term),
        &json!({}),
    );
    assert_eq!(stale_status, 409);
    assert!(
        stale_body.contains("term does not match the current lease")
            || stale_body.contains("stale"),
        "expected stale leader rejection body, got: {stale_body}"
    );

    let generation_after_reject = get_json(
        &client,
        &format!("{restarted_leader}/v1/authority"),
        service_token,
    )["generation"]
        .as_u64()
        .expect("generation after stale mutation rejection");
    assert_eq!(generation_after_reject, generation_before);

    let forwarding_leader = wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &urls,
        "cluster leader remains stable before follower forwarding",
    );
    let forwarding_generation_before = get_json(
        &client,
        &format!("{forwarding_leader}/v1/authority"),
        service_token,
    )["generation"]
        .as_u64()
        .expect("generation before follower forwarding");
    let forwarding_peer_url = urls
        .iter()
        .find(|candidate| *candidate != &forwarding_leader)
        .cloned()
        .expect("forwarding peer url");

    let forwarded = post_json(
        &client,
        &format!("{forwarding_peer_url}/v1/authority"),
        service_token,
        &json!({}),
    );
    assert_eq!(
        forwarded["handledBy"].as_str(),
        Some(forwarding_leader.as_str())
    );
    assert_eq!(
        forwarded["leaderUrl"].as_str(),
        Some(forwarding_leader.as_str())
    );
    assert_eq!(
        forwarded["generation"].as_u64(),
        Some(forwarding_generation_before.saturating_add(1))
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
    fs::create_dir_all(&dir).expect("create test dir");

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

    let (status, body) = post_json_status(
        &client,
        &format!("{expected_leader_url}/v1/budgets/authorize-exposure"),
        service_token,
        &json!({
            "capabilityId": "cap-stalled-commit",
            "grantIndex": 0,
            "maxInvocations": 5,
            "exposureUnits": 60,
            "maxExposurePerInvocation": 100,
            "maxTotalExposureUnits": 400,
            "holdId": "cap-stalled-commit-hold-1",
            "eventId": "cap-stalled-commit-hold-1:authorize"
        }),
    );
    assert_eq!(status, 503);
    assert!(
        body.contains("leader-visible") || body.contains("quorum commit"),
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
            let Some(usage) = budgets["usages"].as_array().and_then(|usages| {
                usages
                    .iter()
                    .find(|usage| usage["grantIndex"].as_u64() == Some(0))
            }) else {
                return false;
            };
            usage["invocationCount"].as_u64() == Some(0)
                && usage["totalExposureCharged"].as_u64() == Some(0)
                && usage["totalRealizedSpend"].as_u64() == Some(0)
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
    fs::create_dir_all(&dir).expect("create test dir");

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
        &format!("{follower_url}/v1/budgets/authorize-exposure"),
        service_token,
        &json!({
            "capabilityId": "cap-denied-cluster",
            "grantIndex": 0,
            "maxInvocations": 1,
            "exposureUnits": 25,
            "maxExposurePerInvocation": 50,
            "maxTotalExposureUnits": 10,
            "holdId": "cap-denied-cluster-hold-1",
            "eventId": "cap-denied-cluster-hold-1:authorize"
        }),
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
    assert_expected_write_visibility_metadata(&denied_budget, &expected_leader_url);
    assert!(denied_budget["invocationCount"].is_null());
    assert!(denied_budget["totalExposureCharged"].is_null());
    assert!(denied_budget["totalRealizedSpend"].is_null());

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
    fs::create_dir_all(&dir).expect("create test dir");

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
