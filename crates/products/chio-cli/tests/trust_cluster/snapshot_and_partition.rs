#[test]
fn trust_control_cluster_snapshot_replays_holds_and_mutation_events() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_snapshot_replays_holds_and_mutation_events",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("snapshot-budget-holds");
    fs::create_dir_all(&dir).expect("create test dir");

    let nodes = reserve_cluster_nodes(3);
    let (addr_late, late_url) = nodes[0].clone();
    let (addr_a, url_a) = nodes[1].clone();
    let (addr_b, url_b) = nodes[2].clone();
    let warm_urls = vec![url_a.clone(), url_b.clone()];
    let all_urls = vec![late_url.clone(), url_a.clone(), url_b.clone()];
    let service_token = "cluster-snapshot-budget-token";
    let warm_leader_url = url_a.clone();
    let late_budget_db = dir.join("budgets-late.sqlite3");

    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        &[late_url.clone(), url_b.clone()],
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
        &[late_url.clone(), url_a.clone()],
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
            "warm budget node health reachable",
        );
    }

    wait_until_with_diagnostics(
        "warm budget cluster converges without late joiner",
        Duration::from_secs(90),
        || {
            warm_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(warm_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(2)
            })
        },
        || cluster_status_diagnostics(&client, &warm_urls, service_token),
    );

    let authorize = post_json_eventually_ok_with_diagnostics(
        &client,
        &format!("{url_b}/v1/budgets/authorize-exposure"),
        service_token,
        &json!({
            "capabilityId": "cap-snapshot-hold",
            "grantIndex": 0,
            "maxInvocations": 5,
            "exposureUnits": 90,
            "maxExposurePerInvocation": 100,
            "maxTotalExposureUnits": 400,
            "holdId": "cap-snapshot-hold-1",
            "eventId": "cap-snapshot-hold-1:authorize"
        }),
        "snapshot hold authorization reaches quorum",
        Duration::from_secs(90),
        || cluster_status_diagnostics(&client, &warm_urls, service_token),
    );
    assert_eq!(authorize["allowed"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&authorize, &warm_leader_url);

    let release = post_json(
        &client,
        &format!("{url_a}/v1/budgets/reconcile-spend"),
        service_token,
        &json!({
            "capabilityId": "cap-snapshot-hold",
            "grantIndex": 0,
            "reductionUnits": 30,
            "holdId": "cap-snapshot-hold-1",
            "eventId": "cap-snapshot-hold-1:release"
        }),
    );
    assert_eq!(release["releasedExposureUnits"].as_u64(), Some(30));
    assert_expected_write_visibility_metadata(&release, &warm_leader_url);
    assert_budget_invocation_count(
        &client,
        &warm_leader_url,
        service_token,
        "cap-snapshot-hold",
        0,
        1,
    );
    assert_budget_totals(
        &client,
        &warm_leader_url,
        service_token,
        "cap-snapshot-hold",
        0,
        60,
        0,
    );

    let _late_server = spawn_trust_service(
        addr_late,
        service_token,
        &dir.join("receipts-late.sqlite3"),
        &dir.join("revocations-late.sqlite3"),
        &dir.join("authority-late.sqlite3"),
        &late_budget_db,
        None,
        &late_url,
        &[url_a.clone(), url_b.clone()],
    );

    wait_for_node_health(
        &client,
        &late_url,
        service_token,
        "late budget node health reachable",
    );

    wait_until_with_diagnostics(
        "late joiner snapshots budget hold history",
        Duration::from_secs(90),
        || {
            let Some(status) = try_internal_cluster_status(&client, &late_url, service_token)
            else {
                return false;
            };
            let Some(budgets) = try_get_json(
                &client,
                &format!("{late_url}/v1/budgets?capabilityId=cap-snapshot-hold&limit=10"),
                service_token,
            ) else {
                return false;
            };
            status["leaderUrl"].as_str().is_some()
                && status["hasQuorum"].as_bool() == Some(true)
                && status["reachableNodes"].as_u64().unwrap_or(0) >= 2
                && budgets["count"].as_u64() == Some(1)
                && budgets["usages"][0]["invocationCount"].as_u64() == Some(1)
                && budgets["usages"][0]["totalExposureCharged"].as_u64() == Some(60)
                && budgets["usages"][0]["totalRealizedSpend"].as_u64() == Some(0)
        },
        || cluster_status_diagnostics(&client, &all_urls, service_token),
    );

    let late_store = SqliteBudgetStore::open(&late_budget_db).expect("open late budget db");
    let pre_reconcile_events = late_store
        .list_mutation_events(10, Some("cap-snapshot-hold"), Some(0))
        .expect("list replayed mutation events");
    let pre_reconcile_event_ids = pre_reconcile_events
        .iter()
        .map(|event| event.event_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        pre_reconcile_event_ids,
        vec![
            "cap-snapshot-hold-1:authorize",
            "cap-snapshot-hold-1:release",
        ]
    );
    drop(late_store);

    let reconcile = post_json(
        &client,
        &format!("{late_url}/v1/budgets/reconcile-spend"),
        service_token,
        &json!({
            "capabilityId": "cap-snapshot-hold",
            "grantIndex": 0,
            "authorizedExposureUnits": 60,
            "realizedSpendUnits": 45,
            "holdId": "cap-snapshot-hold-1",
            "eventId": "cap-snapshot-hold-1:reconcile"
        }),
    );
    assert_eq!(reconcile["releasedExposureUnits"].as_u64(), Some(15));
    assert_leader_visible_metadata(&reconcile);
    assert_budget_totals(
        &client,
        &late_url,
        service_token,
        "cap-snapshot-hold",
        0,
        0,
        45,
    );

    let late_store = SqliteBudgetStore::open(&late_budget_db).expect("reopen late budget db");
    let usage = late_store
        .get_usage("cap-snapshot-hold", 0)
        .expect("get replayed budget usage")
        .expect("late usage row");
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(usage.total_cost_realized_spend, 45);

    let post_reconcile_event_ids = late_store
        .list_mutation_events(10, Some("cap-snapshot-hold"), Some(0))
        .expect("list late mutation events after reconcile")
        .into_iter()
        .map(|event| event.event_id)
        .collect::<Vec<_>>();
    assert_eq!(
        post_reconcile_event_ids,
        vec![
            "cap-snapshot-hold-1:authorize".to_string(),
            "cap-snapshot-hold-1:release".to_string(),
            "cap-snapshot-hold-1:reconcile".to_string(),
        ]
    );
}

#[test]
fn trust_control_cluster_multi_region_partition_qualification() {
    if skip_when_loopback_bind_denied("trust_control_cluster_multi_region_partition_qualification")
    {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("multi-region-qualification");
    fs::create_dir_all(&dir).expect("create test dir");

    let nodes = reserve_cluster_nodes(3);
    let (addr_a, url_a) = nodes[0].clone();
    let (addr_b, url_b) = nodes[1].clone();
    let (addr_c, url_c) = nodes[2].clone();
    let all_urls = vec![url_a.clone(), url_b.clone(), url_c.clone()];
    let majority_urls = vec![url_a.clone(), url_b.clone()];
    let isolated_url = url_c.clone();
    let service_token = "cluster-multi-region-token";

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

    for base_url in &all_urls {
        wait_until(
            "cluster node health reachable",
            Duration::from_secs(20),
            || try_get_json(&client, &format!("{base_url}/health"), service_token).is_some(),
        );
    }

    let expected_leader_url = wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &all_urls,
        "simulated three-region leader convergence",
    );
    wait_until_with_diagnostics(
        "simulated three-region quorum convergence",
        Duration::from_secs(90),
        || {
            all_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(3)
                    && status["quorumSize"].as_u64() == Some(2)
            })
        },
        || cluster_status_diagnostics(&client, &all_urls, service_token),
    );

    let mut healed_partition_samples_ms = Vec::new();
    let split_brain_observed = std::cell::Cell::new(false);
    for index in 0..MULTI_REGION_PARTITION_SAMPLES {
        for base_url in &majority_urls {
            let response = set_cluster_partition(
                &client,
                base_url,
                service_token,
                std::slice::from_ref(&isolated_url),
            );
            assert_eq!(response["selfUrl"].as_str(), Some(base_url.as_str()));
            assert_eq!(
                response["blockedPeerUrls"].as_array().map(Vec::len),
                Some(1)
            );
        }
        let isolated_partition = set_cluster_partition(
            &client,
            &isolated_url,
            service_token,
            &[url_a.clone(), url_b.clone()],
        );
        assert_eq!(isolated_partition["hasQuorum"].as_bool(), Some(false));

        wait_until_with_diagnostics(
            &format!("partition convergence sample {index}"),
            Duration::from_secs(90),
            || {
                let majority_ok = majority_urls.iter().all(|base_url| {
                    let Some(status) =
                        try_internal_cluster_status(&client, base_url, service_token)
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
                if isolated_status["role"].as_str() == Some("leader")
                    || isolated_status["leaderUrl"].as_str() == Some(isolated_url.as_str())
                {
                    split_brain_observed.set(true);
                }
                majority_ok
                    && isolated_status["leaderUrl"].is_null()
                    && isolated_status["hasQuorum"].as_bool() == Some(false)
                    && isolated_status["reachableNodes"].as_u64() == Some(1)
                    && isolated_status["role"].as_str() == Some("candidate")
            },
            || cluster_status_diagnostics(&client, &all_urls, service_token),
        );
        assert!(
            !split_brain_observed.get(),
            "isolated node must never claim self leadership during partition"
        );

        if index == 0 {
            let denied_receipt = serde_json::to_value(sample_receipt(
                "multi-region-denied",
                "cap-multi-region-denied",
            ))
            .expect("denied receipt json");
            let (status, body) = post_json_status(
                &client,
                &format!("{isolated_url}/v1/receipts/tools"),
                service_token,
                &denied_receipt,
            );
            assert_eq!(status, 503);
            assert!(
                body.contains("quorum") || body.contains("leader"),
                "expected quorum failure body, got: {body}"
            );
        }

        let receipt_nonce = format!("multi-region-heal-{index}");
        let capability_id = format!("cap-multi-region-heal-{index}");
        let signed_receipt = sample_receipt(&receipt_nonce, &capability_id);
        // `ChioReceipt::sign` overwrites the supplied id with the canonical content
        // hash (`chio_receipt_id`) and re-purposes the input string as a signing
        // nonce. Match visibility against the stored id, not the nonce.
        let receipt_id = signed_receipt.id.clone();
        let receipt = serde_json::to_value(&signed_receipt).expect("receipt json");
        let stored = post_json(
            &client,
            &format!("{url_b}/v1/receipts/tools"),
            service_token,
            &receipt,
        );
        assert_eq!(stored["stored"].as_bool(), Some(true));
        assert_expected_write_visibility_metadata(&stored, &expected_leader_url);
        assert!(
            !tool_receipt_visible(
                &client,
                &isolated_url,
                service_token,
                &capability_id,
                &receipt_id,
            ),
            "partitioned receipt must be absent from the isolated node before heal"
        );

        let heal_started_at = Instant::now();
        for base_url in &all_urls {
            let response = set_cluster_partition(&client, base_url, service_token, &[]);
            assert_eq!(
                response["blockedPeerUrls"].as_array().map(Vec::len),
                Some(0)
            );
        }

        let lag_ms = measure_until_with_diagnostics(
            &format!("post-heal replication sample {index}"),
            heal_started_at,
            Duration::from_secs(90),
            || {
                let converged = all_urls.iter().all(|base_url| {
                    let Some(status) =
                        try_internal_cluster_status(&client, base_url, service_token)
                    else {
                        return false;
                    };
                    status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                        && status["hasQuorum"].as_bool() == Some(true)
                        && status["reachableNodes"].as_u64() == Some(3)
                        && tool_receipt_visible(
                            &client,
                            base_url,
                            service_token,
                            &capability_id,
                            &receipt_id,
                        )
                });
                converged
            },
            || cluster_status_diagnostics(&client, &all_urls, service_token),
        );
        healed_partition_samples_ms.push(lag_ms);
    }

    let report = json!({
        "phase": 298,
        "scenario": "local-simulated-three-region-partition-qualification",
        "generatedAt": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs(),
        "clusterSyncIntervalMs": 2000,
        "regions": [
            {"name": "region-a", "baseUrl": url_a},
            {"name": "region-b", "baseUrl": url_b},
            {"name": "region-c", "baseUrl": url_c},
        ],
        "consistencyChecks": {
            "leaderUrl": expected_leader_url,
            "minorityWritesFailClosed": true,
            "healedClusterRestoresQuorum": true,
            "splitBrainObserved": split_brain_observed.get(),
        },
        "postHealReplicationMs": {
            "samples": healed_partition_samples_ms,
            "summary": latency_summary(&healed_partition_samples_ms),
        },
        "notes": [
            "This artifact records local simulated-region qualification numbers, not hosted WAN latencies.",
            "Replication lag is measured from partition heal until all nodes converge on the expected replicated receipt visibility."
        ]
    });
    let report_path = write_multi_region_qualification_report(&report);
    assert!(report_path.exists(), "qualification report should exist");
    println!(
        "multi-region qualification report: {}",
        report_path.display()
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize qualification report")
    );
}

#[test]
fn trust_control_cluster_repeat_run_qualification() {
    let _test_lock = trust_cluster_test_lock();
    for run_index in 1..=TRUST_CLUSTER_QUALIFICATION_RUNS {
        run_trust_control_cluster_proving_scenario(run_index, TRUST_CLUSTER_QUALIFICATION_RUNS);
    }
}
