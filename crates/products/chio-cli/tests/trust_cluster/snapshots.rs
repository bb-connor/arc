use super::*;

#[test]
fn trust_control_cluster_late_joiner_catches_up_from_snapshot_and_compacts() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_late_joiner_catches_up_from_snapshot_and_compacts",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let state = chio_test_support::private_tempdir().expect("create private state directory");
    let dir = state.path().to_path_buf();

    let nodes = reserve_cluster_nodes(3);
    let (addr_a, url_a) = nodes[0].clone();
    let (addr_b, url_b) = nodes[1].clone();
    let (addr_c, url_c) = nodes[2].clone();
    let warm_urls = vec![url_a.clone(), url_b.clone()];
    let all_urls = vec![url_a.clone(), url_b.clone(), url_c.clone()];
    let service_token = "cluster-snapshot-token";
    let _recovery = authority_fixture::enroll_authorities(&dir, "a", &["b", "c"]);
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

#[test]
fn trust_control_cluster_snapshot_replays_holds_and_mutation_events() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_snapshot_replays_holds_and_mutation_events",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let state = chio_test_support::private_tempdir().expect("create private state directory");
    let dir = state.path().to_path_buf();

    let nodes = reserve_cluster_nodes(3);
    let (addr_late, late_url) = nodes[0].clone();
    let (addr_a, url_a) = nodes[1].clone();
    let (addr_b, url_b) = nodes[2].clone();
    let warm_urls = vec![url_a.clone(), url_b.clone()];
    let all_urls = vec![late_url.clone(), url_a.clone(), url_b.clone()];
    let service_token = "cluster-snapshot-budget-token";
    let _recovery = authority_fixture::enroll_authorities(&dir, "a", &["b", "late"]);
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

    let capture = post_json(
        &client,
        &format!("{url_b}/v1/budgets/capture-invocation"),
        service_token,
        &json!({
            "capabilityId": "cap-snapshot-hold",
            "grantIndex": 0,
            "holdId": "cap-snapshot-hold-1",
            "eventId": "cap-snapshot-hold-1:capture-invocation"
        }),
    );
    assert!(matches!(
        capture["decision"].as_str(),
        Some("captured" | "already_captured")
    ));
    assert_expected_write_visibility_metadata(&capture, &warm_leader_url);
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
            "cap-snapshot-hold-1:capture-invocation",
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
            "cap-snapshot-hold-1:capture-invocation".to_string(),
            "cap-snapshot-hold-1:reconcile".to_string(),
        ]
    );
}
