#[test]
fn remote_composite_reverse_preserves_exact_cleanup_evidence() {
    let transition_response = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "invocationCount": 0,
        "totalExposureCharged": 0,
        "totalRealizedSpend": 0,
        "budgetAuthority": budget_authority_json(42),
        "budgetCommit": budget_commit_json(42)
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &transition_response, "application/json", 1);
    let decision = validate_composite_authorize_response(
        &composite_authorize_request_view(),
        composite_authorize_response_view(),
    )
    .test_expect("validated composite authorization");
    let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
        panic!("expected authorized composite decision");
    };
    let authority = authorized.metadata.authority.clone().test_unwrap();
    let admission_operation =
        BudgetAdmissionOperationBinding::new("operation-budget".to_string(), "44".repeat(32))
            .test_unwrap();
    let evidence = RemoteCompositeHoldEvidence {
        admission_operation: admission_operation.clone(),
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        invocation_quotas: authorized
            .invocation_counts_after
            .iter()
            .map(|usage| usage.quota.clone())
            .collect(),
        invocation_counts_after: authorized.invocation_counts_after,
        revocation_set: authorized.revocation_set.test_unwrap(),
        authorized_exposure_units: authorized.authorized_exposure_units,
        monetary_state: authorized.monetary_state,
        authority: authority.clone(),
    };
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret").test_expect("build client"),
        cached_usage: Mutex::new(HashMap::new()),
        composite_holds: Mutex::new(HashMap::from([("hold-budget".to_string(), evidence)])),
    };

    let reversed = store
        .reverse_budget_hold(BudgetReverseHoldRequest {
            admission_operation: Some(admission_operation),
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            reversed_exposure_units: 120,
            hold_id: Some("hold-budget".to_string()),
            event_id: Some("hold-budget:reverse".to_string()),
            authority: Some(authority),
        })
        .test_expect("reverse composite hold");

    assert_eq!(
        reversed.invocation_state,
        BudgetInvocationReservationState::Reversed
    );
    assert_eq!(reversed.monetary_state, BudgetMonetaryHoldState::Reversed);
    assert!(reversed.revocation_set.is_some());
    assert!(reversed
        .invocation_counts_after
        .iter()
        .all(|usage| usage.reserved_invocations_after == 0));
    assert_eq!(reversed.metadata.budget_commit_index, Some(42));
}

#[test]
fn remote_budget_release_retry_returns_frozen_decision_after_later_write() {
    let transition_response = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "invocationCount": 1,
        "releasedExposureUnits": 25,
        "totalExposureCharged": 75,
        "totalRealizedSpend": 0,
        "budgetAuthority": budget_authority_json(42),
        "budgetCommit": budget_commit_json(42)
    })
    .to_string();
    let server =
        scripted_transition_server(transition_response, later_authorize_response(43, 2, 85, 0));
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");
    let request = BudgetReleaseHoldRequest {
        admission_operation: None,
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        released_exposure_units: 25,
        hold_id: Some("hold-budget".to_string()),
        event_id: Some("hold-budget:release".to_string()),
        authority: None,
    };

    let first = store
        .release_budget_hold(request.clone())
        .test_expect("initial remote release");
    assert!(store
        .try_charge_cost_with_ids(
            "cap-budget",
            2,
            Some(10),
            10,
            Some(100),
            Some(1_000),
            Some("hold-budget-later"),
            Some("hold-budget-later:authorize"),
        )
        .test_expect("later same-grant authorization"));
    let later = store
        .get_usage("cap-budget", 2)
        .test_expect("later cached release usage")
        .test_expect("later cached release usage");
    let retry = store
        .release_budget_hold(request)
        .test_expect("retry remote release");

    assert_eq!(retry, first);
    assert_eq!(
        store
            .get_usage("cap-budget", 2)
            .test_expect("cached usage after release retry")
            .test_expect("cached usage after release retry"),
        later
    );
}

#[test]
fn remote_budget_reconcile_retry_returns_frozen_decision_after_later_write() {
    let transition_response = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "invocationCount": 1,
        "releasedExposureUnits": 30,
        "totalExposureCharged": 0,
        "totalRealizedSpend": 70,
        "budgetAuthority": budget_authority_json(42),
        "budgetCommit": budget_commit_json(42)
    })
    .to_string();
    let server =
        scripted_transition_server(transition_response, later_authorize_response(43, 2, 10, 70));
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");
    let request = BudgetReconcileHoldRequest {
        admission_operation: None,
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        exposed_cost_units: 100,
        realized_spend_units: 70,
        hold_id: Some("hold-budget".to_string()),
        event_id: Some("hold-budget:reconcile".to_string()),
        authority: None,
    };

    let first = store
        .reconcile_budget_hold(request.clone())
        .test_expect("initial remote reconcile");
    assert!(store
        .try_charge_cost_with_ids(
            "cap-budget",
            2,
            Some(10),
            10,
            Some(100),
            Some(1_000),
            Some("hold-budget-later"),
            Some("hold-budget-later:authorize"),
        )
        .test_expect("later same-grant authorization"));
    let later = store
        .get_usage("cap-budget", 2)
        .test_expect("later cached reconcile usage")
        .test_expect("later cached reconcile usage");
    let retry = store
        .reconcile_budget_hold(request)
        .test_expect("retry remote reconcile");

    assert_eq!(retry, first);
    assert_eq!(
        store
            .get_usage("cap-budget", 2)
            .test_expect("cached usage after reconcile retry")
            .test_expect("cached usage after reconcile retry"),
        later
    );
}

#[test]
fn remote_budget_capture_rejects_missing_response_authority() {
    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "invocationCount": 1,
        "releasedExposureUnits": 45,
        "totalExposureCharged": 0,
        "totalRealizedSpend": 75
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret").test_expect("build client"),
        cached_usage: Mutex::new(HashMap::new()),
        composite_holds: Mutex::new(HashMap::new()),
    };
    let cached_before = BudgetUsageRecord {
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        invocation_count: 9,
        updated_at: 1234,
        seq: 99,
        total_cost_exposed: 900,
        total_cost_realized_spend: 75,
    };
    store
        .cached_usage
        .lock()
        .test_expect("seed capture cache")
        .insert(("cap-budget".to_string(), 2), cached_before.clone());
    let error = store
        .capture_budget_hold(BudgetCaptureHoldRequest {
            admission_operation: None,
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            exposed_cost_units: 120,
            realized_spend_units: 75,
            hold_id: Some("hold-budget".to_string()),
            event_id: Some("hold-budget:capture".to_string()),
            authority: Some(BudgetEventAuthority {
                authority_id: "budget-primary".to_string(),
                lease_id: "lease-7".to_string(),
                lease_epoch: 7,
            }),
        })
        .test_expect_err("capture without response authority must fail closed");

    assert!(error
        .to_string()
        .contains("omitted the requested budget authority"));
    assert_eq!(
        store
            .cached_usage
            .lock()
            .test_expect("capture cache after rejected evidence")
            .get(&("cap-budget".to_string(), 2))
            .cloned(),
        Some(cached_before)
    );
}

#[test]
fn remote_budget_authorize_rejects_contradictory_authority_and_commit() {
    let mut commit = budget_commit_json(41);
    commit["authorityId"] = serde_json::Value::String("budget-secondary".to_string());
    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "invocationCount": 1,
        "totalExposureCharged": 120,
        "totalRealizedSpend": 0,
        "budgetAuthority": budget_authority_json(41),
        "budgetCommit": commit
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");

    let error = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-budget".to_string(),
            2,
            Some(10),
            120,
            Some(200),
            Some(1_000),
            Some("hold-budget".to_string()),
            Some("hold-budget:authorize".to_string()),
            None,
        ))
        .test_expect_err("contradictory authority evidence must fail closed");

    assert!(error
        .to_string()
        .contains("budget authority does not match budget commit authority"));
}

#[test]
fn remote_budget_authorize_rejects_ha_authority_without_commit() {
    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "invocationCount": 1,
        "totalExposureCharged": 120,
        "totalRealizedSpend": 0,
        "budgetAuthority": budget_authority_json(41)
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret").test_expect("build client"),
        cached_usage: Mutex::new(HashMap::new()),
        composite_holds: Mutex::new(HashMap::new()),
    };

    let error = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-budget".to_string(),
            2,
            Some(10),
            120,
            Some(200),
            Some(1_000),
            Some("hold-budget".to_string()),
            Some("hold-budget:authorize".to_string()),
            None,
        ))
        .test_expect_err("HA authority without commit must fail closed");

    assert!(error
        .to_string()
        .contains("remote HA budget authority omitted its quorum commit"));
    assert!(store
        .cached_usage
        .lock()
        .test_expect("authorize cache after rejected evidence")
        .is_empty());
}

#[test]
fn remote_budget_authorize_rejects_false_quorum_commit() {
    let mut commit = budget_commit_json(41);
    commit["quorumCommitted"] = serde_json::Value::Bool(false);
    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "invocationCount": 1,
        "totalExposureCharged": 120,
        "totalRealizedSpend": 0,
        "budgetAuthority": budget_authority_json(41),
        "budgetCommit": commit
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");

    let error = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-budget".to_string(),
            2,
            Some(10),
            120,
            Some(200),
            Some(1_000),
            Some("hold-budget".to_string()),
            Some("hold-budget:authorize".to_string()),
            None,
        ))
        .test_expect_err("false quorum commit must fail closed");

    assert!(error
        .to_string()
        .contains("budget commit is not quorum committed"));
}

#[test]
fn remote_budget_authorize_rejects_duplicate_commit_witnesses() {
    let mut commit = budget_commit_json(41);
    commit["witnessUrls"] = serde_json::json!(["http://leader-a", "http://leader-a"]);
    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "invocationCount": 1,
        "totalExposureCharged": 120,
        "totalRealizedSpend": 0,
        "budgetAuthority": budget_authority_json(41),
        "budgetCommit": commit
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");

    let error = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-budget".to_string(),
            2,
            Some(10),
            120,
            Some(200),
            Some(1_000),
            Some("hold-budget".to_string()),
            Some("hold-budget:authorize".to_string()),
            None,
        ))
        .test_expect_err("duplicate commit witnesses must fail closed");

    assert!(error
        .to_string()
        .contains("budget commit contains duplicate witness URLs"));
}

#[test]
fn remote_budget_low_level_terminal_rejects_response_authority_mismatch() {
    let mut authority = budget_authority_json(42);
    authority["authorityId"] = serde_json::Value::String("budget-secondary".to_string());
    let mut commit = budget_commit_json(42);
    commit["authorityId"] = serde_json::Value::String("budget-secondary".to_string());
    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "invocationCount": 0,
        "totalExposureCharged": 0,
        "totalRealizedSpend": 0,
        "budgetAuthority": authority,
        "budgetCommit": commit
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");
    let requested = BudgetEventAuthority {
        authority_id: "budget-primary".to_string(),
        lease_id: "lease-7".to_string(),
        lease_epoch: 7,
    };

    let error = store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-budget",
            2,
            120,
            Some("hold-budget"),
            Some("hold-budget:reverse"),
            Some(&requested),
        )
        .test_expect_err("mismatched terminal authority must fail closed");

    assert!(error
        .to_string()
        .contains("does not match the requested budget authority"));
}

#[test]
fn remote_budget_initial_authorize_ignores_local_authority_and_terminals_preserve_it() {
    let server = ScriptedResponseServer::spawn(vec![
        ScriptedResponse {
            status: 200,
            body: serde_json::json!({
                "capabilityId": "cap-budget",
                "grantIndex": 2,
                "allowed": true,
                "invocationCount": 1,
                "totalExposureCharged": 120,
                "totalRealizedSpend": 0
            })
            .to_string(),
            content_type: "application/json",
        },
        ScriptedResponse {
            status: 200,
            body: serde_json::json!({
                "capabilityId": "cap-budget",
                "grantIndex": 2,
                "invocationCount": 0,
                "totalExposureCharged": 0,
                "totalRealizedSpend": 0,
                "budgetAuthority": budget_authority_json(42),
                "budgetCommit": budget_commit_json(42)
            })
            .to_string(),
            content_type: "application/json",
        },
        ScriptedResponse {
            status: 200,
            body: serde_json::json!({
                "capabilityId": "cap-budget",
                "grantIndex": 2,
                "invocationCount": 1,
                "releasedExposureUnits": 25,
                "totalExposureCharged": 75,
                "totalRealizedSpend": 0,
                "budgetAuthority": budget_authority_json(43),
                "budgetCommit": budget_commit_json(43)
            })
            .to_string(),
            content_type: "application/json",
        },
        ScriptedResponse {
            status: 200,
            body: serde_json::json!({
                "capabilityId": "cap-budget",
                "grantIndex": 2,
                "invocationCount": 1,
                "releasedExposureUnits": 30,
                "totalExposureCharged": 0,
                "totalRealizedSpend": 70,
                "budgetAuthority": budget_authority_json(44),
                "budgetCommit": budget_commit_json(44)
            })
            .to_string(),
            content_type: "application/json",
        },
    ]);
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");
    let authority = BudgetEventAuthority {
        authority_id: "budget-primary".to_string(),
        lease_id: "lease-7".to_string(),
        lease_epoch: 7,
    };
    let admission_operation =
        BudgetAdmissionOperationBinding::new("operation-budget".to_string(), "44".repeat(32))
            .test_unwrap();

    let authorized = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-budget".to_string(),
            2,
            Some(10),
            120,
            Some(200),
            Some(1_000),
            Some("hold-budget-authorize".to_string()),
            Some("hold-budget:authorize".to_string()),
            Some(authority.clone()),
        ))
        .test_expect("authorize with bound authority");
    let BudgetAuthorizeHoldDecision::Authorized(authorized) = authorized else {
        panic!("expected authorized decision");
    };
    assert_eq!(authorized.metadata.authority, None);

    let reversed = store
        .reverse_budget_hold(BudgetReverseHoldRequest {
            admission_operation: Some(admission_operation.clone()),
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            reversed_exposure_units: 120,
            hold_id: Some("hold-budget-reverse".to_string()),
            event_id: Some("hold-budget:reverse".to_string()),
            authority: Some(authority.clone()),
        })
        .test_expect("reverse with bound authority");
    assert_eq!(reversed.metadata.authority, Some(authority.clone()));

    let released = store
        .release_budget_hold(BudgetReleaseHoldRequest {
            admission_operation: Some(admission_operation.clone()),
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            released_exposure_units: 25,
            hold_id: Some("hold-budget-release".to_string()),
            event_id: Some("hold-budget:release".to_string()),
            authority: Some(authority.clone()),
        })
        .test_expect("release with bound authority");
    assert_eq!(released.metadata.authority, Some(authority.clone()));

    let reconciled = store
        .reconcile_budget_hold(BudgetReconcileHoldRequest {
            admission_operation: Some(admission_operation),
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            exposed_cost_units: 100,
            realized_spend_units: 70,
            hold_id: Some("hold-budget-reconcile".to_string()),
            event_id: Some("hold-budget:reconcile".to_string()),
            authority: Some(authority.clone()),
        })
        .test_expect("reconcile with bound authority");
    assert_eq!(reconciled.metadata.authority, Some(authority));

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert!(
        !requests[0].body.contains("\"budgetAuthority\""),
        "initial authorization must not transmit kernel-local authority"
    );
    for request in &requests[1..] {
        assert!(request
            .body
            .contains("\"operationId\":\"operation-budget\""));
        assert!(request
            .body
            .contains(&format!("\"requestBindingHash\":\"{}\"", "44".repeat(32))));
        assert!(request.body.contains("\"budgetAuthority\""));
        assert!(request.body.contains("\"authorityId\":\"budget-primary\""));
        assert!(request.body.contains("\"leaseId\":\"lease-7\""));
        assert!(request.body.contains("\"leaseEpoch\":7"));
    }
}

#[test]
fn unsequenced_capture_retry_invalidates_later_cached_usage() {
    let capture_response = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "invocationCount": 1,
        "releasedExposureUnits": 45,
        "totalExposureCharged": 0,
        "totalRealizedSpend": 75
    })
    .to_string();
    let later_authorize_response = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "invocationCount": 2,
        "totalExposureCharged": 10,
        "totalRealizedSpend": 75
    })
    .to_string();
    let server = ScriptedResponseServer::spawn(vec![
        ScriptedResponse {
            status: 200,
            body: capture_response.clone(),
            content_type: "application/json",
        },
        ScriptedResponse {
            status: 200,
            body: later_authorize_response,
            content_type: "application/json",
        },
        ScriptedResponse {
            status: 200,
            body: capture_response,
            content_type: "application/json",
        },
    ]);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret").test_expect("build client"),
        cached_usage: Mutex::new(HashMap::new()),
        composite_holds: Mutex::new(HashMap::new()),
    };
    let request = BudgetCaptureHoldRequest {
        admission_operation: None,
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        exposed_cost_units: 120,
        realized_spend_units: 75,
        hold_id: Some("hold-budget".to_string()),
        event_id: Some("hold-budget:capture".to_string()),
        authority: None,
    };

    let first = store
        .capture_budget_hold(request.clone())
        .test_expect("initial unsequenced capture");
    assert!(store
        .cached_usage
        .lock()
        .test_expect("capture cache")
        .is_empty());
    assert!(store
        .try_charge_cost_with_ids(
            "cap-budget",
            2,
            Some(10),
            10,
            Some(100),
            Some(1_000),
            Some("hold-budget-later"),
            Some("hold-budget-later:authorize"),
        )
        .test_expect("later cached authorization"));
    assert_eq!(
        store
            .cached_usage
            .lock()
            .test_expect("later usage cache")
            .get(&("cap-budget".to_string(), 2))
            .test_expect("later cached usage")
            .total_cost_exposed,
        10
    );

    let retry = store
        .capture_budget_hold(request)
        .test_expect("unsequenced capture retry");
    assert_eq!(retry, first);
    assert!(store
        .cached_usage
        .lock()
        .test_expect("retry capture cache")
        .is_empty());
}

#[test]
fn trusted_authority_signer_check_accepts_rotated_keys() {
    let current = Keypair::generate().public_key();
    let previous = Keypair::generate().public_key();
    let outsider = Keypair::generate().public_key();
    let trusted = vec![previous.clone(), current];

    ensure_signed_by_trusted_authority("trust activation", &previous, &trusted)
        .test_expect("previous authority key should remain trusted");
    let error = ensure_signed_by_trusted_authority("trust activation", &outsider, &trusted)
        .test_expect_err("outsider signer should fail closed");
    assert!(error
        .to_string()
        .contains("does not match a trusted trust-control authority signer"));
}

#[test]
fn retry_statuses_and_error_adapters_match_expected_behavior() {
    assert!(should_retry_status(500));
    assert!(should_retry_status(502));
    assert!(should_retry_status(503));
    assert!(should_retry_status(504));
    assert!(!should_retry_status(400));
    assert!(!should_retry_status(401));

    let message = "backend unavailable".to_string();
    let receipt_error = into_receipt_store_error(CliError::cli_other_error(message.clone()));
    let revocation_error = into_revocation_store_error(CliError::cli_other_error(message.clone()));
    let budget_error = into_budget_store_error(CliError::cli_other_error(message.clone()));

    assert!(receipt_error.to_string().contains(&message));
    assert!(revocation_error.to_string().contains(&message));
    assert!(budget_error.to_string().contains(&message));
}
