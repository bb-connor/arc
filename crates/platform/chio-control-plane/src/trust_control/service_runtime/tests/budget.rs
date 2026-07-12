use super::super::super::*;
use super::super::budget::build_remote_budget_store;
use super::super::client::{build_client, should_retry_status};
use super::super::errors::{
    into_budget_store_error, into_receipt_store_error, into_revocation_store_error,
};
use super::super::issuance::ensure_signed_by_trusted_authority;
use super::support::{
    assert_json_post, ScriptedResponse, ScriptedResponseServer, StaticResponseServer,
};
use chio_test_support::prelude::*;

fn budget_authority_json(seq: u64) -> serde_json::Value {
    serde_json::json!({
        "authorityId": "budget-primary",
        "leaderUrl": "http://leader-a",
        "budgetTerm": 7,
        "leaseId": "lease-7",
        "leaseEpoch": 7,
        "leaseExpiresAt": 5000,
        "leaseTtlMs": 750,
        "guaranteeLevel": "ha_quorum_commit",
        "budgetCommitIndex": seq
    })
}

fn budget_commit_json(seq: u64) -> serde_json::Value {
    serde_json::json!({
        "budgetSeq": seq,
        "commitIndex": seq,
        "quorumCommitted": true,
        "quorumSize": 2,
        "committedNodes": 2,
        "witnessUrls": ["http://leader-a", "http://follower-b"],
        "authorityId": "budget-primary",
        "budgetTerm": 7,
        "leaseId": "lease-7",
        "leaseEpoch": 7
    })
}

fn budget_leader_visible_authority_json() -> serde_json::Value {
    serde_json::json!({
        "authorityId": "budget-primary",
        "leaderUrl": "http://leader-a",
        "budgetTerm": 7,
        "leaseId": "lease-7",
        "leaseEpoch": 7,
        "leaseExpiresAt": 5000,
        "leaseTtlMs": 750,
        "guaranteeLevel": "ha_leader_visible"
    })
}

fn later_authorize_response(
    seq: u64,
    invocation_count: u32,
    total_exposed: u64,
    total_realized: u64,
) -> String {
    serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "invocationCount": invocation_count,
        "totalExposureCharged": total_exposed,
        "totalRealizedSpend": total_realized,
        "budgetAuthority": budget_authority_json(seq),
        "budgetCommit": budget_commit_json(seq)
    })
    .to_string()
}

fn scripted_transition_server(
    transition_response: String,
    later_response: String,
) -> ScriptedResponseServer {
    ScriptedResponseServer::spawn(vec![
        ScriptedResponse {
            status: 200,
            body: transition_response.clone(),
            content_type: "application/json",
        },
        ScriptedResponse {
            status: 200,
            body: later_response,
            content_type: "application/json",
        },
        ScriptedResponse {
            status: 200,
            body: transition_response,
            content_type: "application/json",
        },
    ])
}

#[test]
fn budget_wrappers_use_split_budget_routes() {
    let server = StaticResponseServer::spawn(200, "{}", "application/json", 4);
    let client = build_client(&server.url, "secret").test_expect("build client");

    let _ = client.try_charge_cost("cap-budget", 2, Some(9), 120, Some(150), Some(900));
    let _ = client.reverse_charge_cost("cap-budget", 2, 120);
    let _ = client.reconcile_budget_spend("cap-budget", 2, 120, 75);
    let _ = client.capture_budget_spend_with_ids("cap-budget", 2, 120, 75, None, None, None);

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert_json_post(
        &requests[0],
        BUDGET_AUTHORIZE_EXPOSURE_PATH,
        &[
            "\"exposureUnits\":120",
            "\"maxExposurePerInvocation\":150",
            "\"maxTotalExposureUnits\":900",
        ],
    );
    assert_json_post(
        &requests[1],
        BUDGET_RELEASE_EXPOSURE_PATH,
        &["\"exposureUnits\":120"],
    );
    assert_json_post(
        &requests[2],
        BUDGET_RECONCILE_SPEND_PATH,
        &[
            "\"authorizedExposureUnits\":120",
            "\"realizedSpendUnits\":75",
            "\"reductionUnits\":45",
        ],
    );
    assert_json_post(
        &requests[3],
        BUDGET_CAPTURE_EXPOSURE_PATH,
        &[
            "\"authorizedExposureUnits\":120",
            "\"realizedSpendUnits\":75",
            "\"reductionUnits\":45",
        ],
    );
}

#[test]
fn remote_budget_store_authority_apis_include_budget_event_identity() {
    let server = StaticResponseServer::spawn(200, "{}", "application/json", 5);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret").test_expect("build client"),
        cached_usage: Mutex::new(HashMap::new()),
    };
    let capture_authority = BudgetEventAuthority {
        authority_id: "budget-primary".to_string(),
        lease_id: "lease-7".to_string(),
        lease_epoch: 7,
    };

    let _ = store.try_charge_cost_with_ids_and_authority(
        "cap-budget",
        2,
        Some(9),
        120,
        Some(150),
        Some(900),
        Some("hold-budget"),
        Some("hold-budget:authorize"),
        Some(&capture_authority),
    );
    let _ = store.reverse_charge_cost_with_ids_and_authority(
        "cap-budget",
        2,
        120,
        Some("hold-budget"),
        Some("hold-budget:reverse"),
        Some(&capture_authority),
    );
    let _ = store.reduce_charge_cost_with_ids_and_authority(
        "cap-budget",
        2,
        20,
        Some("hold-budget"),
        Some("hold-budget:release"),
        Some(&capture_authority),
    );
    let _ = store.settle_charge_cost_with_ids_and_authority(
        "cap-budget",
        2,
        120,
        75,
        Some("hold-budget"),
        Some("hold-budget:reconcile"),
        Some(&capture_authority),
    );
    let _ = store.capture_budget_hold(BudgetCaptureHoldRequest {
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        exposed_cost_units: 120,
        realized_spend_units: 75,
        hold_id: Some("hold-budget".to_string()),
        event_id: Some("hold-budget:capture".to_string()),
        authority: Some(capture_authority),
    });

    let requests = server.requests();
    assert_eq!(requests.len(), 5);
    assert_json_post(
        &requests[0],
        BUDGET_AUTHORIZE_EXPOSURE_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:authorize\"",
        ],
    );
    assert!(
        !requests[0].body.contains("\"budgetAuthority\""),
        "the server, not the caller, owns initial authorization authority"
    );
    assert_json_post(
        &requests[1],
        BUDGET_RELEASE_EXPOSURE_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:reverse\"",
            "\"budgetAuthority\":",
            "\"authorityId\":\"budget-primary\"",
            "\"leaseId\":\"lease-7\"",
            "\"leaseEpoch\":7",
        ],
    );
    assert_json_post(
        &requests[2],
        BUDGET_RECONCILE_SPEND_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:release\"",
            "\"budgetAuthority\":",
            "\"authorityId\":\"budget-primary\"",
            "\"leaseId\":\"lease-7\"",
            "\"leaseEpoch\":7",
        ],
    );
    assert_json_post(
        &requests[3],
        BUDGET_RECONCILE_SPEND_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:reconcile\"",
            "\"budgetAuthority\":",
            "\"authorityId\":\"budget-primary\"",
            "\"leaseId\":\"lease-7\"",
            "\"leaseEpoch\":7",
        ],
    );
    assert_json_post(
        &requests[4],
        BUDGET_CAPTURE_EXPOSURE_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:capture\"",
            "\"budgetAuthority\":",
            "\"authorityId\":\"budget-primary\"",
            "\"leaseId\":\"lease-7\"",
            "\"leaseEpoch\":7",
        ],
    );
}

#[test]
fn budget_usage_view_round_trips_split_and_aggregate_fields() {
    let usage: BudgetUsageView = serde_json::from_value(serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 3,
        "invocationCount": 4,
        "totalExposureCharged": 75,
        "totalRealizedSpend": 60,
        "updatedAt": 1234,
        "seq": 9
    }))
    .test_expect("parse split budget usage view");

    assert_eq!(usage.capability_id, "cap-budget");
    assert_eq!(usage.grant_index, 3);
    assert_eq!(usage.invocation_count, 4);
    assert_eq!(usage.total_cost_exposed, 75);
    assert_eq!(usage.total_cost_realized_spend, 60);
    assert_eq!(usage.updated_at, 1234);
    assert_eq!(usage.seq, Some(9));

    let encoded = serde_json::to_value(&usage).test_expect("serialize budget usage view");
    assert_eq!(encoded["totalExposureCharged"], 75);
    assert_eq!(encoded["totalRealizedSpend"], 60);
    assert!(encoded.get("totalCostCharged").is_none());
}

#[test]
fn remote_budget_store_preserves_authority_term_and_commit_metadata() {
    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "invocationCount": 5,
        "totalExposureCharged": 120,
        "totalRealizedSpend": 75,
        "budgetAuthority": {
            "authorityId": "http://leader-a",
            "leaderUrl": "http://leader-a",
            "budgetTerm": 7,
            "leaseId": "http://leader-a#term-7",
            "leaseEpoch": 7,
            "leaseExpiresAt": 5000,
            "leaseTtlMs": 750,
            "guaranteeLevel": "ha_quorum_commit",
            "budgetCommitIndex": 41
        },
        "budgetCommit": {
            "budgetSeq": 41,
            "commitIndex": 41,
            "quorumCommitted": true,
            "quorumSize": 2,
            "committedNodes": 2,
            "witnessUrls": ["http://leader-a", "http://peer-b"],
            "authorityId": "http://leader-a",
            "budgetTerm": 7,
            "leaseId": "http://leader-a#term-7",
            "leaseEpoch": 7
        }
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret").test_expect("build client"),
        cached_usage: Mutex::new(HashMap::new()),
    };

    let decision = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-budget".to_string(),
            2,
            Some(9),
            120,
            Some(150),
            Some(900),
            Some("hold-budget".to_string()),
            Some("hold-budget:authorize".to_string()),
            None,
        ))
        .test_expect("authorize remote budget hold");

    let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
        panic!("expected remote authorize to succeed");
    };
    let authority = authorized
        .metadata
        .authority
        .test_expect("budget authority metadata");
    assert_eq!(authority.authority_id, "http://leader-a");
    assert_eq!(authority.lease_id, "http://leader-a#term-7");
    assert_eq!(authority.lease_epoch, 7);
    assert_eq!(authorized.metadata.budget_commit_index, Some(41));
    assert_eq!(
        authorized.metadata.guarantee_level,
        BudgetGuaranteeLevel::HaLinearizable
    );
    assert_eq!(
        authorized.metadata.event_id.as_deref(),
        Some("hold-budget:authorize")
    );

    let usage = store
        .get_usage("cap-budget", 2)
        .test_expect("get cached usage")
        .test_expect("cached usage record");
    assert_eq!(usage.seq, 41);
    assert_eq!(usage.invocation_count, 5);
    assert_eq!(usage.total_cost_exposed, 120);
    assert_eq!(usage.total_cost_realized_spend, 75);
}

#[test]
fn remote_budget_grant_only_authorize_has_no_monetary_state() {
    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "invocationCount": 1,
        "totalExposureCharged": 0,
        "totalRealizedSpend": 0
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");

    let decision = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-budget".to_string(),
            2,
            Some(9),
            0,
            None,
            None,
            Some("hold-budget".to_string()),
            Some("hold-budget:authorize".to_string()),
            None,
        ))
        .test_expect("authorize grant-only remote budget hold");
    let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
        panic!("expected grant-only authorization to succeed");
    };
    assert_eq!(authorized.monetary_state, BudgetMonetaryHoldState::None);
    assert_eq!(
        authorized.invocation_state,
        BudgetInvocationReservationState::Absent
    );
    assert_eq!(authorized.metadata.authority, None);
    assert_eq!(
        authorized.metadata.guarantee_level,
        BudgetGuaranteeLevel::SingleNodeAtomic
    );
}

#[test]
fn remote_budget_allowed_authorize_retry_returns_frozen_decision_after_later_write() {
    let authorize_response = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "invocationCount": 1,
        "totalExposureCharged": 100,
        "totalRealizedSpend": 0,
        "budgetAuthority": budget_authority_json(42),
        "budgetCommit": budget_commit_json(42)
    })
    .to_string();
    let server =
        scripted_transition_server(authorize_response, later_authorize_response(43, 2, 110, 0));
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");
    let request = BudgetAuthorizeHoldRequest::legacy(
        "cap-budget".to_string(),
        2,
        Some(10),
        100,
        Some(200),
        Some(1_000),
        Some("hold-budget".to_string()),
        Some("hold-budget:authorize".to_string()),
        None,
    );

    let first = store
        .authorize_budget_hold(request.clone())
        .test_expect("initial remote authorization");
    let BudgetAuthorizeHoldDecision::Authorized(first_authorized) = &first else {
        panic!("expected initial authorization to be allowed");
    };
    assert_eq!(first_authorized.invocation_count_after, 1);
    assert_eq!(first_authorized.committed_cost_units_after, 100);
    assert!(store
        .try_charge_cost_with_ids(
            "cap-budget",
            2,
            Some(10),
            10,
            Some(200),
            Some(1_000),
            Some("hold-budget-later"),
            Some("hold-budget-later:authorize"),
        )
        .test_expect("later same-grant authorization"));
    let later = store
        .get_usage("cap-budget", 2)
        .test_expect("later authorize usage")
        .test_expect("later authorize usage");
    assert_eq!(later.seq, 43);
    assert_eq!(later.invocation_count, 2);
    assert_eq!(later.total_cost_exposed, 110);

    let retry = store
        .authorize_budget_hold(request)
        .test_expect("retry remote authorization");
    assert_eq!(retry, first);
    assert_eq!(
        store
            .get_usage("cap-budget", 2)
            .test_expect("cached usage after authorize retry")
            .test_expect("cached usage after authorize retry"),
        later
    );
}

#[test]
fn remote_budget_denied_authorize_retry_returns_frozen_decision_and_invalidates_cache() {
    let denied_response = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": false,
        "invocationCount": 1,
        "totalExposureCharged": 80,
        "totalRealizedSpend": 0,
        "budgetAuthority": budget_leader_visible_authority_json()
    })
    .to_string();
    let server =
        scripted_transition_server(denied_response, later_authorize_response(43, 2, 90, 0));
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret").test_expect("build client"),
        cached_usage: Mutex::new(HashMap::new()),
    };
    let request = BudgetAuthorizeHoldRequest::legacy(
        "cap-budget".to_string(),
        2,
        Some(10),
        30,
        Some(100),
        Some(100),
        Some("hold-budget-denied".to_string()),
        Some("hold-budget-denied:authorize".to_string()),
        None,
    );

    let first = store
        .authorize_budget_hold(request.clone())
        .test_expect("initial denied remote authorization");
    let BudgetAuthorizeHoldDecision::Denied(first_denied) = &first else {
        panic!("expected initial authorization to be denied");
    };
    assert_eq!(first_denied.invocation_count_after, 1);
    assert_eq!(first_denied.committed_cost_units_after, 80);
    assert!(store
        .cached_usage
        .lock()
        .test_expect("denied authorize cache")
        .is_empty());
    assert!(store
        .try_charge_cost_with_ids(
            "cap-budget",
            2,
            Some(10),
            10,
            Some(100),
            Some(100),
            Some("hold-budget-later"),
            Some("hold-budget-later:authorize"),
        )
        .test_expect("later same-grant authorization"));
    assert_eq!(
        store
            .cached_usage
            .lock()
            .test_expect("later authorize cache")
            .get(&("cap-budget".to_string(), 2))
            .test_expect("later authorize cache entry")
            .seq,
        43
    );

    let retry = store
        .authorize_budget_hold(request)
        .test_expect("retry denied remote authorization");
    assert_eq!(retry, first);
    assert!(store
        .cached_usage
        .lock()
        .test_expect("denied authorize retry cache")
        .is_empty());
}

#[test]
fn remote_budget_capture_uses_distinct_truthful_terminal_state() {
    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "invocationCount": 1,
        "releasedExposureUnits": 45,
        "totalExposureCharged": 0,
        "totalRealizedSpend": 75,
        "budgetAuthority": {
            "authorityId": "http://leader-a",
            "leaderUrl": "http://leader-a",
            "budgetTerm": 7,
            "leaseId": "http://leader-a#term-7",
            "leaseEpoch": 7,
            "leaseExpiresAt": 5000,
            "leaseTtlMs": 750,
            "guaranteeLevel": "ha_quorum_commit",
            "budgetCommitIndex": 42
        },
        "budgetCommit": {
            "budgetSeq": 42,
            "commitIndex": 42,
            "quorumCommitted": true,
            "quorumSize": 2,
            "committedNodes": 2,
            "witnessUrls": ["http://leader-a", "http://follower-b"],
            "authorityId": "http://leader-a",
            "budgetTerm": 7,
            "leaseId": "http://leader-a#term-7",
            "leaseEpoch": 7
        }
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");

    let captured = store
        .capture_budget_hold(BudgetCaptureHoldRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            exposed_cost_units: 120,
            realized_spend_units: 75,
            hold_id: Some("hold-budget".to_string()),
            event_id: Some("hold-budget:capture".to_string()),
            authority: None,
        })
        .test_expect("capture remote budget hold");

    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Captured);
    assert_eq!(captured.committed_cost_units_after, 75);
    assert_eq!(captured.metadata.budget_commit_index, Some(42));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_json_post(
        &requests[0],
        BUDGET_CAPTURE_EXPOSURE_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:capture\"",
        ],
    );
}

#[test]
fn remote_budget_capture_retry_returns_frozen_decision_without_regressing_cache() {
    let capture_response = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "invocationCount": 1,
        "releasedExposureUnits": 45,
        "totalExposureCharged": 0,
        "totalRealizedSpend": 75,
        "budgetAuthority": {
            "authorityId": "budget-primary",
            "leaderUrl": "http://leader-a",
            "budgetTerm": 7,
            "leaseId": "lease-7",
            "leaseEpoch": 7,
            "leaseExpiresAt": 5000,
            "leaseTtlMs": 750,
            "guaranteeLevel": "ha_quorum_commit",
            "budgetCommitIndex": 42
        },
        "budgetCommit": {
            "budgetSeq": 42,
            "commitIndex": 42,
            "quorumCommitted": true,
            "quorumSize": 2,
            "committedNodes": 2,
            "witnessUrls": ["http://leader-a", "http://follower-b"],
            "authorityId": "budget-primary",
            "budgetTerm": 7,
            "leaseId": "lease-7",
            "leaseEpoch": 7
        }
    })
    .to_string();
    let later_authorize_response = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "invocationCount": 2,
        "totalExposureCharged": 10,
        "totalRealizedSpend": 75,
        "budgetAuthority": {
            "authorityId": "budget-primary",
            "leaderUrl": "http://leader-a",
            "budgetTerm": 7,
            "leaseId": "lease-7",
            "leaseEpoch": 7,
            "leaseExpiresAt": 5000,
            "leaseTtlMs": 750,
            "guaranteeLevel": "ha_quorum_commit",
            "budgetCommitIndex": 43
        },
        "budgetCommit": {
            "budgetSeq": 43,
            "commitIndex": 43,
            "quorumCommitted": true,
            "quorumSize": 2,
            "committedNodes": 2,
            "witnessUrls": ["http://leader-a", "http://follower-b"],
            "authorityId": "budget-primary",
            "budgetTerm": 7,
            "leaseId": "lease-7",
            "leaseEpoch": 7
        }
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
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");
    let authority = BudgetEventAuthority {
        authority_id: "budget-primary".to_string(),
        lease_id: "lease-7".to_string(),
        lease_epoch: 7,
    };
    let request = BudgetCaptureHoldRequest {
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        exposed_cost_units: 120,
        realized_spend_units: 75,
        hold_id: Some("hold-budget".to_string()),
        event_id: Some("hold-budget:capture".to_string()),
        authority: Some(authority),
    };

    let first = store
        .capture_budget_hold(request.clone())
        .test_expect("initial remote capture");
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
        .test_expect("read later cached usage")
        .test_expect("later cached usage");
    assert_eq!(later.seq, 43);
    assert_eq!(later.invocation_count, 2);
    assert_eq!(later.total_cost_exposed, 10);

    let retry = store
        .capture_budget_hold(request)
        .test_expect("retry remote capture");
    assert_eq!(retry, first);
    assert_eq!(
        store
            .get_usage("cap-budget", 2)
            .test_expect("read cached usage after retry")
            .test_expect("cached usage after retry"),
        later
    );
}

#[test]
fn remote_budget_reverse_retry_returns_frozen_decision_after_later_write() {
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
    let server =
        scripted_transition_server(transition_response, later_authorize_response(43, 1, 10, 0));
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");
    let request = BudgetReverseHoldRequest {
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        reversed_exposure_units: 120,
        hold_id: Some("hold-budget".to_string()),
        event_id: Some("hold-budget:reverse".to_string()),
        authority: None,
    };

    let first = store
        .reverse_budget_hold(request.clone())
        .test_expect("initial remote reverse");
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
        .test_expect("later cached reverse usage")
        .test_expect("later cached reverse usage");
    let retry = store
        .reverse_budget_hold(request)
        .test_expect("retry remote reverse");

    assert_eq!(retry, first);
    assert_eq!(
        store
            .get_usage("cap-budget", 2)
            .test_expect("cached usage after reverse retry")
            .test_expect("cached usage after reverse retry"),
        later
    );
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
    };
    let request = BudgetCaptureHoldRequest {
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
