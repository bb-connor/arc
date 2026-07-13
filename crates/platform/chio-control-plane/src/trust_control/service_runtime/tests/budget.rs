use super::super::super::*;
use super::super::budget::build_remote_budget_store;
use super::super::client::{build_client, should_retry_status};
use super::super::errors::{
    into_budget_store_error, into_receipt_store_error, into_revocation_store_error,
};
use super::super::issuance::ensure_signed_by_trusted_authority;
use super::support::{assert_json_post, StaticResponseServer};
use chio_kernel::budget_store::{
    BudgetCancelCapturedBeforeDispatchRequest, BudgetCaptureHoldRequest,
    BudgetCumulativeApprovalState,
};
use chio_test_support::prelude::*;

#[test]
fn remote_budget_store_rejects_composite_authorization_before_network_io(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = build_remote_budget_store("http://127.0.0.1:1", "secret")?;
    let identity_error = match store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        max_invocations: None,
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 10,
        max_cost_per_invocation: Some(10),
        max_total_cost_units: Some(10),
        hold_id: Some("hold-composite".to_string()),
        event_id: None,
        authority: None,
    }) {
        Ok(_) => {
            return Err(std::io::Error::other("remote store accepted partial identity").into())
        }
        Err(error) => error,
    };
    assert!(identity_error.to_string().contains("non-empty identifiers"));
    let error = match store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        max_invocations: Some(1),
        invocation_quotas: vec![chio_kernel::budget_store::BudgetInvocationQuota {
            key: chio_kernel::budget_store::BudgetQuotaKey::grant("cap-composite", 0),
            max_invocations: 1,
        }],
        cumulative_approval: None,
        admission_binding: Some(chio_kernel::budget_store::BudgetAdmissionBinding {
            operation_id: "op-composite".to_string(),
            revocation_set: chio_kernel::supplemental_quota::CanonicalRevocationSet::canonicalize(
                vec!["cap-composite".to_string()],
            )?,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: 10,
        max_cost_per_invocation: Some(10),
        max_total_cost_units: Some(10),
        hold_id: Some("hold-composite".to_string()),
        event_id: Some("hold-composite:authorize".to_string()),
        authority: None,
    }) {
        Ok(_) => {
            return Err(
                std::io::Error::other("remote store accepted composite authorization").into(),
            )
        }
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("composite budget authorization is not supported"));
    let capture_error =
        match store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            hold_id: "hold-composite".to_string(),
            event_id: "hold-composite:capture".to_string(),
            trusted_time: Some(1),
            authority: None,
        }) {
            Ok(_) => {
                return Err(
                    std::io::Error::other("remote store accepted trusted capture time").into(),
                )
            }
            Err(error) => error,
        };
    assert!(capture_error
        .to_string()
        .contains("trusted capture time is not supported"));
    let empty_capture = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        hold_id: "hold-composite".to_string(),
        event_id: String::new(),
        trusted_time: None,
        authority: None,
    });
    assert!(empty_capture
        .as_ref()
        .is_err_and(|error| error.to_string().contains("non-empty hold_id and event_id")));
    let reverse_error = match store.reverse_budget_hold(BudgetReverseHoldRequest {
        capability_id: "cap-composite".to_string(),
        grant_index: 0,
        reversed_exposure_units: 10,
        hold_id: Some("hold-composite".to_string()),
        event_id: Some("hold-composite:reverse".to_string()),
        expected_cumulative_approval_state: Some(BudgetCumulativeApprovalState::PendingApproval),
        authority: None,
    }) {
        Ok(_) => {
            return Err(std::io::Error::other(
                "remote store accepted state-fenced cumulative approval reversal",
            )
            .into())
        }
        Err(error) => error,
    };
    assert!(reverse_error
        .to_string()
        .contains("cumulative approval state-fenced reversal"));
    for (result, expected) in [
        (
            store.release_budget_hold(BudgetReleaseHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                released_exposure_units: 10,
                hold_id: Some("hold-composite".to_string()),
                event_id: Some("hold-composite:release".to_string()),
                authority: None,
            }),
            "cannot preserve invocation state",
        ),
        (
            store.reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                exposed_cost_units: 10,
                realized_spend_units: 5,
                hold_id: Some("hold-composite".to_string()),
                event_id: Some("hold-composite:reconcile".to_string()),
                authority: None,
            }),
            "requires a locally captured hold",
        ),
        (
            store.capture_budget_hold(BudgetCaptureHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                exposed_cost_units: 10,
                realized_spend_units: 5,
                hold_id: Some("hold-composite".to_string()),
                event_id: Some("hold-composite:capture-spend".to_string()),
                authority: None,
            }),
            "distinct monetary capture transition",
        ),
    ] {
        let Err(error) = result else {
            return Err(
                std::io::Error::other("remote store fabricated rich lifecycle state").into(),
            );
        };
        assert!(error.to_string().contains(expected));
    }
    Ok(())
}

#[test]
fn budget_wrappers_use_split_budget_routes() {
    let server = StaticResponseServer::spawn(200, "{}", "application/json", 4);
    let client = build_client(&server.url, "secret").test_expect("build client");

    let _ = client.try_charge_cost("cap-budget", 2, Some(9), 120, Some(150), Some(900));
    let _ = client.capture_invocation_reservations(
        "cap-budget",
        2,
        "hold-budget",
        "hold-budget:capture-invocation",
    );
    let _ = client.reverse_charge_cost("cap-budget", 2, 120);
    let _ = client.reconcile_budget_spend("cap-budget", 2, 120, 75);

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
        BUDGET_CAPTURE_INVOCATION_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:capture-invocation\"",
        ],
    );
    assert_json_post(
        &requests[2],
        BUDGET_RELEASE_EXPOSURE_PATH,
        &["\"exposureUnits\":120"],
    );
    assert_json_post(
        &requests[3],
        BUDGET_RECONCILE_SPEND_PATH,
        &[
            "\"authorizedExposureUnits\":120",
            "\"realizedSpendUnits\":75",
            "\"reductionUnits\":45",
        ],
    );
}

#[test]
fn budget_wrappers_include_budget_event_identity_when_provided() {
    let server = StaticResponseServer::spawn(200, "{}", "application/json", 4);
    let client = build_client(&server.url, "secret").test_expect("build client");

    let _ = client.try_charge_cost_with_ids(
        "cap-budget",
        2,
        Some(9),
        120,
        Some(150),
        Some(900),
        Some("hold-budget"),
        Some("hold-budget:authorize"),
    );
    let _ = client.capture_invocation_reservations(
        "cap-budget",
        2,
        "hold-budget",
        "hold-budget:capture-invocation",
    );
    let _ = client.reverse_charge_cost_with_ids(
        "cap-budget",
        2,
        120,
        Some("hold-budget"),
        Some("hold-budget:reverse"),
    );
    let _ = client.reconcile_budget_spend_with_ids(
        "cap-budget",
        2,
        120,
        75,
        Some("hold-budget"),
        Some("hold-budget:reconcile"),
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert_json_post(
        &requests[0],
        BUDGET_AUTHORIZE_EXPOSURE_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:authorize\"",
        ],
    );
    assert_json_post(
        &requests[1],
        BUDGET_CAPTURE_INVOCATION_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:capture-invocation\"",
        ],
    );
    assert_json_post(
        &requests[2],
        BUDGET_RELEASE_EXPOSURE_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:reverse\"",
        ],
    );
    assert_json_post(
        &requests[3],
        BUDGET_RECONCILE_SPEND_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:reconcile\"",
        ],
    );
}

#[test]
fn remote_budget_store_preserves_capture_decision() -> Result<(), Box<dyn std::error::Error>> {
    for (wire, expected_captured) in [("captured", true), ("already_captured", false)] {
        let body = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 2,
            "holdId": "hold-budget",
            "eventId": "hold-budget:original-capture",
            "decision": wire,
            "invocationCountAfter": 1,
            "usageInvocationCount": 2,
            "committedCostUnitsAfter": 100,
            "exposureUnits": 100,
            "totalCostExposedAfter": 100,
            "totalCostRealizedSpendAfter": 0,
            "usageSeq": 7,
        })
        .to_string();
        let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
        let store = build_remote_budget_store(&server.url, "secret")?;

        let decision = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            hold_id: "hold-budget".to_string(),
            event_id: "hold-budget:original-capture".to_string(),
            trusted_time: None,
            authority: None,
        })?;

        let (captured, mutation) = match decision {
            BudgetInvocationCaptureDecision::Captured(mutation) => (true, mutation),
            BudgetInvocationCaptureDecision::AlreadyCaptured(mutation) => (false, mutation),
        };
        assert_eq!(captured, expected_captured);
        assert_eq!(mutation.hold_id.as_deref(), Some("hold-budget"));
        assert_eq!(mutation.invocation_count_after, 1);
        assert_eq!(mutation.committed_cost_units_after, 100);
        assert_eq!(mutation.exposure_units, 100);
        assert_eq!(mutation.monetary_state, BudgetMonetaryState::Exposed);
        assert_eq!(
            mutation.metadata.event_id.as_deref(),
            Some("hold-budget:original-capture")
        );
        let usage = store
            .get_usage("cap-budget", 2)?
            .ok_or_else(|| std::io::Error::other("captured usage was not cached"))?;
        assert_eq!(usage.invocation_count, 2);
        assert_eq!(usage.total_cost_exposed, 100);
        assert_eq!(usage.total_cost_realized_spend, 0);
        assert_eq!(usage.seq, 7);
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_capture_identity_substitution(
) -> Result<(), Box<dyn std::error::Error>> {
    for (field, substituted) in [
        ("capabilityId", serde_json::json!("cap-other")),
        ("grantIndex", serde_json::json!(3)),
        ("holdId", serde_json::json!("hold-other")),
        ("eventId", serde_json::json!("hold-budget:other-capture")),
    ] {
        let mut body = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 2,
            "holdId": "hold-budget",
            "eventId": "hold-budget:capture",
            "decision": "already_captured",
            "invocationCountAfter": 1,
            "usageInvocationCount": 1,
            "committedCostUnitsAfter": 100,
            "exposureUnits": 100,
            "totalCostExposedAfter": 100,
            "totalCostRealizedSpendAfter": 0,
            "usageSeq": 7,
        });
        body[field] = substituted;
        let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
        let store = build_remote_budget_store(&server.url, "secret")?;
        let result = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            hold_id: "hold-budget".to_string(),
            event_id: "hold-budget:capture".to_string(),
            trusted_time: None,
            authority: None,
        });
        assert!(result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("changed the request identity")));
    }
    Ok(())
}

#[test]
fn remote_budget_store_binds_authorize_response_identity_and_event(
) -> Result<(), Box<dyn std::error::Error>> {
    for (field, substituted) in [
        ("capabilityId", serde_json::json!("cap-other")),
        ("grantIndex", serde_json::json!(3)),
    ] {
        let mut body = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 2,
            "allowed": true,
            "decision": "authorized",
            "holdId": "hold-budget",
            "eventId": "server-substituted-event",
            "exposureUnits": 100,
            "realizedSpendUnits": 0,
            "mutationInvocationCountAfter": 1,
            "mutationCommittedCostUnitsAfter": 100,
            "usageSeq": 7,
            "invocationCount": 1,
            "totalExposureCharged": 100,
            "totalRealizedSpend": 0,
        });
        body[field] = substituted;
        let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
        let store = build_remote_budget_store(&server.url, "secret")?;
        let result = store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            max_invocations: Some(1),
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
            requested_exposure_units: 100,
            max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(100),
            hold_id: Some("hold-budget".to_string()),
            event_id: Some("hold-budget:authorize".to_string()),
            authority: None,
        });
        assert!(result.as_ref().is_err_and(|error| error
            .to_string()
            .contains("authorization response changed the request identity")));
    }

    for (decision, allowed) in [("authorized", true), ("denied", false)] {
        let substituted = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 2,
            "allowed": allowed,
            "decision": decision,
            "holdId": "hold-budget",
            "eventId": "server-substituted-event",
            "usageSeq": 7,
            "invocationCount": 1,
            "totalExposureCharged": 100,
            "totalRealizedSpend": 0,
        })
        .to_string();
        let valid = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 2,
            "allowed": allowed,
            "decision": decision,
            "holdId": "hold-budget",
            "eventId": "hold-budget:authorize",
            "exposureUnits": if allowed { Some(100_u64) } else { None },
            "realizedSpendUnits": if allowed { Some(0_u64) } else { None },
            "mutationInvocationCountAfter": 1,
            "mutationCommittedCostUnitsAfter": 100,
            "usageSeq": 7,
            "invocationCount": 1,
            "totalExposureCharged": 100,
            "totalRealizedSpend": 0,
        })
        .to_string();
        let server = StaticResponseServer::spawn(200, &substituted, "application/json", 2);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
            captured_holds: std::sync::Mutex::new(std::collections::HashSet::new()),
        };
        store.cache_usage("cap-budget", 2, Some(5), Some(5), Some(50), Some(25))?;
        let request = BudgetAuthorizeHoldRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            max_invocations: Some(1),
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
            requested_exposure_units: 100,
            max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(100),
            hold_id: Some("hold-budget".to_string()),
            event_id: Some("hold-budget:authorize".to_string()),
            authority: None,
        };
        let result = store.authorize_budget_hold(request.clone());
        let cached = store
            .cached_usage("cap-budget", 2)
            .ok_or_else(|| std::io::Error::other("seeded cache missing"))?;

        server.set_body(&valid);
        let decision = store.authorize_budget_hold(request)?;
        let metadata = match decision {
            BudgetAuthorizeHoldDecision::Authorized(authorized) => authorized.metadata,
            BudgetAuthorizeHoldDecision::Denied(denied) => denied.metadata,
            other => {
                return Err(std::io::Error::other(format!(
                    "unexpected remote authorization decision: {other:?}"
                ))
                .into())
            }
        };
        assert!(result.as_ref().is_err_and(|error| error
            .to_string()
            .contains("authorization response changed or omitted the request event identity")));
        assert_eq!(cached.seq, 5);
        assert_eq!(cached.invocation_count, 5);
        assert_eq!(cached.total_cost_exposed, 50);
        assert_eq!(cached.total_cost_realized_spend, 25);
        assert_eq!(metadata.event_id.as_deref(), Some("hold-budget:authorize"));
        let cached = store
            .cached_usage("cap-budget", 2)
            .ok_or_else(|| std::io::Error::other("valid retry cache missing"))?;
        assert_eq!(cached.seq, 7);
        assert_eq!(cached.invocation_count, 1);
        assert_eq!(cached.total_cost_exposed, 100);
        assert_eq!(cached.total_cost_realized_spend, 0);
    }
    Ok(())
}

#[test]
fn remote_budget_store_requires_coherent_authorize_event_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let generated_body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "decision": "authorized",
        "eventId": "server-generated-event",
        "exposureUnits": 10,
        "realizedSpendUnits": 0,
        "mutationInvocationCountAfter": 1,
        "mutationCommittedCostUnitsAfter": 10,
        "usageSeq": 1,
        "invocationCount": 1,
        "totalExposureCharged": 10,
        "totalRealizedSpend": 0,
    })
    .to_string();
    let generated_server = StaticResponseServer::spawn(200, &generated_body, "application/json", 1);
    let generated_store = build_remote_budget_store(&generated_server.url, "secret")?;
    let generated = generated_store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        max_invocations: None,
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 10,
        max_cost_per_invocation: Some(10),
        max_total_cost_units: Some(10),
        hold_id: None,
        event_id: None,
        authority: None,
    })?;
    let BudgetAuthorizeHoldDecision::Authorized(generated) = generated else {
        return Err(
            std::io::Error::other("server-generated event authorization was denied").into(),
        );
    };
    assert_eq!(
        generated.metadata.event_id.as_deref(),
        Some("server-generated-event")
    );

    for (decision, allowed, hold_id, request_event_id, response_event_id, expected) in [
        (
            "authorized",
            true,
            None,
            Some("requested-event"),
            "substituted-event",
            "changed or omitted the request event identity",
        ),
        (
            "already_captured",
            false,
            Some("hold-budget"),
            Some("hold-budget:authorize"),
            "",
            "omitted non-empty capture event identity",
        ),
        (
            "already_captured",
            false,
            None,
            None,
            "hold-budget:original-capture",
            "requires a hold identity",
        ),
    ] {
        let body = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 2,
            "allowed": allowed,
            "decision": decision,
            "holdId": hold_id,
            "eventId": response_event_id,
            "exposureUnits": 10,
            "realizedSpendUnits": 0,
            "mutationInvocationCountAfter": 1,
            "mutationCommittedCostUnitsAfter": 10,
            "usageSeq": 2,
            "invocationCount": 1,
            "totalExposureCharged": 10,
            "totalRealizedSpend": 0,
        })
        .to_string();
        let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
        let store = build_remote_budget_store(&server.url, "secret")?;
        let result = store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            max_invocations: None,
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
            requested_exposure_units: 10,
            max_cost_per_invocation: Some(10),
            max_total_cost_units: Some(10),
            hold_id: hold_id.map(ToOwned::to_owned),
            event_id: request_event_id.map(ToOwned::to_owned),
            authority: None,
        });
        assert!(result
            .as_ref()
            .is_err_and(|error| error.to_string().contains(expected)));
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_incomplete_event_projection_without_poisoning_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    let incomplete = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "decision": "authorized",
        "holdId": "hold-budget",
        "eventId": "hold-budget:authorize",
        "exposureUnits": 100,
        "realizedSpendUnits": 0,
        "mutationInvocationCountAfter": 1,
        "usageSeq": 7,
        "invocationCount": 1,
        "totalExposureCharged": 100,
        "totalRealizedSpend": 0,
    })
    .to_string();
    let valid = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "decision": "authorized",
        "holdId": "hold-budget",
        "eventId": "hold-budget:authorize",
        "exposureUnits": 100,
        "realizedSpendUnits": 0,
        "mutationInvocationCountAfter": 1,
        "mutationCommittedCostUnitsAfter": 100,
        "usageSeq": 7,
        "invocationCount": 1,
        "totalExposureCharged": 100,
        "totalRealizedSpend": 0,
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &incomplete, "application/json", 2);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret")?,
        cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
        captured_holds: std::sync::Mutex::new(std::collections::HashSet::new()),
    };
    store.cache_usage("cap-budget", 2, Some(5), Some(5), Some(50), Some(25))?;
    let request = BudgetAuthorizeHoldRequest {
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        max_invocations: Some(1),
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(100),
        hold_id: Some("hold-budget".to_string()),
        event_id: Some("hold-budget:authorize".to_string()),
        authority: None,
    };
    let incomplete_result = store.authorize_budget_hold(request.clone());
    let cached_after_incomplete = store
        .cached_usage("cap-budget", 2)
        .ok_or_else(|| std::io::Error::other("seeded cache missing"))?;
    server.set_body(&valid);
    let valid_result = store.authorize_budget_hold(request);
    let cached_after_valid = store
        .cached_usage("cap-budget", 2)
        .ok_or_else(|| std::io::Error::other("valid retry cache missing"))?;

    assert!(incomplete_result.as_ref().is_err_and(|error| error
        .to_string()
        .contains("omitted event-time committed cost")));
    assert_eq!(cached_after_incomplete.seq, 5);
    assert_eq!(cached_after_incomplete.invocation_count, 5);
    assert_eq!(cached_after_incomplete.total_cost_exposed, 50);
    assert_eq!(cached_after_incomplete.total_cost_realized_spend, 25);
    assert!(valid_result.is_ok());
    assert_eq!(cached_after_valid.seq, 7);
    assert_eq!(cached_after_valid.invocation_count, 1);
    assert_eq!(cached_after_valid.total_cost_exposed, 100);
    assert_eq!(cached_after_valid.total_cost_realized_spend, 0);
    Ok(())
}

#[test]
fn remote_budget_store_rejects_impossible_authorize_projection_without_poisoning_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    for (decision, allowed, event_id, invocation_count_after, committed_cost_after) in [
        ("authorized", true, "hold-budget:authorize", 0, 100),
        ("authorized", true, "hold-budget:authorize", 1, 99),
        (
            "already_captured",
            false,
            "hold-budget:original-capture",
            0,
            100,
        ),
        (
            "already_captured",
            false,
            "hold-budget:original-capture",
            1,
            99,
        ),
    ] {
        let body = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 2,
            "allowed": allowed,
            "decision": decision,
            "holdId": "hold-budget",
            "eventId": event_id,
            "exposureUnits": 100,
            "realizedSpendUnits": 0,
            "mutationInvocationCountAfter": invocation_count_after,
            "mutationCommittedCostUnitsAfter": committed_cost_after,
            "usageSeq": 7,
            "invocationCount": 9,
            "totalExposureCharged": 900,
            "totalRealizedSpend": 90,
        })
        .to_string();
        let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
            captured_holds: std::sync::Mutex::new(std::collections::HashSet::new()),
        };
        store.cache_usage("cap-budget", 2, Some(5), Some(5), Some(50), Some(25))?;
        let result = store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            max_invocations: Some(1),
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
            requested_exposure_units: 100,
            max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(100),
            hold_id: Some("hold-budget".to_string()),
            event_id: Some("hold-budget:authorize".to_string()),
            authority: None,
        });
        let cached = store
            .cached_usage("cap-budget", 2)
            .ok_or_else(|| std::io::Error::other("seeded cache missing"))?;
        assert!(result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("impossible event-time state")));
        assert_eq!(cached.seq, 5);
        assert_eq!(cached.invocation_count, 5);
        assert_eq!(cached.total_cost_exposed, 50);
        assert_eq!(cached.total_cost_realized_spend, 25);
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_oversized_grant_before_network_io(
) -> Result<(), Box<dyn std::error::Error>> {
    let Ok(oversized_grant) = usize::try_from(u64::from(u32::MAX) + 1) else {
        return Ok(());
    };
    let store = build_remote_budget_store("http://127.0.0.1:1", "secret")?;
    let legacy = store.try_charge_cost("cap-budget", oversized_grant, None, 10, Some(10), Some(10));
    let rich = store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: "cap-budget".to_string(),
        grant_index: oversized_grant,
        max_invocations: None,
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 10,
        max_cost_per_invocation: Some(10),
        max_total_cost_units: Some(10),
        hold_id: None,
        event_id: None,
        authority: None,
    });
    for error in [legacy.err(), rich.err()] {
        assert!(error.is_some_and(|error| error.to_string().contains("exceeds u32 range")));
    }
    Ok(())
}

#[test]
fn remote_budget_store_legacy_with_ids_validates_identity_before_network(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = build_remote_budget_store("http://127.0.0.1:1", "secret")?;
    for (hold_id, event_id) in [
        (Some("hold-budget"), None),
        (Some(""), Some("event")),
        (Some("hold-budget"), Some("")),
        (None, Some("")),
    ] {
        for result in [
            store
                .try_charge_cost_with_ids("cap-budget", 0, None, 0, None, None, hold_id, event_id)
                .map(|_| ()),
            store.reverse_charge_cost_with_ids("cap-budget", 0, 0, hold_id, event_id),
            store.reduce_charge_cost_with_ids("cap-budget", 0, 0, hold_id, event_id),
            store.settle_charge_cost_with_ids("cap-budget", 0, 0, 0, hold_id, event_id),
        ] {
            assert!(result
                .as_ref()
                .is_err_and(|error| error.to_string().contains("requires non-empty identifiers")));
        }
    }

    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 0,
        "allowed": true,
        "decision": "authorized",
        "eventId": "event-only",
        "invocationCount": 1,
        "releasedExposureUnits": 0,
        "totalExposureCharged": 0,
        "totalRealizedSpend": 0,
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 4);
    let store = build_remote_budget_store(&server.url, "secret")?;
    assert!(store.try_charge_cost_with_ids(
        "cap-budget",
        0,
        None,
        0,
        None,
        None,
        None,
        Some("event-only"),
    )?);
    store.reverse_charge_cost_with_ids("cap-budget", 0, 0, None, Some("event-only"))?;
    store.reduce_charge_cost_with_ids("cap-budget", 0, 0, None, Some("event-only"))?;
    store.settle_charge_cost_with_ids("cap-budget", 0, 0, 0, None, Some("event-only"))?;

    for (request_hold_id, event_id, response_hold_id) in [
        (None, "event-only", "hold-added"),
        (Some("hold-budget"), "hold-budget:event", "hold-other"),
    ] {
        let body = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 0,
            "allowed": true,
            "decision": "authorized",
            "holdId": response_hold_id,
            "eventId": event_id,
            "invocationCount": 1,
            "releasedExposureUnits": 0,
            "totalExposureCharged": 0,
            "totalRealizedSpend": 0,
        })
        .to_string();
        let server = StaticResponseServer::spawn(200, &body, "application/json", 4);
        let store = build_remote_budget_store(&server.url, "secret")?;
        for result in [
            store
                .try_charge_cost_with_ids(
                    "cap-budget",
                    0,
                    None,
                    0,
                    None,
                    None,
                    request_hold_id,
                    Some(event_id),
                )
                .map(|_| ()),
            store.reverse_charge_cost_with_ids("cap-budget", 0, 0, request_hold_id, Some(event_id)),
            store.reduce_charge_cost_with_ids("cap-budget", 0, 0, request_hold_id, Some(event_id)),
            store.settle_charge_cost_with_ids(
                "cap-budget",
                0,
                0,
                0,
                request_hold_id,
                Some(event_id),
            ),
        ] {
            assert!(result
                .as_ref()
                .is_err_and(|error| error.to_string().contains("hold/event identity")));
        }
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_legacy_identity_substitution_without_poisoning_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "capabilityId": "cap-other",
        "grantIndex": 2,
        "allowed": true,
        "decision": "authorized",
        "invocationCount": 9,
        "totalExposureCharged": 900,
        "totalRealizedSpend": 90,
        "releasedExposureUnits": 25,
        "budgetCommit": {
            "budgetSeq": 7,
            "commitIndex": 7,
            "quorumCommitted": true,
            "quorumSize": 1,
            "committedNodes": 1,
            "witnessUrls": [],
            "authorityId": "local",
            "budgetTerm": 1,
            "leaseId": "local#1",
            "leaseEpoch": 1
        }
    })
    .to_string();
    for operation in ["charge", "reverse", "release", "settle"] {
        let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
            captured_holds: std::sync::Mutex::new(std::collections::HashSet::new()),
        };
        store.cache_usage("cap-budget", 2, Some(5), Some(5), Some(50), Some(25))?;
        let result = match operation {
            "charge" => store
                .try_charge_cost("cap-budget", 2, None, 100, Some(100), Some(100))
                .map(|_| ()),
            "reverse" => store.reverse_charge_cost("cap-budget", 2, 100),
            "release" => store.reduce_charge_cost("cap-budget", 2, 25),
            "settle" => store.settle_charge_cost("cap-budget", 2, 100, 75),
            _ => return Err(std::io::Error::other("unknown budget operation").into()),
        };
        let cached = store
            .cached_usage("cap-budget", 2)
            .ok_or_else(|| std::io::Error::other("seeded cache missing"))?;
        assert!(result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("changed the request identity")));
        assert_eq!(cached.seq, 5);
        assert_eq!(cached.invocation_count, 5);
        assert_eq!(cached.total_cost_exposed, 50);
        assert_eq!(cached.total_cost_realized_spend, 25);
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_reconcile_mismatch_without_poisoning_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    for (released_exposure, total_realized_spend, expected) in [
        (24, 75, "released exposure"),
        (25, 50, "impossible event-time state"),
    ] {
        let body = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 2,
            "holdId": "hold-budget",
            "eventId": "hold-budget:reconcile",
            "invocationCount": 1,
            "releasedExposureUnits": released_exposure,
            "totalExposureCharged": 0,
            "totalRealizedSpend": total_realized_spend,
            "budgetCommit": {
                "budgetSeq": 7,
                "commitIndex": 7,
                "quorumCommitted": true,
                "quorumSize": 1,
                "committedNodes": 1,
                "witnessUrls": [],
                "authorityId": "local",
                "budgetTerm": 1,
                "leaseId": "local#1",
                "leaseEpoch": 1
            }
        })
        .to_string();
        let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
            captured_holds: std::sync::Mutex::new(std::collections::HashSet::from([(
                "cap-budget".to_string(),
                2,
                "hold-budget".to_string(),
            )])),
        };
        store.cache_usage("cap-budget", 2, Some(5), Some(5), Some(50), Some(25))?;
        let result = store.reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            exposed_cost_units: 100,
            realized_spend_units: 75,
            hold_id: Some("hold-budget".to_string()),
            event_id: Some("hold-budget:reconcile".to_string()),
            authority: None,
        });
        let cached = store
            .cached_usage("cap-budget", 2)
            .ok_or_else(|| std::io::Error::other("seeded cache missing"))?;
        assert!(result
            .as_ref()
            .is_err_and(|error| error.to_string().contains(expected)));
        assert_eq!(cached.seq, 5);
        assert_eq!(cached.invocation_count, 5);
        assert_eq!(cached.total_cost_exposed, 50);
        assert_eq!(cached.total_cost_realized_spend, 25);
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_reconcile_hold_or_event_substitution_without_poisoning_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    for (field, replacement) in [
        ("holdId", Some(serde_json::json!("hold-other"))),
        (
            "eventId",
            Some(serde_json::json!("hold-budget:other-reconcile")),
        ),
        ("holdId", None),
        ("eventId", None),
    ] {
        let mut body = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 2,
            "holdId": "hold-budget",
            "eventId": "hold-budget:reconcile",
            "invocationCount": 1,
            "releasedExposureUnits": 25,
            "totalExposureCharged": 0,
            "totalRealizedSpend": 75,
            "budgetCommit": {
                "budgetSeq": 7,
                "commitIndex": 7,
                "quorumCommitted": true,
                "quorumSize": 1,
                "committedNodes": 1,
                "witnessUrls": [],
                "authorityId": "local",
                "budgetTerm": 1,
                "leaseId": "local#1",
                "leaseEpoch": 1
            }
        });
        if let Some(replacement) = replacement {
            body[field] = replacement;
        } else {
            body.as_object_mut()
                .ok_or_else(|| std::io::Error::other("reconcile response was not an object"))?
                .remove(field);
        }
        let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
            captured_holds: std::sync::Mutex::new(std::collections::HashSet::from([(
                "cap-budget".to_string(),
                2,
                "hold-budget".to_string(),
            )])),
        };
        store.cache_usage("cap-budget", 2, Some(5), Some(5), Some(50), Some(25))?;
        let result = store.reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            exposed_cost_units: 100,
            realized_spend_units: 75,
            hold_id: Some("hold-budget".to_string()),
            event_id: Some("hold-budget:reconcile".to_string()),
            authority: None,
        });
        let cached = store
            .cached_usage("cap-budget", 2)
            .ok_or_else(|| std::io::Error::other("seeded cache missing"))?;
        assert!(result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("hold/event identity")));
        assert_eq!(cached.seq, 5);
        assert_eq!(cached.invocation_count, 5);
        assert_eq!(cached.total_cost_exposed, 50);
        assert_eq!(cached.total_cost_realized_spend, 25);
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_impossible_capture_event_state(
) -> Result<(), Box<dyn std::error::Error>> {
    for (field, invalid) in [
        ("invocationCountAfter", serde_json::json!(0)),
        ("committedCostUnitsAfter", serde_json::json!(99)),
    ] {
        let mut body = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 2,
            "holdId": "hold-budget",
            "eventId": "hold-budget:capture",
            "decision": "captured",
            "exposureUnits": 100,
            "invocationCountAfter": 1,
            "usageInvocationCount": 1,
            "committedCostUnitsAfter": 100,
            "totalCostExposedAfter": 100,
            "totalCostRealizedSpendAfter": 0,
            "usageSeq": 7,
        });
        body[field] = invalid;
        let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
            captured_holds: std::sync::Mutex::new(std::collections::HashSet::new()),
        };
        let result = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            hold_id: "hold-budget".to_string(),
            event_id: "hold-budget:capture".to_string(),
            trusted_time: None,
            authority: None,
        });
        assert!(result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("impossible event-time state")));
        assert!(store.cached_usage("cap-budget", 2).is_none());
        assert!(store
            .captured_holds
            .lock()
            .test_expect("captured hold fence")
            .is_empty());
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_reverse_identity_substitution(
) -> Result<(), Box<dyn std::error::Error>> {
    for (field, substituted) in [
        ("capabilityId", serde_json::json!("cap-other")),
        ("grantIndex", serde_json::json!(3)),
    ] {
        let mut body = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 2,
            "invocationCount": 0,
            "totalExposureCharged": 0,
            "totalRealizedSpend": 0,
        });
        body[field] = substituted;
        let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
        let store = build_remote_budget_store(&server.url, "secret")?;
        let result = store.reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            reversed_exposure_units: 100,
            hold_id: Some("hold-budget".to_string()),
            event_id: Some("hold-budget:reverse".to_string()),
            expected_cumulative_approval_state: None,
            authority: None,
        });
        assert!(result.as_ref().is_err_and(|error| error
            .to_string()
            .contains("reversal response changed the request identity")));
    }
    Ok(())
}

#[test]
fn remote_budget_store_rejects_reverse_hold_or_event_substitution_without_poisoning_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    for (field, replacement) in [
        ("holdId", Some(serde_json::json!("hold-other"))),
        (
            "eventId",
            Some(serde_json::json!("hold-budget:other-reverse")),
        ),
        ("holdId", None),
        ("eventId", None),
    ] {
        let mut body = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 2,
            "holdId": "hold-budget",
            "eventId": "hold-budget:reverse",
            "invocationCount": 0,
            "totalExposureCharged": 0,
            "totalRealizedSpend": 0,
            "budgetCommit": {
                "budgetSeq": 7,
                "commitIndex": 7,
                "quorumCommitted": true,
                "quorumSize": 1,
                "committedNodes": 1,
                "witnessUrls": [],
                "authorityId": "local",
                "budgetTerm": 1,
                "leaseId": "local#1",
                "leaseEpoch": 1
            }
        });
        if let Some(replacement) = replacement {
            body[field] = replacement;
        } else {
            body.as_object_mut()
                .ok_or_else(|| std::io::Error::other("reverse response was not an object"))?
                .remove(field);
        }
        let server = StaticResponseServer::spawn(200, &body.to_string(), "application/json", 1);
        let store = RemoteBudgetStore {
            client: build_client(&server.url, "secret")?,
            cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
            captured_holds: std::sync::Mutex::new(std::collections::HashSet::new()),
        };
        store.cache_usage("cap-budget", 2, Some(5), Some(5), Some(50), Some(25))?;
        let result = store.reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            reversed_exposure_units: 100,
            hold_id: Some("hold-budget".to_string()),
            event_id: Some("hold-budget:reverse".to_string()),
            expected_cumulative_approval_state: None,
            authority: None,
        });
        let cached = store
            .cached_usage("cap-budget", 2)
            .ok_or_else(|| std::io::Error::other("seeded cache missing"))?;
        assert!(result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("hold/event identity")));
        assert_eq!(cached.seq, 5);
        assert_eq!(cached.invocation_count, 5);
        assert_eq!(cached.total_cost_exposed, 50);
        assert_eq!(cached.total_cost_realized_spend, 25);
    }
    Ok(())
}

#[test]
fn remote_budget_store_reconciles_only_a_locally_captured_hold(
) -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "holdId": "hold-budget",
        "eventId": "hold-budget:capture",
        "decision": "captured",
        "exposureUnits": 100,
        "invocationCountAfter": 1,
        "usageInvocationCount": 1,
        "committedCostUnitsAfter": 100,
        "totalCostExposedAfter": 100,
        "totalCostRealizedSpendAfter": 0,
        "usageSeq": 7,
        "invocationCount": 1,
        "releasedExposureUnits": 25,
        "totalExposureCharged": 0,
        "totalRealizedSpend": 75,
        "budgetCommit": {
            "budgetSeq": 8,
            "commitIndex": 8,
            "quorumCommitted": true,
            "quorumSize": 1,
            "committedNodes": 1,
            "witnessUrls": [],
            "authorityId": "local",
            "budgetTerm": 1,
            "leaseId": "local#1",
            "leaseEpoch": 1
        }
    })
    .to_string();
    let reconcile_body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "holdId": "hold-budget",
        "eventId": "hold-budget:reconcile",
        "invocationCount": 1,
        "releasedExposureUnits": 25,
        "totalExposureCharged": 0,
        "totalRealizedSpend": 75,
        "budgetCommit": {
            "budgetSeq": 8,
            "commitIndex": 8,
            "quorumCommitted": true,
            "quorumSize": 1,
            "committedNodes": 1,
            "witnessUrls": [],
            "authorityId": "local",
            "budgetTerm": 1,
            "leaseId": "local#1",
            "leaseEpoch": 1
        }
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 2);
    let store = build_remote_budget_store(&server.url, "secret")?;
    store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        hold_id: "hold-budget".to_string(),
        event_id: "hold-budget:capture".to_string(),
        trusted_time: None,
        authority: None,
    })?;
    server.set_body(&reconcile_body);
    let reconciled = store.reconcile_budget_hold(BudgetReconcileHoldRequest {
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        exposed_cost_units: 100,
        realized_spend_units: 75,
        hold_id: Some("hold-budget".to_string()),
        event_id: Some("hold-budget:reconcile".to_string()),
        authority: None,
    })?;
    assert_eq!(reconciled.invocation_state, BudgetInvocationState::Captured);
    assert_eq!(reconciled.monetary_state, BudgetMonetaryState::Reconciled);
    assert_eq!(reconciled.exposure_units, 100);
    assert_eq!(reconciled.realized_spend_units, 75);
    assert_eq!(reconciled.committed_cost_units_after, 75);
    assert_eq!(
        reconciled.metadata.event_id.as_deref(),
        Some("hold-budget:reconcile")
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_json_post(
        &requests[1],
        BUDGET_RECONCILE_SPEND_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:reconcile\"",
            "\"authorizedExposureUnits\":100",
            "\"realizedSpendUnits\":75",
        ],
    );
    Ok(())
}

#[test]
fn remote_budget_store_preserves_captured_authorize_replay_decision(
) -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 0,
        "allowed": false,
        "decision": "already_captured",
        "holdId": "hold-budget",
        "eventId": "hold-budget:original-capture",
        "exposureUnits": 100,
        "realizedSpendUnits": 0,
        "mutationInvocationCountAfter": 1,
        "mutationCommittedCostUnitsAfter": 100,
        "usageSeq": 9,
        "invocationCount": 2,
        "totalExposureCharged": 200,
        "totalRealizedSpend": 0,
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store = build_remote_budget_store(&server.url, "secret")?;

    let decision = store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: "cap-budget".to_string(),
        grant_index: 0,
        max_invocations: Some(1),
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(100),
        hold_id: Some("hold-budget".to_string()),
        event_id: Some("hold-budget:replayed-authorize".to_string()),
        authority: None,
    })?;

    let BudgetAuthorizeHoldDecision::AlreadyCaptured(mutation) = decision else {
        return Err(std::io::Error::other(
            "captured authorize replay did not fail closed with capture evidence",
        )
        .into());
    };
    assert_eq!(mutation.hold_id.as_deref(), Some("hold-budget"));
    assert_eq!(mutation.exposure_units, 100);
    assert_eq!(mutation.monetary_state, BudgetMonetaryState::Exposed);
    assert_eq!(mutation.realized_spend_units, 0);
    assert_eq!(mutation.invocation_count_after, 1);
    assert_eq!(mutation.committed_cost_units_after, 100);
    assert_eq!(
        mutation.metadata.event_id.as_deref(),
        Some("hold-budget:original-capture")
    );
    let usage = store
        .get_usage("cap-budget", 0)?
        .ok_or_else(|| std::io::Error::other("current replay usage was not cached"))?;
    assert_eq!(usage.seq, 9);
    assert_eq!(usage.invocation_count, 2);
    assert_eq!(usage.total_cost_exposed, 200);
    Ok(())
}

#[test]
fn remote_budget_store_retains_capture_when_cancellation_is_unsupported(
) -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "holdId": "hold-budget",
        "eventId": "hold-budget:capture",
        "decision": "captured",
        "invocationCountAfter": 1,
        "usageInvocationCount": 2,
        "committedCostUnitsAfter": 100,
        "exposureUnits": 100,
        "totalCostExposedAfter": 100,
        "totalCostRealizedSpendAfter": 25,
        "usageSeq": 8,
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store = build_remote_budget_store(&server.url, "secret")?;
    let _capture = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        hold_id: "hold-budget".to_string(),
        event_id: "hold-budget:capture".to_string(),
        trusted_time: None,
        authority: None,
    })?;

    let cancellation =
        store.cancel_captured_before_dispatch(BudgetCancelCapturedBeforeDispatchRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            hold_id: "hold-budget".to_string(),
            event_id: "hold-budget:cancel".to_string(),
            authority: None,
        });
    assert!(matches!(
        cancellation,
        Err(BudgetStoreError::Invariant(reason))
            if reason == "captured-before-dispatch cancellation is not supported by this budget store"
    ));
    assert_eq!(server.requests().len(), 1);

    let usage = store
        .get_usage("cap-budget", 2)?
        .ok_or_else(|| std::io::Error::other("captured usage was not retained"))?;
    assert_eq!(usage.invocation_count, 2);
    assert_eq!(usage.total_cost_exposed, 100);
    assert_eq!(usage.total_cost_realized_spend, 25);
    assert_eq!(usage.seq, 8);
    Ok(())
}

#[test]
fn remote_capture_cancel_and_authorize_replays_cannot_regress_cached_usage(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = StaticResponseServer::spawn(200, "{}", "application/json", 0);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret")?,
        cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
        captured_holds: std::sync::Mutex::new(std::collections::HashSet::new()),
    };
    store.cache_usage("cap-budget", 0, Some(12), Some(3), Some(300), Some(25))?;

    for replay_seq in [Some(4), Some(8), None] {
        store.cache_usage("cap-budget", 0, replay_seq, Some(1), Some(100), Some(0))?;
        let usage = store
            .get_usage("cap-budget", 0)?
            .ok_or_else(|| std::io::Error::other("cached usage missing"))?;
        assert_eq!(usage.seq, 12);
        assert_eq!(usage.invocation_count, 3);
        assert_eq!(usage.total_cost_exposed, 300);
        assert_eq!(usage.total_cost_realized_spend, 25);
    }
    let conflict = store.cache_usage("cap-budget", 0, Some(12), Some(4), Some(300), Some(25));
    assert!(conflict
        .as_ref()
        .is_err_and(|error| error.to_string().contains("same sequence")));
    store.cache_usage("cap-budget", 0, None, None, None, None)?;
    let usage = store
        .get_usage("cap-budget", 0)?
        .ok_or_else(|| std::io::Error::other("newer cache did not survive stale removal"))?;
    assert_eq!(usage.seq, 12);
    store.cache_usage("cap-budget", 1, Some(0), Some(1), Some(10), Some(5))?;
    store.cache_usage("cap-budget", 1, Some(1), None, None, None)?;
    let unprojected = store
        .get_usage("cap-budget", 1)?
        .ok_or_else(|| std::io::Error::other("unprojected replay removed cached usage"))?;
    assert_eq!(unprojected.seq, 0);
    assert_eq!(unprojected.invocation_count, 1);
    assert_eq!(unprojected.total_cost_exposed, 10);
    assert_eq!(unprojected.total_cost_realized_spend, 5);
    Ok(())
}

#[test]
fn remote_budget_list_cannot_regress_or_conflict_with_newer_cached_usage(
) -> Result<(), Box<dyn std::error::Error>> {
    let stale = serde_json::json!({
        "configured": true,
        "backend": "sqlite",
        "capabilityId": "cap-budget",
        "count": 1,
        "usages": [{
            "capabilityId": "cap-budget",
            "grantIndex": 0,
            "invocationCount": 1,
            "totalExposureCharged": 100,
            "totalRealizedSpend": 0,
            "updatedAt": 4,
            "seq": 4
        }]
    })
    .to_string();
    let conflict = serde_json::json!({
        "configured": true,
        "backend": "sqlite",
        "capabilityId": "cap-budget",
        "count": 1,
        "usages": [{
            "capabilityId": "cap-budget",
            "grantIndex": 0,
            "invocationCount": 4,
            "totalExposureCharged": 300,
            "totalRealizedSpend": 25,
            "updatedAt": 12,
            "seq": 12
        }]
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &stale, "application/json", 2);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret")?,
        cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
        captured_holds: std::sync::Mutex::new(std::collections::HashSet::new()),
    };
    store.cache_usage("cap-budget", 0, Some(12), Some(3), Some(300), Some(25))?;
    let stale_result = store.list_usages(10, Some("cap-budget"));
    server.set_body(&conflict);
    let conflict_result = store.list_usages(10, Some("cap-budget"));
    let cached = store
        .cached_usage("cap-budget", 0)
        .ok_or_else(|| std::io::Error::other("seeded cache missing"))?;

    let stale_result = stale_result?;
    assert_eq!(stale_result.len(), 1);
    assert_eq!(stale_result[0].seq, 12);
    assert_eq!(stale_result[0].invocation_count, 3);
    assert!(conflict_result
        .as_ref()
        .is_err_and(|error| error.to_string().contains("same sequence")));
    assert_eq!(cached.seq, 12);
    assert_eq!(cached.invocation_count, 3);
    assert_eq!(cached.total_cost_exposed, 300);
    assert_eq!(cached.total_cost_realized_spend, 25);
    Ok(())
}

#[test]
fn remote_budget_get_rejects_substituted_capability_without_partial_cache_update(
) -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "configured": true,
        "backend": "sqlite",
        "capabilityId": "cap-budget",
        "count": 2,
        "usages": [
            {
                "capabilityId": "cap-budget",
                "grantIndex": 1,
                "invocationCount": 1,
                "totalExposureCharged": 10,
                "totalRealizedSpend": 0,
                "updatedAt": 1,
                "seq": 1
            },
            {
                "capabilityId": "cap-other",
                "grantIndex": 2,
                "invocationCount": 9,
                "totalExposureCharged": 900,
                "totalRealizedSpend": 90,
                "updatedAt": 9,
                "seq": 9
            }
        ]
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret")?,
        cached_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
        captured_holds: std::sync::Mutex::new(std::collections::HashSet::new()),
    };
    let result = store.get_usage("cap-budget", 2);
    assert!(result.as_ref().is_err_and(|error| error
        .to_string()
        .contains("changed the requested capability identity")));
    assert!(store.cached_usage("cap-budget", 1).is_none());
    assert!(store.cached_usage("cap-other", 2).is_none());
    Ok(())
}

#[test]
fn legacy_authorize_response_without_decision_remains_readable(
) -> Result<(), Box<dyn std::error::Error>> {
    let allowed: TryChargeCostResponse = serde_json::from_value(serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 0,
        "allowed": true
    }))?;
    assert_eq!(
        allowed.decision,
        BudgetAuthorizeExposureDecision::Authorized
    );
    let denied: TryChargeCostResponse = serde_json::from_value(serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 0,
        "allowed": false
    }))?;
    assert_eq!(denied.decision, BudgetAuthorizeExposureDecision::Denied);
    Ok(())
}

#[test]
fn budget_transition_responses_round_trip_optional_hold_and_event_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    let reverse: ReverseChargeCostResponse = serde_json::from_value(serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "holdId": "hold-budget",
        "eventId": "hold-budget:reverse"
    }))?;
    assert_eq!(reverse.hold_id.as_deref(), Some("hold-budget"));
    assert_eq!(reverse.event_id.as_deref(), Some("hold-budget:reverse"));
    let reverse = serde_json::to_value(reverse)?;
    assert_eq!(reverse["holdId"], "hold-budget");
    assert_eq!(reverse["eventId"], "hold-budget:reverse");

    let reconcile: ReduceChargeCostResponse = serde_json::from_value(serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "holdId": "hold-budget",
        "eventId": "hold-budget:reconcile"
    }))?;
    assert_eq!(reconcile.hold_id.as_deref(), Some("hold-budget"));
    assert_eq!(reconcile.event_id.as_deref(), Some("hold-budget:reconcile"));
    let reconcile = serde_json::to_value(reconcile)?;
    assert_eq!(reconcile["holdId"], "hold-budget");
    assert_eq!(reconcile["eventId"], "hold-budget:reconcile");

    let legacy: ReverseChargeCostResponse = serde_json::from_value(serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2
    }))?;
    assert!(legacy.hold_id.is_none());
    assert!(legacy.event_id.is_none());
    Ok(())
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
        "decision": "authorized",
        "holdId": "hold-budget",
        "eventId": "hold-budget:authorize",
        "exposureUnits": 120,
        "realizedSpendUnits": 0,
        "mutationInvocationCountAfter": 5,
        "mutationCommittedCostUnitsAfter": 195,
        "usageSeq": 41,
        "invocationCount": 5,
        "totalExposureCharged": 120,
        "totalRealizedSpend": 75,
        "budgetAuthority": {
            "authorityId": "http://leader-b",
            "leaderUrl": "http://leader-b",
            "budgetTerm": 8,
            "leaseId": "http://leader-b#term-8",
            "leaseEpoch": 8,
            "leaseExpiresAt": 5000,
            "leaseTtlMs": 750,
            "guaranteeLevel": "ha_leader_visible",
            "budgetCommitIndex": 99
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
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");

    let decision = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            max_invocations: Some(9),
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
            requested_exposure_units: 120,
            max_cost_per_invocation: Some(150),
            max_total_cost_units: Some(900),
            hold_id: Some("hold-budget".to_string()),
            event_id: Some("hold-budget:authorize".to_string()),
            authority: None,
        })
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
fn authority_key_cache_from_status_validates_and_deduplicates_current_key() {
    let current = Keypair::generate().public_key().to_hex();
    let trusted_only = Keypair::generate().public_key().to_hex();

    let cache = AuthorityKeyCache::from_status(&TrustAuthorityStatus {
        configured: true,
        backend: Some("sqlite".to_string()),
        public_key: Some(current.clone()),
        generation: Some(7),
        rotated_at: Some(11),
        applies_to_future_sessions_only: false,
        trusted_public_keys: vec![trusted_only.clone()],
    })
    .test_expect("cache from valid status");

    assert_eq!(
        cache.current.as_ref().test_expect("current key").to_hex(),
        current
    );
    assert_eq!(cache.trusted.len(), 2);
    assert!(cache
        .trusted
        .iter()
        .any(|public_key| public_key.to_hex() == current));
    assert!(cache
        .trusted
        .iter()
        .any(|public_key| public_key.to_hex() == trusted_only));

    let missing_current = match AuthorityKeyCache::from_status(&TrustAuthorityStatus {
        configured: true,
        backend: None,
        public_key: None,
        generation: None,
        rotated_at: None,
        applies_to_future_sessions_only: false,
        trusted_public_keys: Vec::new(),
    }) {
        Ok(_) => panic!("missing current key should fail"),
        Err(error) => error,
    };
    assert!(missing_current
        .to_string()
        .contains("no current authority public key"));

    let unconfigured = match AuthorityKeyCache::from_status(&TrustAuthorityStatus {
        configured: false,
        backend: None,
        public_key: Some(current),
        generation: None,
        rotated_at: None,
        applies_to_future_sessions_only: false,
        trusted_public_keys: Vec::new(),
    }) {
        Ok(_) => panic!("unconfigured authority should fail"),
        Err(error) => error,
    };
    assert!(unconfigured
        .to_string()
        .contains("does not have an authority configured"));
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
