use super::super::super::*;
use super::super::budget::{
    admission_capture_request_from_view, build_remote_admission_capture_authority,
    build_remote_budget_store, canonical_revocation_set_from_view, invocation_quota_from_view,
};
use super::super::budget::{
    validate_composite_authorize_response, validate_invocation_capture_response,
};
use super::super::client::{build_client, should_retry_status};
use super::super::errors::{
    into_budget_store_error, into_receipt_store_error, into_revocation_store_error,
};
use super::super::issuance::ensure_signed_by_trusted_authority;
use super::support::{
    assert_json_post, ScriptedResponse, ScriptedResponseServer, StaticResponseServer,
    TEST_SERVER_ENDPOINT_MARKER,
};
use chio_test_support::prelude::*;

fn budget_authority_json(seq: u64) -> serde_json::Value {
    serde_json::json!({
        "authorityId": TEST_SERVER_ENDPOINT_MARKER,
        "leaderUrl": TEST_SERVER_ENDPOINT_MARKER,
        "budgetTerm": 7,
        "leaseId": format!("{TEST_SERVER_ENDPOINT_MARKER}#term-7"),
        "leaseEpoch": 7,
        "leaseExpiresAt": 5000,
        "leaseTtlMs": 750,
        "guaranteeLevel": "ha_linearizable",
        "budgetCommitIndex": seq
    })
}

fn budget_commit_json(seq: u64) -> serde_json::Value {
    serde_json::json!({
        "budgetSeq": seq,
        "commitIndex": seq,
        "quorumCommitted": true,
        "quorumSize": 1,
        "committedNodes": 1,
        "witnessUrls": [TEST_SERVER_ENDPOINT_MARKER],
        "authorityId": TEST_SERVER_ENDPOINT_MARKER,
        "budgetTerm": 7,
        "leaseId": format!("{TEST_SERVER_ENDPOINT_MARKER}#term-7"),
        "leaseEpoch": 7
    })
}

fn budget_authority_view(seq: u64, guarantee_level: &str) -> BudgetAuthorityMetadataView {
    BudgetAuthorityMetadataView {
        authority_id: "budget-primary".to_string(),
        leader_url: "http://leader-a".to_string(),
        budget_term: 7,
        lease_id: "lease-7".to_string(),
        lease_epoch: 7,
        lease_expires_at: 5_000,
        lease_ttl_ms: 750,
        guarantee_level: guarantee_level.to_string(),
        budget_commit_index: Some(seq),
        partition_escrow_evidence: None,
    }
}

fn budget_commit_view(seq: u64) -> BudgetWriteCommitView {
    BudgetWriteCommitView {
        budget_seq: seq,
        commit_index: seq,
        quorum_committed: true,
        quorum_size: 2,
        committed_nodes: 2,
        witness_urls: vec![
            "http://leader-a".to_string(),
            "http://follower-b".to_string(),
        ],
        authority_id: "budget-primary".to_string(),
        budget_term: 7,
        lease_id: "lease-7".to_string(),
        lease_epoch: 7,
    }
}

fn quota_view(
    profile: BudgetQuotaProfileView,
    owner_id: &str,
    grant_index: Option<u32>,
    max_invocations: u32,
) -> BudgetInvocationQuotaView {
    BudgetInvocationQuotaView {
        key: BudgetQuotaKeyView {
            profile,
            owner_id: owner_id.to_string(),
            grant_index,
        },
        max_invocations,
    }
}

fn canonical_revocation_set_view() -> CanonicalRevocationSetView {
    let ids = vec!["cap-budget".to_string(), "cap-root".to_string()];
    let canonical = canonical_json_bytes(&ids).test_unwrap();
    let mut digest_input = b"chio.revocation-set.v1\0".to_vec();
    digest_input.extend_from_slice(&canonical);
    CanonicalRevocationSetView {
        ids,
        digest: sha256_hex(&digest_input),
    }
}

fn composite_admission_evidence_view() -> BudgetInvocationAdmissionEvidenceView {
    BudgetInvocationAdmissionEvidenceView {
        invocation_quotas: vec![
            quota_view(
                BudgetQuotaProfileView::GrantInvocation,
                "cap-budget",
                Some(2),
                9,
            ),
            quota_view(
                BudgetQuotaProfileView::AggregateFamilyInvocation,
                &"22".repeat(32),
                None,
                4,
            ),
        ],
        revocation_set: canonical_revocation_set_view(),
        aggregate_root_capability_id: Some("cap-root".to_string()),
        aggregate_binding_digest: Some("44".repeat(32)),
        supplemental_binding: None,
        partition_escrow_evidence: None,
    }
}

fn composite_authorize_request_view() -> CompositeBudgetAuthorizeRequest {
    CompositeBudgetAuthorizeRequest {
        existing_only: false,
        operation_id: "operation-budget".to_string(),
        request_binding_hash: "44".repeat(32),
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        requested_exposure_units: 120,
        max_exposure_per_invocation: Some(150),
        max_total_exposure_units: Some(900),
        hold_id: "hold-budget".to_string(),
        event_id: "hold-budget:authorize".to_string(),
        admission_evidence: composite_admission_evidence_view(),
    }
}

fn quota_usage_views() -> Vec<BudgetInvocationQuotaUsageView> {
    composite_admission_evidence_view()
        .invocation_quotas
        .into_iter()
        .map(|quota| BudgetInvocationQuotaUsageView {
            quota,
            reserved_invocations_after: 1,
            captured_invocations_after: 0,
        })
        .collect()
}

fn composite_authorize_response_view() -> CompositeBudgetAuthorizeResponse {
    CompositeBudgetAuthorizeResponse {
        operation_id: "operation-budget".to_string(),
        request_binding_hash: "44".repeat(32),
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        hold_id: "hold-budget".to_string(),
        event_id: "hold-budget:authorize".to_string(),
        allowed: true,
        authorized_exposure_units: Some(120),
        attempted_exposure_units: None,
        committed_cost_units_after: 120,
        invocation_count_after: 1,
        invocation_counts_after: quota_usage_views(),
        invocation_state: BudgetInvocationReservationStateView::Authorized,
        monetary_state: BudgetMonetaryHoldStateView::Exposed,
        admission_evidence: composite_admission_evidence_view(),
        budget_authority: Some(budget_authority_view(41, "ha_linearizable")),
        budget_commit: Some(budget_commit_view(41)),
    }
}

fn capture_request_view() -> CaptureInvocationReservationsRequest {
    CaptureInvocationReservationsRequest {
        operation_id: "operation-budget".to_string(),
        request_binding_hash: "44".repeat(32),
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        hold_id: "hold-budget".to_string(),
        event_id: "hold-budget:capture-invocations".to_string(),
        budget_authority: Some(BudgetMutationAuthorityView {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        }),
    }
}

fn invocation_capture_response_view() -> CaptureInvocationReservationsResponse {
    let mut usages = quota_usage_views();
    for usage in &mut usages {
        usage.reserved_invocations_after = 0;
        usage.captured_invocations_after = 1;
    }
    CaptureInvocationReservationsResponse {
        operation_id: "operation-budget".to_string(),
        request_binding_hash: "44".repeat(32),
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        hold_id: "hold-budget".to_string(),
        event_id: "hold-budget:capture-invocations".to_string(),
        exposure_units: 0,
        realized_spend_units: 0,
        committed_cost_units_after: 120,
        invocation_count_after: 1,
        invocation_counts_after: usages,
        invocation_state: BudgetInvocationReservationStateView::Captured,
        monetary_state: BudgetMonetaryHoldStateView::Exposed,
        revocation_set: canonical_revocation_set_view(),
        budget_authority: Some(budget_authority_view(42, "ha_linearizable")),
        budget_commit: Some(budget_commit_view(42)),
    }
}

fn invocation_capture_response_view_for_endpoint(
    endpoint: &str,
) -> CaptureInvocationReservationsResponse {
    let mut response = invocation_capture_response_view();
    response.budget_authority = Some(BudgetAuthorityMetadataView {
        authority_id: endpoint.to_string(),
        leader_url: endpoint.to_string(),
        budget_term: 7,
        lease_id: format!("{endpoint}#admission-term-7"),
        lease_epoch: 7,
        lease_expires_at: 5_000,
        lease_ttl_ms: 750,
        guarantee_level: "ha_linearizable".to_string(),
        budget_commit_index: Some(42),
        partition_escrow_evidence: None,
    });
    response.budget_commit = Some(BudgetWriteCommitView {
        budget_seq: 42,
        commit_index: 42,
        quorum_committed: true,
        quorum_size: 1,
        committed_nodes: 1,
        witness_urls: vec![endpoint.to_string()],
        authority_id: endpoint.to_string(),
        budget_term: 7,
        lease_id: format!("{endpoint}#admission-term-7"),
        lease_epoch: 7,
    });
    response
}

fn combined_admission_capture_request_view() -> CombinedAdmissionCaptureRequest {
    let evidence = composite_admission_evidence_view();
    CombinedAdmissionCaptureRequest {
        operation_id: "operation-budget".to_string(),
        request_binding_hash: "44".repeat(32),
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        hold_id: "hold-budget".to_string(),
        event_id: "hold-budget:capture-invocations".to_string(),
        budget_authority: Some(BudgetMutationAuthorityView {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        }),
        revocation_set: evidence.revocation_set.clone(),
        bound_revocation_set_digest: evidence.revocation_set.digest,
        authorization_artifact_digests: vec!["aa".repeat(32)],
        aggregate_root_capability_id: evidence.aggregate_root_capability_id,
        aggregate_root_binding_digest: evidence.aggregate_binding_digest,
        last_observed_revocation_index: Some(0),
    }
}

fn combined_admission_capture_response(
    outcome: AdmissionCaptureOutcomeView,
) -> CombinedAdmissionCaptureResponse {
    combined_admission_capture_response_for_endpoint(outcome, "budget-primary")
}

fn combined_admission_capture_response_for_endpoint(
    outcome: AdmissionCaptureOutcomeView,
    endpoint: &str,
) -> CombinedAdmissionCaptureResponse {
    let request = combined_admission_capture_request_view();
    let captured = outcome == AdmissionCaptureOutcomeView::Captured;
    let invocation_quotas: Vec<AdmissionCaptureInvocationQuotaView> =
        composite_admission_evidence_view()
        .invocation_quotas
        .into_iter()
        .map(|quota| {
            if captured {
                AdmissionCaptureInvocationQuotaView::Transition(
                    AdmissionCaptureInvocationQuotaTransitionView {
                        key: quota.key,
                        max_invocations: quota.max_invocations,
                        reserved_invocations_before: 1,
                        reserved_invocations_after: 0,
                        captured_invocations_before: 0,
                        captured_invocations_after: 1,
                    },
                )
            } else {
                AdmissionCaptureInvocationQuotaView::Definition(quota)
            }
        })
        .collect();
    CombinedAdmissionCaptureResponse {
        operation_id: request.operation_id.clone(),
        request_binding_hash: request.request_binding_hash.clone(),
        capability_id: request.capability_id.clone(),
        grant_index: request.grant_index,
        hold_id: request.hold_id.clone(),
        event_id: request.event_id.clone(),
        outcome,
        budget: captured.then(|| invocation_capture_response_view_for_endpoint(endpoint)),
        revocation_set: request.revocation_set.clone(),
        revoked_capability_ids: if captured {
            Vec::new()
        } else {
            vec![request.capability_id.clone()]
        },
        metadata: AdmissionCaptureMetadataView {
            operation_id: request.operation_id,
            hold_id: request.hold_id,
            event_id: request.event_id,
            checked_revocation_set_digest: request.bound_revocation_set_digest,
            invocation_quotas: invocation_quotas.clone(),
            authorization_artifact_digests: request.authorization_artifact_digests,
            aggregate_root_capability_id: request.aggregate_root_capability_id,
            aggregate_root_binding_digest: request.aggregate_root_binding_digest,
            budget_commit_index: Some(42),
            revocation_commit_index: 43,
            authority_commit_index: 44,
            leader_epoch: Some(7),
            guarantee_level: BudgetGuaranteeLevelView::HaLinearizable,
            partition_escrow_evidence: None,
            authority: Some(BudgetMutationAuthorityView {
                authority_id: endpoint.to_string(),
                lease_id: format!("{endpoint}#admission-term-7"),
                lease_epoch: 7,
            }),
            invocation_state: if captured {
                BudgetInvocationReservationStateView::Captured
            } else {
                BudgetInvocationReservationStateView::Authorized
            },
            monetary_state: BudgetMonetaryHoldStateView::Exposed,
        },
    }
}

fn admission_capture_point_response(
    capture: Option<CombinedAdmissionCaptureResponse>,
) -> AdmissionCapturePointQueryResponse {
    AdmissionCapturePointQueryResponse {
        operation_id: "operation-budget".to_string(),
        request_binding_hash: "44".repeat(32),
        capture,
    }
}

fn seeded_remote_admission_capture_authority(
    endpoint: &str,
) -> RemoteAdmissionCaptureAuthority {
    let evidence = composite_admission_evidence_view();
    let invocation_quotas = evidence
        .invocation_quotas
        .iter()
        .map(invocation_quota_from_view)
        .collect::<Result<Vec<_>, _>>()
        .test_expect("native capture quotas");
    let revocation_set = canonical_revocation_set_from_view(&evidence.revocation_set)
        .test_expect("native capture revocation set");
    let admission_operation =
        BudgetAdmissionOperationBinding::new("operation-budget".to_string(), "44".repeat(32))
            .test_expect("capture admission operation");
    let authority = BudgetEventAuthority {
        authority_id: endpoint.to_string(),
        lease_id: format!("{endpoint}#admission-term-7"),
        lease_epoch: 7,
    };
    let hold = RemoteCompositeHoldEvidence {
        authorization_event_id: "hold-budget:authorize".to_string(),
        last_event_id: "hold-budget:authorize".to_string(),
        last_event_seq: 41,
        admission_operation,
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        invocation_quotas: invocation_quotas.clone(),
        invocation_counts_after: invocation_quotas
            .into_iter()
            .map(|quota| BudgetInvocationQuotaUsage {
                quota,
                reserved_invocations_after: 1,
                captured_invocations_after: 0,
            })
            .collect(),
        invocation_state: BudgetInvocationReservationState::Authorized,
        revocation_set,
        authorized_exposure_units: 120,
        remaining_exposure_units: 120,
        monetary_state: BudgetMonetaryHoldState::Exposed,
        authority,
        partition_escrow_evidence: None,
    };
    RemoteAdmissionCaptureAuthority {
        client: build_client(endpoint, "secret").test_expect("build capture client"),
        partition_escrow_authority: None,
        composite_holds: Arc::new(Mutex::new(HashMap::from([(
            "hold-budget".to_string(),
            hold,
        )]))),
    }
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
    ScriptedResponseServer::spawn_with_mutation_absence(vec![
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
fn composite_budget_client_uses_dedicated_routes_and_never_sends_authority_on_authorize() {
    let server = StaticResponseServer::spawn(200, "{}", "application/json", 3);
    let client = build_client(&server.url, "secret").test_expect("build client");

    let _ = client.authorize_composite_budget_hold(&composite_authorize_request_view());
    let _ = client.capture_invocation_reservations(&capture_request_view());
    let _ = client.query_invocation_capture(&CaptureInvocationPointQueryRequest {
        capture_request: capture_request_view(),
    });

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_json_post(
        &requests[0],
        BUDGET_AUTHORIZE_HOLD_PATH,
        &[
            "\"admissionEvidence\"",
            "\"invocationQuotas\"",
            "\"revocationSet\"",
        ],
    );
    assert!(!requests[0].body.contains("budgetAuthority"));
    assert_json_post(
        &requests[1],
        BUDGET_CAPTURE_INVOCATIONS_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:capture-invocations\"",
            "\"budgetAuthority\"",
            "\"leaseEpoch\":7",
        ],
    );
    assert_json_post(
        &requests[2],
        BUDGET_CAPTURE_INVOCATIONS_QUERY_PATH,
        &[
            "\"captureRequest\"",
            "\"operationId\":\"operation-budget\"",
            "\"eventId\":\"hold-budget:capture-invocations\"",
        ],
    );
}

#[test]
fn composite_budget_client_does_not_fallback_when_dedicated_route_is_missing() {
    let server = StaticResponseServer::spawn(404, "missing", "text/plain", 1);
    let client = build_client(&server.url, "secret").test_expect("build client");

    let error = client
        .authorize_composite_budget_hold(&composite_authorize_request_view())
        .test_expect_err("a missing composite endpoint must fail closed");

    assert!(error.to_string().contains("404"));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target, BUDGET_AUTHORIZE_HOLD_PATH);
}

#[test]
fn committed_composite_replay_uses_only_the_read_only_query_route() {
    let body = serde_json::to_string(&composite_authorize_response_view())
        .test_expect("serialize composite authorization response");
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let client = build_client(&server.url, "secret").test_expect("build client");
    let mut request = composite_authorize_request_view();
    request.existing_only = true;

    client
        .query_committed_composite_budget_authorization(&request)
        .test_expect("query committed composite authorization");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_json_post(
        &requests[0],
        BUDGET_AUTHORIZE_HOLD_QUERY_PATH,
        &[
            "\"existingOnly\":true",
            "\"eventId\":\"hold-budget:authorize\"",
            "\"admissionEvidence\"",
        ],
    );
    assert!(!requests[0].body.contains("budgetAuthority"));
}

#[test]
fn missing_committed_replay_query_never_falls_back_to_fresh_authorization() {
    let server = StaticResponseServer::spawn(404, "missing", "text/plain", 1);
    let client = build_client(&server.url, "secret").test_expect("build client");
    let mut request = composite_authorize_request_view();
    request.existing_only = true;

    let error = client
        .query_committed_composite_budget_authorization(&request)
        .test_expect_err("missing committed replay query must fail closed");

    assert!(error.to_string().contains("404"));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target, BUDGET_AUTHORIZE_HOLD_QUERY_PATH);
}

#[test]
fn composite_authorize_response_requires_exact_ordered_evidence_and_ha_commit() {
    let request = composite_authorize_request_view();
    let response = composite_authorize_response_view();
    let decision = validate_composite_authorize_response(&request, response)
        .test_expect("valid composite response");
    let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
        panic!("expected authorized composite response");
    };
    assert_eq!(authorized.invocation_counts_after.len(), 2);
    assert_eq!(authorized.invocation_count_after, 1);
    assert_eq!(
        authorized.metadata.guarantee_level,
        BudgetGuaranteeLevel::HaLinearizable
    );

    let mut changed_operation = composite_authorize_response_view();
    changed_operation.operation_id = "operation-alias".to_string();
    let error = validate_composite_authorize_response(&request, changed_operation)
        .test_expect_err("changed admission operation must fail closed");
    assert!(error.to_string().contains("identity"));

    let mut changed_request_binding = composite_authorize_response_view();
    changed_request_binding.request_binding_hash = "55".repeat(32);
    let error = validate_composite_authorize_response(&request, changed_request_binding)
        .test_expect_err("changed admission request binding must fail closed");
    assert!(error.to_string().contains("identity"));

    let mut reordered = composite_authorize_response_view();
    reordered.invocation_counts_after.swap(0, 1);
    let error = validate_composite_authorize_response(&request, reordered)
        .test_expect_err("reordered quota response must fail closed");
    assert!(error.to_string().contains("ordered invocation quota"));

    let mut changed_maximum = composite_authorize_response_view();
    changed_maximum.invocation_counts_after[1]
        .quota
        .max_invocations += 1;
    let error = validate_composite_authorize_response(&request, changed_maximum)
        .test_expect_err("changed immutable maximum must fail closed");
    assert!(error.to_string().contains("ordered invocation quota"));

    let mut changed_revocations = composite_authorize_response_view();
    changed_revocations
        .admission_evidence
        .revocation_set
        .ids
        .pop();
    let error = validate_composite_authorize_response(&request, changed_revocations)
        .test_expect_err("changed revocation set must fail closed");
    assert!(error.to_string().contains("admission evidence"));

    let mut quorum_pull_only = composite_authorize_response_view();
    quorum_pull_only.budget_authority = Some(budget_authority_view(41, "ha_quorum_commit"));
    let error = validate_composite_authorize_response(&request, quorum_pull_only)
        .test_expect_err("quorum/pull evidence must not claim linearizability");
    assert!(error.to_string().contains("HA-linearizable"));

    for guarantee in [
        "single_node_atomic",
        "partition_escrowed",
        "advisory_posthoc",
    ] {
        let mut non_linearizable = composite_authorize_response_view();
        non_linearizable.budget_authority = Some(budget_authority_view(41, guarantee));
        non_linearizable.budget_commit = None;
        let error = validate_composite_authorize_response(&request, non_linearizable)
            .test_expect_err("non-linearizable composite authority must fail closed");
        assert!(error.to_string().contains("HA-linearizable"));
    }
}

#[test]
fn invocation_capture_response_requires_cached_quota_revocation_state_and_exact_authority() {
    let request_view = composite_authorize_request_view();
    let expected_quotas = request_view
        .admission_evidence
        .invocation_quotas
        .iter()
        .map(|quota| {
            let profile = match quota.key.profile {
                BudgetQuotaProfileView::GrantInvocation => BudgetQuotaProfile::GrantInvocation,
                BudgetQuotaProfileView::AggregateCapabilityInvocation => {
                    BudgetQuotaProfile::AggregateCapabilityInvocation
                }
                BudgetQuotaProfileView::AggregateFamilyInvocation => {
                    BudgetQuotaProfile::AggregateFamilyInvocation
                }
                BudgetQuotaProfileView::SupplementalBrokerExecution => {
                    BudgetQuotaProfile::SupplementalBrokerExecution
                }
            };
            let key = BudgetQuotaKey::from_persisted_parts(
                profile,
                quota.key.owner_id.clone(),
                quota.key.grant_index,
            )
            .test_unwrap();
            BudgetInvocationQuota::from_persisted_parts(key, quota.max_invocations).test_unwrap()
        })
        .collect::<Vec<_>>();
    let expected_revocations = CanonicalRevocationSet::from_persisted_parts(
        request_view.admission_evidence.revocation_set.ids.clone(),
        request_view
            .admission_evidence
            .revocation_set
            .digest
            .clone(),
    )
    .test_unwrap();
    let request = BudgetCaptureInvocationRequest {
        admission_operation: Some(
            BudgetAdmissionOperationBinding::new("operation-budget".to_string(), "44".repeat(32))
                .test_unwrap(),
        ),
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        hold_id: Some("hold-budget".to_string()),
        event_id: Some("hold-budget:capture-invocations".to_string()),
        authority: Some(BudgetEventAuthority {
            authority_id: "budget-primary".to_string(),
            lease_id: "lease-7".to_string(),
            lease_epoch: 7,
        }),
    };

    let decision = validate_invocation_capture_response(
        &request,
        &expected_quotas,
        &expected_revocations,
        BudgetMonetaryHoldState::Exposed,
        invocation_capture_response_view(),
    )
    .test_expect("valid invocation capture response");
    assert_eq!(
        decision.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(decision.monetary_state, BudgetMonetaryHoldState::Exposed);

    let mut changed_operation = invocation_capture_response_view();
    changed_operation.operation_id = "operation-alias".to_string();
    let error = validate_invocation_capture_response(
        &request,
        &expected_quotas,
        &expected_revocations,
        BudgetMonetaryHoldState::Exposed,
        changed_operation,
    )
    .test_expect_err("changed invocation capture operation must fail closed");
    assert!(error.to_string().contains("identity"));

    let mut reordered = invocation_capture_response_view();
    reordered.invocation_counts_after.swap(0, 1);
    let error = validate_invocation_capture_response(
        &request,
        &expected_quotas,
        &expected_revocations,
        BudgetMonetaryHoldState::Exposed,
        reordered,
    )
    .test_expect_err("reordered capture quotas must fail closed");
    assert!(error.to_string().contains("ordered invocation quota"));

    let mut wrong_authority = invocation_capture_response_view();
    let wrong_metadata = wrong_authority.budget_authority.as_mut().test_unwrap();
    wrong_metadata.budget_term = 8;
    wrong_metadata.lease_id = "lease-8".to_string();
    wrong_metadata.lease_epoch = 8;
    let wrong_commit = wrong_authority.budget_commit.as_mut().test_unwrap();
    wrong_commit.budget_term = 8;
    wrong_commit.lease_id = "lease-8".to_string();
    wrong_commit.lease_epoch = 8;
    let error = validate_invocation_capture_response(
        &request,
        &expected_quotas,
        &expected_revocations,
        BudgetMonetaryHoldState::Exposed,
        wrong_authority,
    )
    .test_expect_err("capture authority mismatch must fail closed");
    assert!(error.to_string().contains("requested budget authority"));

    let mut wrong_revocation = invocation_capture_response_view();
    wrong_revocation.revocation_set.digest = "ff".repeat(32);
    let error = validate_invocation_capture_response(
        &request,
        &expected_quotas,
        &expected_revocations,
        BudgetMonetaryHoldState::Exposed,
        wrong_revocation,
    )
    .test_expect_err("capture revocation mismatch must fail closed");
    assert!(error.to_string().contains("revocation set"));
}

#[test]
fn remote_budget_invocation_capture_point_query_restores_the_exact_capture() {
    let body = serde_json::to_string(&CaptureInvocationPointQueryResponse {
        operation_id: "operation-budget".to_string(),
        request_binding_hash: "44".repeat(32),
        capture: Some(invocation_capture_response_view_for_endpoint(
            TEST_SERVER_ENDPOINT_MARKER,
        )),
    })
    .test_expect("serialize invocation capture point response");
    let server =
        StaticResponseServer::spawn_with_mutation_absence(200, &body, "application/json", 1);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret").test_expect("build client"),
        partition_escrow_authority: None,
        cached_usage: Mutex::new(HashMap::new()),
        composite_holds: Arc::new(Mutex::new(HashMap::new())),
    };
    let evidence = composite_admission_evidence_view();
    let invocation_quotas = evidence
        .invocation_quotas
        .iter()
        .map(|quota| {
            let profile = match quota.key.profile {
                BudgetQuotaProfileView::GrantInvocation => BudgetQuotaProfile::GrantInvocation,
                BudgetQuotaProfileView::AggregateCapabilityInvocation => {
                    BudgetQuotaProfile::AggregateCapabilityInvocation
                }
                BudgetQuotaProfileView::AggregateFamilyInvocation => {
                    BudgetQuotaProfile::AggregateFamilyInvocation
                }
                BudgetQuotaProfileView::SupplementalBrokerExecution => {
                    BudgetQuotaProfile::SupplementalBrokerExecution
                }
            };
            BudgetInvocationQuota::from_persisted_parts(
                BudgetQuotaKey::from_persisted_parts(
                    profile,
                    quota.key.owner_id.clone(),
                    quota.key.grant_index,
                )
                .test_unwrap(),
                quota.max_invocations,
            )
            .test_unwrap()
        })
        .collect::<Vec<_>>();
    let revocation_set = CanonicalRevocationSet::from_persisted_parts(
        evidence.revocation_set.ids,
        evidence.revocation_set.digest,
    )
    .test_unwrap();
    let admission_operation =
        BudgetAdmissionOperationBinding::new("operation-budget".to_string(), "44".repeat(32))
            .test_unwrap();
    let authority = BudgetEventAuthority {
        authority_id: server.url.clone(),
        lease_id: format!("{}#admission-term-7", server.url),
        lease_epoch: 7,
    };
    store.composite_holds.lock().test_unwrap().insert(
        "hold-budget".to_string(),
        RemoteCompositeHoldEvidence {
            authorization_event_id: "hold-budget:authorize".to_string(),
            last_event_id: "hold-budget:authorize".to_string(),
            last_event_seq: 41,
            admission_operation: admission_operation.clone(),
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            invocation_quotas: invocation_quotas.clone(),
            invocation_counts_after: invocation_quotas
                .iter()
                .cloned()
                .map(|quota| BudgetInvocationQuotaUsage {
                    quota,
                    reserved_invocations_after: 1,
                    captured_invocations_after: 0,
                })
                .collect(),
            invocation_state: BudgetInvocationReservationState::Authorized,
            revocation_set,
            authorized_exposure_units: 120,
            remaining_exposure_units: 120,
            monetary_state: BudgetMonetaryHoldState::Exposed,
            authority: authority.clone(),
            partition_escrow_evidence: None,
        },
    );
    let request = BudgetCaptureInvocationRequest {
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        hold_id: Some("hold-budget".to_string()),
        event_id: Some("hold-budget:capture-invocations".to_string()),
        authority: Some(authority),
        admission_operation: Some(admission_operation),
    };
    let captured = store
        .query_invocation_capture(&request)
        .test_expect("query remote invocation capture")
        .test_expect("persisted invocation capture");
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_json_post(
        &requests[0],
        BUDGET_CAPTURE_INVOCATIONS_QUERY_PATH,
        &[
            "\"captureRequest\"",
            "\"requestBindingHash\":\"4444444444444444444444444444444444444444444444444444444444444444\"",
            "\"eventId\":\"hold-budget:capture-invocations\"",
        ],
    );
    assert_eq!(requests[1].target, BUDGET_MUTATION_EVENT_QUERY_PATH);
}

#[test]
fn remote_admission_capture_point_query_recovers_miss_captured_and_denied() {
    let responses: Vec<ScriptedResponse> = [
        admission_capture_point_response(None),
        admission_capture_point_response(Some(combined_admission_capture_response(
            AdmissionCaptureOutcomeView::Captured,
        ))),
        admission_capture_point_response(Some(combined_admission_capture_response(
            AdmissionCaptureOutcomeView::DeniedRevoked,
        ))),
    ]
    .into_iter()
    .map(|response| ScriptedResponse {
        status: 200,
        body: serde_json::to_string(&response).test_unwrap(),
        content_type: "application/json",
    })
    .collect();
    let responses = responses
        .into_iter()
        .map(|mut response| {
            response.body = response
                .body
                .replace("budget-primary", TEST_SERVER_ENDPOINT_MARKER)
                .replace("lease-7", &format!("{TEST_SERVER_ENDPOINT_MARKER}#admission-term-7"));
            response
        })
        .collect();
    let server = ScriptedResponseServer::spawn_with_mutation_absence(responses);
    let authority = seeded_remote_admission_capture_authority(&server.url);
    let mut request_view = combined_admission_capture_request_view();
    request_view.budget_authority = Some(BudgetMutationAuthorityView {
        authority_id: server.url.clone(),
        lease_id: format!("{}#admission-term-7", server.url),
        lease_epoch: 7,
    });
    let request = admission_capture_request_from_view(&request_view)
        .test_expect("native admission capture request");

    assert!(authority
        .query_admission_capture(&request)
        .test_expect("query capture miss")
        .is_none());
    assert!(matches!(
        authority
            .query_admission_capture(&request)
            .test_expect("query captured outcome"),
        Some(AdmissionCaptureDecision::Captured { .. })
    ));
    assert!(matches!(
        authority
            .query_admission_capture(&request)
            .test_expect("query denied outcome"),
        Some(AdmissionCaptureDecision::Denied(_))
    ));

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    for captured in requests
        .into_iter()
        .filter(|request| request.target == ADMISSION_CAPTURE_QUERY_PATH)
    {
        assert_json_post(
            &captured,
            ADMISSION_CAPTURE_QUERY_PATH,
            &[
                "\"captureRequest\":",
                "\"operationId\":\"operation-budget\"",
                &format!("\"requestBindingHash\":\"{}\"", "44".repeat(32)),
            ],
        );
    }
}

#[test]
fn remote_admission_capture_point_query_rejects_rebinding_and_malformed_bodies() {
    let mut changed_operation = admission_capture_point_response(None);
    changed_operation.operation_id = "other-operation".to_string();
    let mut changed_binding = admission_capture_point_response(None);
    changed_binding.request_binding_hash = "55".repeat(32);
    let mut changed_capture =
        combined_admission_capture_response(AdmissionCaptureOutcomeView::DeniedRevoked);
    changed_capture.request_binding_hash = "66".repeat(32);
    let rebound_capture = admission_capture_point_response(Some(changed_capture));
    let mut malformed = serde_json::to_value(admission_capture_point_response(None)).test_unwrap();
    malformed
        .as_object_mut()
        .test_expect("point-query response object")
        .insert("unknown".to_string(), serde_json::json!(true));
    let server = ScriptedResponseServer::spawn(vec![
        ScriptedResponse {
            status: 200,
            body: serde_json::to_string(&changed_operation).test_unwrap(),
            content_type: "application/json",
        },
        ScriptedResponse {
            status: 200,
            body: serde_json::to_string(&changed_binding).test_unwrap(),
            content_type: "application/json",
        },
        ScriptedResponse {
            status: 200,
            body: serde_json::to_string(&rebound_capture).test_unwrap(),
            content_type: "application/json",
        },
        ScriptedResponse {
            status: 200,
            body: serde_json::to_string(&malformed).test_unwrap(),
            content_type: "application/json",
        },
    ]);
    let authority = build_remote_admission_capture_authority(&server.url, "secret")
        .test_expect("build remote capture authority");
    let request = admission_capture_request_from_view(&combined_admission_capture_request_view())
        .test_expect("native admission capture request");

    for expected in ["operation binding", "operation binding", "bound identity"] {
        let error = authority
            .query_admission_capture(&request)
            .test_expect_err("rebound query response must fail closed");
        assert!(error.to_string().contains(expected), "{error}");
    }
    assert!(matches!(
        authority.query_admission_capture(&request),
        Err(AdmissionCaptureError::Unavailable(_))
    ));
}

#[test]
fn remote_budget_store_authority_apis_include_budget_event_identity() {
    let server =
        StaticResponseServer::spawn_with_mutation_absence(200, "{}", "application/json", 5);
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret").test_expect("build client"),
        partition_escrow_authority: None,
        cached_usage: Mutex::new(HashMap::new()),
        composite_holds: Arc::new(Mutex::new(HashMap::new())),
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
        admission_operation: None,
        capability_id: "cap-budget".to_string(),
        grant_index: 2,
        exposed_cost_units: 120,
        realized_spend_units: 75,
        hold_id: Some("hold-budget".to_string()),
        event_id: Some("hold-budget:capture".to_string()),
        authority: Some(capture_authority),
    });

    let requests = server.requests();
    let requests = requests
        .into_iter()
        .filter(|request| request.target != BUDGET_MUTATION_EVENT_QUERY_PATH)
        .collect::<Vec<_>>();
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
            "guaranteeLevel": "ha_linearizable",
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
        partition_escrow_authority: None,
        cached_usage: Mutex::new(HashMap::new()),
        composite_holds: Arc::new(Mutex::new(HashMap::new())),
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
        "totalRealizedSpend": 0,
        "budgetAuthority": budget_authority_json(41),
        "budgetCommit": budget_commit_json(41)
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
    assert!(authorized.metadata.authority.is_some());
    assert_eq!(
        authorized.metadata.guarantee_level,
        BudgetGuaranteeLevel::HaLinearizable
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
        "budgetAuthority": budget_authority_json(42),
        "budgetCommit": budget_commit_json(42)
    })
    .to_string();
    let server =
        scripted_transition_server(denied_response, later_authorize_response(43, 2, 90, 0));
    let store = RemoteBudgetStore {
        client: build_client(&server.url, "secret").test_expect("build client"),
        partition_escrow_authority: None,
        cached_usage: Mutex::new(HashMap::new()),
        composite_holds: Arc::new(Mutex::new(HashMap::new())),
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
        "budgetAuthority": budget_authority_json(42),
        "budgetCommit": budget_commit_json(42)
    })
    .to_string();
    let server =
        StaticResponseServer::spawn_with_mutation_absence(200, &body, "application/json", 1);
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");

    let captured = store
        .capture_budget_hold(BudgetCaptureHoldRequest {
            admission_operation: None,
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
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].target, BUDGET_MUTATION_EVENT_QUERY_PATH);
    assert_json_post(
        &requests[1],
        BUDGET_CAPTURE_EXPOSURE_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:capture\"",
        ],
    );
    assert_eq!(requests[2].target, BUDGET_MUTATION_EVENT_QUERY_PATH);
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
        "budgetAuthority": budget_authority_json(42),
        "budgetCommit": budget_commit_json(42)
    })
    .to_string();
    let later_authorize_response = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "invocationCount": 2,
        "totalExposureCharged": 10,
        "totalRealizedSpend": 75,
        "budgetAuthority": budget_authority_json(43),
        "budgetCommit": budget_commit_json(43)
    })
    .to_string();
    let server = ScriptedResponseServer::spawn_with_mutation_absence(vec![
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
        authority_id: server.url.clone(),
        lease_id: format!("{}#term-7", server.url),
        lease_epoch: 7,
    };
    let request = BudgetCaptureHoldRequest {
        admission_operation: None,
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
        admission_operation: None,
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
