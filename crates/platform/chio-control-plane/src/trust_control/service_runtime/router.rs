use super::super::active_defense_handlers::{
    handle_active_defense_event, handle_active_defense_health,
};
use super::super::cluster::{
    handle_budget_mutation_event_replica_query, handle_internal_admission_append_entries,
    handle_internal_admission_capture_query, handle_internal_admission_proposal,
    handle_internal_admission_request_vote, handle_internal_admission_snapshot,
    handle_internal_admission_snapshot_install, handle_internal_authority_snapshot,
    handle_internal_budgets_delta, handle_internal_child_receipts_delta,
    handle_internal_cluster_snapshot, handle_internal_cluster_status,
    handle_internal_committed_composite_authorization_query,
    handle_internal_invocation_capture_query, handle_internal_lineage_delta,
    handle_internal_revocations_delta, handle_internal_tool_receipts_delta,
};
use super::super::dashboard_auth::{
    handle_create_dashboard_session, handle_delete_dashboard_session, handle_get_dashboard_session,
};
use super::super::dashboard_reports::{
    install_dashboard_report_fallback, install_dashboard_report_routes,
};
use super::super::*;
use axum::extract::DefaultBodyLimit;

/// Body-size ceiling for evidence import, overriding the service-wide 1 MiB cap
/// on this one route. An exported evidence bundle legitimately embeds many
/// receipts plus its manifest and transparency data, so a whole-bundle import
/// routinely exceeds the general request cap; it still needs a bound so the
/// buffered `Json` decode cannot grow without limit.
const EVIDENCE_IMPORT_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Body-size ceiling for a stream-receipt append, overriding the service-wide
/// 1 MiB cap on the two receipt-append routes. A stream receipt embeds one
/// 64-hex-char chunk digest per retained chunk, and a kernel retains up to its
/// configured chunk cap (over a million chunks by default), so a full receipt
/// (a sidecar sync or a cross-node replication of a receipt that was valid under
/// the receipt format) runs to tens of MiB and dwarfs the general request cap.
/// The bound covers the default chunk ceiling (around 67 MiB of digests) with
/// room for the surrounding receipt envelope, while still bounding the buffered
/// `Json` decode so an oversized body cannot grow without limit.
const RECEIPT_APPEND_MAX_BODY_BYTES: usize = 128 * 1024 * 1024;

/// Two protocol-bounded canonical byte arrays encoded as JSON number arrays,
/// plus the fixed event envelope.
const ACTIVE_DEFENSE_EVENT_MAX_BODY_BYTES: usize = 9 * 1024 * 1024;

pub(crate) fn build_router(state: TrustServiceState) -> Router {
    // Seed the fixed alert-pack label sets at zero before this serve process can
    // be scraped. The trust-control /metrics route renders the fail-open /
    // dispatch-failure / capability-revocation families, but unlike the chio-cli,
    // chio-wall, and tower startup paths the service-runtime does not otherwise
    // call preregister_known_label_sets. On a fresh, healthy-but-quiet control
    // plane those families would be absent, so the shipped absent_over_time
    // backstops would page on a scrape gap that never happened. Idempotent.
    chio_metrics_spec::runtime::preregister_known_label_sets();

    let router = trust_control_health::install_health_routes(Router::new())
        .route(
            DASHBOARD_SESSION_PATH,
            get(handle_get_dashboard_session)
                .post(handle_create_dashboard_session)
                .delete(handle_delete_dashboard_session)
                .layer::<_, std::convert::Infallible>(DefaultBodyLimit::max(4 * 1024))
                .layer(SetResponseHeaderLayer::overriding(
                    axum::http::header::CACHE_CONTROL,
                    HeaderValue::from_static("no-store"),
                )),
        )
        .route(
            ACTIVE_DEFENSE_HEALTH_PATH,
            get(handle_active_defense_health),
        )
        .route(
            ACTIVE_DEFENSE_EVENTS_PATH,
            post(handle_active_defense_event)
                .layer(DefaultBodyLimit::max(ACTIVE_DEFENSE_EVENT_MAX_BODY_BYTES)),
        )
        .route(
            AUTHORITY_PATH,
            get(handle_authority_status).post(handle_rotate_authority),
        )
        .route(
            AUTHORITY_KEY_LOG_SYNC_PATH,
            post(handle_authority_key_log_sync).layer(DefaultBodyLimit::max(4 * 1024)),
        )
        .route(ISSUE_CAPABILITY_PATH, post(handle_issue_capability))
        .route(
            AGGREGATE_FAMILY_ROOT_LOOKUP_PATH,
            get(handle_lookup_aggregate_family_root),
        )
        .route(FEDERATED_ISSUE_PATH, post(handle_federated_issue))
        .route(SCIM_USERS_PATH, post(handle_scim_create_user))
        .route(SCIM_USER_PATH, delete(handle_scim_delete_user))
        .route(
            FEDERATION_PROVIDERS_PATH,
            get(handle_list_enterprise_providers),
        )
        .route(
            FEDERATION_PROVIDER_PATH,
            get(handle_get_enterprise_provider)
                .put(handle_upsert_enterprise_provider)
                .delete(handle_delete_enterprise_provider),
        )
        .route(
            FEDERATION_POLICIES_PATH,
            get(handle_list_federation_policies),
        )
        .route(
            FEDERATION_POLICY_PATH,
            get(handle_get_federation_policy)
                .put(handle_upsert_federation_policy)
                .delete(handle_delete_federation_policy),
        )
        .route(
            FEDERATION_POLICY_EVALUATE_PATH,
            post(handle_evaluate_federation_policy),
        )
        .route(
            CERTIFICATIONS_PATH,
            get(handle_list_certifications).post(handle_publish_certification),
        )
        .route(CERTIFICATION_PATH, get(handle_get_certification))
        .route(
            CERTIFICATION_RESOLVE_PATH,
            get(handle_resolve_certification),
        )
        .route(
            CERTIFICATION_DISCOVERY_PATH,
            post(handle_publish_certification_network),
        )
        .route(
            CERTIFICATION_DISCOVERY_RESOLVE_PATH,
            get(handle_discover_certification),
        )
        .route(
            CERTIFICATION_DISCOVERY_SEARCH_PATH,
            get(handle_search_certification_marketplace),
        )
        .route(
            CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH,
            get(handle_transparency_certification_marketplace),
        )
        .route(
            CERTIFICATION_DISCOVERY_CONSUME_PATH,
            post(handle_consume_certification_marketplace),
        )
        .route(CERTIFICATION_REVOKE_PATH, post(handle_revoke_certification))
        .route(
            CERTIFICATION_DISPUTE_PATH,
            post(handle_dispute_certification),
        )
        .route(
            PUBLIC_CERTIFICATION_METADATA_PATH,
            get(handle_public_certification_metadata),
        )
        .route(
            PUBLIC_CERTIFICATION_RESOLVE_PATH,
            get(handle_public_resolve_certification),
        )
        .route(
            PUBLIC_CERTIFICATION_SEARCH_PATH,
            get(handle_public_search_certifications),
        )
        .route(
            PUBLIC_CERTIFICATION_TRANSPARENCY_PATH,
            get(handle_public_certification_transparency),
        )
        .route(
            PUBLIC_GENERIC_NAMESPACE_PATH,
            get(handle_public_generic_namespace),
        )
        .route(
            PUBLIC_GENERIC_LISTINGS_PATH,
            get(handle_public_generic_listings),
        )
        .route(
            GENERIC_TRUST_ACTIVATION_ISSUE_PATH,
            post(handle_issue_generic_trust_activation),
        )
        .route(
            GENERIC_TRUST_ACTIVATION_EVALUATE_PATH,
            post(handle_evaluate_generic_trust_activation),
        )
        .route(
            GENERIC_GOVERNANCE_CHARTER_ISSUE_PATH,
            post(handle_issue_generic_governance_charter),
        )
        .route(
            GENERIC_GOVERNANCE_CASE_ISSUE_PATH,
            post(handle_issue_generic_governance_case),
        )
        .route(
            GENERIC_GOVERNANCE_CASE_EVALUATE_PATH,
            post(handle_evaluate_generic_governance_case),
        )
        .route(
            OPEN_MARKET_FEE_SCHEDULE_ISSUE_PATH,
            post(handle_issue_open_market_fee_schedule),
        )
        .route(
            OPEN_MARKET_PENALTY_ISSUE_PATH,
            post(handle_issue_open_market_penalty),
        )
        .route(
            OPEN_MARKET_PENALTY_EVALUATE_PATH,
            post(handle_evaluate_open_market_penalty),
        )
        .route(
            PASSPORT_ISSUER_METADATA_PATH,
            get(handle_passport_issuer_metadata),
        )
        .route(
            PUBLIC_PASSPORT_ISSUER_DISCOVERY_PATH,
            get(handle_public_passport_issuer_discovery),
        )
        .route(
            PUBLIC_PASSPORT_VERIFIER_DISCOVERY_PATH,
            get(handle_public_passport_verifier_discovery),
        )
        .route(
            PUBLIC_PASSPORT_DISCOVERY_TRANSPARENCY_PATH,
            get(handle_public_passport_discovery_transparency),
        )
        .route(PASSPORT_ISSUER_JWKS_PATH, get(handle_passport_issuer_jwks))
        .route(
            PASSPORT_SD_JWT_TYPE_METADATA_PATH,
            get(handle_passport_sd_jwt_type_metadata),
        )
        .route(
            CHIO_PASSPORT_JWT_VC_JSON_TYPE_METADATA_PATH,
            get(handle_passport_jwt_vc_json_type_metadata),
        )
        .route(
            PASSPORT_ISSUANCE_OFFERS_PATH,
            post(handle_create_passport_issuance_offer),
        )
        .route(
            PASSPORT_ISSUANCE_TOKEN_PATH,
            post(handle_redeem_passport_issuance_token),
        )
        .route(
            PASSPORT_ISSUANCE_CREDENTIAL_PATH,
            post(handle_redeem_passport_issuance_credential),
        )
        .route(
            PASSPORT_STATUSES_PATH,
            get(handle_list_passport_statuses).post(handle_publish_passport_status),
        )
        .route(PASSPORT_STATUS_PATH, get(handle_get_passport_status))
        .route(
            PASSPORT_STATUS_RESOLVE_PATH,
            get(handle_resolve_passport_status),
        )
        .route(
            PUBLIC_PASSPORT_STATUS_RESOLVE_PATH,
            get(handle_public_resolve_passport_status),
        )
        .route(
            PASSPORT_STATUS_REVOKE_PATH,
            post(handle_revoke_passport_status),
        )
        .route(
            PASSPORT_VERIFIER_POLICIES_PATH,
            get(handle_list_verifier_policies),
        )
        .route(
            PASSPORT_VERIFIER_POLICY_PATH,
            get(handle_get_verifier_policy)
                .put(handle_upsert_verifier_policy)
                .delete(handle_delete_verifier_policy),
        )
        .route(
            PASSPORT_CHALLENGES_PATH,
            post(handle_create_passport_challenge),
        )
        .route(
            PASSPORT_CHALLENGE_VERIFY_PATH,
            post(handle_verify_passport_challenge),
        )
        .route(
            PUBLIC_PASSPORT_CHALLENGE_PATH,
            get(handle_public_get_passport_challenge),
        )
        .route(
            PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH,
            post(handle_public_verify_passport_challenge),
        )
        .route(
            OID4VP_VERIFIER_METADATA_PATH,
            get(handle_oid4vp_verifier_metadata),
        )
        .route(
            PASSPORT_OID4VP_REQUESTS_PATH,
            post(handle_create_oid4vp_request),
        )
        .route(
            PUBLIC_PASSPORT_WALLET_EXCHANGE_PATH,
            get(handle_public_get_wallet_exchange),
        )
        .route(
            PUBLIC_PASSPORT_OID4VP_REQUEST_PATH,
            get(handle_public_get_oid4vp_request),
        )
        .route(
            PUBLIC_PASSPORT_OID4VP_LAUNCH_PATH,
            get(handle_public_launch_oid4vp_request),
        )
        .route(
            PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH,
            post(handle_public_submit_oid4vp_response),
        )
        .route(
            REVOCATIONS_PATH,
            get(handle_list_revocations).post(handle_revoke_capability),
        )
        .route(
            TOOL_RECEIPTS_PATH,
            get(handle_list_tool_receipts)
                .post(handle_append_tool_receipt)
                .layer(DefaultBodyLimit::max(RECEIPT_APPEND_MAX_BODY_BYTES)),
        )
        .route(
            CHILD_RECEIPTS_PATH,
            get(handle_list_child_receipts)
                .post(handle_append_child_receipt)
                .layer(DefaultBodyLimit::max(RECEIPT_APPEND_MAX_BODY_BYTES)),
        )
        .route(BUDGETS_PATH, get(handle_list_budgets))
        .route(BUDGET_INCREMENT_PATH, post(handle_try_increment_budget))
        .route(BUDGET_AUTHORIZE_EXPOSURE_PATH, post(handle_try_charge_cost))
        .route(
            BUDGET_AUTHORIZE_HOLD_PATH,
            post(handle_authorize_composite_budget_hold),
        )
        .route(
            BUDGET_AUTHORIZE_HOLD_QUERY_PATH,
            post(handle_query_committed_composite_budget_authorization),
        )
        .route(
            BUDGET_CAPTURE_INVOCATIONS_PATH,
            post(handle_capture_invocation_reservations),
        )
        .route(
            BUDGET_CAPTURE_INVOCATIONS_QUERY_PATH,
            post(handle_invocation_capture_point_query),
        )
        .route(
            ADMISSION_CAPTURE_PATH,
            post(handle_combined_admission_capture),
        )
        .route(
            ADMISSION_CAPTURE_QUERY_PATH,
            post(handle_admission_capture_point_query),
        )
        .route(
            BUDGET_RELEASE_EXPOSURE_PATH,
            post(handle_reverse_charge_cost),
        )
        .route(BUDGET_RECONCILE_SPEND_PATH, post(handle_reduce_charge_cost))
        .route(
            BUDGET_CAPTURE_EXPOSURE_PATH,
            post(handle_capture_budget_hold),
        )
        .route(
            BUDGET_MUTATION_EVENT_QUERY_PATH,
            post(handle_budget_mutation_event_replica_query),
        )
        .route(
            INTERNAL_CLUSTER_STATUS_PATH,
            get(handle_internal_cluster_status),
        )
        .route(
            INTERNAL_CLUSTER_SNAPSHOT_PATH,
            get(handle_internal_cluster_snapshot),
        )
        .route(
            INTERNAL_ADMISSION_REQUEST_VOTE_PATH,
            post(handle_internal_admission_request_vote),
        )
        .route(
            INTERNAL_ADMISSION_APPEND_ENTRIES_PATH,
            post(handle_internal_admission_append_entries),
        )
        .route(
            INTERNAL_ADMISSION_PROPOSAL_PATH,
            post(handle_internal_admission_proposal),
        )
        .route(
            INTERNAL_ADMISSION_CAPTURE_QUERY_PATH,
            post(handle_internal_admission_capture_query),
        )
        .route(
            INTERNAL_COMPOSITE_AUTHORIZE_QUERY_PATH,
            post(handle_internal_committed_composite_authorization_query),
        )
        .route(
            INTERNAL_INVOCATION_CAPTURE_QUERY_PATH,
            post(handle_internal_invocation_capture_query),
        )
        .route(
            INTERNAL_ADMISSION_SNAPSHOT_PATH,
            get(handle_internal_admission_snapshot)
                .post(handle_internal_admission_snapshot_install),
        )
        .route(
            INTERNAL_AUTHORITY_SNAPSHOT_PATH,
            get(handle_internal_authority_snapshot),
        )
        .route(
            INTERNAL_REVOCATIONS_DELTA_PATH,
            get(handle_internal_revocations_delta),
        )
        .route(
            INTERNAL_TOOL_RECEIPTS_DELTA_PATH,
            get(handle_internal_tool_receipts_delta),
        )
        .route(
            INTERNAL_CHILD_RECEIPTS_DELTA_PATH,
            get(handle_internal_child_receipts_delta),
        )
        .route(
            INTERNAL_BUDGETS_DELTA_PATH,
            get(handle_internal_budgets_delta),
        )
        .route(
            INTERNAL_LINEAGE_DELTA_PATH,
            get(handle_internal_lineage_delta),
        )
        .route(RECEIPT_QUERY_PATH, get(handle_query_receipts))
        .route(RECEIPT_ANALYTICS_PATH, get(handle_receipt_analytics))
        .route(EVIDENCE_EXPORT_PATH, post(handle_evidence_export))
        .route(
            EVIDENCE_IMPORT_PATH,
            post(handle_evidence_import)
                .layer(DefaultBodyLimit::max(EVIDENCE_IMPORT_MAX_BODY_BYTES)),
        )
        .route(
            FEDERATION_EVIDENCE_SHARES_PATH,
            get(handle_shared_evidence_report),
        )
        .route(COST_ATTRIBUTION_PATH, get(handle_cost_attribution_report))
        .route(OPERATOR_REPORT_PATH, get(handle_operator_report))
        .route(
            COMPTROLLER_SURFACE_PATH,
            get(handle_comptroller_surface_report),
        )
        .route(
            RUNTIME_ATTESTATION_APPRAISAL_PATH,
            post(handle_runtime_attestation_appraisal_report),
        )
        .route(
            RUNTIME_ATTESTATION_APPRAISAL_RESULT_PATH,
            post(handle_runtime_attestation_appraisal_result_export),
        )
        .route(
            RUNTIME_ATTESTATION_APPRAISAL_IMPORT_PATH,
            post(handle_runtime_attestation_appraisal_import),
        )
        .route(BEHAVIORAL_FEED_PATH, get(handle_behavioral_feed_report))
        .route(EXPOSURE_LEDGER_PATH, get(handle_exposure_ledger_report))
        .route(CREDIT_SCORECARD_PATH, get(handle_credit_scorecard_report))
        .route(CAPITAL_BOOK_PATH, get(handle_capital_book_report))
        .route(
            CAPITAL_INSTRUCTION_ISSUE_PATH,
            post(handle_issue_capital_execution_instruction),
        )
        .route(
            CAPITAL_ALLOCATION_ISSUE_PATH,
            post(handle_issue_capital_allocation_decision),
        )
        .route(
            CREDIT_FACILITY_REPORT_PATH,
            get(handle_credit_facility_report),
        )
        .route(
            CREDIT_FACILITY_ISSUE_PATH,
            post(handle_issue_credit_facility),
        )
        .route(
            CREDIT_FACILITIES_REPORT_PATH,
            get(handle_query_credit_facilities),
        )
        .route(CREDIT_BOND_REPORT_PATH, get(handle_credit_bond_report))
        .route(CREDIT_BOND_ISSUE_PATH, post(handle_issue_credit_bond))
        .route(CREDIT_BONDS_REPORT_PATH, get(handle_query_credit_bonds))
        .route(
            CREDIT_BONDED_EXECUTION_SIMULATION_PATH,
            post(handle_credit_bonded_execution_simulation_report),
        )
        .route(
            CREDIT_LOSS_LIFECYCLE_REPORT_PATH,
            get(handle_credit_loss_lifecycle_report),
        )
        .route(
            CREDIT_LOSS_LIFECYCLE_ISSUE_PATH,
            post(handle_issue_credit_loss_lifecycle),
        )
        .route(
            CREDIT_LOSS_LIFECYCLE_LIST_PATH,
            get(handle_query_credit_loss_lifecycle),
        )
        .route(CREDIT_BACKTEST_PATH, get(handle_credit_backtest_report))
        .route(
            CREDIT_PROVIDER_RISK_PACKAGE_PATH,
            get(handle_credit_provider_risk_package_report),
        )
        .route(
            LIABILITY_PROVIDER_ISSUE_PATH,
            post(handle_issue_liability_provider),
        )
        .route(
            LIABILITY_PROVIDERS_REPORT_PATH,
            get(handle_query_liability_providers),
        )
        .route(
            LIABILITY_PROVIDER_RESOLVE_PATH,
            get(handle_resolve_liability_provider),
        )
        .route(
            LIABILITY_QUOTE_REQUEST_ISSUE_PATH,
            post(handle_issue_liability_quote_request),
        )
        .route(
            LIABILITY_QUOTE_RESPONSE_ISSUE_PATH,
            post(handle_issue_liability_quote_response),
        )
        .route(
            LIABILITY_PRICING_AUTHORITY_ISSUE_PATH,
            post(handle_issue_liability_pricing_authority),
        )
        .route(
            LIABILITY_PLACEMENT_ISSUE_PATH,
            post(handle_issue_liability_placement),
        )
        .route(
            LIABILITY_BOUND_COVERAGE_ISSUE_PATH,
            post(handle_issue_liability_bound_coverage),
        )
        .route(
            LIABILITY_AUTO_BIND_DECISION_ISSUE_PATH,
            post(handle_issue_liability_auto_bind),
        )
        .route(
            LIABILITY_MARKET_WORKFLOW_REPORT_PATH,
            get(handle_query_liability_market_workflows),
        )
        .route(
            LIABILITY_CLAIM_PACKAGE_ISSUE_PATH,
            post(handle_issue_liability_claim_package),
        )
        .route(
            LIABILITY_CLAIM_RESPONSE_ISSUE_PATH,
            post(handle_issue_liability_claim_response),
        )
        .route(
            LIABILITY_CLAIM_DISPUTE_ISSUE_PATH,
            post(handle_issue_liability_claim_dispute),
        )
        .route(
            LIABILITY_CLAIM_ADJUDICATION_ISSUE_PATH,
            post(handle_issue_liability_claim_adjudication),
        )
        .route(
            LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ISSUE_PATH,
            post(handle_issue_liability_claim_payout_instruction),
        )
        .route(
            LIABILITY_CLAIM_PAYOUT_RECEIPT_ISSUE_PATH,
            post(handle_issue_liability_claim_payout_receipt),
        )
        .route(
            LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ISSUE_PATH,
            post(handle_issue_liability_claim_settlement_instruction),
        )
        .route(
            LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ISSUE_PATH,
            post(handle_issue_liability_claim_settlement_receipt),
        )
        .route(
            LIABILITY_CLAIM_WORKFLOW_REPORT_PATH,
            get(handle_query_liability_claim_workflows),
        )
        .route(SETTLEMENT_REPORT_PATH, get(handle_settlement_report))
        .route(
            SETTLEMENT_RECONCILE_PATH,
            post(handle_record_settlement_reconciliation),
        )
        .route(
            METERED_BILLING_REPORT_PATH,
            get(handle_metered_billing_report),
        )
        .route(
            METERED_BILLING_RECONCILE_PATH,
            post(handle_record_metered_billing_reconciliation),
        )
        .route(
            ECONOMIC_RECEIPT_REPORT_PATH,
            get(handle_economic_receipt_report),
        )
        .route(
            ECONOMIC_COMPLETION_FLOW_REPORT_PATH,
            get(handle_economic_completion_flow_report),
        )
        .route(
            AUTHORIZATION_CONTEXT_REPORT_PATH,
            get(handle_authorization_context_report),
        )
        .route(
            AUTHORIZATION_PROFILE_METADATA_PATH,
            get(handle_authorization_profile_metadata_report),
        )
        .route(
            AUTHORIZATION_REVIEW_PACK_PATH,
            get(handle_authorization_review_pack_report),
        )
        .route(
            UNDERWRITING_INPUT_PATH,
            get(handle_underwriting_policy_input),
        )
        .route(
            UNDERWRITING_DECISION_PATH,
            get(handle_underwriting_decision_report),
        )
        .route(
            UNDERWRITING_SIMULATION_PATH,
            post(handle_underwriting_simulation_report),
        )
        .route(
            UNDERWRITING_DECISIONS_REPORT_PATH,
            get(handle_query_underwriting_decisions),
        )
        .route(
            UNDERWRITING_DECISION_ISSUE_PATH,
            post(handle_issue_underwriting_decision),
        )
        .route(
            UNDERWRITING_APPEALS_PATH,
            post(handle_create_underwriting_appeal),
        )
        .route(
            UNDERWRITING_APPEAL_RESOLVE_PATH,
            post(handle_resolve_underwriting_appeal),
        )
        .route(LOCAL_REPUTATION_PATH, get(handle_local_reputation))
        .route(REPUTATION_COMPARE_PATH, post(handle_reputation_compare))
        .route(
            PORTABLE_REPUTATION_SUMMARY_ISSUE_PATH,
            post(handle_issue_portable_reputation_summary),
        )
        .route(
            PORTABLE_NEGATIVE_EVENT_ISSUE_PATH,
            post(handle_issue_portable_negative_event),
        )
        .route(
            PORTABLE_REPUTATION_EVALUATE_PATH,
            post(handle_evaluate_portable_reputation),
        )
        .route(LINEAGE_RECORD_PATH, post(handle_record_lineage_snapshot))
        .route(LINEAGE_PATH, get(handle_get_lineage))
        .route(LINEAGE_CHAIN_PATH, get(handle_get_delegation_chain))
        .route(AGENT_RECEIPTS_PATH, get(handle_agent_receipts))
        // Prometheus scrape endpoint, composed from the kernel guard families and
        // the alert-pack families. Inherits the same serving posture as the other
        // trust-control routes.
        .route("/metrics", get(handle_trust_control_metrics));

    let router = if state.dashboard_report_bridge.is_some() {
        install_dashboard_report_routes(router)
    } else {
        router
    };
    let router = install_dashboard_report_fallback(router);

    // Wire the dashboard SPA after all API routes so it acts as a catch-all.
    // API routes registered above take priority over the fallback service.
    // The conditional avoids a hard startup failure when the dashboard has not
    // been built (e.g. in CI or API-only deployments).
    let dashboard_dir = std::path::Path::new(DASHBOARD_DIST_DIR);
    let router = if dashboard_dir.join("index.html").exists() {
        let spa_fallback = ServeFile::new(dashboard_dir.join("index.html"));
        let spa_service = ServeDir::new(dashboard_dir).not_found_service(spa_fallback);
        router.fallback_service(spa_service)
    } else {
        warn!(
            "dashboard/dist/index.html not found -- dashboard UI will not be served. \
             Run 'npm run build' in crates/products/chio-cli/dashboard/ to enable."
        );
        router
    };

    let router = router.with_state(state);

    // Dashboard SPA is served from the same origin via ServeDir -- no CORS
    // headers needed.

    // Apply Content-Security-Policy to every response to restrict resource
    // loading to same-origin and prevent XSS escalation.
    let csp_value = HeaderValue::from_static(CSP_VALUE);
    router.layer(SetResponseHeaderLayer::overriding(
        axum::http::header::CONTENT_SECURITY_POLICY,
        csp_value,
    ))
}

/// Prometheus scrape body for the trust-control surface: the kernel guard
/// families plus the alert-pack families, composed (never fabricated) from the
/// chio-metrics-spec runtime families.
///
/// The route shares the trust-control listener, which binds `config.listen` and
/// may be externally reachable, so it fails closed: it requires the SAME
/// service-token bearer auth the authority/receipt/passport/budget routes
/// enforce before returning operational counters and guard labels. Prometheus
/// scrapes it with a configured bearer token.
async fn handle_trust_control_metrics(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = super::super::report_validation::validate_service_auth(
        &headers,
        &state.config.service_token,
    ) {
        return response;
    }
    let alert_pack = || {
        let mut out = String::new();
        chio_metrics_spec::runtime::render_alert_pack_families(&mut out);
        out
    };
    let body = chio_metrics_spec::runtime::compose_metrics_body(&[
        &chio_kernel::render_guard_metrics_prometheus,
        &alert_pack,
    ]);
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::super::super::*;
    use super::handle_trust_control_metrics;
    use chio_test_support::prelude::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn metrics_state(service_token: &str) -> TrustServiceState {
        let config = TrustServiceConfig {
            listen: "127.0.0.1:0".parse().test_unwrap(),
            service_token: service_token.to_string(),
            dashboard_read_token: Some("dashboard-secret".to_string()),
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
            partition_escrow_authority: None,
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
        };
        TrustServiceState {
            config,
            dashboard_sessions: dashboard_auth::DashboardSessionStore::production(),
            dashboard_report_bridge: None,
            authority_keyring: None,
            authority_test_backend: None,
            active_defense: super::super::TrustControlActiveDefenseService::disabled(),
            enterprise_provider_registry: None,
            verifier_policy_registry: None,
            federation_admission_rate_limiter: Arc::new(Mutex::new(
                FederationAdmissionRateLimiter::default(),
            )),
            authority_issuance_rotation_lock: Arc::new(Mutex::new(())),
            cluster: None,
            cluster_progress: None,
        }
    }

    #[tokio::test]
    async fn dashboard_session_is_read_only_bounded_and_logout_invalidates_it() {
        use axum::body::{to_bytes, Body};
        use axum::http::header::{CACHE_CONTROL, COOKIE, SET_COOKIE};
        use axum::http::Request;
        use tower::ServiceExt;

        let receipt_file = tempfile::NamedTempFile::new().test_unwrap();
        drop(SqliteReceiptStore::open(receipt_file.path()).test_unwrap());
        let mut state = metrics_state("service-secret");
        state.config.receipt_db_path = Some(receipt_file.path().to_path_buf());

        let wrong_login = Request::builder()
            .method("POST")
            .uri(DASHBOARD_SESSION_PATH)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"token":"service-secret"}"#))
            .test_unwrap();
        let wrong_response = super::build_router(state.clone())
            .oneshot(wrong_login)
            .await
            .test_unwrap();
        assert_eq!(wrong_response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            wrong_response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert!(wrong_response.headers().get(SET_COOKIE).is_none());

        let login = Request::builder()
            .method("POST")
            .uri(DASHBOARD_SESSION_PATH)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"token":"dashboard-secret"}"#))
            .test_unwrap();
        let login_response = super::build_router(state.clone())
            .oneshot(login)
            .await
            .test_unwrap();
        assert_eq!(login_response.status(), StatusCode::OK);
        let set_cookie = login_response
            .headers()
            .get(SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .test_expect("dashboard login set-cookie")
            .to_string();
        assert!(set_cookie.starts_with("__Host-chio_dashboard="));
        assert!(set_cookie.contains("; Path=/; Max-Age=900; Secure; HttpOnly; SameSite=Strict"));
        assert!(!set_cookie.contains("Domain="));
        let cookie = set_cookie
            .split(';')
            .next()
            .test_expect("dashboard cookie pair")
            .to_string();
        let login_body = to_bytes(login_response.into_body(), 4 * 1024)
            .await
            .test_unwrap();
        let login_body = String::from_utf8(login_body.to_vec()).test_unwrap();
        assert!(!login_body.contains("dashboard-secret"));
        assert!(!login_body.contains(cookie.split_once('=').test_unwrap().1));
        assert!(login_body.contains("\"relayReports\":{\"observability\":false"));

        let read = Request::builder()
            .uri(RECEIPT_QUERY_PATH)
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .test_unwrap();
        let read_response = super::build_router(state.clone())
            .oneshot(read)
            .await
            .test_unwrap();
        assert_eq!(read_response.status(), StatusCode::OK);
        assert_eq!(
            read_response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );

        let mutation = Request::builder()
            .method("POST")
            .uri(REVOCATIONS_PATH)
            .header("content-type", "application/json")
            .header(COOKIE, &cookie)
            .body(Body::from(r#"{"capabilityId":"cap-1"}"#))
            .test_unwrap();
        let mutation_response = super::build_router(state.clone())
            .oneshot(mutation)
            .await
            .test_unwrap();
        assert_eq!(mutation_response.status(), StatusCode::UNAUTHORIZED);

        let duplicate_cookie_headers = Request::builder()
            .uri(RECEIPT_QUERY_PATH)
            .header(COOKIE, &cookie)
            .header(COOKIE, "unrelated=value")
            .body(Body::empty())
            .test_unwrap();
        let duplicate_response = super::build_router(state.clone())
            .oneshot(duplicate_cookie_headers)
            .await
            .test_unwrap();
        assert_eq!(duplicate_response.status(), StatusCode::UNAUTHORIZED);

        let duplicate_authorization_headers = Request::builder()
            .uri(RECEIPT_QUERY_PATH)
            .header(COOKIE, &cookie)
            .header(AUTHORIZATION, "Bearer service-secret")
            .header(AUTHORIZATION, "Bearer service-secret")
            .body(Body::empty())
            .test_unwrap();
        let duplicate_authorization_response = super::build_router(state.clone())
            .oneshot(duplicate_authorization_headers)
            .await
            .test_unwrap();
        assert_eq!(
            duplicate_authorization_response.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            duplicate_authorization_response
                .headers()
                .get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );

        let hidden_report = Request::builder()
            .uri("/v1/chio/pheromone/observability")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .test_unwrap();
        let hidden_report_response = super::build_router(state.clone())
            .oneshot(hidden_report)
            .await
            .test_unwrap();
        assert_eq!(hidden_report_response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            hidden_report_response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );

        let mut bridged_state = state.clone();
        let report_upstream = std::net::TcpListener::bind("127.0.0.1:0").test_unwrap();
        report_upstream.set_nonblocking(true).test_unwrap();
        bridged_state.config.dashboard_report_origin = Some(format!(
            "http://{}/",
            report_upstream.local_addr().test_unwrap()
        ));
        bridged_state.config.dashboard_report_token = Some("relay-read-secret".to_string());
        bridged_state.config.dashboard_allow_insecure_report_origin = true;
        bridged_state.dashboard_report_bridge =
            dashboard_reports::DashboardReportBridge::from_config(&bridged_state.config)
                .test_unwrap();

        let bridged_session = Request::builder()
            .uri(DASHBOARD_SESSION_PATH)
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .test_unwrap();
        let bridged_session_response = super::build_router(bridged_state.clone())
            .oneshot(bridged_session)
            .await
            .test_unwrap();
        assert_eq!(bridged_session_response.status(), StatusCode::OK);
        let bridged_session_body = to_bytes(bridged_session_response.into_body(), 8 * 1024)
            .await
            .test_unwrap();
        let bridged_session_body = String::from_utf8(bridged_session_body.to_vec()).test_unwrap();
        assert!(bridged_session_body.contains("\"observability\":true"));
        assert!(bridged_session_body.contains("\"alerts\":false"));

        let report_without_cookie = Request::builder()
            .uri("/v1/chio/pheromone/observability")
            .body(Body::empty())
            .test_unwrap();
        let report_without_cookie_response = super::build_router(bridged_state.clone())
            .oneshot(report_without_cookie)
            .await
            .test_unwrap();
        assert_eq!(
            report_without_cookie_response.status(),
            StatusCode::UNAUTHORIZED
        );

        let report_mutation = Request::builder()
            .method("POST")
            .uri("/v1/chio/pheromone/observability")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .test_unwrap();
        let report_mutation_response = super::build_router(bridged_state.clone())
            .oneshot(report_mutation)
            .await
            .test_unwrap();
        assert_eq!(
            report_mutation_response.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            report_mutation_response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );

        let report_head = Request::builder()
            .method("HEAD")
            .uri("/v1/chio/pheromone/observability")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .test_unwrap();
        let report_head_response = super::build_router(bridged_state.clone())
            .oneshot(report_head)
            .await
            .test_unwrap();
        assert_eq!(
            report_head_response.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            report_head_response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );

        for unavailable_path in [
            "/v1/chio/pheromone/batches",
            "/v1/chio/pheromone/alerts",
            "/v1/chio/pheromone/alert-assurance",
        ] {
            let unavailable = Request::builder()
                .uri(unavailable_path)
                .header(COOKIE, &cookie)
                .body(Body::empty())
                .test_unwrap();
            let unavailable_response = super::build_router(bridged_state.clone())
                .oneshot(unavailable)
                .await
                .test_unwrap();
            assert_eq!(unavailable_response.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                unavailable_response.headers().get(CACHE_CONTROL),
                Some(&HeaderValue::from_static("no-store"))
            );
        }
        let unavailable_mutation = Request::builder()
            .method("POST")
            .uri("/v1/chio/pheromone/batches")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .test_unwrap();
        let unavailable_mutation_response = super::build_router(bridged_state.clone())
            .oneshot(unavailable_mutation)
            .await
            .test_unwrap();
        assert_eq!(
            unavailable_mutation_response.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            unavailable_mutation_response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert!(matches!(
            report_upstream.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));

        let logout = Request::builder()
            .method("DELETE")
            .uri(DASHBOARD_SESSION_PATH)
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .test_unwrap();
        let logout_response = super::build_router(state.clone())
            .oneshot(logout)
            .await
            .test_unwrap();
        assert_eq!(logout_response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            logout_response
                .headers()
                .get(SET_COOKIE)
                .and_then(|value| value.to_str().ok()),
            Some(
                "__Host-chio_dashboard=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict"
            )
        );

        let after_logout = Request::builder()
            .uri(DASHBOARD_SESSION_PATH)
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .test_unwrap();
        let after_logout_response = super::build_router(state)
            .oneshot(after_logout)
            .await
            .test_unwrap();
        assert_eq!(after_logout_response.status(), StatusCode::UNAUTHORIZED);
    }

    fn active_defense_event_json() -> Vec<u8> {
        let event = chio_security_types::ports::UnverifiedSecurityEvent {
            tenant_id: chio_security_types::ports::TenantId::new("tenant-router").test_unwrap(),
            event_id: chio_security_types::ports::EventId::new("event-router").test_unwrap(),
            producer_id: chio_security_types::ports::ProducerId::new("producer-router")
                .test_unwrap(),
            event_time_unix_ms: 1_000,
            received_at_unix_ms: 1_001,
            canonical_body: chio_security_types::ports::CanonicalBody::new(b"{}".to_vec())
                .test_unwrap(),
            body_hash: chio_security_types::ports::Digest32::new([3_u8; 32]),
            source_evidence: chio_security_types::ports::CanonicalBody::new(b"{}".to_vec())
                .test_unwrap(),
        };
        serde_json::to_vec(&event).test_unwrap()
    }

    #[tokio::test]
    async fn partition_fault_injection_is_not_exposed_as_a_network_route() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let request = Request::builder()
            .method("POST")
            .uri("/v1/internal/cluster/partition")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"blockedPeerUrls":[]}"#))
            .test_unwrap();
        let response = super::build_router(metrics_state("secret"))
            .oneshot(request)
            .await
            .test_unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn active_defense_routes_require_service_auth_and_fail_closed_when_disabled() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let health = Request::builder()
            .uri(ACTIVE_DEFENSE_HEALTH_PATH)
            .body(Body::empty())
            .test_unwrap();
        let health_response = super::build_router(metrics_state("secret"))
            .oneshot(health)
            .await
            .test_unwrap();
        assert_eq!(health_response.status(), StatusCode::UNAUTHORIZED);

        let event = Request::builder()
            .method("POST")
            .uri(ACTIVE_DEFENSE_EVENTS_PATH)
            .header("content-type", "application/json")
            .header("authorization", "Bearer secret")
            .body(Body::from(active_defense_event_json()))
            .test_unwrap();
        let event_response = super::build_router(metrics_state("secret"))
            .oneshot(event)
            .await
            .test_unwrap();
        assert_eq!(event_response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let health = Request::builder()
            .uri(ACTIVE_DEFENSE_HEALTH_PATH)
            .header("authorization", "Bearer secret")
            .body(Body::empty())
            .test_unwrap();
        let health_response = super::build_router(metrics_state("secret"))
            .oneshot(health)
            .await
            .test_unwrap();
        assert_eq!(health_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn active_defense_event_wire_shape_rejects_unknown_fields() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let mut event: serde_json::Value =
            serde_json::from_slice(&active_defense_event_json()).test_unwrap();
        event["fallback"] = serde_json::Value::Bool(true);
        let request = Request::builder()
            .method("POST")
            .uri(ACTIVE_DEFENSE_EVENTS_PATH)
            .header("content-type", "application/json")
            .header("authorization", "Bearer secret")
            .body(Body::from(serde_json::to_vec(&event).test_unwrap()))
            .test_unwrap();
        let response = super::build_router(metrics_state("secret"))
            .oneshot(request)
            .await
            .test_unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// The /metrics route shares the trust-control listener and must fail closed.
    /// An unauthenticated scrape is rejected with 401 rather than exposing
    /// operational counters and guard labels.
    #[tokio::test]
    async fn trust_control_metrics_rejects_unauthenticated_request() {
        let state = metrics_state("service-secret");
        let response = handle_trust_control_metrics(State(state), HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A scrape presenting the configured service token is served (200).
    #[tokio::test]
    async fn trust_control_metrics_accepts_valid_service_token() {
        let state = metrics_state("service-secret");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer service-secret"),
        );
        let response = handle_trust_control_metrics(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authority_key_log_sync_is_service_only_strict_and_route_bounded() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;

        let state = metrics_state("service-secret");
        let dashboard_request = Request::builder()
            .method("POST")
            .uri(AUTHORITY_KEY_LOG_SYNC_PATH)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, "Bearer dashboard-secret")
            .body(Body::from("{}"))
            .test_unwrap();
        assert_eq!(
            super::build_router(state.clone())
                .oneshot(dashboard_request)
                .await
                .test_unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let duplicate_authorization = Request::builder()
            .method("POST")
            .uri(AUTHORITY_KEY_LOG_SYNC_PATH)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, "Bearer service-secret")
            .header(AUTHORIZATION, "Bearer service-secret")
            .body(Body::from("{}"))
            .test_unwrap();
        assert_eq!(
            super::build_router(state.clone())
                .oneshot(duplicate_authorization)
                .await
                .test_unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let unknown_field = Request::builder()
            .method("POST")
            .uri(AUTHORITY_KEY_LOG_SYNC_PATH)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, "Bearer service-secret")
            .body(Body::from(r#"{"unexpected":true}"#))
            .test_unwrap();
        assert_eq!(
            super::build_router(state.clone())
                .oneshot(unknown_field)
                .await
                .test_unwrap()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let oversized = Request::builder()
            .method("POST")
            .uri(AUTHORITY_KEY_LOG_SYNC_PATH)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, "Bearer service-secret")
            .body(Body::from(vec![b' '; 4 * 1024 + 1]))
            .test_unwrap();
        assert_eq!(
            super::build_router(state.clone())
                .oneshot(oversized)
                .await
                .test_unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );

        let authorized = Request::builder()
            .method("POST")
            .uri(AUTHORITY_KEY_LOG_SYNC_PATH)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, "Bearer service-secret")
            .body(Body::from("{}"))
            .test_unwrap();
        assert_eq!(
            super::build_router(state)
                .oneshot(authorized)
                .await
                .test_unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// Building the trust-control serve router must seed the fixed alert-pack
    /// label sets, so a fresh, healthy-but-quiet control plane renders the
    /// fail-open / dispatch-failure / capability-revocation families at zero and
    /// the shipped absent_over_time backstops fire only on a true scrape gap, not
    /// on a control plane that simply has not had an event yet.
    #[tokio::test]
    async fn build_router_seeds_alert_pack_series_for_absent_over_time_backstops() {
        let state = metrics_state("service-secret");
        let _router = super::build_router(state);

        let mut body = String::new();
        chio_metrics_spec::runtime::render_alert_pack_families(&mut body);
        assert!(
            body.contains("chio_dispatch_failure_total{surface=\"http_authority\",outcome=\"error\"}"),
            "the dispatch-failure family must be present at zero after building the serve router: {body}"
        );
        assert!(
            body.contains("chio_fail_open_suspected_total{surface=\"tower\"}"),
            "the fail-open family must be present at zero after building the serve router: {body}"
        );
        assert!(
            body.contains("chio_capability_revocation_lag_seconds"),
            "the capability-revocation-lag family must be present after building the serve router: {body}"
        );
    }

    #[tokio::test]
    async fn composite_budget_and_admission_capture_routes_are_distinct_and_fail_closed() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        for path in [
            BUDGET_AUTHORIZE_HOLD_PATH,
            BUDGET_AUTHORIZE_HOLD_QUERY_PATH,
            BUDGET_CAPTURE_INVOCATIONS_PATH,
            ADMISSION_CAPTURE_PATH,
            ADMISSION_CAPTURE_QUERY_PATH,
            INTERNAL_COMPOSITE_AUTHORIZE_QUERY_PATH,
        ] {
            let request = Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .test_unwrap();
            let response = super::build_router(metrics_state("secret"))
                .oneshot(request)
                .await
                .test_unwrap();
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{path}");
        }

        let revocation_ids = vec!["cap-1".to_string()];
        let canonical_ids = canonical_json_bytes(&revocation_ids).test_unwrap();
        let mut revocation_digest_input = b"chio.revocation-set.v1\0".to_vec();
        revocation_digest_input.extend_from_slice(&canonical_ids);
        let revocation_digest = sha256_hex(&revocation_digest_input);
        let composite_requests = [
            (
                BUDGET_AUTHORIZE_HOLD_PATH,
                serde_json::json!({
                    "operationId": "operation-authorize-1",
                    "requestBindingHash": "11".repeat(32),
                    "capabilityId": "cap-1",
                    "grantIndex": 0,
                    "requestedExposureUnits": 0,
                    "holdId": "hold-1",
                    "eventId": "event-1",
                    "admissionEvidence": {
                        "invocationQuotas": [{
                            "key": {
                                "profile": "chio.grant-invocation.v1",
                                "ownerId": "cap-1",
                                "grantIndex": 0
                            },
                            "maxInvocations": 1
                        }],
                        "revocationSet": {
                            "ids": ["cap-1"],
                            "digest": revocation_digest.clone()
                        }
                    }
                }),
            ),
            (
                BUDGET_CAPTURE_INVOCATIONS_PATH,
                serde_json::json!({
                    "operationId": "operation-capture-1",
                    "requestBindingHash": "22".repeat(32),
                    "capabilityId": "cap-1",
                    "grantIndex": 0,
                    "holdId": "hold-1",
                    "eventId": "event-2",
                    "budgetAuthority": {
                        "authorityId": "leader-1",
                        "leaseId": "lease-1",
                        "leaseEpoch": 1
                    }
                }),
            ),
        ];
        for (path, body) in composite_requests {
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header(AUTHORIZATION, "Bearer secret")
                .body(Body::from(body.to_string()))
                .test_unwrap();
            let response = super::build_router(metrics_state("secret"))
                .oneshot(request)
                .await
                .test_unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        }

        let request = Request::builder()
            .method("POST")
            .uri(ADMISSION_CAPTURE_PATH)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, "Bearer secret")
            .body(Body::from(
                serde_json::json!({
                    "operationId": "operation-1",
                    "requestBindingHash": "33".repeat(32),
                    "capabilityId": "cap-1",
                    "grantIndex": 0,
                    "holdId": "hold-1",
                    "eventId": "event-1",
                    "revocationSet": {
                        "ids": ["cap-1"],
                        "digest": revocation_digest.clone()
                    },
                    "boundRevocationSetDigest": revocation_digest.clone(),
                    "authorizationArtifactDigests": []
                })
                .to_string(),
            ))
            .test_unwrap();
        let response = super::build_router(metrics_state("secret"))
            .oneshot(request)
            .await
            .test_unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let request = Request::builder()
            .method("POST")
            .uri(ADMISSION_CAPTURE_QUERY_PATH)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, "Bearer secret")
            .body(Body::from(
                serde_json::json!({
                    "captureRequest": {
                        "operationId": "operation-1",
                        "requestBindingHash": "33".repeat(32),
                        "capabilityId": "cap-1",
                        "grantIndex": 0,
                        "holdId": "hold-1",
                        "eventId": "event-1",
                        "revocationSet": {
                            "ids": ["cap-1"],
                            "digest": revocation_digest.clone()
                        },
                        "boundRevocationSetDigest": revocation_digest,
                        "authorizationArtifactDigests": []
                    }
                })
                .to_string(),
            ))
            .test_unwrap();
        let response = super::build_router(metrics_state("secret"))
            .oneshot(request)
            .await
            .test_unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A stream receipt embeds one digest per retained chunk, so a valid receipt
    /// append routinely exceeds the service-wide 1 MiB request cap. The two
    /// receipt-append routes carry their own larger body limit so replicating or
    /// importing such a receipt reaches the handler instead of being rejected with
    /// 413, while a route without the override stays capped: the relaxation is
    /// route-specific, not a global loosening.
    #[tokio::test]
    async fn receipt_append_routes_accept_bodies_above_the_service_body_cap() {
        use axum::body::Body;
        use axum::http::Request;
        use chio_http_serve::{apply_server_hygiene, ServeHygieneConfig};
        use tower::ServiceExt;

        // Mirror the service-wide 1 MiB body cap the trust-control serve site
        // applies around the router.
        let hygiene = ServeHygieneConfig {
            max_body_bytes: Some(1024 * 1024),
            request_timeout: None,
            ..ServeHygieneConfig::default()
        };
        let build = || apply_server_hygiene(super::build_router(metrics_state("secret")), &hygiene);

        // Over the 1 MiB service cap but well under the receipt cap. The bytes are
        // not a valid receipt, so the handler's own decode still rejects them, but
        // NOT with 413: the point is the larger route limit lets the request reach
        // the handler at all.
        let oversized = vec![b'x'; 2 * 1024 * 1024];

        for path in [TOOL_RECEIPTS_PATH, CHILD_RECEIPTS_PATH] {
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(oversized.clone()))
                .test_unwrap();
            let response = build().oneshot(request).await.test_unwrap();
            assert_ne!(
                response.status(),
                StatusCode::PAYLOAD_TOO_LARGE,
                "{path} must accept a receipt body above the 1 MiB service cap"
            );
        }

        let request = Request::builder()
            .method("POST")
            .uri(ISSUE_CAPABILITY_PATH)
            .header("content-type", "application/json")
            .body(Body::from(oversized))
            .test_unwrap();
        let response = build().oneshot(request).await.test_unwrap();
        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "a route without the receipt-append override must still cap at 1 MiB"
        );
    }
}
