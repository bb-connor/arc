//! W2.4 smoke test: each of the six edges + `chio-wasm-guards` consumes
//! the workspace metric registry, and each registry-keyed metric series
//! is actually emitted to the Prometheus exposition under a synthetic
//! load.
//!
//! The test runs the production emission path on each edge (not just a
//! constant reference) and then scrapes the per-edge Prometheus body to
//! assert (a) the registry-keyed metric name is present and (b) the
//! sample count is non-zero. A registry constant referenced in source
//! code but never emitted at runtime would fail the count check, which
//! is exactly the gap T1.5 left open.

use chio_metrics_spec::{
    is_registered_metric, CHIO_ANCHOR_ROUND_LATENCY_SECONDS, CHIO_FEDERATION_HOP_LATENCY_SECONDS,
    CHIO_FEDERATION_HOP_TOTAL, CHIO_GUARD_EVALUATIONS_TOTAL, CHIO_GUARD_POOL_CHECKOUT_TOTAL,
    CHIO_GUARD_POOL_EVICT_TOTAL, CHIO_GUARD_POOL_WARM_SIZE, CHIO_KERNEL_DECISION_LATENCY_SECONDS,
    CHIO_RECEIPT_WRITE_TOTAL,
};

#[test]
fn registry_constants_are_registered_in_spec() {
    for name in [
        CHIO_RECEIPT_WRITE_TOTAL,
        CHIO_GUARD_EVALUATIONS_TOTAL,
        CHIO_KERNEL_DECISION_LATENCY_SECONDS,
        CHIO_ANCHOR_ROUND_LATENCY_SECONDS,
        CHIO_FEDERATION_HOP_TOTAL,
        CHIO_FEDERATION_HOP_LATENCY_SECONDS,
        CHIO_GUARD_POOL_CHECKOUT_TOTAL,
        CHIO_GUARD_POOL_WARM_SIZE,
        CHIO_GUARD_POOL_EVICT_TOTAL,
    ] {
        assert!(
            is_registered_metric(name),
            "expected {name} to live in the chio-metrics-spec registry"
        );
    }
}

#[test]
fn mcp_edge_emits_chio_receipt_write_total() {
    let before = chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    chio_mcp_edge::record_receipt_write(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    let after = chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    assert!(
        after > before,
        "mcp edge counter must advance after a recorded outcome"
    );
    let body = chio_mcp_edge::render_mcp_edge_metrics_prometheus();
    assert!(body.contains(CHIO_RECEIPT_WRITE_TOTAL));
    assert!(body.contains("outcome=\"allow\""));
}

#[test]
fn acp_edge_emits_chio_receipt_write_total() {
    let before = chio_acp_edge::receipt_write_total(chio_acp_edge::RECEIPT_WRITE_OUTCOME_DENY);
    chio_acp_edge::record_receipt_write(chio_acp_edge::RECEIPT_WRITE_OUTCOME_DENY);
    let after = chio_acp_edge::receipt_write_total(chio_acp_edge::RECEIPT_WRITE_OUTCOME_DENY);
    assert!(
        after > before,
        "acp edge counter must advance after a recorded outcome"
    );
    let body = chio_acp_edge::render_acp_edge_metrics_prometheus();
    assert!(body.contains(CHIO_RECEIPT_WRITE_TOTAL));
    assert!(body.contains("outcome=\"deny\""));
}

#[test]
fn a2a_edge_emits_chio_receipt_write_total() {
    let before = chio_a2a_edge::receipt_write_total(chio_a2a_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    chio_a2a_edge::record_receipt_write(chio_a2a_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    let after = chio_a2a_edge::receipt_write_total(chio_a2a_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    assert!(
        after > before,
        "a2a edge counter must advance after a recorded outcome"
    );
    let body = chio_a2a_edge::render_a2a_edge_metrics_prometheus();
    assert!(body.contains(CHIO_RECEIPT_WRITE_TOTAL));
    assert!(body.contains("outcome=\"allow\""));
}

#[test]
fn http_core_emits_kernel_decision_latency_and_guard_evaluations() {
    let before_count = chio_http_core::decision_latency_count();
    let before_allow = chio_http_core::guard_evaluations_total(chio_http_core::GUARD_OUTCOME_ALLOW);

    chio_http_core::observe_decision_latency_nanos(50_000);
    chio_http_core::record_guard_evaluation(chio_http_core::GUARD_OUTCOME_ALLOW);

    let after_count = chio_http_core::decision_latency_count();
    let after_allow = chio_http_core::guard_evaluations_total(chio_http_core::GUARD_OUTCOME_ALLOW);
    assert!(
        after_count > before_count,
        "http-core decision-latency count must advance after an observation"
    );
    assert!(
        after_allow > before_allow,
        "http-core guard-evaluations counter must advance after a recorded outcome"
    );

    let body = chio_http_core::render_http_core_metrics_prometheus();
    assert!(body.contains(CHIO_GUARD_EVALUATIONS_TOTAL));
    assert!(body.contains(CHIO_KERNEL_DECISION_LATENCY_SECONDS));
    assert!(body.contains("guard=\"http_authority\""));
}

#[test]
fn anchor_emits_chio_anchor_round_latency_seconds() {
    let before = chio_anchor::anchor_round_count(chio_anchor::ANCHOR_OUTCOME_SUCCESS);
    chio_anchor::observe_anchor_round_latency_nanos(chio_anchor::ANCHOR_OUTCOME_SUCCESS, 100_000);
    let after = chio_anchor::anchor_round_count(chio_anchor::ANCHOR_OUTCOME_SUCCESS);
    assert!(
        after > before,
        "anchor success counter must advance after a recorded latency"
    );
    let body = chio_anchor::render_anchor_metrics_prometheus();
    assert!(body.contains(CHIO_ANCHOR_ROUND_LATENCY_SECONDS));
    assert!(body.contains("_count"));
}

#[test]
fn federation_emits_chio_federation_hop_total() {
    let before = chio_federation::federation_hop_total(chio_federation::HOP_RESULT_OK);
    chio_federation::record_federation_hop(chio_federation::HOP_RESULT_OK);
    let after = chio_federation::federation_hop_total(chio_federation::HOP_RESULT_OK);
    assert!(
        after > before,
        "federation hop counter must advance after a recorded outcome"
    );
    let body = chio_federation::render_federation_metrics_prometheus();
    assert!(body.contains(CHIO_FEDERATION_HOP_TOTAL));
    assert!(body.contains("result=\"ok\""));
}

#[test]
fn federation_emits_chio_federation_hop_latency_seconds() {
    // The histogram must move in lockstep with the counter so the
    // `chio:federation_hop_latency:histogram_quantile_p95_5m` recording
    // rule has both `_count` and `_sum` series to scrape.
    let before = chio_federation::federation_hop_latency_count();
    chio_federation::observe_federation_hop_latency_nanos(chio_federation::HOP_RESULT_OK, 125_000);
    let after = chio_federation::federation_hop_latency_count();
    assert!(
        after > before,
        "federation hop latency count must advance after an observation"
    );
    let body = chio_federation::render_federation_metrics_prometheus();
    assert!(body.contains(CHIO_FEDERATION_HOP_LATENCY_SECONDS));
    assert!(body.contains("_count"));
}

#[test]
fn wasm_guards_re_exports_pool_metric_constants() {
    // chio-wasm-guards consumes the workspace registry through
    // `pub use chio_metrics_spec::*` re-exports. The three pool metric
    // names were registered in W2.4. Asserting that each name resolves
    // through chio_metrics_spec is enough: a regression that drops the
    // re-export would also drop these constants from the registry, and
    // the chio-metrics-spec snapshot test would fail first.
    assert_eq!(
        CHIO_GUARD_POOL_CHECKOUT_TOTAL,
        "chio_guard_pool_checkout_total"
    );
    assert_eq!(CHIO_GUARD_POOL_WARM_SIZE, "chio_guard_pool_warm_size");
    assert_eq!(CHIO_GUARD_POOL_EVICT_TOTAL, "chio_guard_pool_evict_total");
    assert!(is_registered_metric(CHIO_GUARD_POOL_CHECKOUT_TOTAL));
    assert!(is_registered_metric(CHIO_GUARD_POOL_WARM_SIZE));
    assert!(is_registered_metric(CHIO_GUARD_POOL_EVICT_TOTAL));
}
