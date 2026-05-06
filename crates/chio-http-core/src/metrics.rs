//! HTTP-core verdict-edge metrics surfaced through the workspace
//! `chio-metrics-spec` registry. Wave 2.4 of the trj4 closeout wires the
//! HTTP edge into the workspace registry: every authority dispatch through
//! `HttpAuthority::evaluate` increments
//! [`CHIO_GUARD_EVALUATIONS_TOTAL`] with a `(guard, outcome)` label
//! pair and observes the dispatch latency under
//! [`CHIO_KERNEL_DECISION_LATENCY_SECONDS`].

use std::sync::atomic::{AtomicU64, Ordering};

pub use chio_metrics_spec::{CHIO_GUARD_EVALUATIONS_TOTAL, CHIO_KERNEL_DECISION_LATENCY_SECONDS};

pub const GUARD_LABEL_HTTP_AUTHORITY: &str = "http_authority";

pub const GUARD_OUTCOME_ALLOW: &str = "allow";
pub const GUARD_OUTCOME_DENY: &str = "deny";
pub const GUARD_OUTCOME_ERROR: &str = "error";

static GUARD_EVAL_ALLOW: AtomicU64 = AtomicU64::new(0);
static GUARD_EVAL_DENY: AtomicU64 = AtomicU64::new(0);
static GUARD_EVAL_ERROR: AtomicU64 = AtomicU64::new(0);
static DECISION_LATENCY_NS_SUM: AtomicU64 = AtomicU64::new(0);
static DECISION_LATENCY_COUNT: AtomicU64 = AtomicU64::new(0);

/// Record the outcome of an HTTP authority evaluation. The `outcome`
/// argument should be one of [`GUARD_OUTCOME_ALLOW`],
/// [`GUARD_OUTCOME_DENY`], or [`GUARD_OUTCOME_ERROR`].
pub fn record_guard_evaluation(outcome: &str) {
    match outcome {
        GUARD_OUTCOME_ALLOW => {
            GUARD_EVAL_ALLOW.fetch_add(1, Ordering::Relaxed);
        }
        GUARD_OUTCOME_DENY => {
            GUARD_EVAL_DENY.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            GUARD_EVAL_ERROR.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Observe a kernel decision latency sample in nanoseconds.
pub fn observe_decision_latency_nanos(nanos: u64) {
    DECISION_LATENCY_NS_SUM.fetch_add(nanos, Ordering::Relaxed);
    DECISION_LATENCY_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[must_use]
pub fn guard_evaluations_total(outcome: &str) -> u64 {
    match outcome {
        GUARD_OUTCOME_ALLOW => GUARD_EVAL_ALLOW.load(Ordering::Relaxed),
        GUARD_OUTCOME_DENY => GUARD_EVAL_DENY.load(Ordering::Relaxed),
        _ => GUARD_EVAL_ERROR.load(Ordering::Relaxed),
    }
}

#[must_use]
pub fn decision_latency_count() -> u64 {
    DECISION_LATENCY_COUNT.load(Ordering::Relaxed)
}

#[must_use]
pub fn render_http_core_metrics_prometheus() -> String {
    let mut output = String::new();

    output.push_str("# HELP ");
    output.push_str(CHIO_GUARD_EVALUATIONS_TOTAL);
    output.push_str(" Total guard evaluation outcomes across native and WASM guards.\n");
    output.push_str("# TYPE ");
    output.push_str(CHIO_GUARD_EVALUATIONS_TOTAL);
    output.push_str(" counter\n");
    for outcome in [GUARD_OUTCOME_ALLOW, GUARD_OUTCOME_DENY, GUARD_OUTCOME_ERROR] {
        output.push_str(CHIO_GUARD_EVALUATIONS_TOTAL);
        output.push_str("{guard=\"");
        output.push_str(GUARD_LABEL_HTTP_AUTHORITY);
        output.push_str("\",outcome=\"");
        output.push_str(outcome);
        output.push_str("\"} ");
        output.push_str(&guard_evaluations_total(outcome).to_string());
        output.push('\n');
    }

    output.push_str("# HELP ");
    output.push_str(CHIO_KERNEL_DECISION_LATENCY_SECONDS);
    output.push_str(" Kernel mediation decision latency in seconds.\n");
    output.push_str("# TYPE ");
    output.push_str(CHIO_KERNEL_DECISION_LATENCY_SECONDS);
    output.push_str(" histogram\n");
    output.push_str(CHIO_KERNEL_DECISION_LATENCY_SECONDS);
    output.push_str("_count ");
    output.push_str(&decision_latency_count().to_string());
    output.push('\n');

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_constants_match_spec() {
        assert_eq!(CHIO_GUARD_EVALUATIONS_TOTAL, "chio_guard_evaluations_total");
        assert_eq!(
            CHIO_KERNEL_DECISION_LATENCY_SECONDS,
            "chio_kernel_decision_latency_seconds"
        );
    }
}
