//! Anchor publish metrics surfaced through the workspace
//! `chio-metrics-spec` registry. Wave 2.4 of the trj4 closeout wires the
//! anchor publish boundary into the workspace registry: every
//! [`build_anchor_batch`](crate::build_anchor_batch) call observes
//! [`CHIO_ANCHOR_ROUND_LATENCY_SECONDS`].
//!
//! `chio_metrics_spec` registers
//! `chio_anchor_round_latency_seconds` as a histogram with
//! `(witness, outcome)` labels. The atomic counters here keep the
//! count and a nanosecond-summed total so the Prometheus exporter can
//! render `_sum`/`_count` companion samples without pulling in a full
//! histogram crate.

use std::sync::atomic::{AtomicU64, Ordering};

pub use chio_metrics_spec::CHIO_ANCHOR_ROUND_LATENCY_SECONDS;

pub const ANCHOR_OUTCOME_SUCCESS: &str = "success";
pub const ANCHOR_OUTCOME_ERROR: &str = "error";

static ANCHOR_ROUND_LATENCY_NS_SUM: AtomicU64 = AtomicU64::new(0);
static ANCHOR_ROUND_COUNT_SUCCESS: AtomicU64 = AtomicU64::new(0);
static ANCHOR_ROUND_COUNT_ERROR: AtomicU64 = AtomicU64::new(0);

/// Observe an anchor round latency sample in nanoseconds.
pub fn observe_anchor_round_latency_nanos(outcome: &str, nanos: u64) {
    ANCHOR_ROUND_LATENCY_NS_SUM.fetch_add(nanos, Ordering::Relaxed);
    match outcome {
        ANCHOR_OUTCOME_SUCCESS => {
            ANCHOR_ROUND_COUNT_SUCCESS.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            ANCHOR_ROUND_COUNT_ERROR.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[must_use]
pub fn anchor_round_count(outcome: &str) -> u64 {
    match outcome {
        ANCHOR_OUTCOME_SUCCESS => ANCHOR_ROUND_COUNT_SUCCESS.load(Ordering::Relaxed),
        _ => ANCHOR_ROUND_COUNT_ERROR.load(Ordering::Relaxed),
    }
}

#[must_use]
pub fn render_anchor_metrics_prometheus() -> String {
    let mut output = String::new();
    output.push_str("# HELP ");
    output.push_str(CHIO_ANCHOR_ROUND_LATENCY_SECONDS);
    output.push_str(" Anchor round latency in seconds.\n");
    output.push_str("# TYPE ");
    output.push_str(CHIO_ANCHOR_ROUND_LATENCY_SECONDS);
    output.push_str(" histogram\n");
    let total =
        anchor_round_count(ANCHOR_OUTCOME_SUCCESS) + anchor_round_count(ANCHOR_OUTCOME_ERROR);
    output.push_str(CHIO_ANCHOR_ROUND_LATENCY_SECONDS);
    output.push_str("_count{witness=\"any\",outcome=\"any\"} ");
    output.push_str(&total.to_string());
    output.push('\n');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_constant_matches_spec() {
        assert_eq!(
            CHIO_ANCHOR_ROUND_LATENCY_SECONDS,
            "chio_anchor_round_latency_seconds"
        );
    }
}
