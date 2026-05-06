//! Federation-hop metrics surfaced through the workspace
//! `chio-metrics-spec` registry. Wave 2.4 of the trj4 closeout wires the
//! federation-hop boundary into the workspace registry: every
//! [`co_sign_with_origin`](crate::co_sign_with_origin) call increments
//! [`CHIO_FEDERATION_HOP_TOTAL`] with a `result` label and observes
//! [`CHIO_FEDERATION_HOP_LATENCY_SECONDS`] with the same label so the
//! `chio:federation_hop_latency:histogram_quantile_p95_5m` recording rule
//! in `deploy/prometheus/chio-recording-rules.yml` has a series to scrape.

use std::sync::atomic::{AtomicU64, Ordering};

pub use chio_metrics_spec::{CHIO_FEDERATION_HOP_LATENCY_SECONDS, CHIO_FEDERATION_HOP_TOTAL};

pub const HOP_RESULT_OK: &str = "ok";
pub const HOP_RESULT_ERROR: &str = "error";

static FEDERATION_HOP_OK: AtomicU64 = AtomicU64::new(0);
static FEDERATION_HOP_ERROR: AtomicU64 = AtomicU64::new(0);
static FEDERATION_HOP_LATENCY_NS_SUM: AtomicU64 = AtomicU64::new(0);

pub fn record_federation_hop(result: &str) {
    match result {
        HOP_RESULT_OK => {
            FEDERATION_HOP_OK.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            FEDERATION_HOP_ERROR.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Observe a federation-hop latency sample in nanoseconds, scoped to the
/// hop result. Saturating at u64 keeps the counter monotonic under sustained
/// load without panicking on overflow. Pairs with [`record_federation_hop`]
/// so a single boundary call increments the counter and observes the
/// histogram in lockstep.
pub fn observe_federation_hop_latency_nanos(result: &str, nanos: u64) {
    FEDERATION_HOP_LATENCY_NS_SUM.fetch_add(nanos, Ordering::Relaxed);
    record_federation_hop(result);
}

#[must_use]
pub fn federation_hop_total(result: &str) -> u64 {
    match result {
        HOP_RESULT_OK => FEDERATION_HOP_OK.load(Ordering::Relaxed),
        _ => FEDERATION_HOP_ERROR.load(Ordering::Relaxed),
    }
}

#[must_use]
pub fn federation_hop_latency_count() -> u64 {
    federation_hop_total(HOP_RESULT_OK) + federation_hop_total(HOP_RESULT_ERROR)
}

#[must_use]
pub fn render_federation_metrics_prometheus() -> String {
    let mut output = String::new();
    output.push_str("# HELP ");
    output.push_str(CHIO_FEDERATION_HOP_TOTAL);
    output.push_str(" Total federation hop outcomes.\n");
    output.push_str("# TYPE ");
    output.push_str(CHIO_FEDERATION_HOP_TOTAL);
    output.push_str(" counter\n");
    for result in [HOP_RESULT_OK, HOP_RESULT_ERROR] {
        output.push_str(CHIO_FEDERATION_HOP_TOTAL);
        output.push_str("{result=\"");
        output.push_str(result);
        output.push_str("\"} ");
        output.push_str(&federation_hop_total(result).to_string());
        output.push('\n');
    }
    output.push_str("# HELP ");
    output.push_str(CHIO_FEDERATION_HOP_LATENCY_SECONDS);
    output.push_str(" Federation hop latency in seconds.\n");
    output.push_str("# TYPE ");
    output.push_str(CHIO_FEDERATION_HOP_LATENCY_SECONDS);
    output.push_str(" histogram\n");
    output.push_str(CHIO_FEDERATION_HOP_LATENCY_SECONDS);
    output.push_str("_count{result=\"any\"} ");
    output.push_str(&federation_hop_latency_count().to_string());
    output.push('\n');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_constant_matches_spec() {
        assert_eq!(CHIO_FEDERATION_HOP_TOTAL, "chio_federation_hop_total");
        assert_eq!(
            CHIO_FEDERATION_HOP_LATENCY_SECONDS,
            "chio_federation_hop_latency_seconds"
        );
    }
}
