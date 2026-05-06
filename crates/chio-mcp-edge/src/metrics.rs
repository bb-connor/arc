//! MCP edge metrics surfaced through the workspace `chio-metrics-spec`
//! registry. Wave 2.4 of the trj4 closeout wires the MCP edge into the
//! workspace registry: every successful or failed tool-call response
//! emerging from the kernel boundary increments
//! [`CHIO_RECEIPT_WRITE_TOTAL`] with an `outcome` label.
//!
//! The atomic counters here are the production sink. The Prometheus
//! exporter wraps them in [`render_mcp_edge_metrics_prometheus`]. The
//! conformance smoke test at
//! `crates/chio-conformance/tests/metrics_registry_consumed.rs` asserts
//! that the exposition output contains the registry-keyed series with a
//! non-zero count after a synthetic tool-call dispatch.

use std::sync::atomic::{AtomicU64, Ordering};

pub use chio_metrics_spec::CHIO_RECEIPT_WRITE_TOTAL;

/// Allowed outcome label values for [`CHIO_RECEIPT_WRITE_TOTAL`].
pub const RECEIPT_WRITE_OUTCOME_ALLOW: &str = "allow";
pub const RECEIPT_WRITE_OUTCOME_DENY: &str = "deny";
pub const RECEIPT_WRITE_OUTCOME_ERROR: &str = "error";

static RECEIPT_WRITE_ALLOW: AtomicU64 = AtomicU64::new(0);
static RECEIPT_WRITE_DENY: AtomicU64 = AtomicU64::new(0);
static RECEIPT_WRITE_ERROR: AtomicU64 = AtomicU64::new(0);

/// Record a receipt-write outcome at the MCP edge sink boundary.
///
/// `outcome` must be one of [`RECEIPT_WRITE_OUTCOME_ALLOW`],
/// [`RECEIPT_WRITE_OUTCOME_DENY`], or [`RECEIPT_WRITE_OUTCOME_ERROR`].
/// Unknown values are recorded under the error counter so the gauge does
/// not silently drop emissions.
pub fn record_receipt_write(outcome: &str) {
    match outcome {
        RECEIPT_WRITE_OUTCOME_ALLOW => {
            RECEIPT_WRITE_ALLOW.fetch_add(1, Ordering::Relaxed);
        }
        RECEIPT_WRITE_OUTCOME_DENY => {
            RECEIPT_WRITE_DENY.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            RECEIPT_WRITE_ERROR.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[must_use]
pub fn receipt_write_total(outcome: &str) -> u64 {
    match outcome {
        RECEIPT_WRITE_OUTCOME_ALLOW => RECEIPT_WRITE_ALLOW.load(Ordering::Relaxed),
        RECEIPT_WRITE_OUTCOME_DENY => RECEIPT_WRITE_DENY.load(Ordering::Relaxed),
        _ => RECEIPT_WRITE_ERROR.load(Ordering::Relaxed),
    }
}

/// Render the MCP edge Prometheus exposition for the registry-keyed
/// series. The format is intentionally kept minimal: one
/// `# HELP`/`# TYPE` block plus one labelled sample per outcome.
#[must_use]
pub fn render_mcp_edge_metrics_prometheus() -> String {
    let mut output = String::new();
    output.push_str("# HELP ");
    output.push_str(CHIO_RECEIPT_WRITE_TOTAL);
    output.push_str(" Total receipt write outcomes after policy or guard evaluation.\n");
    output.push_str("# TYPE ");
    output.push_str(CHIO_RECEIPT_WRITE_TOTAL);
    output.push_str(" counter\n");
    for outcome in [
        RECEIPT_WRITE_OUTCOME_ALLOW,
        RECEIPT_WRITE_OUTCOME_DENY,
        RECEIPT_WRITE_OUTCOME_ERROR,
    ] {
        output.push_str(CHIO_RECEIPT_WRITE_TOTAL);
        output.push_str("{outcome=\"");
        output.push_str(outcome);
        output.push_str("\"} ");
        output.push_str(&receipt_write_total(outcome).to_string());
        output.push('\n');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_constant_matches_spec() {
        assert_eq!(CHIO_RECEIPT_WRITE_TOTAL, "chio_receipt_write_total");
    }

    #[test]
    fn render_includes_registry_name_and_outcome_labels() {
        record_receipt_write(RECEIPT_WRITE_OUTCOME_ALLOW);
        let body = render_mcp_edge_metrics_prometheus();
        assert!(body.contains(CHIO_RECEIPT_WRITE_TOTAL));
        assert!(body.contains("outcome=\"allow\""));
    }
}
