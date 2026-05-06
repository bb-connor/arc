//! Federation-hop metrics surfaced through the workspace
//! `chio-metrics-spec` registry. Wave 2.4 of the trj4 closeout wires the
//! federation-hop boundary into the workspace registry: every
//! [`co_sign_with_origin`](crate::co_sign_with_origin) call increments
//! [`CHIO_FEDERATION_HOP_TOTAL`] with a `result` label.

use std::sync::atomic::{AtomicU64, Ordering};

pub use chio_metrics_spec::CHIO_FEDERATION_HOP_TOTAL;

pub const HOP_RESULT_OK: &str = "ok";
pub const HOP_RESULT_ERROR: &str = "error";

static FEDERATION_HOP_OK: AtomicU64 = AtomicU64::new(0);
static FEDERATION_HOP_ERROR: AtomicU64 = AtomicU64::new(0);

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

#[must_use]
pub fn federation_hop_total(result: &str) -> u64 {
    match result {
        HOP_RESULT_OK => FEDERATION_HOP_OK.load(Ordering::Relaxed),
        _ => FEDERATION_HOP_ERROR.load(Ordering::Relaxed),
    }
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
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_constant_matches_spec() {
        assert_eq!(CHIO_FEDERATION_HOP_TOTAL, "chio_federation_hop_total");
    }
}
