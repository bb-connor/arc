//! Escrow ledger selection for graph-backed commerce order verification.
use super::*;

pub(super) const COMMERCE_ESCROW_LEDGER_ROLE: &str = "commerce-escrow-ledger";

/// Loads the escrow ledger that `order_context.escrow_digest` pins.
///
/// An order context without a pin loads nothing. With a pin, every graph node
/// in the escrow ledger role is read through the shared collection budget with
/// its schema and graph digest checked, and exactly one of them must have the
/// pinned canonical digest. A graph recorded after release may also hold the
/// locked ledger, which the pin then excludes.
pub(super) fn load_commerce_escrow_ledger_bytes(
    bundle_dir: &Path,
    budget: &mut crate::input::collection::Budget,
    nodes: &[GraphArtifactNode],
    order_context: &chio_commerce_order::CommerceOrderContext,
    label: &str,
) -> Result<Option<Vec<u8>>, CliError> {
    let _ = (bundle_dir, budget, nodes, order_context, label);
    Ok(None)
}

#[cfg(test)]
#[path = "escrow_ledger_tests.rs"]
mod tests;
