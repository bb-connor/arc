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
    let Some(pinned) = order_context.escrow_digest.as_deref() else {
        return Ok(None);
    };
    let candidates = graph_nodes_by_role(nodes, COMMERCE_ESCROW_LEDGER_ROLE);
    if candidates.is_empty() {
        return Err(graph_not_closed(format!(
            "proof verify: missing {label} escrow ledger for pinned digest {pinned}",
        )));
    }
    let mut selected = Vec::new();
    for node in candidates {
        let bytes = load_graph_bytes_artifact_bounded(
            bundle_dir,
            node,
            chio_commerce_order::COMMERCE_ESCROW_LEDGER_SCHEMA_ID,
            label,
            budget,
        )?;
        let ledger: chio_commerce_order::CommerceEscrowLedger = crate::input::json(&bytes)?;
        let digest = ledger.digest().map_err(|error| {
            artifact_schema_invalid(format!(
                "proof verify: {label} escrow ledger {} is not canonical: {error}",
                node.path,
            ))
        })?;
        if digest == pinned {
            selected.push(bytes);
        }
    }
    let mut selected = selected.into_iter();
    match (selected.next(), selected.next()) {
        (Some(bytes), None) => Ok(Some(bytes)),
        (None, _) => Err(artifact_digest_mismatch(format!(
            "proof verify: no {label} escrow ledger matches pinned digest {pinned}",
        ))),
        (Some(_), Some(_)) => Err(artifact_schema_invalid(format!(
            "proof verify: multiple {label} escrow ledgers match pinned digest {pinned}",
        ))),
    }
}

#[cfg(test)]
#[path = "escrow_ledger_tests.rs"]
mod tests;
