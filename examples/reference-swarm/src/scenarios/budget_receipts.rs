//! Corroborate budget responses against the authenticated control service's
//! receipt inventory. Signature validity is checked here; independent operator
//! key qualification and confinement remain outside this integration fixture.

use std::collections::BTreeSet;

use chio_core_types::receipt::{body::ChioReceipt, decision::Decision};

use super::*;

#[cfg(test)]
mod tests;

pub(super) fn verify_counts(
    receipts: Vec<Value>,
    capability_id: &str,
    server_id: &str,
) -> Fallible<(usize, usize)> {
    let mut identifiers = BTreeSet::new();
    let mut requests = BTreeSet::new();
    let mut allowed = 0;
    let mut denied = 0;
    let expected_reason = format!("invocation budget exhausted for capability {capability_id}");
    for value in receipts {
        let request_id = value["metadata"]["receipt_context"]["request_id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or("receipt has no request identity")?
            .to_owned();
        let receipt: ChioReceipt = serde_json::from_value(value)?;
        if !receipt.verify_signature()?
            || receipt.capability_id != capability_id
            || receipt.tool_server != server_id
            || receipt.tool_name != "stat"
            || !identifiers.insert(receipt.id.clone())
            || !requests.insert(request_id)
        {
            return Err(
                "budget receipt is invalid, duplicated, or belongs to another invocation".into(),
            );
        }
        match receipt.decision {
            Some(Decision::Allow) => allowed += 1,
            Some(Decision::Deny { reason, guard })
                if guard == "kernel" && reason == expected_reason =>
            {
                denied += 1
            }
            _ => {
                return Err(
                    "budget receipt does not attest an allow or exact kernel budget denial".into(),
                )
            }
        }
    }
    Ok((allowed, denied))
}
