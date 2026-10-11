use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::{body::ChioReceiptBody, decision::ToolCallAction};

use super::*;

fn signed(request: &str, decision: Decision) -> Fallible<Value> {
    let key = Keypair::from_seed(&[19; 32]);
    let body: ChioReceiptBody = serde_json::from_value(json!({
        "id": request, "timestamp": 1_700_000_000,
        "capability_id": "cap-1", "tool_server": "reader", "tool_name": "stat",
        "action": ToolCallAction::from_parameters(json!({"path":"README.md"}))?,
        "decision": decision, "receipt_kind": "mediated_decision",
        "boundary_class": "prevent", "tool_origin": "caller_executed",
        "redaction_mode": "none", "content_hash": sha256_hex(b"null"),
        "policy_hash": sha256_hex(b"policy"), "trust_level": "mediated",
        "kernel_key": key.public_key(),
        "metadata": {"receipt_context":{"request_id":request}}
    }))?;
    Ok(serde_json::to_value(ChioReceipt::sign(body, &key)?)?)
}

fn budget_denial() -> Decision {
    Decision::Deny {
        reason: "invocation budget exhausted for capability cap-1".to_owned(),
        guard: "kernel".to_owned(),
    }
}

#[test]
fn verifies_distinct_signed_allows_and_exact_budget_denials() -> Fallible<()> {
    let receipts = vec![
        signed("allow", Decision::Allow)?,
        signed("deny", budget_denial())?,
    ];
    assert_eq!(verify_counts(receipts, "cap-1", "reader")?, (1, 1));
    Ok(())
}

#[test]
fn rejects_tampering_duplicates_and_foreign_or_unrelated_decisions() -> Fallible<()> {
    let valid = signed("one", budget_denial())?;
    assert!(verify_counts(vec![valid.clone(), valid.clone()], "cap-1", "reader").is_err());
    assert!(verify_counts(vec![valid.clone()], "cap-2", "reader").is_err());
    assert!(verify_counts(vec![valid.clone()], "cap-1", "writer").is_err());
    let mut altered = valid;
    altered["decision"]["reason"] = json!("forged reason");
    assert!(verify_counts(vec![altered], "cap-1", "reader").is_err());
    let other = signed(
        "two",
        Decision::Deny {
            reason: "authority unavailable".to_owned(),
            guard: "kernel".to_owned(),
        },
    )?;
    assert!(verify_counts(vec![other], "cap-1", "reader").is_err());
    // Different signatures and receipt IDs cannot double-count one invocation.
    let first = signed("same-request", Decision::Allow)?;
    let second = signed("same-request", budget_denial())?;
    assert!(verify_counts(vec![first, second], "cap-1", "reader").is_err());
    Ok(())
}
