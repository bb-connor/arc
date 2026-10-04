//! Notification payloads contain references, never the denied input or details.
use super::*;

pub(super) fn build_alert(event: &SiemEvent) -> Alert {
    let receipt = &event.receipt;
    let guard = match &receipt.decision {
        Some(Decision::Deny { guard, .. }) => guard.clone(),
        _ => "chio.kernel".to_string(),
    };
    // A guard reason or evidence detail may repeat the secret it blocked.
    // Operators can retrieve the original evidence through the receipt log's
    // authorized read path, using this notification's stable receipt reference.
    let summary = format!(
        "Chio guard deny: {} on {}/{}",
        guard, receipt.tool_server, receipt.tool_name
    );
    let dedup_key = format!("{}::{}::{}", guard, receipt.tool_name, receipt.id);
    let receipt_json = serde_json::json!({
        "projection": "receipt_reference",
        "receipt_id": receipt.id,
        "timestamp": receipt.timestamp,
        "parameter_hash": receipt.action.parameter_hash,
        "policy_hash": receipt.policy_hash,
        "source_redaction_mode": receipt.redaction_mode,
        "payload_included": false,
    });
    Alert {
        summary,
        severity: derive_event_severity(event),
        dedup_key,
        guard,
        tool_name: receipt.tool_name.clone(),
        tool_server: receipt.tool_server.clone(),
        receipt_id: receipt.id.clone(),
        receipt_json,
    }
}
