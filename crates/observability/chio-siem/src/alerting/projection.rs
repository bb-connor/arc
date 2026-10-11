//! Notification payloads contain references, never the denied input or details.
use super::*;

pub(super) fn build_alert(event: &SiemEvent, trusted_pin: Option<&PublicKey>) -> Alert {
    let projection =
        crate::sink_projection::SiemSinkProjection::from_receipt(&event.receipt, trusted_pin);
    let guard = projection
        .guard_sha256
        .as_ref()
        .map(|guard| format!("sha256:{}", guard.as_str()))
        .unwrap_or_else(|| "chio.kernel".to_string());
    let tool_server = format!("sha256:{}", projection.tool_server_sha256.as_str());
    let tool_name = format!("sha256:{}", projection.tool_name_sha256.as_str());
    // A guard reason or evidence detail may repeat the secret it blocked.
    // Operators can retrieve the original evidence through the receipt log's
    // authorized read path, using this notification's stable receipt reference.
    let summary = format!(
        "Chio guard deny: {} on {}/{}",
        guard, tool_server, tool_name
    );
    let dedup_key = format!("{}::{}::{}", guard, tool_name, projection.event_reference());
    let receipt_json = serde_json::json!({
        "projection": "receipt_reference",
        "receipt_id": projection.event_reference(),
        "timestamp": projection.timestamp,
        "parameter_hash": projection.parameter_hash,
        "policy_hash": projection.policy_hash,
        "source_redaction_mode": projection.source_redaction_mode,
        "payload_included": false,
        "original_retrieval_required": true,
        "projection_signed": false,
        "signature_scope": "original_receipt",
    });
    Alert {
        summary,
        severity: derive_event_severity(event),
        dedup_key,
        guard,
        tool_name,
        tool_server,
        receipt_id: projection.event_reference().to_string(),
        receipt_json,
    }
}
