use super::*;

pub(super) fn normalize_transport_output(messages: &mut [Value]) {
    for message in messages {
        normalize_dynamic_transport_fields(message);
    }
}

pub(super) fn normalize_dynamic_transport_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(value) = map.get_mut("receipt") {
                let receipt: chio_core::receipt::body::ChioReceipt =
                    serde_json::from_value(value.clone()).unwrap();
                assert!(receipt.verify_signature().unwrap());
                // These transcripts use separately constructed kernels and
                // sessions. Verify each signature, then compare decision and
                // tool semantics without comparing fresh signing identities.
                *value = json!({
                    "tool_server":receipt.tool_server, "tool_name":receipt.tool_name,
                    "action":receipt.action, "decision":receipt.decision,
                    "receipt_kind":receipt.receipt_kind, "boundary_class":receipt.boundary_class,
                    "observation_outcome":receipt.observation_outcome, "tool_origin":receipt.tool_origin,
                    "redaction_mode":receipt.redaction_mode, "trust_level":receipt.trust_level,
                    "policy_hash":receipt.policy_hash, "tenant_id":receipt.tenant_id,
                });
            }
            if let Some(receipt_id) = map.get_mut("receiptId") {
                *receipt_id = json!("$receipt");
            }
            // Each transport run has a fresh signing identity. Dedicated
            // execution-evidence tests verify these receipts and their bindings.
            map.remove("chioEvidence");
            if let Some(owner_session_id) = map.get_mut("ownerSessionId") {
                *owner_session_id = json!("$session");
            }
            if let Some(owner_request_id) = map.get_mut("ownerRequestId") {
                *owner_request_id = json!("$request");
            }
            // The two transports capture wall-clock timestamps independently;
            // a tick across a second boundary between the stdio and channel
            // runs causes assert_eq! to flake. The shape comparison is what
            // matters, so collapse the captured instants to a sentinel.
            for field in ["createdAt", "lastUpdatedAt"] {
                if let Some(ts) = map.get_mut(field) {
                    *ts = json!("$timestamp");
                }
            }
            for child in map.values_mut() {
                normalize_dynamic_transport_fields(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                normalize_dynamic_transport_fields(child);
            }
        }
        _ => {}
    }
}
