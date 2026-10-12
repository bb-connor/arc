use super::receipt_scopes::next_fixed_runtime_receipt_id;
use crate::*;
use uuid::Uuid;

pub(crate) fn prepare_child_request_receipt(
    policy_hash: &str,
    kernel_key: chio_core::PublicKey,
    context: &OperationContext,
    operation_kind: OperationKind,
    terminal_state: OperationTerminalState,
    outcome_payload: serde_json::Value,
) -> Result<ChildRequestReceiptBody, KernelError> {
    let outcome_hash = canonical_json_bytes(&outcome_payload)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!("failed to hash child outcome: {error}"))
        })?;
    let metadata = child_receipt_metadata(&outcome_payload);
    let parent_request_id = context.parent_request_id.clone().ok_or_else(|| {
        KernelError::ReceiptSigningFailed("child receipt requires parent request lineage".into())
    })?;

    Ok(ChildRequestReceiptBody {
        id: next_receipt_id("child-rcpt")?,
        timestamp: 0,
        session_id: context.session_id.clone(),
        parent_request_id,
        request_id: context.request_id.clone(),
        operation_kind,
        terminal_state,
        outcome_hash,
        policy_hash: policy_hash.to_string(),
        metadata,
        kernel_key,
    })
}

pub(crate) fn next_receipt_id(prefix: &str) -> Result<String, KernelError> {
    if let Some(id) = next_fixed_runtime_receipt_id(prefix)? {
        return Ok(id);
    }
    Ok(format!("{prefix}-{}", Uuid::now_v7()))
}

fn child_receipt_metadata(outcome_payload: &serde_json::Value) -> Option<serde_json::Value> {
    outcome_payload
        .get("outcome")
        .and_then(serde_json::Value::as_str)
        .map(|outcome| {
            let mut metadata = serde_json::Map::new();
            metadata.insert(
                "outcome".to_string(),
                serde_json::Value::String(outcome.to_string()),
            );
            if let Some(message) = outcome_payload
                .get("message")
                .and_then(serde_json::Value::as_str)
            {
                metadata.insert(
                    "message".to_string(),
                    serde_json::Value::String(message.to_string()),
                );
            }
            for key in [
                "message_sha256",
                "message_truncated",
                "encoding_error_code",
                "original_payload_omitted",
            ] {
                if let Some(value) = outcome_payload.get(key) {
                    metadata.insert(key.into(), value.clone());
                }
            }
            serde_json::Value::Object(metadata)
        })
}

pub(crate) fn child_terminal_state<T>(
    request_id: &RequestId,
    result: &Result<T, KernelError>,
) -> OperationTerminalState {
    match result {
        Ok(_) => OperationTerminalState::Completed,
        Err(KernelError::RequestCancelled {
            request_id: cancelled_request_id,
            reason,
        }) if cancelled_request_id == request_id => OperationTerminalState::Cancelled {
            reason: bounded_child_diagnostic(reason),
        },
        Err(KernelError::RequestIncomplete(reason)) => OperationTerminalState::Incomplete {
            reason: bounded_child_diagnostic(reason),
        },
        Err(_) => OperationTerminalState::Completed,
    }
}

pub(crate) fn child_outcome_payload<T: serde::Serialize>(
    result: &Result<T, KernelError>,
) -> Result<serde_json::Value, KernelError> {
    match result {
        Ok(value) => {
            let mut payload = serde_json::Map::new();
            payload.insert(
                "outcome".to_string(),
                serde_json::Value::String("result".into()),
            );
            payload.insert(
                "result".to_string(),
                serde_json::to_value(value).map_err(|error| {
                    KernelError::ReceiptSigningFailed(format!(
                        "failed to serialize child result: {error}"
                    ))
                })?,
            );
            Ok(serde_json::Value::Object(payload))
        }
        Err(error) => {
            let message = error.to_string();
            Ok(serde_json::json!({
                "outcome": "error",
                "message": bounded_child_diagnostic(&message),
                "message_sha256": sha256_hex(message.as_bytes()),
                "message_truncated": message.len() > 512,
            }))
        }
    }
}

fn bounded_child_diagnostic(message: &str) -> String {
    let mut end = message.len().min(512);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_owned()
}
