pub(super) fn record_receipt_write_error() {
    crate::metrics::record_receipt_write(crate::metrics::RECEIPT_WRITE_OUTCOME_ERROR);
}

/// Export the kernel's signed content preimage before MCP result projection.
/// Consumers verify the receipt and this preimage, then use this output instead
/// of trusting a separately projected `content` or `structuredContent` field.
pub(super) fn tool_receipt_envelope(
    receipt: &chio_core::receipt::body::ChioReceipt,
    output: Option<&chio_kernel::ToolCallOutput>,
) -> serde_json::Value {
    use chio_kernel::ToolCallOutput;
    use serde_json::json;
    match output {
        Some(ToolCallOutput::Value(value)) => {
            json!({"version":1,"receipt":receipt,"output_kind":"value","output":value})
        }
        None => json!({"version":1,"receipt":receipt,"output_kind":"none","output":null}),
        // Stream commitments have a different preimage. Export their receipt,
        // but do not claim that the projected MCP result is the signed content.
        Some(ToolCallOutput::Stream(_)) => {
            json!({"version":1,"receipt":receipt,"output_kind":"stream"})
        }
    }
}

pub(super) fn attach_tool_receipt_envelope(
    mut result: serde_json::Value,
    envelope: Option<serde_json::Value>,
) -> serde_json::Value {
    let Some(envelope) = envelope else {
        return result;
    };
    if let Some(object) = result.as_object_mut() {
        let meta = object
            .entry("_meta")
            .or_insert_with(|| serde_json::json!({}));
        // Upstream tools do not own the Chio receipt namespace. Replace even a
        // malformed upstream metadata value before installing kernel evidence.
        if !meta.is_object() {
            *meta = serde_json::json!({});
        }
        if let Some(meta) = meta.as_object_mut() {
            meta.insert("chioReceipt".into(), envelope);
        }
    }
    result
}

fn is_receipt_write_error(error: &chio_kernel::KernelError) -> bool {
    !matches!(
        error,
        chio_kernel::KernelError::RequestCancelled { .. }
            | chio_kernel::KernelError::UrlElicitationsRequired { .. }
    )
}

pub(super) fn record_receipt_write_kernel_error(error: &chio_kernel::KernelError) {
    if is_receipt_write_error(error) {
        record_receipt_write_error();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_and_retryable_url_elicitation_are_not_receipt_write_errors() {
        let url_error = chio_kernel::KernelError::UrlElicitationsRequired {
            message: "URL elicitation required".to_string(),
            elicitations: Vec::new(),
        };
        let cancellation = chio_kernel::KernelError::RequestCancelled {
            request_id: chio_core::session::RequestId::new("cancelled-request"),
            reason: "cancelled by caller".to_string(),
        };

        assert!(!is_receipt_write_error(&url_error));
        assert!(!is_receipt_write_error(&cancellation));
        assert!(is_receipt_write_error(&chio_kernel::KernelError::Internal(
            "receipt sink unavailable".to_string()
        )));
    }
}
