// Kernel-output conversion, Chio metadata envelope builders, and the
// surface/lifecycle metadata for kernel-mediated execution.

fn kernel_output_to_value(output: Option<&ToolCallOutput>) -> Value {
    match output {
        Some(ToolCallOutput::Value(value)) => value.clone(),
        Some(ToolCallOutput::Stream(stream)) => json!({
            "stream": stream
                .chunks
                .iter()
                .map(|chunk| chunk.data.clone())
                .collect::<Vec<_>>()
        }),
        None => Value::Null,
    }
}

fn authoritative_surface_metadata() -> Value {
    json!({
        "chio": {
            "authorityPath": "cross_protocol_orchestrator",
            "authoritative": true,
            "claimEligible": true,
            "receiptBearingInvoke": true,
            "permissionPreviewOnly": true,
            "invokeMode": "blocking_or_deferred_task",
            "runtimeLifecycle": runtime_lifecycle_metadata(RuntimeLifecycleSurface::AcpAuthoritative),
            "lifecycle": {
                "toolInvoke": "blocking_terminal_result",
                "toolStream": "deferred_task_resume",
                "toolCancel": "supported",
                "toolResume": "supported"
            },
            "streamDelivery": "resumed_terminal_payload",
        }
    })
}

fn pending_stream_task_metadata(authority_path: &str) -> Value {
    json!({
        "chio": {
            "receiptId": Value::Null,
            "receipt": Value::Null,
            "decision": "pending",
            "capabilityId": Value::Null,
            "authorityPath": authority_path,
            "authoritative": true,
            "claimEligible": true,
            "receiptBearing": false,
            "receiptPending": true,
            "runtimeLifecycle": runtime_lifecycle_metadata(RuntimeLifecycleSurface::AcpAuthoritative),
            "lifecycle": {
                "toolInvoke": "blocking_terminal_result",
                "toolStream": "deferred_task_resume",
                "toolCancel": "supported",
                "toolResume": "supported"
            }
        }
    })
}

fn cancelled_stream_task_metadata(authority_path: &str) -> Value {
    json!({
        "chio": {
            "receiptId": Value::Null,
            "receipt": Value::Null,
            "decision": "cancelled",
            "capabilityId": Value::Null,
            "authorityPath": authority_path,
            "authoritative": true,
            "claimEligible": true,
            "receiptBearing": false,
            "runtimeLifecycle": runtime_lifecycle_metadata(RuntimeLifecycleSurface::AcpAuthoritative),
            "lifecycle": {
                "toolInvoke": "blocking_terminal_result",
                "toolStream": "deferred_task_resume",
                "toolCancel": "supported",
                "toolResume": "supported"
            }
        }
    })
}

fn acp_invocation_result_from_orchestrated(
    orchestrated: OrchestratedToolCall,
) -> AcpInvocationResult {
    let data = chio_cross_protocol::execution::pending_approval_result(
        orchestrated.response.verdict,
        orchestrated.response.output.as_ref(),
    )
    .unwrap_or_else(|| {
        orchestrated
            .protocol_result
            .clone()
            .unwrap_or_else(|| kernel_output_to_value(orchestrated.response.output.as_ref()))
    });
    let metadata = Some(orchestrated.metadata());
    let response = orchestrated.response;
    let success =
        matches!(response.verdict, KernelVerdict::Allow) && response.terminal_state.is_completed();
    let error = if success {
        None
    } else {
        response
            .reason
            .or_else(|| terminal_state_reason(&response.terminal_state))
    };

    crate::metrics::record_receipt_write_verdict(response.verdict);

    AcpInvocationResult {
        success,
        data,
        error,
        metadata,
    }
}

fn terminal_state_reason(terminal_state: &OperationTerminalState) -> Option<String> {
    match terminal_state {
        OperationTerminalState::Completed => None,
        OperationTerminalState::Cancelled { reason }
        | OperationTerminalState::Incomplete { reason } => Some(reason.clone()),
    }
}

fn build_acp_source_envelope(capability_id: &str, arguments: Value) -> Result<Value, BridgeError> {
    let mut envelope = json!({
        "capabilityId": capability_id,
        "arguments": arguments,
    });
    let _ = ensure_chio_metadata(&mut envelope)?;
    Ok(envelope)
}

fn ensure_chio_metadata(
    envelope: &mut Value,
) -> Result<&mut serde_json::Map<String, Value>, BridgeError> {
    let Some(object) = envelope.as_object_mut() else {
        return Err(BridgeError::InvalidRequest(
            "request envelope must be a JSON object".to_string(),
        ));
    };
    let metadata = object
        .entry("metadata".to_string())
        .or_insert_with(|| json!({}));
    let Some(metadata_obj) = metadata.as_object_mut() else {
        return Err(BridgeError::InvalidRequest(
            "metadata must be a JSON object".to_string(),
        ));
    };
    let chio = metadata_obj
        .entry("chio".to_string())
        .or_insert_with(|| json!({}));
    chio.as_object_mut().ok_or_else(|| {
        BridgeError::InvalidRequest("metadata.chio must be a JSON object".to_string())
    })
}

fn permission_preview_metadata(path: &str) -> Value {
    json!({
        "chio": {
            "receiptId": Value::Null,
            "receipt": Value::Null,
            "authorityPath": path,
            "authoritative": false,
            "previewOnly": true,
            "claimEligible": false,
            "receiptBearing": false,
            "invokeAuthorityPath": "cross_protocol_orchestrator",
            "reason": "permission preview only",
        }
    })
}
