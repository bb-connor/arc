use super::*;
use uuid::Uuid;

pub(super) fn build_child_request_receipt(
    policy_hash: &str,
    keypair: &Keypair,
    context: &OperationContext,
    operation_kind: OperationKind,
    terminal_state: OperationTerminalState,
    outcome_payload: serde_json::Value,
) -> Result<ChildRequestReceipt, KernelError> {
    let outcome_hash = canonical_json_bytes(&outcome_payload)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!("failed to hash child outcome: {error}"))
        })?;
    let metadata = child_receipt_metadata(&outcome_payload);
    let parent_request_id = context.parent_request_id.clone().ok_or_else(|| {
        KernelError::ReceiptSigningFailed("child receipt requires parent request lineage".into())
    })?;

    let body = ChildRequestReceiptBody {
        id: next_receipt_id("child-rcpt"),
        timestamp: current_unix_timestamp(),
        session_id: context.session_id.clone(),
        parent_request_id,
        request_id: context.request_id.clone(),
        operation_kind,
        terminal_state,
        outcome_hash,
        policy_hash: policy_hash.to_string(),
        metadata,
        kernel_key: keypair.public_key(),
    };

    ChildRequestReceipt::sign(body, keypair)
        .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))
}

pub(super) fn next_receipt_id(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::now_v7())
}

pub(super) fn merge_metadata_objects(
    base: Option<serde_json::Value>,
    extra: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    match (base, extra) {
        (None, extra) => extra,
        (Some(base), None) => Some(base),
        (Some(mut base), Some(extra)) => {
            if let (Some(base_obj), Some(extra_obj)) = (base.as_object_mut(), extra.as_object()) {
                for (key, value) in extra_obj {
                    base_obj.insert(key.clone(), value.clone());
                }
            }
            Some(base)
        }
    }
}

pub(super) fn governed_request_metadata(
    request: &ToolCallRequest,
    attestation_trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
) -> Result<Option<serde_json::Value>, KernelError> {
    let Some(intent) = request.governed_intent.as_ref() else {
        return Ok(None);
    };

    let approval =
        request
            .approval_token
            .as_ref()
            .map(|approval_token| GovernedApprovalReceiptMetadata {
                token_id: approval_token.id.clone(),
                approver_key: approval_token.approver.to_hex(),
                approved: approval_token.decision == GovernedApprovalDecision::Approved,
            });
    let commerce = intent
        .commerce
        .as_ref()
        .map(|commerce| GovernedCommerceReceiptMetadata {
            seller: commerce.seller.clone(),
            shared_payment_token_id: commerce.shared_payment_token_id.clone(),
        });
    let metered_billing =
        intent
            .metered_billing
            .as_ref()
            .map(|metered| MeteredBillingReceiptMetadata {
                settlement_mode: metered.settlement_mode,
                quote: metered.quote.clone(),
                max_billed_units: metered.max_billed_units,
                usage_evidence: None,
            });
    let runtime_assurance = match intent.runtime_attestation.as_ref() {
        Some(attestation) => Some(RuntimeAssuranceReceiptMetadata {
            schema: attestation.schema.clone(),
            verifier_family: verifier_family_for_attestation_schema(&attestation.schema),
            tier: attestation
                .resolve_effective_runtime_assurance(attestation_trust_policy, now)
                .map(|resolved| resolved.effective_tier)
                .unwrap_or(attestation.tier),
            verifier: attestation.verifier.clone(),
            evidence_sha256: attestation.evidence_sha256.clone(),
            workload_identity: attestation.normalized_workload_identity().ok().flatten(),
        }),
        None => None,
    };
    let autonomy = intent
        .autonomy
        .as_ref()
        .map(|autonomy| GovernedAutonomyReceiptMetadata {
            tier: autonomy.tier,
            delegation_bond_id: autonomy.delegation_bond_id.clone(),
        });
    let metadata = GovernedTransactionReceiptMetadata {
        intent_id: intent.id.clone(),
        intent_hash: intent.binding_hash().map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to hash governed transaction intent for receipt metadata: {error}"
            ))
        })?,
        purpose: intent.purpose.clone(),
        server_id: intent.server_id.clone(),
        tool_name: intent.tool_name.clone(),
        max_amount: intent.max_amount.clone(),
        commerce,
        metered_billing,
        approval,
        runtime_assurance,
        call_chain: intent.call_chain.clone(),
        autonomy,
    };

    Ok(Some(serde_json::json!({
        "governed_transaction": metadata
    })))
}

pub(super) fn receipt_attribution_metadata(
    capability: &CapabilityToken,
    matched_grant_index: Option<usize>,
) -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "attribution": ReceiptAttributionMetadata {
            subject_key: capability.subject.to_hex(),
            issuer_key: capability.issuer.to_hex(),
            delegation_depth: capability.delegation_chain.len() as u32,
            grant_index: matched_grant_index.map(|index| index as u32),
        }
    }))
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
            serde_json::Value::Object(metadata)
        })
}

pub(super) fn child_terminal_state<T>(
    request_id: &RequestId,
    result: &Result<T, KernelError>,
) -> OperationTerminalState {
    match result {
        Ok(_) => OperationTerminalState::Completed,
        Err(KernelError::RequestCancelled {
            request_id: cancelled_request_id,
            reason,
        }) if cancelled_request_id == request_id => OperationTerminalState::Cancelled {
            reason: reason.clone(),
        },
        Err(KernelError::RequestIncomplete(reason)) => OperationTerminalState::Incomplete {
            reason: reason.clone(),
        },
        Err(_) => OperationTerminalState::Completed,
    }
}

pub(super) fn child_outcome_payload<T: serde::Serialize>(
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
        Err(error) => Ok(serde_json::json!({
            "outcome": "error",
            "message": error.to_string(),
        })),
    }
}

pub(super) fn receipt_content_for_output(
    output: Option<&ToolCallOutput>,
    stream_chunks_expected: Option<u64>,
) -> Result<ReceiptContent, KernelError> {
    match output {
        Some(ToolCallOutput::Value(value)) => {
            let bytes = canonical_json_bytes(value).map_err(|e| {
                KernelError::ReceiptSigningFailed(format!("failed to hash tool output: {e}"))
            })?;
            Ok(ReceiptContent {
                content_hash: sha256_hex(&bytes),
                metadata: None,
            })
        }
        Some(ToolCallOutput::Stream(stream)) => {
            stream_receipt_content(stream, stream_chunks_expected)
        }
        None => Ok(ReceiptContent {
            content_hash: sha256_hex(b"null"),
            metadata: None,
        }),
    }
}

fn stream_receipt_content(
    stream: &ToolCallStream,
    chunks_expected: Option<u64>,
) -> Result<ReceiptContent, KernelError> {
    let mut chunk_hashes = Vec::with_capacity(stream.chunks.len());
    let mut combined = Vec::new();
    let mut total_bytes = 0u64;

    for chunk in &stream.chunks {
        let bytes = canonical_json_bytes(&chunk.data).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash stream chunk: {e}"))
        })?;
        total_bytes += bytes.len() as u64;
        let chunk_hash = sha256_hex(&bytes);
        combined.extend_from_slice(chunk_hash.as_bytes());
        chunk_hashes.push(chunk_hash);
    }

    Ok(ReceiptContent {
        content_hash: sha256_hex(&combined),
        metadata: Some(serde_json::json!({
            "stream": {
                "chunks_expected": chunks_expected,
                "chunks_received": stream.chunk_count(),
                "total_bytes": total_bytes,
                "chunk_hashes": chunk_hashes,
            }
        })),
    })
}

pub(super) fn truncate_stream_to_byte_limit(
    stream: &ToolCallStream,
    max_stream_total_bytes: u64,
) -> Result<(ToolCallStream, u64, bool), KernelError> {
    let mut accepted = Vec::new();
    let mut total_bytes = 0u64;
    let mut truncated = false;

    for chunk in &stream.chunks {
        let bytes = canonical_json_bytes(&chunk.data).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to size stream chunk: {e}"))
        })?;
        let chunk_bytes = bytes.len() as u64;
        if max_stream_total_bytes > 0
            && total_bytes.saturating_add(chunk_bytes) > max_stream_total_bytes
        {
            truncated = true;
            break;
        }
        total_bytes += chunk_bytes;
        accepted.push(chunk.clone());
    }

    Ok((ToolCallStream { chunks: accepted }, total_bytes, truncated))
}
