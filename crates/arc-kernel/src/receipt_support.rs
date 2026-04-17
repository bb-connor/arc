use std::cell::RefCell;

use super::*;
use arc_appraisal::{verify_runtime_attestation_record, VerifiedRuntimeAttestationRecord};
use arc_core::capability::{
    GovernedCallChainContext, GovernedCallChainEvidenceSource, GovernedCallChainProvenance,
    GovernedProvenanceEvidenceClass, GovernedUpstreamCallChainProof,
};
use uuid::Uuid;

use crate::evidence_export::EvidenceLineageReferences;
use crate::operator_report::GovernedTransactionDiagnostics;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GovernedCallChainReceiptEvidence {
    pub(crate) local_parent_request_id: Option<String>,
    pub(crate) local_parent_receipt_id: Option<String>,
    pub(crate) capability_delegator_subject: Option<String>,
    pub(crate) capability_origin_subject: Option<String>,
    pub(crate) upstream_proof: Option<GovernedUpstreamCallChainProof>,
    pub(crate) continuation_token_id: Option<String>,
    pub(crate) session_anchor_id: Option<String>,
}

thread_local! {
    static GOVERNED_CALL_CHAIN_RECEIPT_EVIDENCE: RefCell<Option<GovernedCallChainReceiptEvidence>> =
        const { RefCell::new(None) };
    static GOVERNED_RUNTIME_ATTESTATION_RECORD: RefCell<Option<VerifiedRuntimeAttestationRecord>> =
        const { RefCell::new(None) };
}

pub(crate) struct ScopedGovernedCallChainReceiptEvidence {
    previous: Option<GovernedCallChainReceiptEvidence>,
}

impl Drop for ScopedGovernedCallChainReceiptEvidence {
    fn drop(&mut self) {
        let previous = self.previous.take();
        GOVERNED_CALL_CHAIN_RECEIPT_EVIDENCE.with(|slot| {
            slot.replace(previous);
        });
    }
}

pub(crate) fn scope_governed_call_chain_receipt_evidence(
    evidence: Option<GovernedCallChainReceiptEvidence>,
) -> ScopedGovernedCallChainReceiptEvidence {
    let previous = GOVERNED_CALL_CHAIN_RECEIPT_EVIDENCE.with(|slot| slot.replace(evidence));
    ScopedGovernedCallChainReceiptEvidence { previous }
}

fn current_governed_call_chain_receipt_evidence() -> Option<GovernedCallChainReceiptEvidence> {
    GOVERNED_CALL_CHAIN_RECEIPT_EVIDENCE.with(|slot| slot.borrow().clone())
}

pub(crate) struct ScopedGovernedRuntimeAttestationRecord {
    previous: Option<VerifiedRuntimeAttestationRecord>,
}

impl Drop for ScopedGovernedRuntimeAttestationRecord {
    fn drop(&mut self) {
        let previous = self.previous.take();
        GOVERNED_RUNTIME_ATTESTATION_RECORD.with(|slot| {
            slot.replace(previous);
        });
    }
}

pub(crate) fn scope_governed_runtime_attestation_receipt_record(
    record: Option<VerifiedRuntimeAttestationRecord>,
) -> ScopedGovernedRuntimeAttestationRecord {
    let previous = GOVERNED_RUNTIME_ATTESTATION_RECORD.with(|slot| slot.replace(record));
    ScopedGovernedRuntimeAttestationRecord { previous }
}

fn current_governed_runtime_attestation_record() -> Option<VerifiedRuntimeAttestationRecord> {
    GOVERNED_RUNTIME_ATTESTATION_RECORD.with(|slot| slot.borrow().clone())
}

fn governed_call_chain_provenance(
    context: GovernedCallChainContext,
) -> GovernedCallChainProvenance {
    let Some(evidence) = current_governed_call_chain_receipt_evidence() else {
        return GovernedCallChainProvenance::asserted(context);
    };

    let upstream_proof = evidence.upstream_proof.clone();
    let mut evidence_sources = Vec::new();

    if evidence.local_parent_request_id.as_deref() == Some(context.parent_request_id.as_str()) {
        evidence_sources.push(GovernedCallChainEvidenceSource::SessionParentRequestLineage);
    }
    if evidence.local_parent_receipt_id.is_some()
        && evidence.local_parent_receipt_id.as_deref() == context.parent_receipt_id.as_deref()
    {
        evidence_sources.push(GovernedCallChainEvidenceSource::LocalParentReceiptLinkage);
    }
    if evidence.capability_delegator_subject.as_deref() == Some(context.delegator_subject.as_str())
    {
        evidence_sources.push(GovernedCallChainEvidenceSource::CapabilityDelegatorSubject);
    }
    if evidence.capability_origin_subject.as_deref() == Some(context.origin_subject.as_str()) {
        evidence_sources.push(GovernedCallChainEvidenceSource::CapabilityOriginSubject);
    }
    if upstream_proof.is_some() {
        evidence_sources.push(GovernedCallChainEvidenceSource::UpstreamDelegatorProof);
    }

    let mut provenance = GovernedCallChainProvenance::new(
        context,
        if upstream_proof.is_some() {
            GovernedProvenanceEvidenceClass::Verified
        } else if evidence_sources.is_empty() {
            GovernedProvenanceEvidenceClass::Asserted
        } else {
            GovernedProvenanceEvidenceClass::Observed
        },
    )
    .with_evidence_sources(evidence_sources);

    if let Some(upstream_proof) = upstream_proof {
        provenance = provenance.with_upstream_proof(upstream_proof);
    }
    if let Some(continuation_token_id) = evidence.continuation_token_id {
        provenance = provenance.with_continuation_token_id(continuation_token_id);
    }
    if let Some(session_anchor_id) = evidence.session_anchor_id {
        provenance = provenance.with_session_anchor_id(session_anchor_id);
    }

    provenance
}

fn governed_transaction_diagnostics(
    call_chain: Option<&GovernedCallChainProvenance>,
) -> Option<GovernedTransactionDiagnostics> {
    let diagnostics = GovernedTransactionDiagnostics {
        asserted_call_chain: call_chain.cloned().filter(|call_chain| {
            call_chain.evidence_class == GovernedProvenanceEvidenceClass::Asserted
        }),
        lineage_references: EvidenceLineageReferences {
            session_anchor_id: call_chain
                .and_then(|call_chain| call_chain.session_anchor_id.clone()),
            request_lineage_id: None,
            receipt_lineage_statement_id: call_chain
                .and_then(|call_chain| call_chain.receipt_lineage_statement_id.clone()),
        },
    };

    (!diagnostics.is_empty()).then_some(diagnostics)
}

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

pub(super) fn verify_governed_runtime_attestation_record(
    attestation: &arc_core::capability::RuntimeAttestationEvidence,
    attestation_trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
) -> Result<VerifiedRuntimeAttestationRecord, KernelError> {
    verify_runtime_attestation_record(attestation, attestation_trust_policy, now).map_err(|error| {
        KernelError::GovernedTransactionDenied(format!(
            "runtime attestation evidence rejected by local verification boundary: {error}"
        ))
    })
}

fn verified_runtime_assurance_receipt_metadata(
    verified_runtime_attestation: &VerifiedRuntimeAttestationRecord,
) -> Option<RuntimeAssuranceReceiptMetadata> {
    if !verified_runtime_attestation.is_locally_accepted() {
        return None;
    }

    Some(RuntimeAssuranceReceiptMetadata {
        schema: verified_runtime_attestation.evidence.schema.clone(),
        verifier_family: Some(verified_runtime_attestation.provenance.verifier_family),
        tier: verified_runtime_attestation.effective_tier(),
        verifier: verified_runtime_attestation
            .provenance
            .canonical_verifier
            .clone(),
        evidence_sha256: verified_runtime_attestation
            .evidence
            .evidence_sha256
            .clone(),
        workload_identity: verified_runtime_attestation.workload_identity().cloned(),
    })
}

fn governed_runtime_assurance_receipt_metadata(
    attestation: Option<&arc_core::capability::RuntimeAttestationEvidence>,
    attestation_trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
) -> Option<RuntimeAssuranceReceiptMetadata> {
    let attestation = attestation?;
    let verified_runtime_attestation =
        verify_governed_runtime_attestation_record(attestation, attestation_trust_policy, now)
            .ok()?;
    verified_runtime_assurance_receipt_metadata(&verified_runtime_attestation)
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
    let runtime_assurance = if let Some(verified_runtime_attestation) =
        current_governed_runtime_attestation_record()
    {
        if intent
            .runtime_attestation
            .as_ref()
            .is_some_and(|attestation| verified_runtime_attestation.evidence != *attestation)
        {
            return Err(KernelError::ReceiptSigningFailed(
                "governed request runtime attestation does not match the scoped verified runtime attestation record".to_string(),
            ));
        }
        verified_runtime_assurance_receipt_metadata(&verified_runtime_attestation)
    } else {
        governed_runtime_assurance_receipt_metadata(
            intent.runtime_attestation.as_ref(),
            attestation_trust_policy,
            now,
        )
    };
    let autonomy = intent
        .autonomy
        .as_ref()
        .map(|autonomy| GovernedAutonomyReceiptMetadata {
            tier: autonomy.tier,
            delegation_bond_id: autonomy.delegation_bond_id.clone(),
        });
    let call_chain = intent
        .call_chain
        .clone()
        .map(governed_call_chain_provenance);
    let governed_transaction_diagnostics = governed_transaction_diagnostics(call_chain.as_ref());
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
        call_chain: call_chain.clone(),
        autonomy,
    };

    let mut metadata_object = serde_json::Map::from_iter([(
        "governed_transaction".to_string(),
        serde_json::to_value(metadata).map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to serialize governed receipt metadata: {error}"
            ))
        })?,
    )]);
    if let Some(diagnostics) = governed_transaction_diagnostics {
        metadata_object.insert(
            "governed_transaction_diagnostics".to_string(),
            serde_json::to_value(diagnostics).map_err(|error| {
                KernelError::ReceiptSigningFailed(format!(
                    "failed to serialize governed transaction diagnostics: {error}"
                ))
            })?,
        );
    }

    Ok(Some(serde_json::Value::Object(metadata_object)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core::capability::{
        ArcScope, AttestationTrustPolicy, AttestationTrustRule, CapabilityToken,
        CapabilityTokenBody, GovernedCallChainContext, GovernedProvenanceEvidenceClass,
        GovernedTransactionIntent, GovernedUpstreamCallChainProof,
        GovernedUpstreamCallChainProofBody, RuntimeAssuranceTier, RuntimeAttestationEvidence,
    };
    use arc_core::crypto::sha256_hex;

    fn test_capability() -> CapabilityToken {
        let keypair = Keypair::generate();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-test".to_string(),
                issuer: keypair.public_key(),
                subject: keypair.public_key(),
                scope: ArcScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::new(),
            },
            &keypair,
        )
        .expect("test capability should sign")
    }

    fn trusted_attestation_trust_policy() -> AttestationTrustPolicy {
        AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(arc_core::appraisal::AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: std::collections::BTreeMap::new(),
            }],
        }
    }

    fn raw_runtime_attestation() -> RuntimeAttestationEvidence {
        RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.v1".to_string(),
            verifier: "verifier.arc".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: sha256_hex(b"raw-runtime-attestation"),
            runtime_identity: Some("spiffe://arc/runtime/test".to_string()),
            workload_identity: None,
            claims: None,
        }
    }

    fn trusted_runtime_attestation() -> RuntimeAttestationEvidence {
        RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test/".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: sha256_hex(b"trusted-runtime-attestation"),
            runtime_identity: Some("spiffe://arc/runtime/test".to_string()),
            workload_identity: None,
            claims: Some(serde_json::json!({
                "azureMaa": {
                    "attestationType": "sgx"
                }
            })),
        }
    }

    fn trusted_nitro_attestation_trust_policy() -> AttestationTrustPolicy {
        AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "aws-nitro".to_string(),
                schema: "arc.runtime-attestation.aws-nitro-attestation.v1".to_string(),
                verifier: "https://nitro.aws.example".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(arc_core::appraisal::AttestationVerifierFamily::AwsNitro),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: Vec::new(),
                required_assertions: std::collections::BTreeMap::new(),
            }],
        }
    }

    fn trusted_nitro_runtime_attestation() -> RuntimeAttestationEvidence {
        RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.aws-nitro-attestation.v1".to_string(),
            verifier: "https://nitro.aws.example/".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: sha256_hex(b"trusted-nitro-runtime-attestation"),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "awsNitro": {
                    "moduleId": "nitro-enclave-1",
                    "digest": "sha384:aws-measurement",
                    "pcrs": { "0": "0123" }
                }
            })),
        }
    }

    #[test]
    fn governed_request_metadata_preserves_asserted_call_chain_and_diagnostics() {
        let call_chain = GovernedCallChainContext {
            chain_id: "chain-1".to_string(),
            parent_request_id: "req-parent-1".to_string(),
            parent_receipt_id: Some("rcpt-parent-1".to_string()),
            origin_subject: "origin-subject".to_string(),
            delegator_subject: "delegator-subject".to_string(),
        };
        let request = ToolCallRequest {
            request_id: "req-current-1".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-1" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-1".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(call_chain.clone()),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        };

        let metadata = governed_request_metadata(&request, None, 0)
            .expect("metadata should build")
            .expect("governed metadata should exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("receipt metadata should deserialize");
        let governed_call_chain = governed
            .call_chain
            .expect("asserted call-chain should remain visible on the signed receipt");
        assert_eq!(
            governed_call_chain.evidence_class,
            GovernedProvenanceEvidenceClass::Asserted
        );
        assert_eq!(
            metadata["governed_transaction_diagnostics"]["assertedCallChain"]["evidenceClass"],
            serde_json::json!("asserted")
        );
        assert_eq!(
            metadata["governed_transaction_diagnostics"]["assertedCallChain"]["chainId"],
            serde_json::json!("chain-1")
        );
        assert_eq!(
            metadata["governed_transaction_diagnostics"]["assertedCallChain"]["parentRequestId"],
            serde_json::json!("req-parent-1")
        );
        let diagnostics: GovernedTransactionDiagnostics =
            serde_json::from_value(metadata["governed_transaction_diagnostics"].clone())
                .expect("diagnostics should deserialize");
        let provenance = diagnostics
            .asserted_call_chain
            .expect("asserted call-chain should be preserved in diagnostics");
        assert_eq!(
            provenance.evidence_class,
            GovernedProvenanceEvidenceClass::Asserted
        );
        assert!(provenance.evidence_sources.is_empty());
        assert_eq!(provenance.into_inner(), call_chain);
    }

    #[test]
    fn governed_request_metadata_marks_matching_local_call_chain_evidence_as_observed() {
        let call_chain = GovernedCallChainContext {
            chain_id: "chain-2".to_string(),
            parent_request_id: "req-parent-2".to_string(),
            parent_receipt_id: Some("rcpt-parent-2".to_string()),
            origin_subject: "subject-origin".to_string(),
            delegator_subject: "subject-delegator".to_string(),
        };
        let request = ToolCallRequest {
            request_id: "req-current-2".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-2" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-2".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(call_chain.clone()),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        };
        let _scope =
            scope_governed_call_chain_receipt_evidence(Some(GovernedCallChainReceiptEvidence {
                local_parent_request_id: Some("req-parent-2".to_string()),
                local_parent_receipt_id: Some("rcpt-parent-2".to_string()),
                capability_delegator_subject: Some("subject-delegator".to_string()),
                capability_origin_subject: Some("subject-origin".to_string()),
                upstream_proof: None,
                continuation_token_id: None,
                session_anchor_id: None,
            }));

        let metadata = governed_request_metadata(&request, None, 0)
            .expect("metadata should build")
            .expect("governed metadata should exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("receipt metadata should deserialize");
        let provenance = governed
            .call_chain
            .expect("call-chain provenance should be present");

        assert_eq!(
            provenance.evidence_class,
            GovernedProvenanceEvidenceClass::Observed
        );
        assert_eq!(
            provenance.evidence_sources,
            vec![
                GovernedCallChainEvidenceSource::SessionParentRequestLineage,
                GovernedCallChainEvidenceSource::LocalParentReceiptLinkage,
                GovernedCallChainEvidenceSource::CapabilityDelegatorSubject,
                GovernedCallChainEvidenceSource::CapabilityOriginSubject,
            ]
        );
        assert_eq!(provenance.into_inner(), call_chain);
        assert!(metadata.get("governed_transaction_diagnostics").is_none());
    }

    #[test]
    fn governed_request_metadata_marks_validated_upstream_call_chain_proof_as_verified() {
        let signer = Keypair::generate();
        let subject = Keypair::generate();
        let call_chain = GovernedCallChainContext {
            chain_id: "chain-verified".to_string(),
            parent_request_id: "req-parent-verified".to_string(),
            parent_receipt_id: Some("rcpt-parent-verified".to_string()),
            origin_subject: "subject-origin".to_string(),
            delegator_subject: "subject-delegator".to_string(),
        };
        let upstream_proof = GovernedUpstreamCallChainProof::sign(
            GovernedUpstreamCallChainProofBody {
                signer: signer.public_key(),
                subject: subject.public_key(),
                chain_id: call_chain.chain_id.clone(),
                parent_request_id: call_chain.parent_request_id.clone(),
                parent_receipt_id: call_chain.parent_receipt_id.clone(),
                origin_subject: call_chain.origin_subject.clone(),
                delegator_subject: call_chain.delegator_subject.clone(),
                issued_at: 100,
                expires_at: 200,
            },
            &signer,
        )
        .expect("upstream proof should sign");
        let request = ToolCallRequest {
            request_id: "req-current-verified".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-verified" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-verified".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(call_chain.clone()),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        };
        let _scope =
            scope_governed_call_chain_receipt_evidence(Some(GovernedCallChainReceiptEvidence {
                local_parent_request_id: None,
                local_parent_receipt_id: None,
                capability_delegator_subject: None,
                capability_origin_subject: None,
                upstream_proof: Some(upstream_proof.clone()),
                continuation_token_id: Some("continuation-verified".to_string()),
                session_anchor_id: Some("anchor-verified".to_string()),
            }));

        let metadata = governed_request_metadata(&request, None, 0)
            .expect("metadata should build")
            .expect("governed metadata should exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("receipt metadata should deserialize");
        let provenance = governed
            .call_chain
            .expect("call-chain provenance should be present");

        assert_eq!(
            provenance.evidence_class,
            GovernedProvenanceEvidenceClass::Verified
        );
        assert_eq!(
            provenance.evidence_sources,
            vec![GovernedCallChainEvidenceSource::UpstreamDelegatorProof]
        );
        assert_eq!(provenance.upstream_proof, Some(upstream_proof));
        assert_eq!(
            provenance.continuation_token_id.as_deref(),
            Some("continuation-verified")
        );
        assert_eq!(
            provenance.session_anchor_id.as_deref(),
            Some("anchor-verified")
        );
        assert_eq!(provenance.into_inner(), call_chain);
        assert!(metadata.get("governed_transaction_diagnostics").is_none());
    }

    #[test]
    fn governed_request_metadata_omits_unverified_runtime_assurance() {
        let request = ToolCallRequest {
            request_id: "req-current-3".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-3" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-3".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: Some(raw_runtime_attestation()),
                call_chain: None,
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        };

        let metadata = governed_request_metadata(&request, None, 150)
            .expect("metadata should build")
            .expect("governed metadata should exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("receipt metadata should deserialize");

        assert!(
            governed.runtime_assurance.is_none(),
            "raw runtime attestation should not appear as verified receipt authority"
        );
    }

    #[test]
    fn governed_request_metadata_uses_verified_runtime_assurance_boundary() {
        let request = ToolCallRequest {
            request_id: "req-current-4".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-4" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-4".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: Some(trusted_runtime_attestation()),
                call_chain: None,
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        };

        let metadata =
            governed_request_metadata(&request, Some(&trusted_attestation_trust_policy()), 150)
                .expect("metadata should build")
                .expect("governed metadata should exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("receipt metadata should deserialize");
        let runtime_assurance = governed
            .runtime_assurance
            .expect("verified runtime assurance should be present");

        assert_eq!(runtime_assurance.tier, RuntimeAssuranceTier::Verified);
        assert_eq!(
            runtime_assurance.verifier_family,
            Some(arc_core::appraisal::AttestationVerifierFamily::AzureMaa)
        );
        assert_eq!(runtime_assurance.verifier, "https://maa.contoso.test");
        assert_eq!(
            runtime_assurance
                .workload_identity
                .expect("verified workload identity should be present")
                .trust_domain,
            "arc"
        );
    }

    #[test]
    fn governed_request_metadata_prefers_scoped_nitro_verified_record() {
        let attestation = trusted_nitro_runtime_attestation();
        let verified_runtime_attestation = verify_governed_runtime_attestation_record(
            &attestation,
            Some(&trusted_nitro_attestation_trust_policy()),
            150,
        )
        .expect("nitro attestation should verify at governed admission");
        let request = ToolCallRequest {
            request_id: "req-current-nitro".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-nitro" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-nitro".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: Some(attestation),
                call_chain: None,
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        };
        let _scope =
            scope_governed_runtime_attestation_receipt_record(Some(verified_runtime_attestation));

        let metadata = governed_request_metadata(&request, None, 150)
            .expect("metadata should build")
            .expect("governed metadata should exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("receipt metadata should deserialize");
        let runtime_assurance = governed
            .runtime_assurance
            .expect("scoped verified runtime assurance should be present");

        assert_eq!(runtime_assurance.tier, RuntimeAssuranceTier::Verified);
        assert_eq!(
            runtime_assurance.verifier_family,
            Some(arc_core::appraisal::AttestationVerifierFamily::AwsNitro)
        );
        assert_eq!(runtime_assurance.verifier, "https://nitro.aws.example");
        assert_eq!(
            runtime_assurance.evidence_sha256,
            sha256_hex(b"trusted-nitro-runtime-attestation")
        );
    }

    #[test]
    fn governed_request_metadata_rejects_mismatched_scoped_runtime_attestation_record() {
        let attestation = trusted_nitro_runtime_attestation();
        let verified_runtime_attestation = verify_governed_runtime_attestation_record(
            &attestation,
            Some(&trusted_nitro_attestation_trust_policy()),
            150,
        )
        .expect("nitro attestation should verify at governed admission");
        let mut mismatched_attestation = attestation.clone();
        mismatched_attestation.evidence_sha256 =
            sha256_hex(b"mismatched-nitro-runtime-attestation");
        let request = ToolCallRequest {
            request_id: "req-current-nitro-mismatch".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-nitro-mismatch" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-nitro-mismatch".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: Some(mismatched_attestation),
                call_chain: None,
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        };
        let _scope =
            scope_governed_runtime_attestation_receipt_record(Some(verified_runtime_attestation));

        let error = governed_request_metadata(&request, None, 150)
            .expect_err("mismatched scoped runtime attestation should fail closed");
        assert!(
            error.to_string().contains(
                "governed request runtime attestation does not match the scoped verified runtime attestation record"
            ),
            "expected mismatch error, got {error}"
        );
    }
}
