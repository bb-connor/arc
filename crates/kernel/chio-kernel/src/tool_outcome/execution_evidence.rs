//! Immutable execution receipt projection. Decoding never recreates authority.
use super::*;
use crate::PaymentJournalRecord;
use chio_core::receipt::body::ChioReceipt;

const SCHEMA: &str = "chio.execution-evidence-projection.v1";
const MAX_BYTES: usize = 1024 * 1024;

/// Data retained by the qualified outcome participant, not a mutation permit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEvidenceRecordV1 {
    schema: String,
    operation_id: AdmissionOperationId,
    receipt_canonical_json: String,
    outcome_sha256: AdmissionDigest,
    payment_identity_sha256: AdmissionDigest,
    recorded_at_unix_ms: u64,
    store_fence: StoreMutationFence,
}

/// Only the kernel can create this live token after signing and lease checks.
pub struct QualifiedExecutionEvidenceV1 {
    record: ExecutionEvidenceRecordV1,
}
impl QualifiedExecutionEvidenceV1 {
    pub fn record(&self) -> &ExecutionEvidenceRecordV1 {
        &self.record
    }
}
impl QualifiedExecutionEvidenceV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn qualify(
        operation: &AdmissionOperationV1,
        retained: &crate::admission_operation::RetainedToolAdmissionRequestV1,
        raw: &RawInvocationOutcomeV1,
        outcome: &ToolOutcomeRecordV1,
        evaluation: &PostReturnEvaluationRecordV1,
        journal: &PaymentJournalRecord,
        resolved: &[u8],
        receipt: &ChioReceipt,
        recorded_at_unix_ms: u64,
        store_fence: StoreMutationFence,
    ) -> Result<Self, ToolOutcomeError> {
        if operation.state() != AdmissionOperationState::Finalizing {
            return Err(ToolOutcomeError::Binding("execution.first_export_state"));
        }
        validate_execution_evidence_request(operation, retained, raw, evaluation)?;
        let record = ExecutionEvidenceRecordV1 {
            schema: SCHEMA.into(),
            operation_id: operation.binding().operation_id().clone(),
            receipt_canonical_json: String::from_utf8(canonical(receipt)?)
                .map_err(|e| ToolOutcomeError::Canonical(e.to_string()))?,
            outcome_sha256: digest_bytes(
                "execution.outcome",
                &canonical(&outcome.to_persisted())?,
            )?,
            payment_identity_sha256: payment_identity_digest(journal)?,
            recorded_at_unix_ms,
            store_fence,
        };
        record.validate_against(operation, raw, outcome, evaluation, journal, resolved)?;
        Ok(Self { record })
    }
}

impl ExecutionEvidenceRecordV1 {
    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }
    pub fn recorded_at_unix_ms(&self) -> u64 {
        self.recorded_at_unix_ms
    }
    pub fn store_fence(&self) -> &StoreMutationFence {
        &self.store_fence
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ToolOutcomeError> {
        if self.schema != SCHEMA {
            return Err(ToolOutcomeError::Invalid("execution.schema"));
        }
        positive("execution.recorded_at", self.recorded_at_unix_ms)?;
        validate_store_fence(&self.store_fence)?;
        self.receipt()?;
        bounded("execution.record", self, MAX_BYTES)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ToolOutcomeError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(ToolOutcomeError::Invalid("execution.size"));
        }
        let record: Self = serde_json::from_slice(bytes)
            .map_err(|e| ToolOutcomeError::Canonical(e.to_string()))?;
        if record.canonical_bytes()? != bytes {
            return Err(ToolOutcomeError::Invalid("execution.noncanonical"));
        }
        Ok(record)
    }
    pub fn receipt(&self) -> Result<ChioReceipt, ToolOutcomeError> {
        if self.receipt_canonical_json.len() > MAX_BYTES {
            return Err(ToolOutcomeError::Invalid("execution.receipt_size"));
        }
        let receipt: ChioReceipt = serde_json::from_str(&self.receipt_canonical_json)
            .map_err(|e| ToolOutcomeError::Canonical(e.to_string()))?;
        if canonical(&receipt)? != self.receipt_canonical_json.as_bytes() {
            return Err(ToolOutcomeError::Invalid("execution.receipt_noncanonical"));
        }
        Ok(receipt)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        raw: &RawInvocationOutcomeV1,
        outcome: &ToolOutcomeRecordV1,
        evaluation: &PostReturnEvaluationRecordV1,
        journal: &PaymentJournalRecord,
        resolved: &[u8],
    ) -> Result<(), ToolOutcomeError> {
        use chio_core::receipt::execution_evidence::verify_pre_settlement_execution_receipt;
        self.canonical_bytes()?;
        let expected = execution_metadata(operation, raw, outcome, evaluation, journal, resolved)?;
        let receipt = self.receipt()?;
        let identity = raw
            .receipt_signing_identity()
            .ok_or(ToolOutcomeError::Binding("execution.original_signer"))?;
        let actual = verify_pre_settlement_execution_receipt(
            &receipt,
            std::slice::from_ref(identity.public_key()),
        )
        .map_err(|e| ToolOutcomeError::Canonical(e.to_string()))?;
        if !receipt
            .verify_signature_with_floor(identity.crypto_floor())
            .map_err(|e| ToolOutcomeError::Canonical(e.to_string()))?
        {
            return Err(ToolOutcomeError::Binding("execution.signature_floor"));
        }
        let request = raw
            .recovery_request()?
            .ok_or(ToolOutcomeError::Binding("execution.request"))?;
        let tenant = operation.binding().to_persisted().authenticated_tenant_id;
        let tenant = (tenant.as_str() != crate::admission_operation::LOCAL_SYSTEM_TENANT_ID)
            .then(|| tenant.as_str().to_owned());
        if !receipt.evidence.is_empty()
            || actual != expected
            || self.operation_id != *operation.binding().operation_id()
            || self.outcome_sha256
                != digest_bytes("execution.outcome", &canonical(&outcome.to_persisted())?)?
            || self.payment_identity_sha256 != payment_identity_digest(journal)?
            || receipt.capability_id != request.capability.id
            || receipt.tool_server != request.server_id
            || receipt.tool_name != request.tool_name
            || receipt.policy_hash != operation.binding().policy_hash().as_str()
            || canonical(&receipt.action)?
                != canonical(
                    &chio_core::receipt::decision::ToolCallAction::from_parameters(
                        request.arguments,
                    )
                    .map_err(|e| ToolOutcomeError::Canonical(e.to_string()))?,
                )?
            || receipt.tenant_id != tenant
            || receipt.timestamp != evaluation.trusted_time_unix_ms() / 1000
            || self.recorded_at_unix_ms < evaluation.trusted_time_unix_ms()
        {
            return Err(ToolOutcomeError::Binding("execution.receipt_sources"));
        }
        validate_successor_fence(&outcome.recording_fence, &self.store_fence)?;
        Ok(())
    }
}

/// Re-derive the public statement exclusively from retained native artifacts.
pub(crate) fn execution_metadata(
    operation: &AdmissionOperationV1,
    raw: &RawInvocationOutcomeV1,
    outcome: &ToolOutcomeRecordV1,
    evaluation: &PostReturnEvaluationRecordV1,
    journal: &PaymentJournalRecord,
    resolved: &[u8],
) -> Result<chio_core::receipt::execution_evidence::ExecutionEvidenceMetadata, ToolOutcomeError> {
    use chio_core::receipt::decision::Decision;
    use chio_core::receipt::execution_evidence::{
        ExecutionEvidenceMetadata, EXECUTION_EVIDENCE_SCHEMA,
    };
    outcome.validate_canonical_blob(operation, &raw.canonical_blob()?)?;
    evaluation.validate_against(operation, outcome)?;
    let request = raw
        .recovery_request()?
        .ok_or(ToolOutcomeError::Binding("execution.request"))?;
    if request.capability.id != operation.binding().capability_id().as_str()
        || sha256_hex(&canonical(&request.capability)?)
            != operation
                .binding()
                .to_persisted()
                .authorization_capability_hash
                .as_str()
        || sha256_hex(&canonical(&request.arguments)?)
            != operation.binding().action_parameter_hash().as_str()
    {
        return Err(ToolOutcomeError::Binding("execution.original_request"));
    }
    let identity = raw
        .receipt_signing_identity()
        .ok_or(ToolOutcomeError::Binding("execution.original_signer"))?;
    identity.validate()?;
    validate_execution_provenance(operation, raw)?;
    let expected_metadata = crate::receipt_support::merge_metadata_objects(
        crate::receipt_support::receipt_attribution_metadata(
            &request.capability,
            Some(raw.matched_grant_index()?),
        ),
        Some(serde_json::json!({"receipt_context": {"request_id": request.request_id}})),
    );
    if raw.receipt_metadata_snapshot() != expected_metadata.as_ref() {
        return Err(ToolOutcomeError::Binding("execution.unsupported_metadata"));
    }
    let ResolvedToolOutcomeV1::Resolved {
        evaluation_id,
        resolved_output,
        resolved_output_size_bytes,
        terminal_dependency_root_digest,
        post_guard_decision_digest,
        pricing_verdict_digest,
        settlement_disposition,
    } = outcome.disposition()
    else {
        return Err(ToolOutcomeError::Binding("execution.unresolved_outcome"));
    };
    let PostReturnEvaluationStateV1::Resolved { resolution } = evaluation.state() else {
        return Err(ToolOutcomeError::Binding("execution.unresolved_evaluation"));
    };
    if evaluation_id != evaluation.evaluation_id()
        || resolved_output != &resolution.resolved_output
        || resolved_output_size_bytes != &resolution.resolved_output_size_bytes
        || terminal_dependency_root_digest != &resolution.terminal_dependency_root_digest
        || post_guard_decision_digest != &resolution.post_guard_decision_digest
        || pricing_verdict_digest != &resolution.pricing_verdict_digest
        || settlement_disposition != &resolution.settlement_disposition
        || u64::try_from(resolved.len()).ok() != Some(*resolved_output_size_bytes)
        || sha256_hex(resolved) != resolved_output.digest().as_str()
    {
        return Err(ToolOutcomeError::Binding("execution.resolution"));
    }
    let value: Value =
        serde_json::from_slice(resolved).map_err(|e| ToolOutcomeError::Canonical(e.to_string()))?;
    if canonical(&value)? != resolved {
        return Err(ToolOutcomeError::Binding("execution.resolved_preimage"));
    }
    let expected_guard = serde_json::json!({
        "schema": "chio.kernel-output-guard-decision.post-return.v1",
        "resolved_output_digest": resolved_output.digest().as_str(),
        "decision": Decision::Allow,
    });
    let expected_pricing = serde_json::json!({
        "schema": "chio.kernel-pricing-verdict.v1", "disposition": settlement_disposition,
    });
    if sha256_hex(&canonical(&expected_guard)?) != post_guard_decision_digest.as_str()
        || sha256_hex(&canonical(&expected_pricing)?) != pricing_verdict_digest.as_str()
    {
        return Err(ToolOutcomeError::Binding("execution.verdict"));
    }
    journal
        .validate()
        .map_err(|e| ToolOutcomeError::Canonical(e.to_string()))?;
    let hold = operation
        .budget_hold_id()
        .ok_or(ToolOutcomeError::Binding("execution.hold"))?;
    let authorization = journal
        .authorization_id
        .as_ref()
        .ok_or(ToolOutcomeError::Binding("execution.authorization"))?;
    let participant = operation
        .payment_participant_id()
        .ok_or(ToolOutcomeError::Binding("execution.payment_participant"))?;
    if journal.operation_id != operation.binding().operation_id().as_str()
        || journal.request_namespace_digest
            != operation.binding().request_namespace_digest().as_str()
        || journal.request_id != request.request_id
        || journal.capability_id != request.capability.id
        || journal.hold_id.as_deref() != Some(hold.as_str())
        || usize::try_from(journal.grant_index).ok() != Some(raw.matched_grant_index()?)
        || participant.as_str() != journal.operation_id
    {
        return Err(ToolOutcomeError::Binding("execution.payment_identity"));
    }
    let metadata = ExecutionEvidenceMetadata {
        schema: EXECUTION_EVIDENCE_SCHEMA.into(),
        phase: "execution_confirmed".into(),
        authority_uuid: operation
            .binding()
            .coordinator_authority_id()
            .as_str()
            .into(),
        operation_id: operation.binding().operation_id().as_str().into(),
        request_id: request.request_id.clone(),
        request_binding_hash: operation.binding().request_binding_hash().as_str().into(),
        request_sha256: sha256_hex(&canonical(&request)?),
        hold_id: hold.as_str().into(),
        authorization_id: authorization.clone(),
        outcome_id: outcome.outcome_id().as_str().into(),
        raw_outcome_sha256: outcome.raw_output_digest().as_str().into(),
        resolved_output_sha256: resolved_output.digest().as_str().into(),
        post_return_evaluation_sha256: sha256_hex(&canonical(&evaluation.to_persisted())?),
        post_guard_decision_sha256: post_guard_decision_digest.as_str().into(),
        pricing_verdict_sha256: pricing_verdict_digest.as_str().into(),
    };
    metadata
        .validate()
        .map_err(|e| ToolOutcomeError::Canonical(e.to_string()))?;
    Ok(metadata)
}

fn payment_identity_digest(
    journal: &PaymentJournalRecord,
) -> Result<AdmissionDigest, ToolOutcomeError> {
    digest_bytes(
        "execution.payment_identity",
        &canonical(&serde_json::json!({
            "schema": "chio.execution-payment-identity.v1",
            "operation_id": journal.operation_id,
            "request_namespace_digest": journal.request_namespace_digest,
            "request_id": journal.request_id, "capability_id": journal.capability_id,
            "grant_index": journal.grant_index, "hold_id": journal.hold_id,
            "rail": journal.rail, "rail_mode": journal.rail_mode,
            "authorization_id": journal.authorization_id,
            "amount_units": journal.amount_units, "currency": journal.currency,
            "created_at_unix_ms": journal.created_at_unix_ms,
        }))?,
    )
}

/// Validate original begin-commit request and evaluation provenance. This pure
/// check grants no dispatch, signing or projection authority.
pub fn validate_execution_evidence_request(
    operation: &AdmissionOperationV1,
    retained: &crate::admission_operation::RetainedToolAdmissionRequestV1,
    raw: &RawInvocationOutcomeV1,
    evaluation: &PostReturnEvaluationRecordV1,
) -> Result<(), ToolOutcomeError> {
    let invalid = |e: crate::admission_operation::AdmissionOperationStoreError| {
        ToolOutcomeError::Canonical(e.to_string())
    };
    retained
        .validate_binding(operation.binding())
        .map_err(invalid)?;
    let request = raw
        .recovery_request()?
        .ok_or(ToolOutcomeError::Binding("execution.original_request"))?;
    retained
        .validate_request_material(&request)
        .map_err(invalid)?;
    let limits = raw.stream_limits();
    let normalized =
        PostReturnNormalizedRequestContextV1::from_verified_normalization(serde_json::json!({
            "schema": "chio.kernel-post-return-context.v1",
            "request_binding_hash": operation.binding().request_binding_hash().as_str(),
            "matched_grant_index": raw.matched_grant_index()?,
            "elapsed_millis": raw.elapsed_millis(),
            "max_stream_total_bytes": limits.max_total_bytes,
            "max_stream_chunks": limits.max_chunks,
            "max_stream_duration_secs": limits.max_duration_secs,
        }))?;
    evaluation.validate_replay_contract(retained.post_return_steps(), &normalized)
}

/// Establish the supported native source profile before consulting payment state.
pub(crate) fn validate_execution_provenance(
    operation: &AdmissionOperationV1,
    raw: &RawInvocationOutcomeV1,
) -> Result<(), ToolOutcomeError> {
    let request = raw
        .recovery_request()?
        .ok_or(ToolOutcomeError::Binding("execution.request"))?;
    if !matches!(raw.output(), InvocationOutputV1::Value { .. })
        || raw.caller_delivery_evidence().is_some()
        || raw.requires_security_release()?
        || raw.security_invocation_context().is_some()
        || raw.federation_context_json().is_some()
        || request.federated_origin_kernel_id.is_some()
        || request.declassification_grant.is_some()
        || request.execution_nonce.is_some()
        || operation.execution_nonce_id().is_some()
    {
        return Err(ToolOutcomeError::Binding(
            "execution.unsupported_provenance",
        ));
    }
    Ok(())
}
