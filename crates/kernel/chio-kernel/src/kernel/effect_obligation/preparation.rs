//! Inputs that must be valid and bounded before a non-durable effect starts.

use super::*;
use crate::kernel::receipt_identity::{with_identity_disposition, IdentityDisposition};
use crate::kernel::responses::PreparedResponse;

pub(super) const FAULT_RESERVE_HEADROOM: usize = 64 * 1024;
const FAULT_REASON: &str = "post-effect finalization failed; output withheld";

#[derive(Clone, PartialEq, Eq)]
pub(super) struct DischargeBinding {
    pub evaluation_id: String,
    pub namespace: String,
    pub request_id: String,
    pub operation_id: Option<String>,
    pub capability_id: String,
    pub server_id: String,
    pub tool_name: String,
    pub policy_hash: String,
    pub parameter_hash: String,
    pub grant_index: usize,
}

impl DischargeBinding {
    pub(super) fn validate_receipt(&self, receipt: &ChioReceipt) -> Result<(), KernelError> {
        if !receipt
            .action
            .verify_hash()
            .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?
        {
            return Err(KernelError::Internal(
                "terminal action does not match its parameter hash".into(),
            ));
        }
        let metadata = receipt.metadata.as_ref();
        let text = |pointer| {
            metadata
                .and_then(|value| value.pointer(pointer))
                .and_then(serde_json::Value::as_str)
        };
        let grant = metadata
            .and_then(|value| value.pointer("/attribution/grant_index"))
            .and_then(serde_json::Value::as_u64);
        let terminal = matches!(
            receipt.decision.as_ref(),
            Some(
                Decision::Allow
                    | Decision::Deny { .. }
                    | Decision::Cancelled { .. }
                    | Decision::Incomplete { .. }
            )
        );
        if self.operation_id.is_some()
            || text("/receipt_context/request_id") != Some(self.request_id.as_str())
            || text("/receipt_context/request_namespace_digest") != Some(self.namespace.as_str())
            || text("/receipt_context/evaluation_id") != Some(self.evaluation_id.as_str())
            || receipt.capability_id != self.capability_id
            || receipt.tool_server != self.server_id
            || receipt.tool_name != self.tool_name
            || receipt.policy_hash != self.policy_hash
            || receipt.receipt_kind != chio_core::receipt::kinds::ReceiptKind::MediatedDecision
            || receipt.action.parameter_hash != self.parameter_hash
            || grant != u64::try_from(self.grant_index).ok()
            || !terminal
        {
            return Err(KernelError::Internal(
                "terminal receipt does not match its post-effect owner".into(),
            ));
        }
        Ok(())
    }
}

pub(in crate::kernel) struct PreparedPostEffect {
    pub(super) binding: DischargeBinding,
    pub(super) evaluation_timestamp: u64,
    pub(super) fault: Option<PreparedFaultReceipt>,
    pub(super) slot: Option<EvidenceSlot>,
}

pub(in crate::kernel) struct PostEffectPreparation<'a> {
    pub request: &'a ToolCallRequest,
    pub matched_grant_index: usize,
    pub budget: &'a PreExecutionBudgetMutation,
    pub payment: Option<&'a PaymentAuthorization>,
    pub metadata: &'a Option<serde_json::Value>,
    pub evidence: &'a crate::kernel::PreInvocationGuardOutput,
    pub payee: Option<&'a VerifiedGovernedPayeeBinding>,
    pub admission: Option<&'a DurableToolAdmission>,
    pub evaluation_started_at: u64,
}

impl ChioKernel {
    pub(in crate::kernel) fn prepare_post_effect(
        &self,
        input: PostEffectPreparation<'_>,
    ) -> Result<PreparedPostEffect, KernelError> {
        let action = ToolCallAction::from_parameters(input.request.arguments.clone())
            .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
        let namespace = self.receipt_request_namespace_digest(&input.request.request_id)?;
        if input.admission.is_some_and(|admission| {
            admission
                .operation()
                .binding()
                .request_namespace_digest()
                .as_str()
                != namespace
        }) {
            return Err(KernelError::Internal(
                "durable admission namespace differs from its evaluation".into(),
            ));
        }
        let binding = DischargeBinding {
            evaluation_id: current_receipt_evaluation_scope_key().ok_or_else(|| {
                KernelError::Internal("post-effect ownership requires an evaluation scope".into())
            })?,
            namespace,
            request_id: input.request.request_id.clone(),
            operation_id: input
                .admission
                .map(|admission| admission.operation_id().to_owned()),
            capability_id: input.request.capability.id.clone(),
            server_id: input.request.server_id.clone(),
            tool_name: input.request.tool_name.clone(),
            policy_hash: self.config.policy_hash.clone(),
            parameter_hash: action.parameter_hash.clone(),
            grant_index: input.matched_grant_index,
        };
        if input.admission.is_some() {
            return Ok(PreparedPostEffect {
                binding,
                evaluation_timestamp: input.evaluation_started_at / 1_000,
                fault: None,
                slot: None,
            });
        }
        // Keep mandatory authority and retention evidence. Caller extras and
        // returned output do not belong in the reserved fault template.
        let minimal = input
            .metadata
            .as_ref()
            .and_then(|value| value.get("chio_runtime"))
            .map(|runtime| serde_json::json!({ "chio_runtime": runtime }));
        let metadata =
            self.ambiguous_dispatch_receipt_metadata(input.budget, input.payment, minimal);
        let metadata = merge_metadata_objects(
            metadata,
            Some(serde_json::json!({
                "receipt_context": { "request_namespace_digest": binding.namespace, "evaluation_id": binding.evaluation_id },
                "chio_runtime": {
                    (crate::kernel::runtime_field::EVALUATION_STARTED_AT): input.evaluation_started_at,
                    (crate::kernel::runtime_field::POST_EFFECT_FAULT): { "step": "drop", "code": "CHIO-KERNEL-POST-EFFECT-DROP", "original_receipt_id": null }
                }
            })),
        );
        let metadata = with_identity_disposition(metadata, IdentityDisposition::Terminal);
        let request_metadata = request_receipt_metadata_with_payee_binding(
            input.request,
            self.attestation_trust_policy.as_ref(),
            input.evaluation_started_at / 1_000,
            metadata.as_ref(),
            input.payee,
        )?;
        let canonical_content = b"null".to_vec();
        let signing_identity = self.freeze_receipt_signing_identity()?;
        let mut body = self.with_pre_invocation_guard_output(input.evidence, || {
            self.prepare_receipt_body(
                ReceiptParams {
                    request_id: Some(&input.request.request_id),
                    capability_id: &input.request.capability.id,
                    tool_name: &input.request.tool_name,
                    server_id: &input.request.server_id,
                    decision: Decision::Cancelled {
                        reason: FAULT_REASON.into(),
                    },
                    action,
                    content_hash: chio_core::crypto::sha256_hex(&canonical_content),
                    canonical_content: Vec::new(),
                    metadata: merge_metadata_objects(
                        merge_metadata_objects(metadata, request_metadata),
                        receipt_attribution_metadata(
                            &input.request.capability,
                            Some(input.matched_grant_index),
                        )?,
                    ),
                    timestamp: 0,
                    trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                    tenant_id: None,
                },
                signing_identity.public_key().clone(),
            )
        })?;
        body.evidence = input.evidence.evidence.clone();
        let bytes = chio_core::canonical::canonical_json_bytes(&body)
            .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?
            .len()
            .checked_add(FAULT_RESERVE_HEADROOM)
            .ok_or(KernelError::PostEffectEvidenceCapacity)?;
        if bytes > self.post_effect_fault_template_limit() {
            return Err(KernelError::PostEffectEvidenceCapacity);
        }
        let bytes =
            std::num::NonZeroUsize::new(bytes).ok_or(KernelError::PostEffectEvidenceCapacity)?;
        let slot = self.acquire_post_effect_evidence_slot(bytes)?;
        Ok(PreparedPostEffect {
            binding,
            evaluation_timestamp: input.evaluation_started_at / 1_000,
            fault: Some(PreparedFaultReceipt {
                body,
                canonical_content,
            }),
            slot: Some(slot),
        })
    }
}

pub(super) fn fault_response(receipt: ChioReceipt, request_id: &str) -> PreparedResponse {
    let reason = match receipt.decision.as_ref() {
        Some(Decision::Cancelled { reason } | Decision::Deny { reason, .. }) => reason.clone(),
        _ => FAULT_REASON.into(),
    };
    PreparedResponse::terminal(
        ToolCallResponse {
            request_id: request_id.to_owned(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.clone()),
            terminal_state: OperationTerminalState::Cancelled { reason },
            receipt,
            execution_nonce: None,
            denial_code: None,
        },
        crate::kernel::responses::ReceiptRecordMode::WithFederation,
    )
}

impl PreparedFaultReceipt {
    pub(in crate::kernel) fn observe_fault_timestamp(&mut self, observed_at: u64) {
        let mut fault = self
            .body
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("chio_runtime"))
            .and_then(|runtime| runtime.get(crate::kernel::runtime_field::POST_EFFECT_FAULT))
            .and_then(serde_json::Value::as_object)
            .cloned()
            .unwrap_or_default();
        retain_bounded_reference(&mut fault, "observed_at", &serde_json::json!(observed_at));
        self.body.metadata = merge_metadata_objects(
            self.body.metadata.take(),
            Some(serde_json::json!({
                "chio_runtime": { (crate::kernel::runtime_field::POST_EFFECT_FAULT): fault }
            })),
        );
    }

    pub(in crate::kernel) fn observe_payment_result(
        &mut self,
        authorization: &PaymentAuthorization,
        result: &crate::payment::PaymentResult,
        amount: u64,
        released: bool,
    ) {
        let final_state = matches!(
            result.settlement_status,
            crate::payment::RailSettlementStatus::Settled
                | crate::payment::RailSettlementStatus::Released
                | crate::payment::RailSettlementStatus::Refunded
        );
        let financial = serde_json::json!({ "financial": {
            "authorization_id": authorization.authorization_id,
            "payment_reference": result.transaction_id,
            "settlement_status": result.settlement_status.to_receipt_status(),
            "rail_status": result.settlement_status,
            "cost_charged": if released { 0 } else { amount },
            "payment_authorization_retained": !final_state,
            "payment_release_confirmed": released && final_state,
            "release_outcome": if released { "acknowledged" } else { "not_released" }
        }});
        self.observe_economics(Some(&financial));
    }
    /// Retain acknowledged economics without importing output, cost breakdowns,
    /// oracle payloads or arbitrary caller metadata into the fault template.
    pub(in crate::kernel) fn observe_economics(&mut self, metadata: Option<&serde_json::Value>) {
        let Some(metadata) = metadata else {
            return;
        };
        let mut observed = serde_json::Map::new();
        if let Some(authority) = metadata.get("budget_authority") {
            let mut authority = authority.clone();
            if let Some(fields) = authority.as_object_mut() {
                for key in ["hold_id", "budget_term", "execution_nonce_id"] {
                    if let Some(value) = fields.get(key).cloned() {
                        retain_bounded_reference(fields, key, &value);
                    }
                }
                for key in ["terminal", "authorize", "invocation_capture", "authority"] {
                    if let Some(object) = fields
                        .get_mut(key)
                        .and_then(serde_json::Value::as_object_mut)
                    {
                        for (field, value) in object.clone() {
                            retain_bounded_reference(object, &field, &value);
                        }
                    }
                }
            }
            observed.insert("budget_authority".into(), authority);
        }
        if let Some(financial) = metadata
            .get("financial")
            .and_then(serde_json::Value::as_object)
        {
            let mut bounded = serde_json::Map::new();
            for key in [
                "grant_index",
                "cost_charged",
                "currency",
                "budget_remaining",
                "budget_total",
                "delegation_depth",
                "root_budget_holder",
                "authorization_id",
                "payment_reference",
                "settlement_status",
                "release_outcome",
                "payment_authorization_retained",
                "payment_capture_ambiguous",
                "payment_capture_error_code",
                "payment_capture_attempt_reference",
                "capture_status",
                "payment_release_attempt_reference",
                "payment_release_reference",
                "payment_release_confirmed",
                "payment_release_error_code",
                "rail_status",
            ] {
                if let Some(value) = financial.get(key) {
                    retain_bounded_reference(&mut bounded, key, value);
                }
            }
            if bounded
                .get("settlement_status")
                .and_then(serde_json::Value::as_str)
                == Some("settled")
            {
                bounded.insert(
                    "payment_authorization_retained".into(),
                    serde_json::Value::Bool(false),
                );
            }
            observed.insert("financial".into(), serde_json::Value::Object(bounded));
        }
        // A replacement value also replaces its bounded representation. Preserve
        // unrelated authority fields, but never carry a prior value's digest or
        // omission marker into the new observation.
        if let Some(previous) = self.body.metadata.as_mut() {
            for (section, replacement) in &observed {
                if let (Some(previous), Some(replacement)) = (
                    previous
                        .get_mut(section)
                        .and_then(serde_json::Value::as_object_mut),
                    replacement.as_object(),
                ) {
                    for field in replacement.keys() {
                        for suffix in ["sha256", "decimal", "omitted"] {
                            previous.remove(&format!("{field}_{suffix}"));
                        }
                    }
                }
            }
        }
        self.body.metadata = merge_metadata_objects(
            self.body.metadata.take(),
            Some(serde_json::Value::Object(observed)),
        );
    }
}

fn retain_bounded_reference(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &serde_json::Value,
) {
    if let serde_json::Value::Number(number) = value {
        if number
            .as_u64()
            .is_some_and(|value| value > 9_007_199_254_740_991)
            || number.as_i64().is_some_and(|value| {
                !(-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&value)
            })
        {
            map.insert(key.into(), serde_json::Value::Null);
            map.insert(
                format!("{key}_decimal"),
                serde_json::Value::String(number.to_string()),
            );
            map.insert(format!("{key}_omitted"), serde_json::Value::Bool(true));
            return;
        }
    }
    if let Some(text) = value.as_str().filter(|text| text.len() > 512) {
        // A new rail/reference value is not predictable before execution. Keep
        // its exact digest and explicitly omit raw bytes rather than retaining
        // an unbounded value or inventing a shortened reference.
        map.insert(key.into(), serde_json::Value::Null);
        map.insert(
            format!("{key}_sha256"),
            serde_json::json!(chio_core::crypto::sha256_hex(text.as_bytes())),
        );
        map.insert(format!("{key}_omitted"), serde_json::Value::Bool(true));
    } else {
        map.insert(key.into(), value.clone());
    }
}

#[cfg(test)]
mod tests;
