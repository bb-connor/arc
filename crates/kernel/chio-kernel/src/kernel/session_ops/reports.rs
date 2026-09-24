//! Kernel-owned session reports that do not participate in execution settlement.

use super::*;
use chio_core::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core::receipt::signing::ReceiptSigningHandle;

enum SessionReport {
    AuthorizationConflict(&'static str),
    EvaluationFailure,
}

impl ChioKernel {
    /// Record a host-reported session evaluation failure using the boot receipt
    /// authority. This observation does not assert an execution outcome, authorize
    /// a retry, release a hold, or complete session lineage. The original operation
    /// remains authoritative. Raw errors and caller metadata are not copied.
    ///
    /// Returns only after the configured receipt persistence contract succeeds.
    /// On failure the host must not substitute an independently signed receipt.
    pub fn record_session_tool_failure(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
    ) -> Result<ChioReceipt, KernelError> {
        self.record_session_report(context, operation, SessionReport::EvaluationFailure)
    }

    pub(super) fn reject_conflicting_session_authorization(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
    ) -> Result<Option<ToolCallResponse>, KernelError> {
        let Some(reason) = operation.authorization_conflict() else {
            return Ok(None);
        };
        self.with_session(&context.session_id, |session| {
            session.validate_context(context)?;
            session.ensure_operation_allowed(OperationKind::ToolCall)?;
            Ok(())
        })?;
        // Reject this attempt before claiming an existing approval wait. This
        // receipt must not terminalize that wait or enter financial settlement.
        let receipt = self.record_session_report(
            context,
            operation,
            SessionReport::AuthorizationConflict(reason),
        )?;
        Ok(Some(ToolCallResponse {
            request_id: context.request_id.to_string(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.into()),
            terminal_state: OperationTerminalState::Completed,
            receipt,
            execution_nonce: None,
        }))
    }

    fn record_session_report(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
        report: SessionReport,
    ) -> Result<ChioReceipt, KernelError> {
        let snapshot = self.with_session(&context.session_id, |session| {
            session.validate_context(context)?;
            let snapshot = session.session_anchor_snapshot();
            if let Some(lineage) = session.request_lineage(&context.request_id) {
                if lineage.session_anchor_id != snapshot.session_anchor.id() {
                    return Err(KernelError::ReceiptSigningFailed(
                        "session report cannot rebind existing request lineage to a different authentication epoch".into(),
                    ));
                }
            }
            Ok(snapshot)
        })?;
        self.ensure_receipt_persistence_ready()?;
        let authority = self.signing_authority.backend.as_ref();
        if !self
            .signing_authority
            .floor
            .allowed_signing_algorithms()
            .contains(&authority.algorithm())
        {
            return Err(KernelError::ReceiptSigningFailed(
                "receipt authority does not satisfy the boot signing floor".into(),
            ));
        }
        let encode_error =
            |error: chio_core::error::Error| KernelError::ReceiptSigningFailed(error.to_string());
        let action =
            ToolCallAction::from_parameters(operation.arguments.clone()).map_err(encode_error)?;
        let operation_bytes = canonical_json_bytes(operation).map_err(encode_error)?;
        let context_bytes = canonical_json_bytes(context).map_err(encode_error)?;
        let capability_bytes = canonical_json_bytes(&operation.capability).map_err(encode_error)?;
        let (kind, decision, receipt_kind, boundary_class, observation_outcome, trust_level) =
            match report {
                SessionReport::AuthorizationConflict(reason) => (
                    "authorization_conflict",
                    Some(Decision::Deny {
                        reason: reason.into(),
                        guard: "session_authorization".into(),
                    }),
                    ReceiptKind::MediatedDecision,
                    BoundaryClass::Prevent,
                    None,
                    TrustLevel::Mediated,
                ),
                SessionReport::EvaluationFailure => (
                    "evaluation_failure_reported",
                    None,
                    ReceiptKind::TraceObservation,
                    BoundaryClass::DetectOnly,
                    Some(ObservationOutcome::Observed),
                    // The signed report is verified, not an execution outcome.
                    TrustLevel::Verified,
                ),
            };
        let event = serde_json::json!({
            "schema": "chio.session.report.v1",
            "kind": kind,
            "session_id": snapshot.session_id,
            "agent_id": snapshot.agent_id,
            "session_anchor_id": snapshot.session_anchor.id(),
            "auth_epoch": snapshot.session_anchor.auth_epoch(),
            "request_id": context.request_id,
            "operation_sha256": sha256_hex(&operation_bytes),
            "context_sha256": sha256_hex(&context_bytes),
            "capability_sha256": sha256_hex(&capability_bytes),
            "execution_outcome": "unknown",
        });
        // Hash the report, not an invented tool output. Explicit tenant binding
        // must not inherit an unrelated ambient request or thread-local scope.
        let content = canonical_json_bytes(&event).map_err(encode_error)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?
            .as_secs();
        let body = ChioReceiptBody {
            id: next_receipt_id("rcpt-session-report"),
            timestamp,
            capability_id: operation.capability.id.clone(),
            tool_server: operation.server_id.clone(),
            tool_name: operation.tool_name.clone(),
            action,
            decision,
            receipt_kind,
            boundary_class,
            observation_outcome,
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: sha256_hex(&content),
            policy_hash: self.config.policy_hash.clone(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({"session_report": event})),
            trust_level,
            tenant_id: extract_tenant_id_from_auth_context(&snapshot.auth_context),
            kernel_key: authority.public_key(),
            bbs_projection_version: None,
        };
        let receipt = chio_kernel_core::sign_receipt_with_handle(
            body,
            authority,
            ReceiptSigningHandle::from_content_preimage(content),
        )
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!("session report signing failed: {error:?}"))
        })?;
        self.record_chio_receipt_without_settlement(&receipt)?;
        Ok(receipt)
    }
}
