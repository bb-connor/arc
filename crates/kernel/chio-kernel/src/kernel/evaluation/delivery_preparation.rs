//! Reachability of a tool server before a durable dispatch commits.

use super::evaluation_helpers::PreDispatchCleanupDeny;
use super::*;
use crate::admission_operation::AdmissionOperationV1;

/// Everything the pre-dispatch denial needs when a tool server cannot accept
/// the dispatch the kernel is about to commit.
pub(super) struct DeliveryPreparation<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) server: &'a Arc<dyn ToolServerConnection>,
    pub(super) context: &'a ToolDispatchContext,
    pub(super) security_dispatch_outcome: &'a mut Option<SecurityDispatchOutcomeHandle>,
    pub(super) pre_invocation_guard_evidence: &'a [chio_core::receipt::metadata::GuardEvidence],
    pub(super) timestamp: u64,
    pub(super) matched_grant_index: usize,
    pub(super) cap: &'a CapabilityToken,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) payment_authorization: Option<&'a PaymentAuthorization>,
    pub(super) durable_operation: Option<&'a AdmissionOperationV1>,
    pub(super) runtime_admission_metadata: Option<serde_json::Value>,
    pub(super) verified_payee_binding: Option<&'a VerifiedGovernedPayeeBinding>,
    pub(super) budget_lease_acquired: bool,
}

impl ChioKernel {
    /// Ask the tool server to prove it can accept the dispatch. A refusal is
    /// a pre-dispatch denial: credentials roll back, the budget is restored,
    /// the operation is compensated and nothing has reached the server.
    pub(super) async fn prepare_remote_delivery(
        &self,
        preparation: DeliveryPreparation<'_>,
    ) -> Result<Option<ToolCallResponse>, KernelError> {
        let Err(error) = preparation
            .server
            .prepare_delivery(preparation.context)
            .await
        else {
            return Ok(None);
        };
        let reason = format!("tool server could not prepare delivery: {error}");
        warn!(
            request_id = %preparation.request.request_id,
            reason = %redacted!(&reason),
            "tool server delivery preparation denied"
        );
        if let Some(outcome) = preparation.security_dispatch_outcome.take() {
            outcome.record_dispatch_failed()?;
        }
        let credential_disposition = if preparation.payment_authorization.is_some() {
            PaymentCredentialDisposition::RetainedAfterAuthorization
        } else {
            PaymentCredentialDisposition::NonePresent
        };
        self.with_pre_invocation_guard_evidence(preparation.pre_invocation_guard_evidence, || {
            self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                PreDispatchCleanupDeny {
                    request: preparation.request,
                    reason: &reason,
                    timestamp: preparation.timestamp,
                    matched_grant_index: preparation.matched_grant_index,
                    cap: preparation.cap,
                    budget_mutation: preparation.budget_mutation,
                    payment_authorization: preparation.payment_authorization,
                    durable_operation: preparation.durable_operation,
                    runtime_admission_metadata: preparation.runtime_admission_metadata,
                    verified_payee_binding: preparation.verified_payee_binding,
                    budget_lease_acquired: preparation.budget_lease_acquired,
                },
                credential_disposition,
            )
        })
        .map(Some)
    }
}
