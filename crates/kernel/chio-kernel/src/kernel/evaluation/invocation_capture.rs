//! Invocation capture for a budgeted dispatch outside durable admission.

use super::*;
use crate::budget_store::BudgetInvocationCaptureDecision;

/// The admitted state a non-durable monetary dispatch captures from.
pub(super) struct NonDurableInvocationCapture<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) cap: &'a CapabilityToken,
    pub(super) budget_mutation: &'a mut PreExecutionBudgetMutation,
    pub(super) now: u64,
    pub(super) matched_grant_index: usize,
    pub(super) extra_metadata: &'a Option<serde_json::Value>,
    pub(super) budget_lease_acquired: bool,
    pub(super) verified_payee_binding: Option<&'a VerifiedGovernedPayeeBinding>,
    pub(super) pre_invocation_guard_evidence: &'a [chio_core::receipt::metadata::GuardEvidence],
}

impl ChioKernel {
    /// Capture the invocation of a non-durable budget hold. A replay of an
    /// already captured invocation and an unconfirmed capture both deny with
    /// the retained metadata; the denial is the response to return.
    pub(super) fn capture_non_durable_invocation(
        &self,
        capture: NonDurableInvocationCapture<'_>,
    ) -> Result<Option<ToolCallResponse>, KernelError> {
        let NonDurableInvocationCapture {
            request,
            cap,
            budget_mutation,
            now,
            matched_grant_index,
            extra_metadata,
            budget_lease_acquired,
            verified_payee_binding,
            pre_invocation_guard_evidence,
        } = capture;
        match self.capture_invocation(cap, budget_mutation) {
            Ok(BudgetInvocationCaptureDecision::Captured(_)) => Ok(None),
            Ok(BudgetInvocationCaptureDecision::AlreadyCaptured(_)) => {
                let reason = "monetary invocation was already dispatched";
                self.with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                    self.build_capture_replay_deny_response(
                        request,
                        reason,
                        now,
                        matched_grant_index,
                        cap,
                        budget_mutation,
                        extra_metadata.clone(),
                        budget_lease_acquired,
                        verified_payee_binding,
                    )
                })
                .map(Some)
            }
            Err(error) => {
                let internal_reason = error.to_string();
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&internal_reason),
                    "budget invocation capture could not be confirmed"
                );
                let reason = "budget invocation capture could not be confirmed";
                self.with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                    self.build_deny_response_with_metadata(
                        request,
                        reason,
                        now,
                        Some(matched_grant_index),
                        self.ambiguous_invocation_capture_receipt_metadata(
                            budget_mutation,
                            extra_metadata.clone(),
                        ),
                    )
                })
                .map(Some)
            }
        }
    }
}
