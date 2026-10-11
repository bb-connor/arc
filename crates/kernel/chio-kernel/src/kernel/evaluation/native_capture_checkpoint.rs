//! Shared default-off capture checkpoint for normal and nested evaluation.
//! Actual mutable custody is read after the callback before choosing cleanup.
use super::evaluation_helpers::PreDispatchCleanupDeny;
use super::*;
use crate::kernel::admission_coordinator::NativeCaptureCheckpointInput;
use crate::kernel::credential_reservation::DispatchCredentialReservation;

pub(super) struct NativeCaptureCheckpointContext<'a> {
    pub request: &'a ToolCallRequest,
    pub security_context: Option<&'a SecurityInvocationContext>,
    pub timestamp: u64,
    pub matched_grant_index: usize,
    pub payment_authorization: Option<&'a PaymentAuthorization>,
    pub metadata: Option<&'a serde_json::Value>,
    pub verified_payee_binding: Option<&'a VerifiedGovernedPayeeBinding>,
    pub budget_lease_acquired: bool,
    pub evidence: &'a [chio_core::receipt::metadata::GuardEvidence],
}

pub(super) type NativeCaptureCheckpointOutcome<'a> =
    std::ops::ControlFlow<Result<ToolCallResponse, KernelError>, DispatchCredentialReservation<'a>>;

impl ChioKernel {
    pub(super) fn evaluate_native_capture_checkpoint<'kernel>(
        &'kernel self,
        mut credentials: DispatchCredentialReservation<'kernel>,
        mut admission: Option<&mut DurableToolAdmission>,
        budget: &mut PreExecutionBudgetMutation,
        context: NativeCaptureCheckpointContext<'_>,
    ) -> NativeCaptureCheckpointOutcome<'kernel> {
        let Some(error) = self.reach_native_capture_checkpoint(NativeCaptureCheckpointInput {
            request: context.request,
            context: context.security_context,
            admission: admission.as_deref_mut(),
            budget,
            credentials: &mut credentials,
            metadata: context.metadata,
        }) else {
            return NativeCaptureCheckpointOutcome::Continue(credentials);
        };
        let reason = error.to_string();
        NativeCaptureCheckpointOutcome::Break(self.build_durable_dispatch_failure_response(
            error,
            PreDispatchCleanupDeny {
                request: context.request,
                reason: &reason,
                timestamp: context.timestamp,
                matched_grant_index: context.matched_grant_index,
                cap: &context.request.capability,
                budget_mutation: budget,
                payment_authorization: context.payment_authorization,
                durable_operation: admission.as_deref().map(DurableToolAdmission::operation),
                runtime_admission_metadata: context.metadata.cloned(),
                verified_payee_binding: context.verified_payee_binding,
                budget_lease_acquired: context.budget_lease_acquired,
            },
            credentials,
            context.evidence,
            None,
        ))
    }
}
