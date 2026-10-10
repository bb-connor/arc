//! Original dispatch custody until its return is recorded or terminal unknown.
use super::*;
use crate::kernel::admission_coordinator::{DurableToolReturn, DurableToolReturnContext};
use std::ops::ControlFlow;

pub(super) struct EvaluationReturnRecording<'a> {
    pub request: &'a ToolCallRequest,
    pub output: &'a ToolServerOutput,
    pub reported_cost: Option<ToolInvocationCost>,
    pub context: Option<&'a DurableToolReturnContext>,
    pub elapsed: Duration,
    pub trusted_now_unix_ms: u64,
    pub timestamp: u64,
    pub matched_grant_index: usize,
    pub budget: &'a PreExecutionBudgetMutation,
    pub payment: Option<&'a PaymentAuthorization>,
    pub metadata: Option<serde_json::Value>,
    pub evidence: &'a [GuardEvidence],
    pub payee: Option<&'a VerifiedGovernedPayeeBinding>,
}

impl ChioKernel {
    pub(super) fn record_evaluation_return(
        &self,
        admission: Option<&mut DurableToolAdmission>,
        guard: &mut PostAdmissionDropGuard<'_>,
        input: EvaluationReturnRecording<'_>,
    ) -> Result<ControlFlow<ToolCallResponse, Option<DurableToolReturn>>, KernelError> {
        let Some(admission) = admission else {
            guard.disarm();
            return Ok(ControlFlow::Continue(None));
        };
        let context = input.context.ok_or_else(|| {
            KernelError::DurableAdmission("tool return lost its frozen dispatch context".into())
        })?;
        let recorded_at = self
            .read_authority_time()?
            .get()
            .max(input.trusted_now_unix_ms);
        match self.record_durable_tool_return(
            admission,
            DurableToolReturnInput {
                request: input.request,
                output: input.output,
                reported_cost: input.reported_cost,
                context,
                elapsed: input.elapsed,
                trusted_now_unix_ms: recorded_at,
            },
        ) {
            Ok(outcome) => {
                guard.disarm();
                Ok(ControlFlow::Continue(Some(outcome)))
            }
            Err(error) => {
                warn!(request_id = %input.request.request_id, reason = %redacted!(&error),
                    "tool return could not be durably recorded");
                let metadata = self.ambiguous_dispatch_receipt_metadata(
                    input.budget,
                    input.payment,
                    input.metadata,
                );
                self.terminalize_dispatch_committed_admission(admission.operation(), recorded_at)?;
                guard.mark_durable_operation_terminalized();
                guard.disarm();
                let response = self.with_pre_invocation_guard_evidence(input.evidence, || {
                    self.build_deny_response_with_metadata_and_payee_binding(
                        input.request,
                        &error.to_string(),
                        input.timestamp,
                        Some(input.matched_grant_index),
                        metadata,
                        input.payee,
                    )
                })?;
                Ok(ControlFlow::Break(response))
            }
        }
    }
}
