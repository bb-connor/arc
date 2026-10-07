//! Current external delivery follows private, immutable effect settlement.
use super::*;

impl ChioKernel {
    pub(in crate::kernel::admission_coordinator) fn require_current_public_tool_response(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        response: &ToolCallResponse,
    ) -> Result<(), KernelError> {
        if self.is_emergency_stopped() {
            return Err(KernelError::GuardDenied(EMERGENCY_STOP_DENY_REASON.into()));
        }
        if !matches!(
            admission.operation.state(),
            AdmissionOperationState::Completed | AdmissionOperationState::DeniedAfterDelivery
        ) {
            return Err(KernelError::DurableAdmission(
                "public return requires committed terminal custody".into(),
            ));
        }
        // The owning reader authenticates the exact original capture and
        // current source/status audience. A refusal changes neither the
        // already committed effect nor its receipt or output artifacts.
        let runtime = self.durable_runtime()?;
        let disposition = runtime
            .store
            .semantic_output_disposition(
                &admission.operation,
                request,
                &runtime.fence,
                runtime.refresh_trusted_time(current_unix_timestamp_ms()),
            )
            .map_err(durable_store_error)?;
        if disposition == Some(chio_security_types::semantic::SemanticOutputDispositionV1::Withhold)
            && response.output.as_ref().is_some_and(|output| {
                output != &ToolCallOutput::Value(serde_json::json!({"status":"withheld"}))
            })
        {
            return Err(KernelError::DurableAdmission(
                "public withheld projection differs from committed disposition".into(),
            ));
        }
        // A current reader or host callback may itself have crossed a stop
        // transition. Never publish bytes from the earlier observation alone.
        if self.is_emergency_stopped() {
            return Err(KernelError::GuardDenied(EMERGENCY_STOP_DENY_REASON.into()));
        }
        Ok(())
    }

    pub(crate) fn finalize_public_durable_tool_return_with_security_release(
        &self,
        admission: &mut DurableToolAdmission,
        request: &ToolCallRequest,
        tool_return: &DurableToolReturn,
        security_release: Option<SecurityRequestLifecycleHandle>,
    ) -> Result<ToolCallResponse, KernelError> {
        let mut response = self.finalize_durable_tool_return_with_security_release(
            admission,
            request,
            tool_return,
            security_release,
        )?;
        self.require_current_public_tool_response(admission, request, &response)?;
        if response.verdict == Verdict::Allow
            && response.output.is_some()
            && tool_return.caller_report_digest().is_none()
        {
            response.execution_nonce = self.mint_execution_nonce_for_allow(
                request,
                &request.capability,
                &response.receipt,
            )?;
        }
        Ok(response)
    }
}
