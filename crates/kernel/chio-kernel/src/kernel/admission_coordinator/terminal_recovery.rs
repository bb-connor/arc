//! Reconciliation enters terminal finalization without acquiring fresh dispatch
//! participants. A missing required release checkpoint remains unresolved.
use super::terminal::DurableToolReturn;
use super::*;

impl ChioKernel {
    pub(crate) fn recover_durable_tool_admission(
        &self,
        admission: &mut DurableToolAdmission,
        request: &ToolCallRequest,
    ) -> Result<Option<ToolCallResponse>, KernelError> {
        match admission.state() {
            AdmissionOperationState::Finalizing => {
                let tool_return = self.load_durable_tool_return(admission)?;
                self.finalize_durable_tool_return(admission, request, &tool_return)
                    .map(Some)
            }
            AdmissionOperationState::Completed | AdmissionOperationState::DeniedAfterDelivery => {
                self.completed_durable_tool_response(admission, request)
                    .map(Some)
            }
            _ => Ok(None),
        }
    }

    pub(crate) fn finalize_durable_tool_return(
        &self,
        admission: &mut DurableToolAdmission,
        request: &ToolCallRequest,
        tool_return: &DurableToolReturn,
    ) -> Result<ToolCallResponse, KernelError> {
        self.finalize_durable_tool_return_with_security_release(
            admission,
            request,
            tool_return,
            None,
        )
    }
}
