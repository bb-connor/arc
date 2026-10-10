//! Exercise a real authenticated namespace through ordinary Kernel admission.
use super::*;

impl ChioKernel {
    /// Test adapter for the existing session-aware evaluator. The real session,
    /// capability, native context and retained operation checks remain enabled.
    /// This grants no process-origin proof or recovery permission.
    pub async fn evaluate_authenticated_original_for_test(
        &self,
        request: &ToolCallRequest,
        session: &chio_core::session::SessionId,
        context: &SecurityInvocationContext,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_authenticated_original_session_for_test(request, session, context)
            .await
    }
}
