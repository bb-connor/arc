//! Non-consuming permission preview selects only the independently configured
//! replay profile. Test helpers cannot bypass operation-owned custody.
use super::*;

impl ChioKernel {
    /// Require the request's proof for a non-consuming preview. Credential
    /// reservation remains a separate operation-owned dispatch step.
    pub(crate) fn verify_required_dpop_preview(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        self.operation_owned_dpop_authority()
            .ok_or(crate::dpop::DpopError::MissingAuthority)?;
        let proof = request
            .dpop_proof
            .as_ref()
            .ok_or(KernelError::Dpop(crate::dpop::DpopError::MissingProof))?;
        self.verify_dpop_for_permission_preview(
            proof,
            cap,
            &request.server_id,
            &request.tool_name,
            &request.arguments,
        )
    }

    /// Verify a proof against the activated, independently selected authority.
    /// This does not claim a nonce; invocation requires durable replay custody.
    pub fn verify_dpop_for_permission_preview(
        &self,
        proof: &dpop::DpopProof,
        cap: &CapabilityToken,
        expected_tool_server: &str,
        expected_tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<(), KernelError> {
        self.verify_operation_owned_dpop(
            proof,
            cap,
            expected_tool_server,
            expected_tool_name,
            arguments,
        )
        .map(|_| ())
    }
}
