//! Policy-owned proof requirement, including capabilities minted by other issuers.
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};

pub(super) struct SenderProofGuard;
impl Guard for SenderProofGuard {
    fn name(&self) -> &str {
        "sender-proof"
    }
    fn evaluate(&self, ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        // The kernel verifies proof and replay custody before running guards. Requiring
        // a proof-bound matching grant prevents an external bearer grant bypassing policy.
        let request = ctx.request;
        let required = chio_kernel::capability_request_requires_dpop_with_model_metadata(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )?;
        Ok(if required {
            GuardDecision::allow()
        } else {
            GuardDecision::deny(Vec::new())
        })
    }
    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }
}
