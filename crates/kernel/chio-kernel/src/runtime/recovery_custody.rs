//! Protected request custody is loaded and checked by the native authority.
use super::ToolCallRequest;
use chio_security_types::recovery::{ContinuationId, IntentDigest, RecoveryScopeV1};

/// Exact caller bytes retained by the serving authority. A wire value cannot
/// construct this token. It is custody evidence, not permission to dispatch.
///
/// ```compile_fail
/// use chio_kernel::RecoveryRequestCustody;
/// let _: Result<RecoveryRequestCustody, _> = serde_json::from_str("{}");
/// ```
///
/// ```compile_fail
/// use chio_kernel::RecoveryRequestCustody;
/// fn duplicate(custody: &RecoveryRequestCustody) {
///     let _: RecoveryRequestCustody = Clone::clone(custody);
/// }
/// ```
pub struct RecoveryRequestCustody {
    pub(crate) scope: RecoveryScopeV1,
    pub(crate) continuation: ContinuationId,
    pub(crate) action_intent: IntentDigest,
    pub(crate) request: ToolCallRequest,
    pub(crate) process_request_digest: String,
    pub(crate) process_binding_digest: String,
    pub(crate) original_nonce: Option<crate::execution_nonce::SignedExecutionNonce>,
}
impl RecoveryRequestCustody {
    pub fn scope(&self) -> &RecoveryScopeV1 {
        &self.scope
    }
    pub fn continuation(&self) -> &ContinuationId {
        &self.continuation
    }
    pub const fn action_intent(&self) -> IntentDigest {
        self.action_intent
    }
    pub fn request(&self) -> &ToolCallRequest {
        &self.request
    }
    pub fn process_request_digest(&self) -> &str {
        &self.process_request_digest
    }
    pub fn process_binding_digest(&self) -> &str {
        &self.process_binding_digest
    }
    /// The already issued original nonce, loaded by the fenced native owner.
    /// This historical attachment is never a fresh nonce or dispatch permit.
    pub fn original_execution_nonce(
        &self,
    ) -> Option<&crate::execution_nonce::SignedExecutionNonce> {
        self.original_nonce.as_ref()
    }
}
impl core::fmt::Debug for RecoveryRequestCustody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryRequestCustody([redacted])")
    }
}
