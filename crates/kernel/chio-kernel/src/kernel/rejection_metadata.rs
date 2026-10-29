//! Preserve an input-independent rejection code in signed denial evidence.
use super::*;
use chio_log_redact::redacted;
use serde_json::{json, Value};

impl KernelError {
    pub(crate) fn rejection_metadata(&self, metadata: Option<Value>) -> Option<Value> {
        let metadata = match metadata {
            Some(value @ Value::Object(_)) => Some(value),
            Some(value) => Some(json!({ "prior_metadata": value })),
            None => None,
        };
        crate::receipt_support::merge_metadata_objects(
            metadata,
            Some(json!({
                "chio_kernel": { "rejection_code": self.report().code }
            })),
        )
    }
}

impl ChioKernel {
    pub(super) fn deny_admission_error(
        &self,
        request: &ToolCallRequest,
        error: &KernelError,
        now: u64,
        metadata: Option<Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let denial = Denial::from_error(error);
        warn!(request_id = %request.request_id, rejection_code = %error.report().code,
            reason = %redacted!(denial.detail()), "admission rejected");
        self.build_deny_response_with_metadata(
            request,
            &denial,
            now,
            None,
            RefusalReceiptMetadata::new(
                error.rejection_metadata(metadata),
                IdentityDisposition::Reusable,
            ),
        )
    }
}
