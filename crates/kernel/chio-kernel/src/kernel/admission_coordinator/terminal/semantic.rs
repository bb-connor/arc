//! Bound output disposition preserves original native effect ownership.
//! This projects retained facts. Current status delivery is checked separately
//! after terminal commitment, so refusal cannot strand an already owned effect.
use super::*;

impl ChioKernel {
    pub(super) fn apply_captured_semantic_disposition(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        output: &mut ToolCallOutput,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        if let Some(disposition) = runtime
            .store
            .semantic_output_disposition(
                &admission.operation,
                request,
                &runtime.fence,
                current_unix_timestamp_ms(),
            )
            .map_err(durable_store_error)?
        {
            if !matches!(output, ToolCallOutput::Value(_)) {
                return Err(KernelError::DurableAdmission(
                    "semantic output channel is unsupported".into(),
                ));
            }
            if disposition == chio_security_types::semantic::SemanticOutputDispositionV1::Withhold {
                *output = ToolCallOutput::Value(serde_json::json!({"status":"withheld"}));
            }
        }
        Ok(())
    }
}
