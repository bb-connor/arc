//! Classify delivered payloads, not raw pre-redaction values or stream hashes.
use super::*;
use chio_kernel::ToolCallOutput;

impl NativeFlowResolver {
    pub(super) fn classify_output(
        &self,
        context: &chio_kernel::tool_outcome::DurableSecurityReleaseContext<'_>,
    ) -> Result<InformationLabel, NativeFlowError> {
        let request: chio_kernel::ToolCallRequest =
            serde_json::from_str(context.request_canonical_json())
                .map_err(|_| NativeFlowError::PolicyEvidence)?;
        self.classified_output_label(&request, context.security_context(), context.output())
    }

    fn classified_output_label(
        &self,
        request: &chio_kernel::ToolCallRequest,
        context: &chio_kernel::SecurityInvocationContext,
        output: &ToolCallOutput,
    ) -> Result<InformationLabel, NativeFlowError> {
        let policy = self.policy();
        let (security, bridge) =
            policy.resolve_admitted_tool_security(&request.server_id, &request.tool_name)?;
        // A stream's signing preimage contains only digests. Classify the
        // ordered delivered chunks together, including every chunk's payload.
        let payload = match output {
            ToolCallOutput::Value(value) => canonical_body(value)?,
            ToolCallOutput::Stream(stream) => canonical_body(&serde_json::Value::Array(
                stream
                    .chunks
                    .iter()
                    .map(|chunk| chunk.data.clone())
                    .collect(),
            ))?,
        };
        let classification = self
            .config
            .category_labels
            .classify(
                self.classifier.as_ref(),
                &ClassificationRequest {
                    tenant_id: context.as_v1().tenant_id().clone(),
                    request_id: RequestId::new(request.request_id.clone())
                        .map_err(|_| FlowDenial::InvalidManifest)?,
                    payload_digest: digest(payload.as_bytes()),
                    payload,
                },
            )
            .map_err(|_| FlowDenial::ClassifierFailure)?;
        let mut label = classification
            .label()
            .join(security.effective_output_floor())
            .unwrap_or(InformationLabel::Top);
        if let Some(floor) = bridge.flow().and_then(|flow| flow.output_label.as_ref()) {
            label = label.join(floor).unwrap_or(InformationLabel::Top);
        }
        // Current inherited principal/lineage/session restrictions are joined
        // atomically by the original operation's writer, never a legacy store.
        Ok(label)
    }
}
