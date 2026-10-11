//! Classify delivered payloads, not raw pre-redaction values or stream hashes.
use super::*;
use chio_kernel::ToolCallOutput;
use chio_security_types::ports::ClassificationPayload;

fn classification_payload(value: &serde_json::Value) -> Result<ClassificationPayload, FlowDenial> {
    let bytes =
        chio_core::canonical_json_bytes(value).map_err(|_| FlowDenial::ClassifierFailure)?;
    ClassificationPayload::new(bytes).map_err(|_| FlowDenial::ClassifierFailure)
}

impl NativeFlowResolver {
    pub(super) fn classify_output(
        &self,
        context: &chio_kernel::tool_outcome::DurableSecurityReleaseContext<'_>,
    ) -> Result<InformationLabel, NativeFlowError> {
        let request: chio_kernel::ToolCallRequest =
            chio_core::canonical::UntrustedJsonText::from_wire(
                (context.request_canonical_json()).as_bytes(),
                64 * 1024 * 1024,
            )
            .and_then(|input| input.decode_signed())
            .map_err(NativeFlowError::from)?;
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
            ToolCallOutput::Value(value) => classification_payload(value)?,
            ToolCallOutput::Stream(stream) => classification_payload(&serde_json::Value::Array(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::adapters::canonical_body;

    #[test]
    fn complete_broker_envelope_is_classified_without_the_authority_body_limit() {
        let output = serde_json::json!({"body": vec![b'x'; 500_000]});
        let payload = classification_payload(&output)
            .unwrap_or_else(|error| panic!("classify delivered envelope: {error}"));
        let original = chio_core::canonical_json_bytes(&output)
            .unwrap_or_else(|error| panic!("canonical envelope: {error}"));
        assert!(original.len() > 1_048_576);
        assert_eq!(payload.as_bytes(), original);
        assert!(matches!(
            canonical_body(&output),
            Err(FlowDenial::ClassifierFailure)
        ));
    }
}
