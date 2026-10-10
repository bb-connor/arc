//! Validate complete bounded NDJSON before evaluating calls or forwarding bytes.
use crate::{response, OllamaAdapter};
use chio_provider_adapter_core::{
    ensure_streaming_allow_no_redactions, http::parse_ndjson_lines, input,
};
use chio_tool_call_fabric::{ProviderError, ToolInvocation, VerdictResult};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedNdjsonStream {
    pub bytes: Vec<u8>,
    pub invocations: Vec<ToolInvocation>,
    pub verdicts: Vec<VerdictResult>,
}

impl OllamaAdapter {
    pub fn gate_sse_stream<F>(
        &self,
        raw: &[u8],
        mut evaluate: F,
    ) -> Result<GatedNdjsonStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        self.ensure_supported_api_version()?;
        let frames = parse_ndjson_lines(raw, "Ollama")?;
        let mut invocations = Vec::new();
        let mut done = false;
        for frame in frames {
            if done {
                return Err(ProviderError::Malformed(
                    "Ollama data followed its terminal frame".into(),
                ));
            }
            if frame.get("error").is_some() {
                return Err(ProviderError::Malformed(
                    "Ollama stream reported an upstream error".into(),
                ));
            }
            done = frame.get("done").and_then(Value::as_bool).ok_or_else(|| {
                ProviderError::Malformed("Ollama frame omitted its done flag".into())
            })?;
            response::classify_content_policy(&frame)?;
            if let Some(message) = frame.get("message") {
                if !message.is_object() {
                    return Err(ProviderError::Malformed(
                        "Ollama message must be an object".into(),
                    ));
                }
                if let Some(calls) = message.get("tool_calls") {
                    let calls = calls.as_array().ok_or_else(|| {
                        ProviderError::Malformed("Ollama tool_calls must be an array".into())
                    })?;
                    for entry in calls {
                        if invocations.len() >= input::MAX_TOOL_CALLS {
                            return Err(ProviderError::StreamCapacityExceeded);
                        }
                        let call = response::tool_call_part(entry)?;
                        let invocation =
                            self.invocation_from_tool_call(invocations.len(), &call)?;
                        if !invocation.bridge_security.as_ref().is_some_and(
                            chio_manifest::BridgeSecurityMetadata::has_registry_coordinates,
                        ) {
                            return Err(ProviderError::Malformed("Ollama stream evaluation requires a registry-admitted security sidecar".into()));
                        }
                        invocations.push(invocation);
                    }
                }
            }
        }
        if !done {
            return Err(ProviderError::Malformed(
                "Ollama stream ended without its terminal frame".into(),
            ));
        }
        let mut verdicts = Vec::with_capacity(invocations.len());
        for invocation in &invocations {
            let verdict = evaluate(invocation)?;
            ensure_streaming_allow_no_redactions(
                "Ollama",
                "tool_call",
                &invocation.tool_name,
                None,
                &verdict,
            )?;
            verdicts.push(verdict);
        }
        Ok(GatedNdjsonStream {
            bytes: raw.to_vec(),
            invocations,
            verdicts,
        })
    }
}
