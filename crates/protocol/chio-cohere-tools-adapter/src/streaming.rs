//! Cohere SSE gating for `/v2/chat` stream payloads.
//!
//! Cohere v2 streams a tool call as `tool-call-start` (id, name, initial
//! arguments), zero or more `tool-call-delta` argument fragments and a
//! `tool-call-end`. Deterministic conformance fixtures instead carry the fully
//! assembled `tool_call` on `tool-call-end`. The gate accepts both shapes,
//! requires them to agree when both are present, rejects unknown events and any
//! tool-call payload outside the tool-call frames, and evaluates every call
//! before any byte is released.

use chio_provider_adapter_core::{
    ensure_streaming_allow_no_redactions, parse_sse_frames, GatedStream, SseParseOptions,
};
use chio_tool_call_fabric::{ProviderError, ToolInvocation, VerdictResult};
use serde_json::Value;

use crate::{native::ToolCallBlock, CohereAdapter};

pub type GatedSseStream = GatedStream;

const COHERE_SSE_OPTIONS: SseParseOptions =
    SseParseOptions::rejecting_unknown("Cohere").with_event_type_cross_check();

/// Cohere v2 chat stream events the gate understands.
const KNOWN_EVENTS: &[&str] = &[
    "message-start",
    "content-start",
    "content-delta",
    "content-end",
    "tool-plan-delta",
    "tool-call-start",
    "tool-call-delta",
    "tool-call-end",
    "citation-start",
    "citation-end",
    "message-end",
];

/// A tool call opened by `tool-call-start` and not yet ended.
struct OpenCall {
    index: Option<u64>,
    id: String,
    name: String,
    arguments: String,
}

impl CohereAdapter {
    /// Gate a Cohere v2 SSE payload.
    pub fn gate_sse_stream<F>(
        &self,
        raw: &[u8],
        mut evaluate: F,
    ) -> Result<GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        self.ensure_supported_api_version()?;
        let frames = parse_sse_frames(raw, COHERE_SSE_OPTIONS)?;
        let mut output: Vec<u8> = Vec::new();
        let mut invocations = Vec::new();
        let mut verdicts = Vec::new();
        let mut open: Option<OpenCall> = None;
        let mut message_open = false;

        for frame in frames {
            let Some(event) = frame.event.as_deref() else {
                if frame.data.is_some() {
                    return Err(malformed("Cohere SSE data frame carried no event name"));
                }
                output.extend_from_slice(&frame.raw);
                continue;
            };
            if !KNOWN_EVENTS.contains(&event) {
                return Err(ProviderError::Malformed(format!(
                    "Cohere SSE event {event} is not supported by the gate"
                )));
            }
            let data = frame.data.as_ref();
            match event {
                "message-start" => message_open = true,
                "message-end" => {
                    if open.is_some() {
                        return Err(malformed("Cohere message-end arrived inside a tool call"));
                    }
                    message_open = false;
                }
                "tool-call-start" => {
                    if open.is_some() {
                        return Err(malformed(
                            "Cohere tool-call-start arrived before the previous call ended",
                        ));
                    }
                    open = Some(open_call(data)?);
                }
                "tool-call-delta" => {
                    let call = open.as_mut().ok_or_else(|| {
                        malformed("Cohere tool-call-delta arrived without tool-call-start")
                    })?;
                    ensure_same_index(call, data)?;
                    let fragment = streamed_tool_call(data)
                        .and_then(|call| call.get("function"))
                        .and_then(|function| function.get("arguments"))
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            malformed("Cohere tool-call-delta was missing argument text")
                        })?;
                    if call.arguments.len().saturating_add(fragment.len())
                        > chio_provider_adapter_core::input::MAX_ARGUMENT_BYTES
                    {
                        return Err(ProviderError::StreamCapacityExceeded);
                    }
                    call.arguments.push_str(fragment);
                }
                "tool-call-end" => {
                    let embedded = data
                        .filter(|data| embedded_tool_call(data).is_some())
                        .map(tool_call_from_data)
                        .transpose()?;
                    let block = match (open.take(), embedded) {
                        (Some(assembled), Some(embedded)) => {
                            ensure_same_index(&assembled, data)?;
                            if embedded.id != assembled.id
                                || embedded.function.name != assembled.name
                                || embedded.function.arguments != assembled.arguments
                            {
                                return Err(malformed(
                                    "Cohere tool-call-end disagreed with the streamed tool call",
                                ));
                            }
                            embedded
                        }
                        (Some(assembled), None) => {
                            ensure_same_index(&assembled, data)?;
                            ToolCallBlock::new(assembled.id, assembled.name, assembled.arguments)
                        }
                        (None, Some(embedded)) => embedded,
                        (None, None) => {
                            return Err(malformed(
                                "Cohere tool-call-end frame was missing tool_call",
                            ))
                        }
                    };
                    let invocation = self.invocation_from_tool_call(&block)?;
                    if !invocation.bridge_security.as_ref().is_some_and(
                        chio_manifest::BridgeSecurityMetadata::has_registry_coordinates,
                    ) {
                        return Err(ProviderError::Malformed(
                            "Cohere SSE tool-call evaluation requires a registry-admitted security sidecar"
                                .to_string(),
                        ));
                    }
                    if invocations.len() >= chio_provider_adapter_core::input::MAX_TOOL_CALLS {
                        return Err(ProviderError::StreamCapacityExceeded);
                    }
                    invocations.push(invocation);
                }
                _ => {
                    if data.is_some_and(carries_tool_call_payload) {
                        return Err(ProviderError::Malformed(format!(
                            "Cohere {event} frame carried a tool call outside the tool-call frames"
                        )));
                    }
                }
            }
            output.extend_from_slice(&frame.raw);
        }
        if open.is_some() {
            return Err(malformed("Cohere stream ended before the tool call ended"));
        }
        if message_open {
            return Err(malformed("Cohere stream ended before message-end"));
        }

        for invocation in &invocations {
            let verdict = evaluate(invocation)?;
            ensure_streaming_allow_no_redactions(
                "Cohere",
                "tool_call",
                &invocation.tool_name,
                None,
                &verdict,
            )?;
            verdicts.push(verdict);
        }

        Ok(GatedSseStream {
            bytes: output,
            invocations,
            verdicts,
        })
    }
}

fn malformed(message: &str) -> ProviderError {
    ProviderError::Malformed(message.to_string())
}

/// The `delta.message.tool_calls` object Cohere sends on start and delta frames.
fn streamed_tool_call(data: Option<&Value>) -> Option<&Value> {
    data?.get("delta")?.get("message")?.get("tool_calls")
}

fn open_call(data: Option<&Value>) -> Result<OpenCall, ProviderError> {
    let call = streamed_tool_call(data)
        .ok_or_else(|| malformed("Cohere tool-call-start was missing its tool call"))?;
    let kind = call
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("function");
    if kind != "function" {
        return Err(ProviderError::Malformed(format!(
            "Cohere tool call type {kind} is not supported by the gate"
        )));
    }
    let text = |value: Option<&Value>, what: &str| -> Result<String, ProviderError> {
        value
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                ProviderError::Malformed(format!("Cohere tool-call-start missing {what}"))
            })
    };
    let function = call.get("function");
    Ok(OpenCall {
        index: data
            .and_then(|data| data.get("index"))
            .and_then(Value::as_u64),
        id: text(call.get("id"), "id")?,
        name: text(function.and_then(|function| function.get("name")), "name")?,
        arguments: function
            .and_then(|function| function.get("arguments"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

fn ensure_same_index(call: &OpenCall, data: Option<&Value>) -> Result<(), ProviderError> {
    let index = data
        .and_then(|data| data.get("index"))
        .and_then(Value::as_u64);
    match (call.index, index) {
        (Some(expected), Some(actual)) if expected != actual => {
            Err(malformed("Cohere tool-call frame index changed mid-call"))
        }
        _ => Ok(()),
    }
}

fn embedded_tool_call(data: &Value) -> Option<&Value> {
    data.get("tool_call")
        .or_else(|| data.get("delta").and_then(|delta| delta.get("tool_call")))
}

/// True when a non-tool frame carries any `tool_call` or `tool_calls` member.
fn carries_tool_call_payload(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            key == "tool_call" || key == "tool_calls" || carries_tool_call_payload(value)
        }),
        Value::Array(items) => items.iter().any(carries_tool_call_payload),
        _ => false,
    }
}

fn tool_call_from_data(data: &Value) -> Result<ToolCallBlock, ProviderError> {
    let Some(block) = embedded_tool_call(data) else {
        return Err(ProviderError::Malformed(
            "Cohere tool-call-end frame was missing tool_call".to_string(),
        ));
    };
    let parsed: ToolCallBlock =
        chio_provider_adapter_core::input::typed(block.clone()).map_err(ProviderError::from)?;
    Ok(parsed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::cell::Cell;
    use std::sync::Arc;

    use chio_tool_call_fabric::{ProviderError, ReceiptId, VerdictResult};

    use crate::{transport, CohereAdapter, CohereAdapterConfig};

    fn adapter() -> CohereAdapter {
        CohereAdapter::new(
            CohereAdapterConfig::new(
                "cohere-stream",
                "Cohere stream",
                "0.1.0",
                "deadbeef",
                "org_chio_stream",
            ),
            Arc::new(transport::MockTransport::new()),
        )
    }

    #[test]
    fn tool_call_end_without_tool_call_fails_closed() {
        let adapter = adapter();
        let evaluated = Cell::new(false);
        let err = adapter
            .gate_sse_stream(
                b"event: tool-call-end\ndata: {\"delta\":{}}\n\n",
                |_invocation| {
                    evaluated.set(true);
                    Ok(VerdictResult::Allow {
                        redactions: vec![],
                        receipt_id: ReceiptId("rcpt_stream_allow".to_string()),
                    })
                },
            )
            .expect_err("terminal Cohere tool-call frame without a tool_call must fail closed");

        assert!(!evaluated.get(), "malformed frame must not reach evaluator");
        assert!(matches!(err, ProviderError::Malformed(_)));
        assert!(err.to_string().contains("missing tool_call"));
    }
}
