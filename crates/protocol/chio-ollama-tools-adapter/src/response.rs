//! Native Ollama response-envelope parsing for `/api/chat`.

use chio_tool_call_fabric::{ProviderError, ProviderRequest};
use serde_json::Value;

use crate::native::ToolCallPart;

pub(crate) fn tool_calls(raw: ProviderRequest) -> Result<Vec<ToolCallPart>, ProviderError> {
    let value: Value =
        chio_provider_adapter_core::input::json(&raw.0).map_err(ProviderError::from)?;
    let body = response_body(value)?;
    classify_content_policy(&body)?;
    extract_tool_calls(&body)
}

fn response_body(value: Value) -> Result<Value, ProviderError> {
    chio_provider_adapter_core::response_body(value, "Ollama")
}

pub(crate) fn classify_content_policy(body: &Value) -> Result<(), ProviderError> {
    if body
        .get("policy")
        .and_then(Value::as_str)
        .is_some_and(|policy| policy.trim().eq_ignore_ascii_case("refusal"))
    {
        return Err(ProviderError::ContentPolicy("Ollama model refusal".into()));
    }
    Ok(())
}

fn extract_tool_calls(body: &Value) -> Result<Vec<ToolCallPart>, ProviderError> {
    let message = match body.get("message") {
        Some(value) => value,
        None => return Ok(Vec::new()),
    };
    let array = match message.get("tool_calls").and_then(Value::as_array) {
        Some(array) => array,
        None => return Ok(Vec::new()),
    };
    let mut calls = Vec::with_capacity(array.len());
    for entry in array {
        calls.push(tool_call_part(entry)?);
    }
    Ok(calls)
}

pub(crate) fn tool_call_part(entry: &Value) -> Result<ToolCallPart, ProviderError> {
    chio_provider_adapter_core::input::typed(entry.clone()).map_err(ProviderError::from)
}
