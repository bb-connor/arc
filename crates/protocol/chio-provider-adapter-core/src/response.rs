//! Shared response-envelope parsing primitives for provider adapters.
//!
//! Every native adapter accepts an outer transport envelope that may wrap the
//! provider payload under a `body`, `response`, or `payload` field (optionally
//! as a JSON-encoded string). [`response_body`] normalizes that envelope, and
//! [`openai_tool_call_to_function_call`] decodes a single OpenAI-compatible
//! `tool_calls[]` entry for the providers that speak the `chat/completions`
//! shape. The provider name only ever varies the error text, so it is carried
//! through a `provider_label` parameter.

use chio_tool_call_fabric::ProviderError;
use serde_json::Value;

/// Normalize a transport envelope down to the provider response body.
///
/// If the value carries a `body`, `response`, or `payload` envelope field the
/// nested body is unwrapped (an object directly, or a JSON-encoded string that
/// parses into a value); otherwise the value is returned unchanged. A present
/// envelope field that is neither an object nor a decodable string fails closed
/// as [`ProviderError::Malformed`], labelled with `provider_label`.
pub fn response_body(value: Value, provider_label: &str) -> Result<Value, ProviderError> {
    let mut nested = ["body", "response", "payload"]
        .into_iter()
        .filter_map(|field| value.get(field).map(|value| (field, value)));
    match (nested.next(), nested.next()) {
        (Some(_), Some(_)) => Err(ProviderError::Malformed(format!(
            "{provider_label} supplied multiple response envelopes"
        ))),
        (Some((field, body)), None) => {
            if !body.is_object() && !body.is_string() {
                return Err(ProviderError::Malformed(format!(
                    "{provider_label} envelope field `{field}` must contain an object"
                )));
            }
            nested_response_body(body)
        }
        (None, _) if value.is_object() => Ok(value),
        _ => Err(ProviderError::Malformed(
            "provider response must be an object".into(),
        )),
    }
}

/// Unwrap a single envelope field value into a response body.
///
/// Objects are returned directly; JSON-encoded strings are parsed; any other
/// shape fails closed with its typed cause retained.
pub fn nested_response_body(value: &Value) -> Result<Value, ProviderError> {
    let value = match value {
        Value::Object(_) => value.clone(),
        Value::String(body) => crate::input::text(body)?,
        _ => {
            return Err(ProviderError::Malformed(
                "response envelope must contain an object".into(),
            ))
        }
    };
    if !value.is_object() {
        return Err(ProviderError::Malformed(
            "response body must be an object".into(),
        ));
    }
    Ok(value)
}

/// Decode an OpenAI-compatible `tool_calls[]` entry of shape
/// `{ id, type: "function", function: { name, arguments } }` into a normalized
/// call built by `build`.
///
/// Non-function tool-call kinds are skipped (returning [`None`]). The
/// `build` constructor receives the decoded `(id, name, arguments)` so each
/// adapter can produce its own native call struct without duplicating the
/// decode logic. `provider_label` only varies the fail-closed error text.
pub fn openai_tool_call_to_function_call<T>(
    entry: &Value,
    provider_label: &str,
    build: impl FnOnce(String, String, Value) -> T,
) -> Result<Option<T>, ProviderError> {
    let kind = entry
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("function");
    if kind != "function" {
        return Ok(None);
    }
    let id = entry
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::Malformed(format!(
                "{provider_label} tool_calls[].id was missing or non-string"
            ))
        })?
        .to_string();
    let function = match entry.get("function") {
        Some(function) => function,
        None => {
            return Err(ProviderError::Malformed(format!(
                "{provider_label} tool_calls[].function was missing"
            )))
        }
    };
    let name = function
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::Malformed(format!(
                "{provider_label} tool_calls[].function.name was missing or non-string"
            ))
        })?
        .to_string();
    let args_value = match function.get("arguments") {
        Some(Value::String(arguments)) => crate::input::arguments(arguments)?,
        Some(other) => crate::input::argument_object(other.clone())?,
        None => {
            return Err(ProviderError::BadToolArgs(
                "tool call is missing arguments".into(),
            ))
        }
    };
    for identity in [&id, &name] {
        if identity.is_empty()
            || identity.len() > 4096
            || identity.trim() != identity
            || identity.chars().any(char::is_control)
        {
            return Err(ProviderError::Malformed(
                "tool call identity is invalid".into(),
            ));
        }
    }

    Ok(Some(build(id, name, args_value)))
}
