//! Native Groq response-envelope parsing for `chat/completions`.

use chio_provider_adapter_core::{openai_tool_call_to_function_call, response_body};
use chio_tool_call_fabric::{ProviderError, ProviderRequest};
use serde_json::Value;

use crate::native::FunctionCallPart;

pub(crate) fn function_calls(raw: ProviderRequest) -> Result<Vec<FunctionCallPart>, ProviderError> {
    let value: Value =
        chio_provider_adapter_core::input::json(&raw.0).map_err(ProviderError::from)?;
    let body = response_body(value, "Groq chat/completions")?;
    classify_content_policy(&body)?;
    extract_function_calls(&body)
}

fn classify_content_policy(body: &Value) -> Result<(), ProviderError> {
    if let Some(reason) = safety_block_reason(body) {
        return Err(ProviderError::ContentPolicy(format!(
            "Groq safety block: {reason}"
        )));
    }
    Ok(())
}

fn safety_block_reason(body: &Value) -> Option<String> {
    if let Some(reason) = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| {
            choices.iter().enumerate().find_map(|(index, choice)| {
                choice
                    .get("finish_reason")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|reason| *reason == "content_filter")
                    .map(|reason| format!("choices[{index}].finish_reason={reason}"))
            })
        })
    {
        return Some(reason);
    }

    body.get("promptFeedback")
        .and_then(|feedback| feedback.get("blockReason"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map(|reason| {
            if reason == "SAFETY" {
                "promptFeedback.blockReason=SAFETY"
            } else {
                "promptFeedback blocked the request"
            }
            .into()
        })
}

fn extract_function_calls(body: &Value) -> Result<Vec<FunctionCallPart>, ProviderError> {
    let mut calls = Vec::new();
    if let Some(choices) = body.get("choices").and_then(Value::as_array) {
        for choice in choices {
            let tool_calls = choice
                .get("message")
                .and_then(|message| message.get("tool_calls"))
                .and_then(Value::as_array);
            if let Some(tool_calls) = tool_calls {
                for entry in tool_calls {
                    if let Some(part) =
                        openai_tool_call_to_function_call(entry, "Groq", |id, name, args| {
                            FunctionCallPart { id, name, args }
                        })?
                    {
                        calls.push(part);
                    }
                }
            }
        }
    }
    Ok(calls)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod diagnostic_tests {
    #[test]
    fn refusal_diagnostics_do_not_echo_arbitrary_provider_text() {
        let payload =
            serde_json::json!({"promptFeedback":{"blockReason":"private-provider-payload"}});
        let error = super::classify_content_policy(&payload).unwrap_err();
        assert!(!format!("{error} {error:?}").contains("private-provider-payload"));
    }
}
