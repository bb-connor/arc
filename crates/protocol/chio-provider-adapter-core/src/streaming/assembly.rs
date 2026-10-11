//! Assemble complete calls and validate termination before any evaluator runs.
use super::DecodedToolCall;
use crate::{input, SseFrame};
use chio_tool_call_fabric::ProviderError;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct Pending {
    id: Option<String>,
    name: Option<String>,
    arguments: String,
    object: Option<Value>,
    has_arguments: bool,
}
#[derive(Default)]
struct Choice {
    calls: BTreeMap<u64, Pending>,
    finished: bool,
}
fn malformed(message: &'static str) -> ProviderError {
    ProviderError::Malformed(message.into())
}
fn identity(slot: &mut Option<String>, value: Option<&Value>) -> Result<(), ProviderError> {
    let Some(value) = value else {
        return Ok(());
    };
    let value = value
        .as_str()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 4096
                && value.trim() == *value
                && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| malformed("stream identity must be a nonempty bounded string"))?;
    if slot.as_ref().is_some_and(|prior| prior != value) {
        return Err(malformed("stream identity changed"));
    }
    if slot.is_none() {
        *slot = Some(value.into());
    }
    Ok(())
}
fn index(value: Option<&Value>, fallback: u64) -> Result<u64, ProviderError> {
    match value {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| malformed("stream index is invalid")),
        None => Ok(fallback),
    }
}

pub(super) fn assemble(
    frames: &[SseFrame],
    sentinel_required: bool,
) -> Result<Vec<DecodedToolCall>, ProviderError> {
    let mut choices = BTreeMap::<u64, Choice>::new();
    let mut response_id = None;
    let mut done = false;
    let mut call_count = 0usize;
    for frame in frames {
        if frame.done {
            if done {
                return Err(malformed("duplicate stream terminator"));
            }
            done = true;
            continue;
        }
        let Some(data) = &frame.data else {
            continue;
        };
        if done {
            return Err(malformed("data followed the stream terminator"));
        }
        if !data.is_object() || data.get("error").is_some() {
            return Err(malformed(
                "provider stream reported an invalid or failed response",
            ));
        }
        identity(&mut response_id, data.get("id"))?;
        let list = data
            .get("choices")
            .ok_or_else(|| malformed("stream frame omitted choices"))?;
        let list = list
            .as_array()
            .ok_or_else(|| malformed("stream choices must be an array"))?;
        for (position, value) in list.iter().enumerate() {
            let choice_index = index(value.get("index"), position as u64)?;
            if !choices.contains_key(&choice_index) && choices.len() >= input::MAX_TOOL_CALLS {
                return Err(ProviderError::StreamCapacityExceeded);
            }
            let choice = choices.entry(choice_index).or_default();
            if choice.finished {
                return Err(malformed("stream choice continued after finishing"));
            }
            let delta = value.get("delta").filter(|value| !value.is_null());
            let message = value.get("message").filter(|value| !value.is_null());
            if delta.is_some() && message.is_some() {
                return Err(malformed("stream choice has both delta and message"));
            }
            if let Some(source) = delta.or(message) {
                if !source.is_object() {
                    return Err(malformed("stream message must be an object"));
                }
                if let Some(calls) = source.get("tool_calls") {
                    let calls = calls
                        .as_array()
                        .ok_or_else(|| malformed("stream tool_calls must be an array"))?;
                    for (position, entry) in calls.iter().enumerate() {
                        if !entry.is_object() {
                            return Err(malformed("stream tool call must be an object"));
                        }
                        if entry
                            .get("type")
                            .is_some_and(|kind| kind.as_str() != Some("function"))
                        {
                            return Err(malformed("unsupported stream tool call kind"));
                        }
                        let call_index = index(entry.get("index"), position as u64)?;
                        if !choice.calls.contains_key(&call_index) {
                            if call_count >= input::MAX_TOOL_CALLS {
                                return Err(ProviderError::StreamCapacityExceeded);
                            }
                            call_count += 1;
                        }
                        let pending = choice.calls.entry(call_index).or_default();
                        identity(&mut pending.id, entry.get("id"))?;
                        if let Some(function) = entry.get("function") {
                            if !function.is_object() {
                                return Err(malformed("stream function must be an object"));
                            }
                            identity(&mut pending.name, function.get("name"))?;
                            if let Some(arguments) = function.get("arguments") {
                                match arguments {
                                    Value::String(part) if pending.object.is_none() => {
                                        input::append_arguments(&mut pending.arguments, part)?
                                    }
                                    Value::Object(_) if !pending.has_arguments => {
                                        pending.object =
                                            Some(input::argument_object(arguments.clone())?)
                                    }
                                    _ => {
                                        return Err(malformed(
                                            "stream arguments changed representation",
                                        ))
                                    }
                                }
                                pending.has_arguments = true;
                            }
                        }
                    }
                }
            }
            if let Some(reason) = value
                .get("finish_reason")
                .filter(|reason| !reason.is_null())
            {
                let reason = reason
                    .as_str()
                    .ok_or_else(|| malformed("stream finish reason must be a string"))?;
                if !choice.calls.is_empty() && !matches!(reason, "tool_calls" | "stop") {
                    return Err(malformed(
                        "stream did not finish its tool calls successfully",
                    ));
                }
                choice.finished = true;
            }
        }
    }
    if sentinel_required && !done {
        return Err(malformed("stream ended without its terminator"));
    }
    if choices.values().any(|choice| !choice.finished) || (!done && choices.is_empty()) {
        return Err(malformed("stream ended before all choices finished"));
    }
    let mut ids = BTreeSet::new();
    let mut calls = Vec::new();
    for choice in choices.into_values() {
        for pending in choice.calls.into_values() {
            let id = pending
                .id
                .ok_or_else(|| malformed("stream tool call is missing its id"))?;
            let name = pending
                .name
                .ok_or_else(|| malformed("stream tool call is missing its name"))?;
            if !ids.insert(id.clone()) {
                return Err(malformed("stream reuses a tool call id"));
            }
            if !pending.has_arguments {
                return Err(malformed("stream tool call is missing arguments"));
            }
            let args = match pending.object {
                Some(value) => value,
                None => input::arguments(&pending.arguments)?,
            };
            calls.push(DecodedToolCall { id, name, args });
        }
    }
    Ok(calls)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{parse_sse_frames, SseParseOptions};
    use serde_json::json;

    fn stream(parts: &[&str]) -> Vec<u8> {
        let mut raw = String::new();
        for part in parts {
            raw.push_str(&format!("data: {}\n\n", json!({"id":"response", "choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call","type":"function","function":{"name":"tool","arguments":part}}]}}]})));
        }
        raw.push_str("data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n");
        raw.into_bytes()
    }
    fn decode(raw: &[u8]) -> Result<Vec<DecodedToolCall>, ProviderError> {
        let frames = parse_sse_frames(
            raw,
            SseParseOptions::ignoring_unknown("test").with_done_sentinel("[DONE]"),
        )?;
        assemble(&frames, true)
    }
    #[test]
    fn complete_fragmented_arguments_are_assembled_once() {
        let result = decode(&stream(&["{\"a\":", "1}"])).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].args, json!({"a":1}));
    }
    #[test]
    fn invalid_tail_identity_or_arguments_prevent_all_evaluation() {
        let complete = stream(&["{}"]);
        let mut trailing = complete.clone();
        trailing.extend_from_slice(b"data: {}\n\n");
        let changed = String::from_utf8(stream(&["{", "}"]))
            .unwrap()
            .replacen("\"id\":\"call\"", "\"id\":\"different\"", 1)
            .into_bytes();
        let missing = complete[..complete.len() - b"data: [DONE]\n\n".len()].to_vec();
        for invalid in [
            stream(&["{\"x\":1,", "\"x\":2}"]),
            stream(&["{"]),
            trailing,
            changed,
            missing,
        ] {
            let mut evaluated = 0;
            let result = crate::gate_openai_sse_tool_calls(
                &invalid,
                "test",
                Some("[DONE]"),
                |_| panic!("invalid stream reached invocation projection"),
                |_| {
                    evaluated += 1;
                    panic!("invalid stream reached evaluator")
                },
            );
            assert!(result.is_err());
            assert_eq!(evaluated, 0);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod completion_tests {
    #[test]
    fn upstream_error_and_transport_sentinel_cannot_complete_a_choice() {
        let call = "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call\",\"function\":{\"name\":\"tool\",\"arguments\":\"{}\"}}]}}]}\n\n";
        for tail in [
            "data: [DONE]\n\n",
            "data: {\"error\":{\"message\":\"private-provider-payload\"}}\n\ndata: [DONE]\n\n",
        ] {
            let mut evaluated = 0;
            let error = crate::gate_openai_sse_tool_calls(
                format!("{call}{tail}").as_bytes(),
                "test",
                Some("[DONE]"),
                |_| panic!("incomplete stream reached projection"),
                |_| {
                    evaluated += 1;
                    panic!("incomplete stream reached evaluator")
                },
            )
            .unwrap_err();
            assert_eq!(evaluated, 0);
            assert!(!format!("{error} {error:?}").contains("private-provider-payload"));
        }
    }
}
