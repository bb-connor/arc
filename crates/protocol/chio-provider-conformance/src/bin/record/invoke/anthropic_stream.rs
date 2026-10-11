//! Reconstruct fixture arguments only after the complete recorded message validates.
use crate::RecordError;
use chio_provider_adapter_core::input;
use chio_tool_call_fabric::ProviderError;
use serde_json::Value;

fn malformed(message: &'static str) -> RecordError {
    ProviderError::Malformed(message.into()).into()
}

pub(super) fn tool_blocks<'a>(
    payloads: impl IntoIterator<Item = &'a Value>,
) -> Result<Vec<Value>, RecordError> {
    let mut started = false;
    let mut closed = false;
    let mut active: Option<(u64, Value, String)> = None;
    let mut blocks = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for payload in payloads {
        let event = payload
            .get("event")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("recorded stream event is missing its name"))?;
        let data = payload
            .get("data")
            .filter(|data| data.is_object())
            .ok_or_else(|| malformed("recorded stream event data must be an object"))?;
        if event == "ping" {
            continue;
        }
        if closed {
            return Err(malformed("recorded stream continued after message_stop"));
        }
        if event == "message_start" {
            if started {
                return Err(malformed("recorded stream repeated message_start"));
            }
            started = true;
            continue;
        }
        if !started {
            return Err(malformed("recorded stream omitted message_start"));
        }
        if event == "error" {
            return Err(malformed("recorded provider stream failed"));
        }
        if event == "message_stop" {
            if active.is_some() {
                return Err(malformed("recorded message ended inside a content block"));
            }
            closed = true;
            continue;
        }
        if !event.starts_with("content_block_") {
            continue;
        }
        let index = data
            .get("index")
            .and_then(Value::as_u64)
            .ok_or_else(|| malformed("recorded content block is missing its index"))?;
        match event {
            "content_block_start" => {
                if active.is_some() {
                    return Err(malformed("recorded content blocks overlap"));
                }
                let block = data
                    .get("content_block")
                    .filter(|block| block.is_object())
                    .ok_or_else(|| malformed("recorded content block must be an object"))?;
                active = Some((index, block.clone(), String::new()));
            }
            "content_block_delta" => {
                let (current, block, arguments) = active
                    .as_mut()
                    .ok_or_else(|| malformed("recorded delta has no content block"))?;
                if *current != index {
                    return Err(malformed("recorded delta changed content block index"));
                }
                if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                    let delta = data
                        .get("delta")
                        .ok_or_else(|| malformed("recorded tool delta is missing"))?;
                    if delta.get("type").and_then(Value::as_str) != Some("input_json_delta") {
                        return Err(malformed("recorded tool delta has the wrong type"));
                    }
                    let part = delta
                        .get("partial_json")
                        .and_then(Value::as_str)
                        .ok_or_else(|| malformed("recorded argument delta must be text"))?;
                    input::append_arguments(arguments, part)?;
                }
            }
            "content_block_stop" => {
                let (current, mut block, arguments) = active
                    .take()
                    .ok_or_else(|| malformed("recorded stop has no content block"))?;
                if current != index {
                    return Err(malformed("recorded stop changed content block index"));
                }
                if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                    let original = block
                        .get("input")
                        .filter(|input| input.is_object())
                        .ok_or_else(|| malformed("recorded tool input must be an object"))?;
                    if !arguments.is_empty() {
                        if original
                            .as_object()
                            .is_some_and(|object| !object.is_empty())
                        {
                            return Err(malformed(
                                "recorded tool mixed initial and streamed arguments",
                            ));
                        }
                        block["input"] = input::arguments(&arguments)?;
                    }
                    let id = block
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| malformed("recorded tool call is missing its id"))?;
                    if !ids.insert(id.to_owned()) {
                        return Err(malformed("recorded stream reuses a tool call id"));
                    }
                    if blocks.len() >= input::MAX_TOOL_CALLS {
                        return Err(ProviderError::StreamCapacityExceeded.into());
                    }
                    blocks.push(block);
                }
            }
            _ => return Err(malformed("unknown recorded content block event")),
        }
    }
    if !started || !closed {
        return Err(malformed("recorded stream did not complete its message"));
    }
    Ok(blocks)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;
    fn events(parts: &[&str]) -> Vec<Value> {
        let mut events = vec![
            json!({"event":"message_start", "data":{}}),
            json!({"event":"content_block_start", "data":{"index":0,"content_block":{"type":"tool_use","id":"call","name":"tool","input":{}}}}),
        ];
        for part in parts {
            events.push(json!({"event":"content_block_delta", "data":{"index":0,"delta":{"type":"input_json_delta","partial_json":part}}}));
        }
        events.extend([
            json!({"event":"content_block_stop", "data":{"index":0}}),
            json!({"event":"message_stop", "data":{}}),
        ]);
        events
    }
    #[test]
    fn capture_reconstructs_arguments_and_rejects_ambiguous_or_incomplete_message() {
        let valid = events(&["{\"location\":", "\"Boston\"}"]);
        assert_eq!(
            tool_blocks(&valid).unwrap()[0]["input"],
            json!({"location":"Boston"})
        );
        assert!(tool_blocks(&events(&["{\"a\":1,", "\"a\":2}"])).is_err());
        assert!(tool_blocks(&valid[..valid.len() - 1]).is_err());
    }
}
