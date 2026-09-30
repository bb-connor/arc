//! Bounded original provider JSON, before projection or tool-call construction.
use chio_core::canonical::{UntrustedJsonError, UntrustedJsonText};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ARGUMENT_BYTES: usize = 1024 * 1024;
pub const MAX_RECORDS: usize = 16_384;
pub const MAX_TOOL_CALLS: usize = 1024;

pub fn json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, UntrustedJsonError> {
    json_bounded(bytes, MAX_DOCUMENT_BYTES)
}
pub fn text<T: DeserializeOwned>(text: &str) -> Result<T, UntrustedJsonError> {
    json(text.as_bytes())
}
pub fn json_bounded<T: DeserializeOwned>(
    bytes: &[u8],
    bound: usize,
) -> Result<T, UntrustedJsonError> {
    let canonical = UntrustedJsonText::from_wire(bytes, bound)?.canonicalize()?;
    serde_json::from_slice(&canonical).map_err(UntrustedJsonError::Decode)
}
/// Projection is allowed only after the original document has passed ingress.
pub fn typed<T: DeserializeOwned>(value: Value) -> Result<T, UntrustedJsonError> {
    serde_json::from_value(value).map_err(UntrustedJsonError::Decode)
}
pub fn arguments(text: &str) -> Result<Value, chio_tool_call_fabric::ProviderError> {
    let value = json_bounded(text.as_bytes(), MAX_ARGUMENT_BYTES)?;
    argument_object(value)
}
pub fn argument_object(value: Value) -> Result<Value, chio_tool_call_fabric::ProviderError> {
    if !value.is_object() {
        return Err(chio_tool_call_fabric::ProviderError::BadToolArgs(
            "tool arguments must be an object".into(),
        ));
    }
    let bytes =
        chio_core::canonical_json_bytes(&value).map_err(UntrustedJsonError::Canonicalization)?;
    UntrustedJsonText::from_wire(&bytes, MAX_ARGUMENT_BYTES)?.canonicalize()?;
    Ok(value)
}
pub fn append_arguments(
    buffer: &mut String,
    delta: &str,
) -> Result<(), chio_tool_call_fabric::ProviderError> {
    if delta.len() > MAX_ARGUMENT_BYTES.saturating_sub(buffer.len()) {
        return Err(UntrustedJsonError::TooLarge {
            bytes: buffer.len().saturating_add(delta.len()),
            bound: MAX_ARGUMENT_BYTES,
        }
        .into());
    }
    buffer.push_str(delta);
    Ok(())
}

/// Validate every normalized invocation before it reaches an evaluator.
pub fn invocation(
    value: chio_tool_call_fabric::ToolInvocation,
) -> Result<chio_tool_call_fabric::ToolInvocation, chio_tool_call_fabric::ProviderError> {
    value.validate()?;
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn original_json_and_nested_arguments_reject_ambiguity() {
        for document in [
            r#"{"tool":"one","tool":"two"}"#,
            r#"{"x":1e9999}"#,
            r#"{"x":9007199254740993}"#,
        ] {
            let error = text::<Value>(document).unwrap_err();
            assert!(error.source().is_some());
            assert!(!format!("{error:?} {error}").contains(document));
        }
        for arguments in [r#"{"x":1,"x":2}"#, "[]", "null", "", r#"{"x":1} trailing"#] {
            assert!(super::arguments(arguments).is_err());
        }
        assert_eq!(
            super::arguments(r#"{ "z": 1, "a": [true] }"#).unwrap(),
            serde_json::json!({"a":[true],"z":1})
        );
    }

    #[test]
    fn limits_apply_before_argument_append_or_decode() {
        let mut text = " ".repeat(MAX_ARGUMENT_BYTES - 1);
        append_arguments(&mut text, " ").unwrap();
        let snapshot = text.len();
        assert!(append_arguments(&mut text, "x").is_err());
        assert_eq!(text.len(), snapshot);
        assert!(json_bounded::<Value>(b"{}", 1).is_err());
    }
}
