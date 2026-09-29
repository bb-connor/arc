//! Bounded provider bytes and original argument text. These values carry no authority.
use chio_core::canonical::{UntrustedJsonError, UntrustedJsonText};
use serde_json::Value;

#[cfg(feature = "provider-adapter")]
pub(crate) const MAX_PROVIDER_JSON_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_TOOL_ARGUMENT_BYTES: usize = 1024 * 1024;

#[cfg(feature = "provider-adapter")]
pub(crate) fn read_json(bytes: &[u8]) -> Result<Value, UntrustedJsonError> {
    UntrustedJsonText::from_wire(bytes, MAX_PROVIDER_JSON_BYTES)?.decode_signed()
}

pub(crate) fn arguments(text: &str) -> Result<Value, UntrustedJsonError> {
    let canonical =
        UntrustedJsonText::from_wire(text.as_bytes(), MAX_TOOL_ARGUMENT_BYTES)?.canonicalize()?;
    // Deserialize an object after canonicalization, preserving the shape cause.
    let object: serde_json::Map<String, Value> =
        serde_json::from_slice(&canonical).map_err(UntrustedJsonError::Decode)?;
    Ok(Value::Object(object))
}
