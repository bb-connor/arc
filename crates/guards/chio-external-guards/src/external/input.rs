//! Preserve original request and response JSON until the owner's contract is checked.
use super::ExternalGuardError;
use chio_core_types::canonical::UntrustedJsonText;
use serde::de::DeserializeOwned;

const MAX_JSON_BYTES: usize = 1024 * 1024;

pub(super) fn arguments<T: DeserializeOwned>(text: &str) -> Result<T, ExternalGuardError> {
    UntrustedJsonText::from_wire(text.as_bytes(), MAX_JSON_BYTES)
        .and_then(|input| input.decode_signed())
        .map_err(ExternalGuardError::InvalidInput)
}

pub(super) fn response<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ExternalGuardError> {
    UntrustedJsonText::from_wire(bytes, MAX_JSON_BYTES)
        .and_then(|input| input.decode_external())
        .map_err(ExternalGuardError::InvalidResponse)
}
