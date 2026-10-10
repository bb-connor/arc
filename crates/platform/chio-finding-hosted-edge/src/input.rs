//! Strict external canonical JSON. Signed identity is always the original bytes.

use chio_core_types::canonical::{SharedUntrustedJsonError, UntrustedJsonError, UntrustedJsonText};
use serde::de::DeserializeOwned;

pub(crate) fn canonical(bytes: &[u8], bound: usize) -> Result<Vec<u8>, SharedUntrustedJsonError> {
    let canonical = UntrustedJsonText::from_wire(bytes, bound)?.canonicalize()?;
    if canonical != bytes {
        return Err(UntrustedJsonError::NonCanonical.into());
    }
    Ok(canonical)
}

pub(crate) fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    bound: usize,
) -> Result<T, SharedUntrustedJsonError> {
    canonical(bytes, bound)?;
    UntrustedJsonText::from_wire(bytes, bound)?
        .decode_signed()
        .map_err(Into::into)
}
