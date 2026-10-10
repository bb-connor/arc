//! Original request validation before a handler can access state.

use chio_core_types::canonical::{SharedUntrustedJsonError, UntrustedJsonText};
use serde::de::DeserializeOwned;

pub(crate) const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_CAPABILITY_BYTES: usize = 64 * 1024;

pub(crate) fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    bound: usize,
) -> Result<T, SharedUntrustedJsonError> {
    UntrustedJsonText::from_wire(bytes, bound)
        .and_then(|input| input.decode_signed())
        .map_err(Into::into)
}
