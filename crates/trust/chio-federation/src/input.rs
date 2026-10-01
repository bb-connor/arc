//! Bounded native federation documents. Decoding does not admit a treaty.
use chio_core_types::canonical::{UntrustedJsonError, UntrustedJsonText};
use serde::de::DeserializeOwned;

pub(crate) const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, UntrustedJsonError> {
    UntrustedJsonText::from_wire(bytes, MAX_DOCUMENT_BYTES)?.decode_signed()
}
