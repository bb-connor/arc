//! Native proof packages and their trust documents retain exact signed integers.
//! Parsing grants no authority; the package verifier owns signature and trust checks.
use chio_core_types::canonical::{UntrustedJsonError, UntrustedJsonText};
use serde::de::DeserializeOwned;

pub(crate) const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, UntrustedJsonError> {
    UntrustedJsonText::from_wire(bytes, MAX_DOCUMENT_BYTES)?.decode_signed()
}
