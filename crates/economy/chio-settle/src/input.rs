//! Bounded original-byte contracts for settlement ingress.
use chio_core::canonical::{SharedUntrustedJsonError, UntrustedJsonError, UntrustedJsonText};
use serde::{de::DeserializeOwned, Serialize};

pub(crate) fn canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    bound: usize,
) -> Result<T, SharedUntrustedJsonError> {
    UntrustedJsonText::from_wire(bytes, bound)
        .and_then(|input| input.decode_canonical())
        .map_err(Into::into)
}

pub(crate) fn external_canonical<T: DeserializeOwned>(
    bytes: &[u8],
    bound: usize,
) -> Result<T, SharedUntrustedJsonError> {
    let input = UntrustedJsonText::from_wire(bytes, bound)?;
    if input.canonicalize()?.as_slice() != bytes {
        return Err(UntrustedJsonError::NonCanonical.into());
    }
    input.decode_signed().map_err(Into::into)
}
