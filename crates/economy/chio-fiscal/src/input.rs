//! Bounded original bytes for native canonical evidence.
use chio_core_types::canonical::{SharedUntrustedJsonError, UntrustedJsonText};
use serde::{de::DeserializeOwned, Serialize};

pub(crate) fn canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    bound: usize,
) -> Result<T, SharedUntrustedJsonError> {
    UntrustedJsonText::from_wire(bytes, bound)
        .and_then(|input| input.decode_canonical())
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_canonical_contract_retains_full_width_integers(
    ) -> Result<(), SharedUntrustedJsonError> {
        let bytes = br#"{"counter":18446744073709551615}"#;
        let value: serde_json::Value = canonical(bytes, 128)?;
        assert_eq!(value["counter"].as_u64(), Some(u64::MAX));
        Ok(())
    }
}
