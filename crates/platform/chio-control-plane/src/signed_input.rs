//! Bounded original-byte readers for operator files carrying authenticated data.

use std::io::Read;
use std::path::Path;

use chio_core::canonical::UntrustedJsonText;
use serde::de::DeserializeOwned;

use crate::CliError;

pub(crate) const MAX_SIGNED_FILE_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn read_bounded(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(crate::integer::count(MAX_SIGNED_FILE_BYTES + 1))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CliError> {
    Ok(UntrustedJsonText::from_wire(bytes, MAX_SIGNED_FILE_BYTES)?.decode_signed()?)
}

pub(crate) fn read<T: DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    decode(&read_bounded(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_input_keeps_full_width_integers_and_rejects_nested_aliases() {
        let value: serde_json::Value =
            decode(br#"{"amount":18446744073709551615,"nested":{"limit":1}}"#)
                .unwrap_or_else(|error| panic!("valid signed input: {error}"));
        assert_eq!(value["amount"].as_u64(), Some(u64::MAX));
        for bytes in [
            br#"{"nested":{"limit":0,"limit":1}}"#.as_slice(),
            br#"{"nested":{"limit":1.0000000000000001}}"#.as_slice(),
        ] {
            assert!(matches!(
                decode::<serde_json::Value>(bytes),
                Err(CliError::SignedJson(
                    chio_core::canonical::UntrustedJsonError::SignedInput(_)
                ))
            ));
        }
    }
}
