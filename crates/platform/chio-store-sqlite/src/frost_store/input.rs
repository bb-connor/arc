//! Exact canonical JSON is the persistent FROST record contract.
use super::FrostStoreError;
use chio_core::canonical::UntrustedJsonText;
use serde::{de::DeserializeOwned, Serialize};

pub(super) fn decode_record<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, FrostStoreError> {
    UntrustedJsonText::from_wire(bytes, 32 * 1024 * 1024)?
        .decode_canonical()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[test]
    fn stored_records_reject_duplicate_fields_and_noncanonical_bytes() {
        for wire in [
            br#"{"epoch":1,"epoch":2}"#.as_slice(),
            br#"{ "epoch":1}"#.as_slice(),
        ] {
            assert!(matches!(
                decode_record::<BTreeMap<String, u64>>(wire),
                Err(FrostStoreError::SignedInput(
                    chio_core::canonical::UntrustedJsonError::NonCanonical
                ))
            ));
        }
        let full_width =
            decode_record::<BTreeMap<String, u64>>(br#"{"epoch":18446744073709551615}"#);
        assert_eq!(
            full_width.unwrap_or_else(|e| panic!("native integer: {e}"))["epoch"],
            u64::MAX
        );
    }
}
