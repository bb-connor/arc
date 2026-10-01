use chio_core_types::canonical::{UntrustedJsonError, UntrustedJsonText};
use chio_core_types::sha256_hex;
use serde::{de::DeserializeOwned, Serialize};

use crate::HostedMarketStoreError;

const MAX_JOB_JSON_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn validate_identifier(value: &str, maximum: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(());
    }
    Ok(())
}

pub(crate) fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), HostedMarketStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(HostedMarketStoreError::Invalid(field))
}

/// Verify original canonical bytes before any typed projection.
fn canonical_input(bytes: &[u8]) -> Result<UntrustedJsonText<'_>, UntrustedJsonError> {
    let input = UntrustedJsonText::from_wire(bytes, MAX_JOB_JSON_BYTES)?;
    if input.canonicalize()? != bytes {
        return Err(UntrustedJsonError::NonCanonical);
    }
    Ok(input)
}

pub(crate) fn validate_canonical_json(
    bytes: &[u8],
    _field: &'static str,
) -> Result<(), HostedMarketStoreError> {
    canonical_input(bytes)
        .map(|_| ())
        .map_err(|error| HostedMarketStoreError::InvalidInput(error.into()))
}

pub(crate) fn decode_durable<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, HostedMarketStoreError> {
    canonical_input(bytes)
        .and_then(|input| input.decode_signed())
        .map_err(|error| HostedMarketStoreError::CorruptInput(error.into()))
}

/// Checkpoint and principal writers serialize native typed integers. Requiring
/// the external I-JSON range here would reject their own valid signed records.
pub(crate) fn decode_native_durable<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, HostedMarketStoreError> {
    UntrustedJsonText::from_wire(bytes, MAX_JOB_JSON_BYTES)
        .and_then(|input| input.decode_canonical())
        .map_err(|error| HostedMarketStoreError::CorruptInput(error.into()))
}

pub(crate) fn decode_artifact<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, HostedMarketStoreError> {
    canonical_input(bytes)
        .and_then(|input| input.decode_canonical())
        .map_err(|error| HostedMarketStoreError::InvalidInput(error.into()))
}

pub(crate) fn verify_payload(digest: &str, bytes: &[u8]) -> Result<(), HostedMarketStoreError> {
    validate_digest(digest, "durable digest")?;
    canonical_input(bytes).map_err(|error| HostedMarketStoreError::CorruptInput(error.into()))?;
    if sha256_hex(bytes) != digest {
        return Err(HostedMarketStoreError::DigestMismatch);
    }
    Ok(())
}

pub(crate) fn checked_i64(value: u64, field: &'static str) -> Result<i64, HostedMarketStoreError> {
    if value == 0 {
        return Err(HostedMarketStoreError::Invalid(field));
    }
    i64::try_from(value).map_err(|_| HostedMarketStoreError::Invalid(field))
}

pub(crate) fn checked_nonnegative_i64(
    value: u64,
    field: &'static str,
) -> Result<i64, HostedMarketStoreError> {
    i64::try_from(value).map_err(|_| HostedMarketStoreError::Invalid(field))
}

pub(crate) fn stored_u64(value: i64) -> Result<u64, HostedMarketStoreError> {
    u64::try_from(value).map_err(|_| HostedMarketStoreError::DigestMismatch)
}

/// Map a sqlx failure to the opaque wire error after logging its class.
/// The wire variant stays `Unavailable` so caller and replay semantics are
/// unchanged; the log carries what actually failed so operators can tell
/// pool exhaustion from a constraint rejection or a network fault.
pub(crate) fn unavailable(error: sqlx::Error) -> HostedMarketStoreError {
    let class = match &error {
        sqlx::Error::PoolTimedOut => "pool_timeout",
        sqlx::Error::PoolClosed => "pool_closed",
        sqlx::Error::Io(_) => "io",
        sqlx::Error::Tls(_) => "tls",
        sqlx::Error::Database(_) => "database",
        sqlx::Error::RowNotFound => "row_not_found",
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => "decode",
        _ => "other",
    };
    tracing::warn!(class, error = %error, "hosted market store operation failed");
    HostedMarketStoreError::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn durable_original_bytes_reject_ambiguity_and_noncanonical_identity() {
        let valid = br#"{"count":7}"#;
        assert_eq!(
            decode_durable::<serde_json::Value>(valid).test_expect("valid durable JSON"),
            serde_json::json!({"count": 7})
        );
        for bytes in [
            br#"{"private-marker":1,"private-marker":2}"#.as_slice(),
            b" {\"count\":7}",
            b"{\"count\":7.0}",
        ] {
            let error = decode_durable::<serde_json::Value>(bytes)
                .test_expect_err("original identity must reject");
            assert!(matches!(&error, HostedMarketStoreError::CorruptInput(_)));
            assert!(std::error::Error::source(&error).is_some());
            assert!(!format!("{error:?} {error}").contains("private-marker"));
        }
        let oversized = vec![b' '; MAX_JOB_JSON_BYTES + 1];
        let error =
            decode_durable::<serde_json::Value>(&oversized).test_expect_err("readback is bounded");
        assert!(
            matches!(error, HostedMarketStoreError::CorruptInput(source) if source.code() == "urn:chio:error:attest:signed-json-too-large")
        );
    }
}
