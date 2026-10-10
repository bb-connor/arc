//! Bounded original documents. Decoding does not authenticate a proof.
use chio_core::canonical::{UntrustedJsonError, UntrustedJsonText};
use serde::de::DeserializeOwned;
use std::{io::Read, path::Path};

#[path = "input/collection.rs"]
pub(crate) mod collection;
#[path = "input/config.rs"]
pub(crate) mod config;
#[path = "input/private.rs"]
pub(crate) mod private;
#[path = "input/snapshot.rs"]
pub(crate) mod snapshot;
#[path = "input/time.rs"]
pub(crate) mod time;

pub(crate) const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    bound: usize,
) -> Result<T, UntrustedJsonError> {
    UntrustedJsonText::from_wire(bytes, bound)?.decode_signed()
}

pub(crate) fn text<T: DeserializeOwned>(text: &str) -> Result<T, crate::CliError> {
    Ok(decode(text.as_bytes(), MAX_DOCUMENT_BYTES)?)
}

pub(crate) fn project<T: DeserializeOwned>(value: serde_json::Value) -> Result<T, crate::CliError> {
    serde_json::from_value(value).map_err(|error| UntrustedJsonError::Decode(error).into())
}

/// Exact canonical I-JSON, including preservation by the complete typed schema.
pub(crate) fn canonical_ijson<T: DeserializeOwned + serde::Serialize>(
    bytes: &[u8],
) -> Result<T, crate::CliError> {
    let input = UntrustedJsonText::from_wire(bytes, MAX_DOCUMENT_BYTES)?;
    input.canonicalize()?;
    Ok(input.decode_canonical()?)
}

pub(crate) fn json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, UntrustedJsonError> {
    decode(bytes, MAX_DOCUMENT_BYTES)
}

pub(crate) fn read(path: impl AsRef<Path>) -> Result<Vec<u8>, std::io::Error> {
    read_regular(path.as_ref(), MAX_DOCUMENT_BYTES)
}

pub(crate) fn read_text(path: impl AsRef<Path>) -> Result<String, crate::CliError> {
    String::from_utf8(read(path)?).map_err(|source| {
        crate::CliError::with_source(&chio_errors::_generated::error_codes::CLI_JSON, source)
    })
}

pub(crate) fn literal<T: DeserializeOwned>(value: &str) -> Result<T, serde_json::Error> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
}

pub(crate) fn read_stream(reader: impl Read, bound: usize) -> Result<Vec<u8>, std::io::Error> {
    let limit = u64::try_from(bound)
        .ok()
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| std::io::Error::other("invalid input byte limit"))?;
    let mut bytes = Vec::new();
    reader.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err(std::io::Error::other(UntrustedJsonError::TooLarge {
            bytes: bytes.len(),
            bound,
        }));
    }
    Ok(bytes)
}

pub(crate) fn read_regular(path: &Path, bound: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("input must be a regular file"));
    }
    read_stream(file, bound)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn original_document_numbers_and_private_causes_are_preserved() {
        let value: serde_json::Value =
            text(r#"{"native":18446744073709551615,"float":1.0}"#).unwrap();
        assert_eq!(value["native"].as_u64(), Some(u64::MAX));
        assert_eq!(value["float"].as_f64(), Some(1.0));
        for bytes in [
            br#"{"secret-marker":1,"secret-marker":2}"#.as_slice(),
            br#"{"number":0.123456789012345678901}"#,
        ] {
            let error = decode::<serde_json::Value>(bytes, 100).unwrap_err();
            assert!(matches!(error, UntrustedJsonError::SignedInput(_)));
            assert!(error.source().is_some());
            assert!(!format!("{error} {error:?}").contains("secret-marker"));
        }
        assert!(matches!(
            decode::<serde_json::Value>(b"{}", 1),
            Err(UntrustedJsonError::TooLarge { bytes: 2, bound: 1 })
        ));
    }

    #[test]
    fn regular_file_limit_applies_before_decoding() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.json");
        std::fs::write(&path, b"{} ").unwrap();
        let error = read_regular(&path, 2).unwrap_err();
        assert!(matches!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<UntrustedJsonError>(),
            Some(UntrustedJsonError::TooLarge { bytes: 3, bound: 2 })
        ));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "input/tests.rs"]
mod boundary_tests;
