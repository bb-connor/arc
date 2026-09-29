//! Bounded peer input. The shared parser preserves original-token semantics.
use crate::CliError;
use serde::de::DeserializeOwned;

pub(crate) fn read<T: DeserializeOwned>(
    reader: impl std::io::Read,
    cap: usize,
) -> Result<T, CliError> {
    use std::io::Read as _;
    let limit = u64::try_from(cap)
        .ok()
        .and_then(|cap| cap.checked_add(1))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "JSON input bound exceeds reader range",
            )
        })?;
    let mut buffer = Vec::new();
    reader.take(limit).read_to_end(&mut buffer)?;
    Ok(chio_core::canonical::UntrustedJsonText::from_wire(&buffer, cap)?.decode_signed()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_peer_reader_stops_at_limit_and_retains_parser_cause(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::error::Error as _;
        let mut bytes = std::io::Cursor::new(vec![b' '; 100]);
        let error = read::<serde_json::Value>(&mut bytes, 16)
            .err()
            .ok_or("accepted oversized body")?;
        assert_eq!(bytes.position(), 17);
        assert_eq!(
            error.report().code,
            "urn:chio:error:attest:signed-json-too-large"
        );
        let error = read::<serde_json::Value>(br#"{"secret":1,"secret":2}"#.as_slice(), 64)
            .err()
            .ok_or("accepted duplicate")?;
        assert_eq!(
            error.report().code,
            "urn:chio:error:attest:signed-json-invalid-input"
        );
        assert!(error.source().is_some());
        assert!(!format!("{error:?}").contains("secret"));
        assert_eq!(
            read::<serde_json::Value>(br#"{"valid":true}"#.as_slice(), 64)?["valid"],
            true
        );
        Ok(())
    }
}
