//! Bounded native pheromone evidence; signature, schema and admission checks remain with owners.
use chio_core_types::canonical::{UntrustedJsonError, UntrustedJsonText};
use serde::de::DeserializeOwned;

pub(crate) const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, UntrustedJsonError> {
    UntrustedJsonText::from_wire(bytes, MAX_DOCUMENT_BYTES)?.decode_signed()
}

/// Borrow the SQLite cell before allocating or decoding a document. The inner
/// error leaves the query without being stringified by rusqlite conversion.
pub(crate) fn row_decode<T: DeserializeOwned>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Result<T, UntrustedJsonError>> {
    let raw = row.get_ref(index)?;
    let text = raw.as_str().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(index, raw.data_type(), Box::new(error))
    })?;
    Ok(decode(text.as_bytes()))
}

pub(crate) fn row_text(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Result<String, UntrustedJsonError>> {
    let raw = row.get_ref(index)?;
    let text = raw.as_str().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(index, raw.data_type(), Box::new(error))
    })?;
    Ok(UntrustedJsonText::from_wire(text.as_bytes(), MAX_DOCUMENT_BYTES).map(|_| text.to_owned()))
}

pub(crate) fn encode<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<String, UntrustedJsonError> {
    let text = serde_json::to_string(value).map_err(UntrustedJsonError::Decode)?;
    UntrustedJsonText::from_wire(text.as_bytes(), MAX_DOCUMENT_BYTES)?;
    Ok(text)
}
