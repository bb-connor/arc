//! One strict decoder for retained decisions and their receipt-key integrity.
use super::*;

#[derive(Debug, thiserror::Error)]
pub(super) enum RecordLoadError {
    #[error("unknown approval")]
    Unknown,
    #[error("approval record integrity check failed")]
    Integrity,
    #[error(transparent)]
    Storage(#[from] rusqlite::Error),
    #[error(transparent)]
    Input(#[from] chio_core::canonical::UntrustedJsonError),
    #[error(transparent)]
    Signature(#[from] chio_core::error::Error),
}

impl RecordLoadError {
    pub(super) fn response(self) -> Response {
        match self {
            Self::Unknown => failure(StatusCode::NOT_FOUND, self),
            Self::Integrity => failure(StatusCode::CONFLICT, self),
            Self::Input(error) => input::with_source(internal(error.code()), error),
            other => internal(other),
        }
    }
}

pub(super) fn load_record(
    connection: &Connection,
    id: &str,
    record_key: &PublicKey,
) -> Result<ApprovalRecord, RecordLoadError> {
    let serialized: String = connection
        .query_row(
            "SELECT signed_record FROM remote_operator_approvals WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(RecordLoadError::Unknown)?;
    let signed: SignedRecord = decode_json(serialized.as_bytes(), MAX_SESSION_JSON_BYTES)?;
    if signed.record.id != id
        || !record_key.verify_canonical_strict(&signed.record, &signed.signature)?
    {
        return Err(RecordLoadError::Integrity);
    }
    Ok(signed.record)
}
