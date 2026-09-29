use super::canonical_json_bytes;
use super::sha256;
use super::CanonicalBody;
use super::Digest32;
use super::PortError;
use super::PortResult;
use super::RecordId;
use super::InformationLabel;
use super::params;
use super::Connection;
use super::OptionalExtension;
# [cfg (target_os = "macos")]
use super::security_state_lifecycle_lock_path;


pub(super) fn sqlite_error(error: rusqlite::Error) -> PortError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            PortError::conflict()
        }
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..) => PortError::integrity_failure(),
        rusqlite::Error::ToSqlConversionFailure(_) => PortError::invalid_data(),
        _ => PortError::unavailable(),
    }
}

pub(super) fn schema_version_error(error: crate::SchemaVersionError) -> PortError {
    match error {
        crate::SchemaVersionError::Sqlite(error) => sqlite_error(error),
        crate::SchemaVersionError::ForeignDatabase { .. }
        | crate::SchemaVersionError::MismatchedStore { .. }
        | crate::SchemaVersionError::FutureSchema { .. } => PortError::integrity_failure(),
    }
}

pub(super) fn to_i64(value: u64) -> PortResult<i64> {
    i64::try_from(value).map_err(|_| PortError::invalid_data())
}

pub(super) fn from_i64(value: i64) -> PortResult<u64> {
    u64::try_from(value).map_err(|_| PortError::integrity_failure())
}

pub(super) fn body_hash(body: &[u8]) -> [u8; 32] {
    let hash = sha256(body);
    let mut result = [0_u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
}

fn validate_body(body: &CanonicalBody, expected: &Digest32) -> PortResult<()> {
    if body_hash(body.as_bytes()).as_slice() != expected.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub(super) fn validate_canonical_json_body(body: &CanonicalBody, expected: &Digest32) -> PortResult<()> {
    validate_body(body, expected)?;
    let value: serde_json::Value =
        chio_core::canonical::UntrustedJsonText::from_wire(body.as_bytes(), 64 * 1024 * 1024)
            .and_then(|input| input.decode_signed())
            .map_err(|_| PortError::invalid_data())?;
    let canonical = canonical_json_bytes(&value).map_err(|_| PortError::invalid_data())?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

pub(super) fn decode_digest(bytes: Vec<u8>) -> PortResult<Digest32> {
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PortError::integrity_failure())?;
    Ok(Digest32::new(value))
}

pub(super) fn canonical_request_hash<T: serde::Serialize>(value: &T) -> PortResult<[u8; 32]> {
    let canonical = canonical_json_bytes(value).map_err(|_| PortError::invalid_data())?;
    Ok(body_hash(canonical.as_ref()))
}

pub(super) fn validate_encrypted_blob_reference(
    connection: &Connection,
    tenant_id: &str,
    reference: &RecordId,
) -> PortResult<()> {
    let lengths: Option<(i64, i64)> = connection
        .query_row(
            r#"
            SELECT length(nonce), length(ciphertext) FROM chio_encrypted_blobs
            WHERE blob_id = ?1 AND tenant_id = ?2
            "#,
            params![reference.as_str(), tenant_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((nonce_length, ciphertext_length)) = lengths else {
        return Err(PortError::invalid_data());
    };
    if nonce_length != 12 || ciphertext_length < 16 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub(super) fn encode_label(label: &InformationLabel) -> PortResult<(Vec<u8>, [u8; 32])> {
    let body = canonical_json_bytes(label).map_err(|_| PortError::invalid_data())?;
    let hash = body_hash(body.as_ref());
    Ok((body, hash))
}

pub(super) fn decode_label(body: Vec<u8>, stored_hash: Vec<u8>) -> PortResult<InformationLabel> {
    let hash = decode_digest(stored_hash)?;
    if body_hash(&body).as_slice() != hash.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    let label: InformationLabel =
        chio_core::canonical::UntrustedJsonText::from_wire(&body, 64 * 1024 * 1024)
            .and_then(|input| input.decode_signed())
            .map_err(|_| PortError::integrity_failure())?;
    let canonical = canonical_json_bytes(&label).map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != body.as_slice() {
        return Err(PortError::integrity_failure());
    }
    Ok(label)
}



pub(super) fn normalize_sql(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    let mut quote_terminator = None;
    let mut pending_space = false;
    while let Some(character) = characters.next() {
        if let Some(terminator) = quote_terminator {
            normalized.push(character);
            if character == terminator {
                if characters.peek() == Some(&terminator) {
                    if let Some(escaped_terminator) = characters.next() {
                        normalized.push(escaped_terminator);
                    }
                } else {
                    quote_terminator = None;
                }
            }
            continue;
        }
        if character.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !normalized.is_empty() {
            normalized.push(' ');
        }
        pending_space = false;
        normalized.push(character);
        quote_terminator = match character {
            '\'' | '"' | '`' => Some(character),
            '[' => Some(']'),
            _ => None,
        };
    }
    normalized
}

pub(super) fn table_definition_is_exact(
    connection: &Connection,
    table: &str,
    expected_sql: &str,
) -> PortResult<bool> {
    let actual = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    Ok(actual.is_some_and(|sql| normalize_sql(&sql) == normalize_sql(expected_sql)))
}

pub(super) fn schema_object_definition_is_exact(
    connection: &Connection,
    object_type: &str,
    name: &str,
    expected_sql: &str,
) -> PortResult<bool> {
    let actual = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    Ok(actual.is_some_and(|sql| normalize_sql(&sql) == normalize_sql(expected_sql)))
}
