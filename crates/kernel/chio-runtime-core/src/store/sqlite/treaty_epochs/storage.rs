use super::*;
use serde::de::DeserializeOwned;

pub(super) const MAX_PINS: usize = crate::treaty_epoch::MAX_TREATY_EPOCH_AUTHORITIES;
pub(super) const MAX_RECORDS: usize = crate::treaty_epoch::MAX_TREATY_EPOCH_RECORDS;
pub(super) const MAX_AUTHORIZATIONS: usize = crate::treaty_epoch::MAX_TREATY_EPOCH_AUTHORIZATIONS;

pub(super) fn check_count(
    tx: &Connection,
    table: &str,
    limit: usize,
    inserting: bool,
) -> Result<(), ChioRuntimeError> {
    let count: i64 = tx
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .map_err(sqlite_error)?;
    let count = usize::try_from(count).map_err(|_| {
        refusal(
            "treaty_epoch_capacity",
            "negative treaty authority row count",
        )
    })?;
    if count > limit || (inserting && count == limit) {
        return Err(refusal(
            "treaty_epoch_capacity",
            "treaty authority table exceeds its bound",
        ));
    }
    Ok(())
}

pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ChioRuntimeError> {
    let bytes = chio_core_types::crypto::canonical_json_bytes(value)
        .map_err(|error| ChioRuntimeError::Canonical(error.to_string()))?;
    if bytes.len() > MAX_TREATY_EPOCH_BYTES {
        return Err(refusal(
            "treaty_epoch_invalid",
            "treaty authority record exceeds its byte bound",
        ));
    }
    Ok(bytes)
}

pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ChioRuntimeError> {
    chio_core_types::canonical::UntrustedJsonText::from_wire(bytes, MAX_TREATY_EPOCH_BYTES)?
        .decode_signed()
        .map_err(Into::into)
}

pub(super) fn read_blob(
    tx: &Connection,
    sql: &str,
    args: impl rusqlite::Params,
) -> Result<Option<Vec<u8>>, ChioRuntimeError> {
    let row: Option<Option<Vec<u8>>> = tx
        .query_row(sql, args, |r| r.get(0))
        .optional()
        .map_err(sqlite_error)?;
    match row {
        Some(None) => Err(refusal(
            "treaty_epoch_invalid",
            "treaty authority storage is malformed or oversized",
        )),
        Some(Some(bytes)) => Ok(Some(bytes)),
        None => Ok(None),
    }
}

pub(super) fn authority_id(
    verifier: &AdmissionIdentifier,
    treaty: &AdmissionIdentifier,
) -> Result<String, ChioRuntimeError> {
    crate::canonical_sha256(&("chio.treaty-epoch-authority.v1", verifier, treaty))
}

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Pin {
    pub verifier_id: AdmissionIdentifier,
    pub treaty_id: AdmissionIdentifier,
    pub authority: PublicKey,
}

pub(super) fn load_pin(
    tx: &Connection,
    verifier: &AdmissionIdentifier,
    treaty: &AdmissionIdentifier,
) -> Result<Pin, ChioRuntimeError> {
    check_count(tx, "runtime_treaty_epoch_pins", MAX_PINS, false)?;
    let key = authority_id(verifier, treaty)?;
    let bytes = read_blob(tx, "SELECT CASE WHEN typeof(canonical_bytes) = 'blob' AND length(canonical_bytes) BETWEEN 1 AND 1048576 THEN canonical_bytes END FROM runtime_treaty_epoch_pins WHERE authority_id = ?1", params![key])?
        .ok_or_else(|| refusal("treaty_epoch_unavailable", "treaty epoch authority pin is absent"))?;
    let pin: Pin = decode(&bytes)?;
    if &pin.verifier_id != verifier || &pin.treaty_id != treaty {
        return Err(refusal(
            "treaty_epoch_binding_mismatch",
            "treaty pin differs from its authority index",
        ));
    }
    Ok(pin)
}

pub(super) fn load_head(
    tx: &Connection,
    key: &str,
) -> Result<Option<AdmissionDigest>, ChioRuntimeError> {
    check_count(tx, "runtime_treaty_epoch_heads", MAX_PINS, false)?;
    let row: Option<Option<String>> = tx.query_row("SELECT CASE WHEN typeof(record_digest) = 'text' AND length(record_digest) = 64 AND octet_length(record_digest) <= 128 AND instr(record_digest, char(0)) = 0 AND record_digest NOT GLOB '*[^0-9a-f]*' THEN record_digest END FROM runtime_treaty_epoch_heads WHERE authority_id = ?1", params![key], |r| r.get(0)).optional().map_err(sqlite_error)?;
    match row {
        None => Ok(None),
        Some(Some(value)) => AdmissionDigest::try_new("treaty_epoch_head", value)
            .map(Some)
            .map_err(|_| {
                refusal(
                    "treaty_epoch_invalid",
                    "treaty epoch head digest is malformed",
                )
            }),
        Some(None) => Err(refusal(
            "treaty_epoch_invalid",
            "treaty epoch head storage is malformed",
        )),
    }
}

pub(super) fn load_record(
    tx: &Connection,
    pin: &Pin,
    digest: &AdmissionDigest,
) -> Result<VerifiedTreatyEpochUpdate, ChioRuntimeError> {
    check_count(tx, "runtime_treaty_epoch_records", MAX_RECORDS, false)?;
    let key = authority_id(&pin.verifier_id, &pin.treaty_id)?;
    let bytes = read_blob(tx, "SELECT CASE WHEN typeof(canonical_bytes) = 'blob' AND length(canonical_bytes) BETWEEN 1 AND 1048576 THEN canonical_bytes END FROM runtime_treaty_epoch_records WHERE authority_id = ?1 AND record_digest = ?2", params![key, digest.as_str()])?
        .ok_or_else(|| refusal("treaty_epoch_invalid", "treaty epoch head has no retained signed record"))?;
    let update = treaty_epoch_from_wire(&bytes, &pin.authority).map_err(epoch_error)?;
    let stored_sequence: i64 = tx.query_row("SELECT sequence FROM runtime_treaty_epoch_records WHERE authority_id = ?1 AND record_digest = ?2", params![key, digest.as_str()], |r| r.get(0)).map_err(sqlite_error)?;
    if update.body_digest() != digest
        || update.body().verifier_id != pin.verifier_id
        || update.body().treaty_id != pin.treaty_id
        || u64::try_from(stored_sequence).ok() != Some(update.body().sequence)
    {
        return Err(refusal(
            "treaty_epoch_binding_mismatch",
            "retained epoch differs from its index",
        ));
    }
    Ok(update)
}
