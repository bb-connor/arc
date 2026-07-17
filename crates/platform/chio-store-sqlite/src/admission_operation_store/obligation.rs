use chio_core::capability::scope::MonetaryAmount;
use chio_credit::obligation::{ObligationDispositionTransitionV1, ObligationDispositionV1};
use chio_settle::channel::SignedChannelReservationV1;

use super::*;

#[derive(Deserialize)]
struct PersistedObligationProjectionV1 {
    source: PersistedObligationSourceV1,
    atom: ObligationAtomV1,
    disposition_record: ObligationDispositionRecordV1,
}

#[derive(Deserialize)]
struct PersistedObligationSourceV1 {
    source_authority_digest: String,
    source_record_id: String,
    source_record_digest: String,
    source_recorded_at_unix_ms: u64,
    consumer_receipt_id: String,
    consumer_receipt_digest: String,
}

#[derive(Deserialize)]
struct PersistedChannelTerminalV1 {
    reservation_id: String,
    reservation_digest: String,
    receipt_id: String,
    receipt_digest: String,
    actual_charge: MonetaryAmount,
    obligation_atom_id: Option<String>,
    obligation_atom_digest: Option<String>,
    signed_reservation: SignedChannelReservationV1,
}

struct StoredAtomRow {
    operation_id: String,
    atom_digest: String,
    source_receipt_id: String,
    source_receipt_digest: String,
    atom_json: Vec<u8>,
    committed_at_unix_ms: i64,
    store_uuid: String,
    store_lease_id: String,
    store_owner_epoch: i64,
}

struct StoredDispositionRow {
    version: i64,
    lifecycle_fence: i64,
    atom_digest: String,
    disposition_digest: String,
    operation_id: String,
    record_json: Vec<u8>,
    committed_at_unix_ms: i64,
    store_uuid: String,
    store_lease_id: String,
    store_owner_epoch: i64,
}

pub(super) fn insert_obligation_projection(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    obligation_json: Option<&[u8]>,
    channel_json: Option<&[u8]>,
    projection_trusted_time_unix_ms: u64,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let Some(obligation_json) = obligation_json else {
        return Ok(());
    };
    let projection = decode_projection(obligation_json)?;
    validate_projection(&projection, channel_json, projection_trusted_time_unix_ms)?;
    let produced =
        ObligationDispositionRecordV1::produced(&projection.atom).map_err(obligation_error)?;
    insert_atom(
        transaction,
        operation_id,
        &projection.atom,
        committed_at_unix_ms,
        fence,
    )?;
    insert_disposition(
        transaction,
        operation_id,
        &projection.atom,
        &produced,
        committed_at_unix_ms,
        fence,
    )?;
    if projection.disposition_record != produced {
        insert_disposition(
            transaction,
            operation_id,
            &projection.atom,
            &projection.disposition_record,
            committed_at_unix_ms,
            fence,
        )?;
    }
    Ok(())
}

pub(super) fn verify_obligation_projection(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
    obligation_json: Option<&[u8]>,
    channel_json: Option<&[u8]>,
    projection_trusted_time_unix_ms: u64,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let source_row_count: i64 = connection
        .query_row(
            r#"
            SELECT (SELECT COUNT(*) FROM obligation_atoms WHERE operation_id = ?1)
                 + (SELECT COUNT(*) FROM obligation_disposition_records WHERE operation_id = ?1)
            "#,
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let Some(obligation_json) = obligation_json else {
        if source_row_count != 0 {
            return Err(invariant(
                "terminal projection without an obligation has obligation state",
            ));
        }
        return Ok(());
    };
    let projection = decode_projection(obligation_json)?;
    validate_projection(&projection, channel_json, projection_trusted_time_unix_ms)?;
    let stored = load_durable_obligation(connection, projection.atom.obligation_id())?
        .ok_or_else(|| invariant("terminal obligation is absent from canonical storage"))?;
    let disposition_rows = load_disposition_rows(connection, projection.atom.obligation_id())?;
    let projected_row = disposition_rows
        .iter()
        .find(|row| {
            stored_u64(row.version, "obligation_disposition_version")
                .is_ok_and(|version| version == projection.disposition_record.version())
        })
        .ok_or_else(|| invariant("terminal obligation disposition is absent"))?;
    let projected_disposition: ObligationDispositionRecordV1 =
        decode_canonical(&projected_row.record_json, "obligation disposition")?;
    if stored.atom != projection.atom || projected_disposition != projection.disposition_record {
        return Err(invariant(
            "canonical obligation differs from its terminal projection",
        ));
    }
    let atom_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM obligation_atoms WHERE obligation_id = ?1 AND operation_id = ?2",
            params![projection.atom.obligation_id(), operation_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let prefix_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM obligation_disposition_records WHERE obligation_id = ?1 AND version <= ?2",
            params![
                projection.atom.obligation_id(),
                sqlite_i64(
                    projection.disposition_record.version(),
                    "obligation_disposition_version"
                )?,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if atom_count != 1
        || prefix_count
            != sqlite_i64(
                projection.disposition_record.version(),
                "obligation_disposition_version",
            )?
    {
        return Err(invariant(
            "terminal obligation lacks its exact canonical prefix",
        ));
    }
    verify_projection_metadata(
        connection,
        operation_id,
        projection.atom.obligation_id(),
        projection.disposition_record.version(),
        committed_at_unix_ms,
        fence,
    )
}

pub(super) fn load_durable_obligation(
    connection: &Connection,
    obligation_id: &str,
) -> Result<Option<DurableObligationV1>, AdmissionOperationStoreError> {
    let atom_row = connection
        .query_row(
            r#"
            SELECT operation_id, atom_digest, source_receipt_id, source_receipt_digest,
                   atom_json, committed_at_unix_ms, store_uuid, store_lease_id,
                   store_owner_epoch
            FROM obligation_atoms
            WHERE obligation_id = ?1
            "#,
            [obligation_id],
            |row| {
                Ok(StoredAtomRow {
                    operation_id: row.get(0)?,
                    atom_digest: row.get(1)?,
                    source_receipt_id: row.get(2)?,
                    source_receipt_digest: row.get(3)?,
                    atom_json: row.get(4)?,
                    committed_at_unix_ms: row.get(5)?,
                    store_uuid: row.get(6)?,
                    store_lease_id: row.get(7)?,
                    store_owner_epoch: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(atom_row) = atom_row else {
        return Ok(None);
    };
    let atom: ObligationAtomV1 = decode_canonical(&atom_row.atom_json, "obligation atom")?;
    atom.validate().map_err(obligation_error)?;
    let atom_digest = atom.digest().map_err(obligation_error)?;
    if atom.obligation_id() != obligation_id
        || atom_digest != atom_row.atom_digest
        || atom.source_receipt_id() != atom_row.source_receipt_id
        || atom.source_receipt_digest() != atom_row.source_receipt_digest
    {
        return Err(invariant("stored obligation atom columns are inconsistent"));
    }
    verify_exact_lease(
        connection,
        &atom_row.store_uuid,
        &atom_row.store_lease_id,
        atom_row.store_owner_epoch,
    )?;
    let rows = load_disposition_rows(connection, obligation_id)?;
    if rows.is_empty() {
        return Err(invariant("stored obligation lacks a disposition"));
    }
    let mut previous: Option<ObligationDispositionRecordV1> = None;
    for row in &rows {
        let disposition: ObligationDispositionRecordV1 =
            decode_canonical(&row.record_json, "obligation disposition")?;
        disposition
            .validate_against(&atom)
            .map_err(obligation_error)?;
        let expected = match &previous {
            None => ObligationDispositionRecordV1::produced(&atom).map_err(obligation_error)?,
            Some(previous) => previous
                .advance(&atom, disposition.last_transition().clone())
                .map_err(obligation_error)?,
        };
        if disposition != expected
            || disposition.version() != stored_u64(row.version, "obligation_disposition_version")?
            || disposition.lifecycle_fence()
                != stored_u64(
                    row.lifecycle_fence,
                    "obligation_disposition_lifecycle_fence",
                )?
            || disposition.atom_digest() != row.atom_digest
            || disposition.digest(&atom).map_err(obligation_error)? != row.disposition_digest
        {
            return Err(invariant(
                "stored obligation disposition columns are inconsistent",
            ));
        }
        verify_exact_lease(
            connection,
            &row.store_uuid,
            &row.store_lease_id,
            row.store_owner_epoch,
        )?;
        if disposition.version() == 1
            && (row.operation_id != atom_row.operation_id
                || row.committed_at_unix_ms != atom_row.committed_at_unix_ms
                || row.store_uuid != atom_row.store_uuid
                || row.store_lease_id != atom_row.store_lease_id
                || row.store_owner_epoch != atom_row.store_owner_epoch)
        {
            return Err(invariant(
                "produced obligation disposition differs from its atom commit",
            ));
        }
        previous = Some(disposition);
    }
    let disposition = previous.ok_or_else(|| invariant("stored obligation lacks a disposition"))?;
    Ok(Some(DurableObligationV1 { atom, disposition }))
}

fn decode_projection(
    bytes: &[u8],
) -> Result<PersistedObligationProjectionV1, AdmissionOperationStoreError> {
    serde_json::from_slice(bytes).map_err(|error| {
        invariant(format!(
            "terminal obligation projection is invalid: {error}"
        ))
    })
}

fn validate_projection(
    projection: &PersistedObligationProjectionV1,
    channel_json: Option<&[u8]>,
    projection_trusted_time_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    projection.atom.validate().map_err(obligation_error)?;
    projection
        .disposition_record
        .validate_against(&projection.atom)
        .map_err(obligation_error)?;
    let atom_digest = projection.atom.digest().map_err(obligation_error)?;
    if projection.source.source_record_id != projection.atom.obligation_id()
        || projection.source.source_record_digest != atom_digest
        || projection.source.source_authority_digest
            != projection.atom.pre_action_authority_digest()
        || projection.source.source_recorded_at_unix_ms != projection.atom.created_at_unix_ms()
        || projection.source.consumer_receipt_id != projection.atom.source_receipt_id()
        || projection.source.consumer_receipt_digest != projection.atom.source_receipt_digest()
        || projection.atom.created_at_unix_ms() != projection_trusted_time_unix_ms
    {
        return Err(invariant(
            "terminal obligation source does not match its exact atom",
        ));
    }
    let produced =
        ObligationDispositionRecordV1::produced(&projection.atom).map_err(obligation_error)?;
    if projection.disposition_record != produced {
        let expected = produced
            .advance(
                &projection.atom,
                projection.disposition_record.last_transition().clone(),
            )
            .map_err(obligation_error)?;
        if projection.disposition_record != expected {
            return Err(invariant(
                "terminal obligation disposition is not a direct atom transition",
            ));
        }
    }
    match projection.disposition_record.disposition() {
        ObligationDispositionV1::Channelized {
            channel_id,
            reservation_id,
        } => validate_channel_projection(
            projection,
            channel_json.ok_or_else(|| {
                invariant("channelized obligation lacks its channel terminal record")
            })?,
            channel_id,
            reservation_id,
        ),
        _ if channel_json.is_some() => Err(invariant(
            "channel terminal projection has a non-channelized obligation",
        )),
        _ => Ok(()),
    }
}

fn validate_channel_projection(
    projection: &PersistedObligationProjectionV1,
    channel_json: &[u8],
    channel_id: &str,
    reservation_id: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let channel: PersistedChannelTerminalV1 = serde_json::from_slice(channel_json)
        .map_err(|error| invariant(format!("channel terminal projection is invalid: {error}")))?;
    channel
        .signed_reservation
        .body
        .validate()
        .map_err(|error| invariant(format!("invalid channel reservation: {error}")))?;
    let reservation_digest = channel
        .signed_reservation
        .digest()
        .map_err(|error| invariant(format!("invalid channel reservation: {error}")))?;
    let atom_digest = projection.atom.digest().map_err(obligation_error)?;
    let transition_matches = matches!(
        projection.disposition_record.last_transition(),
        ObligationDispositionTransitionV1::ReserveChannel {
            channel_id: transitioned_channel,
            reservation_id: transitioned_reservation,
            authority_digest,
        } if transitioned_channel == channel_id
            && transitioned_reservation == reservation_id
            && authority_digest == &channel.reservation_digest
    );
    if channel.actual_charge.units == 0
        || &channel.actual_charge != projection.atom.amount()
        || channel.reservation_id != reservation_id
        || channel.signed_reservation.body.reservation_id != reservation_id
        || channel.signed_reservation.body.channel_id != channel_id
        || channel.reservation_digest != reservation_digest
        || channel.obligation_atom_id.as_deref() != Some(projection.atom.obligation_id())
        || channel.obligation_atom_digest.as_deref() != Some(atom_digest.as_str())
        || channel.receipt_id != projection.atom.source_receipt_id()
        || channel.receipt_digest != projection.atom.source_receipt_digest()
        || channel.reservation_digest != projection.atom.pre_action_authority_digest()
        || !transition_matches
    {
        return Err(invariant(
            "channel terminal record does not match its canonical obligation",
        ));
    }
    Ok(())
}

fn insert_atom(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    atom: &ObligationAtomV1,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let atom_json = canonical_json_bytes(atom)
        .map_err(|error| invariant(format!("obligation atom encoding failed: {error}")))?;
    let atom_digest = atom.digest().map_err(obligation_error)?;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO obligation_atoms (
                obligation_id, operation_id, atom_digest, source_receipt_id,
                source_receipt_digest, atom_json, committed_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                atom.obligation_id(),
                operation_id.as_str(),
                atom_digest,
                atom.source_receipt_id(),
                atom.source_receipt_digest(),
                atom_json,
                sqlite_i64(committed_at_unix_ms, "obligation_committed_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "obligation_store_owner_epoch")?,
            ],
        )
        .map_err(obligation_sqlite_error)?;
    if inserted != 1 {
        return Err(invariant("obligation atom did not insert exactly once"));
    }
    Ok(())
}

fn insert_disposition(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    atom: &ObligationAtomV1,
    disposition: &ObligationDispositionRecordV1,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let record_json = canonical_json_bytes(disposition)
        .map_err(|error| invariant(format!("obligation disposition encoding failed: {error}")))?;
    let disposition_digest = disposition.digest(atom).map_err(obligation_error)?;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO obligation_disposition_records (
                obligation_id, version, lifecycle_fence, atom_digest,
                disposition_digest, operation_id, record_json, committed_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                disposition.obligation_id(),
                sqlite_i64(disposition.version(), "obligation_disposition_version")?,
                sqlite_i64(
                    disposition.lifecycle_fence(),
                    "obligation_disposition_lifecycle_fence"
                )?,
                disposition.atom_digest(),
                disposition_digest,
                operation_id.as_str(),
                record_json,
                sqlite_i64(committed_at_unix_ms, "obligation_committed_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "obligation_store_owner_epoch")?,
            ],
        )
        .map_err(obligation_sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "obligation disposition did not insert exactly once",
        ));
    }
    Ok(())
}

fn load_disposition_rows(
    connection: &Connection,
    obligation_id: &str,
) -> Result<Vec<StoredDispositionRow>, AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT version, lifecycle_fence, atom_digest, disposition_digest,
                   operation_id, record_json, committed_at_unix_ms, store_uuid,
                   store_lease_id, store_owner_epoch
            FROM obligation_disposition_records
            WHERE obligation_id = ?1
            ORDER BY version
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([obligation_id], |row| {
            Ok(StoredDispositionRow {
                version: row.get(0)?,
                lifecycle_fence: row.get(1)?,
                atom_digest: row.get(2)?,
                disposition_digest: row.get(3)?,
                operation_id: row.get(4)?,
                record_json: row.get(5)?,
                committed_at_unix_ms: row.get(6)?,
                store_uuid: row.get(7)?,
                store_lease_id: row.get(8)?,
                store_owner_epoch: row.get(9)?,
            })
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(rows)
}

fn verify_projection_metadata(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
    obligation_id: &str,
    projected_disposition_version: u64,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let invalid: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM obligation_atoms
                WHERE obligation_id = ?1
                  AND (operation_id <> ?2 OR committed_at_unix_ms <> ?3
                       OR store_uuid <> ?4 OR store_lease_id <> ?5
                       OR store_owner_epoch <> ?6)
                UNION ALL
                SELECT 1 FROM obligation_disposition_records
                WHERE obligation_id = ?1
                  AND version <= ?7
                  AND (operation_id <> ?2 OR committed_at_unix_ms <> ?3
                       OR store_uuid <> ?4 OR store_lease_id <> ?5
                       OR store_owner_epoch <> ?6)
            )
            "#,
            params![
                obligation_id,
                operation_id.as_str(),
                sqlite_i64(committed_at_unix_ms, "obligation_committed_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "obligation_store_owner_epoch")?,
                sqlite_i64(
                    projected_disposition_version,
                    "obligation_disposition_version"
                )?,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if invalid {
        return Err(invariant(
            "canonical obligation is not bound to its terminal projection fence",
        ));
    }
    Ok(())
}

fn verify_exact_lease(
    connection: &Connection,
    store_uuid: &str,
    store_lease_id: &str,
    store_owner_epoch: i64,
) -> Result<(), AdmissionOperationStoreError> {
    let count: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*) FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2 AND lease_id = ?3
            "#,
            params![store_uuid, store_owner_epoch, store_lease_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if count != 1 {
        return Err(invariant("canonical obligation has no exact serving lease"));
    }
    Ok(())
}

fn decode_canonical<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
    label: &str,
) -> Result<T, AdmissionOperationStoreError> {
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| invariant(format!("{label} is invalid: {error}")))?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|error| invariant(format!("{label} encoding failed: {error}")))?;
    if canonical != bytes {
        return Err(invariant(format!("{label} is not canonical")));
    }
    Ok(value)
}

fn obligation_error(
    error: chio_credit::obligation::ObligationError,
) -> AdmissionOperationStoreError {
    invariant(format!("invalid canonical obligation: {error}"))
}

fn obligation_sqlite_error(error: rusqlite::Error) -> AdmissionOperationStoreError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
        invariant(format!(
            "canonical obligation conflicts with durable state: {error}"
        ))
    } else {
        sqlite_error(error)
    }
}
