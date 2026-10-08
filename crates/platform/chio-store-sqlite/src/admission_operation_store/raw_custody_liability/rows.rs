//! Closed physical row families derive their sizes from the owning SQL source.
use super::*;
use rusqlite::types::ValueRef;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::admission_operation_store) enum RawWriteTableData {
    Blobs,
    Outcomes,
    Operations,
    AdmissionCommits,
    AdmissionMeta,
    GlobalCommits,
    GlobalMeta,
}

impl RawWriteTableData {
    pub(in crate::admission_operation_store) fn table_name(self) -> &'static str {
        match self {
            Self::Blobs => "tool_outcome_blobs",
            Self::Outcomes => "tool_outcomes",
            Self::Operations => "admission_operations",
            Self::AdmissionCommits => "admission_operation_commits",
            Self::AdmissionMeta => "admission_operation_commit_meta",
            Self::GlobalCommits => "authority_global_commits",
            Self::GlobalMeta => "authority_global_commit_meta",
        }
    }

    fn key_column(self) -> &'static str {
        match self {
            Self::Blobs => "digest",
            Self::Outcomes | Self::Operations => "operation_id",
            Self::AdmissionCommits | Self::GlobalCommits => "commit_sequence",
            Self::AdmissionMeta | Self::GlobalMeta => "singleton",
        }
    }
}

/// These maxima are not caller-provided row sizes or refundable page credits.
pub(in crate::admission_operation_store) struct RawRowWriteShapeData {
    table: RawWriteTableData,
    before_bytes: Option<u64>,
    after_bytes: u64,
    mutations: u64,
    index_bytes: Vec<u64>,
}

impl RawRowWriteShapeData {
    pub(in crate::admission_operation_store) fn table(&self) -> RawWriteTableData {
        self.table
    }

    pub(in crate::admission_operation_store) fn before_record_bytes(&self) -> Option<u64> {
        self.before_bytes
    }

    pub(in crate::admission_operation_store) fn maximum_after_record_bytes(&self) -> u64 {
        self.after_bytes
    }

    pub(in crate::admission_operation_store) fn mutations(&self) -> u64 {
        self.mutations
    }

    pub(in crate::admission_operation_store) fn index_record_bytes(&self) -> &[u64] {
        &self.index_bytes
    }
}

struct RowData {
    payloads: Vec<u64>,
    digest: String,
}

pub(super) fn source_digest(
    tx: &Connection,
    table: RawWriteTableData,
    key: &str,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(read_row(tx, table, key)?
        .map(|row| row.digest)
        .unwrap_or_else(|| sha256_hex(b"chio.sqlite.absent-raw-row.v1")))
}

fn read_row(
    tx: &Connection,
    table: RawWriteTableData,
    key: &str,
) -> Result<Option<RowData>, AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(&format!(
            "SELECT * FROM main.{} WHERE {}=?1",
            table.table_name(),
            table.key_column(),
        ))
        .map_err(sqlite_error)?;
    let count = statement.column_count();
    let mut rows = statement.query([key]).map_err(sqlite_error)?;
    let Some(row) = rows.next().map_err(sqlite_error)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"chio.sqlite.raw-row-source.v1");
    let mut payloads = Vec::with_capacity(count);
    for column in 0..count {
        let value = row.get_ref(column).map_err(sqlite_error)?;
        let text = matches!(value, ValueRef::Text(_));
        match value {
            ValueRef::Null => {
                bytes.push(0);
                payloads.push(0);
            }
            ValueRef::Integer(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&value.to_be_bytes());
                // Eight bytes conservatively cover every SQLite integer serial
                // representation, including the original's later version.
                payloads.push(8);
            }
            ValueRef::Text(value) | ValueRef::Blob(value) => {
                bytes.push(if text { 2 } else { 3 });
                let length = u64::try_from(value.len())
                    .map_err(|_| invariant("Raw row payload length exhausted"))?;
                bytes.extend_from_slice(&length.to_be_bytes());
                bytes.extend_from_slice(value);
                payloads.push(length);
            }
            ValueRef::Real(_) => return Err(invariant("Raw row has an unsupported real column")),
        }
    }
    if rows.next().map_err(sqlite_error)?.is_some() {
        return Err(invariant("Raw row source key is not unique"));
    }
    Ok(Some(RowData {
        payloads,
        digest: sha256_hex(&bytes),
    }))
}

fn record_bytes(cells: &[u64]) -> Result<u64, AdmissionOperationStoreError> {
    // One up-to-nine-byte header-size varint and one per serial type. Rowid
    // and cell-pointer bytes are covered by the separately priced tree pages.
    let fields =
        u64::try_from(cells.len()).map_err(|_| invariant("Raw row field count exhausted"))?;
    let headers = fields
        .checked_add(1)
        .and_then(|value| value.checked_mul(9))
        .ok_or_else(|| invariant("Raw record header size exhausted"))?;
    cells.iter().try_fold(headers, |total, bytes| {
        total
            .checked_add(*bytes)
            .ok_or_else(|| invariant("Raw record payload size exhausted"))
    })
}

fn text_bytes(value: &str) -> Result<u64, AdmissionOperationStoreError> {
    u64::try_from(value.len()).map_err(|_| invariant("Raw text length exhausted"))
}

pub(super) fn describe_raw_rows(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    request: &RawCustodyWriteRequest<'_>,
    outcome_json: &[u8],
) -> Result<Vec<RawRowWriteShapeData>, AdmissionOperationStoreError> {
    let blob_bytes = u64::try_from(request.blob.bytes().len())
        .map_err(|_| invariant("Raw canonical blob size exhausted"))?;
    let uuid = text_bytes(&owner.fence.store_uuid)?;
    let lease = text_bytes(&owner.fence.lease_id)?;
    let operation_id = request.operation.binding().operation_id().as_str();
    let blob_key = request.blob.blob_ref().digest().as_str();
    let before_blob = read_row(tx, RawWriteTableData::Blobs, blob_key)?;
    let (blob_size, present): (Option<i64>, Option<Vec<u8>>) = tx
        .query_row(
            "SELECT blob_size_bytes,canonical_bytes FROM main.tool_outcome_blobs WHERE digest=?1",
            [blob_key],
            |row| Ok((Some(row.get(0)?), row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?
        .unwrap_or((None, None));
    if blob_size
        .map(|size| stored_u64(size, "Raw existing blob size"))
        .transpose()?
        .is_some_and(|size| size != blob_bytes)
        || present
            .as_ref()
            .is_some_and(|bytes| bytes.as_slice() != request.blob.bytes())
    {
        return Err(invariant(
            "Raw blob differs from its immutable existing source",
        ));
    }
    let blob_after = if let Some(row) = &before_blob {
        let mut cells = row.payloads.clone();
        if cells.len() != 7 {
            return Err(invariant(
                "Raw blob shape differs from its compiled columns",
            ));
        }
        cells[2] = blob_bytes;
        record_bytes(&cells)?
    } else {
        record_bytes(&[64, 8, blob_bytes, 8, uuid, lease, 8])?
    };
    let mut shapes = vec![RawRowWriteShapeData {
        table: RawWriteTableData::Blobs,
        before_bytes: before_blob
            .as_ref()
            .map(|row| record_bytes(&row.payloads))
            .transpose()?,
        after_bytes: blob_after,
        mutations: u64::from(present.is_none()),
        // The ON CONFLICT rehydration branch changes only canonical_bytes.
        // A genuinely present identical blob does not execute an UPDATE.
        index_bytes: if before_blob.is_none() {
            vec![record_bytes(&[64, 8])?]
        } else {
            Vec::new()
        },
    }];
    let operation = read_row(tx, RawWriteTableData::Operations, operation_id)?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    let mut operation_after = operation.payloads.clone();
    if operation_after.len() != 18 {
        return Err(invariant(
            "Raw operation shape differs from its compiled columns",
        ));
    }
    let coordinator =
        coordinator_lease_id_for_epoch(tx, owner, request.operation.coordinator_lease_epoch())?;
    operation_after[3] = 262_144;
    operation_after[4] = operation_after[4].max(text_bytes("finalizing")?);
    for column in [5, 6, 7, 8, 9, 12, 13, 14, 17] {
        operation_after[column] = 8;
    }
    for (column, length) in [
        (10, text_bytes(request.claim.claimant_id.as_str())?),
        (11, text_bytes(coordinator.as_str())?),
        (15, uuid),
        (16, lease),
    ] {
        operation_after[column] = operation_after[column].max(length);
    }
    shapes.push(RawRowWriteShapeData {
        table: RawWriteTableData::Outcomes,
        before_bytes: None,
        after_bytes: record_bytes(&[
            64,
            64,
            text_bytes(request.outcome.to_persisted().request_id.as_str())?,
            64,
            8,
            64,
            64,
            u64::try_from(outcome_json.len())
                .map_err(|_| invariant("Raw outcome payload exhausted"))?,
            8,
            8,
            uuid,
            lease,
            8,
        ])?,
        mutations: 1,
        index_bytes: vec![
            record_bytes(&[64, 8])?,
            record_bytes(&[64, 8])?,
            record_bytes(&[64, 64, 8])?,
        ],
    });
    shapes.push(RawRowWriteShapeData {
        table: RawWriteTableData::Operations,
        before_bytes: Some(record_bytes(&operation.payloads)?),
        after_bytes: record_bytes(&operation_after)?,
        // A claim can replay without writing. Reserving its maximum one write
        // alongside the required Finalizing write never earns replay credit.
        mutations: 2,
        index_bytes: vec![record_bytes(&[8, 8, 8, 64, 8])?],
    });
    shapes.push(RawRowWriteShapeData {
        table: RawWriteTableData::AdmissionCommits,
        before_bytes: None,
        after_bytes: record_bytes(&[8, 64, 8, 16, 64, 64, 64, 64, 64, uuid, lease, 8, 8, 8])?,
        mutations: 2,
        index_bytes: vec![record_bytes(&[64, 8, 8])?],
    });
    shapes.push(RawRowWriteShapeData {
        table: RawWriteTableData::GlobalCommits,
        before_bytes: None,
        after_bytes: record_bytes(&[8, 16, 9, 64, 8, 64, 64, 64, 64, uuid, lease, 8])?,
        mutations: 2,
        index_bytes: vec![record_bytes(&[9, 64, 8, 8])?],
    });
    for (table, cells) in [
        (RawWriteTableData::AdmissionMeta, vec![8, 8, 64, 8]),
        (RawWriteTableData::GlobalMeta, vec![8, 8, 64]),
    ] {
        let row = read_row(tx, table, "1")?
            .ok_or_else(|| invariant("Raw metadata lost its authentic singleton"))?;
        shapes.push(RawRowWriteShapeData {
            table,
            before_bytes: Some(record_bytes(&row.payloads)?),
            after_bytes: record_bytes(&cells)?,
            mutations: 2,
            index_bytes: Vec::new(),
        });
    }
    Ok(shapes)
}
