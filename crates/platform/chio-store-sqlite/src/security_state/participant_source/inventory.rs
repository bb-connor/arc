use chio_security_types::ports::{FlowStateKey, IsolationEpochId, LineageId, SessionId, TenantId};
use chio_security_types::PrincipalId;
use rusqlite::Connection;
use sha2::{Digest as _, Sha256};

use super::evidence::{TableFingerprint, MAX_INVENTORY_BYTES, MAX_ROWS};
use super::{schema, Error, Result};

const MAX_ROW_BYTES: i64 = 2 * 1024 * 1024;

pub(super) fn read(connection: &Connection) -> Result<Vec<TableFingerprint>> {
    visit(connection, |_, _| Ok(()))
}

pub(super) fn visit(
    connection: &Connection,
    mut retain: impl FnMut(&'static str, &[u8]) -> Result<()>,
) -> Result<Vec<TableFingerprint>> {
    let mut result = Vec::with_capacity(schema::TABLES.len());
    let mut total_rows = 0_u64;
    let mut total_bytes = 0_u64;
    for table in schema::TABLES {
        let mut columns_statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = columns_statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if columns.is_empty() || columns.len() > 64 {
            return Err(Error::Invalid("source column count exceeds bounds"));
        }
        let names = columns
            .iter()
            .map(|column| format!("\"{column}\""))
            .collect::<Vec<_>>()
            .join(",");
        let row_bytes = columns
            .iter()
            .map(|column| format!("COALESCE(length(CAST(\"{column}\" AS BLOB)), 0)"))
            .collect::<Vec<_>>()
            .join(" + ");
        let (count, bytes, largest): (i64, i64, i64) = connection.query_row(&format!(
            "SELECT COUNT(*), COALESCE(SUM({row_bytes}), 0), COALESCE(MAX({row_bytes}), 0) FROM {table}"),
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        let count = u64::try_from(count).map_err(|_| Error::Invalid("invalid source row count"))?;
        let bytes =
            u64::try_from(bytes).map_err(|_| Error::Invalid("invalid source byte count"))?;
        total_rows = total_rows
            .checked_add(count)
            .ok_or(Error::Invalid("source row count overflow"))?;
        if total_rows > MAX_ROWS || bytes > MAX_INVENTORY_BYTES || largest > MAX_ROW_BYTES {
            return Err(Error::Invalid("source inventory exceeds bounds"));
        }
        // Source schemas are verified before this function. Sorting every
        // canonical column also makes row order independent of SQLite rowids.
        let mut statement =
            connection.prepare(&format!("SELECT {names} FROM {table} ORDER BY {names}"))?;
        let mut rows = statement.query([])?;
        let mut hasher = TableHasher::new(table);
        let mut observed = 0_u64;
        let mut encoded_bytes = 0_u64;
        while let Some(row) = rows.next()? {
            let values = (0..columns.len())
                .map(|index| row.get_ref(index))
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let encoded = super::row_codec::encode_retained_security_values(table, &values)?;
            let size = u64::try_from(encoded.len())
                .map_err(|_| Error::Invalid("source row size overflow"))?;
            encoded_bytes = encoded_bytes
                .checked_add(size)
                .ok_or(Error::Invalid("source bytes overflow"))?;
            total_bytes = total_bytes
                .checked_add(size)
                .ok_or(Error::Invalid("source total bytes overflow"))?;
            if total_bytes > MAX_INVENTORY_BYTES {
                return Err(Error::Invalid("source encoded inventory exceeds bounds"));
            }
            hasher.push(&encoded)?;
            retain(table, &encoded)?;
            observed = observed
                .checked_add(1)
                .ok_or(Error::Invalid("source row count overflow"))?;
        }
        if observed != count {
            return Err(Error::Invalid("source row count changed during inventory"));
        }
        let fingerprint = hasher.finish();
        if fingerprint.row_count != observed || fingerprint.encoded_bytes != encoded_bytes {
            return Err(Error::Invalid("source row framing differs from inventory"));
        }
        result.push(fingerprint);
    }
    Ok(result)
}

/// The persisted v1 framing is shared by source reads and destination readback.
/// Callers must separately bind the result to a pinned, validated fingerprint.
pub(crate) struct TableHasher {
    table: String,
    hasher: Sha256,
    rows: u64,
    bytes: u64,
}

impl TableHasher {
    pub(crate) fn new(table: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"chio.security-participant-source.table.v1\0");
        hasher.update((table.len() as u64).to_be_bytes());
        hasher.update(table.as_bytes());
        Self {
            table: table.into(),
            hasher,
            rows: 0,
            bytes: 0,
        }
    }

    pub(crate) fn push(&mut self, row: &[u8]) -> Result<()> {
        let bytes = u64::try_from(row.len()).map_err(|_| Error::Invalid("row size overflow"))?;
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or(Error::Invalid("row count overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(Error::Invalid("row bytes overflow"))?;
        if self.rows > MAX_ROWS || self.bytes > MAX_INVENTORY_BYTES {
            return Err(Error::Invalid("retained row stream exceeds source bounds"));
        }
        self.hasher.update(bytes.to_be_bytes());
        self.hasher.update(row);
        Ok(())
    }

    pub(crate) fn finish(mut self) -> TableFingerprint {
        self.hasher.update(self.rows.to_be_bytes());
        TableFingerprint {
            table: self.table,
            row_count: self.rows,
            encoded_bytes: self.bytes,
            digest: hex::encode(self.hasher.finalize()),
        }
    }
}

/// Bound the inventory before calling existing domain decoders. Historical
/// expired fences and unresolved consumptions remain inventory, not permission.
pub(super) fn validate_domain(connection: &Connection) -> Result<()> {
    let lifecycle_valid: bool = connection.query_row(
        "SELECT COUNT(*) = 1 AND COALESCE(MIN(singleton = 1 AND schema_version = 2
        AND readiness_cursor = ?1 AND reconciliation_active IN (0, 1)
        AND live_dispatch_sealed IN (0, 1) AND compaction_active = 0
        AND (reconciliation_active = 0 OR live_dispatch_sealed = 0)), 0)
        FROM security_declassification_lifecycle",
        [super::super::DECLASSIFICATION_READINESS_CURSOR],
        |row| row.get(0),
    )?;
    if !lifecycle_valid {
        return Err(Error::Invalid("declassification lifecycle is not stable"));
    }
    super::super::validate_declassification_evidence_integrity(connection)
        .map_err(|_| Error::Invalid("declassification source integrity failed"))?;
    for table in [
        "security_principal_flow_state",
        "security_lineage_flow_state",
        "security_session_flow_state",
    ] {
        let mut statement = connection.prepare(&format!(
            "SELECT label_json, label_hash, generation FROM {table}"
        ))?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            if row.get::<_, i64>(2)? <= 0 {
                return Err(Error::Invalid("flow generation must be positive"));
            }
            super::super::decode_label(row.get(0)?, row.get(1)?)
                .map_err(|_| Error::Invalid("flow label integrity failed"))?;
        }
    }
    let mut statement = connection.prepare(
        "SELECT tenant_id, principal_id, lineage_id, session_id,
        isolation_epoch_id, generation FROM security_flow_contexts",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        fn invalid<T>(_: T) -> Error {
            Error::Invalid("invalid flow context identity")
        }
        let key = FlowStateKey {
            tenant_id: TenantId::new(row.get::<_, String>(0)?).map_err(invalid)?,
            principal_id: PrincipalId::new(row.get::<_, String>(1)?).map_err(invalid)?,
            lineage_id: LineageId::new(row.get::<_, String>(2)?).map_err(invalid)?,
            session_id: SessionId::new(row.get::<_, String>(3)?).map_err(invalid)?,
            isolation_epoch_id: IsolationEpochId::new(row.get::<_, String>(4)?).map_err(invalid)?,
        };
        if row.get::<_, i64>(5)? <= 0 {
            return Err(Error::Invalid("flow context generation must be positive"));
        }
        super::super::load_flow_snapshot(connection, &key)
            .map_err(|_| Error::Invalid("flow context integrity failed"))?
            .ok_or(Error::Invalid("flow context is missing its epoch"))?;
    }
    super::super::flow_state::verify_retained_egress_history(connection)
        .map_err(|_| Error::Invalid("retained egress fence integrity failed"))?;
    Ok(())
}
