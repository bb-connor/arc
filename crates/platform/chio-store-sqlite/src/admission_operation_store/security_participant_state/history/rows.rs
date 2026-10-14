//! Compare current row identities to imported bytes plus anchored row changes.
//! No historical domain command is re-executed or promoted to authority.
use super::*;
use crate::security_state::{
    decode_retained_security_row, encode_retained_security_values, retained_security_columns,
};

/// Page cache of the scratch inventory in KiB. Retained history grows only the
/// scratch file, never the verifier's memory.
const SCRATCH_CACHE_KIB: i64 = 2048;

/// The current-row inventory reconstructed from imported bytes and anchored
/// row changes. It lives in a private temporary SQLite database that SQLite
/// deletes when this verifier drops it. A row is its table plus the digest and
/// length of its exact image; the row and byte totals are kept as it changes.
struct Inventory {
    scratch: Connection,
    rows: u64,
    bytes: u64,
}

impl Inventory {
    fn open() -> Result<Self, AdmissionOperationStoreError> {
        let scratch = Connection::open("").map_err(sqlite_error)?;
        scratch
            .pragma_update(None, "cache_size", -SCRATCH_CACHE_KIB)
            .map_err(sqlite_error)?;
        scratch
            .pragma_update(None, "temp_store", "FILE")
            .map_err(sqlite_error)?;
        scratch
            .pragma_update(None, "synchronous", "OFF")
            .map_err(sqlite_error)?;
        let journal: String = scratch
            .pragma_update_and_check(None, "journal_mode", "OFF", |row| row.get(0))
            .map_err(sqlite_error)?;
        if !journal.eq_ignore_ascii_case("off") {
            return Err(invalid("native row inventory scratch kept a journal"));
        }
        scratch
            .execute_batch(
                "CREATE TABLE inventory (
                     table_name TEXT NOT NULL,
                     digest TEXT NOT NULL,
                     bytes INTEGER NOT NULL,
                     PRIMARY KEY (table_name, digest)
                 ) STRICT, WITHOUT ROWID;
                 BEGIN;",
            )
            .map_err(sqlite_error)?;
        Ok(Self {
            scratch,
            rows: 0,
            bytes: 0,
        })
    }

    /// A decoded image enters as a new row; an existing identical row refuses.
    fn insert(&mut self, table: &str, image: &str) -> Result<(), AdmissionOperationStoreError> {
        decode_retained_security_row(table, image.as_bytes()).map_err(invalid)?;
        let size = u64::try_from(image.len()).map_err(invalid)?;
        let stored = i64::try_from(size).map_err(invalid)?;
        let inserted = self
            .scratch
            .prepare_cached(
                "INSERT OR IGNORE INTO inventory (table_name, digest, bytes) VALUES (?1, ?2, ?3)",
            )
            .map_err(sqlite_error)?
            .execute(params![table, sha256_hex(image.as_bytes()), stored])
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invalid("native mutation duplicates an existing row"));
        }
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or_else(|| invalid("native row count overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(size)
            .ok_or_else(|| invalid("native byte count overflow"))?;
        Ok(())
    }

    /// Exactly one row with this table, digest and length leaves the inventory.
    fn remove(
        &mut self,
        table: &str,
        image: &[u8],
        refusal: &'static str,
    ) -> Result<(), AdmissionOperationStoreError> {
        let size = u64::try_from(image.len()).map_err(invalid)?;
        let stored = i64::try_from(size).map_err(invalid)?;
        let removed = self
            .scratch
            .prepare_cached(
                "DELETE FROM inventory WHERE table_name = ?1 AND digest = ?2 AND bytes = ?3",
            )
            .map_err(sqlite_error)?
            .execute(params![table, sha256_hex(image), stored])
            .map_err(sqlite_error)?;
        if removed != 1 {
            return Err(invalid(refusal));
        }
        self.rows = self
            .rows
            .checked_sub(1)
            .ok_or_else(|| invalid("native row count underflow"))?;
        self.bytes = self
            .bytes
            .checked_sub(size)
            .ok_or_else(|| invalid("native byte count underflow"))?;
        Ok(())
    }

    /// A decoded before-image leaves the inventory as its exact predecessor.
    fn remove_before(
        &mut self,
        table: &str,
        image: &str,
    ) -> Result<(), AdmissionOperationStoreError> {
        decode_retained_security_row(table, image.as_bytes()).map_err(invalid)?;
        self.remove(
            table,
            image.as_bytes(),
            "native mutation before-image has no exact predecessor",
        )
    }

    fn is_empty(&self) -> Result<bool, AdmissionOperationStoreError> {
        let retained: bool = self
            .scratch
            .query_row("SELECT EXISTS(SELECT 1 FROM inventory)", [], |row| {
                row.get(0)
            })
            .map_err(sqlite_error)?;
        Ok(self.rows == 0 && self.bytes == 0 && !retained)
    }
}

pub(in crate::admission_operation_store::security_participant_state) fn verify_rows(
    connection: &Connection,
    source: &SecurityParticipantMigrationRecord,
    initialization: &SecurityParticipantStateInitialization,
) -> Result<(), AdmissionOperationStoreError> {
    let authority = initialization.authority.as_str();
    let head = super::head(connection, authority)?;
    let egress = super::super::egress::exists(connection)?
        && super::super::egress::head(connection, authority)? != 0;
    let output = super::super::output::exists(connection)?
        && super::super::output::head(connection, authority)? != 0;
    let nonce_preflight = super::super::nonce_preflight::exists(connection)?
        && super::super::nonce_preflight::head(connection, authority)? != 0;
    if head == 1
        && !egress
        && !output
        && !nonce_preflight
        && super::super::knowledge::head(connection, authority)? == 0
    {
        return super::super::storage::verify_rows(connection, source);
    }
    let mut inventory = Inventory::open()?;
    let mut statement = connection
        .prepare(
            "SELECT table_name, canonical_row FROM security_participant_migration_rows
         WHERE security_authority_id = ?1 ORDER BY table_name, row_index",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([authority]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let table: String = row.get(0).map_err(sqlite_error)?;
        let bytes = row
            .get_ref(1)
            .map_err(sqlite_error)?
            .as_blob()
            .map_err(invalid)?;
        inventory.insert(&table, std::str::from_utf8(bytes).map_err(invalid)?)?;
    }
    drop(rows);
    drop(statement);
    super::ordered::visit(connection, initialization, |event| {
        for change in event.changes() {
            // Each decoded family independently enforces its exact row policy.
            // Join-v1 still cannot remove rows, release fences or spend grants.
            if let Some(before) = &change.before {
                inventory.remove_before(&change.table, before)?;
            }
            if let Some(after) = &change.after {
                inventory.insert(&change.table, after)?;
            }
        }
        if (inventory.rows, inventory.bytes) != event.totals() {
            return Err(invalid(
                "native current row bounds differ from anchored history",
            ));
        }
        Ok(())
    })?;
    for table in schema::TABLES {
        let fields = retained_security_columns(table.source).map_err(invalid)?;
        let columns = fields
            .iter()
            .map(|field| format!("\"{field}\""))
            .collect::<Vec<_>>()
            .join(",");
        let mut statement = connection
            .prepare(&format!(
                "SELECT {columns} FROM {} WHERE security_authority_id = ?1",
                table.native
            ))
            .map_err(sqlite_error)?;
        let mut rows = statement.query([authority]).map_err(sqlite_error)?;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let values = (0..fields.len())
                .map(|index| row.get_ref(index))
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(sqlite_error)?;
            let bytes = encode_retained_security_values(table.source, &values).map_err(invalid)?;
            inventory.remove(
                table.source,
                &bytes,
                "native current row differs from anchored history",
            )?;
        }
    }
    if !inventory.is_empty()? {
        return Err(invalid("native current rows are missing anchored history"));
    }
    Ok(())
}
