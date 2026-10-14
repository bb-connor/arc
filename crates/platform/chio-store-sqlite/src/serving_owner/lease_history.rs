use chio_sqlite_file_identity::{SqliteTransactionWriteShapeData, SqliteTreeWriteShapeData};
use rusqlite::Connection;

use super::{read_u64, SqliteServingOwnerError};

const SERVING_LEASE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS chio_serving_leases (
    store_uuid TEXT NOT NULL,
    owner_epoch INTEGER NOT NULL CHECK (owner_epoch > 0),
    lease_id TEXT NOT NULL CHECK (lease_id <> ''),
    start_head_index INTEGER NOT NULL CHECK (start_head_index > 0),
    end_head_index INTEGER CHECK (
        end_head_index IS NULL OR end_head_index >= start_head_index
    ),
    opened_at_ms INTEGER NOT NULL CHECK (opened_at_ms > 0),
    PRIMARY KEY (store_uuid, owner_epoch),
    UNIQUE (lease_id),
    FOREIGN KEY (store_uuid) REFERENCES chio_serving_owner(store_uuid)
);

CREATE TRIGGER IF NOT EXISTS chio_serving_leases_close_only
BEFORE UPDATE ON chio_serving_leases
WHEN NOT (
    OLD.store_uuid IS NEW.store_uuid
    AND OLD.owner_epoch IS NEW.owner_epoch
    AND OLD.lease_id IS NEW.lease_id
    AND OLD.start_head_index IS NEW.start_head_index
    AND OLD.opened_at_ms IS NEW.opened_at_ms
    AND OLD.end_head_index IS NULL
    AND NEW.end_head_index IS NOT NULL
    AND NEW.end_head_index >= OLD.start_head_index
)
BEGIN
    SELECT RAISE(ABORT, 'serving lease history is immutable');
END;

CREATE TRIGGER IF NOT EXISTS chio_serving_leases_no_delete
BEFORE DELETE ON chio_serving_leases
BEGIN
    SELECT RAISE(ABORT, 'serving lease history is immutable');
END;
"#;

pub(super) fn initialize_serving_lease_schema(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    // A serving restart authenticates its retained catalog. Even a no-op
    // CREATE is a schema mutation to SQLite's authorizer, and outstanding
    // native loans deliberately prohibit changing their priced catalog.
    if serving_lease_schema_catalog(connection)?.is_empty() {
        connection.execute_batch(SERVING_LEASE_SCHEMA)?;
    }
    verify_serving_lease_schema(connection)
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

fn serving_lease_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, SqliteServingOwnerError> {
    let mut statement = connection.prepare(
        r#"
        SELECT type, name, tbl_name, sql
        FROM sqlite_schema
        WHERE name GLOB '*chio_serving_leases*'
           OR tbl_name = 'chio_serving_leases'
        ORDER BY type, name, tbl_name
        "#,
    )?;
    let catalog = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(catalog)
}

fn verify_serving_lease_schema(connection: &Connection) -> Result<(), SqliteServingOwnerError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SERVING_LEASE_SCHEMA)?;
    if serving_lease_schema_catalog(connection)? != serving_lease_schema_catalog(&expected)? {
        return Err(SqliteServingOwnerError::Invalid(
            "serving lease schema differs from the canonical definition".to_string(),
        ));
    }
    Ok(())
}

struct ServingLeaseRecord {
    store_uuid: String,
    owner_epoch: u64,
    lease_id: String,
    start_head_index: u64,
    end_head_index: Option<u64>,
    opened_at_ms: u64,
}

pub(super) fn verify_serving_lease_history(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    verify_serving_lease_schema(connection)?;
    let (store_uuid, owner_epoch, active_lease_id, active_opened_at_ms) = connection.query_row(
        r#"
        SELECT store_uuid, owner_epoch, lease_id, opened_at_ms
        FROM chio_serving_owner WHERE singleton = 1
        "#,
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        },
    )?;
    let owner_epoch = read_u64(owner_epoch, "owner_epoch")?;
    let authority_head = connection.query_row(
        "SELECT head_index FROM admission_authority_meta WHERE singleton = 1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let authority_head = read_u64(authority_head, "admission authority head")?;

    let mut statement = connection.prepare(
        r#"
        SELECT store_uuid, owner_epoch, lease_id,
               start_head_index, end_head_index, opened_at_ms
        FROM chio_serving_leases
        ORDER BY owner_epoch ASC
        "#,
    )?;
    let leases = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Option<i64>>(4)?,
            row.get::<_, i64>(5)?,
        ))
    })?;

    let mut expected_epoch = 1_u64;
    let mut previous_end = None;
    for lease in leases {
        let lease = lease?;
        let lease = ServingLeaseRecord {
            store_uuid: lease.0,
            owner_epoch: read_u64(lease.1, "serving lease owner_epoch")?,
            lease_id: lease.2,
            start_head_index: read_u64(lease.3, "serving lease start_head_index")?,
            end_head_index: lease
                .4
                .map(|value| read_u64(value, "serving lease end_head_index"))
                .transpose()?,
            opened_at_ms: read_u64(lease.5, "serving lease opened_at_ms")?,
        };
        if lease.store_uuid != store_uuid
            || lease.owner_epoch != expected_epoch
            || lease.lease_id.is_empty()
            || lease.start_head_index == 0
            || lease.start_head_index > authority_head
            || lease.opened_at_ms == 0
            || previous_end.is_some_and(|end| end != lease.start_head_index)
        {
            return Err(SqliteServingOwnerError::Invalid(
                "serving lease history is not a dense authority chain".to_string(),
            ));
        }
        if lease.owner_epoch < owner_epoch {
            let end = lease.end_head_index.ok_or_else(|| {
                SqliteServingOwnerError::Invalid("a prior serving lease remains open".to_string())
            })?;
            if end < lease.start_head_index || end > authority_head {
                return Err(SqliteServingOwnerError::Invalid(
                    "a prior serving lease has an invalid authority interval".to_string(),
                ));
            }
            previous_end = Some(end);
        } else if lease.owner_epoch == owner_epoch {
            let active_opened_at_ms = active_opened_at_ms
                .ok_or_else(|| {
                    SqliteServingOwnerError::Invalid(
                        "active serving owner has no open timestamp".to_string(),
                    )
                })
                .and_then(|value| read_u64(value, "active serving owner opened_at_ms"))?;
            if lease.end_head_index.is_some()
                || active_lease_id.as_deref() != Some(lease.lease_id.as_str())
                || active_opened_at_ms != lease.opened_at_ms
            {
                return Err(SqliteServingOwnerError::Invalid(
                    "active serving lease does not match its owner fence".to_string(),
                ));
            }
            previous_end = None;
        } else {
            return Err(SqliteServingOwnerError::Invalid(
                "serving lease history extends beyond its owner epoch".to_string(),
            ));
        }
        expected_epoch = expected_epoch.checked_add(1).ok_or_else(|| {
            SqliteServingOwnerError::Invalid("serving lease epoch overflowed u64".to_string())
        })?;
    }

    let lease_count = expected_epoch - 1;
    if owner_epoch == 0 {
        if lease_count != 0 || active_lease_id.is_some() || active_opened_at_ms.is_some() {
            return Err(SqliteServingOwnerError::Invalid(
                "inactive serving owner has lease history".to_string(),
            ));
        }
    } else if lease_count != owner_epoch || previous_end.is_some() {
        return Err(SqliteServingOwnerError::Invalid(
            "serving lease history does not end at the active owner epoch".to_string(),
        ));
    }
    Ok(())
}

/// Conservative encoded overhead of one row or index entry beyond the actual
/// variable text lengths the caller supplies: serial-type headers, integer
/// varints and row slack.
const LEASE_ROW_OVERHEAD_BYTES: u64 = 128;

fn lease_text_bytes(value: &str) -> Result<u64, SqliteServingOwnerError> {
    u64::try_from(value.len()).map_err(|_| {
        SqliteServingOwnerError::Invalid("serving lease text exceeds SQLite range".to_string())
    })
}

fn lease_shape_add(left: u64, right: u64) -> Result<u64, SqliteServingOwnerError> {
    left.checked_add(right).ok_or_else(|| {
        SqliteServingOwnerError::Invalid("serving lease shape bytes exhausted".to_string())
    })
}

/// The complete write shape of one serving lease transition on the held
/// authority transaction: the previous lease release (when a lease was open),
/// the `chio_serving_owner` singleton row rewrite and the fresh
/// `chio_serving_leases` row with both of its automatic index entries. The
/// close-only and no-delete triggers only read; the owner row's UNIQUE
/// `store_uuid` index key is unchanged and so is not written. Nothing in this
/// shape reads the file's size, so its price stays exactly this transition's
/// own rows whatever retained history the authority holds.
///
/// Every text length is the actual provisioned or minted value, so the
/// payloads are real and bounded, never an invented fixed escape.
pub(super) fn serving_lease_transition_shape(
    closing_previous_lease: bool,
    store_uuid: &str,
    lease_id: &str,
    database_path: &str,
    lock_root: &str,
) -> Result<SqliteTransactionWriteShapeData, SqliteServingOwnerError> {
    let text = lease_text_bytes;
    let owner_row = [
        LEASE_ROW_OVERHEAD_BYTES,
        text(store_uuid)?,
        text(lease_id)?,
        text(database_path)?,
        text(lock_root)?,
    ]
    .into_iter()
    .try_fold(0_u64, lease_shape_add)?;
    let lease_row = [LEASE_ROW_OVERHEAD_BYTES, text(store_uuid)?, text(lease_id)?]
        .into_iter()
        .try_fold(0_u64, lease_shape_add)?;
    // One automatic index entry carries the store UUID and the epoch or the
    // lease ID; both are bounded by the same text sum.
    let lease_index = [LEASE_ROW_OVERHEAD_BYTES, text(store_uuid)?, text(lease_id)?]
        .into_iter()
        .try_fold(0_u64, lease_shape_add)?;
    let tree = |result: Result<SqliteTreeWriteShapeData, String>| {
        result.map_err(SqliteServingOwnerError::Invalid)
    };
    // Releasing the previous lease rewrites one retained row under its
    // unchanged key, and the ambiguous record shape keeps the existing-row
    // cost; a first acquisition only appends a fresh record.
    let lease_table = if closing_previous_lease {
        tree(SqliteTreeWriteShapeData::record(
            Some(lease_row),
            lease_row,
            2,
        ))?
    } else {
        tree(SqliteTreeWriteShapeData::fresh_insertions(lease_row, 1))?
    };
    let trees = vec![
        // The owner singleton row rewrite.
        tree(SqliteTreeWriteShapeData::record(
            Some(owner_row),
            owner_row,
            1,
        ))?,
        lease_table,
        // The PRIMARY KEY (store_uuid, owner_epoch) automatic index entry.
        tree(SqliteTreeWriteShapeData::fresh_insertions(lease_index, 1))?,
        // The UNIQUE (lease_id) automatic index entry.
        tree(SqliteTreeWriteShapeData::fresh_insertions(lease_index, 1))?,
    ];
    SqliteTransactionWriteShapeData::checked(trees).map_err(SqliteServingOwnerError::Invalid)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod transition_shape_tests {
    use super::*;
    use chio_sqlite_file_identity::{price_transaction_write_shape, SqliteFramePriceProfileData};

    const INTAKE_WAL_LIMIT_BYTES: u64 = 64 * 1024 * 1024;

    fn priced(closing_previous_lease: bool) -> Result<u64, String> {
        let profile = SqliteFramePriceProfileData::checked(4096, 0)?;
        let shape = serving_lease_transition_shape(
            closing_previous_lease,
            "0123456789abcdef0123456789abcdef",
            "ffffffff-ffff-7fff-8fff-ffffffffffff",
            "/secure/authorities/authority.db",
            "/secure/authorities/locks",
        )
        .map_err(|error| error.to_string())?;
        Ok(price_transaction_write_shape(&profile, &shape)?.wal_bytes())
    }

    /// A lease transition prices only its own rows, whatever retained
    /// history the authority holds: the price stays inside the original
    /// fixed whole-file intake contract, and releasing a previous lease
    /// costs strictly more than a first acquisition. The conservative
    /// 20-level balance formulas price even this tiny transition at several
    /// MiB of WAL headroom, so the asserted contract is the 64MiB intake
    /// limit, not an invented tighter target.
    #[test]
    fn a_lease_transition_prices_its_own_rows_not_the_retained_file() -> Result<(), String> {
        let fresh = priced(false)?;
        let closing = priced(true)?;
        assert!(
            fresh < INTAKE_WAL_LIMIT_BYTES,
            "a first lease acquisition must stay inside the intake contract, priced {fresh}"
        );
        assert!(
            closing < INTAKE_WAL_LIMIT_BYTES,
            "a lease release plus acquisition must stay inside the intake contract, priced {closing}"
        );
        assert!(
            closing > fresh,
            "releasing the previous lease must retain the existing-row cost"
        );
        Ok(())
    }
}
