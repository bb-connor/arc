//! Schema stamping shared by every Chio operator store.
//!
//! Each store stamps `PRAGMA application_id` (to tell a Chio store apart from an
//! unrelated SQLite file) and `PRAGMA user_version` (the per-store schema
//! revision), and refuses to open a database whose version is newer than this
//! binary understands or whose contents are not provably ours. The checks run
//! on the open path only, so they add no cost to the append hot path.
//!
//! The `application_id` is shared by every Chio store, so it proves a file is a
//! Chio store but not which one. To keep a path mistargeted at a sibling store
//! (opening a budget or authority database as a receipt store) from writing this
//! store's tables into it, a populated database must also carry one of this
//! store's anchor tables; otherwise it is refused as belonging to another store.
//!
//! Fail-closed: a foreign, misdirected, or future database is refused before any
//! write, so a rollback to an older binary or a mistargeted path is caught at
//! open rather than after data has been commingled or a newer schema misread.

use rusqlite::Connection;

/// ASCII "CHIO" as a big-endian `i32`, stamped into every Chio operator store.
pub const CHIO_SQLITE_APPLICATION_ID: i32 = 0x4348_494f;

/// Failure to validate or apply a store's schema stamp.
#[derive(Debug, thiserror::Error)]
pub enum SchemaVersionError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database application_id {found:#x} is not a Chio store (expected {expected:#x})")]
    ForeignDatabase { found: i32, expected: i32 },
    #[error(
        "database carries the Chio application_id but none of this store's tables ({expected_anchors:?}); refusing to open another store's database"
    )]
    MismatchedStore { expected_anchors: Vec<String> },
    #[error(
        "database schema version {found} is newer than this binary supports ({supported}); refusing to open"
    )]
    FutureSchema { found: i32, supported: i32 },
}

/// Read and validate the schema stamp, returning the on-disk version so the
/// caller can run additive migrations up to `supported_version`.
///
/// A zero stamp (`application_id == 0 && user_version == 0`) is ambiguous: it is
/// shared by a freshly created file, a legacy Chio store written before stamping
/// existed, and countless unrelated SQLite files. It is adopted and stamped only
/// when the contents prove provenance (the database is empty or carries one of
/// this store's `legacy_tables`); otherwise it is refused as
/// [`SchemaVersionError::ForeignDatabase`] rather than commingling Chio tables
/// into a foreign file.
///
/// A database already stamped with the shared Chio `application_id` proves it is
/// a Chio store, but not that it is *this* store's. A populated stamped database
/// must therefore also carry one of `legacy_tables`, or it is refused as
/// [`SchemaVersionError::MismatchedStore`] so a path aimed at a sibling store's
/// database (a budget or authority file) never gets this store's tables written
/// into it. An empty stamped database (freshly stamped, tables not yet created)
/// is always accepted.
pub fn check_schema_version(
    conn: &Connection,
    supported_version: i32,
    legacy_tables: &[&str],
) -> Result<i32, SchemaVersionError> {
    let app_id: i32 = conn.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let user_version: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

    if app_id == 0 && user_version == 0 {
        if !database_belongs_to_store(conn, legacy_tables)? {
            return Err(SchemaVersionError::ForeignDatabase {
                found: app_id,
                expected: CHIO_SQLITE_APPLICATION_ID,
            });
        }
        conn.execute_batch(&format!(
            "PRAGMA application_id = {CHIO_SQLITE_APPLICATION_ID};"
        ))?;
        return Ok(0);
    }
    if app_id != CHIO_SQLITE_APPLICATION_ID {
        return Err(SchemaVersionError::ForeignDatabase {
            found: app_id,
            expected: CHIO_SQLITE_APPLICATION_ID,
        });
    }
    if !database_belongs_to_store(conn, legacy_tables)? {
        return Err(SchemaVersionError::MismatchedStore {
            expected_anchors: legacy_tables
                .iter()
                .map(|table| table.to_string())
                .collect(),
        });
    }
    if user_version > supported_version {
        return Err(SchemaVersionError::FutureSchema {
            found: user_version,
            supported: supported_version,
        });
    }
    Ok(user_version)
}

/// Whether a database may be adopted as this store's. It qualifies when it has no
/// user tables (a freshly created or freshly stamped file) or when it carries a
/// known anchor table (a legacy pre-stamping store, or a reopened store of the
/// same kind). This keeps an unrelated SQLite file from being written into and
/// keeps a sibling Chio store's populated database from being mistaken for this
/// one, without falsely rejecting an empty or same-kind database.
fn database_belongs_to_store(
    conn: &Connection,
    legacy_tables: &[&str],
) -> Result<bool, SchemaVersionError> {
    let user_table_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if user_table_count == 0 {
        return Ok(true);
    }
    for table in legacy_tables {
        let present: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )?;
        if present {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Stamp the schema revision after migrations have run.
///
/// `PRAGMA` does not accept bound parameters; `version` is always a compile-time
/// constant owned by the calling store, never caller input.
pub fn stamp_schema_version(conn: &Connection, version: i32) -> Result<(), SchemaVersionError> {
    conn.execute_batch(&format!("PRAGMA user_version = {version};"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    const SUPPORTED: i32 = 0;

    #[test]
    fn fresh_empty_db_adopts_v0_and_stamps_application_id() -> Result<(), Box<dyn std::error::Error>>
    {
        let conn = Connection::open_in_memory()?;
        let version = check_schema_version(&conn, SUPPORTED, &["chio_tool_receipts"])?;
        assert_eq!(version, 0);
        let app_id: i32 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        assert_eq!(app_id, CHIO_SQLITE_APPLICATION_ID);
        Ok(())
    }

    #[test]
    fn legacy_unstamped_db_with_anchor_table_adopts_v0() -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("CREATE TABLE chio_tool_receipts (id TEXT PRIMARY KEY);")?;
        let version = check_schema_version(&conn, SUPPORTED, &["chio_tool_receipts"])?;
        assert_eq!(version, 0);
        let app_id: i32 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        assert_eq!(app_id, CHIO_SQLITE_APPLICATION_ID);
        Ok(())
    }

    #[test]
    fn foreign_db_with_unknown_tables_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("CREATE TABLE someone_elses_table (id TEXT PRIMARY KEY);")?;
        let error = check_schema_version(&conn, SUPPORTED, &["chio_tool_receipts"]);
        assert!(matches!(
            error,
            Err(SchemaVersionError::ForeignDatabase { .. })
        ));
        let app_id: i32 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        assert_eq!(app_id, 0, "a foreign database is not stamped");
        Ok(())
    }

    #[test]
    fn foreign_application_id_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA application_id = 305419896;")?; // 0x12345678
        let error = check_schema_version(&conn, SUPPORTED, &["chio_tool_receipts"]);
        assert!(matches!(
            error,
            Err(SchemaVersionError::ForeignDatabase { .. })
        ));
        Ok(())
    }

    #[test]
    fn stamped_database_of_a_different_store_kind_is_refused(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A budget database carries the shared Chio application_id but none of
        // the receipt store's anchor tables. Opening it as a receipt store must
        // fail closed rather than write receipt tables into the budget file.
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(&format!(
            "PRAGMA application_id = {CHIO_SQLITE_APPLICATION_ID};
             CREATE TABLE capability_grant_budgets (id TEXT PRIMARY KEY);"
        ))?;
        let error = check_schema_version(&conn, SUPPORTED, &["chio_tool_receipts"]);
        assert!(matches!(
            error,
            Err(SchemaVersionError::MismatchedStore { .. })
        ));
        Ok(())
    }

    #[test]
    fn stamped_database_carrying_a_store_anchor_is_accepted(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(&format!(
            "PRAGMA application_id = {CHIO_SQLITE_APPLICATION_ID};
             CREATE TABLE chio_tool_receipts (receipt_id TEXT PRIMARY KEY);"
        ))?;
        assert_eq!(
            check_schema_version(&conn, SUPPORTED, &["chio_tool_receipts"])?,
            0
        );
        Ok(())
    }

    #[test]
    fn future_schema_is_refused_without_mutation() -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(&format!(
            "PRAGMA application_id = {CHIO_SQLITE_APPLICATION_ID}; PRAGMA user_version = 5;"
        ))?;
        let error = check_schema_version(&conn, 3, &["chio_tool_receipts"]);
        assert!(matches!(
            error,
            Err(SchemaVersionError::FutureSchema {
                found: 5,
                supported: 3
            })
        ));
        let user_version: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        assert_eq!(user_version, 5, "a refused future database is not mutated");
        Ok(())
    }

    #[test]
    fn stamp_then_reopen_reports_stamped_version() -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        check_schema_version(&conn, 2, &["chio_tool_receipts"])?;
        stamp_schema_version(&conn, 2)?;
        let version = check_schema_version(&conn, 2, &["chio_tool_receipts"])?;
        assert_eq!(version, 2);
        Ok(())
    }

    #[test]
    fn every_own_file_store_stamps_application_id() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let stamped = |name: &str| -> Result<i32, Box<dyn std::error::Error>> {
            let conn = Connection::open(dir.path().join(name))?;
            Ok(conn.query_row("PRAGMA application_id", [], |r| r.get(0))?)
        };

        crate::SqliteRevocationStore::open(dir.path().join("revocation.db"))?;
        crate::SqliteBudgetStore::open(dir.path().join("budget.db"))?;
        crate::SqliteApprovalStore::open(dir.path().join("approval.db"))?;
        crate::SqliteBatchApprovalStore::open(dir.path().join("batch.db"))?;
        crate::SqliteExecutionNonceStore::open(dir.path().join("nonce.db"))?;
        crate::SqliteMemoryProvenanceStore::open(dir.path().join("provenance.db"))?;
        crate::SqliteEncryptedBlobStore::open(dir.path().join("blob.db"))?;
        crate::SqliteCapabilityAuthority::open(dir.path().join("authority.db"))?;

        for name in [
            "revocation.db",
            "budget.db",
            "approval.db",
            "batch.db",
            "nonce.db",
            "provenance.db",
            "blob.db",
            "authority.db",
        ] {
            assert_eq!(
                stamped(name)?,
                CHIO_SQLITE_APPLICATION_ID,
                "{name} not stamped"
            );
        }
        Ok(())
    }

    #[test]
    fn receipt_store_adopts_a_file_already_holding_approval_tables(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // `chio api protect` opens the approval store first, then the receipt
        // store, on one shared file. The receipt store must adopt the file the
        // approval store stamped rather than reject it as a foreign store.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sidecar.db");
        crate::SqliteApprovalStore::open(&path)?;
        crate::SqliteReceiptStore::open(&path)?;
        Ok(())
    }

    #[test]
    fn receipt_store_refuses_a_stamped_budget_database() -> Result<(), Box<dyn std::error::Error>> {
        // A path mistargeted at a budget database must fail closed instead of
        // writing receipt tables into another store's file.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("budget.db");
        crate::SqliteBudgetStore::open(&path)?;
        assert!(crate::SqliteReceiptStore::open(&path).is_err());
        Ok(())
    }

    #[test]
    fn approval_store_refuses_a_standalone_revocation_database(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The revocation store lives in its own file alongside the sidecar
        // database. A `--receipt-store` mistargeted at that revocation file must
        // fail closed: `chio api protect` opens the approval store first, so if a
        // lone `revoked_capabilities` table let it adopt the file, it would write
        // approval tables into the revocation database and the receipt store would
        // then accept the commingled file too.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sidecar.db.revocations");
        crate::SqliteRevocationStore::open(&path)?;
        assert!(crate::SqliteApprovalStore::open(&path).is_err());
        assert!(crate::SqliteReceiptStore::open(&path).is_err());
        Ok(())
    }

    // Table-driven schema-version monotonicity (this crate has no proptest
    // dev-dependency): for every v_disk <= v_bin the reopen is stable and never
    // downgrades; for v_disk > v_bin the open refuses and leaves the file
    // unmodified.
    #[test]
    fn schema_version_monotonicity_across_binary_and_disk_versions(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for v_bin in 0..4i32 {
            for v_disk in 0..6i32 {
                let conn = Connection::open_in_memory()?;
                conn.execute_batch(&format!(
                    "PRAGMA application_id = {CHIO_SQLITE_APPLICATION_ID}; PRAGMA user_version = {v_disk};"
                ))?;
                let result = check_schema_version(&conn, v_bin, &["chio_tool_receipts"]);
                let after: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
                if v_disk > v_bin {
                    assert!(matches!(
                        result,
                        Err(SchemaVersionError::FutureSchema { .. })
                    ));
                    assert_eq!(after, v_disk, "a refused database must not be mutated");
                } else {
                    assert_eq!(result?, v_disk);
                    assert_eq!(after, v_disk, "check must not change user_version");
                }
            }
        }
        Ok(())
    }
}
