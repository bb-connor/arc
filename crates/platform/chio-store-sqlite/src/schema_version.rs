//! Schema stamping shared by every Chio operator store.
//!
//! Each store stamps `PRAGMA application_id` (to tell a Chio store apart from an
//! unrelated SQLite file) and records its schema version in a keyed metadata
//! table, then refuses to open a database whose version it does not own or whose
//! contents are not provably ours. The checks run on the open path only, so they
//! add no cost to the append hot path.
//!
//! Per-store versions live in a keyed table rather than the database-wide
//! `PRAGMA user_version` because the sidecar co-locates several stores in one
//! SQLite file, and one global pragma cannot represent independent versions.
//!
//! The `application_id` is shared by every Chio store, so it proves a file is a
//! Chio store but not which one. A populated database must also carry one of
//! this store's anchor tables; otherwise it is refused as belonging to another
//! store, so a mistargeted path never gets this store's tables written into it.
//!
//! Fail-closed: a foreign, misdirected, stale or future database is refused
//! before any write.

use rusqlite::{params, Connection, OptionalExtension};

/// ASCII "CHIO" as a big-endian `i32`, stamped into every Chio operator store.
pub const CHIO_SQLITE_APPLICATION_ID: i32 = 0x4348_494f;

/// Table holding each co-located store's schema version, keyed by a stable
/// per-store identifier.
const SCHEMA_VERSION_TABLE: &str = "chio_store_schema_versions";

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
    #[error(
        "database schema version {found} is not the current schema version {current}; refusing to open"
    )]
    StaleSchema { found: i32, current: i32 },
}

/// Validate the stamp of a store that has exactly one schema.
///
/// An empty database is stamped with the Chio `application_id` and accepted, as
/// is a Chio database that carries one of `anchor_tables` but no row for
/// `store_key` (a co-located sibling's file this store has not opened yet). The
/// caller then creates its current schema and records `current_version` with
/// [`stamp_schema_version`]. A database stamped at any version other than
/// `current_version` is refused: [`SchemaVersionError::StaleSchema`] when older,
/// [`SchemaVersionError::FutureSchema`] when newer.
pub fn check_current_schema(
    conn: &Connection,
    store_key: &str,
    current_version: i32,
    anchor_tables: &[&str],
) -> Result<(), SchemaVersionError> {
    check_store_identity(conn, anchor_tables)?;
    match read_store_schema_version(conn, store_key)? {
        None => Ok(()),
        Some(found) if found == current_version => Ok(()),
        Some(found) if found > current_version => Err(SchemaVersionError::FutureSchema {
            found,
            supported: current_version,
        }),
        Some(found) => Err(SchemaVersionError::StaleSchema {
            found,
            current: current_version,
        }),
    }
}

/// Validate the stamp of a store that migrates through a version ladder and
/// return its on-disk version (0 when this store has not stamped one), so the
/// caller can apply its steps up to `supported_version`.
///
/// The identity checks match [`check_current_schema`]; a version above
/// `supported_version` is refused as [`SchemaVersionError::FutureSchema`].
pub fn check_schema_version(
    conn: &Connection,
    store_key: &str,
    supported_version: i32,
    anchor_tables: &[&str],
) -> Result<i32, SchemaVersionError> {
    check_store_identity(conn, anchor_tables)?;
    let on_disk_version = read_store_schema_version(conn, store_key)?.unwrap_or(0);
    if on_disk_version > supported_version {
        return Err(SchemaVersionError::FutureSchema {
            found: on_disk_version,
            supported: supported_version,
        });
    }
    Ok(on_disk_version)
}

/// Prove the database is this store's or empty, stamping the `application_id`
/// into an empty one.
///
/// An unstamped database (`application_id == 0`) is accepted only when it has no
/// user tables; populated, it is refused as
/// [`SchemaVersionError::ForeignDatabase`]. A stamped, populated database must
/// carry one of `anchor_tables`, or it is refused as
/// [`SchemaVersionError::MismatchedStore`].
fn check_store_identity(conn: &Connection, anchor_tables: &[&str]) -> Result<(), SchemaVersionError> {
    let app_id: i32 = conn.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let empty = user_table_count(conn)? == 0;

    if app_id == 0 {
        if !empty {
            return Err(SchemaVersionError::ForeignDatabase {
                found: app_id,
                expected: CHIO_SQLITE_APPLICATION_ID,
            });
        }
        conn.execute_batch(&format!(
            "PRAGMA application_id = {CHIO_SQLITE_APPLICATION_ID};"
        ))?;
        return Ok(());
    }
    if app_id != CHIO_SQLITE_APPLICATION_ID {
        return Err(SchemaVersionError::ForeignDatabase {
            found: app_id,
            expected: CHIO_SQLITE_APPLICATION_ID,
        });
    }
    if !empty && !carries_anchor_table(conn, anchor_tables)? {
        return Err(SchemaVersionError::MismatchedStore {
            expected_anchors: anchor_tables
                .iter()
                .map(|table| table.to_string())
                .collect(),
        });
    }
    Ok(())
}

/// The schema version recorded for `store_key`, or `None` when this store has
/// never stamped one into the database.
fn read_store_schema_version(
    conn: &Connection,
    store_key: &str,
) -> Result<Option<i32>, SchemaVersionError> {
    let table_present: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [SCHEMA_VERSION_TABLE],
        |row| row.get(0),
    )?;
    if !table_present {
        return Ok(None);
    }
    Ok(conn
        .query_row(
            &format!("SELECT version FROM {SCHEMA_VERSION_TABLE} WHERE store_key = ?1"),
            [store_key],
            |row| row.get(0),
        )
        .optional()?)
}

fn user_table_count(conn: &Connection) -> Result<i64, SchemaVersionError> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?)
}

fn carries_anchor_table(
    conn: &Connection,
    anchor_tables: &[&str],
) -> Result<bool, SchemaVersionError> {
    for table in anchor_tables {
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

/// Record this store's schema version in keyed metadata.
///
/// The table and column names are compile-time constants; `store_key` and
/// `version` are store-owned values bound as parameters, never caller input.
pub fn stamp_schema_version(
    conn: &Connection,
    store_key: &str,
    version: i32,
) -> Result<(), SchemaVersionError> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {SCHEMA_VERSION_TABLE} (
             store_key TEXT PRIMARY KEY,
             version INTEGER NOT NULL
         );"
    ))?;
    conn.execute(
        &format!(
            "INSERT INTO {SCHEMA_VERSION_TABLE} (store_key, version) VALUES (?1, ?2) \
             ON CONFLICT(store_key) DO UPDATE SET version = excluded.version"
        ),
        params![store_key, version],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    const CURRENT: i32 = 1;
    const STORE_KEY: &str = "receipt";
    const ANCHORS: &[&str] = &["chio_tool_receipts"];

    fn stamped_store_with_anchor() -> Result<Connection, Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(&format!(
            "PRAGMA application_id = {CHIO_SQLITE_APPLICATION_ID};
             CREATE TABLE chio_tool_receipts (receipt_id TEXT PRIMARY KEY);"
        ))?;
        Ok(conn)
    }

    #[test]
    fn fresh_database_opens_and_is_stamped() -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        check_current_schema(&conn, STORE_KEY, CURRENT, ANCHORS)?;
        let app_id: i32 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        assert_eq!(app_id, CHIO_SQLITE_APPLICATION_ID);

        conn.execute_batch("CREATE TABLE chio_tool_receipts (receipt_id TEXT PRIMARY KEY);")?;
        stamp_schema_version(&conn, STORE_KEY, CURRENT)?;
        check_current_schema(&conn, STORE_KEY, CURRENT, ANCHORS)?;
        assert_eq!(read_store_schema_version(&conn, STORE_KEY)?, Some(CURRENT));
        Ok(())
    }

    #[test]
    fn older_stamp_is_refused_as_stale_without_mutation() -> Result<(), Box<dyn std::error::Error>>
    {
        let conn = stamped_store_with_anchor()?;
        stamp_schema_version(&conn, STORE_KEY, 0)?;
        let error = check_current_schema(&conn, STORE_KEY, CURRENT, ANCHORS);
        assert!(matches!(
            error,
            Err(SchemaVersionError::StaleSchema {
                found: 0,
                current: CURRENT
            })
        ));
        assert_eq!(read_store_schema_version(&conn, STORE_KEY)?, Some(0));
        Ok(())
    }

    #[test]
    fn newer_stamp_is_refused_as_future_without_mutation() -> Result<(), Box<dyn std::error::Error>>
    {
        let conn = stamped_store_with_anchor()?;
        stamp_schema_version(&conn, STORE_KEY, 5)?;
        let error = check_current_schema(&conn, STORE_KEY, CURRENT, ANCHORS);
        assert!(matches!(
            error,
            Err(SchemaVersionError::FutureSchema {
                found: 5,
                supported: CURRENT
            })
        ));
        assert_eq!(read_store_schema_version(&conn, STORE_KEY)?, Some(5));
        Ok(())
    }

    #[test]
    fn unstamped_populated_database_is_refused_without_mutation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("CREATE TABLE chio_tool_receipts (id TEXT PRIMARY KEY);")?;
        for result in [
            check_current_schema(&conn, STORE_KEY, CURRENT, ANCHORS),
            check_schema_version(&conn, STORE_KEY, CURRENT, ANCHORS).map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(SchemaVersionError::ForeignDatabase {
                    found: 0,
                    expected: CHIO_SQLITE_APPLICATION_ID
                })
            ));
        }
        let app_id: i32 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        assert_eq!(app_id, 0, "a refused database is not stamped");
        Ok(())
    }

    #[test]
    fn foreign_application_id_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA application_id = 305419896;")?;
        let error = check_current_schema(&conn, STORE_KEY, CURRENT, ANCHORS);
        assert!(matches!(
            error,
            Err(SchemaVersionError::ForeignDatabase {
                found: 305_419_896,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn stamped_database_of_a_different_store_kind_is_refused(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(&format!(
            "PRAGMA application_id = {CHIO_SQLITE_APPLICATION_ID};
             CREATE TABLE capability_grant_budgets (id TEXT PRIMARY KEY);"
        ))?;
        let error = check_current_schema(&conn, STORE_KEY, CURRENT, ANCHORS);
        assert!(matches!(
            error,
            Err(SchemaVersionError::MismatchedStore { .. })
        ));
        Ok(())
    }

    #[test]
    fn co_located_stores_track_independent_schema_versions(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        check_current_schema(&conn, "approval", CURRENT, &["chio_hitl_pending"])?;
        conn.execute_batch("CREATE TABLE chio_hitl_pending (approval_id TEXT PRIMARY KEY);")?;
        stamp_schema_version(&conn, "approval", CURRENT)?;

        stamp_schema_version(&conn, "receipt", 2)?;
        let database_wide: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        assert_eq!(
            database_wide, 0,
            "per-store versions must not be written to the database-wide pragma"
        );

        check_current_schema(&conn, "approval", CURRENT, &["chio_hitl_pending"])?;
        assert_eq!(
            check_schema_version(&conn, "receipt", 2, &["chio_hitl_pending"])?,
            2
        );
        Ok(())
    }

    #[test]
    fn every_own_file_store_stamps_application_id() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        crate::test_authority::secure_directory(dir.path());
        let stamped = |name: &str| -> Result<i32, Box<dyn std::error::Error>> {
            let conn = Connection::open(dir.path().join(name))?;
            Ok(conn.query_row("PRAGMA application_id", [], |r| r.get(0))?)
        };

        crate::SqliteRevocationStore::open(dir.path().join("revocation.db"))?;
        crate::SqliteBudgetStore::open(dir.path().join("budget.db"))?;
        crate::SqliteApprovalStore::open(dir.path().join("approval.db"))?;
        crate::SqliteExecutionNonceStore::open(dir.path().join("nonce.db"))?;
        crate::SqliteMemoryProvenanceStore::open(dir.path().join("provenance.db"))?;
        crate::SqliteEncryptedBlobStore::open(dir.path().join("blob.db"))?;
        crate::SqliteCapabilityAuthority::open(dir.path().join("authority.db"))?;

        for name in [
            "revocation.db",
            "budget.db",
            "approval.db",
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
    fn approval_store_adopts_a_receipt_first_sidecar_file() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sidecar.db");
        crate::SqliteReceiptStore::open(&path)?;
        crate::SqliteApprovalStore::open_colocated_with_receipt_store(&path)?;
        Ok(())
    }

    #[test]
    fn receipt_store_refuses_a_standalone_approval_database(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("approval.db");
        crate::SqliteApprovalStore::open(&path)?;
        assert!(crate::SqliteReceiptStore::open(&path).is_err());
        Ok(())
    }

    #[test]
    fn receipt_store_refuses_a_stamped_budget_database() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("budget.db");
        crate::SqliteBudgetStore::open(&path)?;
        assert!(crate::SqliteReceiptStore::open(&path).is_err());
        Ok(())
    }

    #[test]
    fn approval_store_refuses_a_standalone_revocation_database(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sidecar.db.revocations");
        crate::SqliteRevocationStore::open(&path)?;
        assert!(crate::SqliteApprovalStore::open(&path).is_err());
        assert!(crate::SqliteReceiptStore::open(&path).is_err());
        Ok(())
    }

    #[test]
    fn ladder_check_accepts_every_older_version_and_refuses_newer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for v_bin in 0..4i32 {
            for v_disk in 0..6i32 {
                let conn = stamped_store_with_anchor()?;
                stamp_schema_version(&conn, STORE_KEY, v_disk)?;
                let result = check_schema_version(&conn, STORE_KEY, v_bin, ANCHORS);
                if v_disk > v_bin {
                    assert!(matches!(
                        result,
                        Err(SchemaVersionError::FutureSchema { .. })
                    ));
                } else {
                    assert_eq!(result?, v_disk);
                }
                assert_eq!(read_store_schema_version(&conn, STORE_KEY)?, Some(v_disk));
            }
        }
        Ok(())
    }
}
