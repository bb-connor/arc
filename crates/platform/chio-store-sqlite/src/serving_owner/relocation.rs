//! Relocation of a provisioned authority store to another path or host.
//!
//! The serving owner binds an authority database to its canonical path and to
//! the inodes of the database and its serving lock, so a copied or restored
//! database refuses to serve. Relocation is the sanctioned way to move that
//! binding: `export` retires the store where it is and seals its commit chain
//! heads, and `import` re-anchors a byte-identical copy at its new location
//! after proving the copy matches the seal. An exported store never serves
//! again at its old location, so one export yields at most one serving lineage
//! per import; importing the same copy twice is the operator's responsibility
//! to avoid, and both imports would share history only up to the seal.

use std::fs::{self, File};
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::global_commit_chain::verify_global_commit_chain;
use super::lease_history::initialize_serving_lease_schema;
use super::rollback_anchor::RollbackAnchor;
use super::{
    acquire_serving_lock, canonical_lock_root, create_lock_file, database_parent,
    load_provisioning_record, load_provisioning_record_tx, metadata_device, metadata_inode, now_ms,
    open_existing_database, open_lock_file, owner_table_exists, path_identity, path_text, read_u64,
    sqlite_u64, validate_database_identity, validate_database_metadata,
    validate_database_path_component, validate_lock_metadata, validate_open_lock_file,
    validate_provisioning_record, validate_secure_directory, validate_uuid_v7,
    verify_authority_store_invariants, verify_serving_owner_schema, SchemaCatalogEntry,
    SqliteAuthorityStore, SqliteServingOwnerError,
};
use crate::admission_operation_store::verify_admission_commit_chain;

pub const RELOCATION_SEAL_FORMAT: &str = "chio.sqlite-authority-relocation-seal.v1";

const SERVING_RELOCATION_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS chio_serving_relocation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    state TEXT NOT NULL CHECK (state IN ('exported', 'imported')),
    export_id TEXT NOT NULL CHECK (export_id <> ''),
    exported_at_ms INTEGER NOT NULL CHECK (exported_at_ms > 0),
    exported_owner_epoch INTEGER NOT NULL CHECK (exported_owner_epoch >= 0),
    exported_admission_head INTEGER NOT NULL CHECK (exported_admission_head >= 0),
    exported_admission_digest TEXT NOT NULL CHECK (exported_admission_digest <> ''),
    exported_global_head INTEGER NOT NULL CHECK (exported_global_head >= 0),
    exported_global_digest TEXT NOT NULL CHECK (exported_global_digest <> ''),
    import_id TEXT CHECK (import_id IS NULL OR import_id <> ''),
    imported_at_ms INTEGER CHECK (imported_at_ms IS NULL OR imported_at_ms > 0),
    CHECK ((state = 'exported') = (import_id IS NULL AND imported_at_ms IS NULL))
);
"#;

/// The commit chain heads an exported store carried when it was retired.
/// A copy must reproduce exactly these heads and digests to be imported.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelocationSeal {
    pub format: String,
    pub store_uuid: String,
    pub export_id: String,
    pub exported_at_ms: u64,
    pub owner_epoch: u64,
    pub admission_commit_head: u64,
    pub admission_commit_chain_digest: String,
    pub global_commit_head: u64,
    pub global_commit_chain_digest: String,
}

/// The outcome of re-anchoring an exported copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelocationImport {
    pub seal: RelocationSeal,
    pub import_id: String,
}

pub(super) enum RelocationState {
    Unmoved,
    Exported(RelocationSeal),
    Imported,
}

pub(super) fn initialize_serving_relocation_schema(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    connection.execute_batch(SERVING_RELOCATION_SCHEMA)?;
    verify_serving_relocation_schema(connection)
}

pub(super) fn verify_serving_relocation_schema(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SERVING_RELOCATION_SCHEMA)?;
    if relocation_schema_catalog(connection)? != relocation_schema_catalog(&expected)? {
        return Err(SqliteServingOwnerError::Invalid(
            "serving relocation schema differs from the canonical definition".to_string(),
        ));
    }
    Ok(())
}

fn relocation_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, SqliteServingOwnerError> {
    let mut statement = connection.prepare(
        r#"
        SELECT type, name, tbl_name, sql FROM sqlite_schema
        WHERE name = 'chio_serving_relocation' OR tbl_name = 'chio_serving_relocation'
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

/// The relocation record, or `Unmoved` for a store created before relocation
/// existed. Reading never creates the table, so a refusal performs no write.
pub(super) fn relocation_state(
    connection: &Connection,
) -> Result<RelocationState, SqliteServingOwnerError> {
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'chio_serving_relocation')",
        [],
        |row| row.get(0),
    )?;
    if !present {
        return Ok(RelocationState::Unmoved);
    }
    let row = connection
        .query_row(
            r#"
            SELECT state, export_id, exported_at_ms, exported_owner_epoch,
                   exported_admission_head, exported_admission_digest,
                   exported_global_head, exported_global_digest, import_id
            FROM chio_serving_relocation WHERE singleton = 1
            "#,
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(RelocationState::Unmoved);
    };
    let store_uuid: String = connection.query_row(
        "SELECT store_uuid FROM chio_serving_owner WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let seal = RelocationSeal {
        format: RELOCATION_SEAL_FORMAT.to_string(),
        store_uuid,
        export_id: row.1.clone(),
        exported_at_ms: read_u64(row.2, "exported_at_ms")?,
        owner_epoch: read_u64(row.3, "exported_owner_epoch")?,
        admission_commit_head: read_u64(row.4, "exported_admission_head")?,
        admission_commit_chain_digest: row.5,
        global_commit_head: read_u64(row.6, "exported_global_head")?,
        global_commit_chain_digest: row.7,
    };
    validate_uuid_v7(&seal.export_id, "relocation export ID")?;
    match (row.0.as_str(), row.8) {
        ("exported", None) => Ok(RelocationState::Exported(seal)),
        ("imported", Some(import_id)) => {
            validate_uuid_v7(&import_id, "relocation import ID")?;
            Ok(RelocationState::Imported)
        }
        _ => Err(SqliteServingOwnerError::Invalid(
            "serving relocation record is inconsistent".to_string(),
        )),
    }
}

/// Serving and re-provisioning stop at an exported store until it is imported.
/// Callers check before their first write so a refused open leaves the
/// exported file byte-identical to its manifest.
pub(super) fn refuse_exported(connection: &Connection) -> Result<(), SqliteServingOwnerError> {
    match relocation_state(connection)? {
        RelocationState::Exported(seal) => Err(SqliteServingOwnerError::Exported(seal.export_id)),
        RelocationState::Unmoved | RelocationState::Imported => Ok(()),
    }
}

fn next_relocation_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

impl SqliteAuthorityStore {
    /// Retire this store at its current location and seal its commit chain
    /// heads so a byte-identical copy can be imported elsewhere.
    ///
    /// Requires a stopped store: the serving lock must be free. After this
    /// returns, `open_serving` and `provision` refuse the store at this path
    /// until an import re-anchors it. The write-ahead log is checkpointed and
    /// truncated so the database file alone carries the sealed state.
    pub fn export_for_relocation(
        database_path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
    ) -> Result<RelocationSeal, SqliteServingOwnerError> {
        Self::ensure_serving_supported()?;
        let database_path = database_path.as_ref();
        validate_database_path_component(database_path)?;
        let database_path = fs::canonicalize(database_path)?;
        let lock_root = canonical_lock_root(lock_root.as_ref())?;
        let root_lock = File::open(&lock_root)?;
        root_lock.lock()?;
        validate_secure_directory(database_parent(&database_path), "authority database parent")?;
        let expected_database = fs::metadata(&database_path)?;
        let mut connection = open_existing_database(&database_path)?;
        validate_database_identity(&database_path, &expected_database)?;
        if !owner_table_exists(&connection)? {
            return Err(SqliteServingOwnerError::NotProvisioned(path_text(
                &database_path,
            )?));
        }
        verify_serving_owner_schema(&connection)?;
        let record = load_provisioning_record(&connection)?.ok_or_else(|| {
            SqliteServingOwnerError::PartialProvision(database_path.display().to_string())
        })?;
        validate_provisioning_record(&database_path, &lock_root, &record)?;
        path_identity::inspect(&lock_root, &database_path, Some(&record.store_uuid))?;
        let lock_path = lock_root.join(format!("{}.lock", record.store_uuid));
        let lock_file = open_lock_file(&lock_path)?;
        validate_open_lock_file(&lock_root, &lock_file, &record)?;
        acquire_serving_lock(&lock_file, &database_path)?;
        validate_open_lock_file(&lock_root, &lock_file, &record)?;
        validate_provisioning_record(&database_path, &lock_root, &record)?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;
            "#,
        )?;
        initialize_serving_lease_schema(&connection)?;
        initialize_serving_relocation_schema(&connection)?;
        if let RelocationState::Exported(seal) = relocation_state(&connection)? {
            return Err(SqliteServingOwnerError::Exported(seal.export_id));
        }
        verify_authority_store_invariants(&connection)?;
        let rollback_anchor = RollbackAnchor::new(
            lock_file,
            &lock_root,
            &record.store_uuid,
            record.lock_device,
            record.lock_inode,
        )?;
        rollback_anchor.reconcile_startup(&connection)?;
        let admission = verify_admission_commit_chain(&connection)?;
        let global = verify_global_commit_chain(&connection)?;
        let seal = RelocationSeal {
            format: RELOCATION_SEAL_FORMAT.to_string(),
            store_uuid: record.store_uuid.clone(),
            export_id: next_relocation_id(),
            exported_at_ms: read_u64(now_ms()?, "exported_at_ms")?,
            owner_epoch: record.owner_epoch,
            admission_commit_head: admission.head_sequence,
            admission_commit_chain_digest: admission.chain_digest,
            global_commit_head: global.head_sequence,
            global_commit_chain_digest: global.chain_digest,
        };
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_provisioning_record_tx(&transaction)?.ok_or_else(|| {
            SqliteServingOwnerError::NotProvisioned(database_path.display().to_string())
        })?;
        if current.store_uuid != record.store_uuid || current.owner_epoch != record.owner_epoch {
            return Err(SqliteServingOwnerError::AlreadyServing(
                "serving owner changed while exporting".to_string(),
            ));
        }
        let changed = transaction.execute(
            r#"
            INSERT OR REPLACE INTO chio_serving_relocation (
                singleton, state, export_id, exported_at_ms, exported_owner_epoch,
                exported_admission_head, exported_admission_digest,
                exported_global_head, exported_global_digest, import_id, imported_at_ms
            ) VALUES (1, 'exported', ?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL)
            "#,
            params![
                &seal.export_id,
                sqlite_u64(seal.exported_at_ms, "exported_at_ms")?,
                sqlite_u64(seal.owner_epoch, "exported_owner_epoch")?,
                sqlite_u64(seal.admission_commit_head, "exported_admission_head")?,
                &seal.admission_commit_chain_digest,
                sqlite_u64(seal.global_commit_head, "exported_global_head")?,
                &seal.global_commit_chain_digest,
            ],
        )?;
        if changed != 1 {
            return Err(SqliteServingOwnerError::Invalid(
                "relocation export did not record exactly one seal".to_string(),
            ));
        }
        verify_authority_store_invariants(&transaction)?;
        transaction.commit().map_err(|error| {
            SqliteServingOwnerError::OutcomeUnknown(format!(
                "sqlite relocation export commit outcome is unknown: {error}"
            ))
        })?;
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        File::open(&database_path)?.sync_all()?;
        File::open(database_parent(&database_path))?.sync_all()?;
        validate_database_identity(&database_path, &expected_database)?;
        Ok(seal)
    }

    /// Re-anchor an exported copy at `database_path`, binding the serving
    /// owner to this location and creating fresh lock artifacts in `lock_root`.
    ///
    /// The copy must reproduce the sealed commit chain heads exactly; a copy
    /// taken behind the export, or a store that was never exported, is
    /// refused. Lock files and identity markers copied from the previous
    /// location are replaced, and an interrupted import can be repeated.
    pub fn import_relocated(
        database_path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
    ) -> Result<RelocationImport, SqliteServingOwnerError> {
        Self::ensure_serving_supported()?;
        let database_path = database_path.as_ref();
        validate_database_path_component(database_path)?;
        let database_path = fs::canonicalize(database_path)?;
        let lock_root = canonical_lock_root(lock_root.as_ref())?;
        let root_lock = File::open(&lock_root)?;
        root_lock.lock()?;
        validate_secure_directory(database_parent(&database_path), "authority database parent")?;
        let expected_database = fs::metadata(&database_path)?;
        let mut connection = open_existing_database(&database_path)?;
        validate_database_identity(&database_path, &expected_database)?;
        if !owner_table_exists(&connection)? {
            return Err(SqliteServingOwnerError::NotProvisioned(path_text(
                &database_path,
            )?));
        }
        verify_serving_owner_schema(&connection)?;
        let record = load_provisioning_record(&connection)?.ok_or_else(|| {
            SqliteServingOwnerError::PartialProvision(database_path.display().to_string())
        })?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;
            "#,
        )?;
        initialize_serving_lease_schema(&connection)?;
        initialize_serving_relocation_schema(&connection)?;
        let seal = match relocation_state(&connection)? {
            RelocationState::Exported(seal) => seal,
            RelocationState::Unmoved => {
                return Err(SqliteServingOwnerError::Invalid(
                    "authority store was not exported for relocation".to_string(),
                ))
            }
            RelocationState::Imported => {
                return Err(SqliteServingOwnerError::Invalid(
                    "authority store was already imported; export it again before moving it"
                        .to_string(),
                ))
            }
        };
        let admission = verify_admission_commit_chain(&connection)?;
        let global = verify_global_commit_chain(&connection)?;
        if record.store_uuid != seal.store_uuid
            || record.owner_epoch != seal.owner_epoch
            || admission.head_sequence != seal.admission_commit_head
            || admission.chain_digest != seal.admission_commit_chain_digest
            || global.head_sequence != seal.global_commit_head
            || global.chain_digest != seal.global_commit_chain_digest
        {
            return Err(SqliteServingOwnerError::Invalid(
                "authority store content does not match its relocation seal".to_string(),
            ));
        }
        verify_authority_store_invariants(&connection)?;

        // Lock artifacts belong to the previous location; nothing serves an
        // exported store, so they are replaced rather than reused.
        let lock_path = lock_root.join(format!("{}.lock", record.store_uuid));
        remove_previous_lock_artifacts(&lock_root, &lock_path)?;
        let lock_file = create_lock_file(&lock_path)?;
        let lock_metadata = lock_file.metadata()?;
        validate_lock_metadata(&lock_root, &lock_metadata)?;
        lock_file.sync_all()?;
        File::open(&lock_root)?.sync_all()?;
        acquire_serving_lock(&lock_file, &database_path)?;
        let rollback_anchor = RollbackAnchor::new(
            lock_file,
            &lock_root,
            &record.store_uuid,
            read_u64(metadata_device(&lock_metadata)?, "lock_device")?,
            read_u64(metadata_inode(&lock_metadata)?, "lock_inode")?,
        )?;
        rollback_anchor.seed_new(&connection)?;

        let database_metadata = fs::metadata(&database_path)?;
        validate_database_metadata(&database_metadata)?;
        let import_id = next_relocation_id();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            r#"
            UPDATE chio_serving_owner
            SET database_path = ?1, database_device = ?2, database_inode = ?3,
                lock_root = ?4, lock_device = ?5, lock_inode = ?6
            WHERE singleton = 1 AND store_uuid = ?7 AND owner_epoch = ?8
            "#,
            params![
                path_text(&database_path)?,
                metadata_device(&database_metadata)?,
                metadata_inode(&database_metadata)?,
                path_text(&lock_root)?,
                metadata_device(&lock_metadata)?,
                metadata_inode(&lock_metadata)?,
                &record.store_uuid,
                sqlite_u64(record.owner_epoch, "owner_epoch")?,
            ],
        )?;
        if changed != 1 {
            return Err(SqliteServingOwnerError::AlreadyServing(
                "serving owner changed while importing".to_string(),
            ));
        }
        let marked = transaction.execute(
            r#"
            UPDATE chio_serving_relocation
            SET state = 'imported', import_id = ?1, imported_at_ms = ?2
            WHERE singleton = 1 AND state = 'exported' AND export_id = ?3
            "#,
            params![&import_id, now_ms()?, &seal.export_id],
        )?;
        if marked != 1 {
            return Err(SqliteServingOwnerError::Invalid(
                "relocation import did not close exactly one export".to_string(),
            ));
        }
        verify_authority_store_invariants(&transaction)?;
        transaction.commit().map_err(|error| {
            SqliteServingOwnerError::OutcomeUnknown(format!(
                "sqlite relocation import commit outcome is unknown: {error}"
            ))
        })?;
        rollback_anchor.sync_after_commit(&connection)?;
        path_identity::ensure(&lock_root, &database_path, &record.store_uuid)?;
        File::open(&database_path)?.sync_all()?;
        File::open(database_parent(&database_path))?.sync_all()?;
        validate_database_identity(&database_path, &expected_database)?;
        Ok(RelocationImport { seal, import_id })
    }
}

fn remove_previous_lock_artifacts(
    lock_root: &Path,
    lock_path: &Path,
) -> Result<(), SqliteServingOwnerError> {
    for entry in fs::read_dir(lock_root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let stale_marker = name.starts_with(".chio-path-") && name.ends_with(".identity");
        if entry.path() == lock_path || stale_marker {
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.file_type().is_file() {
                return Err(SqliteServingOwnerError::Invalid(
                    "previous lock artifact is not a regular file".to_string(),
                ));
            }
            fs::remove_file(entry.path())?;
        }
    }
    File::open(lock_root)?.sync_all()?;
    Ok(())
}
