//! Relocation of a provisioned authority store to another path or host.
//!
//! The serving owner binds an authority database to its canonical path and to
//! the inodes of the database and its serving lock, so a copied or restored
//! database refuses to serve. Relocation is the sanctioned way to move that
//! binding: `export` retires the store where it is and seals its commit chain
//! heads, and `import` re-anchors a byte-identical copy at its new location
//! after proving the copy matches the seal. An exported store does not serve
//! again until an import re-anchors it. Import replaces a destination's lock
//! artifacts only when its rollback anchor records nothing beyond the
//! exported state and its lock root has not bound the destination path to
//! the store; only the export's own location, still holding its retirement
//! record, is imported over its provisioning binding. A retained copy of the
//! export can therefore retry an import that stopped before its database
//! commit, but once an import commits at a destination every further import
//! of that export there is refused, even after its anchor is emptied or
//! truncated. Restoring or deleting the lock root removes that evidence with
//! the anchor. Imports under distinct lock roots are not coordinated: each is
//! its own serving lineage, sharing history only up to the seal.

use chio_security_types::clock::{Clock, ClockError, SystemClock, UnixMillis};
use std::fs::{self, File};
use std::path::Path;
use std::sync::Arc;

use rusqlite::{config::DbConfig, params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::global_commit_chain::verify_global_commit_chain;
use super::lease_history::initialize_serving_lease_schema;
use super::rollback_anchor::{ReplaceableAnchor, RollbackAnchor};
use super::{
    acquire_serving_lock, canonical_lock_root, create_lock_file, database_parent,
    load_provisioning_record, load_provisioning_record_tx, metadata_device, metadata_inode,
    open_existing_database, open_lock_file, owner_table_exists, path_identity, path_text, read_u64,
    sqlite_u64, validate_database_identity, validate_database_metadata,
    validate_database_path_component, validate_lock_metadata, validate_open_lock_file,
    validate_provisioning_record, validate_secure_directory, validate_uuid_v7,
    verify_authority_store_invariants, verify_serving_owner_schema, ProvisioningRecord,
    SchemaCatalogEntry, SqliteAuthorityStore, SqliteServingOwnerError,
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

/// Import state qualified under the relocation lock before caller verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationImportPhase {
    /// The authority must still match its original exported file bytes.
    Exported,
    /// The same seal has committed at this inode/location with verified custody.
    /// Its authority WAL may contain that commit; application files still need verification.
    Committed,
}

pub(super) enum RelocationState {
    Unmoved,
    Exported(RelocationSeal),
    Imported(RelocationImport),
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
            Ok(RelocationState::Imported(RelocationImport {
                seal,
                import_id,
            }))
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
        RelocationState::Unmoved | RelocationState::Imported(_) => Ok(()),
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
    /// truncated so the database file alone carries the sealed state. Repeating
    /// an export returns the same verified seal and finishes its checkpoint,
    /// allowing a host to recover a failure while writing its manifest.
    pub fn export_for_relocation(
        database_path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
    ) -> Result<RelocationSeal, SqliteServingOwnerError> {
        Self::export_for_relocation_with_clock(database_path, lock_root, Arc::new(SystemClock))
    }

    /// Execute this offline composition command with the supplied time authority.
    pub fn export_for_relocation_with_clock(
        database_path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
        clock: Arc<dyn Clock>,
    ) -> Result<RelocationSeal, SqliteServingOwnerError> {
        Self::ensure_serving_supported()?;
        let clock = crate::store_clock::StoreClock::new(clock);
        clock.unix_millis()?;
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
        let prior_export = match relocation_state(&connection)? {
            RelocationState::Exported(seal) => Some(seal),
            _ => None,
        };
        verify_authority_store_invariants(&connection)?;
        let rollback_anchor = RollbackAnchor::new(
            lock_file,
            &lock_root,
            &record.store_uuid,
            record.lock_device,
            record.lock_inode,
        )?;
        let admission = verify_admission_commit_chain(&connection)?;
        let global = verify_global_commit_chain(&connection)?;
        relocation_time(
            &clock,
            &connection,
            admission.trusted_time_high_water_unix_ms,
        )?;
        rollback_anchor.reconcile_startup(&connection)?;
        if let Some(seal) = prior_export {
            if seal.store_uuid != record.store_uuid
                || seal.owner_epoch != record.owner_epoch
                || seal.admission_commit_head != admission.head_sequence
                || seal.admission_commit_chain_digest != admission.chain_digest
                || seal.global_commit_head != global.head_sequence
                || seal.global_commit_chain_digest != global.chain_digest
            {
                return Err(SqliteServingOwnerError::Invalid(
                    "authority store content does not match its relocation seal".to_string(),
                ));
            }
            finish_export(&connection, &database_path, &expected_database)?;
            return Ok(seal);
        }
        let seal = RelocationSeal {
            format: RELOCATION_SEAL_FORMAT.to_string(),
            store_uuid: record.store_uuid.clone(),
            export_id: next_relocation_id(),
            exported_at_ms: relocation_time(
                &clock,
                &connection,
                admission.trusted_time_high_water_unix_ms,
            )?
            .get(),
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
        // Retirement is protected outside SQLite before an export can be
        // acknowledged. Restoring an older database cannot erase this fence.
        rollback_anchor.sync_after_commit(&connection)?;
        finish_export(&connection, &database_path, &expected_database)?;
        Ok(seal)
    }

    /// Re-anchor an exported copy at `database_path`, binding the serving
    /// owner to this location and creating fresh lock artifacts in `lock_root`.
    ///
    /// The copy must reproduce the sealed commit chain heads exactly; a copy
    /// taken behind the export, or a store that was never exported, is
    /// refused. Lock files and identity markers copied from the previous
    /// location are replaced, and an interrupted import can be repeated. A
    /// destination whose rollback anchor records history beyond the seal, or
    /// whose lock root already bound it to the store through a committed
    /// import, is refused with `RelocationDestinationAnchored`, leaving its
    /// anchor, lock and identity markers untouched.
    pub fn import_relocated(
        database_path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
    ) -> Result<RelocationImport, SqliteServingOwnerError> {
        Self::import_relocated_with_clock(database_path, lock_root, Arc::new(SystemClock))
    }

    /// Execute this offline composition command with the supplied time authority.
    pub fn import_relocated_with_clock(
        database_path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
        clock: Arc<dyn Clock>,
    ) -> Result<RelocationImport, SqliteServingOwnerError> {
        Self::import_relocated_inner(database_path, lock_root, None, |_| Ok(()), clock)
    }

    /// Verify an external manifest before the first import mutation. A retry
    /// after the import committed validates the same seal and current location,
    /// and only finishes the anchor and path marker; it never re-anchors a copy
    /// of imported state or a store that has since served. The caller must
    /// verify its application files on every attempt.
    pub fn import_relocated_checked(
        database_path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
        expected: &RelocationSeal,
        verify_exported: impl FnOnce() -> Result<(), SqliteServingOwnerError>,
    ) -> Result<RelocationImport, SqliteServingOwnerError> {
        Self::import_relocated_checked_with_clock(
            database_path,
            lock_root,
            expected,
            verify_exported,
            Arc::new(SystemClock),
        )
    }

    /// Execute this offline composition command with the supplied time authority.
    pub fn import_relocated_checked_with_clock(
        database_path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
        expected: &RelocationSeal,
        verify_exported: impl FnOnce() -> Result<(), SqliteServingOwnerError>,
        clock: Arc<dyn Clock>,
    ) -> Result<RelocationImport, SqliteServingOwnerError> {
        Self::import_relocated_inner(
            database_path,
            lock_root,
            Some(expected),
            |phase| {
                if phase == RelocationImportPhase::Exported {
                    verify_exported()?;
                }
                Ok(())
            },
            clock,
        )
    }

    /// Verify all relocated files after the store qualifies the import phase.
    /// The callback runs before import or recovery writes, including checkpoint
    /// on close. Only a verified same-location committed import receives
    /// `Committed`; callers must still verify application files on that path.
    pub fn import_relocated_checked_with_phase(
        database_path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
        expected: &RelocationSeal,
        verify_files: impl FnOnce(RelocationImportPhase) -> Result<(), SqliteServingOwnerError>,
    ) -> Result<RelocationImport, SqliteServingOwnerError> {
        Self::import_relocated_checked_with_phase_and_clock(
            database_path,
            lock_root,
            expected,
            verify_files,
            Arc::new(SystemClock),
        )
    }

    /// Execute this offline composition command with the supplied time authority.
    pub fn import_relocated_checked_with_phase_and_clock(
        database_path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
        expected: &RelocationSeal,
        verify_files: impl FnOnce(RelocationImportPhase) -> Result<(), SqliteServingOwnerError>,
        clock: Arc<dyn Clock>,
    ) -> Result<RelocationImport, SqliteServingOwnerError> {
        Self::import_relocated_inner(
            database_path,
            lock_root,
            Some(expected),
            verify_files,
            clock,
        )
    }

    fn import_relocated_inner(
        database_path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
        expected: Option<&RelocationSeal>,
        verify_files: impl FnOnce(RelocationImportPhase) -> Result<(), SqliteServingOwnerError>,
        clock: Arc<dyn Clock>,
    ) -> Result<RelocationImport, SqliteServingOwnerError> {
        Self::ensure_serving_supported()?;
        let clock = crate::store_clock::StoreClock::new(clock);
        clock.unix_millis()?;
        let database_path = database_path.as_ref();
        validate_database_path_component(database_path)?;
        let database_path = fs::canonicalize(database_path)?;
        let lock_root = canonical_lock_root(lock_root.as_ref())?;
        let root_lock = File::open(&lock_root)?;
        root_lock.lock()?;
        validate_secure_directory(database_parent(&database_path), "authority database parent")?;
        let expected_database = fs::metadata(&database_path)?;
        let mut connection = open_existing_database(&database_path)?;
        // Merely reading a WAL can make an ordinary connection checkpoint it
        // during drop. A refused seal/location/file check must not do that.
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
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
        let (seal, imported_id) = match relocation_state(&connection)? {
            RelocationState::Exported(seal) => (seal, None),
            RelocationState::Imported(imported) => (imported.seal, Some(imported.import_id)),
            RelocationState::Unmoved => {
                return Err(SqliteServingOwnerError::Invalid(
                    "authority store was not exported for relocation".to_string(),
                ));
            }
        };
        relocation_time(&clock, &connection, seal.exported_at_ms)?;
        if expected.is_some_and(|expected| *expected != seal) {
            return Err(SqliteServingOwnerError::Invalid(
                "authority seal differs from the relocation manifest".to_string(),
            ));
        }
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

        if let Some(import_id) = imported_id {
            // The database commit already bound this inode and location. Keep
            // those artifacts and finish only the fallible post-commit writes.
            validate_provisioning_record(&database_path, &lock_root, &record)?;
            let lock_file = open_lock_file(&lock_root.join(format!("{}.lock", record.store_uuid)))?;
            validate_open_lock_file(&lock_root, &lock_file, &record)?;
            acquire_serving_lock(&lock_file, &database_path)?;
            let anchor = RollbackAnchor::new(
                lock_file,
                &lock_root,
                &record.store_uuid,
                record.lock_device,
                record.lock_inode,
            )?;
            anchor.verify_extends(&connection, &anchor.committed_record()?)?;
            verify_files(RelocationImportPhase::Committed)?;
            relocation_time(
                &clock,
                &connection,
                seal.exported_at_ms
                    .max(admission.trusted_time_high_water_unix_ms),
            )?;
            connection.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, false)?;
            anchor.reconcile_startup(&connection)?;
            path_identity::ensure(&lock_root, &database_path, &record.store_uuid)?;
            File::open(&database_path)?.sync_all()?;
            File::open(database_parent(&database_path))?.sync_all()?;
            validate_database_identity(&database_path, &expected_database)?;
            return Ok(RelocationImport { seal, import_id });
        }

        // An existing anchor at the destination may record a lineage that
        // served after an earlier import of this export. It is replaced only
        // when it records nothing beyond the exported state, and it stays
        // locked until the replacement is created.
        let lock_path = lock_root.join(format!("{}.lock", record.store_uuid));
        let previous_anchor = lock_replaceable_anchor(
            &lock_root,
            &lock_path,
            &database_path,
            &record.store_uuid,
            &connection,
        )?;
        verify_files(RelocationImportPhase::Exported)?;
        relocation_time(
            &clock,
            &connection,
            seal.exported_at_ms
                .max(admission.trusted_time_high_water_unix_ms),
        )?;
        refuse_bound_destination(
            &lock_root,
            &database_path,
            &record,
            previous_anchor.as_ref().map(|(_, image)| *image),
        )?;
        // Verification refusals are read-only. From here, authorized I/O can
        // partially complete and retains the normal import retry semantics.
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, false)?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;",
        )?;
        remove_previous_lock_artifacts(
            &lock_root,
            &lock_path,
            &database_path,
            Path::new(&record.database_path),
            &record.store_uuid,
            previous_anchor.as_ref().map(|(anchor, _)| anchor),
        )?;
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
            params![
                &import_id,
                i64::try_from(
                    relocation_time(
                        &clock,
                        &transaction,
                        seal.exported_at_ms
                            .max(admission.trusted_time_high_water_unix_ms)
                    )?
                    .get()
                )
                .map_err(|_| ClockError::Overflow)?,
                &seal.export_id
            ],
        )?;
        if marked != 1 {
            return Err(SqliteServingOwnerError::Invalid(
                "relocation import did not close exactly one export".to_string(),
            ));
        }
        verify_authority_store_invariants(&transaction)?;
        // Seed the new location with the imported state. Seeding the exported
        // source state would carry its permanent retirement fence here.
        rollback_anchor.seed_new(&transaction)?;
        #[cfg(test)]
        if import_commit_cutpoint::take() {
            return Err(SqliteServingOwnerError::OutcomeUnknown(
                "relocation import stopped before its database commit".to_string(),
            ));
        }
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

/// Lock the destination's existing serving lock and prove its rollback anchor
/// records nothing beyond the exported state. Reads only; a refusal leaves the
/// anchor, the lock and the path markers untouched.
fn lock_replaceable_anchor(
    lock_root: &Path,
    lock_path: &Path,
    database_path: &Path,
    store_uuid: &str,
    connection: &Connection,
) -> Result<Option<(RollbackAnchor, ReplaceableAnchor)>, SqliteServingOwnerError> {
    match fs::symlink_metadata(lock_path) {
        Ok(_) => {
            let file = open_lock_file(lock_path)?;
            let metadata = file.metadata()?;
            validate_lock_metadata(lock_root, &metadata)?;
            acquire_serving_lock(&file, database_path)?;
            let anchor = RollbackAnchor::new(
                file,
                lock_root,
                store_uuid,
                read_u64(metadata_device(&metadata)?, "lock_device")?,
                read_u64(metadata_inode(&metadata)?, "lock_inode")?,
            )?;
            let image = anchor.verify_replaceable_by_export(connection)?;
            Ok(Some((anchor, image)))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Refuse a destination path this lock root already bound to the authority.
///
/// A marker created in place for the destination is written only after
/// provisioning, serving or an import commits there, and an interrupted
/// import removes it before it seeds a new anchor. The exported store's own
/// location, still holding its retirement record, carries its provisioning
/// marker into an in-place import. Anywhere else the marker proves the
/// destination committed a lineage that an emptied or truncated anchor may
/// no longer show, so the exported copy cannot replace it.
fn refuse_bound_destination(
    lock_root: &Path,
    database_path: &Path,
    record: &ProvisioningRecord,
    anchor: Option<ReplaceableAnchor>,
) -> Result<(), SqliteServingOwnerError> {
    let retired_source = Path::new(&record.database_path) == database_path
        && Path::new(&record.lock_root) == lock_root
        && anchor == Some(ReplaceableAnchor::Retirement);
    if !retired_source
        && path_identity::bound_in_place(lock_root, database_path, &record.store_uuid)?
    {
        return Err(SqliteServingOwnerError::RelocationDestinationAnchored(
            path_identity::marker_path(lock_root, database_path)?
                .display()
                .to_string(),
        ));
    }
    Ok(())
}

/// Lock artifacts belong to the previous location or to an import of this
/// export that never served, so they are replaced rather than reused. The
/// lock removed is the one whose anchor was proven replaceable.
fn remove_previous_lock_artifacts(
    lock_root: &Path,
    lock_path: &Path,
    database_path: &Path,
    previous_database_path: &Path,
    store_uuid: &str,
    previous_anchor: Option<&RollbackAnchor>,
) -> Result<(), SqliteServingOwnerError> {
    if let Some(anchor) = previous_anchor {
        anchor.validate_identity()?;
    }
    path_identity::remove_for_relocation(
        lock_root,
        previous_database_path,
        store_uuid,
        previous_database_path != database_path,
    )?;
    if previous_database_path != database_path {
        path_identity::remove_for_relocation(lock_root, database_path, store_uuid, false)?;
    }
    if previous_anchor.is_some() {
        fs::remove_file(lock_path)?;
    }
    File::open(lock_root)?.sync_all()?;
    Ok(())
}

/// Stops the next import on this thread after it seeds its anchor and before
/// its database commit, leaving the image a crash at that point leaves.
#[cfg(test)]
pub(super) mod import_commit_cutpoint {
    use std::cell::Cell;

    thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
    }

    pub(in crate::serving_owner) fn arm() {
        ARMED.with(|armed| armed.set(true));
    }

    pub(super) fn take() -> bool {
        ARMED.with(|armed| armed.replace(false))
    }
}

/// Bound offline relocation time to retained serving and admission history.
fn relocation_time(
    clock: &crate::store_clock::StoreClock,
    connection: &Connection,
    durable_floor: u64,
) -> Result<UnixMillis, SqliteServingOwnerError> {
    let opened_at: i64 = connection.query_row(
        "SELECT COALESCE(opened_at_ms, 0) FROM chio_serving_owner WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let floor = read_u64(opened_at, "opened_at_ms")?.max(durable_floor);
    let observed = clock.unix_millis()?;
    observed.duration_since(UnixMillis::new(floor))?;
    i64::try_from(observed.get()).map_err(|_| ClockError::Overflow)?;
    Ok(observed)
}

/// SQLite reports a busy checkpoint as a result row, not an execution error.
fn finish_export(
    connection: &Connection,
    database: &Path,
    expected: &fs::Metadata,
) -> Result<(), SqliteServingOwnerError> {
    let busy: i64 =
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
    if busy != 0 {
        return Err(SqliteServingOwnerError::Invalid(
            "relocation checkpoint is busy".to_string(),
        ));
    }
    File::open(database)?.sync_all()?;
    File::open(database_parent(database))?.sync_all()?;
    validate_database_identity(database, expected)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn resumed_export_finalization_refuses_a_replaced_database_inode(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("authority.db");
        let connection = Connection::open(&database)?;
        connection.execute_batch(
            "CREATE TABLE retained(value INTEGER); INSERT INTO retained VALUES(1);",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&database, fs::Permissions::from_mode(0o600))?;
        }
        let expected = fs::metadata(&database)?;
        finish_export(&connection, &database, &expected)?;
        let original = directory.path().join("original.db");
        fs::rename(&database, &original)?;
        fs::copy(&original, &database)?;
        let refused = finish_export(&connection, &database, &expected);
        assert!(
            matches!(refused, Err(SqliteServingOwnerError::Invalid(ref reason)) if reason.contains("identity changed")),
            "{refused:?}"
        );
        assert_eq!(fs::read(&database)?, fs::read(&original)?);
        Ok(())
    }
}
