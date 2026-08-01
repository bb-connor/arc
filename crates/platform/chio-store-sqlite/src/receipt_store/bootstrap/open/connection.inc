/// Identity of one store instance for the rows it journals, distinct across
/// every open of every process (a fresh UUID, never persisted or reused).
/// Reconciliation treats a row carrying a different token as another
/// instance's work, so nothing about the token needs to survive a restart:
/// a restarted instance's previous rows are foreign to it by construction,
/// exactly as a crashed sibling's are.
fn fresh_instance_token() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Mark this instance as a live writer on the database file: a shared
/// advisory lock on a sidecar file, plus an exclusive lock on a per-owner
/// mark named by `instance_token`, both held for the store's lifetime and
/// released by the OS when the process exits, cleanly or not.
/// Dispatch-intent reconciliation reads liveness from these marks before
/// claiming open intents as orphans: a foreign row's owner is probed
/// through its own per-owner mark, and a row naming no probeable owner is
/// claimed only after converting the shared mark to exclusive, proving no
/// sibling writer instance at all. Probes and conversions happen only
/// under the sibling-serializing probe mutex at `probe_path` (see
/// `WriterLifetimeLock`). Taking the shared mark blocks only while a
/// sibling holds the exclusive conversion for the duration of its bounded
/// reconcile pass. In-memory databases have no on-disk file to coordinate
/// on and take no locks.
fn acquire_writer_lifetime_lock(
    path: &Path,
    instance_token: &str,
) -> Result<Option<WriterLifetimeLock>, ReceiptStoreError> {
    let (Some(lock_path), Some(probe_path), Some(owner_mark_path)) = (
        crate::sqlite_writer_lock_path(path),
        crate::sqlite_reconcile_lock_path(path),
        crate::sqlite_owner_mark_path(path, instance_token),
    ) else {
        return Ok(None);
    };
    let mark = open_sidecar_lock_file(&lock_path)?;
    mark.lock_shared()?;
    // The owner mark is held before the store can journal a single row, so
    // a reconcile probe that acquires it is proof this owner journals
    // nothing further. A fresh UUID cannot be contended; refuse rather
    // than share.
    let owner_lock = open_sidecar_lock_file(&owner_mark_path)?;
    match owner_lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err(ReceiptStoreError::Conflict(format!(
                "owner liveness mark for a fresh store open is already held: {}",
                owner_mark_path.display()
            )));
        }
        Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    Ok(Some(WriterLifetimeLock {
        mark,
        probe_path,
        database_path: path.to_path_buf(),
        _owner_mark: OwnerLivenessMark::new(owner_lock, owner_mark_path),
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReceiptConnectionOpenStage {
    Initial,
    Pool,
}

fn open_receipt_connection(
    path: &Path,
    flags: rusqlite::OpenFlags,
    stage: ReceiptConnectionOpenStage,
) -> Result<Connection, rusqlite::Error> {
    #[cfg(test)]
    connection_open_test_hooks::before_open(path, stage)
        .map_err(rusqlite::Error::InvalidParameterName)?;
    let opened = Connection::open_with_flags(path, flags);
    #[cfg(test)]
    connection_open_test_hooks::after_open(path, stage)
        .map_err(rusqlite::Error::InvalidParameterName)?;
    #[cfg(not(test))]
    let _ = stage;
    opened
}

#[cfg(test)]
pub(crate) mod connection_open_test_hooks {
    use super::ReceiptConnectionOpenStage;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::{LazyLock, Mutex};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SwapState {
        Installed,
        Swapped,
        Completed,
    }

    #[derive(Debug)]
    struct SwapHook {
        stage: ReceiptConnectionOpenStage,
        replacement: PathBuf,
        displaced: PathBuf,
        state: SwapState,
    }

    static SWAPS: LazyLock<Mutex<BTreeMap<PathBuf, SwapHook>>> =
        LazyLock::new(|| Mutex::new(BTreeMap::new()));

    pub(crate) fn install(
        path: PathBuf,
        replacement: PathBuf,
        displaced: PathBuf,
        stage: ReceiptConnectionOpenStage,
    ) -> Result<(), String> {
        if path == replacement || path == displaced || replacement == displaced {
            return Err("receipt connection swap paths must be distinct".to_string());
        }
        let mut swaps = SWAPS
            .lock()
            .map_err(|_| "receipt connection swap hook lock is poisoned".to_string())?;
        if swaps.contains_key(&path) {
            return Err("receipt connection swap hook is already installed".to_string());
        }
        swaps.insert(
            path,
            SwapHook {
                stage,
                replacement,
                displaced,
                state: SwapState::Installed,
            },
        );
        Ok(())
    }

    pub(crate) fn take_completed(path: &Path) -> Result<bool, String> {
        let mut swaps = SWAPS
            .lock()
            .map_err(|_| "receipt connection swap hook lock is poisoned".to_string())?;
        Ok(swaps
            .remove(path)
            .is_some_and(|hook| hook.state == SwapState::Completed))
    }

    pub(super) fn before_open(
        path: &Path,
        stage: ReceiptConnectionOpenStage,
    ) -> Result<(), String> {
        let mut swaps = SWAPS
            .lock()
            .map_err(|_| "receipt connection swap hook lock is poisoned".to_string())?;
        let Some(hook) = swaps.get_mut(path) else {
            return Ok(());
        };
        if hook.stage != stage || hook.state != SwapState::Installed {
            return Ok(());
        }
        std::fs::rename(path, &hook.displaced)
            .map_err(|error| format!("failed to displace receipt database: {error}"))?;
        if let Err(error) = std::fs::rename(&hook.replacement, path) {
            let _ = std::fs::rename(&hook.displaced, path);
            return Err(format!(
                "failed to install replacement receipt database: {error}"
            ));
        }
        hook.state = SwapState::Swapped;
        Ok(())
    }

    pub(super) fn after_open(path: &Path, stage: ReceiptConnectionOpenStage) -> Result<(), String> {
        let mut swaps = SWAPS
            .lock()
            .map_err(|_| "receipt connection swap hook lock is poisoned".to_string())?;
        let Some(hook) = swaps.get_mut(path) else {
            return Ok(());
        };
        if hook.stage != stage || hook.state != SwapState::Swapped {
            return Ok(());
        }
        std::fs::rename(path, &hook.replacement)
            .map_err(|error| format!("failed to remove replacement receipt database: {error}"))?;
        if let Err(error) = std::fs::rename(&hook.displaced, path) {
            let _ = std::fs::rename(&hook.replacement, path);
            return Err(format!(
                "failed to restore retained receipt database: {error}"
            ));
        }
        hook.state = SwapState::Completed;
        Ok(())
    }
}

pub(crate) struct ReceiptConnectionManager {
    path: PathBuf,
    flags: rusqlite::OpenFlags,
    database_identity_file: Arc<ReceiptDatabaseIdentityFile>,
    max_page_count: Option<u32>,
}

impl ReceiptConnectionManager {
    pub(in crate::receipt_store) fn new(
        path: &Path,
        database_identity_file: Arc<ReceiptDatabaseIdentityFile>,
        max_page_count: Option<u32>,
    ) -> Self {
        Self {
            path: path.to_path_buf(),
            flags: existing_database_open_flags(),
            database_identity_file,
            max_page_count,
        }
    }
}

impl std::fmt::Debug for ReceiptConnectionManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReceiptConnectionManager")
            .field("path", &self.path)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

impl r2d2::ManageConnection for ReceiptConnectionManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let mut connection =
            open_receipt_connection(&self.path, self.flags, ReceiptConnectionOpenStage::Pool)?;
        self.database_identity_file
            .validate_live_connection(&connection)
            .map_err(receipt_store_error_as_sqlite_error)?;
        configure_sqlite_connection(&mut connection, self.max_page_count)
            .map_err(receipt_store_error_as_sqlite_error)?;
        self.database_identity_file
            .validate_live_connection(&connection)
            .map_err(receipt_store_error_as_sqlite_error)?;
        validate_receipt_connection_hygiene(&connection)?;
        Ok(connection)
    }

    fn is_valid(&self, connection: &mut Self::Connection) -> Result<(), Self::Error> {
        self.database_identity_file
            .validate_live_connection(connection)
            .map_err(receipt_store_error_as_sqlite_error)?;
        validate_receipt_connection_hygiene(connection)
    }

    fn has_broken(&self, connection: &mut Self::Connection) -> bool {
        self.database_identity_file
            .validate_live_connection(connection)
            .is_err()
            || validate_receipt_connection_hygiene(connection).is_err()
    }
}

fn validate_receipt_connection_hygiene(connection: &Connection) -> Result<(), rusqlite::Error> {
    if !connection.is_autocommit() {
        return Err(rusqlite::Error::InvalidParameterName(
            "receipt pool connection has an open transaction".to_string(),
        ));
    }

    let mut main_schema_count = 0_usize;
    for (_, schema, _) in sqlite_database_list(connection)? {
        match schema.as_str() {
            "main" => main_schema_count += 1,
            "temp" => {}
            _ => {
                return Err(rusqlite::Error::InvalidParameterName(format!(
                    "receipt pool connection has unexpected attached schema {schema:?}"
                )))
            }
        }
    }
    if main_schema_count != 1 {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "receipt pool connection reported {main_schema_count} main schemas"
        )));
    }
    validate_no_temp_schema_objects(connection)?;
    connection.execute_batch("SELECT 1")
}

/// Read SQLite's attached-database catalog through the PRAGMA statement itself.
/// The table-valued database-list spelling participates in ordinary
/// table-name resolution and can be shadowed by a persistent or TEMP table.
pub(in crate::receipt_store) fn sqlite_database_list(
    connection: &Connection,
) -> Result<Vec<(i64, String, Option<String>)>, rusqlite::Error> {
    let mut statement = connection.prepare("PRAGMA database_list")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    let mut databases = Vec::new();
    for row in rows {
        databases.push(row?);
    }
    Ok(databases)
}

/// TEMP objects are connection-local executable state. In particular, a TEMP
/// trigger on a main receipt table is invisible to `main.sqlite_master` but fires
/// when retention drops the main delete guards. Never return such a connection
/// to either receipt pool, and let destructive retention invoke the same check at
/// its locked boundaries.
pub(in crate::receipt_store) fn validate_no_temp_schema_objects(
    connection: &Connection,
) -> Result<(), rusqlite::Error> {
    let temp_object: Option<(String, String)> = connection
        .query_row(
            "SELECT type, name FROM temp.sqlite_master ORDER BY type, name LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((object_type, name)) = temp_object {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "receipt pool connection contains unexpected TEMP {object_type} {name:?}"
        )));
    }
    Ok(())
}

fn receipt_store_error_as_sqlite_error(error: ReceiptStoreError) -> rusqlite::Error {
    match error {
        ReceiptStoreError::Sqlite(error) => error,
        other => rusqlite::Error::InvalidParameterName(other.to_string()),
    }
}

fn build_receipt_pool(
    path: &Path,
    max_size: u32,
    pool_name: &str,
    database_identity_file: Arc<ReceiptDatabaseIdentityFile>,
    max_page_count: Option<u32>,
) -> Result<Pool<ReceiptConnectionManager>, ReceiptStoreError> {
    if max_size == 0 {
        return Err(ReceiptStoreError::Pool(format!(
            "{pool_name} receipt sqlite pool max_size must be greater than zero"
        )));
    }
    let manager = ReceiptConnectionManager::new(path, database_identity_file, max_page_count);
    let preflight = r2d2::ManageConnection::connect(&manager)
        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))?;
    drop(preflight);
    Pool::builder()
        .max_size(max_size)
        .build(manager)
        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
}

fn existing_database_open_flags() -> rusqlite::OpenFlags {
    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
        | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW
}

fn create_database_open_flags() -> rusqlite::OpenFlags {
    existing_database_open_flags() | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
}

fn require_existing_receipt_schema(
    path: &Path,
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    const REQUIRED_TABLES: &[&str] = &[
        "chio_tool_receipts",
        "chio_child_receipts",
        "claim_receipt_log_entries",
        "kernel_checkpoints",
        "checkpoint_tree_heads",
        "checkpoint_predecessor_witnesses",
        "checkpoint_publication_metadata",
    ];

    for table in REQUIRED_TABLES {
        let exists: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [*table],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(ReceiptStoreError::NotFound(format!(
                "receipt database {} is not an initialized Chio receipt store: missing table {table}",
                path.display()
            )));
        }
    }

    Ok(())
}

/// Refuse an unstamped database whose generic legacy anchor (`http_receipts` or
/// `tool_receipts`) does not carry a receipt payload column. These names are
/// generic enough that an unrelated SQLite database could hold one by
/// coincidence; the schema-version check would otherwise adopt and stamp such a
/// file as a receipt store. A database already carrying the Chio application_id
/// is provably a Chio store and is left to the schema-version check.
fn reject_foreign_legacy_receipt_anchor(connection: &Connection) -> Result<(), ReceiptStoreError> {
    let application_id: i32 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id != 0 {
        return Ok(());
    }
    for anchor in RECEIPT_STORE_GENERIC_LEGACY_ANCHOR_TABLES {
        if table_exists(connection, anchor)?
            && !table_has_receipt_payload_column(connection, anchor)?
        {
            return Err(ReceiptStoreError::Conflict(format!(
                "database has a `{anchor}` table without a receipt payload column \
                 (raw_json or receipt_json); refusing to adopt a foreign database as a receipt store"
            )));
        }
    }
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, ReceiptStoreError> {
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )?;
    Ok(present)
}

/// Whether `table` stores a receipt payload under a recognised JSON column:
/// `raw_json` on the current store, `receipt_json` on the pre-stamping one. The
/// table name is one of the store's own compile-time anchors, never caller
/// input, and `PRAGMA table_info` takes no bound parameter for it.
fn table_has_receipt_payload_column(
    connection: &Connection,
    table: &str,
) -> Result<bool, ReceiptStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let column: String = row.get(1)?;
        if column.eq_ignore_ascii_case("raw_json") || column.eq_ignore_ascii_case("receipt_json") {
            return Ok(true);
        }
    }
    Ok(false)
}
