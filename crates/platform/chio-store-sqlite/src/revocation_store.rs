use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use chio_kernel::{RevocationRecord, RevocationStore, RevocationStoreError};
use rusqlite::{params, Connection, OptionalExtension};

pub(crate) const ADMISSION_AUTHORITY_META_TABLE: &str = "admission_authority_meta";

pub struct SqliteRevocationStore {
    connection: Mutex<Connection>,
    database_identity_file: Option<Arc<crate::durable_sqlite::DurableSqliteFile>>,
    admission_authority_mode: Option<String>,
    /// Whether the backing database lives only in process memory and so loses
    /// every revocation on restart. Computed from the open path, not assumed
    /// durable: an in-memory SQLite database must not satisfy the durability
    /// gate the way a real filesystem path does.
    ephemeral: bool,
}

/// Maximum capability identifier accepted by the revocation authority.
pub const MAX_REVOCATION_CAPABILITY_ID_BYTES: usize = 1024;

/// Whether a SQLite path opens a database that lives only in memory for the life
/// of the process. rusqlite enables URI filenames, so the bare `:memory:`
/// sentinel, `file::memory:`, and any `file:...?mode=memory` URI all open a
/// non-durable database that loses every revocation on restart.
fn path_opens_in_memory(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    if value.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    let Some(rest) = value.strip_prefix("file:") else {
        return false;
    };
    let (name, query) = match rest.split_once('?') {
        Some((name, query)) => (name, Some(query)),
        None => (rest, None),
    };
    if name.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    query.is_some_and(|query| {
        query
            .split('&')
            .any(|param| param.eq_ignore_ascii_case("mode=memory"))
    })
}

/// Revocation-store schema revision. Bump on every schema-affecting change.
const REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 1;
/// Stable key under which this store records its schema revision in the shared
/// keyed metadata table, distinct from any co-located store's key.
const REVOCATION_STORE_SCHEMA_KEY: &str = "revocation";
/// Tables shipped before schema stamping existed, used to adopt a pre-stamping
/// revocation database rather than reject it as foreign.
const REVOCATION_STORE_LEGACY_ANCHOR_TABLES: &[&str] = &["revoked_capabilities"];
const REVOCATION_TABLE_SQL: &str = r#"
    CREATE TABLE revoked_capabilities (
        capability_id TEXT NOT NULL PRIMARY KEY CHECK (
            typeof(capability_id) = 'text'
            AND length(CAST(capability_id AS BLOB)) BETWEEN 1 AND 1024
            AND instr(CAST(capability_id AS BLOB), X'00') = 0
        ),
        revoked_at INTEGER NOT NULL CHECK (
            typeof(revoked_at) = 'integer'
            AND revoked_at >= 0
        )
    )
"#;
const REVOCATION_INDEX_SQL: &str = r#"
    CREATE INDEX idx_revoked_capabilities_revoked_at
        ON revoked_capabilities(revoked_at)
"#;
const LEGACY_REVOCATION_TABLE_SQL: &str = r#"
    CREATE TABLE revoked_capabilities (
        capability_id TEXT PRIMARY KEY,
        revoked_at INTEGER NOT NULL
    )
"#;

impl SqliteRevocationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RevocationStoreError> {
        let path = path.as_ref();
        let ephemeral = path_opens_in_memory(path);
        if !ephemeral {
            // Derive the directory from the resolved filesystem path: a `file:`
            // URI sibling (`file:/var/lib/chio/receipts.db.revocations?mode=rwc`)
            // has a query and scheme that a raw `parent()` would fold into a
            // bogus directory, leaving the real one uncreated.
            if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
                fs::create_dir_all(&parent)?;
            }
        }

        let connection = Connection::open(path)?;
        Self::from_connection(connection, ephemeral, None)
    }

    /// Open a durable revocation authority through a retained trusted parent.
    ///
    /// The retained file descriptor is revalidated against both the directory
    /// entry and SQLite's live main-file handle before every operation. A path
    /// replacement after topology preparation therefore fails closed instead
    /// of redirecting revocation reads or writes to another database.
    pub fn open_hardened(
        path: impl AsRef<Path>,
        directory: Arc<crate::durable_sqlite::TrustedSqliteDirectory>,
    ) -> Result<Self, RevocationStoreError> {
        let database_identity_file = directory
            .open_database(path, true)
            .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
        Self::open_hardened_file(database_identity_file)
    }

    /// Open a durable revocation authority from a file descriptor retained
    /// during side-effect-free topology preparation.
    pub fn open_hardened_file(
        database_identity_file: Arc<crate::durable_sqlite::DurableSqliteFile>,
    ) -> Result<Self, RevocationStoreError> {
        let connection = database_identity_file
            .open_connection(
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
        Self::from_connection(connection, false, Some(database_identity_file))
    }

    fn from_connection(
        mut connection: Connection,
        ephemeral: bool,
        database_identity_file: Option<Arc<crate::durable_sqlite::DurableSqliteFile>>,
    ) -> Result<Self, RevocationStoreError> {
        // Provenance inspection, legacy adoption, schema migration, and version
        // stamping share one transaction. A foreign database is rejected before
        // WAL or any other mutating PRAGMA runs, while a malformed v0 database
        // rolls back its application-id adoption and partial rebuild together.
        let transaction = connection.transaction()?;
        let on_disk_version = crate::check_schema_version(
            &transaction,
            REVOCATION_STORE_SCHEMA_KEY,
            REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION,
            REVOCATION_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
        let admission_authority_mode = combined_managed_mode(&transaction)?;
        match on_disk_version {
            0 => migrate_revocation_schema_v0_to_v1(
                &transaction,
                admission_authority_mode.is_some(),
            )?,
            REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION => {
                validate_revocation_schema(&transaction)?;
            }
            unsupported => {
                return Err(RevocationStoreError::Sync(format!(
                    "unsupported revocation schema version {unsupported}"
                )))
            }
        }
        crate::stamp_schema_version(
            &transaction,
            REVOCATION_STORE_SCHEMA_KEY,
            REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
        transaction.commit()?;

        configure_revocation_connection(&connection)?;
        if let Some(database_identity_file) = database_identity_file.as_ref() {
            database_identity_file
                .validate_live_connection(&connection)
                .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
        }

        Ok(Self {
            connection: Mutex::new(connection),
            database_identity_file,
            admission_authority_mode,
            ephemeral,
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, RevocationStoreError> {
        let connection = self.connection.lock().map_err(|_| {
            RevocationStoreError::Sync("sqlite revocation store lock poisoned".to_string())
        })?;
        if let Some(database_identity_file) = self.database_identity_file.as_ref() {
            database_identity_file
                .validate_live_connection(&connection)
                .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
        }
        Ok(connection)
    }

    pub fn is_admission_authority_managed(&self) -> bool {
        self.admission_authority_mode.is_some()
    }

    fn require_direct_write(&self) -> Result<(), RevocationStoreError> {
        match self.admission_authority_mode.as_deref() {
            Some(mode) => Err(RevocationStoreError::Sync(format!(
                "revocation database is managed by the `{mode}` admission capture authority"
            ))),
            None => Ok(()),
        }
    }

    pub fn list_revocations(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<RevocationRecord>, RevocationStoreError> {
        if let Some(capability_id) = capability_id {
            validate_revocation_capability_id(capability_id)?;
        }
        let limit = sqlite_limit(limit)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT capability_id, revoked_at
            FROM revoked_capabilities
            WHERE (?1 IS NULL OR capability_id = ?1)
            ORDER BY revoked_at DESC, capability_id ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![capability_id, limit], |row| {
            Ok(RevocationRecord {
                capability_id: row.get(0)?,
                revoked_at: row.get(1)?,
            })
        })?;
        let records = rows.collect::<Result<Vec<_>, _>>()?;
        validate_revocation_records(&records)?;
        Ok(records)
    }

    pub fn list_revocations_after(
        &self,
        limit: usize,
        after_revoked_at: Option<i64>,
        after_capability_id: Option<&str>,
    ) -> Result<Vec<RevocationRecord>, RevocationStoreError> {
        if let Some(revoked_at) = after_revoked_at {
            validate_revoked_at(revoked_at)?;
        }
        if let Some(capability_id) = after_capability_id {
            validate_revocation_capability_id(capability_id)?;
        }
        let limit = sqlite_limit(limit)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT capability_id, revoked_at
            FROM revoked_capabilities
            WHERE (
                ?1 IS NULL
                OR revoked_at > ?1
                OR (revoked_at = ?1 AND ?2 IS NOT NULL AND capability_id > ?2)
            )
            ORDER BY revoked_at ASC, capability_id ASC
            LIMIT ?3
            "#,
        )?;
        let rows = statement.query_map(
            params![after_revoked_at, after_capability_id, limit],
            |row| {
                Ok(RevocationRecord {
                    capability_id: row.get(0)?,
                    revoked_at: row.get(1)?,
                })
            },
        )?;
        let records = rows.collect::<Result<Vec<_>, _>>()?;
        validate_revocation_records(&records)?;
        Ok(records)
    }

    pub fn upsert_revocation(&self, record: &RevocationRecord) -> Result<(), RevocationStoreError> {
        validate_revocation_capability_id(&record.capability_id)?;
        validate_revoked_at(record.revoked_at)?;
        self.require_direct_write()?;
        self.connection()?.execute(
            r#"
            INSERT INTO revoked_capabilities (capability_id, revoked_at)
            VALUES (?1, ?2)
            ON CONFLICT(capability_id) DO UPDATE SET
                revoked_at = MAX(revoked_at, excluded.revoked_at)
            "#,
            params![record.capability_id, record.revoked_at],
        )?;
        Ok(())
    }

    /// The head of the revocation stream as the pagination cursor tuple
    /// (revoked_at, capability_id), or None when empty. list_revocations_after
    /// paginates ascending, so the head is the descending row.
    pub fn latest_revocation_cursor(&self) -> Result<Option<(i64, String)>, RevocationStoreError> {
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT revoked_at, capability_id FROM revoked_capabilities \
                 ORDER BY revoked_at DESC, capability_id DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if let Some((revoked_at, capability_id)) = row.as_ref() {
            validate_revoked_at(*revoked_at)?;
            validate_revocation_capability_id(capability_id)?;
        }
        Ok(row)
    }
}

fn sqlite_limit(limit: usize) -> Result<i64, RevocationStoreError> {
    i64::try_from(limit).map_err(|_| {
        RevocationStoreError::Sync("revocation list limit exceeds SQLite integer range".to_string())
    })
}

fn validate_revocation_capability_id(capability_id: &str) -> Result<(), RevocationStoreError> {
    if capability_id.is_empty()
        || capability_id.len() > MAX_REVOCATION_CAPABILITY_ID_BYTES
        || capability_id.bytes().any(|byte| byte == 0)
    {
        return Err(RevocationStoreError::Sync(
            "revocation capability ID is empty, oversized, or contains NUL".to_string(),
        ));
    }
    Ok(())
}

fn validate_revocation_records(records: &[RevocationRecord]) -> Result<(), RevocationStoreError> {
    for record in records {
        validate_revocation_capability_id(&record.capability_id)?;
        validate_revoked_at(record.revoked_at)?;
    }
    Ok(())
}

fn validate_revoked_at(revoked_at: i64) -> Result<(), RevocationStoreError> {
    if revoked_at < 0 {
        return Err(RevocationStoreError::Sync(
            "revocation timestamp must be a nonnegative Unix timestamp".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn configure_revocation_connection(
    connection: &Connection,
) -> Result<(), RevocationStoreError> {
    connection.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = FULL;
        PRAGMA busy_timeout = 5000;
        PRAGMA foreign_keys = ON;
        "#,
    )?;
    Ok(())
}

pub(crate) fn ensure_revocation_schema(
    connection: &Connection,
) -> Result<(), RevocationStoreError> {
    let table_sql = revocation_table_sql(connection)?;
    match table_sql.as_deref() {
        None => create_revocation_schema(connection)?,
        Some(sql) if normalize_schema_sql(sql) == normalize_schema_sql(REVOCATION_TABLE_SQL) => {}
        Some(sql)
            if normalize_schema_sql(sql) == normalize_schema_sql(LEGACY_REVOCATION_TABLE_SQL) =>
        {
            migrate_legacy_revocation_schema(connection, false)?;
        }
        Some(_) => {
            return Err(RevocationStoreError::Sync(
                "revocation table constraints are invalid".to_string(),
            ));
        }
    }
    validate_revocation_schema(connection)
}

fn create_revocation_schema(connection: &Connection) -> Result<(), RevocationStoreError> {
    connection.execute_batch(&format!("{REVOCATION_TABLE_SQL};{REVOCATION_INDEX_SQL};"))?;
    Ok(())
}

fn validate_revocation_schema(connection: &Connection) -> Result<(), RevocationStoreError> {
    validate_revocation_columns(connection, true)?;

    let table_sql = revocation_table_sql(connection)?
        .ok_or_else(|| RevocationStoreError::Sync("revocation table is missing".to_string()))?;
    if normalize_schema_sql(&table_sql) != normalize_schema_sql(REVOCATION_TABLE_SQL) {
        return Err(RevocationStoreError::Sync(
            "revocation table constraints are invalid".to_string(),
        ));
    }

    validate_revocation_index(connection)?;
    validate_persisted_revocation_rows(connection)
}

fn validate_legacy_revocation_schema(connection: &Connection) -> Result<(), RevocationStoreError> {
    validate_revocation_columns(connection, false)?;
    let table_sql = revocation_table_sql(connection)?.ok_or_else(|| {
        RevocationStoreError::Sync("legacy revocation table is missing".to_string())
    })?;
    if normalize_schema_sql(&table_sql) != normalize_schema_sql(LEGACY_REVOCATION_TABLE_SQL) {
        return Err(RevocationStoreError::Sync(
            "legacy revocation table constraints are invalid".to_string(),
        ));
    }
    validate_revocation_index(connection)?;
    validate_persisted_revocation_rows(connection)
}

fn validate_revocation_columns(
    connection: &Connection,
    capability_id_not_null: bool,
) -> Result<(), RevocationStoreError> {
    let columns = connection
        .prepare("PRAGMA table_info(revoked_capabilities)")?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = vec![
        (
            "capability_id".to_string(),
            "TEXT".to_string(),
            i64::from(capability_id_not_null),
            None,
            1,
        ),
        ("revoked_at".to_string(), "INTEGER".to_string(), 1, None, 0),
    ];
    if columns != expected {
        return Err(RevocationStoreError::Sync(
            "revocation columns, nullability, or primary key are invalid".to_string(),
        ));
    }
    Ok(())
}

fn revocation_table_sql(connection: &Connection) -> Result<Option<String>, RevocationStoreError> {
    connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'revoked_capabilities'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(Into::into)
}

fn validate_revocation_index(connection: &Connection) -> Result<(), RevocationStoreError> {
    let index_sql = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_revoked_capabilities_revoked_at'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            RevocationStoreError::Sync("revocation timestamp index is missing".to_string())
        })?;
    if normalize_schema_sql(&index_sql) != normalize_schema_sql(REVOCATION_INDEX_SQL) {
        return Err(RevocationStoreError::Sync(
            "revocation timestamp index is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_persisted_revocation_rows(connection: &Connection) -> Result<(), RevocationStoreError> {
    let invalid_row_exists = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM revoked_capabilities
            WHERE typeof(capability_id) != 'text'
               OR length(CAST(capability_id AS BLOB)) NOT BETWEEN 1 AND 1024
               OR instr(CAST(capability_id AS BLOB), X'00') != 0
               OR typeof(revoked_at) != 'integer'
               OR revoked_at < 0
        )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if invalid_row_exists {
        return Err(RevocationStoreError::Sync(
            "revocation database contains an invalid persisted row".to_string(),
        ));
    }
    Ok(())
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(';')
        .replacen("CREATE TABLE IF NOT EXISTS", "CREATE TABLE", 1)
        .replacen("CREATE INDEX IF NOT EXISTS", "CREATE INDEX", 1)
}

fn migrate_revocation_schema_v0_to_v1(
    connection: &Connection,
    reinstall_managed_guards: bool,
) -> Result<(), RevocationStoreError> {
    let Some(table_sql) = revocation_table_sql(connection)? else {
        create_revocation_schema(connection)?;
        return validate_revocation_schema(connection);
    };
    if normalize_schema_sql(&table_sql) == normalize_schema_sql(REVOCATION_TABLE_SQL) {
        return validate_revocation_schema(connection);
    }
    if normalize_schema_sql(&table_sql) != normalize_schema_sql(LEGACY_REVOCATION_TABLE_SQL) {
        return Err(RevocationStoreError::Sync(
            "legacy revocation table constraints are invalid".to_string(),
        ));
    }

    migrate_legacy_revocation_schema(connection, reinstall_managed_guards)
}

fn migrate_legacy_revocation_schema(
    connection: &Connection,
    reinstall_managed_guards: bool,
) -> Result<(), RevocationStoreError> {
    validate_legacy_revocation_schema(connection)?;

    connection.execute_batch(&format!(
        r#"
        ALTER TABLE revoked_capabilities
            RENAME TO chio_revoked_capabilities_v0_migration;

        {REVOCATION_TABLE_SQL};

        INSERT INTO revoked_capabilities (capability_id, revoked_at)
        SELECT capability_id, revoked_at
        FROM chio_revoked_capabilities_v0_migration;

        DROP TABLE chio_revoked_capabilities_v0_migration;

        {REVOCATION_INDEX_SQL};
        "#
    ))?;
    if reinstall_managed_guards {
        connection
            .execute_batch(crate::admission_capture_authority::INSTALL_REVOCATION_WRITE_GUARDS)?;
    }
    validate_revocation_schema(connection)
}

fn combined_managed_mode(connection: &Connection) -> Result<Option<String>, RevocationStoreError> {
    let marker_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        params![ADMISSION_AUTHORITY_META_TABLE],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if !marker_exists {
        return Ok(None);
    }
    let mode = connection
        .query_row(
            "SELECT mode FROM admission_authority_meta WHERE singleton = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    mode.map(Some).ok_or_else(|| {
        RevocationStoreError::Sync(
            "revocation database has incomplete admission authority metadata".to_string(),
        )
    })
}

impl RevocationStore for SqliteRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        validate_revocation_capability_id(capability_id)?;
        let exists = self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
            params![capability_id],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(exists != 0)
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        validate_revocation_capability_id(capability_id)?;
        self.require_direct_write()?;
        let revoked_at = revoked_at_from_system_time(std::time::SystemTime::now())?;
        let inserted = self
            .connection()?
            .query_row(
            r#"
            INSERT INTO revoked_capabilities (capability_id, revoked_at) VALUES (?1, ?2) ON CONFLICT(capability_id) DO NOTHING RETURNING 1
            "#,
                params![capability_id, revoked_at],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        Ok(inserted.is_some())
    }

    fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }
}

fn revoked_at_from_system_time(now: std::time::SystemTime) -> Result<i64, RevocationStoreError> {
    let elapsed = now.duration_since(std::time::UNIX_EPOCH).map_err(|_| {
        RevocationStoreError::Sync("system clock is before the Unix epoch".to_string())
    })?;
    i64::try_from(elapsed.as_secs()).map_err(|_| {
        RevocationStoreError::Sync(
            "system clock exceeds the SQLite revocation timestamp range".to_string(),
        )
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::SqliteAdmissionCaptureAuthority;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn stamp_revocation_v1(connection: &Connection) {
        connection
            .execute_batch(&format!(
                "PRAGMA application_id = {};",
                crate::CHIO_SQLITE_APPLICATION_ID
            ))
            .unwrap();
        crate::stamp_schema_version(
            connection,
            REVOCATION_STORE_SCHEMA_KEY,
            REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .unwrap();
    }

    #[test]
    fn sqlite_revocation_store_persists_across_reopen() {
        let path = unique_db_path("chio-revocations");
        {
            let store = SqliteRevocationStore::open(&path).unwrap();
            assert!(!store.is_revoked("cap-1").unwrap());
            assert!(store.revoke("cap-1").unwrap());
            assert!(store.is_revoked("cap-1").unwrap());
            assert!(!store.revoke("cap-1").unwrap());
        }

        let reopened = SqliteRevocationStore::open(&path).unwrap();
        assert!(reopened.is_revoked("cap-1").unwrap());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn latest_revocation_cursor_returns_head_or_none() -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_db_path("chio-rev-head");
        let store = SqliteRevocationStore::open(&path)?;
        assert_eq!(store.latest_revocation_cursor()?, None);
        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-a".to_string(),
            revoked_at: 10,
        })?;
        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-b".to_string(),
            revoked_at: 25,
        })?;
        assert_eq!(
            store.latest_revocation_cursor()?,
            Some((25, "cap-b".to_string()))
        );
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn file_backed_revocation_store_reports_durable() {
        let path = unique_db_path("chio-rev-durable");
        let store = SqliteRevocationStore::open(&path).unwrap();
        assert!(
            !store.is_ephemeral(),
            "a filesystem-backed revocation store is durable"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn in_memory_revocation_store_reports_ephemeral() {
        for path in [":memory:", "file::memory:", "file:rev?mode=memory"] {
            let store = SqliteRevocationStore::open(path).unwrap();
            assert!(
                store.is_ephemeral(),
                "in-memory revocation store {path} must report ephemeral so the durability gate refuses it"
            );
        }
    }

    #[test]
    fn open_creates_parent_dirs_for_a_file_uri_with_query() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("chio-rev-uri-{nonce}"));
        let db = base.join("nested").join("receipts.db.revocations");
        let parent = db.parent().expect("db path has a parent");
        assert!(
            !parent.exists(),
            "precondition: the parent dir must not exist yet"
        );

        // A `file:` URI sibling path carrying a query. A raw `parent()` would
        // resolve to `file:.../nested`, create a bogus relative directory, and
        // leave the real parent uncreated, so SQLite would fail to open it.
        let uri = format!("file:{}?mode=rwc", db.display());
        let store = SqliteRevocationStore::open(uri.as_str()).unwrap();

        assert!(
            !store.is_ephemeral(),
            "a file: URI to a real filesystem path is durable"
        );
        assert!(
            parent.exists(),
            "the real parent directory must be created before SQLite opens the URI"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn sqlite_revocation_store_lists_filtered_entries() {
        let path = unique_db_path("chio-revocations-filtered");
        let store = SqliteRevocationStore::open(&path).unwrap();
        assert!(store.revoke("cap-1").unwrap());
        assert!(store.revoke("cap-2").unwrap());

        let all = store.list_revocations(10, None).unwrap();
        assert_eq!(all.len(), 2);

        let filtered = store.list_revocations(10, Some("cap-1")).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].capability_id, "cap-1");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn admission_managed_store_allows_reads_but_rejects_direct_writes() {
        let path = unique_db_path("chio-managed-revocations");
        let authority = SqliteAdmissionCaptureAuthority::open(&path).expect("open authority");
        authority.revoke("cap-managed").expect("managed revoke");

        let store = SqliteRevocationStore::open(&path).expect("open managed reader");
        assert!(store.is_admission_authority_managed());
        assert!(store.is_revoked("cap-managed").expect("managed read"));
        assert_eq!(
            store
                .list_revocations(10, None)
                .expect("managed revocation list")
                .len(),
            1
        );
        assert!(store.revoke("cap-direct").is_err());
        assert!(store
            .upsert_revocation(&RevocationRecord {
                capability_id: "cap-import".to_string(),
                revoked_at: 1,
            })
            .is_err());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn stamped_v1_rejects_weakened_same_name_table_without_mutation() {
        let path = unique_db_path("chio-rev-weakened-table");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE revoked_capabilities (
                    capability_id TEXT NOT NULL PRIMARY KEY,
                    revoked_at INTEGER NOT NULL
                );
                CREATE INDEX idx_revoked_capabilities_revoked_at
                    ON revoked_capabilities(revoked_at);
                INSERT INTO revoked_capabilities VALUES ('cap-preserved', 7);
                "#,
            )
            .unwrap();
        stamp_revocation_v1(&connection);
        let before = revocation_table_sql(&connection).unwrap().unwrap();
        drop(connection);

        let error = SqliteRevocationStore::open(&path).err().unwrap();
        assert!(error.to_string().contains("constraints are invalid"));

        let connection = Connection::open(&path).unwrap();
        assert_eq!(revocation_table_sql(&connection).unwrap().unwrap(), before);
        assert_eq!(
            connection
                .query_row(
                    "SELECT capability_id, revoked_at FROM revoked_capabilities",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap(),
            ("cap-preserved".to_string(), 7)
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stamped_v1_rejects_weakened_same_name_index_without_mutation() {
        let path = unique_db_path("chio-rev-weakened-index");
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(REVOCATION_TABLE_SQL).unwrap();
        connection
            .execute_batch(
                "CREATE INDEX idx_revoked_capabilities_revoked_at \
                 ON revoked_capabilities(capability_id);",
            )
            .unwrap();
        stamp_revocation_v1(&connection);
        let before = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = \
                 'idx_revoked_capabilities_revoked_at'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        drop(connection);

        let error = SqliteRevocationStore::open(&path).err().unwrap();
        assert!(error.to_string().contains("timestamp index is invalid"));

        let connection = Connection::open(&path).unwrap();
        let after = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = \
                 'idx_revoked_capabilities_revoked_at'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(after, before);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stamped_v1_rejects_negative_persisted_timestamp() {
        let path = unique_db_path("chio-rev-negative-row");
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(REVOCATION_TABLE_SQL).unwrap();
        connection.execute_batch(REVOCATION_INDEX_SQL).unwrap();
        connection
            .execute_batch(
                r#"
                PRAGMA ignore_check_constraints = ON;
                INSERT INTO revoked_capabilities VALUES ('cap-negative', -1);
                PRAGMA ignore_check_constraints = OFF;
                "#,
            )
            .unwrap();
        stamp_revocation_v1(&connection);
        drop(connection);

        let error = SqliteRevocationStore::open(&path).err().unwrap();
        assert!(error.to_string().contains("invalid persisted row"));
        let connection = Connection::open(&path).unwrap();
        let timestamp = connection
            .query_row(
                "SELECT revoked_at FROM revoked_capabilities WHERE capability_id = 'cap-negative'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(timestamp, -1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn valid_v0_store_upgrades_transactionally_to_v1() {
        let path = unique_db_path("chio-rev-v0-upgrade");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(&format!(
                "{LEGACY_REVOCATION_TABLE_SQL};{REVOCATION_INDEX_SQL}; \
                 INSERT INTO revoked_capabilities VALUES ('cap-v0', 11);"
            ))
            .unwrap();
        drop(connection);

        let store = SqliteRevocationStore::open(&path).unwrap();
        assert!(store.is_revoked("cap-v0").unwrap());
        drop(store);

        let connection = Connection::open(&path).unwrap();
        validate_revocation_schema(&connection).unwrap();
        let version = connection
            .query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = 'revocation'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(version, 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn invalid_v0_row_rolls_back_schema_adoption_and_migration() {
        let path = unique_db_path("chio-rev-v0-rollback");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(&format!(
                "{LEGACY_REVOCATION_TABLE_SQL};{REVOCATION_INDEX_SQL}; \
                 INSERT INTO revoked_capabilities VALUES ('cap-negative', -1);"
            ))
            .unwrap();
        let before = revocation_table_sql(&connection).unwrap().unwrap();
        drop(connection);

        let error = SqliteRevocationStore::open(&path).err().unwrap();
        assert!(error.to_string().contains("invalid persisted row"));

        let connection = Connection::open(&path).unwrap();
        let application_id = connection
            .query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))
            .unwrap();
        assert_eq!(application_id, 0);
        assert_eq!(revocation_table_sql(&connection).unwrap().unwrap(), before);
        let version_table_exists = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chio_store_schema_versions')",
                [],
                |row| row.get::<_, bool>(0),
            )
            .unwrap();
        assert!(!version_table_exists);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn foreign_database_is_rejected_without_schema_mutation() {
        let path = unique_db_path("chio-rev-foreign");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE unrelated_data (id TEXT PRIMARY KEY); \
                 INSERT INTO unrelated_data VALUES ('preserve-me');",
            )
            .unwrap();
        drop(connection);

        assert!(SqliteRevocationStore::open(&path).is_err());

        let connection = Connection::open(&path).unwrap();
        let application_id = connection
            .query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))
            .unwrap();
        assert_eq!(application_id, 0);
        let tables = connection
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(tables, vec!["unrelated_data".to_string()]);
        let value = connection
            .query_row("SELECT id FROM unrelated_data", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap();
        assert_eq!(value, "preserve-me");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn negative_timestamp_inputs_and_pre_epoch_clock_fail_closed() {
        let path = unique_db_path("chio-rev-negative-input");
        let store = SqliteRevocationStore::open(&path).unwrap();
        assert!(store
            .upsert_revocation(&RevocationRecord {
                capability_id: "cap-negative".to_string(),
                revoked_at: -1,
            })
            .is_err());
        assert!(store.list_revocations_after(1, Some(-1), None).is_err());
        assert!(store.list_revocations(1, None).unwrap().is_empty());

        let pre_epoch = UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap();
        assert!(revoked_at_from_system_time(pre_epoch).is_err());
        let _ = fs::remove_file(path);
    }
}
