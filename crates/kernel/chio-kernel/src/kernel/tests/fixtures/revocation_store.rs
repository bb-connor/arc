//! Durable revocation test fixture.
use super::*;

pub(in crate::kernel::tests) struct SqliteRevocationStore {
    pub(in crate::kernel::tests) path: PathBuf,
}

impl SqliteRevocationStore {
    pub(in crate::kernel::tests) fn open(path: impl AsRef<Path>) -> Result<Self, RevocationStoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(
            r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;

                CREATE TABLE IF NOT EXISTS revoked_capabilities (
                    capability_id TEXT PRIMARY KEY,
                    revoked_at INTEGER NOT NULL
                );
                "#,
        )?;
        Ok(Self { path })
    }

    pub(in crate::kernel::tests) fn connection(&self) -> Result<rusqlite::Connection, RevocationStoreError> {
        Ok(rusqlite::Connection::open(&self.path)?)
    }
}

impl RevocationStore for SqliteRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        let connection = self.connection()?;
        let exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
            params![capability_id],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(exists != 0)
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        let connection = self.connection()?;
        let revoked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        let rows = connection.execute(
            r#"
                INSERT INTO revoked_capabilities (capability_id, revoked_at)
                VALUES (?1, ?2)
                ON CONFLICT(capability_id) DO NOTHING
                "#,
            params![capability_id, revoked_at],
        )?;
        Ok(rows > 0)
    }
}

