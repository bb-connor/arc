//! Persisted per-exporter high-water mark (RFC-0009 F78). A SIEM-owned RW SQLite
//! file, distinct from the read-only receipt DB (ADR-0009: the receipt DB stays
//! read-only). Fail-closed: a write failure denies advancing the mark.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use crate::manager::SiemError;

pub struct SiemCursorStore {
    conn: Mutex<rusqlite::Connection>,
}

impl SiemCursorStore {
    pub fn open(path: &Path) -> Result<Self, SiemError> {
        let conn =
            rusqlite::Connection::open(path).map_err(|e| SiemError::DbError(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS siem_export_cursor (
                 exporter_name TEXT PRIMARY KEY,
                 acked_seq     INTEGER NOT NULL
             );",
        )
        .map_err(|e| SiemError::DbError(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn acked_seqs(&self) -> Result<BTreeMap<String, u64>, SiemError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SiemError::DbError("cursor store lock poisoned".to_string()))?;
        let mut stmt = conn
            .prepare("SELECT exporter_name, acked_seq FROM siem_export_cursor")
            .map_err(|e| SiemError::DbError(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| SiemError::DbError(e.to_string()))?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (name, seq) = row.map_err(|e| SiemError::DbError(e.to_string()))?;
            out.insert(name, seq.max(0) as u64);
        }
        Ok(out)
    }

    /// Advance the mark for `exporter`. Monotonic: never regresses below the
    /// current value.
    pub fn set_acked(&self, exporter: &str, acked_seq: u64) -> Result<(), SiemError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SiemError::DbError("cursor store lock poisoned".to_string()))?;
        conn.execute(
            "INSERT INTO siem_export_cursor (exporter_name, acked_seq) VALUES (?1, ?2) \
             ON CONFLICT(exporter_name) DO UPDATE SET acked_seq = MAX(acked_seq, excluded.acked_seq)",
            rusqlite::params![exporter, acked_seq as i64],
        )
        .map_err(|e| SiemError::DbError(e.to_string()))?;
        Ok(())
    }

    pub fn min_acked(&self) -> Result<Option<u64>, SiemError> {
        Ok(self.acked_seqs()?.values().copied().min())
    }
}
