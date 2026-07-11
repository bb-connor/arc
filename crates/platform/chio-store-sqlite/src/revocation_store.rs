use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chio_kernel::{RevocationRecord, RevocationStore, RevocationStoreError};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

/// Outcome of the atomic anti-farm-cap-enforced Pass issuance admission
/// ([`SqliteRevocationStore::try_record_pass_issuance_under_caps`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassIssuanceAdmission {
    /// The issuance was admitted under the caps and persisted (a new row), or it
    /// was an idempotent re-record of an already-present window-scoped id.
    Admitted,
    /// The per-window distribution cap was already full; nothing was persisted.
    DeniedWindowExhausted,
    /// The live-population cap was already reached; nothing was persisted.
    DeniedPopulationCap,
}

pub struct SqliteRevocationStore {
    connection: Mutex<Connection>,
}

impl SqliteRevocationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RevocationStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let connection = Connection::open(path)?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS revoked_capabilities (
                capability_id TEXT PRIMARY KEY,
                revoked_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_revoked_capabilities_revoked_at
                ON revoked_capabilities(revoked_at);

            CREATE TABLE IF NOT EXISTS issued_passes (
                capability_id TEXT PRIMARY KEY,
                window_ym TEXT NOT NULL,
                valid_from INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_issued_passes_window_ym
                ON issued_passes(window_ym);
            "#,
        )?;

        // Additive migration: stores created before the live-population fix have
        // an issued_passes table WITHOUT a valid_from column. Add it idempotently.
        // The default 0 keeps legacy rows always-eligible by valid_from (so their
        // prior live-count semantics are preserved), while every new row records
        // the real window-start so a future-window (e.g. next-month, refresh-
        // persisted) Pass cannot inflate the current live population.
        if !Self::issued_passes_has_valid_from(&connection)? {
            connection.execute_batch(
                "ALTER TABLE issued_passes ADD COLUMN valid_from INTEGER NOT NULL DEFAULT 0;",
            )?;
        }

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Whether the `issued_passes` table already carries the `valid_from` column
    /// (true for fresh stores; false for pre-migration stores).
    fn issued_passes_has_valid_from(connection: &Connection) -> Result<bool, RevocationStoreError> {
        let mut statement = connection.prepare("PRAGMA table_info(issued_passes)")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let column_name: String = row.get(1)?;
            if column_name == "valid_from" {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, RevocationStoreError> {
        self.connection.lock().map_err(|_| {
            RevocationStoreError::Sync("sqlite revocation store lock poisoned".to_string())
        })
    }

    pub fn list_revocations(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<RevocationRecord>, RevocationStoreError> {
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
        let rows = statement.query_map(params![capability_id, limit as i64], |row| {
            Ok(RevocationRecord {
                capability_id: row.get(0)?,
                revoked_at: row.get(1)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_revocations_after(
        &self,
        limit: usize,
        after_revoked_at: Option<i64>,
        after_capability_id: Option<&str>,
    ) -> Result<Vec<RevocationRecord>, RevocationStoreError> {
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
            params![after_revoked_at, after_capability_id, limit as i64],
            |row| {
                Ok(RevocationRecord {
                    capability_id: row.get(0)?,
                    revoked_at: row.get(1)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Record (idempotently) that a Pass capability was issued in `window_ym`,
    /// expiring at `expires_at` (unix seconds). The capability id is the primary
    /// key, so re-recording the SAME window-scoped Pass id (the deterministic
    /// `chiopass:<hash>` is subject+window derived) never double-counts the
    /// issuance. This is the persisted issued-Pass roster the anti-farm
    /// distribution counters are sourced from.
    pub fn record_pass_issuance(
        &self,
        capability_id: &str,
        window_ym: &str,
        valid_from: i64,
        expires_at: i64,
    ) -> Result<(), RevocationStoreError> {
        self.connection()?.execute(
            r#"
            INSERT INTO issued_passes (capability_id, window_ym, valid_from, expires_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(capability_id) DO UPDATE SET
                window_ym = excluded.window_ym,
                valid_from = excluded.valid_from,
                expires_at = excluded.expires_at
            "#,
            params![capability_id, window_ym, valid_from, expires_at],
        )?;
        Ok(())
    }

    /// Atomically admit a Pass issuance against the anti-farm distribution caps
    /// and persist it, all inside ONE `IMMEDIATE` SQLite transaction.
    ///
    /// This closes the read-then-mint-then-write race: two concurrent
    /// `chio pass issue` processes (each with its own connection) cannot both read
    /// stale counts, both mint, and both exceed the caps. The transaction takes
    /// the database write lock before counting, so the count/check/insert is
    /// serialized across processes and the cap is enforced at WRITE time.
    ///
    /// The deterministic `chiopass:<hash>` id is the roster key, so re-recording
    /// an already-present id is an idempotent update that is admitted even when the
    /// caps are full (it adds no new population). A NEW id is admitted only when
    /// `window_issued_count < window_token_capacity` AND
    /// `active_population < active_population_cap` (counted EXCLUDING the row being
    /// inserted, matching the pre-mint admission semantics in
    /// `evaluate_pass_admission`). When a cap is full nothing is persisted and the
    /// corresponding `Denied*` outcome is returned, so the in-memory mint is
    /// discarded fail-closed.
    #[allow(clippy::too_many_arguments)]
    pub fn try_record_pass_issuance_under_caps(
        &self,
        capability_id: &str,
        window_ym: &str,
        valid_from: i64,
        expires_at: i64,
        now: i64,
        window_token_capacity: u64,
        active_population_cap: u64,
    ) -> Result<PassIssuanceAdmission, RevocationStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let already_present = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM issued_passes WHERE capability_id = ?1)",
            params![capability_id],
            |row| row.get::<_, i64>(0),
        )? != 0;

        if !already_present {
            let window_count: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM issued_passes WHERE window_ym = ?1",
                params![window_ym],
                |row| row.get(0),
            )?;
            if u64::try_from(window_count).unwrap_or(u64::MAX) >= window_token_capacity {
                // Dropping the transaction rolls back; nothing is persisted.
                return Ok(PassIssuanceAdmission::DeniedWindowExhausted);
            }
            let active_count: i64 = transaction.query_row(
                r#"
                SELECT COUNT(*)
                FROM issued_passes AS issued
                WHERE issued.valid_from <= ?1
                  AND issued.expires_at > ?1
                  AND NOT EXISTS (
                      SELECT 1 FROM revoked_capabilities AS revoked
                      WHERE revoked.capability_id = issued.capability_id
                  )
                "#,
                params![now],
                |row| row.get(0),
            )?;
            if u64::try_from(active_count).unwrap_or(u64::MAX) >= active_population_cap {
                return Ok(PassIssuanceAdmission::DeniedPopulationCap);
            }
        }

        transaction.execute(
            r#"
            INSERT INTO issued_passes (capability_id, window_ym, valid_from, expires_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(capability_id) DO UPDATE SET
                window_ym = excluded.window_ym,
                valid_from = excluded.valid_from,
                expires_at = excluded.expires_at
            "#,
            params![capability_id, window_ym, valid_from, expires_at],
        )?;
        transaction.commit()?;
        Ok(PassIssuanceAdmission::Admitted)
    }

    /// Whether `capability_id` is already on the issued-Pass roster. The
    /// deterministic `chiopass:<hash>` id is the roster key, so a `true` result means
    /// re-recording it is an idempotent NO-GROWTH update that
    /// [`Self::try_record_pass_issuance_under_caps`] admits even at a full cap. The
    /// issuance entrypoint uses this to recognise an idempotent re-issue BEFORE its
    /// fast pre-mint admission precheck, so a legitimate re-issue at the cap is not
    /// wrongly denied while the authoritative cap transaction still gates genuinely
    /// new subjects. Sourced from persisted state; fail-closed on a store IO fault.
    pub fn pass_issuance_exists(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        let exists = self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM issued_passes WHERE capability_id = ?1)",
            params![capability_id],
            |row| row.get::<_, i64>(0),
        )? != 0;
        Ok(exists)
    }

    /// Count the Passes persisted as issued in `window_ym` (the per-window
    /// anti-farm cap leg). Sourced from persisted state, never recomputed.
    pub fn count_window_issuances(&self, window_ym: &str) -> Result<u64, RevocationStoreError> {
        let count: i64 = self.connection()?.query_row(
            "SELECT COUNT(*) FROM issued_passes WHERE window_ym = ?1",
            params![window_ym],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    /// Count the LIVE issued Passes at `now` (the active-population cap leg): an
    /// issued Pass is live when its window has already opened (`valid_from <= now`)
    /// and it has not expired (`expires_at > now`) and its capability id is not in
    /// the revoked set. Sourced from persisted state.
    ///
    /// The `valid_from <= now` bound stops a refresh-persisted FUTURE-window Pass
    /// (e.g. a July Pass minted while refreshing a June Pass) from counting as live
    /// in the current window and prematurely denying unrelated first-window
    /// issuances.
    pub fn count_active_passes(&self, now: i64) -> Result<u64, RevocationStoreError> {
        let count: i64 = self.connection()?.query_row(
            r#"
            SELECT COUNT(*)
            FROM issued_passes AS issued
            WHERE issued.valid_from <= ?1
              AND issued.expires_at > ?1
              AND NOT EXISTS (
                  SELECT 1 FROM revoked_capabilities AS revoked
                  WHERE revoked.capability_id = issued.capability_id
              )
            "#,
            params![now],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    pub fn upsert_revocation(&self, record: &RevocationRecord) -> Result<(), RevocationStoreError> {
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
        Ok(row)
    }
}

impl RevocationStore for SqliteRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        let exists = self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
            params![capability_id],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(exists != 0)
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        let revoked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
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
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
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
    fn sqlite_revocation_store_counts_persisted_issued_passes() {
        let path = unique_db_path("chio-issued-passes");
        let store = SqliteRevocationStore::open(&path).unwrap();

        // Two Passes in window 2026-06, one in 2026-07. All open at valid_from 0.
        store
            .record_pass_issuance("chiopass:a", "2026-06", 0, 2_000)
            .unwrap();
        store
            .record_pass_issuance("chiopass:b", "2026-06", 0, 2_000)
            .unwrap();
        store
            .record_pass_issuance("chiopass:c", "2026-07", 0, 5_000)
            .unwrap();

        assert_eq!(store.count_window_issuances("2026-06").unwrap(), 2);
        assert_eq!(store.count_window_issuances("2026-07").unwrap(), 1);
        assert_eq!(store.count_window_issuances("2026-08").unwrap(), 0);

        // At now=1000 all three are live (none expired, none revoked).
        assert_eq!(store.count_active_passes(1_000).unwrap(), 3);

        // Revoking b removes it from the live population.
        assert!(store.revoke("chiopass:b").unwrap());
        assert_eq!(store.count_active_passes(1_000).unwrap(), 2);

        // At now=2500, a and b are expired (expires 2000); c (expires 5000) is the
        // only live, non-revoked Pass.
        assert_eq!(store.count_active_passes(2_500).unwrap(), 1);

        // Idempotent: re-recording the same window-scoped id does not inflate the
        // window count.
        store
            .record_pass_issuance("chiopass:a", "2026-06", 0, 2_000)
            .unwrap();
        assert_eq!(store.count_window_issuances("2026-06").unwrap(), 2);

        // The roster persists across reopen.
        drop(store);
        let reopened = SqliteRevocationStore::open(&path).unwrap();
        assert_eq!(reopened.count_window_issuances("2026-06").unwrap(), 2);

        let _ = fs::remove_file(path);
    }

    /// Finding 9: a FUTURE-window Pass (its window has not opened yet) is NOT
    /// counted in the current live population, so it cannot prematurely deny an
    /// unrelated first-window issuance.
    #[test]
    fn future_window_pass_is_not_counted_active() {
        let path = unique_db_path("chio-future-window");
        let store = SqliteRevocationStore::open(&path).unwrap();

        // A current-window Pass opened at 1_000 expiring at 3_000.
        store
            .record_pass_issuance("chiopass:june", "2026-06", 1_000, 3_000)
            .unwrap();
        // A future-window (e.g. refresh-persisted July) Pass that does not open
        // until 3_000 but already has a far-future expiry.
        store
            .record_pass_issuance("chiopass:july", "2026-07", 3_000, 6_000)
            .unwrap();

        // At now=2_000 only the June Pass is live: July has not opened
        // (valid_from 3_000 > 2_000), even though its expiry is in the future.
        assert_eq!(store.count_active_passes(2_000).unwrap(), 1);
        // At now=3_000 June has expired and July has opened: still exactly one.
        assert_eq!(store.count_active_passes(3_000).unwrap(), 1);
        // At now=4_000 only July is live.
        assert_eq!(store.count_active_passes(4_000).unwrap(), 1);

        let _ = fs::remove_file(path);
    }

    /// Finding 4: the atomic admission guard enforces the anti-farm caps at write
    /// time. With the window cap full, a NEW distinct id is rejected and nothing
    /// is persisted; an idempotent re-record of an already-present id is still
    /// admitted; and the population cap is enforced the same way.
    #[test]
    fn atomic_admission_enforces_caps_at_write_time() {
        let path = unique_db_path("chio-atomic-admission");
        let store = SqliteRevocationStore::open(&path).unwrap();

        // Window cap of 2: the first two distinct ids are admitted.
        let now = 1_000;
        assert_eq!(
            store
                .try_record_pass_issuance_under_caps("chiopass:a", "2026-06", 0, 9_000, now, 2, 100)
                .unwrap(),
            PassIssuanceAdmission::Admitted
        );
        assert_eq!(
            store
                .try_record_pass_issuance_under_caps("chiopass:b", "2026-06", 0, 9_000, now, 2, 100)
                .unwrap(),
            PassIssuanceAdmission::Admitted
        );
        assert_eq!(store.count_window_issuances("2026-06").unwrap(), 2);

        // The window is full: a THIRD distinct id is denied and not persisted.
        assert_eq!(
            store
                .try_record_pass_issuance_under_caps("chiopass:c", "2026-06", 0, 9_000, now, 2, 100)
                .unwrap(),
            PassIssuanceAdmission::DeniedWindowExhausted
        );
        assert_eq!(store.count_window_issuances("2026-06").unwrap(), 2);

        // An idempotent re-record of an already-present id is still admitted even
        // with the window full (it adds no new population).
        assert_eq!(
            store
                .try_record_pass_issuance_under_caps("chiopass:a", "2026-06", 0, 9_000, now, 2, 100)
                .unwrap(),
            PassIssuanceAdmission::Admitted
        );
        assert_eq!(store.count_window_issuances("2026-06").unwrap(), 2);

        // The population cap is enforced the same way: a roomy window but a full
        // live population denies a new id in a DIFFERENT window.
        assert_eq!(
            store
                .try_record_pass_issuance_under_caps("chiopass:d", "2026-07", 0, 9_000, now, 100, 2)
                .unwrap(),
            PassIssuanceAdmission::DeniedPopulationCap
        );
        assert_eq!(store.count_window_issuances("2026-07").unwrap(), 0);

        let _ = fs::remove_file(path);
    }
}
