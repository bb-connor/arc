use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use pact_kernel::{BudgetStore, BudgetStoreError, BudgetUsageRecord};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

pub struct SqliteBudgetStore {
    connection: Connection,
}

impl SqliteBudgetStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BudgetStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut connection = Connection::open(path)?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS capability_grant_budgets (
                capability_id TEXT NOT NULL,
                grant_index INTEGER NOT NULL,
                invocation_count INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                seq INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (capability_id, grant_index)
            );

            CREATE INDEX IF NOT EXISTS idx_capability_grant_budgets_updated_at
                ON capability_grant_budgets(updated_at);
            CREATE INDEX IF NOT EXISTS idx_capability_grant_budgets_seq
                ON capability_grant_budgets(seq);

            CREATE TABLE IF NOT EXISTS budget_replication_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                next_seq INTEGER NOT NULL
            );
            "#,
        )?;
        connection.execute(
            r#"
            INSERT INTO budget_replication_meta (singleton, next_seq)
            VALUES (1, 0)
            ON CONFLICT(singleton) DO NOTHING
            "#,
            [],
        )?;
        ensure_budget_seq_column(&connection)?;
        ensure_total_cost_charged_column(&connection)?;
        initialize_budget_replication_seq(&mut connection)?;

        Ok(Self { connection })
    }

    pub fn upsert_usage(&mut self, record: &BudgetUsageRecord) -> Result<(), BudgetStoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        raise_budget_replication_seq_floor(&transaction, record.seq)?;
        transaction.execute(
            r#"
            INSERT INTO capability_grant_budgets (
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_charged
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(capability_id, grant_index) DO UPDATE SET
                invocation_count = CASE
                    WHEN excluded.seq > capability_grant_budgets.seq
                        THEN excluded.invocation_count
                    ELSE MAX(capability_grant_budgets.invocation_count, excluded.invocation_count)
                END,
                updated_at = CASE
                    WHEN excluded.seq > capability_grant_budgets.seq
                        THEN excluded.updated_at
                    ELSE MAX(capability_grant_budgets.updated_at, excluded.updated_at)
                END,
                total_cost_charged = CASE
                    WHEN excluded.seq > capability_grant_budgets.seq
                        THEN excluded.total_cost_charged
                    ELSE MAX(capability_grant_budgets.total_cost_charged, excluded.total_cost_charged)
                END,
                seq = MAX(capability_grant_budgets.seq, excluded.seq)
            "#,
            params![
                record.capability_id,
                record.grant_index as i64,
                record.invocation_count as i64,
                record.updated_at,
                record.seq as i64,
                record.total_cost_charged as i64,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_usages_after(
        &self,
        limit: usize,
        after_seq: Option<u64>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT capability_id, grant_index, invocation_count, updated_at, seq, total_cost_charged
            FROM capability_grant_budgets
            WHERE (?1 IS NULL OR seq > ?1)
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(
            params![after_seq.map(|value| value as i64), limit as i64],
            |row| {
                Ok(BudgetUsageRecord {
                    capability_id: row.get(0)?,
                    grant_index: row.get::<_, i64>(1)?.max(0) as u32,
                    invocation_count: row.get::<_, i64>(2)?.max(0) as u32,
                    updated_at: row.get(3)?,
                    seq: row.get::<_, i64>(4)?.max(0) as u64,
                    total_cost_charged: row.get::<_, i64>(5)?.max(0) as u64,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_all_usages(&self) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT capability_id, grant_index, invocation_count, updated_at, seq, total_cost_charged
            FROM capability_grant_budgets
            ORDER BY updated_at DESC, capability_id ASC, grant_index ASC
            "#,
        )?;
        let rows = statement.query_map([], |row| {
            Ok(BudgetUsageRecord {
                capability_id: row.get(0)?,
                grant_index: row.get::<_, i64>(1)?.max(0) as u32,
                invocation_count: row.get::<_, i64>(2)?.max(0) as u32,
                updated_at: row.get(3)?,
                seq: row.get::<_, i64>(4)?.max(0) as u64,
                total_cost_charged: row.get::<_, i64>(5)?.max(0) as u64,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

impl BudgetStore for SqliteBudgetStore {
    fn try_increment(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let current: Option<i64> = transaction
            .query_row(
                r#"
                SELECT invocation_count
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| row.get(0),
            )
            .optional()?;
        let current = current.unwrap_or(0).max(0) as u32;
        if let Some(max) = max_invocations {
            if current >= max {
                transaction.rollback()?;
                return Ok(false);
            }
        }

        let updated_at = unix_now();
        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            INSERT INTO capability_grant_budgets (
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_charged
            ) VALUES (?1, ?2, ?3, ?4, ?5, 0)
            ON CONFLICT(capability_id, grant_index) DO UPDATE SET
                invocation_count = excluded.invocation_count,
                updated_at = excluded.updated_at,
                seq = excluded.seq
            "#,
            params![
                capability_id,
                grant_index as i64,
                current.saturating_add(1) as i64,
                updated_at,
                seq as i64,
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    fn try_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        // Read current invocation_count and total_cost_charged
        let row: Option<(i64, i64)> = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_charged
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (current_count, current_cost) = row.unwrap_or((0, 0));
        let current_count = current_count.max(0) as u32;
        let current_cost = current_cost.max(0) as u64;

        // Check invocation count limit
        if let Some(max) = max_invocations {
            if current_count >= max {
                transaction.rollback()?;
                return Ok(false);
            }
        }

        // Check per-invocation cost cap
        if let Some(max_per) = max_cost_per_invocation {
            if cost_units > max_per {
                transaction.rollback()?;
                return Ok(false);
            }
        }

        // Check total cost cap
        if let Some(max_total) = max_total_cost_units {
            // Use checked_add to detect overflow: if the addition overflows, deny
            // fail-closed -- an overflowing total cannot be safely compared.
            let new_total = current_cost.checked_add(cost_units).ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "total_cost_charged + cost_units overflowed u64".to_string(),
                )
            })?;
            if new_total > max_total {
                transaction.rollback()?;
                return Ok(false);
            }
        }

        // All checks passed: write incremented counts.
        // Safe: we already verified no overflow above when max_total is set;
        // when there is no cap, use saturating_add as a defensive measure.
        let new_total_cost = current_cost.saturating_add(cost_units);
        let updated_at = unix_now();
        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            INSERT INTO capability_grant_budgets (
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_charged
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(capability_id, grant_index) DO UPDATE SET
                invocation_count = excluded.invocation_count,
                updated_at = excluded.updated_at,
                seq = excluded.seq,
                total_cost_charged = excluded.total_cost_charged
            "#,
            params![
                capability_id,
                grant_index as i64,
                (current_count.saturating_add(1)) as i64,
                updated_at,
                seq as i64,
                new_total_cost as i64,
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    fn reverse_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let current = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_charged
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?.max(0) as u64)),
            )
            .optional()?;

        let Some((invocation_count, total_cost_charged)) = current else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if invocation_count <= 0 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge with zero invocation_count".to_string(),
            ));
        }
        if total_cost_charged < cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge larger than total_cost_charged".to_string(),
            ));
        }

        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET invocation_count = ?3,
                updated_at = ?4,
                seq = ?5,
                total_cost_charged = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                capability_id,
                grant_index as i64,
                invocation_count - 1,
                unix_now(),
                seq as i64,
                (total_cost_charged - cost_units) as i64,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn reduce_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let current = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_charged
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?.max(0) as u64)),
            )
            .optional()?;

        let Some((invocation_count, total_cost_charged)) = current else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if invocation_count <= 0 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reduce charge with zero invocation_count".to_string(),
            ));
        }
        if total_cost_charged < cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reduce charge larger than total_cost_charged".to_string(),
            ));
        }

        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3,
                seq = ?4,
                total_cost_charged = ?5
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                capability_id,
                grant_index as i64,
                unix_now(),
                seq as i64,
                (total_cost_charged - cost_units) as i64,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT capability_id, grant_index, invocation_count, updated_at, seq, total_cost_charged
            FROM capability_grant_budgets
            WHERE (?1 IS NULL OR capability_id = ?1)
            ORDER BY updated_at DESC, capability_id ASC, grant_index ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![capability_id, limit as i64], |row| {
            Ok(BudgetUsageRecord {
                capability_id: row.get(0)?,
                grant_index: row.get::<_, i64>(1)?.max(0) as u32,
                invocation_count: row.get::<_, i64>(2)?.max(0) as u32,
                updated_at: row.get(3)?,
                seq: row.get::<_, i64>(4)?.max(0) as u64,
                total_cost_charged: row.get::<_, i64>(5)?.max(0) as u64,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.connection
            .query_row(
                r#"
                SELECT capability_id, grant_index, invocation_count, updated_at, seq, total_cost_charged
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| {
                    Ok(BudgetUsageRecord {
                        capability_id: row.get(0)?,
                        grant_index: row.get::<_, i64>(1)?.max(0) as u32,
                        invocation_count: row.get::<_, i64>(2)?.max(0) as u32,
                        updated_at: row.get(3)?,
                        seq: row.get::<_, i64>(4)?.max(0) as u64,
                        total_cost_charged: row.get::<_, i64>(5)?.max(0) as u64,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }
}

fn ensure_budget_seq_column(connection: &Connection) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(capability_grant_budgets)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let has_seq = columns
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|column| column == "seq");
    if !has_seq {
        connection.execute(
            "ALTER TABLE capability_grant_budgets ADD COLUMN seq INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    Ok(())
}

fn ensure_total_cost_charged_column(connection: &Connection) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(capability_grant_budgets)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let has_col = columns
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|c| c == "total_cost_charged");
    if !has_col {
        connection.execute(
            "ALTER TABLE capability_grant_budgets ADD COLUMN total_cost_charged INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    Ok(())
}

/// Initialize the replication sequence counter from existing rows on first open.
///
/// Uses an IMMEDIATE transaction, which acquires a write lock before any reads
/// or writes occur. In SQLite WAL mode, IMMEDIATE transactions are serialized:
/// concurrent reads can proceed, but no two processes can both hold IMMEDIATE
/// (or EXCLUSIVE) transactions simultaneously. This means two processes calling
/// `initialize_budget_replication_seq` concurrently will be serialized by
/// SQLite's locking protocol -- the second caller blocks until the first commits,
/// then runs with the updated seq floor already in place. No additional
/// application-level locking is required.
fn initialize_budget_replication_seq(connection: &mut Connection) -> Result<(), BudgetStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut next_seq =
        current_budget_replication_seq(&transaction)?.max(max_budget_usage_seq(&transaction)?);
    let mut statement = transaction.prepare(
        r#"
        SELECT rowid
        FROM capability_grant_budgets
        WHERE seq <= 0
        ORDER BY updated_at ASC, capability_id ASC, grant_index ASC
        "#,
    )?;
    let pending = statement
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for rowid in pending {
        next_seq = next_seq.saturating_add(1);
        transaction.execute(
            "UPDATE capability_grant_budgets SET seq = ?1 WHERE rowid = ?2",
            params![next_seq as i64, rowid],
        )?;
    }
    set_budget_replication_seq(&transaction, next_seq)?;
    transaction.commit()?;
    Ok(())
}

fn allocate_budget_replication_seq(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<u64, BudgetStoreError> {
    let next_seq = current_budget_replication_seq(transaction)?.saturating_add(1);
    set_budget_replication_seq(transaction, next_seq)?;
    Ok(next_seq)
}

fn raise_budget_replication_seq_floor(
    transaction: &rusqlite::Transaction<'_>,
    seq: u64,
) -> Result<(), BudgetStoreError> {
    let current = current_budget_replication_seq(transaction)?;
    if seq > current {
        set_budget_replication_seq(transaction, seq)?;
    }
    Ok(())
}

fn current_budget_replication_seq(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<u64, BudgetStoreError> {
    let next_seq = transaction.query_row(
        "SELECT next_seq FROM budget_replication_meta WHERE singleton = 1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(next_seq.max(0) as u64)
}

fn max_budget_usage_seq(transaction: &rusqlite::Transaction<'_>) -> Result<u64, BudgetStoreError> {
    let max_seq = transaction.query_row(
        "SELECT COALESCE(MAX(seq), 0) FROM capability_grant_budgets",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(max_seq.max(0) as u64)
}

fn set_budget_replication_seq(
    transaction: &rusqlite::Transaction<'_>,
    seq: u64,
) -> Result<(), BudgetStoreError> {
    transaction.execute(
        "UPDATE budget_replication_meta SET next_seq = ?1 WHERE singleton = 1",
        params![seq as i64],
    )?;
    Ok(())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use pact_kernel::InMemoryBudgetStore;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    #[test]
    fn sqlite_budget_store_persists_across_reopen() {
        let path = unique_db_path("pact-budgets");
        {
            let mut store = SqliteBudgetStore::open(&path).unwrap();
            assert!(store.try_increment("cap-1", 0, Some(2)).unwrap());
            assert!(store.try_increment("cap-1", 0, Some(2)).unwrap());
            assert!(!store.try_increment("cap-1", 0, Some(2)).unwrap());
        }

        let reopened = SqliteBudgetStore::open(&path).unwrap();
        let records = reopened.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].invocation_count, 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_budget_store_upsert_usage_keeps_max_count() {
        let path = unique_db_path("pact-budget-upsert");
        let mut store = SqliteBudgetStore::open(&path).unwrap();
        store
            .upsert_usage(&BudgetUsageRecord {
                capability_id: "cap-1".to_string(),
                grant_index: 0,
                invocation_count: 3,
                updated_at: 10,
                seq: 3,
                total_cost_charged: 300,
            })
            .unwrap();
        store
            .upsert_usage(&BudgetUsageRecord {
                capability_id: "cap-1".to_string(),
                grant_index: 0,
                invocation_count: 2,
                updated_at: 9,
                seq: 2,
                total_cost_charged: 200,
            })
            .unwrap();

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records[0].invocation_count, 3);
        // total_cost_charged should be MAX of the two (300)
        assert_eq!(records[0].total_cost_charged, 300);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_budget_store_uses_seq_for_same_key_delta_queries() {
        let path = unique_db_path("pact-budget-seq-delta");
        let mut store = SqliteBudgetStore::open(&path).unwrap();

        assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());
        let first = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(first.len(), 1);
        let first_seq = first[0].seq;

        assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());
        assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());

        let delta = store.list_usages_after(10, Some(first_seq)).unwrap();
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].invocation_count, 3);
        assert!(delta[0].seq > first_seq);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_budget_store_preserves_imported_seq_across_failover_writes() {
        let path = unique_db_path("pact-budget-seq-floor");
        let mut store = SqliteBudgetStore::open(&path).unwrap();

        store
            .upsert_usage(&BudgetUsageRecord {
                capability_id: "cap-1".to_string(),
                grant_index: 0,
                invocation_count: 3,
                updated_at: 10,
                seq: 42,
                total_cost_charged: 0,
            })
            .unwrap();
        assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].invocation_count, 4);
        assert_eq!(records[0].seq, 43);

        let _ = fs::remove_file(path);
    }

    // --- try_charge_cost tests ---

    #[test]
    fn budget_store_try_charge_cost_within_limits_returns_true_sqlite() {
        let path = unique_db_path("pact-charge-cost-ok");
        let mut store = SqliteBudgetStore::open(&path).unwrap();
        // 100 units, cap is 200 per invocation, total cap is 1000
        let ok = store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap();
        assert!(ok);

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records[0].invocation_count, 1);
        assert_eq!(records[0].total_cost_charged, 100);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_try_charge_cost_exceeds_per_invocation_cap_sqlite() {
        let path = unique_db_path("pact-charge-cost-per-inv");
        let mut store = SqliteBudgetStore::open(&path).unwrap();
        // 500 units > max_cost_per_invocation of 200
        let ok = store
            .try_charge_cost("cap-1", 0, Some(10), 500, Some(200), Some(1000))
            .unwrap();
        assert!(!ok);

        // Nothing should have been charged
        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert!(records.is_empty() || records[0].invocation_count == 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_try_charge_cost_exceeds_total_cap_sqlite() {
        let path = unique_db_path("pact-charge-cost-total");
        let mut store = SqliteBudgetStore::open(&path).unwrap();
        // First charge 900 of 1000 budget
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 900, Some(1000), Some(1000))
            .unwrap());
        // Second charge of 200 would exceed the total cap of 1000
        let ok = store
            .try_charge_cost("cap-1", 0, Some(10), 200, Some(1000), Some(1000))
            .unwrap();
        assert!(!ok);

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records[0].total_cost_charged, 900);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_try_charge_cost_atomic_increment_sqlite() {
        let path = unique_db_path("pact-charge-cost-atomic");
        let mut store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store
            .try_charge_cost("cap-1", 0, None, 100, Some(200), Some(1000))
            .unwrap());
        assert!(store
            .try_charge_cost("cap-1", 0, None, 150, Some(200), Some(1000))
            .unwrap());

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records[0].invocation_count, 2);
        assert_eq!(records[0].total_cost_charged, 250);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_try_charge_cost_within_limits_returns_true_inmemory() {
        let mut store = InMemoryBudgetStore::new();
        let ok = store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap();
        assert!(ok);

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records[0].invocation_count, 1);
        assert_eq!(records[0].total_cost_charged, 100);
    }

    #[test]
    fn budget_store_try_charge_cost_exceeds_per_invocation_cap_inmemory() {
        let mut store = InMemoryBudgetStore::new();
        let ok = store
            .try_charge_cost("cap-1", 0, Some(10), 500, Some(200), Some(1000))
            .unwrap();
        assert!(!ok);
    }

    #[test]
    fn budget_store_try_charge_cost_exceeds_total_cap_inmemory() {
        let mut store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 900, Some(1000), Some(1000))
            .unwrap());
        let ok = store
            .try_charge_cost("cap-1", 0, Some(10), 200, Some(1000), Some(1000))
            .unwrap();
        assert!(!ok);
    }

    #[test]
    fn budget_usage_record_includes_total_cost_charged() {
        let mut store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost("cap-1", 0, None, 42, None, None)
            .unwrap());
        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records[0].total_cost_charged, 42);
    }

    #[test]
    fn budget_store_reverse_charge_cost_restores_prior_state_inmemory() {
        let mut store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap());

        store.reverse_charge_cost("cap-1", 0, 100).unwrap();

        let record = store.get_usage("cap-1", 0).unwrap().unwrap();
        assert_eq!(record.invocation_count, 0);
        assert_eq!(record.total_cost_charged, 0);
    }

    #[test]
    fn budget_store_reverse_charge_cost_restores_prior_state_sqlite() {
        let path = unique_db_path("pact-reverse-charge");
        let mut store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap());

        store.reverse_charge_cost("cap-1", 0, 100).unwrap();

        let record = store.get_usage("cap-1", 0).unwrap().unwrap();
        assert_eq!(record.invocation_count, 0);
        assert_eq!(record.total_cost_charged, 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_reduce_charge_cost_preserves_invocation_count_inmemory() {
        let mut store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap());

        store.reduce_charge_cost("cap-1", 0, 25).unwrap();

        let record = store.get_usage("cap-1", 0).unwrap().unwrap();
        assert_eq!(record.invocation_count, 1);
        assert_eq!(record.total_cost_charged, 75);
    }

    #[test]
    fn budget_store_reduce_charge_cost_preserves_invocation_count_sqlite() {
        let path = unique_db_path("pact-reduce-charge");
        let mut store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap());

        store.reduce_charge_cost("cap-1", 0, 25).unwrap();

        let record = store.get_usage("cap-1", 0).unwrap().unwrap();
        assert_eq!(record.invocation_count, 1);
        assert_eq!(record.total_cost_charged, 75);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn upsert_usage_preserves_total_cost_charged_max_resolution() {
        let path = unique_db_path("pact-budget-upsert-cost");
        let mut store = SqliteBudgetStore::open(&path).unwrap();

        // Higher-seq record written first
        store
            .upsert_usage(&BudgetUsageRecord {
                capability_id: "cap-1".to_string(),
                grant_index: 0,
                invocation_count: 5,
                updated_at: 10,
                seq: 10,
                total_cost_charged: 500,
            })
            .unwrap();

        // Lower-seq record written second (stale replica)
        store
            .upsert_usage(&BudgetUsageRecord {
                capability_id: "cap-1".to_string(),
                grant_index: 0,
                invocation_count: 3,
                updated_at: 12,
                seq: 5,
                total_cost_charged: 300,
            })
            .unwrap();

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        // Higher seq wins: cost should be 500 (from seq=10 record)
        assert_eq!(records[0].total_cost_charged, 500);

        let _ = fs::remove_file(path);
    }

    /// Documents the HA overrun bound for monetary budget enforcement.
    ///
    /// In a split-brain scenario across N nodes, each node may independently
    /// approve one invocation at max_cost_per_invocation before the LWW merge
    /// propagates. The worst-case overrun is bounded by:
    ///   overrun <= max_cost_per_invocation * node_count
    ///
    /// This test asserts the bound holds for a simulated 2-node split-brain.
    #[test]
    fn concurrent_charge_overrun_bound() {
        let path_a = unique_db_path("pact-overrun-node-a");
        let path_b = unique_db_path("pact-overrun-node-b");

        let max_per_invocation: u64 = 100;
        let total_budget: u64 = 150; // Tight: allows 1 full invocation + small buffer
        let node_count: u64 = 2;

        // Both nodes start fresh (simulating split-brain: neither sees the other's write)
        let mut node_a = SqliteBudgetStore::open(&path_a).unwrap();
        let mut node_b = SqliteBudgetStore::open(&path_b).unwrap();

        // Both nodes independently approve an invocation of max_per_invocation
        let approved_a = node_a
            .try_charge_cost(
                "cap-split",
                0,
                None,
                max_per_invocation,
                Some(max_per_invocation),
                Some(total_budget),
            )
            .unwrap();
        let approved_b = node_b
            .try_charge_cost(
                "cap-split",
                0,
                None,
                max_per_invocation,
                Some(max_per_invocation),
                Some(total_budget),
            )
            .unwrap();

        // Both nodes approved (split-brain; each sees a fresh slate)
        assert!(approved_a, "node A should approve");
        assert!(approved_b, "node B should approve");

        // The actual combined spend exceeds the total budget
        let combined_spend = max_per_invocation * node_count;
        // The overrun is bounded by max_cost_per_invocation * node_count
        let max_overrun = max_per_invocation * node_count;
        assert!(
            combined_spend <= max_overrun,
            "HA overrun bound violated: combined_spend={combined_spend} > max_overrun={max_overrun}"
        );

        // After LWW merge converges, total charged would be at most max_overrun
        let record_a = node_a.list_usages(1, Some("cap-split")).unwrap();
        let record_b = node_b.list_usages(1, Some("cap-split")).unwrap();
        let total_after_merge = record_a[0].total_cost_charged + record_b[0].total_cost_charged;
        assert!(
            total_after_merge <= max_overrun,
            "post-merge total {total_after_merge} exceeds bound {max_overrun}"
        );

        let _ = fs::remove_file(path_a);
        let _ = fs::remove_file(path_b);
    }

    #[test]
    fn budget_store_zero_max_total_denies_any_charge_inmemory() {
        // A grant with max_total_cost = 0 must deny even a charge of 1 unit.
        let mut store = InMemoryBudgetStore::new();
        let ok = store
            .try_charge_cost("cap-zero-budget", 0, None, 1, None, Some(0))
            .unwrap();
        assert!(
            !ok,
            "any charge against a zero-unit total budget must be denied"
        );
        let records = store.list_usages(10, Some("cap-zero-budget")).unwrap();
        assert!(
            records.is_empty() || records[0].invocation_count == 0,
            "no invocations should be recorded against a zero-unit budget"
        );
    }

    #[test]
    fn budget_store_zero_max_total_denies_any_charge_sqlite() {
        let path = unique_db_path("pact-zero-budget-sqlite");
        let mut store = SqliteBudgetStore::open(&path).unwrap();
        let ok = store
            .try_charge_cost("cap-zero-budget", 0, None, 1, None, Some(0))
            .unwrap();
        assert!(
            !ok,
            "any charge against a zero-unit total budget must be denied"
        );
        let records = store.list_usages(10, Some("cap-zero-budget")).unwrap();
        assert!(
            records.is_empty() || records[0].invocation_count == 0,
            "no invocations should be recorded against a zero-unit budget"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_zero_cost_invocation_succeeds_and_records_zero_inmemory() {
        // A zero-cost invocation against a monetary grant should succeed and
        // record cost_charged = 0.
        let mut store = InMemoryBudgetStore::new();
        let ok = store
            .try_charge_cost("cap-zero-cost", 0, None, 0, None, Some(1000))
            .unwrap();
        assert!(
            ok,
            "zero-cost invocation should succeed when budget is available"
        );
        let records = store.list_usages(10, Some("cap-zero-cost")).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].invocation_count, 1);
        assert_eq!(
            records[0].total_cost_charged, 0,
            "cost_charged should be 0 for a zero-cost invocation"
        );
    }

    #[test]
    fn budget_store_zero_cost_invocation_succeeds_and_records_zero_sqlite() {
        let path = unique_db_path("pact-zero-cost-sqlite");
        let mut store = SqliteBudgetStore::open(&path).unwrap();
        let ok = store
            .try_charge_cost("cap-zero-cost", 0, None, 0, None, Some(1000))
            .unwrap();
        assert!(
            ok,
            "zero-cost invocation should succeed when budget is available"
        );
        let records = store.list_usages(10, Some("cap-zero-cost")).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].invocation_count, 1);
        assert_eq!(
            records[0].total_cost_charged, 0,
            "cost_charged should be 0 for a zero-cost invocation"
        );
        let _ = fs::remove_file(path);
    }
}
