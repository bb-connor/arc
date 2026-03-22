use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

#[derive(Debug, thiserror::Error)]
pub enum BudgetStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("failed to prepare budget store directory: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetUsageRecord {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub updated_at: i64,
    pub seq: u64,
    pub total_cost_charged: u64,
}

pub trait BudgetStore: Send {
    fn try_increment(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError>;

    /// Atomically check monetary budget limits and charge cost if within bounds.
    ///
    /// Checks:
    /// 1. `invocation_count < max_invocations` (if set)
    /// 2. `cost_units <= max_cost_per_invocation` (if set)
    /// 3. `total_cost_charged + cost_units <= max_total_cost_units` (if set)
    ///
    /// On pass: increments `invocation_count` by 1 and `total_cost_charged` by
    /// `cost_units`, allocates a new replication seq, returns `Ok(true)`.
    /// On any limit exceeded: rolls back, returns `Ok(false)`.
    ///
    // SAFETY: HA overrun bound = max_cost_per_invocation x node_count
    // In a split-brain scenario, each HA node may independently approve up to
    // one invocation at the full per-invocation cap before the LWW merge
    // propagates the updated total. The maximum possible overrun is therefore
    // bounded by max_cost_per_invocation multiplied by the number of active
    // nodes in the HA cluster.
    fn try_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError>;

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError>;
}

#[derive(Default)]
pub struct InMemoryBudgetStore {
    counts: HashMap<(String, usize), BudgetUsageRecord>,
    next_seq: u64,
}

impl InMemoryBudgetStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BudgetStore for InMemoryBudgetStore {
    fn try_increment(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        let key = (capability_id.to_string(), grant_index);
        let next_seq = self.next_seq.saturating_add(1);
        self.next_seq = next_seq;
        let entry = self.counts.entry(key).or_insert_with(|| BudgetUsageRecord {
            capability_id: capability_id.to_string(),
            grant_index: grant_index as u32,
            invocation_count: 0,
            updated_at: unix_now(),
            seq: 0,
            total_cost_charged: 0,
        });
        if let Some(max) = max_invocations {
            if entry.invocation_count >= max {
                return Ok(false);
            }
        }
        entry.invocation_count = entry.invocation_count.saturating_add(1);
        entry.updated_at = unix_now();
        entry.seq = next_seq;
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
        let key = (capability_id.to_string(), grant_index);
        let entry = self.counts.entry(key).or_insert_with(|| BudgetUsageRecord {
            capability_id: capability_id.to_string(),
            grant_index: grant_index as u32,
            invocation_count: 0,
            updated_at: unix_now(),
            seq: 0,
            total_cost_charged: 0,
        });

        // Check invocation count limit
        if let Some(max) = max_invocations {
            if entry.invocation_count >= max {
                return Ok(false);
            }
        }

        // Check per-invocation cost cap
        if let Some(max_per) = max_cost_per_invocation {
            if cost_units > max_per {
                return Ok(false);
            }
        }

        // Check total cost cap
        if let Some(max_total) = max_total_cost_units {
            if entry.total_cost_charged.saturating_add(cost_units) > max_total {
                return Ok(false);
            }
        }

        // All checks passed: atomically update counts
        let next_seq = self.next_seq.saturating_add(1);
        self.next_seq = next_seq;
        entry.invocation_count = entry.invocation_count.saturating_add(1);
        entry.total_cost_charged = entry.total_cost_charged.saturating_add(cost_units);
        entry.updated_at = unix_now();
        entry.seq = next_seq;
        Ok(true)
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let mut records = self
            .counts
            .values()
            .filter(|record| capability_id.is_none_or(|value| record.capability_id == value))
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            right
                .updated_at
                .cmp(&left.updated_at)
                .then_with(|| left.capability_id.cmp(&right.capability_id))
                .then_with(|| left.grant_index.cmp(&right.grant_index))
        });
        records.truncate(limit);
        Ok(records)
    }
}

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
            if current_cost.saturating_add(cost_units) > max_total {
                transaction.rollback()?;
                return Ok(false);
            }
        }

        // All checks passed: write incremented counts
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
                (current_cost.saturating_add(cost_units)) as i64,
            ],
        )?;
        transaction.commit()?;
        Ok(true)
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
}
