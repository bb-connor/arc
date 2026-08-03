use super::*;

pub(super) fn sqlite_integer_from_u64(value: u64, label: &str) -> Result<i64, BudgetStoreError> {
    i64::try_from(value)
        .map_err(|_| BudgetStoreError::Overflow(format!("{label} exceeds SQLite INTEGER")))
}

fn checked_next_replication_seq(current: u64) -> Result<u64, BudgetStoreError> {
    let next = current.checked_add(1).ok_or_else(|| {
        BudgetStoreError::Overflow("budget replication sequence overflowed u64".to_string())
    })?;
    sqlite_integer_from_u64(next, "budget replication sequence")?;
    Ok(next)
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
pub(super) fn initialize_budget_replication_seq(
    connection: &mut Connection,
) -> Result<(), BudgetStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut next_seq = current_budget_replication_seq(&transaction)?
        .max(max_budget_usage_seq(&transaction)?)
        .max(max_budget_invocation_quota_seq(&transaction)?)
        .max(max_budget_mutation_event_seq(&transaction)?);
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
        next_seq = checked_next_replication_seq(next_seq)?;
        let sqlite_next_seq = sqlite_integer_from_u64(next_seq, "budget replication sequence")?;
        transaction.execute(
            "UPDATE capability_grant_budgets SET seq = ?1 WHERE rowid = ?2",
            params![sqlite_next_seq, rowid],
        )?;
    }

    let existing_event_seq_count = transaction.query_row(
        "SELECT COUNT(*) FROM budget_mutation_events WHERE event_seq IS NOT NULL AND event_seq > 0",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    if existing_event_seq_count <= 0 {
        let mut statement = transaction.prepare(
            r#"
            SELECT rowid
            FROM budget_mutation_events
            ORDER BY rowid ASC
            "#,
        )?;
        let pending = statement
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut event_seq = 0u64;
        for rowid in pending {
            event_seq = checked_next_replication_seq(event_seq)?;
            let sqlite_event_seq = sqlite_integer_from_u64(event_seq, "budget event sequence")?;
            transaction.execute(
                "UPDATE budget_mutation_events SET event_seq = ?1 WHERE rowid = ?2",
                params![sqlite_event_seq, rowid],
            )?;
        }
        next_seq = next_seq.max(event_seq);
    } else {
        let mut statement = transaction.prepare(
            r#"
            SELECT rowid
            FROM budget_mutation_events
            WHERE event_seq IS NULL OR event_seq <= 0
            ORDER BY rowid ASC
            "#,
        )?;
        let pending = statement
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for rowid in pending {
            next_seq = checked_next_replication_seq(next_seq)?;
            let sqlite_next_seq = sqlite_integer_from_u64(next_seq, "budget replication sequence")?;
            transaction.execute(
                "UPDATE budget_mutation_events SET event_seq = ?1 WHERE rowid = ?2",
                params![sqlite_next_seq, rowid],
            )?;
        }
    }
    set_budget_replication_seq(&transaction, next_seq)?;
    transaction.commit()?;
    Ok(())
}

pub(super) fn allocate_budget_replication_seq(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<u64, BudgetStoreError> {
    let authoritative = max_budget_usage_seq(transaction)?
        .max(max_budget_invocation_quota_seq(transaction)?)
        .max(max_budget_mutation_event_seq(transaction)?);
    let current = if SqliteBudgetStore::admission_authority_mode(transaction)?.is_some() {
        authoritative
    } else {
        current_budget_replication_seq(transaction)?.max(authoritative)
    };
    let next_seq = checked_next_replication_seq(current)?;
    set_budget_replication_seq(transaction, next_seq)?;
    Ok(next_seq)
}

pub(super) fn raise_budget_replication_seq_floor(
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
        |row| budget_u64_from_row(row, 0, "next_seq"),
    )?;
    Ok(next_seq)
}

fn max_budget_usage_seq(transaction: &rusqlite::Transaction<'_>) -> Result<u64, BudgetStoreError> {
    let max_seq = transaction.query_row(
        "SELECT COALESCE(MAX(seq), 0) FROM capability_grant_budgets",
        [],
        |row| budget_u64_from_row(row, 0, "seq"),
    )?;
    Ok(max_seq)
}

fn max_budget_invocation_quota_seq(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<u64, BudgetStoreError> {
    let max_seq = transaction.query_row(
        "SELECT COALESCE(MAX(seq), 0) FROM budget_invocation_quota_usage",
        [],
        |row| budget_u64_from_row(row, 0, "invocation quota usage sequence"),
    )?;
    Ok(max_seq)
}

fn max_budget_mutation_event_seq(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<u64, BudgetStoreError> {
    let max_seq = transaction.query_row(
        "SELECT COALESCE(MAX(event_seq), 0) FROM budget_mutation_events",
        [],
        |row| budget_u64_from_row(row, 0, "event_seq"),
    )?;
    Ok(max_seq)
}

fn set_budget_replication_seq(
    transaction: &rusqlite::Transaction<'_>,
    seq: u64,
) -> Result<(), BudgetStoreError> {
    let sqlite_seq = sqlite_integer_from_u64(seq, "budget replication sequence")?;
    transaction.execute(
        "UPDATE budget_replication_meta SET next_seq = ?1 WHERE singleton = 1",
        params![sqlite_seq],
    )?;
    Ok(())
}

pub(super) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
