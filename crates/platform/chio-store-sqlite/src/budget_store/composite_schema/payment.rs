//! Preserve original journal facts while adding exact debit and attempt custody.
use super::*;

#[cfg(test)]
#[path = "payment/tests.rs"]
mod tests;

const VERSION: i32 = 12;
const SCHEMA: &str = include_str!("payment/schema.sql");
const LEGACY: &str = include_str!("payment/legacy_v11.sql");
const COLUMNS: &str = "operation_id, journal_version, request_namespace_digest, request_id,
 capability_id, grant_index, hold_id, rail, rail_mode, authorization_id, transaction_id,
 amount_units, settle_action, settle_amount_units, release_authority_kind,
 release_authority_evidence_id, release_authority_evidence_digest,
 release_authority_operation_version, currency, state, created_at_unix_ms, updated_at_unix_ms";
const CANCELLED_BRANCH: &str = r#"                OR
                (state = 'closed'
                 AND authorization_id IS NULL AND transaction_id IS NULL
                 AND settle_action IS NULL AND settle_amount_units IS NULL
                 AND release_authority_kind IS NULL
                 AND release_authority_evidence_id IS NULL
                 AND release_authority_evidence_digest IS NULL
                 AND release_authority_operation_version IS NULL)
"#;
type CatalogEntry = (String, String, String, Option<String>);

pub(super) fn ensure(
    transaction: &rusqlite::Transaction<'_>,
    on_disk_version: i32,
) -> Result<(), BudgetStoreError> {
    let actual = catalog(transaction)?;
    if actual.is_empty() {
        if on_disk_version >= VERSION {
            return Err(invalid("schema12 payment journal catalog is missing"));
        }
        transaction.execute_batch(SCHEMA)?;
    } else if on_disk_version >= VERSION {
        verify(transaction, SCHEMA)?;
    } else {
        let legacy = expected(LEGACY)?;
        let pre_cancel = expected(&LEGACY.replace(CANCELLED_BRANCH, ""))?;
        if actual != legacy && !(on_disk_version < 11 && actual == pre_cancel) {
            return Err(invalid(
                "pre-schema12 payment journal catalog is not a supported predecessor",
            ));
        }
        migrate(transaction)?;
    }
    verify(transaction, SCHEMA)
}

fn migrate(transaction: &rusqlite::Transaction<'_>) -> Result<(), BudgetStoreError> {
    let before: i64 =
        transaction.query_row("SELECT COUNT(*) FROM payment_journal", [], |row| row.get(0))?;
    transaction.execute_batch("PRAGMA defer_foreign_keys=ON;")?;
    transaction.execute_batch(&format!(
        "CREATE TEMP TABLE payment_journal_migration AS SELECT {COLUMNS} FROM payment_journal;
         DROP TRIGGER payment_journal_identity_immutable;
         DROP TRIGGER payment_journal_no_delete;
         DROP TABLE payment_journal;"
    ))?;
    transaction.execute_batch(SCHEMA)?;
    transaction.execute_batch(&format!(
        "INSERT INTO payment_journal ({COLUMNS}) SELECT {COLUMNS} FROM payment_journal_migration;
         DROP TABLE payment_journal_migration;"
    ))?;
    let after: i64 =
        transaction.query_row("SELECT COUNT(*) FROM payment_journal", [], |row| row.get(0))?;
    if before != after {
        return Err(invalid(
            "schema12 migration lost an original payment journal row",
        ));
    }
    verify_budget_foreign_keys(transaction)?;
    transaction.execute_batch("PRAGMA defer_foreign_keys=OFF;")?;
    Ok(())
}

fn catalog(connection: &Connection) -> Result<Vec<CatalogEntry>, BudgetStoreError> {
    let (count, bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(CAST(sql AS BLOB))),0) FROM sqlite_schema
         WHERE lower(tbl_name)='payment_journal' OR lower(name) GLOB 'payment_journal_*'
            OR lower(name) GLOB 'idx_payment_journal_*'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if !(0..=16).contains(&count) || !(0..=131_072).contains(&bytes) {
        return Err(invalid("payment journal catalog exceeds its bound"));
    }
    let mut statement = connection.prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema
         WHERE lower(tbl_name)='payment_journal' OR lower(name) GLOB 'payment_journal_*'
            OR lower(name) GLOB 'idx_payment_journal_*' ORDER BY type,name,tbl_name",
    )?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(entries)
}

fn expected(sql: &str) -> Result<Vec<CatalogEntry>, BudgetStoreError> {
    let memory = Connection::open_in_memory()?;
    memory.execute_batch(sql)?;
    catalog(&memory)
}

fn verify(connection: &Connection, sql: &str) -> Result<(), BudgetStoreError> {
    if catalog(connection)? != expected(sql)? {
        return Err(invalid("schema12 payment journal catalog differs"));
    }
    Ok(())
}

fn invalid(reason: &str) -> BudgetStoreError {
    BudgetStoreError::Invariant(reason.into())
}
