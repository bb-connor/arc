#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
use super::*;

#[path = "composite_schema/payment/sql_normalizer.rs"]
mod sql_normalizer;

#[cfg(test)]
#[path = "composite_schema/payment/tests.rs"]
mod payment_tests;

pub(super) const SCHEMA: &str = concat!(
    include_str!("schema.sql"),
    include_str!("composite_schema/payment/schema.sql")
);

const CATALOG_PREDICATE: &str = "lower(tbl_name) GLOB 'budget_*'
    OR lower(name) GLOB 'budget_*' OR lower(name) GLOB 'idx_budget_*'
    OR lower(tbl_name) = 'capability_grant_budgets'
    OR lower(name) GLOB 'capability_grant_budgets_*'
    OR lower(name) GLOB 'idx_capability_grant_budgets_*'
    OR lower(tbl_name) IN ('payment_journal', 'payment_release_evidence')
    OR lower(name) GLOB 'payment_journal_*'
    OR lower(name) GLOB 'idx_payment_journal_*'
    OR lower(name) GLOB 'payment_release_evidence_*'";

type CatalogEntry = (String, String, String, Option<String>);

fn budget_catalog(connection: &Connection) -> Result<Vec<CatalogEntry>, BudgetStoreError> {
    let (count, bytes): (i64, i64) = connection.query_row(
        &format!(
            "SELECT COUNT(*), COALESCE(SUM(
                 COALESCE(length(CAST(sql AS BLOB)), 0)
                 + length(CAST(name AS BLOB)) + length(CAST(tbl_name AS BLOB))
             ), 0) FROM sqlite_schema WHERE {CATALOG_PREDICATE}"
        ),
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if !(0..=128).contains(&count) || !(0..=262_144).contains(&bytes) {
        return Err(BudgetStoreError::Invariant(
            "budget schema exceeds its catalog bounds".into(),
        ));
    }
    let mut statement = connection.prepare(&format!(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE {CATALOG_PREDICATE} ORDER BY type, name, tbl_name"
    ))?;
    let entries = statement
        .query_map([], |row| {
            let sql: Option<String> = row.get(3)?;
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                sql.as_deref().map(sql_normalizer::normalize_sql),
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(entries)
}

pub(super) fn verify_budget_catalog(connection: &Connection) -> Result<(), BudgetStoreError> {
    let actual = budget_catalog(connection)?;
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SCHEMA)?;
    if actual != budget_catalog(&expected)? {
        return Err(schema_shape_error());
    }
    Ok(())
}

pub(super) fn schema_shape_error() -> BudgetStoreError {
    BudgetStoreError::Invariant("budget schema does not match the current v1 shape".into())
}

pub(super) fn verify_budget_replication_state(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let invalid: bool = connection.query_row(
        "SELECT NOT EXISTS (
             SELECT 1 FROM budget_replication_meta WHERE singleton = 1 AND typeof(next_seq) = 'integer' AND next_seq >= 0
         ) OR EXISTS (
             SELECT 1 FROM capability_grant_budgets WHERE typeof(seq) <> 'integer' OR seq <= 0
         ) OR EXISTS (
             SELECT 1 FROM budget_mutation_events WHERE typeof(event_seq) <> 'integer' OR event_seq <= 0
         ) OR EXISTS (
             SELECT 1 FROM budget_usage_history_anchors WHERE anchored_schema_version <> 1
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid {
        return Err(BudgetStoreError::Invariant(
            "budget replication state is invalid".into(),
        ));
    }
    Ok(())
}
