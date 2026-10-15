//! Bounded TEXT columns refuse embedded NULs and bounded BLOB columns refuse
//! TEXT.
//!
//! SQLite's `length()` and `GLOB` stop at the first NUL in a TEXT value, so a
//! valid prefix could otherwise carry an unbounded tail. Each probe copies one
//! bounded column definition out of a live catalog into a UTF-8 and a UTF-16
//! database, inserts a value whose prefix is valid and whose tail is a NUL plus
//! a megabyte of padding, and requires the column CHECK to refuse it.

use std::error::Error;

use rusqlite::types::Value;
use rusqlite::{ffi, Connection};

const PADDING: usize = 1 << 20;
const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

type TestResult = Result<(), Box<dyn Error>>;

#[derive(Clone, Copy)]
enum Bound {
    /// A TEXT column whose valid value is the given string.
    Text(&'static str),
    /// A TEXT column of exact width, which must also refuse an in-width NUL.
    ExactText(&'static str),
    /// A BLOB column whose valid value has the given length.
    Blob(usize),
}

fn column_definition(table_sql: &str, column: &str) -> Option<String> {
    let open = table_sql.find('(')?;
    let mut depth = 0usize;
    let mut quoted = false;
    let mut start = open + 1;
    let mut items = Vec::new();
    for (offset, ch) in table_sql[open..].char_indices() {
        let index = open + offset;
        match ch {
            '\'' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => {
                depth -= 1;
                if depth == 0 {
                    items.push(&table_sql[start..index]);
                    break;
                }
            }
            ',' if !quoted && depth == 1 => {
                items.push(&table_sql[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    items
        .into_iter()
        .map(str::trim)
        .find(|item| item.split_whitespace().next() == Some(column))
        .map(str::to_owned)
}

fn insert(probe: &Connection, value: Value) -> rusqlite::Result<usize> {
    probe.execute("INSERT INTO probe VALUES (?1)", [value])
}

fn is_check_refusal(result: &rusqlite::Result<usize>) -> bool {
    matches!(
        result,
        Err(rusqlite::Error::SqliteFailure(error, Some(_)))
            if error.extended_code == ffi::SQLITE_CONSTRAINT_CHECK
    )
}

fn nul_padded(prefix: &str) -> String {
    format!("{prefix}\0{}", "a".repeat(PADDING))
}

fn assert_column_refuses_nul_padding(
    catalog: &Connection,
    table: &str,
    column: &str,
    bound: Bound,
) -> TestResult {
    let table_sql: String = catalog.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get(0),
    )?;
    let definition =
        column_definition(&table_sql, column).ok_or(format!("{table}.{column} is not defined"))?;
    for encoding in ["UTF-8", "UTF-16le"] {
        let probe = Connection::open_in_memory()?;
        probe.execute_batch(&format!(
            "PRAGMA encoding = '{encoding}'; CREATE TABLE probe ({definition});"
        ))?;
        match bound {
            Bound::Text(valid) | Bound::ExactText(valid) => {
                assert_eq!(
                    insert(&probe, Value::Text(valid.to_owned()))?,
                    1,
                    "{table}.{column}"
                );
                let padded = insert(&probe, Value::Text(nul_padded(valid)));
                assert!(is_check_refusal(&padded), "{table}.{column}: {padded:?}");
            }
            Bound::Blob(len) => {
                assert_eq!(
                    insert(&probe, Value::Blob(vec![1; len]))?,
                    1,
                    "{table}.{column}"
                );
                let text = insert(&probe, Value::Text(nul_padded(&"a".repeat(len))));
                assert!(is_check_refusal(&text), "{table}.{column}: {text:?}");
            }
        }
        if let Bound::ExactText(valid) = bound {
            let mut in_width = valid[..valid.len() - 1].to_owned();
            in_width.push('\0');
            let refused = insert(&probe, Value::Text(in_width));
            assert!(is_check_refusal(&refused), "{table}.{column}: {refused:?}");
        }
    }
    Ok(())
}

fn catalog(schema: &str) -> rusqlite::Result<Connection> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(schema)?;
    Ok(connection)
}

#[test]
fn caller_execution_ledger_refuses_nul_padding() -> TestResult {
    let catalog = catalog(include_str!("caller_execution_ledger.sql"))?;
    assert_column_refuses_nul_padding(
        &catalog,
        "caller_executor_configuration",
        "device",
        Bound::Text("device"),
    )?;
    assert_column_refuses_nul_padding(
        &catalog,
        "caller_executor_configuration",
        "identity",
        Bound::Blob(32),
    )
}

#[test]
fn channel_lifecycle_refuses_nul_padding() -> TestResult {
    let catalog = catalog(include_str!("channel_lifecycle_store.sql"))?;
    assert_column_refuses_nul_padding(
        &catalog,
        "channel_lifecycle_records",
        "open_digest",
        Bound::ExactText(HEX64),
    )?;
    assert_column_refuses_nul_padding(
        &catalog,
        "channel_lifecycle_records",
        "open_json",
        Bound::Blob(16),
    )
}

#[test]
fn channel_release_publisher_refuses_nul_padding() -> TestResult {
    let catalog = catalog(include_str!("channel_release_publisher_store.sql"))?;
    assert_column_refuses_nul_padding(
        &catalog,
        "chio_channel_release_publications",
        "open_digest",
        Bound::ExactText(HEX64),
    )
}

#[test]
fn economic_state_cache_refuses_nul_padding() -> TestResult {
    let catalog = catalog(include_str!("economic_state_cache.sql"))?;
    assert_column_refuses_nul_padding(
        &catalog,
        "economic_state_stages",
        "checkpoint_digest",
        Bound::ExactText(HEX64),
    )
}

#[test]
fn finding_challenge_refuses_nul_padding() -> TestResult {
    let catalog = catalog(include_str!("finding_challenge_store.sql"))?;
    assert_column_refuses_nul_padding(
        &catalog,
        "challenges",
        "challenge_envelope_sha256",
        Bound::ExactText(HEX64),
    )?;
    assert_column_refuses_nul_padding(&catalog, "challenges", "listing_id", Bound::Text("listing"))
}

#[test]
fn finding_market_refuses_nul_padding() -> TestResult {
    let catalog = catalog(include_str!("finding_market_store.sql"))?;
    assert_column_refuses_nul_padding(
        &catalog,
        "collateral_allocations",
        "backing_envelope_sha256",
        Bound::ExactText(HEX64),
    )?;
    assert_column_refuses_nul_padding(&catalog, "findings", "artifact_json", Bound::Text("{}"))
}

#[test]
fn finding_purchase_refuses_nul_padding() -> TestResult {
    let catalog = catalog(include_str!("finding_purchase_store.sql"))?;
    assert_column_refuses_nul_padding(
        &catalog,
        "purchase_reservations",
        "bid_envelope_sha256",
        Bound::ExactText(HEX64),
    )?;
    assert_column_refuses_nul_padding(
        &catalog,
        "purchase_reservations",
        "agent_id",
        Bound::Text("agent"),
    )
}

#[test]
fn finding_recovery_refuses_nul_padding() -> TestResult {
    let catalog = catalog(include_str!("finding_recovery_store.sql"))?;
    assert_column_refuses_nul_padding(
        &catalog,
        "finding_recovery_issuances",
        "original_subject_key_hex",
        Bound::ExactText(HEX64),
    )
}

#[test]
fn finding_status_refuses_nul_padding() -> TestResult {
    let catalog = catalog(include_str!("finding_status_store.sql"))?;
    assert_column_refuses_nul_padding(
        &catalog,
        "finding_status_epochs",
        "signed_epoch_sha256",
        Bound::ExactText(HEX64),
    )
}

#[test]
fn fiscal_refuses_nul_padding() -> TestResult {
    let catalog = catalog(include_str!("fiscal_store.sql"))?;
    assert_column_refuses_nul_padding(
        &catalog,
        "fiscal_authority_state",
        "finalized_checkpoint_digest",
        Bound::ExactText(HEX64),
    )?;
    assert_column_refuses_nul_padding(
        &catalog,
        "fiscal_authority_state",
        "state_json",
        Bound::Blob(16),
    )
}

#[test]
fn frost_refuses_nul_padding() -> TestResult {
    let mut catalog = Connection::open_in_memory()?;
    crate::frost_store::initialize_frost_schema(&mut catalog)?;
    assert_column_refuses_nul_padding(
        &catalog,
        "frost_ceremonies",
        "config_digest",
        Bound::ExactText(HEX64),
    )?;
    assert_column_refuses_nul_padding(
        &catalog,
        "frost_ceremonies",
        "secret_nonce",
        Bound::Blob(12),
    )
}

#[test]
fn enterprise_migration_state_refuses_nul_padding() -> TestResult {
    let catalog = catalog(crate::enterprise_migration_state::CREATE_TABLE_SQL)?;
    assert_column_refuses_nul_padding(
        &catalog,
        "enterprise_migration_transitions",
        "deployment_id",
        Bound::Text("deployment"),
    )
}

#[test]
fn finding_operator_stores_refuse_nul_padding() -> TestResult {
    let bundles = catalog(crate::finding_operator_bundle_store::SCHEMA)?;
    assert_column_refuses_nul_padding(
        &bundles,
        "chio_finding_operator_bundles",
        "bundle_sha256",
        Bound::Text(HEX64),
    )?;
    let payments = catalog(crate::finding_operator_payment::SCHEMA)?;
    assert_column_refuses_nul_padding(
        &payments,
        "chio_finding_operator_payments",
        "currency",
        Bound::Text("USD"),
    )?;
    let payloads = catalog(crate::finding_payload_store::FINDING_PAYLOAD_SCHEMA)?;
    assert_column_refuses_nul_padding(
        &payloads,
        "chio_finding_payloads",
        "payload_sha256",
        Bound::Text(HEX64),
    )?;
    assert_column_refuses_nul_padding(&payloads, "chio_finding_payloads", "nonce", Bound::Blob(12))
}

#[test]
fn sealed_decoy_registry_refuses_nul_padding() -> TestResult {
    let catalog = catalog(crate::sealed_decoy_registry::SEALED_DECOY_SCHEMA_SQL)?;
    assert_column_refuses_nul_padding(
        &catalog,
        "sealed_decoy_records_v1",
        "tenant_id",
        Bound::Text("tenant"),
    )
}

#[test]
fn settle_attempts_refuse_nul_padding() -> TestResult {
    let catalog = catalog(crate::dead_letters::SETTLE_DEAD_LETTERS_MIGRATION)?;
    catalog.execute_batch(crate::settle_attempts::SETTLE_ATTEMPTS_MIGRATION)?;
    assert_column_refuses_nul_padding(
        &catalog,
        "settle_attempts",
        "lease_owner",
        Bound::Text("owner"),
    )
}

#[test]
fn receipt_checkpoint_refuses_nul_padding() -> TestResult {
    let catalog = Connection::open_in_memory()?;
    crate::receipt_store::support::ensure_checkpoint_schema(&catalog)?;
    assert_column_refuses_nul_padding(
        &catalog,
        "checkpoint_predecessor_witnesses",
        "previous_checkpoint_sha256",
        Bound::ExactText(HEX64),
    )
}

#[test]
fn approval_store_refuses_nul_padding() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("approvals.sqlite3");
    drop(crate::approval_store::SqliteApprovalStore::open(&path)?);
    let catalog = Connection::open(&path)?;
    assert_column_refuses_nul_padding(
        &catalog,
        "chio_hitl_operation_reservations",
        "approval_set_hash",
        Bound::ExactText(HEX64),
    )
}

#[test]
fn encrypted_blob_store_refuses_nul_padding() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("blobs.sqlite3");
    drop(crate::encrypted_blob::SqliteEncryptedBlobStore::open(
        &path,
    )?);
    let catalog = Connection::open(&path)?;
    assert_column_refuses_nul_padding(&catalog, "chio_encrypted_blobs", "nonce", Bound::Blob(12))
}
