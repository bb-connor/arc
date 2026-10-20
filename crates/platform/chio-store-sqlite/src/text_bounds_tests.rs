//! Bounded TEXT columns refuse embedded NULs and bounded BLOB columns refuse
//! TEXT.
//!
//! SQLite's `length()` and `GLOB` stop at the first NUL in a TEXT value, and
//! `length()` skips UTF-8 continuation bytes, so a value with a valid character
//! count could otherwise carry an unbounded tail. Each probe copies one bounded
//! column definition out of a live catalog into UTF-8, UTF-16le and UTF-16be
//! databases. It requires the column CHECK to accept a valid value and to
//! refuse a valid prefix followed by a NUL and a megabyte of padding, and a
//! prefix followed by one UTF-8 lead byte and a megabyte of continuation bytes.
//! The octet ceilings need `octet_length()`, which the bundled SQLite must
//! provide.

use std::error::Error;

use rusqlite::types::Value;
use rusqlite::{ffi, Connection};

const PADDING: usize = 1 << 20;
const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
enum Bound<'a> {
    /// A TEXT column whose valid value is the given string.
    Text(&'a str),
    /// A TEXT column of exact width, which must also refuse an in-width NUL.
    ExactText(&'a str),
    /// A BLOB column whose valid value has the given length.
    Blob(usize),
}

pub(crate) fn column_definition(table_sql: &str, column: &str) -> Option<String> {
    table_items(table_sql)
        .into_iter()
        .find(|item| item.split_whitespace().next() == Some(column))
}

fn table_items(table_sql: &str) -> Vec<String> {
    let Some(open) = table_sql.find('(') else {
        return Vec::new();
    };
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
        .map(|item| item.trim().to_owned())
        .collect()
}

fn insert(probe: &Connection, value: Value) -> rusqlite::Result<usize> {
    probe.execute("INSERT INTO probe VALUES (?1)", [value])
}

fn insert_text_bytes(probe: &Connection, bytes: Vec<u8>) -> rusqlite::Result<usize> {
    probe.execute(
        "INSERT INTO probe VALUES (CAST(?1 AS TEXT))",
        [Value::Blob(bytes)],
    )
}

fn continuation_padded(valid: &str) -> Vec<u8> {
    let mut bytes = valid.as_bytes()[..valid.len() - 1].to_vec();
    bytes.push(0xc0);
    bytes.resize(bytes.len() + PADDING, 0x80);
    bytes
}

fn is_constraint_refusal(result: &rusqlite::Result<usize>, code: i32) -> bool {
    matches!(
        result,
        Err(rusqlite::Error::SqliteFailure(error, Some(_)))
            if error.extended_code == code
    )
}

fn nul_padded(prefix: &str) -> String {
    format!("{prefix}\0{}", "a".repeat(PADDING))
}

fn assert_column_refuses_nul_padding(
    catalog: &Connection,
    table: &str,
    column: &str,
    bound: Bound<'_>,
) -> TestResult {
    let table_sql: String = catalog.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get(0),
    )?;
    let definition =
        column_definition(&table_sql, column).ok_or(format!("{table}.{column} is not defined"))?;
    let strict = if is_strict(&table_sql) { " STRICT" } else { "" };
    for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
        let probe = Connection::open_in_memory()?;
        probe.execute_batch(&format!(
            "PRAGMA encoding = '{encoding}'; PRAGMA foreign_keys = OFF;
             CREATE TABLE probe ({definition}){strict};"
        ))?;
        match bound {
            Bound::Text(valid) | Bound::ExactText(valid) => {
                assert_eq!(
                    insert(&probe, Value::Text(valid.to_owned()))?,
                    1,
                    "{table}.{column}"
                );
                let padded = insert(&probe, Value::Text(nul_padded(valid)));
                assert!(
                    is_constraint_refusal(&padded, ffi::SQLITE_CONSTRAINT_CHECK),
                    "{table}.{column}: {padded:?}"
                );
                let stretched = insert_text_bytes(&probe, continuation_padded(valid));
                assert!(
                    is_constraint_refusal(&stretched, ffi::SQLITE_CONSTRAINT_CHECK),
                    "{table}.{column}: {stretched:?}"
                );
            }
            Bound::Blob(len) => {
                assert_eq!(
                    insert(&probe, Value::Blob(vec![1; len]))?,
                    1,
                    "{table}.{column}"
                );
                let text = insert(&probe, Value::Text(nul_padded(&"a".repeat(len))));
                let code = if is_strict(&table_sql) {
                    ffi::SQLITE_CONSTRAINT_DATATYPE
                } else {
                    ffi::SQLITE_CONSTRAINT_CHECK
                };
                assert!(
                    is_constraint_refusal(&text, code),
                    "{table}.{column}: {text:?}"
                );
            }
        }
        if let Bound::ExactText(valid) = bound {
            let mut in_width = valid[..valid.len() - 1].to_owned();
            in_width.push('\0');
            let refused = insert(&probe, Value::Text(in_width));
            assert!(
                is_constraint_refusal(&refused, ffi::SQLITE_CONSTRAINT_CHECK),
                "{table}.{column}: {refused:?}"
            );
        }
        let rows: i64 = probe.query_row("SELECT count(*) FROM probe", [], |row| row.get(0))?;
        assert_eq!(rows, 1, "{table}.{column}: refusal changed the stored rows");
    }
    Ok(())
}

#[test]
fn bundled_sqlite_provides_octet_length() -> TestResult {
    assert!(
        rusqlite::version_number() >= 3_043_000,
        "{}",
        rusqlite::version()
    );
    let probe = Connection::open_in_memory()?;
    let octets: i64 = probe.query_row("SELECT octet_length('ab')", [], |row| row.get(0))?;
    assert_eq!(octets, 2);
    Ok(())
}

fn is_strict(table_sql: &str) -> bool {
    table_sql
        .rsplit(')')
        .next()
        .is_some_and(|options| options.split(',').any(|option| option.trim() == "STRICT"))
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
    crate::test_schema::apply(
        &mut catalog,
        &["frost"],
        crate::frost_store::initialize_frost_schema,
        |error| crate::frost_store::FrostStoreError::InvalidState(error.to_string()),
    )?;
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
    let catalog = catalog(crate::dead_letters::SETTLE_DEAD_LETTERS_SCHEMA)?;
    catalog.execute_batch(crate::settle_attempts::SETTLE_ATTEMPTS_SCHEMA)?;
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
fn work_delegation_store_refuses_nul_padding() -> TestResult {
    let catalog = catalog(include_str!("delegation_store.sql"))?;
    assert_column_refuses_nul_padding(
        &catalog,
        "work_delegation_namespace",
        "namespace",
        Bound::ExactText(HEX64),
    )?;
    for column in ["slot_id", "parent_id", "root_id"] {
        assert_column_refuses_nul_padding(
            &catalog,
            "work_delegation_slots",
            column,
            Bound::Text("slot"),
        )?;
    }
    for column in ["slot", "selection"] {
        assert_column_refuses_nul_padding(
            &catalog,
            "work_delegation_slots",
            column,
            Bound::Text("{}"),
        )?;
    }
    assert_column_refuses_nul_padding(
        &catalog,
        "work_delegation_permits",
        "permit",
        Bound::Text("{}"),
    )?;
    assert_column_refuses_nul_padding(
        &catalog,
        "work_delegation_commands",
        "command_id",
        Bound::Text("command"),
    )?;
    assert_column_refuses_nul_padding(
        &catalog,
        "work_delegation_commands",
        "request_digest",
        Bound::ExactText(HEX64),
    )?;
    assert_column_refuses_nul_padding(
        &catalog,
        "work_delegation_events",
        "state_digest",
        Bound::ExactText(HEX64),
    )
}

#[test]
fn work_graph_store_refuses_nul_padding() -> TestResult {
    let catalog = catalog(include_str!("work_graph_store.sql"))?;
    assert_column_refuses_nul_padding(
        &catalog,
        "work_graph_heads",
        "graph_id",
        Bound::Text("graph"),
    )?;
    assert_column_refuses_nul_padding(
        &catalog,
        "work_graph_heads",
        "bundle_sha256",
        Bound::ExactText(HEX64),
    )?;
    for column in ["graph_sha256", "bundle_sha256", "successor_bundle_sha256"] {
        assert_column_refuses_nul_padding(
            &catalog,
            "work_graph_versions",
            column,
            Bound::ExactText(HEX64),
        )?;
    }
    for column in ["bundle_sha256", "parent_bundle_sha256"] {
        assert_column_refuses_nul_padding(
            &catalog,
            "work_graph_issuances",
            column,
            Bound::ExactText(HEX64),
        )?;
    }
    Ok(())
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

/// A value the column accepts, so the probe can test refusals around it.
fn admission_bound(
    catalog: &Connection,
    table: &str,
    definition: &str,
) -> TestResult<Option<OwnedBound>> {
    let table_sql: String = catalog.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get(0),
    )?;
    let strict = if is_strict(&table_sql) { " STRICT" } else { "" };
    let probe = Connection::open_in_memory()?;
    probe.execute_batch(&format!(
        "PRAGMA foreign_keys = OFF; CREATE TABLE probe ({definition}){strict};"
    ))?;
    let column = definition.split_whitespace().next().unwrap_or_default();
    let exact = definition.contains(&format!("length({column}) = "));
    if definition.split_whitespace().nth(1) == Some("TEXT") {
        for text in [HEX64, "a", "1", "operation"] {
            if insert(&probe, Value::Text(text.to_owned())).is_ok() {
                return Ok(Some(if exact {
                    OwnedBound::ExactText(text.to_owned())
                } else {
                    OwnedBound::Text(text.to_owned())
                }));
            }
        }
        return Ok(None);
    }
    for len in [1, 16, 32, 64] {
        if insert(&probe, Value::Blob(vec![1; len])).is_ok() {
            return Ok(Some(OwnedBound::Blob(len)));
        }
    }
    Ok(None)
}

enum OwnedBound {
    Text(String),
    ExactText(String),
    Blob(usize),
}

#[test]
fn admission_operation_catalog_refuses_nul_padding() -> TestResult {
    let catalog = catalog(&crate::admission_operation_store::admission_operation_schema_sql()?)?;
    let tables = catalog
        .prepare("SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND sql IS NOT NULL ORDER BY name")?
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut probed = 0usize;
    let mut unprobed = Vec::new();
    for (table, sql) in &tables {
        assert!(
            !sql.contains("length(CAST("),
            "{table} bounds bytes in the database encoding"
        );
        for item in table_items(sql) {
            let mut words = item.split_whitespace();
            let (Some(column), Some(kind)) = (words.next(), words.next()) else {
                continue;
            };
            // A DPoP nonce is opaque client text and may contain NUL; its
            // octet ceiling bounds it instead.
            let nul_allowed = table == "dpop_replay_claim_resources" && column == "nonce";
            if kind == "TEXT" && !nul_allowed && sql.contains(&format!("length({column})")) {
                assert!(
                    sql.contains(&format!("instr({column}, char(0)) = 0")),
                    "{table}.{column} is length-bounded without a NUL guard"
                );
            }
            // Recovery records bound their text with table constraints, which a
            // single-column probe cannot copy; recovery_records::tests::
            // malformed_text and encodings exercise them in place.
            let table_bounded = table.starts_with("admission_operation_recovery_");
            if table_bounded
                || !matches!(kind, "TEXT" | "BLOB")
                || !item.contains(&format!("length({column})"))
            {
                continue;
            }
            let Some(owned) = admission_bound(&catalog, table, &item)? else {
                unprobed.push(format!("{table}.{column}"));
                continue;
            };
            let bound = match &owned {
                OwnedBound::Text(text) => Bound::Text(text),
                OwnedBound::ExactText(text) => Bound::ExactText(text),
                OwnedBound::Blob(len) => Bound::Blob(*len),
            };
            assert_column_refuses_nul_padding(&catalog, table, column, bound)?;
            probed += 1;
        }
    }
    assert!(
        unprobed.is_empty(),
        "no accepted probe value for {unprobed:?}"
    );
    assert!(probed > 150, "{probed} bounded admission columns");
    Ok(())
}

#[test]
fn root_exchange_store_refuses_nul_padding() -> TestResult {
    let catalog = catalog(include_str!("root_exchange_store.sql"))?;
    for (table, column) in [
        ("root_exchange_events", "digest"),
        ("root_exchange_replay", "replay_key_digest"),
        ("root_exchange_roots", "tag_key_id"),
        ("root_exchange_roots", "subject_tag"),
        ("root_exchange_roots", "tenant_tag"),
        ("root_exchange_roots", "replay_key_digest"),
        ("root_exchange_roots", "artifact_digest"),
        ("root_exchange_roots", "request_digest"),
        ("root_exchange_roots", "root_policy_digest"),
        ("root_exchange_roots", "provider_identity_digest"),
        ("root_exchange_roots", "key_snapshot_digest"),
        ("root_exchange_roots", "context_digest"),
        ("root_exchange_roots", "authorization_projection_digest"),
        ("root_exchange_bearer_tokens", "token_digest"),
        ("root_exchange_key_snapshots", "snapshot_digest"),
        ("root_exchange_policies", "root_policy_digest"),
        (
            "root_exchange_provider_identities",
            "provider_identity_digest",
        ),
    ] {
        assert_column_refuses_nul_padding(&catalog, table, column, Bound::ExactText(HEX64))?;
    }
    for (table, column, valid) in [
        ("root_exchange_events", "subject", "cap-1"),
        ("root_exchange_replay", "capability_id", "cap-1"),
        ("root_exchange_roots", "capability_id", "cap-1"),
        ("root_exchange_roots", "root_policy_rule_id", "rule-1"),
        ("root_exchange_roots", "client_id", "client-1"),
        (
            "root_exchange_key_snapshots",
            "issuer",
            "https://idp.example",
        ),
        ("root_exchange_openings", "capability_id", "cap-1"),
        ("root_exchange_openings", "salt_ref", "anchor.sub"),
    ] {
        assert_column_refuses_nul_padding(&catalog, table, column, Bound::Text(valid))?;
    }
    for (table, column, len) in [
        ("root_exchange_roots", "delegation_context", 2),
        ("root_exchange_roots", "root_capability", 2),
        ("root_exchange_key_snapshots", "snapshot", 2),
        ("root_exchange_policies", "policy", 2),
        ("root_exchange_provider_identities", "identity", 2),
    ] {
        assert_column_refuses_nul_padding(&catalog, table, column, Bound::Blob(len))?;
    }
    Ok(())
}
