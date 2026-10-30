//! Receipt openings: the fresh-only v1 DDL refusals, the store identity, reads and erasure.

use super::super::openings::{seed_receipt_store_identity, RECEIPT_OPENINGS_SCHEMA};
use super::super::*;
use super::support::*;
use chio_core::receipt::disclosure::MAX_DISCLOSURE_OPENINGS;
use chio_kernel::receipt_store::{OpeningReadScope, OpeningState, OpeningStatus};
use rusqlite::Connection;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const R: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const R2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const O: &str = "0123456789abcdef0123456789abcdef";
const O2: &str = "fedcba9876543210fedcba9876543210";
const OPENING_TABLES: [&str; 9] = [
    "receipt_openings",
    "receipt_metadata_values",
    "receipt_store_identity",
    "receipt_opening_erasures",
    "receipt_erasure_facts",
    "replication_quarantine_erasures",
    "receipt_openings_watermarks",
    "receipt_openings_member_watermarks",
    "receipt_openings_peer_cursors",
];

fn bare() -> Result<Connection, rusqlite::Error> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECEIPT_OPENINGS_SCHEMA)?;
    Ok(connection)
}

fn run(connection: &Connection, sql: &str) -> Result<(), rusqlite::Error> {
    connection.execute_batch(
        &sql.replace("{R}", R)
            .replace("{R2}", R2)
            .replace("{O}", O)
            .replace("{O2}", O2),
    )
}

/// Every row of every openings table, rendered with `quote()` so types are visible.
fn dump(connection: &Connection) -> Result<Vec<String>, rusqlite::Error> {
    let mut rows = Vec::new();
    for table in OPENING_TABLES {
        let columns = connection
            .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if columns.is_empty() {
            rows.push(format!("{table}:absent"));
            continue;
        }
        let select = columns
            .iter()
            .map(|column| format!("quote({column})"))
            .collect::<Vec<_>>()
            .join(" || ',' || ");
        let mut statement = connection.prepare(&format!("SELECT {select} FROM {table}"))?;
        for row in statement.query_map([], |row| row.get::<_, String>(0))? {
            rows.push(format!("{table}:{}", row?));
        }
    }
    rows.sort();
    Ok(rows)
}

fn scalar(connection: &Connection, sql: &str) -> Result<String, rusqlite::Error> {
    connection.query_row(&format!("SELECT quote(({sql}))"), [], |row| row.get(0))
}

macro_rules! accepts {
    ($name:ident, [$($setup:expr),*], $statement:expr) => {
        #[test]
        fn $name() -> TestResult {
            let connection = bare()?;
            $(run(&connection, $setup)?;)*
            run(&connection, $statement)?;
            Ok(())
        }
    };
    ($name:ident, [$($setup:expr),*], $statement:expr, $query:expr => $expected:expr) => {
        #[test]
        fn $name() -> TestResult {
            let connection = bare()?;
            $(run(&connection, $setup)?;)*
            run(&connection, $statement)?;
            assert_eq!(scalar(&connection, $query)?, $expected);
            Ok(())
        }
    };
}

macro_rules! refuses {
    ($name:ident, [$($setup:expr),*], $statement:expr, $message:expr) => {
        #[test]
        fn $name() -> TestResult {
            let connection = bare()?;
            $(run(&connection, $setup)?;)*
            let before = dump(&connection)?;
            let error = run(&connection, $statement)
                .err()
                .ok_or("statement was accepted")?;
            assert!(error.to_string().contains($message), "{error}");
            assert_eq!(dump(&connection)?, before);
            Ok(())
        }
    };
}

const CHECK: &str = "CHECK constraint failed";
const IDENTITY_IMMUTABLE: &str = "receipt store id is immutable";
const FACT_PERMANENT: &str = "receipt erasure fact is permanent";
const CONFLICT_PERMANENT: &str = "erasure conflict record is permanent";

const PRESENT: &str =
    "INSERT INTO receipt_openings VALUES ('{R}', 'params', 'present', zeroblob(32), 1)";
const OFF: &str = "PRAGMA recursive_triggers = OFF";
const ON: &str = "PRAGMA recursive_triggers = ON";

macro_rules! opening {
    ($salt_ref:expr, $state:expr, $salt:expr) => {
        concat!(
            "INSERT INTO receipt_openings VALUES ('{R}', ",
            $salt_ref,
            ", ",
            $state,
            ", ",
            $salt,
            ", 1)"
        )
    };
}

accepts!(opening_row_accepts_present_blob32, [], PRESENT,
    "SELECT state || typeof(salt) || length(salt) FROM receipt_openings" => "'presentblob32'");
accepts!(opening_row_accepts_erased_null, [], opening!("'params'", "'erased'", "NULL"),
    "SELECT state || typeof(salt) FROM receipt_openings" => "'erasednull'");
accepts!(
    opening_row_accepts_claim_salt_ref,
    [],
    opening!("'anchor.claims.client_id'", "'present'", "zeroblob(32)")
);
refuses!(
    opening_row_refuses_erased_with_blob1,
    [],
    opening!("'params'", "'erased'", "zeroblob(1)"),
    CHECK
);
refuses!(
    opening_row_refuses_erased_with_blob32,
    [],
    opening!("'params'", "'erased'", "zeroblob(32)"),
    CHECK
);
refuses!(
    opening_row_refuses_erased_with_text,
    [],
    opening!("'params'", "'erased'", "'x'"),
    CHECK
);
refuses!(
    opening_row_refuses_present_with_text32,
    [],
    opening!(
        "'params'",
        "'present'",
        "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
    ),
    CHECK
);
refuses!(
    opening_row_refuses_present_with_null,
    [],
    opening!("'params'", "'present'", "NULL"),
    CHECK
);
refuses!(
    opening_row_refuses_present_with_blob31,
    [],
    opening!("'params'", "'present'", "zeroblob(31)"),
    CHECK
);
refuses!(
    opening_row_refuses_present_with_blob33,
    [],
    opening!("'params'", "'present'", "zeroblob(33)"),
    CHECK
);
refuses!(
    opening_row_refuses_present_with_integer,
    [],
    opening!("'params'", "'present'", "7"),
    CHECK
);
refuses!(
    opening_row_refuses_lost_state,
    [],
    opening!("'params'", "'lost'", "NULL"),
    CHECK
);
refuses!(
    opening_row_refuses_state_with_nul,
    [],
    opening!("'params'", "'erased' || char(0) || 'x'", "NULL"),
    CHECK
);
refuses!(
    opening_row_refuses_salt_ref_uppercase,
    [],
    opening!("'Params'", "'present'", "zeroblob(32)"),
    CHECK
);
refuses!(
    opening_row_refuses_salt_ref_empty_segment,
    [],
    opening!("'a..b'", "'present'", "zeroblob(32)"),
    CHECK
);
refuses!(
    opening_row_refuses_salt_ref_trailing_dot,
    [],
    opening!("'params.'", "'present'", "zeroblob(32)"),
    CHECK
);
refuses!(
    opening_row_refuses_salt_ref_leading_digit,
    [],
    opening!("'1params'", "'present'", "zeroblob(32)"),
    CHECK
);
refuses!(
    opening_row_refuses_salt_ref_dash,
    [],
    opening!("'par-ams'", "'present'", "zeroblob(32)"),
    CHECK
);
refuses!(
    opening_row_refuses_salt_ref_empty,
    [],
    opening!("''", "'present'", "zeroblob(32)"),
    CHECK
);
refuses!(
    opening_row_refuses_salt_ref_65_chars,
    [],
    opening!("printf('%.65c', 'a')", "'present'", "zeroblob(32)"),
    CHECK
);
refuses!(
    opening_row_refuses_salt_ref_with_embedded_nul,
    [],
    opening!("'params' || char(0) || 'BAD'", "'present'", "zeroblob(32)"),
    CHECK
);
refuses!(
    opening_row_refuses_salt_ref_with_trailing_nul,
    [],
    opening!("'params' || char(0)", "'present'", "zeroblob(32)"),
    CHECK
);
refuses!(
    opening_row_refuses_receipt_id_uppercase,
    [],
    "INSERT INTO receipt_openings VALUES (upper('{R}'), 'params', 'present', zeroblob(32), 1)",
    CHECK
);
refuses!(
    opening_row_refuses_receipt_id_63_chars,
    [],
    "INSERT INTO receipt_openings VALUES (substr('{R}', 2), 'params', 'present', zeroblob(32), 1)",
    CHECK
);
refuses!(opening_row_refuses_receipt_id_with_trailing_nul, [],
    "INSERT INTO receipt_openings VALUES ('{R}' || char(0) || 'BAD', 'params', 'present', zeroblob(32), 1)", CHECK);
refuses!(opening_row_refuses_receipt_id_with_inner_nul, [],
    "INSERT INTO receipt_openings VALUES (substr('{R}', 1, 31) || char(0) || substr('{R}', 1, 32), 'params', 'present', zeroblob(32), 1)", CHECK);
refuses!(
    opening_row_refuses_state_at_text,
    [],
    "INSERT INTO receipt_openings VALUES ('{R}', 'params', 'present', zeroblob(32), 'x')",
    CHECK
);
refuses!(
    opening_row_refuses_state_at_negative,
    [],
    "INSERT INTO receipt_openings VALUES ('{R}', 'params', 'present', zeroblob(32), -1)",
    CHECK
);
accepts!(opening_update_accepts_erase_clearing_salt, [PRESENT],
    "UPDATE receipt_openings SET state = 'erased', salt = NULL",
    "SELECT state || typeof(salt) FROM receipt_openings" => "'erasednull'");
refuses!(
    opening_update_refuses_erase_leaving_salt,
    [PRESENT],
    "UPDATE receipt_openings SET state = 'erased'",
    CHECK
);
refuses!(
    erase_leaving_salt_refuses,
    [PRESENT],
    "UPDATE receipt_openings SET state = 'erased'",
    CHECK
);
refuses!(
    opening_update_refuses_salt_ref_nul,
    [PRESENT],
    "UPDATE receipt_openings SET salt_ref = 'params' || char(0)",
    CHECK
);
refuses!(
    opening_update_refuses_receipt_id_nul,
    [PRESENT],
    "UPDATE receipt_openings SET receipt_id = '{R}' || char(0)",
    CHECK
);
refuses!(
    opening_update_refuses_state_nul,
    [PRESENT],
    "UPDATE receipt_openings SET state = 'present' || char(0)",
    CHECK
);
refuses!(
    opening_update_refuses_text_salt,
    [PRESENT],
    "UPDATE receipt_openings SET salt = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
    CHECK
);

const VALUE: &str = "INSERT INTO receipt_metadata_values VALUES \
    ('{R}', 'metadata.financial.cost_breakdown', 'present', '{\"a\":1}', 1792234800)";

macro_rules! value_row {
    ($receipt_id:expr, $salt_ref:expr, $state:expr, $value:expr) => {
        concat!(
            "INSERT INTO receipt_metadata_values VALUES (",
            $receipt_id,
            ", ",
            $salt_ref,
            ", ",
            $state,
            ", ",
            $value,
            ", 1792234800)"
        )
    };
}

accepts!(values_row_accepts_present_json, [], VALUE,
    "SELECT state || value FROM receipt_metadata_values" => "'present{\"a\":1}'");
accepts!(
    values_row_accepts_erased_null,
    [],
    value_row!("'{R}'", "'metadata.governed_transaction.purpose'", "'erased'", "NULL"),
    "SELECT state || typeof(value) FROM receipt_metadata_values" => "'erasednull'"
);
refuses!(
    values_row_refuses_present_null,
    [],
    value_row!(
        "'{R}'",
        "'metadata.financial.cost_breakdown'",
        "'present'",
        "NULL"
    ),
    CHECK
);
refuses!(
    values_row_refuses_present_invalid_json,
    [],
    value_row!(
        "'{R}'",
        "'metadata.financial.cost_breakdown'",
        "'present'",
        "'not json'"
    ),
    CHECK
);
refuses!(
    values_row_refuses_present_blob,
    [],
    value_row!(
        "'{R}'",
        "'metadata.financial.cost_breakdown'",
        "'present'",
        "zeroblob(4)"
    ),
    CHECK
);
refuses!(
    values_row_refuses_erased_with_value,
    [],
    value_row!(
        "'{R}'",
        "'metadata.financial.cost_breakdown'",
        "'erased'",
        "'1'"
    ),
    CHECK
);
refuses!(
    values_row_refuses_salt_ref_not_metadata,
    [],
    value_row!("'{R}'", "'params'", "'present'", "'1'"),
    CHECK
);
refuses!(
    values_row_refuses_salt_ref_embedded_nul,
    [],
    value_row!(
        "'{R}'",
        "'metadata.x' || char(0) || 'y'",
        "'present'",
        "'1'"
    ),
    CHECK
);
refuses!(
    values_row_refuses_receipt_id_embedded_nul,
    [],
    value_row!("'{R}' || char(0)", "'metadata.x'", "'present'", "'1'"),
    CHECK
);
refuses!(
    values_row_refuses_state_lost,
    [],
    value_row!("'{R}'", "'metadata.x'", "'lost'", "NULL"),
    CHECK
);
accepts!(values_update_accepts_erase_clearing_value, [VALUE],
    "UPDATE receipt_metadata_values SET state = 'erased', value = NULL, state_at = 1792234801",
    "SELECT state || typeof(value) || state_at FROM receipt_metadata_values" => "'erasednull1792234801'");
refuses!(
    values_update_refuses_erase_leaving_value,
    [VALUE],
    "UPDATE receipt_metadata_values SET state = 'erased', state_at = 1792234801",
    CHECK
);
refuses!(
    values_update_refuses_salt_ref_nul,
    [VALUE],
    "UPDATE receipt_metadata_values SET salt_ref = salt_ref || char(0)",
    CHECK
);

const IDENTITY: &str = "INSERT INTO receipt_store_identity VALUES (1, '{O}'); \
    INSERT INTO receipt_openings_watermarks VALUES ('{O}', 0, 0)";
const SECOND_WATERMARK: &str = "INSERT INTO receipt_openings_watermarks VALUES ('{O2}', 3, 1)";

accepts!(store_identity_accepts, [], IDENTITY,
    "SELECT store_id FROM receipt_store_identity" => "'0123456789abcdef0123456789abcdef'");
refuses!(
    store_identity_refuses_second_row,
    [IDENTITY],
    "INSERT INTO receipt_store_identity VALUES (2, '{O2}')",
    IDENTITY_IMMUTABLE
);
refuses!(
    store_identity_refuses_duplicate_singleton,
    [IDENTITY],
    "INSERT INTO receipt_store_identity VALUES (1, '{O2}')",
    IDENTITY_IMMUTABLE
);
refuses!(
    store_identity_refuses_uppercase,
    [],
    "INSERT INTO receipt_store_identity VALUES (1, upper('{O}'))",
    CHECK
);
refuses!(
    store_identity_refuses_31_chars,
    [],
    "INSERT INTO receipt_store_identity VALUES (1, substr('{O}', 2))",
    CHECK
);
refuses!(
    store_identity_refuses_33_chars,
    [],
    "INSERT INTO receipt_store_identity VALUES (1, '{O}' || 'a')",
    CHECK
);
refuses!(store_identity_refuses_embedded_nul, [],
    "INSERT INTO receipt_store_identity VALUES (1, substr('{O}', 1, 15) || char(0) || substr('{O}', 17))", CHECK);
refuses!(
    store_identity_refuses_url,
    [],
    "INSERT INTO receipt_store_identity VALUES (1, 'https://node.example/0123456789a')",
    CHECK
);
refuses!(
    store_identity_update_refuses,
    [IDENTITY],
    "UPDATE receipt_store_identity SET store_id = '{O2}'",
    IDENTITY_IMMUTABLE
);
refuses!(
    store_identity_delete_refuses,
    [IDENTITY],
    "DELETE FROM receipt_store_identity",
    IDENTITY_IMMUTABLE
);
refuses!(
    store_identity_insert_or_replace_refuses_recursive_triggers_off,
    [IDENTITY, SECOND_WATERMARK, OFF],
    "INSERT OR REPLACE INTO receipt_store_identity VALUES (1, '{O2}')",
    IDENTITY_IMMUTABLE
);
refuses!(
    store_identity_replace_refuses_recursive_triggers_off,
    [IDENTITY, SECOND_WATERMARK, OFF],
    "REPLACE INTO receipt_store_identity VALUES (1, '{O2}')",
    IDENTITY_IMMUTABLE
);
refuses!(
    store_identity_second_insert_refuses_recursive_triggers_off,
    [IDENTITY, SECOND_WATERMARK, OFF],
    "INSERT INTO receipt_store_identity VALUES (1, '{O2}')",
    IDENTITY_IMMUTABLE
);
refuses!(
    store_identity_insert_or_replace_refuses_recursive_triggers_on,
    [IDENTITY, SECOND_WATERMARK, ON],
    "INSERT OR REPLACE INTO receipt_store_identity VALUES (1, '{O2}')",
    IDENTITY_IMMUTABLE
);
refuses!(
    store_identity_replace_refuses_recursive_triggers_on,
    [IDENTITY, SECOND_WATERMARK, ON],
    "REPLACE INTO receipt_store_identity VALUES (1, '{O2}')",
    IDENTITY_IMMUTABLE
);
refuses!(
    store_identity_second_insert_refuses_recursive_triggers_on,
    [IDENTITY, SECOND_WATERMARK, ON],
    "INSERT INTO receipt_store_identity VALUES (1, '{O2}')",
    IDENTITY_IMMUTABLE
);

const FACT: &str = "INSERT INTO receipt_erasure_facts VALUES ('{R}', '{O}', 1, 10, 11, 0)";
const CONFLICTED_FACT: &str =
    "INSERT INTO receipt_erasure_facts VALUES ('{R}', '{O}', 1, 10, 11, 1)";

accepts!(erasure_fact_accepts, [], FACT);
accepts!(erasure_fact_accepts_conflicted, [], CONFLICTED_FACT);
refuses!(
    erasure_fact_refuses_conflicted_2,
    [],
    "INSERT INTO receipt_erasure_facts VALUES ('{R}', '{O}', 1, 10, 11, 2)",
    CHECK
);
refuses!(
    erasure_fact_refuses_conflicted_negative,
    [],
    "INSERT INTO receipt_erasure_facts VALUES ('{R}', '{O}', 1, 10, 11, -1)",
    CHECK
);
refuses!(
    erasure_fact_refuses_conflicted_text,
    [],
    "INSERT INTO receipt_erasure_facts VALUES ('{R}', '{O}', 1, 10, 11, 'x')",
    CHECK
);
refuses!(
    erasure_fact_refuses_conflicted_null,
    [],
    "INSERT INTO receipt_erasure_facts VALUES ('{R}', '{O}', 1, 10, 11, NULL)",
    "NOT NULL constraint failed"
);
refuses!(
    erasure_fact_refuses_receipt_id_uppercase,
    [],
    "INSERT INTO receipt_erasure_facts VALUES (upper('{R}'), '{O}', 1, 10, 11, 0)",
    CHECK
);
refuses!(erasure_fact_refuses_origin_node_url, [],
    "INSERT INTO receipt_erasure_facts VALUES ('{R}', 'https://node.example/0123456789a', 1, 10, 11, 0)", CHECK);
refuses!(
    erasure_fact_refuses_origin_seq_zero,
    [],
    "INSERT INTO receipt_erasure_facts VALUES ('{R}', '{O}', 0, 10, 11, 0)",
    CHECK
);
refuses!(
    erasure_fact_refuses_negative_erased_at,
    [],
    "INSERT INTO receipt_erasure_facts VALUES ('{R}', '{O}', 1, -1, 11, 0)",
    CHECK
);
refuses!(
    erasure_fact_refuses_negative_recorded_at,
    [],
    "INSERT INTO receipt_erasure_facts VALUES ('{R}', '{O}', 1, 10, -1, 0)",
    CHECK
);
refuses!(
    erasure_fact_refuses_second_insert,
    [FACT],
    FACT,
    FACT_PERMANENT
);
refuses!(
    erasure_fact_insert_or_replace_refuses_recursive_triggers_off,
    [FACT, OFF],
    "INSERT OR REPLACE INTO receipt_erasure_facts VALUES ('{R}', '{O2}', 2, 12, 13, 0)",
    FACT_PERMANENT
);
refuses!(
    erasure_fact_insert_or_replace_refuses_recursive_triggers_on,
    [FACT, ON],
    "INSERT OR REPLACE INTO receipt_erasure_facts VALUES ('{R}', '{O2}', 2, 12, 13, 0)",
    FACT_PERMANENT
);
accepts!(erasure_fact_update_marks_conflict_accepts, [FACT],
    "UPDATE receipt_erasure_facts SET conflicted = 1",
    "SELECT conflicted FROM receipt_erasure_facts" => "1");
refuses!(
    erasure_fact_update_clears_conflict_refuses,
    [CONFLICTED_FACT],
    "UPDATE receipt_erasure_facts SET conflicted = 0",
    FACT_PERMANENT
);
refuses!(
    erasure_fact_update_changes_origin_refuses,
    [FACT],
    "UPDATE receipt_erasure_facts SET origin_store_id = '{O2}'",
    FACT_PERMANENT
);
refuses!(
    erasure_fact_update_changes_erased_at_refuses,
    [FACT],
    "UPDATE receipt_erasure_facts SET erased_at = 12",
    FACT_PERMANENT
);
refuses!(
    erasure_fact_delete_refuses,
    [FACT],
    "DELETE FROM receipt_erasure_facts",
    FACT_PERMANENT
);

macro_rules! conflict {
    ($origin:expr, $reason:expr, $hold:expr, $stored:expr, $incoming:expr, $resolved:expr) => {
        concat!(
            "INSERT INTO replication_quarantine_erasures (origin_store_id, origin_openings_seq, \
             reason, hold, stored_receipt_id, stored_erased_at, incoming_receipt_id, \
             incoming_erased_at, source_node_id, recorded_at, resolved_at) VALUES (",
            $origin,
            ", 7, ",
            $reason,
            ", ",
            $hold,
            ", ",
            $stored,
            ", ",
            $incoming,
            ", 12, 'https://peer.example', 20, ",
            $resolved,
            ")"
        )
    };
}

const BELOW: &str = conflict!(
    "'{O2}'",
    "'erasure_event_conflict'",
    "'below_watermark'",
    "'{R}', 10",
    "'{R2}'",
    "NULL"
);
const FROZEN: &str = conflict!(
    "'{O2}'",
    "'erasure_event_conflict'",
    "'origin_frozen'",
    "'{R}', 10",
    "'{R2}'",
    "NULL"
);
const RESOLVE: &str = "UPDATE replication_quarantine_erasures SET resolved_at = 30";
const HOLD: &str = "SELECT hold FROM replication_quarantine_erasures";

accepts!(conflict_row_accepts_below_watermark, [], BELOW);
accepts!(
    conflict_row_accepts_frozen_after_gc,
    [],
    conflict!(
        "'{O2}'",
        "'erasure_event_conflict'",
        "'origin_frozen'",
        "NULL, NULL",
        "'{R2}'",
        "NULL"
    )
);
accepts!(
    conflict_row_accepts_own_origin,
    [IDENTITY],
    conflict!(
        "'{O}'",
        "'erasure_event_conflict_own_origin'",
        "'own_origin'",
        "'{R}', 10",
        "'{R2}'",
        "NULL"
    )
);
refuses!(
    conflict_row_refuses_unknown_hold,
    [],
    conflict!(
        "'{O2}'",
        "'erasure_event_conflict'",
        "'later'",
        "'{R}', 10",
        "'{R2}'",
        "NULL"
    ),
    CHECK
);
refuses!(
    conflict_row_refuses_own_origin_hold_with_plain_reason,
    [],
    conflict!(
        "'{O2}'",
        "'erasure_event_conflict'",
        "'own_origin'",
        "'{R}', 10",
        "'{R2}'",
        "NULL"
    ),
    CHECK
);
refuses!(
    conflict_row_refuses_plain_hold_with_own_origin_reason,
    [],
    conflict!(
        "'{O2}'",
        "'erasure_event_conflict_own_origin'",
        "'below_watermark'",
        "'{R}', 10",
        "'{R2}'",
        "NULL"
    ),
    CHECK
);
refuses!(
    conflict_row_refuses_stored_receipt_without_erased_at,
    [],
    conflict!(
        "'{O2}'",
        "'erasure_event_conflict'",
        "'below_watermark'",
        "'{R}', NULL",
        "'{R2}'",
        "NULL"
    ),
    CHECK
);
refuses!(
    conflict_row_refuses_origin_node_url,
    [],
    conflict!(
        "'https://node.example/0123456789a'",
        "'erasure_event_conflict'",
        "'below_watermark'",
        "'{R}', 10",
        "'{R2}'",
        "NULL"
    ),
    CHECK
);
refuses!(
    conflict_row_refuses_incoming_receipt_uppercase,
    [],
    conflict!(
        "'{O2}'",
        "'erasure_event_conflict'",
        "'below_watermark'",
        "'{R}', 10",
        "upper('{R2}')",
        "NULL"
    ),
    CHECK
);
refuses!(
    conflict_row_refuses_resolved_before_recorded,
    [],
    conflict!(
        "'{O2}'",
        "'erasure_event_conflict'",
        "'below_watermark'",
        "'{R}', 10",
        "'{R2}'",
        "5"
    ),
    CHECK
);
refuses!(
    conflict_row_refuses_duplicate_event,
    [BELOW],
    BELOW,
    CONFLICT_PERMANENT
);
refuses!(
    conflict_row_insert_or_replace_refuses_recursive_triggers_off,
    [BELOW, OFF],
    &BELOW.replacen("INSERT", "INSERT OR REPLACE", 1),
    CONFLICT_PERMANENT
);
refuses!(
    conflict_row_insert_or_replace_refuses_recursive_triggers_on,
    [BELOW, ON],
    &BELOW.replacen("INSERT", "INSERT OR REPLACE", 1),
    CONFLICT_PERMANENT
);
accepts!(conflict_row_resolve_accepts, [BELOW], RESOLVE,
    "SELECT resolved_at FROM replication_quarantine_erasures" => "30");
refuses!(
    conflict_row_unresolve_refuses,
    [BELOW, RESOLVE],
    "UPDATE replication_quarantine_erasures SET resolved_at = NULL",
    CONFLICT_PERMANENT
);
refuses!(
    conflict_row_second_resolve_refuses,
    [BELOW, RESOLVE],
    "UPDATE replication_quarantine_erasures SET resolved_at = 40",
    CONFLICT_PERMANENT
);
refuses!(
    conflict_row_update_hold_refuses,
    [FROZEN],
    "UPDATE replication_quarantine_erasures SET hold = 'below_watermark'",
    CONFLICT_PERMANENT
);
refuses!(
    conflict_row_delete_refuses,
    [BELOW],
    "DELETE FROM replication_quarantine_erasures",
    CONFLICT_PERMANENT
);
accepts!(conflict_row_escalate_accepts_recursive_triggers_off, [BELOW, OFF],
    "UPDATE replication_quarantine_erasures SET hold = 'origin_frozen'", HOLD => "'origin_frozen'");
accepts!(conflict_row_escalate_accepts_recursive_triggers_on, [BELOW, ON],
    "UPDATE replication_quarantine_erasures SET hold = 'origin_frozen'", HOLD => "'origin_frozen'");
refuses!(
    conflict_row_downgrade_refuses_recursive_triggers_off,
    [FROZEN, OFF],
    "UPDATE replication_quarantine_erasures SET hold = 'below_watermark'",
    CONFLICT_PERMANENT
);
refuses!(
    conflict_row_downgrade_refuses_recursive_triggers_on,
    [FROZEN, ON],
    "UPDATE replication_quarantine_erasures SET hold = 'below_watermark'",
    CONFLICT_PERMANENT
);
refuses!(
    conflict_row_update_source_node_refuses_recursive_triggers_off,
    [BELOW, OFF],
    "UPDATE replication_quarantine_erasures SET source_node_id = 'https://other.example'",
    CONFLICT_PERMANENT
);
refuses!(
    conflict_row_update_source_node_refuses_recursive_triggers_on,
    [BELOW, ON],
    "UPDATE replication_quarantine_erasures SET source_node_id = 'https://other.example'",
    CONFLICT_PERMANENT
);
refuses!(
    conflict_row_escalate_to_own_origin_refuses,
    [BELOW],
    "UPDATE replication_quarantine_erasures SET hold = 'own_origin'",
    CONFLICT_PERMANENT
);
refuses!(
    conflict_row_escalate_and_resolve_together_refuses,
    [BELOW],
    "UPDATE replication_quarantine_erasures SET hold = 'origin_frozen', resolved_at = 30",
    CONFLICT_PERMANENT
);
refuses!(
    conflict_row_escalate_resolved_refuses,
    [BELOW, RESOLVE],
    "UPDATE replication_quarantine_erasures SET hold = 'origin_frozen'",
    CONFLICT_PERMANENT
);
refuses!(
    conflict_row_noop_update_refuses,
    [BELOW],
    "UPDATE replication_quarantine_erasures SET hold = hold",
    CONFLICT_PERMANENT
);
refuses!(
    conflict_row_plain_hold_naming_own_store_refuses,
    [IDENTITY],
    conflict!(
        "'{O}'",
        "'erasure_event_conflict'",
        "'below_watermark'",
        "'{R}', 10",
        "'{R2}'",
        "NULL"
    ),
    "a conflict naming this store has hold own_origin"
);
accepts!(
    conflict_row_plain_hold_naming_other_store_accepts,
    [IDENTITY],
    BELOW
);
accepts!(
    conflict_row_own_origin_naming_own_store_accepts,
    [IDENTITY],
    conflict!(
        "'{O}'",
        "'erasure_event_conflict_own_origin'",
        "'own_origin'",
        "'{R}', 10",
        "'{R2}'",
        "NULL"
    )
);

const ERASURE: &str = "INSERT INTO receipt_opening_erasures (receipt_id, origin_store_id, \
    origin_openings_seq, erased_at) VALUES ('{R}', '{O}', 1, 10)";

macro_rules! erasure {
    ($receipt:expr, $origin:expr, $seq:expr, $erased_at:expr) => {
        concat!(
            "INSERT INTO receipt_opening_erasures (receipt_id, origin_store_id, \
             origin_openings_seq, erased_at) VALUES (",
            $receipt,
            ", ",
            $origin,
            ", ",
            $seq,
            ", ",
            $erased_at,
            ")"
        )
    };
}

accepts!(erasure_row_accepts, [], ERASURE);
accepts!(
    erasure_row_accepts_same_receipt_two_origins,
    [ERASURE],
    erasure!("'{R}'", "'{O2}'", "1", "10")
);
refuses!(
    erasure_row_refuses_duplicate_origin_pair,
    [ERASURE],
    erasure!("'{R2}'", "'{O}'", "1", "11"),
    "UNIQUE constraint failed"
);
refuses!(
    erasure_row_refuses_origin_seq_zero,
    [],
    erasure!("'{R}'", "'{O}'", "0", "10"),
    CHECK
);
refuses!(
    erasure_row_refuses_origin_seq_text,
    [],
    erasure!("'{R}'", "'{O}'", "'x'", "10"),
    CHECK
);
refuses!(
    erasure_row_refuses_empty_origin,
    [],
    erasure!("'{R}'", "''", "1", "10"),
    CHECK
);
refuses!(
    erasure_row_refuses_origin_with_nul,
    [],
    erasure!(
        "'{R}'",
        "substr('{O}', 1, 15) || char(0) || substr('{O}', 17)",
        "1",
        "10"
    ),
    CHECK
);
refuses!(
    erasure_row_refuses_origin_node_url,
    [],
    erasure!("'{R}'", "'https://node.example/0123456789a'", "1", "10"),
    CHECK
);
refuses!(
    erasure_row_refuses_origin_uppercase,
    [],
    erasure!("'{R}'", "upper('{O}')", "1", "10"),
    CHECK
);
refuses!(
    erasure_row_refuses_receipt_id_uppercase,
    [],
    erasure!("upper('{R}')", "'{O}'", "1", "10"),
    CHECK
);
refuses!(
    erasure_row_refuses_negative_erased_at,
    [],
    erasure!("'{R}'", "'{O}'", "1", "-1"),
    CHECK
);
refuses!(
    erasure_row_refuses_text_openings_seq,
    [],
    "INSERT INTO receipt_opening_erasures VALUES ('x', '{R}', '{O}', 1, 10)",
    "datatype mismatch"
);
accepts!(erasure_seq_never_reused_after_delete,
    [ERASURE, erasure!("'{R}'", "'{O}'", "2", "10"),
     "DELETE FROM receipt_opening_erasures WHERE openings_seq = 2"],
    erasure!("'{R}'", "'{O}'", "3", "10"),
    "SELECT max(openings_seq) FROM receipt_opening_erasures" => "3");

const WATERMARK: &str = "INSERT INTO receipt_openings_watermarks VALUES ('{O}', 5, 3)";

accepts!(watermark_accepts, [], WATERMARK);
refuses!(
    watermark_refuses_horizon_above_applied,
    [],
    "INSERT INTO receipt_openings_watermarks VALUES ('{O}', 3, 5)",
    CHECK
);
refuses!(
    watermark_refuses_negative_applied,
    [],
    "INSERT INTO receipt_openings_watermarks VALUES ('{O}', -1, 0)",
    CHECK
);
refuses!(
    watermark_refuses_text_horizon,
    [],
    "INSERT INTO receipt_openings_watermarks VALUES ('{O}', 5, 'x')",
    CHECK
);
refuses!(
    watermark_refuses_origin_node_url,
    [],
    "INSERT INTO receipt_openings_watermarks VALUES ('https://node.example/0123456789a', 5, 3)",
    CHECK
);
refuses!(
    watermark_update_refuses_horizon_past_applied,
    [WATERMARK],
    "UPDATE receipt_openings_watermarks SET gc_horizon = 9",
    CHECK
);
accepts!(
    member_watermark_accepts,
    [],
    "INSERT INTO receipt_openings_member_watermarks VALUES ('https://peer.example', '{O}', 4)"
);
refuses!(
    member_watermark_refuses_negative,
    [],
    "INSERT INTO receipt_openings_member_watermarks VALUES ('https://peer.example', '{O}', -1)",
    CHECK
);
refuses!(member_watermark_refuses_origin_node_url, [],
    "INSERT INTO receipt_openings_member_watermarks VALUES ('https://peer.example', 'https://node.example/0123456789a', 4)",
    CHECK);
accepts!(
    peer_cursor_accepts,
    [],
    "INSERT INTO receipt_openings_peer_cursors VALUES ('https://peer.example', 4)"
);
refuses!(
    peer_cursor_refuses_negative,
    [],
    "INSERT INTO receipt_openings_peer_cursors VALUES ('https://peer.example', -1)",
    CHECK
);
refuses!(
    peer_cursor_refuses_text,
    [],
    "INSERT INTO receipt_openings_peer_cursors VALUES ('https://peer.example', 'x')",
    CHECK
);

fn salt_ref(value: &str) -> Result<chio_core::root_authority::SaltRef, Box<dyn std::error::Error>> {
    Ok(chio_core::root_authority::SaltRef::new(value)?)
}

/// A published receipt with present `params` and `content` openings, written directly
/// because the append does not carry openings yet.
fn store_with_openings(
    path: &std::path::Path,
) -> Result<(SqliteReceiptStore, String), Box<dyn std::error::Error>> {
    let store = SqliteReceiptStore::open(path)?;
    let receipt = sample_receipt();
    store.append_chio_receipt(&receipt)?;
    let receipt_id = receipt.id.clone();
    let id = receipt_id.clone();
    store
        .writer_handle()
        .run_write_anchored_metadata(move |transaction| {
            for salt_ref in ["params", "content"] {
                transaction.execute(
                    "INSERT INTO receipt_openings VALUES (?1, ?2, 'present', zeroblob(32), 1)",
                    rusqlite::params![id, salt_ref],
                )?;
            }
            Ok(())
        })?;
    Ok((store, receipt_id))
}

fn raw_dump(path: &std::path::Path) -> Result<Vec<String>, rusqlite::Error> {
    let connection = Connection::open(path)?;
    let mut rows = dump(&connection)?;
    let mut statement = connection
        .prepare("SELECT type || ':' || name || ':' || ifnull(sql, '') FROM sqlite_schema")?;
    for row in statement.query_map([], |row| row.get::<_, String>(0))? {
        rows.push(row?);
    }
    rows.sort();
    Ok(rows)
}

fn own_store_id(path: &std::path::Path) -> Result<String, rusqlite::Error> {
    Connection::open(path)?.query_row("SELECT store_id FROM receipt_store_identity", [], |row| {
        row.get(0)
    })
}

#[test]
fn missing_row_reads_unknown() -> TestResult {
    let (_dir, path) = chio_test_support::temp_sqlite_path("chio-openings-unknown");
    let store = SqliteReceiptStore::open(&path)?;
    assert_eq!(store.opening_status(R)?, OpeningStatus::Unknown);
    let scope = OpeningReadScope {
        salt_refs: vec![salt_ref("params")?],
        tenant_binding: None,
    };
    assert!(matches!(
        store.read_openings(R, &scope)?,
        OpeningState::Unknown
    ));
    Ok(())
}

#[test]
fn read_returns_only_requested_present_openings() -> TestResult {
    let (_dir, path) = chio_test_support::temp_sqlite_path("chio-openings-read");
    let (store, receipt_id) = store_with_openings(&path)?;
    assert_eq!(store.opening_status(&receipt_id)?, OpeningStatus::Present);
    let scope = OpeningReadScope {
        salt_refs: vec![salt_ref("params")?],
        tenant_binding: None,
    };
    let OpeningState::Present(opened) = store.read_openings(&receipt_id, &scope)? else {
        return Err("present openings did not read as present".into());
    };
    assert_eq!(
        opened
            .salts
            .keys()
            .map(|key| key.as_str())
            .collect::<Vec<_>>(),
        ["params"]
    );
    let missing = OpeningReadScope {
        salt_refs: vec![salt_ref("metadata.x.y")?],
        tenant_binding: None,
    };
    assert!(matches!(
        store.read_openings(&receipt_id, &missing)?,
        OpeningState::Unknown
    ));
    Ok(())
}

fn scope_of(count: usize) -> Result<OpeningReadScope, Box<dyn std::error::Error>> {
    Ok(OpeningReadScope {
        salt_refs: (0..count)
            .map(|index| salt_ref(&format!("s{index}")))
            .collect::<Result<_, _>>()?,
        tenant_binding: None,
    })
}

fn add_openings(
    store: &SqliteReceiptStore,
    receipt_id: &str,
    salt_refs: std::ops::Range<usize>,
) -> Result<(), ReceiptStoreError> {
    let id = receipt_id.to_owned();
    store
        .writer_handle()
        .run_write_anchored_metadata(move |transaction| {
            for index in salt_refs {
                transaction.execute(
                    "INSERT INTO receipt_openings VALUES (?1, ?2, 'present', zeroblob(32), 1)",
                    rusqlite::params![id, format!("s{index}")],
                )?;
            }
            Ok(())
        })
}

#[test]
fn read_refuses_an_empty_scope() -> TestResult {
    let (_dir, path) = chio_test_support::temp_sqlite_path("chio-openings-empty-scope");
    let (store, receipt_id) = store_with_openings(&path)?;
    let error = store
        .read_openings(&receipt_id, &scope_of(0)?)
        .err()
        .ok_or("an empty scope read as an answer")?;
    assert!(
        matches!(error, ReceiptStoreError::ReadBoundary(_)),
        "{error:?}"
    );
    Ok(())
}

#[test]
fn read_refuses_a_scope_above_the_opening_cap() -> TestResult {
    let (_dir, path) = chio_test_support::temp_sqlite_path("chio-openings-wide-scope");
    let (store, receipt_id) = store_with_openings(&path)?;
    assert!(matches!(
        store.read_openings(&receipt_id, &scope_of(MAX_DISCLOSURE_OPENINGS)?)?,
        OpeningState::Unknown
    ));
    let error = store
        .read_openings(&receipt_id, &scope_of(MAX_DISCLOSURE_OPENINGS + 1)?)
        .err()
        .ok_or("a scope above the opening cap was read")?;
    assert!(
        matches!(error, ReceiptStoreError::ReadBoundary(_)),
        "{error:?}"
    );
    Ok(())
}

#[test]
fn opening_rows_above_the_cap_read_as_corrupt() -> TestResult {
    let (_dir, path) = chio_test_support::temp_sqlite_path("chio-openings-row-cap");
    let (store, receipt_id) = store_with_openings(&path)?;
    add_openings(&store, &receipt_id, 0..MAX_DISCLOSURE_OPENINGS - 2)?;
    assert_eq!(store.opening_status(&receipt_id)?, OpeningStatus::Present);
    add_openings(
        &store,
        &receipt_id,
        MAX_DISCLOSURE_OPENINGS - 2..MAX_DISCLOSURE_OPENINGS - 1,
    )?;
    let status = store
        .opening_status(&receipt_id)
        .err()
        .ok_or("openings above the cap reported a status")?;
    assert!(
        matches!(status, ReceiptStoreError::CorruptOpeningRow(_)),
        "{status:?}"
    );
    let read = store
        .read_openings(&receipt_id, &scope_of(1)?)
        .err()
        .ok_or("openings above the cap were read")?;
    assert!(
        matches!(read, ReceiptStoreError::CorruptOpeningRow(_)),
        "{read:?}"
    );
    Ok(())
}

struct FailingRng;

impl chio_core::rng::Rng for FailingRng {
    fn fill_bytes(&self, _dest: &mut [u8]) -> Result<(), chio_core::rng::RngError> {
        Err(chio_core::rng::RngError("entropy source unavailable"))
    }
}

#[test]
fn identity_draw_failure_is_an_entropy_fault_not_a_conflict() -> TestResult {
    let mut connection = bare()?;
    let transaction = connection.transaction()?;
    let error = seed_receipt_store_identity(&transaction, &FailingRng)
        .err()
        .ok_or("a failed draw seeded a store identity")?;
    assert!(matches!(error, ReceiptStoreError::Io(_)), "{error:?}");
    Ok(())
}

#[test]
fn erase_writes_tombstones() -> TestResult {
    let (_dir, path) = chio_test_support::temp_sqlite_path("chio-openings-erase");
    let (store, receipt_id) = store_with_openings(&path)?;
    store.erase_openings(&receipt_id, 77)?;
    assert_eq!(
        store.opening_status(&receipt_id)?,
        OpeningStatus::Erased { erased_at: 77 }
    );
    let scope = OpeningReadScope {
        salt_refs: vec![salt_ref("params")?],
        tenant_binding: None,
    };
    assert!(matches!(
        store.read_openings(&receipt_id, &scope)?,
        OpeningState::Erased { erased_at: 77 }
    ));
    let own = own_store_id(&path)?;
    let connection = Connection::open(&path)?;
    let rows: Vec<String> = connection
        .prepare(
            "SELECT state || typeof(salt) || state_at FROM receipt_openings WHERE receipt_id = ?1",
        )?
        .query_map([&receipt_id], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    assert_eq!(rows, ["erasednull77", "erasednull77"]);
    let erasure: (String, i64, i64) = connection.query_row(
        "SELECT origin_store_id, origin_openings_seq, erased_at FROM receipt_opening_erasures \
         WHERE receipt_id = ?1",
        [&receipt_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(erasure, (own.clone(), 1, 77));
    let fact: (String, i64, i64) = connection.query_row(
        "SELECT origin_store_id, origin_openings_seq, conflicted FROM receipt_erasure_facts \
         WHERE receipt_id = ?1",
        [&receipt_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(fact, (own.clone(), 1, 0));
    let applied: i64 = connection.query_row(
        "SELECT applied_through FROM receipt_openings_watermarks WHERE origin_store_id = ?1",
        [&own],
        |row| row.get(0),
    )?;
    assert_eq!(applied, 1);
    Ok(())
}

#[test]
fn erase_twice_keeps_the_first_erasure() -> TestResult {
    let (_dir, path) = chio_test_support::temp_sqlite_path("chio-openings-erase-twice");
    let (store, receipt_id) = store_with_openings(&path)?;
    store.erase_openings(&receipt_id, 77)?;
    let before = raw_dump(&path)?;
    store.erase_openings(&receipt_id, 99)?;
    assert_eq!(raw_dump(&path)?, before);
    assert_eq!(
        store.opening_status(&receipt_id)?,
        OpeningStatus::Erased { erased_at: 77 }
    );
    Ok(())
}

#[test]
fn erase_tombstones_metadata_values_in_the_same_transaction() -> TestResult {
    let (_dir, path) = chio_test_support::temp_sqlite_path("chio-openings-erase-values");
    let (store, receipt_id) = store_with_openings(&path)?;
    let id = receipt_id.clone();
    store
        .writer_handle()
        .run_write_anchored_metadata(move |transaction| {
            transaction.execute(
                "INSERT INTO receipt_metadata_values \
                 VALUES (?1, 'metadata.financial.cost_breakdown', 'present', '{\"a\":1}', 1)",
                [&id],
            )?;
            Ok(())
        })?;
    store.erase_openings(&receipt_id, 77)?;
    let connection = Connection::open(&path)?;
    let values: Vec<String> = connection
        .prepare(
            "SELECT salt_ref || ':' || state || ':' || typeof(value) || ':' || state_at \
             FROM receipt_metadata_values WHERE receipt_id = ?1",
        )?
        .query_map([&receipt_id], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    assert_eq!(values, ["metadata.financial.cost_breakdown:erased:null:77"]);
    assert_eq!(
        store.opening_status(&receipt_id)?,
        OpeningStatus::Erased { erased_at: 77 }
    );
    Ok(())
}

#[test]
fn erase_refuses_unpublished_receipt() -> TestResult {
    let (_dir, path) = chio_test_support::temp_sqlite_path("chio-openings-unpublished");
    let store = SqliteReceiptStore::open(&path)?;
    let error = store
        .erase_openings(R, 77)
        .err()
        .ok_or("unpublished erase was accepted")?;
    assert!(
        matches!(error, ReceiptStoreError::ReceiptNotPublished(ref id) if id == R),
        "{error:?}"
    );
    Ok(())
}

#[test]
fn erase_emits_new_openings_seq() -> TestResult {
    let (_dir, path) = chio_test_support::temp_sqlite_path("chio-openings-seq");
    let (store, first) = store_with_openings(&path)?;
    let second = sample_receipt_with_id("rcpt-openings-second");
    store.append_chio_receipt(&second)?;
    store.erase_openings(&first, 1)?;
    store.erase_openings(&second.id, 2)?;
    let connection = Connection::open(&path)?;
    let rows: Vec<(i64, i64)> = connection
        .prepare("SELECT openings_seq, origin_openings_seq FROM receipt_opening_erasures ORDER BY openings_seq")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    assert_eq!(rows, [(1, 1), (2, 2)]);
    Ok(())
}

#[test]
fn store_origin_id_stable_across_restart() -> TestResult {
    let (_dir, path) = chio_test_support::temp_sqlite_path("chio-openings-identity");
    drop(SqliteReceiptStore::open(&path)?);
    let first = own_store_id(&path)?;
    assert_eq!(first.len(), 32);
    drop(SqliteReceiptStore::open_existing(&path)?);
    assert_eq!(own_store_id(&path)?, first);
    Ok(())
}

fn refused_open_leaves_store_unchanged(
    name: &str,
    damage: &str,
    expected: fn(&ReceiptStoreError) -> bool,
) -> TestResult {
    let (_dir, path) = chio_test_support::temp_sqlite_path(name);
    drop(SqliteReceiptStore::open(&path)?);
    Connection::open(&path)?.execute_batch(damage)?;
    let before = raw_dump(&path)?;
    let error = SqliteReceiptStore::open_existing(&path)
        .err()
        .ok_or("damaged store opened")?;
    assert!(expected(&error), "{error:?}");
    assert_eq!(raw_dump(&path)?, before);
    Ok(())
}

#[test]
fn store_id_missing_refuses_open_without_mutation() -> TestResult {
    refused_open_leaves_store_unchanged(
        "chio-openings-id-missing",
        "DROP TRIGGER receipt_store_identity_no_delete; DELETE FROM receipt_store_identity;",
        |error| matches!(error, ReceiptStoreError::StoreIdMissing),
    )
}

#[test]
fn store_id_changed_refuses_open_without_mutation() -> TestResult {
    refused_open_leaves_store_unchanged(
        "chio-openings-id-changed",
        "DELETE FROM receipt_openings_watermarks;",
        |error| matches!(error, ReceiptStoreError::StoreIdChanged),
    )
}

#[test]
fn store_id_no_replace_trigger_missing_refuses_open() -> TestResult {
    refused_open_leaves_store_unchanged(
        "chio-openings-no-replace-missing",
        "DROP TRIGGER receipt_store_identity_no_replace;",
        |error| matches!(error, ReceiptStoreError::StoreIdChanged),
    )
}

#[test]
fn old_layout_refuses_without_mutation() -> TestResult {
    refused_open_leaves_store_unchanged(
        "chio-openings-old-layout",
        "DROP TABLE receipt_openings_peer_cursors;",
        |error| {
            !matches!(
                error,
                ReceiptStoreError::StoreIdMissing | ReceiptStoreError::StoreIdChanged
            )
        },
    )
}

#[test]
fn values_table_missing_refuses_open_without_mutation() -> TestResult {
    refused_open_leaves_store_unchanged(
        "chio-openings-values-missing",
        "DROP TABLE receipt_metadata_values;",
        |error| {
            !matches!(
                error,
                ReceiptStoreError::StoreIdMissing | ReceiptStoreError::StoreIdChanged
            )
        },
    )
}

const ENCODINGS: [&str; 3] = ["UTF-8", "UTF-16le", "UTF-16be"];

fn bare_in(encoding: &str) -> Result<Connection, rusqlite::Error> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(&format!("PRAGMA encoding = '{encoding}';"))?;
    connection.execute_batch(RECEIPT_OPENINGS_SCHEMA)?;
    Ok(connection)
}

fn refused_in(encoding: &str, statement: &str) -> TestResult {
    let connection = bare_in(encoding)?;
    let before = dump(&connection)?;
    let error = run(&connection, statement)
        .err()
        .ok_or(format!("{encoding}: accepted {statement}"))?;
    assert!(error.to_string().contains(CHECK), "{encoding}: {error}");
    assert_eq!(dump(&connection)?, before);
    Ok(())
}

#[test]
fn every_table_accepts_a_valid_row_in_every_encoding() -> TestResult {
    let rows = [
        PRESENT,
        VALUE,
        IDENTITY,
        ERASURE,
        FACT,
        BELOW,
        WATERMARK,
        "INSERT INTO receipt_openings_member_watermarks VALUES ('https://peer.example', '{O}', 4)",
        "INSERT INTO receipt_openings_peer_cursors VALUES ('https://peer.example', 4)",
    ];
    for encoding in ENCODINGS {
        for row in rows {
            let connection = bare_in(encoding)?;
            run(&connection, row).map_err(|error| format!("{encoding}: {row}: {error}"))?;
        }
    }
    Ok(())
}

#[test]
fn key_bounds_count_characters_in_every_encoding() -> TestResult {
    let salt_ref_max = format!("a{}", "b".repeat(63));
    let short_receipt = R.get(1..).ok_or("receipt id fixture")?;
    let short_store = O.get(1..).ok_or("store id fixture")?;
    let node_max = "\u{e9}".repeat(2048);
    for encoding in ENCODINGS {
        let connection = bare_in(encoding)?;
        run(
            &connection,
            &format!(
                "INSERT INTO receipt_openings VALUES ('{{R}}', '{salt_ref_max}', 'present', zeroblob(32), 1)"
            ),
        )?;
        run(
            &connection,
            &format!("INSERT INTO receipt_openings_peer_cursors VALUES ('{node_max}', 4)"),
        )?;
        refused_in(
            encoding,
            &format!(
                "INSERT INTO receipt_openings VALUES ('{{R}}', '{salt_ref_max}c', 'present', zeroblob(32), 1)"
            ),
        )?;
        refused_in(
            encoding,
            &format!(
                "INSERT INTO receipt_openings VALUES ('{short_receipt}', 'params', 'present', zeroblob(32), 1)"
            ),
        )?;
        refused_in(
            encoding,
            &format!("INSERT INTO receipt_store_identity VALUES (1, '{short_store}')"),
        )?;
        refused_in(
            encoding,
            &format!("INSERT INTO receipt_openings_peer_cursors VALUES ('{node_max}a', 4)"),
        )?;
    }
    Ok(())
}

#[test]
fn node_id_refuses_a_continuation_stretched_utf8_value() -> TestResult {
    let stretched = format!(
        "CAST(x'{}c3{}' AS TEXT)",
        "61".repeat(2047),
        "80".repeat(1 << 16)
    );
    refused_in(
        "UTF-8",
        &format!("INSERT INTO receipt_openings_peer_cursors VALUES ({stretched}, 4)"),
    )
}

#[test]
fn utf16_store_opens_reads_and_erases_openings() -> TestResult {
    for encoding in ["UTF-16le", "UTF-16be"] {
        let (_dir, path) = chio_test_support::temp_sqlite_path("chio-openings-utf16");
        let external = Connection::open(&path)?;
        external.execute_batch(&format!(
            "PRAGMA encoding = '{encoding}';
             CREATE TABLE encoding_anchor (value TEXT);
             DROP TABLE encoding_anchor;"
        ))?;
        let (store, receipt_id) = store_with_openings(&path)?;
        let actual: String = external.pragma_query_value(None, "encoding", |row| row.get(0))?;
        assert_eq!(actual, encoding);
        assert_eq!(own_store_id(&path)?.len(), 32);
        let scope = OpeningReadScope {
            salt_refs: vec![salt_ref("params")?, salt_ref("content")?],
            tenant_binding: None,
        };
        let OpeningState::Present(opened) = store.read_openings(&receipt_id, &scope)? else {
            return Err(format!("{encoding}: present openings did not read as present").into());
        };
        assert_eq!(opened.salts.len(), 2, "{encoding}");
        store.erase_openings(&receipt_id, 77)?;
        assert_eq!(
            store.opening_status(&receipt_id)?,
            OpeningStatus::Erased { erased_at: 77 },
            "{encoding}"
        );
    }
    Ok(())
}
