//! Content-binding history head for anchored SQLite stores.
//!
//! A qualified store keeps a rolling SHA-256 head next to its generation. Each
//! anchored commit extends the head with a digest of every row its
//! transaction changed, so two databases that reach the same generation with
//! different content carry different heads and the anchor refuses the fork.
//!
//! Row changes are captured by connection-local TEMP triggers on every main
//! table, which also cover `WITHOUT ROWID` tables and rows written by the
//! store's own triggers. They append to `temp.chio_tx_log`, which the head
//! computation reads before the generation row is advanced.

use std::collections::BTreeSet;

use rusqlite::functions::FunctionFlags;
use rusqlite::types::ValueRef;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

const GENESIS_DOMAIN: &[u8] = b"chio.store-head.genesis.v1";
const STEP_DOMAIN: &[u8] = b"chio.store-head.v1";
const ROW_DIGEST_FUNCTION: &str = "chio_store_row_digest";
const LOG_TABLE: &str = "chio_tx_log";
const LOG_META_TABLE: &str = "chio_tx_log_meta";
const LOG_TRIGGER_PREFIX: &str = "chio_tx_log_";
#[derive(Debug)]
struct ChangeLogError(String);

impl std::fmt::Display for ChangeLogError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ChangeLogError {}

fn change_log_error(message: String) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(ChangeLogError(message)))
}

/// Columns of the generation rows that the commit itself rewrites; they are
/// excluded from the row digest so the head does not depend on its own update.
pub(crate) struct ChangeLogScope<'a> {
    /// Tables whose rows are not logged at all.
    pub(crate) skip_tables: &'a [&'a str],
    /// `(table, column)` pairs left out of that table's row digest.
    pub(crate) excluded_columns: &'a [(&'a str, &'a str)],
}

/// Lowercase hex of the head a freshly created store starts from.
pub(crate) fn genesis_head_hex() -> String {
    hex::encode(Sha256::digest(GENESIS_DOMAIN))
}

fn feed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn register_row_digest(connection: &Connection) -> rusqlite::Result<()> {
    if connection
        .query_row(&format!("SELECT {ROW_DIGEST_FUNCTION}()"), [], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .is_ok()
    {
        return Ok(());
    }
    connection.create_scalar_function(
        ROW_DIGEST_FUNCTION,
        -1,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let mut hasher = Sha256::new();
            for index in 0..context.len() {
                match context.get_raw(index) {
                    ValueRef::Null => hasher.update([0u8]),
                    ValueRef::Integer(value) => {
                        hasher.update([1u8]);
                        hasher.update(value.to_be_bytes());
                    }
                    ValueRef::Real(value) => {
                        hasher.update([2u8]);
                        hasher.update(value.to_bits().to_be_bytes());
                    }
                    ValueRef::Text(value) => {
                        hasher.update([3u8]);
                        feed(&mut hasher, value);
                    }
                    ValueRef::Blob(value) => {
                        hasher.update([4u8]);
                        feed(&mut hasher, value);
                    }
                }
            }
            Ok(hasher.finalize().to_vec())
        },
    )
}

fn quote_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn main_tables(connection: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare(
        "SELECT name FROM main.sqlite_master \
         WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' \
           AND sql NOT LIKE 'CREATE VIRTUAL%' ORDER BY name",
    )?;
    let names = statement.query_map([], |row| row.get::<_, String>(0))?;
    names.collect()
}

/// Every main table with its columns. A change here between installing the
/// triggers and computing the head means the triggers no longer cover the rows.
fn table_signature(connection: &Connection) -> rusqlite::Result<String> {
    let mut lines = Vec::new();
    for table in main_tables(connection)? {
        lines.push(format!(
            "{table}({})",
            table_columns(connection, &table)?.join(",")
        ));
    }
    Ok(lines.join("\n"))
}

fn log_triggers(connection: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare(
        "SELECT name FROM temp.sqlite_master WHERE type = 'trigger' \
         AND name LIKE 'chio\\_tx\\_log\\_%' ESCAPE '\\' ORDER BY name",
    )?;
    let names = statement.query_map([], |row| row.get::<_, String>(0))?;
    names.collect()
}

fn table_columns(connection: &Connection, table: &str) -> rusqlite::Result<Vec<String>> {
    let mut statement =
        connection.prepare(&format!("PRAGMA main.table_info({})", quote_literal(table)))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    columns.collect()
}

fn install_triggers(connection: &Connection, scope: &ChangeLogScope<'_>) -> rusqlite::Result<()> {
    let stale: Vec<String> = {
        let mut statement = connection.prepare(
            "SELECT name FROM temp.sqlite_master WHERE type = 'trigger' AND name LIKE 'chio\\_tx\\_log\\_%' ESCAPE '\\'",
        )?;
        let names = statement.query_map([], |row| row.get::<_, String>(0))?;
        names.collect::<rusqlite::Result<_>>()?
    };
    for name in stale {
        connection.execute_batch(&format!("DROP TRIGGER temp.{}", quote_identifier(&name)))?;
    }
    let skipped: BTreeSet<&str> = scope.skip_tables.iter().copied().collect();
    for table in main_tables(connection)? {
        if skipped.contains(table.as_str()) {
            continue;
        }
        let columns: Vec<String> = table_columns(connection, &table)?
            .into_iter()
            .filter(|column| {
                !scope
                    .excluded_columns
                    .iter()
                    .any(|(t, c)| *t == table && c == column)
            })
            .collect();
        if columns.is_empty() || columns.len() > 100 {
            return Err(change_log_error(format!(
                "store head cannot log table {table}: {} columns",
                columns.len()
            )));
        }
        let row = |prefix: &str| {
            columns
                .iter()
                .map(|column| format!("{prefix}.{}", quote_identifier(column)))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let tag = quote_literal(&table);
        let base = format!("{LOG_TRIGGER_PREFIX}{table}");
        let target = format!("main.{}", quote_identifier(&table));
        for (suffix, event, old, new) in [
            (
                "i",
                "INSERT",
                "NULL".to_string(),
                format!("{ROW_DIGEST_FUNCTION}({})", row("NEW")),
            ),
            (
                "u",
                "UPDATE",
                format!("{ROW_DIGEST_FUNCTION}({})", row("OLD")),
                format!("{ROW_DIGEST_FUNCTION}({})", row("NEW")),
            ),
            (
                "d",
                "DELETE",
                format!("{ROW_DIGEST_FUNCTION}({})", row("OLD")),
                "NULL".to_string(),
            ),
        ] {
            connection.execute_batch(&format!(
                "CREATE TEMP TRIGGER {name} AFTER {event} ON {target} BEGIN \
                 INSERT INTO {LOG_TABLE} (tbl, op, old_digest, new_digest) \
                 VALUES ({tag}, '{suffix}', {old}, {new}); END;",
                name = quote_identifier(&format!("{base}_{suffix}")),
            ))?;
        }
    }
    Ok(())
}

/// Start logging row changes for the transaction that is about to run on
/// `connection`. Call it once the transaction has begun and before any write.
pub(crate) fn begin_change_log(
    connection: &Connection,
    scope: &ChangeLogScope<'_>,
) -> rusqlite::Result<()> {
    register_row_digest(connection)?;
    connection.execute_batch(&format!(
        "CREATE TEMP TABLE IF NOT EXISTS {LOG_TABLE} (\
             seq INTEGER PRIMARY KEY AUTOINCREMENT, tbl TEXT NOT NULL, op TEXT NOT NULL, \
             old_digest BLOB, new_digest BLOB); \
         CREATE TEMP TABLE IF NOT EXISTS {LOG_META_TABLE} (schema_version INTEGER NOT NULL, tables TEXT NOT NULL, triggers TEXT NOT NULL); \
         DELETE FROM temp.{LOG_TABLE};"
    ))?;
    let schema_version: i64 =
        connection.query_row("PRAGMA main.schema_version", [], |row| row.get(0))?;
    let installed: Option<i64> = connection
        .query_row(
            &format!("SELECT schema_version FROM temp.{LOG_META_TABLE}"),
            [],
            |row| row.get(0),
        )
        .ok();
    if installed != Some(schema_version) {
        install_triggers(connection, scope)?;
        connection.execute_batch(&format!("DELETE FROM temp.{LOG_META_TABLE};"))?;
        connection.execute(
            &format!(
                "INSERT INTO temp.{LOG_META_TABLE} (schema_version, tables, triggers) \
                 VALUES (?1, ?2, ?3)"
            ),
            rusqlite::params![
                schema_version,
                table_signature(connection)?,
                log_triggers(connection)?.join("\n")
            ],
        )?;
    }
    Ok(())
}

/// The head that follows `previous_head_hex` once this transaction commits:
/// SHA-256 over the step domain, the previous head and every logged change in
/// execution order.
pub(crate) fn next_head_hex(
    connection: &Connection,
    previous_head_hex: &str,
) -> rusqlite::Result<String> {
    let (logged_tables, installed_triggers): (String, String) = connection.query_row(
        &format!("SELECT tables, triggers FROM temp.{LOG_META_TABLE}"),
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if logged_tables != table_signature(connection)? {
        return Err(change_log_error(
            "a table was created, dropped or altered inside an anchored transaction".to_string(),
        ));
    }
    if installed_triggers != log_triggers(connection)?.join("\n") {
        return Err(change_log_error(
            "the change-log triggers are not the installed set".to_string(),
        ));
    }
    let mut hasher = Sha256::new();
    feed(&mut hasher, STEP_DOMAIN);
    feed(&mut hasher, previous_head_hex.as_bytes());
    let mut statement = connection.prepare(&format!(
        "SELECT tbl, op, old_digest, new_digest FROM temp.{LOG_TABLE} ORDER BY seq"
    ))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        feed(&mut hasher, row.get::<_, String>(0)?.as_bytes());
        feed(&mut hasher, row.get::<_, String>(1)?.as_bytes());
        feed(
            &mut hasher,
            &row.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default(),
        );
        feed(
            &mut hasher,
            &row.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
        );
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Reject a head value that is not 64 lowercase hex characters.
pub(crate) fn canonical_head(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const NO_SKIP: ChangeLogScope<'static> = ChangeLogScope {
        skip_tables: &[],
        excluded_columns: &[("counters", "generation")],
    };

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE plain (id INTEGER PRIMARY KEY, body TEXT NOT NULL); \
                 CREATE TABLE keyed (k TEXT PRIMARY KEY, v BLOB) WITHOUT ROWID; \
                 CREATE TABLE counters (id INTEGER PRIMARY KEY, generation INTEGER NOT NULL, note TEXT);\
                 INSERT INTO counters VALUES (1, 0, 'a');",
            )
            .unwrap();
        connection
    }

    fn log_trigger_names(connection: &Connection) -> Vec<String> {
        let mut statement = connection
            .prepare(
                "SELECT name FROM temp.sqlite_master WHERE type = 'trigger' \
                 AND name LIKE 'chio\\_tx\\_log\\_%' ESCAPE '\\' ORDER BY name",
            )
            .unwrap();
        let names = statement.query_map([], |row| row.get(0)).unwrap();
        names.map(Result::unwrap).collect()
    }

    fn head_after(connection: &Connection, work: &str) -> String {
        let tx = connection.unchecked_transaction().unwrap();
        begin_change_log(&tx, &NO_SKIP).unwrap();
        tx.execute_batch(work).unwrap();
        let head = next_head_hex(&tx, &genesis_head_hex()).unwrap();
        tx.rollback().unwrap();
        head
    }

    #[test]
    fn identical_changes_give_identical_heads_and_different_changes_do_not() {
        let connection = connection();
        let one = head_after(&connection, "INSERT INTO plain (body) VALUES ('x');");
        assert_eq!(
            one,
            head_after(&connection, "INSERT INTO plain (body) VALUES ('x');")
        );
        assert_ne!(
            one,
            head_after(&connection, "INSERT INTO plain (body) VALUES ('y');")
        );
    }

    #[test]
    fn without_rowid_tables_are_bound() {
        let connection = connection();
        let a = head_after(&connection, "INSERT INTO keyed VALUES ('k', x'01');");
        let b = head_after(&connection, "INSERT INTO keyed VALUES ('k', x'02');");
        assert_ne!(a, b);
        assert_ne!(a, head_after(&connection, "SELECT 1;"));
    }

    #[test]
    fn updates_and_deletes_are_bound() {
        let connection = connection();
        connection
            .execute_batch("INSERT INTO plain (body) VALUES ('x'), ('y');")
            .unwrap();
        let updated = head_after(&connection, "UPDATE plain SET body = 'z' WHERE id = 1;");
        let deleted = head_after(&connection, "DELETE FROM plain WHERE id = 1;");
        assert_ne!(updated, deleted);
        assert_ne!(updated, head_after(&connection, "SELECT 1;"));
    }

    #[test]
    fn excluded_columns_do_not_move_the_head_but_other_columns_do() {
        let connection = connection();
        let base = head_after(&connection, "UPDATE counters SET generation = 1;");
        assert_eq!(
            base,
            head_after(&connection, "UPDATE counters SET generation = 9;")
        );
        assert_ne!(
            base,
            head_after(&connection, "UPDATE counters SET note = 'b';")
        );
    }

    #[test]
    fn a_table_created_inside_the_transaction_is_refused() {
        let connection = connection();
        let tx = connection.unchecked_transaction().unwrap();
        begin_change_log(&tx, &NO_SKIP).unwrap();
        tx.execute_batch("CREATE TABLE late (v TEXT);").unwrap();
        assert!(next_head_hex(&tx, &genesis_head_hex()).is_err());
    }

    #[test]
    fn a_table_without_triggers_refuses_the_head() {
        let connection = connection();
        let tx = connection.unchecked_transaction().unwrap();
        begin_change_log(&tx, &NO_SKIP).unwrap();
        let names = log_trigger_names(&tx);
        assert_eq!(names.len(), 9);
        for suffix in ["i", "u", "d"] {
            tx.execute_batch(&format!("DROP TRIGGER temp.\"chio_tx_log_plain_{suffix}\""))
                .unwrap();
            assert!(next_head_hex(&tx, &genesis_head_hex()).is_err(), "{suffix}");
            tx.execute_batch("ROLLBACK").unwrap();
            tx.execute_batch("BEGIN").unwrap();
            begin_change_log(&tx, &NO_SKIP).unwrap();
        }
    }

    #[test]
    fn a_schema_change_inside_the_transaction_refuses_the_head() {
        let connection = connection();
        let tx = connection.unchecked_transaction().unwrap();
        begin_change_log(&tx, &NO_SKIP).unwrap();
        tx.execute_batch("ALTER TABLE plain ADD COLUMN extra TEXT;")
            .unwrap();
        assert!(next_head_hex(&tx, &genesis_head_hex()).is_err());
    }

    #[test]
    fn a_schema_change_between_transactions_reinstalls_the_triggers() {
        let connection = connection();
        let tx = connection.unchecked_transaction().unwrap();
        begin_change_log(&tx, &NO_SKIP).unwrap();
        tx.execute_batch("ALTER TABLE plain ADD COLUMN extra TEXT;")
            .unwrap();
        tx.commit().unwrap();
        let with_a = head_after(
            &connection,
            "INSERT INTO plain (body, extra) VALUES ('x', 'a');",
        );
        let with_b = head_after(
            &connection,
            "INSERT INTO plain (body, extra) VALUES ('x', 'b');",
        );
        assert_ne!(with_a, with_b);
    }

    #[test]
    fn a_missing_row_digest_function_fails_the_write() {
        let connection = connection();
        let tx = connection.unchecked_transaction().unwrap();
        begin_change_log(&tx, &NO_SKIP).unwrap();
        tx.remove_function(ROW_DIGEST_FUNCTION, -1).unwrap();
        let error = tx
            .execute_batch("INSERT INTO plain (body) VALUES ('x');")
            .expect_err("write without the digest function");
        assert!(error.to_string().contains(ROW_DIGEST_FUNCTION), "{error}");
    }

    #[test]
    fn an_erroring_row_digest_function_fails_the_write() {
        let connection = connection();
        let tx = connection.unchecked_transaction().unwrap();
        begin_change_log(&tx, &NO_SKIP).unwrap();
        tx.create_scalar_function(ROW_DIGEST_FUNCTION, -1, FunctionFlags::SQLITE_UTF8, |_| {
            Err::<Vec<u8>, _>(rusqlite::Error::UserFunctionError(
                "digest unavailable".into(),
            ))
        })
        .unwrap();
        assert!(tx
            .execute_batch("INSERT INTO plain (body) VALUES ('x');")
            .is_err());
    }

    #[test]
    fn a_rolled_back_transaction_leaves_nothing_in_the_log() {
        let connection = connection();
        let empty = head_after(&connection, "SELECT 1;");
        let tx = connection.unchecked_transaction().unwrap();
        begin_change_log(&tx, &NO_SKIP).unwrap();
        tx.execute_batch("INSERT INTO plain (body) VALUES ('x');")
            .unwrap();
        tx.rollback().unwrap();
        let logged: i64 = connection
            .query_row("SELECT COUNT(*) FROM temp.chio_tx_log", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);
        assert_eq!(logged, 0);
        assert_eq!(empty, head_after(&connection, "SELECT 1;"));
    }

    #[test]
    fn text_is_digested_as_utf8_whatever_the_database_encoding() {
        let work = "INSERT INTO plain (body) VALUES ('h\u{e9}llo \u{1f600} \u{4e16}\u{754c}');";
        let utf8 = head_after(&connection(), work);
        let utf16 = Connection::open_in_memory().unwrap();
        utf16
            .execute_batch(
                "PRAGMA encoding = 'UTF-16le'; \
                 CREATE TABLE plain (id INTEGER PRIMARY KEY, body TEXT NOT NULL); \
                 CREATE TABLE keyed (k TEXT PRIMARY KEY, v BLOB) WITHOUT ROWID; \
                 CREATE TABLE counters (id INTEGER PRIMARY KEY, generation INTEGER NOT NULL, note TEXT);\
                 INSERT INTO counters VALUES (1, 0, 'a');",
            )
            .unwrap();
        let encoding: String = utf16
            .query_row("PRAGMA encoding", [], |row| row.get(0))
            .unwrap();
        assert_eq!(encoding, "UTF-16le");
        assert_eq!(utf8, head_after(&utf16, work));
    }

    #[test]
    fn savepoint_rollbacks_leave_no_trace() {
        let connection = connection();
        let tx = connection.unchecked_transaction().unwrap();
        begin_change_log(&tx, &NO_SKIP).unwrap();
        let before = next_head_hex(&tx, &genesis_head_hex()).unwrap();
        tx.execute_batch(
            "SAVEPOINT s; INSERT INTO plain (body) VALUES ('x'); ROLLBACK TO s; RELEASE s;",
        )
        .unwrap();
        assert_eq!(before, next_head_hex(&tx, &genesis_head_hex()).unwrap());
    }

    #[test]
    fn genesis_head_is_the_documented_domain_digest() {
        assert_eq!(
            genesis_head_hex(),
            hex::encode(Sha256::digest(b"chio.store-head.genesis.v1"))
        );
        assert!(canonical_head(&genesis_head_hex()));
        assert!(!canonical_head("ABC"));
    }
}
