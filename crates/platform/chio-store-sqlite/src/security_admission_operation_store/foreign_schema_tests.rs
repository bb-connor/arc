//! The standalone security admission operation store owns its database file.
//! A file whose admission tables carry another schema is refused before the
//! store runs any DDL against it.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]

use std::path::Path;

use chio_kernel::AdmissionOperationError;
use rusqlite::Connection;

use super::SqliteAdmissionOperationStore;

fn table_names(path: &Path) -> Vec<String> {
    let connection = Connection::open(path).expect("open a reader");
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .expect("prepare the table listing");
    let rows = statement
        .query_map([], |row| row.get(0))
        .expect("list tables");
    rows.collect::<Result<Vec<String>, _>>()
        .expect("read table names")
}

fn open_error(path: &Path) -> AdmissionOperationError {
    match SqliteAdmissionOperationStore::open(path) {
        Ok(_) => panic!("the security admission store opened a foreign database"),
        Err(error) => error,
    }
}

fn assert_refused_table(error: &AdmissionOperationError, table: &str) {
    assert!(
        matches!(
            error,
            AdmissionOperationError::Invalid(detail)
                if detail.contains(table) && detail.contains("its own database file")
        ),
        "{error:?}"
    );
}

#[test]
fn a_canonical_admission_database_is_refused_before_any_ddl() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("canonical-admission.db");
    Connection::open(&path)
        .expect("open the canonical database")
        .execute_batch(include_str!("../admission_operation_store.sql"))
        .expect("install the canonical admission schema");
    let tables = table_names(&path);

    assert_refused_table(&open_error(&path), "admission_operations");
    assert_eq!(
        table_names(&path),
        tables,
        "the refused file gains no tables"
    );
}

#[test]
fn a_foreign_cleanup_action_table_is_refused_before_any_ddl() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("foreign-cleanup.db");
    Connection::open(&path)
        .expect("open the foreign database")
        .execute_batch("CREATE TABLE admission_cleanup_actions (action_id TEXT PRIMARY KEY);")
        .expect("install a foreign cleanup table");

    assert_refused_table(&open_error(&path), "admission_cleanup_actions");
    assert_eq!(
        table_names(&path),
        ["admission_cleanup_actions"],
        "the refused file gains no tables"
    );
}

#[test]
fn a_database_this_store_created_reopens() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("security-admission.db");
    drop(SqliteAdmissionOperationStore::open(&path).expect("create the store"));

    SqliteAdmissionOperationStore::open(&path).expect("reopen the store");
}
