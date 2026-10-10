//! Column sets of the tables this store owns. They match the `CREATE TABLE`
//! statements in `from_connection` column for column, in declaration order.

use chio_kernel::AdmissionOperationError;
use rusqlite::Connection;

use super::sqlite_error;

const OWNED_TABLES: [(&str, &[&str]); 2] = [
    (
        "admission_operations",
        &[
            "operation_id",
            "kind",
            "coordinator_authority_id",
            "request_id",
            "capability_id",
            "authorization_capability_hash",
            "request_binding_hash",
            "policy_hash",
            "broker_attempt_id",
            "budget_hold_id",
            "approval_set_hash",
            "execution_nonce_id",
            "state",
            "dispatch_state",
            "coordinator_lease_epoch",
            "version",
            "last_error",
            "updated_at",
        ],
    ),
    (
        "admission_cleanup_actions",
        &[
            "action_id",
            "operation_id",
            "request_binding_hash",
            "kind",
            "payload_json",
            "payload_hash",
            "state",
            "claim_token",
            "claim_deadline_unix_ms",
            "version",
            "last_error",
            "created_at",
            "updated_at",
        ],
    ),
];

/// Refuses a database file in which any table this store owns already exists
/// with a different column set. Runs before the store issues DDL, so a refused
/// file gains no tables or indexes.
pub(super) fn require_owned_table_shapes(
    connection: &Connection,
) -> Result<(), AdmissionOperationError> {
    for (table, expected) in OWNED_TABLES {
        let columns = table_columns(connection, table)?;
        let owned = columns
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied());
        if !columns.is_empty() && !owned {
            return Err(AdmissionOperationError::Invalid(format!(
                "existing {table} table does not carry the security admission operation schema; \
                 this store requires its own database file"
            )));
        }
    }
    Ok(())
}

fn table_columns(
    connection: &Connection,
    table: &str,
) -> Result<Vec<String>, AdmissionOperationError> {
    let mut statement = connection
        .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([table], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
}
