use rusqlite::{Connection, TransactionBehavior};

use super::{sqlite_error, ChioRuntimeError, SqliteRuntimeOrchestrationStore};

const SCHEMA: &str = include_str!("schema.sql");
const SCHEMA_VERSION: i64 = 1;
type CatalogEntry = (String, String, String, Option<String>);

fn catalog(connection: &Connection) -> Result<Vec<CatalogEntry>, ChioRuntimeError> {
    let oversized: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' AND
         (length(CAST(name AS BLOB)) > 512 OR length(CAST(tbl_name AS BLOB)) > 512 OR length(CAST(sql AS BLOB)) > 65536))
         OR (SELECT COUNT(*) FROM (SELECT 1 FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' LIMIT 65)) > 64",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if oversized {
        return Err(mismatch());
    }
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type, name, tbl_name")
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
}

fn mismatch() -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "runtime_store_schema_mismatch",
        detail: "runtime store requires the exact v1 schema".to_string(),
    }
}

impl SqliteRuntimeOrchestrationStore {
    pub(super) fn init_schema(&self) -> Result<(), ChioRuntimeError> {
        let reference = Connection::open_in_memory().map_err(sqlite_error)?;
        reference.execute_batch(SCHEMA).map_err(sqlite_error)?;
        let expected = catalog(&reference)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let actual = catalog(&transaction)?;
        let version: i64 = transaction
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(sqlite_error)?;
        if actual.is_empty() && version == 0 {
            transaction.execute_batch(SCHEMA).map_err(sqlite_error)?;
            transaction
                .pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(sqlite_error)?;
        } else if version != SCHEMA_VERSION || actual != expected {
            return Err(mismatch());
        }
        if catalog(&transaction)? != expected {
            return Err(mismatch());
        }
        transaction.commit().map_err(sqlite_error)
    }
}
