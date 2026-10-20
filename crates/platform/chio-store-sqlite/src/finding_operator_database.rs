use std::path::Path;

use rusqlite::Connection;

use crate::schema_version::{inspect_schema, SchemaTransaction, SchemaVersionError};

const NAMESPACES: &[&str] = &[
    "finding_operator_bundle",
    "finding_payload",
    "finding_operator_payment",
];

fn schema() -> String {
    [
        crate::finding_operator_bundle_store::SCHEMA,
        crate::finding_payload_store::FINDING_PAYLOAD_SCHEMA,
        crate::finding_operator_payment::SCHEMA,
    ]
    .join("\n")
}

pub fn initialize_finding_operator_database(path: impl AsRef<Path>) -> Result<(), String> {
    let path = path.as_ref();
    if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut connection = Connection::open(path).map_err(|error| error.to_string())?;
    let transaction =
        SchemaTransaction::begin(&mut connection, NAMESPACES).map_err(|error| error.to_string())?;
    let sql = schema();
    if transaction.is_fresh() {
        transaction
            .connection()
            .execute_batch(&sql)
            .map_err(|error| error.to_string())?;
        for namespace in NAMESPACES {
            transaction
                .stamp(namespace)
                .map_err(|error| error.to_string())?;
        }
    }
    transaction
        .validate_catalog(&sql)
        .map_err(|error| error.to_string())?;
    transaction.commit().map_err(|error| error.to_string())?;
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;",
        )
        .map_err(|error| error.to_string())
}

pub(crate) fn initialize_component(
    connection: &mut Connection,
    namespace: &str,
    sql: &str,
) -> Result<(), SchemaVersionError> {
    let standalone = [namespace];
    let composite = match inspect_schema(connection, &standalone) {
        Ok(_) => false,
        Err(SchemaVersionError::UnexpectedNamespaces) => {
            inspect_schema(connection, NAMESPACES)?;
            true
        }
        Err(error) => return Err(error),
    };
    let declared = if composite { NAMESPACES } else { &standalone };
    let transaction = SchemaTransaction::begin(connection, declared)?;
    if transaction.is_fresh() {
        transaction.connection().execute_batch(sql)?;
        transaction.stamp(namespace)?;
    }
    let composite_sql;
    let expected = if composite {
        composite_sql = schema();
        composite_sql.as_str()
    } else {
        sql
    };
    transaction.validate_catalog(expected)?;
    transaction.commit()?;
    connection.execute_batch(
        "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;",
    )?;
    Ok(())
}
