use std::path::Path;

use rusqlite::Connection;

use crate::schema_version::{inspect_schema, SchemaState, SchemaTransaction, SchemaVersionError};

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

pub fn initialize_finding_operator_database(
    path: impl AsRef<Path>,
) -> Result<(), SchemaVersionError> {
    let path = path.as_ref();
    if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
        std::fs::create_dir_all(parent)?;
    }
    let mut connection = Connection::open(path)?;
    initialize_connection(&mut connection)
}

pub(crate) fn initialize_connection(connection: &mut Connection) -> Result<(), SchemaVersionError> {
    let transaction = SchemaTransaction::begin(connection, NAMESPACES)?;
    let sql = schema();
    if transaction.is_fresh() {
        transaction.connection().execute_batch(&sql)?;
        for namespace in NAMESPACES {
            transaction.stamp(namespace)?;
        }
    }
    transaction.validate_catalog(&sql)?;
    transaction.commit()?;
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;",
        )
        .map_err(SchemaVersionError::from)
}

pub(crate) fn validate_component(connection: &mut Connection) -> Result<(), SchemaVersionError> {
    let transaction = connection.transaction()?;
    if inspect_schema(&transaction, NAMESPACES)? != SchemaState::Current {
        return Err(SchemaVersionError::CreationNotAllowed);
    }
    crate::schema_version::validate_catalog(&transaction, &schema())?;
    transaction.commit()?;
    Ok(())
}
