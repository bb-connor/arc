use rusqlite::{Connection, OptionalExtension};

mod creation;
pub use creation::{inspect_schema, SchemaTransaction};
pub(crate) use creation::{validate_catalog, METADATA_SCHEMA};

pub const CHIO_SQLITE_APPLICATION_ID: i32 = 0x4348_494f;
const SCHEMA_VERSION_TABLE: &str = "chio_store_schema_versions";

#[derive(Debug, thiserror::Error)]
pub enum SchemaVersionError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("schema creation requires distinct nonempty namespace keys")]
    InvalidCreationPlan,
    #[error("schema namespace {store_key} is missing")]
    MissingSchema { store_key: String },
    #[error("schema creation is not allowed for this namespace")]
    CreationNotAllowed,
    #[error("schema metadata differs from its canonical definition")]
    MalformedMetadata,
    #[error("schema metadata contains undeclared namespaces")]
    UnexpectedNamespaces,
    #[error("schema catalog differs from its canonical definition")]
    CatalogMismatch,
    #[error("database application_id {found:#x} is not a Chio store (expected {expected:#x})")]
    ForeignDatabase { found: i32, expected: i32 },
    #[error(
        "database schema version {found} is not the current schema version {current}; refusing to open"
    )]
    StaleSchema { found: i32, current: i32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaState {
    Empty,
    Current,
}

pub(crate) fn read_store_schema_version(
    conn: &Connection,
    store_key: &str,
) -> Result<Option<i32>, SchemaVersionError> {
    let table_present: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [SCHEMA_VERSION_TABLE],
        |row| row.get(0),
    )?;
    if !table_present {
        return Ok(None);
    }
    Ok(conn
        .query_row(
            &format!("SELECT version FROM {SCHEMA_VERSION_TABLE} WHERE store_key = ?1"),
            [store_key],
            |row| row.get(0),
        )
        .optional()?)
}
