use super::{sqlite_error, Connection, PortError, PortResult};

type Entry = (String, String, String, Option<String>);

const FILTER: &str = "lower(name) GLOB 'security_*' OR lower(tbl_name) GLOB 'security_*'
    OR lower(name) = 'chio_store_schema_versions' OR lower(tbl_name) = 'chio_store_schema_versions'";

pub(super) struct Catalog(Vec<Entry>);

impl Catalog {
    pub(super) fn canonical() -> PortResult<Self> {
        let model = Connection::open_in_memory().map_err(sqlite_error)?;
        super::create_schema(&model)?;
        crate::stamp_schema_version(&model, "security_state", 1)
            .map_err(super::schema_version_error)?;
        Self::read(&model)
    }

    fn read(connection: &Connection) -> PortResult<Self> {
        let (count, bytes): (i64, i64) = connection.query_row(
            &format!(
                "SELECT COUNT(*), COALESCE(SUM(length(CAST(type AS BLOB)) + length(CAST(name AS BLOB))
                 + length(CAST(tbl_name AS BLOB)) + COALESCE(length(CAST(sql AS BLOB)), 0)), 0)
                 FROM sqlite_schema WHERE {FILTER}"
            ),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(sqlite_error)?;
        if !(0..=512).contains(&count) || !(0..=1_048_576).contains(&bytes) {
            return Err(PortError::integrity_failure());
        }
        let mut statement = connection
            .prepare(&format!(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE {FILTER}
             ORDER BY type COLLATE BINARY, name COLLATE BINARY, tbl_name COLLATE BINARY"
            ))
            .map_err(sqlite_error)?;
        let entries = statement
            .query_map([], |row| {
                let sql: Option<String> = row.get(3)?;
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    sql.as_deref().map(super::super::normalize_sql),
                ))
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<Entry>, _>>()
            .map_err(sqlite_error)?;
        Ok(Self(entries))
    }

    pub(super) fn preflight(&self, connection: &Connection) -> PortResult<()> {
        let observed = Self::read(connection)?;
        let is_metadata =
            |entry: &&Entry| entry.2.eq_ignore_ascii_case("chio_store_schema_versions");
        let metadata: Vec<_> = observed.0.iter().filter(is_metadata).collect();
        if !metadata.is_empty() && metadata != self.0.iter().filter(is_metadata).collect::<Vec<_>>()
        {
            return Err(PortError::integrity_failure());
        }
        let namespace_present = observed.0.iter().any(|entry| {
            entry.1.to_ascii_lowercase().starts_with("security_")
                || entry.2.to_ascii_lowercase().starts_with("security_")
        });
        if namespace_present
            && crate::schema_version::read_store_schema_version(connection, "security_state")
                .map_err(super::schema_version_error)?
                .is_none()
        {
            return Err(super::schema_version_error(
                crate::SchemaVersionError::StaleSchema {
                    found: 0,
                    current: 1,
                },
            ));
        }
        let application_id: i32 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(sqlite_error)?;
        if application_id == 0 {
            let populated: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*')",
                    [],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if populated {
                return Err(PortError::integrity_failure());
            }
        }
        Ok(())
    }

    pub(super) fn validate(&self, connection: &Connection) -> PortResult<()> {
        if Self::read(connection)?.0 != self.0 {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }
}
