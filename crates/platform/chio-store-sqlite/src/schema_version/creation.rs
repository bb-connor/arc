use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};

use super::{SchemaVersionError, CHIO_SQLITE_APPLICATION_ID};

const METADATA_SCHEMA: &str = "CREATE TABLE chio_store_schema_versions (
    store_key TEXT NOT NULL PRIMARY KEY,
    version INTEGER NOT NULL CHECK (version = 1)
) STRICT";

pub struct SchemaTransaction<'connection> {
    transaction: Transaction<'connection>,
    namespaces: BTreeSet<String>,
    fresh: bool,
}

impl<'connection> SchemaTransaction<'connection> {
    pub fn begin(
        connection: &'connection mut Connection,
        namespaces: &[&str],
    ) -> Result<Self, SchemaVersionError> {
        let declared: BTreeSet<String> = namespaces.iter().map(|key| (*key).to_owned()).collect();
        if declared.is_empty()
            || declared.len() != namespaces.len()
            || declared.iter().any(|key| key.is_empty())
        {
            return Err(SchemaVersionError::InvalidCreationPlan);
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let app_id: i32 = transaction.query_row("PRAGMA application_id", [], |row| row.get(0))?;
        let empty: bool = transaction.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM sqlite_schema)",
            [],
            |row| row.get(0),
        )?;
        let fresh = app_id == 0 && empty;
        if fresh {
            transaction.execute_batch(METADATA_SCHEMA)?;
            transaction.pragma_update(None, "application_id", CHIO_SQLITE_APPLICATION_ID)?;
        } else {
            if app_id != CHIO_SQLITE_APPLICATION_ID {
                return Err(SchemaVersionError::ForeignDatabase {
                    found: app_id,
                    expected: CHIO_SQLITE_APPLICATION_ID,
                });
            }
            validate_metadata(&transaction)?;
            validate_namespaces(&transaction, &declared)?;
        }
        Ok(Self {
            transaction,
            namespaces: declared,
            fresh,
        })
    }

    pub fn is_fresh(&self) -> bool {
        self.fresh
    }

    pub fn connection(&self) -> &Transaction<'connection> {
        &self.transaction
    }

    pub fn validate_catalog(&self, schema: &str) -> Result<(), SchemaVersionError> {
        let expected = Connection::open_in_memory()?;
        expected.execute_batch(METADATA_SCHEMA)?;
        expected.execute_batch(schema)?;
        if catalog(&self.transaction)? != catalog(&expected)? {
            return Err(SchemaVersionError::CatalogMismatch);
        }
        Ok(())
    }

    pub fn stamp(&self, namespace: &str) -> Result<(), SchemaVersionError> {
        if !self.fresh || !self.namespaces.contains(namespace) {
            return Err(SchemaVersionError::CreationNotAllowed);
        }
        self.transaction.execute(
            "INSERT INTO chio_store_schema_versions (store_key, version) VALUES (?1, 1)",
            [namespace],
        )?;
        Ok(())
    }

    pub fn commit(self) -> Result<(), SchemaVersionError> {
        let app_id: i32 = self
            .transaction
            .query_row("PRAGMA application_id", [], |row| row.get(0))?;
        if app_id != CHIO_SQLITE_APPLICATION_ID {
            return Err(SchemaVersionError::ForeignDatabase {
                found: app_id,
                expected: CHIO_SQLITE_APPLICATION_ID,
            });
        }
        validate_metadata(&self.transaction)?;
        validate_namespaces(&self.transaction, &self.namespaces)?;
        self.transaction.commit()?;
        Ok(())
    }
}

type CatalogEntry = (String, String, String, Option<String>);

fn catalog(connection: &Connection) -> Result<Vec<CatalogEntry>, SchemaVersionError> {
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(entries)
}

fn validate_metadata(connection: &Connection) -> Result<(), SchemaVersionError> {
    let sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'chio_store_schema_versions'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if sql.as_deref() != Some(METADATA_SCHEMA) {
        return Err(SchemaVersionError::MalformedMetadata);
    }
    let mut statement = connection.prepare(
        "SELECT type, name FROM sqlite_schema
         WHERE tbl_name = 'chio_store_schema_versions' ORDER BY type, name",
    )?;
    let objects = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if objects
        != [
            (
                "index".to_owned(),
                "sqlite_autoindex_chio_store_schema_versions_1".to_owned(),
            ),
            ("table".to_owned(), "chio_store_schema_versions".to_owned()),
        ]
    {
        return Err(SchemaVersionError::MalformedMetadata);
    }
    Ok(())
}

fn validate_namespaces(
    connection: &Connection,
    namespaces: &BTreeSet<String>,
) -> Result<(), SchemaVersionError> {
    for namespace in namespaces {
        let found: Option<i32> = connection
            .query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
                [namespace],
                |row| row.get(0),
            )
            .optional()?;
        match found {
            Some(1) => {}
            Some(found) => {
                return Err(SchemaVersionError::StaleSchema { found, current: 1 });
            }
            None => {
                return Err(SchemaVersionError::MissingSchema {
                    store_key: namespace.clone(),
                });
            }
        }
    }
    let mut statement = connection
        .prepare("SELECT store_key FROM chio_store_schema_versions ORDER BY store_key")?;
    let actual = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    if &actual != namespaces {
        return Err(SchemaVersionError::UnexpectedNamespaces);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_creation_commits_declared_v1_namespaces() -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        let creation = SchemaTransaction::begin(&mut connection, &["receipt", "approval"])?;
        assert!(creation.is_fresh());
        creation.connection().execute_batch(
            "CREATE TABLE receipts (id TEXT PRIMARY KEY); CREATE TABLE approvals (id TEXT PRIMARY KEY);",
        )?;
        creation.stamp("receipt")?;
        creation.stamp("approval")?;
        creation.commit()?;
        let reopen = SchemaTransaction::begin(&mut connection, &["receipt", "approval"])?;
        assert!(!reopen.is_fresh());
        reopen.commit()?;
        Ok(())
    }

    #[test]
    fn dropping_creation_rolls_back_identity_and_ddl() -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        {
            let creation = SchemaTransaction::begin(&mut connection, &["receipt"])?;
            creation
                .connection()
                .execute_batch("CREATE TABLE receipts (id TEXT PRIMARY KEY);")?;
            creation.stamp("receipt")?;
        }
        let app_id: i32 = connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
        assert_eq!(app_id, 0);
        let objects: i64 =
            connection.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| row.get(0))?;
        assert_eq!(objects, 0);
        Ok(())
    }

    #[test]
    fn missing_declared_stamp_rolls_back_creation() -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        let creation = SchemaTransaction::begin(&mut connection, &["receipt", "approval"])?;
        creation
            .connection()
            .execute_batch("CREATE TABLE receipts (id TEXT PRIMARY KEY);")?;
        creation.stamp("receipt")?;
        assert!(
            matches!(creation.commit(), Err(SchemaVersionError::MissingSchema { store_key }) if store_key == "approval")
        );
        let objects: i64 =
            connection.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| row.get(0))?;
        assert_eq!(objects, 0);
        let app_id: i32 = connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
        assert_eq!(app_id, 0);
        Ok(())
    }

    #[test]
    fn reopen_refuses_a_deleted_stamp_without_recreating_it(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        let creation = SchemaTransaction::begin(&mut connection, &["receipt", "approval"])?;
        creation.stamp("receipt")?;
        creation.stamp("approval")?;
        creation.commit()?;
        connection.execute(
            "DELETE FROM chio_store_schema_versions WHERE store_key = 'approval'",
            [],
        )?;
        assert!(
            matches!(SchemaTransaction::begin(&mut connection, &["receipt", "approval"]), Err(SchemaVersionError::MissingSchema { store_key }) if store_key == "approval")
        );
        assert_eq!(
            super::super::read_store_schema_version(&connection, "approval")?,
            None
        );
        Ok(())
    }

    #[test]
    fn creation_refuses_a_view_only_catalog() -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        connection.execute_batch("CREATE VIEW foreign_view AS SELECT 7 AS value;")?;
        assert!(matches!(
            SchemaTransaction::begin(&mut connection, &["receipt"]),
            Err(SchemaVersionError::ForeignDatabase {
                found: 0,
                expected: CHIO_SQLITE_APPLICATION_ID
            })
        ));
        let app_id: i32 = connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
        assert_eq!(app_id, 0);
        let value: i64 =
            connection.query_row("SELECT value FROM foreign_view", [], |row| row.get(0))?;
        assert_eq!(value, 7);
        Ok(())
    }

    #[test]
    fn creation_refuses_a_second_stamp() -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        let creation = SchemaTransaction::begin(&mut connection, &["receipt"])?;
        creation.stamp("receipt")?;
        assert!(
            matches!(creation.stamp("receipt"), Err(SchemaVersionError::Sqlite(rusqlite::Error::SqliteFailure(error, _))) if error.code == rusqlite::ErrorCode::ConstraintViolation)
        );
        assert_eq!(
            super::super::read_store_schema_version(creation.connection(), "receipt")?,
            Some(1)
        );
        Ok(())
    }

    #[test]
    fn reopen_cannot_add_a_namespace() -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        let creation = SchemaTransaction::begin(&mut connection, &["receipt"])?;
        creation.stamp("receipt")?;
        creation.commit()?;
        let reopen = SchemaTransaction::begin(&mut connection, &["receipt"])?;
        assert!(matches!(
            reopen.stamp("approval"),
            Err(SchemaVersionError::CreationNotAllowed)
        ));
        reopen.commit()?;
        assert_eq!(
            super::super::read_store_schema_version(&connection, "approval")?,
            None
        );
        Ok(())
    }

    #[test]
    fn reopen_refuses_extra_metadata_objects() -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        let creation = SchemaTransaction::begin(&mut connection, &["receipt"])?;
        creation.stamp("receipt")?;
        creation.commit()?;
        connection.execute_batch(
            "CREATE INDEX extra_metadata_index ON chio_store_schema_versions(version);",
        )?;
        assert!(matches!(
            SchemaTransaction::begin(&mut connection, &["receipt"]),
            Err(SchemaVersionError::MalformedMetadata)
        ));
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'extra_metadata_index')",
            [],
            |row| row.get(0),
        )?;
        assert!(present);
        Ok(())
    }

    #[test]
    fn creation_refuses_duplicate_or_empty_declarations() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut connection = Connection::open_in_memory()?;
        for namespaces in [&[][..], &["receipt", "receipt"][..], &[""][..]] {
            assert!(matches!(
                SchemaTransaction::begin(&mut connection, namespaces),
                Err(SchemaVersionError::InvalidCreationPlan)
            ));
        }
        let objects: i64 =
            connection.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| row.get(0))?;
        assert_eq!(objects, 0);
        Ok(())
    }
}
