use crate::receipt_store::evidence_retention;
use chio_kernel::ReceiptStoreError;
use chio_security_types::schema::SchemaRefusal;

#[test]
fn archive_schema_rejects_substituted_security_identity_guards(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::create_archive_schema;

    let mut connection = rusqlite::Connection::open_in_memory()?;
    connection.execute_batch("ATTACH DATABASE ':memory:' AS archive")?;
    create_archive_schema(&mut connection)?;
    connection.execute_batch(
        "DROP TRIGGER archive.chio_security_evidence_index_reject_update;
         CREATE TRIGGER archive.chio_security_evidence_index_reject_update
         BEFORE UPDATE ON chio_security_evidence_index BEGIN SELECT 1; END;",
    )?;
    assert!(matches!(
        create_archive_schema(&mut connection),
        Err(ReceiptStoreError::Schema(SchemaRefusal::CatalogMismatch))
    ));
    Ok(())
}

use chio_test_support::temp_sqlite_path;

#[test]
fn archive_schema_is_stamped_with_the_current_version() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::create_archive_schema;

    let (_archive_dir, archive) = temp_sqlite_path("chio-schema-stamp-archive");
    let escaped_archive = archive
        .to_str()
        .ok_or("archive path invalid")?
        .replace('\'', "''");
    let mut connection = rusqlite::Connection::open_in_memory()?;
    connection.execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
    create_archive_schema(&mut connection)?;
    let first_sink_id: String = connection.query_row(
        "SELECT sink_id FROM archive.chio_receipt_sink_identity WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        uuid::Uuid::parse_str(&first_sink_id)?.to_string(),
        first_sink_id
    );
    create_archive_schema(&mut connection)?;
    let replayed_sink_id: String = connection.query_row(
        "SELECT sink_id FROM archive.chio_receipt_sink_identity WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(replayed_sink_id, first_sink_id);
    connection.execute_batch("DETACH DATABASE archive")?;

    assert!(matches!(
        crate::SqliteReceiptStore::open_existing(&archive),
        Err(ReceiptStoreError::Schema(
            chio_security_types::schema::SchemaRefusal::CatalogMismatch
        ))
    ));

    let archived = rusqlite::Connection::open(&archive)?;
    let application_id: i32 = archived.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    assert_eq!(application_id, crate::CHIO_SQLITE_APPLICATION_ID);
    let version: i32 = archived.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        version,
        crate::receipt_store::support::RECEIPT_STORE_SCHEMA_VERSION
    );

    drop(archived);
    let _ = std::fs::remove_file(archive);
    Ok(())
}

#[test]
fn archive_schema_refuses_an_archive_without_the_current_version(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::create_archive_schema;

    for version in [Some(0), Some(7), None] {
        let expected = match version {
            Some(found) => SchemaRefusal::StaleSchema { found, current: 1 },
            None => SchemaRefusal::MissingSchema {
                store_key: "receipt".to_owned(),
            },
        };
        let (_archive_dir, archive) = temp_sqlite_path("chio-schema-stamp-archive");
        let mut creator = rusqlite::Connection::open_in_memory()?;
        creator.execute(
            "ATTACH DATABASE ?1 AS archive",
            [archive.to_str().ok_or("archive path")?],
        )?;
        create_archive_schema(&mut creator)?;
        creator.execute_batch("DETACH DATABASE archive")?;
        let archived = rusqlite::Connection::open(&archive)?;
        match version {
            Some(version) => crate::test_schema::write_version(&archived, "receipt", version)?,
            None => {
                archived.execute("DELETE FROM chio_store_schema_versions", [])?;
            }
        }
        drop(archived);

        let escaped_archive = archive
            .to_str()
            .ok_or("archive path invalid")?
            .replace('\'', "''");
        let mut connection = rusqlite::Connection::open_in_memory()?;
        connection.execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
        let error = create_archive_schema(&mut connection)
            .err()
            .ok_or("a non-current archive must be refused")?;
        assert!(
            matches!(&error, ReceiptStoreError::Schema(refusal) if refusal == &expected),
            "unexpected error: {error}"
        );
        connection.execute_batch("DETACH DATABASE archive")?;
        let _ = std::fs::remove_file(archive);
    }

    let (_archive_dir, archive) = temp_sqlite_path("chio-schema-stamp-archive");
    {
        let foreign = rusqlite::Connection::open(&archive)?;
        foreign.execute_batch(&format!(
            "PRAGMA application_id = {}; CREATE TABLE chio_tool_receipts (seq INTEGER);",
            crate::CHIO_SQLITE_APPLICATION_ID
        ))?;
    }
    let escaped_archive = archive
        .to_str()
        .ok_or("archive path invalid")?
        .replace('\'', "''");
    let mut connection = rusqlite::Connection::open_in_memory()?;
    connection.execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
    let error = create_archive_schema(&mut connection)
        .err()
        .ok_or("an unversioned populated archive must be refused")?;
    assert!(
        matches!(
            &error,
            ReceiptStoreError::Schema(SchemaRefusal::MissingSchema { store_key })
                if store_key == "receipt"
        ),
        "unexpected error: {error}"
    );
    connection.execute_batch("DETACH DATABASE archive")?;
    let _ = std::fs::remove_file(archive);
    Ok(())
}

#[test]
fn current_archive_schema_rejects_substituted_cost_indexes(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::create_archive_schema;

    for (name, columns) in [
        (
            "idx_chio_tool_receipts_cost",
            "tenant_id, cost_currency, seq, cost_charged_be",
        ),
        (
            "idx_chio_tool_receipts_cost_global",
            "cost_currency, seq, cost_charged_be",
        ),
    ] {
        let (_archive_dir, archive) = temp_sqlite_path("chio-schema-stamp-archive");
        let mut creator = rusqlite::Connection::open_in_memory()?;
        creator.execute(
            "ATTACH DATABASE ?1 AS archive",
            [archive.to_str().ok_or("archive path")?],
        )?;
        create_archive_schema(&mut creator)?;
        creator.execute_batch("DETACH DATABASE archive")?;

        let archived = rusqlite::Connection::open(&archive)?;
        archived.execute_batch(&format!(
            "DROP INDEX {name}; CREATE INDEX {name} ON chio_tool_receipts({columns});"
        ))?;
        drop(archived);

        let escaped_archive = archive
            .to_str()
            .ok_or("archive path invalid")?
            .replace('\'', "''");
        let mut connection = rusqlite::Connection::open_in_memory()?;
        connection.execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
        let Err(error) = create_archive_schema(&mut connection) else {
            return Err("archive cost projection schema unexpectedly passed".into());
        };
        assert!(matches!(
            error,
            ReceiptStoreError::Schema(SchemaRefusal::CatalogMismatch)
        ));

        drop(connection);
        let _ = std::fs::remove_file(archive);
    }
    Ok(())
}

#[test]
fn archive_admitting_unsigned_projection_lineage_is_refused(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::create_archive_schema;

    let mut connection = rusqlite::Connection::open_in_memory()?;
    connection.execute_batch(
        "ATTACH DATABASE ':memory:' AS archive;
         CREATE TABLE archive.capability_lineage (
             capability_id TEXT PRIMARY KEY,
             provenance TEXT NOT NULL DEFAULT 'legacy_projection'
                 CHECK (provenance IN ('signed_token', 'synthetic_anchor', 'legacy_projection'))
         );",
    )?;
    assert!(matches!(create_archive_schema(&mut connection),
        Err(ReceiptStoreError::Schema(SchemaRefusal::ForeignDatabase { found: 0, expected })) if expected == crate::CHIO_SQLITE_APPLICATION_ID));
    Ok(())
}

fn memory_archive() -> Result<rusqlite::Connection, ReceiptStoreError> {
    let connection = rusqlite::Connection::open_in_memory()?;
    connection.execute_batch("ATTACH DATABASE ':memory:' AS archive")?;
    Ok(connection)
}

#[test]
fn archive_empty_creation_refuses_a_view_only_catalog() -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = memory_archive()?;
    connection.execute_batch("CREATE VIEW archive.foreign_view AS SELECT 1 AS value")?;
    let before: i64 =
        connection.query_row("PRAGMA archive.schema_version", [], |row| row.get(0))?;
    assert!(
        matches!(evidence_retention::create_archive_schema(&mut connection),
        Err(ReceiptStoreError::Schema(SchemaRefusal::ForeignDatabase { found: 0, expected })) if expected == crate::CHIO_SQLITE_APPLICATION_ID)
    );
    assert_eq!(
        connection.query_row("PRAGMA archive.schema_version", [], |row| row
            .get::<_, i64>(0))?,
        before
    );
    assert_eq!(
        connection.query_row("PRAGMA archive.application_id", [], |row| row
            .get::<_, i32>(0))?,
        0
    );
    Ok(())
}

#[test]
fn archive_reopen_never_rewrites_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = memory_archive()?;
    evidence_retention::create_archive_schema(&mut connection)?;
    let changes = connection.total_changes();
    evidence_retention::create_archive_schema(&mut connection)?;
    assert_eq!(connection.total_changes(), changes);
    Ok(())
}

#[test]
fn archive_missing_table_is_not_recreated() -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = memory_archive()?;
    evidence_retention::create_archive_schema(&mut connection)?;
    connection.execute_batch("DROP TABLE archive.chio_child_receipts")?;
    assert!(matches!(
        evidence_retention::create_archive_schema(&mut connection),
        Err(ReceiptStoreError::Schema(SchemaRefusal::CatalogMismatch))
    ));
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM archive.sqlite_schema WHERE name = 'chio_child_receipts'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}

#[test]
fn archive_missing_sink_identity_is_not_reseeded() -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = memory_archive()?;
    evidence_retention::create_archive_schema(&mut connection)?;
    connection.execute("DELETE FROM archive.chio_receipt_sink_identity", [])?;
    assert!(
        matches!(evidence_retention::create_archive_schema(&mut connection),
        Err(ReceiptStoreError::Conflict(message))
            if message == "retention archive sink identity is missing")
    );
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM archive.chio_receipt_sink_identity",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}

#[test]
fn archive_schema_refusals_preserve_the_damaged_catalog() -> Result<(), Box<dyn std::error::Error>>
{
    for (damage, expected) in [
        (
            "PRAGMA archive.application_id = 7",
            SchemaRefusal::ForeignDatabase {
                found: 7,
                expected: crate::CHIO_SQLITE_APPLICATION_ID,
            },
        ),
        (
            "ALTER TABLE archive.chio_store_schema_versions ADD COLUMN extra TEXT",
            SchemaRefusal::MalformedMetadata,
        ),
        (
            "INSERT INTO archive.chio_store_schema_versions(store_key, version) VALUES('extra', 1)",
            SchemaRefusal::UnexpectedNamespaces,
        ),
    ] {
        let mut connection = memory_archive()?;
        evidence_retention::create_archive_schema(&mut connection)?;
        connection.execute_batch(damage)?;
        let changes = connection.total_changes();
        let schema_version: i64 =
            connection.query_row("PRAGMA archive.schema_version", [], |row| row.get(0))?;
        let error = evidence_retention::create_archive_schema(&mut connection)
            .err()
            .ok_or("damaged archive accepted")?;
        assert!(matches!(error, ReceiptStoreError::Schema(refusal) if refusal == expected));
        assert_eq!(connection.total_changes(), changes);
        assert_eq!(
            connection.query_row("PRAGMA archive.schema_version", [], |row| row
                .get::<_, i64>(0))?,
            schema_version
        );
    }
    Ok(())
}
