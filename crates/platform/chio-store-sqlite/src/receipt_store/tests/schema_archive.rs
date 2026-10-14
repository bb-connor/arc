use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::ReceiptStore;

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
    assert!(matches!(create_archive_schema(&mut connection),
        Err(chio_kernel::ReceiptStoreError::Conflict(message))
            if message == "security evidence index schema differs from the canonical definition"));
    Ok(())
}

fn unique_archive_path() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "chio-schema-stamp-archive-{}-{nonce}.sqlite3",
        std::process::id()
    ))
}

#[test]
fn archive_schema_is_stamped_with_the_current_version() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::create_archive_schema;

    let archive = unique_archive_path();
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

    let reopened = crate::SqliteReceiptStore::open_existing(&archive)?;
    assert_eq!(reopened.durable_sink_id(), None);
    drop(reopened);

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

    for (version, expected) in [
        (
            Some(0),
            "retention archive schema version 0 is not the current receipt schema version 1",
        ),
        (
            Some(7),
            "retention archive schema version 7 is not the current receipt schema version 1",
        ),
        (None, "retention archive carries no receipt schema version"),
    ] {
        let archive = unique_archive_path();
        drop(crate::SqliteReceiptStore::open(&archive)?);
        let archived = rusqlite::Connection::open(&archive)?;
        match version {
            Some(version) => crate::stamp_schema_version(&archived, "receipt", version)?,
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
            matches!(&error, chio_kernel::ReceiptStoreError::Conflict(message) if message == expected),
            "unexpected error: {error}"
        );
        connection.execute_batch("DETACH DATABASE archive")?;
        let _ = std::fs::remove_file(archive);
    }

    let archive = unique_archive_path();
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
            chio_kernel::ReceiptStoreError::Conflict(message)
                if message == "retention archive carries tables but no receipt schema version"
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
        let archive = unique_archive_path();
        drop(crate::SqliteReceiptStore::open(&archive)?);

        let archived = rusqlite::Connection::open(&archive)?;
        crate::receipt_store::support::drop_transparency_projection_guards(&archived)?;
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
        assert!(error.to_string().contains("cost projection schema"));

        drop(connection);
        let _ = std::fs::remove_file(archive);
    }
    Ok(())
}
