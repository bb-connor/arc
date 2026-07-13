use std::time::{SystemTime, UNIX_EPOCH};

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
fn archive_schema_is_stamped_and_rejects_older_binaries() -> Result<(), Box<dyn std::error::Error>>
{
    use crate::receipt_store::evidence_retention::create_archive_schema;

    let archive = unique_archive_path();
    let escaped_archive = archive
        .to_str()
        .ok_or("archive path invalid")?
        .replace('\'', "''");
    let mut connection = rusqlite::Connection::open_in_memory()?;
    connection.execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
    create_archive_schema(&mut connection)?;
    connection.execute_batch("DETACH DATABASE archive")?;

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
        crate::receipt_store::support::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
    );
    assert!(matches!(
        crate::check_schema_version(&archived, "receipt", 0, &["chio_tool_receipts"]),
        Err(crate::SchemaVersionError::FutureSchema { found, supported })
            if found == crate::receipt_store::support::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
                && supported == 0
    ));

    drop(archived);
    let _ = std::fs::remove_file(archive);
    Ok(())
}
