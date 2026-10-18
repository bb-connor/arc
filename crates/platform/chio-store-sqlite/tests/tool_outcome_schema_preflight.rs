#![cfg(unix)]

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use chio_kernel::tool_outcome::ToolOutcomeStoreError;
use chio_store_sqlite::SqliteAuthorityStore;
use rusqlite::Connection;

#[test]
fn provision_refuses_noncurrent_outcome_stamp_before_writes() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
    let database = temp.path().join("authority.db");
    let locks = temp.path().join("locks");
    fs::create_dir(&locks)?;
    fs::set_permissions(&locks, fs::Permissions::from_mode(0o700))?;
    SqliteAuthorityStore::provision(&database, &locks)?;
    {
        let connection = Connection::open(&database)?;
        connection.execute(
            "UPDATE chio_store_schema_versions SET version = 4 WHERE store_key = 'tool_outcome'",
            [],
        )?;
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    }
    let image = fs::read(&database)?;
    let error = SqliteAuthorityStore::provision(&database, &locks)
        .err()
        .ok_or("provisioning accepted a noncurrent tool outcome stamp")?;
    let inner = error
        .source()
        .and_then(|source| source.downcast_ref::<ToolOutcomeStoreError>())
        .ok_or_else(|| format!("tool outcome refusal lost its typed source: {error}"))?;
    assert_eq!(
        inner.to_string(),
        "tool outcome schema version 4 is not the current schema version 1; refusing to open"
    );
    assert_eq!(fs::read(&database)?, image);
    Ok(())
}
