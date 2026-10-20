/// Snapshot every durable table so refusal tests cover claims, participants,
/// commit chains, and derived authority state together.
pub(crate) fn authority_snapshot(
    connection: &rusqlite::Connection,
) -> rusqlite::Result<Vec<(String, Vec<String>)>> {
    let names = connection.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    names
        .into_iter()
        .map(|name| {
            let mut statement =
                connection.prepare(&format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))?;
            let columns = statement.column_count();
            let mut rows = statement
                .query_map([], |row| {
                    let values = (0..columns)
                        .map(|index| row.get::<_, rusqlite::types::Value>(index))
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(format!("{values:?}"))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows.sort();
            Ok((name, rows))
        })
        .collect()
}
use super::{
    is_in_memory_sqlite_path, sqlite_parent_dir_to_create, sqlite_uri_has_nonlocal_authority,
};
use std::path::{Path, PathBuf};

#[test]
fn resolves_parent_dir_from_file_uris_and_plain_paths() {
    // A `file:` URI with a query resolves to the real filesystem parent, not
    // a `file:`-prefixed directory folded out of the raw string.
    assert_eq!(
        sqlite_parent_dir_to_create(Path::new(
            "file:/var/lib/chio/receipts.db.revocations?mode=rwc"
        )),
        Some(PathBuf::from("/var/lib/chio"))
    );
    // A `file://` URI with an empty authority drops the `//`.
    assert_eq!(
        sqlite_parent_dir_to_create(Path::new("file:///var/lib/chio/db?cache=shared")),
        Some(PathBuf::from("/var/lib/chio"))
    );
    // A plain filesystem path keeps its parent unchanged.
    assert_eq!(
        sqlite_parent_dir_to_create(Path::new("/var/lib/chio/receipts.db")),
        Some(PathBuf::from("/var/lib/chio"))
    );
    // A bare filename has no directory component to create.
    assert_eq!(sqlite_parent_dir_to_create(Path::new("receipts.db")), None);
    assert_eq!(
        sqlite_parent_dir_to_create(Path::new("file:receipts.db?mode=rwc")),
        None
    );
    // In-memory databases have no backing directory.
    assert_eq!(sqlite_parent_dir_to_create(Path::new(":memory:")), None);
    assert_eq!(
        sqlite_parent_dir_to_create(Path::new("file:receipts.db?mode=memory")),
        None
    );
}

#[test]
fn classifies_in_memory_sqlite_paths() {
    for path in [
        ":memory:",
        ":MEMORY:",
        "file::memory:",
        "file:receipts.db?mode=memory",
        "file:receipts.db?cache=shared&mode=memory",
        "file:pool?vfs=memdb",
        "file:pool?mode%3Dmemory",
        "file:pool?mode=%6demory",
        "file:%3Amemory%3A",
        "file:%00",
        "file::memory:%00",
        "file:pool?mode=memory%00",
    ] {
        assert!(
            is_in_memory_sqlite_path(path),
            "{path} must classify as in-memory"
        );
    }
}

#[test]
fn classifies_durable_sqlite_paths() {
    for path in [
        "receipts.db",
        "/var/lib/chio/receipts.db",
        "file:/var/lib/chio/receipts.db?mode=rwc",
        "file:receipts.db",
        "memory-notes.db",
    ] {
        assert!(
            !is_in_memory_sqlite_path(path),
            "{path} must classify as durable"
        );
    }
}

#[test]
fn classifies_sqlite_uri_authorities() {
    for path in [
        "receipts.db",
        "file:/var/lib/chio/receipts.db",
        "file:///var/lib/chio/receipts.db",
        "file://localhost/var/lib/chio/receipts.db",
        "file://LOCALHOST/var/lib/chio/receipts.db",
        "file://%6cocalhost/var/lib/chio/receipts.db",
    ] {
        assert!(!sqlite_uri_has_nonlocal_authority(path), "{path}");
    }
    for path in [
        "file://remote-host/var/lib/chio/receipts.db",
        "file://%72emote-host/var/lib/chio/receipts.db",
        "file://localhost%00/var/lib/chio/receipts.db",
        "file://%zz/var/lib/chio/receipts.db",
    ] {
        assert!(sqlite_uri_has_nonlocal_authority(path), "{path}");
    }
}
