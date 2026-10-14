//! Startup observations of the held journal file that need no native store.
//! Genesis and the supported historical upgrade run under the native scope
//! and are covered against the production library in `tests/journal_startup.rs`.
use super::*;
use crate::store::Store;
use rusqlite::params;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn empty_genesis_inventory_is_bound_to_the_held_file() -> TestResult {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let authority = uuid::Uuid::new_v4().to_string();
    let path = crate::store::private_file(&directory.path().join("process.db"))?;
    let mut held = Store::open(&path, &authority, "journal key")?;
    let first = held.native_return_inventory()?;
    let second = held.native_return_inventory()?;
    assert_eq!(first, second);
    assert_eq!(first.journal_namespace, held.namespace);
    assert_eq!(first.journal_authority, authority);
    assert_eq!(
        [
            first.root_count,
            first.process_count,
            first.account_count,
            first.phase_count,
            first.history_sequence
        ],
        [0; 5]
    );
    assert_eq!(first.current_write_count, 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(first.file_inode, std::fs::metadata(&path)?.ino());
    }
    first
        .validate_data()
        .map_err(|_| "the genesis inventory is not valid DATA")?;
    Ok(())
}

#[test]
fn unknown_layouts_refuse_without_mutation() -> TestResult {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let authority = uuid::Uuid::new_v4().to_string();
    let namespace = uuid::Uuid::new_v4().to_string();
    for (name, extra) in [
        ("stray.db", None),
        (
            "historical-with-stray.db",
            Some("CREATE TABLE stray(value)"),
        ),
    ] {
        let path = crate::store::private_file(&directory.path().join(name))?;
        let db = rusqlite::Connection::open(&path)?;
        match extra {
            None => db.execute_batch("CREATE TABLE stray(value)")?,
            Some(stray) => {
                db.execute_batch(include_str!(
                    "../../../tests/fixtures/legacy-process-v1.sql"
                ))?;
                db.execute(
                    "INSERT INTO process_runtime VALUES(1,1,?1,?2,'journal key')",
                    params![namespace, authority],
                )?;
                db.execute_batch(stray)?;
            }
        }
        drop(db);
        let before = std::fs::read(&path)?;
        let refused = Store::open(&path, &authority, "journal key");
        assert!(refused.is_err(), "{name} was accepted as a journal");
        assert_eq!(
            std::fs::read(&path)?,
            before,
            "{name} was mutated by a refused open"
        );
    }
    Ok(())
}
