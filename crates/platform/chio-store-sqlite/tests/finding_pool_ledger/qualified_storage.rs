use super::*;

#[test]
fn qualified_pool_rejects_percent_decoded_nul_uris() {
    for path in ["file:%00", "file::memory:%00", "file:pool?mode=memory%00"] {
        assert!(
            matches!(
                open_qualified(path, ledger_domain()),
                Err(FindingPoolLedgerError::Storage(_))
            ),
            "{path} must be rejected before SQLite opens it"
        );
    }
}

#[test]
fn qualified_pool_creates_percent_decoded_uri_parent() {
    let directory = tempfile::tempdir().test_expect("create ledger directory");
    let decoded_parent = directory.path().join("pool");
    let encoded_uri = format!(
        "file:{}%2Fpool%2Fpool.sqlite3?mode=rwc",
        directory.path().display()
    );

    drop(
        open_qualified(&encoded_uri, ledger_domain())
            .test_expect("open qualified ledger through encoded URI"),
    );

    assert!(decoded_parent.join("pool.sqlite3").is_file());
}

#[test]
fn qualified_pool_rejects_sqlite_uris_that_disable_file_locking() {
    let directory = tempfile::tempdir().test_expect("create ledger directory");
    let database = directory.path().join("pool.sqlite3");
    let base = format!("file:{}", database.display());
    for path in [
        format!("{base}?nolock=1"),
        format!("{base}?%6eolock=1"),
        format!("{base}?vfs=unix-none"),
        format!("{base}?vfs=unix%2dnone"),
    ] {
        assert!(
            matches!(
                open_qualified(&path, ledger_domain()),
                Err(FindingPoolLedgerError::Storage(_))
            ),
            "lockless SQLite URI {path:?} must not qualify"
        );
    }
}

#[test]
fn qualified_pool_rejects_read_only_sqlite_uris() {
    let directory = tempfile::tempdir().test_expect("create ledger directory");
    let database = directory.path().join("pool.sqlite3");
    drop(open_qualified(&database, ledger_domain()).test_expect("initialize writable pool ledger"));
    let base = format!("file:{}", database.display());
    for path in [
        format!("{base}?mode=ro"),
        format!("{base}?%6dode=%72o"),
        format!("{base}?immutable=1"),
    ] {
        assert!(
            matches!(
                open_qualified(&path, ledger_domain()),
                Err(FindingPoolLedgerError::Storage(_))
            ),
            "read-only SQLite URI {path:?} must not qualify"
        );
    }
}

#[cfg(unix)]
#[test]
fn qualified_pool_rejects_a_symlink_database_path() {
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().test_expect("create ledger directory");
    let target = directory.path().join("target.sqlite3");
    let alias = directory.path().join("pool.sqlite3");
    std::fs::File::create(&target).test_expect("create target database");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
        .test_expect("secure target database");
    symlink(&target, &alias).test_expect("create database symlink");

    assert!(matches!(
        open_qualified(&alias, format!("{}:symlink", ledger_domain())),
        Err(FindingPoolLedgerError::Storage(_))
    ));
}

#[cfg(unix)]
#[test]
fn qualified_pool_rejects_group_or_world_writable_database_files() {
    use std::os::unix::fs::PermissionsExt as _;

    for mode in [0o620, 0o602] {
        let directory = tempfile::tempdir().test_expect("create ledger directory");
        let database = directory.path().join("pool.sqlite3");
        std::fs::File::create(&database).test_expect("create pool database");
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(mode))
            .test_expect("set unsafe pool database mode");
        assert!(matches!(
            open_qualified(
                &database,
                format!("{}:unsafe-mode-{mode:o}", ledger_domain()),
            ),
            Err(FindingPoolLedgerError::Storage(message))
                if message.contains("unsafe ownership or permissions")
        ));
    }
}

#[test]
fn cognition_market_qualified_pool_refuses_in_memory_storage() {
    for path in [
        ":memory:",
        "",
        "file:",
        "file://",
        "file://localhost",
        "file://?mode=rwc",
        "file://localhost?mode=rwc",
        "file://other-host/tmp/pool.sqlite3",
        "file:?mode=rwc",
        "file:pool?vfs=memdb",
        "file:pool?mode%3Dmemory",
        "file:pool?mode=%6demory",
        "file:%3Amemory%3A",
        "file::memory:#fragment",
        "file:pool?mode=memory#fragment",
        "file:pool?vfs=memdb#fragment",
    ] {
        assert!(
            matches!(
                open_qualified(path, ledger_domain()),
                Err(FindingPoolLedgerError::Storage(_))
            ),
            "temporary SQLite path {path:?} must not qualify"
        );
    }
}
