//! Reclamation before the receipt store opens.
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::super::reclaim_abandoned_snapshots;
use crate::receipt_query_snapshot_backing::snapshot_parent_of;
use crate::receipt_store::SqliteReceiptStore;

fn private_directory(path: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// A snapshot directory with a database file and no owner, as an owner that
/// died leaves it.
fn abandoned_directory(parent: &Path) -> PathBuf {
    let path = parent.join(uuid::Uuid::now_v7().hyphenated().to_string());
    private_directory(&path);
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path.join("snapshot.sqlite3"))
        .unwrap();
    path
}

/// Diagnostic bound on waiting for the last connection to close; not a
/// timing claim.
const HANG: Duration = Duration::from_secs(60);

fn sidecar(live: &Path, suffix: &str) -> PathBuf {
    let mut name = live.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Wait until no connection to `live` remains. Dropping the store can leave
/// pool connections that a pool worker thread closes later. The last close
/// checkpoints the WAL and removes the WAL and shared-memory files, so once
/// both are gone the database files no longer change.
fn wait_for_last_close(live: &Path) {
    let deadline = Instant::now() + HANG;
    while sidecar(live, "-wal").exists() || sidecar(live, "-shm").exists() {
        assert!(
            Instant::now() < deadline,
            "a connection to {live:?} stayed open"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A closed receipt database, with no connection left open, and three
/// abandoned snapshots beside it.
fn closed_store_with_abandoned_snapshots() -> (tempfile::TempDir, PathBuf, Vec<PathBuf>) {
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let live = root.path().join("live.db");
    drop(SqliteReceiptStore::open(&live).unwrap());
    wait_for_last_close(&live);
    let parent = snapshot_parent_of(&live);
    private_directory(&parent);
    let abandoned = (0..3).map(|_| abandoned_directory(&parent)).collect();
    (root, live, abandoned)
}

/// The receipt database and its sidecars, byte for byte.
fn source_files(live: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .map(|suffix| {
            (
                suffix.to_string(),
                std::fs::read(sidecar(live, suffix)).ok(),
            )
        })
        .collect()
}

#[test]
fn abandoned_snapshots_are_reclaimed_before_the_store_opens_without_touching_it() {
    let (_root, live, abandoned) = closed_store_with_abandoned_snapshots();
    let before = source_files(&live);
    reclaim_abandoned_snapshots(&live);
    for directory in &abandoned {
        assert!(!directory.exists(), "{directory:?} remains");
    }
    assert_eq!(
        source_files(&live),
        before,
        "reclamation touched the receipt database"
    );
    drop(SqliteReceiptStore::open(&live).unwrap());
}

#[test]
fn opening_the_store_writes_before_anything_else_reclaims_abandoned_snapshots() {
    let (_root, live, abandoned) = closed_store_with_abandoned_snapshots();
    let before = source_files(&live);
    let store = SqliteReceiptStore::open(&live).unwrap();
    // The open wrote to the receipt database's files (at least its WAL and
    // shared-memory files), and nothing reclaimed the abandoned snapshots
    // first: on a full data filesystem this open is where startup would fail.
    assert_ne!(source_files(&live), before, "the open wrote nothing");
    assert!(abandoned.iter().all(|directory| directory.exists()));
    drop(store);
}
