//! Reclamation before the receipt store opens.
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::super::reclaim_abandoned_snapshots;
use crate::receipt_store::SqliteReceiptStore;

const PARENT_NAME: &str = "chio-receipt-snapshots-v2";

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

/// A closed receipt database and three abandoned snapshots beside it.
fn closed_store_with_abandoned_snapshots() -> (tempfile::TempDir, PathBuf, Vec<PathBuf>) {
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let live = root.path().join("live.db");
    // Dropping the store joins its writer and closes every connection.
    drop(SqliteReceiptStore::open(&live).unwrap());
    let parent = root.path().join(PARENT_NAME);
    private_directory(&parent);
    let abandoned = (0..3).map(|_| abandoned_directory(&parent)).collect();
    (root, live, abandoned)
}

/// The receipt database and its sidecars, byte for byte.
fn source_files(live: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .map(|suffix| {
            let mut name = live.as_os_str().to_os_string();
            name.push(suffix);
            (suffix.to_string(), std::fs::read(&name).ok())
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
    // The open committed a write (its schema stamp), and nothing reclaimed
    // the abandoned snapshots first: on a full data filesystem this open is
    // where startup would fail.
    assert_ne!(source_files(&live), before, "the open wrote nothing");
    assert!(abandoned.iter().all(|directory| directory.exists()));
    drop(store);
}
