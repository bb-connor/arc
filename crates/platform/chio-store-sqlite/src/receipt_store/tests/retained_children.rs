//! Complete-history child receipt lookup and authenticated identity controls.

use std::path::PathBuf;

use chio_kernel::{ChildRequestReceipt, ReceiptStore, ReceiptStoreError};

use super::support::{
    receipt_test_keypair, sample_child_receipt_with_keypair_and_timestamp, signer,
};
use crate::SqliteReceiptStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct RetainedChildren {
    store: SqliteReceiptStore,
    archive: PathBuf,
    children: Vec<ChildRequestReceipt>,
    _directory: tempfile::TempDir,
}

impl RetainedChildren {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("live.sqlite3");
        let archive = directory.path().join("archive.sqlite3");
        let store = SqliteReceiptStore::open(&path)?;
        let keypair = receipt_test_keypair();
        store.enable_background_checkpoints(signer(&keypair, 2))?;
        let mut children = Vec::new();
        for index in 0..4 {
            let child = sample_child_receipt_with_keypair_and_timestamp(
                &format!("retained-child-{index}"),
                if index < 2 { 100 } else { 200 },
                &keypair,
            );
            store.append_child_receipt(&child)?;
            children.push(child);
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(2)?.is_some());
        store.archive_receipts_before(150, archive.to_str().ok_or("archive path invalid")?)?;
        let connection = store.reader_connection_for_test()?;
        let live_children: i64 =
            connection.query_row("SELECT COUNT(*) FROM chio_child_receipts", [], |row| {
                row.get(0)
            })?;
        assert_eq!(
            live_children, 2,
            "actual retention moved the first child batch"
        );
        Ok(Self {
            store,
            archive,
            children,
            _directory: directory,
        })
    }
}

#[test]
fn live_child_lookup_misses_archived_children_and_keeps_live_children() -> TestResult {
    let fixture = RetainedChildren::new()?;
    let archive = rusqlite::Connection::open(&fixture.archive)?;
    let archived: i64 = archive.query_row(
        "SELECT COUNT(*) FROM chio_child_receipts WHERE receipt_id = ?1",
        rusqlite::params![fixture.children[0].id],
        |row| row.get(0),
    )?;
    assert_eq!(
        archived, 1,
        "retention preserved the original archived child"
    );
    assert!(fixture
        .store
        .load_child_receipt(&fixture.children[0].id)?
        .is_none());
    assert!(fixture
        .store
        .load_child_receipt(&fixture.children[2].id)?
        .is_some());
    Ok(())
}

#[test]
fn retained_child_lookup_reads_an_uncheckpointed_live_append() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteReceiptStore::open(directory.path().join("live.sqlite3"))?;
    let child = sample_child_receipt_with_keypair_and_timestamp(
        "retained-child-live-tail",
        100,
        &receipt_test_keypair(),
    );
    store.append_child_receipt(&child)?;
    let loaded = store
        .load_retained_child_receipt(&child.id)?
        .ok_or("retained lookup missed the committed live child")?;
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(&loaded)?,
        chio_core::canonical::canonical_json_bytes(&child)?
    );
    Ok(())
}

#[test]
fn retained_child_lookup_reads_archived_and_live_children() -> TestResult {
    let fixture = RetainedChildren::new()?;
    assert!(
        fixture
            .store
            .load_child_receipt(&fixture.children[0].id)?
            .is_none(),
        "the existing live-only reader does not resolve archived children"
    );
    for expected in &fixture.children {
        let actual = fixture
            .store
            .load_retained_child_receipt(&expected.id)?
            .ok_or("retained lookup missed a committed child")?;
        assert_eq!(actual.id, expected.id);
        assert_eq!(
            chio_core::canonical::canonical_json_bytes(&actual)?,
            chio_core::canonical::canonical_json_bytes(expected)?
        );
    }
    assert!(fixture
        .store
        .load_retained_child_receipt("retained-child-absent")?
        .is_none());
    Ok(())
}

#[test]
fn retained_child_lookup_rejects_a_valid_signed_archive_replacement() -> TestResult {
    let fixture = RetainedChildren::new()?;
    let original = &fixture.children[0];
    let replacement =
        sample_child_receipt_with_keypair_and_timestamp(&original.id, 101, &receipt_test_keypair());
    let archive = rusqlite::Connection::open(&fixture.archive)?;
    archive.execute_batch("DROP TRIGGER IF EXISTS chio_child_receipts_reject_update;")?;
    assert_eq!(
        archive.execute(
            "UPDATE chio_child_receipts SET raw_json = ?1 WHERE receipt_id = ?2",
            rusqlite::params![serde_json::to_string(&replacement)?, original.id],
        )?,
        1
    );
    assert!(matches!(
        fixture.store.load_retained_child_receipt(&original.id),
        Err(ReceiptStoreError::ReadBoundary(_) | ReceiptStoreError::Conflict(_))
    ));
    Ok(())
}

#[test]
fn retained_child_lookup_rejects_a_rebound_archive_id() -> TestResult {
    let fixture = RetainedChildren::new()?;
    let archive = rusqlite::Connection::open(&fixture.archive)?;
    archive.execute_batch("DROP TRIGGER IF EXISTS chio_child_receipts_reject_update;")?;
    assert_eq!(
        archive.execute(
            "UPDATE chio_child_receipts SET receipt_id = ?1 WHERE receipt_id = ?2",
            rusqlite::params!["retained-child-rebound", fixture.children[0].id],
        )?,
        1
    );
    assert!(matches!(
        fixture
            .store
            .load_retained_child_receipt("retained-child-rebound"),
        Err(ReceiptStoreError::ReadBoundary(_) | ReceiptStoreError::Conflict(_))
    ));
    Ok(())
}

#[test]
fn retained_child_lookup_rejects_a_rebound_live_id() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteReceiptStore::open(directory.path().join("live.sqlite3"))?;
    let child = sample_child_receipt_with_keypair_and_timestamp(
        "retained-child-live-identity",
        100,
        &receipt_test_keypair(),
    );
    store.append_child_receipt(&child)?;
    let original_id = child.id;
    store.writer_handle().run_write(move |connection| {
        connection.execute_batch("DROP TRIGGER IF EXISTS chio_child_receipts_reject_update;")?;
        assert_eq!(
            connection.execute(
                "UPDATE chio_child_receipts SET receipt_id = ?1 WHERE receipt_id = ?2",
                rusqlite::params!["retained-child-live-rebound", original_id],
            )?,
            1
        );
        Ok(())
    })?;
    assert!(matches!(
        store.load_retained_child_receipt("retained-child-live-rebound"),
        Err(ReceiptStoreError::ReadBoundary(_) | ReceiptStoreError::Conflict(_))
    ));
    Ok(())
}
