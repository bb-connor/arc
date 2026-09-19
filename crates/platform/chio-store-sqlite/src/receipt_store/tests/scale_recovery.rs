//! Deliberate receipt-history qualification, separate from append timing.

use super::super::*;
use super::support::*;
use sha2::{Digest, Sha256};
use std::time::Instant;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn receipt_at(sequence: u64, history: u64, keypair: &Keypair) -> ChioReceipt {
    sample_receipt_with_keypair(
        &format!("history-recovery-{sequence}"),
        if sequence <= history / 2 { 100 } else { 500 },
        keypair,
    )
}

fn assert_sqlite_integrity(path: &Path) -> TestResult {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let rows = connection
        .prepare("PRAGMA integrity_check")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows, ["ok"]);
    assert!(connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_none());
    Ok(())
}

fn assert_sampled_receipts(
    store: &SqliteReceiptStore,
    history: u64,
    keypair: &Keypair,
) -> TestResult {
    for sequence in [1, history / 2, history / 2 + 1, history] {
        let expected = receipt_at(sequence, history, keypair);
        let actual = store
            .load_retained_chio_receipt(&expected.id)?
            .ok_or("retained receipt missing")?;
        assert_eq!(
            canonical_json_bytes(&actual)?,
            canonical_json_bytes(&expected)?
        );
        let commitment = store
            .load_retained_chio_receipt_commitment(&expected.id)?
            .ok_or("retained commitment missing")?;
        assert_eq!(commitment.entry_seq, sequence);
        assert_eq!(commitment.receipt_id, expected.id);
        assert_eq!(commitment.kernel_key, keypair.public_key());
        assert_eq!(
            commitment.receipt_sha256,
            hex::encode(Sha256::digest(canonical_json_bytes(&expected)?))
        );
    }
    Ok(())
}

fn run_history_recovery(history: u64) -> TestResult {
    assert!(history >= 1_000 && history.is_multiple_of(200));
    let (directory, path) = temp_db("chio-history-recovery-")?;
    // The archive identity is persisted as a canonical path.
    let archive = fs::canonicalize(directory.path())?.join("archive.sqlite3");
    let backup = directory.path().join("backup.sqlite3");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 100))?;
    let started = Instant::now();
    for sequence in 1..=history {
        assert_eq!(
            store.append_chio_receipt_returning_seq(&receipt_at(sequence, history, &keypair))?,
            sequence
        );
    }
    store.flush_receipt_writes()?;
    println!(
        "history={history} stage=seed elapsed_ms={} db_bytes={}",
        started.elapsed().as_millis(),
        store.db_size_bytes()?
    );

    let started = Instant::now();
    let status = store.receipt_checkpoint_status(None)?;
    assert!(status.healthy, "{status:?}");
    assert_eq!(status.latest_committed_entry_seq, history);
    assert_eq!(status.latest_checkpointed_entry_seq, history);
    assert_eq!(status.latest_checkpoint_seq, Some(history / 100));
    let original_head = store
        .load_checkpoint_by_seq(history / 100)?
        .ok_or("checkpoint missing")?;
    assert_sqlite_integrity(&path)?;
    assert_sampled_receipts(&store, history, &keypair)?;
    println!(
        "history={history} stage=full_integrity elapsed_ms={}",
        started.elapsed().as_millis()
    );

    let started = Instant::now();
    let query = ReceiptQuery {
        since: Some(500),
        until: Some(500),
        cursor: Some(history - 100),
        limit: 50,
        read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
        ..ReceiptQuery::default()
    };
    let first = store.query_receipts(&query)?;
    assert_eq!(first.total_count, history / 2);
    assert_eq!(first.receipts.len(), 50);
    assert_eq!(first.next_cursor, Some(history - 50));
    let second = store.query_receipts(&ReceiptQuery {
        cursor: first.next_cursor,
        ..query.clone()
    })?;
    assert_eq!(second.total_count, history / 2);
    assert_eq!(second.receipts.len(), 50);
    assert_eq!(second.next_cursor, Some(history));
    let exhausted = store.query_receipts(&ReceiptQuery {
        cursor: second.next_cursor,
        ..query
    })?;
    assert_eq!(exhausted.total_count, history / 2);
    assert!(exhausted.receipts.is_empty());
    assert_eq!(exhausted.next_cursor, None);
    for (offset, row) in first.receipts.iter().chain(&second.receipts).enumerate() {
        let sequence = history - 99 + offset as u64;
        assert_eq!(row.seq, sequence);
        assert_eq!(row.receipt.id, receipt_at(sequence, history, &keypair).id);
    }
    println!(
        "history={history} stage=filtered_pages_and_exhaustion elapsed_ms={}",
        started.elapsed().as_millis()
    );

    let started = Instant::now();
    // SQLite creates a consistent complete snapshot, including committed WAL
    // contents. A raw copy of only the main database would be insufficient.
    let snapshot = Connection::open(&path)?;
    snapshot.execute(
        "VACUUM INTO ?1",
        [backup.to_str().ok_or("backup path encoding")?],
    )?;
    drop(snapshot);
    assert_sqlite_integrity(&backup)?;
    println!(
        "history={history} stage=backup elapsed_ms={} backup_bytes={}",
        started.elapsed().as_millis(),
        fs::metadata(&backup)?.len()
    );
    drop(store);

    let started = Instant::now();
    let store = SqliteReceiptStore::open_existing(&path)?;
    store.flush_receipt_writes()?;
    assert!(!store.writer_serving_closed());
    assert_eq!(store.latest_committed_entry_seq()?, history);
    assert_eq!(
        canonical_json_bytes(&store.load_checkpoint_by_seq(history / 100)?)?,
        canonical_json_bytes(&Some(&original_head))?
    );
    println!(
        "history={history} stage=reopen_ready elapsed_ms={}",
        started.elapsed().as_millis()
    );

    let started = Instant::now();
    assert_eq!(
        store.archive_receipts_before(150, archive.to_str().ok_or("archive path encoding")?)?,
        history / 2
    );
    let status = store.receipt_checkpoint_status(None)?;
    assert!(status.healthy, "{status:?}");
    assert_eq!(status.retention_watermark_entry_seq, Some(history / 2));
    assert_eq!(status.latest_checkpointed_entry_seq, history);
    assert_eq!(
        store
            .query_receipts(&ReceiptQuery {
                limit: 1,
                read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
                ..ReceiptQuery::default()
            })?
            .total_count,
        history / 2
    );
    assert!(store
        .load_chio_receipt(&receipt_at(1, history, &keypair).id)?
        .is_none());
    assert_sampled_receipts(&store, history, &keypair)?;
    assert_sqlite_integrity(&path)?;
    assert_sqlite_integrity(&archive)?;
    println!(
        "history={history} stage=archive_half elapsed_ms={} live_db_bytes={} archive_bytes={}",
        started.elapsed().as_millis(),
        store.db_size_bytes()?,
        fs::metadata(&archive)?.len()
    );
    drop(store);

    let started = Instant::now();
    let store = SqliteReceiptStore::open_existing(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 100))?;
    assert_sampled_receipts(&store, history, &keypair)?;
    assert_eq!(
        store.append_chio_receipt_returning_seq(&receipt_at(history + 1, history, &keypair))?,
        history + 1
    );
    store.flush_receipt_writes()?;
    assert!(!store.writer_serving_closed());
    println!(
        "history={history} stage=reopen_retained_append elapsed_ms={}",
        started.elapsed().as_millis()
    );
    drop(store);

    let started = Instant::now();
    let restored = SqliteReceiptStore::open_existing(&backup)?;
    restored.flush_receipt_writes()?;
    assert!(!restored.writer_serving_closed());
    assert_eq!(restored.latest_committed_entry_seq()?, history);
    assert_eq!(
        canonical_json_bytes(&restored.load_checkpoint_by_seq(history / 100)?)?,
        canonical_json_bytes(&Some(&original_head))?
    );
    assert_sampled_receipts(&restored, history, &keypair)?;
    assert!(restored
        .load_chio_receipt(&receipt_at(history + 1, history, &keypair).id)?
        .is_none());
    assert_eq!(
        restored.append_chio_receipt_returning_seq(&receipt_at(history + 1, history, &keypair))?,
        history + 1
    );
    restored.flush_receipt_writes()?;
    println!(
        "history={history} stage=restore_ready_append elapsed_ms={}",
        started.elapsed().as_millis()
    );
    drop(restored);
    Ok(())
}

#[test]
fn receipt_history_recovery_campaign_calibration() -> TestResult {
    run_history_recovery(1_000)
}

#[test]
#[ignore = "milestone campaign; one million real appends, integrity, retention and restore"]
fn million_receipts_preserve_integrity_queries_retention_and_restore() -> TestResult {
    run_history_recovery(1_000_000)
}
