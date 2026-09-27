use std::sync::{mpsc, Arc};
use std::time::Duration;

use chio_kernel::ReceiptWriterLiveness;

use crate::SqliteReceiptStore;

#[test]
fn retention_repair_revalidates_integrity_before_reopening_either_mode(
) -> Result<(), Box<dyn std::error::Error>> {
    for incremental_verification in [false, true] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("live.db");
        let keypair = super::support::receipt_test_keypair();
        {
            let store = SqliteReceiptStore::open(&path)?;
            let receipt = super::support::sample_receipt_with_keypair("repair-health", 1, &keypair);
            store.append_chio_receipt_returning_seq(&receipt)?;
            store.flush_receipt_writes()?;
            store.create_next_receipt_checkpoint(1, &keypair)?;
        }
        let store = SqliteReceiptStore::open_existing_with_options(
            &path,
            crate::SqliteStoreOptions {
                pool: crate::SqlitePoolConfig::default(),
                incremental_verification,
            },
        )?;
        store.flush_receipt_writes()?;
        let connection = rusqlite::Connection::open(&path)?;
        let original: String = connection.query_row(
            "SELECT signature FROM kernel_checkpoints WHERE checkpoint_seq = 1",
            [],
            |row| row.get(0),
        )?;
        connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update")?;
        connection.execute("UPDATE kernel_checkpoints SET signature = 'corrupt'", [])?;
        // No orphaned rows need removing. Recovery must nevertheless verify
        // the whole checkpoint chain before publishing a serving head.
        assert_eq!(store.retention_repair("unused-archive.sqlite3")?, 0);
        assert!(store.receipt_commit_actor.writer_serving_closed());
        connection.execute("UPDATE kernel_checkpoints SET signature = ?1", [original])?;
        assert_eq!(store.retention_repair("unused-archive.sqlite3")?, 0);
        assert!(!store.receipt_commit_actor.writer_serving_closed());
        let receipt = super::support::sample_receipt_with_keypair("after-repair", 2, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
        store.flush_receipt_writes()?;
        assert!(store.receipt_store_health()?.healthy);
    }
    Ok(())
}

#[test]
fn rotation_waiting_for_storage_remains_inflight_until_its_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let live = directory.path().join("live.db");
    let store = Arc::new(SqliteReceiptStore::open(&live)?);
    let keypair = super::support::receipt_test_keypair();
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for seq in 1..=2 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("rotation-liveness-{seq}"),
            seq,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // A second SQLite writer retains the live write lock. The rotation can
    // verify the committed prefix but cannot archive and delete it yet.
    let blocking_writer = rusqlite::Connection::open(&live)?;
    blocking_writer.execute_batch("BEGIN IMMEDIATE")?;
    let archive = directory.path().join("archive.db");
    let archive = archive
        .to_str()
        .ok_or("archive path is not UTF-8")?
        .to_owned();
    let rotating = Arc::clone(&store);
    let (completed, result) = mpsc::sync_channel(1);
    let rotation = std::thread::spawn(move || {
        let _ = completed.send(rotating.archive_receipts_before(3_000, &archive));
    });
    let waiting = result.recv_timeout(Duration::from_millis(100));
    let inflight = store.receipt_commit_actor.writer_counters().inflight;
    let liveness = store.writer_liveness(Duration::ZERO);
    // Release the fault and join before asserting, including on a regression.
    blocking_writer.execute_batch("ROLLBACK")?;
    let outcome = match waiting {
        Ok(outcome) => Some(outcome),
        Err(mpsc::RecvTimeoutError::Timeout) => result.recv_timeout(Duration::from_secs(5)).ok(),
        Err(mpsc::RecvTimeoutError::Disconnected) => None,
    };
    rotation.join().map_err(|_| "rotation thread panicked")?;
    assert_eq!(inflight, 1, "a storage wait disappeared from writer health");
    assert_eq!(liveness, ReceiptWriterLiveness::Wedged);
    assert_eq!(outcome.ok_or("rotation did not respond")??, 2);
    let drained = store.receipt_commit_actor.writer_counters();
    assert_eq!(drained.inflight, 0);
    assert_eq!(drained.queue_depth, 0);
    assert_eq!(
        store.writer_liveness(Duration::ZERO),
        ReceiptWriterLiveness::Healthy
    );
    Ok(())
}

#[test]
fn timed_out_rotation_keeps_ownership_and_commits_once_after_release(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::{ReceiptStoreError, RetentionConfig};

    let directory = tempfile::tempdir()?;
    let store = SqliteReceiptStore::open(directory.path().join("live.db"))?;
    let keypair = super::support::receipt_test_keypair();
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for seq in 1..=2 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("rotation-timeout-{seq}"),
            seq,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let writer = store.writer_handle();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let blocker = std::thread::spawn(move || {
        writer.run_write(move |_| {
            let _ = entered_tx.send(());
            release_rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(|error| {
                    ReceiptStoreError::ReadBoundary(format!("test writer release failed: {error}"))
                })?;
            Ok(())
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(5))?;
    let mut config = RetentionConfig {
        archive_path: directory
            .path()
            .join("archive.db")
            .to_str()
            .ok_or("invalid archive path")?
            .to_owned(),
        explicit_cutoff_unix_secs: Some(3_000),
        rotation_timeout: Duration::from_millis(20),
        ..RetentionConfig::default()
    };
    let result = store.rotate_if_needed(&config);
    let waiting = store.receipt_commit_actor.writer_counters();
    let liveness = store.writer_liveness(Duration::from_secs(60));
    // Always release the actor before checking the result, including on failure.
    release_tx.send(())?;
    blocker.join().map_err(|_| "blocking writer panicked")??;
    store.flush_receipt_writes()?;

    assert!(
        matches!(result, Err(ReceiptStoreError::Timeout { operation, timeout_ms: 20 })
        if operation == "receipt retention rotation")
    );
    assert_eq!(waiting.inflight, 2);
    assert_eq!(waiting.queue_depth, 1);
    assert_eq!(waiting.timed_out_inflight, 1);
    assert_eq!(liveness, ReceiptWriterLiveness::Wedged);
    let drained = store.receipt_commit_actor.writer_counters();
    assert_eq!(drained.inflight, 0);
    assert_eq!(drained.queue_depth, 0);
    assert_eq!(drained.timed_out_inflight, 0);
    assert_eq!(
        store.writer_liveness(Duration::ZERO),
        ReceiptWriterLiveness::Healthy
    );
    assert_eq!(store.tool_receipt_count()?, 0);
    let archive = rusqlite::Connection::open(&config.archive_path)?;
    let archived: i64 =
        archive.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
            row.get(0)
        })?;
    assert_eq!(archived, 2);
    config.rotation_timeout = Duration::from_secs(5);
    assert_eq!(store.rotate_if_needed(&config)?, 0);
    assert!(store.receipt_store_health()?.healthy);
    Ok(())
}

#[test]
fn invalid_rotation_deadline_rejects_before_admission() -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::{ReceiptStoreError, RetentionConfig};

    let directory = tempfile::tempdir()?;
    let store = SqliteReceiptStore::open(directory.path().join("live.db"))?;
    store.flush_receipt_writes()?;
    let baseline = store.receipt_commit_actor.writer_counters();
    let archive = directory.path().join("archive.db");
    for timeout in [Duration::ZERO, Duration::MAX] {
        let config = RetentionConfig {
            rotation_timeout: timeout,
            archive_path: archive.to_str().ok_or("invalid archive path")?.to_owned(),
            ..RetentionConfig::default()
        };
        assert!(
            matches!(store.rotate_if_needed(&config), Err(ReceiptStoreError::ReadBoundary(message))
            if message == "retention rotation timeout must be positive and representable")
        );
    }
    assert!(!archive.exists());
    let after = store.receipt_commit_actor.writer_counters();
    assert_eq!(after.accepted_total, baseline.accepted_total);
    assert_eq!(after.inflight, 0);
    assert_eq!(after.timed_out_total, baseline.timed_out_total);
    Ok(())
}
