use std::sync::{mpsc, Arc};
use std::time::Duration;

use chio_kernel::ReceiptWriterLiveness;

use crate::SqliteReceiptStore;

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
