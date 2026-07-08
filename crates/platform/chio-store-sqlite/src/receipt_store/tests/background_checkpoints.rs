use super::super::*;
use super::support::*;

fn signer(keypair: &Keypair, max_batch: u64) -> BackgroundCheckpointSigner {
    BackgroundCheckpointSigner {
        keypair: Arc::new(keypair.clone()),
        max_batch,
    }
}

#[test]
fn maybe_build_checkpoint_builds_one_checkpoint_per_crossed_threshold(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-threshold");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 3))?;

    // 7 appends with max_batch 3: exactly two checkpoints (1..=3, 4..=6);
    // entry 7 stays uncheckpointed (partial final batch, ADR-0008).
    for i in 0..7 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-bg-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    // Flush is the synchronization barrier: the actor builds checkpoints
    // inside the same command iteration as the batch commit, and a Flush
    // enqueued afterwards is only served once that iteration finishes.
    store.flush_receipt_writes()?;

    let first = store
        .load_checkpoint_by_seq(1)?
        .ok_or("checkpoint 1 missing")?;
    let second = store
        .load_checkpoint_by_seq(2)?
        .ok_or("checkpoint 2 missing")?;
    assert!(
        store.load_checkpoint_by_seq(3)?.is_none(),
        "no third checkpoint yet"
    );
    assert_eq!(
        (first.body.batch_start_seq, first.body.batch_end_seq),
        (1, 3)
    );
    assert_eq!(
        (second.body.batch_start_seq, second.body.batch_end_seq),
        (4, 6)
    );
    // previous_checkpoint_sha256 links to the head's cached predecessor.
    let expected_digest = chio_kernel::checkpoint::checkpoint_body_sha256(&first.body)?;
    assert_eq!(
        second.body.previous_checkpoint_sha256.as_deref(),
        Some(expected_digest.as_str())
    );
    assert!(first.body.previous_checkpoint_sha256.is_none());

    // The full audit surface agrees (chain + projections all valid).
    let status = store.receipt_checkpoint_status(Some(3))?;
    assert!(
        status.healthy,
        "audit after background checkpoints: {status:?}"
    );
    assert_eq!(status.latest_checkpoint_seq, Some(2));
    assert_eq!(status.latest_checkpointed_entry_seq, 6);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn zero_max_batch_disables_background_checkpointing() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-disabled");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 0))?;
    for i in 0..5 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-bg-off-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_none(),
        "batch_size 0 disables checkpoints"
    );
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn one_big_batch_crossing_two_thresholds_builds_both_checkpoints(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-multicross");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 2))?;
    // 4 appends may commit as ONE group-commit batch; the while-loop in
    // maybe_build_checkpoint must still emit checkpoints 1..=2 and 3..=4.
    for i in 0..4 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-bg-multi-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(1)?.is_some());
    assert!(store.load_checkpoint_by_seq(2)?.is_some());
    assert!(store.load_checkpoint_by_seq(3)?.is_none());
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn background_and_writer_routed_child_appends_share_the_threshold(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-child");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 2))?;
    let receipt = sample_receipt_with_keypair("rcpt-bg-child-0", 1, &keypair);
    store.append_chio_receipt_returning_seq(&receipt)?;
    let child = sample_child_receipt_with_keypair_and_timestamp("child-bg-1", 2, &keypair);
    store.append_child_receipt_record(&child)?; // writer-routed, claim-log row 2
    store.flush_receipt_writes()?;
    let checkpoint = store
        .load_checkpoint_by_seq(1)?
        .ok_or("child append must count toward the threshold")?;
    assert_eq!(
        (
            checkpoint.body.batch_start_seq,
            checkpoint.body.batch_end_seq
        ),
        (1, 2)
    );
    let _ = fs::remove_file(path);
    Ok(())
}
