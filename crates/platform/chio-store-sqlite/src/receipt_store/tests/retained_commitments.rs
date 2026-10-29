//! Authenticated retained-receipt lookup coverage.

use chio_kernel::{ReceiptStore, ReceiptStoreError};

use crate::SqliteReceiptStore;

use chio_test_support::temp_sqlite_path;

#[test]
fn retained_receipt_lookup_reads_only_from_a_trusted_archive(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_path_dir, path) = temp_sqlite_path("retained-receipt-live");
    let (_archive_dir, archive) = temp_sqlite_path("retained-receipt-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    let mut archived_id = String::new();
    for i in 0..4u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("retained-{i}"),
            i + 1,
            if i < 2 { 100 } else { 200 },
            &keypair,
        );
        if i == 0 {
            archived_id.clone_from(&receipt.id);
        }
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert_eq!(store.archive_receipts_before(150, archive_path)?, 2);

    let retained = store
        .load_retained_chio_receipt(&archived_id)?
        .ok_or("trusted archive lookup missed the archived receipt")?;
    assert_eq!(retained.id, archived_id);
    let commitment = store
        .load_retained_chio_receipt_commitment(&archived_id)?
        .ok_or("trusted archive lookup missed the archived receipt commitment")?;
    let canonical = chio_core::canonical::canonical_json_bytes(&retained)?;
    assert_eq!(commitment.receipt_id, archived_id);
    assert_eq!(
        commitment.receipt_sha256,
        chio_core::crypto::sha256_hex(&canonical)
    );
    assert_eq!(commitment.kernel_key, retained.kernel_key);

    drop(store);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn retained_receipt_commitment_rejects_an_uncheckpointed_live_tail(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_path_dir, path) = temp_sqlite_path("retained-receipt-uncheckpointed-tail");
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;

    let mut checkpointed_id = String::new();
    let mut tail_id = String::new();
    for i in 0..3u64 {
        let receipt = super::support::sample_receipt_with_keypair(
            &format!("retained-tail-{i}"),
            i + 1,
            &keypair,
        );
        if i == 0 {
            checkpointed_id.clone_from(&receipt.id);
        } else if i == 2 {
            tail_id.clone_from(&receipt.id);
        }
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(1)?.is_some());
    assert!(
        store
            .load_retained_chio_receipt_commitment(&checkpointed_id)?
            .is_some(),
        "a checkpointed live commitment must remain available"
    );

    let error = store
        .load_retained_chio_receipt_commitment(&tail_id)
        .err()
        .ok_or("uncheckpointed live-tail commitment was accepted")?;
    assert!(matches!(&error, ReceiptStoreError::ReadBoundary(_)));
    assert!(error.to_string().contains("authenticated checkpoint"));

    drop(store);
    let _ = std::fs::remove_file(&path);
    Ok(())
}
