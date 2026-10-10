use super::support::*;
use crate::clock_consumer_tests::TestClock;
use chio_security_types::clock::{ClockError, FixedClock};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn sqlite_injected_receipt_clock_reaches_writer_and_checkpoint_builders() -> TestResult {
    let (_temp, path) = temp_db("injected-receipt-clock")?;
    let clock = TestClock::new();
    let store = SqliteReceiptStore::open_with_clock(&path, clock.clone())?;
    let keypair = receipt_test_keypair();
    let first = sample_receipt_with_keypair("injected-first", 1, &keypair);
    store.append_chio_receipt_returning_seq(&first)?;
    store.create_next_receipt_checkpoint(1, &keypair)?;
    assert_eq!(
        store
            .load_checkpoint_by_seq(1)?
            .ok_or("missing foreground checkpoint")?
            .body
            .issued_at,
        42
    );
    store.enable_background_checkpoints(signer(&keypair, 1))?;
    store.append_chio_receipt_returning_seq(&sample_receipt_with_keypair(
        "injected-second",
        2,
        &keypair,
    ))?;
    store.flush_receipt_writes()?;
    assert_eq!(
        store
            .load_checkpoint_by_seq(2)?
            .ok_or("missing background checkpoint")?
            .body
            .issued_at,
        42
    );
    assert_eq!(
        store
            .receipt_commit_actor
            .health
            .first_accept_unix_ms
            .load(std::sync::atomic::Ordering::SeqCst),
        42_000
    );
    assert_eq!(
        store
            .receipt_commit_actor
            .health
            .last_commit_unix_ms
            .load(std::sync::atomic::Ordering::SeqCst),
        42_000
    );
    Ok(())
}

#[test]
fn sqlite_injected_receipt_clock_fault_preserves_evidence_and_reconciliation() -> TestResult {
    for fault in [
        Err(ClockError::Unavailable),
        Err(ClockError::Overflow),
        Ok(TestClock::reading(41_999, 100)),
        Ok(TestClock::reading(42_000, 99)),
    ] {
        let (_temp, path) = temp_db("injected-receipt-fault")?;
        let clock = TestClock::new();
        let store = SqliteReceiptStore::open_with_clock(&path, clock.clone())?;
        let keypair = receipt_test_keypair();
        let receipt = sample_receipt_with_keypair("injected-retained", 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
        assert_eq!(
            store.upsert_settlement_reconciliation(
                &receipt.id,
                SettlementReconciliationState::Reconciled,
                None
            )?,
            42
        );
        store.flush_receipt_writes()?;
        let connection = rusqlite::Connection::open(&path)?;
        let before = crate::tests::authority_snapshot(&connection)?;
        clock.set(fault)?;
        assert!(store.append_chio_receipt_returning_seq(&receipt).is_err());
        assert!(store
            .upsert_settlement_reconciliation(
                &receipt.id,
                SettlementReconciliationState::Open,
                None
            )
            .is_err());
        assert!(store.retention_repair("unused-clock-archive").is_err());
        assert_eq!(crate::tests::authority_snapshot(&connection)?, before);
    }
    Ok(())
}

#[test]
fn sqlite_injected_retention_clock_stamps_tombstones() -> TestResult {
    let (temp, path) = temp_db("injected-retention-clock")?;
    let store = SqliteReceiptStore::open_with_clock(&path, Arc::new(FixedClock::new(300_000)))?;
    let keypair = receipt_test_keypair();
    store.append_chio_receipt_returning_seq(&sample_receipt_with_keypair(
        "retention-clock",
        1,
        &keypair,
    ))?;
    store.create_next_receipt_checkpoint(1, &keypair)?;
    let archive = temp.path().join("archive.sqlite3");
    assert_eq!(
        store.archive_receipts_before(150, archive.to_str().ok_or("archive path UTF-8")?)?,
        1
    );
    let tombstoned_at: i64 = store.connection()?.query_row(
        "SELECT tombstoned_at FROM receipt_retention_tombstones",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(tombstoned_at, 300_000);
    Ok(())
}
