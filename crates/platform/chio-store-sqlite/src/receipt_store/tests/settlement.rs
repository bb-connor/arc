use super::super::*;
use super::support::*;

fn attempt_count(store: &SqliteReceiptStore, receipt_id: &str) -> Result<u64, ReceiptStoreError> {
    let connection = store.connection()?;
    let count = connection.query_row(
        "SELECT COUNT(*) FROM settle_attempts WHERE receipt_id = ?1",
        [receipt_id],
        |row| row.get::<_, i64>(0),
    )?;
    sqlite_u64(count, "settlement attempt count")
}

#[test]
fn settlement_projection_binding_is_scoped_to_one_writer() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-settlement-binding");
    let store = SqliteReceiptStore::open(&path)?;

    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&store),
        chio_kernel::AtomicReceiptProjection::SettlementObservationV1
    );
    let binding = ReceiptStore::settlement_store_binding(&store)
        .ok_or("migrated receipt store did not expose settlement binding")?;
    assert_eq!(
        store
            .writer_handle()
            .settlement_store_binding()
            .ok_or("writer handle did not copy settlement binding")?,
        binding
    );
    assert_eq!(
        store
            .writer_handle()
            .settlement_store_binding()
            .ok_or("second writer handle did not copy settlement binding")?,
        binding
    );

    let separate = SqliteReceiptStore::open(&path)?;
    assert_ne!(
        ReceiptStore::settlement_store_binding(&separate),
        Some(binding)
    );
    drop(separate);
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&reopened),
        chio_kernel::AtomicReceiptProjection::SettlementObservationV1
    );
    assert!(ReceiptStore::settlement_store_binding(&reopened).is_some());

    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn open_existing_does_not_install_missing_settlement_schema(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-settlement-open-existing");
    let store = SqliteReceiptStore::open(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch("DROP TABLE settle_attempts")?;
        Ok(())
    })?;
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&reopened),
        chio_kernel::AtomicReceiptProjection::Unsupported
    );
    assert_eq!(ReceiptStore::settlement_store_binding(&reopened), None);
    let unsupported_receipt = sample_receipt_with_id("rcpt-settlement-unsupported");
    let unsupported = ReceiptStore::append_chio_receipt_with_pending_observation(
        &reopened,
        &unsupported_receipt,
        &chio_kernel::PendingSettlementObservation {
            next_visible_at_ms: 1,
        },
    );
    assert!(matches!(
        unsupported,
        Err(ReceiptStoreError::Unsupported(_))
    ));
    assert!(reopened
        .load_chio_receipt(&unsupported_receipt.id)?
        .is_none());
    let connection = reopened.connection()?;
    let attempts_table: Option<String> = connection
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'settle_attempts'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    assert_eq!(attempts_table, None);

    drop(connection);
    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn open_existing_does_not_reinstall_missing_settlement_guard(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-settlement-open-existing-guard");
    let store = SqliteReceiptStore::open(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch("DROP TRIGGER trg_settle_attempts_reject_terminal_insert")?;
        Ok(())
    })?;
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&reopened),
        chio_kernel::AtomicReceiptProjection::Unsupported
    );
    assert_eq!(ReceiptStore::settlement_store_binding(&reopened), None);
    let connection = reopened.connection()?;
    let guard: Option<String> = connection
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name = 'trg_settle_attempts_reject_terminal_insert'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    assert_eq!(guard, None);

    drop(connection);
    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn open_existing_rejects_same_named_noop_settlement_guard() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-settlement-open-existing-noop-guard");
    let store = SqliteReceiptStore::open(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER trg_settle_attempts_reject_terminal_insert; \
             CREATE TRIGGER trg_settle_attempts_reject_terminal_insert \
             BEFORE INSERT ON settle_attempts BEGIN SELECT 1; END;",
        )?;
        Ok(())
    })?;
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&reopened),
        chio_kernel::AtomicReceiptProjection::Unsupported
    );
    assert_eq!(ReceiptStore::settlement_store_binding(&reopened), None);

    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn open_existing_rejects_unconstrained_settlement_table() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-settlement-open-existing-drifted-table");
    let store = SqliteReceiptStore::open(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TABLE settle_attempts; \
             CREATE TABLE settle_attempts (\
                 receipt_id TEXT, finalized_at INTEGER, work_kind TEXT, attempts INTEGER, \
                 next_visible_at_ms INTEGER, row_version INTEGER, lease_owner TEXT, \
                 lease_token TEXT, lease_until_ms INTEGER, reason_code TEXT, \
                 reason_detail_sha256 BLOB, updated_at_ms INTEGER\
             );",
        )?;
        connection.execute_batch(crate::settle_attempts::SETTLE_ATTEMPTS_MIGRATION)?;
        Ok(())
    })?;
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&reopened),
        chio_kernel::AtomicReceiptProjection::Unsupported
    );
    assert_eq!(ReceiptStore::settlement_store_binding(&reopened), None);

    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn open_existing_rejects_extra_settlement_trigger() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-settlement-open-existing-extra-trigger");
    let store = SqliteReceiptStore::open(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "CREATE TRIGGER delete_seeded_settlement_attempt \
             AFTER INSERT ON settle_attempts BEGIN \
                 DELETE FROM settle_attempts WHERE receipt_id = NEW.receipt_id; \
             END;",
        )?;
        Ok(())
    })?;
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&reopened),
        chio_kernel::AtomicReceiptProjection::Unsupported
    );
    assert_eq!(ReceiptStore::settlement_store_binding(&reopened), None);

    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn atomic_receipt_append_seeds_attempt_zero_once() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-settlement-atomic-append");
    let store = SqliteReceiptStore::open(&path)?;
    let receipt = sample_receipt_with_id("rcpt-settlement-atomic");
    let pending = chio_kernel::PendingSettlementObservation {
        next_visible_at_ms: 9_001,
    };

    ReceiptStore::append_chio_receipt_with_pending_observation(&store, &receipt, &pending)?;
    let connection = store.connection()?;
    let row = connection.query_row(
        "SELECT finalized_at, work_kind, attempts, next_visible_at_ms, row_version, lease_owner, lease_token, lease_until_ms, reason_code, reason_detail_sha256 FROM settle_attempts WHERE receipt_id = ?1",
        [receipt.id.as_str()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<Vec<u8>>>(9)?,
            ))
        },
    )?;
    assert_eq!(row.0, i64::try_from(receipt.timestamp)?);
    assert_eq!(row.1, "pending_observation");
    assert_eq!(row.2, 0);
    assert_eq!(row.3, 9_001);
    assert_eq!(row.4, 0);
    assert_eq!(
        (row.5, row.6, row.7, row.8, row.9),
        (None, None, None, None, None)
    );
    drop(connection);

    store.writer_handle().run_write({
        let receipt_id = receipt.id.clone();
        move |connection| {
            connection.execute(
                "DELETE FROM settle_attempts WHERE receipt_id = ?1",
                [receipt_id],
            )?;
            Ok(())
        }
    })?;
    ReceiptStore::append_chio_receipt_with_pending_observation(&store, &receipt, &pending)?;
    assert_eq!(attempt_count(&store, &receipt.id)?, 0);

    let conflicting = sample_receipt_with_id("rcpt-settlement-attempt-conflict");
    store.writer_handle().run_write({
        let receipt_id = conflicting.id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO settle_attempts (receipt_id, finalized_at, work_kind, attempts, next_visible_at_ms, row_version, updated_at_ms) VALUES (?1, 1, 'pending_observation', 0, 1, 0, 1)",
                [receipt_id],
            )?;
            Ok(())
        }
    })?;
    let conflict =
        ReceiptStore::append_chio_receipt_with_pending_observation(&store, &conflicting, &pending);
    assert!(conflict.is_err());
    assert!(store.load_chio_receipt(&conflicting.id)?.is_none());
    assert_eq!(attempt_count(&store, &conflicting.id)?, 1);

    let overflow = sample_receipt_with_id("rcpt-settlement-visible-overflow");
    let overflow_result = ReceiptStore::append_chio_receipt_with_pending_observation(
        &store,
        &overflow,
        &chio_kernel::PendingSettlementObservation {
            next_visible_at_ms: u64::MAX,
        },
    );
    assert!(overflow_result.is_err());
    assert!(store.load_chio_receipt(&overflow.id)?.is_none());

    drop(store);
    let _ = fs::remove_file(path);
    Ok(())
}
