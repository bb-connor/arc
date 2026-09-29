use super::super::*;
use super::support::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn overflowing_terminal_totals_cannot_report_a_healthy_writer() {
    let counters = ReceiptWriterCounters {
        accepted_total: u64::MAX,
        committed_total: u64::MAX,
        failed_total: 1,
        ..Default::default()
    };
    assert_eq!(
        classify_writer_liveness(&counters, 1_000, 128, None, 0),
        chio_kernel::ReceiptWriterLiveness::Dead
    );
}

fn append_command(id: &str) -> Result<ReceiptCommitCommand, ReceiptStoreError> {
    let receipt = sample_receipt_with_id(id);
    let raw_json = serde_json::to_string(&receipt)?;
    let (response, _receiver) = mpsc::sync_channel(1);
    Ok(ReceiptCommitCommand::Append(Box::new(
        ReceiptCommitRequest {
            receipt,
            raw_json,
            ensure_lineage: false,
            response,
        },
    )))
}

#[test]
fn dropping_queued_commands_releases_all_owned_counters_once() -> TestResult {
    let (sender, receiver) = receipt_commit_channel();
    let health = &sender.health;
    for index in 0..3 {
        sender.try_send(append_command(&format!("queued-{index}"))?)?;
    }
    assert_eq!(health.accepted_total.load(Ordering::SeqCst), 3);
    assert_eq!(health.queue_depth.load(Ordering::SeqCst), 3);
    drop(receiver);
    assert_eq!(health.queue_depth.load(Ordering::SeqCst), 0);
    assert_eq!(health.inflight.load(Ordering::SeqCst), 0);
    assert_eq!(health.failed_total.load(Ordering::SeqCst), 3);
    assert_eq!(health.accepted_total.load(Ordering::SeqCst), 3);
    assert!(!health.accounting_poisoned.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn unwind_releases_only_its_command_and_completion_is_idempotent() -> TestResult {
    let (sender, receiver) = receipt_commit_channel();
    sender.try_send(append_command("panicked")?)?;
    sender.try_send(append_command("surviving")?)?;
    let (first, first_permit) = receiver.recv()?.dequeue();
    let (_second, mut second_permit) = receiver.recv()?.dequeue();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned = (first, first_permit);
        panic!("injected actor unwind");
    }));
    assert!(
        matches!(unwind, Err(payload) if payload.downcast_ref::<&str>() == Some(&"injected actor unwind"))
    );
    assert_eq!(sender.health.inflight.load(Ordering::SeqCst), 1);
    assert_eq!(sender.health.failed_total.load(Ordering::SeqCst), 1);
    second_permit.finish(true);
    second_permit.finish(false);
    drop(second_permit);
    assert_eq!(sender.health.inflight.load(Ordering::SeqCst), 0);
    assert_eq!(sender.health.committed_total.load(Ordering::SeqCst), 1);
    assert_eq!(sender.health.failed_total.load(Ordering::SeqCst), 1);
    assert!(!sender.health.accounting_poisoned.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn exhausted_writer_counters_refuse_before_enqueue_and_stay_closed() -> TestResult {
    for counter_name in ["inflight", "accepted", "queue"] {
        let (sender, receiver) = receipt_commit_channel();
        let health = &sender.health;
        let counter = match counter_name {
            "inflight" => &health.inflight,
            "accepted" => &health.accepted_total,
            _ => &health.queue_depth,
        };
        counter.store(u64::MAX, Ordering::SeqCst);
        assert!(matches!(sender.try_send(append_command("overflow")?),
            Err(ReceiptStoreError::Conflict(message)) if message.contains("overflow")));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert_eq!(counter.load(Ordering::SeqCst), u64::MAX);
        health.set_head_poisoned(false);
        *health
            .last_error
            .lock()
            .map_err(|_| "health lock poisoned")? = None;
        assert!(matches!(sender.try_send(append_command("still-closed")?),
            Err(ReceiptStoreError::Conflict(message)) if message.contains("admission after accounting failure")));
    }
    Ok(())
}

#[test]
fn terminal_counter_exhaustion_preserves_ownership_and_latches_failure() -> TestResult {
    for committed in [true, false] {
        let (sender, receiver) = receipt_commit_channel();
        sender.try_send(append_command("terminal-overflow")?)?;
        let (_command, mut permit) = receiver.recv()?.dequeue();
        let counter = if committed {
            &sender.health.committed_total
        } else {
            &sender.health.failed_total
        };
        counter.store(u64::MAX, Ordering::SeqCst);
        permit.finish(committed);
        drop(permit);
        assert_eq!(counter.load(Ordering::SeqCst), u64::MAX);
        assert_eq!(sender.health.inflight.load(Ordering::SeqCst), 0);
        assert_eq!(sender.health.queue_depth.load(Ordering::SeqCst), 0);
        assert!(sender.health.accounting_poisoned.load(Ordering::SeqCst));
    }
    Ok(())
}

#[test]
fn timeout_counter_exhaustion_never_wraps_or_releases_unowned_slots() {
    for total in [true, false] {
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let counter = if total {
            &health.timed_out_total
        } else {
            &health.timed_out_inflight
        };
        counter.store(u64::MAX, Ordering::SeqCst);
        let (completion, timeout) = writer_command_tracker(&health);
        timeout.note_timeout(RECEIPT_WRITE_TIMEOUT_MARKER);
        drop(completion);
        assert_eq!(counter.load(Ordering::SeqCst), u64::MAX);
        assert!(health.accounting_poisoned.load(Ordering::SeqCst));
    }
}

#[test]
fn receipt_count_overflow_rolls_back_the_actual_append_transaction() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteReceiptStore::open(directory.path().join("receipt.db"))?;
    let mut head = VerifiedHead {
        latest_checkpoint: None,
        chain_frontier: None,
        claim_log_count: u64::MAX,
        claim_log_max_seq: 0,
    };
    let ReceiptCommitCommand::Append(request) = append_command("count-overflow")? else {
        unreachable!()
    };
    assert!(
        matches!(append_receipt_batch(&store.pool, &mut head, true, None, None, &[*request]),
        Err(ReceiptStoreError::Conflict(message)) if message == "receipt claim count overflow")
    );
    let connection = store.connection()?;
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
            row.get(0)
        })?;
    assert_eq!(count, 0);
    assert_eq!(head.claim_log_count, u64::MAX);
    assert_eq!(head.claim_log_max_seq, 0);
    Ok(())
}

#[test]
fn checkpoint_predecessor_is_typed_constrained_and_checked_on_read() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("receipt.db");
    let store = SqliteReceiptStore::open(&path)?;
    let key = receipt_test_keypair();
    for index in 0..2 {
        store.append_chio_receipt_returning_seq(&sample_receipt_with_id(&format!(
            "checkpoint-{index}"
        )))?;
        store.create_next_receipt_checkpoint(1, &key)?;
    }
    let connection = Connection::open(&path)?;
    let checkpoints = load_all_persisted_checkpoint_rows(&connection)?;
    assert_eq!(checkpoints.len(), 2);
    let verified = parse_persisted_checkpoint_row(checkpoints[1].clone())?;
    assert_eq!(
        checkpoints[1].previous_checkpoint_sha256,
        verified.body.previous_checkpoint_sha256
    );
    let sql: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE name = 'kernel_checkpoints_project_tree_head'",
        [],
        |row| row.get(0),
    )?;
    assert!(!sql.contains("json_extract"));
    connection.execute_batch("DROP TRIGGER kernel_checkpoints_reject_update")?;
    assert!(
        matches!(connection.execute("UPDATE kernel_checkpoints SET previous_checkpoint_sha256 = 'invalid' WHERE checkpoint_seq = 2", []),
        Err(rusqlite::Error::SqliteFailure(error, _)) if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_CHECK)
    );
    connection.execute(
        "UPDATE kernel_checkpoints SET previous_checkpoint_sha256 = ?1 WHERE checkpoint_seq = 2",
        ["0".repeat(64)],
    )?;
    let row = load_persisted_checkpoint_row(&connection, 2)?.ok_or("checkpoint missing")?;
    assert!(
        matches!(parse_persisted_checkpoint_row(row), Err(ReceiptStoreError::Conflict(message)) if message.contains("predecessor column does not match signed body"))
    );
    Ok(())
}

fn seed_checkpoint_chain(path: &Path) -> TestResult {
    let store = SqliteReceiptStore::open(path)?;
    for index in 0..2 {
        store.append_chio_receipt(&sample_receipt_with_id(&format!("upgrade-{index}")))?;
        store.create_next_receipt_checkpoint(1, &receipt_test_keypair())?;
    }
    Ok(())
}

fn signed_checkpoint_rows(connection: &Connection) -> rusqlite::Result<Vec<(String, String)>> {
    connection
        .prepare(
            "SELECT statement_json, signature FROM kernel_checkpoints ORDER BY checkpoint_seq",
        )?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect()
}

fn downgrade_checkpoint_column_to_v6(connection: &Connection) -> TestResult {
    connection.execute_batch(
        "DROP TRIGGER IF EXISTS kernel_checkpoints_project_tree_head;
         DROP TRIGGER IF EXISTS kernel_checkpoints_enforce_append_only;
         ALTER TABLE kernel_checkpoints DROP COLUMN previous_checkpoint_sha256;",
    )?;
    connection.execute_batch(include_str!("fixtures/checkpoint_projection_v6.sql"))?;
    crate::stamp_schema_version(connection, "receipt", 6)?;
    Ok(())
}

fn assert_checkpoint_column_constraints(connection: &Connection) -> TestResult {
    use rusqlite::types::Value;
    for (table, guard) in [
        ("kernel_checkpoints", "kernel_checkpoints_reject_update"),
        (
            "checkpoint_tree_heads",
            "checkpoint_tree_heads_reject_update",
        ),
        (
            "checkpoint_predecessor_witnesses",
            "checkpoint_predecessor_witnesses_reject_update",
        ),
        (
            "checkpoint_publication_metadata",
            "checkpoint_publication_metadata_reject_update",
        ),
    ] {
        connection.execute_batch(&format!("DROP TRIGGER IF EXISTS {guard}"))?;
        for invalid in [
            Value::Text("a".repeat(63)),
            Value::Text("A".repeat(64)),
            Value::Text("g".repeat(64)),
            Value::Blob(vec![b'a'; 64]),
        ] {
            assert!(
                matches!(
                    connection.execute(&format!("UPDATE {table} SET previous_checkpoint_sha256 = ?1"), [invalid]),
                    Err(rusqlite::Error::SqliteFailure(error, _))
                        if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_CHECK
                ),
                "malformed predecessor must be refused by {table}"
            );
        }
    }
    Ok(())
}

#[test]
fn checkpoint_v6_upgrade_preserves_signatures_constraints_and_restart() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("upgrade.db");
    seed_checkpoint_chain(&path)?;
    let connection = Connection::open(&path)?;
    let original = signed_checkpoint_rows(&connection)?;
    downgrade_checkpoint_column_to_v6(&connection)?;
    drop(connection);
    let store = SqliteReceiptStore::open(&path)?;
    assert_eq!(signed_checkpoint_rows(&*store.connection()?)?, original);
    store.append_chio_receipt(&sample_receipt_with_id("after-upgrade"))?;
    store.create_next_receipt_checkpoint(1, &receipt_test_keypair())?;
    drop(store);
    let store = SqliteReceiptStore::open(&path)?;
    let mut connection = Connection::open(&path)?;
    assert_eq!(load_all_persisted_checkpoint_rows(&connection)?.len(), 3);
    verify_checkpoint_chain_integrity(&connection)?;
    let tx = connection.transaction()?;
    assert_checkpoint_column_constraints(&tx)?;
    tx.rollback()?;
    drop(connection);
    drop(store);
    Ok(())
}

#[test]
fn invalid_checkpoint_v6_upgrade_rolls_back_schema_guards_and_version() -> TestResult {
    for invalid_signature in [true, false] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("refused.db");
        seed_checkpoint_chain(&path)?;
        let connection = Connection::open(&path)?;
        downgrade_checkpoint_column_to_v6(&connection)?;
        if invalid_signature {
            connection.execute_batch("DROP TRIGGER kernel_checkpoints_reject_update;
                UPDATE kernel_checkpoints SET signature = lower(hex(zeroblob(64))) WHERE checkpoint_seq = 2;
                CREATE TRIGGER kernel_checkpoints_reject_update BEFORE UPDATE ON kernel_checkpoints
                BEGIN SELECT RAISE(ABORT, 'kernel checkpoints are immutable'); END;")?;
        } else {
            connection.execute_batch("DROP TRIGGER checkpoint_tree_heads_reject_update;
                UPDATE checkpoint_tree_heads SET previous_checkpoint_sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE checkpoint_seq = 2;
                CREATE TRIGGER checkpoint_tree_heads_reject_update BEFORE UPDATE ON checkpoint_tree_heads
                BEGIN SELECT RAISE(ABORT, 'checkpoint tree heads are immutable'); END;")?;
        }
        let before = signed_checkpoint_rows(&connection)?;
        let schema = |connection: &Connection| -> rusqlite::Result<Vec<(String, String)>> {
            connection
                .prepare("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name")?
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect()
        };
        let before_schema = schema(&connection)?;
        drop(connection);
        assert!(matches!(
            SqliteReceiptStore::open(&path),
            Err(ReceiptStoreError::Conflict(_))
        ));
        let connection = Connection::open(&path)?;
        assert_eq!(schema(&connection)?, before_schema);
        assert_eq!(signed_checkpoint_rows(&connection)?, before);
        assert_eq!(
            connection.query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'",
                [],
                |row| row.get::<_, i32>(0)
            )?,
            6
        );
    }
    Ok(())
}

#[test]
fn checkpoint_archive_upgrades_and_reopens_with_exact_typed_predecessors() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("live.db");
    let archive = directory.path().join("archive.db");
    seed_checkpoint_chain(&path)?;
    let store = SqliteReceiptStore::open(&path)?;
    let original = signed_checkpoint_rows(&*store.connection()?)?;
    assert_eq!(
        store.archive_receipts_before(2, archive.to_str().ok_or("archive path")?)?,
        2
    );
    drop(store);
    let connection = Connection::open(&archive)?;
    assert_eq!(signed_checkpoint_rows(&connection)?, original);
    downgrade_checkpoint_column_to_v6(&connection)?;
    drop(connection);
    let mut connection = Connection::open_in_memory()?;
    connection.execute(
        "ATTACH DATABASE ?1 AS archive",
        [archive.to_str().ok_or("archive path")?],
    )?;
    evidence_retention::create_archive_schema(&mut connection)?;
    evidence_retention::create_archive_schema(&mut connection)?;
    connection.execute_batch("DETACH DATABASE archive")?;
    // Writable open materializes the archive's documented empty projection shells.
    let archived = SqliteReceiptStore::open(&archive)?;
    drop(archived);
    let archived = SqliteReceiptStore::open_existing(&archive)?;
    assert_eq!(signed_checkpoint_rows(&*archived.connection()?)?, original);
    verify_checkpoint_chain_integrity(&*archived.connection()?)?;
    let mut connection = Connection::open(&archive)?;
    let tx = connection.transaction()?;
    assert_checkpoint_column_constraints(&tx)?;
    tx.rollback()?;
    Ok(())
}

#[test]
fn overflowing_retention_duration_refuses_before_archiving_or_deleting() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("live.sqlite");
    let archive = directory.path().join("archive.sqlite");
    let store = SqliteReceiptStore::open(&path)?;
    store.append_chio_receipt(&sample_receipt_with_id("duration-overflow"))?;
    store.flush_receipt_writes()?;
    let config = chio_kernel::RetentionConfig {
        retention_days: u64::MAX,
        archive_path: archive.to_str().ok_or("archive path")?.to_owned(),
        ..Default::default()
    };
    assert!(matches!(store.rotate_if_needed(&config),
        Err(ReceiptStoreError::ReadBoundary(message)) if message == "retention duration overflow"));
    let count: i64 = Connection::open(&path)?.query_row(
        "SELECT COUNT(*) FROM chio_tool_receipts",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    assert!(!archive.exists());
    let valid = chio_kernel::RetentionConfig {
        retention_days: 36_500,
        ..config
    };
    assert_eq!(store.rotate_if_needed(&valid)?, 0);
    Ok(())
}
