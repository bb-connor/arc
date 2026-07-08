use super::super::*;
use super::support::*;

fn open_seeded_store(
    prefix: &str,
    receipts: usize,
) -> Result<(std::path::PathBuf, SqliteReceiptStore, Keypair), Box<dyn std::error::Error>> {
    let path = unique_db_path(prefix);
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..receipts {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-head-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    Ok((path, store, keypair))
}

#[test]
fn seed_verified_head_matches_persisted_state() -> Result<(), Box<dyn std::error::Error>> {
    let (path, store, keypair) = open_seeded_store("chio-head-seed", 5)?;
    store.create_next_receipt_checkpoint(3, &keypair)?;

    let connection = store.connection()?;
    let head = seed_verified_head(&connection)?;
    assert_eq!(head.claim_log_count, 5);
    assert_eq!(head.claim_log_max_seq, 5);
    assert_eq!(head.checkpoint_seq(), 1);
    assert_eq!(head.checkpointed_entry_seq(), 3);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn verify_head_accepts_matching_head_and_catches_up_forward(
) -> Result<(), Box<dyn std::error::Error>> {
    let (path, store, keypair) = open_seeded_store("chio-head-accept", 4)?;
    let connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;

    // Matching head: one row read + digest compare, Ok.
    verify_head_against_latest_checkpoint(&connection, &mut head)?;

    // A checkpoint created out of band (manual operator path) validly
    // extends the chain: the head catches up instead of false-Conflicting.
    store.create_next_receipt_checkpoint(4, &keypair)?;
    verify_head_against_latest_checkpoint(&connection, &mut head)?;
    assert_eq!(head.checkpoint_seq(), 1);
    assert_eq!(head.checkpointed_entry_seq(), 4);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn verify_head_rejects_tampered_latest_checkpoint_with_conflict(
) -> Result<(), Box<dyn std::error::Error>> {
    let (path, store, keypair) = open_seeded_store("chio-head-tamper", 3)?;
    store.create_next_receipt_checkpoint(3, &keypair)?;
    let connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;

    // Tamper the persisted latest checkpoint body out of band (drop the
    // immutability trigger first, exactly like tests/support tamper helpers).
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, '\"batch_end_seq\":3', '\"batch_end_seq\":2')",
        [],
    )?;

    let error = verify_head_against_latest_checkpoint(&connection, &mut head)
        .err()
        .ok_or("tampered checkpoint must be rejected")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("chio receipt audit"),
                "Conflict must point the operator at the audit CLI, got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn claim_log_delta_aggregate_is_scoped_to_the_floor() -> Result<(), Box<dyn std::error::Error>> {
    let (path, store, _keypair) = open_seeded_store("chio-head-delta", 6)?;
    let connection = store.connection()?;
    assert_eq!(claim_log_delta_count_and_max_seq(&connection, 0)?, (6, 6));
    assert_eq!(claim_log_delta_count_and_max_seq(&connection, 4)?, (2, 6));
    // Empty range: count 0, max falls back to the floor.
    assert_eq!(claim_log_delta_count_and_max_seq(&connection, 6)?, (0, 6));
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn incremental_append_updates_the_head_and_stays_correct() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-head-incremental");
    let store = SqliteReceiptStore::open(&path)?; // default: incremental on
    assert!(store.incremental_verification_enabled());
    let keypair = receipt_test_keypair();
    for i in 0..7 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-inc-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let snapshot = store.writer_head_snapshot();
    assert_eq!(snapshot.claim_log_count, 7);
    assert_eq!(snapshot.claim_log_max_seq, 7);
    // The head equals what a full re-verification computes.
    let connection = store.connection()?;
    let reference = seed_verified_head(&connection)?;
    assert_eq!(snapshot.claim_log_count, reference.claim_log_count);
    assert_eq!(snapshot.claim_log_max_seq, reference.claim_log_max_seq);
    assert_eq!(snapshot.checkpoint_seq, reference.checkpoint_seq());
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn append_denies_when_head_diverges() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-head-deny");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-deny-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(3, &keypair)?;
    // Prime the head past the checkpoint (any append or flush suffices).
    store.flush_receipt_writes()?;

    // Out-of-band mutation of the persisted latest checkpoint row.
    let connection = store.connection()?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    // Mutate a REAL body field (an ignored extra field would not change the
    // RFC 8785 digest of the parsed body): batch_end_seq 3 -> 2.
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, '\"batch_end_seq\":3', '\"batch_end_seq\":2')",
        [],
    )?;
    drop(connection);

    // The NEXT append fails closed with Conflict pointing at the audit CLI.
    let receipt = sample_receipt_with_keypair("rcpt-deny-after-tamper", 99, &keypair);
    let error = store
        .append_chio_receipt_returning_seq(&receipt)
        .err()
        .ok_or("append after tamper must be denied")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(message.contains("chio receipt audit"), "got: {message}");
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // The audit surface localizes the divergence (full chain verify fails
    // with a checkpoint-identifying error).
    let status = store.receipt_checkpoint_status(Some(1))?;
    assert!(!status.healthy);
    let checkpoint_error = status
        .checkpoint_error
        .ok_or("audit must report the fault")?;
    assert!(
        checkpoint_error.contains("checkpoint") || checkpoint_error.contains("1"),
        "audit must localize the divergent checkpoint: {checkpoint_error}"
    );
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn writer_routed_inserts_do_not_false_conflict_the_next_append(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-head-resync");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let receipt = sample_receipt_with_keypair("rcpt-resync-0", 1, &keypair);
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;

    // Writer-routed child receipt inserts a claim-log row via the projection
    // trigger (bootstrap/open.rs:711); manual checkpoint creation inserts a
    // checkpoint row. Both must be absorbed by the post-Write resync.
    let child = sample_child_receipt_with_keypair_and_timestamp("child-resync-1", 2, &keypair);
    store.append_child_receipt_record(&child)?;
    store.create_next_receipt_checkpoint(2, &keypair)?;

    // The next appends must succeed (no projection-drift Conflict, no
    // predecessor Conflict).
    for i in 1..4 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-resync-{i}"), (i + 2) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let snapshot = store.writer_head_snapshot();
    assert_eq!(snapshot.claim_log_max_seq, 5); // 1 tool + 1 child + 3 tool
    assert_eq!(snapshot.checkpoint_seq, 1);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn full_verification_fallback_still_catches_projection_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-head-fallback");
    let keypair = receipt_test_keypair();
    // `ChioReceipt::sign` overwrites `body.id` with the authoritative
    // `chio_receipt_id` (an RFC 8785 canonical-body sha256), discarding the
    // caller-supplied seed string, so the persisted `receipt_id` must be read
    // back from the signed receipt, not the seed passed to
    // `sample_receipt_with_keypair`.
    let receipt_id = {
        let store = SqliteReceiptStore::open(&path)?;
        let receipt = sample_receipt_with_keypair("rcpt-fallback-0", 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
        store.flush_receipt_writes()?;
        receipt.id.clone()
    };
    let store = SqliteReceiptStore::open_existing_with_options(
        &path,
        crate::SqliteStoreOptions {
            pool: crate::SqlitePoolConfig::default(),
            incremental_verification: false,
        },
    )?;
    assert!(!store.incremental_verification_enabled());

    // Same tamper the legacy full path catches today.
    tamper_claim_log_tool_receipt(&store, &receipt_id, |receipt| {
        receipt.tool_name = "tampered".to_string();
    });
    let receipt = sample_receipt_with_keypair("rcpt-fallback-1", 2, &keypair);
    let error = store
        .append_chio_receipt_returning_seq(&receipt)
        .err()
        .ok_or("full-path append after tamper must be denied")?;
    assert!(matches!(error, ReceiptStoreError::Conflict(_)));
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn reseed_clears_a_poisoned_head_after_repairing_the_database(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-head-reseed");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-reseed-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(3, &keypair)?;

    // Poison: tamper the latest checkpoint, trigger the denial, then repair
    // the row back to its original bytes and reseed.
    let connection = store.connection()?;
    let original: String = connection.query_row(
        "SELECT statement_json FROM kernel_checkpoints WHERE checkpoint_seq = 1",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, '\"batch_end_seq\":3', '\"batch_end_seq\":2')",
        [],
    )?;
    drop(connection);

    let receipt = sample_receipt_with_keypair("rcpt-reseed-denied", 50, &keypair);
    assert!(store.append_chio_receipt_returning_seq(&receipt).is_err());

    // Repair the database out of band, then reseed the head. The denied
    // append above ran `ensure_checkpoint_transparency_guards` before its
    // predecessor check failed, silently recreating the immutability
    // trigger; an out-of-band repair must drop it again before writing,
    // exactly as the initial tamper did.
    let connection = store.connection()?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = ?1 WHERE checkpoint_seq = 1",
        rusqlite::params![original],
    )?;
    drop(connection);
    store.reseed_verified_head()?;

    // Appends flow again.
    let receipt = sample_receipt_with_keypair("rcpt-reseed-ok", 51, &keypair);
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;
    let health = store.receipt_store_health()?;
    assert!(
        health.writer.last_error.is_none(),
        "reseed must clear last_error"
    );
    let _ = fs::remove_file(path);
    Ok(())
}

/// `chio receipt audit --repair` on a store whose data is STILL corrupt (the
/// operator ran `--repair` without actually fixing the underlying rows) must
/// fail closed: `reseed_verified_head` returns `Err`, the writer stays
/// `Poisoned`, and the next append is denied via the poisoned-head Conflict
/// (not silently readopted as healthy). This is the counterpart to
/// `reseed_clears_a_poisoned_head_after_repairing_the_database`, which proves
/// the success path; this test proves the fail-closed path the review
/// flagged as untested.
#[test]
fn reseed_on_still_corrupt_store_stays_poisoned() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-head-reseed-fail");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-reseed-fail-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(3, &keypair)?;

    // Same tamper mechanics as `reseed_clears_a_poisoned_head_after_repairing_the_database`:
    // drop the immutability trigger, then mutate a real body field so the
    // RFC 8785 digest changes. Keep the original bytes so the last section of
    // this test can still prove the same store object recovers once the data
    // really is repaired.
    let connection = store.connection()?;
    let original: String = connection.query_row(
        "SELECT statement_json FROM kernel_checkpoints WHERE checkpoint_seq = 1",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, '\"batch_end_seq\":3', '\"batch_end_seq\":2')",
        [],
    )?;
    drop(connection);

    // Poison the writer's cached head exactly as the existing reseed test
    // does: a denied append surfaces the divergence without repairing it.
    let denied_before_reseed =
        sample_receipt_with_keypair("rcpt-reseed-fail-denied-before", 50, &keypair);
    assert!(store
        .append_chio_receipt_returning_seq(&denied_before_reseed)
        .is_err());

    // The corruption is NOT repaired here (unlike the success-path test):
    // reseed_verified_head reruns full verification on the still-corrupt
    // store and must fail closed.
    let reseed_error = store
        .reseed_verified_head()
        .err()
        .ok_or("reseed on a still-corrupt store must return Err")?;
    match &reseed_error {
        ReceiptStoreError::Conflict(_) => {}
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // The writer-health surface reflects the reseed failure: `last_error` is
    // read here, before the next append below overwrites it with its own
    // (differently worded) poisoned-Conflict text, so this specifically
    // checks the ReseedHead command's own failure, not a downstream echo.
    let health = store.receipt_store_health()?;
    let last_error = health
        .writer
        .last_error
        .clone()
        .ok_or("writer last_error must be set after a failed reseed")?;
    assert_eq!(
        last_error,
        reseed_error.to_string(),
        "writer last_error must mirror the reseed failure"
    );

    // The store stays fail-closed: the next append is still rejected, now
    // via the Poisoned head_state (not the stale predecessor check that
    // denied the pre-reseed append above), which points the operator back at
    // `chio receipt audit --repair`.
    let denied_after_reseed =
        sample_receipt_with_keypair("rcpt-reseed-fail-denied-after", 51, &keypair);
    let error = store
        .append_chio_receipt_returning_seq(&denied_after_reseed)
        .err()
        .ok_or("append on a still-poisoned store must be denied")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("chio receipt audit"),
                "poisoned Conflict must point the operator at the audit CLI, got: {message}"
            );
            assert!(
                message.contains("verified head is unavailable"),
                "poisoned Conflict must come from the Poisoned head_state (not a stale \
                 predecessor-check Conflict), got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // The same store object recovers once the data is actually repaired.
    let connection = store.connection()?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = ?1 WHERE checkpoint_seq = 1",
        rusqlite::params![original],
    )?;
    drop(connection);
    store.reseed_verified_head()?;

    let receipt = sample_receipt_with_keypair("rcpt-reseed-fail-recovered", 52, &keypair);
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;
    let health = store.receipt_store_health()?;
    assert!(
        health.writer.last_error.is_none(),
        "reseed after a real repair must clear last_error"
    );

    let _ = fs::remove_file(path);
    Ok(())
}
