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

/// Codex round 7, finding 3: `reseed_verified_head()` success clears
/// `last_error` and replaces the head, but the actor loop's separate
/// `pending_flush_error` (set by the earlier poisoned append) was left
/// untouched, so a subsequent STANDALONE `flush_receipt_writes()` (no queued
/// writes) kept returning the stale append error even though the reseed
/// revalidated the DB. The fix clears `pending_flush_error` on reseed success.
#[test]
fn reseed_clears_stale_flush_error() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-reseed-clears-flush-error");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt = sample_receipt_with_keypair(
            &format!("rcpt-reseed-flush-{i}"),
            (i + 1) as u64,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(3, &keypair)?;

    // Poison: tamper the latest checkpoint so the next append is denied. The
    // denied append records the actor loop's `pending_flush_error`.
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

    let denied = sample_receipt_with_keypair("rcpt-reseed-flush-denied", 50, &keypair);
    assert!(store.append_chio_receipt_returning_seq(&denied).is_err());
    // A standalone flush now surfaces the stale append error (the bug this fix
    // targets: the flush error outlives the failed append).
    assert!(
        store.flush_receipt_writes().is_err(),
        "a poisoned append must leave the standalone flush returning the stale error"
    );

    // Repair the DB out of band, then reseed. The denied append re-created the
    // immutability trigger, so drop it again before the repair write.
    let connection = store.connection()?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = ?1 WHERE checkpoint_seq = 1",
        rusqlite::params![original],
    )?;
    drop(connection);
    store.reseed_verified_head()?;

    // The finding: a subsequent STANDALONE flush (no intervening append that
    // would itself reset the error) returns Ok, not the stale append error.
    let report = store.flush_receipt_writes();
    assert!(
        report.is_ok(),
        "reseed success must clear the stale flush error: {report:?}"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// Codex round 7, finding 2: when another writer extends the checkpoint chain
/// out of band, the catch-up adoption path verifies signature + predecessor +
/// claim-log range but must ALSO validate the adopted checkpoint's transparency
/// projection rows (which full `verify_checkpoint_chain_integrity` checks)
/// before advancing `head.latest_checkpoint`. A checkpoint with missing /
/// divergent projection rows must NOT be adopted; a valid extension still is
/// (bounded per-checkpoint, not a full-history walk, F22).
#[test]
fn catch_up_validates_checkpoint_projections() -> Result<(), Box<dyn std::error::Error>> {
    // REJECT: an externally persisted checkpoint whose kernel_checkpoints row is
    // present (valid signature, valid predecessor linkage, valid claim-log range)
    // but whose transparency projection rows are MISSING must fail the catch-up
    // closed. The projections are normally auto-populated by the
    // `kernel_checkpoints_project_tree_head` AFTER INSERT trigger, so this drops
    // that trigger out of band before the external insert to leave the projection
    // rows missing (the exact state full verify_checkpoint_chain_integrity
    // rejects).
    let path = unique_db_path("chio-catchup-bad-projections");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..6 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-catchup-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // Checkpoint 1 (1..=3) with full, valid projections.
    store.create_next_receipt_checkpoint(3, &keypair)?;
    let checkpoint_one = store
        .load_checkpoint_by_seq(1)?
        .ok_or("checkpoint 1 missing")?;

    let connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;
    assert_eq!(head.checkpoint_seq(), 1);

    // Another writer extends with a chain-linked checkpoint 2 (4..=6). Drop the
    // projection auto-populate trigger first so the row lands with MISSING
    // transparency projections.
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_project_tree_head;")?;
    let range_bytes = canonical_receipt_bytes(&store, 4, 6);
    let checkpoint_two =
        build_checkpoint_with_previous(2, 4, 6, &range_bytes, &keypair, Some(&checkpoint_one))?;
    insert_checkpoint_row(&store, &checkpoint_two, checkpoint_two.body.batch_end_seq);

    let error = verify_head_against_latest_checkpoint(&connection, &mut head)
        .err()
        .ok_or("catch-up must reject a checkpoint with missing projection rows")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict, got {error:?}"
    );
    assert_eq!(
        head.checkpoint_seq(),
        1,
        "the head must NOT adopt a checkpoint whose projection rows are invalid"
    );
    drop(connection);
    let _ = fs::remove_file(path);

    // ADOPT: a valid extension (projection rows written by the store's own
    // checkpoint builder) is still caught up.
    let good_path = unique_db_path("chio-catchup-good-projections");
    let good_store = SqliteReceiptStore::open(&good_path)?;
    for i in 0..6 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-catchup-ok-{i}"), (i + 1) as u64, &keypair);
        good_store.append_chio_receipt_returning_seq(&receipt)?;
    }
    good_store.flush_receipt_writes()?;
    good_store.create_next_receipt_checkpoint(3, &keypair)?; // cp1 (1..=3)
    let good_connection = good_store.connection()?;
    let mut good_head = seed_verified_head(&good_connection)?;
    assert_eq!(good_head.checkpoint_seq(), 1);
    good_store.create_next_receipt_checkpoint(3, &keypair)?; // cp2 (4..=6), valid projections
    verify_head_against_latest_checkpoint(&good_connection, &mut good_head)?;
    assert_eq!(
        good_head.checkpoint_seq(),
        2,
        "a valid extension with intact projection rows must be adopted"
    );
    drop(good_connection);
    let _ = fs::remove_file(good_path);
    Ok(())
}

/// RFC-0006 fail-closed parity: a writer-routed (Write path) receipt append
/// (child receipt / consuming-auth append) on an `incremental_verification =
/// false` store must run the SAME full claim-log validation the append batch
/// path runs, so uncheckpointed projection drift is denied at append time.
/// Before the fix the fallback pre-check ran only
/// `verify_latest_checkpoint_integrity`, which returns Ok when no checkpoint
/// exists, so a writer-routed append silently committed over tampered rows.
/// Sibling of `full_verification_fallback_still_catches_projection_drift`
/// (which covers the append batch path).
#[test]
fn writer_routed_fallback_append_catches_uncheckpointed_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-writer-fallback-drift");
    let keypair = receipt_test_keypair();
    // Seed one tool receipt on the default (incremental) store; capture the
    // authoritative persisted receipt id.
    let receipt_id = {
        let store = SqliteReceiptStore::open(&path)?;
        let receipt = sample_receipt_with_keypair("rcpt-wfd-0", 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
        store.flush_receipt_writes()?;
        receipt.id.clone()
    };
    // Reopen with incremental verification OFF (full-verification fallback).
    let store = SqliteReceiptStore::open_existing_with_options(
        &path,
        crate::SqliteStoreOptions {
            pool: crate::SqlitePoolConfig::default(),
            incremental_verification: false,
        },
    )?;
    assert!(!store.incremental_verification_enabled());

    // Tamper an UNCHECKPOINTED claim-log row (no checkpoint has been built).
    tamper_claim_log_tool_receipt(&store, &receipt_id, |receipt| {
        receipt.tool_name = "tampered".to_string();
    });

    // A writer-routed child receipt append must be DENIED fail-closed by the
    // pre-write full claim-log validation, not silently committed.
    let child = sample_child_receipt_with_keypair_and_timestamp("child-wfd-1", 2, &keypair);
    let error = store
        .append_child_receipt_record(&child)
        .err()
        .ok_or("writer-routed append after uncheckpointed tamper must be denied")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected fail-closed Conflict, got {error:?}"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// Codex round 3, finding 2: `append_receipt_batch` adopts every
/// claim_receipt_log_entries row past a STALE actor head as trusted baseline
/// (the pre_delta), cross-checking only the rows THIS batch inserts. A shared-DB
/// out-of-band orphan/mismatched row in that adopted range would be trusted; the
/// removed per-append full validation would have rejected it. The fix validates
/// JUST that bounded delta range against the source tables. The single-writer
/// no-stale-head case (empty delta) adds no validation, so F22 holds.
#[test]
fn stale_head_validates_adopted_delta_before_trusting() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-stale-head-delta");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Three real receipts -> claim-log entries 1..=3.
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-stale-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // An out-of-band writer commits an ORPHAN claim-log row (no source receipt)
    // at entry_seq 4. Inserts are not blocked by the reject_update trigger; the
    // CHECK constraint just requires the tool-receipt columns to be populated.
    {
        let connection = store.connection()?;
        connection.execute(
            r#"
            INSERT INTO claim_receipt_log_entries (
                entry_seq, receipt_id, receipt_kind, source_seq, timestamp,
                capability_id, tool_server, tool_name, raw_json
            ) VALUES (4, 'orphan-oob-4', 'tool_receipt', 999, 1, 'cap-oob', 'shell', 'bash', '{}')
            "#,
            [],
        )?;
    }

    // FAIL-CLOSED: a STALE head (claim_log_max_seq = 3) puts the orphan at
    // entry_seq 4 inside the adopted pre_delta. The append must be denied.
    let mut stale_head = VerifiedHead {
        latest_checkpoint: None,
        claim_log_count: 3,
        claim_log_max_seq: 3,
    };
    let receipt = sample_receipt_with_keypair("rcpt-stale-append", 10, &keypair);
    let raw_json = serde_json::to_string(&receipt)?;
    let (response, _rx) = std::sync::mpsc::sync_channel(1);
    let requests = vec![ReceiptCommitRequest {
        receipt,
        raw_json,
        ensure_lineage: false,
        response,
    }];
    let results = append_receipt_batch(&store.pool, &mut stale_head, true, &requests);
    let error = results
        .into_iter()
        .next()
        .ok_or("expected one append result")?
        .err()
        .ok_or("stale-head append over an out-of-band orphan row must be denied")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("chio receipt audit"),
                "fail-closed Conflict must point at the audit CLI, got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // NO-OP (F22): a FRESH head whose claim_log_max_seq already covers the
    // orphan (= 4) has an EMPTY delta, so the range validator does NOT re-scan
    // the below-floor orphan; appending a brand-new receipt succeeds.
    let mut fresh_head = VerifiedHead {
        latest_checkpoint: None,
        claim_log_count: 4,
        claim_log_max_seq: 4,
    };
    let receipt = sample_receipt_with_keypair("rcpt-stale-fresh", 11, &keypair);
    let raw_json = serde_json::to_string(&receipt)?;
    let (response, _rx) = std::sync::mpsc::sync_channel(1);
    let requests = vec![ReceiptCommitRequest {
        receipt,
        raw_json,
        ensure_lineage: false,
        response,
    }];
    let results = append_receipt_batch(&store.pool, &mut fresh_head, true, &requests);
    assert!(
        results.iter().all(|result| result.is_ok()),
        "empty-delta append must add no validation and succeed: {results:?}"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// Codex round 4, finding 2: `resync_head_after_write` advances the head after a
/// Write closure by COUNT/MAX over `claim_receipt_log_entries`. When another
/// process (or a receipt-appending Write job) commits rows PAST this actor's
/// head, resync adopts them without validation, so an out-of-band
/// orphan/divergent row is trusted and later appends skip it as
/// already-verified (a background checkpoint could then cover an unaudited
/// entry). The fix validates JUST the adopted delta (the same bounded
/// `validate_adopted_claim_log_delta` the append path uses) before advancing.
/// The single-writer common case (empty delta) adds no validation, so F22
/// holds.
#[test]
fn resync_validates_adopted_delta() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-resync-delta");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Three real receipts -> claim-log entries 1..=3.
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-resync-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // An out-of-band writer commits an ORPHAN claim-log row (no source receipt)
    // at entry_seq 4, past this actor's head. Same injection as the append-path
    // sibling above; inserts are not blocked by the reject_update trigger.
    {
        let connection = store.connection()?;
        connection.execute(
            r#"
            INSERT INTO claim_receipt_log_entries (
                entry_seq, receipt_id, receipt_kind, source_seq, timestamp,
                capability_id, tool_server, tool_name, raw_json
            ) VALUES (4, 'orphan-resync-4', 'tool_receipt', 999, 1, 'cap-oob', 'shell', 'bash', '{}')
            "#,
            [],
        )?;
    }

    // FAIL-CLOSED: a head at claim_log_max_seq = 3 puts the orphan at entry_seq 4
    // inside the adopted resync delta. The resync must REJECT it (finding 2), not
    // silently absorb it, and must not advance the head.
    let mut stale_head = VerifiedHead {
        latest_checkpoint: None,
        claim_log_count: 3,
        claim_log_max_seq: 3,
    };
    let connection = store.connection()?;
    let error = resync_head_after_write(&connection, &mut stale_head)
        .err()
        .ok_or("resync over an out-of-band orphan row must be rejected")?;
    match &error {
        ReceiptStoreError::Conflict(message) => assert!(
            message.contains("chio receipt audit"),
            "fail-closed Conflict must point at the audit CLI, got: {message}"
        ),
        other => return Err(format!("expected Conflict, got {other}").into()),
    }
    assert_eq!(
        stale_head.claim_log_max_seq, 3,
        "a rejected resync must not adopt the divergent delta"
    );

    // NO-OP (F22): a head already covering the orphan (max_seq = 4) has an EMPTY
    // resync delta, so the range validator does NOT re-scan the below-floor
    // orphan and the resync is a no-op.
    let mut fresh_head = VerifiedHead {
        latest_checkpoint: None,
        claim_log_count: 4,
        claim_log_max_seq: 4,
    };
    resync_head_after_write(&connection, &mut fresh_head)?;
    assert_eq!(
        fresh_head.claim_log_max_seq, 4,
        "empty-delta resync must be a no-op"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// Codex round 5, finding 2: for a writer-routed Write job the actor used to
/// send the caller's result BEFORE running `resync_head_after_write`. Round-4's
/// finding 2 made that resync able to FAIL (poison the head on a divergent
/// adopted delta), so a write whose closure COMMITTED but whose resync then
/// failed still returned `Ok` while the head was left poisoned. The fix defers
/// the response until AFTER resync: a committed write whose resync fails returns
/// the resync error, not a stale `Ok`.
#[test]
fn write_job_response_reflects_resync_failure() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-write-resync-fail");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Real receipts -> claim-log entries 1..=3, writer head at claim_log_max_seq 3.
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-wrf-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // A Write job whose closure COMMITS (returns Ok) but inserts an out-of-band
    // ORPHAN claim-log row at entry_seq 4 (no source receipt). The post-write
    // resync adopts (3, 4] as a delta, validates it, and REJECTS the orphan,
    // poisoning the head. The caller must receive that resync error, NOT Ok.
    let result: Result<(), ReceiptStoreError> =
        store.writer_handle().run_write(move |connection| {
            connection.execute(
                r#"
                INSERT INTO claim_receipt_log_entries (
                    entry_seq, receipt_id, receipt_kind, source_seq, timestamp,
                    capability_id, tool_server, tool_name, raw_json
                ) VALUES (4, 'orphan-wrf-4', 'tool_receipt', 999, 1, 'cap-oob', 'shell', 'bash', '{}')
                "#,
                [],
            )?;
            Ok(())
        });

    let error = result
        .err()
        .ok_or("a committed Write whose resync fails must return the resync error, not Ok")?;
    match &error {
        ReceiptStoreError::Conflict(message) => assert!(
            message.contains("chio receipt audit"),
            "resync failure must surface the fail-closed Conflict, got: {message}"
        ),
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // Teeth: the resync failure poisoned the head, so the next write is denied.
    let next: Result<(), ReceiptStoreError> = store.writer_handle().run_write(|_connection| Ok(()));
    assert!(next.is_err(), "resync failure must poison the head");

    let _ = fs::remove_file(path);
    Ok(())
}

/// Codex round 6, finding 1: on the same-seq fast path
/// `verify_head_against_latest_checkpoint` compared only the RFC 8785 body
/// digest (statement_json) plus the signature/kernel_key columns. The
/// kernel_checkpoints row ALSO stores batch_start_seq/batch_end_seq/tree_size/
/// merkle_root/issued_at as their own columns; a signed-body-bound column
/// tampered out of band while statement_json is untouched passed the digest
/// check. The fix reconciles EVERY such column against the signed body
/// (`ensure_checkpoint_columns_match_body`, O(1) over one row, no Ed25519), so
/// the column tamper now fails closed.
#[test]
fn head_trust_checks_all_checkpoint_columns() -> Result<(), Box<dyn std::error::Error>> {
    let (path, store, keypair) = open_seeded_store("chio-head-allcols", 3)?;
    store.create_next_receipt_checkpoint(3, &keypair)?;
    let connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;

    // Baseline: an untouched same-seq checkpoint verifies clean on the fast path.
    verify_head_against_latest_checkpoint(&connection, &mut head)?;

    // Tamper a SIGNED-BODY integrity COLUMN (batch_end_seq) out of band while
    // leaving statement_json (and thus the body digest) intact, bypassing the
    // immutability trigger. The digest branch alone would accept this.
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    let tampered = connection.execute(
        "UPDATE kernel_checkpoints SET batch_end_seq = batch_end_seq + 1 WHERE checkpoint_seq = 1",
        [],
    )?;
    assert_eq!(tampered, 1, "expected to tamper exactly one checkpoint row");

    let error = verify_head_against_latest_checkpoint(&connection, &mut head)
        .err()
        .ok_or("a tampered signed-body column must be rejected on the fast path")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("batch_end_seq"),
                "Conflict should name the tampered column, got: {message}"
            );
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

/// Codex round 6, finding 2: `validate_adopted_claim_log_delta` iterated only
/// the claim-log rows that CURRENTLY EXIST in the adopted range, so an interior
/// GAP (a missing entry_seq) passed unnoticed. The fix requires the adopted
/// range to be CONTIGUOUS (floor+1..=max with no hole), an O(delta) ordered
/// scan over the already-loaded delta, and rejects fail-closed on a gap while a
/// contiguous delta still passes.
#[test]
fn adopted_delta_rejects_interior_gap() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-adopted-delta-gap");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Four real, correctly-projecting receipts -> contiguous claim-log entries
    // 1,2,3,4. Every row projects from its source receipt, so the projection
    // cross-check alone cannot fail; only the contiguity rule can.
    for i in 0..4 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-gap-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    let connection = store.connection()?;

    // Contiguous delta (0, 4] = {1,2,3,4}: every row present and projecting, so
    // the validator accepts it.
    validate_adopted_claim_log_delta(&connection, 0, 4)?;

    // Punch an INTERIOR hole: delete entry_seq 3 (drop the append-only trigger
    // first), leaving {1,2,4}. The three surviving rows still project cleanly.
    connection.execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;")?;
    let deleted = connection.execute(
        "DELETE FROM claim_receipt_log_entries WHERE entry_seq = 3",
        [],
    )?;
    assert_eq!(deleted, 1, "expected to remove exactly one claim-log row");

    // Now (0, 4] = {1,2,4} is non-contiguous. Without the contiguity check the
    // projection loop would accept the surviving rows and return Ok; the fix
    // detects the gap at entry_seq 3 and fails closed.
    let error = validate_adopted_claim_log_delta(&connection, 0, 4)
        .err()
        .ok_or("a non-contiguous adopted delta must be rejected")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("not contiguous") && message.contains('3'),
                "Conflict should identify the interior gap, got: {message}"
            );
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

/// Codex round 3, finding 3: `verify_head_against_latest_checkpoint` compares
/// only the RFC 8785 body digest for a same-seq checkpoint (to keep the Ed25519
/// verify off the per-append hot path, F22). A persisted `signature` COLUMN
/// corrupted out of band while statement_json is untouched passes that digest
/// check. The fix also compares the signature/kernel_key COLUMNS against the
/// signature-verified cached head (O(1) string compare, no crypto), so the
/// column tamper is caught fail-closed.
#[test]
fn tampered_checkpoint_signature_column_denies_append() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-head-sig-column-tamper");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-sigcol-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(3, &keypair)?;
    // Prime the actor head so its cached latest_checkpoint is checkpoint 1 with
    // the ORIGINAL signature (this append forces the head to catch up to seq 1,
    // so the tamper below lands on the same-seq body-digest branch).
    store.append_chio_receipt_returning_seq(&sample_receipt_with_keypair(
        "rcpt-sigcol-prime",
        4,
        &keypair,
    ))?;
    store.flush_receipt_writes()?;

    // Corrupt ONLY the persisted signature column (statement_json/body intact),
    // bypassing the immutability trigger. A DIFFERENT but valid-hex Ed25519
    // signature (over unrelated bytes) keeps the row parseable.
    let tampered_signature_hex = keypair
        .sign(b"unrelated-bytes-for-a-different-valid-signature")
        .to_hex();
    {
        let connection = store.connection()?;
        let original: String = connection.query_row(
            "SELECT signature FROM kernel_checkpoints WHERE checkpoint_seq = 1",
            [],
            |row| row.get(0),
        )?;
        assert_ne!(original, tampered_signature_hex);
        connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
        connection.execute(
            "UPDATE kernel_checkpoints SET signature = ?1 WHERE checkpoint_seq = 1",
            rusqlite::params![tampered_signature_hex],
        )?;
    }

    // The next append hits the same-seq branch (body digest matches, body was
    // untouched) and must now fail closed on the signature-column mismatch.
    let receipt = sample_receipt_with_keypair("rcpt-sigcol-after", 5, &keypair);
    let error = store
        .append_chio_receipt_returning_seq(&receipt)
        .err()
        .ok_or("append after signature-column tamper must be denied")?;
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
