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
