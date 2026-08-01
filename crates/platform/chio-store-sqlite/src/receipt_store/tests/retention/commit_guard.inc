/// A subsequent rotation only appends the newer suffix to the archive the ledger
/// already committed to; the earlier prefix was deleted from the live store and
/// survives nowhere else. If that archive is missing, recreating an empty file
/// and co-archiving only the new suffix would advance the watermark while the
/// earlier prefix is backed by no archive. Rotation must fail closed and leave
/// the prefix intact. With the missing archive the committed watermark can no
/// longer be trusted, so the pre-rotation chain audit sees the deleted `[1,2]`
/// prefix as a live claim-log gap and refuses there; either that gap refusal or
/// the archive-backing refusal is an acceptable fail-closed outcome, and neither
/// may advance the watermark or delete the surviving suffix.
#[test]
fn rotation_refuses_when_prior_archive_missing() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("rotation-missing-prior-archive");
    let archive = unique_db_path("rotation-missing-prior-archive-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = store_with_archived_first_checkpoint(&path, archive_path, &keypair)?;

    // Delete the archive that backs the committed [1,2] prefix.
    std::fs::remove_file(&archive)?;

    // A second rotation would advance the watermark to cover the aged [3,4]
    // batch; with the prior archive gone it must refuse rather than strand [1,2].
    let result = store.archive_receipts_before(600, archive_path);
    let message = result
        .err()
        .ok_or("expected a fail-closed refusal; rotation stranded the prior prefix")?
        .to_string();
    assert!(
        message.contains("no longer backs the committed watermark")
            || message.contains("gap in checkpoint signer binding"),
        "unexpected error: {message}"
    );

    // Fail-closed: the watermark stays at 2 and the [3,4] rows survive.
    let conn = store.reader_connection_for_test()?;
    let watermark: Option<i64> = conn.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(watermark, Some(2), "the watermark must not advance");
    let survivors: i64 = conn.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq IN (3, 4)",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(survivors, 2, "the suffix rows must survive the refusal");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Repair consumes a precommitted checkpoint-aligned watermark that trusts the
/// whole prefix as archived and skips its Merkle rebuild. For prefix rows
/// already deleted from the live projection there is no live row to compare, so
/// a full-count archive carrying internally divergent bytes could pass a
/// presence check. Repair must verify every archived signed identity and the
/// covered checkpoint roots before cleanup.
#[test]
fn repair_rejects_corrupted_archive_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-corrupt-prefix");
    let archive = unique_db_path("repair-corrupt-prefix-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let divergent_keypair = super::support::Keypair::generate();
    let divergent_receipt = super::support::sample_receipt_with_keypair(
        "cp-0-1",
        100,
        &divergent_keypair,
    );
    let divergent_raw_json = serde_json::to_string(&divergent_receipt)?;

    {
        // One checkpoint covers [1,4] (max_batch 4), so repair rounds to 4.
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 4))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("cp-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        provision_test_archive_file(&archive)?;
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
        // Archive the FULL prefix [1,4] but corrupt entry 1's raw_json, then
        // delete all source rows and delete claim-log rows [1,2] outright (so they
        // have no live row to compare). Orphans [3,4] survive and pass the
        // per-extra identity check; the count check passes (archive holds 4 rows);
        // signed-identity and checkpoint-root validation must reject the
        // corrupted entry 1.
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            let divergent_raw_json = divergent_raw_json.clone();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
                copy_complete_repair_archive_prefix(connection, 4)?;
                connection.execute(
                    "UPDATE archive.claim_receipt_log_entries SET raw_json = ?1 WHERE entry_seq = 1",
                    rusqlite::params![divergent_raw_json.as_str()],
                )?;
                connection.execute(
                    "UPDATE archive.chio_tool_receipts SET raw_json = ?1 WHERE seq = 1",
                    rusqlite::params![divergent_raw_json.as_str()],
                )?;
                commit_attached_repair_archive_authority(connection, &archive_path, 4)?;
                connection.execute_batch(
                    "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 4; \
                     DELETE FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'tool receipts are immutable'); END; \
                     CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete \
                       BEFORE DELETE ON claim_receipt_log_entries \
                       BEGIN SELECT RAISE(ABORT, 'claim receipt log entries are immutable'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let result = store.retention_repair(archive_path);
    let message = result
        .err()
        .ok_or("expected a fail-closed refusal; repair sealed a corrupted archive")?
        .to_string();
    assert!(
        message.contains(
            "retention repair archive projection at entry 1 does not match its signed receipt identity"
        ),
        "unexpected error: {message}"
    );

    // Fail-closed: surviving orphans remain and repair leaves the precommitted
    // watermark unchanged.
    let conn = store.reader_connection_for_test()?;
    let orphans: i64 = conn.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq IN (3, 4)",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        orphans, 2,
        "surviving orphans must remain after the refusal"
    );
    let watermark: Option<i64> = conn.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |r| r.get::<_, Option<i64>>(0),
    )?;
    assert_eq!(
        watermark,
        Some(4),
        "repair must neither replace nor advance the precommitted watermark"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A prior botched rotation can leave a watermark covering the boundary but
/// pointing at a missing or wrong archive, with the orphaned claim-log rows still
/// live. Re-running repair with a different archive must not silently skip the
/// insert (the monotonic ledger cannot be corrected in place) and delete the
/// orphans behind a watermark whose recorded archive can never satisfy
/// verification. Tombstones must be stamped from the archive that backs the
/// watermark, so a supplied archive that is not the ledger archive (here the
/// ledger names a missing file) fails closed without deleting.
#[test]
fn repair_refuses_when_ledger_names_missing_archive() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-ledger-missing-archive");
    let archive = unique_db_path("repair-ledger-missing-archive-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("lm-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        provision_test_archive_file(&archive)?;
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
        // Co-archive [1,2] faithfully into the correct archive, orphan them
        // (delete only their source rows), and record a watermark at boundary 2
        // that names a non-existent archive path (the botched rotation's stale
        // ledger entry).
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                crate::receipt_store::evidence_retention::create_archive_schema(connection)?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'tool receipts are immutable'); END;",
                )?;
                let archive_identity = install_fresh_test_archive_identity(connection)?;
                let archive_content_sha256 =
                    crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
                        connection,
                        "archive",
                        2,
                    )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                // Record a covering watermark that names a path with no archive.
                let missing = format!("{archive_path}.missing");
                crate::receipt_store::support::insert_receipt_retention_watermark(
                    connection,
                    2,
                    100,
                    &missing,
                    &archive_identity,
                    &archive_content_sha256,
                    1,
                )?;
                Ok(())
            }
        })?;
    }

    // Repair with an archive that is not the one the ledger names. The ledger
    // already covers boundary 2 and points at the missing file, so repair cannot
    // stamp tombstones from the archive that backs the watermark and must refuse
    // without deleting the orphans.
    let store = SqliteReceiptStore::open_existing(&path)?;
    let result = store.retention_repair(archive_path);
    let message = result
        .err()
        .ok_or("expected a fail-closed refusal; repair deleted orphans behind a broken ledger")?
        .to_string();
    assert!(
        message.contains("differs from the archive"),
        "unexpected error: {message}"
    );

    // Fail-closed: the orphaned rows survive.
    let conn = store.reader_connection_for_test()?;
    let orphans: i64 = conn.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        orphans, 2,
        "orphaned rows must survive a refusal over a broken ledger"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Primary correctness proof: a state-machine proptest that drives random
/// interleaved sequences of tool/child appends (non-monotonic
/// timestamps within an aged band, to exercise the MAX(timestamp)-over-prefix
/// watermark rule) and rotations against the store, and asserts at every
/// reachable state that the store stays appendable, reopenable, healthy
/// (folding set-equality and chain integrity), and that the archived and live
/// receipt-id sets partition the full appended history with no loss and no
/// double-counting.
// Named `state_machine`, not `prop`: `proptest::prelude::*` re-exports the
// whole proptest crate under the name `prop` (for `prop::collection::vec`
// etc.), so a submodule literally named `prop` combined with `use super::*`
// would glob-import itself and collide with that re-export (E0659 ambiguous
// name).
#[cfg(test)]
mod state_machine {
    use std::collections::BTreeSet;

    use super::*;
    use proptest::prelude::*;

    #[derive(Clone, Debug)]
    enum Op {
        AppendTool(u8),
        AppendChild(u8),
        Rotate,
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..8).prop_map(Op::AppendTool),
            (0u8..8).prop_map(Op::AppendChild),
            Just(Op::Rotate),
        ]
    }

    /// Every receipt_id currently in `chio_tool_receipts` union
    /// `chio_child_receipts` on `store` (live or archive database alike).
    fn receipt_id_set(store: &SqliteReceiptStore) -> Result<BTreeSet<String>, ReceiptStoreError> {
        let connection = store.reader_connection_for_test()?;
        let mut ids = BTreeSet::new();
        let mut tool_statement = connection.prepare("SELECT receipt_id FROM chio_tool_receipts")?;
        let tool_rows = tool_statement.query_map([], |row| row.get::<_, String>(0))?;
        for id in tool_rows {
            ids.insert(id?);
        }
        let mut child_statement =
            connection.prepare("SELECT receipt_id FROM chio_child_receipts")?;
        let child_rows = child_statement.query_map([], |row| row.get::<_, String>(0))?;
        for id in child_rows {
            ids.insert(id?);
        }
        Ok(ids)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]
        #[test]
        #[ignore = "wedges CI runners; see issue #1045"]
        fn prop_retention_preserves_append_invariant(ops in prop::collection::vec(op_strategy(), 1..40)) {
            let path = unique_db_path("prop-retention");
            let archive = unique_db_path("prop-archive");
            let keypair = super::super::support::receipt_test_keypair();
            let archive_path = archive.to_str().ok_or_else(|| TestCaseError::fail("archive path"))?;

            let mut seq = 0u64;
            // The full history of every receipt id ever appended, independent
            // of where it ends up (live or archived): the ground truth that
            // invariant (4) below partitions against.
            let mut appended_ids: BTreeSet<String> = BTreeSet::new();
            {
                let store = SqliteReceiptStore::open(&path).map_err(map_err)?;
                store
                    .enable_background_checkpoints(super::super::support::signer(&keypair, 2))
                    .map_err(map_err)?;
                for (i, op) in ops.iter().enumerate() {
                    // Non-monotonic timestamps within an aged band to exercise
                    // the MAX(timestamp)-over-prefix watermark rule.
                    let ts = 100 + ((i as u64 * 7) % 13);
                    match op {
                        Op::AppendTool(n) => {
                            seq += 1;
                            let r = super::super::support::sample_receipt_with_keypair_and_timestamp(
                                &format!("pt-{seq}-{n}"), seq, ts, &keypair);
                            appended_ids.insert(r.id.clone());
                            store.append_chio_receipt_returning_seq(&r).map_err(map_err)?;
                        }
                        Op::AppendChild(n) => {
                            seq += 1;
                            let r = super::super::support::sample_child_receipt_with_keypair_seq_and_timestamp(
                                &format!("pc-{seq}-{n}"), seq, ts, &keypair);
                            appended_ids.insert(r.id.clone());
                            store.append_child_receipt_record(&r).map_err(map_err)?;
                        }
                        Op::Rotate => {
                            store.flush_receipt_writes().map_err(map_err)?;
                            // Cutoff above BOTH the aged op band (100..=112) and
                            // the probe band (2_000), so every timestamp is
                            // below the cutoff and any fully checkpointed prefix
                            // is eligible for archival. The archival watermark
                            // W = MAX(batch_end_seq) is a PREFIX rule: a
                            // checkpoint qualifies only if no entry in [1, W]
                            // has timestamp >= cutoff. A cutoff below the probe
                            // band would let the low-seq probes poison every
                            // prefix and make the co-archive-and-delete path a
                            // permanent no-op (W = 0), so the archived/live
                            // partition below would never actually be exercised.
                            store.archive_receipts_before(3_000, archive_path).map_err(map_err)?;
                            store.flush_receipt_writes().map_err(map_err)?;
                            prop_assert!(store.receipt_store_health().map_err(map_err)?.healthy);
                        }
                    }
                    // Invariant (1): the next append still succeeds.
                    seq += 1;
                    let probe = super::super::support::sample_receipt_with_keypair_and_timestamp(
                        &format!("probe-{seq}"), seq, 2_000, &keypair);
                    appended_ids.insert(probe.id.clone());
                    store.append_chio_receipt_returning_seq(&probe).map_err(map_err)?;
                }
                store.flush_receipt_writes().map_err(map_err)?;
                prop_assert!(store.receipt_store_health().map_err(map_err)?.healthy);
            }
            // Invariant (2): reopen succeeds (open-time seed re-verifies).
            // The verified-head seed runs on the commit-writer thread, so flush
            // to drain it before sampling health; until the seed completes the
            // head reads poisoned and the writer serves closed.
            let reopened = SqliteReceiptStore::open(&path).map_err(map_err)?;
            reopened.flush_receipt_writes().map_err(map_err)?;
            prop_assert!(reopened.receipt_store_health().map_err(map_err)?.healthy);

            // Invariant (4): the archived and live receipt-id sets partition
            // the full appended history. No id is lost (union covers
            // everything ever appended) and none is double-counted (the two
            // sets are disjoint). A run with no eligible rotation leaves the
            // archive set empty and everything live, which still satisfies
            // the partition.
            let live_ids = receipt_id_set(&reopened).map_err(map_err)?;
            let archive_store = SqliteReceiptStore::open(&archive).map_err(map_err)?;
            let archived_ids = receipt_id_set(&archive_store).map_err(map_err)?;
            let overlap: Vec<&String> = live_ids.intersection(&archived_ids).collect();
            prop_assert!(
                overlap.is_empty(),
                "receipt ids double-counted in both live and archive: {overlap:?}"
            );
            let union: BTreeSet<String> = live_ids.union(&archived_ids).cloned().collect();
            prop_assert_eq!(
                union,
                appended_ids,
                "archived and live receipt-id sets must partition the full appended history"
            );

            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(&archive);
        }
    }

    fn map_err(error: ReceiptStoreError) -> TestCaseError {
        TestCaseError::fail(error.to_string())
    }
}

#[test]
fn rotation_commit_guard_rejects_busy_wal_checkpoint() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::delete_archived_prefix_in_tx;

    let (_directory, store, _path, archive, identity, content) =
        prepare_archive_commit_guard_fixture("rotation-busy-wal")?;
    let archive_path = archive.to_str().ok_or("archive path invalid")?.to_string();
    let reader = rusqlite::Connection::open(&archive)?;
    let mode: String = reader.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    assert_eq!(mode.to_ascii_lowercase(), "wal");
    reader.execute_batch("BEGIN DEFERRED")?;
    reader.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get::<_, i64>(0)
    })?;
    let writer = rusqlite::Connection::open(&archive)?;
    writer.execute_batch("PRAGMA user_version = 1")?;
    drop(writer);

    let error = store
        .writer_handle()
        .run_write({
            let archive_path = archive_path.clone();
            move |connection| {
                delete_archived_prefix_in_tx(
                    connection,
                    0,
                    2,
                    150,
                    &archive_path,
                    &identity,
                    None,
                    &content,
                )
            }
        })
        .err()
        .ok_or("busy archive WAL permitted a destructive live commit")?;
    assert!(
        error.to_string().contains("WAL checkpoint remained busy"),
        "unexpected busy-WAL refusal: {error}"
    );
    assert_eq!(store.tool_receipt_count()?, 2);
    Ok(())
}

#[test]
fn rotation_commit_guard_blocks_wal_writer_until_live_commit(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::delete_archived_prefix_in_tx_with_precommit_boundary_for_test;

    let (_directory, store, _path, archive, identity, content) =
        prepare_archive_commit_guard_fixture("rotation-wal-writer")?;
    let archive_path = archive.to_str().ok_or("archive path invalid")?.to_string();
    let mode_connection = rusqlite::Connection::open(&archive)?;
    let mode: String =
        mode_connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    assert_eq!(mode.to_ascii_lowercase(), "wal");
    drop(mode_connection);

    store.writer_handle().run_write({
        let archive_path = archive_path.clone();
        move |connection| {
            let boundary_path = archive_path.clone();
            delete_archived_prefix_in_tx_with_precommit_boundary_for_test(
                connection,
                0,
                2,
                150,
                &archive_path,
                &identity,
                None,
                &content,
                move || {
                    let writer = rusqlite::Connection::open(&boundary_path)?;
                    writer.busy_timeout(Duration::ZERO)?;
                    if writer
                        .execute(
                            "UPDATE chio_retention_archive_identity SET nonce = nonce \
                             WHERE identity_slot = 1",
                            [],
                        )
                        .is_ok()
                    {
                        return Err(ReceiptStoreError::Conflict(
                            "archive WAL writer bypassed retention ownership".to_string(),
                        ));
                    }
                    Ok(())
                },
            )
        }
    })?;
    assert_eq!(store.tool_receipt_count()?, 0);
    let live = store.reader_connection_for_test()?;
    assert_eq!(
        crate::receipt_store::support::retention_watermark(&live)?,
        Some(2)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn rotation_precommit_path_substitution_rolls_back_staged_delete(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::delete_archived_prefix_in_tx_with_precommit_boundary_for_test;

    for substitution in ["replacement", "symlink", "hardlink"] {
        let (directory, store, _path, archive, identity, content) =
            prepare_archive_commit_guard_fixture(substitution)?;
        let archive_path = archive.to_str().ok_or("archive path invalid")?.to_string();
        let displaced = directory
            .path()
            .join(format!("{substitution}-displaced.sqlite3"));
        let error = store
            .writer_handle()
            .run_write({
                let archive_path = archive_path.clone();
                let displaced = displaced.clone();
                move |connection| {
                    let boundary_path = archive_path.clone();
                    let boundary_displaced = displaced.clone();
                    delete_archived_prefix_in_tx_with_precommit_boundary_for_test(
                        connection,
                        0,
                        2,
                        150,
                        &archive_path,
                        &identity,
                        None,
                        &content,
                        move || {
                            std::fs::rename(&boundary_path, &boundary_displaced)?;
                            match substitution {
                                "replacement" => {
                                    std::fs::copy(&boundary_displaced, &boundary_path)?;
                                }
                                "symlink" => {
                                    std::os::unix::fs::symlink(
                                        &boundary_displaced,
                                        &boundary_path,
                                    )?;
                                }
                                "hardlink" => {
                                    std::fs::hard_link(&boundary_displaced, &boundary_path)?;
                                }
                                _ => {
                                    return Err(ReceiptStoreError::Conflict(
                                        "unknown archive substitution fixture".to_string(),
                                    ));
                                }
                            }
                            Ok(())
                        },
                    )
                }
            })
            .err()
            .ok_or("late archive path substitution committed a live deletion")?;
        assert!(
            error
                .to_string()
                .contains("ownership changed before the live commit"),
            "unexpected {substitution} refusal: {error}"
        );
        assert_eq!(store.tool_receipt_count()?, 2);
        let live = store.reader_connection_for_test()?;
        assert_eq!(
            crate::receipt_store::support::retention_watermark(&live)?,
            None
        );
    }
    Ok(())
}

#[test]
fn repair_commit_guard_blocks_wal_writer_until_live_commit(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::retention_repair_on_writer_with_precommit_boundary_for_test;

    let (_directory, store, path, archive, identity, content) =
        prepare_archive_commit_guard_fixture("repair-wal-writer")?;
    let canonical_archive = std::fs::canonicalize(&archive)?;
    let archive_path = canonical_archive
        .to_str()
        .ok_or("archive path invalid")?
        .to_string();
    store.writer_handle().run_write({
        let archive_path = archive_path.clone();
        move |connection| {
            record_repair_archive_authority(
                connection,
                &archive_path,
                2,
                &identity,
                &content,
            )?;
            connection.execute_batch(
                "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                 DELETE FROM chio_tool_receipts WHERE seq <= 2;",
            )?;
            crate::receipt_store::support::ensure_transparency_projection_guards(connection)?;
            Ok(())
        }
    })?;
    drop(store);
    let mode_connection = rusqlite::Connection::open(&archive)?;
    let mode: String =
        mode_connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    assert_eq!(mode.to_ascii_lowercase(), "wal");
    drop(mode_connection);

    let store = SqliteReceiptStore::open_existing(&path)?;
    let mut recovery_connection = rusqlite::Connection::open(&path)?;
    let boundary_path = archive_path.clone();
    let removed = retention_repair_on_writer_with_precommit_boundary_for_test(
        &mut recovery_connection,
        &archive_path,
        move || {
            let writer = rusqlite::Connection::open(&boundary_path)?;
            writer.busy_timeout(Duration::ZERO)?;
            if writer
                .execute(
                    "UPDATE chio_retention_archive_identity SET nonce = nonce \
                     WHERE identity_slot = 1",
                    [],
                )
                .is_ok()
            {
                return Err(ReceiptStoreError::Conflict(
                    "archive WAL writer bypassed repair ownership".to_string(),
                ));
            }
            Ok(())
        },
    )?;
    drop(recovery_connection);
    assert_eq!(removed, 2);
    store.reseed_verified_head()?;
    assert!(store.receipt_store_health()?.healthy);
    Ok(())
}

/// A dependent row that a second store handle commits into the archived prefix
/// AFTER the co-archival copy but BEFORE the delete transaction takes its write
/// lock must never be deleted un-archived. The delete re-checks co-archival
/// completeness under the BEGIN IMMEDIATE lock and fails closed, so the prefix
/// and the newly inserted row survive for a later rotation to re-copy.
#[test]
fn delete_rejects_auxiliary_mutation_after_content_snapshot(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
        retention_archive_prefix_content_sha256,
    };

    let path = unique_db_path("delete-auxiliary-content-mutation");
    let archive = unique_db_path("delete-auxiliary-content-mutation-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for index in 0..2_u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("delete-auxiliary-content-mutation-{index}"),
            index + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let receipt_id = super::support::first_tool_receipt_id(&store)?;
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO settlement_reconciliations \
                     (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'reconciled', 'faithful-note', 1)",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;
    provision_test_archive_file(&archive)?;

    let refusal = store.writer_handle().run_write({
        let archive_path = archive_path.to_string();
        let receipt_id = receipt_id.clone();
        move |connection| {
            let escaped = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            create_archive_schema(connection)?;
            let archive_identity =
                crate::receipt_store::support::ensure_attached_retention_archive_identity(
                    connection, None,
                )?;
            copy_archived_prefix(connection, 2)?;
            let archive_content_sha256 =
                retention_archive_prefix_content_sha256(connection, "archive", 2)?;
            let changed = connection.execute(
                "UPDATE archive.settlement_reconciliations \
                 SET note = 'hostile-after-snapshot' WHERE receipt_id = ?1",
                rusqlite::params![receipt_id],
            )?;
            if changed != 1 {
                return Err(ReceiptStoreError::Conflict(
                    "fixture did not mutate the archived settlement row".to_string(),
                ));
            }
            connection.execute_batch("DETACH DATABASE archive")?;
            restrict_test_archive_file(std::path::Path::new(&archive_path))?;
            delete_archived_prefix_in_tx(
                connection,
                0,
                2,
                150,
                &archive_path,
                &archive_identity,
                None,
                &archive_content_sha256,
            )
            .err()
            .map(|error| error.to_string())
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(
                    "final delete trusted mutated auxiliary archive content".to_string(),
                )
            })
        }
    })?;
    assert!(
        refusal.contains("content digest"),
        "unexpected final-delete refusal: {refusal}"
    );
    assert_eq!(store.tool_receipt_count()?, 2, "live prefix must survive");
    let live = store.reader_connection_for_test()?;
    let settlement_rows: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(settlement_rows, 1, "live auxiliary evidence must survive");
    assert_eq!(
        crate::receipt_store::support::retention_watermark(&live)?,
        None,
        "rejected delete must not seal a watermark"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn delete_fails_closed_when_a_dependent_row_escapes_the_copy(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
    };
    let path = unique_db_path("toctou-delete");
    let archive = unique_db_path("toctou-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("toctou-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let receipt_id = super::support::first_tool_receipt_id(&store)?;
    provision_test_archive_file(&archive)?;

    // Co-archive the aged [1,2] prefix, then simulate a concurrent handle
    // committing a settlement reconciliation for a receipt in that prefix after
    // the copy has run, and only then attempt the delete.
    let fail_closed = store.writer_handle().run_write({
        let archive_path = archive_path.to_string();
        let receipt_id = receipt_id.clone();
        move |connection| {
            let escaped = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            create_archive_schema(connection)?;
            let archive_identity =
                crate::receipt_store::support::ensure_attached_retention_archive_identity(
                    connection, None,
                )?;
            copy_archived_prefix(connection, 2)?;
            let archive_content_sha256 =
                crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
                    connection,
                    "archive",
                    2,
                )?;
            // The archive now faithfully holds [1,2]. A second writer commits a
            // dependent row into the archived prefix, unseen by the copy above.
            connection.execute(
                "INSERT INTO settlement_reconciliations (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'reconciled', NULL, 1)",
                rusqlite::params![receipt_id],
            )?;
            connection.execute_batch("DETACH DATABASE archive")?;
            restrict_test_archive_file(std::path::Path::new(&archive_path))?;
            let result = delete_archived_prefix_in_tx(
                connection,
                0,
                2,
                150,
                &archive_path,
                &archive_identity,
                None,
                &archive_content_sha256,
            );
            Ok(result.is_err())
        }
    })?;
    assert!(
        fail_closed,
        "the delete must fail closed when a dependent row is not in the archive"
    );

    // Fail-closed: the prefix and the un-archived reconciliation both survive.
    let live = store.reader_connection_for_test()?;
    let live_receipts: i64 = live.query_row(
        "SELECT COUNT(*) FROM chio_tool_receipts WHERE seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_receipts, 2,
        "the archived prefix must survive the refusal"
    );
    let live_settlement: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_settlement, 1,
        "the un-archived reconciliation must survive the refusal"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn delete_fails_closed_when_a_retry_enters_after_the_archive_copy(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
    };
    let path = unique_db_path("toctou-retry-delete");
    let archive = unique_db_path("toctou-retry-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("toctou-retry-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let receipt_id = super::support::first_tool_receipt_id(&store)?;
    let _retry_store = crate::SqliteSettlementRetryStore::open_alongside(&store)?;
    provision_test_archive_file(&archive)?;

    let fail_closed = store.writer_handle().run_write({
        let archive_path = archive_path.to_string();
        let receipt_id = receipt_id.clone();
        move |connection| {
            let escaped = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            create_archive_schema(connection)?;
            let archive_identity =
                crate::receipt_store::support::ensure_attached_retention_archive_identity(
                    connection, None,
                )?;
            copy_archived_prefix(connection, 2)?;
            let archive_content_sha256 =
                crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
                    connection, "archive", 2,
                )?;
            connection.execute(
                "INSERT INTO settle_attempts \
                 (receipt_id, finalized_at, attempts, next_visible_at, last_reason, updated_at) \
                 VALUES (?1, 100, 1, 10, 'late retry', 10)",
                rusqlite::params![receipt_id],
            )?;
            connection.execute_batch("DETACH DATABASE archive")?;
            restrict_test_archive_file(std::path::Path::new(&archive_path))?;
            let result = delete_archived_prefix_in_tx(
                connection,
                0,
                2,
                150,
                &archive_path,
                &archive_identity,
                None,
                &archive_content_sha256,
            );
            Ok(result.is_err())
        }
    })?;
    assert!(
        fail_closed,
        "the delete must refuse a retry inserted after the archive copy"
    );

    let live = store.reader_connection_for_test()?;
    let live_receipts: i64 = live.query_row(
        "SELECT COUNT(*) FROM chio_tool_receipts WHERE seq <= 2",
        [],
        |row| row.get(0),
    )?;
    let retry_rows: i64 = live.query_row(
        "SELECT COUNT(*) FROM settle_attempts WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(live_receipts, 2);
    assert_eq!(retry_rows, 1);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn rotation_rejects_archive_tables_without_required_key_constraints(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("malformed-archive-schema");
    let archive = unique_db_path("malformed-archive-schema-target");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("malformed-archive-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    let seeded = rusqlite::Connection::open(&archive)?;
    seeded.execute_batch(
        "CREATE TABLE chio_tool_receipts ( \
             seq INTEGER, receipt_id TEXT, timestamp INTEGER, capability_id TEXT, \
             subject_key TEXT, issuer_key TEXT, grant_index INTEGER, tool_server TEXT, \
             tool_name TEXT, decision_kind TEXT, policy_hash TEXT, content_hash TEXT, \
             raw_json TEXT, tenant_id TEXT \
         ); \
         INSERT INTO chio_tool_receipts \
             (seq, receipt_id, timestamp, capability_id, tool_server, tool_name, \
              decision_kind, policy_hash, content_hash, raw_json) \
         VALUES \
             (1, 'duplicate-id', 1, 'cap', 'server', 'tool', 'allow', 'policy', 'a', '{}'), \
             (1, 'duplicate-id', 1, 'cap', 'server', 'tool', 'allow', 'policy', 'b', '{}');",
    )?;
    drop(seeded);
    restrict_test_archive_file(&archive)?;

    let result = store.archive_receipts_before(150, archive_path);
    assert!(matches!(
        result,
        Err(ReceiptStoreError::Conflict(message))
            if message.contains("archive table chio_tool_receipts")
    ));
    assert_eq!(
        store.tool_receipt_count()?,
        2,
        "a malformed archive schema must leave the live prefix intact"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn rotation_rejects_an_orphaned_iou_before_creating_the_archive(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::retention_watermark;

    let path = unique_db_path("preflight-orphaned-iou");
    let archive = unique_db_path("preflight-orphaned-iou-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for index in 0..2_u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("preflight-orphaned-iou-{index}"),
            index + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // The receipt-store bootstrap creates the co-located IOU table, but this
    // rotation is intentionally the first receipt-backed IOU consumer. Seed an
    // orphan through a raw connection before the ownership INSERT trigger has
    // ever been installed.
    let raw = rusqlite::Connection::open(&path)?;
    raw.execute(
        "INSERT INTO iou_envelope \
         (receipt_id, iou_id, receipt_timestamp, tenant_id, amount_units, currency, \
          issuer_key, canonical_json) \
         VALUES ('orphan-before-rotation', 'iou-orphan-before-rotation', 100, NULL, 1, \
                 'USD', 'issuer', '{}')",
        [],
    )?;
    drop(raw);

    let result = store.archive_receipts_before(150, archive_path);
    assert!(matches!(
        result,
        Err(ReceiptStoreError::Conflict(message))
            if message.contains("IOU envelope exists without its exact authoritative live receipt")
    ));
    assert!(
        !archive.exists(),
        "ownership preflight must fail before the archive file is created or mutated"
    );
    assert_eq!(
        store.tool_receipt_count()?,
        2,
        "an orphaned IOU must leave the live receipt prefix intact"
    );
    let live = store.reader_connection_for_test()?;
    assert_eq!(
        retention_watermark(&live)?,
        None,
        "an orphaned IOU must not advance retention"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn delete_rechecks_iou_ownership_after_the_archive_copy() -> Result<(), Box<dyn std::error::Error>>
{
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
    };
    use crate::receipt_store::support::retention_watermark;

    let path = unique_db_path("late-orphaned-iou");
    let archive = unique_db_path("late-orphaned-iou-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for index in 0..2_u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("late-orphaned-iou-{index}"),
            index + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    drop(SqliteIouEnvelopeStore::open_alongside(&store)?);
    provision_test_archive_file(&archive)?;

    let refused = store.writer_handle().run_write({
        let archive_path = archive_path.to_string();
        move |connection| {
            let escaped_archive = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
            create_archive_schema(connection)?;
            let archive_identity =
                crate::receipt_store::support::ensure_attached_retention_archive_identity(
                    connection, None,
                )?;
            copy_archived_prefix(connection, 2)?;
            let archive_content_sha256 =
                crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
                    connection, "archive", 2,
                )?;

            // Simulate a second process tampering with the ownership guard and
            // committing an orphan after the archive copy but before the final
            // delete transaction acquires its write lock.
            connection.execute_batch(
                "DROP TRIGGER IF EXISTS iou_envelope_require_live_receipt_insert; \
                 INSERT INTO iou_envelope \
                   (receipt_id, iou_id, receipt_timestamp, tenant_id, amount_units, currency, \
                    issuer_key, canonical_json) \
                 VALUES ('orphan-after-copy', 'iou-orphan-after-copy', 100, NULL, 1, \
                         'USD', 'issuer', '{}');",
            )?;
            connection.execute_batch("DETACH DATABASE archive")?;
            restrict_test_archive_file(std::path::Path::new(&archive_path))?;
            let result = delete_archived_prefix_in_tx(
                connection,
                0,
                2,
                150,
                &archive_path,
                &archive_identity,
                None,
                &archive_content_sha256,
            );
            Ok(matches!(
                result,
                Err(ReceiptStoreError::Conflict(message))
                    if message.contains(
                        "IOU envelope exists without its exact authoritative live receipt"
                    )
            ))
        }
    })?;
    assert!(
        refused,
        "the final delete transaction must reject an IOU orphan inserted after archive copy"
    );
    assert_eq!(
        store.tool_receipt_count()?,
        2,
        "the late IOU orphan must leave the live receipt prefix intact"
    );
    let live = store.reader_connection_for_test()?;
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "the late IOU orphan must leave the claim log intact"
    );
    assert_eq!(
        retention_watermark(&live)?,
        None,
        "the late IOU orphan must not advance retention"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}
