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
    let mut child_statement = connection.prepare("SELECT receipt_id FROM chio_child_receipts")?;
    let child_rows = child_statement.query_map([], |row| row.get::<_, String>(0))?;
    for id in child_rows {
        ids.insert(id?);
    }
    Ok(ids)
}

// The proptest! macro applies PROPTEST_CASES after its local config. CI's
// 256-case setting therefore overrides the former 24-case budget and
// multiplies synchronous=FULL writes and full-chain health folds. A direct
// runner keeps this expensive rotation invariant at 24 cases without
// changing the CI budget for other properties. Issue #1045 retains the
// runner-grade liveness question until the hosted lane completes.
#[test]
fn prop_retention_preserves_append_invariant() -> Result<(), Box<dyn std::error::Error>> {
    let diagnostic_cases = std::env::var("CHIO_RETENTION_CASES");
    let cases = match diagnostic_cases.as_deref() {
        Ok(value) => value
            .parse::<u32>()
            .ok()
            .filter(|cases| (1..=256).contains(cases))
            .ok_or("CHIO_RETENTION_CASES must be between 1 and 256")?,
        Err(std::env::VarError::NotPresent) => 24,
        Err(error) => return Err(error.to_string().into()),
    };
    let trace = diagnostic_cases.is_ok();
    let next_case = std::sync::atomic::AtomicUsize::new(0);
    let mut config = ProptestConfig::with_cases(cases);
    config.source_file = Some(file!());
    // Preserve the saved counterexamples when this property moves modules.
    config.failure_persistence = Some(Box::new(
        proptest::test_runner::FileFailurePersistence::Direct(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/proptest-regressions/receipt_store/tests/retention.txt"
        )),
    ));
    config.test_name = Some(concat!(
        module_path!(),
        "::prop_retention_preserves_append_invariant"
    ));
    let mut runner = proptest::test_runner::TestRunner::new(config);
    runner.run(&prop::collection::vec(op_strategy(), 1..40), |ops| {
        let case = next_case.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let phase = |name: &str| {
            if trace { eprintln!("retention case={case} phase={name}"); }
        };
        phase("begin");
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
            phase("open");
            let store = SqliteReceiptStore::open(&path).map_err(map_err)?;
            store
                .enable_background_checkpoints(super::super::support::signer(&keypair, 2))
                .map_err(map_err)?;
            for (i, op) in ops.iter().enumerate() {
                // Non-monotonic timestamps within an aged band to exercise
                // the MAX(timestamp)-over-prefix watermark rule.
                let ts = 100 + ((i as u64 * 7) % 13);
                if trace { eprintln!("retention case={case} operation={i} kind={op:?}"); }
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
                        phase("flush");
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
                        phase("rotate");
                        store.archive_receipts_before(3_000, archive_path).map_err(map_err)?;
                        // Invariant (3): health stays healthy across the
                        // rotation (folds set-equality and chain
                        // integrity). Asserted at rotation boundaries and
                        // after the final op rather than per append: the
                        // fold re-verifies the whole chain, and rotation is
                        // the transition this invariant guards.
                        phase("flush");
                        store.flush_receipt_writes().map_err(map_err)?;
                        phase("health");
                        prop_assert!(store.receipt_store_health().map_err(map_err)?.healthy);
                    }
                }
                phase("probe");
                // Invariant (1): the next append still succeeds.
                seq += 1;
                let probe = super::super::support::sample_receipt_with_keypair_and_timestamp(
                    &format!("probe-{seq}"), seq, 2_000, &keypair);
                appended_ids.insert(probe.id.clone());
                store.append_chio_receipt_returning_seq(&probe).map_err(map_err)?;
            }
            // Invariant (3) at the end of the run: the final interleaving
            // (including trailing un-rotated appends) leaves a healthy
            // store.
            phase("flush");
                        store.flush_receipt_writes().map_err(map_err)?;
            phase("health");
                        prop_assert!(store.receipt_store_health().map_err(map_err)?.healthy);
            phase("teardown-original");
        }
        phase("reopen");
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
        phase("read-live-ids");
        let live_ids = receipt_id_set(&reopened).map_err(map_err)?;
        let archive_store = SqliteReceiptStore::open(&archive).map_err(map_err)?;
        let reopened_writer = std::sync::Arc::downgrade(&reopened.receipt_commit_actor.worker);
        let archive_writer = std::sync::Arc::downgrade(&archive_store.receipt_commit_actor.worker);
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

        phase("teardown-archive");
        drop(archive_store);
        phase("teardown-reopened");
        drop(reopened);
        prop_assert!(
            reopened_writer.upgrade().is_none() && archive_writer.upgrade().is_none(),
            "case completion must follow both writer owners' teardown"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&archive);
        phase("complete");
        Ok(())
    })?;
    Ok(())
}

fn map_err(error: ReceiptStoreError) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}
