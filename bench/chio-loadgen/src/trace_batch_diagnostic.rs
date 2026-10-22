use super::*;
use std::collections::BTreeSet;
use std::io::Error;
use std::path::PathBuf;
use std::sync::Barrier;

use chio_core::canonical::canonical_json_bytes;
use chio_kernel::ReceiptStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn sqlite_batches_concurrent_kernel_receipts() -> TestResult {
    const WORKERS: usize = 16;
    const ROUNDS: usize = 4;
    let evidence = PathBuf::from(
        std::env::var_os("CHIO_TRACE_BATCH_EVIDENCE_DIR")
            .ok_or_else(|| Error::other("CHIO_TRACE_BATCH_EVIDENCE_DIR is required"))?,
    );
    std::fs::create_dir_all(&evidence)?;
    let database = evidence.join("receipts.sqlite");
    assert!(!database.exists(), "diagnostic requires a fresh database");
    let config = LoadgenConfig {
        arrival_rate_hz: 100,
        duration: Duration::from_secs(120),
        tool_latency: Duration::from_millis(2),
        store: StoreBacking::Sqlite { path: database },
        p99_budget: Duration::from_millis(50),
        rss_growth_budget_bytes: 64 * 1024 * 1024,
    };
    let stack = StackHarness::boot(&config)?;
    let mut receipts = Vec::new();
    for _ in 0..ROUNDS {
        let barrier = Barrier::new(WORKERS);
        let responses = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..WORKERS)
                .map(|_| {
                    scope.spawn(|| {
                        let request = stack.build_request();
                        barrier.wait();
                        stack
                            .runtime
                            .block_on(stack.kernel.evaluate_tool_call(&request))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| Error::other("dispatch worker panicked"))
                })
                .collect::<Result<Vec<_>, _>>()
        })?;
        for response in responses {
            let response = response?;
            std::fs::write(
                evidence.join(format!("receipt-{}.json", receipts.len())),
                canonical_json_bytes(&response.receipt)?,
            )?;
            assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
            assert!(response.receipt.verify_signature()?);
            receipts.push(response.receipt);
        }
    }
    stack.flush_durable()?;
    let store = stack
        .store()
        .ok_or_else(|| Error::other("durable store missing"))?;
    let mirror = stack.kernel.receipt_log();
    let ids: BTreeSet<_> = receipts.iter().map(|receipt| receipt.id.clone()).collect();
    assert_eq!(ids.len(), WORKERS * ROUNDS);
    assert_eq!(mirror.len(), ids.len());
    for receipt in &receipts {
        let durable = store
            .load_chio_receipt(&receipt.id)?
            .ok_or_else(|| Error::other("acknowledged receipt missing from SQLite"))?;
        assert_eq!(
            canonical_json_bytes(receipt)?,
            canonical_json_bytes(&durable)?
        );
        let projected = mirror
            .iter()
            .find(|entry| entry.id == receipt.id)
            .ok_or_else(|| Error::other("acknowledged receipt missing from mirror"))?;
        assert_eq!(
            canonical_json_bytes(receipt)?,
            canonical_json_bytes(projected)?
        );
    }
    let maximum_batch = chio_store_sqlite::receipt_store::trace_batch_diagnostic_max();
    std::fs::write(
        evidence.join("result.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"receipts": ids, "maximum_committed_batch": maximum_batch}),
        )?,
    )?;
    assert!(
        maximum_batch > 1,
        "no real SQLite batch contained multiple receipts"
    );
    Ok(())
}
