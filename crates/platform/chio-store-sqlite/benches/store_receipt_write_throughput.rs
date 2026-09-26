use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
};
use chio_store_sqlite::SqliteReceiptStore;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

const RECEIPTS_PER_BATCH: usize = 64;
const APPENDER_THREADS: usize = 8;

/// Receipts already in the table before the populated group's first measured
/// batch. Append cost is dominated by `fsync` and by the unique-index insert,
/// and only the second of those grows with history, so the two groups bracket
/// the append path rather than duplicating it.
const POPULATED_RECEIPTS: u64 = 20_000;

fn unique_db_path() -> std::path::PathBuf {
    let nonce = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(error) => fail_bench(&format!("time before epoch: {error}")),
    };
    std::env::temp_dir().join(format!("chio-store-receipt-write-bench-{nonce}.sqlite3"))
}

fn receipt_for_index(index: u64) -> ChioReceipt {
    let keypair = Keypair::generate();
    let action = match ToolCallAction::from_parameters(serde_json::json!({
        "index": index
    })) {
        Ok(action) => action,
        Err(error) => fail_bench(&format!("valid tool call action: {error}")),
    };
    match ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("bench-receipt-{index}"),
            timestamp: index,
            capability_id: format!("bench-capability-{index}"),
            tool_server: "bench-server".to_string(),
            tool_name: "bench-tool".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("bench-content-{index}"),
            policy_hash: "bench-policy".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    ) {
        Ok(receipt) => receipt,
        Err(error) => fail_bench(&format!("sign receipt: {error}")),
    }
}

fn bench_store_receipt_write_throughput(c: &mut Criterion) {
    measure_append_throughput(c, "store_receipt_write_throughput", 0);
    measure_append_throughput(
        c,
        "store_receipt_write_throughput_populated",
        POPULATED_RECEIPTS,
    );
}

fn measure_append_throughput(c: &mut Criterion, name: &str, populate: u64) {
    let path = unique_db_path();
    let store = match SqliteReceiptStore::open(&path) {
        Ok(store) => store,
        Err(error) => fail_bench(&format!("open sqlite receipt store: {error}")),
    };
    let receipt_index = AtomicU64::new(1);

    for _ in 0..populate {
        let index = receipt_index.fetch_add(1, Ordering::Relaxed);
        if let Err(error) = store.append_chio_receipt_returning_seq(&receipt_for_index(index)) {
            fail_bench(&format!("populate receipt: {error}"));
        }
    }
    if populate > 0 {
        if let Err(error) = store.flush_receipt_writes() {
            fail_bench(&format!("flush populated receipts: {error}"));
        }
    }

    c.bench_function(name, |b| {
        b.iter_batched(
            || {
                let first_index =
                    receipt_index.fetch_add(RECEIPTS_PER_BATCH as u64, Ordering::Relaxed);
                (0..RECEIPTS_PER_BATCH)
                    .map(|offset| receipt_for_index(first_index + offset as u64))
                    .collect::<Vec<_>>()
            },
            |receipts| {
                let seqs = append_receipts_concurrently(&store, &receipts);
                black_box(seqs);
            },
            BatchSize::SmallInput,
        );
    });

    if let Err(error) = store.flush_receipt_writes() {
        fail_bench(&format!("flush receipt writes: {error}"));
    }
    let _ = std::fs::remove_file(path);
}

fn append_receipts_concurrently(store: &SqliteReceiptStore, receipts: &[ChioReceipt]) -> Vec<u64> {
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for chunk in receipts.chunks(RECEIPTS_PER_BATCH / APPENDER_THREADS) {
            handles.push(scope.spawn(move || {
                chunk
                    .iter()
                    .map(
                        |receipt| match store.append_chio_receipt_returning_seq(receipt) {
                            Ok(seq) => seq,
                            Err(error) => fail_bench(&format!("append receipt: {error}")),
                        },
                    )
                    .collect::<Vec<_>>()
            }));
        }

        handles
            .into_iter()
            .flat_map(|handle| match handle.join() {
                Ok(seqs) => seqs,
                Err(_) => fail_bench("append thread panicked"),
            })
            .collect()
    })
}

fn fail_bench(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

criterion_group!(benches, bench_store_receipt_write_throughput);
criterion_main!(benches);
