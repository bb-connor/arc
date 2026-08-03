use super::super::*;
use super::support::*;

const MEASURED_APPENDS: usize = 200;
const MAX_RATIO: f64 = 4.0;
const DEFAULT_BASE_HISTORY: usize = 100;
const DEFAULT_MID_HISTORY: usize = 500;
const DEFAULT_LARGE_HISTORY: usize = 1_000;
const RELEASE_BASE_HISTORY: usize = 1_000;
const RELEASE_MID_HISTORY: usize = 100_000;
const REQUIRED_RELEASE_HISTORY: usize = 1_000_000;
const SEED_WORKERS: usize = 64;

fn seed_history(
    store: &Arc<SqliteReceiptStore>,
    history: usize,
    label: &str,
    keypair: &Keypair,
) -> Result<(), Box<dyn std::error::Error>> {
    let worker_count = SEED_WORKERS.min(history.max(1));
    let results = std::thread::scope(|scope| {
        (0..worker_count)
            .map(|worker| {
                let store = Arc::clone(store);
                let keypair = keypair.clone();
                scope.spawn(move || {
                    for i in (worker..history).step_by(worker_count) {
                        let receipt = sample_receipt_with_keypair(
                            &format!("rcpt-scale-{label}-seed-{i}"),
                            (i + 1) as u64,
                            &keypair,
                        );
                        store.append_chio_receipt_returning_seq(&receipt)?;
                    }
                    Ok::<(), ReceiptStoreError>(())
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join())
            .collect::<Vec<_>>()
    });
    for result in results {
        result.map_err(|_| std::io::Error::other("scale seed worker panicked"))??;
    }
    Ok(())
}

fn mean_append_nanos_at_history(
    history: usize,
    label: &str,
) -> Result<f64, Box<dyn std::error::Error>> {
    let path = unique_db_path(&format!("chio-scale-{label}"));
    let keypair = receipt_test_keypair();
    let store = Arc::new(SqliteReceiptStore::open(&path)?);
    // Background checkpoints on at the ADR-0008 default batch size, so the
    // measurement covers the full production hot path including checkpoint
    // construction on the writer thread.
    store.enable_background_checkpoints(BackgroundCheckpointSigner {
        backend: Arc::new(chio_core::crypto::Ed25519Backend::new(keypair.clone())),
        max_batch: 100,
    })?;

    seed_history(&store, history, label, &keypair)?;
    store.flush_receipt_writes()?;

    let started = std::time::Instant::now();
    for i in 0..MEASURED_APPENDS {
        let receipt = sample_receipt_with_keypair(
            &format!("rcpt-scale-{label}-measure-{i}"),
            (history + i + 1) as u64,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let elapsed = started.elapsed();

    drop(store);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(format!("{}-wal", path.display()));
    let _ = fs::remove_file(format!("{}-shm", path.display()));
    Ok(elapsed.as_nanos() as f64 / MEASURED_APPENDS as f64)
}

/// Scale proof: per-append cost is batch-bounded (O(b)), not history-bounded.
/// The default profile is bounded and runs in the ordinary test suite. The
/// release qualification profile is executable with:
/// `CHIO_RECEIPT_SCALE_HISTORY=1000000 cargo test -p chio-store-sqlite --release append_scale_proof -- --nocapture`
#[test]
fn append_scale_proof_is_batch_bounded_across_history_sizes(
) -> Result<(), Box<dyn std::error::Error>> {
    let requested_large = std::env::var("CHIO_RECEIPT_SCALE_HISTORY")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()?;
    let (base_history, mid_history, large_history) = match requested_large {
        Some(REQUIRED_RELEASE_HISTORY) => (
            RELEASE_BASE_HISTORY,
            RELEASE_MID_HISTORY,
            REQUIRED_RELEASE_HISTORY,
        ),
        Some(other) => {
            return Err(format!(
                "CHIO_RECEIPT_SCALE_HISTORY must be {REQUIRED_RELEASE_HISTORY}, got {other}"
            )
            .into());
        }
        None => (
            DEFAULT_BASE_HISTORY,
            DEFAULT_MID_HISTORY,
            DEFAULT_LARGE_HISTORY,
        ),
    };
    let at_base = mean_append_nanos_at_history(base_history, "base")?;
    let at_mid = mean_append_nanos_at_history(mid_history, "mid")?;
    let at_large = mean_append_nanos_at_history(large_history, "large")?;

    println!(
        "append mean ns/op: N={base_history}={at_base:.0} N={mid_history}={at_mid:.0} N={large_history}={at_large:.0}"
    );
    println!(
        "ratios vs base: mid={:.2}x large={:.2}x (RFC target 2x, asserted bound {MAX_RATIO}x)",
        at_mid / at_base,
        at_large / at_base
    );

    assert!(
        at_mid / at_base <= MAX_RATIO,
        "append at N={mid_history} is {:.2}x of N={base_history} (bound {MAX_RATIO}x): per-append work grew with history",
        at_mid / at_base
    );
    assert!(
        at_large / at_base <= MAX_RATIO,
        "append at N={large_history} is {:.2}x of N={base_history} (bound {MAX_RATIO}x): per-append work grew with history",
        at_large / at_base
    );
    Ok(())
}
