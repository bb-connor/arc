use super::super::*;
use super::support::*;
use chio_kernel::ReceiptStore;

/// {Append, Write, Flush} from many threads: every Write closure executes on
/// exactly one thread (single-writer serialization), all appends commit, and
/// inflight accounting drains to zero (no lost pre-send increments).
#[test]
fn writer_commands_serialize_and_never_lose_inflight_accounting(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-single-writer-stress");
    let store = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);

    // `std::thread::ThreadId` implements `Hash + Eq` but not `Ord`, so a
    // `HashSet` (not `BTreeSet`) tracks the distinct writer thread here.
    let writer_threads: std::sync::Arc<Mutex<std::collections::HashSet<std::thread::ThreadId>>> =
        std::sync::Arc::new(Mutex::new(std::collections::HashSet::new()));
    let mut handles = Vec::new();

    for worker in 0..4u32 {
        let store = std::sync::Arc::clone(&store);
        let writer_threads = std::sync::Arc::clone(&writer_threads);
        handles.push(thread::spawn(move || -> Result<(), String> {
            for i in 0..25u32 {
                match i % 3 {
                    0 => {
                        let receipt = sample_receipt_with_id(&format!("rcpt-stress-{worker}-{i}"));
                        ReceiptStore::append_chio_receipt_returning_seq(store.as_ref(), &receipt)
                            .map_err(|error| error.to_string())?;
                    }
                    1 => {
                        let observed = store
                            .writer_handle()
                            .run_write(|_connection| Ok(std::thread::current().id()))
                            .map_err(|error| error.to_string())?;
                        writer_threads
                            .lock()
                            .map_err(|_| "writer thread set poisoned".to_string())?
                            .insert(observed);
                    }
                    _ => {
                        store
                            .flush_receipt_writes()
                            .map_err(|error| error.to_string())?;
                    }
                }
            }
            Ok(())
        }));
    }
    for handle in handles {
        handle
            .join()
            .map_err(|_| "stress worker panicked")?
            .map_err(std::io::Error::other)?;
    }

    // Single-writer serialization: every Write job ran on one thread.
    let distinct = writer_threads
        .lock()
        .map_err(|_| "writer thread set poisoned")?
        .len();
    assert_eq!(
        distinct, 1,
        "expected exactly one writer thread, got {distinct}"
    );

    // Quiesce, then check the books: nothing in flight, all appends counted.
    store.flush_receipt_writes()?;
    let health = store.receipt_store_health()?;
    assert_eq!(health.writer.inflight, 0, "inflight must drain to zero");
    // 4 workers x 25 ops, i % 3 == 0 on 9 of 25 iterations per worker.
    assert_eq!(health.writer.committed_total, 4 * 9);
    assert_eq!(health.writer.failed_total, 0);
    assert_eq!(health.latest_committed_entry_seq, 4 * 9);

    let _ = fs::remove_file(path);
    Ok(())
}
