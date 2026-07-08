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

/// Force every pooled reader connection into `PRAGMA query_only = ON`, then
/// exercise the routed write surface: all writes must still succeed (they run
/// on the writer connection), while a direct write through the reader pool
/// must fail. r2d2 creates connections lazily up to max_size, so grabbing all
/// DEFAULT_READER_POOL_MAX_SIZE connections at once pins the whole pool.
#[test]
fn reader_pool_never_begins_a_write_transaction() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-reader-pool-readonly");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;

    {
        let mut held = Vec::new();
        for _ in 0..crate::DEFAULT_READER_POOL_MAX_SIZE {
            held.push(store.connection()?);
        }
        for connection in &held {
            connection.execute_batch("PRAGMA query_only = ON;")?;
        }
    }

    // Control: the reader pool now refuses writes.
    {
        let connection = store.connection()?;
        let denied = connection.execute("CREATE TABLE reader_probe (x INTEGER)", []);
        assert!(denied.is_err(), "reader pool accepted a write");
    }

    // The routed write surface still works end to end.
    let receipt = sample_receipt_with_keypair("rcpt-ro-pool-0", 1, &keypair);
    ReceiptStore::append_chio_receipt_returning_seq(&store, &receipt)?.ok_or("expected seq")?;
    let child = sample_child_receipt_with_keypair_and_timestamp("child-ro-pool-0", 2, &keypair);
    store.append_child_receipt_record(&child)?;
    store.record_session_anchor_record(
        "sess-ro",
        "anchor-ro",
        "fp-ro",
        3,
        None,
        &serde_json::json!({"anchor": "ro"}),
    )?;
    // `record_request_lineage_record` validates `lineage_json` against
    // `chio_core::session::RequestLineageRecord` (requires a `schema` field
    // among others), unlike `record_session_anchor_record`'s unvalidated
    // passthrough JSON above; `request_lineage_json` builds a
    // schema-compliant payload.
    store.record_request_lineage_record(
        "sess-ro",
        "req-ro",
        None,
        Some("anchor-ro"),
        4,
        None,
        &request_lineage_json("req-ro", "anchor-ro", None),
    )?;
    let _links = store.list_receipt_lineage_statement_links("rcpt-ro-pool-0")?;
    let _verification = store.receipt_lineage_verification("rcpt-ro-pool-0")?;
    store.create_next_receipt_checkpoint(2, &keypair)?;

    let iou_store = crate::SqliteIouEnvelopeStore::open_alongside(&store)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    drop(iou_store); // migration DDL ran on the writer; construction succeeding is the assertion

    let _ = fs::remove_file(path);
    Ok(())
}
