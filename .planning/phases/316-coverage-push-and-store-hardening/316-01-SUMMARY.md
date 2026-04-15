# Summary 316-01

Phase `316` replaced the old single-connection `SqliteReceiptStore` backend
with an `r2d2_sqlite` pool, kept the existing WAL / synchronous / busy-timeout
initialization on every pooled connection, and moved the hot runtime receipt
write path onto pooled handles instead of one cached `rusqlite::Connection`.

The runtime-facing write surface now has a real shared-store lane:

- `append_arc_receipt_returning_seq`
- `append_child_receipt_record`
- `record_capability_snapshot`
- `store_checkpoint`

The crate-level verification is green:

- `cargo check -p arc-store-sqlite`
- `cargo check -p arc-kernel`
- `cargo test -p arc-store-sqlite`
- `cargo test -p arc-store-sqlite append_arc_receipt_returning_seq_supports_concurrent_writers -- --nocapture`

The new concurrency test writes receipts through one `Arc<SqliteReceiptStore>`
instance across multiple threads and confirms the inserts succeed with unique
sequence numbers and the expected final receipt count.
