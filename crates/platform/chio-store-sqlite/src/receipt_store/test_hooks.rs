use std::sync::atomic::{AtomicBool, Ordering};

/// When set, `append_receipt_batch` fails the batch between the receipt
/// insert and the lineage ensure, proving the fold is one transaction.
pub(crate) static FAIL_BETWEEN_RECEIPT_AND_LINEAGE: AtomicBool = AtomicBool::new(false);

pub(crate) fn fail_between_receipt_and_lineage() -> bool {
    FAIL_BETWEEN_RECEIPT_AND_LINEAGE.load(Ordering::SeqCst)
}

/// When set, `maybe_build_checkpoint` panics after computing the
/// checkpoint body but before opening its write transaction, proving the
/// background-checkpoint catch_unwind wrap keeps the writer actor alive
/// and leaves `head.latest_checkpoint` unadvanced. Tests run in parallel
/// within this binary and this flag is process-global, so the panic is
/// additionally gated on `PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH`
/// (a `max_batch` value no other test in this crate uses): a test whose
/// signer does not use that exact batch size never panics, even if the
/// flag happens to be `true` while it runs.
pub(crate) static PANIC_DURING_CHECKPOINT_BUILD: AtomicBool = AtomicBool::new(false);

pub(crate) const PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH: u64 = 5;

pub(crate) fn panic_during_checkpoint_build(max_batch: u64) -> bool {
    max_batch == PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH
        && PANIC_DURING_CHECKPOINT_BUILD.load(Ordering::SeqCst)
}

/// When set, `maybe_build_checkpoint` returns a fail-closed `Err` (a
/// NON-panic checkpoint-build failure) for a signer using
/// `FAIL_CHECKPOINT_BUILD_MARKER_MAX_BATCH`, proving a build failure is
/// surfaced to a co-drained flush waiter (the flush-as-checkpoint
/// barrier). It uses a DISTINCT marker from
/// `PANIC_DURING_CHECKPOINT_BUILD` so the two process-global flags cannot
/// interfere across the crate's parallel tests.
pub(crate) static FAIL_CHECKPOINT_BUILD: AtomicBool = AtomicBool::new(false);

pub(crate) const FAIL_CHECKPOINT_BUILD_MARKER_MAX_BATCH: u64 = 7;

pub(crate) fn fail_checkpoint_build(max_batch: u64) -> bool {
    max_batch == FAIL_CHECKPOINT_BUILD_MARKER_MAX_BATCH
        && FAIL_CHECKPOINT_BUILD.load(Ordering::SeqCst)
}

/// When set, `append_receipt_batch` panics before inserting the next
/// request in the batch, proving the append-batch catch_unwind wrap in
/// `receipt_commit_actor_loop` keeps the writer actor alive and fans out
/// a typed error to every request in the interrupted batch. Gated on a
/// `content_hash` marker for the same cross-test isolation reason as
/// `PANIC_DURING_CHECKPOINT_BUILD` above (this flag is process-global,
/// and other tests append receipts concurrently in the same binary).
/// `content_hash`, not `receipt.id`, is the marker: `ChioReceipt::sign`
/// always overwrites `id` with a content-derived hash
/// (`prepare_receipt_body_for_signing`), so a caller-chosen `id` string
/// does not survive signing, but a caller-chosen `content_hash` does.
pub(crate) static PANIC_DURING_APPEND_BATCH: AtomicBool = AtomicBool::new(false);

pub(crate) const PANIC_DURING_APPEND_BATCH_MARKER_RECEIPT_ID: &str =
    "rcpt-test-hook-panic-during-append-batch";

/// `sample_receipt_with_id(id)` sets `content_hash: format!("content-{id}")`;
/// this must match that pattern for `PANIC_DURING_APPEND_BATCH_MARKER_RECEIPT_ID`.
pub(crate) const PANIC_DURING_APPEND_BATCH_MARKER_CONTENT_HASH: &str =
    "content-rcpt-test-hook-panic-during-append-batch";

pub(crate) fn panic_during_append_batch(content_hash: &str) -> bool {
    content_hash == PANIC_DURING_APPEND_BATCH_MARKER_CONTENT_HASH
        && PANIC_DURING_APPEND_BATCH.load(Ordering::SeqCst)
}
