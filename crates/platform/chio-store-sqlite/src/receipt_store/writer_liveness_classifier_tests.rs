use super::*;
use chio_kernel::ReceiptWriterLiveness as Liveness;

const CAPACITY: u64 = RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY as u64;
const NOW: u64 = 1_000_000;
const STALL_MS: u64 = 10_000;

#[test]
fn timed_out_inflight_append_reports_wedged() {
    // A caller timeout is not a terminal failure. The actor still owns the
    // command, so accepted remains ahead of terminal outcomes until it drains.
    let counters = ReceiptWriterCounters {
        accepted_total: 1,
        inflight: 1,
        ..ReceiptWriterCounters::default()
    };
    assert_eq!(
        classify_writer_liveness(&counters, STALL_MS, CAPACITY, Some(NOW - 20_000), NOW),
        Liveness::Wedged
    );
}

#[test]
fn outstanding_timeout_reports_wedged_before_the_stall_threshold() {
    let counters = ReceiptWriterCounters {
        accepted_total: 1,
        inflight: 1,
        timed_out_total: 1,
        timed_out_inflight: 1,
        last_commit_unix_ms: None,
        last_error: Some("sqlite receipt commit append timed out".to_string()),
        ..ReceiptWriterCounters::default()
    };
    assert_eq!(
        classify_writer_liveness(&counters, STALL_MS, CAPACITY, Some(NOW - 6_000), NOW),
        Liveness::Wedged
    );
}

#[test]
fn never_committed_backlog_reports_wedged() {
    // Wedged before the first commit: `last_commit_unix_ms` is `None`, so the
    // stall clock must fall back to the current backlog start.
    let counters = ReceiptWriterCounters {
        accepted_total: 1,
        inflight: 1,
        last_commit_unix_ms: None,
        ..ReceiptWriterCounters::default()
    };
    assert_eq!(
        classify_writer_liveness(&counters, STALL_MS, CAPACITY, Some(NOW - 20_000), NOW),
        Liveness::Wedged
    );
}

#[test]
fn honors_configured_stall_threshold() {
    // Same backlog with a commit 600ms ago: wedged under a fail-fast 500ms
    // threshold, healthy under a lenient 10s threshold. Proves the threshold
    // is a parameter, not a hardcoded constant.
    let counters = ReceiptWriterCounters {
        accepted_total: 2,
        committed_total: 1,
        inflight: 1,
        last_commit_unix_ms: Some(NOW - 600),
        ..ReceiptWriterCounters::default()
    };
    assert_eq!(
        classify_writer_liveness(&counters, 500, CAPACITY, None, NOW),
        Liveness::Wedged
    );
    assert_eq!(
        classify_writer_liveness(&counters, 10_000, CAPACITY, None, NOW),
        Liveness::Healthy
    );
}

#[test]
fn full_commit_channel_reports_saturated() {
    // Channel full right now but still committing (recent commit): a new send
    // would be rejected, so admission must be denied even though the writer
    // is not wedged.
    let counters = ReceiptWriterCounters {
        accepted_total: CAPACITY + 5,
        committed_total: 4,
        inflight: CAPACITY,
        queue_depth: CAPACITY,
        last_commit_unix_ms: Some(NOW - 100),
        ..ReceiptWriterCounters::default()
    };
    assert_eq!(
        classify_writer_liveness(&counters, STALL_MS, CAPACITY, None, NOW),
        Liveness::Saturated
    );
    assert!(!Liveness::Saturated.healthy());
}

#[test]
fn a_drained_but_committing_batch_is_not_reported_saturated() {
    // The actor has drained a full batch out of the channel and is committing
    // it: `inflight` still counts that batch, but its channel slots are
    // already free, so the next send would succeed. Saturation reads
    // `queue_depth`, so this must classify Healthy rather than Saturated.
    // Reading `inflight` here wrongly denied admission under heavy but
    // healthy load.
    let counters = ReceiptWriterCounters {
        accepted_total: CAPACITY + RECEIPT_GROUP_COMMIT_MAX_BATCH as u64,
        committed_total: 0,
        inflight: CAPACITY,
        queue_depth: CAPACITY - RECEIPT_GROUP_COMMIT_MAX_BATCH as u64,
        last_commit_unix_ms: Some(NOW - 100),
        ..ReceiptWriterCounters::default()
    };
    assert_eq!(
        classify_writer_liveness(&counters, STALL_MS, CAPACITY, Some(NOW - 100), NOW),
        Liveness::Healthy
    );
}

#[test]
fn idle_writer_with_fresh_backlog_is_not_wedged() {
    // After a long idle period the last commit is naturally old, but a newly
    // enqueued write has only just started. The stall clock must anchor to the
    // fresh backlog start, not the stale last commit, or the writer is marked
    // wedged and admission denied the instant it accepts work after a quiet
    // period.
    let counters = ReceiptWriterCounters {
        accepted_total: 6,
        committed_total: 5,
        inflight: 1,
        last_commit_unix_ms: Some(NOW - 60_000),
        ..ReceiptWriterCounters::default()
    };
    assert_eq!(
        classify_writer_liveness(&counters, STALL_MS, CAPACITY, Some(NOW - 100), NOW),
        Liveness::Healthy,
        "fresh work after idle must not be judged wedged by the stale last commit"
    );
    // The same stale commit WITH a backlog that has itself gone unserviced
    // past the threshold is a genuine wedge.
    assert_eq!(
        classify_writer_liveness(&counters, STALL_MS, CAPACITY, Some(NOW - 20_000), NOW),
        Liveness::Wedged,
        "a backlog stalled past the threshold must still report wedged"
    );
}

#[test]
fn unavailable_writer_reports_dead() {
    let counters = ReceiptWriterCounters {
        last_error: Some("sqlite receipt commit actor is unavailable".to_string()),
        ..ReceiptWriterCounters::default()
    };
    assert_eq!(
        classify_writer_liveness(&counters, STALL_MS, CAPACITY, None, NOW),
        Liveness::Dead
    );
}

#[test]
fn drained_writer_reports_healthy() {
    let counters = ReceiptWriterCounters {
        accepted_total: 10,
        committed_total: 10,
        inflight: 0,
        last_commit_unix_ms: Some(NOW - 50),
        ..ReceiptWriterCounters::default()
    };
    assert_eq!(
        classify_writer_liveness(&counters, STALL_MS, CAPACITY, None, NOW),
        Liveness::Healthy
    );
}

#[test]
fn a_non_healthy_writer_makes_the_store_unhealthy() {
    // Checkpoint chain intact and no recorded error, but the writer is not
    // making progress: the pre-dispatch gate is denying tool calls, so the
    // top-level health boolean must not stay green.
    assert!(!receipt_store_healthy(true, None, Liveness::Wedged));
    assert!(!receipt_store_healthy(true, None, Liveness::Saturated));
    assert!(!receipt_store_healthy(true, None, Liveness::Dead));
}

#[test]
fn healthy_and_unknown_writers_do_not_downgrade_store_health() {
    assert!(receipt_store_healthy(true, None, Liveness::Healthy));
    // Unknown is the permissive verdict (no async writer, or a read-only
    // observer that cannot see writer liveness).
    assert!(receipt_store_healthy(true, None, Liveness::Unknown));
    // A recorded writer error or an unhealthy checkpoint chain still fails
    // closed regardless of a healthy liveness verdict.
    assert!(!receipt_store_healthy(false, None, Liveness::Healthy));
    assert!(!receipt_store_healthy(
        true,
        Some("checkpoint build failed"),
        Liveness::Healthy
    ));
}
