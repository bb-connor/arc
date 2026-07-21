#[cfg(test)]
mod writer_liveness_classifier_tests {
    use super::*;
    use chio_kernel::ReceiptWriterLiveness as Liveness;

    const CAPACITY: u64 = RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY as u64;
    const NOW: u64 = 1_000_000;
    const STALL_MS: u64 = 10_000;

    #[test]
    fn timed_out_inflight_append_reports_wedged() {
        // A caller-timed-out append records an observation and leaves the actor's
        // command live. It must not claim terminal failure before that command
        // eventually commits or fails.
        let counters = ReceiptWriterCounters {
            accepted_total: 1,
            timeout_total: 1,
            inflight: 1,
            timed_out_inflight: 1,
            ..ReceiptWriterCounters::default()
        };
        assert_eq!(
            classify_writer_liveness(&counters, STALL_MS, CAPACITY, Some(NOW - 20_000), NOW),
            Liveness::Wedged
        );
    }

    #[test]
    fn recorded_append_timeout_reports_wedged_before_the_stall_threshold() {
        // A bounded append that exceeded its budget records an active timeout
        // marker and leaves inflight elevated, but the first accept is only 6s
        // old under a 10s stall threshold. The stall clock alone would still
        // report healthy for another 4s; the command-scoped marker must deny
        // admission immediately.
        let counters = ReceiptWriterCounters {
            accepted_total: 1,
            timeout_total: 1,
            inflight: 1,
            timed_out_inflight: 1,
            last_commit_unix_ms: None,
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

    #[test]
    fn inflight_release_is_exactly_once_and_command_scoped() {
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let (first_lease, first_release, first_previous) =
            WriterInflightLease::acquire(&health);
        let (second_lease, second_release, second_previous) =
            WriterInflightLease::acquire(&health);
        assert_eq!(first_previous, 0);
        assert_eq!(second_previous, 1);
        assert_eq!(health.inflight.load(Ordering::SeqCst), 2);

        first_lease.release();
        assert_eq!(health.inflight.load(Ordering::SeqCst), 1);
        // The caller can observe a disconnected response after the actor lease
        // already unwound. Invoking its paired release handle must not steal
        // the second command's still-live slot.
        first_release.release();
        assert_eq!(health.inflight.load(Ordering::SeqCst), 1);

        second_release.release();
        assert_eq!(health.inflight.load(Ordering::SeqCst), 0);
        // A later queue/actor drop sees the same release bit and is a no-op.
        drop(second_lease);
        assert_eq!(health.inflight.load(Ordering::SeqCst), 0);

        let (queued_lease, queued_release, previous) = WriterInflightLease::acquire(&health);
        assert_eq!(previous, 0);
        drop(queued_lease);
        assert_eq!(health.inflight.load(Ordering::SeqCst), 0);
        queued_release.release();
        assert_eq!(health.inflight.load(Ordering::SeqCst), 0);

        let (timed_out_lease, timed_out_release, previous) =
            WriterInflightLease::acquire(&health);
        assert_eq!(previous, 0);
        // Timeout and detached-call paths drop the caller handle without
        // explicitly releasing it. The actor lease must remain the sole owner
        // of the live inflight count until the command actually completes.
        timed_out_release.note_timeout();
        timed_out_release.note_timeout();
        assert_eq!(health.timeout_total.load(Ordering::SeqCst), 1);
        assert_eq!(health.timed_out_inflight.load(Ordering::SeqCst), 1);
        drop(timed_out_release);
        assert_eq!(health.inflight.load(Ordering::SeqCst), 1);
        timed_out_lease.release();
        assert_eq!(health.inflight.load(Ordering::SeqCst), 0);
        assert_eq!(health.timed_out_inflight.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn successful_maintenance_advances_progress_without_receipt_counters() {
        let health = ReceiptCommitWriterHealth::default();
        let old_backlog_start = 1;
        health
            .backlog_started_unix_ms
            .store(old_backlog_start, Ordering::SeqCst);

        health.note_maintenance_success();

        let progress = health.last_commit_unix_ms.load(Ordering::SeqCst);
        assert!(progress > old_backlog_start);
        assert_eq!(health.accepted_total.load(Ordering::SeqCst), 0);
        assert_eq!(health.committed_total.load(Ordering::SeqCst), 0);

        let counters = ReceiptWriterCounters {
            inflight: 1,
            last_commit_unix_ms: Some(progress),
            ..ReceiptWriterCounters::default()
        };
        assert_eq!(
            classify_writer_liveness(
                &counters,
                STALL_MS,
                CAPACITY,
                Some(old_backlog_start),
                progress,
            ),
            Liveness::Healthy,
            "successful maintenance must refresh progress for queued maintenance"
        );
    }
}

/// Shared release-once handle for one accepted writer command. The caller keeps
/// this handle while the command carries the paired lease. Either side may observe
/// terminal channel loss, but the atomic release bit permits exactly one of
/// them to decrement the global counter. This is command-scoped idempotence:
/// unlike a saturating decrement on the aggregate counter, a duplicate release
/// can never consume another queued command's slot. Dropping the caller's
/// handle is intentionally a no-op: timeout and detached-call paths must leave
/// ownership with the queued or running command lease.
#[derive(Clone)]
struct WriterInflightReleaseHandle {
    state: Arc<WriterInflightReleaseState>,
}

struct WriterInflightReleaseState {
    health: Arc<ReceiptCommitWriterHealth>,
    released: AtomicBool,
    /// Serializes timeout observation with terminal release for this command.
    /// A timeout racing a just-completed command is counted as an observation,
    /// but cannot leave a stale active-timeout marker behind.
    timeout_transition: Mutex<()>,
    timeout_observed: AtomicBool,
    timeout_marked: AtomicBool,
}

impl WriterInflightReleaseHandle {
    fn release(&self) {
        let _transition = match self.state.timeout_transition.lock() {
            Ok(transition) => transition,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !self.state.released.swap(true, Ordering::SeqCst) {
            if self.state.timeout_marked.swap(false, Ordering::SeqCst) {
                atomic_saturating_sub(&self.state.health.timed_out_inflight, 1);
            }
            self.state.health.release_inflight();
        }
    }

    /// Record that this caller's bounded wait elapsed without stealing the
    /// actor-owned lease or claiming terminal failure. Exactly one observation
    /// is counted per command. If terminal release already won the race, the
    /// cumulative observation remains honest but no active marker is installed.
    fn note_timeout(&self) {
        let _transition = match self.state.timeout_transition.lock() {
            Ok(transition) => transition,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.state.timeout_observed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.state
            .health
            .timeout_total
            .fetch_add(1, Ordering::SeqCst);
        if !self.state.released.load(Ordering::SeqCst) {
            self.state.timeout_marked.store(true, Ordering::SeqCst);
            self.state
                .health
                .timed_out_inflight
                .fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Ownership half carried inside an inflight-counted command. Dropping a queued
/// command, unwinding the actor, or explicitly finishing the command releases
/// its release handle. Normal paths publish terminal state, then consume the
/// lease immediately before responding, so a caller that observes its response
/// cannot still see its own command counted.
struct WriterInflightLease {
    release_handle: Option<WriterInflightReleaseHandle>,
}

impl WriterInflightLease {
    fn acquire(
        health: &Arc<ReceiptCommitWriterHealth>,
    ) -> (Self, WriterInflightReleaseHandle, u64) {
        let release_handle = WriterInflightReleaseHandle {
            state: Arc::new(WriterInflightReleaseState {
                health: Arc::clone(health),
                released: AtomicBool::new(false),
                timeout_transition: Mutex::new(()),
                timeout_observed: AtomicBool::new(false),
                timeout_marked: AtomicBool::new(false),
            }),
        };
        let lease = Self {
            release_handle: Some(release_handle.clone()),
        };
        let previous_inflight = health.reserve_inflight();
        (lease, release_handle, previous_inflight)
    }

    fn release(mut self) {
        if let Some(release_handle) = self.release_handle.take() {
            release_handle.release();
        }
    }

    #[cfg(test)]
    fn detached_for_test() -> Self {
        Self {
            release_handle: None,
        }
    }
}

impl Drop for WriterInflightLease {
    fn drop(&mut self) {
        if let Some(release_handle) = self.release_handle.take() {
            release_handle.release();
        }
    }
}

/// Reconcile a writer-routed `Write` job's health counters. Child receipts
/// and authorization-consuming appends run through
/// `WriterHandle::run_write_receipt`, and metadata-only writes through
/// `run_write`; both are `accepted_total`-counted at enqueue, but their
/// success/failure OUTCOME was never folded into `committed_total` /
/// `failed_total`, so accepted / committed / failed did not reconcile and a
/// store dominated by writer-routed receipts undercounted commits. The actor
/// calls this exactly once per `Write` with the responder's resync-adjusted
/// signal (O(1) per write). It runs before the command lease is released and
/// before the prepared response is delivered, so caller return implies terminal
/// accounting is already visible. A committed outcome also refreshes
/// `last_commit_unix_ms`, mirroring the Append path (`commit_receipt_batch`).
fn record_write_job_outcome(health: &ReceiptCommitWriterHealth, committed: bool) {
    if committed {
        health.committed_total.fetch_add(1, Ordering::SeqCst);
        health
            .last_commit_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
    } else {
        health.failed_total.fetch_add(1, Ordering::SeqCst);
    }
}

/// Publish one `Write` command's resync-adjusted terminal state in a strict
/// order: terminal counters, command-specific health state, lease release, then
/// caller response. The response is already prepared from the final job plus
/// resync outcome, so no outcome information is lost by deferring its send.
fn finish_write_response<F>(
    health: &ReceiptCommitWriterHealth,
    inflight: WriterInflightLease,
    respond: WriterResponder,
    resync: Result<(), ReceiptStoreError>,
    publish_health: F,
) where
    F: FnOnce(),
{
    let PreparedWriterResponse { committed, send } = respond(resync);
    record_write_job_outcome(health, committed);
    publish_health();
    inflight.release();
    send();
}

/// Background checkpoint signer, installed once by the kernel after `open`
/// and before serving. `max_batch = 0` disables
/// checkpointing (ADR-0008 semantics).
#[derive(Clone)]
pub struct BackgroundCheckpointSigner {
    pub backend: Arc<dyn SigningBackend>,
    pub max_batch: u64,
}

/// Last verified position of the receipt chain. Owned exclusively by the
/// commit-actor thread; never shared, never locked.
#[derive(Clone, Debug, Default)]
pub(crate) struct VerifiedHead {
    /// The newest checkpoint the actor has verified, already parsed and
    /// signature-checked once. `None` before the first checkpoint.
    latest_checkpoint: Option<KernelCheckpoint>,
    /// Row count of `claim_receipt_log_entries` as last verified.
    claim_log_count: u64,
    /// MAX(entry_seq) of `claim_receipt_log_entries` as last verified.
    claim_log_max_seq: u64,
}

impl VerifiedHead {
    pub(crate) fn checkpoint_seq(&self) -> u64 {
        self.latest_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.checkpoint_seq)
    }

    pub(crate) fn checkpointed_entry_seq(&self) -> u64 {
        self.latest_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq)
    }
}
