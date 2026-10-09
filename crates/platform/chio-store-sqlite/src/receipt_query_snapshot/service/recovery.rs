//! Resource recovery keeps the configured ceiling explicit. Only the owning
//! service can raise it or request a retry; public queries never allocate an
//! increased quota or shorten a backoff.
//!
//! A retry request is answered by the walker's next rebuild attempt. It ends a
//! resource backoff in progress, never shortens an integrity backoff, and is
//! satisfied without a rebuild by a projection that publishes or is serving.
//! Every rebuild authenticates what it publishes; a retry changes when the
//! walker tries, never what it accepts.
use super::*;

/// What an operator recovery request scheduled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptQuerySnapshotRecovery {
    /// A projection is serving. A raised quota applies to it in place and no
    /// rebuild is scheduled.
    Serving,
    /// The walker's next rebuild attempt answers retry request `epoch`. A
    /// resource backoff in progress ends now; an integrity backoff runs out.
    Scheduled { epoch: u64 },
}

/// Why an operator recovery request was refused. A refused request changes
/// neither the quota nor the retry state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptQuerySnapshotRecoveryError {
    #[error("snapshot quota of {requested_bytes} bytes is outside its configured bounds")]
    QuotaOutOfBounds { requested_bytes: u64 },
    #[error(
        "snapshot quota increase cannot lower the current operator budget of {current_bytes} bytes"
    )]
    QuotaBelowCurrent {
        requested_bytes: u64,
        current_bytes: u64,
    },
    #[error("receipt query snapshot service is stopped")]
    Stopped,
    #[error("receipt query snapshot lock poisoned")]
    Poisoned,
}

impl From<ReceiptQuerySnapshotRecoveryError> for ReceiptStoreError {
    fn from(error: ReceiptQuerySnapshotRecoveryError) -> Self {
        match error {
            ReceiptQuerySnapshotRecoveryError::QuotaOutOfBounds { .. }
            | ReceiptQuerySnapshotRecoveryError::QuotaBelowCurrent { .. } => {
                Self::Conflict(error.to_string())
            }
            ReceiptQuerySnapshotRecoveryError::Stopped => {
                ReceiptQuerySnapshotError::Unavailable("stopped".into()).into()
            }
            ReceiptQuerySnapshotRecoveryError::Poisoned => poisoned(),
        }
    }
}

/// Owner view of recovery requests and of how the walker's backoff waits
/// ended. Counters only grow while the service runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptQuerySnapshotRecoveryStatus {
    pub state: ReceiptQuerySnapshotState,
    /// Quota the next extension or build applies. Runtime increases are not
    /// persisted; a restarted owner applies its configured quota.
    pub requested_quota_bytes: u64,
    /// Latest retry request; zero when none was made.
    pub retry_requested: u64,
    /// Latest retry request a rebuild attempt or a publication answered.
    pub retry_answered: u64,
    /// Backoff waits ended by a retry request.
    pub retry_wakes: u64,
    /// Backoff waits ended by a raised quota.
    pub quota_wakes: u64,
    /// Backoff waits that ran to their deadline.
    pub deadline_wakes: u64,
}

/// How a walker backoff wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in super::super) enum WaitEnd {
    Deadline,
    QuotaRaised,
    RetryRequested,
    Cancelled,
}

/// Retry requests and wait outcomes. Answers and counts change under the
/// phase lock, so a waiter that checked them under that lock cannot miss the
/// `changed` notification that follows.
#[derive(Default)]
pub(super) struct RecoveryState {
    retry_requested: AtomicU64,
    retry_answered: AtomicU64,
    retry_wakes: AtomicU64,
    quota_wakes: AtomicU64,
    deadline_wakes: AtomicU64,
    /// Every backoff wait the walker entered: its length, whether a retry
    /// request may end it, and how it ended once it has.
    #[cfg(test)]
    waits: (Mutex<Vec<WaitRecord>>, Condvar),
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in super::super) struct WaitRecord {
    pub(in super::super) wait: Duration,
    pub(in super::super) answers_retry: bool,
    /// Highest retry request the wait had observed when it last chose to keep
    /// waiting.
    pub(in super::super) seen_retry: u64,
    pub(in super::super) end: Option<WaitEnd>,
}

impl ReceiptQuerySnapshots {
    /// Request a larger snapshot page budget without restarting the owner.
    ///
    /// Equivalent to [`Self::request_recovery`] with a quota. Quotas never
    /// increase automatically. [`Self::status`] reports the applied,
    /// page-rounded quota after publication.
    pub fn increase_quota_bytes(&self, quota_bytes: u64) -> Result<(), ReceiptStoreError> {
        self.request_recovery(Some(quota_bytes))
            .map(|_| ())
            .map_err(ReceiptStoreError::from)
    }

    /// Optionally raise the quota, then schedule a rebuild attempt unless a
    /// projection is serving.
    ///
    /// This is a node-local operator API, not an option of any receipt
    /// request. It does no I/O and takes only short internal locks; the
    /// returned outcome reports what was scheduled, not that a rebuild has
    /// succeeded. A raised quota lasts for this process only. A refused
    /// request changes nothing.
    pub fn request_recovery(
        &self,
        quota_bytes: Option<u64>,
    ) -> Result<ReceiptQuerySnapshotRecovery, ReceiptQuerySnapshotRecoveryError> {
        if let Some(requested_bytes) = quota_bytes {
            let mut validated = self.inner.config.clone();
            validated.quota_bytes = requested_bytes;
            validated.validate().map_err(|_| {
                ReceiptQuerySnapshotRecoveryError::QuotaOutOfBounds { requested_bytes }
            })?;
        }
        let phase = self
            .inner
            .phase
            .lock()
            .map_err(|_| ReceiptQuerySnapshotRecoveryError::Poisoned)?;
        if matches!(*phase, Phase::Stopped) || self.inner.cancel.load(Ordering::SeqCst) {
            return Err(ReceiptQuerySnapshotRecoveryError::Stopped);
        }
        if let Some(requested_bytes) = quota_bytes {
            self.inner
                .requested_quota_bytes
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    (requested_bytes >= current).then_some(requested_bytes)
                })
                .map_err(
                    |current_bytes| ReceiptQuerySnapshotRecoveryError::QuotaBelowCurrent {
                        requested_bytes,
                        current_bytes,
                    },
                )?;
        }
        // Publication answers every request made before it under this lock,
        // so a request that sees a serving projection has nothing to retry.
        let outcome = if matches!(*phase, Phase::Ready(_)) {
            ReceiptQuerySnapshotRecovery::Serving
        } else {
            let epoch = self
                .inner
                .recovery
                .retry_requested
                .fetch_add(1, Ordering::SeqCst)
                + 1;
            ReceiptQuerySnapshotRecovery::Scheduled { epoch }
        };
        drop(phase);
        self.inner.wake();
        Ok(outcome)
    }

    /// The lifecycle state, requested quota, retry requests and backoff wait
    /// outcomes, read together under one short lock with no database hold.
    pub fn recovery_status(&self) -> ReceiptQuerySnapshotRecoveryStatus {
        match self.inner.phase.lock() {
            Ok(phase) => self.inner.recovery_status(&phase),
            Err(_) => self.inner.recovery_status(&Phase::Invalid(
                "receipt query snapshot lock poisoned".into(),
            )),
        }
    }

    /// Block the calling thread until `done` accepts the recovery status or
    /// `timeout` elapses, and return the last status checked. Every phase
    /// transition and every ended backoff wait re-checks `done`. Call it from
    /// a blocking context.
    pub fn wait_for_recovery(
        &self,
        timeout: Duration,
        mut done: impl FnMut(&ReceiptQuerySnapshotRecoveryStatus) -> bool,
    ) -> ReceiptQuerySnapshotRecoveryStatus {
        let deadline = Instant::now() + timeout;
        let Ok(mut phase) = self.inner.phase.lock() else {
            return self.recovery_status();
        };
        loop {
            let status = self.inner.recovery_status(&phase);
            let now = Instant::now();
            if done(&status) || now >= deadline {
                return status;
            }
            phase = match self.inner.changed.wait_timeout(phase, deadline - now) {
                Ok((phase, _)) => phase,
                Err(_) => return self.recovery_status(),
            };
        }
    }
}

impl Inner {
    pub(super) fn requested_quota(&self) -> u64 {
        self.requested_quota_bytes.load(Ordering::SeqCst)
    }

    /// Whether a retry request is waiting for the next rebuild attempt.
    pub(super) fn retry_pending(&self) -> bool {
        self.recovery.retry_requested.load(Ordering::SeqCst)
            > self.recovery.retry_answered.load(Ordering::SeqCst)
    }

    /// A publication satisfies every retry request made before it.
    pub(super) fn answer_retries_by_publication(&self) {
        let phase = self.phase.lock();
        self.answer_retries();
        drop(phase);
        self.changed.notify_all();
    }

    /// Record how a backoff wait ended. Unless the walker is stopping, the
    /// rebuild attempt that follows answers every outstanding retry request.
    pub(super) fn end_wait(&self, end: WaitEnd) {
        let phase = self.phase.lock();
        let counter = match end {
            WaitEnd::Deadline => Some(&self.recovery.deadline_wakes),
            WaitEnd::QuotaRaised => Some(&self.recovery.quota_wakes),
            WaitEnd::RetryRequested => Some(&self.recovery.retry_wakes),
            WaitEnd::Cancelled => None,
        };
        if let Some(counter) = counter {
            counter.fetch_add(1, Ordering::SeqCst);
            self.answer_retries();
        }
        drop(phase);
        #[cfg(test)]
        self.record_wait_end(end);
        self.changed.notify_all();
    }

    fn answer_retries(&self) {
        self.recovery.retry_answered.fetch_max(
            self.recovery.retry_requested.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }

    fn recovery_status(&self, phase: &Phase) -> ReceiptQuerySnapshotRecoveryStatus {
        let recovery = &self.recovery;
        ReceiptQuerySnapshotRecoveryStatus {
            state: match phase {
                Phase::Waiting => ReceiptQuerySnapshotState::WaitingForWriterSeed,
                Phase::Building { done, total } => ReceiptQuerySnapshotState::Building {
                    authenticated_entries: *done,
                    target_entries: *total,
                },
                Phase::Ready(_) => ReceiptQuerySnapshotState::Ready,
                Phase::Invalid(reason) => ReceiptQuerySnapshotState::Invalid {
                    reason: reason.clone(),
                },
                Phase::Unavailable(reason) => ReceiptQuerySnapshotState::Unavailable {
                    reason: reason.clone(),
                },
                Phase::Stopped => ReceiptQuerySnapshotState::Stopped,
            },
            requested_quota_bytes: self.requested_quota(),
            retry_requested: recovery.retry_requested.load(Ordering::SeqCst),
            retry_answered: recovery.retry_answered.load(Ordering::SeqCst),
            retry_wakes: recovery.retry_wakes.load(Ordering::SeqCst),
            quota_wakes: recovery.quota_wakes.load(Ordering::SeqCst),
            deadline_wakes: recovery.deadline_wakes.load(Ordering::SeqCst),
        }
    }
}

#[cfg(test)]
impl Inner {
    pub(super) fn record_wait_start(&self, wait: Duration, answers_retry: bool) {
        let (waits, signal) = &self.recovery.waits;
        if let Ok(mut waits) = waits.lock() {
            waits.push(WaitRecord {
                wait,
                answers_retry,
                seen_retry: 0,
                end: None,
            });
        }
        signal.notify_all();
    }

    pub(super) fn retry_requested_for_test(&self) -> u64 {
        self.recovery.retry_requested.load(Ordering::SeqCst)
    }

    /// The wait checked every way to end, having read `seen_retry` before
    /// those checks, and keeps waiting.
    pub(super) fn record_wait_check(&self, seen_retry: u64) {
        let (waits, signal) = &self.recovery.waits;
        if let Ok(mut waits) = waits.lock() {
            if let Some(last) = waits.last_mut() {
                last.seen_retry = seen_retry;
            }
        }
        signal.notify_all();
    }

    fn record_wait_end(&self, end: WaitEnd) {
        let (waits, signal) = &self.recovery.waits;
        if let Ok(mut waits) = waits.lock() {
            if let Some(last) = waits.last_mut() {
                last.end = Some(end);
            }
        }
        signal.notify_all();
    }
}

#[cfg(test)]
impl ReceiptQuerySnapshots {
    /// Block until the walker's recorded backoff waits satisfy `done`, or
    /// `timeout` elapses; return the last record checked. The timeout only
    /// bounds a hang: assertions belong on the returned record.
    pub(in super::super) fn await_waits_for_test(
        &self,
        timeout: Duration,
        mut done: impl FnMut(&[WaitRecord]) -> bool,
    ) -> Vec<WaitRecord> {
        let (waits, signal) = &self.inner.recovery.waits;
        let Ok(guard) = waits.lock() else {
            return Vec::new();
        };
        signal
            .wait_timeout_while(guard, timeout, |waits| !done(waits))
            .map(|(waits, _)| waits.clone())
            .unwrap_or_default()
    }
}
