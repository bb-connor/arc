//! Snapshot service: one walker per store, explicit states, read leases and
//! the freshness rule. Reads never fall back to unauthenticated rows.
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use chio_core::receipt::body::ChioReceipt;
use chio_kernel::checkpoint::{CheckpointChainFrontier, KernelCheckpoint};
use chio_kernel::receipt_query::{
    ReceiptQuery, ReceiptQueryResult, ReceiptQuerySnapshotError, ReceiptReadContext,
    ReceiptSnapshotWatermark,
};
use chio_kernel::ReceiptStoreError;

use super::db::{SnapshotBatch, SnapshotDb, SnapshotDbError};
use super::extend::extend_cycle;
use super::fetch::{fetch, FetchError, FetchLimits, FetchedPage};
use super::pass::{build_snapshot, retry_busy, Pass, PassMode, PassProgress, Target};
use super::query::{locate, read_outcome, select, SelectedRow, Selection};
use super::walk::{observe, Observation, OwnedSink, WalkContext, WalkError, WalkLimits};
use crate::receipt_store::SqliteReceiptStore;

#[path = "service/health.rs"]
mod health;
#[path = "service/recovery.rs"]
mod recovery;
#[path = "service/seed_wait.rs"]
mod seed_wait;

pub use recovery::{
    ReceiptQuerySnapshotRecovery, ReceiptQuerySnapshotRecoveryError,
    ReceiptQuerySnapshotRecoveryStatus,
};
#[cfg(test)]
pub(super) use recovery::{WaitEnd, WaitRecord};

#[cfg(test)]
#[path = "tests/generation_observer.rs"]
mod generation_observer_tests;

/// Snapshot limits and schedules. Every limit is enforced; none is a timing
/// promise.
#[derive(Debug, Clone)]
pub struct ReceiptQuerySnapshotConfig {
    /// Page quota of the process-owned snapshot database.
    pub quota_bytes: u64,
    /// Concurrent reads admitted; further reads are refused as busy.
    pub max_concurrent_reads: usize,
    /// SQLite VM steps one query selection may spend.
    pub query_sql_steps: u64,
    /// SQLite VM steps one page fetch may spend.
    pub fetch_sql_steps: u64,
    /// Receipt bytes one page may carry; a page always carries one receipt.
    pub page_bytes: u64,
    /// Largest stored receipt the walker accepts.
    pub max_receipt_bytes: u64,
    /// Claim entries copied per walker step.
    pub step_rows: u64,
    /// Receipt bytes copied per walker step, unless one row is larger.
    pub step_bytes: u64,
    /// SQLite VM steps one walker transaction may spend.
    pub walker_sql_steps: u64,
    /// Rows committed per snapshot hold.
    pub insert_rows: usize,
    /// Checkpoint rows copied per walker step.
    pub checkpoint_page: u64,
    /// How long a read waits for the snapshot to reach the observed head.
    pub head_wait: Duration,
    /// How old a version's observation may be when a read cannot wait.
    pub max_staleness: Duration,
    /// Interval between extension cycles when no read is waiting.
    pub extension_tick: Duration,
    /// Interval between the starts of full recertification passes.
    pub recertify_interval: Duration,
    /// First wait before rebuilding an invalid snapshot; doubles to an hour.
    pub invalid_retry_backoff: Duration,
    /// SQLite busy timeout of walker connections.
    pub walker_busy_timeout: Duration,
    /// SQLite VM steps one walker hold of the snapshot connection may spend.
    pub hold_sql_steps: u64,
}

impl ReceiptQuerySnapshotConfig {
    /// Refuse limits that would disable a bound or overflow a deadline. Every
    /// count and budget must be positive; every wait has an upper bound.
    pub fn validate(&self) -> Result<(), ReceiptStoreError> {
        const MINIMUM_QUOTA: u64 = 1024 * 1024;
        const MINIMUM_SQL_STEPS: u64 = 1_000;
        const HOUR: Duration = Duration::from_secs(3_600);
        const DAY: Duration = Duration::from_secs(86_400);
        let checks: [(&str, bool); 20] = [
            ("quota_bytes", self.quota_bytes >= MINIMUM_QUOTA),
            ("max_concurrent_reads", self.max_concurrent_reads >= 1),
            ("query_sql_steps", self.query_sql_steps >= MINIMUM_SQL_STEPS),
            ("fetch_sql_steps", self.fetch_sql_steps >= MINIMUM_SQL_STEPS),
            ("page_bytes", self.page_bytes >= 1),
            ("max_receipt_bytes", self.max_receipt_bytes >= 1),
            ("step_rows", self.step_rows >= 1),
            ("step_bytes", self.step_bytes >= 1),
            (
                "walker_sql_steps",
                self.walker_sql_steps >= MINIMUM_SQL_STEPS,
            ),
            ("insert_rows", self.insert_rows >= 1),
            ("checkpoint_page", self.checkpoint_page >= 1),
            ("hold_sql_steps", self.hold_sql_steps >= MINIMUM_SQL_STEPS),
            ("head_wait", self.head_wait <= HOUR),
            ("max_staleness", self.max_staleness <= DAY),
            ("extension_tick", !self.extension_tick.is_zero()),
            ("extension_tick", self.extension_tick <= HOUR),
            ("recertify_interval", self.recertify_interval <= 30 * DAY),
            (
                "invalid_retry_backoff",
                !self.invalid_retry_backoff.is_zero(),
            ),
            ("invalid_retry_backoff", self.invalid_retry_backoff <= HOUR),
            ("walker_busy_timeout", self.walker_busy_timeout <= HOUR),
        ];
        match checks.iter().find(|(_, valid)| !valid) {
            Some((field, _)) => Err(ReceiptQuerySnapshotError::Unavailable(format!(
                "invalid receipt query snapshot configuration: {field} is outside its bounds"
            ))
            .into()),
            None => Ok(()),
        }
    }
}

impl Default for ReceiptQuerySnapshotConfig {
    fn default() -> Self {
        Self {
            quota_bytes: 2 * 1024 * 1024 * 1024,
            max_concurrent_reads: 4,
            query_sql_steps: 10_000_000,
            fetch_sql_steps: 1_000_000,
            page_bytes: 16 * 1024 * 1024,
            max_receipt_bytes: 128 * 1024 * 1024,
            step_rows: 1_024,
            step_bytes: 16 * 1024 * 1024,
            walker_sql_steps: 50_000_000,
            insert_rows: 256,
            checkpoint_page: 1_024,
            head_wait: Duration::from_secs(2),
            max_staleness: Duration::from_secs(30),
            extension_tick: Duration::from_millis(250),
            recertify_interval: Duration::from_secs(3_600),
            invalid_retry_backoff: Duration::from_secs(300),
            walker_busy_timeout: Duration::from_secs(5),
            hold_sql_steps: 5_000_000,
        }
    }
}

/// Lifecycle state reported by [`ReceiptQuerySnapshots::status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptQuerySnapshotState {
    WaitingForWriterSeed,
    Building {
        authenticated_entries: u64,
        target_entries: u64,
    },
    Ready,
    Invalid {
        reason: String,
    },
    Unavailable {
        reason: String,
    },
    Stopped,
}

/// Operator view of the snapshot and its resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptQuerySnapshotStatus {
    pub state: ReceiptQuerySnapshotState,
    pub watermark: Option<ReceiptSnapshotWatermark>,
    pub quota_bytes: u64,
    pub used_bytes: u64,
    pub tool_receipts: u64,
    pub dimensions: u64,
    pub dimension_bytes: u64,
    pub last_recertification_ms: Option<u64>,
}

#[derive(Clone)]
enum Phase {
    Waiting,
    Building { done: u64, total: u64 },
    Ready(Arc<Published>),
    Invalid(String),
    Unavailable(String),
    Stopped,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Meta {
    generation: u64,
    through_entry_seq: i64,
    pub(super) checkpoint_seq: i64,
    observed_at_ms: u64,
    observed_at: Instant,
    recertified_at_ms: u64,
}

pub(super) struct Owned {
    pub(super) db: SnapshotDb,
    pub(super) meta: Meta,
    head: Option<KernelCheckpoint>,
    chain: CheckpointChainFrontier,
    watermark: i64,
    lineage_rowid: i64,
}

/// A published snapshot lineage. Its rows only grow; its versions are the
/// generations committed under `owned`.
pub(super) struct Published {
    lineage: String,
    pub(super) owned: Mutex<Owned>,
    health_sample: Mutex<Option<health::HealthSample>>,
    waiting: Arc<AtomicUsize>,
    changed: Arc<Condvar>,
    cancel: Arc<AtomicBool>,
    /// SQLite VM steps one walker hold of the snapshot connection may spend.
    hold_sql_steps: u64,
    /// Storage failure the next walker commit hold reports.
    #[cfg(test)]
    commit_fault: Mutex<Option<SnapshotDbError>>,
    /// Outcome the next owned-snapshot read reports.
    #[cfg(test)]
    read_fault: Mutex<Option<ReceiptStoreError>>,
    /// Storage failure the next status hold reports.
    #[cfg(test)]
    status_fault: Mutex<Option<SnapshotDbError>>,
    /// Gate the extension stops at, before verifying a checkpoint root or
    /// before publishing a verified step.
    #[cfg(test)]
    gate: (Mutex<TestGate>, Condvar),
    /// Most pending leaves one staging hold wrote.
    #[cfg(test)]
    max_staged_per_hold: AtomicU64,
    /// Receives the state of every successful walker hold of this lineage.
    #[cfg(test)]
    observer: Option<GenerationObserver>,
}

/// Receives the snapshot, lineage and generation after every successful walker
/// hold, with the SQL work handler removed and the snapshot lock still held.
/// Every committed generation is observed before readers can see it. Reads,
/// staging and settlement holds report the generation they leave unchanged.
#[cfg(test)]
pub(super) type GenerationObserver = Arc<dyn Fn(&SnapshotDb, &str, u64) + Send + Sync>;

#[cfg(test)]
thread_local! {
    /// The observer the next service started on this thread installs.
    static NEXT_OBSERVER: std::cell::RefCell<Option<GenerationObserver>> =
        const { std::cell::RefCell::new(None) };
}

/// Where the extension's test gate stands.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GatePoint {
    Settlement,
    Publication,
}

/// What the extension does on reaching an armed gate.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GateAction {
    /// Wait until the gate is released.
    Hold,
    /// End the cycle as contention once, then disarm.
    Interrupt,
}

#[cfg(test)]
#[derive(Default)]
struct TestGate {
    armed: Option<(GatePoint, GateAction)>,
    skip: u32,
    reached: bool,
}

/// Position an extension cycle starts from.
pub(super) struct ExtensionState {
    pub(super) through_entry_seq: i64,
    pub(super) checkpoint_seq: i64,
    pub(super) watermark: i64,
    pub(super) lineage_rowid: i64,
}

impl Published {
    fn lock(&self) -> Result<MutexGuard<'_, Owned>, WalkError> {
        self.owned
            .lock()
            .map_err(|_| WalkError::Integrity("receipt query snapshot lock poisoned".into()))
    }

    /// Hold the snapshot connection for one bounded unit of walker work,
    /// yielding first to reads that are waiting for it.
    fn walker_lock(&self) -> Result<MutexGuard<'_, Owned>, WalkError> {
        let mut spins = 0;
        while self.waiting.load(Ordering::SeqCst) > 0 && spins < 1_000 {
            std::thread::sleep(Duration::from_micros(200));
            spins += 1;
        }
        self.lock()
    }

    pub(super) fn watermark_of(&self, meta: &Meta) -> ReceiptSnapshotWatermark {
        ReceiptSnapshotWatermark {
            snapshot_id: format!("{}:{}", self.lineage, meta.generation),
            through_entry_seq: u64::try_from(meta.through_entry_seq).unwrap_or(0),
            checkpoint_seq: u64::try_from(meta.checkpoint_seq)
                .ok()
                .filter(|seq| *seq > 0),
            observed_at_unix_ms: meta.observed_at_ms,
            recertified_at_unix_ms: meta.recertified_at_ms,
        }
    }

    pub(super) fn extension_state(&self) -> Result<ExtensionState, WalkError> {
        let owned = self.lock()?;
        Ok(ExtensionState {
            through_entry_seq: owned.meta.through_entry_seq,
            checkpoint_seq: owned.meta.checkpoint_seq,
            watermark: owned.watermark,
            lineage_rowid: owned.lineage_rowid,
        })
    }

    pub(super) fn head_and_chain(
        &self,
    ) -> Result<(Option<KernelCheckpoint>, CheckpointChainFrontier), WalkError> {
        let owned = self.lock()?;
        Ok((owned.head.clone(), owned.chain.clone()))
    }

    /// One bounded walker hold of the snapshot connection: SQL work is
    /// limited to `hold_sql_steps` VM steps and cancellation interrupts it.
    /// Exhaustion and cancellation are resource outcomes, never integrity.
    fn hold<T>(
        &self,
        work: impl FnOnce(&mut Owned) -> Result<T, SnapshotDbError>,
    ) -> Result<T, WalkError> {
        let mut owned = self.walker_lock()?;
        let exhausted = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&exhausted);
        let cancel = Arc::clone(&self.cancel);
        let mut remaining = self.hold_sql_steps;
        owned
            .db
            .connection()
            .map_err(SnapshotDbError::from)?
            .progress_handler(
                1_000,
                Some(move || {
                    if cancel.load(Ordering::SeqCst) {
                        return true;
                    }
                    remaining = remaining.saturating_sub(1_000);
                    if remaining == 0 {
                        signal.store(true, Ordering::SeqCst);
                        return true;
                    }
                    false
                }),
            )
            .map_err(|error| WalkError::Integrity(error.to_string()))?;
        let result = work(&mut owned);
        let _ = owned
            .db
            .connection()
            .map_err(SnapshotDbError::from)?
            .progress_handler(0, None::<fn() -> bool>);
        // Test-only SQL must neither consume the production work budget nor
        // inherit cancellation after a successful commit. Keep the same lock
        // through observation so no intermediate generation can be skipped.
        #[cfg(test)]
        if result.is_ok() {
            self.observe(&owned);
        }
        drop(owned);
        match result {
            Ok(value) => Ok(value),
            Err(_) if self.cancel.load(Ordering::SeqCst) => Err(WalkError::Cancelled),
            Err(_) if exhausted.load(Ordering::SeqCst) => Err(WalkError::WalkerBudget),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn with_db<T>(
        &self,
        read: impl FnOnce(&SnapshotDb) -> Result<T, SnapshotDbError>,
    ) -> Result<T, WalkError> {
        self.hold(|owned| read(&owned.db))
    }

    pub(super) fn with_db_mut<T>(
        &self,
        write: impl FnOnce(&mut SnapshotDb) -> Result<T, SnapshotDbError>,
    ) -> Result<T, WalkError> {
        let value = self.hold(|owned| {
            let value = write(&mut owned.db)?;
            owned.meta.generation += 1;
            Ok(value)
        })?;
        self.changed.notify_all();
        Ok(value)
    }

    /// Hand the current held state to the test observer.
    #[cfg(test)]
    fn observe(&self, owned: &Owned) {
        if let Some(observer) = &self.observer {
            observer(&owned.db, &self.lineage, owned.meta.generation);
        }
    }

    /// Stop at the test gate when it is armed at `point`.
    #[cfg(test)]
    pub(super) fn test_gate(&self, point: GatePoint) -> Result<(), WalkError> {
        let (gate, signal) = &self.gate;
        let Ok(mut state) = gate.lock() else {
            return Ok(());
        };
        let Some((armed, action)) = state.armed else {
            return Ok(());
        };
        if armed != point {
            return Ok(());
        }
        if state.skip > 0 {
            state.skip -= 1;
            return Ok(());
        }
        state.reached = true;
        signal.notify_all();
        if action == GateAction::Interrupt {
            state.armed = None;
            return Err(WalkError::Busy("interrupted at the test gate".into()));
        }
        while state.armed.is_some() && !self.cancel.load(Ordering::SeqCst) {
            state = match signal.wait_timeout(state, Duration::from_millis(50)) {
                Ok((state, _)) => state,
                Err(_) => return Ok(()),
            };
        }
        Ok(())
    }

    /// Stage pending leaves without publishing a version: no row becomes
    /// visible and the version's coverage is unchanged.
    pub(super) fn stage(&self, batch: &SnapshotBatch) -> Result<(), WalkError> {
        self.hold(|owned| {
            #[cfg(test)]
            if let Some(fault) = self
                .commit_fault
                .lock()
                .ok()
                .and_then(|mut fault| fault.take())
            {
                return Err(fault);
            }
            owned.db.commit(batch)
        })?;
        #[cfg(test)]
        self.max_staged_per_hold.fetch_max(
            u64::try_from(batch.pending.len()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
        Ok(())
    }

    pub(super) fn sink(&self) -> PublishedSink<'_> {
        PublishedSink { published: self }
    }

    /// Commit a verified checkpoint and advance the owned chain head as one
    /// version, in one bounded hold. The leaves it settles are removed
    /// afterwards by [`Published::settle_residual`].
    pub(super) fn accept_checkpoint(
        &self,
        batch: &SnapshotBatch,
        checkpoint: KernelCheckpoint,
        chain: CheckpointChainFrontier,
    ) -> Result<(), WalkError> {
        self.hold(|owned| {
            owned.db.commit(batch)?;
            owned.meta.checkpoint_seq =
                i64::try_from(checkpoint.body.checkpoint_seq).unwrap_or(i64::MAX);
            owned.head = Some(checkpoint);
            owned.chain = chain;
            owned.meta.generation += 1;
            Ok(())
        })?;
        self.changed.notify_all();
        Ok(())
    }

    /// Remove pending leaves an accepted checkpoint settled, at most `chunk`
    /// per bounded, cancellable hold. Leaves at or below the owned head are
    /// never consulted again, so an interrupted cleanup leaves no wrong
    /// answer behind.
    pub(super) fn settle_residual(
        &self,
        start: i64,
        end: i64,
        chunk: i64,
    ) -> Result<(), WalkError> {
        loop {
            let removed = self.hold(|owned| owned.db.delete_pending_chunk(start, end, chunk))?;
            if removed == 0 {
                return Ok(());
            }
        }
    }

    /// Record that this version covers an observed head target.
    pub(super) fn observed(
        &self,
        observation: Observation,
        observed_at_ms: u64,
        observed_at: Instant,
    ) -> Result<(), WalkError> {
        let mut owned = self.lock()?;
        if owned.meta.through_entry_seq >= observation.head {
            owned.meta.observed_at_ms = observed_at_ms;
            owned.meta.observed_at = observed_at;
            owned.watermark = observation.watermark;
            owned.lineage_rowid = observation.lineage_rowid;
        }
        drop(owned);
        self.changed.notify_all();
        Ok(())
    }

    fn select(
        &self,
        waiting: &AtomicUsize,
        query: &ReceiptQuery,
        sql_steps: u64,
    ) -> Result<(Selection, ReceiptSnapshotWatermark, Meta), ReceiptStoreError> {
        waiting.fetch_add(1, Ordering::SeqCst);
        let owned = self.owned.lock();
        waiting.fetch_sub(1, Ordering::SeqCst);
        let owned = owned.map_err(|_| poisoned())?;
        #[cfg(test)]
        self.injected_read_fault()?;
        let selection = select(&owned.db, query, sql_steps)?;
        Ok((selection, self.watermark_of(&owned.meta), owned.meta))
    }

    fn locate(
        &self,
        waiting: &AtomicUsize,
        receipt_id: &str,
        tenant: Option<&str>,
    ) -> Result<(Option<SelectedRow>, ReceiptSnapshotWatermark), ReceiptStoreError> {
        waiting.fetch_add(1, Ordering::SeqCst);
        let owned = self.owned.lock();
        waiting.fetch_sub(1, Ordering::SeqCst);
        let owned = owned.map_err(|_| poisoned())?;
        #[cfg(test)]
        self.injected_read_fault()?;
        let located = locate(&owned.db, receipt_id, tenant)?;
        Ok((
            located.map(|located| located.row),
            self.watermark_of(&owned.meta),
        ))
    }

    #[cfg(test)]
    fn injected_read_fault(&self) -> Result<(), ReceiptStoreError> {
        match self
            .read_fault
            .lock()
            .ok()
            .and_then(|mut fault| fault.take())
        {
            Some(fault) => Err(fault),
            None => Ok(()),
        }
    }

    fn meta(&self) -> Result<Meta, ReceiptStoreError> {
        Ok(self.owned.lock().map_err(|_| poisoned())?.meta)
    }
}

/// Walker commits to a published lineage: each hold is one version.
pub(super) struct PublishedSink<'a> {
    published: &'a Published,
}

impl OwnedSink for PublishedSink<'_> {
    fn commit(&mut self, batch: &SnapshotBatch, through_entry_seq: i64) -> Result<(), WalkError> {
        self.published.hold(|owned| {
            #[cfg(test)]
            if let Some(fault) = self
                .published
                .commit_fault
                .lock()
                .ok()
                .and_then(|mut fault| fault.take())
            {
                return Err(fault);
            }
            owned.db.commit(batch)?;
            owned.meta.through_entry_seq = owned.meta.through_entry_seq.max(through_entry_seq);
            owned.meta.generation += 1;
            Ok(())
        })?;
        self.published.changed.notify_all();
        Ok(())
    }

    fn read<T, F>(&mut self, read: F) -> Result<T, WalkError>
    where
        F: FnOnce(&SnapshotDb) -> Result<T, SnapshotDbError>,
    {
        self.published.with_db(read)
    }
}

fn poisoned() -> ReceiptStoreError {
    ReceiptQuerySnapshotError::Invalid("receipt query snapshot lock poisoned".into()).into()
}

pub(super) struct Inner {
    pub(super) store: Arc<SqliteReceiptStore>,
    pub(super) config: ReceiptQuerySnapshotConfig,
    requested_quota_bytes: AtomicU64,
    /// Operator retry requests and how the walker's backoff waits ended.
    recovery: recovery::RecoveryState,
    cancel: Arc<AtomicBool>,
    phase: Mutex<Phase>,
    changed: Arc<Condvar>,
    wake: Mutex<bool>,
    wake_signal: Condvar,
    readers: AtomicUsize,
    pub(super) waiting: Arc<AtomicUsize>,
    epoch: AtomicU64,
    /// Epoch of the latest transition to Invalid.
    last_invalid_epoch: AtomicU64,
    last_recertification_ms: AtomicU64,
    #[cfg(test)]
    pause_extension: AtomicBool,
    /// Whether a lineage was published since the walker's last integrity
    /// failure.
    published_since_failure: AtomicBool,
    /// Every wait the walker chose after an integrity failure.
    #[cfg(test)]
    integrity_waits: Mutex<Vec<Duration>>,
    /// Observer every lineage this service publishes receives.
    #[cfg(test)]
    generation_observer: Option<GenerationObserver>,
}

/// Owner of the authenticated receipt query snapshot of one store.
pub struct ReceiptQuerySnapshots {
    pub(super) inner: Arc<Inner>,
    walker: Mutex<Option<JoinHandle<()>>>,
}

/// Admission of one read; released on drop.
pub(super) struct ReadPermit<'a> {
    readers: &'a AtomicUsize,
}

impl Drop for ReadPermit<'_> {
    fn drop(&mut self) {
        self.readers.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ReceiptQuerySnapshots {
    /// Start the walker. The service is `WaitingForWriterSeed`, then
    /// `Building`, until the first version is published; reads refuse with a
    /// typed outcome meanwhile. There is no startup deadline.
    pub fn start(
        store: Arc<SqliteReceiptStore>,
        config: ReceiptQuerySnapshotConfig,
    ) -> Result<Self, ReceiptStoreError> {
        config.validate()?;
        let inner = Arc::new(Inner {
            store,
            requested_quota_bytes: AtomicU64::new(config.quota_bytes),
            recovery: recovery::RecoveryState::default(),
            config,
            cancel: Arc::new(AtomicBool::new(false)),
            phase: Mutex::new(Phase::Waiting),
            changed: Arc::new(Condvar::new()),
            wake: Mutex::new(false),
            wake_signal: Condvar::new(),
            readers: AtomicUsize::new(0),
            waiting: Arc::new(AtomicUsize::new(0)),
            epoch: AtomicU64::new(0),
            last_invalid_epoch: AtomicU64::new(0),
            last_recertification_ms: AtomicU64::new(0),
            #[cfg(test)]
            pause_extension: AtomicBool::new(false),
            published_since_failure: AtomicBool::new(false),
            #[cfg(test)]
            integrity_waits: Mutex::new(Vec::new()),
            #[cfg(test)]
            generation_observer: NEXT_OBSERVER.with(|next| next.borrow_mut().take()),
        });
        let walker = Arc::clone(&inner);
        let handle = std::thread::Builder::new()
            .name("chio-receipt-query-snapshot".to_string())
            .spawn(move || run(&walker))?;
        Ok(Self {
            inner,
            walker: Mutex::new(Some(handle)),
        })
    }

    /// Query receipts from the current authenticated version.
    pub fn query_receipts(
        &self,
        query: &ReceiptQuery,
    ) -> Result<ReceiptQueryResult, ReceiptStoreError> {
        self.serve_page(query).map_err(read_outcome)
    }

    fn serve_page(&self, query: &ReceiptQuery) -> Result<ReceiptQueryResult, ReceiptStoreError> {
        let _permit = self.inner.admit()?;
        let (published, epoch) = self.inner.ready()?;
        self.inner.await_head(&published, false)?;
        let (selection, watermark, _) = self.inner.owned_read(
            &published,
            published.select(
                &self.inner.waiting,
                query,
                self.inner.config.query_sql_steps,
            ),
        )?;
        let page =
            self.inner
                .fetch_page(&published, &selection.rows, selection.tenant.as_deref())?;
        self.inner.recheck_lease(epoch)?;
        let full = selection.rows.len() == selection.limit;
        let next_cursor = if page.short || full {
            page.receipts.last().map(|row| row.seq)
        } else {
            None
        };
        Ok(ReceiptQueryResult {
            receipts: page.receipts,
            total_count: selection.total_count,
            next_cursor,
            snapshot: Some(watermark),
        })
    }

    /// Load one receipt by id. A negative answer covers every commit that
    /// completed before the request, or the read refuses as stale.
    pub fn load_receipt(
        &self,
        receipt_id: &str,
        read_context: &ReceiptReadContext,
    ) -> Result<(Option<ChioReceipt>, ReceiptSnapshotWatermark), ReceiptStoreError> {
        self.serve_point(receipt_id, read_context)
            .map_err(read_outcome)
    }

    fn serve_point(
        &self,
        receipt_id: &str,
        read_context: &ReceiptReadContext,
    ) -> Result<(Option<ChioReceipt>, ReceiptSnapshotWatermark), ReceiptStoreError> {
        let _permit = self.inner.admit()?;
        let scope = ReceiptQuery::default()
            .with_read_context(read_context.clone())
            .effective_read_scope()?;
        let (published, epoch) = self.inner.ready()?;
        let tenant = scope.tenant.as_deref();
        let locate = || {
            self.inner.owned_read(
                &published,
                published.locate(&self.inner.waiting, receipt_id, tenant),
            )
        };
        let (mut located, mut watermark) = locate()?;
        if located.is_none() {
            self.inner.await_head(&published, true)?;
            (located, watermark) = locate()?;
        }
        let receipt = match located {
            None => None,
            Some(row) => {
                let page = self
                    .inner
                    .fetch_page(&published, std::slice::from_ref(&row), tenant)?;
                page.receipts
                    .into_iter()
                    .next()
                    .map(|stored| stored.receipt)
            }
        };
        if let Some(receipt) = receipt.as_ref() {
            if receipt.id != receipt_id {
                let error =
                    format!("retained receipt identity differs from the requested ID {receipt_id}");
                return self.inner.owned_read(
                    &published,
                    Err(ReceiptQuerySnapshotError::Invalid(error).into()),
                );
            }
        }
        self.inner.recheck_lease(epoch)?;
        Ok((receipt, watermark))
    }

    pub fn status(&self) -> ReceiptQuerySnapshotStatus {
        let phase = self
            .inner
            .phase
            .lock()
            .map(|phase| phase.clone())
            .unwrap_or_else(|_| Phase::Invalid("receipt query snapshot lock poisoned".into()));
        let mut status = ReceiptQuerySnapshotStatus {
            state: match &phase {
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
            watermark: None,
            quota_bytes: self.inner.requested_quota(),
            used_bytes: 0,
            tool_receipts: 0,
            dimensions: 0,
            dimension_bytes: 0,
            last_recertification_ms: match self.inner.last_recertification_ms.load(Ordering::SeqCst)
            {
                0 => None,
                value => Some(value),
            },
        };
        if let Phase::Ready(published) = phase {
            // Every metric is maintained, so this is one bounded hold. A metric
            // that cannot be read is never reported as a healthy zero: an
            // integrity failure drops the lineage like any read, and anything
            // else makes the state unavailable.
            let metrics = published.hold(|owned| {
                #[cfg(test)]
                if let Some(fault) = published
                    .status_fault
                    .lock()
                    .ok()
                    .and_then(|mut fault| fault.take())
                {
                    return Err(fault);
                }
                Ok((
                    published.watermark_of(&owned.meta),
                    owned.db.quota_bytes(),
                    owned.db.used_bytes()?,
                    owned.db.tool_row_count()?,
                    owned.db.dim_stats()?,
                ))
            });
            match metrics {
                Ok((watermark, quota, used, rows, (dimensions, bytes))) => {
                    status.watermark = Some(watermark);
                    status.quota_bytes = quota;
                    status.used_bytes = used;
                    status.tool_receipts = rows;
                    status.dimensions = dimensions;
                    status.dimension_bytes = bytes;
                }
                Err(error @ (WalkError::Integrity(_) | WalkError::Regressed(_))) => {
                    let reason = error.to_string();
                    self.inner.invalidate_lineage(&published, &reason);
                    status.state = ReceiptQuerySnapshotState::Invalid { reason };
                }
                Err(error) => {
                    status.state = ReceiptQuerySnapshotState::Unavailable {
                        reason: format!("receipt query snapshot metrics are unavailable: {error}"),
                    };
                }
            }
        }
        status
    }

    /// Set the cancel flag and wait for the walker's current phase to stop.
    /// A phase blocked in an uninterruptible filesystem call stops when that
    /// call returns.
    pub fn shutdown(&self) {
        self.inner.cancel.store(true, Ordering::SeqCst);
        self.inner.wake();
        let handle = self.walker.lock().ok().and_then(|mut handle| handle.take());
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

impl Drop for ReceiptQuerySnapshots {
    fn drop(&mut self) {
        // Without an explicit shutdown the walker is told to stop and left to
        // finish on its own thread, never joined from a caller's runtime.
        self.inner.cancel.store(true, Ordering::SeqCst);
        self.inner.wake();
    }
}

impl Inner {
    pub(super) fn admit(&self) -> Result<ReadPermit<'_>, ReceiptStoreError> {
        let admitted = self.readers.fetch_add(1, Ordering::SeqCst);
        let permit = ReadPermit {
            readers: &self.readers,
        };
        if admitted >= self.config.max_concurrent_reads {
            return Err(ReceiptQuerySnapshotError::Busy.into());
        }
        Ok(permit)
    }

    fn phase(&self) -> Phase {
        self.phase
            .lock()
            .map(|phase| phase.clone())
            .unwrap_or_else(|_| Phase::Invalid("receipt query snapshot lock poisoned".into()))
    }

    fn set_phase(&self, phase: Phase) {
        self.transition(phase, None);
    }

    /// Move to `phase`, or, with `serving`, only while that lineage is still
    /// the one served. Returns whether the phase changed.
    fn transition(&self, phase: Phase, serving: Option<&Arc<Published>>) -> bool {
        let changed = match self.phase.lock() {
            Ok(mut current) => {
                let expected = match (serving, &*current) {
                    (_, Phase::Stopped) => false,
                    (None, _) => true,
                    (Some(lineage), Phase::Ready(served)) => Arc::ptr_eq(lineage, served),
                    (Some(_), _) => false,
                };
                if expected {
                    if !matches!(phase, Phase::Building { .. }) {
                        let epoch = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;
                        if matches!(phase, Phase::Invalid(_)) {
                            self.last_invalid_epoch.store(epoch, Ordering::SeqCst);
                        }
                    }
                    *current = phase;
                }
                expected
            }
            Err(_) => false,
        };
        self.changed.notify_all();
        changed
    }

    /// Drop a served lineage that failed authentication or custody. It is
    /// never served again, even once its storage checks out; only a new
    /// authenticated lineage replaces it.
    fn invalidate_lineage(&self, published: &Arc<Published>, reason: &str) {
        if self.transition(Phase::Invalid(reason.to_string()), Some(published)) {
            tracing::error!(%reason, "receipt query snapshot invalidated");
            self.wake();
        }
    }

    /// The outcome of a read served from `published`. A typed `Invalid` drops
    /// that lineage; every other outcome passes through unchanged.
    pub(super) fn owned_read<T>(
        &self,
        published: &Arc<Published>,
        result: Result<T, ReceiptStoreError>,
    ) -> Result<T, ReceiptStoreError> {
        if let Err(ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError::Invalid(reason))) =
            &result
        {
            self.invalidate_lineage(published, reason);
        }
        result
    }

    pub(super) fn ready(&self) -> Result<(Arc<Published>, u64), ReceiptStoreError> {
        let epoch = self.epoch.load(Ordering::SeqCst);
        let error = match self.phase() {
            Phase::Ready(published) => {
                if self.store.writer_head_poisoned() {
                    self.invalidate("receipt writer head is poisoned");
                    return Err(ReceiptQuerySnapshotError::Invalid(
                        "receipt writer head is poisoned".into(),
                    )
                    .into());
                }
                return Ok((published, epoch));
            }
            Phase::Waiting => ReceiptQuerySnapshotError::Building {
                authenticated_entries: 0,
                target_entries: 0,
            },
            Phase::Building { done, total } => ReceiptQuerySnapshotError::Building {
                authenticated_entries: done,
                target_entries: total,
            },
            Phase::Invalid(reason) => ReceiptQuerySnapshotError::Invalid(reason),
            Phase::Unavailable(reason) => ReceiptQuerySnapshotError::Unavailable(reason),
            Phase::Stopped => ReceiptQuerySnapshotError::Unavailable("stopped".into()),
        };
        Err(error.into())
    }

    /// The lease taken at `ready` holds only if no invalidation or rebuild
    /// happened since and the writer head is not poisoned.
    /// A read keeps its result only if the phase it was admitted under is
    /// unchanged. Otherwise it refuses with the outcome that ended that phase:
    /// Invalid only after an authentication or writer-poison failure, and the
    /// typed availability outcome of the current phase for anything else.
    pub(super) fn recheck_lease(&self, epoch: u64) -> Result<(), ReceiptStoreError> {
        if self.store.writer_head_poisoned() {
            self.invalidate("receipt writer head is poisoned");
        }
        if self.epoch.load(Ordering::SeqCst) == epoch {
            return Ok(());
        }
        let phase = self.phase();
        if self.last_invalid_epoch.load(Ordering::SeqCst) > epoch {
            let reason = match phase {
                Phase::Invalid(reason) => reason,
                _ => "receipt query snapshot was invalidated during the read".to_string(),
            };
            return Err(ReceiptQuerySnapshotError::Invalid(reason).into());
        }
        let error = match phase {
            Phase::Invalid(reason) => ReceiptQuerySnapshotError::Invalid(reason),
            Phase::Unavailable(reason) => ReceiptQuerySnapshotError::Unavailable(reason),
            Phase::Stopped => ReceiptQuerySnapshotError::Unavailable("stopped".into()),
            Phase::Waiting => ReceiptQuerySnapshotError::Building {
                authenticated_entries: 0,
                target_entries: 0,
            },
            Phase::Building { done, total } => ReceiptQuerySnapshotError::Building {
                authenticated_entries: done,
                target_entries: total,
            },
            // A healthy replacement lineage serves the next attempt.
            Phase::Ready(_) => ReceiptQuerySnapshotError::Stale,
        };
        Err(error.into())
    }

    fn invalidate(&self, reason: &str) {
        let current = self.phase();
        if matches!(current, Phase::Ready(_)) {
            tracing::error!(%reason, "receipt query snapshot invalidated");
            self.set_phase(Phase::Invalid(reason.to_string()));
            self.wake();
        }
    }

    fn wake(&self) {
        if let Ok(mut woken) = self.wake.lock() {
            *woken = true;
        }
        self.wake_signal.notify_all();
    }

    fn sleep(&self, duration: Duration) {
        let Ok(woken) = self.wake.lock() else {
            return;
        };
        if let Ok((mut woken, _)) = self
            .wake_signal
            .wait_timeout_while(woken, duration, |woken| {
                !*woken && !self.cancel.load(Ordering::SeqCst)
            })
        {
            *woken = false;
        }
    }

    /// The claim-log head: the live maximum entry, or the watermark when the
    /// live log is empty. Both come from one read transaction, so a rotation
    /// that commits in between cannot produce a torn, too-low head.
    fn head(&self) -> Result<i64, ReceiptStoreError> {
        let mut connection = self.store.connection()?;
        let transaction = connection.transaction()?;
        let budget = crate::receipt_store::support::SqlWorkBudget::new_for(
            &transaction,
            self.config.fetch_sql_steps,
            "receipt query head",
        )?;
        let observed = (|| -> Result<i64, ReceiptStoreError> {
            let watermark =
                crate::receipt_store::support::retention_watermark(&transaction)?.unwrap_or(0);
            #[cfg(test)]
            head_hook::run();
            let max_entry: i64 = transaction.query_row(
                "SELECT COALESCE(MAX(entry_seq), 0) FROM claim_receipt_log_entries",
                [],
                |row| row.get(0),
            )?;
            Ok(max_entry.max(i64::try_from(watermark).unwrap_or(i64::MAX)))
        })();
        let exhausted = budget.exhausted();
        drop(budget);
        let _ = transaction.commit();
        if exhausted {
            return Err(ReceiptQuerySnapshotError::Unavailable(
                "receipt query head exhausted its SQL work budget".into(),
            )
            .into());
        }
        observed
    }

    /// Wait for the version to reach the head observed now. A page may then
    /// be served from a version observed within `max_staleness`; a negative
    /// point read may not.
    pub(super) fn await_head(
        &self,
        published: &Published,
        strict: bool,
    ) -> Result<(), ReceiptStoreError> {
        let target = self.head()?;
        let deadline = Instant::now() + self.config.head_wait;
        loop {
            let meta = published.meta()?;
            if meta.through_entry_seq >= target {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                if !strict && meta.observed_at.elapsed() <= self.config.max_staleness {
                    return Ok(());
                }
                return Err(ReceiptQuerySnapshotError::Stale.into());
            }
            self.wake();
            let guard = self.phase.lock().map_err(|_| poisoned())?;
            let slice = (deadline - now).min(Duration::from_millis(50));
            let _ = self.changed.wait_timeout(guard, slice);
        }
    }

    /// Fetch the receipts behind selected rows of `published`. A mismatch
    /// with what that lineage authenticated drops it.
    fn fetch_page(
        &self,
        published: &Arc<Published>,
        rows: &[SelectedRow],
        tenant: Option<&str>,
    ) -> Result<FetchedPage, ReceiptStoreError> {
        let limits = FetchLimits {
            page_bytes: self.config.page_bytes,
            max_receipt_bytes: self.config.max_receipt_bytes,
            sql_steps: self.config.fetch_sql_steps,
        };
        match fetch(&self.store, rows, tenant, limits) {
            Ok(page) => Ok(page),
            Err(FetchError::Mismatch(reason)) => self.owned_read(
                published,
                Err(ReceiptQuerySnapshotError::Invalid(reason).into()),
            ),
            Err(FetchError::Budget) => Err(ReceiptQuerySnapshotError::Unavailable(
                "receipt query fetch exhausted its SQL work budget".into(),
            )
            .into()),
            Err(FetchError::RowCap { entry_seq, .. }) => self.owned_read(
                published,
                Err(ReceiptQuerySnapshotError::Invalid(format!(
                    "claim entry {entry_seq} no longer holds the receipt the snapshot authenticated"
                ))
                .into()),
            ),
            Err(FetchError::Store(error)) => Err(error),
        }
    }

    fn limits(&self) -> WalkLimits {
        WalkLimits {
            step_rows: self.config.step_rows,
            step_bytes: self.config.step_bytes,
            max_receipt_bytes: self.config.max_receipt_bytes,
            sql_steps: self.config.walker_sql_steps,
            insert_rows: self.config.insert_rows,
            checkpoint_page: self.config.checkpoint_page,
            busy_timeout: self.config.walker_busy_timeout,
        }
    }

    fn now_ms(&self) -> Result<u64, WalkError> {
        self.store
            .query_snapshot_unix_ms()
            .map_err(|error| WalkError::Busy(error.to_string()))
    }
}

/// Walker thread body.
fn run(inner: &Arc<Inner>) {
    let mut backoff = inner.config.invalid_retry_backoff;
    let resource_initial = inner
        .config
        .invalid_retry_backoff
        .min(Duration::from_secs(30));
    let mut resource_backoff = resource_initial;
    loop {
        if inner.cancel.load(Ordering::SeqCst) {
            break;
        }
        if !await_writer_seed(inner) {
            break;
        }
        let requested_quota = inner.requested_quota();
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| build_and_serve(inner)));
        let outcome = outcome.unwrap_or_else(|_| {
            Err(WalkError::Integrity(
                "receipt query snapshot walker panicked".into(),
            ))
        });
        // A retry request ends only a resource wait; an integrity backoff is
        // never shortened.
        let answers_retry = !matches!(
            outcome,
            Err(WalkError::Integrity(_) | WalkError::Regressed(_))
        );
        let retry_after = match outcome {
            Ok(()) | Err(WalkError::Cancelled) => break,
            Err(WalkError::Superseded) => resource_initial,
            Err(error @ (WalkError::Integrity(_) | WalkError::Regressed(_))) => {
                inner.set_phase(Phase::Invalid(error.to_string()));
                // Backoff grows only across failures with no lineage
                // published between them.
                if inner.published_since_failure.swap(false, Ordering::SeqCst) {
                    backoff = inner.config.invalid_retry_backoff;
                }
                let wait = backoff;
                backoff = (backoff * 2).min(Duration::from_secs(3_600));
                #[cfg(test)]
                if let Ok(mut waits) = inner.integrity_waits.lock() {
                    waits.push(wait);
                }
                wait
            }
            Err(error @ (WalkError::Capacity { .. } | WalkError::RowCap { .. })) => {
                // SQLITE_FULL does not distinguish a configured page limit
                // from transient backing pressure. Retry without growing the
                // budget; repeated unsuccessful builds back off to one hour.
                if matches!(inner.phase(), Phase::Ready(_)) {
                    resource_backoff = resource_initial;
                }
                inner.set_phase(Phase::Unavailable(error.to_string()));
                let wait = resource_backoff;
                resource_backoff = (resource_backoff * 2).min(Duration::from_secs(3_600));
                wait
            }
            Err(
                error @ (WalkError::WalkerBudget | WalkError::Busy(_) | WalkError::Unavailable(_)),
            ) => {
                inner.set_phase(Phase::Unavailable(error.to_string()));
                resource_initial
            }
        };
        sleep_until_cancelled(inner, retry_after, requested_quota, answers_retry);
    }

    if let Ok(mut phase) = inner.phase.lock() {
        *phase = Phase::Stopped;
    }
    inner.epoch.fetch_add(1, Ordering::SeqCst);
    inner.changed.notify_all();
}

/// Wait out a backoff. A raised quota ends any wait and a retry request ends
/// a resource wait; how the wait ended is recorded before the walker retries.
fn sleep_until_cancelled(inner: &Inner, wait: Duration, requested_quota: u64, answers_retry: bool) {
    #[cfg(test)]
    inner.record_wait_start(wait, answers_retry);
    let deadline = Instant::now() + wait;
    let end = loop {
        #[cfg(test)]
        let seen_retry = inner.retry_requested_for_test();
        if inner.cancel.load(Ordering::SeqCst) {
            break recovery::WaitEnd::Cancelled;
        }
        if inner.requested_quota() != requested_quota {
            break recovery::WaitEnd::QuotaRaised;
        }
        if answers_retry && inner.retry_pending() {
            break recovery::WaitEnd::RetryRequested;
        }
        let now = Instant::now();
        if now >= deadline {
            break recovery::WaitEnd::Deadline;
        }
        #[cfg(test)]
        inner.record_wait_check(seen_retry);
        inner.sleep(deadline - now);
    };
    inner.end_wait(end);
}

/// Wait without a deadline until the writer finished seeding its verified
/// head. Returns false when cancelled.
fn await_writer_seed(inner: &Inner) -> bool {
    let mut reclaim = seed_wait::SeedWaitReclaim::default();
    loop {
        if inner.cancel.load(Ordering::SeqCst) {
            return false;
        }
        reclaim.poll(inner);
        match inner
            .store
            .wait_for_writer_ready(Duration::from_millis(200))
        {
            Ok(()) if !inner.store.writer_head_poisoned() => return true,
            _ if inner.store.writer_serving_closed() => {
                inner.set_phase(Phase::Invalid(
                    "receipt writer failed to seed a verified head".into(),
                ));
                inner.sleep(Duration::from_secs(1));
            }
            _ => {}
        }
    }
}

fn build_and_serve(inner: &Arc<Inner>) -> Result<(), WalkError> {
    let limits = inner.limits();
    let ctx = WalkContext {
        store: &inner.store,
        limits,
        cancel: &inner.cancel,
        fresh_reads: true,
    };
    let extension_ctx = WalkContext {
        store: &inner.store,
        limits,
        cancel: &inner.cancel,
        fresh_reads: false,
    };
    inner.set_phase(Phase::Building { done: 0, total: 0 });
    let observation = retry_busy(&ctx, || observe(&ctx))?;
    let target = Target {
        head: observation.head,
        checkpoint: observation.checkpoint,
        lineage_rowid: observation.lineage_rowid,
        max_source_seqs: observation.max_source_seqs,
        observed_at_ms: inner.now_ms()?,
        observed_at: Instant::now(),
    };
    let mut report = |done: u64, total: u64| {
        if let Ok(mut phase) = inner.phase.lock() {
            if matches!(*phase, Phase::Building { .. }) {
                *phase = Phase::Building { done, total };
            }
        }
    };
    let started = Instant::now();
    let (db, result) = build_snapshot(&ctx, target, inner.requested_quota(), &mut report)?;
    inner
        .last_recertification_ms
        .store(duration_ms(started.elapsed()), Ordering::SeqCst);
    let published = Arc::new(Published {
        lineage: uuid::Uuid::now_v7().simple().to_string(),
        owned: Mutex::new(Owned {
            db,
            meta: Meta {
                generation: 1,
                through_entry_seq: result.target.head,
                checkpoint_seq: result.target.checkpoint,
                observed_at_ms: result.target.observed_at_ms,
                observed_at: result.target.observed_at,
                recertified_at_ms: inner.now_ms()?,
            },
            head: result.head,
            chain: result.chain,
            watermark: observation.watermark,
            lineage_rowid: result.target.lineage_rowid,
        }),
        health_sample: Mutex::new(None),
        waiting: Arc::clone(&inner.waiting),
        changed: Arc::clone(&inner.changed),
        cancel: Arc::clone(&inner.cancel),
        hold_sql_steps: inner.config.hold_sql_steps,
        #[cfg(test)]
        commit_fault: Mutex::new(None),
        #[cfg(test)]
        read_fault: Mutex::new(None),
        #[cfg(test)]
        status_fault: Mutex::new(None),
        #[cfg(test)]
        gate: (Mutex::new(TestGate::default()), Condvar::new()),
        #[cfg(test)]
        max_staged_per_hold: AtomicU64::new(0),
        #[cfg(test)]
        observer: inner.generation_observer.clone(),
    });
    #[cfg(test)]
    if let Ok(owned) = published.owned.lock() {
        published.observe(&owned);
    }
    published.refresh_health_sample()?;
    inner.set_phase(Phase::Ready(Arc::clone(&published)));
    inner.answer_retries_by_publication();
    inner.published_since_failure.store(true, Ordering::SeqCst);
    serve(inner, &extension_ctx, &ctx, &published)
}

fn is_current(inner: &Inner, published: &Arc<Published>) -> bool {
    matches!(inner.phase(), Phase::Ready(current) if Arc::ptr_eq(&current, published))
}

fn serve(
    inner: &Arc<Inner>,
    ctx: &WalkContext<'_>,
    pass_ctx: &WalkContext<'_>,
    published: &Arc<Published>,
) -> Result<(), WalkError> {
    let mut last_pass_start = Instant::now();
    let mut recertification: Option<(Pass, Instant)> = None;
    let mut covered: Option<Observation> = None;
    loop {
        ctx.check_cancel()?;
        if !is_current(inner, published) {
            // A read invalidated this lineage, or a resource outcome replaced
            // it; either way it is rebuilt, never resumed.
            return Err(match inner.phase() {
                Phase::Invalid(reason) => WalkError::Integrity(reason),
                _ => WalkError::Superseded,
            });
        }
        if inner.store.writer_head_poisoned() {
            return Err(WalkError::Integrity(
                "receipt writer head is poisoned".into(),
            ));
        }
        #[cfg(test)]
        if inner.pause_extension.load(Ordering::SeqCst) {
            inner.sleep(inner.config.extension_tick);
            continue;
        }
        published.hold(|owned| owned.db.increase_quota(inner.requested_quota()))?;
        match extend_cycle(ctx, published, &|| inner.now_ms()) {
            Ok(observation) => covered = Some(observation),
            Err(WalkError::Busy(_)) => {}
            Err(error) => return Err(error),
        }
        published.refresh_health_sample()?;
        // A pass targets an observation the snapshot has fully covered, so its
        // source maxima are pinned at the same moment as its claim-log head.
        let due = last_pass_start.elapsed() >= inner.config.recertify_interval;
        if let (None, true, Some(observation)) = (recertification.as_ref(), due, covered) {
            let target = Target {
                head: observation.head,
                checkpoint: observation.checkpoint,
                lineage_rowid: observation.lineage_rowid,
                max_source_seqs: observation.max_source_seqs,
                observed_at_ms: inner.now_ms()?,
                observed_at: Instant::now(),
            };
            last_pass_start = Instant::now();
            recertification = Some((Pass::new(PassMode::Recertify, target), last_pass_start));
        }
        if let Some((pass, started)) = recertification.as_mut() {
            let mut sink = published.sink();
            match pass.step(pass_ctx, &mut sink) {
                Ok(PassProgress::Continue) | Err(WalkError::Busy(_)) => {}
                Ok(PassProgress::Done(_)) => {
                    let finished_ms = inner.now_ms()?;
                    let mut owned = published.owned.lock().map_err(|_| {
                        WalkError::Integrity("receipt query snapshot lock poisoned".into())
                    })?;
                    owned.meta.recertified_at_ms = finished_ms;
                    drop(owned);
                    inner
                        .last_recertification_ms
                        .store(duration_ms(started.elapsed()), Ordering::SeqCst);
                    recertification = None;
                }
                Err(error) => return Err(error),
            }
            continue;
        }
        inner.sleep(inner.config.extension_tick);
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}

#[cfg(test)]
impl ReceiptQuerySnapshots {
    /// Wait on the publication notification; the timeout only bounds a hung test.
    pub(super) fn wait_for_entry_after_for_test(&self, entry: u64, timeout: Duration) -> bool {
        let Ok(entry) = i64::try_from(entry) else {
            return false;
        };
        let Ok((published, _)) = self.inner.ready() else {
            return false;
        };
        let Ok(owned) = published.owned.lock() else {
            return false;
        };
        published
            .changed
            .wait_timeout_while(owned, timeout, |owned| {
                owned.meta.through_entry_seq <= entry
            })
            .is_ok_and(|(owned, _)| owned.meta.through_entry_seq > entry)
    }

    /// Start a service whose published lineages hand every committed state
    /// to `observer` (see [`GenerationObserver`]).
    pub(super) fn start_observed_for_test(
        store: Arc<SqliteReceiptStore>,
        config: ReceiptQuerySnapshotConfig,
        observer: GenerationObserver,
    ) -> Result<Self, ReceiptStoreError> {
        NEXT_OBSERVER.with(|next| *next.borrow_mut() = Some(observer));
        let started = Self::start(store, config);
        NEXT_OBSERVER.with(|next| next.borrow_mut().take());
        started
    }

    pub(super) fn pause_extension_for_test(&self, paused: bool) {
        self.inner.pause_extension.store(paused, Ordering::SeqCst);
        self.inner.wake();
    }

    pub(super) fn invalidate_for_test(&self, reason: &str) {
        self.inner.invalidate(reason);
    }

    pub(super) fn set_unavailable_for_test(&self, reason: &str) {
        self.inner.set_phase(Phase::Unavailable(reason.to_string()));
    }

    pub(super) fn lease_for_test(&self) -> Result<u64, ReceiptStoreError> {
        self.inner.ready().map(|(_, epoch)| epoch)
    }

    pub(super) fn recheck_lease_for_test(&self, epoch: u64) -> Result<(), ReceiptStoreError> {
        self.inner.recheck_lease(epoch)
    }

    /// Make the walker's next commit hold fail with `fault`, as a failing
    /// snapshot storage backend would.
    pub(super) fn fail_next_commit_for_test(&self, fault: SnapshotDbError) {
        if let Phase::Ready(published) = self.inner.phase() {
            if let Ok(mut slot) = published.commit_fault.lock() {
                *slot = Some(fault);
            }
        }
    }

    /// Make the next owned-snapshot read report `fault`.
    pub(super) fn fail_next_read_for_test(&self, fault: ReceiptStoreError) {
        if let Phase::Ready(published) = self.inner.phase() {
            if let Ok(mut slot) = published.read_fault.lock() {
                *slot = Some(fault);
            }
        }
    }

    pub(super) fn integrity_waits_for_test(&self) -> Vec<Duration> {
        self.inner
            .integrity_waits
            .lock()
            .map(|waits| waits.clone())
            .unwrap_or_default()
    }

    /// Run one statement on the published snapshot's own storage.
    pub(super) fn execute_on_snapshot_for_test(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> usize {
        let Phase::Ready(published) = self.inner.phase() else {
            return 0;
        };
        let Ok(owned) = published.owned.lock() else {
            return 0;
        };
        owned
            .db
            .connection()
            .ok()
            .and_then(|connection| connection.execute(sql, params).ok())
            .unwrap_or(0)
    }

    /// Make the next status hold fail with `fault`.
    /// Arm the extension's test gate on the published lineage, letting it
    /// pass `skip` times first.
    pub(super) fn arm_gate_for_test(&self, point: GatePoint, action: GateAction, skip: u32) {
        if let Phase::Ready(published) = self.inner.phase() {
            if let Ok(mut state) = published.gate.0.lock() {
                *state = TestGate {
                    armed: Some((point, action)),
                    skip,
                    reached: false,
                };
            }
        }
    }

    /// Wait until the extension reaches the armed gate.
    pub(super) fn await_gate_for_test(&self, timeout: Duration) -> bool {
        let Phase::Ready(published) = self.inner.phase() else {
            return false;
        };
        let (gate, signal) = &published.gate;
        let Ok(state) = gate.lock() else {
            return false;
        };
        signal
            .wait_timeout_while(state, timeout, |state| !state.reached)
            .map(|(state, _)| state.reached)
            .unwrap_or(false)
    }

    /// Release the extension's test gate.
    pub(super) fn release_gate_for_test(&self) {
        if let Phase::Ready(published) = self.inner.phase() {
            if let Ok(mut state) = published.gate.0.lock() {
                state.armed = None;
            }
            published.gate.1.notify_all();
        }
    }

    /// Most pending leaves one staging hold wrote on the published lineage.
    pub(super) fn max_staged_per_hold_for_test(&self) -> u64 {
        match self.inner.phase() {
            Phase::Ready(published) => published.max_staged_per_hold.load(Ordering::SeqCst),
            _ => 0,
        }
    }

    pub(super) fn fail_next_status_for_test(&self, fault: SnapshotDbError) {
        if let Phase::Ready(published) = self.inner.phase() {
            if let Ok(mut slot) = published.status_fault.lock() {
                *slot = Some(fault);
            }
        }
    }

    /// The published snapshot's backing file, when its storage has one.
    pub(super) fn backing_path_for_test(&self) -> Option<std::path::PathBuf> {
        let Phase::Ready(published) = self.inner.phase() else {
            return None;
        };
        let owned = published.owned.lock().ok()?;
        let connection = owned.db.connection().ok()?;
        connection
            .path()
            .filter(|path| !path.is_empty())
            .map(std::path::PathBuf::from)
    }

    /// Poison the published snapshot's lock, as a panic inside a hold would.
    pub(super) fn poison_snapshot_for_test(&self) {
        if let Phase::Ready(published) = self.inner.phase() {
            std::thread::scope(|scope| {
                let _ = scope
                    .spawn(|| {
                        let _owned = published.owned.lock();
                        panic!("poisoning the published snapshot");
                    })
                    .join();
            });
        }
    }

    pub(super) fn max_settled_per_hold_for_test(&self) -> u64 {
        match self.inner.phase() {
            Phase::Ready(published) => published
                .owned
                .lock()
                .map(|owned| owned.db.max_settled_per_hold.get())
                .unwrap_or(0),
            _ => 0,
        }
    }
}

/// Test-only interleaving point between the two reads of a head observation.
#[cfg(test)]
pub(super) mod head_hook {
    use std::cell::RefCell;

    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnMut()>>> = RefCell::new(None);
    }

    pub(in super::super) fn set(hook: Option<Box<dyn FnMut()>>) {
        HOOK.with(|slot| *slot.borrow_mut() = hook);
    }

    pub(super) fn run() {
        let hook = HOOK.with(|slot| slot.borrow_mut().take());
        if let Some(mut hook) = hook {
            hook();
        }
    }
}
