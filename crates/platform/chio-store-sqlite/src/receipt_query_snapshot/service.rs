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
use super::query::{locate, select, SelectedRow, Selection};
use super::walk::{observe, Observation, OwnedSink, WalkContext, WalkError, WalkLimits};
use crate::receipt_store::SqliteReceiptStore;

/// Snapshot limits and schedules. Every limit is enforced; none is a timing
/// promise.
#[derive(Debug, Clone)]
pub struct ReceiptQuerySnapshotConfig {
    /// Page quota of the in-memory snapshot database.
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
    checkpoint_seq: i64,
    observed_at_ms: u64,
    observed_at: Instant,
    recertified_at_ms: u64,
}

pub(super) struct Owned {
    db: SnapshotDb,
    meta: Meta,
    head: Option<KernelCheckpoint>,
    chain: CheckpointChainFrontier,
    watermark: i64,
    lineage_rowid: i64,
}

/// A published snapshot lineage. Its rows only grow; its versions are the
/// generations committed under `owned`.
pub(super) struct Published {
    lineage: String,
    owned: Mutex<Owned>,
    waiting: Arc<AtomicUsize>,
    changed: Arc<Condvar>,
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

    fn watermark_of(&self, meta: &Meta) -> ReceiptSnapshotWatermark {
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

    pub(super) fn with_db<T>(
        &self,
        read: impl FnOnce(&SnapshotDb) -> Result<T, SnapshotDbError>,
    ) -> Result<T, WalkError> {
        let owned = self.walker_lock()?;
        Ok(read(&owned.db)?)
    }

    pub(super) fn with_db_mut<T>(
        &self,
        write: impl FnOnce(&mut SnapshotDb) -> Result<T, SnapshotDbError>,
    ) -> Result<T, WalkError> {
        let mut owned = self.walker_lock()?;
        let value = write(&mut owned.db)?;
        owned.meta.generation += 1;
        drop(owned);
        self.changed.notify_all();
        Ok(value)
    }

    pub(super) fn sink(&self) -> PublishedSink<'_> {
        PublishedSink { published: self }
    }

    /// Commit a verified checkpoint, settle its pending leaves and advance the
    /// owned chain head, as one version.
    pub(super) fn accept_checkpoint(
        &self,
        batch: &SnapshotBatch,
        checkpoint: KernelCheckpoint,
        chain: CheckpointChainFrontier,
    ) -> Result<(), WalkError> {
        let mut owned = self.walker_lock()?;
        owned.db.commit(batch)?;
        owned.meta.checkpoint_seq =
            i64::try_from(checkpoint.body.checkpoint_seq).unwrap_or(i64::MAX);
        owned.head = Some(checkpoint);
        owned.chain = chain;
        owned.meta.generation += 1;
        drop(owned);
        self.changed.notify_all();
        Ok(())
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
        let located = locate(&owned.db, receipt_id, tenant)?;
        Ok((
            located.map(|located| located.row),
            self.watermark_of(&owned.meta),
        ))
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
        let mut owned = self.published.walker_lock()?;
        owned.db.commit(batch)?;
        owned.meta.through_entry_seq = owned.meta.through_entry_seq.max(through_entry_seq);
        owned.meta.generation += 1;
        drop(owned);
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

struct Inner {
    store: Arc<SqliteReceiptStore>,
    config: ReceiptQuerySnapshotConfig,
    cancel: Arc<AtomicBool>,
    phase: Mutex<Phase>,
    changed: Arc<Condvar>,
    wake: Mutex<bool>,
    wake_signal: Condvar,
    readers: AtomicUsize,
    waiting: Arc<AtomicUsize>,
    epoch: AtomicU64,
    last_recertification_ms: AtomicU64,
}

/// Owner of the authenticated receipt query snapshot of one store.
pub struct ReceiptQuerySnapshots {
    inner: Arc<Inner>,
    walker: Mutex<Option<JoinHandle<()>>>,
}

/// Admission of one read; released on drop.
struct ReadPermit<'a> {
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
        let inner = Arc::new(Inner {
            store,
            config,
            cancel: Arc::new(AtomicBool::new(false)),
            phase: Mutex::new(Phase::Waiting),
            changed: Arc::new(Condvar::new()),
            wake: Mutex::new(false),
            wake_signal: Condvar::new(),
            readers: AtomicUsize::new(0),
            waiting: Arc::new(AtomicUsize::new(0)),
            epoch: AtomicU64::new(0),
            last_recertification_ms: AtomicU64::new(0),
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
        let _permit = self.inner.admit()?;
        let (published, epoch) = self.inner.ready()?;
        self.inner.await_head(&published, false)?;
        let (selection, watermark, _) = published.select(
            &self.inner.waiting,
            query,
            self.inner.config.query_sql_steps,
        )?;
        let page = self
            .inner
            .fetch_page(&selection.rows, selection.tenant.as_deref())?;
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
        let _permit = self.inner.admit()?;
        let scope = ReceiptQuery::default()
            .with_read_context(read_context.clone())
            .effective_read_scope()?;
        let (published, epoch) = self.inner.ready()?;
        let tenant = scope.tenant.as_deref();
        let (mut located, mut watermark) =
            published.locate(&self.inner.waiting, receipt_id, tenant)?;
        if located.is_none() {
            self.inner.await_head(&published, true)?;
            (located, watermark) = published.locate(&self.inner.waiting, receipt_id, tenant)?;
        }
        let receipt = match located {
            None => None,
            Some(row) => {
                let page = self.inner.fetch_page(std::slice::from_ref(&row), tenant)?;
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
                self.inner.invalidate(&error);
                return Err(ReceiptQuerySnapshotError::Invalid(error).into());
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
            quota_bytes: self.inner.config.quota_bytes,
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
            if let Ok(owned) = published.owned.lock() {
                status.watermark = Some(published.watermark_of(&owned.meta));
                status.quota_bytes = owned.db.quota_bytes();
                status.used_bytes = owned.db.used_bytes().unwrap_or(0);
                status.tool_receipts = owned.db.tool_row_count().unwrap_or(0);
                let (dimensions, bytes) = owned.db.dim_stats().unwrap_or((0, 0));
                status.dimensions = dimensions;
                status.dimension_bytes = bytes;
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
    fn admit(&self) -> Result<ReadPermit<'_>, ReceiptStoreError> {
        let admitted = self.readers.fetch_add(1, Ordering::SeqCst);
        let permit = ReadPermit {
            readers: &self.readers,
        };
        if admitted >= self.config.max_concurrent_reads.max(1) {
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
        if let Ok(mut current) = self.phase.lock() {
            if matches!(*current, Phase::Stopped) {
                return;
            }
            if !matches!(phase, Phase::Building { .. }) {
                self.epoch.fetch_add(1, Ordering::SeqCst);
            }
            *current = phase;
        }
        self.changed.notify_all();
    }

    fn ready(&self) -> Result<(Arc<Published>, u64), ReceiptStoreError> {
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
    fn recheck_lease(&self, epoch: u64) -> Result<(), ReceiptStoreError> {
        if self.store.writer_head_poisoned() {
            self.invalidate("receipt writer head is poisoned");
        }
        if self.epoch.load(Ordering::SeqCst) != epoch {
            let reason = match self.phase() {
                Phase::Invalid(reason) | Phase::Unavailable(reason) => reason,
                _ => "receipt query snapshot changed lineage during the read".to_string(),
            };
            return Err(ReceiptQuerySnapshotError::Invalid(reason).into());
        }
        Ok(())
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

    fn head(&self) -> Result<i64, ReceiptStoreError> {
        let connection = self.store.connection()?;
        let watermark =
            crate::receipt_store::support::retention_watermark(&connection)?.unwrap_or(0);
        let max_entry: i64 = connection.query_row(
            "SELECT COALESCE(MAX(entry_seq), 0) FROM claim_receipt_log_entries",
            [],
            |row| row.get(0),
        )?;
        Ok(max_entry.max(i64::try_from(watermark).unwrap_or(i64::MAX)))
    }

    /// Wait for the version to reach the head observed now. A page may then
    /// be served from a version observed within `max_staleness`; a negative
    /// point read may not.
    fn await_head(&self, published: &Published, strict: bool) -> Result<(), ReceiptStoreError> {
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

    fn fetch_page(
        &self,
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
            Err(FetchError::Mismatch(reason)) => {
                self.invalidate(&reason);
                Err(ReceiptQuerySnapshotError::Invalid(reason).into())
            }
            Err(FetchError::Budget) => Err(ReceiptQuerySnapshotError::Unavailable(
                "receipt query fetch exhausted its SQL work budget".into(),
            )
            .into()),
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
    loop {
        if inner.cancel.load(Ordering::SeqCst) {
            break;
        }
        if !await_writer_seed(inner) {
            break;
        }
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| build_and_serve(inner)));
        let outcome = outcome.unwrap_or_else(|_| {
            Err(WalkError::Integrity(
                "receipt query snapshot walker panicked".into(),
            ))
        });
        let retry_after = match outcome {
            Ok(()) | Err(WalkError::Cancelled) => break,
            Err(error @ (WalkError::Integrity(_) | WalkError::Regressed(_))) => {
                inner.set_phase(Phase::Invalid(error.to_string()));
                let wait = backoff;
                backoff = (backoff * 2).min(Duration::from_secs(3_600));
                Some(wait)
            }
            Err(error @ (WalkError::Capacity { .. } | WalkError::RowCap { .. })) => {
                // A resource limit stays until the configuration or the stored
                // history changes; the service does not rebuild on its own.
                inner.set_phase(Phase::Unavailable(error.to_string()));
                None
            }
            Err(error @ (WalkError::WalkerBudget | WalkError::Busy(_))) => {
                inner.set_phase(Phase::Unavailable(error.to_string()));
                Some(
                    inner
                        .config
                        .invalid_retry_backoff
                        .min(Duration::from_secs(30)),
                )
            }
        };
        match retry_after {
            Some(wait) => sleep_until_cancelled(inner, wait),
            None => {
                while !inner.cancel.load(Ordering::SeqCst) {
                    inner.sleep(Duration::from_secs(3_600));
                }
            }
        }
    }
    if let Ok(mut phase) = inner.phase.lock() {
        *phase = Phase::Stopped;
    }
    inner.epoch.fetch_add(1, Ordering::SeqCst);
    inner.changed.notify_all();
}

fn sleep_until_cancelled(inner: &Inner, wait: Duration) {
    let deadline = Instant::now() + wait;
    while !inner.cancel.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        inner.sleep(deadline - now);
    }
}

/// Wait without a deadline until the writer finished seeding its verified
/// head. Returns false when cancelled.
fn await_writer_seed(inner: &Inner) -> bool {
    loop {
        if inner.cancel.load(Ordering::SeqCst) {
            return false;
        }
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
    let (db, result) = build_snapshot(&ctx, target, inner.config.quota_bytes, &mut report)?;
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
        waiting: Arc::clone(&inner.waiting),
        changed: Arc::clone(&inner.changed),
    });
    inner.set_phase(Phase::Ready(Arc::clone(&published)));
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
            // A read invalidated this lineage; rebuild after backoff.
            return Err(WalkError::Integrity(match inner.phase() {
                Phase::Invalid(reason) => reason,
                _ => "receipt query snapshot lineage was superseded".into(),
            }));
        }
        if inner.store.writer_head_poisoned() {
            return Err(WalkError::Integrity(
                "receipt writer head is poisoned".into(),
            ));
        }
        match extend_cycle(ctx, published, &|| inner.now_ms()) {
            Ok(observation) => covered = Some(observation),
            Err(WalkError::Busy(_)) => {}
            Err(error) => return Err(error),
        }
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
