//! ExporterManager: cursor-pull loop that reads receipts from SQLite and fans out to exporters.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::params;
use tokio::sync::watch;

use chio_kernel::{ReceiptReadBoundary, ReceiptReadContext};

use crate::dlq::{DeadLetterQueue, FailedEvent};
use crate::event::SiemEvent;
use crate::exporter::{ExportError, Exporter};
use crate::ratelimit::{ExportRateLimiter, RateLimitConfig};
use crate::redaction::redact_for_operator_log;

const MAX_RETRY_BACKOFF_MS: u64 = 60_000;

/// Error variants for ExporterManager operations.
#[derive(Debug, thiserror::Error)]
pub enum SiemError {
    /// SQLite database error.
    #[error("database error: {0}")]
    DbError(String),

    /// Configuration error (invalid path, zero batch size, etc.).
    #[error("config error: {0}")]
    ConfigError(String),
}

/// Configuration for the ExporterManager cursor-pull loop.
#[derive(Debug, Clone)]
pub struct SiemConfig {
    /// Path to the Chio kernel receipt SQLite database.
    pub db_path: PathBuf,
    /// Interval between polls for new receipts. Default: 5 seconds.
    pub poll_interval: Duration,
    /// Maximum number of receipts to read per poll cycle. Default: 100.
    pub batch_size: usize,
    /// Maximum number of retry attempts per exporter before DLQ. Default: 3.
    pub max_retries: u32,
    /// Base backoff in milliseconds for exponential retry (actual: base * 2^attempt). Default: 500.
    pub base_backoff_ms: u64,
    /// Maximum capacity of the dead-letter queue. Default: 1000.
    pub dlq_capacity: usize,
    /// Optional per-exporter batch rate limit. None means unlimited.
    pub rate_limit: Option<RateLimitConfig>,
    /// Kernel public keys trusted to produce authoritative receipts.
    pub trusted_kernel_keys: BTreeSet<String>,
    /// Explicit read authority for local receipt polling. SIEM polling is an
    /// operator surface and must not run with tenant-scoped authority.
    pub read_context: ReceiptReadContext,
    /// Optional path to the SIEM-owned RW cursor store (per-exporter high-water
    /// mark). When set, delivery is at-least-once: the read cursor resumes at
    /// min(acked_seq) so a failed exporter forces bounded redelivery instead of
    /// a silent skip (RFC-0009 F78). None keeps the legacy advance-regardless
    /// behavior. Distinct from the read-only receipt DB (ADR-0009).
    pub cursor_db_path: Option<PathBuf>,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("receipts.sqlite3"),
            poll_interval: Duration::from_secs(5),
            batch_size: 100,
            max_retries: 3,
            base_backoff_ms: 500,
            dlq_capacity: DeadLetterQueue::DEFAULT_CAPACITY,
            rate_limit: None,
            trusted_kernel_keys: BTreeSet::new(),
            read_context: ReceiptReadContext::local_operator_admin_all(),
            cursor_db_path: None,
        }
    }
}

/// Manages the receipt cursor-pull loop and fans events out to registered exporters.
///
/// The manager reads receipts from the Chio kernel SQLite database using a
/// seq-based cursor, builds SiemEvents, and forwards batches to each registered
/// Exporter. Failed exports are retried with exponential backoff; events that
/// exhaust all retries are placed on the DeadLetterQueue.
///
/// When `SiemConfig::cursor_db_path` is None the read cursor is NOT persisted:
/// on restart the manager re-exports all receipts from seq=0 (both Splunk HEC
/// timestamp dedup and Elasticsearch _id upsert handle duplicates idempotently).
/// When set, a per-exporter high-water mark is persisted and the cursor resumes
/// at min(acked_seq) for at-least-once delivery (RFC-0009 F78).
///
/// A single read-only SQLite connection is opened at construction time and
/// reused across all poll cycles. This avoids the overhead of re-opening the
/// file on every tick and keeps WAL-mode shared-read semantics stable.
///
/// The connection is wrapped in `Mutex` so that `ExporterManager` remains
/// `Send + Sync` and can be moved into a `tokio::spawn` task. The mutex is
/// only locked during the synchronous DB read phase of each poll cycle; it is
/// always released before any `.await` point.
pub struct ExporterManager {
    exporters: Vec<Box<dyn Exporter>>,
    dlq: DeadLetterQueue,
    cursor: u64,
    config: SiemConfig,
    rate_limiter: Option<ExportRateLimiter>,
    /// Persistent read-only connection to the receipt database.
    conn: Mutex<rusqlite::Connection>,
    // The poll loop emits export/lag/dlq metrics through this sink (RFC-0009
    // Part F). Defaults to no-op so chio-siem stays decoupled from the metric
    // registry (ADR-0009); the host installs a registry-backed sink.
    metrics: std::sync::Arc<dyn crate::metrics_sink::SiemMetricsSink>,
    /// SIEM-owned RW high-water-mark store (RFC-0009 F78). None keeps the legacy
    /// advance-regardless behavior.
    cursor_store: Option<crate::cursor_store::SiemCursorStore>,
    /// In-memory per-exporter high-water mark, seeded from the store at open and
    /// advanced only on confirmed acceptance.
    acked: std::collections::BTreeMap<String, u64>,
}

impl ExporterManager {
    /// Create a new ExporterManager with the given configuration.
    ///
    /// Opens the SQLite database at `config.db_path` immediately and returns
    /// an error if the file cannot be opened.
    pub fn new(config: SiemConfig) -> Result<Self, SiemError> {
        if config.batch_size == 0 {
            return Err(SiemError::ConfigError(
                "batch_size must be greater than zero".to_string(),
            ));
        }
        if config.poll_interval.is_zero() {
            return Err(SiemError::ConfigError(
                "poll_interval must be greater than zero".to_string(),
            ));
        }
        validate_admin_read_context(&config.read_context)?;

        let rate_limiter = config
            .rate_limit
            .clone()
            .map(ExportRateLimiter::new)
            .transpose()
            .map_err(|error| {
                SiemError::ConfigError(format!("invalid rate-limit config: {error}"))
            })?;

        let conn = rusqlite::Connection::open_with_flags(
            &config.db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| SiemError::DbError(e.to_string()))?;

        let dlq = DeadLetterQueue::new(config.dlq_capacity);
        // Open the SIEM-owned cursor store when configured and resume the read
        // cursor at the slowest exporter's high-water mark (RFC-0009 F78).
        let cursor_store = match &config.cursor_db_path {
            Some(path) => Some(crate::cursor_store::SiemCursorStore::open(path)?),
            None => None,
        };
        let acked = match &cursor_store {
            Some(store) => store.acked_seqs()?,
            None => std::collections::BTreeMap::new(),
        };
        let cursor = acked.values().copied().min().unwrap_or(0);
        Ok(Self {
            exporters: Vec::new(),
            dlq,
            cursor,
            config,
            rate_limiter,
            conn: Mutex::new(conn),
            metrics: crate::metrics_sink::noop_metrics_sink(),
            cursor_store,
            acked,
        })
    }

    /// Attach a metrics sink (RFC-0009). Defaults to no-op so headless callers
    /// are unchanged.
    #[must_use]
    pub fn with_metrics_sink(
        mut self,
        sink: std::sync::Arc<dyn crate::metrics_sink::SiemMetricsSink>,
    ) -> Self {
        self.metrics = sink;
        self
    }

    /// Register an exporter to receive receipt batches.
    ///
    /// With a configured cursor store, a registered exporter that has no
    /// persisted high-water mark row is seeded at BASELINE (0): it must receive
    /// every receipt persisted before it was registered, so it pins the resume
    /// cursor at 0 until its first ack rather than inheriting an already-advanced
    /// cursor from a faster peer and silently skipping the backlog (RFC-0009 F78,
    /// Codex round-2 finding 1). The read cursor is then recomputed as the
    /// minimum high-water mark across the known exporter set. In legacy None mode
    /// the cursor is not persisted and always advances past the batch, so no
    /// baseline pin is applied here.
    pub fn add_exporter(&mut self, exporter: Box<dyn Exporter>) {
        if self.cursor_store.is_some() {
            // Key by registration index + name so two same-named instances keep
            // distinct high-water marks (Codex round-4 finding 4).
            let key = exporter_cursor_key(self.exporters.len(), exporter.name());
            self.acked.entry(key).or_insert(0);
            self.cursor = self.acked.values().copied().min().unwrap_or(0);
        }
        self.exporters.push(exporter);
    }

    /// Return the current number of entries in the dead-letter queue.
    pub fn dlq_len(&self) -> usize {
        self.dlq.len()
    }

    /// Run the cursor-pull loop until the cancellation channel signals true.
    ///
    /// On each tick, fetches the next batch of receipts after the current
    /// cursor using the persistent connection, builds SiemEvents, and fans
    /// them out to all registered exporters with exponential backoff retry.
    /// Events that exhaust all retries are placed on the DLQ. The cursor is
    /// advanced past the batch after all exporters have processed it (whether
    /// successful or DLQ'd).
    pub async fn run(&mut self, mut cancel: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(self.config.poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.poll_once().await {
                        tracing::error!(error = %redact_for_operator_log(&e), "SIEM poll cycle failed");
                    }
                }
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        tracing::info!("SIEM ExporterManager received cancellation -- shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Execute one poll cycle: fetch a batch of receipts, fan out to exporters.
    ///
    /// Uses the persistent `self.conn` rather than opening a new connection
    /// on every tick.
    async fn poll_once(&mut self) -> Result<(), SiemError> {
        let cursor = self.cursor;
        let batch_size = self.config.batch_size;
        validate_admin_read_context(&self.config.read_context)?;

        // Lock the connection only for the synchronous DB read; release before any await.
        let rows: Vec<(u64, String)> = {
            let conn = self.conn.lock().map_err(|_| {
                SiemError::DbError("receipt db connection lock poisoned".to_string())
            })?;

            let mut stmt = conn
                .prepare(
                    "SELECT seq, raw_json \
                     FROM chio_tool_receipts \
                     WHERE seq > ?1 \
                     ORDER BY seq ASC \
                     LIMIT ?2",
                )
                .map_err(|e| SiemError::DbError(e.to_string()))?;

            let mapped = stmt
                .query_map(params![cursor as i64, batch_size as i64], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|e| SiemError::DbError(e.to_string()))?;

            let mut result = Vec::new();
            for row in mapped {
                let (seq, raw_json) = row.map_err(|e| SiemError::DbError(e.to_string()))?;
                result.push((seq.max(0) as u64, raw_json));
            }
            result
            // `conn` MutexGuard and `stmt` are dropped here -- lock released before any await.
        };

        if rows.is_empty() {
            return Ok(());
        }

        // Parse rows into SiemEvents.
        let mut events: Vec<SiemEvent> = Vec::with_capacity(rows.len());
        let mut max_seq = self.cursor;

        for (seq, raw_json) in &rows {
            match serde_json::from_str::<chio_core::receipt::body::ChioReceipt>(raw_json) {
                Ok(receipt) => {
                    events.push(SiemEvent::from_receipt_with_trusted_kernel_keys(
                        receipt,
                        Some(&self.config.trusted_kernel_keys),
                    ));
                    if *seq > max_seq {
                        max_seq = *seq;
                    }
                }
                Err(error) => {
                    // RFC-0009 F80 + Codex #6: durably persist the malformed row
                    // to the SIEM cursor DB's dead_letters table BEFORE advancing
                    // past it. The in-memory DLQ is best-effort (drop-oldest, lost
                    // on restart/overflow), so advancing acked_seq past a row
                    // captured only in memory would skip the receipt permanently
                    // and break at-least-once. On a persist failure we leave the
                    // cursor BEHIND the row (return early via `?` without touching
                    // self.cursor) so the next poll re-reads and retries it.
                    self.metrics.record_export(
                        "_deserialize",
                        crate::metrics_sink::ExportOutcome::Malformed,
                    );
                    let failed_at = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let redacted = redact_for_operator_log(&error).to_string();
                    if let Some(store) = &self.cursor_store {
                        store.persist_dead_letter(
                            *seq,
                            "_deserialize",
                            raw_json,
                            &redacted,
                            failed_at,
                        )?;
                    }
                    self.dlq.push(FailedEvent {
                        event_json: format!("{{\"raw_seq\":{seq}}}"),
                        error: redacted,
                        failed_at,
                        exporter_name: "_deserialize".to_string(),
                    });
                    // Report the DLQ depth for the malformed-row producer here
                    // too (Codex round-2 finding 3): a batch of only malformed
                    // rows returns before the exporter loop that refreshes
                    // dlq_depth, so without this the `_deserialize` gauge would
                    // stay absent/stale while the in-memory DLQ grows and the
                    // alert-pack backstop underreports malformed-row failures.
                    // Scope the depth to `_deserialize` entries only (Codex
                    // round-4 finding 2): the DLQ is shared, so the global length
                    // would fold a coexisting exporter backlog into the
                    // malformed-row gauge (the cross-exporter attribution bug
                    // round-3 finding 4 fixed for the exporter loop).
                    self.metrics.set_dlq_depth(
                        "_deserialize",
                        self.dlq.depth_for_exporter("_deserialize") as u64,
                    );
                    tracing::warn!(
                        seq = seq,
                        "Failed to deserialize receipt -- captured to durable DLQ"
                    );
                    // Durably captured (or legacy None mode, which replays from
                    // seq=0 on restart), so advancing past it is now safe.
                    if *seq > max_seq {
                        max_seq = *seq;
                    }
                }
            }
        }

        if events.is_empty() {
            // Only malformed rows -- still advance cursor.
            self.cursor = max_seq;
            return Ok(());
        }

        // Fan out to each registered exporter with retry. The high-water mark
        // for an exporter advances only on confirmed acceptance (RFC-0009 F78).
        for index in 0..self.exporters.len() {
            let exporter = self.exporters[index].as_ref();
            let exporter_name = exporter.name().to_string();
            // Ack/cursor state is keyed per-instance (index + name); metrics stay
            // keyed by the bare name (Codex round-4 finding 4).
            let cursor_key = exporter_cursor_key(index, &exporter_name);
            let result = Self::export_with_retry(
                &mut self.rate_limiter,
                self.config.max_retries,
                self.config.base_backoff_ms,
                exporter,
                &events,
            )
            .await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            match result {
                Ok(_exported) => {
                    for _ in &events {
                        self.metrics
                            .record_export(&exporter_name, crate::metrics_sink::ExportOutcome::Ok);
                    }
                    // Lag: persistence-to-ack for the newest event in the batch.
                    if let Some(persisted) = events.iter().map(|e| e.receipt.timestamp).max() {
                        self.metrics.observe_export_lag(
                            &exporter_name,
                            "info",
                            now.saturating_sub(persisted) as f64,
                        );
                    }
                    self.acked.insert(cursor_key.clone(), max_seq);
                    if let Some(store) = &self.cursor_store {
                        store.set_acked(&cursor_key, max_seq)?;
                    }
                }
                Err(e) => {
                    for event in &events {
                        self.metrics
                            .record_export(&exporter_name, crate::metrics_sink::ExportOutcome::Dlq);
                        let event_json = serde_json::to_string(event).unwrap_or_else(|_| {
                            format!("{{\"serialize_error\": \"receipt {}\"}}", event.receipt.id)
                        });
                        self.dlq.push(FailedEvent {
                            event_json,
                            error: e.to_string(),
                            failed_at: now,
                            exporter_name: exporter_name.clone(),
                        });
                    }
                    tracing::warn!(
                        exporter = exporter_name,
                        error = %redact_for_operator_log(&e),
                        dlq_len = self.dlq.len(),
                        "All retries exhausted -- events pushed to DLQ; high-water mark held"
                    );
                    // acked_seq for this exporter is NOT advanced: the range is
                    // redelivered next poll (at-least-once). Idempotent ingest
                    // (ADR-0009) dedups downstream.
                }
            }
            // Report the DLQ depth attributed to THIS exporter only. Using the
            // global `self.dlq.len()` for every exporter label would report a
            // non-zero depth on a healthy exporter just because a different sink
            // failed in the same poll (Codex round-3 finding 4).
            self.metrics.set_dlq_depth(
                &exporter_name,
                self.dlq.depth_for_exporter(&exporter_name) as u64,
            );
        }

        // Advance the read cursor. In legacy None mode (no cursor store) the
        // cursor ALWAYS advances past the batch: delivery is not persisted and
        // downstream ingest dedups idempotently, so a failed exporter must not
        // hold the cursor or the next tick re-reads the same batch and pushes
        // duplicate DLQ entries indefinitely until it recovers (Codex round-2
        // finding 2 -- preserve the pre-F78 advance-regardless behavior). With a
        // configured cursor store the cursor resumes at the slowest REGISTERED
        // exporter so nothing is skipped: a registered exporter that has never
        // acked is held at its baseline (at-least-once, RFC-0009 F78, Codex
        // round-1 finding 1). Zero registered exporters falls back to max_seq.
        self.cursor = if self.cursor_store.is_some() {
            let exporter_keys: Vec<String> = self
                .exporters
                .iter()
                .enumerate()
                .map(|(index, e)| exporter_cursor_key(index, e.name()))
                .collect();
            let key_refs: Vec<&str> = exporter_keys.iter().map(String::as_str).collect();
            resume_cursor(&key_refs, &self.acked, cursor, max_seq)
        } else {
            max_seq
        };

        Ok(())
    }

    /// Call export_batch on an exporter with exponential backoff retry.
    ///
    /// Returns Ok(n) on success, or the last error after all retries are exhausted.
    async fn export_with_retry(
        rate_limiter: &mut Option<ExportRateLimiter>,
        max_retries: u32,
        base_backoff_ms: u64,
        exporter: &dyn Exporter,
        events: &[SiemEvent],
    ) -> Result<usize, ExportError> {
        let mut last_err: Option<ExportError> = None;

        for attempt in 0..=max_retries {
            if attempt > 0 {
                let backoff_ms = retry_backoff_ms(base_backoff_ms, attempt);
                tracing::debug!(
                    exporter = exporter.name(),
                    attempt = attempt,
                    backoff_ms = backoff_ms,
                    "Retrying export after backoff"
                );
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }

            Self::wait_for_export_slot(rate_limiter, exporter.name()).await;

            match exporter.export_batch(events).await {
                Ok(n) => return Ok(n),
                Err(e) => {
                    tracing::warn!(
                        exporter = exporter.name(),
                        attempt = attempt,
                        error = %redact_for_operator_log(&e),
                        "Export attempt failed"
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| ExportError::HttpError("unknown error".to_string())))
    }

    async fn wait_for_export_slot(
        rate_limiter: &mut Option<ExportRateLimiter>,
        exporter_name: &str,
    ) {
        let Some(rate_limiter) = rate_limiter.as_mut() else {
            return;
        };

        loop {
            let delay = rate_limiter.acquire_delay(exporter_name);
            if delay.is_zero() {
                return;
            }

            tracing::debug!(
                exporter = exporter_name,
                delay_ms = delay.as_millis() as u64,
                "Rate limiting exporter batch"
            );
            tokio::time::sleep(delay).await;
        }
    }
}

/// Per-instance cursor/ack key (RFC-0009 F78, Codex round-4 finding 4).
///
/// Built-in exporters return static names (every `WebhookExporter` is
/// "webhook"), so keying the high-water mark by name alone would let one
/// instance's ack advance a same-named peer's cursor and skip redelivery for a
/// failed peer, violating at-least-once. The registration index disambiguates
/// duplicate names. It is deterministic across restarts as long as exporters are
/// registered in the same order (they are, from a fixed config), so the durable
/// `siem_export_cursor` rows resume correctly. Distinct from the metric label,
/// which stays the bare exporter name (two "webhook" instances share the
/// "webhook" series, keeping label cardinality bounded).
fn exporter_cursor_key(index: usize, name: &str) -> String {
    format!("{index}:{name}")
}

/// Compute the read cursor after a poll: the minimum high-water mark across all
/// REGISTERED exporters, so the cursor never advances past receipts the slowest
/// exporter has not consumed (at-least-once, RFC-0009 F78).
///
/// A registered exporter absent from `acked` has never acked (it failed before
/// its first successful export); it is held at `baseline` (the pre-poll cursor)
/// so the un-acked batch is redelivered rather than skipped (Codex round-1
/// finding 1). With zero registered exporters the cursor advances to `max_seq`,
/// matching the legacy headless / malformed-only advance-regardless behavior.
fn resume_cursor(
    exporter_names: &[&str],
    acked: &std::collections::BTreeMap<String, u64>,
    baseline: u64,
    max_seq: u64,
) -> u64 {
    exporter_names
        .iter()
        .map(|name| acked.get(*name).copied().unwrap_or(baseline))
        .min()
        .unwrap_or(max_seq)
}

fn retry_backoff_ms(base_backoff_ms: u64, attempt: u32) -> u64 {
    let shift = attempt.saturating_sub(1).min(u64::BITS - 1);
    let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    base_backoff_ms
        .saturating_mul(multiplier)
        .min(MAX_RETRY_BACKOFF_MS)
}

fn validate_admin_read_context(read_context: &ReceiptReadContext) -> Result<(), SiemError> {
    if matches!(read_context.boundary, ReceiptReadBoundary::AdminAll) {
        Ok(())
    } else {
        Err(SiemError::ConfigError(
            "SIEM receipt polling requires explicit admin receipt read authority".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn resume_cursor_holds_at_baseline_for_a_never_acked_exporter() {
        // "webhook" is registered but has never acked (absent from `acked`).
        // Even though "splunk" acked up to seq 10, the cursor must be HELD at the
        // pre-poll baseline (3) so the batch is redelivered to "webhook"
        // (at-least-once). The old `min(acked)` logic would have advanced to 10,
        // permanently skipping [4..10] for "webhook".
        let mut acked = std::collections::BTreeMap::new();
        acked.insert("splunk".to_string(), 10u64);
        let cursor = resume_cursor(&["splunk", "webhook"], &acked, 3, 10);
        assert_eq!(
            cursor, 3,
            "a never-acked exporter holds the cursor at baseline"
        );
    }

    #[test]
    fn resume_cursor_advances_to_the_slowest_acked_exporter() {
        let mut acked = std::collections::BTreeMap::new();
        acked.insert("splunk".to_string(), 10u64);
        acked.insert("webhook".to_string(), 7u64);
        let cursor = resume_cursor(&["splunk", "webhook"], &acked, 3, 10);
        assert_eq!(
            cursor, 7,
            "the cursor resumes at the slowest acked exporter"
        );
    }

    #[test]
    fn resume_cursor_advances_to_max_seq_with_zero_exporters() {
        let acked = std::collections::BTreeMap::new();
        let cursor = resume_cursor(&[], &acked, 3, 10);
        assert_eq!(
            cursor, 10,
            "with no registered exporters the cursor advances (legacy headless behavior)"
        );
    }

    #[test]
    fn retry_backoff_ms_saturates_at_configured_ceiling() {
        assert_eq!(retry_backoff_ms(500, 1), 500);
        assert_eq!(retry_backoff_ms(500, 2), 1_000);
        assert_eq!(retry_backoff_ms(500, 40), MAX_RETRY_BACKOFF_MS);
    }

    #[test]
    fn retry_backoff_ms_saturates_overflowing_base_delay() {
        assert_eq!(retry_backoff_ms(u64::MAX, 2), MAX_RETRY_BACKOFF_MS);
    }

    #[test]
    fn manager_new_rejects_zero_poll_interval_before_opening_db() {
        let error = match ExporterManager::new(SiemConfig {
            db_path: PathBuf::from("/definitely/not/a/chio/receipt/db.sqlite3"),
            poll_interval: Duration::ZERO,
            ..SiemConfig::default()
        }) {
            Ok(_) => panic!("zero poll interval should be rejected before opening db"),
            Err(error) => error,
        };

        assert!(
            matches!(error, SiemError::ConfigError(message) if message.contains("poll_interval"))
        );
    }

    #[test]
    fn manager_new_rejects_non_admin_read_context_before_opening_db() -> TestResult {
        let error = match ExporterManager::new(SiemConfig {
            db_path: PathBuf::from("/definitely/not/a/chio/receipt/db.sqlite3"),
            read_context: ReceiptReadContext::authenticated_tenant("tenant-a"),
            ..SiemConfig::default()
        }) {
            Ok(_) => {
                return Err(std::io::Error::other(
                    "tenant-scoped read context should be rejected before opening db",
                )
                .into());
            }
            Err(error) => error,
        };

        assert!(
            matches!(error, SiemError::ConfigError(message) if message.contains("admin receipt read authority"))
        );
        Ok(())
    }

    /// Seed a receipt DB carrying a single malformed row at seq=1.
    fn seed_malformed_receipt_db(path: &std::path::Path) -> TestResult {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE chio_tool_receipts (
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 receipt_id TEXT NOT NULL UNIQUE,
                 timestamp INTEGER NOT NULL,
                 capability_id TEXT NOT NULL,
                 tool_server TEXT NOT NULL,
                 tool_name TEXT NOT NULL,
                 decision_kind TEXT NOT NULL,
                 policy_hash TEXT NOT NULL,
                 content_hash TEXT NOT NULL,
                 raw_json TEXT NOT NULL
             );",
        )?;
        conn.execute(
            "INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, \
             tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json) \
             VALUES ('m1', 1, 'c', 's', 't', 'allow', 'p', 'h', 'not valid receipt json')",
            [],
        )?;
        Ok(())
    }

    /// Codex #6 / RFC-0009 F80: a malformed row is durably persisted to the
    /// cursor DB's dead_letters table BEFORE the read cursor advances past it.
    #[tokio::test]
    async fn malformed_row_persisted_durably_before_cursor_advances() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_malformed_receipt_db(&receipt_db)?;
        let cursor_db = dir.path().join("cursor.sqlite3");

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?;

        // No exporters: a malformed-only batch. A healthy poll must persist the
        // malformed row durably and only then advance the read cursor.
        manager.poll_once().await?;

        assert_eq!(
            manager.cursor, 1,
            "cursor advances past a durably-persisted malformed row"
        );
        let store = crate::cursor_store::SiemCursorStore::open(&cursor_db)?;
        assert_eq!(
            store.dead_letter_seqs()?,
            vec![1u64],
            "the malformed row must be durably captured in dead_letters"
        );
        Ok(())
    }

    /// Codex #6 / RFC-0009 F80: if the durable persist fails, the cursor is left
    /// BEHIND the malformed row (not advanced), so at-least-once is preserved and
    /// the next poll re-reads it.
    #[tokio::test]
    async fn malformed_row_persist_failure_leaves_cursor_behind() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_malformed_receipt_db(&receipt_db)?;
        let cursor_db = dir.path().join("cursor.sqlite3");

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?;

        // Force the durable persist to fail: drop the dead_letters table out from
        // under the manager's cursor-store connection via a second connection.
        {
            let conn = rusqlite::Connection::open(&cursor_db)?;
            conn.execute("DROP TABLE siem_dead_letters", [])?;
        }

        let result = manager.poll_once().await;
        assert!(
            result.is_err(),
            "a durable-persist failure must propagate and hold the cursor"
        );
        assert_eq!(
            manager.cursor, 0,
            "the cursor must stay behind an un-persisted malformed row (at-least-once)"
        );
        Ok(())
    }

    /// A metrics sink that records every `set_dlq_depth` call for assertions.
    #[derive(Default)]
    struct RecordingSink {
        dlq_depths: Mutex<Vec<(String, u64)>>,
    }

    impl crate::metrics_sink::SiemMetricsSink for RecordingSink {
        fn record_export(&self, _exporter: &str, _outcome: crate::metrics_sink::ExportOutcome) {}
        fn observe_export_lag(&self, _exporter: &str, _severity: &str, _lag_seconds: f64) {}
        fn set_dlq_depth(&self, exporter: &str, depth: u64) {
            if let Ok(mut depths) = self.dlq_depths.lock() {
                depths.push((exporter.to_string(), depth));
            }
        }
        fn record_alert_dispatch(&self, _route: &str, _outcome: &str) {}
        fn observe_alert_dispatch_latency(&self, _route: &str, _outcome: &str, _latency: f64) {}
    }

    /// A mock exporter that always succeeds (records nothing).
    struct OkExporter {
        name: String,
    }

    impl Exporter for OkExporter {
        fn export_batch<'a>(
            &'a self,
            events: &'a [SiemEvent],
        ) -> crate::exporter::ExportFuture<'a> {
            let n = events.len();
            Box::pin(async move { Ok(n) })
        }
        fn name(&self) -> &str {
            &self.name
        }
    }

    /// A mock exporter that always fails, forcing the batch into the DLQ.
    struct FailExporter {
        name: String,
    }

    impl Exporter for FailExporter {
        fn export_batch<'a>(
            &'a self,
            _events: &'a [SiemEvent],
        ) -> crate::exporter::ExportFuture<'a> {
            Box::pin(async move { Err(ExportError::HttpError("simulated failure".to_string())) })
        }
        fn name(&self) -> &str {
            &self.name
        }
    }

    /// Sign a minimal-but-valid receipt so the poll loop parses it into an event.
    fn sample_receipt(id: &str) -> Result<chio_core::receipt::body::ChioReceipt, Box<dyn Error>> {
        use chio_core::crypto::Keypair;
        use chio_core::receipt::{
            body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
        };
        let keypair = Keypair::generate();
        let action = ToolCallAction::from_parameters(serde_json::json!({}))
            .map_err(|error| format!("action parameters serialize in tests: {error}"))?;
        let body = ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1,
            capability_id: "cap-manager-test".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "content-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, &keypair)
            .map_err(|error| format!("ChioReceipt::sign must succeed in tests: {error}").into())
    }

    /// Seed a receipt DB with `count` valid receipts (seq 1..=count).
    fn seed_valid_receipt_db(path: &std::path::Path, count: usize) -> TestResult {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE chio_tool_receipts (
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 receipt_id TEXT NOT NULL UNIQUE,
                 timestamp INTEGER NOT NULL,
                 capability_id TEXT NOT NULL,
                 tool_server TEXT NOT NULL,
                 tool_name TEXT NOT NULL,
                 decision_kind TEXT NOT NULL,
                 policy_hash TEXT NOT NULL,
                 content_hash TEXT NOT NULL,
                 raw_json TEXT NOT NULL
             );",
        )?;
        for i in 0..count {
            let receipt = sample_receipt(&format!("rcpt-{i:04}"))?;
            let raw_json = serde_json::to_string(&receipt)?;
            conn.execute(
                "INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, \
                 tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json) \
                 VALUES (?1, 1, 'c', 's', 't', 'allow', 'p', 'h', ?2)",
                rusqlite::params![receipt.id, raw_json],
            )?;
        }
        Ok(())
    }

    /// Codex round-2 finding 1: on startup with a cursor store, a registered
    /// exporter that has NO persisted cursor row is treated as baseline (0), so
    /// it pins the resume cursor at 0 until it acks -- even when a peer exporter
    /// has already persisted an advanced high-water mark. Without the fix, the
    /// startup cursor would resume at the persisted peer's mark and the newly
    /// registered exporter would permanently skip the earlier backlog.
    #[tokio::test]
    async fn missing_exporter_cursor_pins_resume_at_baseline_on_startup() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_valid_receipt_db(&receipt_db, 3)?;
        let cursor_db = dir.path().join("cursor.sqlite3");
        {
            // "splunk" (registration index 0) has already acked up to seq 100;
            // "webhook" has no row. The durable key is per-instance (Codex
            // round-4 finding 4), so pre-seed under splunk's index-keyed row.
            let store = crate::cursor_store::SiemCursorStore::open(&cursor_db)?;
            store.set_acked(&exporter_cursor_key(0, "splunk"), 100)?;
        }

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?;
        assert_eq!(
            manager.cursor, 100,
            "before webhook registers, the cursor resumes at the persisted mark"
        );
        manager.add_exporter(Box::new(OkExporter {
            name: "splunk".to_string(),
        }));
        manager.add_exporter(Box::new(OkExporter {
            name: "webhook".to_string(),
        }));
        assert_eq!(
            manager.cursor, 0,
            "a registered exporter with no persisted cursor row pins resume at baseline 0"
        );
        Ok(())
    }

    /// Codex round-2 finding 2: in the default None mode (no cursor store) a
    /// failed exporter must NOT hold the read cursor. The cursor advances to
    /// max_seq (legacy advance-regardless) so the next poll does not re-read and
    /// re-DLQ the same batch forever.
    #[tokio::test]
    async fn legacy_none_mode_advances_cursor_past_failed_batch() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_valid_receipt_db(&receipt_db, 3)?;

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            max_retries: 0,
            cursor_db_path: None,
            ..SiemConfig::default()
        })?;
        manager.add_exporter(Box::new(FailExporter {
            name: "webhook".to_string(),
        }));

        manager.poll_once().await?;
        assert_eq!(
            manager.cursor, 3,
            "None mode advances past the DLQ'd batch (legacy behavior preserved)"
        );
        Ok(())
    }

    /// Codex round-2 finding 2 (paired): WITH a cursor store, the same failed
    /// exporter holds the cursor at its baseline so the un-acked batch is
    /// redelivered (at-least-once), the behavior that must be gated on a
    /// configured store.
    #[tokio::test]
    async fn configured_store_holds_cursor_for_failed_never_acked_exporter() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_valid_receipt_db(&receipt_db, 3)?;
        let cursor_db = dir.path().join("cursor.sqlite3");

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            max_retries: 0,
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?;
        manager.add_exporter(Box::new(FailExporter {
            name: "webhook".to_string(),
        }));

        manager.poll_once().await?;
        assert_eq!(
            manager.cursor, 0,
            "with a cursor store the failed never-acked exporter holds the cursor at baseline"
        );
        Ok(())
    }

    /// Codex round-2 finding 3: a batch of only malformed rows returns before the
    /// exporter loop, so the `_deserialize` DLQ-depth gauge must be reported from
    /// the malformed-capture path itself or it stays absent while the DLQ grows.
    #[tokio::test]
    async fn malformed_row_reports_deserialize_dlq_depth() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_malformed_receipt_db(&receipt_db)?;
        let cursor_db = dir.path().join("cursor.sqlite3");

        let sink = std::sync::Arc::new(RecordingSink::default());
        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?
        .with_metrics_sink(sink.clone());

        manager.poll_once().await?;

        let depths = sink
            .dlq_depths
            .lock()
            .map_err(|_| std::io::Error::other("dlq depth lock poisoned"))?;
        assert!(
            depths.contains(&("_deserialize".to_string(), 1)),
            "the deserialize DLQ depth must be reported for a malformed row: {depths:?}"
        );
        Ok(())
    }

    /// Seed a receipt DB with `valid` valid receipts (seq 1..=valid) followed by
    /// one malformed row (seq valid+1).
    fn seed_valid_then_malformed_receipt_db(path: &std::path::Path, valid: usize) -> TestResult {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE chio_tool_receipts (
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 receipt_id TEXT NOT NULL UNIQUE,
                 timestamp INTEGER NOT NULL,
                 capability_id TEXT NOT NULL,
                 tool_server TEXT NOT NULL,
                 tool_name TEXT NOT NULL,
                 decision_kind TEXT NOT NULL,
                 policy_hash TEXT NOT NULL,
                 content_hash TEXT NOT NULL,
                 raw_json TEXT NOT NULL
             );",
        )?;
        for i in 0..valid {
            let receipt = sample_receipt(&format!("rcpt-{i:04}"))?;
            let raw_json = serde_json::to_string(&receipt)?;
            conn.execute(
                "INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, \
                 tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json) \
                 VALUES (?1, 1, 'c', 's', 't', 'allow', 'p', 'h', ?2)",
                rusqlite::params![receipt.id, raw_json],
            )?;
        }
        conn.execute(
            "INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, \
             tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json) \
             VALUES ('malformed-1', 1, 'c', 's', 't', 'allow', 'p', 'h', 'not valid receipt json')",
            [],
        )?;
        Ok(())
    }

    /// Codex round-4 finding 2: the `_deserialize` DLQ-depth gauge must count only
    /// `_deserialize` entries, never the global queue length. A coexisting
    /// exporter backlog must not inflate the malformed-row gauge (the
    /// cross-exporter attribution bug round-3 F4 fixed for the exporter path, but
    /// which the malformed-capture path still exhibited).
    #[tokio::test]
    async fn deserialize_dlq_depth_excludes_other_exporter_backlog() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        // seq 1,2 valid; seq 3 malformed.
        seed_valid_then_malformed_receipt_db(&receipt_db, 2)?;

        let sink = std::sync::Arc::new(RecordingSink::default());
        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            max_retries: 0,
            // Batch of 2 so poll 1 reads only the two valid rows and poll 2 reads
            // the malformed row alone (a malformed-only batch).
            batch_size: 2,
            // Legacy None mode: the cursor advances past the failed batch so poll 2
            // reaches the malformed row.
            cursor_db_path: None,
            ..SiemConfig::default()
        })?
        .with_metrics_sink(sink.clone());
        // A failing exporter fills the SHARED DLQ with two "webhook" entries.
        manager.add_exporter(Box::new(FailExporter {
            name: "webhook".to_string(),
        }));

        // Poll 1: both valid rows fail export -> 2 "webhook" DLQ entries.
        manager.poll_once().await?;
        // Poll 2: the malformed row alone -> the _deserialize gauge must report 1,
        // not the global DLQ length of 3 (2 webhook + 1 _deserialize).
        manager.poll_once().await?;

        assert_eq!(
            manager.dlq_len(),
            3,
            "the shared DLQ holds the webhook backlog plus the malformed row"
        );
        let depths = sink
            .dlq_depths
            .lock()
            .map_err(|_| std::io::Error::other("dlq depth lock poisoned"))?;
        let deserialize_depth = depths
            .iter()
            .rev()
            .find(|(name, _)| name == "_deserialize")
            .map(|(_, depth)| *depth);
        assert_eq!(
            deserialize_depth,
            Some(1),
            "the _deserialize gauge must exclude the webhook backlog: {depths:?}"
        );
        Ok(())
    }

    /// Codex round-3 finding 4: when one exporter fails and another succeeds in
    /// the same poll, the DLQ depth must be attributed to the FAILING exporter
    /// only. A healthy exporter must report depth 0 even though a different sink
    /// filled the shared DLQ.
    #[tokio::test]
    async fn dlq_depth_is_attributed_to_the_failing_exporter_only() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_valid_receipt_db(&receipt_db, 2)?;

        let sink = std::sync::Arc::new(RecordingSink::default());
        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            max_retries: 0,
            cursor_db_path: None,
            ..SiemConfig::default()
        })?
        .with_metrics_sink(sink.clone());
        // Register the failing exporter FIRST so the shared DLQ is already
        // non-empty when the succeeding exporter's depth is reported.
        manager.add_exporter(Box::new(FailExporter {
            name: "fail-sink".to_string(),
        }));
        manager.add_exporter(Box::new(OkExporter {
            name: "ok-sink".to_string(),
        }));

        manager.poll_once().await?;

        let depths = sink
            .dlq_depths
            .lock()
            .map_err(|_| std::io::Error::other("dlq depth lock poisoned"))?;
        assert!(
            depths.contains(&("ok-sink".to_string(), 0)),
            "the succeeding exporter must report DLQ depth 0: {depths:?}"
        );
        assert!(
            depths
                .iter()
                .any(|(name, depth)| name == "fail-sink" && *depth > 0),
            "the failing exporter must report its own non-zero DLQ depth: {depths:?}"
        );
        Ok(())
    }

    /// Codex round-4 finding 4: high-water marks must be keyed by a unique
    /// per-instance identity, not by exporter name alone. Two exporters that
    /// return the same static name ("webhook") - as every built-in
    /// WebhookExporter does - must keep DISTINCT cursor state. When index 0 acks
    /// and index 1 exhausts retries, the failed instance's range must be
    /// redelivered (at-least-once), not skipped because its same-named peer
    /// advanced a shared key.
    #[tokio::test]
    async fn duplicate_exporter_names_keep_distinct_cursor_state() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_valid_receipt_db(&receipt_db, 3)?;
        let cursor_db = dir.path().join("cursor.sqlite3");

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            max_retries: 0,
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?;
        // Both instances report the name "webhook": index 0 succeeds, index 1
        // fails. Under name-only keying the succeeding instance's ack would
        // advance the shared "webhook" mark and skip redelivery for the failed
        // one, violating at-least-once.
        manager.add_exporter(Box::new(OkExporter {
            name: "webhook".to_string(),
        }));
        manager.add_exporter(Box::new(FailExporter {
            name: "webhook".to_string(),
        }));

        manager.poll_once().await?;

        // The failed instance (index 1) never acked, so the read cursor is HELD
        // at baseline 0 for redelivery. Name-only keying would have advanced the
        // shared mark to 3 and permanently skipped [1..3] for the failed one.
        assert_eq!(
            manager.cursor, 0,
            "the failed same-named instance holds the cursor at baseline for redelivery"
        );
        // The succeeding instance still advanced its OWN durable high-water mark.
        let store = crate::cursor_store::SiemCursorStore::open(&cursor_db)?;
        assert_eq!(
            store.acked_seqs()?.values().copied().max(),
            Some(3),
            "the succeeding instance advanced its own high-water mark"
        );
        Ok(())
    }
}
