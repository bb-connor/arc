//! ExporterManager: cursor-pull loop that reads receipts from SQLite and fans out to exporters.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::params;
use tokio::sync::watch;

use crate::dlq::{DeadLetterQueue, FailedEvent};
use crate::event::SiemEvent;
use crate::exporter::{ExportError, Exporter};

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
    /// Path to the PACT kernel receipt SQLite database.
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
        }
    }
}

/// Manages the receipt cursor-pull loop and fans events out to registered exporters.
///
/// The manager reads receipts from the PACT kernel SQLite database using a
/// seq-based cursor, builds SiemEvents, and forwards batches to each registered
/// Exporter. Failed exports are retried with exponential backoff; events that
/// exhaust all retries are placed on the DeadLetterQueue.
///
/// The cursor is NOT persisted to disk. On restart, the manager re-exports all
/// receipts from seq=0. Both Splunk HEC (timestamp dedup) and Elasticsearch
/// (_id upsert) handle duplicate events idempotently.
pub struct ExporterManager {
    exporters: Vec<Box<dyn Exporter>>,
    dlq: DeadLetterQueue,
    cursor: u64,
    config: SiemConfig,
}

impl ExporterManager {
    /// Create a new ExporterManager with the given configuration.
    pub fn new(config: SiemConfig) -> Self {
        let dlq = DeadLetterQueue::new(config.dlq_capacity);
        Self {
            exporters: Vec::new(),
            dlq,
            cursor: 0,
            config,
        }
    }

    /// Register an exporter to receive receipt batches.
    pub fn add_exporter(&mut self, exporter: Box<dyn Exporter>) {
        self.exporters.push(exporter);
    }

    /// Return the current number of entries in the dead-letter queue.
    pub fn dlq_len(&self) -> usize {
        self.dlq.len()
    }

    /// Run the cursor-pull loop until the cancellation channel signals true.
    ///
    /// On each tick, opens a fresh read-only rusqlite connection, fetches the
    /// next batch of receipts after the current cursor, builds SiemEvents, and
    /// fans them out to all registered exporters with exponential backoff retry.
    /// Events that exhaust all retries are placed on the DLQ. The cursor is
    /// advanced past the batch after all exporters have processed it (whether
    /// successful or DLQ'd).
    pub async fn run(&mut self, mut cancel: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(self.config.poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.poll_once().await {
                        tracing::error!(error = %e, "SIEM poll cycle failed");
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
    async fn poll_once(&mut self) -> Result<(), SiemError> {
        let db_path = self.config.db_path.clone();
        let cursor = self.cursor;
        let batch_size = self.config.batch_size;

        // Open a fresh connection per-poll in spawn_blocking to avoid holding a
        // read lock across polls. WAL-mode readers do not block kernel writers.
        let rows = tokio::task::spawn_blocking(move || -> Result<Vec<(u64, String)>, SiemError> {
            let conn = rusqlite::Connection::open_with_flags(
                &db_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|e| SiemError::DbError(e.to_string()))?;

            let mut stmt = conn
                .prepare(
                    "SELECT seq, raw_json \
                     FROM pact_tool_receipts \
                     WHERE seq > ?1 \
                     ORDER BY seq ASC \
                     LIMIT ?2",
                )
                .map_err(|e| SiemError::DbError(e.to_string()))?;

            let rows = stmt
                .query_map(params![cursor as i64, batch_size as i64], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|e| SiemError::DbError(e.to_string()))?;

            let mut result = Vec::new();
            for row in rows {
                let (seq, raw_json) = row.map_err(|e| SiemError::DbError(e.to_string()))?;
                result.push((seq.max(0) as u64, raw_json));
            }
            Ok(result)
        })
        .await
        .map_err(|e| SiemError::DbError(format!("spawn_blocking join error: {e}")))?
        .map_err(|e| SiemError::DbError(e.to_string()))?;

        if rows.is_empty() {
            return Ok(());
        }

        // Parse rows into SiemEvents.
        let mut events: Vec<SiemEvent> = Vec::with_capacity(rows.len());
        let mut max_seq = self.cursor;

        for (seq, raw_json) in &rows {
            match serde_json::from_str::<pact_core::receipt::PactReceipt>(raw_json) {
                Ok(receipt) => {
                    events.push(SiemEvent::from_receipt(receipt));
                    if *seq > max_seq {
                        max_seq = *seq;
                    }
                }
                Err(e) => {
                    tracing::warn!(seq = seq, error = %e, "Failed to deserialize receipt -- skipping");
                    // Still advance past malformed rows.
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

        let mut any_dlq = false;

        // Fan out to each registered exporter with retry.
        for exporter in &self.exporters {
            let result = self.export_with_retry(exporter.as_ref(), &events).await;
            if let Err(e) = result {
                any_dlq = true;
                // Serialize failed events and push to DLQ.
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                for event in &events {
                    let event_json = serde_json::to_string(event).unwrap_or_else(|_| {
                        format!("{{\"serialize_error\": \"receipt {}\"}}", event.receipt.id)
                    });
                    self.dlq.push(FailedEvent {
                        event_json,
                        error: e.to_string(),
                        failed_at: now,
                        exporter_name: exporter.name().to_string(),
                    });
                }

                tracing::warn!(
                    exporter = exporter.name(),
                    error = %e,
                    dlq_len = self.dlq.len(),
                    "All retries exhausted -- events pushed to DLQ"
                );
            }
        }

        // CRITICAL: advance cursor regardless of DLQ status so we do not re-poll the same range.
        if any_dlq {
            tracing::info!(
                seq_range_start = self.cursor,
                seq_range_end = max_seq,
                "Cursor advanced past batch containing DLQ'd events"
            );
        }
        self.cursor = max_seq;

        Ok(())
    }

    /// Call export_batch on an exporter with exponential backoff retry.
    ///
    /// Returns Ok(n) on success, or the last error after all retries are exhausted.
    async fn export_with_retry(
        &self,
        exporter: &dyn Exporter,
        events: &[SiemEvent],
    ) -> Result<usize, ExportError> {
        let mut last_err: Option<ExportError> = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                let backoff_ms = self.config.base_backoff_ms * (1u64 << (attempt - 1));
                tracing::debug!(
                    exporter = exporter.name(),
                    attempt = attempt,
                    backoff_ms = backoff_ms,
                    "Retrying export after backoff"
                );
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }

            match exporter.export_batch(events).await {
                Ok(n) => return Ok(n),
                Err(e) => {
                    tracing::warn!(
                        exporter = exporter.name(),
                        attempt = attempt,
                        error = %e,
                        "Export attempt failed"
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| ExportError::HttpError("unknown error".to_string())))
    }
}
