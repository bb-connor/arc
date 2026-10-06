//! Fenced terminal-envelope maintenance. Eligible bytes are decoded only after
//! the immutable-size byte ceiling and indexed ownership checks pass.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[path = "payload_compaction/eligibility.rs"]
mod eligibility;
use eligibility::{qualified_replay_owners, ReplayOwners};

/// Operator-selected ceilings for a single maintenance transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolOutcomeCompactionLimits {
    /// Includes compacted, recent and non-raw blobs inspected for cursor progress.
    pub max_rows: usize,
    /// Maximum payload bytes inspected or cleared, measured from immutable sizes.
    pub max_payload_bytes: u64,
    /// SQLite VM instructions, including fence, clock and anchor verification.
    pub max_sql_steps: u64,
}

impl Default for ToolOutcomeCompactionLimits {
    fn default() -> Self {
        Self {
            max_rows: 64,
            max_payload_bytes: 16 * 1024 * 1024,
            max_sql_steps: 2_000_000,
        }
    }
}

impl ToolOutcomeCompactionLimits {
    pub fn validate(self) -> Result<Self, ToolOutcomeStoreError> {
        if self.max_rows == 0
            || self.max_rows > 1_024
            || self.max_payload_bytes == 0
            || self.max_payload_bytes > 269_484_032
            || self.max_sql_steps == 0
            || self.max_sql_steps > 10_000_000
        {
            return Err(invariant(
                "terminal raw payload compaction limits are outside their bounds",
            ));
        }
        Ok(self)
    }
}

/// A committed page. Reaching the cursor boundary is not a claim of universal erasure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolOutcomeCompactionPage {
    pub inspected: u64,
    pub compacted: u64,
    pub compacted_bytes: u64,
    /// Original bytes decoded for retention classification in this page.
    pub inspected_payload_bytes: u64,
    /// Preflight bytes for authenticating the selected owners and their sealed
    /// replay evidence. Combined with payload bytes under the same byte cap.
    pub inspected_verification_bytes: u64,
    /// Decoded raw owners, independently bounded by `max_rows` per page.
    pub inspected_owner_rows: u64,
    pub retained_live: u64,
    pub retained_resolved: u64,
    pub retained_unsupported: u64,
    pub retained_non_completed: u64,
    pub retained_owner_budget: u64,
    /// The last inspected digest; None means the current scan reached its tail.
    /// A later scan starts at None so newly terminal or rehydrated blobs are revisited.
    pub next_digest: Option<AdmissionDigest>,
    /// This page stopped before a terminal blob that would exceed its byte ceiling.
    pub byte_budget_exhausted: bool,
    pub sql_steps: u64,
}

impl SqliteToolOutcomeStore {
    /// Inspect at most `max_rows` blob metadata rows in digest order. The default
    /// byte and SQL ceilings still apply; production owners may select tighter limits.
    pub fn compact_retained_invocation_blobs_page(
        &self,
        retention_cutoff_unix_ms: u64,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        after_digest: Option<&AdmissionDigest>,
        max_rows: usize,
    ) -> Result<ToolOutcomeCompactionPage, ToolOutcomeStoreError> {
        self.compact_retained_invocation_blobs_page_with_limits(
            retention_cutoff_unix_ms,
            active_fence,
            trusted_now_unix_ms,
            after_digest,
            ToolOutcomeCompactionLimits {
                max_rows,
                ..ToolOutcomeCompactionLimits::default()
            },
        )
    }

    /// Derive time and the cutoff from this existing serving owner's authority
    /// clock. A maintenance worker supplies a TTL, never a client timestamp.
    pub fn compact_terminal_invocation_blobs_page(
        &self,
        terminal_raw_payload_ttl_ms: u64,
        active_fence: &StoreMutationFence,
        after_digest: Option<&AdmissionDigest>,
        limits: ToolOutcomeCompactionLimits,
    ) -> Result<ToolOutcomeCompactionPage, ToolOutcomeStoreError> {
        if terminal_raw_payload_ttl_ms == 0 {
            return Err(invariant("terminal raw payload TTL must be positive"));
        }
        let now = self
            .serving_owner
            .clock
            .unix_millis()
            .map_err(|error| ToolOutcomeStoreError::Unavailable(error.to_string()))?
            .get();
        self.compact_retained_invocation_blobs_page_with_limits(
            now.saturating_sub(terminal_raw_payload_ttl_ms),
            active_fence,
            now,
            after_digest,
            limits,
        )
    }

    pub fn compact_retained_invocation_blobs_page_with_limits(
        &self,
        retention_cutoff_unix_ms: u64,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        after_digest: Option<&AdmissionDigest>,
        limits: ToolOutcomeCompactionLimits,
    ) -> Result<ToolOutcomeCompactionPage, ToolOutcomeStoreError> {
        let limits = limits.validate()?;
        if retention_cutoff_unix_ms > trusted_now_unix_ms {
            return Err(invariant(
                "terminal raw payload cutoff exceeds trusted time",
            ));
        }
        let cutoff = sqlite_u64(retention_cutoff_unix_ms, "retention_cutoff_unix_ms")?;
        let mut connection = self
            .connection
            .lock_for_maintenance()
            .map_err(|error| ToolOutcomeStoreError::Unavailable(error.to_string()))?;
        // Install before BEGIN so custody/anchor checks cannot hide an unbounded
        // scan before the limited selection. Clear before any recovery rollback.
        let result = {
            let mut budget = CompactionSqlBudget::new(&mut connection, limits.max_sql_steps)?;
            let result = self.compact_page_under_budget(
                budget.connection(),
                cutoff,
                active_fence,
                trusted_now_unix_ms,
                after_digest,
                limits,
            );
            budget.finish(result)
        };
        if !connection.is_autocommit() {
            connection.execute_batch("ROLLBACK").map_err(|error| {
                ToolOutcomeStoreError::Unavailable(
                    self.serving_owner
                        .outcome_unknown(format!(
                            "terminal raw payload maintenance rollback failed: {error}"
                        ))
                        .to_string(),
                )
            })?;
            if !connection.is_autocommit() {
                return Err(ToolOutcomeStoreError::Unavailable(
                    self.serving_owner
                        .outcome_unknown(
                            "terminal raw payload maintenance left an open transaction",
                        )
                        .to_string(),
                ));
            }
        }
        result
    }

    fn compact_page_under_budget(
        &self,
        connection: &mut Connection,
        cutoff: i64,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        after_digest: Option<&AdmissionDigest>,
        limits: ToolOutcomeCompactionLimits,
    ) -> Result<ToolOutcomeCompactionPage, ToolOutcomeStoreError> {
        let transaction = self.begin_write(connection, active_fence, trusted_now_unix_ms)?;
        let rows = {
            let mut statement = transaction.prepare(
                "SELECT digest, blob_size_bytes, recorded_at_unix_ms, canonical_bytes IS NOT NULL
                 FROM tool_outcome_blobs WHERE digest > ?1 ORDER BY digest LIMIT ?2"
            ).map_err(sqlite_error)?;
            let rows = statement
                .query_map(
                    params![
                        after_digest.map_or("", AdmissionDigest::as_str),
                        i64::try_from(limits.max_rows)
                            .map_err(|_| invariant("invalid compaction row ceiling"))?,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, bool>(3)?,
                        ))
                    },
                )
                .map_err(sqlite_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
        };
        let full_page = rows.len() == limits.max_rows;
        let mut page = ToolOutcomeCompactionPage {
            inspected: 0,
            compacted: 0,
            compacted_bytes: 0,
            inspected_payload_bytes: 0,
            inspected_verification_bytes: 0,
            inspected_owner_rows: 0,
            retained_live: 0,
            retained_resolved: 0,
            retained_unsupported: 0,
            retained_non_completed: 0,
            retained_owner_budget: 0,
            next_digest: None,
            byte_budget_exhausted: false,
            sql_steps: 0,
        };
        let mut last_inspected = after_digest.cloned();
        for (digest, size, recorded_at, present) in rows {
            page.inspected = page.inspected.saturating_add(1);
            let digest = AdmissionDigest::try_new("compaction_digest", digest)
                .map_err(|error| invariant(error.to_string()))?;
            if present && recorded_at <= cutoff {
                let (raw_owner, live_owner, resolved_owner, non_completed): (bool, bool, bool, bool) = transaction
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM tool_outcomes INDEXED BY tool_outcomes_raw_digest_owners WHERE raw_output_digest = ?1),
                        EXISTS(SELECT 1 FROM tool_outcomes AS o INDEXED BY tool_outcomes_raw_digest_owners JOIN admission_operations a
                            ON a.operation_id = o.operation_id
                            WHERE o.raw_output_digest = ?1 AND a.terminal = 0),
                        EXISTS(SELECT 1 FROM tool_outcomes INDEXED BY tool_outcomes_resolved_digest_owners
                            WHERE json_extract(outcome_json, '$.disposition.resolved_output.digest') = ?1)
                        OR EXISTS(SELECT 1 FROM post_return_evaluations INDEXED BY post_return_evaluations_resolved_digest_owners
                            WHERE json_extract(evaluation_json, '$.state.resolution.resolved_output.digest') = ?1),
                        EXISTS(SELECT 1 FROM tool_outcomes AS o INDEXED BY tool_outcomes_raw_digest_owners JOIN admission_operations a
                            ON a.operation_id=o.operation_id WHERE o.raw_output_digest=?1 AND a.state <> 'completed')",
                        [digest.as_str()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .map_err(sqlite_error)?;
                if raw_owner && live_owner {
                    page.retained_live = page.retained_live.saturating_add(1);
                } else if raw_owner && resolved_owner {
                    page.retained_resolved = page.retained_resolved.saturating_add(1);
                } else if raw_owner && non_completed {
                    page.retained_non_completed = page.retained_non_completed.saturating_add(1);
                } else if raw_owner {
                    let size = u64::try_from(size)
                        .map_err(|_| invariant("invalid retained payload size"))?;
                    let next_bytes = page
                        .inspected_payload_bytes
                        .checked_add(size)
                        .and_then(|bytes| bytes.checked_add(page.inspected_verification_bytes))
                        .ok_or_else(|| invariant("compaction byte count overflow"))?;
                    if next_bytes > limits.max_payload_bytes {
                        if page.inspected_payload_bytes == 0 {
                            return Err(ToolOutcomeStoreError::Unavailable(
                                "terminal raw payload exceeds the maintenance payload byte budget; bytes and cursor retained".into()
                            ));
                        }
                        page.byte_budget_exhausted = true;
                        break;
                    }
                    let bytes: Vec<u8> = transaction
                        .query_row(
                            "SELECT canonical_bytes FROM tool_outcome_blobs WHERE digest = ?1",
                            [digest.as_str()],
                            |row| row.get(0),
                        )
                        .map_err(sqlite_error)?;
                    if u64::try_from(bytes.len()).ok() != Some(size)
                        || sha256_hex(&bytes) != digest.as_str()
                    {
                        return Err(invariant("selected retention payload conflicts with its immutable digest or size"));
                    }
                    page.inspected_payload_bytes =
                        page.inspected_payload_bytes.saturating_add(size);
                    let raw = RawInvocationOutcomeV1::from_canonical_bytes(&bytes)
                        .map_err(|error| invariant(error.to_string()))?;
                    if !raw.supports_compacted_value_replay() {
                        page.retained_unsupported = page.retained_unsupported.saturating_add(1);
                        last_inspected = Some(digest);
                        continue;
                    }
                    match qualified_replay_owners(
                        &transaction,
                        &raw,
                        &digest,
                        size,
                        &mut page,
                        limits,
                    )? {
                        ReplayOwners::Qualified => {}
                        ReplayOwners::Unsupported => {
                            page.retained_unsupported = page.retained_unsupported.saturating_add(1);
                            last_inspected = Some(digest);
                            continue;
                        }
                        ReplayOwners::OwnerBudget => {
                            page.retained_owner_budget =
                                page.retained_owner_budget.saturating_add(1);
                            last_inspected = Some(digest);
                            continue;
                        }
                        ReplayOwners::ByteDeferred => {
                            if page.compacted == 0 {
                                return Err(ToolOutcomeStoreError::Unavailable("terminal raw payload replay verification exceeds the maintenance payload byte budget; bytes and cursor retained".into()));
                            }
                            page.byte_budget_exhausted = true;
                            break;
                        }
                    }
                    // Keep the schema's independent all-owner terminal trigger.
                    let changed = transaction
                        .execute(
                            "UPDATE tool_outcome_blobs SET canonical_bytes = NULL
                         WHERE digest = ?1 AND canonical_bytes IS NOT NULL",
                            [digest.as_str()],
                        )
                        .map_err(sqlite_error)?;
                    if changed != 1 {
                        return Err(invariant("compaction lost its selected payload"));
                    }
                    page.compacted = page.compacted.saturating_add(1);
                    page.compacted_bytes = page.compacted_bytes.saturating_add(size);
                }
            }
            last_inspected = Some(digest);
        }
        if full_page || page.byte_budget_exhausted {
            page.next_digest = last_inspected;
        }
        self.commit_write(transaction)?;
        self.sync_after_write(connection)?;
        Ok(page)
    }
}

struct CompactionSqlBudget<'connection> {
    connection: &'connection mut Connection,
    exhausted: Arc<AtomicBool>,
    steps: Arc<AtomicU64>,
}

impl<'connection> CompactionSqlBudget<'connection> {
    fn new(
        connection: &'connection mut Connection,
        max_steps: u64,
    ) -> Result<Self, ToolOutcomeStoreError> {
        let exhausted = Arc::new(AtomicBool::new(false));
        let steps = Arc::new(AtomicU64::new(0));
        let signal = exhausted.clone();
        let count = steps.clone();
        let mut remaining = max_steps;
        let mut interrupted = false;
        connection
            .progress_handler(
                1,
                Some(move || {
                    // Interrupt once. A failed statement immediately returns to the
                    // caller; allowing its rollback avoids stranding the transaction.
                    if interrupted {
                        return false;
                    }
                    remaining = remaining.saturating_sub(1);
                    count.fetch_add(1, Ordering::Relaxed);
                    if remaining == 0 {
                        signal.store(true, Ordering::Relaxed);
                        interrupted = true;
                        return true;
                    }
                    false
                }),
            )
            .map_err(sqlite_error)?;
        Ok(Self {
            connection,
            exhausted,
            steps,
        })
    }

    fn connection(&mut self) -> &mut Connection {
        self.connection
    }

    fn finish(
        self,
        result: Result<ToolOutcomeCompactionPage, ToolOutcomeStoreError>,
    ) -> Result<ToolOutcomeCompactionPage, ToolOutcomeStoreError> {
        if self.exhausted.load(Ordering::Relaxed) {
            let cause = result
                .err()
                .map(|error| error.to_string())
                .unwrap_or_else(|| "maintenance result unavailable".into());
            return Err(ToolOutcomeStoreError::Unavailable(format!(
                "terminal raw payload maintenance exhausted its SQL work budget: {cause}"
            )));
        }
        result.map(|mut page| {
            page.sql_steps = self.steps.load(Ordering::Relaxed);
            page
        })
    }
}

impl Drop for CompactionSqlBudget<'_> {
    fn drop(&mut self) {
        let _ = self.connection.progress_handler(0, None::<fn() -> bool>);
    }
}
