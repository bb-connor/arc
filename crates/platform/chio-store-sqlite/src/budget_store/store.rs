use super::*;

/// Quorum-witness identity of a stored budget mutation event: its `event_seq`,
/// origin `authority_id`, and origin `lease_epoch`.
pub type BudgetEventWitness = (u64, Option<String>, Option<u64>);
const MAX_DIAGNOSTIC_ABANDONED_EVENT_SEQS: usize = 100_000;

struct ImportedMutationSqlIntegers {
    event_seq: i64,
    usage_seq: Option<i64>,
    exposure_units: i64,
    realized_spend_units: i64,
    max_cost_per_invocation: Option<i64>,
    max_total_cost_units: Option<i64>,
    total_cost_exposed_after: i64,
    total_cost_realized_spend_after: i64,
    lease_epoch: Option<i64>,
}

struct StoredAuthorizationClaim {
    event_id: String,
    capability_id: String,
    grant_index: usize,
    requested_exposure_units: u64,
    max_invocations: Option<u32>,
    max_exposure_per_invocation: Option<u64>,
    max_total_exposure_units: Option<u64>,
    authority: Option<BudgetEventAuthority>,
    allowed: Option<bool>,
}

impl ImportedMutationSqlIntegers {
    fn try_from_record(record: &BudgetMutationRecord) -> Result<Self, BudgetStoreError> {
        Ok(Self {
            event_seq: sqlite_integer_from_u64(record.event_seq, "budget event sequence")?,
            usage_seq: record
                .usage_seq
                .map(|value| sqlite_integer_from_u64(value, "budget usage sequence"))
                .transpose()?,
            exposure_units: sqlite_integer_from_u64(record.exposure_units, "budget exposure")?,
            realized_spend_units: sqlite_integer_from_u64(
                record.realized_spend_units,
                "budget realized spend",
            )?,
            max_cost_per_invocation: record
                .max_cost_per_invocation
                .map(|value| sqlite_integer_from_u64(value, "budget per-invocation maximum"))
                .transpose()?,
            max_total_cost_units: record
                .max_total_cost_units
                .map(|value| sqlite_integer_from_u64(value, "budget total maximum"))
                .transpose()?,
            total_cost_exposed_after: sqlite_integer_from_u64(
                record.total_cost_exposed_after,
                "budget exposure total",
            )?,
            total_cost_realized_spend_after: sqlite_integer_from_u64(
                record.total_cost_realized_spend_after,
                "budget realized-spend total",
            )?,
            lease_epoch: record
                .authority
                .as_ref()
                .map(|authority| {
                    sqlite_integer_from_u64(authority.lease_epoch, "budget lease epoch")
                })
                .transpose()?,
        })
    }
}

impl SqliteBudgetStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BudgetStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut connection = Connection::open(path)?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS capability_grant_budgets (
                capability_id TEXT NOT NULL,
                grant_index INTEGER NOT NULL,
                invocation_count INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                seq INTEGER NOT NULL DEFAULT 0,
                total_cost_exposed INTEGER NOT NULL DEFAULT 0,
                total_cost_realized_spend INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (capability_id, grant_index)
            );

            CREATE INDEX IF NOT EXISTS idx_capability_grant_budgets_updated_at
                ON capability_grant_budgets(updated_at);

            CREATE TABLE IF NOT EXISTS budget_replication_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                next_seq INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS budget_authorization_holds (
                hold_id TEXT PRIMARY KEY,
                capability_id TEXT NOT NULL,
                grant_index INTEGER NOT NULL,
                authorized_exposure_units INTEGER NOT NULL,
                remaining_exposure_units INTEGER NOT NULL,
                invocation_count_debited INTEGER NOT NULL,
                disposition TEXT NOT NULL,
                authority_id TEXT,
                lease_id TEXT,
                lease_epoch INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_budget_authorization_holds_capability
                ON budget_authorization_holds(capability_id, grant_index);

            -- A hold ID is an authorization-attempt namespace, including denied
            -- attempts. Keeping this separate from open holds prevents a denial
            -- from fabricating mutable hold state while still making the namespace
            -- permanently non-rebindable.
            CREATE TABLE IF NOT EXISTS budget_authorization_claims (
                hold_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                capability_id TEXT NOT NULL,
                grant_index INTEGER NOT NULL,
                requested_exposure_units INTEGER NOT NULL,
                max_invocations INTEGER,
                max_exposure_per_invocation INTEGER,
                max_total_exposure_units INTEGER,
                authority_id TEXT,
                lease_id TEXT,
                lease_epoch INTEGER,
                allowed INTEGER CHECK (allowed IS NULL OR allowed IN (0, 1)),
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS budget_mutation_events (
                event_id TEXT PRIMARY KEY,
                hold_id TEXT,
                capability_id TEXT NOT NULL,
                grant_index INTEGER NOT NULL,
                kind TEXT NOT NULL,
                allowed INTEGER,
                recorded_at INTEGER NOT NULL,
                event_seq INTEGER,
                usage_seq INTEGER,
                exposure_units INTEGER NOT NULL DEFAULT 0,
                realized_spend_units INTEGER NOT NULL DEFAULT 0,
                max_invocations INTEGER,
                max_exposure_per_invocation INTEGER,
                max_total_exposure_units INTEGER,
                invocation_count_after INTEGER NOT NULL,
                total_cost_exposed_after INTEGER NOT NULL,
                total_cost_realized_spend_after INTEGER NOT NULL,
                authority_id TEXT,
                lease_id TEXT,
                lease_epoch INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_budget_mutation_events_capability
                ON budget_mutation_events(capability_id, grant_index, recorded_at);

            CREATE UNIQUE INDEX IF NOT EXISTS idx_budget_mutation_events_event_seq
                ON budget_mutation_events(event_seq);

            CREATE TABLE IF NOT EXISTS budget_import_floors (
                authority_id TEXT PRIMARY KEY,
                floor_seq    INTEGER NOT NULL DEFAULT 0,
                CHECK (floor_seq >= 0)
            );

            CREATE TABLE IF NOT EXISTS budget_ack_head_watermark (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                head_seq  INTEGER NOT NULL DEFAULT 0,
                CHECK (head_seq >= 0)
            );

            -- Incrementally-maintained per-origin ack head, so the status path does
            -- not GROUP BY the full mutation history every call. Each entry is the
            -- highest event_seq that origin has WITHIN the verified global contiguous
            -- prefix (<= the watermark); a DELETE clears it (see the trigger) so a
            -- hole forces a rebuild rather than leaving a stale-high per-origin head.
            CREATE TABLE IF NOT EXISTS budget_origin_ack_heads (
                authority_id TEXT PRIMARY KEY,
                head_seq     INTEGER NOT NULL,
                CHECK (head_seq >= 0)
            );

            -- Metadata tombstones for event_seqs that were CONSUMED but have no
            -- surviving mutation event: the leader-local rollback-retry path
            -- (existing_event_allowed) and the delta-import replace path delete a
            -- rolled-back authorize and re-append it under a fresh higher seq,
            -- permanently abandoning the original seq. Recording the abandoned seq
            -- lets the global contiguous ack head treat it as FILLED so it does not
            -- stall cluster-wide at the hole. This never over-counts: an abandoned
            -- seq is never a live write (its write was rolled back / superseded), so
            -- no witness targets it; a genuinely MISSING event (never received, never
            -- deleted here) is not recorded and still caps the head.
            CREATE TABLE IF NOT EXISTS budget_abandoned_event_seqs (
                seq INTEGER PRIMARY KEY,
                CHECK (seq > 0)
            );

            -- Snapshot-carried tombstone runs stay compact even when one range
            -- covers millions or billions of event slots. Consumers merge this
            -- table with point tombstones and live mutation-event singleton ranges.
            CREATE TABLE IF NOT EXISTS budget_abandoned_event_ranges (
                start_seq INTEGER NOT NULL,
                end_seq INTEGER NOT NULL,
                PRIMARY KEY (start_seq, end_seq),
                CHECK (start_seq > 0),
                CHECK (end_seq >= start_seq)
            );

            CREATE INDEX IF NOT EXISTS idx_budget_abandoned_event_ranges_end
                ON budget_abandoned_event_ranges(end_seq);
            "#,
        )?;
        ensure_budget_ack_head_reset_trigger(&connection)?;
        connection.execute(
            r#"
            INSERT INTO budget_replication_meta (singleton, next_seq)
            VALUES (1, 0)
            ON CONFLICT(singleton) DO NOTHING
            "#,
            [],
        )?;
        connection.execute(
            r#"
            INSERT INTO budget_ack_head_watermark (singleton, head_seq)
            VALUES (1, 0)
            ON CONFLICT(singleton) DO NOTHING
            "#,
            [],
        )?;
        ensure_budget_seq_column(&connection)?;
        ensure_split_budget_cost_columns(&connection)?;
        ensure_budget_hold_authority_columns(&connection)?;
        ensure_budget_mutation_event_authority_columns(&connection)?;
        ensure_budget_mutation_event_seq_column(&connection)?;
        ensure_composite_budget_schema(&connection)?;
        ensure_budget_authorization_claims(&mut connection)?;
        initialize_budget_replication_seq(&mut connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub(super) fn connection(&self) -> Result<MutexGuard<'_, Connection>, BudgetStoreError> {
        self.connection.lock().map_err(|_| {
            BudgetStoreError::Invariant("sqlite budget store lock poisoned".to_string())
        })
    }

    /// Highest budget mutation event_seq, or 0 when empty. Mirrors the private
    /// max_budget_mutation_event_seq helper (replication.rs) but is a public
    /// head read for the status path.
    pub fn max_mutation_event_seq(&self) -> Result<u64, BudgetStoreError> {
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "SELECT COALESCE(MAX(event_seq), 0) FROM budget_mutation_events",
            [],
            |row| row.get(0),
        )?;
        Ok(seq.max(0) as u64)
    }

    /// Highest mutation event_seq written under one origin authority, or 0 when
    /// none. The cluster budget-write handler reads this immediately after a
    /// local (leader) write to build the write's quorum-witness token: it is
    /// always >= the just-written event's own seq (a concurrent same-origin
    /// write can only raise it), so the per-origin contiguous witness can only
    /// under-count witnesses, never over-count one (fail-closed).
    pub fn max_mutation_event_seq_for_authority(
        &self,
        authority_id: &str,
    ) -> Result<u64, BudgetStoreError> {
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "SELECT COALESCE(MAX(event_seq), 0) FROM budget_mutation_events WHERE authority_id = ?1",
            rusqlite::params![authority_id],
            |row| row.get(0),
        )?;
        Ok(seq.max(0) as u64)
    }

    /// The exact event_seq of the mutation event written under `event_id`, or
    /// None if no such event exists (or it predates seq assignment). The
    /// cluster budget-write handler waits on THIS write's own event_seq, looked
    /// up by the write's event_id, instead of MAX(event_seq) for the authority:
    /// a concurrent same-authority commit (or an idempotent retry while later
    /// same-origin events already exist) can raise that MAX above this write's
    /// seq, making the quorum wait target the wrong (higher) seq and roll back a
    /// write that itself reached quorum. Looked up by the unique event_id, this
    /// is race-free and, for an idempotent retry, returns the ORIGINAL event's
    /// seq.
    pub fn mutation_event_seq_for_event_id(
        &self,
        event_id: &str,
    ) -> Result<Option<u64>, BudgetStoreError> {
        let connection = self.connection()?;
        let seq: Option<Option<i64>> = connection
            .query_row(
                "SELECT event_seq FROM budget_mutation_events WHERE event_id = ?1",
                rusqlite::params![event_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?;
        Ok(seq.flatten().map(|value| value.max(0) as u64))
    }

    /// Per-origin contiguous ack head, anchored on the peer's GLOBAL contiguous
    /// import head.
    ///
    /// `event_seq` is a single store-wide dense sequence, so each origin's events
    /// are a sparse subsequence of one global stream; a per-origin gaps-and-
    /// islands run (partitioned by authority) mis-models this: an origin whose
    /// block starts mid-sequence after a leadership change looks like a gap and is
    /// wrongly dropped, stalling its writes.
    ///
    /// Instead this first computes the GLOBAL contiguous head H (the largest seq
    /// such that every global event_seq in `1..=H` is present with no hole) as a
    /// single gaps-and-islands run over the whole stream (NOT partitioned),
    /// anchored at genesis (island 0). A hole caps H below it. Legacy
    /// NULL-authority events still occupy their global slot, so they count for
    /// contiguity (a present slot is not a gap) but are never reported as an ack.
    /// It then reports, per origin, `MAX(event_seq)` among that origin's events
    /// with `event_seq <= H`.
    ///
    /// Sound because global-contiguity enforcement on the puller means holding H
    /// implies holding EVERY event (all origins) at
    /// seq `<= H`, so `head[origin] >= write.event_seq` iff the peer durably holds
    /// that write and all its predecessors. Fail-closed: a global hole caps H, so
    /// no origin is ever reported past a missing global predecessor, and a missing
    /// prefix (nothing at seq 1) yields H = 0 and no acks.
    ///
    /// NOTE: genesis anchoring assumes budget mutation events are never
    /// bulk-compacted below seq 1 (they are not today); if such compaction is
    /// added, anchor at a durable global floor instead.
    ///
    /// NOTE: a rollback-retry that abandons a seq (existing_event_allowed)
    /// leaves a permanent interior hole that caps this GLOBAL head, stalling
    /// quorum budget-writes above the hole for EVERY origin cluster-wide (not
    /// per-origin) until operator intervention - it does not self-heal, since a
    /// snapshot from the holed leader carries the hole. Fail-closed (a hole
    /// withholds quorum and never over-counts).
    /// PERF: this runs on every cluster status request (once per sync round, an
    /// interval clamped as low as 50ms), so it must not rescan the whole ledger.
    /// The GLOBAL contiguous head is maintained incrementally against a durable
    /// watermark W (`budget_ack_head_watermark`): each call only advances W over
    /// the rows ABOVE it (a window scan bounded to `event_seq > W`), so steady
    /// state cost is O(new rows), not O(history). Soundness holds because W only
    /// advances while the run stays gap-free, and any DELETE of a mutation event
    /// resets W to 0 (`reset_budget_ack_head_watermark`, backstopped structurally
    /// by the `budget_mutation_events_reset_ack_head_watermark` AFTER DELETE
    /// trigger so a future or out-of-band delete site cannot skip the reset),
    /// forcing the next call to re-verify from genesis so a hole punched below W
    /// can never leave a stale-high head that over-counts.
    pub fn budget_ack_heads(&self) -> Result<Vec<(String, u64)>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let watermark: i64 = transaction.query_row(
            "SELECT head_seq FROM budget_ack_head_watermark WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let watermark = watermark.max(0) as u64;
        // Advance the head over slots ABOVE the watermark only. A slot is FILLED if
        // a real mutation event occupies it OR it is a recorded abandoned/tombstoned
        // seq (a rolled-back-then-re-appended write's original seq). The contiguous
        // run from W+1 has island == W (its first slot W+1 has ROW_NUMBER 1), so the
        // new head is MAX(seq) in that island, or W when W+1 is neither present nor
        // abandoned. Treating abandoned seqs as filled lets the head advance past a
        // rollback-retry hole; a genuinely MISSING event (never recorded as
        // abandoned) is NOT filled and still caps the head.
        // NULL-authority events still occupy a slot for contiguity but are never
        // reported as an ack below.
        // Fast path (avoid rescanning the ledger after a gap):
        // the contiguous run can only advance when the very next slot (W+1) is
        // FILLED (a mutation event or a recorded abandoned seq). When a real hole
        // sits at W+1 (data loss, or a legacy snapshot that lacks abandoned slots),
        // the head is pinned at W forever, yet the window query below still computes
        // ROW_NUMBER() over the whole suffix `> W` on every status-path call. Probe
        // the single W+1 slot first (an indexed point lookup): if it is absent, the
        // head is W, so skip the O(suffix) window scan entirely. This is purely an
        // optimization: the window query ALSO yields exactly W when W+1 is absent
        // (the smallest filled seq > W then has island >= W+1, so no row matches the
        // island == W run and COALESCE(MAX(seq), W) collapses to W), so the
        // genesis-anchored gaps-and-islands head is unchanged.
        let watermark_i64 = watermark as i64;
        let next_slot = watermark_i64.saturating_add(1);
        let next_slot_filled: bool = transaction.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM budget_mutation_events WHERE event_seq = ?1
                UNION ALL
                SELECT 1 FROM budget_abandoned_event_seqs WHERE seq = ?1
                UNION ALL
                SELECT 1
                FROM budget_abandoned_event_ranges
                WHERE start_seq <= ?1 AND end_seq >= ?1
            )
            "#,
            rusqlite::params![next_slot],
            |row| row.get::<_, i64>(0).map(|value| value != 0),
        )?;
        let head: i64 = if watermark_i64 == i64::MAX {
            watermark_i64
        } else if next_slot_filled {
            transaction.query_row(
                r#"
                WITH raw_intervals AS (
                    SELECT event_seq AS start_seq, event_seq AS end_seq
                    FROM budget_mutation_events
                    WHERE event_seq IS NOT NULL AND event_seq > ?1
                    UNION ALL
                    SELECT seq AS start_seq, seq AS end_seq
                    FROM budget_abandoned_event_seqs
                    WHERE seq > ?1
                    UNION ALL
                    SELECT
                        CASE WHEN start_seq <= ?1 THEN ?1 + 1 ELSE start_seq END,
                        end_seq
                    FROM budget_abandoned_event_ranges
                    WHERE end_seq > ?1
                ),
                ordered AS (
                    SELECT
                        start_seq,
                        end_seq,
                        MAX(end_seq) OVER (
                            ORDER BY start_seq, end_seq
                            ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
                        ) AS previous_max_end
                    FROM raw_intervals
                ),
                marked AS (
                    SELECT
                        start_seq,
                        end_seq,
                        CASE
                            WHEN previous_max_end IS NULL THEN 1
                            WHEN start_seq > previous_max_end
                             AND start_seq - previous_max_end > 1 THEN 1
                            ELSE 0
                        END AS starts_new_run
                    FROM ordered
                ),
                grouped_intervals AS (
                    SELECT
                        start_seq,
                        end_seq,
                        SUM(starts_new_run) OVER (
                            ORDER BY start_seq, end_seq
                            ROWS UNBOUNDED PRECEDING
                        ) AS run_id
                    FROM marked
                ),
                merged AS (
                    SELECT MIN(start_seq) AS start_seq, MAX(end_seq) AS end_seq
                    FROM grouped_intervals
                    GROUP BY run_id
                )
                SELECT COALESCE(MAX(end_seq), ?1) AS head_seq
                FROM merged
                WHERE start_seq <= ?1 + 1
                "#,
                rusqlite::params![watermark_i64],
                |row| row.get(0),
            )?
        } else {
            watermark_i64
        };
        let head = head.max(0) as u64;
        if head > watermark {
            transaction.execute(
                "UPDATE budget_ack_head_watermark SET head_seq = ?1 WHERE singleton = 1",
                rusqlite::params![head as i64],
            )?;
            // Fold ONLY the newly-covered rows (watermark, head] into the durable
            // per-origin heads, so the status path never GROUPs the full history:
            // steady-state cost is O(new rows). MAX keeps each origin monotone
            // within a hole-free window; a DELETE clears this table (trigger +
            // reset helper), so a per-origin head can never sit above a hole.
            transaction.execute(
                r#"
                INSERT INTO budget_origin_ack_heads (authority_id, head_seq)
                SELECT authority_id, MAX(event_seq)
                FROM budget_mutation_events
                WHERE authority_id IS NOT NULL
                  AND event_seq IS NOT NULL
                  AND event_seq > ?1
                  AND event_seq <= ?2
                GROUP BY authority_id
                ON CONFLICT(authority_id)
                    DO UPDATE SET head_seq = MAX(head_seq, excluded.head_seq)
                "#,
                rusqlite::params![watermark as i64, head as i64],
            )?;
        }
        let mut statement =
            transaction.prepare("SELECT authority_id, head_seq FROM budget_origin_ack_heads")?;
        let rows = statement
            .query_map([], |row| {
                let origin: String = row.get(0)?;
                let ack_head = budget_u64_from_row(row, 1, "ack_head")?;
                Ok((origin, ack_head))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(BudgetStoreError::from)?;
        drop(statement);
        transaction.commit()?;
        Ok(rows)
    }

    /// Reset the durable contiguous ack-head watermark to 0, forcing the next
    /// `budget_ack_heads` call to re-verify the global run from genesis. Called
    /// whenever a mutation event is DELETED (a hole may have been punched at or
    /// below the watermark): re-verification caps the head below the hole so a
    /// stale-high watermark can never over-count a witness.
    ///
    /// This is redundant with the `budget_mutation_events_reset_ack_head_watermark`
    /// AFTER DELETE trigger created in `open` (defense-in-depth): the trigger fires
    /// structurally on every delete against the table, so this manual call is a
    /// belt-and-suspenders in-transaction reset at each known call site, not the
    /// sole enforcement point.
    fn reset_budget_ack_head_watermark(
        transaction: &rusqlite::Transaction<'_>,
    ) -> Result<(), BudgetStoreError> {
        transaction.execute(
            "UPDATE budget_ack_head_watermark SET head_seq = 0 WHERE singleton = 1",
            [],
        )?;
        // Clear the incrementally-maintained per-origin heads too: a hole below a
        // per-origin head would otherwise leave it stale-high until a full rebuild.
        transaction.execute("DELETE FROM budget_origin_ack_heads", [])?;
        Ok(())
    }

    /// The abandoned/tombstoned event_seqs (rolled-back-then-re-appended writes'
    /// original seqs) that `budget_ack_heads` treats as filled slots. Replicated
    /// in the cluster snapshot so a FRESH follower - which never held the original
    /// event and so never fired the delete-trigger that records it locally - still
    /// learns the slot is abandoned and does not stall its contiguous head at the
    /// hole.
    pub fn list_abandoned_event_seqs(&self) -> Result<Vec<u64>, BudgetStoreError> {
        let seqs = self.list_abandoned_event_seqs_in_range(
            0,
            u64::MAX,
            MAX_DIAGNOSTIC_ABANDONED_EVENT_SEQS + 1,
        )?;
        if seqs.len() > MAX_DIAGNOSTIC_ABANDONED_EVENT_SEQS {
            return Err(BudgetStoreError::Invariant(format!(
                "abandoned budget sequence diagnostic exceeds {MAX_DIAGNOSTIC_ABANDONED_EVENT_SEQS} entries; use range output"
            )));
        }
        Ok(seqs)
    }

    /// The abandoned event_seqs RANGE-ENCODED as inclusive `(start, end)` runs of
    /// consecutive seqs (ascending, non-overlapping).
    ///
    /// The cluster snapshot carries the abandoned set this way instead of one entry
    /// per seq. A rollback storm abandons a long CONTIGUOUS run of seqs; enumerated,
    /// that is millions of integers that push the snapshot body past
    /// MAX_PEER_RESPONSE_BYTES, so the force-snapshot recovery path fails to decode
    /// cluster_snapshot() and the peer stalls in force_snapshot forever (unlike the
    /// delta path, the snapshot backstop has no further fallback). Range-encoded,
    /// each contiguous run collapses to one
    /// small pair, and the run count is bounded by the number of live mutation events
    /// (a run is separated from the next by a filled non-abandoned slot), which the
    /// snapshot already carries and which dominate the byte budget - so if the events
    /// fit under the cap the ranges do too. The encoding is LOSSLESS: a follower
    /// stores the runs compactly, so the filled-or-abandoned head-advance semantics
    /// are preserved without materializing every sequence. Point tombstones and
    /// compact ranges are merged canonically in SQL.
    pub fn list_abandoned_event_seq_ranges(&self) -> Result<Vec<(u64, u64)>, BudgetStoreError> {
        let connection = self.connection()?;
        Self::query_abandoned_event_seq_ranges(&connection, 0, i64::MAX)
    }

    /// The quorum-witness identity of the mutation event stored under `event_id`:
    /// `(event_seq, authority_id, lease_epoch)`, or None when no such event exists
    /// or it predates seq assignment. The witness must target the event's STORED
    /// origin authority, not the current lease: an idempotent retry after
    /// leadership moved re-reads the already-written event, and peers advertise it
    /// under its ORIGINAL authority, so keying the wait on the current leader would
    /// look under the wrong origin and time out a write that already committed.
    /// A null-seq (legacy) row returns None so the caller
    /// falls back to the authority MAX rather than witnessing on seq 0.
    pub fn mutation_event_witness_for_event_id(
        &self,
        event_id: &str,
    ) -> Result<Option<BudgetEventWitness>, BudgetStoreError> {
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT event_seq, authority_id, lease_epoch FROM budget_mutation_events WHERE event_id = ?1",
                rusqlite::params![event_id],
                |row| {
                    let seq: Option<i64> = row.get(0)?;
                    let authority_id: Option<String> = row.get(1)?;
                    let lease_epoch: Option<i64> = row.get(2)?;
                    Ok((seq, authority_id, lease_epoch))
                },
            )
            .optional()?;
        Ok(row.and_then(|(seq, authority_id, lease_epoch)| {
            seq.map(|seq| {
                (
                    seq.max(0) as u64,
                    authority_id,
                    lease_epoch.map(|epoch| epoch.max(0) as u64),
                )
            })
        }))
    }

    /// Abandoned event_seqs strictly above `after_seq` (ascending). The budget
    /// delta endpoint returns these alongside the pulled events so the puller can
    /// treat the abandoned slots as filled and not reject the leader's legitimately
    /// gappy stream.
    pub fn list_abandoned_event_seqs_after(
        &self,
        after_seq: u64,
    ) -> Result<Vec<u64>, BudgetStoreError> {
        let seqs = self.list_abandoned_event_seqs_in_range(
            after_seq,
            u64::MAX,
            MAX_DIAGNOSTIC_ABANDONED_EVENT_SEQS + 1,
        )?;
        if seqs.len() > MAX_DIAGNOSTIC_ABANDONED_EVENT_SEQS {
            return Err(BudgetStoreError::Invariant(format!(
                "abandoned budget sequence diagnostic exceeds {MAX_DIAGNOSTIC_ABANDONED_EVENT_SEQS} entries; use bounded or range output"
            )));
        }
        Ok(seqs)
    }

    /// Abandoned event_seqs in `(after_seq, up_to_seq]` (ascending), at most
    /// `limit` entries.
    ///
    /// The budget delta endpoint uses this to BOUND the abandoned list it serves.
    /// A rollback storm can pack an
    /// arbitrarily large abandoned window between the follower cursor and the next
    /// live event; serializing all of it (the old unbounded
    /// `list_abandoned_event_seqs_after` + in-memory `<= page_max` filter) could
    /// exceed the peer-response byte cap, so the client rejects the body while
    /// decoding and never gets to classify the oversized window as
    /// snapshot-recovery, pinning the cursor forever. Both the upper bound and the
    /// row cap are pushed into SQL so a huge window is never materialized here.
    pub fn list_abandoned_event_seqs_in_range(
        &self,
        after_seq: u64,
        up_to_seq: u64,
        limit: usize,
    ) -> Result<Vec<u64>, BudgetStoreError> {
        if limit == 0 || up_to_seq <= after_seq || after_seq >= i64::MAX as u64 {
            return Ok(Vec::new());
        }
        let after_seq = sqlite_integer_from_u64(after_seq, "abandoned range lower bound")?;
        let up_to_seq = i64::try_from(up_to_seq).unwrap_or(i64::MAX);
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let connection = self.connection()?;
        let mut range_statement = connection.prepare(
            r#"
            SELECT
                CASE WHEN start_seq <= ?1 THEN ?1 + 1 ELSE start_seq END,
                CASE WHEN end_seq > ?2 THEN ?2 ELSE end_seq END
            FROM budget_abandoned_event_ranges
            WHERE end_seq > ?1 AND start_seq <= ?2
            ORDER BY start_seq ASC, end_seq ASC
            LIMIT ?3
            "#,
        )?;
        let ranges = range_statement
            .query_map(rusqlite::params![after_seq, up_to_seq, limit_i64], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(range_statement);

        let mut point_statement = connection.prepare(
            r#"
            SELECT point.seq
            FROM budget_abandoned_event_seqs AS point
            WHERE point.seq > ?1
              AND point.seq <= ?2
              AND NOT EXISTS (
                  SELECT 1
                  FROM budget_abandoned_event_ranges AS range
                  WHERE range.start_seq <= point.seq AND range.end_seq >= point.seq
              )
            ORDER BY point.seq ASC
            LIMIT ?3
            "#,
        )?;
        let points = point_statement
            .query_map(rusqlite::params![after_seq, up_to_seq, limit_i64], |row| {
                row.get::<_, i64>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(point_statement);

        let mut intervals = ranges;
        intervals.extend(points.into_iter().map(|seq| (seq, seq)));
        intervals.sort_unstable();
        let mut merged = Vec::<(i64, i64)>::new();
        for (start, end) in intervals {
            if let Some((_, merged_end)) = merged.last_mut() {
                if start <= *merged_end || start - *merged_end == 1 {
                    *merged_end = (*merged_end).max(end);
                    continue;
                }
            }
            merged.push((start, end));
        }
        let mut seqs = Vec::new();
        for (start, end) in merged {
            let mut seq = u64::try_from(start).map_err(|_| {
                BudgetStoreError::Invariant(
                    "stored abandoned budget range has a negative start".to_string(),
                )
            })?;
            let end = u64::try_from(end).map_err(|_| {
                BudgetStoreError::Invariant(
                    "stored abandoned budget range has a negative end".to_string(),
                )
            })?;
            loop {
                if seqs.len() == limit {
                    return Ok(seqs);
                }
                seqs.push(seq);
                if seq == end {
                    break;
                }
                seq = seq.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "abandoned budget sequence materialization overflowed u64".to_string(),
                    )
                })?;
            }
        }
        Ok(seqs)
    }

    fn query_abandoned_event_seq_ranges(
        connection: &Connection,
        after_seq: i64,
        up_to_seq: i64,
    ) -> Result<Vec<(u64, u64)>, BudgetStoreError> {
        let mut statement = connection.prepare(
            r#"
            WITH raw_intervals AS (
                SELECT seq AS start_seq, seq AS end_seq
                FROM budget_abandoned_event_seqs
                WHERE seq > ?1 AND seq <= ?2
                UNION ALL
                SELECT
                    CASE WHEN start_seq <= ?1 THEN ?1 + 1 ELSE start_seq END,
                    CASE WHEN end_seq > ?2 THEN ?2 ELSE end_seq END
                FROM budget_abandoned_event_ranges
                WHERE end_seq > ?1 AND start_seq <= ?2
            ),
            ordered AS (
                SELECT
                    start_seq,
                    end_seq,
                    MAX(end_seq) OVER (
                        ORDER BY start_seq, end_seq
                        ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
                    ) AS previous_max_end
                FROM raw_intervals
            ),
            marked AS (
                SELECT
                    start_seq,
                    end_seq,
                    CASE
                        WHEN previous_max_end IS NULL THEN 1
                        WHEN start_seq > previous_max_end
                         AND start_seq - previous_max_end > 1 THEN 1
                        ELSE 0
                    END AS starts_new_run
                FROM ordered
            ),
            grouped_intervals AS (
                SELECT
                    start_seq,
                    end_seq,
                    SUM(starts_new_run) OVER (
                        ORDER BY start_seq, end_seq
                        ROWS UNBOUNDED PRECEDING
                    ) AS run_id
                FROM marked
            )
            SELECT MIN(start_seq), MAX(end_seq)
            FROM grouped_intervals
            GROUP BY run_id
            ORDER BY MIN(start_seq) ASC
            "#,
        )?;
        let rows = statement.query_map(rusqlite::params![after_seq, up_to_seq], |row| {
            Ok((
                budget_u64_from_row(row, 0, "abandoned range start")?,
                budget_u64_from_row(row, 1, "abandoned range end")?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(BudgetStoreError::from)
    }

    /// Record snapshot-carried abandoned event_seqs (see `list_abandoned_event_seqs`).
    /// Fail-closed: this only ADDS filled slots (an abandoned seq is never a live
    /// write, so it cannot inflate any origin's ack head), and it resets the
    /// watermark so the next `budget_ack_heads` recomputes with the new slots.
    pub fn record_abandoned_event_seqs(&self, seqs: &[u64]) -> Result<(), BudgetStoreError> {
        let sqlite_seqs = seqs
            .iter()
            .copied()
            .filter(|seq| *seq != 0)
            .map(|seq| sqlite_integer_from_u64(seq, "abandoned budget event sequence"))
            .collect::<Result<Vec<_>, _>>()?;
        if sqlite_seqs.is_empty() {
            return Ok(());
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for seq in sqlite_seqs {
            transaction.execute(
                "INSERT OR IGNORE INTO budget_abandoned_event_seqs(seq) VALUES (?1)",
                rusqlite::params![seq],
            )?;
        }
        Self::reset_budget_ack_head_watermark(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    /// Record snapshot-carried abandoned event_seqs given as inclusive `(start, end)`
    /// RANGES (see `list_abandoned_event_seq_ranges`).
    ///
    /// Canonical ranges are ascending, disjoint, and separated by at least one live or
    /// unknown slot. The complete range set is validated and converted before a
    /// connection or write transaction is acquired. Valid ranges remain compact in
    /// durable storage, so very large recovery spans take O(range count) work. The
    /// caller must install the snapshot's later boundary events first: every range end
    /// must be at or below the current replication floor and must not overlap a live
    /// event slot.
    pub fn record_abandoned_event_seq_ranges(
        &self,
        ranges: &[(u64, u64)],
    ) -> Result<(), BudgetStoreError> {
        let mut sqlite_ranges = Vec::with_capacity(ranges.len());
        let mut previous_end = None;
        for &(start, end) in ranges {
            if start == 0 || end < start {
                return Err(BudgetStoreError::Invariant(
                    "abandoned budget ranges must be nonzero and non-inverted".to_string(),
                ));
            }
            if let Some(previous_end) = previous_end {
                if start <= previous_end {
                    return Err(BudgetStoreError::Invariant(
                        "abandoned budget ranges must be strictly ascending and non-overlapping"
                            .to_string(),
                    ));
                }
                if previous_end
                    .checked_add(1)
                    .is_some_and(|adjacent| start == adjacent)
                {
                    return Err(BudgetStoreError::Invariant(
                        "adjacent abandoned budget ranges must be merged".to_string(),
                    ));
                }
            }
            sqlite_ranges.push((
                sqlite_integer_from_u64(start, "abandoned budget range start")?,
                sqlite_integer_from_u64(end, "abandoned budget range end")?,
            ));
            previous_end = Some(end);
        }
        if sqlite_ranges.is_empty() {
            return Ok(());
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let replication_floor = transaction.query_row(
            "SELECT next_seq FROM budget_replication_meta WHERE singleton = 1",
            [],
            |row| budget_u64_from_row(row, 0, "budget replication sequence"),
        )?;
        let incoming_max_end = ranges.last().map_or(0, |(_, end)| *end);
        if incoming_max_end > replication_floor {
            return Err(BudgetStoreError::Invariant(format!(
                "abandoned budget range end {incoming_max_end} exceeds replication floor {replication_floor}"
            )));
        }
        for (start, end) in &sqlite_ranges {
            let overlapping_event = transaction
                .query_row(
                    r#"
                    SELECT event_seq
                    FROM budget_mutation_events
                    WHERE event_seq >= ?1 AND event_seq <= ?2
                    LIMIT 1
                    "#,
                    rusqlite::params![start, end],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if let Some(event_seq) = overlapping_event {
                return Err(BudgetStoreError::Invariant(format!(
                    "abandoned budget range overlaps live event sequence {event_seq}"
                )));
            }
        }
        let mut statement = transaction.prepare(
            "SELECT start_seq, end_seq FROM budget_abandoned_event_ranges ORDER BY start_seq, end_seq",
        )?;
        let mut canonical_ranges = statement
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        canonical_ranges.extend(sqlite_ranges);
        canonical_ranges.sort_unstable();
        let mut merged_ranges = Vec::<(i64, i64)>::new();
        for (start, end) in canonical_ranges {
            if let Some((_, merged_end)) = merged_ranges.last_mut() {
                if start <= *merged_end || start - *merged_end == 1 {
                    *merged_end = (*merged_end).max(end);
                    continue;
                }
            }
            merged_ranges.push((start, end));
        }
        transaction.execute("DELETE FROM budget_abandoned_event_ranges", [])?;
        for (start, end) in merged_ranges {
            transaction.execute(
                r#"
                INSERT INTO budget_abandoned_event_ranges(start_seq, end_seq)
                VALUES (?1, ?2)
                "#,
                rusqlite::params![start, end],
            )?;
        }
        raise_budget_replication_seq_floor(&transaction, incoming_max_end)?;
        Self::reset_budget_ack_head_watermark(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    /// The durable trusted floor for one origin (0 when none recorded).
    ///
    /// IMPORTANT: this floor does NOT gate the budget ack
    /// head. `budget_ack_heads` is GENESIS-anchored: it walks the contiguous global
    /// event prefix from seq 1 (over `budget_mutation_events` UNION the recorded
    /// abandoned seqs, from a watermark that resets to 0 on any delete) and never
    /// reads `budget_import_floors`. Raising an origin's import floor therefore
    /// never advances that origin's ack head, and a delta page that jumps over the
    /// floor is still rejected as non-contiguous by the puller. The floor is written
    /// only on snapshot install (`record_budget_import_floors`) to record the
    /// provably-covered lower bound of an installed snapshot. This singular reader
    /// has NO production consumer; it is a diagnostic/test surface that verifies
    /// snapshot install persisted the floor. Do not wire it into ack-head, quorum,
    /// or witness accounting.
    pub fn budget_import_floor(&self, authority_id: &str) -> Result<u64, BudgetStoreError> {
        let connection = self.connection()?;
        let floor: i64 = connection
            .query_row(
                "SELECT floor_seq FROM budget_import_floors WHERE authority_id = ?1",
                rusqlite::params![authority_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        Ok(floor.max(0) as u64)
    }

    /// Raise each origin's trusted floor to (min covered event_seq) - 1 for the
    /// events in a freshly installed snapshot. Never lowers a floor. A
    /// puller-introduced gap can never raise the floor because the puller never
    /// calls this; only snapshot install does.
    pub fn record_budget_import_floors(
        &self,
        events: &[BudgetMutationRecord],
    ) -> Result<(), BudgetStoreError> {
        use std::collections::BTreeMap;
        let mut min_by_origin: BTreeMap<&str, u64> = BTreeMap::new();
        for event in events {
            let Some(authority) = event.authority.as_ref() else {
                continue;
            };
            let entry = min_by_origin
                .entry(authority.authority_id.as_str())
                .or_insert(event.event_seq);
            *entry = (*entry).min(event.event_seq);
        }
        let floors = min_by_origin
            .into_iter()
            .map(|(origin, min_seq)| {
                Ok((
                    origin,
                    sqlite_integer_from_u64(
                        min_seq.saturating_sub(1),
                        "budget import floor sequence",
                    )?,
                ))
            })
            .collect::<Result<Vec<_>, BudgetStoreError>>()?;
        if floors.is_empty() {
            return Ok(());
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (origin, floor) in floors {
            transaction.execute(
                "INSERT INTO budget_import_floors (authority_id, floor_seq) VALUES (?1, ?2) \
                 ON CONFLICT(authority_id) DO UPDATE SET floor_seq = MAX(floor_seq, excluded.floor_seq)",
                rusqlite::params![origin, floor],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn upsert_usage(&self, record: &BudgetUsageRecord) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::upsert_usage_in_transaction(&transaction, record)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn import_snapshot_records(
        &self,
        usages: &[BudgetUsageRecord],
        events: &[BudgetMutationRecord],
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for usage in usages {
            Self::upsert_usage_in_transaction(&transaction, usage)?;
        }
        for event in events {
            Self::import_mutation_record_in_transaction(&transaction, event)?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn upsert_usage_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetUsageRecord,
    ) -> Result<(), BudgetStoreError> {
        let seq = sqlite_integer_from_u64(record.seq, "budget usage sequence")?;
        let total_cost_exposed =
            sqlite_integer_from_u64(record.total_cost_exposed, "budget exposure total")?;
        let total_cost_realized_spend = sqlite_integer_from_u64(
            record.total_cost_realized_spend,
            "budget realized-spend total",
        )?;
        raise_budget_replication_seq_floor(transaction, record.seq)?;
        transaction.execute(
            r#"
            INSERT INTO capability_grant_budgets (
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_exposed,
                total_cost_realized_spend
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(capability_id, grant_index) DO UPDATE SET
                invocation_count = CASE
                    WHEN excluded.seq >= capability_grant_budgets.seq
                        THEN excluded.invocation_count
                    ELSE capability_grant_budgets.invocation_count
                END,
                updated_at = CASE
                    WHEN excluded.seq >= capability_grant_budgets.seq
                        THEN excluded.updated_at
                    ELSE capability_grant_budgets.updated_at
                END,
                total_cost_exposed = CASE
                    WHEN excluded.seq >= capability_grant_budgets.seq
                        THEN excluded.total_cost_exposed
                    ELSE capability_grant_budgets.total_cost_exposed
                END,
                total_cost_realized_spend = CASE
                    WHEN excluded.seq >= capability_grant_budgets.seq
                        THEN excluded.total_cost_realized_spend
                    ELSE capability_grant_budgets.total_cost_realized_spend
                END,
                seq = MAX(capability_grant_budgets.seq, excluded.seq)
            "#,
            params![
                &record.capability_id,
                i64::from(record.grant_index),
                i64::from(record.invocation_count),
                record.updated_at,
                seq,
                total_cost_exposed,
                total_cost_realized_spend,
            ],
        )?;
        Ok(())
    }

    pub fn delete_mutation_event(&self, event_id: &str) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM budget_mutation_events WHERE event_id = ?1",
            params![event_id],
        )?;
        Self::reset_budget_ack_head_watermark(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn delete_hold(&self, hold_id: &str) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM budget_authorization_holds WHERE hold_id = ?1",
            params![hold_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn hold_authority(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let authority = Self::load_hold(&transaction, hold_id)?.and_then(|hold| hold.authority);
        transaction.rollback()?;
        Ok(authority)
    }

    pub fn authorization_authority_source(
        &self,
        hold_id: Option<&str>,
        event_id: &str,
    ) -> Result<SqliteBudgetAuthorizationAuthority, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;

        let source = if let Some(claim) = hold_id
            .map(|hold_id| Self::load_authorization_claim(&transaction, hold_id))
            .transpose()?
            .flatten()
        {
            let compensated = claim.allowed == Some(true)
                && Self::rollback_event_exists(
                    &transaction,
                    &claim.event_id,
                    hold_id,
                    &claim.capability_id,
                    claim.grant_index,
                    claim.requested_exposure_units,
                    claim.authority.as_ref(),
                )?;
            if compensated {
                SqliteBudgetAuthorizationAuthority::Current
            } else {
                SqliteBudgetAuthorizationAuthority::Persisted(claim.authority)
            }
        } else if let Some(event) = Self::load_mutation_event(&transaction, event_id)? {
            let compensated = event.kind == BudgetMutationKind::AuthorizeExposure
                && event.allowed == Some(true)
                && Self::rollback_event_exists(
                    &transaction,
                    &event.event_id,
                    event.hold_id.as_deref(),
                    &event.capability_id,
                    event.grant_index as usize,
                    event.exposure_units,
                    event.authority.as_ref(),
                )?;
            if compensated {
                SqliteBudgetAuthorizationAuthority::Current
            } else {
                SqliteBudgetAuthorizationAuthority::Persisted(event.authority)
            }
        } else {
            SqliteBudgetAuthorizationAuthority::Current
        };

        transaction.rollback()?;
        Ok(source)
    }

    pub(super) fn authorization_authority_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority_mode: &SqliteBudgetAuthorizationAuthorityMode,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        if let Some(claim) = hold_id
            .map(|hold_id| Self::load_authorization_claim(transaction, hold_id))
            .transpose()?
            .flatten()
        {
            let compensated = claim.allowed == Some(true)
                && Self::rollback_event_exists(
                    transaction,
                    &claim.event_id,
                    hold_id,
                    &claim.capability_id,
                    claim.grant_index,
                    claim.requested_exposure_units,
                    claim.authority.as_ref(),
                )?;
            if !compensated {
                return Self::persisted_authorization_authority(authority_mode, claim.authority);
            }
            return Self::replacement_authorization_authority(
                authority_mode,
                claim.authority.as_ref(),
            );
        }

        if let Some(event) = event_id
            .map(|event_id| Self::load_mutation_event(transaction, event_id))
            .transpose()?
            .flatten()
        {
            let compensated = event.kind == BudgetMutationKind::AuthorizeExposure
                && event.allowed == Some(true)
                && Self::rollback_event_exists(
                    transaction,
                    &event.event_id,
                    event.hold_id.as_deref(),
                    &event.capability_id,
                    event.grant_index as usize,
                    event.exposure_units,
                    event.authority.as_ref(),
                )?;
            if !compensated {
                return Self::persisted_authorization_authority(authority_mode, event.authority);
            }
            return Self::replacement_authorization_authority(
                authority_mode,
                event.authority.as_ref(),
            );
        }

        Self::replacement_authorization_authority(authority_mode, None)
    }

    fn persisted_authorization_authority(
        authority_mode: &SqliteBudgetAuthorizationAuthorityMode,
        persisted_authority: Option<BudgetEventAuthority>,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        if let SqliteBudgetAuthorizationAuthorityMode::CallerPinned(requested_authority) =
            authority_mode
        {
            if requested_authority != &persisted_authority {
                return Err(BudgetStoreError::Invariant(
                    "persisted budget authorization authority changed on retry".to_string(),
                ));
            }
        }
        Ok(persisted_authority)
    }

    fn replacement_authorization_authority(
        authority_mode: &SqliteBudgetAuthorizationAuthorityMode,
        previous_authority: Option<&BudgetEventAuthority>,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        match authority_mode {
            SqliteBudgetAuthorizationAuthorityMode::CallerPinned(requested_authority) => {
                if previous_authority.is_some() && requested_authority.is_none() {
                    return Err(BudgetStoreError::Invariant(
                        "compensated HA authorization cannot rebind without current authority metadata"
                            .to_string(),
                    ));
                }
                Ok(requested_authority.clone())
            }
            SqliteBudgetAuthorizationAuthorityMode::ServerCurrent(current_authority) => {
                Self::resolved_current_authority(current_authority, previous_authority)
            }
        }
    }

    fn resolved_current_authority(
        current_authority: &SqliteBudgetCurrentAuthority,
        previous_authority: Option<&BudgetEventAuthority>,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        let SqliteBudgetCurrentAuthority::Resolved(current_authority) = current_authority else {
            return Err(BudgetStoreError::Invariant(
                "current budget authority is required for a new or compensated authorization"
                    .to_string(),
            ));
        };
        if previous_authority.is_some() && current_authority.is_none() {
            return Err(BudgetStoreError::Invariant(
                "compensated HA authorization cannot rebind without current authority metadata"
                    .to_string(),
            ));
        }
        Ok(current_authority.clone())
    }

    pub fn import_mutation_record(
        &self,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::import_mutation_record_in_transaction(&transaction, record)?;
        transaction.commit()?;
        Ok(())
    }

    fn import_mutation_record_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        let sqlite_record = ImportedMutationSqlIntegers::try_from_record(record)?;
        Self::validate_imported_mutation_shape(record)?;
        let event_seq_is_abandoned = transaction.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM budget_abandoned_event_seqs WHERE seq = ?1
                UNION ALL
                SELECT 1
                FROM budget_abandoned_event_ranges
                WHERE start_seq <= ?1 AND end_seq >= ?1
            )
            "#,
            params![sqlite_record.event_seq],
            |row| row.get::<_, i64>(0).map(|value| value != 0),
        )?;
        if event_seq_is_abandoned {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event sequence {} was already recorded as abandoned",
                record.event_seq
            )));
        }

        let mut replacement_event_seq = None;
        let duplicate_event =
            if let Some(existing) = Self::load_mutation_event(transaction, &record.event_id)? {
                if Self::same_imported_mutation(&existing, record) {
                    true
                } else if record.event_seq > existing.event_seq
                    && Self::rolled_back_authorize_can_be_replaced(transaction, &existing, record)?
                {
                    replacement_event_seq = Some((
                        existing.event_seq,
                        sqlite_integer_from_u64(
                            existing.event_seq,
                            "superseded budget event sequence",
                        )?,
                    ));
                    false
                } else {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget event_id `{}` was reused for a different mutation",
                        record.event_id
                    )));
                }
            } else {
                false
            };

        if record.kind == BudgetMutationKind::AuthorizeExposure {
            let allowed = record.allowed.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "imported authorization mutation is missing its frozen decision".to_string(),
                )
            })?;
            if let Some(hold_id) = record.hold_id.as_deref() {
                Self::claim_authorization_attempt(
                    transaction,
                    hold_id,
                    &record.event_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    record.exposure_units,
                    record.max_invocations,
                    record.max_cost_per_invocation,
                    record.max_total_cost_units,
                    record.authority.as_ref(),
                    Some(allowed),
                )?;
            }
        }

        raise_budget_replication_seq_floor(transaction, record.event_seq)?;
        if let Some(usage_seq) = record.usage_seq {
            raise_budget_replication_seq_floor(transaction, usage_seq)?;
        }
        if duplicate_event {
            return Ok(());
        }

        if let Some((existing_event_seq, sqlite_existing_event_seq)) = replacement_event_seq {
            transaction.execute(
                "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                params![record.event_id],
            )?;
            if existing_event_seq > 0 && existing_event_seq != record.event_seq {
                transaction.execute(
                    "INSERT OR IGNORE INTO budget_abandoned_event_seqs(seq) VALUES (?1)",
                    params![sqlite_existing_event_seq],
                )?;
            }
            Self::reset_budget_ack_head_watermark(transaction)?;
            if let Some(hold_id) = record.hold_id.as_deref() {
                transaction.execute(
                    "DELETE FROM budget_authorization_holds WHERE hold_id = ?1",
                    params![hold_id],
                )?;
            }
        }

        Self::insert_imported_mutation_event(transaction, record, &sqlite_record)?;
        Self::apply_imported_hold_state(transaction, record)?;
        Ok(())
    }

    /// Insert one imported mutation event row verbatim. Shared by the new-event
    /// import path and the follower rollback-retry REPLACE path (which deletes the
    /// superseded row and tombstones its seq before re-inserting the leader's
    /// re-appended event under its fresh higher event_seq). A plain INSERT is
    /// deliberate and fail-closed: the unique event_seq index rejects a corrupt
    /// stream that reused a seq for a different event rather than silently masking
    /// it.
    fn insert_imported_mutation_event(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
        sqlite_record: &ImportedMutationSqlIntegers,
    ) -> Result<(), BudgetStoreError> {
        transaction.execute(
            r#"
                INSERT INTO budget_mutation_events (
                    event_id,
                    hold_id,
                    capability_id,
                    grant_index,
                    kind,
                    allowed,
                    recorded_at,
                    event_seq,
                    usage_seq,
                    exposure_units,
                    realized_spend_units,
                    max_invocations,
                    max_exposure_per_invocation,
                    max_total_exposure_units,
                    invocation_count_after,
                    total_cost_exposed_after,
                    total_cost_realized_spend_after,
                    authority_id,
                    lease_id,
                    lease_epoch
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
                "#,
            params![
                record.event_id,
                record.hold_id,
                record.capability_id,
                i64::from(record.grant_index),
                record.kind.as_str(),
                record.allowed.map(|value| if value { 1_i64 } else { 0_i64 }),
                record.recorded_at,
                sqlite_record.event_seq,
                sqlite_record.usage_seq,
                sqlite_record.exposure_units,
                sqlite_record.realized_spend_units,
                record.max_invocations.map(i64::from),
                sqlite_record.max_cost_per_invocation,
                sqlite_record.max_total_cost_units,
                i64::from(record.invocation_count_after),
                sqlite_record.total_cost_exposed_after,
                sqlite_record.total_cost_realized_spend_after,
                record.authority.as_ref().map(|value| value.authority_id.as_str()),
                record.authority.as_ref().map(|value| value.lease_id.as_str()),
                sqlite_record.lease_epoch,
            ],
        )?;
        Ok(())
    }

    fn validate_imported_mutation_shape(
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        if !record.invocation_counts_after.is_empty()
            || record.revocation_set.is_some()
            || (record.kind == BudgetMutationKind::AuthorizeExposure && record.allowed.is_none())
            || matches!(
                record.kind,
                BudgetMutationKind::ReserveInvocations
                    | BudgetMutationKind::CaptureInvocations
                    | BudgetMutationKind::ReverseInvocations
            )
        {
            return Err(BudgetStoreError::Invariant(
                "legacy SQLite schema cannot import composite budget mutations".to_string(),
            ));
        }

        let expected_invocation_state = match record.kind {
            BudgetMutationKind::IncrementInvocation => {
                if record.allowed == Some(false) {
                    BudgetInvocationReservationState::Denied
                } else {
                    BudgetInvocationReservationState::Captured
                }
            }
            BudgetMutationKind::AuthorizeExposure
            | BudgetMutationKind::CaptureExposure
            | BudgetMutationKind::ReverseExposure
            | BudgetMutationKind::ReleaseExposure
            | BudgetMutationKind::ReconcileSpend => BudgetInvocationReservationState::Absent,
            BudgetMutationKind::ReserveInvocations
            | BudgetMutationKind::CaptureInvocations
            | BudgetMutationKind::ReverseInvocations => {
                return Err(BudgetStoreError::Invariant(
                    "legacy SQLite schema cannot import composite budget mutations".to_string(),
                ));
            }
        };
        let expected_monetary_state = match record.kind {
            BudgetMutationKind::AuthorizeExposure
                if record.allowed != Some(false) && record.exposure_units > 0 =>
            {
                BudgetMonetaryHoldState::Exposed
            }
            BudgetMutationKind::CaptureExposure => BudgetMonetaryHoldState::Captured,
            BudgetMutationKind::ReverseExposure => BudgetMonetaryHoldState::Reversed,
            BudgetMutationKind::ReleaseExposure => BudgetMonetaryHoldState::Released,
            BudgetMutationKind::ReconcileSpend => BudgetMonetaryHoldState::Reconciled,
            BudgetMutationKind::IncrementInvocation | BudgetMutationKind::AuthorizeExposure => {
                BudgetMonetaryHoldState::None
            }
            BudgetMutationKind::ReserveInvocations
            | BudgetMutationKind::CaptureInvocations
            | BudgetMutationKind::ReverseInvocations => {
                return Err(BudgetStoreError::Invariant(
                    "legacy SQLite schema cannot import composite budget mutations".to_string(),
                ));
            }
        };
        if record.invocation_state != expected_invocation_state
            || record.monetary_state != expected_monetary_state
        {
            return Err(BudgetStoreError::Invariant(
                "imported budget mutation state does not match its persisted legacy projection"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn same_imported_mutation(
        existing: &BudgetMutationRecord,
        imported: &BudgetMutationRecord,
    ) -> bool {
        existing.event_id == imported.event_id
            && existing.hold_id == imported.hold_id
            && existing.capability_id == imported.capability_id
            && existing.grant_index == imported.grant_index
            && existing.kind == imported.kind
            && existing.allowed == imported.allowed
            && existing.recorded_at == imported.recorded_at
            && existing.event_seq == imported.event_seq
            && existing.usage_seq == imported.usage_seq
            && existing.exposure_units == imported.exposure_units
            && existing.realized_spend_units == imported.realized_spend_units
            && existing.max_invocations == imported.max_invocations
            && existing.max_cost_per_invocation == imported.max_cost_per_invocation
            && existing.max_total_cost_units == imported.max_total_cost_units
            && existing.invocation_count_after == imported.invocation_count_after
            && existing.invocation_counts_after == imported.invocation_counts_after
            && existing.invocation_state == imported.invocation_state
            && existing.monetary_state == imported.monetary_state
            && existing.revocation_set == imported.revocation_set
            && existing.total_cost_exposed_after == imported.total_cost_exposed_after
            && existing.total_cost_realized_spend_after == imported.total_cost_realized_spend_after
            && existing.authority == imported.authority
    }

    pub fn list_usages_after(
        &self,
        limit: usize,
        after_seq: Option<u64>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_exposed,
                total_cost_realized_spend
            FROM capability_grant_budgets
            WHERE (?1 IS NULL OR seq > ?1)
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(
            params![after_seq.map(|value| value as i64), limit as i64],
            record_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_all_usages(&self) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_exposed,
                total_cost_realized_spend
            FROM capability_grant_budgets
            ORDER BY updated_at DESC, capability_id ASC, grant_index ASC
            "#,
        )?;
        let rows = statement.query_map([], record_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_mutation_events_after_seq(
        &self,
        limit: usize,
        after_event_seq: u64,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT
                event_id,
                hold_id,
                capability_id,
                grant_index,
                kind,
                allowed,
                recorded_at,
                event_seq,
                usage_seq,
                exposure_units,
                realized_spend_units,
                max_invocations,
                max_exposure_per_invocation,
                max_total_exposure_units,
                invocation_count_after,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority_id,
                lease_id,
                lease_epoch
            FROM budget_mutation_events
            WHERE event_seq > ?1
            ORDER BY event_seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![after_event_seq as i64, limit as i64], |row| {
            mutation_record_from_row(row)
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn generated_event_id(
        transaction: &rusqlite::Transaction<'_>,
    ) -> Result<String, BudgetStoreError> {
        let count =
            transaction.query_row("SELECT COUNT(*) FROM budget_mutation_events", [], |row| {
                row.get::<_, i64>(0)
            })?;
        Ok(format!(
            "sqlite-budget-event-{}-{}",
            unix_now(),
            count.max(0) + 1
        ))
    }

    pub(super) fn load_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
    ) -> Result<Option<SqliteBudgetHold>, BudgetStoreError> {
        transaction
            .query_row(
                r#"
                SELECT
                    hold_id,
                    capability_id,
                    grant_index,
                    authorized_exposure_units,
                    remaining_exposure_units,
                    invocation_count_debited,
                    disposition,
                    authority_id,
                    lease_id,
                    lease_epoch
                FROM budget_authorization_holds
                WHERE hold_id = ?1
                "#,
                params![hold_id],
                |row| {
                    let disposition = row.get::<_, String>(6)?;
                    let authority =
                        sqlite_budget_event_authority(row.get(7)?, row.get(8)?, row.get(9)?)?;
                    Ok(SqliteBudgetHold {
                        hold_id: row.get(0)?,
                        capability_id: row.get(1)?,
                        grant_index: budget_usize_from_row(row, 2, "grant_index")?,
                        authorized_exposure_units: budget_u64_from_row(
                            row,
                            3,
                            "authorized_exposure_units",
                        )?,
                        remaining_exposure_units: budget_u64_from_row(
                            row,
                            4,
                            "remaining_exposure_units",
                        )?,
                        invocation_count_debited: row.get::<_, i64>(5)? > 0,
                        disposition: HoldDisposition::parse(&disposition).ok_or_else(|| {
                            rusqlite::Error::FromSqlConversionFailure(
                                6,
                                rusqlite::types::Type::Text,
                                Box::new(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("unknown hold disposition `{disposition}`"),
                                )),
                            )
                        })?,
                        authority,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub(super) fn load_mutation_event(
        transaction: &rusqlite::Transaction<'_>,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        transaction
            .query_row(
                r#"
                SELECT
                    event_id,
                    hold_id,
                    capability_id,
                    grant_index,
                    kind,
                    allowed,
                    recorded_at,
                    event_seq,
                    usage_seq,
                    exposure_units,
                    realized_spend_units,
                    max_invocations,
                    max_exposure_per_invocation,
                    max_total_exposure_units,
                    invocation_count_after,
                    total_cost_exposed_after,
                    total_cost_realized_spend_after,
                    authority_id,
                    lease_id,
                    lease_epoch
                FROM budget_mutation_events
                WHERE event_id = ?1
                "#,
                params![event_id],
                mutation_record_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(super) fn create_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let now = unix_now();
        transaction.execute(
            r#"
            INSERT INTO budget_authorization_holds (
                hold_id,
                capability_id,
                grant_index,
                authorized_exposure_units,
                remaining_exposure_units,
                invocation_count_debited,
                disposition,
                authority_id,
                lease_id,
                lease_epoch,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9, ?10, ?10)
            "#,
            params![
                hold_id,
                capability_id,
                grant_index as i64,
                authorized_exposure_units as i64,
                authorized_exposure_units as i64,
                HoldDisposition::Open.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority.map(|value| value.lease_epoch as i64),
                now,
            ],
        )?;
        Ok(())
    }

    pub(super) fn update_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        remaining_exposure_units: u64,
        disposition: HoldDisposition,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET remaining_exposure_units = ?2,
                disposition = ?3,
                authority_id = ?4,
                lease_id = ?5,
                lease_epoch = ?6,
                updated_at = ?7
            WHERE hold_id = ?1
            "#,
            params![
                hold_id,
                remaining_exposure_units as i64,
                disposition.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority.map(|value| value.lease_epoch as i64),
                unix_now(),
            ],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn upsert_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        remaining_exposure_units: u64,
        disposition: HoldDisposition,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let now = unix_now();
        transaction.execute(
            r#"
            INSERT INTO budget_authorization_holds (
                hold_id,
                capability_id,
                grant_index,
                authorized_exposure_units,
                remaining_exposure_units,
                invocation_count_debited,
                disposition,
                authority_id,
                lease_id,
                lease_epoch,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9, ?10, ?10)
            ON CONFLICT(hold_id) DO UPDATE SET
                capability_id = excluded.capability_id,
                grant_index = excluded.grant_index,
                authorized_exposure_units = excluded.authorized_exposure_units,
                remaining_exposure_units = excluded.remaining_exposure_units,
                invocation_count_debited = excluded.invocation_count_debited,
                disposition = excluded.disposition,
                authority_id = excluded.authority_id,
                lease_id = excluded.lease_id,
                lease_epoch = excluded.lease_epoch,
                updated_at = excluded.updated_at
            "#,
            params![
                hold_id,
                capability_id,
                grant_index as i64,
                authorized_exposure_units as i64,
                remaining_exposure_units as i64,
                disposition.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority.map(|value| value.lease_epoch as i64),
                now,
            ],
        )?;
        Ok(())
    }

    pub(super) fn delete_hold_if_exists(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
    ) -> Result<(), BudgetStoreError> {
        transaction.execute(
            "DELETE FROM budget_authorization_holds WHERE hold_id = ?1",
            params![hold_id],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn claim_authorization_attempt(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        event_id: &str,
        capability_id: &str,
        grant_index: usize,
        requested_exposure_units: u64,
        max_invocations: Option<u32>,
        max_exposure_per_invocation: Option<u64>,
        max_total_exposure_units: Option<u64>,
        authority: Option<&BudgetEventAuthority>,
        allowed: Option<bool>,
    ) -> Result<(Option<bool>, bool), BudgetStoreError> {
        let grant_index_i64 = sqlite_integer_from_u64(
            u64::try_from(grant_index).map_err(|_| {
                BudgetStoreError::Overflow(
                    "budget authorization claim grant index exceeds u64".to_string(),
                )
            })?,
            "budget authorization claim grant index",
        )?;
        let requested_exposure_i64 = sqlite_integer_from_u64(
            requested_exposure_units,
            "budget authorization claim exposure",
        )?;
        let max_exposure_i64 = max_exposure_per_invocation
            .map(|value| {
                sqlite_integer_from_u64(value, "budget authorization claim per-invocation maximum")
            })
            .transpose()?;
        let max_total_i64 = max_total_exposure_units
            .map(|value| sqlite_integer_from_u64(value, "budget authorization claim total maximum"))
            .transpose()?;
        let lease_epoch_i64 = authority
            .map(|value| {
                sqlite_integer_from_u64(value.lease_epoch, "budget authorization claim lease epoch")
            })
            .transpose()?;

        let existing = Self::load_authorization_claim(transaction, hold_id)?;

        if let Some(existing) = existing {
            let mut rollback_rebind = false;
            let request_matches = existing.event_id == event_id
                && existing.capability_id == capability_id
                && existing.grant_index == grant_index
                && existing.requested_exposure_units == requested_exposure_units
                && existing.max_invocations == max_invocations
                && existing.max_exposure_per_invocation == max_exposure_per_invocation
                && existing.max_total_exposure_units == max_total_exposure_units;
            if !request_matches {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` authorization claim was reused for a different event or input"
                )));
            }
            if let Some(requested_allowed) = allowed {
                if existing
                    .allowed
                    .is_some_and(|existing_allowed| existing_allowed != requested_allowed)
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authorization decision changed"
                    )));
                }
            }
            if existing.authority.as_ref() != authority {
                let fenced_rollback_rebind = existing.allowed == Some(true)
                    && Self::rollback_event_exists(
                        transaction,
                        event_id,
                        Some(hold_id),
                        capability_id,
                        grant_index,
                        requested_exposure_units,
                        existing.authority.as_ref(),
                    )?;
                if !fenced_rollback_rebind {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authorization authority changed"
                    )));
                }
                transaction.execute(
                    r#"
                    UPDATE budget_authorization_claims
                    SET authority_id = ?2,
                        lease_id = ?3,
                        lease_epoch = ?4
                    WHERE hold_id = ?1
                    "#,
                    params![
                        hold_id,
                        authority.map(|value| value.authority_id.as_str()),
                        authority.map(|value| value.lease_id.as_str()),
                        lease_epoch_i64,
                    ],
                )?;
                rollback_rebind = true;
            }
            if let Some(allowed) = allowed {
                transaction.execute(
                    "UPDATE budget_authorization_claims SET allowed = ?2 WHERE hold_id = ?1 AND allowed IS NULL",
                    params![hold_id, if allowed { 1_i64 } else { 0_i64 }],
                )?;
            }
            return Ok((existing.allowed, rollback_rebind));
        }

        let event_claimed_by: Option<String> = transaction
            .query_row(
                "SELECT hold_id FROM budget_authorization_claims WHERE event_id = ?1",
                params![event_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing_hold_id) = event_claimed_by {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` is already claimed by hold `{existing_hold_id}`"
            )));
        }
        let legacy_hold_exists = transaction
            .query_row(
                "SELECT 1 FROM budget_authorization_holds WHERE hold_id = ?1",
                params![hold_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if legacy_hold_exists {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` already occupies an unclaimed hold namespace"
            )));
        }

        transaction.execute(
            r#"
            INSERT INTO budget_authorization_claims (
                hold_id,
                event_id,
                capability_id,
                grant_index,
                requested_exposure_units,
                max_invocations,
                max_exposure_per_invocation,
                max_total_exposure_units,
                authority_id,
                lease_id,
                lease_epoch,
                allowed,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            params![
                hold_id,
                event_id,
                capability_id,
                grant_index_i64,
                requested_exposure_i64,
                max_invocations.map(i64::from),
                max_exposure_i64,
                max_total_i64,
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                lease_epoch_i64,
                allowed.map(|value| if value { 1_i64 } else { 0_i64 }),
                unix_now(),
            ],
        )?;
        Ok((None, false))
    }

    fn load_authorization_claim(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
    ) -> Result<Option<StoredAuthorizationClaim>, BudgetStoreError> {
        transaction
            .query_row(
                r#"
                SELECT
                    event_id,
                    capability_id,
                    grant_index,
                    requested_exposure_units,
                    max_invocations,
                    max_exposure_per_invocation,
                    max_total_exposure_units,
                    authority_id,
                    lease_id,
                    lease_epoch,
                    allowed
                FROM budget_authorization_claims
                WHERE hold_id = ?1
                "#,
                params![hold_id],
                |row| {
                    Ok(StoredAuthorizationClaim {
                        event_id: row.get(0)?,
                        capability_id: row.get(1)?,
                        grant_index: budget_usize_from_row(row, 2, "claim grant_index")?,
                        requested_exposure_units: budget_u64_from_row(
                            row,
                            3,
                            "claim requested_exposure_units",
                        )?,
                        max_invocations: optional_budget_u32_from_row(
                            row,
                            4,
                            "claim max_invocations",
                        )?,
                        max_exposure_per_invocation: optional_budget_u64_from_row(
                            row,
                            5,
                            "claim max_exposure_per_invocation",
                        )?,
                        max_total_exposure_units: optional_budget_u64_from_row(
                            row,
                            6,
                            "claim max_total_exposure_units",
                        )?,
                        authority: sqlite_budget_event_authority(
                            row.get(7)?,
                            row.get(8)?,
                            row.get(9)?,
                        )?,
                        allowed: row.get::<_, Option<i64>>(10)?.map(|value| value != 0),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn apply_imported_hold_state(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        let Some(hold_id) = record.hold_id.as_deref() else {
            return Ok(());
        };

        match record.kind {
            BudgetMutationKind::IncrementInvocation => Ok(()),
            BudgetMutationKind::ReserveInvocations
            | BudgetMutationKind::CaptureInvocations
            | BudgetMutationKind::ReverseInvocations => Err(BudgetStoreError::Invariant(
                "legacy SQLite schema cannot import composite budget mutations".to_string(),
            )),
            BudgetMutationKind::AuthorizeExposure => {
                if record.allowed == Some(true) {
                    Self::upsert_hold(
                        transaction,
                        hold_id,
                        &record.capability_id,
                        record.grant_index as usize,
                        record.exposure_units,
                        record.exposure_units,
                        HoldDisposition::Open,
                        record.authority.as_ref(),
                    )
                } else {
                    Self::delete_hold_if_exists(transaction, hold_id)
                }
            }
            BudgetMutationKind::ReleaseExposure => {
                let hold = Self::load_hold(transaction, hold_id)?.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing budget hold `{hold_id}` while importing release event"
                    ))
                })?;
                if hold.capability_id != record.capability_id
                    || hold.grant_index != record.grant_index as usize
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` does not match capability/grant"
                    )));
                }
                let remaining = hold
                    .remaining_exposure_units
                    .checked_sub(record.exposure_units)
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(format!(
                            "budget hold `{hold_id}` cannot release more than remaining exposure"
                        ))
                    })?;
                let disposition = if remaining == 0 {
                    HoldDisposition::Released
                } else {
                    HoldDisposition::Open
                };
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    hold.authorized_exposure_units,
                    remaining,
                    disposition,
                    record.authority.as_ref().or(hold.authority.as_ref()),
                )
            }
            BudgetMutationKind::ReverseExposure => {
                let authorized_exposure_units = Self::load_hold(transaction, hold_id)?
                    .map(|hold| hold.authorized_exposure_units)
                    .unwrap_or(record.exposure_units);
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    authorized_exposure_units,
                    0,
                    HoldDisposition::Reversed,
                    record.authority.as_ref(),
                )
            }
            BudgetMutationKind::ReconcileSpend => {
                let authorized_exposure_units = Self::load_hold(transaction, hold_id)?
                    .map(|hold| hold.authorized_exposure_units)
                    .unwrap_or(record.exposure_units);
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    authorized_exposure_units,
                    0,
                    HoldDisposition::Reconciled,
                    record.authority.as_ref(),
                )
            }
            BudgetMutationKind::CaptureExposure => {
                let existing = Self::load_hold(transaction, hold_id)?;
                let authorized_exposure_units = if let Some(hold) = existing.as_ref() {
                    if hold.capability_id != record.capability_id
                        || hold.grant_index != record.grant_index as usize
                    {
                        return Err(BudgetStoreError::Invariant(format!(
                            "budget hold `{hold_id}` does not match capability/grant"
                        )));
                    }
                    if hold.disposition != HoldDisposition::Open {
                        return Err(BudgetStoreError::Invariant(format!(
                            "budget hold `{hold_id}` is no longer open"
                        )));
                    }
                    if hold.remaining_exposure_units != record.exposure_units {
                        return Err(BudgetStoreError::Invariant(format!(
                            "budget hold `{hold_id}` does not match captured exposure"
                        )));
                    }
                    Self::validate_hold_authority(
                        hold_id,
                        hold.authority.as_ref(),
                        record.authority.as_ref(),
                    )?;
                    hold.authorized_exposure_units
                } else {
                    record.exposure_units
                };
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    authorized_exposure_units,
                    0,
                    HoldDisposition::Captured,
                    record
                        .authority
                        .as_ref()
                        .or_else(|| existing.as_ref().and_then(|hold| hold.authority.as_ref())),
                )
            }
        }
    }

    pub(super) fn ensure_open_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<SqliteBudgetHold, BudgetStoreError> {
        let hold = Self::load_hold(transaction, hold_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing budget hold `{hold_id}`"))
        })?;
        if hold.capability_id != capability_id || hold.grant_index != grant_index {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` does not match capability/grant"
            )));
        }
        if hold.disposition != HoldDisposition::Open {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` is no longer open"
            )));
        }
        Ok(hold)
    }

    pub(super) fn validate_hold_authority(
        hold_id: &str,
        current: Option<&BudgetEventAuthority>,
        requested: Option<&BudgetEventAuthority>,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        match (current, requested) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` was created without authority lease metadata"
            ))),
            (Some(_), None) => Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` requires authority lease metadata"
            ))),
            (Some(current), Some(requested)) => {
                if current.authority_id != requested.authority_id {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authority_id does not match the open lease"
                    )));
                }
                if requested.lease_id != current.lease_id {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` lease_id does not match the open lease epoch"
                    )));
                }
                if requested.lease_epoch < current.lease_epoch {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authority lease epoch regressed"
                    )));
                }
                if requested.lease_epoch > current.lease_epoch {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authority lease epoch advanced beyond the open lease"
                    )));
                }
                Ok(Some(requested.clone()))
            }
        }
    }

    fn existing_increment_allowed(
        transaction: &rusqlite::Transaction<'_>,
        event_id: Option<&str>,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<Option<bool>, BudgetStoreError> {
        let Some(event_id) = event_id else {
            return Ok(None);
        };
        let existing = transaction
            .query_row(
                r#"
                SELECT capability_id, grant_index, kind, allowed, max_invocations
                FROM budget_mutation_events
                WHERE event_id = ?1
                "#,
                params![event_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        budget_usize_from_row(row, 1, "grant_index")?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        optional_budget_u32_from_row(row, 4, "max_invocations")?,
                    ))
                },
            )
            .optional()?;
        let Some((
            existing_capability_id,
            existing_grant_index,
            existing_kind,
            existing_allowed,
            existing_max_invocations,
        )) = existing
        else {
            return Ok(None);
        };
        let mutation_matches = existing_capability_id == capability_id
            && existing_grant_index == grant_index
            && existing_kind == BudgetMutationKind::IncrementInvocation.as_str()
            && existing_max_invocations == max_invocations;
        if !mutation_matches {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` was reused for a different mutation"
            )));
        }
        Ok(Some(existing_allowed.unwrap_or(0) > 0))
    }

    fn sqlite_like_prefix_pattern(prefix: &str) -> String {
        let mut pattern = String::with_capacity(prefix.len() + 1);
        for ch in prefix.chars() {
            match ch {
                '\\' | '%' | '_' => {
                    pattern.push('\\');
                    pattern.push(ch);
                }
                _ => pattern.push(ch),
            }
        }
        pattern.push('%');
        pattern
    }

    pub(super) fn rollback_event_exists(
        transaction: &rusqlite::Transaction<'_>,
        event_id: &str,
        hold_id: Option<&str>,
        capability_id: &str,
        grant_index: usize,
        exposure_units: u64,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        let rollback_prefix = format!("{event_id}:rollback:");
        let rollback_prefix_pattern = Self::sqlite_like_prefix_pattern(&rollback_prefix);
        let grant_index = i64::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Overflow(
                "budget rollback grant index exceeds SQLite INTEGER".to_string(),
            )
        })?;
        let exposure_units = sqlite_integer_from_u64(exposure_units, "budget rollback exposure")?;
        let lease_epoch = authority
            .map(|value| sqlite_integer_from_u64(value.lease_epoch, "budget rollback lease epoch"))
            .transpose()?;
        Ok(transaction
            .query_row(
                r#"
                SELECT 1
                FROM budget_mutation_events
                WHERE event_id LIKE ?1 ESCAPE '\'
                  AND kind = ?2
                  AND allowed IS NULL
                  AND hold_id IS ?3
                  AND capability_id = ?4
                  AND grant_index = ?5
                  AND exposure_units = ?6
                  AND realized_spend_units = 0
                  AND max_invocations IS NULL
                  AND max_exposure_per_invocation IS NULL
                  AND max_total_exposure_units IS NULL
                  AND authority_id IS ?7
                  AND lease_id IS ?8
                  AND lease_epoch IS ?9
                  AND usage_seq = event_seq
                LIMIT 1
                "#,
                params![
                    rollback_prefix_pattern,
                    BudgetMutationKind::ReverseExposure.as_str(),
                    hold_id,
                    capability_id,
                    grant_index,
                    exposure_units,
                    authority.map(|value| value.authority_id.as_str()),
                    authority.map(|value| value.lease_id.as_str()),
                    lease_epoch,
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    fn rolled_back_authorize_can_be_replaced(
        transaction: &rusqlite::Transaction<'_>,
        existing: &BudgetMutationRecord,
        replacement: &BudgetMutationRecord,
    ) -> Result<bool, BudgetStoreError> {
        if existing.kind != BudgetMutationKind::AuthorizeExposure
            || replacement.kind != BudgetMutationKind::AuthorizeExposure
            || existing.allowed != Some(true)
            || replacement.allowed != Some(true)
        {
            return Ok(false);
        }
        let same_mutation_scope = existing.hold_id == replacement.hold_id
            && existing.capability_id == replacement.capability_id
            && existing.grant_index == replacement.grant_index
            && existing.exposure_units == replacement.exposure_units
            && existing.realized_spend_units == replacement.realized_spend_units
            && existing.max_invocations == replacement.max_invocations
            && existing.max_cost_per_invocation == replacement.max_cost_per_invocation
            && existing.max_total_cost_units == replacement.max_total_cost_units;
        if !same_mutation_scope {
            return Ok(false);
        }
        Self::rollback_event_exists(
            transaction,
            &existing.event_id,
            existing.hold_id.as_deref(),
            &existing.capability_id,
            existing.grant_index as usize,
            existing.exposure_units,
            existing.authority.as_ref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn existing_event_allowed(
        transaction: &rusqlite::Transaction<'_>,
        event_id: Option<&str>,
        kind: BudgetMutationKind,
        capability_id: &str,
        grant_index: usize,
        hold_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
        exposure_units: u64,
        realized_spend_units: u64,
        max_invocations: Option<u32>,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<Option<Option<bool>>, BudgetStoreError> {
        let Some(event_id) = event_id else {
            return Ok(None);
        };
        let existing = transaction
            .query_row(
                r#"
                SELECT
                    hold_id,
                    capability_id,
                    grant_index,
                    kind,
                    allowed,
                    exposure_units,
                    realized_spend_units,
                    max_invocations,
                    max_exposure_per_invocation,
                    max_total_exposure_units,
                    invocation_count_after,
                    total_cost_exposed_after,
                    total_cost_realized_spend_after,
                    authority_id,
                    lease_id,
                    lease_epoch
                FROM budget_mutation_events
                WHERE event_id = ?1
                "#,
                params![event_id],
                |row| {
                    let existing_authority =
                        sqlite_budget_event_authority(row.get(13)?, row.get(14)?, row.get(15)?)?;
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        budget_usize_from_row(row, 2, "grant_index")?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        budget_u64_from_row(row, 5, "exposure_units")?,
                        budget_u64_from_row(row, 6, "realized_spend_units")?,
                        optional_budget_u32_from_row(row, 7, "max_invocations")?,
                        optional_budget_u64_from_row(row, 8, "max_exposure_per_invocation")?,
                        optional_budget_u64_from_row(row, 9, "max_total_exposure_units")?,
                        budget_u32_from_row(row, 10, "invocation_count_after")?,
                        budget_u64_from_row(row, 11, "total_cost_exposed_after")?,
                        budget_u64_from_row(row, 12, "total_cost_realized_spend_after")?,
                        existing_authority,
                    ))
                },
            )
            .optional()?;
        let Some((
            existing_hold_id,
            existing_capability_id,
            existing_grant_index,
            existing_kind,
            existing_allowed,
            existing_exposure_units,
            existing_realized_spend_units,
            existing_max_invocations,
            existing_max_exposure_per_invocation,
            existing_max_total_exposure_units,
            existing_invocation_count_after,
            existing_total_cost_exposed_after,
            existing_total_cost_realized_spend_after,
            existing_authority,
        )) = existing
        else {
            return Ok(None);
        };
        let max_invocations_matches = existing_max_invocations == max_invocations;
        let max_per_matches = existing_max_exposure_per_invocation == max_cost_per_invocation;
        let max_total_matches = existing_max_total_exposure_units == max_total_cost_units;
        let mutation_scope_matches = existing_capability_id == capability_id
            && existing_grant_index == grant_index
            && existing_kind == kind.as_str()
            && existing_hold_id.as_deref() == hold_id
            && existing_exposure_units == exposure_units
            && existing_realized_spend_units == realized_spend_units
            && max_invocations_matches
            && max_per_matches
            && max_total_matches;
        let authority_matches = existing_authority.as_ref() == authority;
        let existing_allowed = existing_allowed.map(|value| value > 0);
        let rollback_exists = kind == BudgetMutationKind::AuthorizeExposure
            && existing_allowed == Some(true)
            && Self::rollback_event_exists(
                transaction,
                event_id,
                existing_hold_id.as_deref(),
                &existing_capability_id,
                existing_grant_index,
                existing_exposure_units,
                existing_authority.as_ref(),
            )?;
        if !mutation_scope_matches || (!authority_matches && !rollback_exists) {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` was reused for a different mutation"
            )));
        }
        if rollback_exists {
            let current = transaction
                .query_row(
                    r#"
                    SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                    FROM capability_grant_budgets
                    WHERE capability_id = ?1 AND grant_index = ?2
                    "#,
                    params![capability_id, grant_index as i64],
                    |row| {
                        Ok((
                            budget_u32_from_row(row, 0, "invocation_count")?,
                            budget_u64_from_row(row, 1, "total_cost_exposed")?,
                            budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                        ))
                    },
                )
                .optional()?;
            let usage_matches = current.is_some_and(
                |(invocation_count, total_cost_exposed, total_cost_realized_spend)| {
                    invocation_count == existing_invocation_count_after
                        && total_cost_exposed == existing_total_cost_exposed_after
                        && total_cost_realized_spend == existing_total_cost_realized_spend_after
                },
            );
            let hold_matches = match hold_id {
                Some(hold_id) => Self::load_hold(transaction, hold_id)?.is_some_and(|hold| {
                    hold.capability_id == capability_id
                        && hold.grant_index == grant_index
                        && hold.authorized_exposure_units == exposure_units
                        && hold.remaining_exposure_units == exposure_units
                        && hold.invocation_count_debited
                        && hold.disposition == HoldDisposition::Open
                }),
                None => true,
            };
            if usage_matches && hold_matches {
                return Ok(Some(existing_allowed));
            }
            // This is a GENUINE rollback-retry: the rolled-back authorize is
            // deleted and the caller re-appends it under a fresh higher seq. Record
            // the freed seq as abandoned/tombstoned BEFORE the delete so the global
            // contiguous ack head treats it as filled and does not stall cluster-
            // wide at the resulting hole. This recording is deliberately ONLY at the
            // rollback-retry site (not the AFTER DELETE trigger), so that a data-loss
            // delete still caps the head (fail-closed). Never over-counts: the
            // abandoned seq's write was superseded, so no live write targets it.
            let abandoned_seq: Option<i64> = transaction
                .query_row(
                    "SELECT event_seq FROM budget_mutation_events WHERE event_id = ?1",
                    params![event_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten();
            transaction.execute(
                "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                params![event_id],
            )?;
            if let Some(seq) = abandoned_seq {
                if seq > 0 {
                    transaction.execute(
                        "INSERT OR IGNORE INTO budget_abandoned_event_seqs(seq) VALUES (?1)",
                        params![seq],
                    )?;
                }
            }
            Self::reset_budget_ack_head_watermark(transaction)?;
            if let Some(hold_id) = hold_id {
                transaction.execute(
                    "DELETE FROM budget_authorization_holds WHERE hold_id = ?1",
                    params![hold_id],
                )?;
            }
            return Ok(None);
        }
        Ok(Some(existing_allowed))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn append_mutation_event(
        transaction: &rusqlite::Transaction<'_>,
        event_id: Option<&str>,
        hold_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
        capability_id: &str,
        grant_index: usize,
        kind: BudgetMutationKind,
        allowed: Option<bool>,
        event_seq: u64,
        usage_seq: Option<u64>,
        exposure_units: u64,
        realized_spend_units: u64,
        max_invocations: Option<u32>,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        invocation_count_after: u32,
        total_cost_exposed_after: u64,
        total_cost_realized_spend_after: u64,
    ) -> Result<(), BudgetStoreError> {
        let event_id = match event_id {
            Some(event_id) => event_id.to_string(),
            None => Self::generated_event_id(transaction)?,
        };
        let sqlite_integer = |value: u64, label: &str| {
            i64::try_from(value)
                .map_err(|_| BudgetStoreError::Overflow(format!("{label} exceeds SQLite INTEGER")))
        };
        let grant_index = i64::try_from(grant_index).map_err(|_| {
            BudgetStoreError::Overflow("budget grant index exceeds SQLite INTEGER".to_string())
        })?;
        let event_seq = sqlite_integer(event_seq, "budget event sequence")?;
        let usage_seq = usage_seq
            .map(|value| sqlite_integer(value, "budget usage sequence"))
            .transpose()?;
        let exposure_units = sqlite_integer(exposure_units, "budget exposure")?;
        let realized_spend_units = sqlite_integer(realized_spend_units, "budget realized spend")?;
        let max_cost_per_invocation = max_cost_per_invocation
            .map(|value| sqlite_integer(value, "budget per-invocation maximum"))
            .transpose()?;
        let max_total_cost_units = max_total_cost_units
            .map(|value| sqlite_integer(value, "budget total maximum"))
            .transpose()?;
        let total_cost_exposed_after =
            sqlite_integer(total_cost_exposed_after, "budget exposure total")?;
        let total_cost_realized_spend_after = sqlite_integer(
            total_cost_realized_spend_after,
            "budget realized-spend total",
        )?;
        let lease_epoch = authority
            .map(|value| sqlite_integer(value.lease_epoch, "budget lease epoch"))
            .transpose()?;
        transaction.execute(
            r#"
            INSERT INTO budget_mutation_events (
                event_id,
                hold_id,
                capability_id,
                grant_index,
                kind,
                allowed,
                recorded_at,
                event_seq,
                usage_seq,
                exposure_units,
                realized_spend_units,
                max_invocations,
                max_exposure_per_invocation,
                max_total_exposure_units,
                invocation_count_after,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority_id,
                lease_id,
                lease_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
            "#,
            params![
                event_id,
                hold_id,
                capability_id,
                grant_index,
                kind.as_str(),
                allowed.map(|value| if value { 1_i64 } else { 0_i64 }),
                unix_now(),
                event_seq,
                usage_seq,
                exposure_units,
                realized_spend_units,
                max_invocations.map(i64::from),
                max_cost_per_invocation,
                max_total_cost_units,
                i64::from(invocation_count_after),
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                lease_epoch,
            ],
        )?;
        Ok(())
    }

    pub(super) fn reject_composite_managed_grant(
        transaction: &rusqlite::Transaction<'_>,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<(), BudgetStoreError> {
        let managed = transaction
            .query_row(
                r#"
                SELECT 1
                FROM budget_composite_managed_grants
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if managed {
            return Err(BudgetStoreError::Invariant(format!(
                "grant `{capability_id}` requires composite invocation admission"
            )));
        }
        Ok(())
    }

    pub fn try_increment_with_event_id(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(allowed) = SqliteBudgetStore::existing_increment_allowed(
            &transaction,
            event_id,
            capability_id,
            grant_index,
            max_invocations,
        )? {
            transaction.rollback()?;
            return Ok(allowed);
        }
        SqliteBudgetStore::reject_composite_managed_grant(
            &transaction,
            capability_id,
            grant_index,
        )?;

        let current: Option<(u32, u64, u64)> = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?;
        let (current, total_cost_exposed, total_cost_realized_spend) = current.unwrap_or((0, 0, 0));
        let updated_at = unix_now();

        if let Some(max) = max_invocations {
            if current >= max {
                let event_seq = allocate_budget_replication_seq(&transaction)?;
                SqliteBudgetStore::append_mutation_event(
                    &transaction,
                    event_id,
                    None,
                    None,
                    capability_id,
                    grant_index,
                    BudgetMutationKind::IncrementInvocation,
                    Some(false),
                    event_seq,
                    None,
                    0,
                    0,
                    max_invocations,
                    None,
                    None,
                    current,
                    total_cost_exposed,
                    total_cost_realized_spend,
                )?;
                transaction.commit()?;
                return Ok(false);
            }
        }

        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            INSERT INTO capability_grant_budgets (
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_exposed,
                total_cost_realized_spend
            ) VALUES (?1, ?2, ?3, ?4, ?5, 0, 0)
            ON CONFLICT(capability_id, grant_index) DO UPDATE SET
                invocation_count = excluded.invocation_count,
                updated_at = excluded.updated_at,
                seq = excluded.seq
            "#,
            params![
                capability_id,
                grant_index as i64,
                current.saturating_add(1) as i64,
                updated_at,
                seq as i64,
            ],
        )?;
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            None,
            None,
            capability_id,
            grant_index,
            BudgetMutationKind::IncrementInvocation,
            Some(true),
            seq,
            Some(seq),
            0,
            0,
            max_invocations,
            None,
            None,
            current.saturating_add(1),
            total_cost_exposed,
            total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(true)
    }
}
