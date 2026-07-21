use super::*;

/// Quorum-witness identity of a stored budget mutation event: its `event_seq`,
/// origin `authority_id`, and origin `lease_epoch`.
pub type BudgetEventWitness = (u64, Option<String>, Option<u64>);
/// Grant key to `(maximum, captured, replication sequence)`.
type SuppliedCompatibilityQuotas =
    std::collections::BTreeMap<(String, u32), (u32, u32, u64)>;
/// Grant key to `(invocation count, replication sequence)`.
type SuppliedCompatibilityUsages = std::collections::BTreeMap<(String, u32), (u32, u64)>;
const MAX_DIAGNOSTIC_ABANDONED_EVENT_SEQS: usize = 100_000;
const SQLITE_LOCK_WAIT: Duration = Duration::from_secs(5);
const SQLITE_WAL_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const BUDGET_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 0;
const BUDGET_STORE_SCHEMA_KEY: &str = "budget";
const BUDGET_STORE_LEGACY_ANCHOR_TABLES: &[&str] = &["capability_grant_budgets"];

pub(super) fn retry_write_ahead_logging(
    mut enable: impl FnMut() -> rusqlite::Result<String>,
    mut before_deadline: impl FnMut() -> bool,
    mut wait: impl FnMut(),
) -> Result<(), BudgetStoreError> {
    loop {
        match enable() {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => return Ok(()),
            Ok(mode) => {
                if before_deadline() {
                    wait();
                    continue;
                }
                return Err(BudgetStoreError::Invariant(format!(
                    "sqlite budget store requires WAL mode, got `{mode}`"
                )));
            }
            Err(error)
                if matches!(
                    error.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                ) && before_deadline() =>
            {
                wait();
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn enable_write_ahead_logging(connection: &Connection) -> Result<(), BudgetStoreError> {
    let deadline = Instant::now() + SQLITE_LOCK_WAIT;
    connection.busy_timeout(SQLITE_WAL_RETRY_INTERVAL)?;
    let result = retry_write_ahead_logging(
        || {
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| {
                row.get::<_, String>(0)
            })
        },
        || Instant::now() < deadline,
        || std::thread::sleep(SQLITE_WAL_RETRY_INTERVAL),
    );
    connection.busy_timeout(SQLITE_LOCK_WAIT)?;
    result
}

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

struct RawQuotaRow {
    profile: String,
    owner_id: String,
    grant_index_key: i64,
    maximum: u32,
    reserved: u32,
    captured: u32,
    updated_at: i64,
    seq: u64,
}

#[derive(Clone, Copy)]
pub(super) struct BudgetAdmissionOperationParts<'a> {
    pub(super) operation_id: &'a str,
    pub(super) request_binding_hash: &'a str,
}

impl<'a> BudgetAdmissionOperationParts<'a> {
    pub(super) fn new(operation_id: &'a str, request_binding_hash: &'a str) -> Self {
        Self {
            operation_id,
            request_binding_hash,
        }
    }

    fn from_binding(binding: &'a BudgetAdmissionOperationBinding) -> Self {
        Self::new(binding.operation_id(), binding.request_binding_hash())
    }
}

pub(super) struct BudgetHoldCreateInput<'a> {
    pub(super) hold_id: &'a str,
    pub(super) capability_id: &'a str,
    pub(super) grant_index: usize,
    pub(super) authorized_exposure_units: u64,
    pub(super) authority: Option<&'a BudgetEventAuthority>,
    pub(super) admission_operation: Option<BudgetAdmissionOperationParts<'a>>,
}

pub(super) struct BudgetHoldUpsertInput<'a> {
    pub(super) hold_id: &'a str,
    pub(super) capability_id: &'a str,
    pub(super) grant_index: usize,
    pub(super) authorized_exposure_units: u64,
    pub(super) remaining_exposure_units: u64,
    pub(super) disposition: HoldDisposition,
    pub(super) authority: Option<&'a BudgetEventAuthority>,
    pub(super) admission_operation: Option<BudgetAdmissionOperationParts<'a>>,
}

pub(super) struct BudgetMutationEventInput<'a> {
    pub(super) event_id: Option<&'a str>,
    pub(super) hold_id: Option<&'a str>,
    pub(super) authority: Option<&'a BudgetEventAuthority>,
    pub(super) capability_id: &'a str,
    pub(super) grant_index: usize,
    pub(super) kind: BudgetMutationKind,
    pub(super) allowed: Option<bool>,
    pub(super) event_seq: u64,
    pub(super) usage_seq: Option<u64>,
    pub(super) exposure_units: u64,
    pub(super) realized_spend_units: u64,
    pub(super) max_invocations: Option<u32>,
    pub(super) max_cost_per_invocation: Option<u64>,
    pub(super) max_total_cost_units: Option<u64>,
    pub(super) invocation_count_after: u32,
    pub(super) total_cost_exposed_after: u64,
    pub(super) total_cost_realized_spend_after: u64,
    pub(super) admission_operation: Option<BudgetAdmissionOperationParts<'a>>,
}

impl RawQuotaRow {
    fn from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            profile: row.get(0)?,
            owner_id: row.get(1)?,
            grant_index_key: row.get(2)?,
            maximum: budget_u32_from_row(row, 3, "quota max_invocations")?,
            reserved: budget_u32_from_row(row, 4, "quota reserved_invocations")?,
            captured: budget_u32_from_row(row, 5, "quota captured_invocations")?,
            updated_at: row.get(6)?,
            seq: budget_u64_from_row(row, 7, "quota usage sequence")?,
        })
    }
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
        reject_volatile_database_path(path)?;
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            fs::create_dir_all(parent)?;
        }

        let connection = Connection::open(path)?;
        crate::check_schema_version(
            &connection,
            BUDGET_STORE_SCHEMA_KEY,
            BUDGET_STORE_SUPPORTED_SCHEMA_VERSION,
            BUDGET_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        Self::from_connection(connection, BudgetStoreProfile::SingleNodeDurable)
    }

    /// Open a durable budget authority through one retained trusted parent.
    pub fn open_hardened(
        path: impl AsRef<Path>,
        directory: Arc<crate::durable_sqlite::TrustedSqliteDirectory>,
    ) -> Result<Self, BudgetStoreError> {
        let database_identity_file = directory
            .open_database(path, true)
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        let connection = database_identity_file
            .open_connection(
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        crate::check_schema_version(
            &connection,
            BUDGET_STORE_SCHEMA_KEY,
            BUDGET_STORE_SUPPORTED_SCHEMA_VERSION,
            BUDGET_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        Self::from_connection_with_identity(
            connection,
            BudgetStoreProfile::SingleNodeDurable,
            Some(database_identity_file),
        )
    }

    pub fn open_in_memory() -> Result<Self, BudgetStoreError> {
        let connection = Connection::open_in_memory()?;
        Self::from_connection(connection, BudgetStoreProfile::EphemeralLocal)
    }

    fn from_connection(
        connection: Connection,
        authority_profile: BudgetStoreProfile,
    ) -> Result<Self, BudgetStoreError> {
        Self::from_connection_with_identity(connection, authority_profile, None)
    }

    fn from_connection_with_identity(
        mut connection: Connection,
        authority_profile: BudgetStoreProfile,
        database_identity_file: Option<Arc<crate::durable_sqlite::DurableSqliteFile>>,
    ) -> Result<Self, BudgetStoreError> {
        connection.busy_timeout(SQLITE_LOCK_WAIT)?;
        if authority_profile == BudgetStoreProfile::SingleNodeDurable {
            enable_write_ahead_logging(&connection)?;
            if let Some(database_identity_file) = database_identity_file.as_ref() {
                database_identity_file
                    .validate_live_connection(&connection)
                    .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
            }
        }
        connection.execute_batch(
            r#"
            PRAGMA synchronous = FULL;

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
                operation_id TEXT,
                request_binding_hash TEXT,
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
                updated_at INTEGER NOT NULL,
                CHECK (
                    (operation_id IS NULL AND request_binding_hash IS NULL)
                    OR
                    (operation_id IS NOT NULL AND request_binding_hash IS NOT NULL)
                )
            );

            CREATE INDEX IF NOT EXISTS idx_budget_authorization_holds_capability
                ON budget_authorization_holds(capability_id, grant_index);

            CREATE TABLE IF NOT EXISTS payment_journal (
                request_id          TEXT PRIMARY KEY,
                capability_id       TEXT NOT NULL,
                grant_index         INTEGER NOT NULL,
                operation_id        TEXT,
                request_binding_hash TEXT,
                authority_id        TEXT,
                lease_id            TEXT,
                lease_epoch         INTEGER,
                hold_id             TEXT,
                rail                TEXT NOT NULL,
                authorization_id    TEXT,
                transaction_id      TEXT,
                budget_exposure_units INTEGER NOT NULL,
                amount_units        INTEGER NOT NULL,
                settle_action       TEXT,
                settle_amount_units INTEGER,
                currency            TEXT NOT NULL,
                state               TEXT NOT NULL,
                created_at          INTEGER NOT NULL,
                updated_at          INTEGER NOT NULL,
                tenant_id           TEXT,
                CHECK (
                    (operation_id IS NULL AND request_binding_hash IS NULL)
                    OR
                    (operation_id IS NOT NULL AND request_binding_hash IS NOT NULL)
                ),
                CHECK (
                    operation_id IS NULL
                    OR (
                        length(operation_id) BETWEEN 1 AND 512
                        AND instr(operation_id, char(0)) = 0
                    )
                ),
                CHECK (
                    request_binding_hash IS NULL
                    OR (
                        length(request_binding_hash) = 64
                        AND request_binding_hash NOT GLOB '*[^0-9a-f]*'
                    )
                ),
                CHECK (
                    (authority_id IS NULL AND lease_id IS NULL AND lease_epoch IS NULL)
                    OR
                    (
                        authority_id IS NOT NULL
                        AND lease_id IS NOT NULL
                        AND lease_epoch IS NOT NULL
                        AND lease_epoch >= 0
                    )
                )
            );

            CREATE INDEX IF NOT EXISTS idx_payment_journal_state
                ON payment_journal(state);

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
                operation_id TEXT,
                request_binding_hash TEXT,
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
                lease_epoch INTEGER,
                CHECK (
                    (operation_id IS NULL AND request_binding_hash IS NULL)
                    OR
                    (operation_id IS NOT NULL AND request_binding_hash IS NOT NULL)
                )
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
        ensure_budget_hold_reserved_until_column(&connection)?;
        ensure_budget_hold_reserved_currency_column(&connection)?;
        ensure_budget_hold_reserved_payment_reference_column(&connection)?;
        ensure_budget_hold_reserved_envelope_columns(&connection)?;
        ensure_budget_mutation_event_authority_columns(&connection)?;
        ensure_budget_mutation_event_seq_column(&connection)?;
        ensure_composite_budget_schema(&connection)?;
        ensure_budget_admission_operation_columns(&connection)?;
        ensure_payment_journal_operation_columns(&connection)?;
        ensure_budget_authorization_claims(&mut connection)?;
        ensure_composite_budget_namespace_guards(&connection)?;
        initialize_budget_replication_seq(&mut connection)?;
        crate::stamp_schema_version(
            &connection,
            BUDGET_STORE_SCHEMA_KEY,
            BUDGET_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        if let Some(database_identity_file) = database_identity_file.as_ref() {
            database_identity_file
                .validate_live_connection(&connection)
                .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        }

        Ok(Self {
            connection: Mutex::new(connection),
            authority_profile,
            database_identity_file,
        })
    }

    pub(super) fn connection(&self) -> Result<MutexGuard<'_, Connection>, BudgetStoreError> {
        let connection = self.connection.lock().map_err(|_| {
            BudgetStoreError::Invariant("sqlite budget store lock poisoned".to_string())
        })?;
        if let Some(database_identity_file) = self.database_identity_file.as_ref() {
            database_identity_file
                .validate_live_connection(&connection)
                .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        }
        Ok(connection)
    }

    pub fn is_admission_authority_managed(&self) -> Result<bool, BudgetStoreError> {
        let connection = self.connection()?;
        Ok(Self::admission_authority_mode(&connection)?.is_some())
    }

    pub(super) fn admission_authority_mode(
        connection: &Connection,
    ) -> Result<Option<String>, BudgetStoreError> {
        let marker_exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            params![crate::revocation_store::ADMISSION_AUTHORITY_META_TABLE],
            |row| row.get::<_, i64>(0),
        )? != 0;
        if !marker_exists {
            return Ok(None);
        }
        let mode = connection
            .query_row(
                "SELECT mode FROM admission_authority_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "budget database has incomplete admission authority metadata".to_string(),
                )
            })?;
        if mode != crate::admission_capture_authority::COMBINED_AUTHORITY_MODE {
            return Err(BudgetStoreError::Invariant(format!(
                "unsupported admission authority database mode `{mode}`"
            )));
        }
        Ok(Some(mode))
    }

    fn require_legacy_replication_write(connection: &Connection) -> Result<(), BudgetStoreError> {
        if let Some(mode) = Self::admission_authority_mode(connection)? {
            return Err(BudgetStoreError::Invariant(format!(
                "budget database is managed by the `{mode}` admission authority"
            )));
        }
        Ok(())
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
        let mut connection = self.connection()?;
        Self::require_legacy_replication_write(&connection)?;
        let sqlite_seqs = seqs
            .iter()
            .copied()
            .filter(|seq| *seq != 0)
            .map(|seq| sqlite_integer_from_u64(seq, "abandoned budget event sequence"))
            .collect::<Result<Vec<_>, _>>()?;
        if sqlite_seqs.is_empty() {
            return Ok(());
        }
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
        let mut connection = self.connection()?;
        Self::require_legacy_replication_write(&connection)?;
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
        let mut connection = self.connection()?;
        Self::require_legacy_replication_write(&connection)?;
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
        Self::require_legacy_replication_write(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::upsert_usage_in_transaction(&transaction, record)?;
        Self::validate_imported_usage_invocation_authority(&transaction, record, false)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn import_snapshot_records(
        &self,
        usages: &[BudgetUsageRecord],
        events: &[BudgetMutationRecord],
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        Self::require_legacy_replication_write(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for usage in usages {
            Self::upsert_usage_in_transaction(&transaction, usage)?;
        }
        for event in events {
            Self::import_mutation_record_in_transaction(&transaction, event)?;
        }
        for usage in usages {
            Self::validate_imported_usage_invocation_authority(&transaction, usage, false)?;
        }
        for event in events {
            Self::validate_imported_event_invocation_authority(&transaction, event, None, None)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Atomically import the legacy usage projection, its immutable structured
    /// invocation authority, and the mutation ledger that produced both.
    pub fn import_snapshot_records_with_invocation_quotas(
        &self,
        usages: &[BudgetUsageRecord],
        invocation_quotas: &[BudgetInvocationQuotaUsageRecord],
        events: &[BudgetMutationRecord],
    ) -> Result<(), BudgetStoreError> {
        let supplied_quotas = Self::supplied_compatibility_quotas(invocation_quotas)?;
        let supplied_usages = Self::supplied_compatibility_usages(usages)?;
        let mut connection = self.connection()?;
        Self::require_legacy_replication_write(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for usage in usages {
            Self::upsert_usage_in_transaction(&transaction, usage)?;
        }
        for quota in invocation_quotas {
            Self::upsert_compatibility_invocation_quota_in_transaction(&transaction, quota)?;
        }
        for event in events {
            Self::import_mutation_record_in_transaction(&transaction, event)?;
        }
        for usage in usages {
            let supplied =
                supplied_quotas.contains_key(&(usage.capability_id.clone(), usage.grant_index));
            Self::validate_imported_usage_invocation_authority(&transaction, usage, supplied)?;
        }
        for quota in invocation_quotas {
            let key = quota.usage.quota.key();
            Self::validate_compatibility_projection_for_grant(
                &transaction,
                key.owner_id(),
                key.grant_index().ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "replicated compatibility quota is missing grant_index".to_string(),
                    )
                })?,
            )?;
        }
        for event in events {
            let supplied_quota = supplied_quotas
                .get(&(event.capability_id.clone(), event.grant_index))
                .copied();
            let supplied_usage = supplied_usages
                .get(&(event.capability_id.clone(), event.grant_index))
                .copied();
            Self::validate_imported_event_invocation_authority(
                &transaction,
                event,
                supplied_quota,
                supplied_usage,
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn supplied_compatibility_quotas(
        invocation_quotas: &[BudgetInvocationQuotaUsageRecord],
    ) -> Result<SuppliedCompatibilityQuotas, BudgetStoreError> {
        let mut supplied = std::collections::BTreeMap::new();
        for record in invocation_quotas {
            record.validate_compatibility_projection()?;
            let key = record.usage.quota.key();
            let grant_index = key.grant_index().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "replicated compatibility quota is missing grant_index".to_string(),
                )
            })?;
            let maximum = record.usage.quota.max_invocations();
            let captured = record.usage.captured_invocations_after;
            let map_key = (key.owner_id().to_string(), grant_index);
            if let Some((previous_maximum, previous_captured, previous_seq)) =
                supplied.get(&map_key).copied()
            {
                if previous_maximum != maximum {
                    return Err(BudgetStoreError::Invariant(format!(
                        "invocation quota `{}` was supplied with conflicting immutable maxima",
                        key.owner_id()
                    )));
                }
                if previous_seq == record.seq && previous_captured != captured {
                    return Err(BudgetStoreError::Conflict(format!(
                        "invocation quota `{}` reused sequence {} for different counters",
                        key.owner_id(),
                        record.seq
                    )));
                }
                if previous_seq > record.seq {
                    continue;
                }
            }
            supplied.insert(map_key, (maximum, captured, record.seq));
        }
        Ok(supplied)
    }

    fn supplied_compatibility_usages(
        usages: &[BudgetUsageRecord],
    ) -> Result<SuppliedCompatibilityUsages, BudgetStoreError> {
        let mut supplied = std::collections::BTreeMap::new();
        for usage in usages {
            let key = (usage.capability_id.clone(), usage.grant_index);
            if let Some((previous_count, previous_seq)) = supplied.get(&key).copied() {
                if previous_seq == usage.seq && previous_count != usage.invocation_count {
                    return Err(BudgetStoreError::Conflict(format!(
                        "budget usage `{}` reused sequence {} for different invocation counts",
                        usage.capability_id, usage.seq
                    )));
                }
                if previous_seq > usage.seq {
                    continue;
                }
            }
            supplied.insert(key, (usage.invocation_count, usage.seq));
        }
        Ok(supplied)
    }

    fn validate_imported_event_invocation_authority(
        transaction: &rusqlite::Transaction<'_>,
        event: &BudgetMutationRecord,
        supplied_quota: Option<(u32, u32, u64)>,
        supplied_usage: Option<(u32, u64)>,
    ) -> Result<(), BudgetStoreError> {
        if !matches!(
            event.kind,
            BudgetMutationKind::IncrementInvocation | BudgetMutationKind::AuthorizeExposure
        ) {
            return Ok(());
        }
        let (supplied_maximum, supplied_captured, supplied_quota_seq) =
            supplied_quota.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "replicated invocation event `{}` omitted its immutable quota projection",
                    event.event_id
                ))
            })?;
        let expected_maximum = event.max_invocations.unwrap_or(u32::MAX);
        if supplied_maximum != expected_maximum {
            return Err(BudgetStoreError::Invariant(format!(
                "replicated invocation event `{}` conflicts with its supplied immutable quota maximum",
                event.event_id
            )));
        }
        if supplied_quota_seq < event.event_seq
            || (supplied_quota_seq == event.event_seq
                && supplied_captured != event.invocation_count_after)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "replicated invocation event `{}` is newer than its supplied quota projection",
                event.event_id
            )));
        }
        if event.allowed == Some(true) {
            let (supplied_count, supplied_usage_seq) = supplied_usage.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "replicated allowed invocation event `{}` omitted its usage projection",
                    event.event_id
                ))
            })?;
            let event_usage_seq = event.usage_seq.unwrap_or(event.event_seq);
            if supplied_usage_seq < event_usage_seq
                || (supplied_usage_seq == event_usage_seq
                    && supplied_count != event.invocation_count_after)
            {
                return Err(BudgetStoreError::Invariant(format!(
                    "replicated allowed invocation event `{}` is newer than its supplied usage projection",
                    event.event_id
                )));
            }
        }
        let quota = Self::load_compatibility_invocation_quota_usage(
            transaction,
            &event.capability_id,
            event.grant_index,
        )?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "replicated invocation event `{}` omitted its immutable quota projection",
                event.event_id
            ))
        })?;
        if quota.usage.quota.max_invocations() != expected_maximum {
            return Err(BudgetStoreError::Invariant(format!(
                "replicated invocation event `{}` conflicts with its immutable quota maximum",
                event.event_id
            )));
        }
        Ok(())
    }

    fn upsert_compatibility_invocation_quota_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetInvocationQuotaUsageRecord,
    ) -> Result<(), BudgetStoreError> {
        record.validate_compatibility_projection()?;
        let key = record.usage.quota.key();
        let grant_index = key.grant_index().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "replicated compatibility quota is missing grant_index".to_string(),
            )
        })?;
        Self::reject_composite_managed_grant(transaction, key.owner_id(), grant_index as usize)?;

        let maximum = record.usage.quota.max_invocations();
        let reserved = record.usage.reserved_invocations_after;
        let captured = record.usage.captured_invocations_after;
        let sqlite_seq = sqlite_integer_from_u64(record.seq, "invocation quota usage sequence")?;
        raise_budget_replication_seq_floor(transaction, record.seq)?;

        if let Some(existing) = Self::load_compatibility_invocation_quota_usage(
            transaction,
            key.owner_id(),
            grant_index,
        )? {
            let existing_maximum = existing.usage.quota.max_invocations();
            if existing_maximum != maximum {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` was replicated with a different immutable maximum",
                    key.owner_id()
                )));
            }
            if existing.seq == record.seq
                && (existing.usage.reserved_invocations_after != reserved
                    || existing.usage.captured_invocations_after != captured)
            {
                return Err(BudgetStoreError::Conflict(format!(
                    "invocation quota `{}` reused sequence {} for different counters",
                    key.owner_id(),
                    record.seq
                )));
            }
            if existing.seq >= record.seq {
                return Ok(());
            }
            let updated = transaction.execute(
                r#"
                UPDATE budget_invocation_quota_usage
                SET reserved_invocations = ?4,
                    captured_invocations = ?5,
                    updated_at = ?6,
                    seq = ?7
                WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                  AND max_invocations = ?8
                "#,
                params![
                    key.profile().as_str(),
                    key.owner_id(),
                    i64::from(grant_index),
                    i64::from(reserved),
                    i64::from(captured),
                    record.updated_at,
                    sqlite_seq,
                    i64::from(maximum),
                ],
            )?;
            if updated != 1 {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` disappeared during replication",
                    key.owner_id()
                )));
            }
            return Ok(());
        }

        transaction.execute(
            r#"
            INSERT INTO budget_invocation_quota_usage (
                profile, owner_id, grant_index_key, max_invocations,
                reserved_invocations, captured_invocations, updated_at, seq
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                key.profile().as_str(),
                key.owner_id(),
                i64::from(grant_index),
                i64::from(maximum),
                i64::from(reserved),
                i64::from(captured),
                record.updated_at,
                sqlite_seq,
            ],
        )?;
        Ok(())
    }

    fn validate_compatibility_projection_for_grant(
        transaction: &rusqlite::Transaction<'_>,
        capability_id: &str,
        grant_index: u32,
    ) -> Result<(), BudgetStoreError> {
        let Some(quota) = Self::load_compatibility_invocation_quota_usage(
            transaction,
            capability_id,
            grant_index,
        )?
        else {
            return Ok(());
        };
        let legacy_count = transaction
            .query_row(
                r#"
                SELECT invocation_count
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, i64::from(grant_index)],
                |row| budget_u32_from_row(row, 0, "invocation_count"),
            )
            .optional()?
            .unwrap_or(0);
        if quota.usage.captured_invocations_after != legacy_count {
            return Err(BudgetStoreError::Invariant(format!(
                "legacy grant `{capability_id}` usage diverged from replicated invocation quota"
            )));
        }
        Ok(())
    }

    fn validate_imported_usage_invocation_authority(
        transaction: &rusqlite::Transaction<'_>,
        usage: &BudgetUsageRecord,
        quota_was_supplied: bool,
    ) -> Result<(), BudgetStoreError> {
        let quota = Self::load_compatibility_invocation_quota_usage(
            transaction,
            &usage.capability_id,
            usage.grant_index,
        )?;
        if usage.invocation_count > 0 && !quota_was_supplied {
            return Err(BudgetStoreError::Invariant(format!(
                "replicated usage for grant `{}` omitted its immutable invocation quota",
                usage.capability_id
            )));
        }
        if quota.is_some() {
            Self::validate_compatibility_projection_for_grant(
                transaction,
                &usage.capability_id,
                usage.grant_index,
            )?;
        }
        Ok(())
    }

    fn upsert_usage_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetUsageRecord,
    ) -> Result<(), BudgetStoreError> {
        Self::reject_composite_managed_grant(
            transaction,
            &record.capability_id,
            record.grant_index as usize,
        )?;
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
}
