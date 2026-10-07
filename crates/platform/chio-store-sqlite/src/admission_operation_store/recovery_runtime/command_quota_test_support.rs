//! Bounded fixtures use the fenced protected writer and real command admission.
//! This module is available only under the existing admission-test-support feature.
use super::*;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

/// Return the exact accounting clone for bounded fixture size/invariance evidence.
/// The clone is never persisted, authorized, or used as runtime workflow state.
pub fn recovery_quota_fixture_finalized_shape(
    record: &RecoveryWorkflowRecordV1,
) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
    storage::fixture_finalized_shape(record)
}

/// An owning clock read with a fixed SQLite instruction budget, not a time override.
#[derive(Debug)]
pub struct RecoveryClockWorkFixtureObservation {
    pub observed_at: Result<u64, AdmissionOperationStoreError>,
    pub sampled_vm_steps: u64,
    pub retained_events: u64,
}

struct ClockWorkFixtureGuard<'connection> {
    connection: &'connection Connection,
    steps: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Drop for ClockWorkFixtureGuard<'_> {
    fn drop(&mut self) {
        let _ = self.connection.progress_handler(0, None::<fn() -> bool>);
    }
}

/// Measures only the actual authority clock queries after owner/fence validation.
/// It observes existing authenticated history without changing data or clocks.
pub fn observe_recovery_quota_fixture_clock_work(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
) -> Result<RecoveryClockWorkFixtureObservation, AdmissionOperationStoreError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    const INTERVAL: i32 = 64;
    const MAX_STEPS: u64 = 4096;
    let mut connection = store.connection()?;
    let tx = store.begin_read(&mut connection)?;
    verify_active_owner(&tx, &store.serving_owner, Some(fence))?;
    let indexed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='recovery_fixture_observed_time')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    let retained_events: i64 = tx
        .query_row(
            "SELECT count(*) FROM admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let retained_events = stored_u64(retained_events, "fixture clock event count")?;
    if indexed || retained_events > 65536 {
        return Err(invariant("clock work fixture history or schema refused"));
    }
    let steps = Arc::new(AtomicU64::new(0));
    let signal = Arc::clone(&steps);
    tx.progress_handler(
        INTERVAL,
        Some(move || {
            signal.fetch_add(INTERVAL as u64, Ordering::Relaxed) + INTERVAL as u64 > MAX_STEPS
        }),
    )
    .map_err(sqlite_error)?;
    let guard = ClockWorkFixtureGuard {
        connection: &tx,
        steps,
    };
    let observed_at = super::super::schema::observe_authority_time(&tx);
    let sampled_vm_steps = guard.steps.load(Ordering::Relaxed);
    drop(guard);
    tx.commit().map_err(sqlite_error)?;
    Ok(RecoveryClockWorkFixtureObservation {
        observed_at,
        sampled_vm_steps,
        retained_events,
    })
}

struct LegacyWorkflowConstruction {
    scope: RecoveryScopeV1,
    workflow: WorkflowId,
    saves: u16,
    commands: u16,
}

thread_local! {
    static LEGACY_WORKFLOW_CONSTRUCTION: RefCell<Option<LegacyWorkflowConstruction>> = const { RefCell::new(None) };
}

/// A single old-format construction, never a production allocation reset.
/// Actual actors, origins, owner/fence checks and protected writes stay active.
pub struct RecoveryLegacyQuotaFixtureScope {
    _thread_bound: PhantomData<Rc<()>>,
}

impl Drop for RecoveryLegacyQuotaFixtureScope {
    fn drop(&mut self) {
        LEGACY_WORKFLOW_CONSTRUCTION.with(|state| *state.borrow_mut() = None);
    }
}

fn reject_existing_quota_history(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key GLOB 'workflow-quota:*')
            OR EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key GLOB 'workflow-quota:*')
            OR EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key GLOB 'workflow-quota:*')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if exists {
        return Err(invariant(
            "legacy quota construction requires no existing reservation history",
        ));
    }
    Ok(())
}

/// Construct one genuine unadmitted ready workflow without the new metadata.
/// This is legacy-format evidence, separate from old executable upgrade proof.
pub fn construct_recovery_quota_fixture_legacy_format(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<RecoveryLegacyQuotaFixtureScope, AdmissionOperationStoreError> {
    let mut connection = store.connection()?;
    let tx = store.begin_read(&mut connection)?;
    verify_active_owner(&tx, &store.serving_owner, Some(fence))?;
    if scope.authority_domain.as_str() != fence.store_uuid
        || raw(&tx, &workflow_key(scope, workflow)?)?.is_some()
    {
        return Err(invariant("legacy quota construction scope refused"));
    }
    deployment_tx(&tx, scope)?;
    reject_existing_quota_history(&tx)?;
    tx.commit().map_err(sqlite_error)?;
    LEGACY_WORKFLOW_CONSTRUCTION.with(|state| {
        let mut state = state.borrow_mut();
        if state.is_some() {
            return Err(invariant("legacy quota construction is already active"));
        }
        *state = Some(LegacyWorkflowConstruction {
            scope: scope.clone(),
            workflow: workflow.clone(),
            saves: 0,
            commands: 0,
        });
        Ok(RecoveryLegacyQuotaFixtureScope {
            _thread_bound: PhantomData,
        })
    })
}

pub(super) fn constructing_legacy_workflow(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
    save: bool,
) -> Result<bool, AdmissionOperationStoreError> {
    LEGACY_WORKFLOW_CONSTRUCTION.with(|state| {
        let mut state = state.borrow_mut();
        let Some(state) = state.as_mut() else {
            return Ok(false);
        };
        if state.scope != *scope || state.workflow != *workflow {
            return Err(invariant(
                "legacy quota construction cannot select another workflow",
            ));
        }
        reject_existing_quota_history(tx)?;
        if save {
            if state.saves >= 128 {
                return Err(invariant("legacy quota construction save bound exhausted"));
            }
            state.saves += 1;
        }
        Ok(true)
    })
}

pub(super) fn retain_legacy_command_identity(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<(), AdmissionOperationStoreError> {
    if !constructing_legacy_workflow(tx, scope, workflow, false)? {
        return Err(invariant(
            "legacy inspection requires active legacy-format construction",
        ));
    }
    LEGACY_WORKFLOW_CONSTRUCTION.with(|state| {
        let mut state = state.borrow_mut();
        let state = state
            .as_mut()
            .ok_or_else(|| invariant("legacy construction is absent"))?;
        if state.commands >= 4096 {
            return Err(invariant(
                "legacy quota construction command bound exhausted",
            ));
        }
        state.commands += 1;
        Ok(())
    })
}

/// A foreign command-kind record whose immutable history is retained by the writer.
pub struct RecoveryQuotaFixtureRecord {
    pub scope: RecoveryScopeV1,
    pub key: String,
    pub payload: Vec<u8>,
}

fn fixture_history_digest(tx: &Transaction<'_>) -> Result<String, AdmissionOperationStoreError> {
    let (record_count, event_count): (i64, i64) = tx
        .query_row(
            "SELECT (SELECT count(*) FROM admission_operation_recovery_records),
                (SELECT count(*) FROM admission_operation_recovery_events)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    if !(0..=65536).contains(&record_count) || !(0..=65536).contains(&event_count) {
        return Err(invariant(
            "recovery quota fixture history exceeds its bound",
        ));
    }
    let mut digest = sha256_hex(b"chio.recovery.quota.fixture.history.v1");
    let mut records = tx
        .prepare(
            "SELECT record_key,scope_key,kind,version,payload,native_namespace,native_request
         FROM admission_operation_recovery_records ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let records = records
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                sha256_hex(&row.get::<_, Vec<u8>>(4)?),
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })
        .map_err(sqlite_error)?;
    for record in records {
        digest = sha256_hex(&encode(&(
            "record",
            &digest,
            record.map_err(sqlite_error)?,
        ))?);
    }
    let mut events = tx.prepare(
        "SELECT sequence,record_key,record_version,record_digest,previous_digest,event_digest,observed_at
         FROM admission_operation_recovery_events ORDER BY sequence",
    ).map_err(sqlite_error)?;
    let events = events
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(sqlite_error)?;
    for event in events {
        digest = sha256_hex(&encode(&("event", &digest, event.map_err(sqlite_error)?))?);
    }
    Ok(digest)
}

pub(super) fn install_fixture_observed_time_index(
    tx: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    let installed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='recovery_fixture_observed_time')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if installed {
        return Err(invariant("recovery quota fixture index is already present"));
    }
    let before = fixture_history_digest(tx)?;
    // The fixture index accelerates the clock's max(observed_at) scan. It does
    // not change quota accounting, protected data or immutable event history.
    tx.execute_batch(
        "CREATE INDEX recovery_fixture_observed_time
         ON admission_operation_recovery_events(observed_at)",
    )
    .map_err(sqlite_error)?;
    if fixture_history_digest(tx)? != before {
        return Err(invariant(
            "recovery quota fixture index changed protected history",
        ));
    }
    Ok(())
}

pub(super) fn restore_fixture_canonical_schema(
    tx: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    let before = fixture_history_digest(tx)?;
    tx.execute_batch("DROP INDEX recovery_fixture_observed_time")
        .map_err(sqlite_error)?;
    if fixture_history_digest(tx)? != before {
        return Err(invariant(
            "recovery quota fixture index removal changed protected history",
        ));
    }
    super::super::schema::verify_admission_operation_invariants(tx)
}

/// Checkpoint through the owner connection while retaining its custody checks.
pub fn checkpoint_recovery_quota_fixture_wal(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    store.commit_write(tx)?;
    let (busy, _, _): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(sqlite_error)?;
    if busy != 0 {
        return Err(invariant("recovery quota fixture checkpoint is busy"));
    }
    store.sync_after_write(&connection)
}

/// Allocate bounded, inert SQLite history through the serving owner's writer.
/// This models retained page pressure without rewriting any native participant.
pub fn grow_recovery_quota_fixture_retained_history(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    minimum_bytes: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    const PAGE_BATCH: u64 = 16 * 1024 * 1024;
    const MAXIMUM_BYTES: u64 = 2 * 1024 * 1024 * 1024 + 64 * 1024 * 1024;
    if !(2 * 1024 * 1024 * 1024 + 1..=MAXIMUM_BYTES).contains(&minimum_bytes) {
        return Err(invariant("retained history fixture exceeds its bound"));
    }
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    let before = fixture_history_digest(&tx)?;
    let commits_before: i64 = tx
        .query_row("SELECT count(*) FROM authority_global_commits", [], |row| {
            row.get(0)
        })
        .map_err(sqlite_error)?;
    store.commit_write(tx)?;
    let path = connection
        .path()
        .ok_or_else(|| invariant("fixture database path is absent"))?;
    let path = std::path::PathBuf::from(path);
    let mut database_bytes = std::fs::metadata(&path)
        .map_err(|_| invariant("fixture database metadata is unavailable"))?
        .len();
    for _ in 0..=132 {
        if database_bytes >= minimum_bytes {
            break;
        }
        let tx = store.begin_write(&mut connection, Some(fence))?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS recovery_fixture_retained_history (
                ordinal INTEGER PRIMARY KEY,
                retained_pages BLOB NOT NULL CHECK(length(retained_pages)=16777216)
            )",
        )
        .map_err(sqlite_error)?;
        let count: i64 = tx
            .query_row(
                "SELECT count(*) FROM recovery_fixture_retained_history",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !(0..132).contains(&count) {
            return Err(invariant("retained history fixture row bound exhausted"));
        }
        tx.execute(
            "INSERT INTO recovery_fixture_retained_history(retained_pages) VALUES (zeroblob(?1))",
            [PAGE_BATCH as i64],
        )
        .map_err(sqlite_error)?;
        store.commit_write(tx)?;
        store.sync_after_write(&connection)?;
        connection
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(sqlite_error)?;
        database_bytes = std::fs::metadata(&path)
            .map_err(|_| invariant("fixture database metadata is unavailable"))?
            .len();
    }
    if database_bytes < minimum_bytes || database_bytes > MAXIMUM_BYTES + PAGE_BATCH {
        return Err(invariant(
            "retained history fixture failed to reach its bounded size",
        ));
    }
    let tx = store.begin_read(&mut connection)?;
    let commits_after: i64 = tx
        .query_row("SELECT count(*) FROM authority_global_commits", [], |row| {
            row.get(0)
        })
        .map_err(sqlite_error)?;
    if fixture_history_digest(&tx)? != before || commits_after != commits_before {
        return Err(invariant(
            "retained history fixture changed protected history",
        ));
    }
    super::super::schema::verify_admission_operation_invariants(&tx)?;
    tx.commit().map_err(sqlite_error)?;
    Ok(database_bytes)
}

/// Grow real uncheckpointed inert pages while an independent reader is pinned.
/// Protected records, events and authority commit metadata remain unchanged.
pub fn grow_recovery_quota_fixture_uncheckpointed_history(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    minimum_bytes: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    const MIB: u64 = 1024 * 1024;
    if !(80 * MIB..=96 * MIB).contains(&minimum_bytes) {
        return Err(invariant("uncheckpointed history fixture bound refused"));
    }
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    let before = fixture_history_digest(&tx)?;
    let commits: i64 = tx
        .query_row("SELECT count(*) FROM authority_global_commits", [], |row| {
            row.get(0)
        })
        .map_err(sqlite_error)?;
    store.commit_write(tx)?;
    let page_size: u32 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(invariant("uncheckpointed fixture page size refused"));
    }
    let mut pressure = 0;
    for _ in 0..6 {
        let tx = store.begin_write(&mut connection, Some(fence))?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS recovery_fixture_uncheckpointed_history (
                ordinal INTEGER PRIMARY KEY,
                retained_pages BLOB NOT NULL CHECK(length(retained_pages)=16777216)
            )",
        )
        .map_err(sqlite_error)?;
        let count: i64 = tx
            .query_row(
                "SELECT count(*) FROM recovery_fixture_uncheckpointed_history",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !(0..6).contains(&count) {
            return Err(invariant("uncheckpointed fixture row bound exhausted"));
        }
        tx.execute("INSERT INTO recovery_fixture_uncheckpointed_history(retained_pages) VALUES(zeroblob(16777216))", []).map_err(sqlite_error)?;
        store.commit_write(tx)?;
        store.sync_after_write(&connection)?;
        let (busy, log, checkpointed): (i64, i64, i64) = connection
            .query_row("PRAGMA wal_checkpoint(NOOP)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(sqlite_error)?;
        if busy != 0 || log < 0 || checkpointed < 0 || checkpointed > log {
            return Err(invariant("uncheckpointed fixture observation refused"));
        }
        pressure = u64::try_from(log - checkpointed)
            .ok()
            .and_then(|frames| {
                frames
                    .checked_mul(u64::from(page_size).checked_add(24)?)
                    .and_then(|bytes| bytes.checked_add(32))
            })
            .ok_or_else(|| invariant("uncheckpointed fixture capacity refused"))?;
        if pressure >= minimum_bytes {
            break;
        }
    }
    if pressure < minimum_bytes || pressure >= 128 * MIB {
        return Err(invariant(
            "uncheckpointed history fixture failed to hold bounded pressure",
        ));
    }
    let tx = store.begin_read(&mut connection)?;
    let after: i64 = tx
        .query_row("SELECT count(*) FROM authority_global_commits", [], |row| {
            row.get(0)
        })
        .map_err(sqlite_error)?;
    if commits != after || fixture_history_digest(&tx)? != before {
        return Err(invariant(
            "uncheckpointed fixture changed protected history",
        ));
    }
    super::super::schema::verify_admission_operation_invariants(&tx)?;
    tx.commit().map_err(sqlite_error)?;
    Ok(pressure)
}

/// Retain a bounded batch in the actual foreign protected-record namespaces.
pub fn retain_recovery_quota_fixture_records(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    records: &[RecoveryQuotaFixtureRecord],
) -> Result<(), AdmissionOperationStoreError> {
    let bytes = records.iter().try_fold(0_usize, |total, record| {
        total.checked_add(record.payload.len())
    });
    if records.len() > 8192 || bytes.is_none_or(|bytes| bytes > 48 * 1024 * 1024) {
        return Err(invariant("recovery quota fixture exceeds its bound"));
    }
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    for record in records {
        if record.scope.authority_domain.as_str() != fence.store_uuid
            || ![
                "semantic-capture:",
                "knowledge-checkpoint:",
                "knowledge-join:",
                "knowledge-pin:",
                "confined-boundary:",
                "product-report:",
                "protected-setup:",
            ]
            .iter()
            .any(|prefix| record.key.starts_with(prefix))
            || raw(&tx, &record.key)?.is_some()
        {
            return Err(invariant("recovery quota fixture identity refused"));
        }
        save(
            &tx,
            &store.serving_owner,
            &record.key,
            &scope_key(&record.scope)?,
            "command",
            &record.payload,
            None,
        )?;
    }
    store.commit_write(tx)?;
    store.sync_after_write(&connection)
}

/// Read real inspection commands through the owning authority reader path.
pub fn apply_recovery_quota_fixture_inspections(
    store: &SqliteAdmissionOperationStore,
    actor: &AuthenticatedRecoveryActor,
    commands: &[RecoveryCommandV1],
    fence: &StoreMutationFence,
    now: u64,
) -> Result<Vec<RecoveryCommandResponseV1>, RecoveryCommandPortError> {
    if actor.permission() != RecoveryPermission::Inspect
        || commands.len() > MAX_RECOVERY_COMMANDS
        || commands.iter().any(|command| {
            !matches!(
                command.command,
                RecoveryCommandBodyV1::InspectWorkflow { .. }
            )
        })
    {
        return Err(invariant("recovery quota fixture command refused").into());
    }
    commands
        .iter()
        .map(|command| store.command(actor, command, None, fence, now))
        .collect()
}

/// Retain exact old-format Inspect tombstones without rewriting their history.
pub fn retain_recovery_quota_fixture_legacy_inspections(
    store: &SqliteAdmissionOperationStore,
    actor: &AuthenticatedRecoveryActor,
    workflow: &WorkflowId,
    count: usize,
    fence: &StoreMutationFence,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if actor.permission() != RecoveryPermission::Inspect || !(1..=4096).contains(&count) {
        return Err(invariant("legacy inspection fixture exceeds its bound"));
    }
    store.recovery_mutation(actor, fence, now, |tx, profile, _now| {
        let record = workflow_tx(tx, actor.scope(), workflow)?;
        verify_preview(actor, profile, &record)?;
        install_fixture_observed_time_index(tx)?;
        for index in 0..count {
            let command_id = CommandId::new(&format!("legacy-status-poll-{index}"))
                .map_err(|_| invariant("legacy inspection fixture identity refused"))?;
            let command = RecoveryCommandV1 {
                schema: RecoveryCommandSchema::V1,
                version: VersionV1,
                command_id: command_id.clone(),
                command: RecoveryCommandBodyV1::InspectWorkflow {
                    workflow_id: workflow.clone(),
                },
            };
            super::super::setup::require_command(tx, actor, &store.serving_owner.fence, &command)?;
            storage::save_legacy_inspection(tx, &store.serving_owner, actor, &record, &command_id)?;
        }
        restore_fixture_canonical_schema(tx)
    })
}

/// Retain bounded, real mutating command identities before native execution.
pub fn apply_recovery_quota_fixture_resumptions(
    store: &SqliteAdmissionOperationStore,
    actor: &AuthenticatedRecoveryActor,
    commands: &[RecoveryCommandV1],
    fence: &StoreMutationFence,
    now: u64,
) -> Result<Vec<RecoveryCommandResponseV1>, RecoveryCommandPortError> {
    if actor.permission() != RecoveryPermission::Resume
        || commands.len() > MAX_RECOVERY_COMMANDS
        || commands.iter().any(|command| {
            !matches!(
                command.command,
                RecoveryCommandBodyV1::ResumeWorkflow { .. }
            )
        })
    {
        return Err(invariant("recovery resumption fixture command refused").into());
    }
    store.recovery_mutation_with_headroom(actor, fence, now, true, |tx, profile, now| {
        install_fixture_observed_time_index(tx)?;
        let result = commands
            .iter()
            .map(|command| {
                commands::apply(tx, &store.serving_owner, actor, command, profile, now, None)
            })
            .collect::<Result<Vec<_>, _>>()?;
        restore_fixture_canonical_schema(tx)?;
        Ok(result)
    })
}

/// Fill the knowledge participant event ceiling through its owning save path.
pub fn fill_recovery_quota_fixture_intake_events(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    scope: &RecoveryScopeV1,
    target: u64,
) -> Result<(), AdmissionOperationStoreError> {
    storage::fill_fixture_intake_events(store, fence, scope, target)
}

/// Fill the knowledge participant byte ceiling with bounded canonical rows.
pub fn fill_recovery_quota_fixture_intake_bytes(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    scope: &RecoveryScopeV1,
    target: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if target > 48 * 1024 * 1024 || scope.authority_domain.as_str() != fence.store_uuid {
        return Err(invariant("recovery quota fixture bytes refused"));
    }
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    install_fixture_observed_time_index(&tx)?;
    let current: i64 = tx
        .query_row(
            "SELECT COALESCE(sum(length(payload)),0) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-*'",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let current = stored_u64(current, "fixture retained bytes")?;
    let scope = scope_key(scope)?;
    let mut remaining = target
        .checked_sub(current)
        .ok_or_else(|| invariant("fixture bytes exceeded"))?;
    let mut index = 0;
    while remaining > 0 {
        let mut bytes = remaining.min(MAX_RECOVERY_RECORD_BYTES as u64);
        if remaining - bytes == 1 {
            bytes -= 1;
        }
        if bytes < 2 {
            return Err(invariant("recovery quota fixture byte remainder refused"));
        }
        let key = format!("knowledge-pin:{scope}:quota-byte-reserve:{index}");
        if raw(&tx, &key)?.is_some() {
            return Err(invariant("recovery quota fixture bytes already retained"));
        }
        let padding = "x".repeat(bytes as usize - 2);
        let payload = encode(&padding)?;
        save(
            &tx,
            &store.serving_owner,
            &key,
            &scope,
            "command",
            &payload,
            None,
        )?;
        remaining -= payload.len() as u64;
        index += 1;
    }
    restore_fixture_canonical_schema(&tx)?;
    store.commit_write(tx)?;
    store.sync_after_write(&connection)
}

/// Version actual already-owned work up to the hard settlement event ceiling.
pub fn fill_recovery_quota_fixture_settlement_events(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
    target: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if target > 65536 || scope.authority_domain.as_str() != fence.store_uuid {
        return Err(invariant(
            "recovery quota fixture settlement events refused",
        ));
    }
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    install_fixture_observed_time_index(&tx)?;
    let current: i64 = tx
        .query_row(
            "SELECT count(*) FROM admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let current = stored_u64(current, "fixture event count")?;
    let mut record = workflow_tx(&tx, scope, workflow)?;
    if current > target
        || (record.admission.is_none() && record.control == WorkflowControlV1::Active)
    {
        return Err(invariant("recovery quota fixture settlement refused"));
    }
    for _ in current..target {
        save_workflow(
            &tx,
            &store.serving_owner,
            &mut record,
            WorkflowWriteClass::Native,
        )?;
    }
    restore_fixture_canonical_schema(&tx)?;
    store.commit_write(tx)?;
    store.sync_after_write(&connection)
}

#[derive(Clone, Debug, Default)]
pub struct RecoveryQuotaFixtureDiagnostic {
    pub command_refusal: Option<String>,
    pub issuance_refusal: Option<String>,
    pub native_capture_refusal: Option<String>,
    pub clock_regression: Option<(u64, i64, i64, Option<u64>)>,
}

struct BoundedDiagnosticText {
    text: String,
    remaining_characters: usize,
}

impl std::fmt::Write for BoundedDiagnosticText {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        for character in value.chars() {
            if self.remaining_characters == 0 {
                return Err(std::fmt::Error);
            }
            self.text.push(character);
            self.remaining_characters -= 1;
        }
        Ok(())
    }
}

fn bounded_refusal_text(error: &dyn std::fmt::Display) -> String {
    let mut output = BoundedDiagnosticText {
        text: String::with_capacity(4096),
        remaining_characters: 1024,
    };
    // A full buffer ends formatting while retaining complete UTF8 characters.
    let _ = std::fmt::write(&mut output, format_args!("{error}"));
    output.text
}

thread_local! {
    static FIXTURE_DIAGNOSTIC: RefCell<Option<RecoveryQuotaFixtureDiagnostic>> =
        const { RefCell::new(None) };
}

/// Observe only an explicitly enabled fixture on the current test thread.
pub struct RecoveryQuotaFixtureDiagnosticScope {
    previous: Option<RecoveryQuotaFixtureDiagnostic>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl RecoveryQuotaFixtureDiagnosticScope {
    pub fn error_text(&self, error: &dyn std::fmt::Display) -> String {
        bounded_refusal_text(error)
    }

    pub fn reset(&self) {
        FIXTURE_DIAGNOSTIC.with(|slot| {
            *slot.borrow_mut() = Some(RecoveryQuotaFixtureDiagnostic::default());
        });
    }

    pub fn snapshot(&self) -> Option<RecoveryQuotaFixtureDiagnostic> {
        FIXTURE_DIAGNOSTIC.with(|slot| slot.borrow().clone())
    }
}

impl Drop for RecoveryQuotaFixtureDiagnosticScope {
    fn drop(&mut self) {
        FIXTURE_DIAGNOSTIC.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

/// No clock, database, command or protected payload is changed by this observer.
pub fn observe_recovery_quota_fixture_errors() -> RecoveryQuotaFixtureDiagnosticScope {
    RecoveryQuotaFixtureDiagnosticScope {
        previous: FIXTURE_DIAGNOSTIC
            .with(|slot| slot.replace(Some(RecoveryQuotaFixtureDiagnostic::default()))),
        _thread_bound: PhantomData,
    }
}

pub(in crate::admission_operation_store) fn record_command_refusal(
    error: &RecoveryCommandPortError,
) {
    FIXTURE_DIAGNOSTIC.with(|slot| {
        if let Some(diagnostic) = slot.borrow_mut().as_mut() {
            // Record only the existing error text, never the command body.
            diagnostic
                .command_refusal
                .get_or_insert_with(|| bounded_refusal_text(error));
        }
    });
}

pub(in crate::admission_operation_store) fn record_issuance_refusal(
    error: &AdmissionOperationStoreError,
) {
    FIXTURE_DIAGNOSTIC.with(|slot| {
        if let Some(diagnostic) = slot.borrow_mut().as_mut() {
            diagnostic
                .issuance_refusal
                .get_or_insert_with(|| bounded_refusal_text(error));
        }
    });
}

pub(in crate::admission_operation_store) fn record_native_capture_refusal(
    error: &AdmissionCaptureError,
) {
    FIXTURE_DIAGNOSTIC.with(|slot| {
        if let Some(diagnostic) = slot.borrow_mut().as_mut() {
            diagnostic
                .native_capture_refusal
                .get_or_insert_with(|| bounded_refusal_text(error));
        }
    });
}

pub(in crate::admission_operation_store) fn record_clock_regression(
    observed: u64,
    high_water: i64,
    recovery_high_water: i64,
) {
    FIXTURE_DIAGNOSTIC.with(|slot| {
        if let Some(diagnostic) = slot.borrow_mut().as_mut() {
            diagnostic.clock_regression.get_or_insert_with(|| {
                (
                    observed,
                    high_water,
                    recovery_high_water,
                    chio_kernel::fixed_runtime_unix_secs_for_current_thread(),
                )
            });
        }
    });
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    struct SegmentedDiagnosticError<'a>(&'a std::cell::Cell<bool>);

    impl std::fmt::Display for SegmentedDiagnosticError<'_> {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(&"🦀".repeat(2048))?;
            self.0.set(true);
            formatter.write_str("tail must remain unformatted")
        }
    }

    #[test]
    fn fixture_observer_streams_bounded_utf8_without_formatting_tail() {
        let formatted_tail = std::cell::Cell::new(false);
        let text = bounded_refusal_text(&SegmentedDiagnosticError(&formatted_tail));
        assert_eq!(text.chars().count(), 1024);
        assert_eq!(text.len(), 4096);
        assert!(text.chars().all(|character| character == '🦀'));
        assert!(!formatted_tail.get());
    }

    #[test]
    fn fixture_observer_retains_bounded_first_refusals_and_exact_clock() {
        let observer = observe_recovery_quota_fixture_errors();
        let first = RecoveryCommandPortError::Store(invariant("x".repeat(4096)));
        record_command_refusal(&first);
        record_command_refusal(&RecoveryCommandPortError::Conflict);
        let issuance = invariant("first issuance refusal");
        record_issuance_refusal(&issuance);
        record_issuance_refusal(&invariant("later issuance refusal"));
        let capture = AdmissionCaptureError::Invariant("x".repeat(4096));
        record_native_capture_refusal(&capture);
        record_native_capture_refusal(&AdmissionCaptureError::Fenced);
        let fixed = chio_kernel::fixed_runtime_unix_secs_for_current_thread();
        record_clock_regression(10, 11, 12);
        record_clock_regression(20, 21, 22);
        let snapshot = observer
            .snapshot()
            .unwrap_or_else(|| panic!("observer is not active"));
        let refusal = snapshot
            .command_refusal
            .unwrap_or_else(|| panic!("command refusal missing"));
        assert_eq!(refusal.chars().count(), 1024);
        assert_eq!(
            refusal,
            first.to_string().chars().take(1024).collect::<String>()
        );
        assert_eq!(snapshot.issuance_refusal, Some(issuance.to_string()));
        assert_eq!(
            snapshot.native_capture_refusal,
            Some(capture.to_string().chars().take(1024).collect())
        );
        assert_eq!(snapshot.clock_regression, Some((10, 11, 12, fixed)));
        observer.reset();
        let snapshot = observer
            .snapshot()
            .unwrap_or_else(|| panic!("observer is not active"));
        assert!(snapshot.command_refusal.is_none());
        assert!(snapshot.issuance_refusal.is_none());
        assert!(snapshot.native_capture_refusal.is_none());
        assert!(snapshot.clock_regression.is_none());
    }

    #[test]
    fn fixture_observer_restores_prior_scope_and_is_inactive_without_guard() {
        assert!(FIXTURE_DIAGNOSTIC.with(|slot| slot.borrow().is_none()));
        let outer = observe_recovery_quota_fixture_errors();
        let refusal = RecoveryCommandPortError::Conflict;
        record_command_refusal(&refusal);
        {
            let inner = observe_recovery_quota_fixture_errors();
            record_command_refusal(&RecoveryCommandPortError::Store(invariant("inner refusal")));
            assert_ne!(
                inner.snapshot().and_then(|value| value.command_refusal),
                Some(refusal.to_string())
            );
        }
        assert_eq!(
            outer.snapshot().and_then(|value| value.command_refusal),
            Some(refusal.to_string())
        );
        drop(outer);
        record_command_refusal(&refusal);
        record_issuance_refusal(&invariant("inactive observer"));
        record_clock_regression(30, 31, 32);
        assert!(FIXTURE_DIAGNOSTIC.with(|slot| slot.borrow().is_none()));
    }
}
