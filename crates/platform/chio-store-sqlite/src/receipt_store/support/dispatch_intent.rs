use super::*;

use chio_kernel::receipt_store::{DispatchIntentRecord, SideEffectClass};

/// Column string for a side-effect class. The inverse mapping in
/// `select_open_dispatch_intents` treats any unknown string as side-effecting
/// (fail-safe: an unrecognized class is never demoted to read-only).
fn side_effect_class_str(class: SideEffectClass) -> &'static str {
    match class {
        SideEffectClass::ReadOnly => "read_only",
        SideEffectClass::SideEffecting => "side_effecting",
        SideEffectClass::Monetary => "monetary",
    }
}

/// Insert a dispatch intent. `request_id` is the primary key: a second insert
/// for the same id collides and is rejected fail-closed rather than
/// duplicating an effect record.
pub(crate) fn insert_dispatch_intent_tx(
    tx: &rusqlite::Transaction<'_>,
    intent: &DispatchIntentRecord,
) -> Result<(), ReceiptStoreError> {
    let changed = tx.execute(
        "INSERT INTO chio_dispatch_intents (
            request_id, capability_id, tool_server, tool_name, parameter_hash,
            side_effect_class, monetary, rail, rail_authorization_id, tenant_id,
            created_at_unix_ms, state
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'open')
        ON CONFLICT(request_id) DO NOTHING",
        rusqlite::params![
            intent.request_id.as_str(),
            intent.capability_id.as_str(),
            intent.tool_server.as_str(),
            intent.tool_name.as_str(),
            intent.parameter_hash.as_str(),
            side_effect_class_str(intent.side_effect_class),
            i64::from(intent.monetary),
            intent.rail.as_deref(),
            intent.rail_authorization_id.as_deref(),
            intent.tenant_id.as_deref(),
            sqlite_i64(
                intent.created_at_unix_ms,
                "dispatch intent created_at_unix_ms"
            )?,
        ],
    )?;
    if changed == 0 {
        return Err(ReceiptStoreError::Conflict(format!(
            "dispatch intent for request `{}` already exists",
            intent.request_id
        )));
    }
    Ok(())
}

/// Writer job that durably inserts one dispatch intent in its own immediate
/// transaction. Used by the unbounded write path.
pub(crate) fn dispatch_intent_insert_job(
    intent: &DispatchIntentRecord,
) -> impl FnOnce(&mut SqliteStoreConnection) -> Result<(), ReceiptStoreError> + Send + 'static {
    let intent = intent.clone();
    move |connection| {
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        insert_dispatch_intent_tx(&tx, &intent)?;
        tx.commit()?;
        Ok(())
    }
}

/// Bounded-path variant of [`dispatch_intent_insert_job`]: the caller marks
/// `abandoned` when its response wait times out, and the job refuses to
/// commit once marked. Without the marker, an insert queued behind a slow
/// (but alive) writer could land AFTER the caller already denied before
/// dispatch, and the stale row would dead-letter at the next boot as a false
/// orphan for a call that never executed. The marker is checked both before
/// the transaction (cheap skip) and again immediately before commit, so the
/// unguarded window is only the commit itself; a write racing that window is
/// honored by the caller instead of reported as a timeout.
pub(crate) fn dispatch_intent_insert_job_unless_abandoned(
    intent: &DispatchIntentRecord,
    abandoned: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> impl FnOnce(&mut SqliteStoreConnection) -> Result<(), ReceiptStoreError> + Send + 'static {
    let intent = intent.clone();
    move |connection| {
        let abandoned_error = |request_id: &str| {
            ReceiptStoreError::Conflict(format!(
                "dispatch intent write for request `{request_id}` was abandoned by its \
                 timed-out caller; refusing to land a stale intent"
            ))
        };
        if abandoned.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(abandoned_error(&intent.request_id));
        }
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        insert_dispatch_intent_tx(&tx, &intent)?;
        if abandoned.load(std::sync::atomic::Ordering::SeqCst) {
            // Dropping the transaction rolls the insert back.
            return Err(abandoned_error(&intent.request_id));
        }
        tx.commit()?;
        Ok(())
    }
}

/// Writer job that binds a rail authorization id to one open intent in its
/// own immediate transaction. Shared by the bounded and unbounded paths.
pub(crate) fn dispatch_intent_rail_ref_job(
    request_id: &str,
    rail_authorization_id: &str,
) -> impl FnOnce(&mut SqliteStoreConnection) -> Result<(), ReceiptStoreError> + Send + 'static {
    let request_id = request_id.to_string();
    let rail_authorization_id = rail_authorization_id.to_string();
    move |connection| {
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        attach_dispatch_intent_rail_ref_tx(&tx, &request_id, &rail_authorization_id)?;
        tx.commit()?;
        Ok(())
    }
}

/// Attach a rail authorization id to an open monetary intent (best-effort).
/// Zero rows changed (already consumed, or never written) is `NotFound`.
pub(crate) fn attach_dispatch_intent_rail_ref_tx(
    tx: &rusqlite::Transaction<'_>,
    request_id: &str,
    rail_authorization_id: &str,
) -> Result<(), ReceiptStoreError> {
    let changed = tx.execute(
        "UPDATE chio_dispatch_intents SET rail_authorization_id = ?2 \
         WHERE request_id = ?1 AND state = 'open'",
        rusqlite::params![request_id, rail_authorization_id],
    )?;
    if changed == 0 {
        return Err(ReceiptStoreError::NotFound(format!(
            "open dispatch intent for request `{request_id}` not found for rail-ref attach"
        )));
    }
    Ok(())
}

/// Delete the intent matching `key` inside the receipt-append transaction.
/// Guarded on `request_id` + `parameter_hash` (+ `tenant_id`): a mismatch or
/// missing row returns `Conflict` from inside the transaction, aborting the
/// whole commit (no partial state). The `parameter_hash` guard proves the
/// consumed intent matches the exact call the receipt attests.
pub(crate) fn finalize_dispatch_intent_tx(
    tx: &rusqlite::Transaction<'_>,
    key: &chio_kernel::receipt_store::DispatchIntentKey,
) -> Result<(), ReceiptStoreError> {
    let changed = tx.execute(
        "DELETE FROM chio_dispatch_intents \
         WHERE request_id = ?1 AND parameter_hash = ?2 \
           AND ((tenant_id IS NULL AND ?3 IS NULL) OR tenant_id = ?3)",
        rusqlite::params![
            key.request_id.as_str(),
            key.parameter_hash.as_str(),
            key.tenant_id.as_deref(),
        ],
    )?;
    if changed == 0 {
        return Err(ReceiptStoreError::Conflict(format!(
            "dispatch intent for request `{}` not found with matching parameter_hash; \
             refusing to commit the receipt",
            key.request_id
        )));
    }
    Ok(())
}

/// Writer job that deletes one open intent in its own immediate transaction,
/// for an evaluation that exits without dispatching (no effect ran, no
/// terminal receipt will consume the row).
pub(crate) fn dispatch_intent_clear_job(
    key: &chio_kernel::receipt_store::DispatchIntentKey,
) -> impl FnOnce(&mut SqliteStoreConnection) -> Result<(), ReceiptStoreError> + Send + 'static {
    let key = key.clone();
    move |connection| {
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        clear_dispatch_intent_tx(&tx, &key)?;
        tx.commit()?;
        Ok(())
    }
}

/// Delete the open intent matching `key` for a call that provably never
/// dispatched. Guarded exactly like the consuming delete (request id,
/// parameter hash, tenant) plus the open state; zero rows changed is
/// `NotFound` so the caller logs the anomaly instead of assuming the row is
/// gone.
pub(crate) fn clear_dispatch_intent_tx(
    tx: &rusqlite::Transaction<'_>,
    key: &chio_kernel::receipt_store::DispatchIntentKey,
) -> Result<(), ReceiptStoreError> {
    let changed = tx.execute(
        "DELETE FROM chio_dispatch_intents \
         WHERE request_id = ?1 AND parameter_hash = ?2 \
           AND ((tenant_id IS NULL AND ?3 IS NULL) OR tenant_id = ?3) \
           AND state = 'open'",
        rusqlite::params![
            key.request_id.as_str(),
            key.parameter_hash.as_str(),
            key.tenant_id.as_deref(),
        ],
    )?;
    if changed == 0 {
        return Err(ReceiptStoreError::NotFound(format!(
            "open dispatch intent for request `{}` not found with matching parameter_hash",
            key.request_id
        )));
    }
    Ok(())
}

/// Load every open intent for boot reconciliation, oldest first. A missing
/// table (a pre-journal database sampled over a read-only connection, which
/// runs no migration) reports no open intents.
pub(crate) fn select_open_dispatch_intents(
    connection: &rusqlite::Connection,
) -> Result<Vec<DispatchIntentRecord>, ReceiptStoreError> {
    if !dispatch_intents_table_exists(connection)? {
        return Ok(Vec::new());
    }
    let mut statement = connection.prepare(
        "SELECT request_id, capability_id, tool_server, tool_name, parameter_hash, \
                side_effect_class, monetary, rail, rail_authorization_id, tenant_id, \
                created_at_unix_ms \
         FROM chio_dispatch_intents WHERE state = 'open' ORDER BY created_at_unix_ms",
    )?;
    let rows = statement.query_map([], |row| {
        let class_raw: String = row.get(5)?;
        let side_effect_class = match class_raw.as_str() {
            "read_only" => SideEffectClass::ReadOnly,
            "monetary" => SideEffectClass::Monetary,
            // Fail-safe: an unrecognized class string is treated as
            // side-effecting, never demoted to read-only.
            _ => SideEffectClass::SideEffecting,
        };
        Ok(DispatchIntentRecord {
            request_id: row.get(0)?,
            capability_id: row.get(1)?,
            tool_server: row.get(2)?,
            tool_name: row.get(3)?,
            parameter_hash: row.get(4)?,
            side_effect_class,
            monetary: row.get::<_, i64>(6)? != 0,
            rail: row.get(7)?,
            rail_authorization_id: row.get(8)?,
            tenant_id: row.get(9)?,
            created_at_unix_ms: row.get::<_, i64>(10)?.max(0) as u64,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Mark an orphaned intent as a durable, operator-visible dead-letter
/// incident, recording the reconciler's outcome annotation.
pub(crate) fn dead_letter_dispatch_intent_tx(
    tx: &rusqlite::Transaction<'_>,
    request_id: &str,
    detail: &str,
) -> Result<(), ReceiptStoreError> {
    tx.execute(
        "UPDATE chio_dispatch_intents SET state = 'dead_letter', resolution_detail = ?2 \
         WHERE request_id = ?1 AND state = 'open'",
        rusqlite::params![request_id, detail],
    )?;
    Ok(())
}

/// Mark an orphaned monetary intent whose outcome the reconciler PROVED
/// against the rail as terminally reconciled. Distinct from a dead letter:
/// the outcome is known, so the row must not count as an outcome-unknown
/// incident or flip store health; the annotation preserves the rail
/// reference the proof came from.
pub(crate) fn reconcile_dispatch_intent_tx(
    tx: &rusqlite::Transaction<'_>,
    request_id: &str,
    detail: &str,
) -> Result<(), ReceiptStoreError> {
    tx.execute(
        "UPDATE chio_dispatch_intents SET state = 'reconciled', resolution_detail = ?2 \
         WHERE request_id = ?1 AND state = 'open'",
        rusqlite::params![request_id, detail],
    )?;
    Ok(())
}

/// Count of open (in-flight or unreconciled) dispatch intents, tolerant of a
/// missing table on a pre-journal database.
pub(crate) fn open_dispatch_intent_count_query(
    connection: &rusqlite::Connection,
) -> Result<u64, ReceiptStoreError> {
    dispatch_intent_count_by_state(connection, "open")
}

/// Count of dead-letter (orphaned, outcome-unknown) dispatch intents,
/// tolerant of a missing table on a pre-journal database.
pub(crate) fn dead_letter_dispatch_intent_count_query(
    connection: &rusqlite::Connection,
) -> Result<u64, ReceiptStoreError> {
    dispatch_intent_count_by_state(connection, "dead_letter")
}

fn dispatch_intent_count_by_state(
    connection: &rusqlite::Connection,
    state: &str,
) -> Result<u64, ReceiptStoreError> {
    if !dispatch_intents_table_exists(connection)? {
        return Ok(0);
    }
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_dispatch_intents WHERE state = ?1",
        rusqlite::params![state],
        |row| row.get(0),
    )?;
    Ok(count.max(0) as u64)
}

/// True if the non-audit `chio_dispatch_intents` journal table exists. Every
/// read-write open migrates the table into place and stamps the journal
/// schema revision, but the read-only health sampler may still observe a
/// pre-journal database; it reports a missing table as `false` and callers
/// treat that as zero open/dead-letter intents (an accurate report: a
/// database that never journaled has no orphans).
pub(crate) fn dispatch_intents_table_exists(
    connection: &rusqlite::Connection,
) -> Result<bool, ReceiptStoreError> {
    let name: Option<String> = connection
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'chio_dispatch_intents'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(name.is_some())
}
