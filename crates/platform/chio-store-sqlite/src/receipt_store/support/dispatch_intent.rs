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
            sqlite_i64(intent.created_at_unix_ms, "dispatch intent created_at_unix_ms")?,
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
/// transaction. Shared by the bounded and unbounded write paths so both commit
/// through identical statements.
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

/// True if the non-audit `chio_dispatch_intents` journal table exists. A store
/// opened via `open_existing` on a pre-journal database runs no DDL, so a
/// missing table is reported as `false`; callers treat that as zero
/// open/dead-letter intents (an accurate report: a database that never
/// journaled has no orphans).
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
