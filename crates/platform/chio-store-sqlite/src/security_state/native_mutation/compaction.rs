//! Affine deletion of exact, authenticated dead native rows.
//!
//! Only a checkpoint transaction can mint the owner. While it runs, the native
//! trigger callbacks admit one thing: deleting a planned row of this authority
//! from the transition or egress-fence table, without a replacement image.
//! Every planned before-image must be consumed exactly once. Every exit,
//! including errors and panics, restores the connection's denying callbacks
//! and removes the authorizer before the transaction is released.
use super::*;
use crate::admission_operation_store::NativeCompactionAuthority;
use crate::security_state::decode_retained_security_row;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
use rusqlite::types::Value;
use std::collections::BTreeSet;

struct Table {
    source: &'static str,
    native: &'static str,
    identity: &'static str,
    delete: &'static str,
}

const TABLES: [Table; 2] = [
    Table {
        source: "security_transitions",
        native: "security_participant_state_transitions",
        identity: "transition_id",
        delete: "DELETE FROM security_participant_state_transitions
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND transition_id = ?3",
    },
    Table {
        source: "security_egress_fences",
        native: "security_participant_state_egress_fences",
        identity: "fence_id",
        delete: "DELETE FROM security_participant_state_egress_fences
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND fence_id = ?3",
    },
];

fn table(source: &str) -> Option<&'static Table> {
    TABLES.iter().find(|table| table.source == source)
}

struct Compaction {
    authority: String,
    enabled: AtomicBool,
    planned: Mutex<BTreeSet<(String, String)>>,
}

impl Compaction {
    fn scope(&self, context: &Context<'_>) -> rusqlite::Result<&'static Table> {
        if !self.enabled.load(Ordering::Acquire) || context.len() < 3 {
            return Err(denied());
        }
        let table = table(&context.get::<String>(0)?).ok_or_else(denied)?;
        let before: Option<String> = context.get(1)?;
        let after: Option<String> = context.get(2)?;
        if before.as_deref() != Some(self.authority.as_str()) || after.is_some() {
            return Err(denied());
        }
        Ok(table)
    }

    fn record(&self, context: &Context<'_>) -> rusqlite::Result<i64> {
        let table = self.scope(context)?;
        let columns = retained_security_columns(table.source)
            .map_err(|_| denied())?
            .len();
        if context.len() != 3 + columns {
            return Err(denied());
        }
        let values = (3..3 + columns)
            .map(|index| context.get_raw(index))
            .collect::<Vec<_>>();
        let image = String::from_utf8(
            encode_retained_security_values(table.source, &values).map_err(|_| denied())?,
        )
        .map_err(|_| denied())?;
        let mut planned = self.planned.lock().map_err(|_| denied())?;
        if !planned.remove(&(table.source.to_owned(), image)) {
            return Err(denied());
        }
        Ok(1)
    }
}

/// Removes every compaction hook on all exits. A failed restore leaves the
/// owner disabled, so the retained callbacks still deny every native change.
struct Scope<'connection> {
    connection: &'connection Connection,
    compaction: Arc<Compaction>,
    restored: bool,
}

impl<'connection> Scope<'connection> {
    fn install(
        connection: &'connection Connection,
        compaction: Arc<Compaction>,
    ) -> PortResult<Self> {
        let scope = Self {
            connection,
            compaction,
            restored: false,
        };
        let callback = scope.compaction.clone();
        connection
            .create_scalar_function(AUTHORIZE, 3, FunctionFlags::SQLITE_UTF8, move |context| {
                Ok(i64::from(callback.scope(context).is_ok()))
            })
            .map_err(sqlite_error)?;
        let callback = scope.compaction.clone();
        connection
            .create_scalar_function(FUNCTION, -1, FunctionFlags::SQLITE_UTF8, move |context| {
                callback.record(context)
            })
            .map_err(sqlite_error)?;
        let callback = scope.compaction.clone();
        connection
            .authorizer(Some(move |context: AuthContext<'_>| {
                authorize(&callback, context)
            }))
            .map_err(sqlite_error)?;
        Ok(scope)
    }

    fn restore(&self) -> rusqlite::Result<()> {
        self.compaction.enabled.store(false, Ordering::Release);
        self.connection
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
        deny_native_mutations(self.connection)
    }

    fn finish(mut self) -> PortResult<()> {
        self.restored = true;
        self.restore().map_err(sqlite_error)
    }
}

impl Drop for Scope<'_> {
    fn drop(&mut self) {
        if !self.restored {
            // Restoration disables the owner first, so even a failed restore
            // leaves only callbacks that deny every native change.
            let _ = self.restore();
        }
    }
}

fn authorize(compaction: &Compaction, context: AuthContext<'_>) -> Authorization {
    if matches!(
        context.action,
        AuthAction::Transaction {
            operation: TransactionOperation::Rollback
        }
    ) {
        return Authorization::Allow;
    }
    if !compaction.enabled.load(Ordering::Acquire) {
        return Authorization::Deny;
    }
    match context.action {
        AuthAction::Select
        | AuthAction::Read { .. }
        | AuthAction::Function { .. }
        | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Delete { table_name }
            if context.database_name == Some("main")
                && TABLES.iter().any(|table| table.native == table_name) =>
        {
            Authorization::Allow
        }
        // Inserts, updates, other-table deletes, schema and pragma changes,
        // attached databases, savepoints and commitment stay denied.
        _ => Authorization::Deny,
    }
}

fn cell<'a>(table: &Table, values: &'a [Value], column: &str) -> PortResult<&'a Value> {
    let index = retained_security_columns(table.source)
        .map_err(|_| PortError::integrity_failure())?
        .iter()
        .position(|name| *name == column)
        .ok_or_else(PortError::integrity_failure)?;
    values.get(index).ok_or_else(PortError::integrity_failure)
}

fn text<'a>(table: &Table, values: &'a [Value], column: &str) -> PortResult<&'a str> {
    match cell(table, values, column)? {
        Value::Text(value) => Ok(value),
        _ => Err(PortError::integrity_failure()),
    }
}

/// Recheck the row-local half of the dead-row contract. Journal custody was
/// established by the planning query in this same transaction.
fn validate_dead(table: &Table, values: &[Value], compacted_at: i64) -> PortResult<()> {
    let dead = match table.source {
        "security_transitions" => text(table, values, "transition_kind")? == "flow_join",
        "security_egress_fences" => match (
            cell(table, values, "dispatch_commitment_id")?,
            cell(table, values, "committed_at")?,
            cell(table, values, "expires_at")?,
        ) {
            (Value::Text(_), Value::Integer(_), Value::Integer(_)) => true,
            (Value::Null, Value::Null, Value::Integer(expires_at)) => *expires_at <= compacted_at,
            _ => false,
        },
        _ => false,
    };
    if !dead {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

/// Delete exactly the planned rows under the caller's checkpoint transaction.
pub(crate) fn compact_native_rows<'connection>(
    mut transaction: Transaction<'connection>,
    authorization: NativeCompactionAuthority,
) -> PortResult<(Transaction<'connection>, u64)> {
    transaction.set_drop_behavior(DropBehavior::Rollback);
    if transaction
        .transaction_state(Some("main"))
        .map_err(sqlite_error)?
        != TransactionState::Write
    {
        return Err(PortError::invalid_data());
    }
    let compacted_at =
        i64::try_from(authorization.compacted_at()).map_err(|_| PortError::invalid_data())?;
    let mut keys = Vec::with_capacity(authorization.rows().len());
    let mut planned = BTreeSet::new();
    for (source, image) in authorization.rows() {
        let table = table(source).ok_or_else(PortError::integrity_failure)?;
        let values = decode_retained_security_row(table.source, image.as_bytes())
            .map_err(|_| PortError::integrity_failure())?;
        validate_dead(table, &values, compacted_at)?;
        keys.push((
            table,
            text(table, &values, "tenant_id")?.to_owned(),
            text(table, &values, table.identity)?.to_owned(),
        ));
        if !planned.insert(((*source).to_owned(), image.clone())) {
            return Err(PortError::integrity_failure());
        }
    }
    let compaction = Arc::new(Compaction {
        authority: authorization.authority().to_owned(),
        enabled: AtomicBool::new(true),
        planned: Mutex::new(planned),
    });
    let deleted = {
        let scope = Scope::install(&transaction, compaction.clone())?;
        let mut deleted = 0_u64;
        for (table, tenant, identity) in &keys {
            let changed = transaction
                .execute(
                    table.delete,
                    rusqlite::params![compaction.authority.as_str(), tenant, identity],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(PortError::integrity_failure());
            }
            deleted = deleted
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?;
        }
        if !compaction
            .planned
            .lock()
            .map_err(|_| PortError::integrity_failure())?
            .is_empty()
        {
            return Err(PortError::integrity_failure());
        }
        scope.finish()?;
        deleted
    };
    Ok((transaction, deleted))
}
