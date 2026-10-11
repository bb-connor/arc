//! Affine deletion of exact, authenticated dead native rows.
//!
//! Only a checkpoint transaction can mint the owner. While it runs, the native
//! trigger callbacks admit one thing: deleting a planned row of this authority
//! from the transition, egress-fence, session-label, session-membership or
//! flow-context table, without a replacement image. Every planned before-image
//! must be consumed exactly once. Every exit, including errors and panics,
//! restores the connection's denying callbacks and removes the authorizer
//! before the transaction is released.
//!
//! A session leaves as one unit: its label, its membership and every context
//! under any lineage. Its label must be dominated by its principal label and no
//! egress fence may name it, both rechecked here in the same transaction.
use super::*;
use crate::admission_operation_store::NativeCompactionAuthority;
use crate::security_state::decode_retained_security_row;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
use rusqlite::types::Value;
use std::collections::BTreeSet;

struct Table {
    source: &'static str,
    native: &'static str,
    /// Primary-key columns after the authority, in delete parameter order.
    keys: &'static [&'static str],
    delete: &'static str,
}

const SESSION: [&str; 4] = [
    "tenant_id",
    "principal_id",
    "session_id",
    "isolation_epoch_id",
];

const TABLES: [Table; 5] = [
    Table {
        source: "security_transitions",
        native: "security_participant_state_transitions",
        keys: &["tenant_id", "transition_id"],
        delete: "DELETE FROM security_participant_state_transitions
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND transition_id = ?3",
    },
    Table {
        source: "security_egress_fences",
        native: "security_participant_state_egress_fences",
        keys: &["tenant_id", "fence_id"],
        delete: "DELETE FROM security_participant_state_egress_fences
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND fence_id = ?3",
    },
    Table {
        source: "security_session_flow_state",
        native: "security_participant_state_session_flow_state",
        keys: &SESSION,
        delete: "DELETE FROM security_participant_state_session_flow_state
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3
              AND session_id = ?4 AND isolation_epoch_id = ?5",
    },
    Table {
        source: "security_session_memberships",
        native: "security_participant_state_session_memberships",
        keys: &SESSION,
        delete: "DELETE FROM security_participant_state_session_memberships
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3
              AND session_id = ?4 AND isolation_epoch_id = ?5",
    },
    Table {
        source: "security_flow_contexts",
        native: "security_participant_state_flow_contexts",
        keys: &[
            "tenant_id",
            "principal_id",
            "lineage_id",
            "session_id",
            "isolation_epoch_id",
        ],
        delete: "DELETE FROM security_participant_state_flow_contexts
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3
              AND lineage_id = ?4 AND session_id = ?5 AND isolation_epoch_id = ?6",
    },
];

/// Remaining rows that still name a session, and fences that name it.
const SESSION_REFERENCES: &str = "SELECT
    EXISTS(SELECT 1 FROM security_participant_state_session_flow_state
        WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3
          AND session_id = ?4 AND isolation_epoch_id = ?5)
    OR EXISTS(SELECT 1 FROM security_participant_state_session_memberships
        WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3
          AND session_id = ?4 AND isolation_epoch_id = ?5)
    OR EXISTS(SELECT 1 FROM security_participant_state_flow_contexts
        WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3
          AND session_id = ?4 AND isolation_epoch_id = ?5),
    EXISTS(SELECT 1 FROM security_participant_state_egress_fences
        WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3
          AND session_id = ?4 AND isolation_epoch_id = ?5)";

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
/// established by the planning query in this same transaction. Session rows
/// are checked as whole sessions by `validate_sessions`.
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
        "security_session_flow_state"
        | "security_session_memberships"
        | "security_flow_contexts" => true,
        _ => false,
    };
    if !dead {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

type SessionKey = [String; 4];

fn session_key(table: &Table, values: &[Value]) -> PortResult<SessionKey> {
    Ok([
        text(table, values, SESSION[0])?.to_owned(),
        text(table, values, SESSION[1])?.to_owned(),
        text(table, values, SESSION[2])?.to_owned(),
        text(table, values, SESSION[3])?.to_owned(),
    ])
}

fn session_references(
    connection: &Connection,
    authority: &str,
    session: &SessionKey,
) -> PortResult<(bool, bool)> {
    connection
        .query_row(
            SESSION_REFERENCES,
            rusqlite::params![authority, session[0], session[1], session[2], session[3]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)
}

/// Each planned session leaves whole: one label, one membership, and contexts
/// only of planned sessions. Its label adds nothing to its principal label and
/// no egress fence names it.
fn validate_sessions(
    connection: &Connection,
    authority: &str,
    labels: &BTreeSet<SessionKey>,
    members: &BTreeSet<SessionKey>,
    contexts: &BTreeSet<SessionKey>,
) -> PortResult<()> {
    if labels != members || !contexts.is_subset(labels) {
        return Err(PortError::integrity_failure());
    }
    for session in labels {
        let [tenant, principal, id, epoch] = session;
        let dominated = super::super::native_session_dominated(
            connection,
            authority,
            [tenant, principal, id, epoch],
        )?;
        if !dominated || session_references(connection, authority, session)?.1 {
            return Err(PortError::integrity_failure());
        }
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
    let (mut labels, mut members, mut contexts) =
        (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for (source, image) in authorization.rows() {
        let table = table(source).ok_or_else(PortError::integrity_failure)?;
        let values = decode_retained_security_row(table.source, image.as_bytes())
            .map_err(|_| PortError::integrity_failure())?;
        validate_dead(table, &values, compacted_at)?;
        let unique = match table.source {
            "security_session_flow_state" => labels.insert(session_key(table, &values)?),
            "security_session_memberships" => members.insert(session_key(table, &values)?),
            "security_flow_contexts" => {
                contexts.insert(session_key(table, &values)?);
                true
            }
            _ => true,
        };
        let key = table
            .keys
            .iter()
            .map(|column| text(table, &values, column).map(str::to_owned))
            .collect::<PortResult<Vec<_>>>()?;
        keys.push((table, key));
        if !unique || !planned.insert(((*source).to_owned(), image.clone())) {
            return Err(PortError::integrity_failure());
        }
    }
    validate_sessions(
        &transaction,
        authorization.authority(),
        &labels,
        &members,
        &contexts,
    )?;
    let compaction = Arc::new(Compaction {
        authority: authorization.authority().to_owned(),
        enabled: AtomicBool::new(true),
        planned: Mutex::new(planned),
    });
    let deleted = {
        let scope = Scope::install(&transaction, compaction.clone())?;
        let mut deleted = 0_u64;
        for (table, key) in &keys {
            let parameters = std::iter::once(compaction.authority.as_str())
                .chain(key.iter().map(String::as_str));
            let changed = transaction
                .execute(table.delete, rusqlite::params_from_iter(parameters))
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
    // Every context of an evicted session was planned with it.
    for session in &labels {
        if session_references(&transaction, authorization.authority(), session)?.0 {
            return Err(PortError::integrity_failure());
        }
    }
    Ok((transaction, deleted))
}
