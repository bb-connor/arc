//! Affine native mutations with bounded, lossless row-change evidence.
//!
//! Only the admission store calls this after verifying the actual operation
//! lease. The connection never leaves this module with an enabled callback.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::functions::{Context, FunctionFlags};
use rusqlite::{Connection, DropBehavior, Transaction, TransactionState};
use serde::{Deserialize, Serialize};

use super::scoped_sql::ScopedMutation;
use super::{encode_retained_security_values, retained_security_columns, sqlite_error};
use super::{NativeEgressCommand, NativeEgressResult};
use crate::admission_operation_store::{
    NativeEgressAuthority, NativeFlowJoinAuthority, NativeNoncePreflightJoinAuthority,
    NativeOutputJoinAuthority,
};
use chio_security_types::ports::{FlowJoinRequest, FlowStateSnapshot, PortError, PortResult};

mod row_policy;
mod sql_scope;

const FUNCTION: &str = "chio_native_security_change";
const AUTHORIZE: &str = "chio_native_security_authorize";
const MAX_CHANGES: usize = 4096;
const MAX_BYTES: usize = 8 * 1024 * 1024;

/// The complete table vocabulary for the monotone join journal format.
pub(crate) fn is_native_flow_join_table(table: &str) -> bool {
    matches!(
        table,
        "security_flow_contexts"
            | "security_flow_sequences"
            | "security_isolation_epochs"
            | "security_lineage_flow_state"
            | "security_principal_flow_state"
            | "security_session_flow_state"
            | "security_session_memberships"
            | "security_transitions"
    )
}

/// Historical row images, never a command or fresh mutation authority.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeRowChange {
    pub table: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Default)]
struct Changes {
    rows: Vec<NativeRowChange>,
    bytes: usize,
}

struct Capture {
    authority: String,
    plan: CapturePlan,
    enabled: AtomicBool,
    changes: Mutex<Changes>,
}

// Closed command families. Serialized command data cannot mint either affine
// owner; each owner is created only by the corresponding admission transaction.
enum CapturePlan {
    Join(FlowJoinRequest),
    Egress(NativeEgressCommand),
}

impl CapturePlan {
    fn permits_table(&self, table: &str) -> bool {
        match self {
            Self::Join(_) => is_native_flow_join_table(table),
            Self::Egress(_) => table == "security_egress_fences",
        }
    }

    fn validate(&self, change: &NativeRowChange) -> PortResult<()> {
        match self {
            Self::Join(request) => change.validate_flow_join(request),
            Self::Egress(command) => command.validate_change(change),
        }
    }

    fn max_changes(&self) -> usize {
        match self {
            Self::Join(_) => MAX_CHANGES,
            Self::Egress(_) => 1,
        }
    }
}

fn denied() -> rusqlite::Error {
    rusqlite::Error::UserFunctionError(
        "native security mutation lacks custody or exceeds bounds".into(),
    )
}

pub(crate) fn deny_native_mutations(connection: &Connection) -> rusqlite::Result<()> {
    connection.create_scalar_function(AUTHORIZE, 3, FunctionFlags::SQLITE_UTF8, |_| Ok(0_i64))?;
    connection.create_scalar_function(FUNCTION, -1, FunctionFlags::SQLITE_UTF8, |_| {
        Err::<i64, _>(denied())
    })
}

impl Capture {
    fn scope(&self, context: &Context<'_>) -> rusqlite::Result<String> {
        if !self.enabled.load(Ordering::Acquire) || context.len() < 3 {
            return Err(denied());
        }
        let table: String = context.get(0)?;
        // Each owner selects its closed row policy; a join never gains egress
        // authority, and neither command family can spend declassification.
        if !self.plan.permits_table(&table) {
            return Err(denied());
        }
        let before: Option<String> = context.get(1)?;
        let after: Option<String> = context.get(2)?;
        // A monotone join cannot delete rows, even as a nested trigger effect.
        // Reject before SQL changes state, not only when recovery reads history.
        if after.as_deref() != Some(self.authority.as_str())
            || before.as_ref().is_some_and(|id| id != &self.authority)
        {
            return Err(denied());
        }
        Ok(table)
    }

    fn record(&self, context: &Context<'_>) -> rusqlite::Result<i64> {
        let table = self.scope(context)?;
        let before: Option<String> = context.get(1)?;
        let after: Option<String> = context.get(2)?;
        let columns = retained_security_columns(&table)
            .map_err(|_| denied())?
            .len();
        let images = usize::from(before.is_some()) + usize::from(after.is_some());
        if context.len() != 3 + images * columns {
            return Err(denied());
        }
        let mut offset = 3;
        let mut encode = |present: bool| -> rusqlite::Result<Option<String>> {
            if !present {
                return Ok(None);
            }
            let values = (offset..offset + columns)
                .map(|i| context.get_raw(i))
                .collect::<Vec<_>>();
            offset += columns;
            let bytes = encode_retained_security_values(&table, &values).map_err(|_| denied())?;
            Ok(Some(String::from_utf8(bytes).map_err(|_| denied())?))
        };
        let change = NativeRowChange {
            before: encode(before.is_some())?,
            after: encode(after.is_some())?,
            table,
        };
        self.plan.validate(&change).map_err(|_| denied())?;
        let size = change.before.as_ref().map_or(0, String::len)
            + change.after.as_ref().map_or(0, String::len);
        let mut changes = self.changes.lock().map_err(|_| denied())?;
        let bytes = changes.bytes.checked_add(size).ok_or_else(denied)?;
        if changes.rows.len() >= self.plan.max_changes() || bytes > MAX_BYTES {
            return Err(denied());
        }
        changes.bytes = bytes;
        changes.rows.push(change);
        Ok(1)
    }
}

/// Owns both the transaction and the only enabled row-capture callback.
pub(super) struct NativeFlowOwner<'connection> {
    transaction: Transaction<'connection>,
    authorization: JoinAuthorization,
    capture: Arc<Capture>,
}

enum JoinAuthorization {
    Input(NativeFlowJoinAuthority),
    Output(NativeOutputJoinAuthority),
    NoncePreflight(NativeNoncePreflightJoinAuthority),
}

impl JoinAuthorization {
    fn authority(&self) -> &str {
        match self {
            Self::Input(owner) => owner.authority(),
            Self::Output(owner) => owner.authority(),
            Self::NoncePreflight(owner) => owner.authority(),
        }
    }
    fn request(&self) -> &FlowJoinRequest {
        match self {
            Self::Input(owner) => owner.request(),
            Self::Output(owner) => owner.request(),
            Self::NoncePreflight(owner) => owner.request(),
        }
    }
}

impl NativeFlowOwner<'_> {
    pub(super) fn transaction(&self) -> &Transaction<'_> {
        &self.transaction
    }

    pub(super) fn authority(&self) -> &str {
        self.authorization.authority()
    }
}

// A separate guard allows successful transfer of the owned transaction without
// unsafe extraction or an Option<Transaction> state. Panic and error paths
// disable authority before the transaction rolls back.
struct DisableCapture(Arc<Capture>);

impl Drop for DisableCapture {
    fn drop(&mut self) {
        self.0.enabled.store(false, Ordering::Release);
        let mut changes = match self.0.changes.lock() {
            Ok(changes) => changes,
            Err(poisoned) => poisoned.into_inner(),
        };
        // SQLite retains the disabled callback until the next command. Do not
        // retain rolled-back private row images in that closure.
        changes.rows.clear();
        changes.bytes = 0;
    }
}

pub(crate) fn join_native_flow<'connection>(
    transaction: Transaction<'connection>,
    authorization: NativeFlowJoinAuthority,
) -> PortResult<(
    Transaction<'connection>,
    FlowStateSnapshot,
    Vec<NativeRowChange>,
)> {
    join_native(transaction, JoinAuthorization::Input(authorization))
}

pub(crate) fn join_native_output<'connection>(
    transaction: Transaction<'connection>,
    authorization: NativeOutputJoinAuthority,
) -> PortResult<(
    Transaction<'connection>,
    FlowStateSnapshot,
    Vec<NativeRowChange>,
)> {
    join_native(transaction, JoinAuthorization::Output(authorization))
}

pub(crate) fn join_native_nonce_preflight<'connection>(
    transaction: Transaction<'connection>,
    authorization: NativeNoncePreflightJoinAuthority,
) -> PortResult<(
    Transaction<'connection>,
    FlowStateSnapshot,
    Vec<NativeRowChange>,
)> {
    join_native(
        transaction,
        JoinAuthorization::NoncePreflight(authorization),
    )
}

fn join_native<'connection>(
    mut transaction: Transaction<'connection>,
    authorization: JoinAuthorization,
) -> PortResult<(
    Transaction<'connection>,
    FlowStateSnapshot,
    Vec<NativeRowChange>,
)> {
    transaction.set_drop_behavior(DropBehavior::Rollback);
    if transaction
        .transaction_state(Some("main"))
        .map_err(sqlite_error)?
        != TransactionState::Write
    {
        return Err(PortError::invalid_data());
    }
    let capture = Arc::new(Capture {
        authority: authorization.authority().to_owned(),
        plan: CapturePlan::Join(authorization.request().clone()),
        enabled: AtomicBool::new(true),
        changes: Mutex::new(Changes::default()),
    });
    let owner = NativeFlowOwner {
        transaction,
        authorization,
        capture,
    };
    let disable = DisableCapture(owner.capture.clone());
    install_capture(&owner.transaction, &owner.capture)?;
    let sql_scope = sql_scope::SqlMutationScope::install(&owner.transaction, &owner.capture)?;
    let result = ScopedMutation::native(&owner).join(owner.authorization.request())?;
    super::flow_state::verify_native_join_snapshot(
        owner.transaction(),
        owner.authority(),
        &result,
    )?;
    let rows = std::mem::take(
        &mut owner
            .capture
            .changes
            .lock()
            .map_err(|_| PortError::integrity_failure())?
            .rows,
    );
    sql_scope.finish()?;
    drop(disable);
    Ok((owner.transaction, result, rows))
}

fn install_capture(connection: &Connection, capture: &Arc<Capture>) -> PortResult<()> {
    let callback = capture.clone();
    connection
        .create_scalar_function(AUTHORIZE, 3, FunctionFlags::SQLITE_UTF8, move |context| {
            Ok(i64::from(callback.scope(context).is_ok()))
        })
        .map_err(sqlite_error)?;
    let callback = capture.clone();
    connection
        .create_scalar_function(FUNCTION, -1, FunctionFlags::SQLITE_UTF8, move |context| {
            callback.record(context)
        })
        .map_err(sqlite_error)?;
    Ok(())
}

/// Egress-only affine owner. It cannot be substituted for a flow-join owner.
pub(super) struct NativeEgressOwner<'connection> {
    transaction: Transaction<'connection>,
    authorization: NativeEgressAuthority,
    capture: Arc<Capture>,
}

impl NativeEgressOwner<'_> {
    pub(super) fn transaction(&self) -> &Transaction<'_> {
        &self.transaction
    }
    pub(super) fn authority(&self) -> &str {
        self.authorization.authority()
    }
}

pub(crate) fn mutate_native_egress<'connection>(
    mut transaction: Transaction<'connection>,
    authorization: NativeEgressAuthority,
    trusted_now: u64,
) -> PortResult<(
    Transaction<'connection>,
    NativeEgressResult,
    Vec<NativeRowChange>,
)> {
    transaction.set_drop_behavior(DropBehavior::Rollback);
    if transaction
        .transaction_state(Some("main"))
        .map_err(sqlite_error)?
        != TransactionState::Write
    {
        return Err(PortError::invalid_data());
    }
    let capture = Arc::new(Capture {
        authority: authorization.authority().into(),
        plan: CapturePlan::Egress(authorization.command().clone()),
        enabled: AtomicBool::new(true),
        changes: Mutex::new(Changes::default()),
    });
    let owner = NativeEgressOwner {
        transaction,
        authorization,
        capture,
    };
    let disable = DisableCapture(owner.capture.clone());
    install_capture(&owner.transaction, &owner.capture)?;
    let sql_scope = sql_scope::SqlMutationScope::install(&owner.transaction, &owner.capture)?;
    let scoped = ScopedMutation::native_egress(&owner);
    let result = match owner.authorization.command() {
        NativeEgressCommand::Acquire(plan) => {
            NativeEgressResult::Acquired(scoped.acquire_egress_fence(plan, || Ok(trusted_now))?)
        }
        NativeEgressCommand::Commit(commitment) => NativeEgressResult::Committed(
            scoped.commit_egress_fence(commitment, || Ok(trusted_now))?,
        ),
    };
    super::flow_state::verify_native_egress_result(
        owner.transaction(),
        owner.authority(),
        owner.authorization.command(),
    )?;
    let rows = std::mem::take(
        &mut owner
            .capture
            .changes
            .lock()
            .map_err(|_| PortError::integrity_failure())?
            .rows,
    );
    if rows.len() != 1 || result != owner.authorization.command().expected_result()? {
        return Err(PortError::integrity_failure());
    }
    sql_scope.finish()?;
    drop(disable);
    Ok((owner.transaction, result, rows))
}
