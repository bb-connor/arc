//! Restrict the entire native SQL command, including nested trigger effects.
//! Row capture additionally enforces exact authority, identity and row changes.
use super::*;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

pub(super) struct SqlMutationScope<'connection> {
    connection: &'connection Connection,
    cleared: bool,
}

impl<'connection> SqlMutationScope<'connection> {
    pub(super) fn install(
        connection: &'connection Connection,
        capture: &Arc<Capture>,
    ) -> PortResult<Self> {
        let capture = capture.clone();
        connection
            .authorizer(Some(move |context: AuthContext<'_>| {
                authorize(&capture, context)
            }))
            .map_err(sqlite_error)?;
        Ok(Self {
            connection,
            cleared: false,
        })
    }

    pub(super) fn finish(mut self) -> PortResult<()> {
        self.clear().map_err(sqlite_error)?;
        self.cleared = true;
        Ok(())
    }

    fn clear(&self) -> rusqlite::Result<()> {
        self.connection
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
    }
}

impl Drop for SqlMutationScope<'_> {
    fn drop(&mut self) {
        if !self.cleared {
            // No successful path may ignore a removal error. On failure the
            // outer capture guard disables the retained hook, which denies
            // future work but still permits transaction rollback.
            let _ = self.clear();
        }
    }
}

fn authorize(capture: &Capture, context: AuthContext<'_>) -> Authorization {
    if matches!(
        context.action,
        AuthAction::Transaction {
            operation: TransactionOperation::Rollback
        }
    ) {
        return Authorization::Allow;
    }
    if !capture.enabled.load(Ordering::Acquire) {
        return Authorization::Deny;
    }
    match context.action {
        AuthAction::Select
        | AuthAction::Read { .. }
        | AuthAction::Function { .. }
        | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Insert { table_name } | AuthAction::Update { table_name, .. }
            if context.database_name == Some("main")
                && permits_native_table(&capture.plan, table_name) =>
        {
            Authorization::Allow
        }
        // Deny unknown actions, other-table writes, all deletes, schema/pragma
        // changes, attached databases, savepoints and transaction commitment.
        _ => Authorization::Deny,
    }
}

fn permits_native_table(plan: &CapturePlan, table: &str) -> bool {
    let source = match table {
        "security_participant_state_flow_contexts" => "security_flow_contexts",
        "security_participant_state_flow_sequences" => "security_flow_sequences",
        "security_participant_state_isolation_epochs" => "security_isolation_epochs",
        "security_participant_state_lineage_flow_state" => "security_lineage_flow_state",
        "security_participant_state_principal_flow_state" => "security_principal_flow_state",
        "security_participant_state_session_flow_state" => "security_session_flow_state",
        "security_participant_state_session_memberships" => "security_session_memberships",
        "security_participant_state_transitions" => "security_transitions",
        "security_participant_state_egress_fences" => "security_egress_fences",
        _ => return false,
    };
    plan.permits_table(source)
}
