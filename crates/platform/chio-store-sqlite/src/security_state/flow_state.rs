//! Shared flow semantics within the caller-owned security transaction.
//!
//! Domain semantics share a closed legacy/native query catalog. Production
//! mutations require an affine owner. Native inspection cannot activate an
//! imported participant or establish admission-operation custody. The native
//! admission command currently exposes only monotone label joins.

use super::*;

mod egress;
mod egress_history;
mod epochs;
mod generations;
mod input_join;
mod labels;
mod mutations;
#[cfg(test)]
mod tests;
mod transitions;

use super::scoped_sql::{flow as sql, ScopedMutation as FlowMutation, ScopedReader as FlowReader};
use egress::validate_fence;
pub(super) use egress_history::{verify_retained_egress_history, verify_retained_egress_values};
use epochs::{ensure_epoch_for_join, load_isolation_transition, validate_isolation_transition};
use generations::*;
pub(crate) use input_join::{resolve_native_input_join, resolve_native_label_join};
use labels::*;
use transitions::{scoped_record_transition, scoped_transition_status};

pub(crate) fn planned_native_egress_fence(request: &EgressFenceRequest) -> PortResult<EgressFence> {
    egress_history::from_request(request)
}

pub(super) fn verify_native_egress_result(
    connection: &Connection,
    authority: &str,
    command: &super::NativeEgressCommand,
) -> PortResult<()> {
    let fence = command.fence()?;
    let stored = egress_history::RetainedEgressFence::load(
        FlowReader::native(connection, authority),
        &fence.key.tenant_id,
        egress_history::Lookup::Fence(&fence.fence_id),
    )?
    .ok_or_else(PortError::integrity_failure)?;
    let expected_commitment = match command.expected_result()? {
        super::NativeEgressResult::Acquired(_) => None,
        super::NativeEgressResult::Committed(committed) => Some(committed),
    };
    if stored.fence != fence || stored.commitment != expected_commitment {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

/// Read both views in the caller's transaction. Effective inherited labels may
/// exist without an exact context row; native first-join concurrency checks use
/// the latter's presence, not the inherited snapshot's effective generation.
pub(crate) fn observe_native_flow_state(
    transaction: &rusqlite::Transaction<'_>,
    authority: &str,
    key: &FlowStateKey,
) -> PortResult<(Option<FlowStateSnapshot>, Option<u64>)> {
    let reader = FlowReader::native(transaction, authority);
    let stored_context_generation = load_context_generation(reader, key)?;
    let snapshot = load_scoped_flow_snapshot(reader, key)?;
    Ok((snapshot, stored_context_generation))
}

/// Validate the actual post-mutation rows, not only the computed return value.
pub(super) fn verify_native_join_snapshot(
    connection: &Connection,
    authority: &str,
    expected: &FlowStateSnapshot,
) -> PortResult<()> {
    let actual =
        load_scoped_flow_snapshot(FlowReader::native(connection, authority), &expected.key)?;
    if actual.as_ref() != Some(expected) {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

impl FlowStateStore for SqliteSecurityStateStore {
    fn load(&self, key: &FlowStateKey) -> PortResult<Option<FlowStateSnapshot>> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        participant_source::ensure_legacy_writable(&transaction)?;
        let snapshot = load_flow_snapshot(&transaction, key)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn join(&self, request: &FlowJoinRequest) -> PortResult<FlowStateSnapshot> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let (owner, snapshot) = SecurityStateWriteTransaction::new(transaction)?.join(request)?;
        owner.into_transaction().commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn open_isolation_epoch(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<FlowStateSnapshot> {
        validate_isolation_transition(transition)?;
        {
            let mut connection = self.connection()?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .map_err(sqlite_error)?;
            participant_source::ensure_legacy_writable(&transaction)?;
            let replay = load_isolation_transition(FlowReader::legacy(&transaction), transition)?;
            transaction.commit().map_err(sqlite_error)?;
            if let Some(snapshot) = replay {
                return Ok(snapshot);
            }
        }
        // Configured evidence verification may perform external I/O. Never hold
        // the connection or writer lock across that callback. The mutation must
        // recheck the transition and current labels after reacquiring the lock.
        let verified = self.isolation_epoch_verifier.verify(transition)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let (owner, snapshot) = SecurityStateWriteTransaction::new(transaction)?
            .open_isolation_epoch(transition, &verified)?;
        owner.into_transaction().commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn acquire_egress_fence(&self, request: &EgressFenceRequest) -> PortResult<EgressFence> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let (owner, fence) = SecurityStateWriteTransaction::new(transaction)?
            .acquire_egress_fence(request, self.clock.as_ref())?;
        owner.into_transaction().commit().map_err(sqlite_error)?;
        Ok(fence)
    }

    fn validate_egress_fence(&self, fence: &EgressFence) -> PortResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let trusted_now = self.trusted_now_in_transaction(&transaction)?;
        validate_fence(FlowReader::legacy(&transaction), fence, trusted_now)?;
        transaction.commit().map_err(sqlite_error)
    }

    fn commit_egress_fence(
        &self,
        commitment: &EgressFenceCommit,
    ) -> PortResult<CommittedEgressFence> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let (owner, committed) = SecurityStateWriteTransaction::new(transaction)?
            .commit_egress_fence(commitment, self.clock.as_ref())?;
        owner.into_transaction().commit().map_err(sqlite_error)?;
        Ok(committed)
    }
}

pub(super) fn load_flow_snapshot(
    connection: &Connection,
    key: &FlowStateKey,
) -> PortResult<Option<FlowStateSnapshot>> {
    load_scoped_flow_snapshot(FlowReader::legacy(connection), key)
}

impl SecurityStateWriteTransaction<'_> {
    pub(in super::super) fn join(
        self,
        request: &FlowJoinRequest,
    ) -> PortResult<(Self, FlowStateSnapshot)> {
        let snapshot = FlowMutation::legacy(self.transaction()).join(request)?;
        Ok((self, snapshot))
    }

    pub(in super::super) fn open_isolation_epoch(
        self,
        transition: &IsolationEpochTransition,
        verified: &VerifiedIsolationEvidence,
    ) -> PortResult<(Self, FlowStateSnapshot)> {
        let snapshot =
            FlowMutation::legacy(self.transaction()).open_isolation_epoch(transition, verified)?;
        Ok((self, snapshot))
    }

    pub(in super::super) fn acquire_egress_fence(
        self,
        request: &EgressFenceRequest,
        clock: &dyn SecurityStateClock,
    ) -> PortResult<(Self, EgressFence)> {
        let fence = FlowMutation::legacy(self.transaction())
            .acquire_egress_fence(request, || {
                trusted_time_in_transaction(self.transaction(), clock)
            })?;
        Ok((self, fence))
    }

    pub(in super::super) fn commit_egress_fence(
        self,
        commitment: &EgressFenceCommit,
        clock: &dyn SecurityStateClock,
    ) -> PortResult<(Self, CommittedEgressFence)> {
        let committed = FlowMutation::legacy(self.transaction())
            .commit_egress_fence(commitment, || {
                trusted_time_in_transaction(self.transaction(), clock)
            })?;
        Ok((self, committed))
    }
}

/// Read-only semantic verification in addition to the byte-exact initialization
/// fingerprints. An authority identifier selects data, never serving authority.
pub(crate) fn verify_native_flow_state(connection: &Connection, authority: &str) -> PortResult<()> {
    use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId};
    use chio_security_types::PrincipalId;
    let reader = FlowReader::native(connection, authority);
    reader.visit(sql::ALL_CONTEXTS, |row| {
        fn invalid<T>(_: T) -> PortError {
            PortError::integrity_failure()
        }
        let key = FlowStateKey {
            tenant_id: TenantId::new(row.get::<_, String>(0).map_err(sqlite_error)?)
                .map_err(invalid)?,
            principal_id: PrincipalId::new(row.get::<_, String>(1).map_err(sqlite_error)?)
                .map_err(invalid)?,
            lineage_id: LineageId::new(row.get::<_, String>(2).map_err(sqlite_error)?)
                .map_err(invalid)?,
            session_id: SessionId::new(row.get::<_, String>(3).map_err(sqlite_error)?)
                .map_err(invalid)?,
            isolation_epoch_id: IsolationEpochId::new(
                row.get::<_, String>(4).map_err(sqlite_error)?,
            )
            .map_err(invalid)?,
        };
        if row.get::<_, i64>(5).map_err(sqlite_error)? <= 0 {
            return Err(PortError::integrity_failure());
        }
        load_scoped_flow_snapshot(reader, &key)?.ok_or_else(PortError::integrity_failure)?;
        Ok(())
    })?;
    egress_history::verify_scoped_egress_history(reader)
}
