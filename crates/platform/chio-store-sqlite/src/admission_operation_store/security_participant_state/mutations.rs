//! The actual admission lease owns a monotone native flow mutation.
use super::*;
use chio_kernel::SecurityInvocationContext;
use chio_security_types::ports::{BoundedVec, FlowJoinRequest, FlowStateSnapshot};

#[path = "mutations/command.rs"]
mod command;
use command::Command;

/// Affine, crate-private authority created only inside the verified admission
/// transaction. Inspection, serialized history and raw SQL handles cannot mint
/// it. It authorizes this monotone join, never external execution.
pub(crate) struct NativeFlowJoinAuthority {
    authority: AdmissionIdentifier,
    request: FlowJoinRequest,
}

impl NativeFlowJoinAuthority {
    pub(crate) fn authority(&self) -> &str {
        self.authority.as_str()
    }
    pub(crate) fn request(&self) -> &FlowJoinRequest {
        &self.request
    }
}

pub(super) fn require_request(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    context: &SecurityInvocationContext,
    key: &chio_security_types::ports::FlowStateKey,
) -> Result<
    chio_kernel::admission_operation::RetainedToolAdmissionRequestV1,
    AdmissionOperationStoreError,
> {
    operation.validate()?;
    if operation.state() != AdmissionOperationState::BrokerAttemptRegistered
        || operation.dispatch_commit().is_some()
    {
        return Err(invalid(
            "native flow join requires original pre-budget dispatch preparation",
        ));
    }
    let original = super::super::retained_request::load_retained_request_tx(connection, operation)?
        .ok_or_else(|| invalid("native mutation requires the original retained request"))?;
    original.validate_native_security_context(context)?;
    let context = context.as_v1();
    if &key.tenant_id != context.tenant_id()
        || &key.principal_id != context.principal_id()
        || &key.session_id != context.session_id()
        || &key.lineage_id != context.lineage_root_id()
        || &key.isolation_epoch_id != context.isolation_epoch_id()
    {
        return Err(invalid(
            "native flow key differs from the original security identity",
        ));
    }
    Ok(original)
}

impl SqliteAdmissionOperationStore {
    /// Join native labels under the actual current operation/recovery lease.
    /// The trusted host must select the initialized authority independently of
    /// agent metadata, and bind it at original admission before the first join.
    /// This does not activate dispatch, acquire an egress fence,
    /// consume declassification, or release any imported historical obligation.
    /// One immutable join is allowed per operation. Retries return the recorded
    /// result, not a fresh flow observation or an execution permit.
    pub fn join_security_participant_flow(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        initialized: &SecurityParticipantStateInitialization,
        context: &SecurityInvocationContext,
        request: &FlowJoinRequest,
        trusted_now_unix_ms: u64,
    ) -> Result<FlowStateSnapshot, AdmissionOperationStoreError> {
        self.join_native_command(
            operation,
            lease,
            initialized,
            context,
            Command::Raw(request),
            trusted_now_unix_ms,
        )
        .map(|record| record.result)
    }

    pub(in crate::admission_operation_store) fn join_security_participant_input(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        initialized: &SecurityParticipantStateInitialization,
        context: &SecurityInvocationContext,
        input: &chio_kernel::admission_operation::NativeSecurityInputJoinRequestV1,
        trusted_now_unix_ms: u64,
    ) -> Result<
        chio_kernel::admission_operation::NativeSecurityInputJoinRecordV1,
        AdmissionOperationStoreError,
    > {
        self.join_native_command(
            operation,
            lease,
            initialized,
            context,
            Command::Input(input),
            trusted_now_unix_ms,
        )?
        .input_record(initialized)
    }

    fn join_native_command(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        initialized: &SecurityParticipantStateInitialization,
        context: &SecurityInvocationContext,
        command: Command<'_>,
        trusted_now_unix_ms: u64,
    ) -> Result<history::Record, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(lease.store_fence()))?;
        observed_time(&tx, trusted_now_unix_ms)?;
        verify_participant_recovery_tx(
            &tx,
            &self.serving_owner,
            operation,
            lease,
            trusted_now_unix_ms,
        )?;
        ensure_no_reserved_terminal_stage(&tx, operation.binding().operation_id())?;
        let original = require_request(&tx, operation, context, command.key())?;
        command.validate(operation.binding().operation_id())?;
        // The serving owner verified current rows at open, rejects external
        // connection writes and pins its anchored head here. Every native
        // change is captured below; do not replay history on each command.
        let actual = records::load_metadata(&tx, initialized.authority.as_str())?
            .ok_or_else(|| invalid("native initialization is absent"))?;
        if &actual != initialized || actual.fence.store_uuid != lease.store_fence().store_uuid {
            return Err(invalid(
                "native initialization differs from selected destination history",
            ));
        }
        if let Some(record) = history::load_for_operation(&tx, operation.binding().operation_id())?
        {
            // Flow generation may advance after the original join. Stable
            // context is rechecked above against the retained request.
            if record.authority != actual.authority || !command.matches(&record) {
                return Err(invalid(
                    "native operation cannot replace its authority or command",
                ));
            }
            return Ok(record);
        }
        // Existing context-only journals remain historical data. They cannot
        // acquire a first native mutation without an original authority binding.
        original.validate_native_security_authority(&actual.admission_binding()?)?;
        if original.authority_profile().is_none() {
            return Err(invalid(
                "first native mutation requires an original authority profile",
            ));
        }
        let occupied: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM security_participant_state_transitions
             WHERE security_authority_id = ?1 AND tenant_id = ?2 AND transition_id = ?3)",
                params![
                    actual.authority.as_str(),
                    command.key().tenant_id.as_str(),
                    command.transition_id().as_str()
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if occupied {
            return Err(invalid(
                "native transition belongs to another operation or imported history",
            ));
        }
        let generation: Option<i64> = tx.query_row(
            "SELECT generation FROM security_participant_state_flow_contexts WHERE security_authority_id = ?1
             AND tenant_id = ?2 AND principal_id = ?3 AND lineage_id = ?4 AND session_id = ?5 AND isolation_epoch_id = ?6",
            params![actual.authority.as_str(), command.key().tenant_id.as_str(), command.key().principal_id.as_str(),
                command.key().lineage_id.as_str(), command.key().session_id.as_str(), command.key().isolation_epoch_id.as_str()],
            |row| row.get(0),
        ).optional().map_err(sqlite_error)?;
        if generation.map(u64::try_from).transpose().map_err(invalid)?
            != context.as_v1().flow_state_generation()
        {
            return Err(invalid("native flow observation is stale or absent"));
        }
        let head = history::head(&tx, actual.authority.as_str())?;
        let previous = if head == 1 {
            actual.digest.clone()
        } else {
            history::load(&tx, actual.authority.as_str(), head)?
                .ok_or_else(|| invalid("native mutation head absent"))?
                .digest()?
        };
        let (mut current_rows, mut current_bytes) = history::ordered::latest_totals(&tx, &actual)?;
        // Resolve every inherited label in this same write transaction, before
        // minting the affine mutation owner. No partial snapshot or raw writer
        // escapes. The common mutator still validates epoch and membership.
        let request = command.resolve(&tx, actual.authority.as_str())?;
        // Source/history verification can take time. Recheck the actual lease
        // immediately before enabling writes, using the later trusted time for
        // expiry but retaining the independent observation as historical data.
        let now = observed_time(&tx, trusted_now_unix_ms)?;
        verify_participant_recovery_tx(
            &tx,
            &self.serving_owner,
            operation,
            lease,
            trusted_now_unix_ms,
        )?;
        let authorization = NativeFlowJoinAuthority {
            authority: actual.authority.clone(),
            request: request.clone(),
        };
        let (tx, result, changes) =
            crate::security_state::join_native_flow(tx, authorization).map_err(invalid)?;
        verify_participant_recovery_tx(
            &tx,
            &self.serving_owner,
            operation,
            lease,
            trusted_now_unix_ms,
        )?;
        cutpoint(7)?;
        for change in &changes {
            if let Some(before) = &change.before {
                current_rows = current_rows
                    .checked_sub(1)
                    .ok_or_else(|| invalid("native row count underflow"))?;
                current_bytes = current_bytes
                    .checked_sub(u64::try_from(before.len()).map_err(invalid)?)
                    .ok_or_else(|| invalid("native byte count underflow"))?;
            }
            if let Some(after) = &change.after {
                current_rows = current_rows
                    .checked_add(1)
                    .ok_or_else(|| invalid("native row count overflow"))?;
                current_bytes = current_bytes
                    .checked_add(u64::try_from(after.len()).map_err(invalid)?)
                    .ok_or_else(|| invalid("native byte count overflow"))?;
            }
        }
        let record = history::Record {
            schema: history::format(command.input().is_some()),
            authority: actual.authority.clone(),
            sequence: head
                .checked_add(1)
                .ok_or_else(|| invalid("native mutation sequence overflow"))?,
            initialization: actual.digest.clone(),
            previous,
            operation: operation.to_persisted(),
            lease: history::LeaseHistory::new(lease),
            context: context.clone(),
            input: command.input().cloned(),
            request: request.clone(),
            result: result.clone(),
            observed_at: now,
            decision_at: trusted_now_unix_ms,
            changes: BoundedVec::new(changes).map_err(invalid)?,
            current_rows,
            current_bytes,
        };
        record.validate(&tx)?;
        record.insert(&tx)?;
        history::head(&tx, actual.authority.as_str())?;
        history::ordered::validate_history_bounds(&tx, actual.authority.as_str())?;
        storage::verify_no_orphans(&tx)?;
        cutpoint(8)?;
        self.serving_owner
            .append_global_commit(
                &tx,
                history::MUTATION,
                PROJECTION_KIND,
                actual.authority.as_str(),
                record.sequence,
            )
            .map_err(map_owner_error)?;
        cutpoint(9)?;
        self.commit_write(tx)?;
        if let Err(error) = cutpoint(10) {
            return Err(map_owner_error(
                self.serving_owner.outcome_unknown(error.to_string()),
            ));
        }
        self.sync_after_write(&connection)?;
        cutpoint(11)?;
        Ok(record)
    }
}
