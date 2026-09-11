//! The actual operation lease owns acquisition and commitment, never a caller
//! marker or imported fence. Historical retry results are not fresh permission.
use super::*;

impl SqliteAdmissionOperationStore {
    #[allow(clippy::too_many_arguments)]
    pub fn acquire_security_participant_egress(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        initialized: &SecurityParticipantStateInitialization,
        context: &SecurityInvocationContext,
        request: &ToolCallRequest,
        plan: &EgressFenceRequest,
        now: u64,
    ) -> Result<EgressFence, AdmissionOperationStoreError> {
        match self.mutate_security_participant_egress(
            operation,
            lease,
            initialized,
            context,
            request,
            NativeEgressCommand::Acquire(plan.clone()),
            now,
        )? {
            NativeEgressResult::Acquired(fence) => Ok(fence),
            NativeEgressResult::Committed(_) => {
                Err(invalid("native egress acquisition result differs"))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_security_participant_egress(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        initialized: &SecurityParticipantStateInitialization,
        context: &SecurityInvocationContext,
        request: &ToolCallRequest,
        commitment: &EgressFenceCommit,
        now: u64,
    ) -> Result<CommittedEgressFence, AdmissionOperationStoreError> {
        match self.mutate_security_participant_egress(
            operation,
            lease,
            initialized,
            context,
            request,
            NativeEgressCommand::Commit(commitment.clone()),
            now,
        )? {
            NativeEgressResult::Committed(fence) => Ok(fence),
            NativeEgressResult::Acquired(_) => {
                Err(invalid("native egress commitment result differs"))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mutate_security_participant_egress(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        initialized: &SecurityParticipantStateInitialization,
        context: &SecurityInvocationContext,
        request: &ToolCallRequest,
        command: NativeEgressCommand,
        decision_at: u64,
    ) -> Result<NativeEgressResult, AdmissionOperationStoreError> {
        let fence = command.fence().map_err(invalid)?;
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(lease.store_fence()))?;
        super::super::observed_time(&tx, decision_at)?;
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, lease, decision_at)?;
        ensure_no_reserved_terminal_stage(&tx, operation.binding().operation_id())?;
        verify_catalog(&tx)?;
        let actual = super::super::records::load_metadata(&tx, initialized.authority.as_str())?
            .ok_or_else(|| invalid("native egress initialization is absent"))?;
        if &actual != initialized || actual.fence.store_uuid != lease.store_fence().store_uuid {
            return Err(invalid(
                "native egress initialization differs from selected destination",
            ));
        }
        let original = contract::require_original(
            &tx,
            operation,
            context,
            &actual.admission_binding()?,
            &fence,
        )?;
        original.validate_request_material(request)?;
        let live_request_hash = contract::live_request_hash(request)?;
        if let Some(existing) =
            load_operation(&tx, operation.binding().operation_id(), command.phase())?
        {
            if existing.authority != actual.authority
                || existing.initialization != actual.digest
                || existing.command != command
                || existing.live_request_hash != live_request_hash
            {
                return Err(invalid("native egress retry replaced its original command"));
            }
            return Ok(existing.result);
        }
        let acquisition_digest = match &command {
            NativeEgressCommand::Acquire(_) => {
                let occupied: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM security_participant_state_egress_fences
                    WHERE security_authority_id = ?1 AND ((tenant_id = ?2 AND request_id = ?3) OR fence_id = ?4))",
                    params![actual.authority.as_str(),fence.key.tenant_id.as_str(),fence.request_id.as_str(),fence.fence_id.as_str()], |row| row.get(0)).map_err(sqlite_error)?;
                if occupied {
                    return Err(invalid(
                        "native egress fence belongs to imported or another operation's history",
                    ));
                }
                None
            }
            NativeEgressCommand::Commit(_) => {
                let acquired = load_operation(&tx, operation.binding().operation_id(), "acquired")?
                    .ok_or_else(|| invalid("native egress commit requires owned acquisition"))?;
                if acquired.authority != actual.authority
                    || acquired.initialization != actual.digest
                    || acquired.command.fence().map_err(invalid)? != fence
                    || acquired.live_request_hash != live_request_hash
                    || acquired.decision_at > decision_at
                {
                    return Err(invalid("native egress commit replaced acquired custody"));
                }
                Some(AdmissionDigest::try_new(
                    "native_egress_acquisition",
                    acquired.digest()?,
                )?)
            }
        };
        let egress_head = head(&tx, actual.authority.as_str())?;
        let previous = if egress_head == 0 {
            actual.digest.clone()
        } else {
            load(&tx, actual.authority.as_str(), egress_head)?
                .ok_or_else(|| invalid("native egress head is absent"))?
                .digest()?
        };
        let (mut current_rows, mut current_bytes) =
            super::super::history::ordered::latest_totals(&tx, &actual)?;
        let before = footprint(&tx)?;
        let observed_at = super::super::observed_time(&tx, decision_at)?;
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, lease, decision_at)?;
        let authority = NativeEgressAuthority {
            authority: actual.authority.clone(),
            command: command.clone(),
        };
        let (tx, result, changes) = crate::security_state::mutate_native_egress(
            tx,
            authority,
            observed_at.max(decision_at),
        )
        .map_err(invalid)?;
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, lease, decision_at)?;
        super::super::cutpoint(12)?;
        // Domain callbacks cannot append initialization or journal records.
        if footprint(&tx)? != before {
            return Err(invalid(
                "native egress domain mutation escaped its journal boundary",
            ));
        }
        for change in &changes {
            if let Some(image) = &change.before {
                current_rows = current_rows
                    .checked_sub(1)
                    .ok_or_else(|| invalid("native row count underflow"))?;
                current_bytes = current_bytes
                    .checked_sub(u64::try_from(image.len()).map_err(invalid)?)
                    .ok_or_else(|| invalid("native byte count underflow"))?;
            }
            if let Some(image) = &change.after {
                current_rows = current_rows
                    .checked_add(1)
                    .ok_or_else(|| invalid("native row count overflow"))?;
                current_bytes = current_bytes
                    .checked_add(u64::try_from(image.len()).map_err(invalid)?)
                    .ok_or_else(|| invalid("native byte count overflow"))?;
            }
        }
        let record = Record {
            schema: Record::format(),
            authority: actual.authority.clone(),
            sequence: egress_head
                .checked_add(1)
                .ok_or_else(|| invalid("native egress sequence overflow"))?,
            initialization: actual.digest.clone(),
            previous,
            operation: operation.to_persisted(),
            lease: super::super::history::LeaseHistory::new(lease),
            context: context.clone(),
            command,
            result: result.clone(),
            live_request_hash,
            acquisition_digest,
            observed_at,
            decision_at,
            changes: BoundedVec::new(changes).map_err(invalid)?,
            current_rows,
            current_bytes,
        };
        record.validate(&tx)?;
        record.insert(&tx)?;
        let expected = (
            before.0,
            before.1,
            before
                .2
                .checked_add(1)
                .ok_or_else(|| invalid("native journal count overflow"))?,
            before.3,
        );
        if head(&tx, actual.authority.as_str())? != record.sequence || footprint(&tx)? != expected {
            return Err(invalid("native egress append introduced other history"));
        }
        super::super::history::ordered::validate_history_bounds(&tx, actual.authority.as_str())?;
        super::super::storage::verify_no_orphans(&tx)?;
        super::super::cutpoint(13)?;
        self.serving_owner
            .append_global_commit(
                &tx,
                record.mutation(),
                PROJECTION,
                actual.authority.as_str(),
                record.sequence,
            )
            .map_err(map_owner_error)?;
        if footprint(&tx)?
            != (
                expected.0,
                expected.1,
                expected.2,
                expected
                    .3
                    .checked_add(1)
                    .ok_or_else(|| invalid("native global count overflow"))?,
            )
        {
            return Err(invalid(
                "native egress global append introduced other history",
            ));
        }
        super::super::cutpoint(14)?;
        self.commit_write(tx)?;
        if let Err(error) = super::super::cutpoint(15) {
            return Err(map_owner_error(
                self.serving_owner.outcome_unknown(error.to_string()),
            ));
        }
        self.sync_after_write(&connection)?;
        super::super::cutpoint(16)?;
        Ok(result)
    }
}

fn footprint(
    connection: &Connection,
) -> Result<(i64, i64, i64, i64), AdmissionOperationStoreError> {
    connection.query_row("SELECT (SELECT COUNT(*) FROM security_participant_state_initializations),
        (SELECT COUNT(*) FROM security_participant_state_mutations), (SELECT COUNT(*) FROM security_participant_egress_events),
        (SELECT COUNT(*) FROM authority_global_commits)", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(sqlite_error)
}
