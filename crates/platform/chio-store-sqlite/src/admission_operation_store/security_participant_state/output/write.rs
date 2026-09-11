//! Physical output taint joins under the original finalization lease.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Commit one monotone output join for the exact captured invocation and
    /// resolved evaluation. Retries return history, never fresh permission.
    /// This neither releases egress/credentials nor publishes tool output.
    pub fn join_security_participant_output(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        initialized: &SecurityParticipantStateInitialization,
        intent: &NativeSecurityOutputJoinRequestV1,
        decision_at: u64,
    ) -> Result<NativeSecurityOutputJoinRecordV1, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(lease.store_fence()))?;
        observed_time(&tx, decision_at)?;
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, lease, decision_at)?;
        ensure_no_reserved_terminal_stage(&tx, operation.binding().operation_id())?;
        verify_catalog(&tx)?;
        let actual = super::super::records::load_metadata(&tx, initialized.authority.as_str())?
            .ok_or_else(|| invalid("native output initialization is absent"))?;
        if &actual != initialized || actual.fence.store_uuid != lease.store_fence().store_uuid {
            return Err(invalid(
                "native output initialization changed destination history",
            ));
        }
        contract::require_original(&tx, operation, &actual, intent, true)?;
        if let Some(record) = load_operation(&tx, operation.binding().operation_id())? {
            if record.intent != *intent {
                return Err(invalid("native output retry replaced its original intent"));
            }
            return record.evidence(&actual);
        }
        let (_, generation) = crate::security_state::observe_native_flow_state(
            &tx,
            actual.authority.as_str(),
            intent.key(),
        )
        .map_err(invalid)?;
        if generation != Some(intent.observed_generation()) {
            return Err(invalid("native output flow observation is stale or absent"));
        }
        let occupied: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM security_participant_state_transitions
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND transition_id = ?3)",
                params![
                    actual.authority.as_str(),
                    intent.key().tenant_id.as_str(),
                    intent.transition_id().as_str()
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if occupied {
            return Err(invalid("native output transition belongs to other history"));
        }
        let output_head = head(&tx, actual.authority.as_str())?;
        let previous = if output_head == 0 {
            actual.digest.clone()
        } else {
            load(&tx, actual.authority.as_str(), output_head)?
                .ok_or_else(|| invalid("native output head absent"))?
                .digest()?
        };
        let (mut current_rows, mut current_bytes) =
            super::super::history::ordered::latest_totals(&tx, &actual)?;
        // Read all inherited labels in this same write transaction. A current
        // lineage or principal may be more restrictive than the classified label.
        let request = crate::security_state::resolve_native_label_join(
            &tx,
            actual.authority.as_str(),
            intent.key(),
            intent.output_label(),
            intent.transition_id(),
        )
        .map_err(invalid)?;
        let before = footprint(&tx)?;
        let observed_at = observed_time(&tx, decision_at)?;
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, lease, decision_at)?;
        let authorization = NativeOutputJoinAuthority {
            authority: actual.authority.clone(),
            request: request.clone(),
        };
        let (tx, result, changes) =
            crate::security_state::join_native_output(tx, authorization).map_err(invalid)?;
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, lease, decision_at)?;
        checkpoint(&tx, 17)?;
        if footprint(&tx)? != before {
            return Err(invalid(
                "native output mutation escaped its journal boundary",
            ));
        }
        intent.validate_resolution(&request, &result)?;
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
            sequence: output_head
                .checked_add(1)
                .ok_or_else(|| invalid("native output sequence overflow"))?,
            initialization: actual.digest.clone(),
            previous,
            operation: operation.to_persisted(),
            lease: super::super::history::LeaseHistory::new(lease),
            intent: intent.clone(),
            request,
            result,
            observed_at,
            decision_at,
            changes: BoundedVec::new(changes).map_err(invalid)?,
            current_rows,
            current_bytes,
        };
        record.validate(&tx)?;
        record.insert(&tx)?;
        let mut expected = before;
        expected[3] = expected[3]
            .checked_add(1)
            .ok_or_else(|| invalid("native output count overflow"))?;
        if head(&tx, actual.authority.as_str())? != record.sequence || footprint(&tx)? != expected {
            return Err(invalid("native output append introduced other history"));
        }
        super::super::history::ordered::validate_history_bounds(&tx, actual.authority.as_str())?;
        super::super::storage::verify_no_orphans(&tx)?;
        checkpoint(&tx, 18)?;
        self.serving_owner
            .append_global_commit(
                &tx,
                MUTATION,
                PROJECTION,
                actual.authority.as_str(),
                record.sequence,
            )
            .map_err(map_owner_error)?;
        expected[4] = expected[4]
            .checked_add(1)
            .ok_or_else(|| invalid("native global count overflow"))?;
        if footprint(&tx)? != expected {
            return Err(invalid(
                "native output global append introduced other history",
            ));
        }
        // Expiry is checked again at the physical commit boundary, not renewed
        // merely because policy evaluation or the monotone join succeeded.
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, lease, decision_at)?;
        checkpoint(&tx, 19)?;
        self.commit_write(tx)?;
        if let Err(error) = checkpoint(&connection, 20) {
            return Err(map_owner_error(
                self.serving_owner.outcome_unknown(error.to_string()),
            ));
        }
        self.sync_after_write(&connection)?;
        checkpoint(&connection, 21)?;
        let loaded = load_operation(&connection, operation.binding().operation_id())?
            .ok_or_else(|| invalid("native output physical acknowledgement is absent"))?;
        if loaded.bytes()? != record.bytes()? {
            return Err(invalid("native output physical acknowledgement differs"));
        }
        loaded.evidence(&actual)
    }

    /// Independent anchored readback. No policy is evaluated or lease minted.
    pub fn load_security_participant_output(
        &self,
        operation: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<NativeSecurityOutputJoinRecordV1>, AdmissionOperationStoreError> {
        self.load_native_output_join_record(operation, fence, now)
            .map(|stored| stored.and_then(|(_, history)| history))
    }

    pub(in crate::admission_operation_store) fn load_native_output_join_record(
        &self,
        operation: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Option<NativeSecurityOutputJoinRecordV1>,
        )>,
        AdmissionOperationStoreError,
    > {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        observed_time(&tx, now)?;
        super::super::verify_coverage(&tx).map_err(map_owner_error)?;
        let Some(stored) = load_by_operation_id_tx(&tx, operation)? else {
            return Ok(None);
        };
        stored.verify_decision_time(now)?;
        let history = load_operation(&tx, operation)?
            .map(|record| {
                let initialized =
                    super::super::records::load_metadata(&tx, record.authority.as_str())?
                        .ok_or_else(|| invalid("native output readback lost initialization"))?;
                record.evidence(&initialized)
            })
            .transpose()?;
        Ok(Some((stored.operation, history)))
    }
}

fn footprint(connection: &Connection) -> Result<[i64; 5], AdmissionOperationStoreError> {
    connection.query_row("SELECT (SELECT COUNT(*) FROM security_participant_state_initializations),
        (SELECT COUNT(*) FROM security_participant_state_mutations), (SELECT COUNT(*) FROM security_participant_egress_events),
        (SELECT COUNT(*) FROM security_participant_output_events), (SELECT COUNT(*) FROM authority_global_commits)", [],
        |row| Ok([row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?])).map_err(sqlite_error)
}
