//! Physical preflight taint joins under the original Prepared operation lease.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Commit one monotone input join before issuing an execution nonce. Retries return history, never fresh permission.
    /// This neither releases egress/credentials nor publishes tool output.
    pub fn join_security_participant_nonce_preflight(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        initialized: &SecurityParticipantStateInitialization,
        context: &chio_kernel::SecurityInvocationContext,
        intent: &NativeSecurityNoncePreflightJoinRequestV1,
        decision_at: u64,
    ) -> Result<NativeSecurityNoncePreflightJoinRecordV1, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(lease.store_fence()))?;
        observed_time(&tx, decision_at)?;
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, lease, decision_at)?;
        ensure_no_reserved_terminal_stage(&tx, operation.binding().operation_id())?;
        verify_catalog(&tx)?;
        let actual = super::super::records::load_metadata(&tx, initialized.authority.as_str())?
            .ok_or_else(|| invalid("native nonce preflight initialization is absent"))?;
        if &actual != initialized || actual.fence.store_uuid != lease.store_fence().store_uuid {
            return Err(invalid(
                "native nonce preflight initialization changed destination history",
            ));
        }
        contract::require_original(&tx, operation, &actual, context, intent)?;
        if let Some(record) = load_operation(&tx, operation.binding().operation_id())? {
            if record.intent != *intent || record.context != *context {
                return Err(invalid(
                    "native nonce preflight retry replaced its original intent",
                ));
            }
            return record.evidence(&actual);
        }
        let (_, generation) = crate::security_state::observe_native_flow_state(
            &tx,
            actual.authority.as_str(),
            intent.key(),
        )
        .map_err(invalid)?;
        if generation != context.as_v1().flow_state_generation() {
            return Err(invalid(
                "native nonce preflight flow observation is stale or absent",
            ));
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
            return Err(invalid(
                "native nonce preflight transition belongs to other history",
            ));
        }
        let mut segment = super::super::history::segments::SegmentSnapshot::capture(&tx, &actual)?;
        let nonce_preflight_head =
            segment.head(&tx, super::super::history::segments::Family::NoncePreflight)?;
        let previous = if nonce_preflight_head == 0 {
            actual.digest.clone()
        } else {
            load(&tx, actual.authority.as_str(), nonce_preflight_head)?
                .ok_or_else(|| invalid("native nonce preflight head absent"))?
                .digest()?
        };
        let (mut current_rows, mut current_bytes) =
            super::super::history::ordered::latest_totals(&tx, &segment)?;
        // Read all inherited labels in this same write transaction. A current
        // lineage or principal may be more restrictive than the classified label.
        let request = crate::security_state::resolve_native_label_join(
            &tx,
            actual.authority.as_str(),
            intent.key(),
            intent.input_label(),
            intent.transition_id(),
        )
        .map_err(invalid)?;
        let observed_at = observed_time(&tx, decision_at)?;
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, lease, decision_at)?;
        let authorization = NativeNoncePreflightJoinAuthority {
            authority: actual.authority.clone(),
            request: request.clone(),
        };
        let (tx, result, changes) =
            crate::security_state::join_native_nonce_preflight(tx, authorization)
                .map_err(invalid)?;
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, lease, decision_at)?;
        checkpoint(&tx, 22)?;
        if !segment.unchanged(&tx)? {
            return Err(invalid(
                "native nonce preflight mutation escaped its journal boundary",
            ));
        }
        intent.validate_resolution(operation.binding().operation_id(), &request, &result)?;
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
            sequence: nonce_preflight_head
                .checked_add(1)
                .ok_or_else(|| invalid("native nonce preflight sequence overflow"))?,
            initialization: actual.digest.clone(),
            previous,
            operation: operation.to_persisted(),
            lease: super::super::history::LeaseHistory::new(lease),
            context: context.clone(),
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
        super::super::storage::require_tenant_live(
            &tx,
            actual.authority.as_str(),
            intent.key().tenant_id.as_str(),
        )?;
        crate::admission_operation_store::recovery::resources::check_intake_committing(&tx)?;
        let append = super::super::history::segments::Append::nonce_preflight(&record)?;
        segment.prepare_pre_effect_append(&tx, &self.serving_owner, &append)?;
        record.insert(&tx)?;
        segment.appended(&tx, append.entry())?;
        checkpoint(&tx, 23)?;
        self.serving_owner
            .append_global_commit(
                &tx,
                MUTATION,
                PROJECTION,
                actual.authority.as_str(),
                record.sequence,
            )
            .map_err(map_owner_error)?;
        segment.committed(&tx, append.entry())?;
        // Expiry is checked again at the physical commit boundary, not renewed
        // merely because policy evaluation or the monotone join succeeded.
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, lease, decision_at)?;
        checkpoint(&tx, 24)?;
        self.commit_write(tx)?;
        if let Err(error) = checkpoint(&connection, 25) {
            return Err(map_owner_error(
                self.serving_owner.outcome_unknown(error.to_string()),
            ));
        }
        self.sync_after_write(&connection)?;
        checkpoint(&connection, 26)?;
        let loaded = load_operation(&connection, operation.binding().operation_id())?
            .ok_or_else(|| invalid("native nonce preflight physical acknowledgement is absent"))?;
        if loaded.bytes()? != record.bytes()? {
            return Err(invalid(
                "native nonce preflight physical acknowledgement differs",
            ));
        }
        loaded.evidence(&actual)
    }

    /// Independent anchored readback. No policy is evaluated or lease minted.
    pub fn load_security_participant_nonce_preflight(
        &self,
        operation: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<NativeSecurityNoncePreflightJoinRecordV1>, AdmissionOperationStoreError>
    {
        self.load_native_nonce_preflight_join_record(operation, fence, now)
            .map(|stored| stored.and_then(|(_, history)| history))
    }

    pub(in crate::admission_operation_store) fn load_native_nonce_preflight_join_record(
        &self,
        operation: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Option<NativeSecurityNoncePreflightJoinRecordV1>,
        )>,
        AdmissionOperationStoreError,
    > {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        observed_time(&tx, now)?;
        super::super::verify_current_catalogs(&tx)?;
        let Some(stored) = load_by_operation_id_tx(&tx, operation)? else {
            return Ok(None);
        };
        stored.verify_decision_time(now)?;
        let history = load_operation(&tx, operation)?
            .map(|record| {
                record.require_own_commit(&tx)?;
                let initialized = super::super::records::load_current_named(
                    &tx,
                    record.authority.as_str(),
                    &record.initialization,
                )?;
                record.evidence(&initialized)
            })
            .transpose()?;
        Ok(Some((stored.operation, history)))
    }
}
