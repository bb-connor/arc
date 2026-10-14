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
        // The funded Output's price bounds its frames by its dirty pages, which
        // reach the WAL once only while the cache never spills mid-transaction.
        let previous_spill: i64 = connection
            .query_row("PRAGMA main.cache_spill", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        connection
            .execute_batch("PRAGMA main.cache_spill = 0")
            .map_err(sqlite_error)?;
        let result =
            (|| -> Result<NativeSecurityOutputJoinRecordV1, AdmissionOperationStoreError> {
                let tx = self.begin_write(&mut connection, Some(lease.store_fence()))?;
                observed_time(&tx, decision_at)?;
                verify_participant_recovery_tx(
                    &tx,
                    &self.serving_owner,
                    operation,
                    lease,
                    decision_at,
                )?;
                ensure_no_reserved_terminal_stage(&tx, operation.binding().operation_id())?;
                verify_catalog(&tx)?;
                let actual =
                    super::super::records::load_metadata(&tx, initialized.authority.as_str())?
                        .ok_or_else(|| invalid("native output initialization is absent"))?;
                if &actual != initialized
                    || actual.fence.store_uuid != lease.store_fence().store_uuid
                {
                    return Err(invalid(
                        "native output initialization changed destination history",
                    ));
                }
                contract::require_original(&tx, operation, &actual, intent, true)?;
                if let Some(record) = load_operation(&tx, operation.binding().operation_id())? {
                    if record.intent != *intent {
                        return Err(invalid("native output retry replaced its original intent"));
                    }
                    if operation
                        .provider_attempt()
                        .is_some_and(|attempt| attempt.is_native_caller_report())
                    {
                        // The kernel's observation precedes this transaction. Another
                        // owner of native mutation authority could strengthen inherited
                        // state in that interval. Verify complete current taint here,
                        // under the same write lease, before acknowledging the original
                        // caller output transition. Replay never creates a new join.
                        let current = crate::security_state::resolve_native_label_join(
                            &tx,
                            actual.authority.as_str(),
                            intent.key(),
                            intent.output_label(),
                            intent.transition_id(),
                        )
                        .map_err(invalid)?;
                        if current != record.request {
                            return Err(invalid(
                                "native caller output replay no longer covers current source",
                            ));
                        }
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
                let mut segment =
                    super::super::history::segments::SegmentSnapshot::capture(&tx, &actual)?;
                let output_head =
                    segment.head(&tx, super::super::history::segments::Family::Output)?;
                let previous = if output_head == 0 {
                    actual.digest.clone()
                } else {
                    load(&tx, actual.authority.as_str(), output_head)?
                        .ok_or_else(|| invalid("native output head absent"))?
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
                    intent.output_label(),
                    intent.transition_id(),
                )
                .map_err(invalid)?;
                let observed_at = observed_time(&tx, decision_at)?;
                verify_participant_recovery_tx(
                    &tx,
                    &self.serving_owner,
                    operation,
                    lease,
                    decision_at,
                )?;
                let declassification =
                    declassification::expected(&tx, operation, observed_at.max(decision_at))?;
                if let Some(outcome) = &declassification {
                    crate::security_state::verify_native_pending_declassification(
                        &tx,
                        actual.authority.as_str(),
                        &outcome.consumption,
                    )
                    .map_err(invalid)?;
                }
                // Before the join's first write: a native original may add only
                // its own authenticated Output growth (and its seal's priced
                // frames), and every other owed loan stays reserved.
                super::super::finishing_account::authorize_native_finishing_growth(
                    &tx,
                    &self.serving_owner,
                    operation,
                    &[
                        crate::admission_operation_store::recovery::storage::NativeFinishingPurposeV1::OutputJoin,
                        crate::admission_operation_store::recovery::storage::NativeFinishingPurposeV1::NativeJournalSeal,
                    ],
                )?;
                let authorization = NativeOutputJoinAuthority {
                    operation_id: operation.binding().operation_id().as_str().to_owned(),
                    authority: actual.authority.clone(),
                    request: request.clone(),
                    declassification: declassification.clone().map(Box::new),
                };
                let (tx, result, changes) =
                    crate::security_state::join_native_output(tx, authorization)
                        .map_err(invalid)?;
                verify_participant_recovery_tx(
                    &tx,
                    &self.serving_owner,
                    operation,
                    lease,
                    decision_at,
                )?;
                checkpoint(&tx, 17)?;
                if !segment.unchanged(&tx)? {
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
                    schema: Record::format(declassification.is_some()),
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
                    declassification,
                };
                record.validate(&tx)?;
                super::super::storage::require_tenant_live(
                    &tx,
                    actual.authority.as_str(),
                    intent.key().tenant_id.as_str(),
                )?;
                // Read the authentic prepaid allowance without advancing the journal.
                // The Output append and any required seal must finish against this
                // snapshot before their account transitions append global commits.
                let seal = super::super::finishing_account::native_finishing_seal_allowance(
                    &tx, operation,
                )?;
                if seal.is_none() {
                    crate::admission_operation_store::recovery::resources::check_committing(&tx)?;
                }
                let allowance = seal.as_ref().map(|data| {
                    super::super::finishing_plan::VerifiedNativeSealAllowance::from_account(
                        &tx, data,
                    )
                });
                let append = super::super::history::segments::Append::output(&record)?;
                let boundary = segment.prepare_owed_append(
                    &tx,
                    &self.serving_owner,
                    &append,
                    allowance.as_ref(),
                )?;
                record.insert(&tx)?;
                segment.appended(&tx, append.entry())?;
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
                segment.committed(&tx, append.entry())?;
                // Consume the exact owed purposes in this same transaction, after
                // the producer has verified its uninterrupted journal append. Cache
                // spill is disabled: neither rows nor spends publish before COMMIT.
                let funded = super::super::finishing_account::spend_native_finishing_purpose(
                    &tx,
                    &self.serving_owner,
                    operation,
                    crate::admission_operation_store::recovery::storage::NativeFinishingPurposeV1::OutputJoin,
                )?;
                if seal.is_some()
                    != (funded == super::super::finishing_account::NativeFinishingSpend::Spent)
                {
                    return Err(invalid(
                        "native Output funding changed within its transaction",
                    ));
                }
                if seal.is_some() && boundary == super::super::history::segments::Boundary::Sealed {
                    super::super::finishing_account::spend_native_finishing_purpose(
                        &tx,
                        &self.serving_owner,
                        operation,
                        crate::admission_operation_store::recovery::storage::NativeFinishingPurposeV1::NativeJournalSeal,
                    )?;
                }
                // Expiry is checked again at the physical commit boundary, not renewed
                // merely because policy evaluation or the monotone join succeeded.
                verify_participant_recovery_tx(
                    &tx,
                    &self.serving_owner,
                    operation,
                    lease,
                    decision_at,
                )?;
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
            })();
        let restored =
            connection.execute_batch(&format!("PRAGMA main.cache_spill = {previous_spill}"));
        // Committed or rolled back, the connection returns to the ordinary cap.
        let capped = self.serving_owner.native_capacity().restore(&connection);
        let record = result?;
        restored.map_err(sqlite_error)?;
        capped.map_err(invalid)?;
        Ok(record)
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
