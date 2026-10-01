//! Independent, fenced readback of the committed native budget participant.
use super::*;

/// Historical physical capture and its original authority cuts. These values
/// never authorize another capture, tool delivery or provider retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeDispatchCaptureWitness {
    pub capture: chio_kernel::AdmissionBudgetCapture,
    pub authority_commit_index: u64,
    pub revocation_commit_index: u64,
}

impl SqliteAdmissionOperationStore {
    /// Read the original capture decision and current operation in one anchored
    /// snapshot. This never refreshes policy, reacquires custody or executes.
    pub fn load_native_dispatch_capture(
        &self,
        operation_id: &AdmissionOperationId,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<chio_kernel::AdmissionBudgetCapture>, AdmissionOperationStoreError> {
        let capture = {
            let mut connection = self.connection()?;
            let transaction = self.begin_read(&mut connection)?;
            verify_active_owner(&transaction, &self.serving_owner, Some(active_fence))?;
            verify_trusted_time(&transaction, trusted_now_unix_ms)?;
            let Some(capture) =
                self.native_capture_tx(&transaction, operation_id, trusted_now_unix_ms)?
            else {
                return Ok(None);
            };
            capture
        };
        #[cfg(feature = "admission-test-support")]
        {
            self.native_capture_readback_for_test(capture)
        }
        #[cfg(not(feature = "admission-test-support"))]
        {
            Ok(Some(capture))
        }
    }

    /// Authenticate the original capture, global commit and revocation cut in
    /// one fenced snapshot. Later unrelated revocations and owner replacement
    /// cannot substitute their current indices for this historical decision.
    pub fn load_native_dispatch_capture_witness(
        &self,
        operation_id: &AdmissionOperationId,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<NativeDispatchCaptureWitness>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(active_fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let Some(capture) =
            self.native_capture_tx(&transaction, operation_id, trusted_now_unix_ms)?
        else {
            return Ok(None);
        };
        let chio_kernel::budget_store::BudgetInvocationCaptureDecision::Captured(decision) =
            &capture.decision
        else {
            return Err(invariant("native witness requires physical capture"));
        };
        let binding = decision
            .admission_binding
            .as_ref()
            .ok_or_else(|| invariant("native witness lost its original admission binding"))?;
        if let Some(observed) = binding.last_observed_revocation.as_ref() {
            observed
                .validate()
                .map_err(|error| invariant(error.to_string()))?;
            if decision.metadata.authority.as_ref() != Some(&observed.authority) {
                return Err(invariant("native witness changed revocation authority"));
            }
        }
        let dispatch = capture
            .operation
            .dispatch_commit()
            .ok_or_else(|| invariant("native witness lost its dispatch commitment"))?;
        let mut statement = transaction
            .prepare(
                "SELECT budget.commit_sequence, authority.commit_sequence
             FROM admission_operation_commits AS admission
             JOIN authority_global_commits AS budget
               ON budget.projection_reference_digest = admission.participant_digest
              AND budget.projection_kind = 'budget'
              AND budget.mutation_kind = 'capture_invocation'
             JOIN authority_global_commits AS authority
               ON authority.projection_kind = 'admission'
              AND authority.projection_key = admission.operation_id
              AND authority.projection_sequence = admission.commit_sequence
              AND authority.mutation_kind = admission.mutation_kind
             WHERE admission.operation_id = ?1 AND admission.operation_version = ?2
               AND admission.mutation_kind = 'compare_and_swap'
               AND budget.projection_key = ?3 AND budget.projection_sequence = ?4
               AND admission.store_uuid = ?5 AND admission.store_lease_id = ?6
               AND admission.store_owner_epoch = ?7
               AND budget.store_uuid = admission.store_uuid
               AND budget.store_lease_id = admission.store_lease_id
               AND budget.store_owner_epoch = admission.store_owner_epoch
               AND authority.store_uuid = admission.store_uuid
               AND authority.store_lease_id = admission.store_lease_id
               AND authority.store_owner_epoch = admission.store_owner_epoch
             LIMIT 2",
            )
            .map_err(sqlite_error)?;
        let mut rows = statement
            .query(params![
                operation_id.as_str(),
                sqlite_i64(dispatch.committed_version, "dispatch_version")?,
                decision.metadata.event_id.as_deref(),
                decision
                    .metadata
                    .budget_commit_index
                    .map(|index| sqlite_i64(index, "budget_index"))
                    .transpose()?,
                dispatch.store_fence.store_uuid,
                dispatch.store_fence.lease_id,
                sqlite_i64(dispatch.store_fence.owner_epoch, "capture_epoch")?,
            ])
            .map_err(sqlite_error)?;
        let row = rows
            .next()
            .map_err(sqlite_error)?
            .ok_or_else(|| invariant("native witness lost its original global commitment"))?;
        let budget_index: i64 = row.get(0).map_err(sqlite_error)?;
        let authority_index: i64 = row.get(1).map_err(sqlite_error)?;
        if budget_index <= 0
            || authority_index <= budget_index
            || rows.next().map_err(sqlite_error)?.is_some()
        {
            return Err(invariant(
                "native witness has ambiguous or unordered commitments",
            ));
        }
        drop(rows);
        drop(statement);
        // History predating global-chain adoption forms an unindexed prefix.
        // Every subsequent revocation has its own global record. Anchor and
        // projection verification above authenticate both histories; a hole
        // among indexed revocations is not a pre-adoption record.
        let (cut, unindexed_end, indexed_start): (Option<i64>, Option<i64>, Option<i64>) = transaction
            .query_row(
                "SELECT
                   MAX(CASE WHEN global.commit_sequence IS NULL OR global.commit_sequence < ?1
                            THEN revocation.commit_index END),
                   MAX(CASE WHEN global.commit_sequence IS NULL THEN revocation.commit_index END),
                   MIN(CASE WHEN global.commit_sequence IS NOT NULL THEN revocation.commit_index END)
                 FROM admission_authority_commits AS revocation
                 LEFT JOIN authority_global_commits AS global
                   ON global.projection_kind = 'revocation'
                  AND global.projection_key = revocation.capability_id
                  AND global.projection_sequence = revocation.commit_index",
                [budget_index],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(sqlite_error)?;
        if unindexed_end
            .zip(indexed_start)
            .is_some_and(|(end, start)| end >= start)
        {
            return Err(invariant(
                "native witness has incomplete revocation history",
            ));
        }
        let cut = cut
            .filter(|index| *index > 0)
            .ok_or_else(|| invariant("native witness lost revocation genesis"))?;
        let revocation_commit_index = stored_u64(cut, "historical_revocation_index")?;
        if binding
            .last_observed_revocation
            .as_ref()
            .is_some_and(|observed| observed.commit_index > revocation_commit_index)
        {
            return Err(invariant(
                "native witness predates its original revocation observation",
            ));
        }
        // Independently reject invalid historical captures, including records
        // written before the physical capture path checked supplemental IDs.
        let mut revoked = transaction
            .prepare(
                "SELECT EXISTS(SELECT 1 FROM admission_authority_commits
             WHERE kind = 'revocation' AND capability_id = ?1 AND commit_index <= ?2)",
            )
            .map_err(sqlite_error)?;
        for member in binding.revocation_set.ids() {
            if revoked
                .query_row(params![member, cut], |row| row.get::<_, bool>(0))
                .map_err(sqlite_error)?
            {
                return Err(invariant(
                    "native witness includes an authority revoked before capture",
                ));
            }
        }
        drop(revoked);
        let witness = NativeDispatchCaptureWitness {
            capture,
            authority_commit_index: stored_u64(authority_index, "capture_authority_index")?,
            revocation_commit_index,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(Some(witness))
    }

    fn native_capture_tx(
        &self,
        transaction: &Transaction<'_>,
        operation_id: &AdmissionOperationId,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<chio_kernel::AdmissionBudgetCapture>, AdmissionOperationStoreError> {
        let Some(stored) = load_by_operation_id_tx(transaction, operation_id)? else {
            return Ok(None);
        };
        stored.verify_decision_time(trusted_now_unix_ms)?;
        if stored.operation.native_dispatch_ledger_digest().is_none() {
            return Ok(None);
        }
        let original = retained_request::load_retained_request_tx(transaction, &stored.operation)?
            .ok_or_else(|| invariant("native capture readback lost its original request"))?;
        if original.native_security_authority_binding().is_none() {
            return Err(invariant(
                "native capture readback lost its original authority",
            ));
        }
        let budget = crate::budget_store::SqliteBudgetStore::open_alongside(
            self.connection.clone(),
            self.serving_owner.clone(),
        );
        let decision = budget
            .load_native_capture_decision_tx(transaction, &stored.operation, &original)
            .map_err(|error| invariant(error.to_string()))?;
        Ok(Some(chio_kernel::AdmissionBudgetCapture {
            decision: chio_kernel::budget_store::BudgetInvocationCaptureDecision::Captured(
                decision,
            ),
            operation: stored.operation,
        }))
    }
}
