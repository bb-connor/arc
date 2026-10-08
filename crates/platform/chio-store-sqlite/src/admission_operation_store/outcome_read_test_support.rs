//! Rollback-only primitive observations of hostile input in the owning transaction.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Authenticate the real retained original, insert explicitly hostile input
    /// on this owner's connection, observe the private read, then roll it back.
    /// This default-off test API never commits an outcome or returns its bytes.
    #[doc(hidden)]
    pub fn profiled_outcome_read_allocations_for_test(
        &self,
        operation_id: &AdmissionOperationId,
        hostile_raw: &[u8],
        hostile_evaluation: Option<&[u8]>,
    ) -> Result<(u64, u64, u64, u64), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, None)?;
        let stored = load_by_operation_id_tx(&transaction, operation_id)?
            .ok_or_else(|| invariant("read allocation probe original operation is absent"))?;
        let original = retained_request::load_retained_request_tx(&transaction, &stored.operation)?
            .ok_or_else(|| invariant("read allocation probe retained original is absent"))?;
        let profile = original.native_output_retention().ok_or_else(|| {
            invariant("read allocation probe requires an actual selected original profile")
        })?;
        if original.native_security_authority_binding().is_none()
            || stored.operation.state() != AdmissionOperationState::CompensatedBeforeDispatch
            || stored.operation.dispatch_commit().is_some()
            || stored.operation.native_dispatch_ledger_digest().is_some()
            || stored.operation.tool_outcome_id().is_some()
        {
            return Err(invariant(
                "read allocation probe requires a genuine uncaptured denied original",
            ));
        }
        let limits = (profile.envelopes().raw(), profile.envelopes().evaluation());
        let raw_limit = limits
            .0
            .checked_add(1)
            .ok_or_else(|| invariant("read allocation probe Raw limit overflowed"))?;
        let evaluation_limit = limits
            .1
            .checked_add(1)
            .ok_or_else(|| invariant("read allocation probe evaluation limit overflowed"))?;
        if hostile_raw.is_empty()
            || u64::try_from(hostile_raw.len()).map_err(|error| invariant(error.to_string()))?
                > raw_limit
            || hostile_evaluation.is_some_and(|bytes| bytes.is_empty())
            || hostile_evaluation
                .map(|bytes| u64::try_from(bytes.len()))
                .transpose()
                .map_err(|error| invariant(error.to_string()))?
                .is_some_and(|bytes| bytes > evaluation_limit)
        {
            return Err(invariant(
                "read allocation probe input exceeds its one-byte boundary control",
            ));
        }
        let digest = AdmissionDigest::try_new("hostile_blob", sha256_hex(hostile_raw))?;
        let fence = &self.serving_owner.fence;
        let at = sqlite_i64(stored.updated_at_unix_ms, "read_probe_time")?;
        let epoch = sqlite_i64(fence.owner_epoch, "read_probe_owner_epoch")?;
        let changed = transaction
            .execute(
                "INSERT INTO main.tool_outcome_blobs
             (digest, blob_size_bytes, canonical_bytes, recorded_at_unix_ms,
              store_uuid, store_lease_id, store_owner_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    digest.as_str(),
                    i64::try_from(hostile_raw.len())
                        .map_err(|error| invariant(error.to_string()))?,
                    hostile_raw,
                    at,
                    &fence.store_uuid,
                    &fence.lease_id,
                    epoch
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant(
                "read allocation probe did not insert one hostile blob",
            ));
        }
        if let Some(evaluation) = hostile_evaluation {
            let outcome_id = "a".repeat(64);
            let evaluation_id = "b".repeat(64);
            let untrusted_digest = "c".repeat(64);
            let changed = transaction
                .execute(
                    "INSERT INTO main.tool_outcomes
                 (operation_id, outcome_id, request_id, raw_output_digest, outcome_version,
                  lifecycle_digest, participant_digest, outcome_json, recorded_at_unix_ms,
                  updated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5, ?6, ?7, ?7, ?8, ?9, ?10)",
                    params![
                        operation_id.as_str(),
                        &outcome_id,
                        stored.operation.binding().request_id().as_str(),
                        digest.as_str(),
                        &untrusted_digest,
                        b"{".as_slice(),
                        at,
                        &fence.store_uuid,
                        &fence.lease_id,
                        epoch
                    ],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(invariant(
                    "read allocation probe did not insert one hostile outcome",
                ));
            }
            let changed = transaction
                .execute(
                    "INSERT INTO main.post_return_evaluations
                 (operation_id, evaluation_id, outcome_id, evaluation_version,
                  lifecycle_digest, participant_digest, evaluation_json, created_at_unix_ms,
                  updated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch)
                 VALUES (?1, ?2, ?3, 1, ?4, ?4, ?5, ?6, ?6, ?7, ?8, ?9)",
                    params![
                        operation_id.as_str(),
                        evaluation_id,
                        outcome_id,
                        untrusted_digest,
                        evaluation,
                        at,
                        &fence.store_uuid,
                        &fence.lease_id,
                        epoch
                    ],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(invariant(
                    "read allocation probe did not insert one hostile evaluation",
                ));
            }
        }
        // These transient rows are malformed storage input. No original state,
        // attachment, claim, participant history, global frame or anchor changes.
        let (raw, evaluation) =
            crate::tool_outcome_store::cold_read_test_support::original_read_stage_allocations_for_test(
                &transaction,
                operation_id,
                &digest,
            )
            .map_err(|error| invariant(error.to_string()))?;
        transaction.rollback().map_err(sqlite_error)?;
        let transaction = self.begin_read(&mut connection)?;
        let restored = load_by_operation_id_tx(&transaction, operation_id)?
            .ok_or_else(|| invariant("read allocation probe original vanished after rollback"))?;
        let remaining: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM main.tool_outcome_blobs WHERE digest=?1
             UNION ALL SELECT 1 FROM main.tool_outcomes WHERE operation_id=?2
             UNION ALL SELECT 1 FROM main.post_return_evaluations WHERE operation_id=?2)",
                params![digest.as_str(), operation_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if restored.operation != stored.operation
            || restored.recovery_claim != stored.recovery_claim
            || restored.updated_at_unix_ms != stored.updated_at_unix_ms
            || remaining
        {
            return Err(invariant(
                "read allocation probe did not restore the original empty custody",
            ));
        }
        transaction.rollback().map_err(sqlite_error)?;
        Ok((limits.0, limits.1, raw, evaluation))
    }
}
