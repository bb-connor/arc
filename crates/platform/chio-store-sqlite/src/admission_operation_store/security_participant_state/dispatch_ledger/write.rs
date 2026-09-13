//! A lease-owned, atomic journal append. This never captures invocation quota.
use super::super::{egress, history, records};
use super::*;

impl SqliteAdmissionOperationStore {
    /// Retain exact preparation and physical participant references. This is
    /// historical evidence only; dedicated capture and native lifecycle support
    /// are still required before any connector may execute.
    pub fn retain_native_dispatch_ledger(
        &self,
        input: NativeSecurityDispatchLedgerContext<'_>,
    ) -> Result<NativeSecurityDispatchLedgerRecordV1, AdmissionOperationStoreError> {
        let custody = &input.custody;
        let operation = custody.operation;
        require_operation(operation)?;
        let (policy_value, policy) = policy::decode(input.policy_json)?;
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(custody.lease.store_fence()))?;
        let now = observed_time(&tx, custody.trusted_now_unix_ms)?;
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, custody.lease, now)?;
        ensure_no_reserved_terminal_stage(&tx, operation.binding().operation_id())?;
        storage::verify_coverage(&tx)?;
        let original = retained_request::load_retained_request_tx(&tx, operation)?
            .ok_or_else(|| invalid("native dispatch ledger requires original admission"))?;
        original.validate_binding(operation.binding())?;
        original.validate_request_material(custody.request)?;
        original.validate_native_security_context(custody.security_context)?;
        original.validate_native_security_authority(custody.binding)?;
        if original.authority_profile().is_none()
            || policy.inputs.native_authority != *custody.binding
        {
            return Err(invalid(
                "native dispatch ledger lacks its supported original authority profile",
            ));
        }
        let initialized =
            records::load_metadata(&tx, custody.binding.security_authority_id().as_str())?
                .ok_or_else(|| invalid("native dispatch ledger initialization is absent"))?;
        if initialized.admission_binding()? != *custody.binding
            || custody.binding.store_uuid().as_str() != custody.lease.store_fence().store_uuid
        {
            return Err(invalid("native dispatch ledger initialization differs"));
        }
        let live_request_digest = egress::live_request_hash(custody.request)?;
        policy.validate_binding(
            operation,
            &original,
            custody.security_context,
            &live_request_digest,
        )?;
        policy.validate_live_declassification(custody.request)?;
        policy.validate_owned_declassification(&tx, operation, &policy_value)?;
        let grant_index = u32::try_from(input.grant_index).map_err(invalid)?;
        let grant = original
            .retained_matching_grant(input.grant_index)
            .ok_or_else(|| invalid("native dispatch ledger selected an unmatched grant"))?;
        if let Some(existing) = storage::load(&tx, operation.binding().operation_id().as_str())? {
            if existing.policy != policy_value
                || existing.grant_index != grant_index
                || existing.live_request_digest != live_request_digest
                || existing.context != *custody.security_context
                || existing.operation != operation.to_persisted()
            {
                return Err(invalid(
                    "native dispatch ledger retry changed its original command",
                ));
            }
            existing.validate(&tx)?;
            storage::verify_reference(&tx, &existing)?;
            return existing.evidence();
        }
        policy.validate_current(&tx, now)?;
        let owned_hold: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM budget_authorization_holds
             WHERE hold_id = ?1 AND operation_id = ?2 AND capability_id = ?3 AND grant_index = ?4 AND invocation_state = 'authorized')",
            params![operation.budget_hold_id().map(AdmissionIdentifier::as_str), operation.binding().operation_id().as_str(), operation.binding().capability_id().as_str(), i64::from(grant_index)],
            |row| row.get(0),
        ).map_err(sqlite_error)?;
        if !owned_hold {
            return Err(invalid(
                "native dispatch ledger hold belongs to another operation or grant",
            ));
        }
        let joined = history::load_for_operation(&tx, operation.binding().operation_id())?
            .ok_or_else(|| invalid("native dispatch ledger requires the original join"))?;
        let egress = egress::load_history(&tx, operation.binding().operation_id())?;
        let runtime = runtime_participant::dispatch_snapshot(&tx, operation, input.grant_index)?;
        let approval =
            governed_approval_claim::dispatch_snapshot(&tx, operation, input.grant_index)?;
        let dpop = dpop_claim::dispatch_snapshot(&tx, operation, input.grant_index)?;
        governed_approval_claim::verify_fresh_approval_tx(&tx, operation, now)?;
        dpop_claim::verify_fresh_dpop_tx(&tx, operation, now)?;
        let record = Record {
            schema: SCHEMA.into(),
            operation: operation.to_persisted(),
            lease: history::LeaseHistory::new(custody.lease),
            context: custody.security_context.clone(),
            grant_index,
            grant_digest: AdmissionDigest::try_new(
                "native_dispatch_grant",
                sha256_hex(&canonical_json_bytes(grant).map_err(invalid)?),
            )?,
            live_request_digest,
            policy: policy_value,
            join_digest: AdmissionDigest::try_new("native_dispatch_join", joined.digest()?)?,
            egress_acquisition: egress
                .as_ref()
                .map(|history| history.acquisition.event_digest.clone()),
            egress_commitment: egress
                .as_ref()
                .and_then(|history| history.commitment.as_ref())
                .map(|committed| committed.event_digest.clone()),
            runtime,
            approval,
            dpop,
            observed_at: now,
            decision_at: custody.trusted_now_unix_ms,
        };
        record.validate(&tx)?;
        tx.execute("INSERT INTO admission_operation_native_dispatch_ledger (operation_id, record_digest, canonical_record) VALUES (?1, ?2, ?3)",
            params![operation.binding().operation_id().as_str(), record.digest()?.as_str(), record.bytes()?]).map_err(sqlite_error)?;
        self.serving_owner
            .append_global_commit(
                &tx,
                MUTATION,
                PROJECTION,
                operation.binding().operation_id().as_str(),
                1,
            )
            .map_err(map_owner_error)?;
        storage::verify_coverage(&tx)?;
        let commit_at = observed_time(&tx, now)?;
        storage::verify_reference(&tx, &record)?;
        policy.validate_current(&tx, commit_at)?;
        verify_participant_recovery_tx(
            &tx,
            &self.serving_owner,
            operation,
            custody.lease,
            commit_at,
        )?;
        let evidence = record.evidence()?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        Ok(evidence)
    }
}
