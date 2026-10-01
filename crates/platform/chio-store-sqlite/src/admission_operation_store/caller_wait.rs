//! Keep captured custody while waiting for the original authenticated report.
//! The ordinary CAS port continues to reject all nonce lifecycle mutations.
use super::*;

/// A wait-only transition verified in the original physical transaction. No
/// public constructor or clone can turn retained evidence into fresh capture.
pub(super) struct VerifiedCallerWait<'tx> {
    connection: &'tx Connection,
    original: &'tx AdmissionOperationV1,
    waiting: &'tx AdmissionOperationV1,
}

impl VerifiedCallerWait<'_> {
    pub(super) fn verify_transition(
        &self,
        connection: &Connection,
        original: &AdmissionOperationV1,
        waiting: &AdmissionOperationV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq(self.connection, connection)
            || self.original != original
            || self.waiting != waiting
            || waiting.state() != AdmissionOperationState::AwaitingCallerReport
            || original.dispatch_commit() != waiting.dispatch_commit()
            || original.native_dispatch_ledger_digest() != waiting.native_dispatch_ledger_digest()
            || original.caller_dispatch_context_digest() != waiting.caller_dispatch_context_digest()
        {
            return Err(invariant(
                "caller wait changed its verified transaction or capture",
            ));
        }
        Ok(())
    }
}

impl SqliteAdmissionOperationStore {
    pub(super) fn retain_caller_wait(
        &self,
        command: &AdmissionOperationCommand,
        now: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        if command.next_state() != Some(AdmissionOperationState::AwaitingCallerReport)
            || !command.attachments().is_empty()
            || command.terminal_replay().is_some()
            || command.last_error().is_some()
        {
            return Err(invariant(
                "caller wait requires its exact nonterminal command",
            ));
        }
        let lease = command.recovery_lease();
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(lease.store_fence()))?;
        verify_trusted_time(&tx, now)?;
        let stored = load_by_operation_id_tx(&tx, command.operation_id())?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        verify_stored_recovery_claim(
            &tx,
            &self.serving_owner,
            &stored,
            lease.untrusted_claim(),
            now,
            lease.store_fence(),
        )?;
        let operation = &stored.operation;
        if !matches!(
            operation.state(),
            AdmissionOperationState::DispatchCommitted
                | AdmissionOperationState::AwaitingCallerReport
        ) {
            return Err(invariant(
                "caller wait requires the original committed dispatch",
            ));
        }
        let original = retained_request::load_retained_request_tx(&tx, operation)?
            .ok_or_else(|| invariant("caller wait lost its original request"))?;
        let executor = original
            .authority_profile()
            .and_then(|profile| profile.caller_executor())
            .ok_or_else(|| invariant("legacy caller cannot acquire authenticated wait custody"))?;
        if !operation.provider_attempt().is_some_and(|attempt| {
            attempt.is_caller_report() && attempt.transport_key_epoch == executor.key_epoch
        }) {
            return Err(invariant(
                "caller wait changed its original executor attempt",
            ));
        }
        let nonce = execution_nonce::verify_reservation(&tx, operation)?
            .ok_or_else(|| invariant("caller wait lost its physical nonce"))?;
        if lease.claimant_id().as_str() != format!("kernel:{}", nonce.issuer().to_hex()) {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        let frame = caller_dispatch_context::load(&tx, operation)?
            .ok_or_else(|| invariant("caller wait lost its physical context"))?;
        if operation
            .provider_attempt()
            .is_some_and(|attempt| attempt.is_native_caller_report())
        {
            if operation.native_dispatch_ledger_digest().is_none()
                || frame
                    .native_release_custody(operation, &original)?
                    .is_none()
            {
                return Err(invariant(
                    "native caller wait lacks original native custody",
                ));
            }
            security_participant_state::dispatch_ledger::verify_capture_attachment(&tx, operation)?;
        } else {
            security_dispatch::verify_native_security_dispatch_tx(&tx, operation)?;
        }
        crate::budget_store::verify_nonce_budget_phase_tx(
            &tx,
            operation,
            crate::budget_store::NonceBudgetPhase::Captured,
        )
        .map_err(|error| invariant(error.to_string()))?;
        let result = operation.apply_command(command, now)?;
        if let AdmissionCommandResult::Applied(updated) = &result {
            let evidence = canonical_json_bytes(&serde_json::json!({
                "schema": "chio.caller-awaiting-report-custody.v1",
                "original_operation": operation.to_persisted(),
                "frozen_context_digest": frame.digest(),
                "nonce_reservation_digest": sha256_hex(nonce.canonical_bytes()),
                "executor": executor
            }))
            .map_err(|error| invariant(error.to_string()))?;
            let verified = VerifiedCallerWait {
                connection: &tx,
                original: operation,
                waiting: updated,
            };
            participant::advance_named_participant_tx(
                &tx,
                &self.serving_owner,
                operation,
                lease,
                updated,
                participant::ParticipantCommit {
                    kind: participant::ParticipantMutation::CallerWait(&verified),
                    digest: &sha256_hex(&evidence),
                },
                now,
            )?;
            execution_nonce::verify_reservation(&tx, updated)?;
            caller_dispatch_context::load(&tx, updated)?;
        }
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        Ok(result)
    }
}
