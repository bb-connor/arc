//! Nonce preparation, capture and terminalization inside the owning transaction.

use super::*;

impl SqliteAdmissionOperationStore {
    pub(in crate::admission_operation_store) fn prepare_nonce_capture(
        &self,
        command: &AdmissionOperationCommand,
        now: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        if command.next_state() != Some(AdmissionOperationState::CapturePending)
            || !command.attachments().is_empty()
            || command.last_error().is_some()
            || command.terminal_replay().is_some()
        {
            return Err(invariant(
                "nonce capture preparation requires its exact command",
            ));
        }
        let lease = command.recovery_lease();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(lease.store_fence()))?;
        verify_trusted_time(&transaction, now)?;
        let stored = load_by_operation_id_tx(&transaction, command.operation_id())?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        ensure_no_reserved_terminal_stage(&transaction, command.operation_id())?;
        qualify_generic_channel_command(&transaction, &stored.operation, command)?;
        verify_stored_recovery_claim(
            &transaction,
            &self.serving_owner,
            &stored,
            lease.untrusted_claim(),
            now,
            lease.store_fence(),
        )?;
        let requirements = stored.operation.binding().participant_requirements();
        if !requirements.execution_nonce
            || !requirements.budget_capture
            || !matches!(
                stored.operation.state(),
                AdmissionOperationState::ReadyToDispatch | AdmissionOperationState::CapturePending
            )
        {
            return Err(invariant(
                "nonce capture preparation has no ready nonce participant",
            ));
        }
        let nonce = fresh_nonce(&transaction, &stored.operation, lease, now)?;
        crate::budget_store::verify_nonce_budget_phase_tx(
            &transaction,
            &stored.operation,
            crate::budget_store::NonceBudgetPhase::Authorized,
        )
        .map_err(|error| invariant(error.to_string()))?;
        let result = stored.operation.apply_command(command, now)?;
        let AdmissionCommandResult::Applied(updated) = result else {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(result);
        };
        let digest = history::preparation_digest(&nonce, &updated, now)?;
        participant::advance_participant_bound_operation_tx(
            &transaction,
            &self.serving_owner,
            &stored.operation,
            lease,
            &updated,
            &digest,
            now,
        )?;
        history::insert(
            &transaction,
            &updated,
            history::Phase::CapturePending,
            Some(&digest),
            now,
        )?;
        verify_reservation(&transaction, &updated)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(AdmissionCommandResult::Applied(updated))
    }
}

fn fresh_nonce(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
    now: u64,
) -> Result<AdmissionExecutionNonceReservationV1, AdmissionOperationStoreError> {
    let nonce = verify_reservation(transaction, operation)?
        .ok_or_else(|| invariant("nonce capture lost its durable reservation"))?;
    if lease.claimant_id().as_str() != format!("kernel:{}", nonce.issuer().to_hex()) {
        return Err(invariant(
            "nonce capture coordinator does not own its issuer",
        ));
    }
    let original = retained_request::load_retained_request_tx(transaction, operation)?
        .ok_or_else(|| invariant("nonce capture lost its original request"))?;
    threshold_approval::verify_nonce_capture_approval(transaction, operation, now)?;
    AdmissionExecutionNonceReservationV1::from_canonical_bytes(
        nonce.canonical_bytes(),
        operation,
        &original,
        nonce.issuer(),
        now,
    )
}

pub(in crate::admission_operation_store) fn verify_capture(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    updated: &AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
    now: u64,
) -> Result<bool, AdmissionOperationStoreError> {
    if operation
        .binding()
        .participant_requirements()
        .execution_nonce
    {
        if operation.state() != AdmissionOperationState::CapturePending {
            return Err(invariant(
                "nonce capture requires durable capture preparation",
            ));
        }
        let stored = load_by_operation_id_tx(transaction, operation.binding().operation_id())?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if stored.operation == *updated {
            // An exact replay recovers historical evidence, not fresh authority.
            // The caller still verifies the exact budget participant commitment
            // before returning, and must not append a second nonce phase.
            let nonce = verify_reservation(transaction, updated)?
                .ok_or_else(|| invariant("nonce capture replay lost its reservation"))?;
            if lease.claimant_id().as_str() != format!("kernel:{}", nonce.issuer().to_hex()) {
                return Err(AdmissionOperationStoreError::Fenced);
            }
            return Ok(true);
        }
        if stored.operation != *operation {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        fresh_nonce(transaction, operation, lease, now)?;
    }
    Ok(false)
}

pub(in crate::admission_operation_store) fn record_capture(
    transaction: &Transaction<'_>,
    updated: &AdmissionOperationV1,
    participant_digest: &str,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if updated.binding().participant_requirements().execution_nonce {
        history::insert(
            transaction,
            updated,
            history::Phase::Committed,
            Some(participant_digest),
            now,
        )?;
        verify_reservation(transaction, updated)?;
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn prepare_terminal(
    transaction: &Transaction<'_>,
    source: &AdmissionOperationV1,
    terminal: &AdmissionOperationV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let Some(nonce) = verify_reservation(transaction, source)? else {
        return Ok(());
    };
    let stored = load_by_operation_id_tx(transaction, source.binding().operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    if stored.operation != *source
        || stored.recovery_claim.as_ref().is_none_or(|claim| {
            claim.claimant_id().as_str() != format!("kernel:{}", nonce.issuer().to_hex())
        })
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    if terminal.state() == AdmissionOperationState::CompensatedBeforeDispatch {
        if !matches!(
            source.state(),
            AdmissionOperationState::ReadyToDispatch | AdmissionOperationState::CapturePending
        ) {
            return Err(invariant("committed nonce cannot be cancelled or refunded"));
        }
        crate::budget_store::verify_nonce_budget_phase_tx(
            transaction,
            source,
            crate::budget_store::NonceBudgetPhase::Released,
        )
        .map_err(|error| invariant(error.to_string()))?;
        history::insert(transaction, terminal, history::Phase::Cancelled, None, now)?;
    } else if !matches!(
        source.state(),
        AdmissionOperationState::DispatchCommitted | AdmissionOperationState::Finalizing
    ) {
        return Err(invariant(
            "nonce terminal requires a committed dispatch or verified cancellation",
        ));
    }
    Ok(())
}
