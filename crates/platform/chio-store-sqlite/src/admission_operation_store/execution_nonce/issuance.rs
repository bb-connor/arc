//! Write-ahead nonce material, not preflight cleanup or reservation authority.

use super::*;

mod record;
pub(in crate::admission_operation_store) use record::{verify, verify_ownership};

impl SqliteAdmissionOperationStore {
    pub(in crate::admission_operation_store) fn issue_nonce(
        &self,
        command: &AdmissionOperationCommand,
        issuance: &AdmissionExecutionNonceReservationV1,
        now: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        let artifact_digest = AdmissionDigest::try_new(
            "execution_nonce_issuance_digest",
            sha256_hex(issuance.canonical_bytes()),
        )?;
        if command.next_state() != Some(AdmissionOperationState::Prepared)
            || command.attachments()
                != [AdmissionAttachment::ExecutionNonceIssuanceDigest(
                    artifact_digest,
                )]
            || command.last_error().is_some()
            || command.terminal_replay().is_some()
        {
            return Err(invariant(
                "nonce issuance requires its exact Prepared command",
            ));
        }
        let lease = command.recovery_lease();
        if lease.claimant_id().as_str() != format!("kernel:{}", issuance.issuer().to_hex()) {
            return Err(invariant(
                "nonce issuer does not match the qualified coordinator",
            ));
        }
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
        if stored.operation.state() != AdmissionOperationState::Prepared
            || stored.operation.attachments().iter().any(|attachment| {
                !matches!(
                    attachment,
                    AdmissionAttachment::ExecutionNonceIssuanceDigest(_)
                )
            })
            || now < stored.updated_at_unix_ms
        {
            return Err(invariant(
                "nonce issuance must precede executable admission participants",
            ));
        }
        let original = retained_request::load_retained_request_tx(&transaction, &stored.operation)?
            .ok_or_else(|| invariant("nonce issuance requires the retained original request"))?;
        let checked = AdmissionExecutionNonceReservationV1::from_canonical_bytes(
            issuance.canonical_bytes(),
            &stored.operation,
            &original,
            issuance.issuer(),
            now,
        )?;
        checked.require_operation_bound_profile()?;
        let retained = verify(&transaction, &stored.operation)?;
        let result = stored.operation.apply_command(command, now)?;
        let AdmissionCommandResult::Applied(updated) = result else {
            if retained
                .as_ref()
                .map(AdmissionExecutionNonceReservationV1::canonical_bytes)
                != Some(checked.canonical_bytes())
            {
                return Err(invariant(
                    "nonce issuance replay lost its immutable artifact",
                ));
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(result);
        };
        if retained.is_some() {
            return Err(invariant(
                "nonce issuance cannot replace an existing artifact",
            ));
        }
        let already_reserved: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_execution_nonce_reservations WHERE nonce_id = ?1)",
            [checked.nonce_id().as_str()], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if already_reserved {
            return Err(invariant("nonce issuance identity is already reserved"));
        }
        let snapshot = encode_operation(&updated)?;
        let digest = record::commit_digest(checked.canonical_bytes(), &snapshot, now)?;
        participant::advance_participant_bound_operation_tx(
            &transaction,
            &self.serving_owner,
            &stored.operation,
            lease,
            &updated,
            &digest,
            now,
        )?;
        transaction
            .execute(
                "INSERT INTO admission_execution_nonce_issuances
                (operation_id, nonce_id, issuer, issuance_json, operation_json, issued_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    updated.binding().operation_id().as_str(),
                    checked.nonce_id().as_str(),
                    checked.issuer().to_hex(),
                    checked.canonical_bytes(),
                    snapshot,
                    sqlite_i64(now, "nonce issued_at_unix_ms")?
                ],
            )
            .map_err(sqlite_error)?;
        verify(&transaction, &updated)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(AdmissionCommandResult::Applied(updated))
    }
}
