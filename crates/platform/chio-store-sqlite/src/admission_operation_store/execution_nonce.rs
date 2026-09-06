//! Atomic nonce reservation and immutable, commit-bound recovery material.

use super::*;
use chio_core::crypto::PublicKey;
use chio_kernel::admission_operation::AdmissionExecutionNonceReservationV1;

mod history;
mod lifecycle;

pub(super) use lifecycle::{prepare_terminal, record_capture, verify_capture};

pub(crate) fn reject_split_nonce_capture(
    transaction: &Transaction<'_>,
    hold_id: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let operation_id: Option<String> = transaction
        .query_row(
            "SELECT operation.operation_id FROM budget_authorization_holds AS hold
         JOIN admission_operations AS operation ON operation.operation_id = hold.operation_id
         WHERE hold.hold_id = ?1",
            [hold_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if let Some(operation_id) = operation_id {
        let operation_id = AdmissionOperationId::from_persisted(operation_id)?;
        let stored = load_by_operation_id_tx(transaction, &operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if stored
            .operation
            .binding()
            .participant_requirements()
            .execution_nonce
        {
            return Err(invariant(
                "nonce-backed holds require atomic admission capture",
            ));
        }
    }
    Ok(())
}

impl SqliteAdmissionOperationStore {
    pub(super) fn reserve_nonce(
        &self,
        command: &AdmissionOperationCommand,
        reservation: &AdmissionExecutionNonceReservationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        if command.next_state() != Some(AdmissionOperationState::ReadyToDispatch)
            || command.attachments()
                != [AdmissionAttachment::ExecutionNonceId(
                    reservation.nonce_id().clone(),
                )]
        {
            return Err(invariant(
                "nonce reservation requires its exact ReadyToDispatch command",
            ));
        }
        let lease = command.recovery_lease();
        if lease.claimant_id().as_str() != format!("kernel:{}", reservation.issuer().to_hex()) {
            return Err(invariant(
                "nonce issuer does not match the qualified coordinator",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(lease.store_fence()))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, command.operation_id())?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        ensure_no_reserved_terminal_stage(&transaction, command.operation_id())?;
        qualify_generic_channel_command(&transaction, &stored.operation, command)?;
        verify_stored_recovery_claim(
            &transaction,
            &self.serving_owner,
            &stored,
            lease.untrusted_claim(),
            trusted_now_unix_ms,
            lease.store_fence(),
        )?;
        if trusted_now_unix_ms < stored.updated_at_unix_ms {
            return Err(invariant("nonce reservation trusted time regressed"));
        }
        let original = retained_request::load_retained_request_tx(&transaction, &stored.operation)?
            .ok_or_else(|| invariant("nonce reservation requires the retained original request"))?;
        let checked = AdmissionExecutionNonceReservationV1::from_canonical_bytes(
            reservation.canonical_bytes(),
            &stored.operation,
            &original,
            reservation.issuer(),
            trusted_now_unix_ms,
        )?;
        checked.require_operation_bound_profile()?;
        let result = stored
            .operation
            .apply_command(command, trusted_now_unix_ms)?;
        let AdmissionCommandResult::Applied(updated) = result else {
            let retained = verify_reservation(&transaction, &stored.operation)?
                .ok_or_else(|| invariant("nonce replay lost its original reservation"))?;
            if retained.canonical_bytes() != reservation.canonical_bytes() {
                return Err(invariant("nonce replay changed its immutable reservation"));
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(result);
        };
        let requirements = stored.operation.binding().participant_requirements();
        let required_state = if requirements.approval {
            AdmissionOperationState::ApprovalReserved
        } else {
            AdmissionOperationState::BudgetAuthorized
        };
        if stored.operation.state() != required_state {
            return Err(invariant(
                "nonce reservation precedes its required participants",
            ));
        }
        let ready_json = encode_operation(&updated)?;
        let digest =
            reservation_digest(checked.canonical_bytes(), &ready_json, trusted_now_unix_ms)?;
        participant::advance_participant_bound_operation_tx(
            &transaction,
            &self.serving_owner,
            &stored.operation,
            lease,
            &updated,
            &digest,
            trusted_now_unix_ms,
        )?;
        transaction
            .execute(
                "INSERT INTO admission_execution_nonce_reservations (
                operation_id, nonce_id, issuer, reservation_json, ready_operation_json,
                reserved_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    command.operation_id().as_str(),
                    checked.nonce_id().as_str(),
                    checked.issuer().to_hex(),
                    checked.canonical_bytes(),
                    ready_json,
                    sqlite_i64(trusted_now_unix_ms, "reserved_at_unix_ms")?,
                ],
            )
            .map_err(sqlite_error)?;
        verify_reservation(&transaction, &updated)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(AdmissionCommandResult::Applied(updated))
    }
}

/// Generic CAS cannot manufacture a reservation or advance past it without a
/// qualified lifecycle participant. Once reserved, every state or attachment
/// mutation must carry the owning participant's physical evidence atomically.
pub(super) fn qualify_generic_command(
    operation: &AdmissionOperationV1,
    command: &AdmissionOperationCommand,
) -> Result<(), AdmissionOperationStoreError> {
    if operation
        .binding()
        .participant_requirements()
        .execution_nonce
        && (operation.execution_nonce_id().is_some()
            || command.next_state() == Some(AdmissionOperationState::ReadyToDispatch)
            || command.next_state() == Some(AdmissionOperationState::CapturePending)
            || command.next_state() == Some(AdmissionOperationState::DispatchCommitted)
            || command
                .attachments()
                .iter()
                .any(|attachment| matches!(attachment, AdmissionAttachment::ExecutionNonceId(_))))
    {
        return Err(invariant(
            "execution nonce transition requires its atomic participant",
        ));
    }
    Ok(())
}

pub(super) fn verify_reservation(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<Option<AdmissionExecutionNonceReservationV1>, AdmissionOperationStoreError> {
    let row = connection
        .query_row(
            "SELECT CASE WHEN length(CAST(nonce_id AS BLOB)) BETWEEN 1 AND 512 THEN nonce_id END,
                    CASE WHEN length(issuer) = 64 THEN issuer END,
                    CASE WHEN length(reservation_json) BETWEEN 1 AND 16384 THEN reservation_json END,
                    CASE WHEN length(ready_operation_json) BETWEEN 1 AND 262144 THEN ready_operation_json END,
                    reserved_at_unix_ms
         FROM admission_execution_nonce_reservations WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let attachment = operation.execution_nonce_id();
    let Some((nonce_id, issuer, reservation_json, ready_json, reserved_at)) = row else {
        if attachment.is_some() {
            return Err(invariant(
                "operation nonce attachment has no durable reservation",
            ));
        }
        history::verify_absent(connection, operation)?;
        return Ok(None);
    };
    let (Some(nonce_id), Some(issuer), Some(reservation_json), Some(ready_json)) =
        (nonce_id, issuer, reservation_json, ready_json)
    else {
        return Err(invariant(
            "durable nonce reservation exceeds its storage bound",
        ));
    };
    if attachment.map(AdmissionIdentifier::as_str) != Some(nonce_id.as_str())
        || ready_json.is_empty()
        || ready_json.len() > MAX_PERSISTED_OPERATION_BYTES
    {
        return Err(invariant(
            "durable nonce reservation and operation state disagree",
        ));
    }
    let ready = AdmissionOperationV1::from_persisted(
        serde_json::from_slice::<PersistedAdmissionOperationV1>(&ready_json)
            .map_err(|error| invariant(error.to_string()))?,
    )?;
    if ready.binding() != operation.binding()
        || ready.state() != AdmissionOperationState::ReadyToDispatch
        || !history::preserves_attachments(&ready, operation)
        || ready.version() > operation.version()
        || encode_operation(&ready)? != ready_json
    {
        return Err(invariant(
            "nonce reservation Ready snapshot does not match its operation",
        ));
    }
    let reserved_at = stored_u64(reserved_at, "nonce reserved_at_unix_ms")?;
    let digest = reservation_digest(&reservation_json, &ready_json, reserved_at)?;
    let committed: bool = connection
        .query_row(
            "SELECT COUNT(*) = 1 FROM admission_operation_commits
         WHERE operation_id = ?1 AND operation_version = ?2
           AND mutation_kind = 'compare_and_swap' AND participant_digest = ?3
           AND operation_digest = ?4 AND recorded_at_unix_ms = ?5",
            params![
                operation.binding().operation_id().as_str(),
                sqlite_i64(ready.version(), "reserved_operation_version")?,
                digest,
                sha256_hex(&ready_json),
                sqlite_i64(reserved_at, "nonce reserved_at_unix_ms")?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !committed {
        return Err(invariant(
            "nonce reservation lost its exact admission commit",
        ));
    }
    let original = retained_request::load_retained_request_tx(connection, operation)?
        .ok_or_else(|| invariant("durable nonce reservation lost its original request"))?;
    let issuer = PublicKey::from_hex(&issuer).map_err(|error| invariant(error.to_string()))?;
    let checked = AdmissionExecutionNonceReservationV1::from_canonical_bytes(
        &reservation_json,
        &ready,
        &original,
        &issuer,
        reserved_at,
    )?;
    if checked.nonce_id().as_str() != nonce_id {
        return Err(invariant("nonce reservation identifier was substituted"));
    }
    history::verify(connection, operation, &ready, &checked, reserved_at)?;
    Ok(Some(checked))
}

pub(super) fn verify_ownership(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let orphan: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_execution_nonce_reservations AS nonce
         WHERE NOT EXISTS(SELECT 1 FROM admission_operations AS operation
                          WHERE operation.operation_id = nonce.operation_id))",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if orphan {
        return Err(invariant(
            "execution nonce reservation has no owning operation",
        ));
    }
    history::verify_ownership(connection)?;
    Ok(())
}

fn reservation_digest(
    reservation: &[u8],
    ready: &[u8],
    reserved_at_unix_ms: u64,
) -> Result<String, AdmissionOperationStoreError> {
    #[derive(Serialize)]
    struct Commit {
        schema: &'static str,
        reservation_digest: String,
        ready_operation_digest: String,
        reserved_at_unix_ms: u64,
    }
    canonical_json_bytes(&Commit {
        schema: "chio.admission-execution-nonce-commit.v1",
        reservation_digest: sha256_hex(reservation),
        ready_operation_digest: sha256_hex(ready),
        reserved_at_unix_ms,
    })
    .map(|bytes| sha256_hex(&bytes))
    .map_err(|error| invariant(error.to_string()))
}
