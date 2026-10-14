//! Native readback of every Process purpose. Each receipt is minted from the
//! account found through its source alias and from immutable native history,
//! so a Process replay always receives the identical receipt.
use super::*;
use chio_kernel::process_return_custody::{
    NativeProcessReturnCustodyPort, ProcessNativeReturnCaptureDataV1,
    ProcessOriginalNonceCustodyDataV1, ProcessOriginalReturnFateDataV1,
    ProcessReturnBankReadbackDataV1, ProcessReturnInventoryDataV1,
    ProcessReturnReconciliationDataV1, PROCESS_ORIGINAL_NONCE_CUSTODY_SCHEMA,
    PROCESS_RETURN_CAPTURE_SCHEMA, PROCESS_RETURN_RECONCILIATION_SCHEMA,
};

/// The actual store as the scoped issuer's private owner port.
pub(super) struct FinishingCustodyPort<'a> {
    pub(super) store: &'a SqliteAdmissionOperationStore,
}

impl NativeProcessReturnCustodyPort for FinishingCustodyPort<'_> {
    fn verify_original_process_return_inventory(
        &self,
        inventory: &ProcessReturnInventoryDataV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ProcessReturnBankReadbackDataV1, AdmissionOperationStoreError> {
        self.store
            .verify_original_process_return_inventory_from_port(inventory, fence, now)
    }

    fn verify_original_process_return_enrollment(
        &self,
        source: &ProcessReturnSourceDataV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ProcessReturnFundingDataV1, AdmissionOperationStoreError> {
        self.store
            .verify_original_process_return_enrollment_from_port(source, fence, now)
    }
}

impl SqliteAdmissionOperationStore {
    /// The bank readback of an actual Process file inventory in one fenced
    /// native read at the issuer's trusted time.
    pub(in crate::admission_operation_store) fn verify_original_process_return_inventory_from_port(
        &self,
        inventory: &ProcessReturnInventoryDataV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ProcessReturnBankReadbackDataV1, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        verify_trusted_time(&tx, now)?;
        let readback =
            crate::admission_operation_store::recovery::storage::process_return_bank_readback(
                &tx,
                &fence.store_uuid,
                inventory,
            )?;
        tx.commit().map_err(sqlite_error)?;
        Ok(readback)
    }

    /// One original Process current write under the held native mutation
    /// sequencer. The concrete journal writer's whole file inventory is read
    /// back against the native bank, the bank proof is minted in this scope,
    /// and the writer revalidates and commits under that proof.
    pub(in crate::admission_operation_store) fn commit_original_process_current_write_from_port(
        &self,
        provider: &dyn chio_kernel::native_finishing::NativeProcessCurrentWriteProvider,
        issuer: &chio_kernel::native_finishing::NativeProcessBankProofIssuer<'_>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        issuer.require_scoped_owner(self, fence, now)?;
        let write = provider
            .as_any()
            .downcast_ref::<chio_process::native_return_custody::ProcessNativeCurrentWrite>()
            .ok_or_else(|| {
                invalid("Process current writes accept only the concrete journal writer")
            })?;
        let inventory = write
            .inventory()
            .map_err(|error| invalid(format!("Process journal inventory refused: {error}")))?;
        issuer.require_process_authority(&inventory.journal_authority)?;
        self.verify_process_enrollment_inverse(write, &inventory, fence, now)?;
        let port = FinishingCustodyPort { store: self };
        let bank = issuer.verify_in_current_writer(self, &port, &inventory)?;
        issuer.require_scoped_bank(&bank, &inventory)?;
        write
            .execute(&bank)
            .map_err(|error| invalid(format!("Process current write refused: {error}")))
    }

    /// Authenticate the complete Process enrollment inverse before a current
    /// write. A crash can leave a committed Process enrollment while its
    /// native account is still Prepared. Confirm only that authentic enrollment
    /// in the existing native state machine before minting the bank proof.
    /// Absent Prepared accounts keep their debt until an authentic compensated
    /// terminal proves that neither dispatch nor enrollment can follow.
    fn verify_process_enrollment_inverse(
        &self,
        write: &chio_process::native_return_custody::ProcessNativeCurrentWrite,
        inventory: &ProcessReturnInventoryDataV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        verify_trusted_time(&tx, now)?;
        let mut last_sequence = 0_u64;
        let mut changed = false;
        let streamed = write.verify_retained_enrollments(
            inventory,
            |source, funding, account_digest, sequence, event_digest| {
                if sequence <= last_sequence {
                    return Err(unavailable());
                }
                last_sequence = sequence;
                let retained =
                    load_native_finishing_account_for_source(&tx, &source_digest(source)?)?
                        .ok_or_else(unavailable)?;
                let account = &retained.account;
                if !account
                    .identity
                    .process
                    .as_ref()
                    .is_some_and(|member| member.source == *source)
                    || funding_data(&tx, account)? != *funding
                    || funding.process_account_digest != account_digest
                {
                    return Err(unavailable());
                }
                let actual = NativeFinishingProcessEnrollmentV1 {
                    account_digest: account_digest.to_owned(),
                    event_sequence: sequence,
                    event_digest: event_digest.to_owned(),
                };
                match (&account.process_enrollment, account.state) {
                    (None, NativeFinishingStateV1::Prepared) => {
                        let next = account.confirming(Some(actual))?;
                        persist_native_finishing_transition(
                            &tx,
                            &self.serving_owner,
                            &retained,
                            &next,
                        )?;
                        changed = true;
                    }
                    (
                        Some(recorded),
                        NativeFinishingStateV1::Confirmed | NativeFinishingStateV1::Settled,
                    ) if *recorded == actual => (),
                    _ => return Err(unavailable()),
                }
                Ok(())
            },
        )?;
        let lending =
            crate::admission_operation_store::recovery::storage::process_file_enrollments(
                &tx, inventory,
            )?;
        if streamed != lending.enrolled {
            return Err(unavailable());
        }
        // All actual enrollments were authenticated above. The native
        // sequencer stays held through this readback and the concrete Process
        // writer, so a new enrollment cannot race the terminal release.
        for operation in lending.unconfirmed {
            let retained =
                load_native_finishing_account(&tx, &operation)?.ok_or_else(unavailable)?;
            let id = operation_id(&retained.account)?;
            let stored = load_by_operation_id_tx(&tx, &id)?.ok_or_else(unavailable)?;
            if stored.operation.state() != AdmissionOperationState::CompensatedBeforeDispatch {
                continue;
            }
            let completed: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM main.admission_operation_terminal_projections
                 WHERE operation_id=?1 AND terminal_state='compensated_before_dispatch'
                 AND terminal_operation_version=?2)
                 AND NOT EXISTS(SELECT 1 FROM main.tool_outcomes WHERE operation_id=?1)
                 AND NOT EXISTS(SELECT 1 FROM main.admission_operation_terminal_records
                 WHERE operation_id=?1 AND record_kind='receipt')",
                    params![
                        operation,
                        i64::try_from(stored.operation.version()).map_err(|_| unavailable())?
                    ],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if !completed
                || stored.operation.dispatch_commit().is_some()
                || stored.operation.tool_outcome_id().is_some()
            {
                return Err(unavailable());
            }
            let next = retained.account.settling()?;
            persist_native_finishing_transition(&tx, &self.serving_owner, &retained, &next)?;
            changed = true;
        }
        if changed {
            self.commit_write(tx)?;
            self.sync_after_write(&connection)?;
        } else {
            tx.rollback().map_err(sqlite_error)?;
        }
        Ok(())
    }

    pub(in crate::admission_operation_store) fn verify_original_process_return_enrollment_from_port(
        &self,
        source: &ProcessReturnSourceDataV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ProcessReturnFundingDataV1, AdmissionOperationStoreError> {
        self.read_process_custody(source, fence, now, |tx, retained| {
            if retained.account.state == NativeFinishingStateV1::Settled {
                return Err(unavailable());
            }
            funding_data(tx, &retained.account)
        })
    }

    pub(in crate::admission_operation_store) fn verify_original_process_nonce_custody_from_port(
        &self,
        source: &ProcessReturnSourceDataV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ProcessOriginalNonceCustodyDataV1, AdmissionOperationStoreError> {
        self.read_process_custody(source, fence, now, |tx, retained| {
            let account = &retained.account;
            if account.state != NativeFinishingStateV1::Confirmed || !source.original_nonce_pending
            {
                return Err(unavailable());
            }
            let funding = funding_data(tx, account)?;
            let stored = load_by_operation_id_tx(tx, &operation_id(account)?)?
                .ok_or_else(unavailable)?;
            let reservation =
                crate::admission_operation_store::execution_nonce::issuance::verify(
                    tx,
                    &stored.operation,
                )?
                .ok_or_else(unavailable)?;
            let (issuance, snapshot): (Vec<u8>, Vec<u8>) = tx
                .query_row(
                    "SELECT issuance_json,operation_json FROM main.admission_execution_nonce_issuances
                     WHERE operation_id=?1",
                    [account.identity.operation_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(sqlite_error)?;
            if issuance != reservation.canonical_bytes() {
                return Err(unavailable());
            }
            let issued = AdmissionOperationV1::from_persisted(
                serde_json::from_slice(&snapshot).map_err(invalid)?,
            )?;
            Ok(ProcessOriginalNonceCustodyDataV1 {
                schema: PROCESS_ORIGINAL_NONCE_CUSTODY_SCHEMA.to_owned(),
                process_source_digest: funding.process_source_digest.clone(),
                process_account_digest: funding.process_account_digest.clone(),
                original_nonce_source_digest: sha256_hex(&issuance),
                original_nonce_sequence: admission_version_commit(
                    tx,
                    &account.identity.operation_id,
                    issued.version(),
                )?,
                original_nonce_sequence_domain:
                    NativeReturnSequenceDomainDataV1::AuthorityGlobalCommit,
                original_nonce: reservation.signed_nonce().clone(),
                native_funding: funding,
            })
        })
    }

    pub(in crate::admission_operation_store) fn verify_original_process_return_capture_from_port(
        &self,
        source: &ProcessReturnSourceDataV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ProcessNativeReturnCaptureDataV1, AdmissionOperationStoreError> {
        self.read_process_custody(source, fence, now, |tx, retained| {
            capture_receipt(tx, &retained.account)
        })
    }

    pub(in crate::admission_operation_store) fn verify_original_process_return_reconciliation_from_port(
        &self,
        source: &ProcessReturnSourceDataV1,
        final_receipt_digest: &str,
        final_sequence: u64,
        final_event_digest: &str,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ProcessReturnReconciliationDataV1, AdmissionOperationStoreError> {
        self.read_process_custody(source, fence, now, |tx, retained| {
            let account = &retained.account;
            let capture = capture_receipt(tx, account)?;
            if digest_of(&capture)? != final_receipt_digest {
                return Err(unavailable());
            }
            let (reconciliation_digest, reconciliation_sequence) = native_finishing_version_commit(
                tx,
                &account.identity.operation_id,
                retained.version,
            )?;
            let native_file = account
                .identity
                .files
                .iter()
                .find(|file| file.role == NativeFinishingFileRoleV1::Native)
                .ok_or_else(unavailable)?;
            let (bank_epoch, _, _) = crate::admission_operation_store::recovery::storage::native_finishing_bank_readback(
                tx,
                &account.identity.store_uuid,
                native_file,
            )?;
            Ok(ProcessReturnReconciliationDataV1 {
                schema: PROCESS_RETURN_RECONCILIATION_SCHEMA.to_owned(),
                process_source_digest: capture.process_source_digest.clone(),
                process_account_digest: capture.process_account_digest.clone(),
                process_final_receipt_digest: final_receipt_digest.to_owned(),
                process_final_event_sequence: final_sequence,
                process_final_event_digest: final_event_digest.to_owned(),
                native_account_digest: capture.native_funding.native_account_digest.clone(),
                native_reconciliation_sequence: reconciliation_sequence,
                native_reconciliation_sequence_domain:
                    NativeReturnSequenceDomainDataV1::AuthorityGlobalCommit,
                native_reconciliation_digest: reconciliation_digest,
                native_bank_epoch: bank_epoch,
            })
        })
    }

    fn read_process_custody<T>(
        &self,
        source: &ProcessReturnSourceDataV1,
        fence: &StoreMutationFence,
        now: u64,
        f: impl FnOnce(
            &Transaction<'_>,
            &RetainedNativeFinishingAccount,
        ) -> Result<T, AdmissionOperationStoreError>,
    ) -> Result<T, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        verify_trusted_time(&tx, now)?;
        let retained = load_native_finishing_account_for_source(&tx, &source_digest(source)?)?
            .ok_or_else(unavailable)?;
        let member = retained
            .account
            .identity
            .process
            .as_ref()
            .ok_or_else(unavailable)?;
        if member.source != *source {
            return Err(unavailable());
        }
        let value = f(&tx, &retained)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(value)
    }
}

/// The exact original fate retained by the native terminal projection.
/// An operation without a terminal projection has no fate yet.
fn capture_receipt(
    tx: &Transaction<'_>,
    account: &NativeFinishingAccountV1,
) -> Result<ProcessNativeReturnCaptureDataV1, AdmissionOperationStoreError> {
    if account.state != NativeFinishingStateV1::Confirmed
        && account.state != NativeFinishingStateV1::Settled
    {
        return Err(unavailable());
    }
    let funding = funding_data(tx, account)?;
    let operation_id = account.identity.operation_id.as_str();
    let (state, projection_digest, version): (String, String, i64) = tx
        .query_row(
            "SELECT terminal_state,projection_digest,terminal_operation_version
             FROM main.admission_operation_terminal_projections WHERE operation_id=?1",
            [operation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(unavailable)?;
    let version = stored_u64(version, "native terminal version")?;
    let fate = match state.as_str() {
        "completed" | "denied_after_delivery" => {
            let stored = load_by_operation_id_tx(tx, &self::operation_id(account)?)?
                .ok_or_else(unavailable)?;
            let outcome_id = stored
                .operation
                .tool_outcome_id()
                .ok_or_else(unavailable)?
                .as_str()
                .to_owned();
            let dispatch = stored.operation.dispatch_commit().ok_or_else(unavailable)?;
            let raw_output_digest: String = tx
                .query_row(
                    "SELECT raw_output_digest FROM main.tool_outcomes WHERE operation_id=?1",
                    [operation_id],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            let receipt_digest: String = tx
                .query_row(
                    "SELECT record_digest FROM main.admission_operation_terminal_records
                     WHERE operation_id=?1 AND record_kind='receipt'",
                    [operation_id],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            ProcessOriginalReturnFateDataV1::Captured {
                outcome_id,
                raw_output_digest,
                original_dispatch_commit_digest: digest_of(dispatch)?,
                original_outcome_receipt_digest: receipt_digest,
            }
        }
        "outcome_unknown_after_dispatch" => {
            // This is a witness about the original native RETURN, not about
            // whether its external effect occurred. Unknown is an immutable
            // terminal state: no supported transition can accept a later raw
            // return. Workflow finality and economic holds remain separate.
            let stored = load_by_operation_id_tx(tx, &self::operation_id(account)?)?
                .ok_or_else(unavailable)?;
            let raw_exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM main.tool_outcomes WHERE operation_id=?1)",
                    [operation_id],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if stored.operation.state() != AdmissionOperationState::OutcomeUnknownAfterDispatch
                || stored.operation.version() != version
                || stored.operation.dispatch_commit().is_none()
                || stored.operation.tool_outcome_id().is_some()
                || raw_exists
            {
                return Err(unavailable());
            }
            ProcessOriginalReturnFateDataV1::NoFutureReturn {
                original_no_future_return_digest: projection_digest.clone(),
            }
        }
        "compensated_before_dispatch" | "not_accepted_after_dispatch_commit" => {
            ProcessOriginalReturnFateDataV1::NoFutureReturn {
                original_no_future_return_digest: projection_digest.clone(),
            }
        }
        _ => return Err(unavailable()),
    };
    Ok(ProcessNativeReturnCaptureDataV1 {
        schema: PROCESS_RETURN_CAPTURE_SCHEMA.to_owned(),
        process_source_digest: funding.process_source_digest.clone(),
        process_account_digest: funding.process_account_digest.clone(),
        native_capture_sequence: admission_version_commit(tx, operation_id, version)?,
        native_capture_sequence_domain: NativeReturnSequenceDomainDataV1::AuthorityGlobalCommit,
        native_capture_digest: projection_digest,
        fate,
        native_funding: funding,
    })
}

/// The global commit of the first admission commit at one operation version.
fn admission_version_commit(
    tx: &Connection,
    operation_id: &str,
    version: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    let sequence: i64 = tx
        .query_row(
            "SELECT g.commit_sequence FROM main.admission_operation_commits AS c
             JOIN main.authority_global_commits AS g
               ON g.projection_kind='admission' AND g.projection_key=c.operation_id
              AND g.projection_sequence=c.commit_sequence
             WHERE c.operation_id=?1 AND c.operation_version=?2
             ORDER BY c.commit_sequence LIMIT 1",
            params![operation_id, i64::try_from(version).map_err(invalid)?],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    stored_u64(sequence, "native admission global commit")
}

fn operation_id(
    account: &NativeFinishingAccountV1,
) -> Result<AdmissionOperationId, AdmissionOperationStoreError> {
    Ok(AdmissionOperationId::from_persisted(
        account.identity.operation_id.clone(),
    )?)
}

fn unavailable() -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Unavailable(
        "original funded Process custody is not yet available".into(),
    )
}
