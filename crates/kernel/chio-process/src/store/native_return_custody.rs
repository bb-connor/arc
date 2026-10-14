//! Source-owned second-database return accounting. Activation is the owning
//! enrollment transaction: no source DATA, price, account or proof can install
//! the bank; only a genuinely funded enrollment does.
use super::*;
use crate::binding::ProcessCallBinding;
use crate::ProcessRuntime;
use chio_kernel::process_return_custody::{
    FundedProcessNativeReturn, FundedProcessOriginalNonce, FundedProcessReturnEnrollment,
    ProcessNativeReturnCaptureDataV1, ProcessReturnFundingDataV1, ProcessReturnInventoryDataV1,
    ProcessReturnSourceDataV1, ProcessReturnUnavailableReasonDataV1, ReconciledProcessNativeReturn,
    VerifiedProcessReturnBank, MAX_PROCESS_RETURN_SOURCE_BYTES, PROCESS_RETURN_SOURCE_SCHEMA,
    PROCESS_RETURN_UNAVAILABLE_SCHEMA,
};
use chio_sqlite_file_identity::{
    require_physical_write_capacity, SqlitePhysicalDebtAmountData, SqliteWriteCapacityStageData,
};
use rusqlite::Transaction;

mod catalog;
mod cohort;
mod layout;
#[cfg(test)]
mod layout_tests;
mod pricing;
mod rows;
mod source;
pub(super) use layout::classify;
pub(crate) use layout::{LayoutSource, StartupPlan};
pub use pricing::ProcessFinishingTransactionPriceData;
pub use rows::{
    ProcessReturnRowEnvelopeData, ProcessReturnTableData, ProcessReturnTransactionData,
};

/// Cold open-time authentication of the retained cohort for the Store open
/// owner. Forwards to the owning cohort module; it writes and repairs nothing:
/// a version-eight journal with an absent, incomplete or forged cohort
/// refuses, and cohort artifacts refuse before their version.
pub(super) fn verify_before_open(connection: &Connection) -> Result<(), ProcessError> {
    cohort::verify_before_open(connection)
}

pub(crate) const MAX_SOURCE_BYTES: usize = MAX_PROCESS_RETURN_SOURCE_BYTES;
const MAX_ACCOUNT_BYTES: usize = 32_768;
const MAX_RECEIPT_BYTES: usize = 8_192;
const MAX_EVENT_BYTES: usize = 512;
const MAX_ACTIVE_ACCOUNTS: u64 = 64;

/// This opaque producer capsule describes original source DATA. Its cut must
/// be revalidated inside the actual source transaction before native pricing.
/// It is not a bank allowance, permission to capture or retirement evidence.
pub(crate) struct PreparedProcessReturnSource {
    data: ProcessReturnSourceDataV1,
    bytes: Vec<u8>,
    profile: catalog::ProcessWriteProfileData,
    kernel_key: String,
    path: std::path::PathBuf,
    prepared_connection: usize,
    prepared_total_changes: u64,
    rows_digest: String,
}
impl PreparedProcessReturnSource {
    pub(crate) fn data(&self) -> &ProcessReturnSourceDataV1 {
        &self.data
    }
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn profile(&self) -> &catalog::ProcessWriteProfileData {
        &self.profile
    }
}
impl core::fmt::Debug for PreparedProcessReturnSource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PreparedProcessReturnSource([redacted])")
    }
}

/// Borrowed inputs for validating an original call's native return source.
/// Grouping them does not authenticate them; `verify_source_request` checks
/// their binding against the owning runtime and journal.
pub(crate) struct NativeReturnSourceRequest<'a> {
    pub(crate) process_id: &'a str,
    pub(crate) operation_key: &'a str,
    pub(crate) request: &'a ToolCallRequest,
    pub(crate) binding: &'a ProcessCallBinding,
    pub(crate) known_outcome_only: bool,
    pub(crate) security_context: Option<&'a chio_kernel::SecurityInvocationContext>,
}

impl Store {
    pub(crate) fn inspect_original_return_finishing_prices(
        &mut self,
        source: &PreparedProcessReturnSource,
    ) -> Result<Vec<ProcessFinishingTransactionPriceData>, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prices = pricing::price_future_finishing_transactions(&tx, source)?;
        tx.rollback()?;
        Ok(prices)
    }

    /// The actual original source entry. The request is authenticated against
    /// the owning runtime and journal first; the source is then cut inside the
    /// live journal transaction from its real profile, rows and nonce slot.
    pub(crate) fn prepare_native_return_source(
        &mut self,
        runtime: &ProcessRuntime,
        selection: &NativeReturnSourceRequest<'_>,
    ) -> Result<PreparedProcessReturnSource, ProcessError> {
        source::verify_source_request(self, runtime, selection)?;
        let NativeReturnSourceRequest {
            process_id,
            operation_key,
            request,
            binding,
            known_outcome_only,
            security_context,
        } = selection;
        // Attempt-independent logical identity of the operation.
        let logical_request_digest = {
            let mut logical = (*request).clone();
            logical.request_id = runtime.request_id(process_id, operation_key)?;
            digest(&logical)?
        };
        let host_profile_digest = match runtime.security_profile.as_ref() {
            Some(profile) => Some(digest(profile)?),
            None => None,
        };
        let host_route_digest = match runtime.routes.get(&request.server_id) {
            Some(route) => Some(digest(route)?),
            None => None,
        };
        let launch_receipt_digest = match runtime.launch_receipts.get(&request.server_id) {
            Some(receipt) => Some(digest(receipt)?),
            None => None,
        };
        let security_context_digest = match security_context {
            Some(context) => {
                let bytes = chio_core_types::canonical_json_bytes(context)
                    .map_err(|_| ProcessError::Conflict)?;
                Some(digest(&bytes)?)
            }
            None => None,
        };
        let address = std::ptr::from_ref(&self.connection) as usize;
        let total_changes = self.connection.total_changes();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (authority, kernel_key): (String, String) = tx.query_row(
            "SELECT authority,kernel_key FROM main.process_runtime WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let profile = catalog::prepare_active_profile(
            &tx,
            &self.path,
            &self.namespace,
            &authority,
            &kernel_key,
        )?;
        let (stored_binding, attempt): (String, u32) = tx.query_row(
            "SELECT request_hash,attempts FROM main.process_calls WHERE process_id=?1 AND operation_key=?2",
            params![process_id, operation_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if stored_binding != binding.binding_hash
            || !(1..=crate::MAX_DISPATCH_ATTEMPTS).contains(&attempt)
        {
            return Err(ProcessError::Conflict);
        }
        let process = read_process(&tx, process_id)?
            .ok_or_else(|| ProcessError::NotFound(process_id.to_string()))?;
        require_running(&process)?;
        let nonce: Option<Vec<u8>> = tx
            .query_row(
                "SELECT CASE WHEN typeof(nonce_json)='blob' AND length(nonce_json) BETWEEN 1 AND 16384 THEN nonce_json END
                 FROM main.process_call_nonces WHERE process_id=?1 AND operation_key=?2 AND attempt=?3",
                params![process_id, operation_key, attempt],
                |row| row.get(0),
            )
            .optional()?;
        let (original_nonce_pending, original_nonce_digest) = match &nonce {
            Some(bytes) => (false, Some(chio_core_types::crypto::sha256_hex(bytes))),
            None => (true, None),
        };
        let request_id = runtime.request_id_for_attempt(process_id, operation_key, attempt)?;
        if request.request_id != request_id {
            return Err(ProcessError::Conflict);
        }
        let mut data = ProcessReturnSourceDataV1 {
            schema: PROCESS_RETURN_SOURCE_SCHEMA.to_owned(),
            journal_namespace: self.namespace.clone(),
            journal_authority: authority,
            kernel_key_digest: digest(&kernel_key)?,
            file_device: profile.file_device(),
            file_inode: profile.file_inode(),
            catalog_digest: profile.catalog_digest().to_owned(),
            cut_digest: String::new(),
            process_id: process_id.to_string(),
            root_process_id: process.root_id.clone(),
            operation_key: operation_key.to_string(),
            request_id,
            attempt,
            logical_request_digest,
            call_binding_digest: binding.binding_hash.clone(),
            current_request_digest: binding.request_hash.clone(),
            capability_digest: digest(&process.capability)?,
            known_outcome_only: *known_outcome_only,
            host_profile_digest,
            host_route_digest,
            launch_receipt_digest,
            security_context_digest,
            original_nonce_pending,
            original_nonce_digest,
        };
        let rows_digest = source::source_row_digest(&tx, &data)?;
        data.cut_digest = rows_digest.clone();
        let bytes =
            chio_kernel::process_return_custody::canonical_process_return_source_data(&data)
                .map_err(|_| ProcessError::Conflict)?;
        tx.commit()?;
        Ok(PreparedProcessReturnSource {
            data,
            bytes,
            profile,
            kernel_key,
            path: self.path.clone(),
            prepared_connection: address,
            prepared_total_changes: total_changes,
            rows_digest,
        })
    }

    /// Retain the genuinely funded original account. The enrollment installs
    /// the retained bank family and moves the journal to version eight at the
    /// first account, preserves the exact prepared source and the verified
    /// native funding, and is exactly-once: replaying the same original
    /// identity with the same proof verifies the recorded row, funding and
    /// enrolled event and writes nothing. Later restart, cancel, checkpoint
    /// or nonce progress never invalidates the retained original.
    pub(crate) fn enroll_funded_native_return(
        &mut self,
        source: &PreparedProcessReturnSource,
        funding: FundedProcessReturnEnrollment,
    ) -> Result<RetainedProcessReturnAccount, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Replay lookup runs only when the retained family is already
        // installed. An absent family cannot hold any retained account: its
        // tables never existed and its rows cannot be deleted, so this is not
        // an absence-read-as-zero-debt path. An existing family is verified,
        // never rebuilt, before any replay is trusted.
        if cohort::family_present(&tx)? {
            cohort::verify_cohort(&tx)?;
            if let Some(existing) = cohort::account_row_by_call(
                &tx,
                &source.data().process_id,
                &source.data().operation_key,
                source.data().attempt,
            )? {
                // Exactly-once replay: the recorded row, funding and enrolled
                // event are re-authenticated against this journal's immutable
                // original identity; mutable progress never takes part. Any
                // other funding for this original call or its native
                // operation refuses.
                let envelope = cohort::verify_account_row(&tx, &existing)?;
                if !same_recorded_identity(envelope.source(), source.data()) {
                    return Err(ProcessError::Conflict);
                }
                // Funding names the original retained cut, not the current
                // journal position after its enrollment. Authenticate that row
                // before consuming the proof against its immutable source.
                let funding = funding
                    .consume_for(envelope.source())
                    .map_err(|_| ProcessError::Conflict)?;
                let bytes =
                    cohort::AccountEnvelope::encode(envelope.source().clone(), funding.clone())?;
                let funding_bytes = crate::canonical_json_bytes(&funding)?;
                if existing.account_digest != funding.process_account_digest
                    || existing.bytes != bytes
                    || cohort::account_row_by_native_operation(&tx, &funding.native_operation_id)?
                        .as_ref()
                        .is_none_or(|row| row.account_digest != funding.process_account_digest)
                {
                    return Err(ProcessError::Conflict);
                }
                let event = cohort::phase_event(&tx, &funding.process_account_digest, "enrolled")?
                    .ok_or(ProcessError::Conflict)?;
                if chio_core_types::crypto::sha256_hex(&bytes) != event.2 {
                    return Err(ProcessError::Conflict);
                }
                tx.commit()?;
                return Ok(RetainedProcessReturnAccount {
                    source: envelope.source().clone(),
                    account_digest: funding.process_account_digest.clone(),
                    funding,
                    account_bytes: bytes,
                    funding_bytes,
                    original_event_sequence: event.0,
                    original_event_digest: event.1,
                });
            }
        }
        // First enrollment: the prepared source must still be the exact fresh
        // cut of this uncommitted preparation. A changed preparation refuses
        // rather than silently refreshing its own authority. This runs before
        // family activation so the fresh cut is authenticated against the
        // journal's actual current recipe, predecessor or installed cohort.
        source::verify_retained_source(&tx, source)?;
        let funding = funding
            .consume_for(source.data())
            .map_err(|_| ProcessError::Conflict)?;
        let bytes = cohort::AccountEnvelope::encode(source.data().clone(), funding.clone())?;
        let funding_bytes = crate::canonical_json_bytes(&funding)?;
        // Activate the retained family only inside this same atomic
        // enrollment: the account row, its frontier event and the version
        // commit together or not at all.
        cohort::activate(&tx)?;
        if cohort::account_row_by_native_operation(&tx, &funding.native_operation_id)?.is_some()
            || cohort::account_row(&tx, &funding.process_account_digest)?.is_some()
            || cohort::phase_event(&tx, &funding.process_account_digest, "enrolled")?.is_some()
        {
            return Err(ProcessError::Conflict);
        }
        let changed = tx.execute(
            "INSERT INTO process_native_return_accounts
             (account_digest,process_id,operation_key,attempt,native_operation_id,account_json)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                funding.process_account_digest,
                source.data().process_id,
                source.data().operation_key,
                source.data().attempt,
                funding.native_operation_id,
                bytes
            ],
        )?;
        if changed != 1 {
            return Err(ProcessError::Conflict);
        }
        let (sequence, event_digest) =
            cohort::append_event(&tx, &funding.process_account_digest, "enrolled", &bytes)?;
        cohort::require_version_eight(&tx)?;
        cohort::verify_cohort(&tx)?;
        tx.commit()?;
        Ok(RetainedProcessReturnAccount {
            source: source.data().clone(),
            account_digest: funding.process_account_digest.clone(),
            funding,
            account_bytes: bytes,
            funding_bytes,
            original_event_sequence: sequence,
            original_event_digest: event_digest,
        })
    }

    /// Retain the funded original nonce custody of the original attempt. The
    /// actual original nonce slot is filled with the custody nonce exactly
    /// once; a different retained nonce refuses.
    pub(crate) fn retain_funded_original_nonce(
        &mut self,
        original_account: &RetainedProcessReturnAccount,
        nonce: FundedProcessOriginalNonce,
    ) -> Result<(), ProcessError> {
        let receipt = nonce
            .consume_for(&original_account.source)
            .map_err(|_| ProcessError::Conflict)?;
        let funding_bytes = crate::canonical_json_bytes(&receipt.native_funding)?;
        if funding_bytes != original_account.funding_bytes
            || receipt.process_account_digest != original_account.account_digest
        {
            #[cfg(feature = "admission-test-support")]
            eprintln!(
                "native custody funding mismatch: bytes={} identity={}",
                funding_bytes == original_account.funding_bytes,
                receipt.process_account_digest == original_account.account_digest
            );
            return Err(ProcessError::Conflict);
        }
        let nonce_bytes = crate::canonical_json_bytes(&receipt.original_nonce)?;
        if nonce_bytes.is_empty() || nonce_bytes.len() > 16_384 {
            return Err(ProcessError::Limit("original execution nonce"));
        }
        let bytes = crate::canonical_json_bytes(&receipt)?;
        if bytes.is_empty() || bytes.len() > MAX_ACCOUNT_BYTES {
            return Err(ProcessError::Limit("original nonce custody receipt"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        cohort::verify_cohort(&tx)?;
        verify_retained_account(&tx, original_account)?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT nonce_receipt_json FROM process_native_return_nonce_receipts
                 WHERE account_digest=?1",
                params![original_account.account_digest],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != bytes {
                return Err(ProcessError::Conflict);
            }
            let event =
                cohort::phase_event(&tx, &original_account.account_digest, "nonce_retained")?
                    .ok_or(ProcessError::Conflict)?;
            if chio_core_types::crypto::sha256_hex(&bytes) != event.2 {
                return Err(ProcessError::Conflict);
            }
            cohort::verify_cohort(&tx)?;
            tx.commit()?;
            return Ok(());
        }
        let slot: Option<Vec<u8>> = tx
            .query_row(
                "SELECT nonce_json FROM main.process_call_nonces
                 WHERE process_id=?1 AND operation_key=?2 AND attempt=?3",
                params![
                    original_account.source.process_id,
                    original_account.source.operation_key,
                    original_account.source.attempt
                ],
                |row| row.get(0),
            )
            .optional()?;
        match slot {
            Some(slot) => {
                if slot != nonce_bytes {
                    return Err(ProcessError::Conflict);
                }
            }
            None => {
                let changed = tx.execute(
                    "INSERT INTO main.process_call_nonces
                     (process_id,operation_key,attempt,nonce_json) VALUES(?1,?2,?3,?4)",
                    params![
                        original_account.source.process_id,
                        original_account.source.operation_key,
                        original_account.source.attempt,
                        nonce_bytes
                    ],
                )?;
                if changed != 1 {
                    return Err(ProcessError::Conflict);
                }
            }
        }
        let changed = tx.execute(
            "INSERT INTO process_native_return_nonce_receipts(account_digest,nonce_receipt_json)
             VALUES(?1,?2)",
            params![original_account.account_digest, bytes],
        )?;
        if changed != 1 {
            return Err(ProcessError::Conflict);
        }
        cohort::append_event(
            &tx,
            &original_account.account_digest,
            "nonce_retained",
            &bytes,
        )?;
        cohort::verify_cohort(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// Retain the account's single prepaid unavailability notice. It neither
    /// retires the account nor drops any later output debt.
    pub(crate) fn retain_original_return_unavailable(
        &mut self,
        original_account: &RetainedProcessReturnAccount,
        reason: ProcessReturnUnavailableReasonDataV1,
    ) -> Result<(), ProcessError> {
        let source_bytes =
            chio_kernel::process_return_custody::canonical_process_return_source_data(
                &original_account.source,
            )
            .map_err(|_| ProcessError::Conflict)?;
        let notice = chio_kernel::process_return_custody::ProcessReturnUnavailableDataV1 {
            schema: PROCESS_RETURN_UNAVAILABLE_SCHEMA.to_owned(),
            process_source_digest: chio_core_types::crypto::sha256_hex(&source_bytes),
            process_account_digest: original_account.account_digest.clone(),
            native_operation_id: original_account.funding.native_operation_id.clone(),
            reason,
        };
        let bytes = crate::canonical_json_bytes(&notice)?;
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err(ProcessError::Limit("native return notice"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        cohort::verify_cohort(&tx)?;
        verify_retained_account(&tx, original_account)?;
        if cohort::phase_event(&tx, &original_account.account_digest, "native_custody")?.is_some() {
            return Err(ProcessError::Conflict);
        }
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT notice_json FROM process_native_return_notices WHERE account_digest=?1",
                params![original_account.account_digest],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != bytes {
                return Err(ProcessError::Conflict);
            }
            let event = cohort::phase_event(&tx, &original_account.account_digest, "unavailable")?
                .ok_or(ProcessError::Conflict)?;
            if chio_core_types::crypto::sha256_hex(&bytes) != event.2 {
                return Err(ProcessError::Conflict);
            }
            cohort::verify_cohort(&tx)?;
            tx.commit()?;
            return Ok(());
        }
        let changed = tx.execute(
            "INSERT INTO process_native_return_notices(account_digest,notice_json) VALUES(?1,?2)",
            params![original_account.account_digest, bytes],
        )?;
        if changed != 1 {
            return Err(ProcessError::Conflict);
        }
        cohort::append_event(&tx, &original_account.account_digest, "unavailable", &bytes)?;
        cohort::verify_cohort(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// Retain the genuine native capture custody of the original attempt. The
    /// retained fate must carry the account's exact prepaid funding; a decoded
    /// response or a different funding refuses. Exactly-once replay returns
    /// the same retained receipt and writes nothing.
    pub(crate) fn record_funded_native_return(
        &mut self,
        original_account: &RetainedProcessReturnAccount,
        capture: FundedProcessNativeReturn,
    ) -> Result<RetainedProcessReturnReceipt, ProcessError> {
        let receipt = capture
            .consume_for(&original_account.source)
            .map_err(|_| ProcessError::Conflict)?;
        let funding_bytes = crate::canonical_json_bytes(&receipt.native_funding)?;
        if funding_bytes != original_account.funding_bytes
            || receipt.process_account_digest != original_account.account_digest
        {
            return Err(ProcessError::Conflict);
        }
        let bytes = crate::canonical_json_bytes(&receipt)?;
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err(ProcessError::Limit("native return custody fate"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        cohort::verify_cohort(&tx)?;
        verify_retained_account(&tx, original_account)?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT fate_json FROM process_native_return_fates WHERE account_digest=?1",
                params![original_account.account_digest],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != bytes {
                return Err(ProcessError::Conflict);
            }
            let event =
                cohort::phase_event(&tx, &original_account.account_digest, "native_custody")?
                    .ok_or(ProcessError::Conflict)?;
            if chio_core_types::crypto::sha256_hex(&bytes) != event.2 {
                return Err(ProcessError::Conflict);
            }
            cohort::verify_cohort(&tx)?;
            tx.commit()?;
            return Ok(RetainedProcessReturnReceipt {
                account_digest: original_account.account_digest.clone(),
                receipt,
                receipt_bytes: bytes,
                final_event_sequence: event.0,
                final_event_digest: event.1,
            });
        }
        let changed = tx.execute(
            "INSERT INTO process_native_return_fates(account_digest,fate_json) VALUES(?1,?2)",
            params![original_account.account_digest, bytes],
        )?;
        if changed != 1 {
            return Err(ProcessError::Conflict);
        }
        let (sequence, event_digest) = cohort::append_event(
            &tx,
            &original_account.account_digest,
            "native_custody",
            &bytes,
        )?;
        cohort::verify_cohort(&tx)?;
        tx.commit()?;
        Ok(RetainedProcessReturnReceipt {
            account_digest: original_account.account_digest.clone(),
            receipt,
            receipt_bytes: bytes,
            final_event_sequence: sequence,
            final_event_digest: event_digest,
        })
    }

    /// Close the funded return with the native reconciliation of the exact
    /// retained final receipt and its frontier event. Exactly-once replay of
    /// the same reconciliation writes nothing.
    pub(crate) fn reconcile_funded_native_return(
        &mut self,
        original_account: &RetainedProcessReturnAccount,
        final_receipt: &RetainedProcessReturnReceipt,
        reconciliation: ReconciledProcessNativeReturn,
    ) -> Result<(), ProcessError> {
        if final_receipt.account_digest != original_account.account_digest {
            // A receipt retained for another account never closes this one.
            return Err(ProcessError::Conflict);
        }
        let final_receipt_digest =
            chio_core_types::crypto::sha256_hex(&final_receipt.receipt_bytes);
        let receipt = reconciliation
            .consume_for(
                &original_account.source,
                &final_receipt_digest,
                final_receipt.final_event_sequence,
                &final_receipt.final_event_digest,
            )
            .map_err(|_| ProcessError::Conflict)?;
        if receipt.process_account_digest != original_account.account_digest
            || receipt.native_account_digest != original_account.funding.native_account_digest
            || final_receipt_digest != receipt.process_final_receipt_digest
        {
            return Err(ProcessError::Conflict);
        }
        let bytes = crate::canonical_json_bytes(&receipt)?;
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err(ProcessError::Limit("native return reconciliation"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        cohort::verify_cohort(&tx)?;
        verify_retained_account(&tx, original_account)?;
        if cohort::phase_event(&tx, &original_account.account_digest, "native_custody")?.is_none()
            || cohort::phase_event(&tx, &final_receipt.account_digest, "native_custody")?.is_none()
        {
            return Err(ProcessError::Conflict);
        }
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT reconciliation_json FROM process_native_return_reconciliations
                 WHERE account_digest=?1",
                params![original_account.account_digest],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != bytes {
                return Err(ProcessError::Conflict);
            }
            let event = cohort::phase_event(&tx, &original_account.account_digest, "reconciled")?
                .ok_or(ProcessError::Conflict)?;
            if chio_core_types::crypto::sha256_hex(&bytes) != event.2 {
                return Err(ProcessError::Conflict);
            }
            cohort::verify_cohort(&tx)?;
            tx.commit()?;
            return Ok(());
        }
        let changed = tx.execute(
            "INSERT INTO process_native_return_reconciliations
             (account_digest,reconciliation_json) VALUES(?1,?2)",
            params![original_account.account_digest, bytes],
        )?;
        if changed != 1 {
            return Err(ProcessError::Conflict);
        }
        cohort::append_event(&tx, &original_account.account_digest, "reconciled", &bytes)?;
        cohort::verify_cohort(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// Load one retained account from the installed bank. The complete cohort
    /// and frontier are authenticated first; an absent bank refuses and is
    /// never read as zero debt. Read-only.
    pub(crate) fn load_native_return_account(
        &mut self,
        account_digest: &str,
    ) -> Result<Option<RetainedProcessReturnAccount>, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        cohort::verify_cohort(&tx)?;
        let Some(row) = cohort::account_row(&tx, account_digest)? else {
            tx.commit()?;
            return Ok(None);
        };
        let envelope = cohort::verify_account_row(&tx, &row)?;
        let event =
            cohort::phase_event(&tx, account_digest, "enrolled")?.ok_or(ProcessError::Conflict)?;
        if chio_core_types::crypto::sha256_hex(&row.bytes) != event.2 {
            return Err(ProcessError::Conflict);
        }
        let account = RetainedProcessReturnAccount {
            source: envelope.source().clone(),
            account_digest: row.account_digest,
            funding: envelope.funding().clone(),
            account_bytes: row.bytes,
            funding_bytes: crate::canonical_json_bytes(envelope.funding())?,
            original_event_sequence: event.0,
            original_event_digest: event.1,
        };
        tx.commit()?;
        Ok(Some(account))
    }

    /// Load the retained final custody receipt of one account. Read-only.
    pub(crate) fn load_native_return_receipt(
        &mut self,
        account: &RetainedProcessReturnAccount,
    ) -> Result<Option<RetainedProcessReturnReceipt>, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        cohort::verify_cohort(&tx)?;
        let fate: Option<Vec<u8>> = tx
            .query_row(
                "SELECT fate_json FROM process_native_return_fates WHERE account_digest=?1",
                params![account.account_digest],
                |row| row.get(0),
            )
            .optional()?;
        let Some(bytes) = fate else {
            tx.commit()?;
            return Ok(None);
        };
        let receipt: ProcessNativeReturnCaptureDataV1 =
            serde_json::from_slice(&bytes).map_err(|_| ProcessError::Conflict)?;
        if crate::canonical_json_bytes(&receipt)? != bytes
            || bytes.len() > MAX_RECEIPT_BYTES
            || receipt.process_account_digest != account.account_digest
            || crate::canonical_json_bytes(&receipt.native_funding)? != account.funding_bytes
        {
            return Err(ProcessError::Conflict);
        }
        let event = cohort::phase_event(&tx, &account.account_digest, "native_custody")?
            .ok_or(ProcessError::Conflict)?;
        if chio_core_types::crypto::sha256_hex(&bytes) != event.2 {
            return Err(ProcessError::Conflict);
        }
        let receipt = RetainedProcessReturnReceipt {
            account_digest: account.account_digest.clone(),
            receipt,
            receipt_bytes: bytes,
            final_event_sequence: event.0,
            final_event_digest: event.1,
        };
        tx.commit()?;
        Ok(Some(receipt))
    }

    /// The account's retained reconciliation event, if the funded return has
    /// closed. Read-only.
    pub(crate) fn load_native_return_reconciliation(
        &mut self,
        account: &RetainedProcessReturnAccount,
    ) -> Result<Option<(u64, String)>, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        cohort::verify_cohort(&tx)?;
        let event = cohort::phase_event(&tx, &account.account_digest, "reconciled")?;
        tx.commit()?;
        Ok(event.map(|(sequence, digest, _)| (sequence, digest)))
    }

    /// Complete current file observation consumed by the native bank readback.
    /// The complete installed cohort and frontier are authenticated first.
    /// Read-only.
    pub(crate) fn native_return_inventory(
        &mut self,
    ) -> Result<chio_kernel::process_return_custody::ProcessReturnInventoryDataV1, ProcessError>
    {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        if matches!(self.startup, StartupPlan::Genesis { .. }) {
            let inventory = layout::empty_inventory(
                &tx,
                &self.path,
                &self.namespace,
                &self.authority,
                &self.kernel_key,
            )?;
            tx.commit()?;
            return Ok(inventory);
        }
        let (authority, kernel_key): (String, String) = tx.query_row(
            "SELECT authority,kernel_key FROM main.process_runtime WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let inventory = cohort::inventory(&tx, &self.namespace, &authority, &kernel_key)?;
        tx.commit()?;
        Ok(inventory)
    }

    /// Stream every retained enrollment to the native whole-inverse verifier
    /// in one read transaction under the actual Process lock: the exact
    /// inventory is revalidated first, every authenticated canonical account
    /// and its enrolled event coordinates flow to the callback one row at a
    /// time, and the streamed count must equal the inventory's account
    /// count. Read-only; no lifetime collection. Grants no financial or
    /// invocation authority.
    pub(crate) fn verify_retained_enrollments(
        &mut self,
        inventory: &chio_kernel::process_return_custody::ProcessReturnInventoryDataV1,
        verify: impl FnMut(
            &chio_kernel::process_return_custody::ProcessReturnSourceDataV1,
            &chio_kernel::process_return_custody::ProcessReturnFundingDataV1,
            &str,
            u64,
            &str,
        )
            -> Result<(), chio_kernel::admission_operation::AdmissionOperationStoreError>,
    ) -> Result<u64, chio_kernel::admission_operation::AdmissionOperationStoreError> {
        let refused = |error: rusqlite::Error| {
            chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(format!(
                "Process enrollment stream observation refused: {error}"
            ))
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(refused)?;
        let counted = if fresh_empty_layout(&tx).map_err(|error| {
            chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(format!(
                "Process genesis enrollment layout refused: {error}"
            ))
        })? {
            stream_fresh_enrollments(
                &tx,
                inventory,
                &self.startup,
                &self.path,
                &self.namespace,
                &self.authority,
                &self.kernel_key,
            )?
        } else {
            cohort::stream_enrollments(&tx, inventory, verify)?
        };
        tx.commit().map_err(refused)?;
        if counted != inventory.account_count {
            return Err(
                chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(
                    "Process streamed enrollment count diverged from its inventory".to_owned(),
                ),
            );
        }
        Ok(counted)
    }
}

/// The exact empty genesis layout of the live file: no user object exists at
/// all. A schema holding objects without the runtime table is torn, foreign
/// or tampered and never reaches the enrollment stream.
fn fresh_empty_layout(tx: &rusqlite::Transaction<'_>) -> Result<bool, ProcessError> {
    let objects: i64 = tx.query_row(
        "SELECT count(*) FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects == 0 {
        return Ok(true);
    }
    let runtime_present: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type='table' AND name='process_runtime')",
        [],
        |row| row.get(0),
    )?;
    if runtime_present {
        return Ok(false);
    }
    Err(ProcessError::Conflict)
}

/// The genesis enrollment stream: the native owner authenticates expected
/// absence from actual file content. Only the journal's own genesis startup
/// may present an empty file, the file must hold no user object, and the
/// genesis inventory recomputed from the live empty file must be exactly the
/// inventory the native proof was minted from. Zero enrollments are then a
/// measured fact of that revalidated file, never an inference from a missing
/// table, and the caller still cross-checks the streamed count against the
/// inventory. Any torn, substituted or populated schema refuses.
fn stream_fresh_enrollments(
    tx: &rusqlite::Transaction<'_>,
    minted: &chio_kernel::process_return_custody::ProcessReturnInventoryDataV1,
    startup: &StartupPlan,
    path: &std::path::Path,
    namespace: &str,
    authority: &str,
    kernel_key: &str,
) -> Result<u64, chio_kernel::admission_operation::AdmissionOperationStoreError> {
    use chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant;
    let refused = |error: ProcessError| {
        Invariant(format!(
            "Process genesis enrollment stream refused: {error}"
        ))
    };
    if !matches!(startup, StartupPlan::Genesis { .. }) {
        return Err(refused(ProcessError::Conflict));
    }
    let objects: i64 = tx
        .query_row(
            "SELECT count(*) FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| refused(ProcessError::from(error)))?;
    if objects != 0 {
        return Err(refused(ProcessError::Conflict));
    }
    let recomputed =
        layout::empty_inventory(tx, path, namespace, authority, kernel_key).map_err(refused)?;
    if recomputed != *minted {
        return Err(refused(ProcessError::Conflict));
    }
    if minted.account_count != 0 {
        return Err(refused(ProcessError::Conflict));
    }
    Ok(0)
}

/// Re-authenticate a capsule's retained account inside a writer transaction:
/// its retained whole row must still be the exact funded state of this journal.
/// The full cohort was verified by the caller.
fn verify_retained_account(
    tx: &Transaction<'_>,
    account: &RetainedProcessReturnAccount,
) -> Result<(), ProcessError> {
    let row = cohort::account_row(tx, &account.account_digest)?.ok_or(ProcessError::Conflict)?;
    if row.bytes != account.account_bytes {
        return Err(ProcessError::Conflict);
    }
    Ok(())
}

/// The immutable original identity shared by a recorded source and a fresh
/// preparation of the same original call. Mutable progress (checkpoint,
/// revision, state, tree calls, nonce slot, host observations, the physical
/// profile of the file) and the recorded cut itself are deliberately absent:
/// the journal's frozen binding and capability are verified separately
/// against the recorded row.
fn same_recorded_identity(
    recorded: &ProcessReturnSourceDataV1,
    prepared: &ProcessReturnSourceDataV1,
) -> bool {
    recorded.process_id == prepared.process_id
        && recorded.root_process_id == prepared.root_process_id
        && recorded.operation_key == prepared.operation_key
        && recorded.attempt == prepared.attempt
        && recorded.request_id == prepared.request_id
        && recorded.logical_request_digest == prepared.logical_request_digest
        && recorded.call_binding_digest == prepared.call_binding_digest
        && recorded.current_request_digest == prepared.current_request_digest
        && recorded.capability_digest == prepared.capability_digest
        && recorded.known_outcome_only == prepared.known_outcome_only
        && recorded.journal_namespace == prepared.journal_namespace
        && recorded.journal_authority == prepared.journal_authority
        && recorded.kernel_key_digest == prepared.kernel_key_digest
        && recorded.schema == prepared.schema
        && recorded.file_device == prepared.file_device
        && recorded.file_inode == prepared.file_inode
        && recorded.host_profile_digest == prepared.host_profile_digest
        && recorded.host_route_digest == prepared.host_route_digest
        && recorded.launch_receipt_digest == prepared.launch_receipt_digest
}

/// Minted only by the owning Process enrollment transaction after its real
/// physical allowance and original native account are verified. No constructor
/// or wire decoding is exposed. `account_bytes` is the retained whole row;
/// `funding_bytes` is the canonical plain native funding recorded inside it.
pub(crate) struct RetainedProcessReturnAccount {
    source: ProcessReturnSourceDataV1,
    account_digest: String,
    funding: ProcessReturnFundingDataV1,
    account_bytes: Vec<u8>,
    funding_bytes: Vec<u8>,
    original_event_sequence: u64,
    original_event_digest: String,
}
impl RetainedProcessReturnAccount {
    pub(crate) fn source(&self) -> &ProcessReturnSourceDataV1 {
        &self.source
    }
    pub(crate) fn account_digest(&self) -> &str {
        &self.account_digest
    }
    pub(crate) fn original_event_sequence(&self) -> u64 {
        self.original_event_sequence
    }
    pub(crate) fn original_event_digest(&self) -> &str {
        &self.original_event_digest
    }
}

pub(crate) struct RetainedProcessReturnReceipt {
    account_digest: String,
    receipt: ProcessNativeReturnCaptureDataV1,
    receipt_bytes: Vec<u8>,
    final_event_sequence: u64,
    final_event_digest: String,
}
impl RetainedProcessReturnReceipt {
    pub(crate) fn receipt(&self) -> &ProcessNativeReturnCaptureDataV1 {
        &self.receipt
    }
    pub(crate) fn final_event_sequence(&self) -> u64 {
        self.final_event_sequence
    }
    pub(crate) fn final_event_digest(&self) -> &str {
        &self.final_event_digest
    }
}

/// Every generic current writer preserves the actual outstanding funded
/// liabilities and future transaction headroom of this file and every other
/// same-volume journal. The bank proof is the opaque Kernel-minted readback;
/// raw DATA alone cannot substitute, and no absence becomes zero debt.
pub(super) fn require_current_writer_preserves_process_return_debt(
    tx: &Transaction<'_>,
    bank: &VerifiedProcessReturnBank,
    current_write: &SqlitePhysicalDebtAmountData,
) -> Result<(), ProcessError> {
    // The minted proof is bound to this exact file: the complete observation
    // it was minted from is recomputed from the live journal inside this
    // transaction, so torn state, family loss with retained history, a
    // copied file or a stale proof refuses before capacity is even consulted.
    cohort::revalidate_inventory(tx, bank.inventory_data())?;
    require_capacity(tx, bank, current_write, wal_backlog_bytes(tx)?)
}

/// The capacity equation of one current write against the proof's readback:
/// this file's own reserve, every other same-volume reserve, the actual WAL
/// backlog and the actual free space.
fn require_capacity(
    tx: &Connection,
    bank: &VerifiedProcessReturnBank,
    current_write: &SqlitePhysicalDebtAmountData,
    pending_wal_bytes: u64,
) -> Result<(), ProcessError> {
    let readback = bank.readback_data();
    let owed_this_file = SqlitePhysicalDebtAmountData::checked(
        readback.this_file_reserved_wal_bytes,
        readback.this_file_reserved_disk_bytes,
    )
    .map_err(|_| ProcessError::Conflict)?;
    // Other same-volume reserves keep their disk debt here; their WAL debt is
    // never charged against this file's own WAL limit.
    let owed_other_files =
        [
            SqlitePhysicalDebtAmountData::checked(0, readback.same_filesystem_other_disk_bytes)
                .map_err(|_| ProcessError::Conflict)?,
        ];
    // Same-filesystem available bytes, borrowed from the actual held main-file
    // descriptor so file identity and locks are preserved. Observation DATA
    // only; the loans above remain the authoritative debt.
    let available_disk_bytes = chio_sqlite_file_identity::main_database_available_bytes(tx)
        .map_err(|_| {
            ProcessError::Configuration(
                "Process same-filesystem available disk observation is unavailable",
            )
        })?;
    require_physical_write_capacity(
        SqliteWriteCapacityStageData::Intake,
        pending_wal_bytes,
        available_disk_bytes,
        &owed_this_file,
        &owed_other_files,
        current_write,
    )
    .map_err(|reason| {
        #[cfg(feature = "admission-test-support")]
        eprintln!(
            "Process current-write capacity refused: {reason}; pending_wal={pending_wal_bytes}; available_disk={available_disk_bytes}; current_wal={}; current_disk={}; owed_wal={}; owed_disk={}; other_disk={}",
            current_write.wal_bytes(),
            current_write.disk_bytes(),
            owed_this_file.wal_bytes(),
            owed_this_file.disk_bytes(),
            readback.same_filesystem_other_disk_bytes,
        );
        #[cfg(not(feature = "admission-test-support"))]
        let _ = reason;
        ProcessError::Limit("native return finishing reserve")
    })?;
    Ok(())
}

/// The startup write of the held file, under the minted proof. A new journal
/// is checked against the proof and its capacity before its journal mode or
/// any schema is written, then created; a supported source layout is brought
/// to the compiled layout. Each transaction revalidates the same plan, and
/// the price is the actual catalog delta of the source.
impl Store {
    pub(crate) fn startup_current_write(
        &mut self,
        bank: &VerifiedProcessReturnBank,
    ) -> Result<(), ProcessError> {
        let (authority, kernel_key, path) = (
            self.authority.clone(),
            self.kernel_key.clone(),
            self.path.clone(),
        );
        match self.startup.clone() {
            StartupPlan::Ready => {
                // No catalog or Process row is written. The native inverse
                // already completed any interrupted enrollment; bind its proof
                // to this exact retained journal before serving custody.
                let tx = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Deferred)?;
                cohort::revalidate_inventory(&tx, bank.inventory_data())?;
                tx.rollback()?;
                Ok(())
            }
            StartupPlan::Upgrade(source) => {
                let tx = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                layout::verify_plan(&tx, &path, &authority, &kernel_key, &self.startup)?;
                let rows = layout::describe(&tx, source, &authority, &kernel_key)?;
                let profile = catalog::prepare_active_profile(
                    &tx,
                    &path,
                    &self.namespace,
                    &authority,
                    &kernel_key,
                )?;
                // The retained source and recipe are authenticated under the
                // original connection profile before any transient setting, so
                // no transient bound enters the persisted source or digest.
                let (priced, ceiling) = pricing::price_startup_rows(&tx, &profile, &rows)?;
                require_current_writer_preserves_process_return_debt(&tx, bank, &priced)?;
                let bound = install_startup_page_bound(&tx, ceiling)?;
                let mutated =
                    layout::install(&tx, source, &authority, &kernel_key, &self.namespace)
                        .and_then(|()| tx.commit().map_err(ProcessError::from));
                // The original settings are restored on every exit: the
                // restoration runs before any mutation error propagates, so a
                // refused or rolled back startup never leaves the transient
                // bound on the connection.
                let restored = restore_startup_page_bound(&self.connection, bound);
                mutated?;
                restored?;
                Ok(())
            }
            StartupPlan::Genesis { namespace } => {
                {
                    let tx = self
                        .connection
                        .transaction_with_behavior(TransactionBehavior::Deferred)?;
                    let (priced, _) = genesis_price(
                        &tx,
                        &path,
                        &self.startup,
                        &namespace,
                        &authority,
                        &kernel_key,
                        bank,
                    )?;
                    require_capacity(&tx, bank, &priced, journal_backlog_bytes(&tx)?)?;
                    tx.commit()?;
                }
                self.connection.pragma_update(None, "journal_mode", "WAL")?;
                let tx = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                let (priced, ceiling) = genesis_price(
                    &tx,
                    &path,
                    &self.startup,
                    &namespace,
                    &authority,
                    &kernel_key,
                    bank,
                )?;
                require_capacity(&tx, bank, &priced, journal_backlog_bytes(&tx)?)?;
                let bound = install_startup_page_bound(&tx, ceiling)?;
                let mutated = layout::install(
                    &tx,
                    LayoutSource::Empty,
                    &authority,
                    &kernel_key,
                    &namespace,
                )
                .and_then(|()| tx.commit().map_err(ProcessError::from));
                // The original settings are restored on every exit: the
                // restoration runs before any mutation error propagates, so a
                // refused or rolled back startup never leaves the transient
                // bound on the connection.
                let restored = restore_startup_page_bound(&self.connection, bound);
                mutated?;
                restored?;
                Ok(())
            }
        }
    }
}

/// The saved original connection settings of one startup page bound. They are
/// the values observed when the bound was installed, never an invented
/// default, and they are restored after the transaction committed or rolled
/// back on every exit path.
struct StartupPageBound {
    original_max_page_count: i64,
    original_cache_spill: i64,
}

/// Install the startup-only enforced page ceiling on the writing connection
/// inside the startup transaction: save the original settings, enforce the
/// ceiling, and disable cache spill so every dirty page is a page of the
/// file under the enforced ceiling. The enforced ceiling is never above a
/// stricter original operator max_page_count: it is the smaller of the
/// quoted bound and the original cap, and an unlimited original cap keeps
/// the quoted bound. Both settings are read back after they are set; the max
/// readback is the effective ceiling SQLite enforces on this connection,
/// never the requested value, and an ineffective bound refuses before any
/// mutation with both original settings restored.
fn install_startup_page_bound(
    connection: &Connection,
    ceiling: u64,
) -> Result<StartupPageBound, ProcessError> {
    let original_max_page_count: i64 =
        connection.query_row("PRAGMA main.max_page_count", [], |row| row.get(0))?;
    let original_cache_spill: i64 =
        connection.query_row("PRAGMA main.cache_spill", [], |row| row.get(0))?;
    let enforced = if original_max_page_count > 0 {
        ceiling.min(u64::try_from(original_max_page_count).map_err(|_| ProcessError::Conflict)?)
    } else {
        ceiling
    };
    let enforced = i64::try_from(enforced).map_err(|_| ProcessError::Conflict)?;
    let saved = StartupPageBound {
        original_max_page_count,
        original_cache_spill,
    };
    let installed = (|| -> Result<(), ProcessError> {
        connection.pragma_update(None, "max_page_count", enforced)?;
        connection.pragma_update(None, "cache_spill", "OFF")?;
        let effective: i64 =
            connection.query_row("PRAGMA main.max_page_count", [], |row| row.get(0))?;
        let spill: i64 = connection.query_row("PRAGMA main.cache_spill", [], |row| row.get(0))?;
        if spill != 0 || effective <= 0 || effective > enforced {
            return Err(ProcessError::Configuration(
                "Process startup page bound is not enforced within the quoted and operator limits",
            ));
        }
        Ok(())
    })();
    if let Err(error) = installed {
        restore_startup_page_bound(connection, saved)?;
        return Err(error);
    }
    Ok(saved)
}

/// Restore the writing connection's original settings after its startup
/// transaction committed or rolled back, or after a refused installation.
/// Both settings are written back and both are read back and compared with
/// the observed originals; no default value is ever substituted and a
/// restoration that does not verify refuses.
fn restore_startup_page_bound(
    connection: &Connection,
    bound: StartupPageBound,
) -> Result<(), ProcessError> {
    // Attempt both restorations even if SQLite refuses one of them.
    let page_result =
        connection.pragma_update(None, "max_page_count", bound.original_max_page_count);
    let spill_result = connection.pragma_update(None, "cache_spill", bound.original_cache_spill);
    page_result?;
    spill_result?;
    let restored_max: i64 =
        connection.query_row("PRAGMA main.max_page_count", [], |row| row.get(0))?;
    let restored_spill: i64 =
        connection.query_row("PRAGMA main.cache_spill", [], |row| row.get(0))?;
    if restored_max != bound.original_max_page_count || restored_spill != bound.original_cache_spill
    {
        return Err(ProcessError::Configuration(
            "Process startup page bound restoration did not verify the original settings",
        ));
    }
    Ok(())
}

/// Revalidate that the held file is still the empty file the proof was minted
/// from and price the complete genesis from its actual profile as the
/// smaller of the generic shape bound and the enforced page ceiling.
fn genesis_price(
    tx: &Connection,
    path: &std::path::Path,
    plan: &StartupPlan,
    namespace: &str,
    authority: &str,
    kernel_key: &str,
    bank: &VerifiedProcessReturnBank,
) -> Result<(SqlitePhysicalDebtAmountData, u64), ProcessError> {
    layout::verify_plan(tx, path, authority, kernel_key, plan)?;
    if &layout::empty_inventory(tx, path, namespace, authority, kernel_key)?
        != bank.inventory_data()
    {
        return Err(ProcessError::Conflict);
    }
    let rows = layout::describe(tx, LayoutSource::Empty, authority, kernel_key)?;
    let profile = catalog::prepare_empty_profile(tx, path)?;
    pricing::price_startup_rows(tx, &profile, &rows)
}

/// WAL pressure of a file in either journal mode of a genesis: a rollback
/// journal file has no WAL backlog, and a WAL file is observed.
fn journal_backlog_bytes(tx: &Connection) -> Result<u64, ProcessError> {
    let mode: String = tx.query_row("PRAGMA main.journal_mode", [], |row| row.get(0))?;
    match mode.as_str() {
        "delete" => Ok(0),
        "wal" => wal_backlog_bytes(tx),
        _ => Err(ProcessError::Conflict),
    }
}

impl Store {
    /// The retained account digests of the installed bank, ordered. The
    /// complete cohort is authenticated first; an absent bank still refuses
    /// and is never read as zero debt.
    pub(crate) fn native_return_account_digests(&mut self) -> Result<Vec<String>, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        cohort::verify_cohort(&tx)?;
        let digests: Vec<String> = {
            let mut statement = tx.prepare(
                "SELECT account_digest FROM process_native_return_accounts ORDER BY account_digest",
            )?;
            let digests = statement
                .query_map([], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            digests
        };
        tx.commit()?;
        Ok(digests)
    }

    /// Price the admission of one logical call from its actual journal state,
    /// read-only. The plan is only cost DATA and a precondition snapshot: it
    /// grants no write, and the routed writer revalidates everything inside
    /// its own transaction before any row changes.
    pub(crate) fn prepare_call_admission(
        &mut self,
        id: &str,
        key: &str,
        request: &ToolCallRequest,
        request_hash: &str,
    ) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let process =
            read_process(&tx, id)?.ok_or_else(|| ProcessError::NotFound(id.to_owned()))?;
        require_running(&process)?;
        if digest(&process.capability)? != digest(&request.capability)?
            || request.agent_id != process.capability.subject.to_hex()
        {
            return Err(ProcessError::Conflict);
        }
        let stored: Option<String> = tx
            .query_row(
                "SELECT request_hash FROM main.process_calls WHERE process_id=?1 AND operation_key=?2",
                params![id, key],
                |row| row.get(0),
            )
            .optional()?;
        if stored.as_deref().is_some_and(|hash| hash != request_hash) {
            return Err(ProcessError::Conflict);
        }
        let rows = rows::describe_call_admission(&tx, &process.root_id)?;
        tx.commit()?;
        Ok(rows)
    }

    /// Run one generic Process current write inside the native current-write
    /// scope. The caller's read-only `describe` prices the actual complete
    /// rows from the live journal inside this transaction; the minted bank
    /// proof is revalidated against this exact file; the capacity equation
    /// preserves every outstanding funded liability; only then does the
    /// caller's body run and commit. No routed write bypasses enforcement.
    #[allow(clippy::type_complexity)]
    pub(crate) fn run_current_write(
        &mut self,
        bank: &VerifiedProcessReturnBank,
        describe: &dyn Fn(&Connection) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError>,
        body: Box<
            dyn FnOnce(&Transaction<'_>) -> Result<Box<dyn std::any::Any + Send>, ProcessError>
                + Send
                + Sync,
        >,
    ) -> Result<Box<dyn std::any::Any + Send>, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (authority, kernel_key): (String, String) = tx.query_row(
            "SELECT authority,kernel_key FROM main.process_runtime WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let described = describe(&tx)?;
        let current_write = pricing::price_current_write(
            &tx,
            &self.path,
            &self.namespace,
            &authority,
            &kernel_key,
            &described,
        )?;
        require_current_writer_preserves_process_return_debt(&tx, bank, &current_write)?;
        let value = body(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    /// Execute one priced call admission inside the native current-write
    /// scope. The actual write is priced again from the live journal here, and
    /// the minted bank proof is revalidated against this exact file before
    /// the capacity equation preserves every outstanding funded liability.
    pub(crate) fn admit_current_write(
        &mut self,
        bank: &VerifiedProcessReturnBank,
        id: &str,
        key: &str,
        request: &ToolCallRequest,
        request_hash: &str,
    ) -> Result<(), ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let process =
            read_process(&tx, id)?.ok_or_else(|| ProcessError::NotFound(id.to_owned()))?;
        let (authority, kernel_key): (String, String) = tx.query_row(
            "SELECT authority,kernel_key FROM main.process_runtime WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let described = rows::describe_call_admission(&tx, &process.root_id)?;
        let current_write = pricing::price_current_write(
            &tx,
            &self.path,
            &self.namespace,
            &authority,
            &kernel_key,
            &described,
        )?;
        require_current_writer_preserves_process_return_debt(&tx, bank, &current_write)?;
        super::admit_call(&tx, id, key, request, request_hash)?;
        tx.commit()?;
        Ok(())
    }

    /// Price one checkpoint transition from its actual journal row, read-only.
    pub(crate) fn prepare_checkpoint(
        &mut self,
        id: &str,
        expected_revision: u64,
    ) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let process =
            read_process(&tx, id)?.ok_or_else(|| ProcessError::NotFound(id.to_owned()))?;
        require_running(&process)?;
        if process.checkpoint.revision != expected_revision {
            return Err(ProcessError::CheckpointConflict);
        }
        let rows = vec![rows::describe_checkpoint_transition(&tx, id)?];
        tx.commit()?;
        Ok(rows)
    }

    /// Execute one priced checkpoint transition inside the native
    /// current-write scope, under the same bank and capacity contract as the
    /// admission writer.
    pub(crate) fn checkpoint_current_write(
        &mut self,
        bank: &VerifiedProcessReturnBank,
        id: &str,
        expected_revision: u64,
        value: serde_json::Value,
    ) -> Result<crate::Checkpoint, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (authority, kernel_key): (String, String) = tx.query_row(
            "SELECT authority,kernel_key FROM main.process_runtime WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let described = vec![rows::describe_checkpoint_transition(&tx, id)?];
        let current_write = pricing::price_current_write(
            &tx,
            &self.path,
            &self.namespace,
            &authority,
            &kernel_key,
            &described,
        )?;
        require_current_writer_preserves_process_return_debt(&tx, bank, &current_write)?;
        let checkpoint = super::checkpoint_call(&tx, id, expected_revision, value)?;
        tx.commit()?;
        Ok(checkpoint)
    }
}

/// Price a fresh root or child process row at its complete maxima. Public
/// for the runtime's routed writers; pure cost DATA of the actual bounds.
pub(crate) fn price_new_process_rows() -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    Ok(vec![rows::new_process_row()?])
}

/// Price the bounded recursive cancellation rewrite: one whole existing
/// process row envelope per running descendant of the tree, counted from
/// the actual journal before the write runs.
pub(crate) fn price_cancel_rows(
    tx: &Connection,
    id: &str,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    let count: usize = usize::try_from(tx.query_row(
        "WITH RECURSIVE descendants(id) AS (
            SELECT id FROM processes WHERE id = ?1
            UNION ALL SELECT p.id FROM processes p JOIN descendants d ON p.parent_id = d.id
         ) SELECT count(*) FROM processes WHERE id IN (SELECT id FROM descendants) AND state='running'",
        params![id],
        |row| row.get::<_, i64>(0),
    )?)
    .map_err(|_| ProcessError::Conflict)?;
    let mut rows = Vec::with_capacity(count);
    for _ in 0..count {
        rows.push(rows::existing_process_row()?);
    }
    Ok(rows)
}

/// Price one fresh immutable state-blob row at its quota maxima.
pub(crate) fn price_state_blob_rows() -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    Ok(vec![rows::new_state_blob_row()?])
}

/// Price one dispatch-attempt advance from the actual journal row.
pub(crate) fn price_attempt_advance_rows(
    tx: &Connection,
    process: &str,
    operation: &str,
    expected_binding: &str,
    expected_attempt: u32,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    rows::describe_attempt_advance(tx, process, operation, expected_binding, expected_attempt)
}

/// Price the original Process nonce slot written by a native nonce custody.
pub(crate) fn price_original_nonce_rows() -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError>
{
    rows::describe_original_nonce_transaction()
}

/// Price one fresh immutable artifact object row at its quota maxima.
pub(crate) fn price_artifact_object_rows() -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError>
{
    Ok(vec![rows::new_artifact_object_row()?])
}

/// Price the in-place retirement of one retained artifact object from its
/// actual journal row.
pub(crate) fn price_artifact_object_retirement_rows(
    tx: &Connection,
    process: &str,
    object: &str,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    Ok(vec![rows::describe_artifact_object_retirement(
        tx, process, object,
    )?])
}

/// Price one new confined return slot row.
pub(crate) fn price_confined_slot_reservation_rows(
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    Ok(vec![rows::new_confined_slot_row()?])
}

/// Price the single fill of one reserved confined return slot.
pub(crate) fn price_confined_slot_fill_rows(
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    Ok(vec![rows::confined_slot_fill_row()?])
}

/// Price one ordered confined delivery marker and its feature activation.
pub(crate) fn price_confined_delivery_rows(
    tx: &Connection,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    rows::describe_confined_delivery_marker(tx)
}

/// Price one permanent unused-reservation closure and its feature activation.
pub(crate) fn price_unused_closure_rows(
    tx: &Connection,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    rows::describe_unused_recovery_closure(tx)
}

/// Price the knowledge activation's feature-level transition.
pub(crate) fn price_feature_activation_rows(
    tx: &Connection,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    Ok(vec![rows::describe_feature_level_raise(tx)?])
}

/// Price one recovery reservation from the actual root row of its process.
pub(crate) fn price_recovery_reservation_rows(
    tx: &Connection,
    process: &str,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    let root = read_process(tx, process)?
        .ok_or_else(|| ProcessError::NotFound(process.to_owned()))?
        .root_id;
    rows::describe_recovery_reservation(tx, &root)
}

/// Price one recovery finalization and, when the custody carries the original
/// execution nonce, the original nonce slot written in the same transaction.
pub(crate) fn price_recovery_finalization_rows(
    tx: &Connection,
    process: &str,
    operation: &str,
    retains_nonce: bool,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    let mut rows = rows::describe_recovery_finalization(tx, process, operation)?;
    if retains_nonce {
        rows.extend(rows::describe_original_nonce_transaction()?);
    }
    Ok(rows)
}

/// Price one dynamic child submission.
pub(crate) fn price_child_submission_rows(
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    rows::describe_child_submission()
}

/// Price one direct-child wait record and its settled marker.
pub(crate) fn price_worker_wait_rows() -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    rows::describe_worker_wait()
}

/// Price the delegation keys of one signer provisioning.
pub(crate) fn price_signer_rows(
    count: usize,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    rows::delegation_key_rows(count.max(1))
}

/// Price one new worker credential row.
#[cfg(feature = "worker-server")]
pub(crate) fn price_worker_credential_rows(
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    Ok(vec![rows::new_worker_credential_row()?])
}

/// Price the removal of every credential of one process.
#[cfg(feature = "worker-server")]
pub(crate) fn price_worker_credential_revocation_rows(
    tx: &Connection,
    process: &str,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    rows::describe_worker_credential_revocation(tx, process)
}

/// Uncheckpointed WAL pressure of this exact file, observed without
/// checkpointing or waiting. An empty or fully checkpointed WAL has no
/// pending frames and no fabricated header debt; pending frames each carry
/// their 24-byte frame header plus the 32-byte WAL header.
fn wal_backlog_bytes(tx: &Connection) -> Result<u64, ProcessError> {
    let (log, checkpointed) = catalog::observe_wal_frontier(tx)?;
    let frames = log
        .checked_sub(checkpointed)
        .ok_or(ProcessError::Conflict)?;
    if frames == 0 {
        return Ok(0);
    }
    let page_size =
        u64::try_from(tx.query_row("PRAGMA main.page_size", [], |row| row.get::<_, i64>(0))?)
            .map_err(|_| ProcessError::Conflict)?;
    if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(ProcessError::Conflict);
    }
    frames
        .checked_mul(page_size + 24)
        .and_then(|bytes| bytes.checked_add(32))
        .ok_or(ProcessError::Conflict)
}
