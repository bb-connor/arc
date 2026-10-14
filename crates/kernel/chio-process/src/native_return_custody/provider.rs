//! The concrete Process finishing source of one original native invocation.
//! The native owner downcasts the Kernel marker to exactly this type; neither
//! descriptive DATA nor another provider implementation can stand in for it.
use super::*;
use chio_kernel::native_finishing::NativeProcessFinishingSourceProvider;
use std::sync::Mutex;

/// The original source a finishing carrier presents: a live prepared
/// participant, or the bank loader's authenticated retained custody during
/// startup settlement. The retained variant grants no new write: its
/// enrollment, custody and reconciliation are the exact committed rows.
enum ParticipantSource {
    Prepared(PreparedProcessReturnParticipant),
    Retained {
        custody: ProcessReturnAccountCustody,
        canonical: Vec<u8>,
    },
}

/// Prepared Process source of one original call and, once enrolled or
/// restored, its retained account custody for the post-effect purposes.
pub struct ProcessNativeFinishingSource {
    runtime: ProcessRuntime,
    participant: ParticipantSource,
    account: Mutex<Option<ProcessReturnAccountCustody>>,
}

/// Exact enrollment coordinates read from the Process journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessNativeEnrollmentData {
    account_digest: String,
    event_sequence: u64,
    event_digest: String,
}

impl ProcessNativeEnrollmentData {
    pub fn account_digest(&self) -> &str {
        &self.account_digest
    }
    pub fn event_sequence(&self) -> u64 {
        self.event_sequence
    }
    pub fn event_digest(&self) -> &str {
        &self.event_digest
    }
}

/// Exact reconciliation coordinates read from the Process journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessNativeReconciliationData {
    account_digest: String,
    event_sequence: u64,
    event_digest: String,
}

impl ProcessNativeReconciliationData {
    pub fn account_digest(&self) -> &str {
        &self.account_digest
    }
    pub fn event_sequence(&self) -> u64 {
        self.event_sequence
    }
    pub fn event_digest(&self) -> &str {
        &self.event_digest
    }
}

impl NativeProcessFinishingSourceProvider for ProcessNativeFinishingSource {
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

impl core::fmt::Debug for ProcessNativeFinishingSource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProcessNativeFinishingSource([redacted])")
    }
}

impl ProcessNativeFinishingSource {
    /// Startup settlement carrier of one retained original account: the
    /// participant is the bank loader's authenticated retained custody, so
    /// the native settlement readback observes the exact committed source
    /// without a live request or any new write. Enrolling, restoring or
    /// pricing future purposes from a retained carrier refuses.
    pub(crate) fn from_retained_custody(
        runtime: &ProcessRuntime,
        custody: ProcessReturnAccountCustody,
    ) -> Result<Self, ProcessError> {
        let canonical = chio_kernel::process_return_custody::canonical_process_return_source_data(
            custody.source(),
        )
        .map_err(|_| ProcessError::Conflict)?;
        Ok(Self {
            runtime: runtime.clone(),
            participant: ParticipantSource::Retained { custody, canonical },
            account: Mutex::new(None),
        })
    }

    pub fn source(&self) -> &ProcessReturnSourceDataV1 {
        match &self.participant {
            ParticipantSource::Prepared(participant) => participant.source(),
            ParticipantSource::Retained { custody, .. } => custody.source(),
        }
    }

    pub fn canonical_source_bytes(&self) -> &[u8] {
        match &self.participant {
            ParticipantSource::Prepared(participant) => participant.canonical_source_bytes(),
            ParticipantSource::Retained { canonical, .. } => canonical,
        }
    }

    /// Effect-free price DATA of every future Process purpose, taken inside
    /// the Process writer against the exact prepared source cut. A retained
    /// settlement carrier has no future purpose.
    pub fn future_prices(&self) -> Result<Vec<ProcessFinishingTransactionPriceData>, ProcessError> {
        match &self.participant {
            ParticipantSource::Prepared(participant) => self
                .runtime
                .inspect_original_return_finishing_prices(participant),
            ParticipantSource::Retained { .. } => Err(ProcessError::Conflict),
        }
    }

    /// Enroll once with funding minted by the native Prepared account. The
    /// Process writer returns the retained account on an exact replay.
    /// A retained settlement carrier never enrolls new funding.
    pub fn enroll(
        &self,
        funding: FundedProcessReturnEnrollment,
    ) -> Result<ProcessNativeEnrollmentData, ProcessError> {
        let participant = match &self.participant {
            ParticipantSource::Prepared(participant) => participant,
            ParticipantSource::Retained { .. } => return Err(ProcessError::Conflict),
        };
        let custody = self
            .runtime
            .enroll_original_native_return_participant(participant, funding)?;
        let enrollment = custody.enrollment();
        *self
            .account
            .lock()
            .map_err(|_| ProcessError::StorePoisoned)? = Some(custody);
        Ok(enrollment)
    }

    /// Restore the earlier enrollment of this exact original call by its
    /// retained account digest. No source, quote or account is written. A
    /// retained settlement carrier never restores into new authority.
    pub fn restore(
        &self,
        account_digest: &str,
    ) -> Result<ProcessNativeEnrollmentData, ProcessError> {
        if matches!(self.participant, ParticipantSource::Retained { .. }) {
            return Err(ProcessError::Conflict);
        }
        let custody = self
            .runtime
            .retained_original_native_return_account(account_digest)?
            .ok_or(ProcessError::Conflict)?;
        if !same_original_call(custody.source(), self.source()) {
            return Err(ProcessError::Conflict);
        }
        let enrollment = custody.enrollment();
        *self
            .account
            .lock()
            .map_err(|_| ProcessError::StorePoisoned)? = Some(custody);
        Ok(enrollment)
    }

    /// The original source the retained account enrolled, once enrolled or
    /// restored. A re-prepared current source can differ in its Process cut.
    pub fn enrolled_source(&self) -> Result<Option<ProcessReturnSourceDataV1>, ProcessError> {
        if let ParticipantSource::Retained { custody, .. } = &self.participant {
            return Ok(Some(custody.source().clone()));
        }
        Ok(self
            .account
            .lock()
            .map_err(|_| ProcessError::StorePoisoned)?
            .as_ref()
            .map(|custody| custody.source().clone()))
    }

    /// The retained account's actual reconciliation, if Process committed it.
    pub fn reconciliation(&self) -> Result<Option<ProcessNativeReconciliationData>, ProcessError> {
        self.with_account(|custody| {
            self.runtime
                .retained_original_native_return_reconciliation(custody)
        })
    }

    /// Whether native admission enrolled or restored this call's account.
    pub(crate) fn has_account(&self) -> Result<bool, ProcessError> {
        if matches!(self.participant, ParticipantSource::Retained { .. }) {
            return Ok(true);
        }
        Ok(self
            .account
            .lock()
            .map_err(|_| ProcessError::StorePoisoned)?
            .is_some())
    }

    pub(crate) fn with_account<T>(
        &self,
        f: impl FnOnce(&ProcessReturnAccountCustody) -> Result<T, ProcessError>,
    ) -> Result<T, ProcessError> {
        if let ParticipantSource::Retained { custody, .. } = &self.participant {
            return f(custody);
        }
        let guard = self
            .account
            .lock()
            .map_err(|_| ProcessError::StorePoisoned)?;
        f(guard.as_ref().ok_or(ProcessError::Conflict)?)
    }
}

/// Re-prepared sources of one call differ only in their current Process cut,
/// original nonce custody and refreshed context generation. The native owner
/// binds the original context itself; every call identity stays identical.
fn same_original_call(
    original: &ProcessReturnSourceDataV1,
    current: &ProcessReturnSourceDataV1,
) -> bool {
    original.schema == current.schema
        && original.journal_namespace == current.journal_namespace
        && original.journal_authority == current.journal_authority
        && original.kernel_key_digest == current.kernel_key_digest
        && original.file_device == current.file_device
        && original.file_inode == current.file_inode
        && original.process_id == current.process_id
        && original.root_process_id == current.root_process_id
        && original.operation_key == current.operation_key
        && original.request_id == current.request_id
        && original.attempt == current.attempt
        && original.logical_request_digest == current.logical_request_digest
        && original.call_binding_digest == current.call_binding_digest
        && original.capability_digest == current.capability_digest
        && original.known_outcome_only == current.known_outcome_only
        && original.host_profile_digest == current.host_profile_digest
        && original.host_route_digest == current.host_route_digest
        && original.launch_receipt_digest == current.launch_receipt_digest
}

impl ProcessRuntime {
    /// Prepare the concrete finishing source of one admitted original call
    /// before its native admission. The Kernel carries it as a marker only.
    pub fn native_finishing_source(
        &self,
        process: &str,
        operation: &str,
        request: &ToolCallRequest,
        known_outcome_only: bool,
        context: Option<&SecurityInvocationContext>,
    ) -> Result<ProcessNativeFinishingSource, ProcessError> {
        let participant = self.prepare_original_native_return_participant(
            process,
            operation,
            request,
            known_outcome_only,
            context,
        )?;
        Ok(ProcessNativeFinishingSource {
            runtime: self.clone(),
            participant: ParticipantSource::Prepared(participant),
            account: Mutex::new(None),
        })
    }

    pub(crate) fn retained_original_native_return_account(
        &self,
        account_digest: &str,
    ) -> Result<Option<ProcessReturnAccountCustody>, ProcessError> {
        Ok(self
            .with_store(|store| store.load_native_return_account(account_digest))?
            .map(|original| ProcessReturnAccountCustody { original }))
    }

    pub(crate) fn retained_original_native_return_receipt(
        &self,
        account: &ProcessReturnAccountCustody,
    ) -> Result<Option<ProcessReturnReceiptCustody>, ProcessError> {
        Ok(self
            .with_store(|store| store.load_native_return_receipt(&account.original))?
            .map(|original| ProcessReturnReceiptCustody { original }))
    }

    pub(crate) fn retained_original_native_return_reconciliation(
        &self,
        account: &ProcessReturnAccountCustody,
    ) -> Result<Option<ProcessNativeReconciliationData>, ProcessError> {
        Ok(self
            .with_store(|store| store.load_native_return_reconciliation(&account.original))?
            .map(
                |(event_sequence, event_digest)| ProcessNativeReconciliationData {
                    account_digest: account.original.account_digest().to_owned(),
                    event_sequence,
                    event_digest,
                },
            ))
    }
}

impl ProcessReturnAccountCustody {
    pub(crate) fn source(&self) -> &ProcessReturnSourceDataV1 {
        self.original.source()
    }

    pub(crate) fn enrollment(&self) -> ProcessNativeEnrollmentData {
        ProcessNativeEnrollmentData {
            account_digest: self.original.account_digest().to_owned(),
            event_sequence: self.original.original_event_sequence(),
            event_digest: self.original.original_event_digest().to_owned(),
        }
    }
}

impl ProcessReturnReceiptCustody {
    /// Digest of the retained canonical capture receipt plus its final event.
    pub(crate) fn final_coordinates(&self) -> Result<(String, u64, String), ProcessError> {
        let receipt = crate::sha256_hex(&crate::canonical_json_bytes(self.original.receipt())?);
        Ok((
            receipt,
            self.original.final_event_sequence(),
            self.original.final_event_digest().to_owned(),
        ))
    }
}
