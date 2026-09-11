//! Durable native dispatch preparation, separate from capture and activation.
//! Every physical record has exactly one reference in the authority commit chain.
use super::super::{dpop_claim, governed_approval_claim, retained_request, runtime_participant};
use super::*;
use chio_kernel::admission_operation::{
    NativeSecurityAuthorityBindingV1, NativeSecurityDispatchLedgerContext,
    NativeSecurityDispatchLedgerRecordV1,
};

mod capture;
mod policy;
mod record;
mod storage;
mod write;
pub(in crate::admission_operation_store) use capture::verify_capture_attachment;
pub(crate) use capture::{NativeCaptureBinding, VerifiedNativeCapture};
use record::Record;
pub(in crate::admission_operation_store) use storage::verify_all;

const SCHEMA: &str = "chio.native-dispatch-preparation-ledger.v1";
const PROJECTION: &str = "native_dispatch_ledger";
const MUTATION: &str = "retain_native_dispatch_ledger";
const MAX_RECORD_BYTES: usize = 1024 * 1024;

pub(in crate::admission_operation_store) fn sql() -> &'static str {
    include_str!("../../admission_operation_native_dispatch_ledger.sql")
}

fn require_operation(operation: &AdmissionOperationV1) -> Result<(), AdmissionOperationStoreError> {
    operation.validate()?;
    if operation.state() != AdmissionOperationState::CapturePending
        || operation.binding().kind() != AdmissionOperationKind::ToolDispatch
        || operation.dispatch_commit().is_some()
        || operation
            .binding()
            .participant_requirements()
            .execution_nonce
        || operation.budget_hold_id().is_none()
        || operation
            .provider_attempt()
            .is_none_or(|attempt| attempt.is_caller_report())
    {
        return Err(invalid(
            "native dispatch preparation requires non-nonce kernel capture custody",
        ));
    }
    Ok(())
}

pub(crate) fn projection_reference(
    connection: &Connection,
    operation: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    if sequence != 1 {
        return Err(SqliteServingOwnerError::Invalid(
            "native dispatch ledger sequence differs".into(),
        ));
    }
    let record = storage::load(connection, operation)
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?
        .ok_or_else(|| {
            SqliteServingOwnerError::Invalid("native dispatch ledger reference is absent".into())
        })?;
    record
        .validate(connection)
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    record
        .digest()
        .map(|digest| digest.as_str().to_owned())
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))
}

impl SqliteAdmissionOperationStore {
    /// One fenced, anchored historical read. It performs no reclassification,
    /// reacquisition or deadline extension and returns no execution authority.
    pub fn load_native_dispatch_ledger(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<NativeSecurityDispatchLedgerRecordV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        observed_time(&tx, trusted_now_unix_ms)?;
        storage::verify_coverage(&tx)?;
        let Some(stored) = load_by_operation_id_tx(&tx, operation_id)? else {
            return Ok(None);
        };
        stored.verify_decision_time(trusted_now_unix_ms)?;
        storage::load(&tx, operation_id.as_str())?
            .map(|record| {
                record.validate(&tx)?;
                storage::verify_reference(&tx, &record)?;
                record.evidence()
            })
            .transpose()
    }
}
