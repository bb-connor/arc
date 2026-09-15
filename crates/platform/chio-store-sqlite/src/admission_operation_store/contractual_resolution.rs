//! Fenced append-only capture-waiver successors; original budget events are immutable.
pub(crate) use super::contractual_resolution_read::{load_effective_journal, verify_invariants};
use super::contractual_resolution_read::{load_record, source, validate_budget};
use super::*;
use chio_kernel::payment::*;
fn error(e: impl std::fmt::Display) -> CaptureWaiverError {
    CaptureWaiverError(e.to_string())
}
fn append(
    store: &SqliteAdmissionOperationStore,
    tx: &Transaction<'_>,
    record: &ContractualCaptureWaiverRecordV1,
) -> Result<(), CaptureWaiverError> {
    let bytes = canonical_json_bytes(record).map_err(error)?;
    tx.execute(
        "INSERT INTO capture_waiver_records (operation_id, sequence, request_digest, record_json, record_digest) VALUES (?, ?, ?, ?, ?)",
        params![
            record.operation_id(),
            i64::try_from(record.sequence()).map_err(error)?,
            capture_waiver_digest(record.request())?,
            &bytes,
            sha256_hex(&bytes),
        ],
    ).map_err(error)?;
    store
        .serving_owner
        .append_global_commit(
            tx,
            "capture_waiver",
            "payment_resolution",
            &format!("capture-waiver:{}", record.operation_id()),
            record.sequence(),
        )
        .map_err(error)?;
    Ok(())
}
impl QualifiedContractualCaptureWaiverStore for SqliteAdmissionOperationStore {
    fn capture_waiver_source(
        &self,
        id: &str,
        fence: &StoreMutationFence,
    ) -> Result<CaptureWaiverSourceV1, CaptureWaiverError> {
        if fence != &self.serving_owner.fence {
            return Err(error("waiver read fenced"));
        }
        let mut connection = self.connection().map_err(error)?;
        let tx = self.begin_read(&mut connection).map_err(error)?;
        source(&tx, id)
    }
    fn load_capture_waiver(
        &self,
        id: &str,
        fence: &StoreMutationFence,
    ) -> Result<Option<ContractualCaptureWaiverRecordV1>, CaptureWaiverError> {
        if fence != &self.serving_owner.fence {
            return Err(error("waiver read fenced"));
        }
        let mut connection = self.connection().map_err(error)?;
        let tx = self.begin_read(&mut connection).map_err(error)?;
        load_record(&tx, id)
    }
    fn begin_capture_waiver(
        &self,
        policy: &ContractualCaptureWaiverPolicyV1,
        request: &ContractualCaptureWaiverRequestV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ContractualCaptureWaiverRecordV1, CaptureWaiverError> {
        let mut connection = self.connection().map_err(error)?;
        let tx = self
            .begin_write(&mut connection, Some(fence))
            .map_err(error)?;
        let authority_now = schema::authority_validation_time(&tx, now).map_err(error)?;
        let id = &request.observation.body.operation_id;
        if let Some(record) = load_record(&tx, id)? {
            if capture_waiver_digest(record.request())? != capture_waiver_digest(request)?
                || capture_waiver_digest(record.policy())? != capture_waiver_digest(policy)?
            {
                return Err(error("conflicting waiver authority"));
            }
            return Ok(record);
        }
        // A lease deadline cannot prove an in-flight rail call stopped. Require
        // exclusive serving-owner handoff before accepting this new authority.
        let stored = load_by_operation_id_without_terminal_projection_tx(
            &tx,
            &AdmissionOperationId::from_persisted(id).map_err(error)?,
        )
        .map_err(error)?
        .ok_or_else(|| error("waiver operation absent"))?;
        stored.verify_decision_time(now).map_err(error)?;
        if stored
            .recovery_claim
            .as_ref()
            .is_some_and(|claim| claim.store_fence() == fence)
        {
            return Err(error(
                "capture waiver requires handoff from the active finalizer owner",
            ));
        }
        let actual = source(&tx, id)?;
        ensure_no_reserved_terminal_stage(&tx, actual.operation.binding().operation_id())
            .map_err(error)?;
        validate_budget(&tx, &actual.journal)?;
        let record = ContractualCaptureWaiverRecordV1::accepted(
            policy,
            request,
            &actual,
            fence.clone(),
            authority_now,
        )?;
        append(self, &tx, &record)?;
        self.commit_write(tx).map_err(error)?;
        self.sync_after_write(&connection).map_err(error)?;
        Ok(record)
    }
    fn complete_capture_waiver(
        &self,
        id: &str,
        digest: &str,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ContractualCaptureWaiverRecordV1, CaptureWaiverError> {
        let mut connection = self.connection().map_err(error)?;
        let tx = self
            .begin_write(&mut connection, Some(fence))
            .map_err(error)?;
        let authority_now = schema::authority_validation_time(&tx, now).map_err(error)?;
        let record = load_record(&tx, id)?.ok_or_else(|| error("waiver acceptance absent"))?;
        if capture_waiver_digest(record.request())? != digest {
            return Err(error("waiver completion changed intent"));
        }
        if record.is_complete() {
            return Ok(record);
        }
        let actual = source(&tx, id)?;
        if actual.operation.state() != AdmissionOperationState::Finalizing {
            return Err(error("waiver admission changed"));
        }
        ensure_no_reserved_terminal_stage(&tx, actual.operation.binding().operation_id())
            .map_err(error)?;
        let completed = record.complete(authority_now, fence.clone())?;
        append(self, &tx, &completed)?;
        self.commit_write(tx).map_err(error)?;
        self.sync_after_write(&connection).map_err(error)?;
        Ok(completed)
    }
}
