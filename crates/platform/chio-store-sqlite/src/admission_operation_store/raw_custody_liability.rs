//! The actual Raw producer describes its complete transaction before writing.
//! This source proof describes cost. It grants no claim, capture or bank loan.
use super::*;
use crate::serving_owner::NativeSourceTransactionOrigin;
use chio_kernel::tool_outcome::{CanonicalInvocationBlobV1, ToolOutcomeRecordV1};

mod catalog;
mod rows;
pub(super) use catalog::{
    raw_write_profile, tool_outcome_write_profile, RawWriteProfileData, ToolOutcomeWriteProfileData,
};
pub(super) use rows::{RawRowWriteShapeData, RawWriteTableData};

pub(super) struct RawCustodyWriteRequest<'a> {
    pub(super) operation: &'a AdmissionOperationV1,
    pub(super) blob: &'a CanonicalInvocationBlobV1,
    pub(super) outcome: &'a ToolOutcomeRecordV1,
    pub(super) claim: RecoveryClaimRequest<'a>,
    pub(super) trusted_now_unix_ms: u64,
}

/// No public constructor, Clone or serde. The physical operation and original
/// claim source are retained at the same actual prepared transaction cut.
pub(super) struct VerifiedRawCustodyWriteLiability<'source, 'database> {
    tx: &'source Transaction<'database>,
    owner: &'source SqliteServingOwner,
    origin: &'source NativeSourceTransactionOrigin<'source>,
    request: RawCustodyWriteRequest<'source>,
    operation_source: String,
    blob_source: String,
    admission_head: AdmissionCommitHead,
    global_head: (u64, String),
    profile: RawWriteProfileData,
    rows: Vec<RawRowWriteShapeData>,
}

pub(super) fn prepare_raw_custody_write_liability<'source, 'database>(
    tx: &'source Transaction<'database>,
    writer: (
        &'source SqliteServingOwner,
        &'source NativeSourceTransactionOrigin<'source>,
    ),
    request: RawCustodyWriteRequest<'source>,
) -> Result<VerifiedRawCustodyWriteLiability<'source, 'database>, AdmissionOperationStoreError> {
    let (owner, origin) = writer;
    // Namespace qualification precedes every original, claim or profile read.
    let profile = raw_write_profile(tx)?;
    origin.verify(tx).map_err(map_owner_error)?;
    if !origin.matches_owner(owner) {
        return Err(invariant("Raw liability changed its actual serving owner"));
    }
    let global_head = global_head(tx)?;
    if global_head.0 != origin.prepared_global_sequence() {
        return Err(invariant("Raw liability was prepared after a mutation"));
    }
    verify_active_owner(tx, owner, Some(request.claim.fence))?;
    store::validate_claim_request(&request.claim, request.trusted_now_unix_ms)?;
    let stored = load_by_operation_id_tx(tx, request.operation.binding().operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    if stored.operation != *request.operation
        || request.claim.operation_id != request.operation.binding().operation_id()
        || request.claim.expected_version != request.operation.version()
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    stored.verify_decision_time(request.trusted_now_unix_ms)?;
    let validation_time = schema::authority_validation_time(tx, request.trusted_now_unix_ms)?;
    if validation_time >= request.claim.expires_at_unix_ms {
        return Err(AdmissionOperationError::LeaseExpired.into());
    }
    // Reuse the exact read-only eligibility selected by the actual claim
    // writer. A conflicting live claimant is not a valid Raw source purpose.
    let _claim_selection = store::prepare_recovery_claim_tx(
        tx,
        owner,
        &stored,
        request.claim,
        request.trusted_now_unix_ms,
    )?;
    // An existing compatible claim can survive a reserved terminal stage, but
    // the actual Finalizing producer always refuses that separate condition.
    ensure_no_reserved_terminal_stage(tx, request.claim.operation_id)?;
    request
        .outcome
        .validate_for_store_insert(
            &stored.operation,
            request.blob,
            &owner.fence,
            request.trusted_now_unix_ms,
        )
        .map_err(|error| invariant(error.to_string()))?;
    let outcome_json = crate::tool_outcome_store::encode_outcome(request.outcome)
        .map_err(|error| invariant(error.to_string()))?;
    let existing: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM main.tool_outcomes WHERE operation_id=?1)",
            [request.claim.operation_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if existing {
        // Exact retained outcome replays are resolved by their owning writer;
        // they are not a fresh Raw purpose or a second available reservation.
        return Err(invariant("Raw liability is not a fresh outcome purpose"));
    }
    let operation_source = rows::source_digest(
        tx,
        RawWriteTableData::Operations,
        request.claim.operation_id.as_str(),
    )?;
    let blob_source = rows::source_digest(
        tx,
        RawWriteTableData::Blobs,
        request.blob.blob_ref().digest().as_str(),
    )?;
    let rows = rows::describe_raw_rows(tx, owner, &request, &outcome_json)?;
    let admission_head = load_admission_commit_head(tx)?;
    admission_head
        .head_sequence
        .checked_add(2)
        .filter(|value| *value <= 9_007_199_254_740_991)
        .ok_or_else(|| invariant("Raw admission append capacity is exhausted"))?;
    global_head
        .0
        .checked_add(2)
        .filter(|value| *value <= 9_007_199_254_740_991)
        .ok_or_else(|| invariant("Raw global append capacity is exhausted"))?;
    Ok(VerifiedRawCustodyWriteLiability {
        tx,
        owner,
        origin,
        request,
        operation_source,
        blob_source,
        admission_head,
        global_head,
        profile,
        rows,
    })
}

impl VerifiedRawCustodyWriteLiability<'_, '_> {
    pub(super) fn verify_before(
        &self,
        tx: &Transaction<'_>,
        writer: (&SqliteServingOwner, &NativeSourceTransactionOrigin<'_>),
    ) -> Result<(), AdmissionOperationStoreError> {
        let (owner, origin) = writer;
        let profile = raw_write_profile(tx)?;
        self.origin.verify(tx).map_err(map_owner_error)?;
        origin.verify(tx).map_err(map_owner_error)?;
        if !std::ptr::eq(&**self.tx, &**tx)
            || !std::ptr::eq(self.owner, owner)
            || !origin.matches_owner(owner)
            || origin.prepared_global_sequence() != self.origin.prepared_global_sequence()
            || profile.fingerprint() != self.profile.fingerprint()
            || global_head(tx)? != self.global_head
            || load_admission_commit_head(tx)? != self.admission_head
            || rows::source_digest(
                tx,
                RawWriteTableData::Operations,
                self.request.claim.operation_id.as_str(),
            )? != self.operation_source
            || rows::source_digest(
                tx,
                RawWriteTableData::Blobs,
                self.request.blob.blob_ref().digest().as_str(),
            )? != self.blob_source
        {
            return Err(invariant("Raw liability lost its exact prewrite source"));
        }
        let existing: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM main.tool_outcomes WHERE operation_id=?1)",
                [self.request.claim.operation_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if existing {
            return Err(invariant("Raw liability outcome purpose is already used"));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn operation_id_for_test(&self) -> &str {
        self.request.operation.binding().operation_id().as_str()
    }

    pub(super) fn rows(&self) -> &[RawRowWriteShapeData] {
        &self.rows
    }

    pub(super) fn profile(&self) -> &RawWriteProfileData {
        &self.profile
    }
}

fn global_head(tx: &Connection) -> Result<(u64, String), AdmissionOperationStoreError> {
    let (sequence, digest): (i64, String) = tx
        .query_row(
            "SELECT head_sequence,head_chain_digest FROM main.authority_global_commit_meta
             WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invariant("Raw global head digest is invalid"));
    }
    Ok((stored_u64(sequence, "Raw global head")?, digest))
}
