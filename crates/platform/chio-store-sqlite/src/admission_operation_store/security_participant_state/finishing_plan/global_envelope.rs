//! Current admission producer global rows, never a caller-selected row price.
use super::*;

/// This closed DATA is scoped to the ToolOutcome admission producers below.
/// Native Output, Status, Knowledge, bank and Source41 rows have distinct
/// producer shapes and cannot borrow this current40 envelope.
pub(in crate::admission_operation_store) struct NativeToolOutcomeGlobalEnvelopeData {
    maximum_record_bytes: u64,
    maximum_index_record_bytes: u64,
}

impl NativeToolOutcomeGlobalEnvelopeData {
    pub(in crate::admission_operation_store) fn maximum_record_bytes(&self) -> u64 {
        self.maximum_record_bytes
    }

    pub(in crate::admission_operation_store) fn maximum_index_record_bytes(&self) -> u64 {
        self.maximum_index_record_bytes
    }
}

pub(super) fn describe_original_tool_outcome_global(
    owner: &SqliteServingOwner,
    operation: &AdmissionOperationV1,
) -> Result<NativeToolOutcomeGlobalEnvelopeData, AdmissionOperationStoreError> {
    // The serving owner issues canonical hyphenated UUIDs. Reopening can
    // replace the lease but cannot enlarge that actual source field contract.
    let uuid = canonical_uuid_bytes(&owner.fence.store_uuid)?;
    let lease = canonical_uuid_bytes(&owner.fence.lease_id)?;
    let operation =
        u64::try_from(operation.binding().operation_id().as_str().len()).map_err(invalid)?;
    let projection = u64::try_from("admission".len()).map_err(invalid)?;
    // Raw and EvalBegin can renew a claim. The bounded Pure prefix/final pair
    // uses the actual compare-and-swap participant producer. This envelope
    // deliberately covers no runtime/governed/DPOP/payment participant.
    let mutation = [
        COMBINED_CAPTURE_OPERATION_MUTATION_KIND,
        "participant_update",
        "recovery_claim",
    ]
    .into_iter()
    .map(str::len)
    .max()
    .ok_or_else(|| invalid("ToolOutcome global producer set is empty"))?;
    let mutation = u64::try_from(mutation).map_err(invalid)?;
    // The exact current40 global table has twelve columns and the sole
    // projection index stores its three key fields plus the rowid. The full
    // eight-table catalogue is independently checked before this constructor.
    Ok(NativeToolOutcomeGlobalEnvelopeData {
        maximum_record_bytes: record_bytes(&[
            8, mutation, projection, operation, 8, 64, 64, 64, 64, uuid, lease, 8,
        ])?,
        maximum_index_record_bytes: record_bytes(&[projection, operation, 8, 8])?,
    })
}

fn canonical_uuid_bytes(value: &str) -> Result<u64, AdmissionOperationStoreError> {
    let parsed = uuid::Uuid::parse_str(value).map_err(invalid)?;
    let canonical = parsed.hyphenated().to_string();
    if canonical != value {
        return Err(invalid(
            "native finishing owner identifier is not canonical",
        ));
    }
    u64::try_from(canonical.len()).map_err(invalid)
}

fn record_bytes(cells: &[u64]) -> Result<u64, AdmissionOperationStoreError> {
    // Nine bytes cover each serial-type varint and the record-header length.
    // Integer payloads are charged at eight bytes regardless of present width.
    let header = u64::try_from(cells.len())
        .map_err(invalid)?
        .checked_add(1)
        .and_then(|fields| fields.checked_mul(9))
        .ok_or_else(|| invalid("native global row header overflow"))?;
    cells.iter().try_fold(header, |sum, bytes| {
        sum.checked_add(*bytes)
            .ok_or_else(|| invalid("native global row payload overflow"))
    })
}
