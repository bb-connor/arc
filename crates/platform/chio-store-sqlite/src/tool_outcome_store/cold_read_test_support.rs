//! Read-stage allocation observations for explicitly hostile retained rows.
//! Only byte lengths leave the default-off test support; no custody is minted.
use super::*;
use std::cell::Cell;

thread_local! {
    static READ_ALLOCATION_LENGTHS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
}

pub(super) fn observe_raw_allocation(bytes: usize) {
    READ_ALLOCATION_LENGTHS.with(|observed| {
        let (_, evaluation) = observed.get();
        observed.set((bytes, evaluation));
    });
}

pub(super) fn observe_evaluation_allocation(bytes: usize) {
    READ_ALLOCATION_LENGTHS.with(|observed| {
        let (raw, _) = observed.get();
        observed.set((raw, bytes));
    });
}

/// The caller first authenticates the actual original under its read transaction.
/// Both parser results are deliberately discarded: malformed hostile bytes must
/// not make an allocation regression pass merely by producing a decode error.
pub(crate) fn original_read_stage_allocations_for_test(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    hostile_blob_digest: &AdmissionDigest,
) -> Result<(u64, u64), ToolOutcomeStoreError> {
    READ_ALLOCATION_LENGTHS.with(|observed| observed.set((0, 0)));
    let _ = load_blob_state_connection(transaction, hostile_blob_digest, operation_id.as_str());
    let _ = load_evaluation_connection(transaction, operation_id.as_str());
    let (raw, evaluation) = READ_ALLOCATION_LENGTHS.with(Cell::get);
    Ok((
        u64::try_from(raw).map_err(|error| invariant(error.to_string()))?,
        u64::try_from(evaluation).map_err(|error| invariant(error.to_string()))?,
    ))
}
