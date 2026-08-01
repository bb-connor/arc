use crate::approval::{ApprovalReservation, ApprovalSetReservationInput, ApprovalStore};
use crate::security_admission_operation::{AdmissionOperation, ReplayReservationState};

use super::admission_cleanup::ApprovalCleanupPayload;
use super::{ChioKernel, KernelError};

pub(super) fn approval_set_input_is_valid(input: &ApprovalSetReservationInput) -> bool {
    ApprovalSetReservationInput::new(
        input.approval_set_hash().to_string(),
        input.members().to_vec(),
        input.proposal_deadline(),
    )
    .is_ok_and(|normalized| normalized == *input)
}

fn exact_reservation(
    reservation: ApprovalReservation,
    operation: &AdmissionOperation,
    approval_set: &ApprovalSetReservationInput,
) -> Result<ApprovalReservation, KernelError> {
    if reservation.operation_id() != operation.operation_id()
        || reservation.approval_set() != approval_set
    {
        return Err(KernelError::Internal(
            "approval cleanup reservation has a different operation or set".to_string(),
        ));
    }
    Ok(reservation)
}

impl ChioKernel {
    pub(super) fn execute_approval_cleanup(
        &self,
        approval_store: Option<&dyn ApprovalStore>,
        operation: &AdmissionOperation,
        payload: ApprovalCleanupPayload,
    ) -> Result<(), KernelError> {
        if payload.operation_id != operation.operation_id()
            || operation.approval_set_hash() != Some(payload.approval_set.approval_set_hash())
            || !approval_set_input_is_valid(&payload.approval_set)
        {
            return Err(KernelError::Internal(
                "approval cleanup input does not match the operation".to_string(),
            ));
        }
        let store = approval_store.ok_or_else(|| {
            KernelError::Internal(
                "approval cleanup authority is unavailable for a journaled action".to_string(),
            )
        })?;
        let reservation = match store
            .get_approval_reservation(operation.operation_id())
            .map_err(|error| {
                KernelError::Internal(format!("approval cleanup lookup failed: {error}"))
            })? {
            Some(reservation) => reservation,
            None => match store.reserve_approval_set(
                operation.operation_id(),
                &payload.approval_set,
            ) {
                Ok(reservation) => reservation,
                Err(error) => store
                    .get_approval_reservation(operation.operation_id())
                    .map_err(|lookup| {
                        KernelError::Internal(format!(
                            "approval cleanup reservation failed: {error}; readback failed: {lookup}"
                        ))
                    })?
                    .ok_or_else(|| {
                        KernelError::Internal(format!(
                            "approval cleanup reservation failed without durable readback: {error}"
                        ))
                    })?,
            },
        };
        let reservation = exact_reservation(reservation, operation, &payload.approval_set)?;
        match reservation.state() {
            ReplayReservationState::Cancelled => Ok(()),
            ReplayReservationState::Reserved => {
                let cancelled = match store
                    .cancel_approval_reservation(operation.operation_id())
                {
                    Ok(cancelled) => cancelled,
                    Err(error) => store
                        .get_approval_reservation(operation.operation_id())
                        .map_err(|lookup| {
                            KernelError::Internal(format!(
                                "approval cleanup cancellation failed: {error}; readback failed: {lookup}"
                            ))
                        })?
                        .ok_or_else(|| {
                            KernelError::Internal(format!(
                                "approval cleanup cancellation failed without durable readback: {error}"
                            ))
                        })?,
                };
                let cancelled = exact_reservation(cancelled, operation, &payload.approval_set)?;
                if cancelled.state() != ReplayReservationState::Cancelled {
                    return Err(KernelError::Internal(
                        "approval cleanup did not establish a cancellation tombstone".to_string(),
                    ));
                }
                Ok(())
            }
            // A replay commit can precede capture. If capture or a later
            // pre-dispatch step fails, the committed tombstone remains consumed
            // by design; compensation reverses budget, not replay protection.
            ReplayReservationState::Committed => Ok(()),
        }
    }
}
