//! Operator cancellation and pre-dispatch compensation of governed
//! active-response preparations.

use super::{
    active_response_internal, AdmissionOperationState, ChioKernel,
    GovernedActiveResponseReservation, KernelError,
};

impl ChioKernel {
    /// The approval commit is the dispatch commit point. Operator cancellation
    /// reconciles it first, so a committed approval leaves a recoverable
    /// DispatchCommitted operation that pre-dispatch compensation refuses.
    pub(super) fn cancel_active_response_before_dispatch(
        &self,
        reservation: &GovernedActiveResponseReservation,
        reason: &str,
    ) -> Result<(), KernelError> {
        let operation = self.load_active_response_operation(reservation.operation_id())?;
        if operation.state() == AdmissionOperationState::ApprovalReserved
            && operation.has_same_prepared_binding(&reservation.operation)
        {
            let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
                active_response_internal("durable active-response operation store is not installed")
            })?;
            self.reconcile_governed_active_response_commit(
                operation_store.as_ref(),
                self.approval_store.as_deref(),
                &operation,
            )?;
        }
        self.compensate_active_response_before_dispatch(reservation, reason)
    }

    pub(super) fn compensate_active_response_before_dispatch(
        &self,
        reservation: &GovernedActiveResponseReservation,
        reason: &str,
    ) -> Result<(), KernelError> {
        let mut operation = self.load_active_response_operation(reservation.operation_id())?;
        if !operation.has_same_prepared_binding(&reservation.operation) {
            return Err(active_response_internal(
                "cannot compensate an active-response operation with different identity",
            ));
        }
        if operation.state() == AdmissionOperationState::DispatchCommitted {
            return Err(active_response_internal(
                "cannot compensate after active-response dispatch commitment",
            ));
        }
        if matches!(
            operation.state(),
            AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch
        ) {
            if !self.recover_compensated_admission_operation(operation.operation_id())? {
                return Err(active_response_internal(
                    "active-response cleanup is owned by another recovery worker",
                ));
            }
            return Ok(());
        }
        if operation.state().is_terminal() {
            return Err(active_response_internal(
                "terminal active-response operation cannot be compensated",
            ));
        }

        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            active_response_internal("active-response admission operation store is unavailable")
        })?;
        operation = self.stage_compensation_pending_with_terminal_receipt(
            store.as_ref(),
            &operation,
            reason,
        )?;
        if operation.state() == AdmissionOperationState::CompensationPending {
            if !self.recover_compensated_admission_operation(operation.operation_id())? {
                return Err(active_response_internal(
                    "active-response cleanup is owned by another recovery worker",
                ));
            }
            return Ok(());
        }
        Err(active_response_internal(
            "active-response compensation did not enter its signed terminal outbox",
        ))
    }
}
