//! One retained operation's recovery step; no invocation can be dispatched here.

use super::*;
use crate::admission_operation::{AdmissionRecoveryFailureKind as Kind, AdmissionRecoveryPhase};

pub(super) fn phase(operation: &AdmissionOperationV1) -> AdmissionRecoveryPhase {
    match operation.state() {
        AdmissionOperationState::Finalizing => AdmissionRecoveryPhase::Returned,
        AdmissionOperationState::DispatchCommitted => AdmissionRecoveryPhase::CommittedUnknown,
        AdmissionOperationState::Prepared
        | AdmissionOperationState::BrokerAttemptRegistered
        | AdmissionOperationState::BudgetAuthorized
        | AdmissionOperationState::ApprovalReserved
        | AdmissionOperationState::ReadyToDispatch
        | AdmissionOperationState::CapturePending
        | AdmissionOperationState::ApprovalRequired => AdmissionRecoveryPhase::BeforeDispatch,
        _ => AdmissionRecoveryPhase::Inspection,
    }
}

impl ChioKernel {
    pub(super) fn recover_one_admission(
        &self,
        operation: &AdmissionOperationV1,
        now: u64,
    ) -> Result<bool, KernelError> {
        if operation.binding().kind() != AdmissionOperationKind::ToolDispatch {
            return Err(failure::item_failure(
                Kind::UnsupportedState,
                "retained operation requires its owning non-tool coordinator",
            ));
        }
        match operation.state() {
            state if state.is_terminal() => Ok(false),
            AdmissionOperationState::AwaitingCallerReport => Ok(false),
            AdmissionOperationState::DispatchCommitted => {
                if !self.retain_authenticated_caller_wait(operation, now)? {
                    self.terminalize_dispatch_committed_admission(operation, now)?;
                }
                Ok(true)
            }
            AdmissionOperationState::Prepared
                if self.durable_nonce_issuance_is_live(operation, now)? =>
            {
                Ok(false)
            }
            AdmissionOperationState::ReadyToDispatch
                if self.durable_caller_reservation_is_live(operation, now)? =>
            {
                Ok(false)
            }
            AdmissionOperationState::Prepared
            | AdmissionOperationState::BrokerAttemptRegistered
            | AdmissionOperationState::BudgetAuthorized
            | AdmissionOperationState::ApprovalReserved
            | AdmissionOperationState::ReadyToDispatch
            | AdmissionOperationState::CapturePending => {
                self.compensate_durable_admission_before_dispatch(operation,
                    serde_json::json!({"authority": "startup-recovery", "cause": "no-authoritative-budget-participant"}), now, None)?;
                Ok(true)
            }
            AdmissionOperationState::ApprovalRequired => {
                let deadline = operation
                    .parked_approval_deadline_unix_ms()
                    .map_err(failure::operation_error)?;
                let Some(deadline) = deadline.filter(|deadline| *deadline <= now) else {
                    return Ok(false);
                };
                self.compensate_durable_admission_before_dispatch(operation,
                    serde_json::json!({"authority": "startup-recovery", "cause": "approval-deadline-elapsed", "proposal_deadline_unix_ms": deadline}), now, None)?;
                Ok(true)
            }
            AdmissionOperationState::Finalizing => {
                let retained_request =
                    self.load_original_request_for_finalization(operation, now)?;
                let mut admission = DurableToolAdmission {
                    _live_owner: None,
                    operation: operation.clone(),
                    aggregate_quota: None,
                    supplemental_quota: None,
                    retained_request,
                    issued_nonce: None,
                    nonce_preflight: None,
                };
                let returned = self.load_durable_tool_return(&admission)?;
                let Some(request) = returned.recovery_request().map_err(tool_outcome_error)? else {
                    return Err(failure::item_failure(
                        Kind::RecoveryRequestAbsent,
                        "retained tool return has no authenticated original request",
                    ));
                };
                RECEIPT_EVALUATION_SCOPE_KEY
                    .sync_scope(uuid::Uuid::now_v7().to_string(), || {
                        self.finalize_durable_tool_return(&mut admission, &request, &returned)
                    })?;
                Ok(true)
            }
            _ => Err(failure::item_failure(
                Kind::UnsupportedState,
                "retained operation has no supported tool-admission recovery step",
            )),
        }
    }
}
