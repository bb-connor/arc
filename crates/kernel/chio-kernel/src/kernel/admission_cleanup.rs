use serde::{Deserialize, Serialize};

use super::active_response_operation_binding::ActiveResponseOperationAnchor;
use super::approval_cleanup::approval_set_input_is_valid;
use super::*;
use crate::approval::{ApprovalSetReservationInput, ApprovalStore};
use crate::security_admission_operation::{
    AdmissionCleanupAction, AdmissionCleanupActionCasOutcome, AdmissionCleanupActionClaimOutcome,
    AdmissionCleanupActionCreateOutcome, AdmissionCleanupActionKind, AdmissionCleanupActionState,
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationCasOutcome,
    AdmissionOperationCompareAndSwap, AdmissionOperationKind, AdmissionOperationState,
    AdmissionOperationStore, ReplayReservationState,
};

const CLEANUP_CLAIM_LEASE_MS: u64 = 30_000;
const MAX_ACTIVE_RESPONSE_RECOVERY_OPERATIONS_PER_ACTIVATION: usize = 4_096;
const APPROVAL_CLEANUP_SCHEMA: &str = "chio.admission-cleanup.approval.v2";
const ACTIVE_RESPONSE_APPROVAL_CLEANUP_SCHEMA: &str =
    "chio.admission-cleanup.active-response-approval.v2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ApprovalCleanupPayload {
    pub(super) schema: String,
    pub(super) operation_id: String,
    pub(super) approval_set: ApprovalSetReservationInput,
}

pub(super) enum ActiveResponseOperationAnchorJournalError {
    Conflict,
    Kernel(KernelError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActiveResponseApprovalCleanupPayload {
    schema: String,
    operation_id: String,
    dispatch_anchor: ActiveResponseOperationAnchor,
    approval_set: ApprovalSetReservationInput,
}

impl ChioKernel {
    pub(super) fn prepare_current_admission_authority_replacement(
        &self,
    ) -> Result<(), KernelError> {
        let Some(store) = self.admission_operation_store.as_ref() else {
            return Ok(());
        };
        self.recover_terminal_receipt_outboxes_with_store(
            store.as_ref(),
            AdmissionOperationKind::GovernedActiveResponse,
            None,
        )?;
        self.drain_compensated_active_response_operations(
            store.as_ref(),
            self.approval_store.as_deref(),
        )?;
        let unresolved = store.count_unresolved(AdmissionOperationKind::GovernedActiveResponse)?;
        if unresolved != 0 {
            return Err(KernelError::Internal(format!(
                "admission authority replacement would strand {unresolved} unresolved governed active-response operations"
            )));
        }
        Ok(())
    }

    pub(super) fn journal_active_response_operation_anchor(
        &self,
        operation: &AdmissionOperation,
        candidate: ActiveResponseOperationAnchor,
        approval_set: &ApprovalSetReservationInput,
    ) -> Result<ActiveResponseOperationAnchor, ActiveResponseOperationAnchorJournalError> {
        if operation.kind() != AdmissionOperationKind::GovernedActiveResponse
            || !candidate.is_valid()
            || operation.approval_set_hash() != Some(candidate.approval_set_hash.as_str())
            || candidate.approval_set_hash != approval_set.approval_set_hash()
        {
            return Err(ActiveResponseOperationAnchorJournalError::Kernel(
                KernelError::Internal("active-response operation anchor is invalid".to_string()),
            ));
        }
        let payload = ActiveResponseApprovalCleanupPayload {
            schema: ACTIVE_RESPONSE_APPROVAL_CLEANUP_SCHEMA.to_string(),
            operation_id: operation.operation_id().to_string(),
            dispatch_anchor: candidate.clone(),
            approval_set: approval_set.clone(),
        };
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            ActiveResponseOperationAnchorJournalError::Kernel(KernelError::Internal(
                "durable admission operation store is unavailable".to_string(),
            ))
        })?;
        let anchor_exists = store
            .load_cleanup_actions(operation.operation_id())
            .map_err(KernelError::from)
            .map_err(ActiveResponseOperationAnchorJournalError::Kernel)?
            .iter()
            .any(|action| action.kind() == AdmissionCleanupActionKind::Approval);
        if anchor_exists {
            let retained = self
                .load_active_response_operation_anchor_payload(operation)
                .map_err(ActiveResponseOperationAnchorJournalError::Kernel)?;
            return if retained.approval_set == *approval_set
                && retained
                    .dispatch_anchor
                    .matches_except_authorized_at(&candidate)
            {
                Ok(retained.dispatch_anchor)
            } else {
                Err(ActiveResponseOperationAnchorJournalError::Conflict)
            };
        }
        let action = AdmissionCleanupAction::pending(
            operation,
            AdmissionCleanupActionKind::Approval,
            &payload,
        )
        .map_err(KernelError::from)
        .map_err(ActiveResponseOperationAnchorJournalError::Kernel)?;
        match store.create_cleanup_action(action.clone()) {
            Ok(AdmissionCleanupActionCreateOutcome::Created(retained))
            | Ok(AdmissionCleanupActionCreateOutcome::Existing(retained))
                if retained == action => {}
            Ok(_) => {
                return Err(ActiveResponseOperationAnchorJournalError::Kernel(
                    KernelError::Internal(
                        "active-response anchor store returned a different action".to_string(),
                    ),
                ))
            }
            Err(error) => {
                if let Ok(retained) = self.load_active_response_operation_anchor_payload(operation)
                {
                    return if retained.approval_set == *approval_set
                        && retained
                            .dispatch_anchor
                            .matches_except_authorized_at(&candidate)
                    {
                        Ok(retained.dispatch_anchor)
                    } else {
                        Err(ActiveResponseOperationAnchorJournalError::Conflict)
                    };
                }
                return Err(ActiveResponseOperationAnchorJournalError::Kernel(
                    error.into(),
                ));
            }
        }
        let retained = self
            .load_active_response_operation_anchor_payload(operation)
            .map_err(ActiveResponseOperationAnchorJournalError::Kernel)?;
        if retained.approval_set != *approval_set
            || !retained
                .dispatch_anchor
                .matches_except_authorized_at(&candidate)
        {
            return Err(ActiveResponseOperationAnchorJournalError::Conflict);
        }
        Ok(retained.dispatch_anchor)
    }

    pub(super) fn load_active_response_operation_anchor(
        &self,
        operation: &AdmissionOperation,
    ) -> Result<ActiveResponseOperationAnchor, KernelError> {
        Ok(self
            .load_active_response_operation_anchor_payload(operation)?
            .dispatch_anchor)
    }

    pub(super) fn load_active_response_operation_anchor_with_store(
        &self,
        store: &dyn AdmissionOperationStore,
        operation: &AdmissionOperation,
    ) -> Result<ActiveResponseOperationAnchor, KernelError> {
        Ok(self
            .load_active_response_operation_anchor_payload_with_store(store, operation)?
            .dispatch_anchor)
    }

    fn load_active_response_operation_anchor_payload(
        &self,
        operation: &AdmissionOperation,
    ) -> Result<ActiveResponseApprovalCleanupPayload, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        self.load_active_response_operation_anchor_payload_with_store(store.as_ref(), operation)
    }

    fn load_active_response_operation_anchor_payload_with_store(
        &self,
        store: &dyn AdmissionOperationStore,
        operation: &AdmissionOperation,
    ) -> Result<ActiveResponseApprovalCleanupPayload, KernelError> {
        let actions = store
            .load_cleanup_actions(operation.operation_id())
            .map_err(|error| {
                KernelError::Internal(format!(
                    "active-response operation anchor lookup failed: {error}"
                ))
            })?;
        let approval_actions = actions
            .iter()
            .filter(|action| action.kind() == AdmissionCleanupActionKind::Approval)
            .collect::<Vec<_>>();
        let [action] = approval_actions.as_slice() else {
            return Err(KernelError::Internal(
                "active-response operation must retain exactly one dispatch anchor".to_string(),
            ));
        };
        if action.operation_id() != operation.operation_id()
            || action.request_binding_hash() != operation.request_binding_hash()
        {
            return Err(KernelError::Internal(
                "active-response operation anchor changed operation identity".to_string(),
            ));
        }
        let payload: ActiveResponseApprovalCleanupPayload = parse_cleanup_payload(action)?;
        validate_schema(&payload.schema, ACTIVE_RESPONSE_APPROVAL_CLEANUP_SCHEMA)?;
        if payload.operation_id != operation.operation_id()
            || operation.approval_set_hash()
                != Some(payload.dispatch_anchor.approval_set_hash.as_str())
            || payload.approval_set.approval_set_hash() != payload.dispatch_anchor.approval_set_hash
            || !approval_set_input_is_valid(&payload.approval_set)
            || !payload.dispatch_anchor.is_valid()
        {
            return Err(KernelError::Internal(
                "active-response operation anchor payload is invalid".to_string(),
            ));
        }
        Ok(payload)
    }

    pub(super) fn claim_pre_dispatch_compensation(
        &self,
        operation_id: &str,
        reason: &str,
    ) -> Result<Option<AdmissionOperation>, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let operation = store.load(operation_id)?.ok_or_else(|| {
            KernelError::Internal(format!("admission operation {operation_id} disappeared"))
        })?;
        if operation.kind() != AdmissionOperationKind::GovernedActiveResponse {
            return Ok(None);
        }
        if matches!(
            operation.state(),
            AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch
        ) {
            self.recover_compensated_active_response_operation_with_store(
                store.as_ref(),
                self.approval_store.as_deref(),
                operation_id,
            )?;
            return store.load(operation_id).map_err(KernelError::from);
        }
        if operation.dispatch_state() != AdmissionDispatchState::NotStarted
            || operation.state().is_terminal()
        {
            return Ok(None);
        }
        let staged = self.stage_compensation_pending_with_terminal_receipt(
            store.as_ref(),
            &operation,
            reason,
        )?;
        if staged.state() == AdmissionOperationState::CompensationPending {
            self.recover_compensated_active_response_operation_with_store(
                store.as_ref(),
                self.approval_store.as_deref(),
                operation_id,
            )?;
        }
        store.load(operation_id).map_err(KernelError::from)
    }

    pub(super) fn recover_compensated_admission_operation(
        &self,
        operation_id: &str,
    ) -> Result<bool, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        self.recover_compensated_active_response_operation_with_store(
            store.as_ref(),
            self.approval_store.as_deref(),
            operation_id,
        )
    }

    pub(super) fn drain_compensated_active_response_operations(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        approval_store: Option<&dyn ApprovalStore>,
    ) -> Result<usize, KernelError> {
        let mut operation_ids = operation_store.list_compensated_with_pending_cleanup(
            Some(AdmissionOperationKind::GovernedActiveResponse),
            MAX_ACTIVE_RESPONSE_RECOVERY_OPERATIONS_PER_ACTIVATION + 1,
        )?;
        if operation_ids.len() > MAX_ACTIVE_RESPONSE_RECOVERY_OPERATIONS_PER_ACTIVATION {
            return Err(KernelError::Internal(format!(
                "more governed active-response cleanup operations remain after the bounded {MAX_ACTIVE_RESPONSE_RECOVERY_OPERATIONS_PER_ACTIVATION}-operation recovery batch"
            )));
        }
        let mut recovered = 0usize;
        for operation_id in operation_ids.drain(..) {
            if self.recover_compensated_active_response_operation_with_store(
                operation_store,
                approval_store,
                &operation_id,
            )? {
                recovered = recovered.checked_add(1).ok_or_else(|| {
                    KernelError::Internal(
                        "active-response cleanup recovery count overflowed usize".to_string(),
                    )
                })?;
            }
        }
        Ok(recovered)
    }

    fn recover_compensated_active_response_operation_with_store(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        approval_store: Option<&dyn ApprovalStore>,
        operation_id: &str,
    ) -> Result<bool, KernelError> {
        let operation = operation_store.load(operation_id)?.ok_or_else(|| {
            KernelError::Internal(format!(
                "active-response cleanup operation {operation_id} disappeared"
            ))
        })?;
        if operation.kind() != AdmissionOperationKind::GovernedActiveResponse
            || !matches!(
                operation.state(),
                AdmissionOperationState::CompensationPending
                    | AdmissionOperationState::CompensatedBeforeDispatch
            )
        {
            return Err(KernelError::Internal(format!(
                "active-response cleanup refused operation {} in {}",
                operation.operation_id(),
                operation.state().as_str()
            )));
        }
        if operation.state() == AdmissionOperationState::CompensatedBeforeDispatch {
            self.validate_terminal_receipt_binding_with_store(operation_store, &operation)?;
            self.recover_terminal_receipt_outboxes_with_store(
                operation_store,
                AdmissionOperationKind::GovernedActiveResponse,
                Some(operation.coordinator_authority_id()),
            )?;
            return Ok(true);
        }

        let actions = operation_store.load_cleanup_actions(operation_id)?;
        for action in actions.iter().filter(|action| {
            action.kind() != AdmissionCleanupActionKind::TerminalReceipt
                && action.state() != AdmissionCleanupActionState::Completed
        }) {
            if action.kind() != AdmissionCleanupActionKind::Approval {
                return Err(KernelError::Internal(format!(
                    "governed active-response operation contains unsupported {} cleanup",
                    action.kind().as_str()
                )));
            }
            let active: ActiveResponseApprovalCleanupPayload = parse_cleanup_payload(action)?;
            validate_schema(&active.schema, ACTIVE_RESPONSE_APPROVAL_CLEANUP_SCHEMA)?;
            let payload = ApprovalCleanupPayload {
                schema: APPROVAL_CLEANUP_SCHEMA.to_string(),
                operation_id: active.operation_id,
                approval_set: active.approval_set,
            };
            self.execute_claimed_cleanup_action(operation_store, &operation, action, || {
                self.execute_approval_cleanup(approval_store, &operation, payload)
            })?;
        }

        let participants_completed = operation_store
            .load_cleanup_actions(operation_id)?
            .iter()
            .all(|action| {
                action.kind() == AdmissionCleanupActionKind::TerminalReceipt
                    || action.state() == AdmissionCleanupActionState::Completed
            });
        if !participants_completed {
            return Ok(false);
        }
        let current = operation_store.load(operation_id)?.ok_or_else(|| {
            KernelError::Internal(
                "active-response operation disappeared before terminal receipt commit".to_string(),
            )
        })?;
        match current.state() {
            AdmissionOperationState::CompensationPending => {
                self.finalize_staged_compensation_terminal_receipt(operation_store, &current)?;
            }
            AdmissionOperationState::CompensatedBeforeDispatch => {
                self.validate_terminal_receipt_binding_with_store(operation_store, &current)?;
            }
            state => {
                return Err(KernelError::Internal(format!(
                    "active-response compensation changed to {} before terminal receipt commit",
                    state.as_str()
                )))
            }
        }
        Ok(true)
    }

    fn execute_claimed_cleanup_action<F>(
        &self,
        store: &dyn AdmissionOperationStore,
        operation: &AdmissionOperation,
        action: &AdmissionCleanupAction,
        execute: F,
    ) -> Result<(), KernelError>
    where
        F: FnOnce() -> Result<(), KernelError>,
    {
        let now_unix_ms = current_unix_timestamp_ms();
        let claim_deadline_unix_ms =
            now_unix_ms
                .checked_add(CLEANUP_CLAIM_LEASE_MS)
                .ok_or_else(|| {
                    KernelError::Internal("cleanup claim deadline overflowed u64".to_string())
                })?;
        let claim_token = uuid::Uuid::now_v7().to_string();
        let claimed = match store.claim_cleanup_action(
            action.action_id(),
            &claim_token,
            now_unix_ms,
            claim_deadline_unix_ms,
        )? {
            AdmissionCleanupActionClaimOutcome::Claimed(claimed) => claimed,
            AdmissionCleanupActionClaimOutcome::Completed(_) => return Ok(()),
            AdmissionCleanupActionClaimOutcome::Busy(_) => return Ok(()),
            AdmissionCleanupActionClaimOutcome::Missing => {
                return Err(KernelError::Internal(
                    "cleanup action disappeared during claim".to_string(),
                ))
            }
        };
        if let Err(error) = execute() {
            let _ = store.abandon_cleanup_action(
                claimed.action_id(),
                claimed.version(),
                &claim_token,
                error.to_string(),
            );
            return Err(error);
        }
        match store.acknowledge_cleanup_action(
            claimed.action_id(),
            claimed.version(),
            &claim_token,
        )? {
            AdmissionCleanupActionCasOutcome::Applied(_) => Ok(()),
            AdmissionCleanupActionCasOutcome::Conflict(_) => {
                let completed = store
                    .load_cleanup_actions(operation.operation_id())?
                    .iter()
                    .any(|current| {
                        current.action_id() == claimed.action_id()
                            && current.state() == AdmissionCleanupActionState::Completed
                    });
                if completed {
                    Ok(())
                } else {
                    Err(KernelError::Internal(
                        "cleanup acknowledgement conflicted".to_string(),
                    ))
                }
            }
            AdmissionCleanupActionCasOutcome::Missing => Err(KernelError::Internal(
                "cleanup action disappeared before acknowledgement".to_string(),
            )),
        }
    }

    pub(super) fn discharge_admission_cleanup_action_with_store(
        &self,
        store: &dyn AdmissionOperationStore,
        operation: &AdmissionOperation,
        kind: AdmissionCleanupActionKind,
    ) -> Result<(), KernelError> {
        let actions = store
            .load_cleanup_actions(operation.operation_id())?
            .into_iter()
            .filter(|action| action.kind() == kind)
            .collect::<Vec<_>>();
        let [action] = actions.as_slice() else {
            return Err(KernelError::Internal(format!(
                "operation {} does not have exactly one {} cleanup action",
                operation.operation_id(),
                kind.as_str()
            )));
        };
        self.execute_claimed_cleanup_action(store, operation, action, || Ok(()))
    }

    pub(super) fn reconcile_governed_active_response_commit(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        approval_store: Option<&dyn ApprovalStore>,
        operation: &AdmissionOperation,
    ) -> Result<Option<AdmissionOperation>, KernelError> {
        if operation.kind() != AdmissionOperationKind::GovernedActiveResponse
            || !matches!(
                operation.state(),
                AdmissionOperationState::ApprovalReserved
                    | AdmissionOperationState::DispatchCommitted
            )
        {
            return Ok(None);
        }
        let payload = self
            .load_active_response_operation_anchor_payload_with_store(operation_store, operation)?;
        let store = approval_store.ok_or_else(|| {
            KernelError::Internal(
                "governed active-response approval authority is unavailable during recovery"
                    .to_string(),
            )
        })?;
        let reservation = store
            .get_approval_reservation(operation.operation_id())
            .map_err(|error| {
                KernelError::Internal(format!(
                    "governed active-response approval lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                KernelError::Internal(
                    "governed active-response approval reservation is missing".to_string(),
                )
            })?;
        if reservation.operation_id() != operation.operation_id()
            || reservation.approval_set() != &payload.approval_set
        {
            return Err(KernelError::Internal(
                "governed active-response approval reservation changed its exact binding"
                    .to_string(),
            ));
        }

        match operation.state() {
            AdmissionOperationState::ApprovalReserved => match reservation.state() {
                ReplayReservationState::Reserved | ReplayReservationState::Cancelled => Ok(None),
                ReplayReservationState::Committed => {
                    let expected = operation.transition_checked(
                        AdmissionOperationState::DispatchCommitted,
                        AdmissionDispatchState::Committed,
                        operation.coordinator_lease_epoch(),
                        None,
                    )?;
                    match operation_store.compare_and_swap(AdmissionOperationCompareAndSwap {
                        operation_id: operation.operation_id(),
                        expected_version: operation.version(),
                        coordinator_lease_epoch: operation.coordinator_lease_epoch(),
                        next_state: AdmissionOperationState::DispatchCommitted,
                        next_dispatch_state: AdmissionDispatchState::Committed,
                        next_coordinator_lease_epoch: operation.coordinator_lease_epoch(),
                        last_error: None,
                    })? {
                        AdmissionOperationCasOutcome::Applied(committed)
                            if committed == expected =>
                        {
                            Ok(Some(committed))
                        }
                        AdmissionOperationCasOutcome::Conflict(current)
                            if current.has_same_prepared_binding(operation)
                                && matches!(
                                    current.state(),
                                    AdmissionOperationState::DispatchCommitted
                                        | AdmissionOperationState::Completed
                                ) =>
                        {
                            if current.state() == AdmissionOperationState::Completed {
                                self.validate_terminal_receipt_binding_with_store(
                                    operation_store,
                                    &current,
                                )?;
                            }
                            Ok(Some(current))
                        }
                        AdmissionOperationCasOutcome::Applied(_)
                        | AdmissionOperationCasOutcome::Conflict(_) => Err(KernelError::Internal(
                            "governed active-response dispatch commitment conflicted".to_string(),
                        )),
                        AdmissionOperationCasOutcome::Missing => Err(KernelError::Internal(
                            "governed active-response operation disappeared during recovery"
                                .to_string(),
                        )),
                    }
                }
            },
            AdmissionOperationState::DispatchCommitted => {
                let committed =
                    match reservation.state() {
                        ReplayReservationState::Committed => reservation,
                        ReplayReservationState::Cancelled => return Err(KernelError::Internal(
                            "governed active-response dispatch commitment has a cancelled approval"
                                .to_string(),
                        )),
                        ReplayReservationState::Reserved => store
                            .commit_approval_reservation(operation.operation_id())
                            .map_err(|error| {
                                KernelError::Internal(format!(
                                    "governed active-response approval commit failed: {error}"
                                ))
                            })?,
                    };
                if committed.operation_id() != operation.operation_id()
                    || committed.approval_set() != &payload.approval_set
                    || committed.state() != ReplayReservationState::Committed
                {
                    return Err(KernelError::Internal(
                        "governed active-response approval did not converge to its exact commitment"
                            .to_string(),
                    ));
                }
                Ok(Some(operation.clone()))
            }
            _ => Ok(None),
        }
    }

    pub(super) fn recover_nonterminal_active_response_operations_with_authorities(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        approval_store: Option<&dyn ApprovalStore>,
        expected_coordinator_authority_id: &str,
    ) -> Result<usize, KernelError> {
        let mut operations = operation_store.list_admission_recovery_candidates(
            AdmissionOperationKind::GovernedActiveResponse,
            MAX_ACTIVE_RESPONSE_RECOVERY_OPERATIONS_PER_ACTIVATION + 1,
        )?;
        if operations.len() > MAX_ACTIVE_RESPONSE_RECOVERY_OPERATIONS_PER_ACTIVATION {
            return Err(KernelError::Internal(format!(
                "more governed active-response operations remain after the bounded {MAX_ACTIVE_RESPONSE_RECOVERY_OPERATIONS_PER_ACTIVATION}-operation recovery batch"
            )));
        }
        let mut recovered = self.recover_terminal_receipt_outboxes_with_store(
            operation_store,
            AdmissionOperationKind::GovernedActiveResponse,
            Some(expected_coordinator_authority_id),
        )?;
        for operation in operations.drain(..) {
            if operation.coordinator_authority_id() != expected_coordinator_authority_id {
                return Err(KernelError::Internal(format!(
                    "governed active-response operation {} belongs to a different executor authority",
                    operation.operation_id()
                )));
            }
            match operation.state() {
                AdmissionOperationState::Prepared
                | AdmissionOperationState::ApprovalReserved
                | AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch => {
                    if matches!(
                        operation.state(),
                        AdmissionOperationState::Prepared
                            | AdmissionOperationState::ApprovalReserved
                    ) {
                        self.stage_compensation_pending_with_terminal_receipt(
                            operation_store,
                            &operation,
                            "governed security runtime recovered an uncommitted active response",
                        )?;
                    }
                    if self.recover_compensated_active_response_operation_with_store(
                        operation_store,
                        approval_store,
                        operation.operation_id(),
                    )? {
                        recovered = recovered.checked_add(1).ok_or_else(|| {
                            KernelError::Internal(
                                "active-response recovery count overflowed usize".to_string(),
                            )
                        })?;
                    }
                }
                AdmissionOperationState::DispatchCommitted => {
                    self.reconcile_governed_active_response_commit(
                        operation_store,
                        approval_store,
                        &operation,
                    )?;
                }
                AdmissionOperationState::Completed => {
                    self.validate_terminal_receipt_binding_with_store(operation_store, &operation)?;
                }
                AdmissionOperationState::OutcomeUnknownAfterDispatch => {}
                _ => {
                    return Err(KernelError::Internal(
                        "governed active response entered a tool-dispatch-only state".to_string(),
                    ))
                }
            }
        }
        Ok(recovered)
    }
}

fn parse_cleanup_payload<T: for<'de> Deserialize<'de>>(
    action: &AdmissionCleanupAction,
) -> Result<T, KernelError> {
    serde_json::from_str(action.payload_json()).map_err(|error| {
        KernelError::Internal(format!(
            "cleanup action {} has an invalid participant payload: {error}",
            action.action_id()
        ))
    })
}

fn validate_schema(actual: &str, expected: &str) -> Result<(), KernelError> {
    if actual == expected {
        Ok(())
    } else {
        Err(KernelError::Internal(format!(
            "cleanup payload schema `{actual}` is not `{expected}`"
        )))
    }
}
