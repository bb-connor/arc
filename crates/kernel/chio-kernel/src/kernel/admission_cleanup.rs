use serde::{Deserialize, Serialize};

use super::active_response_operation_binding::ActiveResponseOperationAnchor;
use super::approval_cleanup::approval_set_input_is_valid;
use super::*;
use crate::admission_capture_authority::{
    AdmissionCaptureDecision, AdmissionCaptureRequest, AdmissionCaptureRequestInput,
};
use crate::approval::{ApprovalSetReservationInput, ApprovalStore};
use crate::budget_store::{
    AuthorizedBudgetHold, BudgetAdmissionOperationBinding, BudgetAuthorizationCleanupSnapshot,
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetCommitMetadata,
    BudgetGuaranteeLevel, BudgetInvocationReservationState, BudgetMonetaryHoldState, BudgetStore,
    DeniedBudgetHold,
};
use crate::payment::{
    PaymentJournalRecord, PaymentJournalState, PaymentSettleAction, PaymentSettleIntent,
    RailSettlementState, RailSettlementStatus,
};
use crate::security_admission_operation::{
    AdmissionCleanupAction, AdmissionCleanupActionCasOutcome, AdmissionCleanupActionClaimOutcome,
    AdmissionCleanupActionCreateOutcome, AdmissionCleanupActionKind, AdmissionCleanupActionState,
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationCasOutcome,
    AdmissionOperationCompareAndSwap, AdmissionOperationKind, AdmissionOperationState,
    AdmissionOperationStore, ReplayReservationState,
};

const CLEANUP_CLAIM_LEASE_MS: u64 = 30_000;
const MAX_ADMISSION_CLEANUP_RECOVERY_OPERATIONS_PER_ACTIVATION: usize = 4_096;
const BUDGET_CLEANUP_SCHEMA: &str = "chio.admission-cleanup.budget.v1";
const PAYMENT_CLEANUP_SCHEMA: &str = "chio.admission-cleanup.payment.v1";
const DELEGATED_BUDGET_CLEANUP_SCHEMA: &str = "chio.admission-cleanup.delegated-budget.v1";
const APPROVAL_CLEANUP_SCHEMA: &str = "chio.admission-cleanup.approval.v2";
const ACTIVE_RESPONSE_APPROVAL_CLEANUP_SCHEMA: &str =
    "chio.admission-cleanup.active-response-approval.v2";
const NONCE_CLEANUP_SCHEMA: &str = "chio.admission-cleanup.execution-nonce.v1";
const BROKER_CLEANUP_SCHEMA: &str = "chio.admission-cleanup.broker.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BudgetCleanupPayload {
    schema: String,
    authorization: BudgetAuthorizationCleanupSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PaymentCleanupPayload {
    schema: String,
    operation_id: String,
    request_binding_hash: String,
    amount_units: u64,
    currency: String,
    reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DelegatedBudgetCleanupPayload {
    schema: String,
    operation_id: String,
    request_binding_hash: String,
    parent_capability_id: String,
    child_capability_id: String,
    budget_share_bps: u16,
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NonceCleanupPayload {
    schema: String,
    operation_id: String,
    nonce_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrokerCleanupPayload {
    schema: String,
    operation_id: String,
    request_binding_hash: String,
    attempt_id: String,
}

struct RecoveredAuthorizationValidation<'a> {
    budget_store: &'a dyn BudgetStore,
    authorized: &'a AuthorizedBudgetHold,
    expected_hold: Option<&'a str>,
    expected_exposure: u64,
    expected_event: &'a str,
    expected_authority: Option<&'a crate::budget_store::BudgetEventAuthority>,
    expected_revocation_set: Option<&'a crate::supplemental_quota::CanonicalRevocationSet>,
    expected_monetary_state: BudgetMonetaryHoldState,
}

struct RecoveredCaptureValidation<'a> {
    budget_store: &'a dyn BudgetStore,
    snapshot: &'a BudgetAuthorizationCleanupSnapshot,
    authorized: &'a AuthorizedBudgetHold,
    captured: &'a crate::budget_store::BudgetHoldMutationDecision,
    expected_authority: Option<&'a crate::budget_store::BudgetEventAuthority>,
    expected_revocation_set: Option<&'a crate::supplemental_quota::CanonicalRevocationSet>,
    expected_monetary_state: BudgetMonetaryHoldState,
}

pub(super) struct BudgetCleanupDenialValidation<'a> {
    pub(super) store: &'a dyn BudgetStore,
    pub(super) denied: &'a DeniedBudgetHold,
    pub(super) expected_hold_id: Option<&'a str>,
    pub(super) expected_exposure: u64,
    pub(super) expected_event_id: &'a str,
    pub(super) expected_authority: Option<&'a crate::budget_store::BudgetEventAuthority>,
    pub(super) expected_revocation_set:
        Option<&'a crate::supplemental_quota::CanonicalRevocationSet>,
}

pub(super) struct CallerReservedAdmissionTerms {
    pub(super) operation: AdmissionOperation,
    pub(super) authorization: BudgetAuthorizeHoldRequest,
}

impl ChioKernel {
    /// Resolve the exact caller-reserved operation named by a signed nonce.
    /// The hold index is durable and unique; the returned authorization is
    /// reconstructed from the operation's immutable cleanup journal rather than
    /// from caller input or mutable hold metadata.
    pub(super) fn resolve_caller_reserved_admission_for_nonce(
        &self,
        hold_id: &str,
        bound_capability_id: &str,
        reserving_request_id: &str,
    ) -> Result<CallerReservedAdmissionTerms, KernelError> {
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let operation = operation_store
            .load_by_budget_hold_id(hold_id)?
            .ok_or_else(|| {
                KernelError::Internal(format!(
                    "reserved hold {hold_id} has no exact admission operation owner"
                ))
            })?;
        if operation.kind() != AdmissionOperationKind::ToolDispatch
            || operation.state() != AdmissionOperationState::CallerReserved
            || operation.dispatch_state() != AdmissionDispatchState::Committed
            || operation.budget_hold_id() != Some(hold_id)
            || operation.capability_id() != bound_capability_id
            || operation.request_id() != reserving_request_id
        {
            return Err(KernelError::Internal(format!(
                "reserved hold {hold_id} does not match its signed caller reservation binding"
            )));
        }
        let snapshot = self.load_recovery_budget_snapshot(operation_store.as_ref(), &operation)?;
        let authorization = snapshot.authorization_request()?;
        let expected_operation_binding = BudgetAdmissionOperationBinding::new(
            operation.operation_id().to_string(),
            operation.request_binding_hash().to_string(),
        )?;
        if authorization.hold_id.as_deref() != Some(hold_id)
            || authorization.capability_id != bound_capability_id
            || authorization.admission_operation.as_ref() != Some(&expected_operation_binding)
        {
            return Err(KernelError::Internal(format!(
                "reserved hold {hold_id} changed its immutable cleanup authorization binding"
            )));
        }
        Ok(CallerReservedAdmissionTerms {
            operation,
            authorization,
        })
    }

    pub(super) fn prepare_current_admission_authority_replacement(
        &self,
    ) -> Result<(), KernelError> {
        let Some(store) = self.admission_operation_store.as_ref() else {
            return Ok(());
        };
        self.recover_terminal_receipt_outboxes_with_store(
            store.as_ref(),
            AdmissionOperationKind::ToolDispatch,
            None,
        )?;
        self.recover_terminal_receipt_outboxes_with_store(
            store.as_ref(),
            AdmissionOperationKind::GovernedActiveResponse,
            None,
        )?;
        self.drain_compensated_admission_operations_with_authorities(
            store.as_ref(),
            self.budget_store.as_ref(),
            self.approval_store.as_deref(),
            None,
        )?;
        let unresolved = store
            .count_unresolved(AdmissionOperationKind::ToolDispatch)?
            .checked_add(store.count_unresolved(AdmissionOperationKind::GovernedActiveResponse)?)
            .ok_or_else(|| {
                KernelError::Internal(
                    "unresolved admission authority count overflowed u64".to_string(),
                )
            })?;
        if unresolved != 0 {
            return Err(KernelError::Internal(format!(
                "admission authority replacement would strand {unresolved} unresolved operations"
            )));
        }
        Ok(())
    }

    pub(super) fn journal_budget_cleanup(
        &self,
        operation: &AdmissionOperation,
        authorization: &crate::budget_store::BudgetAuthorizeHoldRequest,
        reverse_event_id: String,
        capture_event_id: String,
    ) -> Result<(), KernelError> {
        let payload = BudgetCleanupPayload {
            schema: BUDGET_CLEANUP_SCHEMA.to_string(),
            authorization: authorization.cleanup_snapshot(reverse_event_id, capture_event_id)?,
        };
        self.create_cleanup_action(operation, AdmissionCleanupActionKind::Budget, &payload)
    }

    pub(super) fn journal_payment_cleanup(
        &self,
        operation: &AdmissionOperation,
        amount_units: u64,
        currency: String,
        reference: String,
    ) -> Result<(), KernelError> {
        let payload = PaymentCleanupPayload {
            schema: PAYMENT_CLEANUP_SCHEMA.to_string(),
            operation_id: operation.operation_id().to_string(),
            request_binding_hash: operation.request_binding_hash().to_string(),
            amount_units,
            currency,
            reference,
        };
        self.create_cleanup_action(operation, AdmissionCleanupActionKind::Payment, &payload)
    }

    pub(super) fn journal_delegated_budget_cleanup(
        &self,
        operation: &AdmissionOperation,
        parent_capability_id: String,
        child_capability_id: String,
        budget_share_bps: u16,
    ) -> Result<(), KernelError> {
        let payload = DelegatedBudgetCleanupPayload {
            schema: DELEGATED_BUDGET_CLEANUP_SCHEMA.to_string(),
            operation_id: operation.operation_id().to_string(),
            request_binding_hash: operation.request_binding_hash().to_string(),
            parent_capability_id,
            child_capability_id,
            budget_share_bps,
        };
        self.create_cleanup_action(
            operation,
            AdmissionCleanupActionKind::DelegatedBudget,
            &payload,
        )
    }

    pub(super) fn journal_approval_cleanup(
        &self,
        operation: &AdmissionOperation,
        approval_set: &ApprovalSetReservationInput,
    ) -> Result<(), KernelError> {
        if operation.approval_set_hash() != Some(approval_set.approval_set_hash()) {
            return Err(KernelError::Internal(
                "approval cleanup input does not match its operation".to_string(),
            ));
        }
        let payload = ApprovalCleanupPayload {
            schema: APPROVAL_CLEANUP_SCHEMA.to_string(),
            operation_id: operation.operation_id().to_string(),
            approval_set: approval_set.clone(),
        };
        self.create_cleanup_action(operation, AdmissionCleanupActionKind::Approval, &payload)
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

    pub(super) fn journal_nonce_cleanup(
        &self,
        operation: &AdmissionOperation,
        nonce_id: String,
    ) -> Result<(), KernelError> {
        let payload = NonceCleanupPayload {
            schema: NONCE_CLEANUP_SCHEMA.to_string(),
            operation_id: operation.operation_id().to_string(),
            nonce_id,
        };
        self.create_cleanup_action(
            operation,
            AdmissionCleanupActionKind::ExecutionNonce,
            &payload,
        )
    }

    pub(super) fn journal_broker_cleanup(
        &self,
        operation: &AdmissionOperation,
        attempt_id: String,
    ) -> Result<(), KernelError> {
        let payload = BrokerCleanupPayload {
            schema: BROKER_CLEANUP_SCHEMA.to_string(),
            operation_id: operation.operation_id().to_string(),
            request_binding_hash: operation.request_binding_hash().to_string(),
            attempt_id,
        };
        self.create_cleanup_action(operation, AdmissionCleanupActionKind::Broker, &payload)
    }

    fn create_cleanup_action<T: Serialize>(
        &self,
        operation: &AdmissionOperation,
        kind: AdmissionCleanupActionKind,
        payload: &T,
    ) -> Result<(), KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let action = AdmissionCleanupAction::pending(operation, kind, payload)?;
        match store.create_cleanup_action(action.clone()) {
            Ok(AdmissionCleanupActionCreateOutcome::Created(created)) if created == action => {
                Ok(())
            }
            Ok(AdmissionCleanupActionCreateOutcome::Existing(existing)) if existing == action => {
                Ok(())
            }
            Ok(AdmissionCleanupActionCreateOutcome::Created(_))
            | Ok(AdmissionCleanupActionCreateOutcome::Existing(_)) => Err(KernelError::Internal(
                "cleanup action persistence changed its immutable participant payload".to_string(),
            )),
            Err(error) => {
                let recovered = store
                    .load_cleanup_actions(operation.operation_id())
                    .ok()
                    .and_then(|actions| {
                        actions
                            .into_iter()
                            .find(|existing| existing.action_id() == action.action_id())
                    });
                if recovered.as_ref() == Some(&action) {
                    Ok(())
                } else {
                    Err(KernelError::Internal(format!(
                        "cleanup action persistence acknowledgement is uncertain: {error}"
                    )))
                }
            }
        }
    }

    pub(super) fn discharge_admission_cleanup_action(
        &self,
        operation: &AdmissionOperation,
        kind: AdmissionCleanupActionKind,
    ) -> Result<(), KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        self.discharge_admission_cleanup_action_with_store(store.as_ref(), operation, kind)
    }

    pub(super) fn discharge_admission_cleanup_action_with_store(
        &self,
        store: &dyn AdmissionOperationStore,
        operation: &AdmissionOperation,
        kind: AdmissionCleanupActionKind,
    ) -> Result<(), KernelError> {
        let action = store
            .load_cleanup_actions(operation.operation_id())?
            .into_iter()
            .find(|action| action.kind() == kind)
            .ok_or_else(|| {
                KernelError::Internal(format!(
                    "admission operation {} has no {} cleanup action to discharge",
                    operation.operation_id(),
                    kind.as_str()
                ))
            })?;
        if action.operation_id() != operation.operation_id()
            || action.request_binding_hash() != operation.request_binding_hash()
        {
            return Err(KernelError::Internal(
                "cleanup action discharge binding does not match its admission operation"
                    .to_string(),
            ));
        }
        if action.state() == AdmissionCleanupActionState::Completed {
            return Ok(());
        }
        let now_unix_ms = cleanup_unix_ms()?;
        let claim_deadline_unix_ms =
            now_unix_ms
                .checked_add(CLEANUP_CLAIM_LEASE_MS)
                .ok_or_else(|| {
                    KernelError::Internal(
                        "cleanup discharge claim deadline overflowed u64".to_string(),
                    )
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
            AdmissionCleanupActionClaimOutcome::Busy(_) => {
                return Err(KernelError::Internal(format!(
                    "{} cleanup action for operation {} is owned by another worker",
                    kind.as_str(),
                    operation.operation_id()
                )))
            }
            AdmissionCleanupActionClaimOutcome::Missing => {
                return Err(KernelError::Internal(format!(
                    "{} cleanup action for operation {} disappeared",
                    kind.as_str(),
                    operation.operation_id()
                )))
            }
        };
        match store.acknowledge_cleanup_action(claimed.action_id(), claimed.version(), &claim_token)
        {
            Ok(AdmissionCleanupActionCasOutcome::Applied(_)) => Ok(()),
            Ok(AdmissionCleanupActionCasOutcome::Conflict(current))
                if current.state() == AdmissionCleanupActionState::Completed =>
            {
                Ok(())
            }
            Ok(AdmissionCleanupActionCasOutcome::Conflict(_)) => {
                Err(KernelError::Internal(format!(
                    "{} cleanup action discharge conflicted for operation {}",
                    kind.as_str(),
                    operation.operation_id()
                )))
            }
            Ok(AdmissionCleanupActionCasOutcome::Missing) => Err(KernelError::Internal(format!(
                "{} cleanup action disappeared during discharge for operation {}",
                kind.as_str(),
                operation.operation_id()
            ))),
            Err(error) => match store.load_cleanup_actions(operation.operation_id()) {
                Ok(actions)
                    if actions.iter().any(|current| {
                        current.kind() == kind
                            && current.state() == AdmissionCleanupActionState::Completed
                    }) =>
                {
                    Ok(())
                }
                _ => Err(KernelError::Internal(format!(
                    "{} cleanup action discharge acknowledgement is uncertain: {error}",
                    kind.as_str()
                ))),
            },
        }
    }

    /// Drive a bounded batch of terminal pre-dispatch cleanup. A successful
    /// return means every operation counted in the result has no unfinished
    /// participant action. Errors fail closed and leave the action retryable.
    pub fn recover_compensated_admission_operations(
        &self,
        limit: usize,
    ) -> Result<usize, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        self.recover_compensated_admission_operations_with_authorities(
            store.as_ref(),
            self.budget_store.as_ref(),
            self.approval_store.as_deref(),
            None,
            limit,
        )
    }

    pub(super) fn recover_nonterminal_admission_kind_with_authorities(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        budget_store: &dyn BudgetStore,
        approval_store: Option<&dyn ApprovalStore>,
        kind: AdmissionOperationKind,
        expected_coordinator_authority_id: &str,
    ) -> Result<usize, KernelError> {
        let scan_limit = MAX_ADMISSION_CLEANUP_RECOVERY_OPERATIONS_PER_ACTIVATION
            .checked_add(1)
            .ok_or_else(|| {
                KernelError::Internal("admission recovery scan limit overflowed usize".to_string())
            })?;
        let mut operations =
            operation_store.list_admission_recovery_candidates(kind, scan_limit)?;
        let more_remaining =
            operations.len() > MAX_ADMISSION_CLEANUP_RECOVERY_OPERATIONS_PER_ACTIVATION;
        operations.truncate(MAX_ADMISSION_CLEANUP_RECOVERY_OPERATIONS_PER_ACTIVATION);
        let mut preflight_errors = Vec::new();
        for operation in &operations {
            if operation.coordinator_authority_id() != expected_coordinator_authority_id {
                preflight_errors.push(format!(
                        "operation {} belongs to coordinator authority `{}` instead of `{expected_coordinator_authority_id}`",
                        operation.operation_id(),
                        operation.coordinator_authority_id()
                    ));
            }
            let validated_historical_caller_handoff = operation.state()
                == AdmissionOperationState::CallerReserved
                && operation.dispatch_state() == AdmissionDispatchState::Committed
                && self
                    .validate_caller_reserved_handoff_with_store(operation_store, operation)
                    .is_ok();
            if operation.policy_hash() != self.config.policy_hash
                && !validated_historical_caller_handoff
            {
                preflight_errors.push(format!(
                        "operation {} belongs to policy `{}` instead of installed policy `{}`; policy rotation requires a zero-unresolved-operation drain",
                        operation.operation_id(),
                        operation.policy_hash(),
                        self.config.policy_hash
                    ));
            }
        }
        if !preflight_errors.is_empty() {
            return Err(KernelError::Internal(format!(
                "one or more nonterminal admission operations remain unrecovered: {}",
                preflight_errors.join("; ")
            )));
        }

        let mut recovered = self.recover_terminal_receipt_outboxes_with_store(
            operation_store,
            kind,
            Some(expected_coordinator_authority_id),
        )?;
        let mut errors = Vec::new();
        for operation in operations.iter() {
            if operation.coordinator_authority_id() != expected_coordinator_authority_id {
                errors.push(format!(
                    "operation {} belongs to coordinator authority `{}` instead of `{expected_coordinator_authority_id}`",
                    operation.operation_id(),
                    operation.coordinator_authority_id()
                ));
                continue;
            }
            if operation.state() == AdmissionOperationState::OutcomeUnknownAfterDispatch {
                continue;
            }
            let validated_historical_caller_handoff = operation.state()
                == AdmissionOperationState::CallerReserved
                && operation.dispatch_state() == AdmissionDispatchState::Committed
                && self
                    .validate_caller_reserved_handoff_with_store(operation_store, operation)
                    .is_ok();
            if operation.policy_hash() != self.config.policy_hash
                && !validated_historical_caller_handoff
            {
                errors.push(format!(
                    "operation {} belongs to policy `{}` instead of installed policy `{}`; policy rotation requires a zero-unresolved-operation drain",
                    operation.operation_id(),
                    operation.policy_hash(),
                    self.config.policy_hash
                ));
                continue;
            }
            if operation.state() == AdmissionOperationState::CallerReserved {
                match self.recover_caller_reserved_operation(
                    operation_store,
                    budget_store,
                    operation,
                ) {
                    Ok(true) => {
                        recovered = recovered.checked_add(1).ok_or_else(|| {
                            KernelError::Internal(
                                "admission recovery count overflowed usize".to_string(),
                            )
                        })?;
                    }
                    Ok(false) => {}
                    Err(error) => errors.push(format!(
                        "operation {} caller reservation recovery failed: {error}",
                        operation.operation_id()
                    )),
                }
                continue;
            }
            if operation.kind() == AdmissionOperationKind::GovernedActiveResponse
                && matches!(
                    operation.state(),
                    AdmissionOperationState::ApprovalReserved
                        | AdmissionOperationState::DispatchCommitted
                )
            {
                match self.reconcile_governed_active_response_commit(
                    operation_store,
                    approval_store,
                    operation,
                ) {
                    Ok(Some(_)) => {
                        recovered = recovered.checked_add(1).ok_or_else(|| {
                            KernelError::Internal(
                                "admission recovery count overflowed usize".to_string(),
                            )
                        })?;
                        continue;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        errors.push(format!(
                            "operation {} governed approval recovery failed: {error}",
                            operation.operation_id()
                        ));
                        continue;
                    }
                }
            }
            if operation.state() == AdmissionOperationState::CompensationPending {
                match self.recover_claimed_admission_operation(
                    operation_store,
                    budget_store,
                    approval_store,
                    operation,
                ) {
                    Ok(()) => {
                        recovered = recovered.checked_add(1).ok_or_else(|| {
                            KernelError::Internal(
                                "admission recovery count overflowed usize".to_string(),
                            )
                        })?;
                    }
                    Err(error) => errors.push(format!(
                        "operation {} compensation recovery failed: {error}",
                        operation.operation_id()
                    )),
                }
                continue;
            }
            let claimed = match operation_store.claim_recovery(
                operation.operation_id(),
                operation.version(),
                operation.coordinator_lease_epoch(),
            ) {
                Ok(AdmissionOperationCasOutcome::Applied(claimed)) => claimed,
                Ok(AdmissionOperationCasOutcome::Conflict(current)) => {
                    errors.push(format!(
                        "operation {} recovery claim conflicted at {}",
                        operation.operation_id(),
                        current.state().as_str()
                    ));
                    continue;
                }
                Ok(AdmissionOperationCasOutcome::Missing) => {
                    errors.push(format!(
                        "operation {} disappeared during recovery claim",
                        operation.operation_id()
                    ));
                    continue;
                }
                Err(error) => {
                    errors.push(format!(
                        "operation {} recovery claim failed: {error}",
                        operation.operation_id()
                    ));
                    continue;
                }
            };
            match self.recover_claimed_admission_operation(
                operation_store,
                budget_store,
                approval_store,
                &claimed,
            ) {
                Ok(()) => {
                    recovered = recovered.checked_add(1).ok_or_else(|| {
                        KernelError::Internal(
                            "admission recovery count overflowed usize".to_string(),
                        )
                    })?;
                }
                Err(error) => errors.push(format!(
                    "operation {} recovery failed: {error}",
                    operation.operation_id()
                )),
            }
        }
        for expected in &operations {
            let Some(operation) = operation_store.load(expected.operation_id())? else {
                errors.push(format!(
                    "operation {} disappeared during post-recovery verification",
                    expected.operation_id()
                ));
                continue;
            };
            if matches!(
                operation.state(),
                AdmissionOperationState::Completed
                    | AdmissionOperationState::CompensatedBeforeDispatch
            ) {
                continue;
            }
            let retained_governed_dispatch = kind == AdmissionOperationKind::GovernedActiveResponse
                && operation.state() == AdmissionOperationState::DispatchCommitted
                && operation.dispatch_state() == AdmissionDispatchState::Committed;
            if operation.coordinator_authority_id() != expected_coordinator_authority_id {
                errors.push(format!(
                    "operation {} remains in {} for coordinator authority `{}` after recovery",
                    operation.operation_id(),
                    operation.state().as_str(),
                    operation.coordinator_authority_id()
                ));
                continue;
            }
            let validated_historical_caller_handoff = operation.state()
                == AdmissionOperationState::CallerReserved
                && operation.dispatch_state() == AdmissionDispatchState::Committed
                && self
                    .validate_caller_reserved_handoff_with_store(operation_store, &operation)
                    .is_ok();
            if operation.policy_hash() != self.config.policy_hash
                && !validated_historical_caller_handoff
            {
                errors.push(format!(
                    "operation {} belongs to policy `{}` instead of installed policy `{}`; policy rotation requires a zero-unresolved-operation drain",
                    operation.operation_id(),
                    operation.policy_hash(),
                    self.config.policy_hash
                ));
                continue;
            }
            if retained_governed_dispatch {
                if let Err(error) = self.reconcile_governed_active_response_commit(
                    operation_store,
                    approval_store,
                    &operation,
                ) {
                    errors.push(format!(
                        "operation {} retained governed dispatch validation failed: {error}",
                        operation.operation_id()
                    ));
                }
                continue;
            }
            if operation.state() == AdmissionOperationState::CallerReserved {
                match self.recover_caller_reserved_operation(
                    operation_store,
                    budget_store,
                    &operation,
                ) {
                    Ok(false) => {}
                    Ok(true) => {
                        recovered = recovered.checked_add(1).ok_or_else(|| {
                            KernelError::Internal(
                                "admission recovery count overflowed usize".to_string(),
                            )
                        })?;
                    }
                    Err(error) => errors.push(format!(
                        "operation {} retained caller reservation validation failed: {error}",
                        operation.operation_id()
                    )),
                }
                continue;
            }
            if operation.state() != AdmissionOperationState::OutcomeUnknownAfterDispatch {
                errors.push(format!(
                    "operation {} remains in {} for coordinator authority `{}` after recovery",
                    operation.operation_id(),
                    operation.state().as_str(),
                    operation.coordinator_authority_id()
                ));
            }
        }
        match self.recover_terminal_receipt_outboxes_with_store(
            operation_store,
            kind,
            Some(expected_coordinator_authority_id),
        ) {
            Ok(post_recovered) => {
                recovered = recovered.checked_add(post_recovered).ok_or_else(|| {
                    KernelError::Internal(
                        "post-recovery terminal receipt count overflowed usize".to_string(),
                    )
                })?;
            }
            Err(error) => errors.push(format!(
                "post-recovery terminal receipt drain failed: {error}"
            )),
        }
        if more_remaining {
            errors.push(format!(
                "more nonterminal admission operations remain after the bounded {MAX_ADMISSION_CLEANUP_RECOVERY_OPERATIONS_PER_ACTIVATION}-operation recovery batch"
            ));
        }
        if errors.is_empty() {
            Ok(recovered)
        } else {
            Err(KernelError::Internal(format!(
                "one or more nonterminal admission operations remain unrecovered: {}",
                errors.join("; ")
            )))
        }
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
                ReplayReservationState::Reserved => Ok(None),
                ReplayReservationState::Cancelled => Ok(None),
                ReplayReservationState::Committed => {
                    let expected = operation
                        .transition_checked(
                            AdmissionOperationState::DispatchCommitted,
                            AdmissionDispatchState::Committed,
                            operation.coordinator_lease_epoch(),
                            None,
                        )
                        .map_err(KernelError::from)?;
                    let committed = match operation_store.compare_and_swap(
                        AdmissionOperationCompareAndSwap {
                            operation_id: operation.operation_id(),
                            expected_version: operation.version(),
                            coordinator_lease_epoch: operation.coordinator_lease_epoch(),
                            next_state: AdmissionOperationState::DispatchCommitted,
                            next_dispatch_state: AdmissionDispatchState::Committed,
                            next_coordinator_lease_epoch: operation.coordinator_lease_epoch(),
                            last_error: None,
                        },
                    ) {
                        Ok(AdmissionOperationCasOutcome::Applied(committed))
                            if committed == expected =>
                        {
                            committed
                        }
                        Ok(AdmissionOperationCasOutcome::Applied(_)) => {
                            return Err(KernelError::Internal(
                                "governed active-response recovery returned a different dispatch commitment"
                                    .to_string(),
                            ))
                        }
                        Ok(AdmissionOperationCasOutcome::Conflict(current))
                            if current.has_same_prepared_binding(operation) =>
                        {
                            match (current.state(), current.dispatch_state()) {
                                (
                                    AdmissionOperationState::DispatchCommitted,
                                    AdmissionDispatchState::Committed,
                                ) => current,
                                (
                                    AdmissionOperationState::Completed,
                                    AdmissionDispatchState::EffectCompleted,
                                ) => {
                                    self.validate_terminal_receipt_binding_with_store(
                                        operation_store,
                                        &current,
                                    )?;
                                    current
                                }
                                _ => {
                                    return Err(KernelError::Internal(
                                        "governed active-response dispatch commitment conflicted"
                                            .to_string(),
                                    ))
                                }
                            }
                        }
                        Ok(AdmissionOperationCasOutcome::Conflict(_)) => {
                            return Err(KernelError::Internal(
                                "governed active-response dispatch commitment changed identity"
                                    .to_string(),
                            ))
                        }
                        Ok(AdmissionOperationCasOutcome::Missing) => {
                            return Err(KernelError::Internal(
                                "governed active-response operation disappeared during recovery"
                                    .to_string(),
                            ))
                        }
                        Err(error) => match operation_store.load(operation.operation_id()) {
                            Ok(Some(current)) if current == expected => current,
                            Ok(Some(current)) if current.has_same_prepared_binding(operation) => {
                                match (current.state(), current.dispatch_state()) {
                                    (
                                        AdmissionOperationState::DispatchCommitted,
                                        AdmissionDispatchState::Committed,
                                    ) => current,
                                    (
                                        AdmissionOperationState::Completed,
                                        AdmissionDispatchState::EffectCompleted,
                                    ) => {
                                        self.validate_terminal_receipt_binding_with_store(
                                            operation_store,
                                            &current,
                                        )?;
                                        current
                                    }
                                    _ => {
                                        return Err(KernelError::Internal(format!(
                                            "governed active-response dispatch commitment acknowledgement is uncertain: {error}"
                                        )))
                                    }
                                }
                            }
                            _ => {
                                return Err(KernelError::Internal(format!(
                                    "governed active-response dispatch commitment acknowledgement is uncertain: {error}"
                                )))
                            }
                        },
                    };
                    Ok(Some(committed))
                }
            },
            AdmissionOperationState::DispatchCommitted => {
                if operation.dispatch_state() != AdmissionDispatchState::Committed {
                    return Err(KernelError::Internal(
                        "governed active-response dispatch commitment has an invalid dispatch state"
                            .to_string(),
                    ));
                }
                let committed = match reservation.state() {
                    ReplayReservationState::Committed => reservation,
                    ReplayReservationState::Cancelled => {
                        return Err(KernelError::Internal(
                            "governed active-response dispatch commitment has a cancelled approval"
                                .to_string(),
                        ))
                    }
                    ReplayReservationState::Reserved => store
                        .commit_approval_reservation(operation.operation_id())
                        .or_else(|_| {
                            store
                                .get_approval_reservation(operation.operation_id())
                                .and_then(|reservation| {
                                    reservation.ok_or_else(|| {
                                        crate::approval::ApprovalStoreError::Backend(
                                            "governed active-response approval disappeared during commit"
                                                .to_string(),
                                        )
                                    })
                                })
                        })
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

    /// Retain a durably issued caller reservation while its exact stamped hold
    /// remains open. Any closed hold proves the spend authority has already made
    /// an irreversible terminal decision. Cold recovery must therefore close the
    /// still-nonterminal operation conservatively when the exact signed terminal
    /// receipt did not commit before the previous runtime stopped.
    /// Returns true when this call terminalized the operation and false when the
    /// live reservation remains intentionally unresolved.
    fn recover_caller_reserved_operation(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        budget_store: &dyn BudgetStore,
        operation: &AdmissionOperation,
    ) -> Result<bool, KernelError> {
        if operation.kind() != AdmissionOperationKind::ToolDispatch
            || operation.state() != AdmissionOperationState::CallerReserved
            || operation.dispatch_state() != AdmissionDispatchState::Committed
        {
            return Err(KernelError::Internal(format!(
                "caller reservation recovery refused operation {} in {}",
                operation.operation_id(),
                operation.state().as_str()
            )));
        }
        self.validate_caller_reserved_handoff_with_store(operation_store, operation)?;
        let hold_id = operation.budget_hold_id().ok_or_else(|| {
            KernelError::Internal(format!(
                "caller reservation operation {} has no budget hold",
                operation.operation_id()
            ))
        })?;
        let indexed_operation = operation_store
            .load_by_budget_hold_id(hold_id)?
            .ok_or_else(|| {
                KernelError::Internal(format!(
                    "caller reservation hold {hold_id} has no indexed admission operation"
                ))
            })?;
        if indexed_operation.operation_id() != operation.operation_id()
            || indexed_operation.request_binding_hash() != operation.request_binding_hash()
            || indexed_operation.capability_id() != operation.capability_id()
            || indexed_operation.budget_hold_id() != Some(hold_id)
        {
            return Err(KernelError::Internal(format!(
                "caller reservation hold {hold_id} changed its exact operation index"
            )));
        }
        let recovery_snapshot = self.load_recovery_budget_snapshot(operation_store, operation)?;
        let authorization_request = recovery_snapshot.authorization_request()?;
        if authorization_request.hold_id.as_deref() != Some(hold_id) {
            return Err(KernelError::Internal(format!(
                "caller reservation operation {} changed its cleanup hold binding",
                operation.operation_id()
            )));
        }
        let mut hold = budget_store.get_budget_hold(hold_id)?.ok_or_else(|| {
            KernelError::Internal(format!(
                "caller reservation operation {} lost its exact budget hold",
                operation.operation_id()
            ))
        })?;
        if hold.hold_id != hold_id
            || hold.capability_id != operation.capability_id()
            || hold.grant_index != authorization_request.grant_index
            || hold.authorized_exposure_units != authorization_request.requested_exposure_units
        {
            return Err(KernelError::Internal(format!(
                "caller reservation operation {} changed its hold binding",
                operation.operation_id()
            )));
        }
        if hold.disposition.is_open() {
            if hold.reserved_until.is_none() {
                return Err(KernelError::Internal(format!(
                    "caller reservation operation {} has an unstamped open hold",
                    operation.operation_id()
                )));
            }
            match self.recover_caller_reserved_handoff_delivery_with_store(
                operation_store,
                operation,
                current_unix_timestamp(),
            ) {
                Ok(()) => return Ok(false),
                Err(KernelError::GuardDenied(_)) => {
                    hold = budget_store.get_budget_hold(hold_id)?.ok_or_else(|| {
                        KernelError::Internal(format!(
                            "caller reservation operation {} lost its exact budget hold during delivery recovery",
                            operation.operation_id()
                        ))
                    })?;
                    if hold.disposition.is_open() {
                        return Ok(false);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        let disposition = hold.disposition.as_str();
        let reason = format!(
            "cold recovery found caller reservation hold {hold_id} {disposition} without an exact terminal receipt"
        );
        self.finalize_caller_reservation_outcome_unknown_with_store(
            operation_store,
            operation,
            &reason,
            Some(serde_json::json!({
                "caller_reservation_recovery": {
                    "hold_id": hold_id,
                    "hold_disposition": disposition,
                }
            })),
        )?;
        Ok(true)
    }

    fn recover_claimed_admission_operation(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        budget_store: &dyn BudgetStore,
        approval_store: Option<&dyn ApprovalStore>,
        operation: &AdmissionOperation,
    ) -> Result<(), KernelError> {
        match (operation.kind(), operation.state()) {
            (
                AdmissionOperationKind::ToolDispatch
                | AdmissionOperationKind::GovernedActiveResponse,
                AdmissionOperationState::CompensationPending,
            ) => {
                if self.recover_compensated_admission_operation_with_authorities(
                    operation_store,
                    budget_store,
                    approval_store,
                    operation.operation_id(),
                )? {
                    Ok(())
                } else {
                    Err(KernelError::Internal(format!(
                        "compensation cleanup for operation {} is owned by another worker",
                        operation.operation_id()
                    )))
                }
            }
            (
                AdmissionOperationKind::ToolDispatch,
                AdmissionOperationState::CapturePending
                | AdmissionOperationState::CallerReservationCapturePending,
            ) => self.recover_capture_pending_operation(
                operation_store,
                budget_store,
                approval_store,
                operation,
            ),
            (AdmissionOperationKind::ToolDispatch, AdmissionOperationState::DispatchCommitted) => {
                self.commit_recovery_replay_reservations(
                    operation_store,
                    approval_store,
                    operation,
                )?;
                Err(KernelError::Internal(format!(
                    "committed admission operation {} has no signed terminal receipt outbox and requires fail-closed reconciliation",
                    operation.operation_id()
                )))
            }
            (
                AdmissionOperationKind::GovernedActiveResponse,
                AdmissionOperationState::DispatchCommitted,
            ) => {
                self.commit_recovery_replay_reservations(
                    operation_store,
                    approval_store,
                    operation,
                )?;
                Err(KernelError::Internal(format!(
                    "committed active-response operation {} has no exact persisted executor receipt and requires fail-closed reconciliation",
                    operation.operation_id()
                )))
            }
            (
                AdmissionOperationKind::ToolDispatch,
                AdmissionOperationState::Prepared
                | AdmissionOperationState::BrokerAttemptRegistered
                | AdmissionOperationState::BudgetAuthorized
                | AdmissionOperationState::DelegatedBudgetReserved
                | AdmissionOperationState::PaymentAuthorized
                | AdmissionOperationState::ApprovalReserved
                | AdmissionOperationState::ReadyToDispatch,
            )
            | (
                AdmissionOperationKind::GovernedActiveResponse,
                AdmissionOperationState::Prepared | AdmissionOperationState::ApprovalReserved,
            ) => {
                let compensation_pending = self.stage_compensation_pending_with_terminal_receipt(
                    operation_store,
                    operation,
                    "cold restart compensated admission before dispatch",
                )?;
                if !self.recover_compensated_admission_operation_with_authorities(
                    operation_store,
                    budget_store,
                    approval_store,
                    compensation_pending.operation_id(),
                )? {
                    return Err(KernelError::Internal(
                        "compensated admission cleanup is owned by another worker".to_string(),
                    ));
                }
                Ok(())
            }
            (AdmissionOperationKind::GovernedActiveResponse, state) => {
                Err(KernelError::Internal(format!(
                    "governed active-response recovery refused tool-only state {}",
                    state.as_str()
                )))
            }
            (_, state) => Err(KernelError::Internal(format!(
                "admission recovery refused operation {} in {}",
                operation.operation_id(),
                state.as_str()
            ))),
        }
    }

    fn recover_capture_pending_operation(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        budget_store: &dyn BudgetStore,
        approval_store: Option<&dyn ApprovalStore>,
        operation: &AdmissionOperation,
    ) -> Result<(), KernelError> {
        let caller_reservation =
            operation.state() == AdmissionOperationState::CallerReservationCapturePending;
        if caller_reservation {
            return self.recover_caller_reservation_capture_pending_handoff(
                operation_store,
                budget_store,
                approval_store,
                operation,
            );
        }
        let snapshot = self.load_recovery_budget_snapshot(operation_store, operation)?;
        if !caller_reservation
            || operation.approval_set_hash().is_some()
            || operation.execution_nonce_id().is_some()
        {
            self.commit_recovery_replay_reservations(operation_store, approval_store, operation)?;
        }
        let _guard = match self.budget_store_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let authorization_request = snapshot.authorization_request()?;
        let authorization_artifact_digests = snapshot.authorization_artifact_digests();
        let expected_hold = authorization_request.hold_id.clone();
        let expected_authorize_event = authorization_request.event_id.clone().ok_or_else(|| {
            KernelError::Internal(
                "recovery budget authorization omitted its event identifier".to_string(),
            )
        })?;
        let expected_exposure = authorization_request.requested_exposure_units;
        let requested_authority = authorization_request.authority.clone();
        let expected_revocation_set = authorization_request.revocation_set().cloned();
        let expected_monetary_state = if authorization_request.requested_exposure_units > 0
            || authorization_request.max_cost_per_invocation.is_some()
            || authorization_request.max_total_cost_units.is_some()
        {
            BudgetMonetaryHoldState::Exposed
        } else {
            BudgetMonetaryHoldState::None
        };
        let authorization = budget_store
            .replay_budget_authorization(authorization_request.clone())
            .or_else(|_| budget_store.replay_budget_authorization(authorization_request.clone()))?;
        let authorization_validation = self.validate_budget_authorization_decision_for_store(
            budget_store,
            &authorization_request,
            &authorization,
            &authorization_artifact_digests,
            "recovery authorization replay",
        );
        let authorized = match authorization {
            BudgetAuthorizeHoldDecision::Authorized(authorized) => authorized,
            BudgetAuthorizeHoldDecision::Denied(denied) => {
                if authorization_validation.is_err() {
                    return Err(KernelError::GuardDenied(
                        "budget authorization denial lacks exact hard-budget authority evidence"
                            .to_string(),
                    ));
                }
                self.validate_budget_cleanup_denial(BudgetCleanupDenialValidation {
                    store: budget_store,
                    denied: &denied,
                    expected_hold_id: expected_hold.as_deref(),
                    expected_exposure,
                    expected_event_id: &expected_authorize_event,
                    expected_authority: requested_authority.as_ref(),
                    expected_revocation_set: expected_revocation_set.as_ref(),
                })?;
                drop(_guard);
                return self.compensate_recovery_capture_denial(
                    operation_store,
                    budget_store,
                    approval_store,
                    operation,
                    "capture recovery found an authoritative authorization denial",
                );
            }
        };
        authorization_validation?;
        self.validate_recovered_authorization(RecoveredAuthorizationValidation {
            budget_store,
            authorized: &authorized,
            expected_hold: expected_hold.as_deref(),
            expected_exposure,
            expected_event: &expected_authorize_event,
            expected_authority: requested_authority.as_ref(),
            expected_revocation_set: expected_revocation_set.as_ref(),
            expected_monetary_state,
        })?;
        let authority =
            if budget_store.budget_guarantee_level() == BudgetGuaranteeLevel::SingleNodeAtomic {
                snapshot.requested_authority().cloned()
            } else {
                authorized.metadata.authority.clone()
            };
        let capture_request = snapshot.capture_request(authority.clone())?;
        let captured = if snapshot.requires_combined_capture() {
            let revocation_set = snapshot.revocation_set()?;
            let request = AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
                operation_id: operation.operation_id().to_string(),
                budget: capture_request,
                revocation_set: revocation_set.clone(),
                bound_revocation_set_digest: revocation_set.digest().to_string(),
                authorization_artifact_digests: snapshot.authorization_artifact_digests(),
                aggregate_root_capability_id: snapshot
                    .aggregate_root_capability_id()
                    .map(ToOwned::to_owned),
                aggregate_root_binding_digest: snapshot
                    .aggregate_root_binding_digest()
                    .map(ToOwned::to_owned),
                last_observed_revocation_index: None,
            })?;
            let capture_authority = self.admission_capture_authority.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "combined admission capture authority is unavailable during recovery"
                        .to_string(),
                )
            })?;
            let decision = match capture_authority.query_admission_capture(&request)? {
                Some(decision) => decision,
                None if caller_reservation => {
                    drop(_guard);
                    return self.compensate_recovery_capture_denial(
                        operation_store,
                        budget_store,
                        approval_store,
                        operation,
                        "caller reservation recovery proved combined capture was never committed",
                    );
                }
                None => capture_authority.capture_admission(request)?,
            };
            match decision {
                AdmissionCaptureDecision::Captured { budget, .. } => *budget,
                AdmissionCaptureDecision::Denied(denial) => {
                    super::ordinary_admission::validate_capture_denial_partition_escrow_evidence(
                        &authorized,
                        &denial,
                        "combined capture recovery denial",
                    )?;
                    drop(_guard);
                    return self.compensate_recovery_capture_denial(
                        operation_store,
                        budget_store,
                        approval_store,
                        operation,
                        "combined admission capture was definitively denied",
                    );
                }
            }
        } else {
            match budget_store.query_invocation_capture(&capture_request)? {
                Some(captured) => captured,
                None if caller_reservation => {
                    drop(_guard);
                    return self.compensate_recovery_capture_denial(
                        operation_store,
                        budget_store,
                        approval_store,
                        operation,
                        "caller reservation recovery proved invocation capture was never committed",
                    );
                }
                None => budget_store.capture_invocation_reservations(capture_request)?,
            }
        };
        self.validate_recovered_capture(RecoveredCaptureValidation {
            budget_store,
            snapshot: &snapshot,
            authorized: &authorized,
            captured: &captured,
            expected_authority: authority.as_ref(),
            expected_revocation_set: expected_revocation_set.as_ref(),
            expected_monetary_state,
        })?;
        drop(_guard);
        if caller_reservation {
            self.recovery_transition(
                operation_store,
                operation,
                AdmissionOperationState::CallerReserved,
                AdmissionDispatchState::Committed,
                None,
            )?;
            return Ok(());
        }
        let committed = self.recovery_transition(
            operation_store,
            operation,
            AdmissionOperationState::DispatchCommitted,
            AdmissionDispatchState::Committed,
            None,
        )?;
        Err(KernelError::Internal(format!(
            "capture recovery committed operation {} without a signed terminal response; downstream redispatch remains fenced pending reconciliation",
            committed.operation_id()
        )))
    }

    pub(super) fn load_recovery_budget_snapshot(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        operation: &AdmissionOperation,
    ) -> Result<BudgetAuthorizationCleanupSnapshot, KernelError> {
        let actions = operation_store.load_cleanup_actions(operation.operation_id())?;
        let action = actions
            .iter()
            .find(|action| action.kind() == AdmissionCleanupActionKind::Budget)
            .ok_or_else(|| {
                KernelError::Internal(
                    "capture-pending operation has no immutable budget recovery payload"
                        .to_string(),
                )
            })?;
        let payload: BudgetCleanupPayload = parse_cleanup_payload(action)?;
        validate_schema(&payload.schema, BUDGET_CLEANUP_SCHEMA)?;
        if payload.authorization.operation_id() != operation.operation_id()
            || payload.authorization.request_binding_hash() != operation.request_binding_hash()
            || payload.authorization.capability_id() != operation.capability_id()
            || Some(payload.authorization.hold_id()) != operation.budget_hold_id()
        {
            return Err(KernelError::Internal(
                "budget recovery payload has a different operation or participant binding"
                    .to_string(),
            ));
        }
        Ok(payload.authorization)
    }

    fn validate_recovered_authorization(
        &self,
        validation: RecoveredAuthorizationValidation<'_>,
    ) -> Result<(), KernelError> {
        let RecoveredAuthorizationValidation {
            budget_store,
            authorized,
            expected_hold,
            expected_exposure,
            expected_event,
            expected_authority,
            expected_revocation_set,
            expected_monetary_state,
        } = validation;
        self.validate_hard_budget_commit_metadata_for_store(
            budget_store,
            &authorized.metadata,
            expected_event,
            expected_authority,
            None,
            "recovery authorization replay",
        )?;
        if authorized.hold_id.as_deref() != expected_hold
            || authorized.authorized_exposure_units != expected_exposure
            || authorized.invocation_state != BudgetInvocationReservationState::Authorized
            || authorized.monetary_state != expected_monetary_state
            || authorized.revocation_set.as_ref() != expected_revocation_set
        {
            return Err(KernelError::Internal(
                "recovery authorization replay changed the immutable participant effect"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_recovered_capture(
        &self,
        validation: RecoveredCaptureValidation<'_>,
    ) -> Result<(), KernelError> {
        let RecoveredCaptureValidation {
            budget_store,
            snapshot,
            authorized,
            captured,
            expected_authority,
            expected_revocation_set,
            expected_monetary_state,
        } = validation;
        self.validate_hard_budget_commit_metadata_for_store(
            budget_store,
            &captured.metadata,
            snapshot.capture_event_id(),
            expected_authority,
            authorized.metadata.budget_commit_index,
            "recovery invocation capture",
        )?;
        if captured.hold_id.as_deref() != Some(snapshot.hold_id())
            || captured.exposure_units != authorized.authorized_exposure_units
            || captured.realized_spend_units != 0
            || captured.invocation_state != BudgetInvocationReservationState::Captured
            || captured.monetary_state != expected_monetary_state
            || captured.revocation_set.as_ref() != expected_revocation_set
            || captured.metadata.partition_escrow_evidence
                != authorized.metadata.partition_escrow_evidence
        {
            return Err(KernelError::Internal(
                "recovered invocation capture changed the immutable participant effect".to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn compensate_recovery_capture_denial(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        budget_store: &dyn BudgetStore,
        approval_store: Option<&dyn ApprovalStore>,
        operation: &AdmissionOperation,
        reason: &str,
    ) -> Result<(), KernelError> {
        let compensation_pending = self.stage_compensation_pending_with_terminal_receipt(
            operation_store,
            operation,
            reason,
        )?;
        if !self.recover_compensated_admission_operation_with_authorities(
            operation_store,
            budget_store,
            approval_store,
            compensation_pending.operation_id(),
        )? {
            return Err(KernelError::Internal(
                "capture-denied cleanup is owned by another worker".to_string(),
            ));
        }
        Ok(())
    }

    fn commit_recovery_replay_reservations(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        approval_store: Option<&dyn ApprovalStore>,
        operation: &AdmissionOperation,
    ) -> Result<(), KernelError> {
        if let Some(expected_hash) = operation.approval_set_hash() {
            let store = approval_store.ok_or_else(|| {
                KernelError::Internal(
                    "approval authority is unavailable for capture-pending recovery".to_string(),
                )
            })?;
            let reservation = store
                .get_approval_reservation(operation.operation_id())
                .map_err(|error| {
                    KernelError::Internal(format!(
                        "recovery approval reservation lookup failed: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    KernelError::Internal(
                        "capture-pending operation has no approval reservation".to_string(),
                    )
                })?;
            if reservation.approval_set().approval_set_hash() != expected_hash {
                return Err(KernelError::Internal(
                    "recovery approval reservation changed its approval set".to_string(),
                ));
            }
            match reservation.state() {
                ReplayReservationState::Committed => {}
                ReplayReservationState::Reserved => {
                    let committed = store
                        .commit_approval_reservation(operation.operation_id())
                        .or_else(|_| {
                            store
                                .get_approval_reservation(operation.operation_id())
                                .and_then(|reservation| {
                                    reservation.ok_or_else(|| {
                                        crate::approval::ApprovalStoreError::Backend(
                                            "approval reservation disappeared during recovery"
                                                .to_string(),
                                        )
                                    })
                                })
                        })
                        .map_err(|error| {
                            KernelError::Internal(format!(
                                "recovery approval reservation commit failed: {error}"
                            ))
                        })?;
                    if committed.state() != ReplayReservationState::Committed
                        || committed.approval_set().approval_set_hash() != expected_hash
                    {
                        return Err(KernelError::Internal(
                            "recovery approval commit returned a different reservation".to_string(),
                        ));
                    }
                }
                ReplayReservationState::Cancelled => {
                    return Err(KernelError::Internal(
                        "capture-pending approval reservation was cancelled".to_string(),
                    ));
                }
            }
            self.discharge_admission_cleanup_action_with_store(
                operation_store,
                operation,
                AdmissionCleanupActionKind::Approval,
            )?;
        }
        if let Some(expected_nonce_id) = operation.execution_nonce_id() {
            let store = self.execution_nonce_store.as_deref().ok_or_else(|| {
                KernelError::Internal(
                    "execution nonce authority is unavailable for capture-pending recovery"
                        .to_string(),
                )
            })?;
            let reservation = store
                .get_nonce_reservation(operation.operation_id())
                .map_err(|error| {
                    KernelError::Internal(format!(
                        "recovery execution nonce lookup failed: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    KernelError::Internal(
                        "capture-pending operation has no execution nonce reservation".to_string(),
                    )
                })?;
            if reservation.nonce_id() != expected_nonce_id {
                return Err(KernelError::Internal(
                    "recovery execution nonce reservation changed its nonce".to_string(),
                ));
            }
            match reservation.state() {
                ReplayReservationState::Committed => {}
                ReplayReservationState::Reserved => {
                    let committed = store
                        .commit_nonce_reservation(operation.operation_id())
                        .or_else(|_| {
                            store.get_nonce_reservation(operation.operation_id()).and_then(
                                |reservation| {
                                    reservation.ok_or_else(|| {
                                        crate::execution_nonce::ExecutionNonceReservationError::Store(
                                            "execution nonce reservation disappeared during recovery"
                                                .to_string(),
                                        )
                                    })
                                },
                            )
                        })
                        .map_err(|error| {
                            KernelError::Internal(format!(
                                "recovery execution nonce commit failed: {error}"
                            ))
                        })?;
                    if committed.state() != ReplayReservationState::Committed
                        || committed.nonce_id() != expected_nonce_id
                    {
                        return Err(KernelError::Internal(
                            "recovery execution nonce commit returned a different reservation"
                                .to_string(),
                        ));
                    }
                }
                ReplayReservationState::Cancelled => {
                    return Err(KernelError::Internal(
                        "capture-pending execution nonce reservation was cancelled".to_string(),
                    ));
                }
            }
            self.discharge_admission_cleanup_action_with_store(
                operation_store,
                operation,
                AdmissionCleanupActionKind::ExecutionNonce,
            )?;
        }
        Ok(())
    }

    fn recovery_transition(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        operation: &AdmissionOperation,
        next_state: AdmissionOperationState,
        next_dispatch_state: AdmissionDispatchState,
        last_error: Option<String>,
    ) -> Result<AdmissionOperation, KernelError> {
        if next_state == AdmissionOperationState::CompensationPending || next_state.is_terminal() {
            return Err(KernelError::Internal(
                "recovery compensation and terminal transitions require an atomic signed receipt outbox"
                    .to_string(),
            ));
        }
        match operation_store.compare_and_swap(AdmissionOperationCompareAndSwap {
            operation_id: operation.operation_id(),
            expected_version: operation.version(),
            coordinator_lease_epoch: operation.coordinator_lease_epoch(),
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch: operation.coordinator_lease_epoch(),
            last_error,
        }) {
            Ok(AdmissionOperationCasOutcome::Applied(next)) => Ok(next),
            Ok(AdmissionOperationCasOutcome::Conflict(current))
                if current.state() == next_state =>
            {
                Ok(current)
            }
            Ok(AdmissionOperationCasOutcome::Conflict(current)) => {
                Err(KernelError::Internal(format!(
                    "admission recovery transition to {} conflicted at {}",
                    next_state.as_str(),
                    current.state().as_str()
                )))
            }
            Ok(AdmissionOperationCasOutcome::Missing) => Err(KernelError::Internal(
                "admission operation disappeared during recovery transition".to_string(),
            )),
            Err(error) => match operation_store.load(operation.operation_id()) {
                Ok(Some(current)) if current.state() == next_state => Ok(current),
                _ => Err(KernelError::Internal(format!(
                    "admission recovery transition to {} failed: {error}",
                    next_state.as_str()
                ))),
            },
        }
    }
}

include!("admission_cleanup/recovery_and_compensation.inc");

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

fn validate_payload_operation(
    operation: &AdmissionOperation,
    operation_id: &str,
    request_binding_hash: Option<&str>,
) -> Result<(), KernelError> {
    if operation.operation_id() != operation_id
        || request_binding_hash.is_some_and(|hash| hash != operation.request_binding_hash())
    {
        return Err(KernelError::Internal(
            "cleanup participant payload has a different operation binding".to_string(),
        ));
    }
    Ok(())
}

fn cleanup_unix_ms() -> Result<u64, KernelError> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| KernelError::Internal(format!("system clock is before epoch: {error}")))?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        KernelError::Internal("cleanup unix timestamp exceeds u64 milliseconds".to_string())
    })
}
