use std::sync::Arc;

use chio_log_redact::redacted;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use super::*;
use crate::admission_operation::{
    AdmissionCleanupAction, AdmissionCleanupActionKind, AdmissionCleanupActionState,
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationCasOutcome,
    AdmissionOperationCompareAndSwap, AdmissionOperationKind, AdmissionOperationState,
    AdmissionOperationStore,
};

const TERMINAL_RECEIPT_OUTBOX_SCHEMA: &str = "chio.admission-terminal-receipt.v1";
const MAX_TERMINAL_RECEIPT_RECOVERY_OPERATIONS_PER_ACTIVATION: usize = 4_096;

#[derive(Clone)]
pub(super) struct ThresholdTerminalReceiptIntent {
    current: AdmissionOperation,
    terminal: AdmissionOperation,
}

pub(super) struct ScopedThresholdTerminalReceiptIntent {
    request_id: String,
    intents: Arc<DashMap<String, ThresholdTerminalReceiptIntent>>,
    previous: Option<ThresholdTerminalReceiptIntent>,
}

/// Immutable projection used to sign an authoritative caller-reservation
/// reconcile receipt before the operation and exact receipt are committed
/// atomically. Keeping both versions prevents the receipt from being signed
/// against one operation projection and staged against another.
#[derive(Clone)]
pub(super) struct CallerReservationCompletionIntent {
    current: AdmissionOperation,
    terminal: AdmissionOperation,
}

impl Drop for ScopedThresholdTerminalReceiptIntent {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            self.intents.insert(self.request_id.clone(), previous);
        } else {
            self.intents.remove(&self.request_id);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalReceiptOutboxPayload {
    schema: String,
    operation_id: String,
    request_binding_hash: String,
    terminal_state: AdmissionOperationState,
    terminal_dispatch_state: AdmissionDispatchState,
    terminal_coordinator_lease_epoch: u64,
    terminal_version: u64,
    terminal_last_error: Option<String>,
    receipt_authority_id: String,
    receipt: ChioReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    executor_receipt: Option<ChioReceipt>,
}

impl ChioKernel {
    /// Project a caller-owned reservation into its exact completed operation
    /// metadata without mutating the store. The reconcile path merges this
    /// metadata before signing, then supplies the signed receipt to
    /// `commit_caller_reservation_completion_receipt`.
    pub(super) fn project_caller_reservation_completion(
        &self,
        operation_id: &str,
    ) -> Result<(serde_json::Value, CallerReservationCompletionIntent), KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let current = store.load(operation_id)?.ok_or_else(|| {
            KernelError::Internal(format!(
                "caller reservation operation {operation_id} disappeared before reconcile"
            ))
        })?;
        let issued = current.state() == AdmissionOperationState::CallerReserved
            && current.dispatch_state() == AdmissionDispatchState::Committed;
        if current.kind() != AdmissionOperationKind::ToolDispatch || !issued {
            return Err(KernelError::Internal(format!(
                "caller reservation operation {operation_id} cannot complete from {}",
                current.state().as_str()
            )));
        }
        self.validate_caller_reserved_handoff_with_store(store.as_ref(), &current)?;
        let terminal = current.transition_checked(
            AdmissionOperationState::Completed,
            AdmissionDispatchState::EffectCompleted,
            current.coordinator_lease_epoch(),
            None,
        )?;
        let metadata = self.ordinary_admission_operation_metadata(&terminal);
        Ok((
            metadata,
            CallerReservationCompletionIntent { current, terminal },
        ))
    }

    /// Atomically commit a previously projected caller-reservation completion
    /// and the exact signed authoritative reconcile receipt.
    pub(super) fn commit_caller_reservation_completion_receipt(
        &self,
        intent: &CallerReservationCompletionIntent,
        receipt: &ChioReceipt,
    ) -> Result<AdmissionOperation, KernelError> {
        let payload = TerminalReceiptOutboxPayload {
            schema: TERMINAL_RECEIPT_OUTBOX_SCHEMA.to_string(),
            operation_id: intent.terminal.operation_id().to_string(),
            request_binding_hash: intent.terminal.request_binding_hash().to_string(),
            terminal_state: intent.terminal.state(),
            terminal_dispatch_state: intent.terminal.dispatch_state(),
            terminal_coordinator_lease_epoch: intent.terminal.coordinator_lease_epoch(),
            terminal_version: intent.terminal.version(),
            terminal_last_error: intent.terminal.last_error().map(ToOwned::to_owned),
            receipt_authority_id: format!("kernel:{}", receipt.kernel_key.to_hex()),
            receipt: receipt.clone(),
            executor_receipt: None,
        };
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let terminal = self.stage_terminal_receipt_outbox_with_store(
            store.as_ref(),
            &intent.current,
            &intent.terminal,
            &payload,
        )?;
        if let Err(error) =
            self.persist_and_acknowledge_terminal_receipt(store.as_ref(), &terminal, &payload)
        {
            warn!(
                operation_id = %terminal.operation_id(),
                receipt_id = %receipt.id,
                reason = %redacted!(&error.to_string()),
                "authoritative caller reservation receipt remains pending in the durable outbox"
            );
        }
        Ok(terminal)
    }

    /// Conservatively close an issued caller reservation whose downstream
    /// outcome cannot be proven. The terminal state and signed receipt outbox
    /// commit atomically, so TTL and cold-recovery callers never leave a closed
    /// hold behind a nonterminal admission operation.
    pub(super) fn finalize_caller_reservation_outcome_unknown(
        &self,
        current: &AdmissionOperation,
        reason: &str,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<AdmissionOperation, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        self.finalize_caller_reservation_outcome_unknown_with_store(
            store.as_ref(),
            current,
            reason,
            extra_metadata,
        )
    }

    pub(super) fn finalize_caller_reservation_outcome_unknown_with_store(
        &self,
        store: &dyn AdmissionOperationStore,
        current: &AdmissionOperation,
        reason: &str,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<AdmissionOperation, KernelError> {
        let issued = current.state() == AdmissionOperationState::CallerReserved
            && current.dispatch_state() == AdmissionDispatchState::Committed;
        let captured_before_handoff = current.state()
            == AdmissionOperationState::CallerReservationCapturePending
            && current.dispatch_state() == AdmissionDispatchState::NotStarted;
        if current.kind() != AdmissionOperationKind::ToolDispatch
            || !(issued || captured_before_handoff)
        {
            return Err(KernelError::Internal(format!(
                "caller reservation operation {} cannot become outcome-unknown from {}",
                current.operation_id(),
                current.state().as_str()
            )));
        }
        if captured_before_handoff {
            if current.policy_hash() != self.config.policy_hash {
                return Err(KernelError::ReceiptSigningFailed(
                    "capture-pending caller reservation policy does not match the installed kernel"
                        .to_string(),
                ));
            }
            self.validate_caller_reservation_capture_pending_for_reap(store, current)?;
        } else {
            self.validate_caller_reserved_handoff_with_store(store, current)
                .map_err(|error| {
                    KernelError::ReceiptSigningFailed(format!(
                        "caller reservation lacks a fully validated final handoff: {error}"
                    ))
                })?;
        }
        let bounded_reason = super::active_response_coordinator::bounded_admission_error(reason);
        let terminal = current.transition_checked(
            AdmissionOperationState::OutcomeUnknownAfterDispatch,
            AdmissionDispatchState::OutcomeUnknown,
            current.coordinator_lease_epoch(),
            Some(bounded_reason.clone()),
        )?;
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "operation_id": terminal.operation_id(),
            "request_binding_hash": terminal.request_binding_hash(),
            "terminal_state": terminal.state().as_str(),
        }))
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to bind caller reservation terminal action: {error}"
            ))
        })?;
        let receipt_content = receipt_content_for_output(None, None)?;
        let metadata = merge_metadata_objects(
            extra_metadata,
            Some(self.ordinary_admission_operation_metadata(&terminal)),
        );
        let receipt = self.build_and_sign_receipt_for_policy_hash(
            ReceiptParams {
                request_id: Some(terminal.request_id()),
                capability_id: terminal.capability_id(),
                tool_name: "caller_reservation",
                server_id: "chio.kernel",
                decision: Decision::Incomplete {
                    reason: bounded_reason,
                },
                action,
                content_hash: receipt_content.content_hash,
                canonical_content: receipt_content.canonical_content,
                metadata,
                timestamp: current_unix_timestamp(),
                trust_level: chio_core::receipt::kinds::TrustLevel::Mediated,
                tenant_id: None,
            },
            current.policy_hash(),
        )?;
        let payload = TerminalReceiptOutboxPayload {
            schema: TERMINAL_RECEIPT_OUTBOX_SCHEMA.to_string(),
            operation_id: terminal.operation_id().to_string(),
            request_binding_hash: terminal.request_binding_hash().to_string(),
            terminal_state: terminal.state(),
            terminal_dispatch_state: terminal.dispatch_state(),
            terminal_coordinator_lease_epoch: terminal.coordinator_lease_epoch(),
            terminal_version: terminal.version(),
            terminal_last_error: terminal.last_error().map(ToOwned::to_owned),
            receipt_authority_id: format!("kernel:{}", receipt.kernel_key.to_hex()),
            receipt,
            executor_receipt: None,
        };
        let terminal =
            self.stage_terminal_receipt_outbox_with_store(store, current, &terminal, &payload)?;
        if let Err(error) =
            self.persist_and_acknowledge_terminal_receipt(store, &terminal, &payload)
        {
            warn!(
                operation_id = %terminal.operation_id(),
                receipt_id = %payload.receipt.id,
                reason = %redacted!(&error.to_string()),
                "caller reservation outcome-unknown receipt remains pending in the durable outbox"
            );
        }
        Ok(terminal)
    }

    pub(super) fn stage_compensation_pending_with_terminal_receipt(
        &self,
        store: &dyn AdmissionOperationStore,
        current: &AdmissionOperation,
        reason: &str,
    ) -> Result<AdmissionOperation, KernelError> {
        self.ensure_receipt_persistence_ready()?;
        if current.state() == AdmissionOperationState::CompensatedBeforeDispatch {
            self.validate_terminal_compensation_receipt(store, current)?;
            return Ok(current.clone());
        }
        if current.state() == AdmissionOperationState::CompensationPending {
            self.validate_staged_compensation_receipt(store, current)?;
            return Ok(current.clone());
        }
        if current.dispatch_state() != AdmissionDispatchState::NotStarted
            || current.state().is_terminal()
        {
            return Err(KernelError::Internal(format!(
                "admission operation {} cannot stage pre-dispatch compensation from {}",
                current.operation_id(),
                current.state().as_str()
            )));
        }
        let bounded_reason = super::active_response_coordinator::bounded_admission_error(reason);
        let compensation_pending = current.transition_checked(
            AdmissionOperationState::CompensationPending,
            AdmissionDispatchState::NotStarted,
            current.coordinator_lease_epoch(),
            Some(bounded_reason.clone()),
        )?;
        let terminal = compensation_pending.transition_checked(
            AdmissionOperationState::CompensatedBeforeDispatch,
            AdmissionDispatchState::NotStarted,
            compensation_pending.coordinator_lease_epoch(),
            Some(bounded_reason.clone()),
        )?;
        let payload =
            self.build_compensation_terminal_receipt_payload(&terminal, &bounded_reason)?;
        validate_terminal_receipt_payload(&terminal, &payload, &self.public_key())?;
        let action = AdmissionCleanupAction::pending(
            current,
            AdmissionCleanupActionKind::TerminalReceipt,
            &payload,
        )?;
        let request = AdmissionOperationCompareAndSwap {
            operation_id: current.operation_id(),
            expected_version: current.version(),
            coordinator_lease_epoch: current.coordinator_lease_epoch(),
            next_state: compensation_pending.state(),
            next_dispatch_state: compensation_pending.dispatch_state(),
            next_coordinator_lease_epoch: compensation_pending.coordinator_lease_epoch(),
            last_error: compensation_pending.last_error().map(ToOwned::to_owned),
        };
        match store.compare_and_swap_with_cleanup_action(request, action.clone()) {
            Ok(AdmissionOperationCasOutcome::Applied(staged)) => Ok(staged),
            Ok(AdmissionOperationCasOutcome::Conflict(observed)) => self
                .validate_recovered_compensation_stage(
                    store,
                    &compensation_pending,
                    &action,
                    observed,
                    None,
                ),
            Ok(AdmissionOperationCasOutcome::Missing) => Err(KernelError::Internal(
                "compensation operation disappeared during signed outbox staging".to_string(),
            )),
            Err(error) => {
                let observed = store.load(current.operation_id())?.ok_or_else(|| {
                    KernelError::Internal(
                        "compensation operation disappeared after uncertain signed outbox staging"
                            .to_string(),
                    )
                })?;
                self.validate_recovered_compensation_stage(
                    store,
                    &compensation_pending,
                    &action,
                    observed,
                    Some(error.to_string()),
                )
            }
        }
    }

    fn validate_recovered_compensation_stage(
        &self,
        store: &dyn AdmissionOperationStore,
        expected_pending: &AdmissionOperation,
        expected_action: &AdmissionCleanupAction,
        observed: AdmissionOperation,
        uncertain_error: Option<String>,
    ) -> Result<AdmissionOperation, KernelError> {
        let exact_action = store
            .load_cleanup_actions(expected_pending.operation_id())?
            .into_iter()
            .find(|action| action.kind() == AdmissionCleanupActionKind::TerminalReceipt)
            .is_some_and(|action| exact_cleanup_action(&action, expected_action));
        if same_operation_projection(&observed, expected_pending) && exact_action {
            return Ok(observed);
        }
        Err(KernelError::Internal(match uncertain_error {
            Some(error) => format!(
                "signed compensation staging is uncertain after `{error}` and exact recovery failed"
            ),
            None => format!(
                "signed compensation staging conflicted at {} without its exact outbox",
                observed.state().as_str()
            ),
        }))
    }

    fn build_compensation_terminal_receipt_payload(
        &self,
        terminal: &AdmissionOperation,
        reason: &str,
    ) -> Result<TerminalReceiptOutboxPayload, KernelError> {
        if terminal.policy_hash() != self.config.policy_hash {
            return Err(KernelError::ReceiptSigningFailed(
                "compensation receipt policy hash does not match the installed kernel policy"
                    .to_string(),
            ));
        }
        let receipt_authority_id = format!("kernel:{}", self.public_key().to_hex());
        if terminal.kind() == AdmissionOperationKind::ToolDispatch
            && terminal.coordinator_authority_id() != receipt_authority_id
        {
            return Err(KernelError::ReceiptSigningFailed(
                "tool-dispatch compensation receipt signer does not match the operation coordinator"
                    .to_string(),
            ));
        }
        let receipt_content = receipt_content_for_output(None, None)?;
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "operation_id": terminal.operation_id(),
            "request_binding_hash": terminal.request_binding_hash(),
            "terminal_state": terminal.state().as_str(),
        }))
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to bind compensation receipt action: {error}"
            ))
        })?;
        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: Some(terminal.request_id()),
            capability_id: terminal.capability_id(),
            tool_name: "admission_compensation",
            server_id: "chio.kernel",
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "kernel.admission_compensation".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata: Some(self.ordinary_admission_operation_metadata(terminal)),
            timestamp: current_unix_timestamp(),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;
        Ok(TerminalReceiptOutboxPayload {
            schema: TERMINAL_RECEIPT_OUTBOX_SCHEMA.to_string(),
            operation_id: terminal.operation_id().to_string(),
            request_binding_hash: terminal.request_binding_hash().to_string(),
            terminal_state: terminal.state(),
            terminal_dispatch_state: terminal.dispatch_state(),
            terminal_coordinator_lease_epoch: terminal.coordinator_lease_epoch(),
            terminal_version: terminal.version(),
            terminal_last_error: terminal.last_error().map(ToOwned::to_owned),
            receipt_authority_id,
            receipt,
            executor_receipt: None,
        })
    }

    fn validate_staged_compensation_receipt(
        &self,
        store: &dyn AdmissionOperationStore,
        compensation_pending: &AdmissionOperation,
    ) -> Result<TerminalReceiptOutboxPayload, KernelError> {
        if compensation_pending.state() != AdmissionOperationState::CompensationPending {
            return Err(KernelError::Internal(
                "staged compensation receipt requires compensation_pending state".to_string(),
            ));
        }
        let terminal = compensation_pending.transition_checked(
            AdmissionOperationState::CompensatedBeforeDispatch,
            AdmissionDispatchState::NotStarted,
            compensation_pending.coordinator_lease_epoch(),
            compensation_pending.last_error().map(ToOwned::to_owned),
        )?;
        let mut actions = store
            .load_cleanup_actions(compensation_pending.operation_id())?
            .into_iter()
            .filter(|action| action.kind() == AdmissionCleanupActionKind::TerminalReceipt);
        let action = actions.next().ok_or_else(|| {
            KernelError::Internal(format!(
                "compensation operation {} has no staged signed terminal receipt",
                compensation_pending.operation_id()
            ))
        })?;
        if actions.next().is_some() {
            return Err(KernelError::Internal(format!(
                "compensation operation {} has multiple staged terminal receipts",
                compensation_pending.operation_id()
            )));
        }
        if action.operation_id() != compensation_pending.operation_id()
            || action.request_binding_hash() != compensation_pending.request_binding_hash()
            || action.state() != AdmissionCleanupActionState::Pending
        {
            return Err(KernelError::Internal(
                "staged compensation receipt changed its action binding".to_string(),
            ));
        }
        let payload: TerminalReceiptOutboxPayload = serde_json::from_str(action.payload_json())
            .map_err(|error| {
                KernelError::Internal(format!(
                    "staged compensation receipt payload is invalid: {error}"
                ))
            })?;
        validate_terminal_receipt_payload(&terminal, &payload, &self.public_key())?;
        Ok(payload)
    }

    fn validate_terminal_compensation_receipt(
        &self,
        store: &dyn AdmissionOperationStore,
        terminal: &AdmissionOperation,
    ) -> Result<TerminalReceiptOutboxPayload, KernelError> {
        if terminal.state() != AdmissionOperationState::CompensatedBeforeDispatch {
            return Err(KernelError::Internal(
                "terminal compensation receipt validation requires a compensated operation"
                    .to_string(),
            ));
        }
        let mut actions = store
            .load_cleanup_actions(terminal.operation_id())?
            .into_iter()
            .filter(|action| action.kind() == AdmissionCleanupActionKind::TerminalReceipt);
        let action = actions.next().ok_or_else(|| {
            KernelError::Internal(format!(
                "compensated operation {} has no exact signed terminal receipt",
                terminal.operation_id()
            ))
        })?;
        if actions.next().is_some()
            || action.operation_id() != terminal.operation_id()
            || action.request_binding_hash() != terminal.request_binding_hash()
            || !matches!(
                action.state(),
                AdmissionCleanupActionState::Pending
                    | AdmissionCleanupActionState::Claimed
                    | AdmissionCleanupActionState::Completed
            )
        {
            return Err(KernelError::Internal(
                "compensated operation changed its terminal receipt action binding".to_string(),
            ));
        }
        let payload: TerminalReceiptOutboxPayload = serde_json::from_str(action.payload_json())
            .map_err(|error| {
                KernelError::Internal(format!(
                    "compensated terminal receipt payload is invalid: {error}"
                ))
            })?;
        self.validate_terminal_receipt_payload_with_store(store, terminal, &payload)?;
        Ok(payload)
    }

    pub(super) fn validate_terminal_receipt_binding_with_store(
        &self,
        store: &dyn AdmissionOperationStore,
        terminal: &AdmissionOperation,
    ) -> Result<(), KernelError> {
        let mut actions = store
            .load_cleanup_actions(terminal.operation_id())?
            .into_iter()
            .filter(|action| action.kind() == AdmissionCleanupActionKind::TerminalReceipt);
        let action = actions.next().ok_or_else(|| {
            KernelError::Internal(format!(
                "terminal operation {} has no exact signed receipt action",
                terminal.operation_id()
            ))
        })?;
        if actions.next().is_some()
            || action.operation_id() != terminal.operation_id()
            || action.request_binding_hash() != terminal.request_binding_hash()
            || !matches!(
                action.state(),
                AdmissionCleanupActionState::Pending
                    | AdmissionCleanupActionState::Claimed
                    | AdmissionCleanupActionState::Completed
            )
        {
            return Err(KernelError::Internal(
                "terminal operation changed its signed receipt action binding".to_string(),
            ));
        }
        let payload: TerminalReceiptOutboxPayload = serde_json::from_str(action.payload_json())
            .map_err(|error| {
                KernelError::Internal(format!(
                    "terminal receipt action payload is invalid: {error}"
                ))
            })?;
        self.validate_terminal_receipt_payload_with_store(store, terminal, &payload)
    }

    pub(super) fn finalize_staged_compensation_terminal_receipt(
        &self,
        store: &dyn AdmissionOperationStore,
        compensation_pending: &AdmissionOperation,
    ) -> Result<AdmissionOperation, KernelError> {
        let payload = self.validate_staged_compensation_receipt(store, compensation_pending)?;
        let terminal = compensation_pending.transition_checked(
            AdmissionOperationState::CompensatedBeforeDispatch,
            AdmissionDispatchState::NotStarted,
            compensation_pending.coordinator_lease_epoch(),
            compensation_pending.last_error().map(ToOwned::to_owned),
        )?;
        self.commit_terminal_receipt_outbox_with_store(
            store,
            compensation_pending,
            &terminal,
            &payload,
        )
    }

    pub(super) fn finalize_active_response_completion_terminal_receipt(
        &self,
        store: &dyn AdmissionOperationStore,
        dispatch_committed: &AdmissionOperation,
        executor_receipt: &ChioReceipt,
    ) -> Result<AdmissionOperation, KernelError> {
        if dispatch_committed.kind() != AdmissionOperationKind::GovernedActiveResponse
            || dispatch_committed.state() != AdmissionOperationState::DispatchCommitted
            || dispatch_committed.dispatch_state() != AdmissionDispatchState::Committed
        {
            return Err(KernelError::Internal(
                "active-response terminal receipt requires a committed governed response"
                    .to_string(),
            ));
        }
        if dispatch_committed.policy_hash() != self.config.policy_hash {
            return Err(KernelError::ReceiptSigningFailed(
                "active-response terminal receipt policy does not match the installed kernel"
                    .to_string(),
            ));
        }
        let terminal = dispatch_committed.transition_checked(
            AdmissionOperationState::Completed,
            AdmissionDispatchState::EffectCompleted,
            dispatch_committed.coordinator_lease_epoch(),
            None,
        )?;
        let executor_receipt_bytes = canonical_json_bytes(executor_receipt).map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to canonicalize active-response executor receipt: {error}"
            ))
        })?;
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "operation_id": terminal.operation_id(),
            "request_binding_hash": terminal.request_binding_hash(),
            "executor_receipt_id": executor_receipt.id,
        }))
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to bind active-response terminal receipt action: {error}"
            ))
        })?;
        let metadata = merge_metadata_objects(
            Some(self.ordinary_admission_operation_metadata(&terminal)),
            Some(serde_json::json!({
                "active_response_terminal_evidence": {
                    "executor_receipt_id": executor_receipt.id,
                    "executor_receipt_hash": sha256_hex(&executor_receipt_bytes),
                    "executor_receipt_key": executor_receipt.kernel_key.to_hex(),
                }
            })),
        );
        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: Some(terminal.request_id()),
            capability_id: terminal.capability_id(),
            tool_name: "governed_active_response",
            server_id: "chio.kernel",
            decision: Decision::Allow,
            action,
            content_hash: sha256_hex(&executor_receipt_bytes),
            canonical_content: executor_receipt_bytes,
            metadata,
            timestamp: current_unix_timestamp(),
            trust_level: chio_core::receipt::kinds::TrustLevel::Mediated,
            tenant_id: executor_receipt.tenant_id.clone(),
        })?;
        let payload = TerminalReceiptOutboxPayload {
            schema: TERMINAL_RECEIPT_OUTBOX_SCHEMA.to_string(),
            operation_id: terminal.operation_id().to_string(),
            request_binding_hash: terminal.request_binding_hash().to_string(),
            terminal_state: terminal.state(),
            terminal_dispatch_state: terminal.dispatch_state(),
            terminal_coordinator_lease_epoch: terminal.coordinator_lease_epoch(),
            terminal_version: terminal.version(),
            terminal_last_error: None,
            receipt_authority_id: format!("kernel:{}", receipt.kernel_key.to_hex()),
            receipt,
            executor_receipt: Some(executor_receipt.clone()),
        };
        self.commit_terminal_receipt_outbox_with_store(
            store,
            dispatch_committed,
            &terminal,
            &payload,
        )
    }

    pub(super) fn scope_threshold_terminal_receipt_outbox(
        &self,
        request: &ToolCallRequest,
        expected: &AdmissionOperation,
        terminal_state: AdmissionOperationState,
        terminal_dispatch_state: AdmissionDispatchState,
        terminal_last_error: Option<String>,
    ) -> Result<(serde_json::Value, ScopedThresholdTerminalReceiptIntent), KernelError> {
        if !matches!(
            (terminal_state, terminal_dispatch_state),
            (
                AdmissionOperationState::Completed,
                AdmissionDispatchState::EffectCompleted
            ) | (
                AdmissionOperationState::OutcomeUnknownAfterDispatch,
                AdmissionDispatchState::OutcomeUnknown
            ) | (
                AdmissionOperationState::CompensatedBeforeDispatch,
                AdmissionDispatchState::NotStarted
            )
        ) {
            return Err(KernelError::Internal(
                "terminal receipt outbox target is not a terminal dispatch projection".to_string(),
            ));
        }
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let current = store.load(expected.operation_id())?.ok_or_else(|| {
            KernelError::Internal(format!(
                "governed admission operation {} disappeared before terminal receipt signing",
                expected.operation_id()
            ))
        })?;
        if !current.has_same_prepared_binding(expected)
            || current.kind() != AdmissionOperationKind::ToolDispatch
            || current.request_id() != request.request_id
            || current.capability_id() != request.capability.id
        {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "governed admission operation {} changed its terminal receipt binding",
                expected.operation_id()
            )));
        }
        let valid_source = match terminal_state {
            AdmissionOperationState::Completed
            | AdmissionOperationState::OutcomeUnknownAfterDispatch => {
                current.state() == AdmissionOperationState::DispatchCommitted
                    && current.dispatch_state() == AdmissionDispatchState::Committed
            }
            AdmissionOperationState::CompensatedBeforeDispatch => {
                current.state() == AdmissionOperationState::CompensationPending
                    && current.dispatch_state() == AdmissionDispatchState::NotStarted
            }
            _ => false,
        };
        if !valid_source {
            return Err(KernelError::Internal(format!(
                "governed admission operation {} cannot stage a terminal receipt from {}",
                current.operation_id(),
                current.state().as_str()
            )));
        }
        let terminal = current.transition_checked(
            terminal_state,
            terminal_dispatch_state,
            current.coordinator_lease_epoch(),
            terminal_last_error,
        )?;
        let intent = ThresholdTerminalReceiptIntent {
            current,
            terminal: terminal.clone(),
        };
        let previous = self
            .threshold_terminal_receipt_intents
            .insert(request.request_id.clone(), intent);
        if previous.is_some() {
            if let Some(previous) = previous {
                self.threshold_terminal_receipt_intents
                    .insert(request.request_id.clone(), previous);
            }
            return Err(KernelError::Internal(format!(
                "request {} already has an active terminal receipt intent",
                request.request_id
            )));
        }
        Ok((
            self.ordinary_admission_operation_metadata(&terminal),
            ScopedThresholdTerminalReceiptIntent {
                request_id: request.request_id.clone(),
                intents: Arc::clone(&self.threshold_terminal_receipt_intents),
                previous: None,
            },
        ))
    }

    pub(super) fn record_scoped_threshold_terminal_receipt(
        &self,
        request: &ToolCallRequest,
        receipt: &ChioReceipt,
    ) -> Result<bool, KernelError> {
        let Some(intent) = self
            .threshold_terminal_receipt_intents
            .get(&request.request_id)
            .map(|entry| entry.value().clone())
        else {
            return Ok(false);
        };
        let payload = TerminalReceiptOutboxPayload {
            schema: TERMINAL_RECEIPT_OUTBOX_SCHEMA.to_string(),
            operation_id: intent.terminal.operation_id().to_string(),
            request_binding_hash: intent.terminal.request_binding_hash().to_string(),
            terminal_state: intent.terminal.state(),
            terminal_dispatch_state: intent.terminal.dispatch_state(),
            terminal_coordinator_lease_epoch: intent.terminal.coordinator_lease_epoch(),
            terminal_version: intent.terminal.version(),
            terminal_last_error: intent.terminal.last_error().map(ToOwned::to_owned),
            receipt_authority_id: format!("kernel:{}", receipt.kernel_key.to_hex()),
            receipt: receipt.clone(),
            executor_receipt: None,
        };
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        self.commit_terminal_receipt_outbox_with_store(
            store.as_ref(),
            &intent.current,
            &intent.terminal,
            &payload,
        )?;
        Ok(true)
    }

    fn commit_terminal_receipt_outbox_with_store(
        &self,
        store: &dyn AdmissionOperationStore,
        current: &AdmissionOperation,
        expected_terminal: &AdmissionOperation,
        payload: &TerminalReceiptOutboxPayload,
    ) -> Result<AdmissionOperation, KernelError> {
        self.ensure_receipt_persistence_ready()?;
        let terminal = self.stage_terminal_receipt_outbox_with_store(
            store,
            current,
            expected_terminal,
            payload,
        )?;
        self.persist_and_acknowledge_terminal_receipt(store, &terminal, payload)?;
        Ok(terminal)
    }

    fn stage_terminal_receipt_outbox_with_store(
        &self,
        store: &dyn AdmissionOperationStore,
        current: &AdmissionOperation,
        expected_terminal: &AdmissionOperation,
        payload: &TerminalReceiptOutboxPayload,
    ) -> Result<AdmissionOperation, KernelError> {
        self.validate_terminal_receipt_payload_with_store(store, expected_terminal, payload)?;
        let action = AdmissionCleanupAction::pending(
            current,
            AdmissionCleanupActionKind::TerminalReceipt,
            payload,
        )?;
        let request = AdmissionOperationCompareAndSwap {
            operation_id: current.operation_id(),
            expected_version: current.version(),
            coordinator_lease_epoch: current.coordinator_lease_epoch(),
            next_state: expected_terminal.state(),
            next_dispatch_state: expected_terminal.dispatch_state(),
            next_coordinator_lease_epoch: expected_terminal.coordinator_lease_epoch(),
            last_error: expected_terminal.last_error().map(ToOwned::to_owned),
        };
        let terminal = match store.compare_and_swap_with_cleanup_action(request, action.clone()) {
            Ok(AdmissionOperationCasOutcome::Applied(terminal)) => terminal,
            Ok(AdmissionOperationCasOutcome::Conflict(current)) => self
                .validate_recovered_terminal_outbox_commit(
                    store,
                    expected_terminal,
                    &action,
                    current,
                    None,
                )?,
            Ok(AdmissionOperationCasOutcome::Missing) => {
                return Err(KernelError::Internal(
                    "terminal receipt operation disappeared during atomic outbox commit"
                        .to_string(),
                ))
            }
            Err(error) => {
                let current = store.load(current.operation_id())?.ok_or_else(|| {
                    KernelError::Internal(
                        "terminal receipt operation disappeared after uncertain atomic commit"
                            .to_string(),
                    )
                })?;
                self.validate_recovered_terminal_outbox_commit(
                    store,
                    expected_terminal,
                    &action,
                    current,
                    Some(error.to_string()),
                )?
            }
        };
        if !same_terminal_projection(&terminal, expected_terminal) {
            return Err(KernelError::Internal(
                "atomic terminal receipt commit returned a different operation projection"
                    .to_string(),
            ));
        }
        Ok(terminal)
    }

    fn validate_recovered_terminal_outbox_commit(
        &self,
        store: &dyn AdmissionOperationStore,
        expected: &AdmissionOperation,
        expected_action: &AdmissionCleanupAction,
        current: AdmissionOperation,
        uncertain_error: Option<String>,
    ) -> Result<AdmissionOperation, KernelError> {
        let exact_action = store
            .load_cleanup_actions(expected.operation_id())?
            .into_iter()
            .find(|action| action.kind() == AdmissionCleanupActionKind::TerminalReceipt)
            .is_some_and(|action| {
                action.action_id() == expected_action.action_id()
                    && action.operation_id() == expected_action.operation_id()
                    && action.request_binding_hash() == expected_action.request_binding_hash()
                    && action.kind() == expected_action.kind()
                    && action.payload_json() == expected_action.payload_json()
                    && action.payload_hash() == expected_action.payload_hash()
                    && matches!(
                        action.state(),
                        AdmissionCleanupActionState::Pending
                            | AdmissionCleanupActionState::Claimed
                            | AdmissionCleanupActionState::Completed
                    )
            });
        if same_terminal_projection(&current, expected) && exact_action {
            return Ok(current);
        }
        Err(KernelError::Internal(match uncertain_error {
            Some(error) => format!(
                "terminal receipt atomic commit is uncertain after `{error}` and exact recovery failed"
            ),
            None => format!(
                "terminal receipt atomic commit conflicted at {} without its exact signed outbox",
                current.state().as_str()
            ),
        }))
    }

    fn persist_and_acknowledge_terminal_receipt(
        &self,
        store: &dyn AdmissionOperationStore,
        operation: &AdmissionOperation,
        payload: &TerminalReceiptOutboxPayload,
    ) -> Result<(), KernelError> {
        self.validate_terminal_receipt_payload_with_store(store, operation, payload)?;
        let request_id = receipt_metadata_string(&payload.receipt, "/receipt_context/request_id");
        self.record_chio_receipt_consuming_optional_intent(&payload.receipt, request_id)?;
        if operation.state() == AdmissionOperationState::Completed
            && operation.broker_attempt_id().is_some()
        {
            if let Some(registrar) = self.supplemental_admission_registrar.as_ref() {
                registrar
                    .finalize_admission(operation.operation_id())
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
            }
        }
        self.discharge_admission_cleanup_action_with_store(
            store,
            operation,
            AdmissionCleanupActionKind::TerminalReceipt,
        )
    }

    pub(super) fn recover_terminal_receipt_outboxes_with_store(
        &self,
        store: &dyn AdmissionOperationStore,
        kind: AdmissionOperationKind,
        expected_coordinator_authority_id: Option<&str>,
    ) -> Result<usize, KernelError> {
        self.ensure_receipt_persistence_ready()?;
        let mut recovered = 0usize;
        let mut errors = Vec::new();
        let operation_ids = store.list_operations_with_pending_cleanup_action(
            kind,
            AdmissionCleanupActionKind::TerminalReceipt,
            MAX_TERMINAL_RECEIPT_RECOVERY_OPERATIONS_PER_ACTIVATION,
        )?;
        for operation_id in operation_ids {
            if store.load(&operation_id)?.is_some_and(|operation| {
                operation.state() == AdmissionOperationState::CompensationPending
            }) {
                continue;
            }
            let result = (|| {
                let operation = store.load(&operation_id)?.ok_or_else(|| {
                    KernelError::Internal(format!(
                        "terminal receipt operation {operation_id} disappeared during recovery"
                    ))
                })?;
                if expected_coordinator_authority_id
                    .is_some_and(|expected| operation.coordinator_authority_id() != expected)
                {
                    return Err(KernelError::Internal(format!(
                        "terminal receipt operation {operation_id} belongs to a different coordinator authority"
                    )));
                }
                let mut actions = store
                    .load_cleanup_actions(&operation_id)?
                    .into_iter()
                    .filter(|action| {
                        action.kind() == AdmissionCleanupActionKind::TerminalReceipt
                            && action.state() != AdmissionCleanupActionState::Completed
                    });
                let action = actions.next().ok_or_else(|| {
                    KernelError::Internal(format!(
                        "terminal receipt operation {operation_id} has no pending signed outbox"
                    ))
                })?;
                if actions.next().is_some() {
                    return Err(KernelError::Internal(format!(
                        "terminal receipt operation {operation_id} has multiple pending signed outboxes"
                    )));
                }
                if action.operation_id() != operation.operation_id()
                    || action.request_binding_hash() != operation.request_binding_hash()
                {
                    return Err(KernelError::Internal(format!(
                        "terminal receipt outbox for operation {operation_id} changed its immutable binding"
                    )));
                }
                let payload: TerminalReceiptOutboxPayload =
                    serde_json::from_str(action.payload_json()).map_err(|error| {
                        KernelError::Internal(format!(
                            "terminal receipt outbox payload is invalid: {error}"
                        ))
                    })?;
                self.persist_and_acknowledge_terminal_receipt(store, &operation, &payload)
            })();
            match result {
                Ok(()) => {
                    recovered = recovered.checked_add(1).ok_or_else(|| {
                        KernelError::Internal(
                            "terminal receipt recovery count overflowed usize".to_string(),
                        )
                    })?;
                }
                Err(error) => errors.push(format!("operation {operation_id}: {error}")),
            }
        }
        if !store
            .list_operations_with_pending_cleanup_action(
                kind,
                AdmissionCleanupActionKind::TerminalReceipt,
                1,
            )?
            .is_empty()
        {
            errors.push(format!(
                "more terminal receipt outboxes remain after the bounded {MAX_TERMINAL_RECEIPT_RECOVERY_OPERATIONS_PER_ACTIVATION}-operation recovery batch"
            ));
        }
        if errors.is_empty() {
            Ok(recovered)
        } else {
            Err(KernelError::Internal(format!(
                "one or more terminal receipt outboxes remain unfinished: {}",
                errors.join("; ")
            )))
        }
    }

    fn validate_terminal_receipt_payload_with_store(
        &self,
        store: &dyn AdmissionOperationStore,
        operation: &AdmissionOperation,
        payload: &TerminalReceiptOutboxPayload,
    ) -> Result<(), KernelError> {
        validate_terminal_receipt_payload(operation, payload, &self.public_key())?;
        if operation.kind() != AdmissionOperationKind::GovernedActiveResponse
            || operation.state() != AdmissionOperationState::Completed
        {
            return Ok(());
        }
        let executor_receipt = payload.executor_receipt.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "completed active-response terminal outbox lacks executor evidence".to_string(),
            )
        })?;
        let executor_receipt_bytes = canonical_json_bytes(executor_receipt).map_err(|error| {
            KernelError::Internal(format!(
                "active-response executor receipt canonicalization failed: {error}"
            ))
        })?;
        let executor_receipt_hash = sha256_hex(&executor_receipt_bytes);
        let expected_action = ToolCallAction::from_parameters(serde_json::json!({
            "operation_id": operation.operation_id(),
            "request_binding_hash": operation.request_binding_hash(),
            "executor_receipt_id": executor_receipt.id,
        }))
        .map_err(|error| {
            KernelError::Internal(format!(
                "active-response terminal action derivation failed: {error}"
            ))
        })?;
        let expected_evidence = serde_json::json!({
            "executor_receipt_id": executor_receipt.id,
            "executor_receipt_hash": executor_receipt_hash,
            "executor_receipt_key": executor_receipt.kernel_key.to_hex(),
        });
        if payload.receipt.content_hash != executor_receipt_hash
            || payload.receipt.action.parameters != expected_action.parameters
            || payload.receipt.action.parameter_hash != expected_action.parameter_hash
            || payload
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.pointer("/active_response_terminal_evidence"))
                != Some(&expected_evidence)
        {
            return Err(KernelError::Internal(
                "active-response terminal wrapper changed its canonical executor evidence"
                    .to_string(),
            ));
        }
        let anchor = self.load_active_response_operation_anchor_with_store(store, operation)?;
        super::active_response_coordinator::validate_active_response_terminal_executor_receipt(
            operation,
            &anchor,
            executor_receipt,
        )
    }
}

fn validate_terminal_receipt_payload(
    operation: &AdmissionOperation,
    payload: &TerminalReceiptOutboxPayload,
    kernel_public_key: &chio_core::crypto::PublicKey,
) -> Result<(), KernelError> {
    if payload.schema != TERMINAL_RECEIPT_OUTBOX_SCHEMA
        || payload.operation_id != operation.operation_id()
        || payload.request_binding_hash != operation.request_binding_hash()
        || payload.terminal_state != operation.state()
        || payload.terminal_dispatch_state != operation.dispatch_state()
        || payload.terminal_coordinator_lease_epoch != operation.coordinator_lease_epoch()
        || payload.terminal_version != operation.version()
        || payload.terminal_last_error.as_deref() != operation.last_error()
        || !matches!(
            (operation.state(), operation.dispatch_state()),
            (
                AdmissionOperationState::Completed,
                AdmissionDispatchState::EffectCompleted
            ) | (
                AdmissionOperationState::OutcomeUnknownAfterDispatch,
                AdmissionDispatchState::OutcomeUnknown
            ) | (
                AdmissionOperationState::CompensatedBeforeDispatch,
                AdmissionDispatchState::NotStarted
            )
        )
    {
        return Err(KernelError::Internal(
            "terminal receipt outbox changed its operation projection".to_string(),
        ));
    }
    let receipt_authority_id = format!("kernel:{}", payload.receipt.kernel_key.to_hex());
    let evidence_shape_valid = matches!(
        (
            operation.kind(),
            operation.state(),
            payload.executor_receipt.as_ref(),
        ),
        (
            AdmissionOperationKind::GovernedActiveResponse,
            AdmissionOperationState::Completed,
            Some(_),
        ) | (
            AdmissionOperationKind::GovernedActiveResponse,
            AdmissionOperationState::CompensatedBeforeDispatch,
            None,
        ) | (AdmissionOperationKind::ToolDispatch, _, None)
    );
    let signer_binding_valid = match operation.kind() {
        AdmissionOperationKind::ToolDispatch => {
            receipt_authority_id == operation.coordinator_authority_id()
        }
        AdmissionOperationKind::GovernedActiveResponse => {
            &payload.receipt.kernel_key == kernel_public_key
        }
    };
    if !evidence_shape_valid
        || payload.receipt_authority_id != receipt_authority_id
        || !signer_binding_valid
        || payload.receipt.trust_level != chio_core::receipt::kinds::TrustLevel::Mediated
        || payload.receipt.capability_id != operation.capability_id()
        || payload.receipt.policy_hash != operation.policy_hash()
        || receipt_metadata_string(&payload.receipt, "/receipt_context/request_id")
            != Some(operation.request_id())
        || receipt_metadata_string(
            &payload.receipt,
            "/protocol_admission/admission_operation/operation_id",
        ) != Some(operation.operation_id())
        || receipt_metadata_string(
            &payload.receipt,
            "/protocol_admission/admission_operation/state",
        ) != Some(operation.state().as_str())
        || receipt_metadata_string(
            &payload.receipt,
            "/protocol_admission/admission_operation/dispatch_state",
        ) != Some(operation.dispatch_state().as_str())
        || receipt_metadata_u64(
            &payload.receipt,
            "/protocol_admission/admission_operation/version",
        ) != Some(operation.version())
        || !receipt_metadata_last_error_matches(&payload.receipt, operation.last_error())
    {
        return Err(KernelError::Internal(
            "signed terminal receipt does not carry the exact operation projection".to_string(),
        ));
    }
    if !payload.receipt.verify_signature().map_err(|error| {
        KernelError::ReceiptSigningFailed(format!(
            "terminal receipt outbox signature verification failed: {error}"
        ))
    })? {
        return Err(KernelError::ReceiptSigningFailed(
            "terminal receipt outbox contains an invalid signature".to_string(),
        ));
    }
    Ok(())
}

fn receipt_metadata_string<'a>(receipt: &'a ChioReceipt, pointer: &str) -> Option<&'a str> {
    receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.pointer(pointer))
        .and_then(serde_json::Value::as_str)
}

fn receipt_metadata_u64(receipt: &ChioReceipt, pointer: &str) -> Option<u64> {
    receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.pointer(pointer))
        .and_then(serde_json::Value::as_u64)
}

fn receipt_metadata_last_error_matches(receipt: &ChioReceipt, expected: Option<&str>) -> bool {
    let value = receipt.metadata.as_ref().and_then(|metadata| {
        metadata.pointer("/protocol_admission/admission_operation/last_error")
    });
    match (value, expected) {
        (Some(serde_json::Value::Null), None) => true,
        (Some(serde_json::Value::String(actual)), Some(expected)) => actual == expected,
        _ => false,
    }
}

fn same_terminal_projection(actual: &AdmissionOperation, expected: &AdmissionOperation) -> bool {
    actual.has_same_prepared_binding(expected)
        && actual.state() == expected.state()
        && actual.dispatch_state() == expected.dispatch_state()
        && actual.coordinator_lease_epoch() == expected.coordinator_lease_epoch()
        && actual.version() == expected.version()
        && actual.last_error() == expected.last_error()
}

fn same_operation_projection(actual: &AdmissionOperation, expected: &AdmissionOperation) -> bool {
    actual.has_same_prepared_binding(expected)
        && actual.state() == expected.state()
        && actual.dispatch_state() == expected.dispatch_state()
        && actual.coordinator_lease_epoch() == expected.coordinator_lease_epoch()
        && actual.version() == expected.version()
        && actual.last_error() == expected.last_error()
}

fn exact_cleanup_action(
    actual: &AdmissionCleanupAction,
    expected: &AdmissionCleanupAction,
) -> bool {
    actual.action_id() == expected.action_id()
        && actual.operation_id() == expected.operation_id()
        && actual.request_binding_hash() == expected.request_binding_hash()
        && actual.kind() == expected.kind()
        && actual.payload_json() == expected.payload_json()
        && actual.payload_hash() == expected.payload_hash()
        && matches!(
            actual.state(),
            AdmissionCleanupActionState::Pending
                | AdmissionCleanupActionState::Claimed
                | AdmissionCleanupActionState::Completed
        )
}
