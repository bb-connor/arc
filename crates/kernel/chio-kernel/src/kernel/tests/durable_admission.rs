use crate::admission_operation::{
    AdmissionBeginResult, AdmissionCaptureError, AdmissionCommandResult, AdmissionIdentifier,
    AdmissionOperationCommand, AdmissionOperationError, AdmissionOperationId,
    AdmissionOperationState,
    AdmissionOperationStore, AdmissionOperationStoreError, AdmissionOperationV1,
    AdmissionProjectionCapabilities, AdmissionReplayClassification, AdmissionReplayKey,
    AdmissionTerminal, AdmissionTerminalProjection, AdmissionTerminalReplay,
    QualifiedAdmissionOperationStore, StoreMutationFence, UntrustedAdmissionRecoveryClaim,
};
use crate::receipt_store::{QualifiedAdmissionProjectionStore, ReceiptStore, ReceiptStoreError};
use crate::tool_outcome::{
    validate_evaluation_store_successor, validate_terminal_store_pair,
    CanonicalInvocationBlobV1, CanonicalResolvedOutputBlobV1, PostReturnEvaluationRecordV1,
    QualifiedToolOutcomeStore, RawInvocationOutcomeV1, ToolOutcomeInsertResultV1,
    ToolOutcomeRecordV1, ToolOutcomeStore, ToolOutcomeStoreError,
};

#[test]
fn durable_admission_runtime_defaults_closed_and_off_requires_explicit_unsafe_ephemeral_mode() {
    use crate::admission_operation::{AdmissionOperationError, DurableAdmissionMode};

    let mut kernel = make_kernel(make_config());
    assert_eq!(
        kernel.durable_admission_mode(),
        DurableAdmissionMode::SideEffecting
    );
    assert_eq!(
        kernel.configure_durable_admission(DurableAdmissionMode::Off, false),
        Err(AdmissionOperationError::UnsafeDurableAdmissionOff)
    );
    kernel
        .configure_durable_admission(DurableAdmissionMode::Monetary, false)
        .expect("monetary qualification mode");
    assert_eq!(
        kernel.durable_admission_mode(),
        DurableAdmissionMode::Monetary
    );
    kernel
        .configure_durable_admission(DurableAdmissionMode::Off, true)
        .expect("explicit unsafe ephemeral mode");
    assert_eq!(kernel.durable_admission_mode(), DurableAdmissionMode::Off);

    let mut durable_config = make_config();
    durable_config.allow_ephemeral_receipt_log = false;
    let mut durable_kernel = make_kernel(durable_config);
    assert_eq!(
        durable_kernel.configure_durable_admission(DurableAdmissionMode::Off, true),
        Err(AdmissionOperationError::UnsafeDurableAdmissionOff)
    );
}

#[derive(Default)]
struct TestAdmissionState {
    operation: Option<AdmissionOperationV1>,
    claim: Option<UntrustedAdmissionRecoveryClaim>,
    raw_outcome: Option<RawInvocationOutcomeV1>,
    tool_outcome: Option<ToolOutcomeRecordV1>,
    post_return_evaluation: Option<PostReturnEvaluationRecordV1>,
    resolved_output: Option<CanonicalResolvedOutputBlobV1>,
    receipt: Option<chio_core::receipt::body::ChioReceipt>,
}

struct TestAdmissionOperationStore {
    fence: std::sync::Mutex<StoreMutationFence>,
    fail_next_outcome_write: std::sync::atomic::AtomicBool,
    fail_next_evaluation_begin: std::sync::atomic::AtomicBool,
    fail_next_evaluation_stage: std::sync::atomic::AtomicBool,
    fail_next_evaluation_finalization: std::sync::atomic::AtomicBool,
    fail_next_terminal_projection: std::sync::atomic::AtomicBool,
    state: std::sync::Mutex<TestAdmissionState>,
}

impl TestAdmissionOperationStore {
    fn new(fence: StoreMutationFence) -> Self {
        Self {
            fence: std::sync::Mutex::new(fence),
            fail_next_outcome_write: std::sync::atomic::AtomicBool::new(false),
            fail_next_evaluation_begin: std::sync::atomic::AtomicBool::new(false),
            fail_next_evaluation_stage: std::sync::atomic::AtomicBool::new(false),
            fail_next_evaluation_finalization: std::sync::atomic::AtomicBool::new(false),
            fail_next_terminal_projection: std::sync::atomic::AtomicBool::new(false),
            state: std::sync::Mutex::new(TestAdmissionState::default()),
        }
    }

    fn fail_next_outcome_write(&self) {
        self.fail_next_outcome_write.store(true, Ordering::SeqCst);
    }

    fn fail_next_terminal_projection(&self) {
        self.fail_next_terminal_projection
            .store(true, Ordering::SeqCst);
    }

    fn fail_next_evaluation_begin(&self) {
        self.fail_next_evaluation_begin.store(true, Ordering::SeqCst);
    }

    fn fail_next_evaluation_stage(&self) {
        self.fail_next_evaluation_stage.store(true, Ordering::SeqCst);
    }

    fn fail_next_evaluation_finalization(&self) {
        self.fail_next_evaluation_finalization
            .store(true, Ordering::SeqCst);
    }

    fn outcome_versions(&self) -> (Option<u64>, Option<u64>) {
        let state = self.state.lock().expect("test admission state lock");
        (
            state
                .post_return_evaluation
                .as_ref()
                .map(PostReturnEvaluationRecordV1::version),
            state.tool_outcome.as_ref().map(ToolOutcomeRecordV1::version),
        )
    }

    fn rotate_fence(&self, fence: StoreMutationFence) {
        *self.fence.lock().expect("test admission fence lock") = fence;
    }

    fn operation(&self) -> AdmissionOperationV1 {
        self.state
            .lock()
            .expect("test admission state lock")
            .operation
            .clone()
            .expect("retained operation")
    }

    fn has_operation(&self) -> bool {
        self.state
            .lock()
            .expect("test admission state lock")
            .operation
            .is_some()
    }

    fn require_fence(
        &self,
        fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError> {
        (fence == &*self.fence.lock().expect("test admission fence lock"))
            .then_some(())
            .ok_or(AdmissionOperationStoreError::Fenced)
    }
}

impl AdmissionOperationStore for TestAdmissionOperationStore {
    fn begin(
        &self,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError> {
        self.require_fence(fence)?;
        operation.validate()?;
        let mut state = self.state.lock().expect("test admission state lock");
        let Some(existing) = state.operation.as_ref() else {
            state.operation = Some(operation.clone());
            return Ok(AdmissionBeginResult::Created(operation.clone()));
        };
        Ok(match existing.classify_replay(operation) {
            AdmissionReplayClassification::Exact { terminal_replay } => {
                AdmissionBeginResult::ExactReplay {
                    operation: existing.clone(),
                    terminal_replay,
                }
            }
            AdmissionReplayClassification::Conflict => AdmissionBeginResult::Conflict {
                existing_operation_id: existing.binding().operation_id().clone(),
            },
        })
    }

    fn load_by_operation_id(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        Ok(self
            .state
            .lock()
            .expect("test admission state lock")
            .operation
            .as_ref()
            .filter(|operation| operation.binding().operation_id() == operation_id)
            .cloned())
    }

    fn load_by_replay_key(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        Ok(self
            .state
            .lock()
            .expect("test admission state lock")
            .operation
            .as_ref()
            .filter(|operation| &operation.replay_key() == replay_key)
            .cloned())
    }

    fn compare_and_swap(
        &self,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        let mut state = self.state.lock().expect("test admission state lock");
        let operation = state
            .operation
            .as_ref()
            .filter(|operation| operation.binding().operation_id() == command.operation_id())
            .cloned()
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        let claim = state
            .claim
            .as_ref()
            .filter(|claim| claim.operation_id() == command.operation_id())
            .ok_or(AdmissionOperationStoreError::Fenced)?;
        let lease = command.recovery_lease();
        if claim.claimant_id() != lease.claimant_id()
            || claim.coordinator_lease_id() != lease.coordinator_lease_id()
            || claim.claimed_version() != lease.claimed_version()
            || claim.expires_at_unix_ms() != lease.expires_at_unix_ms()
            || claim.store_fence() != lease.store_fence()
        {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        let result = operation.apply_command(command, trusted_now_unix_ms)?;
        state.operation = Some(result.clone().into_operation());
        state.claim = None;
        Ok(result)
    }

    fn claim_recovery_untrusted(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        claimant_id: &AdmissionIdentifier,
        _trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        fence: &StoreMutationFence,
    ) -> Result<UntrustedAdmissionRecoveryClaim, AdmissionOperationStoreError> {
        self.require_fence(fence)?;
        let mut state = self.state.lock().expect("test admission state lock");
        let operation = state
            .operation
            .as_ref()
            .filter(|operation| operation.binding().operation_id() == operation_id)
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if operation.version() != expected_version {
            return Err(AdmissionOperationError::StaleVersion {
                expected: expected_version,
                actual: operation.version(),
            }
            .into());
        }
        let claim = UntrustedAdmissionRecoveryClaim::new(
            operation_id.clone(),
            claimant_id.clone(),
            AdmissionIdentifier::try_new("coordinator_lease_id", fence.lease_id.clone())?,
            operation.coordinator_lease_epoch(),
            expected_version,
            expires_at_unix_ms,
            fence.clone(),
        )?;
        state.claim = Some(claim.clone());
        Ok(claim)
    }

    fn revalidate_recovery_claim(
        &self,
        operation: &AdmissionOperationV1,
        claim: &UntrustedAdmissionRecoveryClaim,
        trusted_now_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.require_fence(current_store_fence)?;
        let state = self.state.lock().expect("test admission state lock");
        if state.operation.as_ref() != Some(operation)
            || state.claim.as_ref() != Some(claim)
            || trusted_now_unix_ms >= claim.expires_at_unix_ms()
        {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        Ok(())
    }

    fn list_recoverable(
        &self,
        _not_after_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<AdmissionOperationV1>, AdmissionOperationStoreError> {
        Ok(self
            .state
            .lock()
            .expect("test admission state lock")
            .operation
            .iter()
            .filter(|operation| !operation.state().is_terminal())
            .take(limit)
            .cloned()
            .collect())
    }

    fn load_terminal_replay(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionTerminalReplay>, AdmissionOperationStoreError> {
        Ok(self
            .load_by_replay_key(replay_key)?
            .and_then(|operation| operation.terminal_replay().cloned()))
    }
}

impl QualifiedAdmissionOperationStore for TestAdmissionOperationStore {}

impl ReceiptStore for TestAdmissionOperationStore {
    fn append_chio_receipt(
        &self,
        _receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "test admissions require a terminal projection".to_owned(),
        ))
    }

    fn admission_projection_capabilities(&self) -> AdmissionProjectionCapabilities {
        AdmissionProjectionCapabilities {
            operation_terminal: true,
            tool_outcome: true,
            ..AdmissionProjectionCapabilities::default()
        }
    }

    fn commit_admission_projection(
        &self,
        projection: &AdmissionTerminalProjection,
    ) -> Result<AdmissionTerminal, ReceiptStoreError> {
        if self
            .fail_next_terminal_projection
            .swap(false, Ordering::SeqCst)
        {
            return Err(ReceiptStoreError::Conflict(
                "injected terminal projection failure".to_owned(),
            ));
        }
        let mut state = self.state.lock().map_err(|_| {
            ReceiptStoreError::Conflict("test admission state lock poisoned".to_owned())
        })?;
        let operation = state.operation.clone().ok_or_else(|| {
            ReceiptStoreError::NotFound("test admission operation".to_owned())
        })?;
        let claim = state.claim.as_ref().ok_or_else(|| {
            ReceiptStoreError::Conflict("terminal projection has no recovery claim".to_owned())
        })?;
        let context = projection.context();
        if claim.operation_id() != &context.operation_id
            || claim.coordinator_lease_id() != &context.coordinator_lease_id
            || claim.coordinator_lease_epoch() != context.coordinator_lease_epoch
            || claim.store_fence() != &context.store_fence
        {
            return Err(ReceiptStoreError::Conflict(
                "terminal projection recovery claim mismatch".to_owned(),
            ));
        }
        let updated = operation
            .apply_terminal_projection(projection, &self.admission_projection_capabilities())
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        let replay = updated.terminal_replay().cloned().ok_or_else(|| {
            ReceiptStoreError::Conflict("terminal replay is absent".to_owned())
        })?;
        if let AdmissionTerminalProjection::Completed(completed) = projection {
            state.receipt = Some(completed.receipt.receipt().clone());
        }
        state.operation = Some(updated.clone());
        state.claim = None;
        Ok(AdmissionTerminal {
            operation_id: updated.binding().operation_id().clone(),
            state: updated.state(),
            replay,
        })
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<chio_core::receipt::body::ChioReceipt>, ReceiptStoreError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| {
                ReceiptStoreError::Conflict("test admission state lock poisoned".to_owned())
            })?
            .receipt
            .as_ref()
            .filter(|receipt| receipt.id == receipt_id)
            .cloned())
    }

    fn append_child_receipt(
        &self,
        _receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "test child receipt persistence".to_owned(),
        ))
    }
}

impl QualifiedAdmissionProjectionStore for TestAdmissionOperationStore {
    fn capture_invocation_and_commit_dispatch(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        request: crate::budget_store::BudgetCaptureInvocationRequest,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionOperationV1, AdmissionCaptureError> {
        self.require_fence(active_fence)
            .map_err(|_| AdmissionCaptureError::Fenced)?;
        request
            .validate()
            .map_err(|error| AdmissionCaptureError::Invariant(error.to_string()))?;
        if operation.state() != AdmissionOperationState::CapturePending
            || operation.binding().capability_id().as_str() != request.capability_id
            || operation
                .budget_hold_id()
                .is_none_or(|hold_id| hold_id.as_str() != request.hold_id)
        {
            return Err(AdmissionCaptureError::Invariant(
                "test combined capture binding mismatch".to_owned(),
            ));
        }
        let command = AdmissionOperationCommand::new(
            operation.binding().operation_id().clone(),
            operation.version(),
            recovery_lease.clone(),
            Vec::new(),
            Some(AdmissionOperationState::DispatchCommitted),
            None,
            None,
        )
        .map_err(AdmissionCaptureError::Operation)?;
        self.compare_and_swap(&command, trusted_now_unix_ms)
            .map(AdmissionCommandResult::into_operation)
            .map_err(|error| AdmissionCaptureError::Invariant(error.to_string()))
    }

    fn list_admission_receipts_after(
        &self,
        after_receipt_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<chio_core::receipt::body::ChioReceipt>, ReceiptStoreError> {
        let receipt = self
            .state
            .lock()
            .map_err(|_| {
                ReceiptStoreError::Conflict("test admission state lock poisoned".to_owned())
            })?
            .receipt
            .clone();
        Ok(receipt
            .into_iter()
            .filter(|receipt| after_receipt_id.is_none_or(|after| receipt.id.as_str() > after))
            .take(limit)
            .collect())
    }
}

impl ToolOutcomeStore for TestAdmissionOperationStore {
    fn record_tool_returned(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        blob: &CanonicalInvocationBlobV1,
        record: &ToolOutcomeRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ToolOutcomeInsertResultV1, ToolOutcomeStoreError> {
        self.require_fence(active_fence)
            .map_err(|_| ToolOutcomeStoreError::Fenced)?;
        record
            .validate_for_store_insert(
                operation,
                blob,
                active_fence,
                trusted_now_unix_ms,
            )
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        if self.fail_next_outcome_write.swap(false, Ordering::SeqCst) {
            return Err(ToolOutcomeStoreError::Unavailable(
                "injected tool outcome write failure".to_owned(),
            ));
        }
        let mut state = self.state.lock().expect("test admission state lock");
        let current = state
            .operation
            .as_ref()
            .filter(|current| *current == operation)
            .cloned()
            .ok_or(ToolOutcomeStoreError::CasConflict)?;
        if let Some(existing) = state.tool_outcome.as_ref() {
            if !existing.same_immutable_outcome(record) {
                return Err(ToolOutcomeStoreError::Conflict);
            }
            return Ok(ToolOutcomeInsertResultV1::ExactReplay {
                outcome: existing.clone(),
                operation: current,
            });
        }
        let command = crate::tool_outcome::finalizing_outcome_command(
            operation,
            recovery_lease.clone(),
            record.outcome_id().clone(),
        )
        .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        let finalizing = current
            .apply_command(&command, trusted_now_unix_ms)
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?
            .into_operation();
        let raw = RawInvocationOutcomeV1::from_canonical_bytes(blob.bytes())
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        state.raw_outcome = Some(raw);
        state.tool_outcome = Some(record.clone());
        state.operation = Some(finalizing.clone());
        Ok(ToolOutcomeInsertResultV1::Inserted {
            outcome: record.clone(),
            operation: finalizing,
        })
    }

    fn lookup_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<ToolOutcomeRecordV1>, ToolOutcomeStoreError> {
        Ok(self
            .state
            .lock()
            .expect("test admission state lock")
            .tool_outcome
            .as_ref()
            .filter(|outcome| outcome.operation_id() == operation_id)
            .cloned())
    }

    fn load_raw_invocation_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<RawInvocationOutcomeV1>, ToolOutcomeStoreError> {
        let state = self.state.lock().expect("test admission state lock");
        Ok(state
            .tool_outcome
            .as_ref()
            .filter(|outcome| outcome.operation_id() == operation_id)
            .and(state.raw_outcome.clone()))
    }

    fn lookup_post_return_evaluation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<PostReturnEvaluationRecordV1>, ToolOutcomeStoreError> {
        let state = self.state.lock().expect("test admission state lock");
        Ok(state
            .post_return_evaluation
            .as_ref()
            .filter(|evaluation| evaluation.operation_id() == operation_id)
            .cloned())
    }

    fn begin_post_return_evaluation(
        &self,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        record: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        self.require_fence(active_fence)
            .map_err(|_| ToolOutcomeStoreError::Fenced)?;
        let mut state = self.state.lock().expect("test admission state lock");
        let operation = state.operation.as_ref().ok_or(ToolOutcomeStoreError::NotFound)?;
        let outcome = state.tool_outcome.as_ref().ok_or(ToolOutcomeStoreError::NotFound)?;
        if state.claim.as_ref() != Some(recovery_lease.untrusted_claim()) {
            return Err(ToolOutcomeStoreError::Fenced);
        }
        record
            .validate_against(operation, outcome)
            .and_then(|_| record.validate_for_store_mutation(trusted_now_unix_ms))
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        if self
            .fail_next_evaluation_begin
            .swap(false, Ordering::SeqCst)
        {
            return Err(ToolOutcomeStoreError::Unavailable(
                "injected evaluation begin failure".to_owned(),
            ));
        }
        match state.post_return_evaluation.as_ref() {
            Some(existing) if existing == record => Ok(existing.clone()),
            Some(_) => Err(ToolOutcomeStoreError::Conflict),
            None => {
                state.post_return_evaluation = Some(record.clone());
                Ok(record.clone())
            }
        }
    }

    fn stage_post_return_evaluation(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        next: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        self.require_fence(active_fence)
            .map_err(|_| ToolOutcomeStoreError::Fenced)?;
        let mut state = self.state.lock().expect("test admission state lock");
        if state.claim.as_ref() != Some(recovery_lease.untrusted_claim()) {
            return Err(ToolOutcomeStoreError::Fenced);
        }
        let current = state
            .post_return_evaluation
            .as_ref()
            .filter(|evaluation| evaluation.operation_id() == operation_id)
            .cloned()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        if current.version() != expected_version {
            return Err(ToolOutcomeStoreError::CasConflict);
        }
        validate_evaluation_store_successor(&current, next)
            .and_then(|_| next.validate_for_store_mutation(trusted_now_unix_ms))
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        if self
            .fail_next_evaluation_stage
            .swap(false, Ordering::SeqCst)
        {
            return Err(ToolOutcomeStoreError::Unavailable(
                "injected evaluation stage failure".to_owned(),
            ));
        }
        state.post_return_evaluation = Some(next.clone());
        Ok(next.clone())
    }

    fn finalize_post_return(
        &self,
        operation_id: &AdmissionOperationId,
        expected_evaluation_version: u64,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        terminal_evaluation: &PostReturnEvaluationRecordV1,
        expected_outcome_version: u64,
        terminal_outcome: &ToolOutcomeRecordV1,
        resolved_output: Option<&CanonicalResolvedOutputBlobV1>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(PostReturnEvaluationRecordV1, ToolOutcomeRecordV1), ToolOutcomeStoreError> {
        self.require_fence(active_fence)
            .map_err(|_| ToolOutcomeStoreError::Fenced)?;
        let mut state = self.state.lock().expect("test admission state lock");
        if state.claim.as_ref() != Some(recovery_lease.untrusted_claim()) {
            return Err(ToolOutcomeStoreError::Fenced);
        }
        let operation = state.operation.as_ref().ok_or(ToolOutcomeStoreError::NotFound)?;
        let current_outcome = state.tool_outcome.as_ref().ok_or(ToolOutcomeStoreError::NotFound)?;
        let current_evaluation = state
            .post_return_evaluation
            .as_ref()
            .filter(|evaluation| evaluation.operation_id() == operation_id)
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        if current_evaluation.version() != expected_evaluation_version
            || current_outcome.version() != expected_outcome_version
        {
            return Err(ToolOutcomeStoreError::CasConflict);
        }
        validate_terminal_store_pair(
            operation,
            current_outcome,
            current_evaluation,
            terminal_evaluation,
            terminal_outcome,
            resolved_output,
        )
        .and_then(|_| terminal_evaluation.validate_for_store_mutation(trusted_now_unix_ms))
        .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        if self
            .fail_next_evaluation_finalization
            .swap(false, Ordering::SeqCst)
        {
            return Err(ToolOutcomeStoreError::Unavailable(
                "injected evaluation finalization failure".to_owned(),
            ));
        }
        state.post_return_evaluation = Some(terminal_evaluation.clone());
        state.tool_outcome = Some(terminal_outcome.clone());
        state.resolved_output = resolved_output.cloned();
        Ok((terminal_evaluation.clone(), terminal_outcome.clone()))
    }

    fn load_resolved_output_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<CanonicalResolvedOutputBlobV1>, ToolOutcomeStoreError> {
        let state = self.state.lock().expect("test admission state lock");
        Ok(state
            .tool_outcome
            .as_ref()
            .filter(|outcome| outcome.operation_id() == operation_id)
            .and(state.resolved_output.clone()))
    }
}

impl QualifiedToolOutcomeStore for TestAdmissionOperationStore {}

#[derive(Clone, Default)]
struct AdmissionReceiptProjectionStore {
    receipt: std::sync::Arc<std::sync::Mutex<Option<ChioReceipt>>>,
    successful_appends: std::sync::Arc<AtomicU64>,
    fail_next_append: std::sync::Arc<AtomicBool>,
}

impl AdmissionReceiptProjectionStore {
    fn fail_next_append(&self) {
        self.fail_next_append.store(true, Ordering::SeqCst);
    }

    fn receipt(&self) -> Option<ChioReceipt> {
        self.receipt
            .lock()
            .expect("admission receipt projection lock")
            .clone()
    }

    fn successful_appends(&self) -> u64 {
        self.successful_appends.load(Ordering::SeqCst)
    }
}

impl ReceiptStore for AdmissionReceiptProjectionStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        if self.fail_next_append.swap(false, Ordering::SeqCst) {
            return Err(ReceiptStoreError::Conflict(
                "injected admission receipt projection failure".to_owned(),
            ));
        }
        let mut stored = self.receipt.lock().map_err(|_| {
            ReceiptStoreError::Conflict("admission receipt projection lock poisoned".to_owned())
        })?;
        if let Some(existing) = stored.as_ref() {
            let existing = chio_core::canonical::canonical_json_bytes(existing)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
            let projected = chio_core::canonical::canonical_json_bytes(receipt)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
            return (existing == projected).then_some(()).ok_or_else(|| {
                ReceiptStoreError::Conflict(
                    "admission receipt projection id conflicts".to_owned(),
                )
            });
        }
        *stored = Some(receipt.clone());
        self.successful_appends.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn load_chio_receipt(&self, receipt_id: &str) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok(self
            .receipt
            .lock()
            .map_err(|_| {
                ReceiptStoreError::Conflict("admission receipt projection lock poisoned".to_owned())
            })?
            .as_ref()
            .filter(|receipt| receipt.id == receipt_id)
            .cloned())
    }

    fn append_child_receipt(
        &self,
        _receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "test child receipt persistence".to_owned(),
        ))
    }
}

fn assert_same_receipt(left: &ChioReceipt, right: &ChioReceipt) {
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(left).expect("canonical left receipt"),
        chio_core::canonical::canonical_json_bytes(right).expect("canonical right receipt")
    );
}

fn admission_test_fence() -> StoreMutationFence {
    StoreMutationFence {
        store_uuid: "test-admission-authority".to_string(),
        lease_id: "test-admission-lease".to_string(),
        owner_epoch: 1,
    }
}

struct DurableAdmissionCheckingServer {
    id: String,
    tools: Vec<String>,
    invocations: std::sync::Arc<AtomicU64>,
    store: std::sync::Arc<TestAdmissionOperationStore>,
}

#[async_trait::async_trait]
impl ToolServerConnection for DurableAdmissionCheckingServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        assert_eq!(
            self.store.operation().state(),
            AdmissionOperationState::DispatchCommitted,
            "dispatch must be durably committed before tool invocation"
        );
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

struct DurableIncompleteStreamServer {
    invocations: std::sync::Arc<AtomicU64>,
    store: std::sync::Arc<TestAdmissionOperationStore>,
}

#[async_trait::async_trait]
impl ToolServerConnection for DurableIncompleteStreamServer {
    fn server_id(&self) -> &str {
        "durable-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".to_owned()]
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        assert_eq!(
            self.store.operation().state(),
            AdmissionOperationState::DispatchCommitted,
            "dispatch must be durably committed before tool invocation"
        );
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(Some(ToolServerStreamResult::Incomplete {
            stream: ToolCallStream {
                chunks: vec![ToolCallChunk {
                    data: serde_json::json!({"partial": "ledger-7"}),
                }],
            },
            reason: "transport ended after the side effect".to_owned(),
        }))
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "streaming durable server unexpectedly used value invocation".to_owned(),
        ))
    }
}

fn durable_admission_fixture(
    request_id: &str,
) -> (
    ChioKernel,
    ToolCallRequest,
    std::sync::Arc<TestAdmissionOperationStore>,
    std::sync::Arc<AtomicU64>,
) {
    durable_admission_fixture_with_grants(
        request_id,
        vec![make_grant("durable-server", "mutate")],
    )
}

fn durable_admission_fixture_with_grants(
    request_id: &str,
    grants: Vec<ToolGrant>,
) -> (
    ChioKernel,
    ToolCallRequest,
    std::sync::Arc<TestAdmissionOperationStore>,
    std::sync::Arc<AtomicU64>,
) {
    let mut config = make_config();
    config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut kernel = make_kernel(config);
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence)
        .expect("qualified admission store");
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_string(),
        tools: vec!["mutate".to_string()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(grants),
        300,
    );
    let request = make_request_with_arguments(
        request_id,
        &capability,
        "mutate",
        "durable-server",
        serde_json::json!({"record": "ledger-7", "value": "settled"}),
    );
    (kernel, request, store, invocations)
}

struct VersionlessPostInvocationHook;

impl crate::post_invocation::PostInvocationHook for VersionlessPostInvocationHook {
    fn name(&self) -> &str {
        "versionless-post-hook"
    }

    fn inspect(
        &self,
        _context: &crate::post_invocation::PostInvocationContext<'_>,
        _response: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        crate::post_invocation::PostInvocationVerdict::Allow
    }
}

struct StableRedactingPostInvocationHook {
    replacement: &'static str,
}

impl crate::post_invocation::PostInvocationHook for StableRedactingPostInvocationHook {
    fn name(&self) -> &str {
        "stable-redacting-post-hook"
    }

    fn inspect(
        &self,
        _context: &crate::post_invocation::PostInvocationContext<'_>,
        _response: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        crate::post_invocation::PostInvocationVerdict::Redact(serde_json::json!({
            "kind": "value",
            "value": {"replacement": self.replacement}
        }))
    }

    fn durable_identity(
        &self,
    ) -> Result<Option<crate::post_invocation::PostInvocationHookIdentity>, String> {
        crate::post_invocation::PostInvocationHookIdentity::from_canonical_config(
            "stable-redacting-post-hook",
            "1",
            "chio-kernel.tests.stable-redacting-post-hook.v1",
            &self.replacement,
        )
        .map(Some)
    }
}

struct StableStreamRedactingPostInvocationHook;

impl crate::post_invocation::PostInvocationHook for StableStreamRedactingPostInvocationHook {
    fn name(&self) -> &str {
        "stable-stream-redacting-post-hook"
    }

    fn inspect(
        &self,
        _context: &crate::post_invocation::PostInvocationContext<'_>,
        _response: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        crate::post_invocation::PostInvocationVerdict::Redact(serde_json::json!({
            "kind": "stream",
            "stream": {
                "complete": true,
                "chunks": [{"part": 1}, {"part": 2}]
            }
        }))
    }

    fn durable_identity(
        &self,
    ) -> Result<Option<crate::post_invocation::PostInvocationHookIdentity>, String> {
        crate::post_invocation::PostInvocationHookIdentity::from_canonical_config(
            "stable-stream-redacting-post-hook",
            "1",
            "chio-kernel.tests.stable-stream-redacting-post-hook.v1",
            &(),
        )
        .map(Some)
    }
}

#[test]
fn top_level_durable_admission_commits_before_dispatch_and_blocks_replay() {
    let (kernel, request, store, invocations) = durable_admission_fixture("durable-top-level");

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("first durable dispatch");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(store.operation().state(), AdmissionOperationState::Completed);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("exact replay delivery");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.output, response.output);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let mut conflict = request.clone();
    conflict.arguments = serde_json::json!({"record": "ledger-7", "value": "reopened"});
    let conflict = kernel
        .evaluate_tool_call_blocking(&conflict)
        .expect("conflicting replay denial");
    assert_eq!(conflict.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_completion_projects_the_canonical_receipt_idempotently() {
    let (mut kernel, request, _store, invocations) =
        durable_admission_fixture("durable-receipt-projection");
    let projection = AdmissionReceiptProjectionStore::default();
    kernel
        .set_receipt_store(Box::new(projection.clone()))
        .expect("receipt projection store");

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("durable receipt projection");
    assert_same_receipt(
        projection.receipt().as_ref().expect("projected receipt"),
        &response.receipt,
    );
    assert_eq!(projection.successful_appends(), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("idempotent durable receipt projection replay");
    assert_same_receipt(&replay.receipt, &response.receipt);
    assert_eq!(projection.successful_appends(), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn completed_replay_heals_a_failed_receipt_projection_without_redispatch() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-receipt-projection-recovery");
    let projection = AdmissionReceiptProjectionStore::default();
    projection.fail_next_append();
    kernel
        .set_receipt_store(Box::new(projection.clone()))
        .expect("receipt projection store");

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("receipt projection failure must fail closed");
    assert!(error
        .to_string()
        .contains("injected admission receipt projection failure"));
    assert_eq!(store.operation().state(), AdmissionOperationState::Completed);
    assert!(projection.receipt().is_none());
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("completed replay must heal receipt projection");
    assert_same_receipt(
        projection.receipt().as_ref().expect("healed receipt"),
        &replay.receipt,
    );
    assert_eq!(projection.successful_appends(), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn admission_receipt_reconciliation_heals_a_crash_gap_before_serving() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-receipt-startup-recovery");
    let completed = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("canonical admission completion");

    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut recovered_kernel = make_kernel(recovered_config);
    let projection = AdmissionReceiptProjectionStore::default();
    recovered_kernel
        .set_receipt_store(Box::new(projection.clone()))
        .expect("receipt projection store");
    recovered_kernel
        .set_durable_admission_store(
            store.clone(),
            store.clone(),
            admission_test_fence(),
        )
        .expect("qualified admission store");

    assert_eq!(
        recovered_kernel
            .reconcile_durable_admission_receipt_projections()
            .expect("startup receipt reconciliation"),
        1
    );
    assert_same_receipt(
        projection
            .receipt()
            .as_ref()
            .expect("reconciled receipt"),
        &completed.receipt,
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_tool_return_persistence_retains_dispatch_and_blocks_redispatch() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-return-write-failure");
    store.fail_next_outcome_write();

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("tool return journal failure must fail closed");
    assert!(matches!(
        error,
        KernelError::DurableAdmission(ref reason)
            if reason.contains("injected tool outcome write failure")
    ));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("retained dispatch must produce a denial");
    assert_eq!(replay.verdict, Verdict::Deny);
    assert!(replay
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("DispatchCommitted")));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_terminal_projection_retains_finalizing_operation_and_blocks_redispatch() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-terminal-projection-failure");
    store.fail_next_terminal_projection();

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("terminal projection failure must fail closed");
    assert!(matches!(
        error,
        KernelError::DurableAdmission(ref reason)
            if reason.contains("injected terminal projection failure")
    ));
    assert_eq!(store.operation().state(), AdmissionOperationState::Finalizing);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("retained finalization must recover delivery");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(store.operation().state(), AdmissionOperationState::Completed);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

fn assert_finalization_crash_recovers(
    request_id: &str,
    inject: fn(&TestAdmissionOperationStore),
    expected_error: &str,
    expected_versions: (Option<u64>, Option<u64>),
) {
    let (kernel, request, store, invocations) = durable_admission_fixture(request_id);
    inject(&store);

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("injected finalization crash must fail closed");
    assert!(matches!(
        error,
        KernelError::DurableAdmission(ref reason) if reason.contains(expected_error)
    ));
    assert_eq!(store.operation().state(), AdmissionOperationState::Finalizing);
    assert_eq!(store.outcome_versions(), expected_versions);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let recovered = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("finalization replay must recover delivery");
    assert_eq!(recovered.verdict, Verdict::Allow);
    assert_eq!(store.operation().state(), AdmissionOperationState::Completed);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("completed replay must redeliver the recovered result");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.receipt.id, recovered.receipt.id);
    assert_eq!(replay.output, recovered.output);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn finalization_recovers_before_evaluation_creation() {
    assert_finalization_crash_recovers(
        "durable-evaluation-begin-failure",
        TestAdmissionOperationStore::fail_next_evaluation_begin,
        "injected evaluation begin failure",
        (None, Some(1)),
    );
}

#[test]
fn finalization_recovers_after_frozen_evaluation_creation() {
    assert_finalization_crash_recovers(
        "durable-evaluation-stage-failure",
        TestAdmissionOperationStore::fail_next_evaluation_stage,
        "injected evaluation stage failure",
        (Some(1), Some(1)),
    );
}

#[test]
fn finalization_recovers_after_pure_result_staging() {
    assert_finalization_crash_recovers(
        "durable-evaluation-finalization-failure",
        TestAdmissionOperationStore::fail_next_evaluation_finalization,
        "injected evaluation finalization failure",
        (Some(2), Some(1)),
    );
}

#[test]
fn finalization_recovers_after_store_owner_rotation() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-owner-rotation-recovery");
    store.fail_next_evaluation_begin();

    kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("injected finalization crash must fail closed");
    assert_eq!(store.operation().state(), AdmissionOperationState::Finalizing);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let rotated_fence = StoreMutationFence {
        store_uuid: admission_test_fence().store_uuid,
        lease_id: "test-admission-lease-2".to_owned(),
        owner_epoch: 2,
    };
    store.rotate_fence(rotated_fence.clone());
    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut recovered_kernel = make_kernel(recovered_config);
    recovered_kernel
        .set_durable_admission_store(store.clone(), store.clone(), rotated_fence)
        .expect("rotated qualified admission store");
    recovered_kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_owned(),
        tools: vec!["mutate".to_owned()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));

    let recovered = recovered_kernel
        .evaluate_tool_call_blocking(&request)
        .expect("new serving owner must finish retained finalization");
    assert_eq!(recovered.verdict, Verdict::Allow);
    assert_eq!(store.operation().state(), AdmissionOperationState::Completed);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_post_invocation_identity_binds_transformed_output_and_replay() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-versioned-post-hook");
    kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "filtered",
    }));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("versioned post hook dispatch");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        response.output,
        Some(ToolCallOutput::Value(
            serde_json::json!({"replacement": "filtered"})
        ))
    );
    assert_eq!(store.operation().state(), AdmissionOperationState::Completed);
    assert_eq!(store.outcome_versions(), (Some(4), Some(2)));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("versioned post hook replay");
    assert_eq!(replay.output, response.output);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_redaction_cannot_upgrade_incomplete_transport_and_replay_is_exactly_once() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-incomplete-redacted-stream");
    kernel.register_tool_server(Box::new(DurableIncompleteStreamServer {
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "filtered-partial",
    }));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("durable incomplete stream finalization");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.output,
        Some(ToolCallOutput::Value(
            serde_json::json!({"replacement": "filtered-partial"})
        ))
    );
    assert_eq!(
        response.reason.as_deref(),
        Some("transport ended after the side effect")
    );
    assert_eq!(
        response.receipt.decision,
        Some(chio_core::receipt::decision::Decision::Incomplete {
            reason: "transport ended after the side effect".to_owned(),
        })
    );
    assert_eq!(store.operation().state(), AdmissionOperationState::Completed);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("durable incomplete stream replay");
    assert_eq!(replay.output, response.output);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.terminal_state, response.terminal_state);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_redaction_recovery_uses_the_recorded_stream_limits() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-redaction-stream-limit-snapshot");
    kernel.config.memory_budget.max_stream_chunks = 1;
    kernel.add_post_invocation_hook(Box::new(StableStreamRedactingPostInvocationHook));
    store.fail_next_evaluation_begin();

    kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("injected finalization crash");
    assert_eq!(store.operation().state(), AdmissionOperationState::Finalizing);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    recovered_config.memory_budget.max_stream_chunks = 2;
    let mut recovered_kernel = make_kernel(recovered_config);
    recovered_kernel
        .set_durable_admission_store(
            store.clone(),
            store.clone(),
            admission_test_fence(),
        )
        .expect("qualified admission store");
    recovered_kernel.add_post_invocation_hook(Box::new(StableStreamRedactingPostInvocationHook));
    recovered_kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_owned(),
        tools: vec!["mutate".to_owned()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));

    let recovered = recovered_kernel
        .evaluate_tool_call_blocking(&request)
        .expect("recover redacted stream with recorded limits");
    assert_eq!(recovered.verdict, Verdict::Deny);
    assert!(recovered
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("max chunk count of 1")));
    let Some(ToolCallOutput::Stream(stream)) = recovered.output else {
        panic!("expected retained redacted stream");
    };
    assert_eq!(stream.chunk_count(), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_post_invocation_identity_change_cannot_resume_finalization() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-post-hook-identity-change");
    kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "first",
    }));
    store.fail_next_evaluation_begin();
    kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("injected finalization crash");
    assert_eq!(store.operation().state(), AdmissionOperationState::Finalizing);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut recovered_kernel = make_kernel(recovered_config);
    recovered_kernel
        .set_durable_admission_store(
            store.clone(),
            store.clone(),
            admission_test_fence(),
        )
        .expect("qualified admission store");
    recovered_kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "second",
    }));
    recovered_kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_owned(),
        tools: vec!["mutate".to_owned()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));

    let response = recovered_kernel
        .evaluate_tool_call_blocking(&request)
        .expect("identity substitution denial");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("request id conflicts")));
    assert_eq!(store.operation().state(), AdmissionOperationState::Finalizing);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn unsupported_durable_participants_fail_before_dispatch() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-versionless-post-hook");
    kernel.add_post_invocation_hook(Box::new(VersionlessPostInvocationHook));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("versionless post hook denial");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("has no durable implementation identity")));
    assert!(!store.has_operation());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);

    let mut monetary_grant = make_grant("durable-server", "mutate");
    monetary_grant.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".to_owned(),
    });
    monetary_grant.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".to_owned(),
    });
    let (kernel, request, store, invocations) = durable_admission_fixture_with_grants(
        "durable-unqualified-payment",
        vec![monetary_grant],
    );

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("unqualified payment denial");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("qualified payment journal")));
    assert!(!store.has_operation());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn durable_admission_binds_the_first_budget_eligible_matching_grant() {
    let mut config = make_config();
    config.policy_hash = sha256_hex(b"durable-admission-grant-test-policy");
    let mut kernel = make_kernel(config);
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence)
        .expect("qualified admission store");
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_string(),
        tools: vec!["mutate".to_string()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    let mut exhausted = make_grant("durable-server", "mutate");
    exhausted.max_invocations = Some(1);
    let fallback = make_grant("durable-server", "mutate");
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![exhausted, fallback]),
        300,
    );
    assert!(kernel
        .with_budget_store(|budget| Ok(budget.try_increment(&capability.id, 0, Some(1))?))
        .expect("exhaust first matching grant"));
    let request = make_request("durable-grant-fallback", &capability, "mutate", "durable-server");

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("fallback grant dispatch");

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert!(store
        .operation()
        .budget_hold_id()
        .expect("bound budget hold")
        .as_str()
        .ends_with(":1"));
}

#[test]
fn nested_durable_admission_commits_before_dispatch_and_blocks_replay() {
    let (kernel, request, store, invocations) = durable_admission_fixture("durable-nested");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("nested test runtime");

    let evaluate = |request: &ToolCallRequest| {
        let session_id = kernel
            .open_session(request.agent_id.clone(), vec![request.capability.clone()])
            .expect("nested test session");
        kernel.activate_session(&session_id).expect("active session");
        let context = make_operation_context(&session_id, &request.request_id, &request.agent_id);
        kernel
            .begin_session_request(&context, OperationKind::ToolCall, true)
            .expect("active nested request");
        runtime.block_on(async {
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async(
                    &context,
                    request,
                    &mut client,
                    None,
                )
                .await
        })
    };

    let response = evaluate(&request).expect("first nested durable dispatch");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(store.operation().state(), AdmissionOperationState::Completed);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = evaluate(&request).expect("nested replay delivery");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.output, response.output);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}
