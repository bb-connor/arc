use super::*;

#[path = "durable_admission/configuration.rs"]
mod configuration;
#[path = "durable_admission/cumulative_budget.rs"]
mod cumulative_budget;
#[path = "durable_admission/output_finalization.rs"]
mod output_finalization;
#[path = "durable_admission/pre_dispatch.rs"]
mod pre_dispatch;
#[path = "durable_admission/recovery.rs"]
mod recovery;
use receipt_projection::AdmissionReceiptProjectionStore;

#[path = "durable_admission/authority_profile.rs"]
mod authority_profile;
#[path = "durable_admission/caller_budget_snapshot.rs"]
mod caller_budget_snapshot;
#[path = "durable_admission/delivery_revalidation.rs"]
mod delivery_revalidation;
#[path = "durable_admission/dispatch_commit_failure.rs"]
mod dispatch_commit_failure;
#[path = "durable_admission/dpop_acquisition.rs"]
mod dpop_acquisition;
#[path = "durable_admission/federation_context.rs"]
mod federation_context;
#[path = "durable_admission/governed_acquisition.rs"]
mod governed_acquisition;
#[path = "durable_admission/monetary.rs"]
mod monetary;
#[path = "durable_admission/native_acquisition.rs"]
mod native_acquisition;
#[path = "durable_admission/native_dispatch_ledger.rs"]
mod native_dispatch_ledger;
#[path = "durable_admission/native_egress.rs"]
mod native_egress;
#[path = "durable_admission/operation_store.rs"]
mod operation_store;
#[path = "durable_admission/receipt_projection.rs"]
mod receipt_projection;
#[path = "durable_admission/recovery_lease.rs"]
mod recovery_lease;
#[path = "durable_admission/return_context.rs"]
mod return_context;
#[path = "durable_admission/review_regressions.rs"]
mod review_regressions;
#[path = "durable_admission/runtime_participant.rs"]
mod runtime_participant;
#[path = "durable_admission/security_binding.rs"]
mod security_binding;

#[derive(Default)]
pub(super) struct TestAdmissionState {
    pub(super) operation: Option<AdmissionOperationV1>,
    pub(super) retained_request: Option<crate::admission_operation::RetainedToolAdmissionRequestV1>,
    claim: Option<UntrustedAdmissionRecoveryClaim>,
    raw_outcome: Option<RawInvocationOutcomeV1>,
    tool_outcome: Option<ToolOutcomeRecordV1>,
    post_return_evaluation: Option<PostReturnEvaluationRecordV1>,
    resolved_output: Option<CanonicalResolvedOutputBlobV1>,
    receipt: Option<chio_core::receipt::body::ChioReceipt>,
    budget_authorization: Option<crate::budget_store::BudgetAuthorizeHoldRequest>,
    payment_journal: Option<crate::payment::PaymentJournalRecord>,
    payment_release_evidence: Option<crate::tool_outcome::PersistedMonetaryReleaseEvidenceV1>,
}

pub(super) struct TestAdmissionOperationStore {
    caller_share_times: std::sync::Mutex<Vec<u64>>,
    recovery_lease_faults: recovery_lease::TestRecoveryLeaseFaults,
    native_recovery: native_acquisition::TestNative,
    native_egress: native_egress::TestEgress,
    native_dispatch_ledger: native_dispatch_ledger::TestLedger,
    dpop_recovery: dpop_acquisition::TestDpop,
    approval_recovery: governed_acquisition::TestApproval,
    runtime_recovery: runtime_participant::TestRuntimeRecovery,
    pub(super) fence: std::sync::Mutex<StoreMutationFence>,
    fail_next_outcome_write: std::sync::atomic::AtomicBool,
    fail_next_evaluation_begin: std::sync::atomic::AtomicBool,
    fail_next_evaluation_stage: std::sync::atomic::AtomicBool,
    fail_next_evaluation_finalization: std::sync::atomic::AtomicBool,
    fail_next_terminal_projection: std::sync::atomic::AtomicBool,
    fail_next_payment_settlement_intent: std::sync::atomic::AtomicBool,
    fail_next_budget_authorization: std::sync::atomic::AtomicBool,
    panic_capture_boundary: std::sync::atomic::AtomicU8,
    substitute_capture_participant: std::sync::atomic::AtomicBool,
    budget: std::sync::Arc<crate::budget_store::InMemoryBudgetStore>,
    pub(super) state: std::sync::Mutex<TestAdmissionState>,
}

impl TestAdmissionOperationStore {
    pub(super) fn new(fence: StoreMutationFence) -> Self {
        Self {
            caller_share_times: std::sync::Mutex::new(Vec::new()),
            recovery_lease_faults: recovery_lease::TestRecoveryLeaseFaults::default(),
            native_recovery: native_acquisition::TestNative::default(),
            native_egress: native_egress::TestEgress::default(),
            native_dispatch_ledger: native_dispatch_ledger::TestLedger::default(),
            dpop_recovery: dpop_acquisition::TestDpop::default(),
            approval_recovery: governed_acquisition::TestApproval::default(),
            runtime_recovery: runtime_participant::TestRuntimeRecovery::default(),
            fence: std::sync::Mutex::new(fence),
            fail_next_outcome_write: std::sync::atomic::AtomicBool::new(false),
            fail_next_evaluation_begin: std::sync::atomic::AtomicBool::new(false),
            fail_next_evaluation_stage: std::sync::atomic::AtomicBool::new(false),
            fail_next_evaluation_finalization: std::sync::atomic::AtomicBool::new(false),
            fail_next_terminal_projection: std::sync::atomic::AtomicBool::new(false),
            fail_next_payment_settlement_intent: std::sync::atomic::AtomicBool::new(false),
            fail_next_budget_authorization: std::sync::atomic::AtomicBool::new(false),
            panic_capture_boundary: std::sync::atomic::AtomicU8::new(0),
            substitute_capture_participant: std::sync::atomic::AtomicBool::new(false),
            budget: std::sync::Arc::new(crate::budget_store::InMemoryBudgetStore::new()),
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
        self.fail_next_evaluation_begin
            .store(true, Ordering::SeqCst);
    }

    fn fail_next_evaluation_stage(&self) {
        self.fail_next_evaluation_stage
            .store(true, Ordering::SeqCst);
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
            state
                .tool_outcome
                .as_ref()
                .map(ToolOutcomeRecordV1::version),
        )
    }

    fn rotate_fence(&self, fence: StoreMutationFence) {
        *self.fence.lock().expect("test admission fence lock") = fence;
    }

    pub(super) fn operation(&self) -> AdmissionOperationV1 {
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

    fn payment_journal(&self) -> Option<crate::payment::PaymentJournalRecord> {
        self.state
            .lock()
            .expect("test admission state lock")
            .payment_journal
            .clone()
    }

    fn payment_release_evidence(
        &self,
    ) -> Option<crate::tool_outcome::PersistedMonetaryReleaseEvidenceV1> {
        self.state
            .lock()
            .expect("test admission state lock")
            .payment_release_evidence
            .clone()
    }

    fn fail_next_payment_settlement_intent(&self) {
        self.fail_next_payment_settlement_intent
            .store(true, Ordering::SeqCst);
    }

    fn fail_next_budget_authorization(&self) {
        self.fail_next_budget_authorization
            .store(true, Ordering::SeqCst);
    }

    pub(super) fn budget_store(&self) -> std::sync::Arc<crate::budget_store::InMemoryBudgetStore> {
        self.budget.clone()
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
            payment_terminal: true,
            incident_terminal: true,
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
        let operation = state
            .operation
            .clone()
            .ok_or_else(|| ReceiptStoreError::NotFound("test admission operation".to_owned()))?;
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
        let replay = updated
            .terminal_replay()
            .cloned()
            .ok_or_else(|| ReceiptStoreError::Conflict("terminal replay is absent".to_owned()))?;
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

struct QualifiedDurablePaymentAdapter {
    authorization_references: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    settlement_actions: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    settlement_references: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl PaymentAdapter for QualifiedDurablePaymentAdapter {
    fn rail_id(&self) -> &'static str {
        "test-reversible"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.authorization_references
            .lock()
            .map_err(|_| PaymentError::RailError("test payment lock poisoned".to_owned()))?
            .push(request.reference.clone());
        Ok(PaymentAuthorization {
            authorization_id: "authorization-durable".to_owned(),
            state: PaymentAuthorizationState::Held,
            metadata: serde_json::json!({}),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.settlement_actions
            .lock()
            .map_err(|_| PaymentError::RailError("test payment lock poisoned".to_owned()))?
            .push("capture");
        self.settlement_references
            .lock()
            .map_err(|_| PaymentError::RailError("test payment lock poisoned".to_owned()))?
            .push(reference.to_owned());
        Ok(PaymentResult {
            transaction_id: authorization_id.to_owned(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({}),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.settlement_actions
            .lock()
            .map_err(|_| PaymentError::RailError("test payment lock poisoned".to_owned()))?
            .push("release");
        self.settlement_references
            .lock()
            .map_err(|_| PaymentError::RailError("test payment lock poisoned".to_owned()))?
            .push(reference.to_owned());
        Ok(PaymentResult {
            transaction_id: authorization_id.to_owned(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_owned(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({}),
        })
    }
}

impl QualifiedAdmissionProjectionStore for TestAdmissionOperationStore {
    fn reserve_threshold_approval_and_commit_admission(
        &self,
        command: &AdmissionOperationCommand,
        _reservation: &crate::ThresholdApprovalReplayReservationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        self.compare_and_swap(command, trusted_now_unix_ms)
    }

    fn load_payment_journal(
        &self,
        operation_id: &str,
        active_fence: &StoreMutationFence,
    ) -> Result<
        Option<crate::payment::PaymentJournalRecord>,
        crate::receipt_store::AdmissionPaymentJournalError,
    > {
        self.require_fence(active_fence)
            .map_err(|_| crate::receipt_store::AdmissionPaymentJournalError::Fenced)?;
        Ok(self
            .state
            .lock()
            .map_err(|_| {
                crate::receipt_store::AdmissionPaymentJournalError::Invariant(
                    "test admission state lock poisoned".to_owned(),
                )
            })?
            .payment_journal
            .as_ref()
            .filter(|journal| journal.operation_id == operation_id)
            .cloned())
    }

    fn advance_payment_journal(
        &self,
        advance: crate::receipt_store::AdmissionPaymentJournalAdvance<'_>,
    ) -> Result<
        crate::payment::PaymentJournalRecord,
        crate::receipt_store::AdmissionPaymentJournalError,
    > {
        let crate::receipt_store::AdmissionPaymentJournalAdvance {
            operation,
            recovery_lease,
            expected,
            transition,
            release_evidence,
            active_fence,
            trusted_now_unix_ms: _,
        } = advance;
        self.require_fence(active_fence)
            .map_err(|_| crate::receipt_store::AdmissionPaymentJournalError::Fenced)?;
        let desired = expected.apply_transition(transition).map_err(|error| {
            crate::receipt_store::AdmissionPaymentJournalError::Invariant(error.to_string())
        })?;
        let mut state = self.state.lock().map_err(|_| {
            crate::receipt_store::AdmissionPaymentJournalError::Invariant(
                "test admission state lock poisoned".to_owned(),
            )
        })?;
        if state.operation.as_ref() != Some(operation)
            || state.claim.as_ref() != Some(recovery_lease.untrusted_claim())
        {
            return Err(crate::receipt_store::AdmissionPaymentJournalError::Fenced);
        }
        match (transition, release_evidence) {
            (
                crate::payment::PaymentJournalTransition::BeginRelease { authority },
                Some(evidence),
            ) => {
                let persisted = evidence.to_persisted();
                if persisted.operation_id.as_str() != authority.operation_id
                    || persisted.operation_version != authority.operation_version
                    || persisted.evidence_id.as_str() != authority.evidence_id
                    || persisted.bundle_digest.as_str() != authority.evidence_digest
                {
                    return Err(
                        crate::receipt_store::AdmissionPaymentJournalError::Invariant(
                            "test release evidence binding mismatch".to_owned(),
                        ),
                    );
                }
                if state
                    .payment_release_evidence
                    .as_ref()
                    .is_some_and(|stored| stored != &persisted)
                {
                    return Err(
                        crate::receipt_store::AdmissionPaymentJournalError::Conflict(
                            "test release evidence replay mismatch".to_owned(),
                        ),
                    );
                }
                state.payment_release_evidence = Some(persisted);
            }
            (crate::payment::PaymentJournalTransition::BeginRelease { .. }, None)
            | (_, Some(_)) => {
                return Err(
                    crate::receipt_store::AdmissionPaymentJournalError::Invariant(
                        "test release transition evidence mismatch".to_owned(),
                    ),
                );
            }
            (_, None) => {}
        }
        if state.payment_journal.as_ref() == Some(&desired) {
            return Ok(desired);
        }
        if state.payment_journal.as_ref() != Some(expected) {
            return Err(
                crate::receipt_store::AdmissionPaymentJournalError::Conflict(
                    "test payment journal compare-and-set conflicted".to_owned(),
                ),
            );
        }
        state.payment_journal = Some(desired.clone());
        Ok(desired)
    }

    fn begin_payment_settlement(
        &self,
        begin: crate::receipt_store::AdmissionPaymentSettlementBegin<'_>,
    ) -> Result<
        crate::receipt_store::AdmissionPaymentSettlement,
        crate::receipt_store::AdmissionPaymentJournalError,
    > {
        if self
            .fail_next_payment_settlement_intent
            .swap(false, Ordering::SeqCst)
        {
            return Err(
                crate::receipt_store::AdmissionPaymentJournalError::OutcomeUnknown(
                    "injected payment settlement intent failure".to_owned(),
                ),
            );
        }
        let journal = match begin.transition {
            Some(transition) => self.advance_payment_journal(
                crate::receipt_store::AdmissionPaymentJournalAdvance {
                    operation: begin.operation,
                    recovery_lease: begin.recovery_lease,
                    expected: begin.expected,
                    transition,
                    release_evidence: begin.release_evidence,
                    active_fence: begin.active_fence,
                    trusted_now_unix_ms: begin.trusted_now_unix_ms,
                },
            )?,
            None => {
                if begin.release_evidence.is_some() {
                    return Err(
                        crate::receipt_store::AdmissionPaymentJournalError::Invariant(
                            "test payment settlement evidence requires a transition".to_owned(),
                        ),
                    );
                }
                self.load_payment_journal(
                    begin.operation.binding().operation_id().as_str(),
                    begin.active_fence,
                )?
                .filter(|journal| journal == begin.expected)
                .ok_or_else(|| {
                    crate::receipt_store::AdmissionPaymentJournalError::Conflict(
                        "test payment settlement journal changed".to_owned(),
                    )
                })?
            }
        };
        let budget = crate::budget_store::BudgetStore::reconcile_budget_hold(
            self.budget.as_ref(),
            begin.budget_reconcile,
        )
        .map_err(|error| {
            crate::receipt_store::AdmissionPaymentJournalError::Invariant(error.to_string())
        })?;
        Ok(crate::receipt_store::AdmissionPaymentSettlement {
            journal,
            budget,
            budget_already_reconciled: false,
        })
    }

    fn authorize_budget_and_commit_admission(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        request: crate::budget_store::BudgetAuthorizeHoldRequest,
        payment_journal: Option<crate::payment::PaymentJournalRecord>,
        credit_exposure: Option<chio_credit::obligation::CreditExposureReservationRequest>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        crate::receipt_store::AdmissionBudgetAuthorization,
        crate::receipt_store::AdmissionBudgetAuthorizationError,
    > {
        self.require_fence(active_fence)
            .map_err(|_| crate::receipt_store::AdmissionBudgetAuthorizationError::Fenced)?;
        request.validate().map_err(|error| {
            crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(error.to_string())
        })?;
        if operation.binding().participant_requirements().payment != payment_journal.is_some()
            || operation
                .binding()
                .participant_requirements()
                .credit_exposure
                != credit_exposure.is_some()
        {
            return Err(
                crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                    "test monetary participant mismatch".to_owned(),
                ),
            );
        }
        if let Some(credit_exposure) = credit_exposure.as_ref() {
            credit_exposure.validate().map_err(|error| {
                crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                    error.to_string(),
                )
            })?;
            if credit_exposure.operation_id != operation.binding().operation_id().as_str()
                || credit_exposure.request_id != operation.replay_key().request_id.as_str()
            {
                return Err(
                    crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                        "test credit exposure participant mismatch".to_owned(),
                    ),
                );
            }
        }
        if let Some(journal) = payment_journal.as_ref() {
            journal.validate().map_err(|error| {
                crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                    error.to_string(),
                )
            })?;
        }
        if self
            .fail_next_budget_authorization
            .swap(false, Ordering::SeqCst)
        {
            return Err(
                crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                    "authorization backend unavailable".to_owned(),
                ),
            );
        }
        let request_for_replay = request.clone();
        let decision =
            crate::budget_store::BudgetStore::authorize_budget_hold(self.budget.as_ref(), request)
                .map_err(|error| {
                    crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                        error.to_string(),
                    )
                })?;
        let mut state = self.state.lock().map_err(|_| {
            crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                "test admission state lock poisoned".to_owned(),
            )
        })?;
        let stored = state.operation.clone().ok_or_else(|| {
            crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                "test admission operation is absent".to_owned(),
            )
        })?;
        if &stored != operation {
            return Err(crate::receipt_store::AdmissionBudgetAuthorizationError::Fenced);
        }
        if stored.state() == AdmissionOperationState::BudgetAuthorized {
            let journal_matches = match (&state.payment_journal, &payment_journal) {
                (None, None) => true,
                (Some(stored), Some(proposed)) => stored.matches_hold_replay(proposed),
                _ => false,
            };
            if state.budget_authorization.as_ref() != Some(&request_for_replay) || !journal_matches
            {
                return Err(
                    crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                        "test combined authorization replay mismatch".to_owned(),
                    ),
                );
            }
            return Ok(crate::receipt_store::AdmissionBudgetAuthorization {
                decision,
                operation: stored,
            });
        }
        if !matches!(
            decision,
            crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(_)
        ) {
            return Ok(crate::receipt_store::AdmissionBudgetAuthorization {
                decision,
                operation: stored,
            });
        }
        if state.claim.as_ref() != Some(recovery_lease.untrusted_claim()) {
            return Err(crate::receipt_store::AdmissionBudgetAuthorizationError::Fenced);
        }
        let hold_id = request_for_replay.hold_id.as_deref().ok_or_else(|| {
            crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                "test combined authorization omitted hold_id".to_owned(),
            )
        })?;
        let mut attachments = vec![AdmissionAttachment::BudgetHoldId(
            AdmissionIdentifier::try_new("budget_hold_id", hold_id.to_owned())?,
        )];
        if stored.binding().participant_requirements().payment {
            attachments.push(AdmissionAttachment::PaymentParticipantId(
                AdmissionIdentifier::try_new(
                    "payment_participant_id",
                    stored.binding().operation_id().as_str().to_owned(),
                )?,
            ));
        }
        let command = AdmissionOperationCommand::new(
            stored.binding().operation_id().clone(),
            stored.version(),
            recovery_lease.clone(),
            attachments,
            Some(AdmissionOperationState::BudgetAuthorized),
            None,
            None,
        )?;
        let updated = stored
            .apply_command(&command, trusted_now_unix_ms)?
            .into_operation();
        state.operation = Some(updated.clone());
        state.claim = None;
        state.budget_authorization = Some(request_for_replay);
        state.payment_journal = payment_journal;
        Ok(crate::receipt_store::AdmissionBudgetAuthorization {
            decision,
            operation: updated,
        })
    }

    fn capture_invocation_and_commit_dispatch(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        request: crate::budget_store::BudgetCaptureInvocationRequest,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<crate::receipt_store::AdmissionBudgetCapture, AdmissionCaptureError> {
        let panic_boundary = self.panic_capture_boundary.swap(0, Ordering::SeqCst);
        assert_ne!(panic_boundary, 1, "injected panic before capture mutation");
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
        let decision = crate::budget_store::BudgetStore::capture_invocation_reservations(
            self.budget.as_ref(),
            request,
        )
        .map_err(|error| AdmissionCaptureError::Invariant(error.to_string()))?;
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
        let operation = self
            .compare_and_swap(&command, trusted_now_unix_ms)
            .map(AdmissionCommandResult::into_operation)
            .map_err(|error| AdmissionCaptureError::Invariant(error.to_string()))?;
        assert_ne!(
            panic_boundary, 2,
            "injected panic after dispatch commitment"
        );
        let operation = if self
            .substitute_capture_participant
            .swap(false, Ordering::SeqCst)
        {
            return_context::substitute_captured_participant(operation)?
        } else {
            operation
        };
        Ok(crate::receipt_store::AdmissionBudgetCapture {
            decision,
            operation,
        })
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
            .validate_for_store_insert(operation, blob, active_fence, trusted_now_unix_ms)
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
        let operation = state
            .operation
            .as_ref()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        let outcome = state
            .tool_outcome
            .as_ref()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
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
        let operation = state
            .operation
            .as_ref()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        let current_outcome = state
            .tool_outcome
            .as_ref()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
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

fn assert_same_receipt(left: &ChioReceipt, right: &ChioReceipt) {
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(left).expect("canonical left receipt"),
        chio_core::canonical::canonical_json_bytes(right).expect("canonical right receipt")
    );
}

pub(super) fn admission_test_fence() -> StoreMutationFence {
    StoreMutationFence {
        store_uuid: "test-admission-authority".to_string(),
        lease_id: "test-admission-lease".to_string(),
        owner_epoch: 1,
    }
}

struct DurableAdmissionCheckingServer {
    pub(super) id: String,
    pub(super) tools: Vec<String>,
    pub(super) invocations: std::sync::Arc<AtomicU64>,
    pub(super) store: std::sync::Arc<TestAdmissionOperationStore>,
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

pub(super) fn durable_admission_fixture(
    request_id: &str,
) -> (
    ChioKernel,
    ToolCallRequest,
    std::sync::Arc<TestAdmissionOperationStore>,
    std::sync::Arc<AtomicU64>,
) {
    durable_admission_fixture_with_grants(request_id, vec![make_grant("durable-server", "mutate")])
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
    let tools = grants
        .iter()
        .map(|grant| grant.tool_name.clone())
        .collect::<Vec<_>>();
    let mut config = make_config();
    config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut kernel = make_kernel(config);
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence)
        .expect("qualified admission store");
    kernel.set_budget_store_handle(store.budget_store());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_string(),
        tools,
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    let agent = make_keypair();
    let capability = make_capability(&kernel, &agent, make_scope(grants), 300);
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
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(store.outcome_versions(), expected_versions);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let recovered = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("finalization replay must recover delivery");
    assert_eq!(recovered.verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("completed replay must redeliver the recovered result");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.receipt.id, recovered.receipt.id);
    assert_eq!(replay.output, recovered.output);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}
