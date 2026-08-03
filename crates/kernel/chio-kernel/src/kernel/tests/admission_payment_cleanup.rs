use chio_test_support::prelude::*;

use crate::kernel::ordinary_admission::BudgetTerminalDecisionExpectation;

#[derive(Default)]
struct InCratePaymentJournalStore {
    inner: InMemoryBudgetStore,
    rows: std::sync::Mutex<
        std::collections::HashMap<String, crate::payment::PaymentJournalRecord>,
    >,
}

impl InCratePaymentJournalStore {
    fn new() -> Self {
        Self::default()
    }
}

impl crate::budget_store::BudgetStore for InCratePaymentJournalStore {
    fn authority_profile(&self) -> crate::budget_store::BudgetStoreProfile {
        crate::budget_store::BudgetStoreProfile::SingleNodeDurable
    }

    fn budget_guarantee_level(&self) -> crate::budget_store::BudgetGuaranteeLevel {
        crate::budget_store::BudgetGuaranteeLevel::SingleNodeAtomic
    }

    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, crate::budget_store::BudgetStoreError> {
        self.inner
            .try_increment(capability_id, grant_index, max_invocations)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, crate::budget_store::BudgetStoreError> {
        self.inner.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    fn try_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&crate::budget_store::BudgetEventAuthority>,
    ) -> Result<bool, crate::budget_store::BudgetStoreError> {
        crate::budget_store::BudgetStore::try_charge_cost_with_ids_and_authority(
            &self.inner,
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        self.inner
            .reverse_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        self.inner
            .reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        self.inner.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<crate::budget_store::BudgetUsageRecord>, crate::budget_store::BudgetStoreError>
    {
        self.inner.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<
        Option<crate::budget_store::BudgetUsageRecord>,
        crate::budget_store::BudgetStoreError,
    > {
        self.inner.get_usage(capability_id, grant_index)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<
        Vec<crate::budget_store::BudgetMutationRecord>,
        crate::budget_store::BudgetStoreError,
    > {
        self.inner
            .list_mutation_events(limit, capability_id, grant_index)
    }

    fn get_mutation_event_by_id(
        &self,
        event_id: &str,
    ) -> Result<
        Option<crate::budget_store::BudgetMutationRecord>,
        crate::budget_store::BudgetStoreError,
    > {
        Ok(self
            .inner
            .list_mutation_events(usize::MAX, None, None)?
            .into_iter()
            .find(|record| record.event_id == event_id))
    }

    fn record_payment_journal(
        &self,
        entry: &crate::payment::PaymentJournalRecord,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        let mut rows = self.rows.lock().map_err(|_| {
            crate::budget_store::BudgetStoreError::Invariant(
                "in-crate payment journal lock poisoned".to_string(),
            )
        })?;
        if rows.contains_key(&entry.request_id) {
            return Err(crate::budget_store::BudgetStoreError::Invariant(format!(
                "payment journal request `{}` already exists",
                entry.request_id
            )));
        }
        rows.insert(entry.request_id.clone(), entry.clone());
        Ok(())
    }

    fn advance_payment_journal(
        &self,
        request_id: &str,
        expected: crate::payment::PaymentJournalState,
        next: crate::payment::PaymentJournalState,
        authorization_id: Option<&str>,
        transaction_id: Option<&str>,
        settle: Option<crate::payment::PaymentSettleIntent>,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        use crate::payment::{PaymentJournalState as State, PaymentSettleAction as Action};

        if next == State::Settling && settle.is_none() {
            return Err(crate::budget_store::BudgetStoreError::Invariant(
                "advance to Settling requires a settle intent".to_string(),
            ));
        }
        if next != State::Settling && settle.is_some() {
            return Err(crate::budget_store::BudgetStoreError::Invariant(
                "settle intent is only valid on the Settling transition".to_string(),
            ));
        }
        if let Some(intent) = settle {
            match intent.action {
                Action::Capture | Action::Refund if intent.amount_units.is_none() => {
                    return Err(crate::budget_store::BudgetStoreError::Invariant(
                        "capture and refund settle intents require an exact amount".to_string(),
                    ));
                }
                Action::Release if intent.amount_units.is_some() => {
                    return Err(crate::budget_store::BudgetStoreError::Invariant(
                        "release settle intent cannot carry an amount".to_string(),
                    ));
                }
                Action::Refund if transaction_id.is_none() => {
                    return Err(crate::budget_store::BudgetStoreError::Invariant(
                        "refund settle intent requires the captured transaction id".to_string(),
                    ));
                }
                _ => {}
            }
        }

        let mut rows = self.rows.lock().map_err(|_| {
            crate::budget_store::BudgetStoreError::Invariant(
                "in-crate payment journal lock poisoned".to_string(),
            )
        })?;
        let row = rows.get_mut(request_id).ok_or_else(|| {
            crate::budget_store::BudgetStoreError::Invariant(format!(
                "payment journal advance conflict for `{request_id}`"
            ))
        })?;
        if row.state != expected {
            return Err(crate::budget_store::BudgetStoreError::Invariant(format!(
                "payment journal advance conflict for `{request_id}`"
            )));
        }
        row.state = next;
        if let Some(authorization_id) = authorization_id {
            row.authorization_id = Some(authorization_id.to_string());
        }
        if let Some(transaction_id) = transaction_id {
            row.transaction_id = Some(transaction_id.to_string());
        }
        if let Some(settle) = settle {
            row.settle_action = Some(settle.action);
            row.settle_amount_units = settle.amount_units;
        }
        Ok(())
    }

    fn close_payment_journal(
        &self,
        request_id: &str,
    ) -> Result<bool, crate::budget_store::BudgetStoreError> {
        let mut rows = self.rows.lock().map_err(|_| {
            crate::budget_store::BudgetStoreError::Invariant(
                "in-crate payment journal lock poisoned".to_string(),
            )
        })?;
        let Some(row) = rows.get_mut(request_id) else {
            return Ok(false);
        };
        if matches!(
            row.state,
            crate::payment::PaymentJournalState::Closed
                | crate::payment::PaymentJournalState::ReconcileFailed
        ) {
            return Ok(false);
        }
        row.state = crate::payment::PaymentJournalState::Closed;
        Ok(true)
    }

    fn list_incomplete_payment_journal(
        &self,
        older_than_unix_ms: u64,
    ) -> Result<Vec<crate::payment::PaymentJournalRecord>, crate::budget_store::BudgetStoreError>
    {
        let rows = self.rows.lock().map_err(|_| {
            crate::budget_store::BudgetStoreError::Invariant(
                "in-crate payment journal lock poisoned".to_string(),
            )
        })?;
        let mut incomplete = rows
            .values()
            .filter(|row| {
                row.created_at_unix_ms <= older_than_unix_ms
                    && !matches!(
                        row.state,
                        crate::payment::PaymentJournalState::Closed
                            | crate::payment::PaymentJournalState::ReconcileFailed
                    )
            })
            .cloned()
            .collect::<Vec<_>>();
        incomplete.sort_by(|left, right| {
            left.created_at_unix_ms
                .cmp(&right.created_at_unix_ms)
                .then_with(|| left.request_id.cmp(&right.request_id))
        });
        Ok(incomplete)
    }

    fn get_payment_journal(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::payment::PaymentJournalRecord>, crate::budget_store::BudgetStoreError>
    {
        let rows = self.rows.lock().map_err(|_| {
            crate::budget_store::BudgetStoreError::Invariant(
                "in-crate payment journal lock poisoned".to_string(),
            )
        })?;
        Ok(rows.get(request_id).filter(|row| {
            !matches!(
                row.state,
                crate::payment::PaymentJournalState::Closed
                    | crate::payment::PaymentJournalState::ReconcileFailed
            )
        }).cloned())
    }

    fn get_payment_journal_for_audit(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::payment::PaymentJournalRecord>, crate::budget_store::BudgetStoreError>
    {
        let rows = self.rows.lock().map_err(|_| {
            crate::budget_store::BudgetStoreError::Invariant(
                "in-crate payment journal lock poisoned".to_string(),
            )
        })?;
        Ok(rows.get(request_id).cloned())
    }

    fn payment_journal_reconcile_failed_rail(
        &self,
        request_id: &str,
    ) -> Result<Option<String>, crate::budget_store::BudgetStoreError> {
        let rows = self.rows.lock().map_err(|_| {
            crate::budget_store::BudgetStoreError::Invariant(
                "in-crate payment journal lock poisoned".to_string(),
            )
        })?;
        Ok(rows.get(request_id).and_then(|row| {
            (row.state == crate::payment::PaymentJournalState::ReconcileFailed)
                .then(|| row.rail.clone())
        }))
    }
}

#[derive(Clone)]
struct AdmissionPaymentCleanupRail {
    inner: std::sync::Arc<AdmissionPaymentCleanupRailInner>,
}

struct AdmissionPaymentCleanupRailInner {
    operation_id: String,
    request_binding_hash: String,
    reference: String,
    amount_units: u64,
    currency: String,
    authorization: PaymentAuthorization,
    settlement_transaction_id: Option<String>,
    journal: std::sync::Arc<InCratePaymentJournalStore>,
    settlement_state_calls: std::sync::atomic::AtomicUsize,
    refund_calls: std::sync::Mutex<Vec<String>>,
    refund_moves: std::sync::atomic::AtomicUsize,
    release_calls: std::sync::atomic::AtomicUsize,
    release_moves: std::sync::atomic::AtomicUsize,
}

impl AdmissionPaymentCleanupRail {
    fn new(
        operation: &AdmissionOperation,
        amount_units: u64,
        currency: &str,
        authorization: PaymentAuthorization,
        settlement_transaction_id: Option<String>,
        journal: std::sync::Arc<InCratePaymentJournalStore>,
    ) -> Self {
        Self {
            inner: std::sync::Arc::new(AdmissionPaymentCleanupRailInner {
                operation_id: operation.operation_id().to_string(),
                request_binding_hash: operation.request_binding_hash().to_string(),
                reference: operation.request_id().to_string(),
                amount_units,
                currency: currency.to_string(),
                authorization,
                settlement_transaction_id,
                journal,
                settlement_state_calls: std::sync::atomic::AtomicUsize::new(0),
                refund_calls: std::sync::Mutex::new(Vec::new()),
                refund_moves: std::sync::atomic::AtomicUsize::new(0),
                release_calls: std::sync::atomic::AtomicUsize::new(0),
                release_moves: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    fn validate_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
    ) -> Result<(), PaymentError> {
        if operation_id != self.inner.operation_id
            || request_binding_hash != self.inner.request_binding_hash
        {
            return Err(PaymentError::RailError(
                "payment cleanup operation binding mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_staged(
        &self,
        action: crate::payment::PaymentSettleAction,
        transaction_id: Option<&str>,
    ) -> Result<(), PaymentError> {
        let record = self
            .inner
            .journal
            .get_payment_journal(&self.inner.reference)
            .map_err(|error| PaymentError::RailError(error.to_string()))?
            .ok_or_else(|| {
                PaymentError::RailError("payment cleanup journal is missing".to_string())
            })?;
        let expected_amount = (action == crate::payment::PaymentSettleAction::Refund)
            .then_some(self.inner.amount_units);
        if record.state != crate::payment::PaymentJournalState::Settling
            || record.settle_action != Some(action)
            || record.settle_amount_units != expected_amount
            || record.authorization_id.as_deref()
                != Some(self.inner.authorization.authorization_id.as_str())
            || record.transaction_id.as_deref() != transaction_id
        {
            return Err(PaymentError::RailError(
                "rail mutation ran before its exact payment cleanup intent was journaled"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn refund_calls(&self) -> Vec<String> {
        self.inner
            .refund_calls
            .lock()
            .expect("refund calls")
            .clone()
    }
}

impl PaymentAdapter for AdmissionPaymentCleanupRail {
    fn rail_id(&self) -> &str {
        "admission-payment-cleanup"
    }

    fn authorize(
        &self,
        _request: &crate::payment::PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Err(PaymentError::OperationIdempotencyUnsupported("authorize"))
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<crate::payment::PaymentResult, PaymentError> {
        Err(PaymentError::OperationIdempotencyUnsupported("capture"))
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<crate::payment::PaymentResult, PaymentError> {
        Err(PaymentError::OperationIdempotencyUnsupported("release"))
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<crate::payment::PaymentResult, PaymentError> {
        Err(PaymentError::OperationIdempotencyUnsupported("refund"))
    }

    fn lookup_authorization_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        self.validate_operation(operation_id, request_binding_hash)?;
        Ok(Some(self.inner.authorization.clone()))
    }

    fn release_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        authorization_id: &str,
        reference: &str,
    ) -> Result<crate::payment::PaymentResult, PaymentError> {
        self.validate_operation(operation_id, request_binding_hash)?;
        if authorization_id != self.inner.authorization.authorization_id.as_str()
            || reference != self.inner.reference.as_str()
        {
            return Err(PaymentError::RailError(
                "payment cleanup release identity mismatch".to_string(),
            ));
        }
        self.validate_staged(crate::payment::PaymentSettleAction::Release, None)?;
        self.inner
            .release_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self
            .inner
            .release_moves
            .compare_exchange(
                0,
                1,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
        {
            return Err(PaymentError::Unavailable(
                "release committed but acknowledgement was lost".to_string(),
            ));
        }
        Ok(crate::payment::PaymentResult {
            transaction_id: "payment-cleanup-release-result".to_string(),
            settlement_status: crate::payment::RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }

    fn refund_for_operation(
        &self,
        request: crate::payment::OperationPaymentRefundRequest<'_>,
    ) -> Result<crate::payment::PaymentResult, PaymentError> {
        self.validate_operation(request.operation_id, request.request_binding_hash)?;
        let expected_transaction_id = self
            .inner
            .settlement_transaction_id
            .as_deref()
            .ok_or_else(|| PaymentError::RailError("unexpected refund".to_string()))?;
        if request.transaction_id != expected_transaction_id
            || request.amount_units != self.inner.amount_units
            || request.currency != self.inner.currency.as_str()
            || request.reference != self.inner.reference.as_str()
        {
            return Err(PaymentError::RailError(
                "payment cleanup refund identity mismatch".to_string(),
            ));
        }
        self.validate_staged(
            crate::payment::PaymentSettleAction::Refund,
            Some(expected_transaction_id),
        )?;
        self.inner
            .refund_calls
            .lock()
            .map_err(|_| PaymentError::Unavailable("refund calls poisoned".to_string()))?
            .push(request.transaction_id.to_string());
        if self
            .inner
            .refund_moves
            .compare_exchange(
                0,
                1,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
        {
            return Err(PaymentError::Unavailable(
                "refund committed but acknowledgement was lost".to_string(),
            ));
        }
        Ok(crate::payment::PaymentResult {
            transaction_id: "payment-cleanup-refund-result".to_string(),
            settlement_status: crate::payment::RailSettlementStatus::Refunded,
            metadata: serde_json::json!({}),
        })
    }

    fn settlement_state_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<crate::payment::RailSettlementState, PaymentError> {
        self.validate_operation(operation_id, request_binding_hash)?;
        self.inner
            .settlement_state_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if reference != self.inner.reference.as_str()
            || authorization_id != Some(self.inner.authorization.authorization_id.as_str())
        {
            return Err(PaymentError::RailError(
                "payment cleanup settlement lookup identity mismatch".to_string(),
            ));
        }
        match self.inner.settlement_transaction_id.as_ref() {
            Some(transaction_id) => Ok(crate::payment::RailSettlementState::Settled {
                authorization_id: self.inner.authorization.authorization_id.clone(),
                result: crate::payment::PaymentResult {
                    transaction_id: transaction_id.clone(),
                    settlement_status: crate::payment::RailSettlementStatus::Settled,
                    metadata: serde_json::json!({}),
                },
            }),
            None => Ok(crate::payment::RailSettlementState::Held {
                authorization_id: self.inner.authorization.authorization_id.clone(),
            }),
        }
    }
}

struct AdmissionPaymentCleanupFixture {
    kernel: ChioKernel,
    operation: AdmissionOperation,
    store: std::sync::Arc<InCratePaymentJournalStore>,
    rail: AdmissionPaymentCleanupRail,
}

impl AdmissionPaymentCleanupFixture {
    fn new(
        settled: bool,
        settlement_transaction_id: Option<&str>,
        journal_transaction_id: Option<&str>,
    ) -> Self {
        let mut config = make_config();
        config.policy_hash = "33".repeat(32);
        config.dispatch_intent_journal = crate::DispatchIntentJournalMode::SideEffecting;
        let mut kernel = make_kernel(config);
        let operation_store = std::sync::Arc::new(ProfiledTestStore::new(
            AdmissionOperationStoreProfile::SingleNodeDurable,
        ));
        kernel
            .set_admission_operation_store_handle(operation_store.clone())
            .expect("operation store");
        let store = std::sync::Arc::new(InCratePaymentJournalStore::new());
        kernel
            .set_budget_store_handle(store.clone())
            .expect("budget store");
        let operation = prepared_admission_operation(&kernel);
        operation_store
            .create_prepared(operation.clone())
            .expect("prepared operation");
        let authorization = PaymentAuthorization {
            authorization_id: "payment-cleanup-authorization".to_string(),
            settled,
            metadata: serde_json::json!({}),
        };
        let rail = AdmissionPaymentCleanupRail::new(
            &operation,
            75,
            "USD",
            authorization.clone(),
            settlement_transaction_id.map(str::to_string),
            store.clone(),
        );
        kernel
            .set_payment_adapter(Box::new(rail.clone()))
            .expect("payment adapter");
        store
            .record_payment_journal(&crate::payment::PaymentJournalRecord {
                request_id: operation.request_id().to_string(),
                capability_id: operation.capability_id().to_string(),
                grant_index: 0,
                admission_operation: Some(
                    crate::budget_store::BudgetAdmissionOperationBinding::new(
                        operation.operation_id().to_string(),
                        operation.request_binding_hash().to_string(),
                    )
                    .expect("payment cleanup binding"),
                ),
                authority: None,
                hold_id: operation.budget_hold_id().map(ToOwned::to_owned),
                rail: rail.rail_id().to_string(),
                authorization_id: Some(authorization.authorization_id),
                transaction_id: journal_transaction_id.map(str::to_string),
                budget_exposure_units: 75,
                amount_units: 75,
                settle_action: None,
                settle_amount_units: None,
                currency: "USD".to_string(),
                state: crate::payment::PaymentJournalState::Authorized,
                created_at_unix_ms: 1,
                tenant_id: None,
            })
            .expect("authorized payment journal");
        Self {
            kernel,
            operation,
            store,
            rail,
        }
    }

    fn cleanup(&self) {
        self.kernel
            .execute_reserved_payment_cleanup(
                &self.operation,
                75,
                "USD".to_string(),
                self.operation.request_id().to_string(),
            )
            .expect("payment cleanup");
    }

    fn row(&self) -> crate::payment::PaymentJournalRecord {
        self.store
            .get_payment_journal(self.operation.request_id())
            .expect("payment cleanup row lookup")
            .expect("payment cleanup row")
    }
}

#[derive(Clone)]
struct ForgedTerminalBudgetStore {
    decision: crate::budget_store::BudgetHoldMutationDecision,
    mutation_event: Option<crate::budget_store::BudgetMutationRecord>,
}

impl ForgedTerminalBudgetStore {
    fn new(decision: crate::budget_store::BudgetHoldMutationDecision) -> Self {
        Self {
            decision,
            mutation_event: None,
        }
    }

    fn with_mutation_event(
        decision: crate::budget_store::BudgetHoldMutationDecision,
        mutation_event: crate::budget_store::BudgetMutationRecord,
    ) -> Self {
        Self {
            decision,
            mutation_event: Some(mutation_event),
        }
    }

    fn unused<T>() -> Result<T, crate::budget_store::BudgetStoreError> {
        Err(crate::budget_store::BudgetStoreError::Invariant(
            "unused forged terminal store operation".to_string(),
        ))
    }
}

impl crate::budget_store::BudgetStore for ForgedTerminalBudgetStore {
    fn authority_profile(&self) -> crate::budget_store::BudgetStoreProfile {
        crate::budget_store::BudgetStoreProfile::SingleNodeDurable
    }

    fn try_increment(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _max_invocations: Option<u32>,
    ) -> Result<bool, crate::budget_store::BudgetStoreError> {
        Self::unused()
    }

    fn try_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _max_invocations: Option<u32>,
        _cost_units: u64,
        _max_cost_per_invocation: Option<u64>,
        _max_total_cost_units: Option<u64>,
    ) -> Result<bool, crate::budget_store::BudgetStoreError> {
        Self::unused()
    }

    fn reverse_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _cost_units: u64,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        Self::unused()
    }

    fn reduce_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _cost_units: u64,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        Self::unused()
    }

    fn settle_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _exposed_cost_units: u64,
        _realized_cost_units: u64,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        Self::unused()
    }

    fn list_usages(
        &self,
        _limit: usize,
        _capability_id: Option<&str>,
    ) -> Result<Vec<crate::budget_store::BudgetUsageRecord>, crate::budget_store::BudgetStoreError>
    {
        Ok(Vec::new())
    }

    fn get_usage(
        &self,
        _capability_id: &str,
        _grant_index: usize,
    ) -> Result<
        Option<crate::budget_store::BudgetUsageRecord>,
        crate::budget_store::BudgetStoreError,
    > {
        Ok(None)
    }

    fn get_mutation_event_by_id(
        &self,
        event_id: &str,
    ) -> Result<
        Option<crate::budget_store::BudgetMutationRecord>,
        crate::budget_store::BudgetStoreError,
    > {
        Ok(self
            .mutation_event
            .as_ref()
            .filter(|event| event.event_id == event_id)
            .cloned())
    }

    fn reverse_budget_hold(
        &self,
        _request: crate::budget_store::BudgetReverseHoldRequest,
    ) -> Result<
        crate::budget_store::BudgetReverseHoldDecision,
        crate::budget_store::BudgetStoreError,
    > {
        Ok(self.decision.clone())
    }

    fn release_budget_hold(
        &self,
        _request: crate::budget_store::BudgetReleaseHoldRequest,
    ) -> Result<
        crate::budget_store::BudgetReleaseHoldDecision,
        crate::budget_store::BudgetStoreError,
    > {
        Ok(self.decision.clone())
    }

    fn reconcile_budget_hold(
        &self,
        _request: crate::budget_store::BudgetReconcileHoldRequest,
    ) -> Result<
        crate::budget_store::BudgetReconcileHoldDecision,
        crate::budget_store::BudgetStoreError,
    > {
        Ok(self.decision.clone())
    }
}

fn terminal_validation_charge(kernel: &ChioKernel) -> BudgetChargeResult {
    BudgetChargeResult {
        grant_index: 0,
        cost_charged: 5,
        currency: "USD".to_string(),
        budget_total: 100,
        new_committed_cost_units: 5,
        budget_hold_id: "hold-terminal-validation".to_string(),
        authorize_metadata: BudgetCommitMetadata {
            authority: Some(kernel.local_budget_event_authority()),
            guarantee_level: crate::budget_store::BudgetGuaranteeLevel::SingleNodeAtomic,
            budget_profile: crate::budget_store::BudgetAuthorityProfile::AuthoritativeHoldEvent,
            metering_profile:
                crate::budget_store::BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
            budget_commit_index: Some(41),
            event_id: Some("hold-terminal-validation:authorize".to_string()),
            partition_escrow_evidence: None,
        },
        admission_operation: None,
    }
}

fn terminal_validation_decision(
    charge: &BudgetChargeResult,
    event_id: &str,
    realized_spend_units: u64,
    invocation_state: crate::budget_store::BudgetInvocationReservationState,
    monetary_state: crate::budget_store::BudgetMonetaryHoldState,
) -> crate::budget_store::BudgetHoldMutationDecision {
    crate::budget_store::BudgetHoldMutationDecision {
        hold_id: Some(charge.budget_hold_id.clone()),
        exposure_units: charge.cost_charged,
        realized_spend_units,
        committed_cost_units_after: realized_spend_units,
        invocation_count_after: 1,
        invocation_counts_after: Vec::new(),
        invocation_state,
        monetary_state,
        revocation_set: None,
        metadata: BudgetCommitMetadata {
            authority: charge.authorize_metadata.authority.clone(),
            guarantee_level: charge.authorize_metadata.guarantee_level,
            budget_profile: charge.authorize_metadata.budget_profile,
            metering_profile: charge.authorize_metadata.metering_profile,
            budget_commit_index: Some(42),
            event_id: Some(event_id.to_string()),
            partition_escrow_evidence: None,
        },
    }
}

fn terminal_validation_event(
    charge: &BudgetChargeResult,
    decision: &crate::budget_store::BudgetHoldMutationDecision,
    kind: crate::budget_store::BudgetMutationKind,
) -> crate::budget_store::BudgetMutationRecord {
    let event_seq = decision
        .metadata
        .budget_commit_index
        .expect("terminal validation commit index");
    crate::budget_store::BudgetMutationRecord {
        event_id: decision
            .metadata
            .event_id
            .clone()
            .expect("terminal validation event id"),
        hold_id: decision.hold_id.clone(),
        admission_operation: charge.admission_operation.clone(),
        capability_id: "cap-terminal-validation".to_string(),
        grant_index: u32::try_from(charge.grant_index).expect("terminal validation grant index"),
        kind,
        allowed: None,
        recorded_at: 1,
        event_seq,
        usage_seq: Some(event_seq),
        exposure_units: decision.exposure_units,
        realized_spend_units: decision.realized_spend_units,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: decision.invocation_count_after,
        invocation_counts_after: decision.invocation_counts_after.clone(),
        invocation_state: decision.invocation_state,
        monetary_state: decision.monetary_state,
        revocation_set: decision.revocation_set.clone(),
        total_cost_exposed_after: 0,
        total_cost_realized_spend_after: decision.committed_cost_units_after,
        authority: decision.metadata.authority.clone(),
    }
}

#[test]
fn terminal_budget_helpers_reject_forged_store_decisions_before_projection() {
    let mut reverse_kernel = make_kernel(make_config());
    let reverse_charge = terminal_validation_charge(&reverse_kernel);
    let mut wrong_hold = terminal_validation_decision(
        &reverse_charge,
        "hold-terminal-validation:reverse",
        0,
        crate::budget_store::BudgetInvocationReservationState::Reversed,
        crate::budget_store::BudgetMonetaryHoldState::Reversed,
    );
    wrong_hold.hold_id = Some("hold-attacker-selected".to_string());
    let forged_reverse_projection = wrong_hold.clone();
    reverse_kernel
        .set_budget_store_handle(std::sync::Arc::new(ForgedTerminalBudgetStore::new(
            wrong_hold,
        )))
        .expect("forged reverse store");
    assert!(matches!(
        reverse_kernel.reverse_budget_charge("cap-terminal-validation", &reverse_charge),
        Err(KernelError::GuardDenied(message))
            if message.contains("terminal decision does not match")
    ));
    assert!(matches!(
        reverse_kernel.budget_execution_receipt_metadata(
            &reverse_charge,
            Some(("reversed", &forged_reverse_projection)),
            None,
        ),
        Err(KernelError::GuardDenied(message))
            if message.contains("terminal decision does not match")
    ));

    let mut release_kernel = make_kernel(make_config());
    let release_charge = terminal_validation_charge(&release_kernel);
    let mut wrong_exposure = terminal_validation_decision(
        &release_charge,
        "hold-terminal-validation:release",
        0,
        crate::budget_store::BudgetInvocationReservationState::Absent,
        crate::budget_store::BudgetMonetaryHoldState::Released,
    );
    wrong_exposure.exposure_units = release_charge.cost_charged + 1;
    release_kernel
        .set_budget_store_handle(std::sync::Arc::new(ForgedTerminalBudgetStore::new(
            wrong_exposure,
        )))
        .expect("forged release store");
    assert!(matches!(
        release_kernel.release_budget_charge("cap-terminal-validation", &release_charge),
        Err(KernelError::GuardDenied(message))
            if message.contains("terminal decision does not match")
    ));

    let mut reconcile_kernel = make_kernel(make_config());
    let reconcile_charge = terminal_validation_charge(&reconcile_kernel);
    let mut stale_commit = terminal_validation_decision(
        &reconcile_charge,
        "hold-terminal-validation:reconcile",
        3,
        crate::budget_store::BudgetInvocationReservationState::Absent,
        crate::budget_store::BudgetMonetaryHoldState::Reconciled,
    );
    stale_commit.metadata.budget_commit_index = Some(41);
    reconcile_kernel
        .set_budget_store_handle(std::sync::Arc::new(ForgedTerminalBudgetStore::new(
            stale_commit,
        )))
        .expect("forged reconcile store");
    assert!(matches!(
        reconcile_kernel.reconcile_budget_charge(
            "cap-terminal-validation",
            &reconcile_charge,
            3,
        ),
        Err(KernelError::GuardDenied(message))
            if message.contains("commit index did not advance")
    ));
}

#[test]
fn terminal_budget_helper_rejects_committed_cost_not_bound_to_durable_event() {
    let mut kernel = make_kernel(make_config());
    let charge = terminal_validation_charge(&kernel);
    let committed = terminal_validation_decision(
        &charge,
        "hold-terminal-validation:reconcile",
        3,
        crate::budget_store::BudgetInvocationReservationState::Absent,
        crate::budget_store::BudgetMonetaryHoldState::Reconciled,
    );
    let mutation_event = terminal_validation_event(
        &charge,
        &committed,
        crate::budget_store::BudgetMutationKind::ReconcileSpend,
    );
    let mut forged = committed;
    forged.committed_cost_units_after = 999;
    kernel
        .set_budget_store_handle(std::sync::Arc::new(
            ForgedTerminalBudgetStore::with_mutation_event(forged, mutation_event),
        ))
        .expect("forged committed-cost store");

    assert!(matches!(
        kernel.reconcile_budget_charge("cap-terminal-validation", &charge, 3),
        Err(KernelError::GuardDenied(message))
            if message.contains("durable budget mutation event does not match")
    ));
}

#[test]
fn terminal_budget_helper_rejects_decision_state_not_bound_to_durable_event() {
    let mut kernel = make_kernel(make_config());
    let charge = terminal_validation_charge(&kernel);
    let decision = terminal_validation_decision(
        &charge,
        "hold-terminal-validation:reconcile",
        3,
        crate::budget_store::BudgetInvocationReservationState::Absent,
        crate::budget_store::BudgetMonetaryHoldState::Reconciled,
    );
    let mut mutation_event = terminal_validation_event(
        &charge,
        &decision,
        crate::budget_store::BudgetMutationKind::ReconcileSpend,
    );
    mutation_event.monetary_state = crate::budget_store::BudgetMonetaryHoldState::Released;
    kernel
        .set_budget_store_handle(std::sync::Arc::new(
            ForgedTerminalBudgetStore::with_mutation_event(decision, mutation_event),
        ))
        .expect("forged terminal-state store");

    assert!(matches!(
        kernel.reconcile_budget_charge("cap-terminal-validation", &charge, 3),
        Err(KernelError::GuardDenied(message))
            if message.contains("durable budget mutation event does not match")
    ));
}

#[test]
fn operation_owned_reverse_validation_rejects_a_forged_terminal_disposition() {
    let kernel = make_kernel(make_config());
    let mut charge = terminal_validation_charge(&kernel);
    charge.admission_operation = Some(
        crate::budget_store::BudgetAdmissionOperationBinding::new(
            "operation-terminal-validation".to_string(),
            "ab".repeat(32),
        )
        .expect("operation-owned terminal binding"),
    );
    let mut forged = terminal_validation_decision(
        &charge,
        "hold-terminal-validation:reverse",
        0,
        crate::budget_store::BudgetInvocationReservationState::Reversed,
        crate::budget_store::BudgetMonetaryHoldState::Reversed,
    );
    forged.monetary_state = crate::budget_store::BudgetMonetaryHoldState::Released;
    let store = ForgedTerminalBudgetStore::new(forged.clone());

    assert!(matches!(
        kernel.validate_budget_terminal_decision_for_store(
            &store,
            &forged,
            BudgetTerminalDecisionExpectation {
                authorization_metadata: &charge.authorize_metadata,
                expected_event_id: "hold-terminal-validation:reverse",
                expected_authority: charge.authorize_metadata.authority.as_ref(),
                expected_capability_id: Some("cap-terminal-validation"),
                expected_grant_index: charge.grant_index,
                expected_hold_id: &charge.budget_hold_id,
                expected_admission_operation: charge.admission_operation.as_ref(),
                expected_mutation_kind:
                    crate::budget_store::BudgetMutationKind::ReverseInvocations,
                expected_exposure_units: charge.cost_charged,
                expected_realized_spend_units: 0,
                expected_invocation_state:
                    crate::budget_store::BudgetInvocationReservationState::Reversed,
                expected_monetary_state:
                    crate::budget_store::BudgetMonetaryHoldState::Reversed,
                stage: "operation-owned reverse",
            },
        ),
        Err(KernelError::GuardDenied(message))
            if message.contains("terminal decision does not match")
    ));
}

#[test]
fn single_node_cleanup_denial_requires_the_durable_decision_index() {
    let kernel = make_kernel(make_config());
    let store = InCratePaymentJournalStore::new();
    let authority = crate::budget_store::BudgetEventAuthority {
        authority_id: "budget:cleanup-test".to_string(),
        lease_id: "budget:cleanup-test#1".to_string(),
        lease_epoch: 1,
    };
    let event_id = "budget-cleanup-denial-event";
    let request = crate::budget_store::BudgetAuthorizeHoldRequest::legacy(
        "cap-budget-cleanup-denial".to_string(),
        0,
        Some(1),
        2,
        Some(1),
        Some(10),
        Some("hold-budget-cleanup-denial".to_string()),
        Some(event_id.to_string()),
        Some(authority.clone()),
    );
    let decision = crate::budget_store::BudgetStore::authorize_budget_hold(
        &store,
        request.clone(),
    )
    .test_expect("default single-node denial");
    let frozen_decision = decision.clone();
    let denied = match decision {
        crate::budget_store::BudgetAuthorizeHoldDecision::Denied(denied) => Some(denied),
        crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(_) => None,
    }
    .test_expect("the default single-node store must deny the over-limit request");
    assert!(denied
        .metadata
        .budget_commit_index
        .is_some_and(|commit_index| commit_index > 0));

    assert!(crate::budget_store::BudgetStore::try_increment(
        &store,
        "cap-budget-cleanup-denial",
        0,
        Some(1),
    )
    .test_expect("later live budget use"));
    assert_eq!(
        crate::budget_store::BudgetStore::authorize_budget_hold(&store, request.clone())
            .test_expect("exact default authorization replay"),
        frozen_decision,
        "hard-guarantee replay must return the frozen event snapshot, not later live usage"
    );

    let mut changed_request = request;
    changed_request.requested_exposure_units = 3;
    assert!(matches!(
        crate::budget_store::BudgetStore::authorize_budget_hold(&store, changed_request),
        Err(crate::budget_store::BudgetStoreError::Conflict(_))
    ));

    kernel
        .validate_budget_cleanup_denial(super::admission_cleanup::BudgetCleanupDenialValidation {
            store: &store,
            denied: &denied,
            expected_hold_id: Some("hold-budget-cleanup-denial"),
            expected_exposure: 2,
            expected_event_id: event_id,
            expected_authority: Some(&authority),
            expected_revocation_set: None,
        })
        .test_expect("single-node denial with a durable decision index");

    let mut missing_commit_index = denied.clone();
    missing_commit_index.metadata.budget_commit_index = None;
    assert!(matches!(
        kernel.validate_budget_cleanup_denial(
            super::admission_cleanup::BudgetCleanupDenialValidation {
                store: &store,
                denied: &missing_commit_index,
                expected_hold_id: Some("hold-budget-cleanup-denial"),
                expected_exposure: 2,
                expected_event_id: event_id,
                expected_authority: Some(&authority),
                expected_revocation_set: None,
            },
        ),
        Err(KernelError::GuardDenied(message))
            if message.contains("omitted fenced authority evidence")
    ));

    let mut zero_commit_index = denied;
    zero_commit_index.metadata.budget_commit_index = Some(0);
    assert!(matches!(
        kernel.validate_budget_cleanup_denial(
            super::admission_cleanup::BudgetCleanupDenialValidation {
                store: &store,
                denied: &zero_commit_index,
                expected_hold_id: Some("hold-budget-cleanup-denial"),
                expected_exposure: 2,
                expected_event_id: event_id,
                expected_authority: Some(&authority),
                expected_revocation_set: None,
            },
        ),
        Err(KernelError::GuardDenied(message))
            if message.contains("omitted fenced authority evidence")
    ));
}

#[test]
fn post_dispatch_drop_omits_forged_budget_authority_when_partition_lineage_is_invalid() {
    let kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-invalid-partition-drop",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-invalid-partition-drop",
        &cap,
        "destructive_update",
        "srv-invalid-partition-drop",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    authorize_fabricated_drop_hold(&kernel, &cap.id).expect("fabricated drop hold must authorize");

    let mut charge = make_fabricated_drop_charge();
    charge.authorize_metadata.guarantee_level =
        crate::budget_store::BudgetGuaranteeLevel::PartitionEscrowed;
    assert!(charge
        .authorize_metadata
        .partition_escrow_evidence
        .is_none());
    let forged_metadata = serde_json::json!({
        "budget_authority": {
            "guarantee_level": "forged-guarantee",
            "forged_marker": "must-not-survive"
        },
        "route": {
            "bridge": "partition-lineage-drop-test"
        }
    });
    assert!(matches!(
        kernel.post_dispatch_cleanup_receipt_metadata(
            Some(forged_metadata.clone()),
            Some(&charge),
            &Ok(None),
        ),
        Err(KernelError::Internal(message))
            if message.contains("omitted signed allocation evidence")
    ));
    let budget_mutation = PreExecutionBudgetMutation::Charge(Box::new(charge));

    let mut guard = PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &budget_mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: Some(forged_metadata),
            pre_invocation_guard_evidence: Vec::new(),
            verified_payee_binding: None,
        },
        false,
    );
    guard.mark_dispatch_started();
    drop(guard);

    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log
        .get(0)
        .expect("post-dispatch drop must record a cancellation receipt");
    assert!(receipt.is_cancelled());
    let metadata = receipt
        .metadata
        .as_ref()
        .expect("post-dispatch drop receipt must retain safe base metadata");
    assert!(
        metadata.get("budget_authority").is_none(),
        "invalid PartitionEscrowed lineage must not fall back to caller budget authority"
    );
    assert_eq!(metadata["route"]["bridge"], "partition-lineage-drop-test");
    assert!(receipt.financial_budget_authority_metadata().is_none());
}

#[test]
fn settled_admission_payment_cleanup_refunds_actual_operation_transaction_after_journaling() {
    let fixture = AdmissionPaymentCleanupFixture::new(
        true,
        Some("payment-cleanup-captured-transaction"),
        None,
    );

    fixture.cleanup();

    assert_eq!(
        fixture.rail.refund_calls(),
        vec![
            "payment-cleanup-captured-transaction".to_string(),
            "payment-cleanup-captured-transaction".to_string(),
        ]
    );
    assert_eq!(
        fixture
            .rail
            .inner
            .settlement_state_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture
            .rail
            .inner
            .refund_moves
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the rail saw two exact attempts while its idempotent mutation moved once"
    );
    let row = fixture.row();
    assert_eq!(row.state, crate::payment::PaymentJournalState::Settled);
    assert_eq!(
        row.settle_action,
        Some(crate::payment::PaymentSettleAction::Refund)
    );
    assert_eq!(row.settle_amount_units, Some(75));
    assert_eq!(
        row.transaction_id.as_deref(),
        Some("payment-cleanup-refund-result")
    );
}

#[test]
fn unsettled_admission_payment_cleanup_stages_release_before_exact_retry() {
    let fixture = AdmissionPaymentCleanupFixture::new(false, None, None);

    fixture.cleanup();

    assert_eq!(
        fixture
            .rail
            .inner
            .settlement_state_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        fixture
            .rail
            .inner
            .release_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_eq!(
        fixture
            .rail
            .inner
            .release_moves
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the rail saw two exact attempts while its idempotent mutation moved once"
    );
    let row = fixture.row();
    assert_eq!(row.state, crate::payment::PaymentJournalState::Settled);
    assert_eq!(
        row.settle_action,
        Some(crate::payment::PaymentSettleAction::Release)
    );
    assert_eq!(row.settle_amount_units, None);
    assert_eq!(
        row.transaction_id.as_deref(),
        Some("payment-cleanup-release-result")
    );
}

#[test]
fn settled_admission_payment_cleanup_uses_exact_journaled_capture_transaction() {
    let fixture = AdmissionPaymentCleanupFixture::new(
        true,
        Some("payment-cleanup-journal-transaction"),
        Some("payment-cleanup-journal-transaction"),
    );

    fixture.cleanup();

    assert_eq!(
        fixture.rail.refund_calls(),
        vec![
            "payment-cleanup-journal-transaction".to_string(),
            "payment-cleanup-journal-transaction".to_string(),
        ]
    );
    assert_eq!(
        fixture
            .rail
            .inner
            .settlement_state_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an exact journaled capture transaction must not be replaced by a lookup guess"
    );
    let row = fixture.row();
    assert_eq!(row.state, crate::payment::PaymentJournalState::Settled);
    assert_eq!(
        row.settle_action,
        Some(crate::payment::PaymentSettleAction::Refund)
    );
    assert_eq!(
        row.transaction_id.as_deref(),
        Some("payment-cleanup-refund-result")
    );
}
