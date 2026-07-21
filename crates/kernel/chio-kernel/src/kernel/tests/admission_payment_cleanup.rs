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
        let operation = prepared_admission_operation(&kernel);
        operation_store
            .create_prepared(operation.clone())
            .expect("prepared operation");
        let store = std::sync::Arc::new(InCratePaymentJournalStore::new());
        kernel
            .set_budget_store_handle(store.clone())
            .expect("budget store");
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
