struct DurableAtomicTestBudgetStore {
    budget: InMemoryBudgetStore,
    journal: InCratePaymentJournalStore,
    transaction: std::sync::Mutex<()>,
}

impl DurableAtomicTestBudgetStore {
    fn new() -> Self {
        Self {
            budget: InMemoryBudgetStore::new(),
            journal: InCratePaymentJournalStore::new(),
            transaction: std::sync::Mutex::new(()),
        }
    }

    fn lock_transaction(&self) -> Result<std::sync::MutexGuard<'_, ()>, BudgetStoreError> {
        self.transaction.lock().map_err(|_| {
            BudgetStoreError::Invariant("atomic test budget transaction poisoned".to_string())
        })
    }
}

impl BudgetStore for DurableAtomicTestBudgetStore {
    fn authority_profile(&self) -> crate::budget_store::BudgetStoreProfile {
        crate::budget_store::BudgetStoreProfile::SingleNodeDurable
    }

    fn supports_durable_atomic_payment_journal(&self) -> bool {
        true
    }

    fn budget_guarantee_level(&self) -> crate::budget_store::BudgetGuaranteeLevel {
        crate::budget_store::BudgetGuaranteeLevel::SingleNodeAtomic
    }

    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget
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
    ) -> Result<bool, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
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
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.try_charge_cost_with_ids_and_authority(
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
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget
            .reverse_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.reverse_charge_cost_with_ids(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
        )
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.reverse_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget
            .reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.reduce_charge_cost_with_ids(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
        )
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.reduce_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
        )
    }

    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.settle_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<crate::BudgetUsageRecord>, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<crate::BudgetUsageRecord>, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.get_usage(capability_id, grant_index)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<crate::budget_store::BudgetMutationRecord>, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget
            .list_mutation_events(limit, capability_id, grant_index)
    }

    fn budget_authority_profile(&self) -> crate::budget_store::BudgetAuthorityProfile {
        self.budget.budget_authority_profile()
    }

    fn budget_metering_profile(&self) -> crate::budget_store::BudgetMeteringProfile {
        self.budget.budget_metering_profile()
    }

    fn list_open_holds_older_than(
        &self,
        older_than_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<crate::budget_store::OpenHoldSummary>, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget
            .list_open_holds_older_than(older_than_unix_ms, limit)
    }

    fn expire_open_hold(&self, hold_id: &str) -> Result<bool, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.expire_open_hold(hold_id)
    }

    fn recover_unstamped_caller_reservations(&self) -> Result<usize, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.recover_unstamped_caller_reservations()
    }

    fn open_hold_count(&self) -> Result<u64, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.open_hold_count()
    }

    fn record_payment_journal(
        &self,
        entry: &crate::payment::PaymentJournalRecord,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.journal.record_payment_journal(entry)
    }

    fn advance_payment_journal(
        &self,
        request_id: &str,
        expected: crate::payment::PaymentJournalState,
        next: crate::payment::PaymentJournalState,
        authorization_id: Option<&str>,
        transaction_id: Option<&str>,
        settle: Option<crate::payment::PaymentSettleIntent>,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.journal.advance_payment_journal(
            request_id,
            expected,
            next,
            authorization_id,
            transaction_id,
            settle,
        )
    }

    fn close_payment_journal(&self, request_id: &str) -> Result<bool, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.journal.close_payment_journal(request_id)
    }

    fn list_incomplete_payment_journal(
        &self,
        older_than_unix_ms: u64,
    ) -> Result<Vec<crate::payment::PaymentJournalRecord>, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.journal
            .list_incomplete_payment_journal(older_than_unix_ms)
    }

    fn get_payment_journal(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::payment::PaymentJournalRecord>, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.journal.get_payment_journal(request_id)
    }

    fn payment_journal_reconcile_failed_rail(
        &self,
        request_id: &str,
    ) -> Result<Option<String>, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.journal
            .payment_journal_reconcile_failed_rail(request_id)
    }

    fn authorize_budget_hold(
        &self,
        mut request: crate::budget_store::BudgetAuthorizeHoldRequest,
    ) -> Result<crate::budget_store::BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        let payment_journal = request.payment_journal.take();
        let mut rows = self.journal.rows.lock().map_err(|_| {
            BudgetStoreError::Invariant("in-crate payment journal lock poisoned".to_string())
        })?;
        if let Some(entry) = payment_journal.as_ref() {
            if rows.contains_key(&entry.request_id) {
                return Err(BudgetStoreError::Invariant(format!(
                    "payment journal request `{}` already exists",
                    entry.request_id
                )));
            }
        }
        let decision = self.budget.authorize_budget_hold(request)?;
        if matches!(
            &decision,
            crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(_)
        ) {
            if let Some(entry) = payment_journal {
                rows.insert(entry.request_id.clone(), entry);
            }
        }
        Ok(decision)
    }

    fn reverse_budget_hold(
        &self,
        request: crate::budget_store::BudgetReverseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.reverse_budget_hold(request)
    }

    fn release_budget_hold(
        &self,
        request: crate::budget_store::BudgetReleaseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReleaseHoldDecision, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.release_budget_hold(request)
    }

    fn reconcile_budget_hold(
        &self,
        request: crate::budget_store::BudgetReconcileHoldRequest,
    ) -> Result<crate::budget_store::BudgetReconcileHoldDecision, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.reconcile_budget_hold(request)
    }

    fn capture_budget_hold(
        &self,
        request: crate::budget_store::BudgetCaptureHoldRequest,
    ) -> Result<crate::budget_store::BudgetCaptureHoldDecision, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.capture_budget_hold(request)
    }

    fn capture_invocation_reservations(
        &self,
        request: crate::budget_store::BudgetCaptureInvocationRequest,
    ) -> Result<crate::budget_store::BudgetHoldMutationDecision, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.capture_invocation_reservations(request)
    }

    fn query_invocation_capture(
        &self,
        request: &crate::budget_store::BudgetCaptureInvocationRequest,
    ) -> Result<Option<crate::budget_store::BudgetHoldMutationDecision>, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.query_invocation_capture(request)
    }

    fn reap_orphaned_holds(
        &self,
        realized_by_hold: &std::collections::HashMap<String, u64>,
    ) -> Result<(usize, usize), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.reap_orphaned_holds(realized_by_hold)
    }

    fn count_open_holds(&self) -> Result<usize, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.count_open_holds()
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<crate::budget_store::BudgetHoldSnapshot>, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.get_budget_hold(hold_id)
    }

    fn mark_hold_reserved(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.mark_hold_reserved(
            hold_id,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        )
    }

    fn mark_invocation_hold_reserved(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.mark_invocation_hold_reserved(
            hold_id,
            capability_id,
            grant_index,
            reserved_until_unix_secs,
            envelope,
        )
    }

    fn mark_admission_operation_hold_reserved(
        &self,
        hold_id: &str,
        admission_operation: &crate::budget_store::BudgetAdmissionOperationBinding,
        reserved_until_unix_secs: i64,
        currency: Option<&str>,
        payment_reference: Option<&str>,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.mark_admission_operation_hold_reserved(
            hold_id,
            admission_operation,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        )
    }

    fn reserve_invocation_hold(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.reserve_invocation_hold(
            hold_id,
            capability_id,
            grant_index,
            reserved_until_unix_secs,
            envelope,
        )
    }

    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.reap_expired_reserved_holds(now_unix_secs)
    }

    fn list_open_delegated_reserved_hold_ids(
        &self,
    ) -> Result<Option<Vec<String>>, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.list_open_delegated_reserved_hold_ids()
    }

    fn request_id_has_reserved_hold(
        &self,
        request_id: &str,
    ) -> Result<Option<bool>, BudgetStoreError> {
        let _transaction = self.lock_transaction()?;
        self.budget.request_id_has_reserved_hold(request_id)
    }
}

fn durable_atomic_test_budget_store(
    _prefix: &str,
) -> std::sync::Arc<DurableAtomicTestBudgetStore> {
    std::sync::Arc::new(DurableAtomicTestBudgetStore::new())
}

fn durable_test_admission_operation_store(
    _prefix: &str,
) -> std::sync::Arc<ProfiledTestStore> {
    std::sync::Arc::new(ProfiledTestStore::new(
        AdmissionOperationStoreProfile::SingleNodeDurable,
    ))
}
