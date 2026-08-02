struct MonetaryCostServer {
    id: String,
    reported_cost: Option<ToolInvocationCost>,
}

struct FailingMonetaryServer {
    id: String,
}

/// A monetary tool server that dispatches a pass-through but reports that it
/// does not measure realized cost, mirroring the sidecar mediated route's
/// pre-execution authorization gate.
struct UnmeasuredCostServer {
    id: String,
}

#[async_trait::async_trait]
impl ToolServerConnection for UnmeasuredCostServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["compute".to_string()]
    }

    fn measures_realized_cost(&self) -> bool {
        false
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({ "upstream": "https://example.test" }))
    }
}

struct CountingMonetaryServer {
    id: String,
    invocations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

struct PendingMonetaryServer {
    id: String,
    started: std::sync::Arc<tokio::sync::Notify>,
}

fn forged_budget_authority_metadata() -> serde_json::Value {
    serde_json::json!({
        "budget_authority": {
            "guarantee_level": "forged-guarantee",
            "authority_profile": "forged-authority-profile",
            "metering_profile": "forged-metering-profile",
            "hold_id": "forged-budget-hold",
            "budget_term": "forged-budget-term",
            "authority": {
                "authority_id": "forged-authority",
                "lease_id": "forged-lease",
                "lease_epoch": 999
            },
            "authorize": {
                "event_id": "forged:authorize"
            },
            "terminal": {
                "disposition": "released",
                "event_id": "forged:release"
            },
            "forged_marker": "must-not-survive"
        },
        "chio_runtime": {
            "admission_id": "legitimate-admission-metadata",
            "accepted": true
        },
        "route": {
            "bridge": "collision-test"
        }
    })
}

trait TestBudgetFault: Send + Sync {
    const FAIL_REVERSE: bool;
    const FAIL_RELEASE: bool;
}

struct ReleaseBudgetFault;

impl TestBudgetFault for ReleaseBudgetFault {
    const FAIL_REVERSE: bool = false;
    const FAIL_RELEASE: bool = true;
}

struct ReverseBudgetFault;

impl TestBudgetFault for ReverseBudgetFault {
    const FAIL_REVERSE: bool = true;
    const FAIL_RELEASE: bool = false;
}

struct FaultingDurableAtomicBudgetStore<F> {
    inner: std::sync::Arc<DurableAtomicTestBudgetStore>,
    fault: std::marker::PhantomData<F>,
}

impl<F> FaultingDurableAtomicBudgetStore<F> {
    fn with_durable_atomic_inner() -> Self {
        Self {
            inner: std::sync::Arc::new(DurableAtomicTestBudgetStore::new()),
            fault: std::marker::PhantomData,
        }
    }
}

type FailingReleaseBudgetStore = FaultingDurableAtomicBudgetStore<ReleaseBudgetFault>;
type ReverseFailingBudgetStore = FaultingDurableAtomicBudgetStore<ReverseBudgetFault>;

impl FaultingDurableAtomicBudgetStore<ReleaseBudgetFault> {
    fn new() -> Self {
        Self::with_durable_atomic_inner()
    }
}

impl FaultingDurableAtomicBudgetStore<ReverseBudgetFault> {
    fn new() -> Self {
        Self::with_durable_atomic_inner()
    }
}

impl<F: TestBudgetFault> BudgetStore for FaultingDurableAtomicBudgetStore<F> {
    fn authority_profile(&self) -> crate::budget_store::BudgetStoreProfile {
        self.inner.authority_profile()
    }

    fn supports_durable_atomic_payment_journal(&self) -> bool {
        self.inner.supports_durable_atomic_payment_journal()
    }

    fn budget_guarantee_level(&self) -> crate::budget_store::BudgetGuaranteeLevel {
        self.inner.budget_guarantee_level()
    }

    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
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
    ) -> Result<bool, BudgetStoreError> {
        self.inner.try_charge_cost(
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
        self.inner.try_charge_cost_with_ids(
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
        authority: Option<&crate::budget_store::BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        self.inner.try_charge_cost_with_ids_and_authority(
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
        if F::FAIL_REVERSE {
            return Err(BudgetStoreError::Invariant(
                "reverse store unreachable".to_string(),
            ));
        }
        self.inner
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
        if F::FAIL_REVERSE {
            return Err(BudgetStoreError::Invariant(
                "reverse store unreachable".to_string(),
            ));
        }
        self.inner.reverse_charge_cost_with_ids(
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
        authority: Option<&crate::budget_store::BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        if F::FAIL_REVERSE {
            return Err(BudgetStoreError::Invariant(
                "reverse store unreachable".to_string(),
            ));
        }
        self.inner.reverse_charge_cost_with_ids_and_authority(
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
        self.inner
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
        self.inner.reduce_charge_cost_with_ids(
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
        authority: Option<&crate::budget_store::BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.inner.reduce_charge_cost_with_ids_and_authority(
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
        self.inner.settle_charge_cost(
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
        self.inner.settle_charge_cost_with_ids(
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
        authority: Option<&crate::budget_store::BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.inner.settle_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<crate::budget_store::BudgetMutationRecord>, BudgetStoreError> {
        self.inner
            .list_mutation_events(limit, capability_id, grant_index)
    }

    fn get_mutation_event_by_id(
        &self,
        event_id: &str,
    ) -> Result<Option<crate::budget_store::BudgetMutationRecord>, BudgetStoreError> {
        self.inner.get_mutation_event_by_id(event_id)
    }

    fn budget_authority_profile(&self) -> crate::budget_store::BudgetAuthorityProfile {
        self.inner.budget_authority_profile()
    }

    fn budget_metering_profile(&self) -> crate::budget_store::BudgetMeteringProfile {
        self.inner.budget_metering_profile()
    }

    fn partition_escrow_store_binding(
        &self,
    ) -> Result<Option<crate::budget_store::PartitionEscrowStoreBinding>, BudgetStoreError> {
        self.inner.partition_escrow_store_binding()
    }

    fn list_open_holds_older_than(
        &self,
        older_than_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<crate::budget_store::OpenHoldSummary>, BudgetStoreError> {
        self.inner
            .list_open_holds_older_than(older_than_unix_ms, limit)
    }

    fn expire_open_hold(&self, hold_id: &str) -> Result<bool, BudgetStoreError> {
        self.inner.expire_open_hold(hold_id)
    }

    fn recover_unstamped_caller_reservations(&self) -> Result<usize, BudgetStoreError> {
        self.inner.recover_unstamped_caller_reservations()
    }

    fn open_hold_count(&self) -> Result<u64, BudgetStoreError> {
        self.inner.open_hold_count()
    }

    fn record_payment_journal(
        &self,
        entry: &crate::payment::PaymentJournalRecord,
    ) -> Result<(), BudgetStoreError> {
        self.inner.record_payment_journal(entry)
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
        self.inner.advance_payment_journal(
            request_id,
            expected,
            next,
            authorization_id,
            transaction_id,
            settle,
        )
    }

    fn close_payment_journal(&self, request_id: &str) -> Result<bool, BudgetStoreError> {
        self.inner.close_payment_journal(request_id)
    }

    fn list_incomplete_payment_journal(
        &self,
        older_than_unix_ms: u64,
    ) -> Result<Vec<crate::payment::PaymentJournalRecord>, BudgetStoreError> {
        self.inner
            .list_incomplete_payment_journal(older_than_unix_ms)
    }

    fn get_payment_journal(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::payment::PaymentJournalRecord>, BudgetStoreError> {
        self.inner.get_payment_journal(request_id)
    }

    fn payment_journal_reconcile_failed_rail(
        &self,
        request_id: &str,
    ) -> Result<Option<String>, BudgetStoreError> {
        self.inner.payment_journal_reconcile_failed_rail(request_id)
    }

    fn authorize_budget_hold(
        &self,
        request: crate::budget_store::BudgetAuthorizeHoldRequest,
    ) -> Result<crate::budget_store::BudgetAuthorizeHoldDecision, BudgetStoreError> {
        self.inner.authorize_budget_hold(request)
    }

    fn replay_budget_authorization(
        &self,
        request: crate::budget_store::BudgetAuthorizeHoldRequest,
    ) -> Result<crate::budget_store::BudgetAuthorizeHoldDecision, BudgetStoreError> {
        self.inner.replay_budget_authorization(request)
    }

    fn reverse_budget_hold(
        &self,
        request: crate::budget_store::BudgetReverseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, BudgetStoreError> {
        if F::FAIL_REVERSE {
            return Err(BudgetStoreError::Invariant(
                "reverse store unreachable".to_string(),
            ));
        }
        self.inner.reverse_budget_hold(request)
    }

    fn release_budget_hold(
        &self,
        request: crate::budget_store::BudgetReleaseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReleaseHoldDecision, BudgetStoreError> {
        if F::FAIL_RELEASE {
            return Err(BudgetStoreError::Invariant(
                "injected budget release failure sk_live_abcdefghijklmnopqrstuvwx".to_string(),
            ));
        }
        self.inner.release_budget_hold(request)
    }

    fn reconcile_budget_hold(
        &self,
        request: crate::budget_store::BudgetReconcileHoldRequest,
    ) -> Result<crate::budget_store::BudgetReconcileHoldDecision, BudgetStoreError> {
        self.inner.reconcile_budget_hold(request)
    }

    fn capture_budget_hold(
        &self,
        request: crate::budget_store::BudgetCaptureHoldRequest,
    ) -> Result<crate::budget_store::BudgetCaptureHoldDecision, BudgetStoreError> {
        self.inner.capture_budget_hold(request)
    }

    fn capture_invocation_reservations(
        &self,
        request: crate::budget_store::BudgetCaptureInvocationRequest,
    ) -> Result<crate::budget_store::BudgetHoldMutationDecision, BudgetStoreError> {
        self.inner.capture_invocation_reservations(request)
    }

    fn query_invocation_capture(
        &self,
        request: &crate::budget_store::BudgetCaptureInvocationRequest,
    ) -> Result<Option<crate::budget_store::BudgetHoldMutationDecision>, BudgetStoreError> {
        self.inner.query_invocation_capture(request)
    }

    fn reap_orphaned_holds(
        &self,
        realized_by_hold: &std::collections::HashMap<String, u64>,
    ) -> Result<(usize, usize), BudgetStoreError> {
        self.inner.reap_orphaned_holds(realized_by_hold)
    }

    fn count_open_holds(&self) -> Result<usize, BudgetStoreError> {
        self.inner.count_open_holds()
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<crate::budget_store::BudgetHoldSnapshot>, BudgetStoreError> {
        self.inner.get_budget_hold(hold_id)
    }

    fn mark_hold_reserved(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        self.inner.mark_hold_reserved(
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
        self.inner.mark_invocation_hold_reserved(
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
        self.inner.mark_admission_operation_hold_reserved(
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
        self.inner.reserve_invocation_hold(
            hold_id,
            capability_id,
            grant_index,
            reserved_until_unix_secs,
            envelope,
        )
    }

    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        self.inner.reap_expired_reserved_holds(now_unix_secs)
    }

    fn list_open_delegated_reserved_hold_ids(
        &self,
    ) -> Result<Option<Vec<String>>, BudgetStoreError> {
        self.inner.list_open_delegated_reserved_hold_ids()
    }

    fn request_id_has_reserved_hold(
        &self,
        request_id: &str,
    ) -> Result<Option<bool>, BudgetStoreError> {
        self.inner.request_id_has_reserved_hold(request_id)
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.inner.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.inner.get_usage(capability_id, grant_index)
    }
}

struct StaticPriceOracle {
    rates: std::collections::BTreeMap<(String, String), Result<ExchangeRate, PriceOracleError>>,
}

impl StaticPriceOracle {
    fn new(
        rates: impl IntoIterator<Item = ((String, String), Result<ExchangeRate, PriceOracleError>)>,
    ) -> Self {
        Self {
            rates: rates.into_iter().collect(),
        }
    }
}

impl PriceOracle for StaticPriceOracle {
    fn get_rate<'a>(
        &'a self,
        base: &'a str,
        quote: &'a str,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<ExchangeRate, PriceOracleError>> + Send + 'a>,
    > {
        let response = self
            .rates
            .get(&(base.to_ascii_uppercase(), quote.to_ascii_uppercase()))
            .cloned()
            .unwrap_or_else(|| {
                Err(PriceOracleError::NoPairAvailable {
                    base: base.to_ascii_uppercase(),
                    quote: quote.to_ascii_uppercase(),
                })
            });
        Box::pin(async move { response })
    }

    fn supported_pairs(&self) -> Vec<String> {
        self.rates
            .keys()
            .map(|(base, quote)| format!("{base}/{quote}"))
            .collect()
    }
}

impl MonetaryCostServer {
    fn new(id: &str, cost_units: u64, currency: &str) -> Self {
        Self {
            id: id.to_string(),
            reported_cost: Some(ToolInvocationCost {
                units: cost_units,
                currency: currency.to_string(),
                breakdown: None,
            }),
        }
    }

    fn no_cost(id: &str) -> Self {
        Self {
            id: id.to_string(),
            reported_cost: None,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for MonetaryCostServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "compute".to_string(),
            "compute-a".to_string(),
            "compute-b".to_string(),
        ]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({"result": "ok"}))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((value, self.reported_cost.clone()))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for FailingMonetaryServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["compute".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal("tool server failure".to_string()))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let _ = (tool_name, arguments, bridge);
        Err(KernelError::Internal("tool server failure".to_string()))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingMonetaryServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["compute".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(serde_json::json!({"result": "ok"}))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((value, None))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for PendingMonetaryServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["compute".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.started.notify_waiters();
        std::future::pending::<Result<serde_json::Value, KernelError>>().await
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((value, None))
    }
}

fn make_monetary_grant(
    server: &str,
    tool: &str,
    max_cost_per_invocation: u64,
    max_total_cost: u64,
    currency: &str,
) -> ToolGrant {
    use chio_core::capability::scope::MonetaryAmount;
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: max_cost_per_invocation,
            currency: currency.to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: max_total_cost,
            currency: currency.to_string(),
        }),
        dpop_required: None,
    }
}

fn make_monetary_config() -> KernelConfig {
    KernelConfig {
        keypair: make_keypair(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "11".repeat(32),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: crate::MemoryBudgetConfig::defaults(),
        deadlines: crate::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: crate::DispatchIntentJournalMode::Off,
    }
}

struct SiblingSumMonetaryFixture {
    kernel: ChioKernel,
    child_a: CapabilityToken,
    child_b: CapabilityToken,
    child_a_kp: Keypair,
    child_b_kp: Keypair,
    path: PathBuf,
}

fn make_sibling_sum_monetary_fixture(prefix: &str) -> SiblingSumMonetaryFixture {
    let path = unique_receipt_db_path(prefix);
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = make_kernel(make_monetary_config());
    kernel
        .set_admission_operation_store_handle(durable_test_admission_operation_store(&format!(
            "{prefix}-monetary-operations"
        )))
        .expect("sibling monetary admission operation store");
    kernel
        .set_budget_store_handle(durable_atomic_test_budget_store(&format!(
            "{prefix}-monetary-budget"
        )))
        .expect("sibling monetary budget store");
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let parent_kp = make_keypair();
    let child_a_kp = make_keypair();
    let child_b_kp = make_keypair();
    let mut parent_grant = make_monetary_grant("cost-srv", "compute", 100, 1_000, "USD");
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let child_scope = make_scope(vec![make_monetary_grant(
        "cost-srv", "compute", 100, 1_000, "USD",
    )]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    let aggregate_root =
        chio_core::capability::aggregate_budget::verify_direct_aggregate_root_record(
            &parent,
            &[kernel.config.keypair.public_key()],
        )
        .unwrap();
    let aggregate_root_id = parent.id.clone();
    drop(seed_store);
    kernel
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()))
        .unwrap();
    kernel.set_aggregate_family_root_resolver(std::sync::Arc::new(move |requested_id: &str| {
        if requested_id == aggregate_root_id {
            Ok(aggregate_root.clone())
        } else {
            Err(
                chio_core::capability::aggregate_budget::AggregateFamilyRootResolutionError::Missing,
            )
        }
    }));
    kernel
        .register_budget_parent(parent.id.clone(), 5_000)
        .unwrap();
    trust_delegated_leaf_signer_for_scope(&mut kernel, &parent_kp, &parent_scope);

    let child_a_id = format!("cap-{prefix}-child-a");
    let child_a = make_v2_delegated_child(V2DelegatedChildInput {
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_a_kp,
        parent_scope: &parent_scope,
        child_scope: child_scope.clone(),
        id: &child_a_id,
        share_bps: 4_000,
    });
    let child_b_id = format!("cap-{prefix}-child-b");
    let child_b = make_v2_delegated_child(V2DelegatedChildInput {
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_b_kp,
        parent_scope: &parent_scope,
        child_scope,
        id: &child_b_id,
        share_bps: 4_000,
    });

    SiblingSumMonetaryFixture {
        kernel,
        child_a,
        child_b,
        child_a_kp,
        child_b_kp,
        path,
    }
}

struct SiblingSumInvocationFixture {
    kernel: ChioKernel,
    child_a: CapabilityToken,
    child_b: CapabilityToken,
    child_a_kp: Keypair,
    child_b_kp: Keypair,
    path: PathBuf,
}

fn make_invocation_limited_grant(server: &str, tool: &str, max_invocations: u32) -> ToolGrant {
    let mut grant = make_grant(server, tool);
    grant.max_invocations = Some(max_invocations);
    grant
}

fn make_sibling_sum_invocation_fixture(prefix: &str) -> SiblingSumInvocationFixture {
    let path = unique_receipt_db_path(prefix);
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = make_kernel(make_monetary_config());
    kernel
        .set_admission_operation_store_handle(durable_test_admission_operation_store(&format!(
            "{prefix}-invocation-operations"
        )))
        .expect("sibling invocation admission operation store");
    kernel
        .set_budget_store_handle(durable_atomic_test_budget_store(&format!(
            "{prefix}-invocation-budget"
        )))
        .expect("sibling invocation budget store");
    kernel.register_tool_server(Box::new(EchoServer::new("limited-srv", vec!["compute"])));

    let parent_kp = make_keypair();
    let child_a_kp = make_keypair();
    let child_b_kp = make_keypair();
    let mut parent_grant = make_invocation_limited_grant("limited-srv", "compute", 1);
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let child_scope = make_scope(vec![make_invocation_limited_grant(
        "limited-srv",
        "compute",
        1,
    )]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    let aggregate_root =
        chio_core::capability::aggregate_budget::verify_direct_aggregate_root_record(
            &parent,
            &[kernel.config.keypair.public_key()],
        )
        .unwrap();
    let aggregate_root_id = parent.id.clone();
    drop(seed_store);
    kernel
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()))
        .unwrap();
    kernel.set_aggregate_family_root_resolver(std::sync::Arc::new(move |requested_id: &str| {
        if requested_id == aggregate_root_id {
            Ok(aggregate_root.clone())
        } else {
            Err(
                chio_core::capability::aggregate_budget::AggregateFamilyRootResolutionError::Missing,
            )
        }
    }));
    kernel
        .register_budget_parent(parent.id.clone(), 5_000)
        .unwrap();
    trust_delegated_leaf_signer_for_scope(&mut kernel, &parent_kp, &parent_scope);

    let child_a_id = format!("cap-{prefix}-child-a");
    let child_a = make_v2_delegated_child(V2DelegatedChildInput {
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_a_kp,
        parent_scope: &parent_scope,
        child_scope: child_scope.clone(),
        id: &child_a_id,
        share_bps: 4_000,
    });
    let child_b_id = format!("cap-{prefix}-child-b");
    let child_b = make_v2_delegated_child(V2DelegatedChildInput {
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_b_kp,
        parent_scope: &parent_scope,
        child_scope,
        id: &child_b_id,
        share_bps: 4_000,
    });

    SiblingSumInvocationFixture {
        kernel,
        child_a,
        child_b,
        child_a_kp,
        child_b_kp,
        path,
    }
}

fn make_governed_monetary_grant(
    server: &str,
    tool: &str,
    max_cost_per_invocation: u64,
    max_total_cost: u64,
    currency: &str,
    approval_threshold_units: u64,
) -> ToolGrant {
    let mut grant = make_monetary_grant(
        server,
        tool,
        max_cost_per_invocation,
        max_total_cost,
        currency,
    );
    grant.constraints = vec![
        Constraint::GovernedIntentRequired,
        Constraint::RequireApprovalAbove {
            threshold_units: approval_threshold_units,
        },
    ];
    grant
}

fn with_minimum_runtime_assurance(mut grant: ToolGrant, tier: RuntimeAssuranceTier) -> ToolGrant {
    grant
        .constraints
        .push(Constraint::MinimumRuntimeAssurance(tier));
    grant
}

fn with_minimum_autonomy_tier(mut grant: ToolGrant, tier: GovernedAutonomyTier) -> ToolGrant {
    grant
        .constraints
        .push(Constraint::MinimumAutonomyTier(tier));
    grant
}

fn make_governed_acp_monetary_grant(
    server: &str,
    tool: &str,
    seller: &str,
    max_cost_per_invocation: u64,
    max_total_cost: u64,
    currency: &str,
    approval_threshold_units: u64,
) -> ToolGrant {
    let mut grant = make_governed_monetary_grant(
        server,
        tool,
        max_cost_per_invocation,
        max_total_cost,
        currency,
        approval_threshold_units,
    );
    grant
        .constraints
        .push(Constraint::SellerExact(seller.to_string()));
    grant
}

fn make_governed_intent(
    id: &str,
    server: &str,
    tool: &str,
    purpose: &str,
    units: u64,
    currency: &str,
) -> GovernedTransactionIntent {
    GovernedTransactionIntent::tool_invocation(
        chio_core::capability::governance::GovernedToolInvocationIntentBody {
            id: id.to_string(),
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            purpose: purpose.to_string(),
            max_amount: Some(MonetaryAmount {
                units,
                currency: currency.to_string(),
            }),
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "invoice_id": "inv-1001",
                "operator": "finance-ops",
            })),
        },
    )
}

struct GovernedAcpIntentFixture<'a> {
    id: &'a str,
    server: &'a str,
    tool: &'a str,
    purpose: &'a str,
    seller: &'a str,
    shared_payment_token_id: &'a str,
    settlement_destination_ref: Option<&'a str>,
    units: u64,
    currency: &'a str,
}

fn make_governed_acp_intent(fixture: GovernedAcpIntentFixture<'_>) -> GovernedTransactionIntent {
    GovernedTransactionIntent::tool_invocation(
        chio_core::capability::governance::GovernedToolInvocationIntentBody {
            id: fixture.id.to_string(),
            server_id: fixture.server.to_string(),
            tool_name: fixture.tool.to_string(),
            purpose: fixture.purpose.to_string(),
            max_amount: Some(MonetaryAmount {
                units: fixture.units,
                currency: fixture.currency.to_string(),
            }),
            commerce: Some(chio_core::capability::governance::GovernedCommerceContext {
                seller: fixture.seller.to_string(),
                shared_payment_token_id: fixture.shared_payment_token_id.to_string(),
                settlement_destination_ref: fixture.settlement_destination_ref.map(str::to_string),
            }),
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "invoice_id": "inv-2002",
                "operator": "commerce-ops",
            })),
        },
    )
}

fn make_runtime_attestation(
    tier: RuntimeAssuranceTier,
) -> chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
    let now = current_unix_timestamp();
    chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.enterprise-verifier.json.v1".to_string(),
        verifier: "https://attest.chio.example".to_string(),
        tier,
        issued_at: now.saturating_sub(1),
        expires_at: now + 300,
        evidence_sha256: format!("digest-{tier:?}"),
        runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
        workload_identity: Some(
            chio_core::capability::workload_identity::WorkloadIdentity::parse_spiffe_uri(
                "spiffe://chio/runtime/test",
            )
            .expect("parse runtime workload identity"),
        ),
        claims: Some(serde_json::json!({
            "enterpriseVerifier": {
                "attestationType": "enterprise_confidential_vm",
                "hardwareModel": "AMD_SEV_SNP",
                "secureBoot": "enabled",
                "digest": format!("sha384:digest-{tier:?}")
            }
        })),
    }
}

fn make_trusted_azure_runtime_attestation(
) -> chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
    let now = current_unix_timestamp();
    chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test/".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "digest-azure-attestation".to_string(),
        runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "attestationType": "sgx"
            }
        })),
    }
}

fn make_trusted_google_runtime_attestation(
) -> chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
    let now = current_unix_timestamp();
    chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
        verifier: "https://confidentialcomputing.googleapis.com".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "digest-google-attestation".to_string(),
        runtime_identity: Some(
            "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1".to_string(),
        ),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "googleAttestation": {
                "attestationType": "confidential_vm",
                "hardwareModel": "GCP_AMD_SEV",
                "secureBoot": "enabled"
            }
        })),
    }
}

fn make_trusted_nitro_runtime_attestation(
) -> chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
    let now = current_unix_timestamp();
    chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.aws-nitro-attestation.v1".to_string(),
        verifier: "https://nitro.aws.example/".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "digest-nitro-attestation".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "awsNitro": {
                "moduleId": "nitro-enclave-1",
                "digest": "sha384:aws-measurement",
                "pcrs": { "0": "0123" }
            }
        })),
    }
}

fn make_attestation_trust_policy() -> chio_core::capability::trust_policy::AttestationTrustPolicy {
    chio_core::capability::trust_policy::AttestationTrustPolicy {
        rules: vec![
            chio_core::capability::trust_policy::AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: std::collections::BTreeMap::new(),
            },
            chio_core::capability::trust_policy::AttestationTrustRule {
                name: "google-confidential".to_string(),
                schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
                verifier: "https://confidentialcomputing.googleapis.com".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(
                    chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
                ),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: vec!["confidential_vm".to_string()],
                required_assertions: std::collections::BTreeMap::from([
                    ("hardwareModel".to_string(), "GCP_AMD_SEV".to_string()),
                    ("secureBoot".to_string(), "enabled".to_string()),
                ]),
            },
            chio_core::capability::trust_policy::AttestationTrustRule {
                name: "aws-nitro".to_string(),
                schema: "chio.runtime-attestation.aws-nitro-attestation.v1".to_string(),
                verifier: "https://nitro.aws.example".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AwsNitro),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: Vec::new(),
                required_assertions: std::collections::BTreeMap::from([(
                    "moduleId".to_string(),
                    "nitro-enclave-1".to_string(),
                )]),
            },
        ],
    }
}

fn make_attested_attestation_trust_policy(
) -> chio_core::capability::trust_policy::AttestationTrustPolicy {
    chio_core::capability::trust_policy::AttestationTrustPolicy {
        rules: vec![chio_core::capability::trust_policy::AttestationTrustRule {
            name: "azure-contoso-attested".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Attested,
            verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: Some(120),
            allowed_attestation_types: vec!["sgx".to_string()],
            required_assertions: std::collections::BTreeMap::new(),
        }],
    }
}

fn make_metered_billing_context(
    quote_id: &str,
    provider: &str,
    units: u64,
    currency: &str,
) -> chio_core::capability::governance::MeteredBillingContext {
    let now = current_unix_timestamp();
    chio_core::capability::governance::MeteredBillingContext {
        settlement_mode: chio_core::capability::governance::MeteredSettlementMode::AllowThenSettle,
        quote: chio_core::capability::governance::MeteredBillingQuote {
            quote_id: quote_id.to_string(),
            provider: provider.to_string(),
            billing_unit: "1k_tokens".to_string(),
            quoted_units: units,
            quoted_cost: MonetaryAmount {
                units: 60,
                currency: currency.to_string(),
            },
            issued_at: now.saturating_sub(5),
            expires_at: Some(now + 300),
        },
        max_billed_units: Some(units + 4),
        verified_outcome: None,
    }
}

fn make_governed_call_chain_context(
    chain_id: &str,
    parent_request_id: &str,
) -> GovernedCallChainContext {
    GovernedCallChainContext {
        chain_id: chain_id.to_string(),
        parent_request_id: parent_request_id.to_string(),
        parent_receipt_id: Some("rc-upstream-1".to_string()),
        origin_subject: "subject-origin".to_string(),
        delegator_subject: "subject-delegator".to_string(),
    }
}

fn make_governed_upstream_call_chain_proof(
    signer: &Keypair,
    subject: &PublicKey,
    call_chain: &GovernedCallChainContext,
) -> GovernedUpstreamCallChainProof {
    let now = current_unix_timestamp();
    GovernedUpstreamCallChainProof::sign(
        GovernedUpstreamCallChainProofBody {
            signer: signer.public_key(),
            subject: subject.clone(),
            chain_id: call_chain.chain_id.clone(),
            parent_request_id: call_chain.parent_request_id.clone(),
            parent_receipt_id: call_chain.parent_receipt_id.clone(),
            origin_subject: call_chain.origin_subject.clone(),
            delegator_subject: call_chain.delegator_subject.clone(),
            issued_at: now.saturating_sub(5),
            expires_at: now + 300,
        },
        signer,
    )
    .unwrap()
}

fn attach_governed_upstream_call_chain_proof(
    intent: &mut GovernedTransactionIntent,
    proof: &GovernedUpstreamCallChainProof,
) {
    let intent = intent.as_tool_invocation_mut().expect("tool intent");
    let mut context = match intent.context.take() {
        Some(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    context.insert(
        GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY.to_string(),
        serde_json::to_value(proof).unwrap(),
    );
    intent.context = Some(serde_json::Value::Object(context));
}

struct GovernedCallChainContinuationTokenFixture<'a> {
    signer: &'a Keypair,
    subject: &'a PublicKey,
    call_chain: &'a GovernedCallChainContext,
    parent_session_anchor: SessionAnchorReference,
    parent_receipt_hash: &'a str,
    server_id: &'a str,
    tool_name: &'a str,
    governed_intent_hash: Option<&'a str>,
}

fn make_governed_call_chain_continuation_token(
    fixture: GovernedCallChainContinuationTokenFixture<'_>,
) -> CallChainContinuationToken {
    let now = current_unix_timestamp();
    CallChainContinuationToken::sign(
        CallChainContinuationTokenBody {
            schema: chio_core::capability::governance::CHIO_CALL_CHAIN_CONTINUATION_SCHEMA
                .to_string(),
            token_id: "continuation-token-1".to_string(),
            signer: fixture.signer.public_key(),
            subject: fixture.subject.clone(),
            chain_id: fixture.call_chain.chain_id.clone(),
            parent_request_id: fixture.call_chain.parent_request_id.clone(),
            parent_receipt_id: fixture.call_chain.parent_receipt_id.clone(),
            parent_receipt_hash: Some(fixture.parent_receipt_hash.to_string()),
            parent_session_anchor: Some(fixture.parent_session_anchor),
            current_subject: fixture.subject.to_hex(),
            delegator_subject: fixture.call_chain.delegator_subject.clone(),
            origin_subject: fixture.call_chain.origin_subject.clone(),
            parent_capability_id: None,
            delegation_link_hash: None,
            governed_intent_hash: fixture.governed_intent_hash.map(str::to_string),
            audience: Some(CallChainContinuationAudience {
                server_id: fixture.server_id.to_string(),
                tool_name: fixture.tool_name.to_string(),
            }),
            nonce: Some("nonce-continuation-1".to_string()),
            issued_at: now.saturating_sub(5),
            expires_at: now + 300,
        },
        fixture.signer,
    )
    .unwrap()
}

fn attach_governed_call_chain_continuation_token(
    intent: &mut GovernedTransactionIntent,
    token: &CallChainContinuationToken,
) {
    let intent = intent.as_tool_invocation_mut().expect("tool intent");
    let mut context = match intent.context.take() {
        Some(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    context.insert(
        GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY.to_string(),
        serde_json::to_value(token).unwrap(),
    );
    intent.context = Some(serde_json::Value::Object(context));
}

fn make_governed_autonomy_context(
    tier: GovernedAutonomyTier,
    bond_id: Option<&str>,
) -> GovernedAutonomyContext {
    GovernedAutonomyContext {
        tier,
        delegation_bond_id: bond_id.map(str::to_string),
    }
}

struct CreditBondFixture<'a> {
    signer: &'a Keypair,
    cap: &'a CapabilityToken,
    server: &'a str,
    tool: &'a str,
    disposition: CreditBondDisposition,
    lifecycle_state: CreditBondLifecycleState,
    expires_at: u64,
    runtime_assurance_met: bool,
}

fn make_credit_bond(fixture: CreditBondFixture<'_>) -> SignedCreditBond {
    let now = current_unix_timestamp();
    let report = CreditBondReport {
        schema: CREDIT_BOND_REPORT_SCHEMA.to_string(),
        generated_at: now.saturating_sub(1),
        filters: ExposureLedgerQuery {
            capability_id: Some(fixture.cap.id.clone()),
            agent_subject: Some(fixture.cap.subject.to_hex()),
            tool_server: Some(fixture.server.to_string()),
            tool_name: Some(fixture.tool.to_string()),
            since: None,
            until: None,
            receipt_limit: Some(10),
            decision_limit: Some(5),
        },
        exposure: ExposureLedgerSummary {
            matching_receipts: 1,
            returned_receipts: 1,
            matching_decisions: 0,
            returned_decisions: 0,
            active_decisions: 0,
            superseded_decisions: 0,
            actionable_receipts: 0,
            pending_settlement_receipts: 0,
            failed_settlement_receipts: 0,
            currencies: vec!["USD".to_string()],
            mixed_currency_book: false,
            truncated_receipts: false,
            truncated_decisions: false,
        },
        scorecard: CreditScorecardSummary {
            matching_receipts: 1,
            returned_receipts: 1,
            matching_decisions: 0,
            returned_decisions: 0,
            currencies: vec!["USD".to_string()],
            mixed_currency_book: false,
            confidence: CreditScorecardConfidence::High,
            band: CreditScorecardBand::Prime,
            overall_score: 0.95,
            anomaly_count: 0,
            probationary: false,
        },
        disposition: fixture.disposition,
        prerequisites: CreditBondPrerequisites {
            active_facility_required: true,
            active_facility_met: true,
            runtime_assurance_met: fixture.runtime_assurance_met,
            certification_required: false,
            certification_met: true,
            currency_coherent: true,
        },
        support_boundary: CreditBondSupportBoundary {
            autonomy_gating_supported: true,
            ..CreditBondSupportBoundary::default()
        },
        latest_facility_id: Some("facility-1".to_string()),
        terms: None,
        findings: Vec::new(),
    };
    SignedCreditBond::sign(
        CreditBondArtifact {
            schema: CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
            bond_id: format!("bond-{}-{}-{}", fixture.server, fixture.tool, now),
            issued_at: now.saturating_sub(5),
            expires_at: fixture.expires_at,
            lifecycle_state: fixture.lifecycle_state,
            supersedes_bond_id: None,
            report,
        },
        fixture.signer,
    )
    .unwrap()
}

fn make_governed_approval_token(
    approver: &Keypair,
    subject: &PublicKey,
    intent: &GovernedTransactionIntent,
    request_id: &str,
) -> GovernedApprovalToken {
    let now = current_unix_timestamp();
    GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("approval-{request_id}"),
            approver: approver.public_key(),
            subject: subject.clone(),
            governed_intent_hash: intent.binding_hash().unwrap(),
            threshold_proposal_hash: None,
            request_id: request_id.to_string(),
            issued_at: now.saturating_sub(1),
            expires_at: now + 600,
            decision: GovernedApprovalDecision::Approved,
        },
        approver,
    )
    .unwrap()
}

fn install_durable_legacy_governed_admission_authorities(kernel: &mut ChioKernel) {
    kernel
        .set_admission_operation_store_handle(std::sync::Arc::new(ProfiledTestStore::new(
            AdmissionOperationStoreProfile::SingleNodeDurable,
        )))
        .expect("legacy governed operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("legacy governed approval store");
    kernel
        .set_budget_store_handle(durable_atomic_test_budget_store(
            "legacy-governed-payment-budget",
        ))
        .expect("legacy governed budget store");
}

// --- Monetary enforcement tests ---

#[derive(Clone)]
struct TrackingPaymentAdapter {
    inner: crate::payment::SimPaymentAdapter,
    authorized: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    captured: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    released: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    refunded: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl TrackingPaymentAdapter {
    fn new() -> Self {
        Self {
            inner: crate::payment::SimPaymentAdapter::new(),
            authorized: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            captured: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            released: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            refunded: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

impl PaymentAdapter for TrackingPaymentAdapter {
    fn rail_id(&self) -> &str {
        self.inner.rail_id()
    }

    fn supports_operation_authorization_recovery(&self) -> bool {
        self.inner.supports_operation_authorization_recovery()
    }

    fn supports_operation_payment_mutations(&self) -> bool {
        self.inner.supports_operation_payment_mutations()
    }

    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.authorized
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentAuthorization {
            authorization_id: "auth_tracking".to_string(),
            settled: false,
            metadata: serde_json::json!({ "adapter": "tracking" }),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.captured
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "tracking" }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.released
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "tracking" }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.refunded
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "tracking" }),
        })
    }

    fn authorize_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.authorized
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner
            .authorize_for_operation(operation_id, request_binding_hash, request)
    }

    fn lookup_authorization_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        self.inner
            .lookup_authorization_for_operation(operation_id, request_binding_hash)
    }

    fn capture_for_operation(
        &self,
        request: crate::payment::OperationPaymentCaptureRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        self.captured
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.capture_for_operation(request)
    }

    fn release_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.released
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.release_for_operation(
            operation_id,
            request_binding_hash,
            authorization_id,
            reference,
        )
    }

    fn refund_for_operation(
        &self,
        request: crate::payment::OperationPaymentRefundRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        self.refunded
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.refund_for_operation(request)
    }

    fn settlement_state_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<crate::payment::RailSettlementState, PaymentError> {
        self.inner.settlement_state_for_operation(
            operation_id,
            request_binding_hash,
            reference,
            authorization_id,
        )
    }
}

include!("support_monetary_tail.inc");
