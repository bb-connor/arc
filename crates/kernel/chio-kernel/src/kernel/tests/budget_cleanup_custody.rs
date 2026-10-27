use super::*;
use crate::budget_store::{BudgetHoldAuthorizationRecord, BudgetHoldCleanupCustody};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A bool-returning backend that inherits the default rich authorization method.
struct LegacyBudgetStore {
    inner: InMemoryBudgetStore,
}

impl BudgetStore for LegacyBudgetStore {
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

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner
            .reverse_charge_cost(capability_id, grant_index, cost_units)
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

    delegate_authority_fenced_budget_methods!(inner);

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

fn authorize_request(capability_id: &str) -> BudgetAuthorizeHoldRequest {
    BudgetAuthorizeHoldRequest {
        capability_id: capability_id.to_string(),
        grant_index: 0,
        max_invocations: None,
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(1_000),
        hold_id: Some("cleanup-custody-hold".to_string()),
        event_id: Some("cleanup-custody-hold:authorize".to_string()),
        authority: None,
    }
}

fn authorized(
    store: &dyn BudgetStore,
    request: BudgetAuthorizeHoldRequest,
) -> Result<BudgetHoldAuthorizationRecord, Box<dyn std::error::Error>> {
    match store.authorize_budget_hold(request)? {
        BudgetAuthorizeHoldDecision::Authorized(record) => Ok(record),
        other => Err(std::io::Error::other(format!("unexpected decision: {other:?}")).into()),
    }
}

fn charge(record: BudgetHoldAuthorizationRecord) -> BudgetChargeResult {
    BudgetChargeResult {
        cleanup_custody: record.cleanup_custody,
        grant_index: 0,
        cost_charged: record.authorized_exposure_units,
        currency: "USD".to_string(),
        budget_total: Some(1_000),
        new_committed_cost_units: record.committed_cost_units_after,
        budget_hold_id: record.hold_id.expect("authorized hold identity"),
        authorize_metadata: record.metadata,
        invocation_capture: None,
    }
}

fn exercise_cleanup(replay: bool, legacy: bool) -> TestResult {
    let mut kernel = make_kernel(make_monetary_config());
    if legacy {
        kernel.set_budget_store(Box::new(LegacyBudgetStore {
            inner: InMemoryBudgetStore::new(),
        }));
    }
    let agent = make_keypair();
    let cap = kernel.issue_capability(
        &agent.public_key(),
        make_scope(vec![make_monetary_grant(
            "cost-srv", "compute", 100, 1_000, "USD",
        )]),
        300,
    )?;
    let request = make_request("cleanup-custody-request", &cap, "compute", "cost-srv");
    let budget_request = authorize_request(&cap.id);
    let first = authorized(kernel.budget_store.as_ref(), budget_request.clone())?;
    let record = if replay {
        let replayed = authorized(kernel.budget_store.as_ref(), budget_request)?;
        let mut expected = first;
        expected.cleanup_custody = if legacy {
            BudgetHoldCleanupCustody::Unknown
        } else {
            assert_eq!(expected.cleanup_custody, BudgetHoldCleanupCustody::Fresh);
            BudgetHoldCleanupCustody::Replayed
        };
        assert_eq!(
            replayed, expected,
            "replay preserves every persisted decision field"
        );
        replayed
    } else {
        first
    };
    let expected_custody = if legacy {
        BudgetHoldCleanupCustody::Unknown
    } else if replay {
        BudgetHoldCleanupCustody::Replayed
    } else {
        BudgetHoldCleanupCustody::Fresh
    };
    assert_eq!(record.cleanup_custody, expected_custody);
    let charge = charge(record);
    let adapter = TrackingPaymentAdapter::new();
    let released = Arc::clone(&adapter.released);
    let refunded = Arc::clone(&adapter.refunded);
    let authorization = adapter.authorize(&PaymentAuthorizeRequest {
        amount_units: 100,
        currency: "USD".to_string(),
        payer: "cleanup-custody-payer".to_string(),
        payee: "cleanup-custody-payee".to_string(),
        reference: request.request_id.clone(),
        governed: None,
        commerce: None,
        x402: None,
        authority_expires_at: None,
        reference_is_durable: false,
    })?;
    kernel.set_payment_adapter(Box::new(adapter));

    let outcome = kernel.unwind_pre_dispatch_monetary_invocation_with_evidence(
        &request,
        &cap,
        Some(&charge),
        Some(&authorization),
        None,
        crate::payment::PaymentCredentialDisposition::NonePresent,
    );
    if expected_custody == BudgetHoldCleanupCustody::Fresh {
        let (reversed, evidence) = outcome.map_err(|failure| *failure.error)?;
        assert!(reversed.is_some());
        assert!(evidence.is_some());
        assert_eq!(released.load(Ordering::SeqCst), 1);
    } else {
        let refusal = format!(
            "budget hold cleanup requires fresh custody; current call custody is {}",
            charge.cleanup_custody.as_str()
        );
        let custody_refused = |error: &KernelError| {
            matches!(error, KernelError::BudgetStore(
                crate::budget_store::BudgetStoreError::Invariant(reason)
            ) if reason == &refusal)
        };
        assert!(matches!(&outcome, Err(failure) if custody_refused(&failure.error)));
        assert!(kernel
            .reverse_budget_charge(&cap.id, &charge)
            .err()
            .is_some_and(|error| custody_refused(&error)));
        assert_eq!(released.load(Ordering::SeqCst), 0);
    }
    assert_eq!(refunded.load(Ordering::SeqCst), 0);
    let usage = kernel
        .budget_store
        .get_usage(&cap.id, 0)?
        .expect("budget usage");
    assert_eq!(
        usage.committed_cost_units()?,
        if expected_custody == BudgetHoldCleanupCustody::Fresh {
            0
        } else {
            100
        }
    );
    Ok(())
}

#[test]
fn fresh_ordinary_authorization_can_release_and_reverse() -> TestResult {
    exercise_cleanup(false, false)
}

#[test]
fn replayed_ordinary_authorization_retains_budget_and_payment() -> TestResult {
    exercise_cleanup(true, false)
}

#[test]
fn default_backend_never_claims_fresh_cleanup_custody() -> TestResult {
    for replay in [false, true] {
        exercise_cleanup(replay, true)?;
    }
    Ok(())
}
