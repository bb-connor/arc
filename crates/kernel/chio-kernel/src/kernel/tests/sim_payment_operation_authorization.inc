use crate::payment::PaymentJournalState;

#[derive(Clone, Copy)]
enum OrdinaryOperationAuthorizeScript {
    Preexisting,
    LoseAcknowledgement,
    DeclineWithoutAuthorization,
    LookupUnavailable,
    CleanupPending,
    LegacyUnavailable,
}

#[derive(Clone)]
struct OrdinaryOperationAuthorizationProbe {
    inner: std::sync::Arc<OrdinaryOperationAuthorizationProbeInner>,
}

struct OrdinaryOperationAuthorizationProbeInner {
    operation_id: String,
    request_binding_hash: String,
    authorization: std::sync::Mutex<Option<PaymentAuthorization>>,
    lose_acknowledgement: std::sync::atomic::AtomicBool,
    decline_without_authorization: bool,
    lookup_unavailable: bool,
    operation_authorizes: std::sync::atomic::AtomicUsize,
    legacy_authorizes: std::sync::atomic::AtomicUsize,
    lookups: std::sync::atomic::AtomicUsize,
    operation_releases: std::sync::atomic::AtomicUsize,
}

impl OrdinaryOperationAuthorizationProbe {
    fn new(
        operation_id: &str,
        request_binding_hash: &str,
        script: OrdinaryOperationAuthorizeScript,
    ) -> Self {
        let authorization = matches!(
            script,
            OrdinaryOperationAuthorizeScript::Preexisting
                | OrdinaryOperationAuthorizeScript::CleanupPending
        )
        .then(|| PaymentAuthorization {
            authorization_id: format!("ordinary-auth:{operation_id}"),
            settled: false,
            metadata: serde_json::json!({
                "operation_id": operation_id,
                "request_binding_hash": request_binding_hash,
            }),
        });
        Self {
            inner: std::sync::Arc::new(OrdinaryOperationAuthorizationProbeInner {
                operation_id: operation_id.to_string(),
                request_binding_hash: request_binding_hash.to_string(),
                authorization: std::sync::Mutex::new(authorization),
                lose_acknowledgement: std::sync::atomic::AtomicBool::new(matches!(
                    script,
                    OrdinaryOperationAuthorizeScript::LoseAcknowledgement
                )),
                decline_without_authorization: matches!(
                    script,
                    OrdinaryOperationAuthorizeScript::DeclineWithoutAuthorization
                ),
                lookup_unavailable: matches!(
                    script,
                    OrdinaryOperationAuthorizeScript::LookupUnavailable
                ),
                operation_authorizes: std::sync::atomic::AtomicUsize::new(0),
                legacy_authorizes: std::sync::atomic::AtomicUsize::new(0),
                lookups: std::sync::atomic::AtomicUsize::new(0),
                operation_releases: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    fn operation_authorizes(&self) -> usize {
        self.inner
            .operation_authorizes
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn legacy_authorizes(&self) -> usize {
        self.inner
            .legacy_authorizes
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn lookups(&self) -> usize {
        self.inner
            .lookups
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn operation_releases(&self) -> usize {
        self.inner
            .operation_releases
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn authorization_id(&self) -> String {
        format!("ordinary-auth:{}", self.inner.operation_id)
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
                "ordinary payment operation binding mismatch".to_string(),
            ));
        }
        Ok(())
    }
}

impl PaymentAdapter for OrdinaryOperationAuthorizationProbe {
    fn rail_id(&self) -> &str {
        "ordinary-operation-probe"
    }

    fn supports_operation_authorization_recovery(&self) -> bool {
        true
    }

    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.inner
            .legacy_authorizes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(PaymentError::Unavailable(
            "injected legacy authorization failure".to_string(),
        ))
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError(
            "unexpected legacy capture".to_string(),
        ))
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError(
            "unexpected legacy release".to_string(),
        ))
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError(
            "unexpected legacy refund".to_string(),
        ))
    }

    fn authorize_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.validate_operation(operation_id, request_binding_hash)?;
        if request.operation_id.as_deref() != Some(operation_id)
            || request.request_binding_hash.as_deref() != Some(request_binding_hash)
        {
            return Err(PaymentError::RailError(
                "ordinary authorization request omitted its exact operation binding".to_string(),
            ));
        }
        self.inner
            .operation_authorizes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.inner.decline_without_authorization {
            return Err(PaymentError::Declined(
                "injected authorization decline".to_string(),
            ));
        }
        let mut stored = self
            .inner
            .authorization
            .lock()
            .map_err(|_| PaymentError::Unavailable("authorization probe poisoned".to_string()))?;
        let authorization = stored.get_or_insert_with(|| PaymentAuthorization {
            authorization_id: format!("ordinary-auth:{operation_id}"),
            settled: false,
            metadata: serde_json::json!({
                "operation_id": operation_id,
                "request_binding_hash": request_binding_hash,
            }),
        });
        let authorization = authorization.clone();
        drop(stored);
        if self
            .inner
            .lose_acknowledgement
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(PaymentError::Unavailable(
                "authorization committed but its acknowledgement was lost".to_string(),
            ));
        }
        Ok(authorization)
    }

    fn lookup_authorization_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        self.validate_operation(operation_id, request_binding_hash)?;
        self.inner
            .lookups
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.inner.lookup_unavailable {
            return Err(PaymentError::Unavailable(
                "injected authorization lookup outage".to_string(),
            ));
        }
        self.inner
            .authorization
            .lock()
            .map(|authorization| authorization.clone())
            .map_err(|_| PaymentError::Unavailable("authorization probe poisoned".to_string()))
    }

    fn release_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.validate_operation(operation_id, request_binding_hash)?;
        if authorization_id != self.authorization_id() {
            return Err(PaymentError::RailError(
                "ordinary authorization cleanup named a different hold".to_string(),
            ));
        }
        self.inner
            .operation_releases
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: format!("released:{authorization_id}"),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }
}

struct OrdinaryOperationAuthorizationFixture {
    kernel: ChioKernel,
    request: ToolCallRequest,
    charge: BudgetChargeResult,
    binding: BudgetAdmissionOperationBinding,
    payment: OrdinaryOperationAuthorizationProbe,
    budget_store: std::sync::Arc<chio_store_sqlite::SqliteBudgetStore>,
    budget_db_path: std::path::PathBuf,
}

impl OrdinaryOperationAuthorizationFixture {
    fn new(
        prefix: &str,
        script: OrdinaryOperationAuthorizeScript,
        state: PaymentJournalState,
        exact_journal_binding: bool,
        operation_owned: bool,
    ) -> Self {
        use crate::budget_store::BudgetStore as _;

        let mut config = make_monetary_config();
        config.dispatch_intent_journal = crate::DispatchIntentJournalMode::SideEffecting;
        let mut kernel = make_kernel(config);
        let agent = Keypair::generate();
        let grant = make_governed_monetary_grant("cost-srv", "compute", 10, 1000, "USD", 50);
        let capability = kernel
            .issue_capability(&agent.public_key(), make_scope(vec![grant]), 3600)
            .expect("ordinary payment capability");
        let request_id = format!("request:{prefix}");
        let operation_id = format!("operation:{prefix}");
        let binding = BudgetAdmissionOperationBinding::new(operation_id.clone(), "ab".repeat(32))
            .expect("ordinary payment operation binding");
        let request = ToolCallRequest {
            request_id: request_id.clone(),
            capability: capability.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent.public_key().to_hex(),
            arguments: serde_json::json!({}),
            supplemental_authorization: None,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        };
        let mut charge = make_provisional_charge(10, "USD");
        charge.budget_hold_id = format!("hold:{prefix}");
        charge.admission_operation = operation_owned.then(|| binding.clone());
        let payment = OrdinaryOperationAuthorizationProbe::new(
            binding.operation_id(),
            binding.request_binding_hash(),
            script,
        );
        let budget_db_path = unique_receipt_db_path(prefix);
        let budget_store = std::sync::Arc::new(
            chio_store_sqlite::SqliteBudgetStore::open(&budget_db_path)
                .expect("ordinary payment budget store"),
        );
        kernel
            .set_budget_store_handle(
                std::sync::Arc::clone(&budget_store)
                    as std::sync::Arc<dyn crate::budget_store::BudgetStore>
            )
            .expect("ordinary payment budget store handle");
        kernel
            .set_payment_adapter(Box::new(payment.clone()))
            .expect("ordinary payment adapter");

        let journal_binding = if operation_owned {
            Some(if exact_journal_binding {
                binding.clone()
            } else {
                BudgetAdmissionOperationBinding::new(
                    format!("different:{operation_id}"),
                    "cd".repeat(32),
                )
                .expect("mismatched journal operation binding")
            })
        } else {
            None
        };
        let authorization_id = matches!(
            state,
            PaymentJournalState::Authorized | PaymentJournalState::Settling
        )
        .then(|| payment.authorization_id());
        budget_store
            .record_payment_journal(&crate::payment::PaymentJournalRecord {
                request_id,
                capability_id: capability.id,
                grant_index: 0,
                admission_operation: journal_binding,
                authority: None,
                hold_id: Some(charge.budget_hold_id.clone()),
                rail: payment.rail_id().to_string(),
                authorization_id,
                transaction_id: None,
                budget_exposure_units: charge.cost_charged,
                amount_units: charge.cost_charged,
                settle_action: (state == PaymentJournalState::Settling)
                    .then_some(crate::payment::PaymentSettleAction::Release),
                settle_amount_units: None,
                currency: charge.currency.clone(),
                state,
                created_at_unix_ms: 1,
                tenant_id: None,
            })
            .expect("ordinary payment journal predecessor");
        Self {
            kernel,
            request,
            charge,
            binding,
            payment,
            budget_store,
            budget_db_path,
        }
    }

    fn row(&self) -> crate::payment::PaymentJournalRecord {
        use crate::budget_store::BudgetStore as _;

        self.budget_store
            .get_payment_journal(&self.request.request_id)
            .expect("ordinary payment journal read")
            .expect("ordinary payment journal row")
    }
}

impl Drop for OrdinaryOperationAuthorizationFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.budget_db_path);
    }
}

#[test]
fn ordinary_operation_authorization_reuses_preexisting_exact_result() {
    let fixture = OrdinaryOperationAuthorizationFixture::new(
        "ordinary-auth-preexisting",
        OrdinaryOperationAuthorizeScript::Preexisting,
        PaymentJournalState::Authorized,
        true,
        true,
    );

    let authorization = fixture
        .kernel
        .authorize_payment_if_needed(
            &fixture.request,
            Some(&fixture.charge),
            Some(&fixture.binding),
        )
        .expect("preexisting operation authorization")
        .expect("payment authorization");

    assert_eq!(authorization.authorization_id, fixture.payment.authorization_id());
    assert_eq!(fixture.payment.lookups(), 1);
    assert_eq!(fixture.payment.operation_authorizes(), 0);
    assert_eq!(fixture.payment.operation_releases(), 0);
    assert_eq!(fixture.row().state, PaymentJournalState::Authorized);
}

#[test]
fn ordinary_operation_authorization_lost_ack_recovers_and_persists() {
    let fixture = OrdinaryOperationAuthorizationFixture::new(
        "ordinary-auth-lost-ack",
        OrdinaryOperationAuthorizeScript::LoseAcknowledgement,
        PaymentJournalState::HoldPlaced,
        true,
        true,
    );

    let authorization = fixture
        .kernel
        .authorize_payment_if_needed(
            &fixture.request,
            Some(&fixture.charge),
            Some(&fixture.binding),
        )
        .expect("lost authorization acknowledgement recovery")
        .expect("recovered payment authorization");

    assert_eq!(authorization.authorization_id, fixture.payment.authorization_id());
    assert_eq!(fixture.payment.lookups(), 2);
    assert_eq!(fixture.payment.operation_authorizes(), 1);
    assert_eq!(fixture.payment.operation_releases(), 0);
    let row = fixture.row();
    assert_eq!(row.state, PaymentJournalState::Authorized);
    assert_eq!(row.admission_operation.as_ref(), Some(&fixture.binding));
    assert_eq!(row.authorization_id.as_deref(), Some(authorization.authorization_id.as_str()));
}

#[test]
fn ordinary_operation_authorization_confirmed_none_preserves_original_error() {
    let fixture = OrdinaryOperationAuthorizationFixture::new(
        "ordinary-auth-none",
        OrdinaryOperationAuthorizeScript::DeclineWithoutAuthorization,
        PaymentJournalState::HoldPlaced,
        true,
        true,
    );

    let error = fixture
        .kernel
        .authorize_payment_if_needed(
            &fixture.request,
            Some(&fixture.charge),
            Some(&fixture.binding),
        )
        .expect_err("confirmed absence must preserve the rail decline");

    assert!(matches!(error, PaymentError::Declined(_)));
    assert_eq!(fixture.payment.lookups(), 2);
    assert_eq!(fixture.payment.operation_authorizes(), 1);
    assert_eq!(fixture.payment.operation_releases(), 0);
    assert_eq!(fixture.row().state, PaymentJournalState::HoldPlaced);
}

#[test]
fn ordinary_operation_authorization_lookup_unavailable_does_not_authorize() {
    let fixture = OrdinaryOperationAuthorizationFixture::new(
        "ordinary-auth-lookup-unavailable",
        OrdinaryOperationAuthorizeScript::LookupUnavailable,
        PaymentJournalState::HoldPlaced,
        true,
        true,
    );

    let error = fixture
        .kernel
        .authorize_payment_if_needed(
            &fixture.request,
            Some(&fixture.charge),
            Some(&fixture.binding),
        )
        .expect_err("unavailable lookup must fail before authorize");

    assert!(matches!(error, PaymentError::Unavailable(_)));
    assert_eq!(fixture.payment.lookups(), 1);
    assert_eq!(fixture.payment.operation_authorizes(), 0);
    assert_eq!(fixture.payment.operation_releases(), 0);
    assert_eq!(fixture.row().state, PaymentJournalState::HoldPlaced);
}

#[test]
fn ordinary_operation_authorization_rejects_mismatched_journal_binding() {
    let fixture = OrdinaryOperationAuthorizationFixture::new(
        "ordinary-auth-binding-mismatch",
        OrdinaryOperationAuthorizeScript::Preexisting,
        PaymentJournalState::HoldPlaced,
        false,
        true,
    );

    let error = fixture
        .kernel
        .authorize_payment_if_needed(
            &fixture.request,
            Some(&fixture.charge),
            Some(&fixture.binding),
        )
        .expect_err("a rebound payment journal must fail closed");

    assert!(error.to_string().contains("exact authorization operation"));
    assert_eq!(fixture.payment.lookups(), 1);
    assert_eq!(fixture.payment.operation_authorizes(), 0);
    assert_eq!(fixture.payment.operation_releases(), 0);
    assert_eq!(fixture.row().state, PaymentJournalState::HoldPlaced);
}

#[test]
fn ordinary_operation_authorization_resumes_committed_cleanup_instead_of_dispatching() {
    let fixture = OrdinaryOperationAuthorizationFixture::new(
        "ordinary-auth-cleanup-pending",
        OrdinaryOperationAuthorizeScript::CleanupPending,
        PaymentJournalState::Settling,
        true,
        true,
    );

    let error = fixture
        .kernel
        .authorize_payment_if_needed(
            &fixture.request,
            Some(&fixture.charge),
            Some(&fixture.binding),
        )
        .expect_err("a cleanup-owned authorization cannot return to dispatch");

    assert!(error.to_string().contains("advance to authorized failed"));
    assert_eq!(fixture.payment.lookups(), 1);
    assert_eq!(fixture.payment.operation_authorizes(), 0);
    assert_eq!(fixture.payment.operation_releases(), 1);
    let row = fixture.row();
    assert_eq!(row.state, PaymentJournalState::Settled);
    assert_eq!(row.settle_action, Some(crate::payment::PaymentSettleAction::Release));
}

#[test]
fn legacy_authorization_failure_is_single_shot_without_operation_lookup() {
    let fixture = OrdinaryOperationAuthorizationFixture::new(
        "legacy-auth-single-shot",
        OrdinaryOperationAuthorizeScript::LegacyUnavailable,
        PaymentJournalState::HoldPlaced,
        true,
        false,
    );

    let error = fixture
        .kernel
        .authorize_payment_if_needed(&fixture.request, Some(&fixture.charge), None)
        .expect_err("legacy authorization failure");

    assert!(matches!(error, PaymentError::Unavailable(_)));
    assert_eq!(fixture.payment.legacy_authorizes(), 1);
    assert_eq!(fixture.payment.lookups(), 0);
    assert_eq!(fixture.payment.operation_authorizes(), 0);
    assert_eq!(fixture.payment.operation_releases(), 0);
    assert_eq!(fixture.row().state, PaymentJournalState::HoldPlaced);
}

#[test]
fn ordinary_admission_activation_rejects_partial_operation_payment_adapter() {
    let mut kernel = make_kernel(make_monetary_config());
    let payment = OrdinaryOperationAuthorizationProbe::new(
        "activation-operation",
        &"ab".repeat(32),
        OrdinaryOperationAuthorizeScript::Preexisting,
    );
    kernel
        .set_payment_adapter(Box::new(payment))
        .expect("pre-activation adapter install");

    let error = kernel
        .enable_aggregate_invocation_admission()
        .expect_err("partial operation payment adapter must reject at activation");
    assert!(error
        .to_string()
        .contains("operation-bound payment mutations"));
}
