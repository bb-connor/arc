use super::*;

#[derive(Default)]
pub(super) struct RailCalls {
    pub(super) release_failed: std::sync::atomic::AtomicBool,
    pub(super) capture_pending: std::sync::atomic::AtomicBool,
    pub(super) authorization_failed: std::sync::atomic::AtomicBool,
    pub(super) query_supported: std::sync::atomic::AtomicBool,
    pub(super) authorizations: Mutex<Vec<String>>,
    pub(super) queries: Mutex<Vec<String>>,
    pub(super) releases: Mutex<Vec<String>>,
    pub(super) refunds: Mutex<Vec<(String, u64, String, String)>>,
    pub(super) captures: Mutex<Vec<(String, u64)>>,
}

pub(super) struct RecoveryRail {
    pub(super) prepaid: bool,
    pub(super) calls: Arc<RailCalls>,
}

impl PaymentAdapter for RecoveryRail {
    fn rail_id(&self) -> &'static str {
        "review-payment-rail"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(if self.prepaid {
            PaymentRailMode::PrepaidFinal
        } else {
            PaymentRailMode::ReversibleHold
        })
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.calls
            .authorizations
            .lock()
            .map_err(|_| PaymentError::RailError("test lock".into()))?
            .push(request.reference.clone());
        if self
            .calls
            .authorization_failed
            .swap(false, Ordering::SeqCst)
        {
            return Err(PaymentError::Unavailable(
                "authorization acknowledgement lost".into(),
            ));
        }
        Ok(PaymentAuthorization {
            authorization_id: "original-payment-authorization".into(),
            state: if self.prepaid {
                PaymentAuthorizationState::PrepaidFinal
            } else {
                PaymentAuthorizationState::Held
            },
            metadata: serde_json::json!({}),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        _currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls
            .captures
            .lock()
            .map_err(|_| PaymentError::RailError("test lock".into()))?
            .push((reference.to_owned(), amount_units));
        Ok(PaymentResult {
            transaction_id: authorization_id.into(),
            settlement_status: if self.calls.capture_pending.swap(false, Ordering::SeqCst) {
                RailSettlementStatus::Pending
            } else {
                RailSettlementStatus::Captured
            },
            metadata: serde_json::json!({}),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls
            .releases
            .lock()
            .map_err(|_| PaymentError::RailError("test lock".into()))?
            .push(reference.to_owned());
        if self.calls.release_failed.swap(false, Ordering::SeqCst) {
            return Err(PaymentError::Unavailable(
                "temporary release failure".into(),
            ));
        }
        Ok(PaymentResult {
            transaction_id: authorization_id.into(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls
            .refunds
            .lock()
            .map_err(|_| PaymentError::RailError("test lock".into()))?
            .push((
                transaction_id.into(),
                amount_units,
                currency.into(),
                reference.into(),
            ));
        Ok(PaymentResult {
            transaction_id: "original-payment-refund".into(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({}),
        })
    }

    fn settlement_state(
        &self,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<crate::payment::RailSettlementState, PaymentError> {
        self.calls
            .queries
            .lock()
            .map_err(|_| PaymentError::RailError("query lock".into()))?
            .push(reference.into());
        if !self.calls.query_supported.load(Ordering::SeqCst) {
            return Err(PaymentError::Unavailable(
                "query deliberately unsupported".into(),
            ));
        }
        if authorization_id.is_some() {
            return Err(PaymentError::RailError(
                "recovery must query the original reference".into(),
            ));
        }
        let authorized = self
            .calls
            .authorizations
            .lock()
            .map_err(|_| PaymentError::RailError("authorization lock".into()))?;
        if !authorized.iter().any(|known| known == reference) {
            return Ok(crate::payment::RailSettlementState::NoAuthorization);
        }
        Ok(crate::payment::RailSettlementState::Held {
            authorization_id: "original-payment-authorization".into(),
        })
    }
}

pub(super) fn payment_fixture(
    name: &str,
    prepaid: bool,
) -> (
    ChioKernel,
    ToolCallRequest,
    Arc<TestAdmissionOperationStore>,
    Arc<AtomicU64>,
    Arc<RailCalls>,
) {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".into(),
    });
    grant.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".into(),
    });
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture_with_grants(name, vec![grant]);
    let calls = Arc::new(RailCalls::default());
    kernel.set_payment_adapter(Box::new(RecoveryRail {
        prepaid,
        calls: calls.clone(),
    }));
    (kernel, request, store, invocations, calls)
}

pub(super) fn authorize_without_dispatch(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
) -> TestResult {
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )?;
    let now = current_unix_timestamp_ms();
    let mut admission = kernel
        .begin_durable_tool_admission(request, &matching, now)?
        .ok_or("durable admission")?;
    let (_, mutation) = kernel
        .check_and_increment_budget(
            request,
            &request.capability,
            &matching,
            false,
            Some(&mut admission),
            now,
        )?
        .into_authorized()?;
    kernel
        .authorize_payment_if_needed(
            request,
            mutation.charge_result(),
            Some(&admission),
            now,
            None,
        )?
        .ok_or("payment authorization")?;
    Ok(())
}

pub(super) fn assert_released_budget(store: &TestAdmissionOperationStore) -> TestResult {
    let operation = store.operation();
    let hold = store
        .budget_store()
        .get_budget_hold(operation.budget_hold_id().ok_or("hold ID")?.as_str())?
        .ok_or("original hold")?;
    assert_eq!(
        hold.disposition,
        crate::budget_store::BudgetHoldDispositionView::Reversed
    );
    assert_eq!(hold.remaining_exposure_units, 0);
    Ok(())
}

pub(super) struct PrepaymentRefusalHook(pub(super) Arc<TestAdmissionOperationStore>);

impl crate::post_invocation::PostInvocationHook for PrepaymentRefusalHook {
    fn name(&self) -> &str {
        "review-refuse-after-prepayment"
    }

    fn inspect(
        &self,
        _: &crate::post_invocation::PostInvocationContext<'_>,
        _: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        crate::post_invocation::PostInvocationVerdict::Allow
    }

    fn durable_identity(
        &self,
    ) -> Result<Option<crate::post_invocation::PostInvocationHookIdentity>, String> {
        if self
            .0
            .payment_journal()
            .is_some_and(|journal| journal.authorization_id.is_some())
        {
            return Err("refused after original prepayment".into());
        }
        crate::post_invocation::PostInvocationHookIdentity::from_canonical_config(
            self.name(),
            "1",
            "chio.tests.payment-recovery",
            &(),
        )
        .map(Some)
    }
}
