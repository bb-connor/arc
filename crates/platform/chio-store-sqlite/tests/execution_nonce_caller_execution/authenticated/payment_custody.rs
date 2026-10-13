use super::*;
use chio_core::capability::governance::{
    GovernedTransactionIntent, MeteredBillingContext, MeteredBillingQuote, MeteredSettlementMode,
};
use chio_core::capability::scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant};
use chio_kernel::admission_operation::{AdmissionRecoveryError, AdmissionRecoveryFailureKind};
use chio_kernel::caller_delivery::SignedCallerDeliveryReportV1;
use chio_kernel::payment::{
    PaymentAdapter, PaymentAuthorization, PaymentAuthorizationState, PaymentAuthorizeRequest,
    PaymentError, PaymentJournalRecord, PaymentJournalState, PaymentRailMode, PaymentResult,
    PaymentSettleAction, RailSettlementState,
};
use chio_kernel::receipt_store::QualifiedAdmissionProjectionStore;
use chio_kernel::{BudgetStore, KernelError, ToolInvocationCost};
use chio_store_sqlite::SqliteFindingOperatorPaymentAdapter;
use std::sync::{atomic::AtomicBool, atomic::AtomicUsize, Arc};

const FAULT: &str = "payment-custody-fault";

#[derive(Clone, Copy, Debug)]
pub(super) enum CaptureFault {
    Unavailable,
    RailError,
    Declined,
    InsufficientFunds,
    LostAcknowledgement,
    Panic,
}

impl CaptureFault {
    fn error(self) -> PaymentError {
        match self {
            Self::Unavailable | Self::LostAcknowledgement => {
                PaymentError::Unavailable(FAULT.into())
            }
            Self::RailError => PaymentError::RailError(FAULT.into()),
            Self::Declined => PaymentError::Declined(FAULT.into()),
            Self::InsufficientFunds => PaymentError::InsufficientFunds,
            Self::Panic => panic!("{FAULT}"),
        }
    }

    fn captures(self) -> bool {
        matches!(self, Self::LostAcknowledgement | Self::Panic)
    }
}

#[derive(Default)]
struct Calls {
    authorizations: AtomicUsize,
    captures: AtomicUsize,
    releases: AtomicUsize,
    refunds: AtomicUsize,
    fault_enabled: AtomicBool,
}

struct Rail {
    inner: SqliteFindingOperatorPaymentAdapter,
    calls: Arc<Calls>,
    fault: Option<CaptureFault>,
    prepaid: bool,
    decline: bool,
}

impl PaymentAdapter for Rail {
    fn rail_id(&self) -> &'static str {
        if self.prepaid {
            "caller-prepaid-custody"
        } else {
            "caller-held-custody"
        }
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
        self.calls.authorizations.fetch_add(1, Ordering::SeqCst);
        if self.decline {
            return Err(PaymentError::Declined(FAULT.into()));
        }
        let mut authorization = self.inner.authorize(request)?;
        if self.prepaid {
            let captured = self.capture(
                &authorization.authorization_id,
                request.amount_units,
                &request.currency,
                &request.reference,
            )?;
            authorization.authorization_id = captured.transaction_id;
            authorization.state = PaymentAuthorizationState::PrepaidFinal;
        }
        Ok(authorization)
    }

    fn capture(
        &self,
        authorization: &str,
        amount: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls.captures.fetch_add(1, Ordering::SeqCst);
        if self.calls.fault_enabled.load(Ordering::SeqCst) {
            if let Some(fault) = self.fault {
                if fault.captures() {
                    self.inner
                        .capture(authorization, amount, currency, reference)?;
                }
                return Err(fault.error());
            }
        }
        self.inner
            .capture(authorization, amount, currency, reference)
    }

    fn release(&self, authorization: &str, reference: &str) -> Result<PaymentResult, PaymentError> {
        self.calls.releases.fetch_add(1, Ordering::SeqCst);
        self.inner.release(authorization, reference)
    }

    fn refund(
        &self,
        transaction: &str,
        amount: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.calls.refunds.fetch_add(1, Ordering::SeqCst);
        self.inner.refund(transaction, amount, currency, reference)
    }

    fn settlement_state(
        &self,
        _reference: &str,
        _authorization: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        if self.decline {
            Ok(RailSettlementState::NoAuthorization)
        } else {
            Err(PaymentError::Unavailable(FAULT.into()))
        }
    }
}

pub(super) struct Harness {
    pub(super) fixture: Fixture,
    key: Keypair,
    calls: Arc<Calls>,
    prepaid: bool,
    fault: Option<CaptureFault>,
    decline: bool,
}

impl Harness {
    pub(super) fn new(
        prepaid: bool,
        fault: Option<CaptureFault>,
        decline: bool,
    ) -> TestResult<Self> {
        let (fixture, key) = fixture()?;
        let calls = Arc::new(Calls::default());
        calls.fault_enabled.store(fault.is_some(), Ordering::SeqCst);
        Ok(Self {
            fixture,
            key,
            calls,
            prepaid,
            fault,
            decline,
        })
    }

    pub(super) fn open(&self) -> TestResult<Runtime> {
        let mut runtime = self.fixture.open_with_reconcile(false)?;
        Arc::get_mut(&mut runtime.kernel)
            .ok_or("exclusive kernel")?
            .set_payment_adapter(Box::new(Rail {
                inner: SqliteFindingOperatorPaymentAdapter::open(
                    self.fixture.directory.path().join("custody-payments.db"),
                )?,
                calls: self.calls.clone(),
                fault: self.fault,
                prepaid: self.prepaid,
                decline: self.decline,
            }));
        Ok(runtime)
    }

    fn reserve(&self, runtime: &Runtime) -> TestResult<ToolCallRequest> {
        let mut request = self.fixture.request(runtime, "payment-custody")?;
        request.capability = runtime.kernel.issue_capability(
            &self.fixture.agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: SERVER_ID.into(),
                    tool_name: TOOL_NAME.into(),
                    operations: vec![Operation::Invoke],
                    constraints: if self.prepaid {
                        vec![Constraint::GovernedIntentRequired]
                    } else {
                        Vec::new()
                    },
                    max_invocations: Some(1),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".into(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".into(),
                    }),
                    dpop_required: None,
                }],
                ..Default::default()
            },
            600,
        )?;
        if self.prepaid {
            request.governed_intent = Some(GovernedTransactionIntent {
                id: "caller-prepaid-intent".into(),
                server_id: SERVER_ID.into(),
                tool_name: TOOL_NAME.into(),
                purpose: "prepaid invocation".into(),
                max_amount: Some(MonetaryAmount {
                    units: 100,
                    currency: "USD".into(),
                }),
                commerce: None,
                metered_billing: Some(MeteredBillingContext {
                    settlement_mode: MeteredSettlementMode::MustPrepay,
                    quote: MeteredBillingQuote {
                        quote_id: "caller-prepaid-quote".into(),
                        provider: "caller-payment-custody".into(),
                        billing_unit: "invocation".into(),
                        quoted_units: 1,
                        quoted_cost: MonetaryAmount {
                            units: 100,
                            currency: "USD".into(),
                        },
                        issued_at: request.capability.issued_at,
                        expires_at: Some(request.capability.expires_at),
                    },
                    max_billed_units: Some(1),
                    verified_outcome: None,
                }),
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: None,
                body: Default::default(),
            });
        }
        let reserved = runtime.kernel.reserve_caller_execution_blocking(&request)?;
        assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
        assert!(reserved.receipt.verify_signature()?);
        assert!(matches!(
            reserved.terminal_state,
            OperationTerminalState::Incomplete { .. }
        ));
        request.execution_nonce = Some(*reserved.execution_nonce.ok_or("reserved nonce")?);
        assert_state(&self.fixture, &request, "ready_to_dispatch")?;
        self.assert_calls(0, 0, 0, 0);
        assert_eq!(self.committed(runtime, &request)?, 100);
        assert_eq!(self.fixture.invocations.load(Ordering::SeqCst), 0);
        Ok(request)
    }

    fn report(
        &self,
        authorization: &SignedCallerDispatchAuthorizationV1,
    ) -> TestResult<SignedCallerDeliveryReportV1> {
        let ledger = crate::authenticated::ledger(&self.fixture)?;
        Ok(ledger.execute_once(
            authorization,
            &self.fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &self.key,
            || {
                Ok(CallerExecutionReport {
                    output: serde_json::json!({"external": true}),
                    realized_cost: Some(ToolInvocationCost {
                        units: 100,
                        currency: "USD".into(),
                        breakdown: None,
                    }),
                })
            },
        )?)
    }

    pub(super) fn journal(
        &self,
        runtime: &Runtime,
        request: &ToolCallRequest,
    ) -> TestResult<PaymentJournalRecord> {
        let (id, _) = operation_state(&self.fixture, &request.request_id)?.ok_or("operation")?;
        runtime
            .authority
            .admission_operation_store()
            .load_payment_journal(&id, &runtime.authority.mutation_fence())?
            .ok_or_else(|| "payment journal".into())
    }

    pub(super) fn committed(
        &self,
        runtime: &Runtime,
        request: &ToolCallRequest,
    ) -> TestResult<u64> {
        Ok(runtime
            .authority
            .budget_store()
            .get_usage(&request.capability.id, 0)?
            .ok_or("budget usage")?
            .committed_cost_units()?)
    }

    pub(super) fn captured_payments(&self) -> TestResult<u64> {
        Ok(SqliteFindingOperatorPaymentAdapter::open(
            self.fixture.directory.path().join("custody-payments.db"),
        )?
        .capture_count()?)
    }

    pub(super) fn assert_calls(
        &self,
        authorizations: usize,
        captures: usize,
        releases: usize,
        refunds: usize,
    ) {
        assert_eq!(
            self.calls.authorizations.load(Ordering::SeqCst),
            authorizations
        );
        assert_eq!(self.calls.captures.load(Ordering::SeqCst), captures);
        assert_eq!(self.calls.releases.load(Ordering::SeqCst), releases);
        assert_eq!(self.calls.refunds.load(Ordering::SeqCst), refunds);
    }
}

fn assert_capture_error(error: &KernelError, fault: CaptureFault) {
    let KernelError::AdmissionRecovery(failure) = error else {
        panic!("{error:?}")
    };
    let AdmissionRecoveryError::Payment { kind, source } = failure.as_ref() else {
        panic!("{failure:?}")
    };
    let expected_kind = if matches!(fault, CaptureFault::RailError | CaptureFault::Panic) {
        AdmissionRecoveryFailureKind::ContractChanged
    } else {
        AdmissionRecoveryFailureKind::ParticipantUnavailable
    };
    assert_eq!(*kind, expected_kind);
    match (fault, source) {
        (
            CaptureFault::Unavailable | CaptureFault::LostAcknowledgement,
            PaymentError::Unavailable(detail),
        )
        | (CaptureFault::RailError, PaymentError::RailError(detail))
        | (CaptureFault::Declined, PaymentError::Declined(detail)) => assert_eq!(detail, FAULT),
        (CaptureFault::InsufficientFunds, PaymentError::InsufficientFunds) => {}
        (CaptureFault::Panic, PaymentError::RailError(detail)) => assert_eq!(
            detail,
            "payment adapter retained settlement panicked; outcome unknown"
        ),
        _ => panic!("{source:?}"),
    }
}

#[test]
fn authenticated_capture_errors_retain_payment_custody_until_original_settlement() -> TestResult {
    for fault in [
        CaptureFault::Unavailable,
        CaptureFault::RailError,
        CaptureFault::Declined,
        CaptureFault::InsufficientFunds,
        CaptureFault::LostAcknowledgement,
        CaptureFault::Panic,
    ] {
        let harness = Harness::new(false, Some(fault), false)?;
        let runtime = harness.open()?;
        let request = harness.reserve(&runtime)?;
        let authorization = start(&runtime, &request)?;
        harness.assert_calls(1, 0, 0, 0);
        let report = harness.report(&authorization)?;
        let error = runtime
            .kernel
            .reconcile_authenticated_caller_execution_blocking(&authorization, &report)
            .err()
            .ok_or("ambiguous capture published output")?;
        assert_capture_error(&error, fault);
        assert_state(&harness.fixture, &request, "finalizing")?;
        let journal = harness.journal(&runtime, &request)?;
        assert_eq!(journal.state, PaymentJournalState::Settling);
        assert_eq!(journal.settle_action, Some(PaymentSettleAction::Capture));
        assert_eq!(journal.settle_amount_units, Some(100));
        assert_eq!(harness.committed(&runtime, &request)?, 100);
        assert_eq!(harness.captured_payments()?, u64::from(fault.captures()));
        harness.assert_calls(1, 1, 0, 0);
        assert_eq!(authorization, start(&runtime, &request)?);
        harness.assert_calls(1, 1, 0, 0);
        drop(runtime);
        harness.calls.fault_enabled.store(false, Ordering::SeqCst);
        let reopened = harness.open()?;
        let settled = reopened
            .kernel
            .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
        assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
        assert!(settled.receipt.verify_signature()?);
        let replay = reopened
            .kernel
            .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
        assert_eq!(canonical(&settled.receipt)?, canonical(&replay.receipt)?);
        assert_eq!(harness.captured_payments()?, 1);
        assert_eq!(
            harness.journal(&reopened, &request)?.state,
            PaymentJournalState::Settled
        );
        assert_eq!(harness.committed(&reopened, &request)?, 100);
        harness.assert_calls(1, 2, 0, 0);
        assert_eq!(harness.fixture.invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn prepaid_start_uncertainty_withholds_execution_authority_and_retains_debit() -> TestResult {
    for fault in [CaptureFault::LostAcknowledgement, CaptureFault::Panic] {
        let harness = Harness::new(true, Some(fault), false)?;
        let runtime = harness.open()?;
        let request = harness.reserve(&runtime)?;
        let result = runtime.kernel.start_caller_execution_blocking(
            request.execution_nonce.as_ref().ok_or("nonce")?,
            &request.arguments,
        )?;
        let CallerStartResponse::Denied(denied) = result else {
            return Err("uncertain prepayment authorized execution".into());
        };
        assert_eq!(denied.verdict, Verdict::Deny);
        let code = if matches!(fault, CaptureFault::Panic) {
            "rail_error"
        } else {
            "unavailable"
        };
        assert_eq!(
            denied.reason.as_deref(),
            Some(format!("payment authorization failed: {code}").as_str())
        );
        assert!(denied.output.is_none());
        assert!(denied.receipt.verify_signature()?);
        assert_eq!(harness.captured_payments()?, 1);
        assert_eq!(harness.committed(&runtime, &request)?, 100);
        harness.assert_calls(1, 1, 0, 0);
        let retry = runtime.kernel.start_caller_execution_blocking(
            request.execution_nonce.as_ref().ok_or("nonce")?,
            &request.arguments,
        );
        assert!(matches!(retry, Err(KernelError::DurableAdmission(reason))
            if reason == "caller start requires a ready original reservation"));
        assert_eq!(harness.captured_payments()?, 1);
        assert_eq!(harness.committed(&runtime, &request)?, 100);
        harness.assert_calls(1, 1, 0, 0);
        assert_eq!(harness.fixture.invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn prepaid_start_settles_once_before_signed_authority_is_published() -> TestResult {
    let harness = Harness::new(true, None, false)?;
    let runtime = harness.open()?;
    let request = harness.reserve(&runtime)?;
    let authorization = start(&runtime, &request)?;
    assert_eq!(harness.captured_payments()?, 1);
    assert_eq!(
        harness.journal(&runtime, &request)?.state,
        PaymentJournalState::Settled
    );
    assert_eq!(authorization, start(&runtime, &request)?);
    harness.assert_calls(1, 1, 0, 0);
    let report = harness.report(&authorization)?;
    let settled = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert!(settled.receipt.verify_signature()?);
    let replay = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(canonical(&settled.receipt)?, canonical(&replay.receipt)?);
    assert_eq!(harness.captured_payments()?, 1);
    assert_eq!(harness.committed(&runtime, &request)?, 100);
    harness.assert_calls(1, 1, 0, 0);
    assert_eq!(harness.fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn prepaid_authorization_decline_releases_budget_without_execution_authority() -> TestResult {
    let harness = Harness::new(true, None, true)?;
    let runtime = harness.open()?;
    let request = harness.reserve(&runtime)?;
    let result = runtime.kernel.start_caller_execution_blocking(
        request.execution_nonce.as_ref().ok_or("nonce")?,
        &request.arguments,
    )?;
    let CallerStartResponse::Denied(denied) = result else {
        return Err("declined prepayment authorized execution".into());
    };
    assert_eq!(denied.verdict, Verdict::Deny);
    assert_eq!(
        denied.reason.as_deref(),
        Some("payment authorization failed: declined")
    );
    assert!(denied.output.is_none());
    assert!(denied.receipt.verify_signature()?);
    assert_eq!(harness.committed(&runtime, &request)?, 0);
    assert_eq!(harness.captured_payments()?, 0);
    assert_state(&harness.fixture, &request, "compensated_before_dispatch")?;
    harness.assert_calls(1, 0, 0, 0);
    assert_eq!(harness.fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
