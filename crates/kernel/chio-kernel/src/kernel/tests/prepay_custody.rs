use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AUTHORIZATION_ID: &str = "prepay-custody-authorization";
const CAPTURE_ID: &str = "prepay-custody-capture";
const SENSITIVE_ERROR: &str = "sensitive-prepay-capture-detail";

#[derive(Clone, Copy, Debug)]
enum ErrorKind {
    Unavailable,
    RailError,
    Declined,
    InsufficientFunds,
}

impl ErrorKind {
    fn error(self) -> PaymentError {
        match self {
            Self::Unavailable => PaymentError::Unavailable(SENSITIVE_ERROR.to_string()),
            Self::RailError => PaymentError::RailError(SENSITIVE_ERROR.to_string()),
            Self::Declined => PaymentError::Declined(SENSITIVE_ERROR.to_string()),
            Self::InsufficientFunds => PaymentError::InsufficientFunds,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::RailError => "rail_error",
            Self::Declined => "declined",
            Self::InsufficientFunds => "insufficient_funds",
        }
    }
}

fn prepayment_evidence() -> serde_json::Value {
    serde_json::json!({
        "adapter": "test-prepayment-custody",
        "settlement": "pending",
        "transaction": "prepay-custody-broadcast",
    })
}

#[derive(Clone, Copy)]
enum Mode {
    CaptureError(ErrorKind),
    CapturedThenAcknowledgementLost,
    CapturedThenPanicked,
    Settled,
    AuthorizeDeclined,
    AuthorizeOutcomeUnknown,
}

#[derive(Clone, Default)]
struct Counters {
    authorizations: Arc<AtomicUsize>,
    captures: Arc<AtomicUsize>,
    releases: Arc<AtomicUsize>,
    refunds: Arc<AtomicUsize>,
    invocations: Arc<AtomicUsize>,
    authorization_retained: Arc<AtomicBool>,
    externally_captured: Arc<AtomicBool>,
}

struct PrepaymentAdapter {
    mode: Mode,
    counters: Counters,
}

impl PaymentAdapter for PrepaymentAdapter {
    fn rail_id(&self) -> &'static str {
        "test-prepayment-custody"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.counters.authorizations.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.amount_units, 100);
        assert_eq!(request.currency, "USD");
        if matches!(self.mode, Mode::AuthorizeDeclined) {
            return Err(PaymentError::Declined("authorization declined".to_string()));
        }
        if matches!(self.mode, Mode::AuthorizeOutcomeUnknown) {
            return Err(PaymentError::OutcomeUnknown {
                detail: SENSITIVE_ERROR.to_string(),
                evidence: prepayment_evidence(),
            });
        }
        self.counters
            .authorization_retained
            .store(true, Ordering::SeqCst);
        Ok(PaymentAuthorization {
            authorization_id: AUTHORIZATION_ID.to_string(),
            state: PaymentAuthorizationState::Held,
            metadata: serde_json::Value::Null,
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.counters.captures.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            self.counters.invocations.load(Ordering::SeqCst),
            0,
            "reserve must capture before any tool invocation"
        );
        assert_eq!(authorization_id, AUTHORIZATION_ID);
        assert_eq!(amount_units, 100);
        assert_eq!(currency, "USD");
        match self.mode {
            Mode::CaptureError(error) => Err(error.error()),
            Mode::CapturedThenAcknowledgementLost => {
                self.counters
                    .externally_captured
                    .store(true, Ordering::SeqCst);
                Err(PaymentError::Unavailable(SENSITIVE_ERROR.to_string()))
            }
            Mode::CapturedThenPanicked => {
                self.counters
                    .externally_captured
                    .store(true, Ordering::SeqCst);
                panic!("{SENSITIVE_ERROR}");
            }
            Mode::Settled => {
                self.counters
                    .externally_captured
                    .store(true, Ordering::SeqCst);
                Ok(PaymentResult {
                    transaction_id: CAPTURE_ID.to_string(),
                    settlement_status: RailSettlementStatus::Settled,
                    metadata: serde_json::Value::Null,
                })
            }
            Mode::AuthorizeDeclined | Mode::AuthorizeOutcomeUnknown => {
                unreachable!("an unconfirmed authorization cannot be captured")
            }
        }
    }

    fn release(&self, authorization_id: &str, _: &str) -> Result<PaymentResult, PaymentError> {
        assert_eq!(authorization_id, AUTHORIZATION_ID);
        self.counters.releases.fetch_add(1, Ordering::SeqCst);
        self.counters
            .authorization_retained
            .store(false, Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: "prepay-custody-release".to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::Value::Null,
        })
    }

    fn refund(&self, _: &str, _: u64, _: &str, _: &str) -> Result<PaymentResult, PaymentError> {
        self.counters.refunds.fetch_add(1, Ordering::SeqCst);
        self.counters
            .authorization_retained
            .store(false, Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: "prepay-custody-refund".to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::Value::Null,
        })
    }

    fn replayed_authorization_metadata(&self, _: &str) -> Result<serde_json::Value, PaymentError> {
        Ok(serde_json::json!({}))
    }
}

struct Fixture {
    kernel: ChioKernel,
    request: ToolCallRequest,
    counters: Counters,
}

impl Fixture {
    fn new(mode: Mode) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_dpop(mode, false)
    }

    fn with_dpop(mode: Mode, dpop_required: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = make_monetary_config();
        if dpop_required {
            config.policy_hash = chio_core::crypto::sha256_hex(b"prepayment-custody-policy");
        }
        let mut kernel = make_kernel(config);
        install_strict_nonce_store(&mut kernel);
        if dpop_required {
            super::durable_admission::dpop_acquisition::install_fixture_authority(&mut kernel);
        }
        let counters = Counters::default();
        kernel.set_payment_adapter(Box::new(PrepaymentAdapter {
            mode,
            counters: counters.clone(),
        }));
        kernel.register_tool_server(Box::new(CountingMonetaryServer {
            id: "cost-srv".to_string(),
            invocations: Arc::clone(&counters.invocations),
        }));
        let agent = make_keypair();
        let mut grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
        grant.dpop_required = dpop_required.then_some(true);
        let cap = kernel.issue_capability(&agent.public_key(), make_scope(vec![grant]), 300)?;
        let mut intent = super::sim_payment::make_mustprepay_intent(
            "prepay-custody-intent",
            "cost-srv",
            "compute",
            100,
            "USD",
        );
        let mut request = make_request("prepay-custody-request", &cap, "compute", "cost-srv");
        bind_test_tool_approval(
            &mut kernel,
            &cap,
            &request.arguments,
            &request.request_id,
            &mut intent,
        );
        request.approval_token = Some(make_governed_approval_token(
            &kernel.config.keypair,
            &agent.public_key(),
            &intent,
            &request.request_id,
        ));
        request.governed_intent = Some(intent);
        if dpop_required {
            request.dpop_proof = Some(make_dpop_proof(
                &agent,
                &cap,
                &request.server_id,
                &request.tool_name,
                &request.arguments,
                "prepay-custody-dpop-proof",
            ));
        }
        Ok(Self {
            kernel,
            request,
            counters,
        })
    }

    fn reserve(&self) -> Result<ToolCallResponse, KernelError> {
        self.kernel
            .authorize_tool_call_reserving_blocking_with_metadata(&self.request, None)
    }

    fn exposure(&self) -> Result<u64, Box<dyn std::error::Error>> {
        Ok(self
            .kernel
            .budget_store
            .get_usage(&self.request.capability.id, 0)?
            .ok_or_else(|| std::io::Error::other("prepayment budget usage missing"))?
            .committed_cost_units()?)
    }

    fn assert_capture_failure_retained(
        &self,
        response: &ToolCallResponse,
        code: &str,
    ) -> TestResult {
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.output.is_none());
        assert!(response.execution_nonce.is_none());
        assert_eq!(self.counters.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(self.counters.authorizations.load(Ordering::SeqCst), 1);
        assert_eq!(self.counters.captures.load(Ordering::SeqCst), 1);
        assert_eq!(
            self.counters.releases.load(Ordering::SeqCst),
            0,
            "an unknown prepaid capture must not release its positive authorization"
        );
        assert_eq!(self.counters.refunds.load(Ordering::SeqCst), 0);
        assert!(self.counters.authorization_retained.load(Ordering::SeqCst));
        assert_eq!(
            self.exposure()?,
            100,
            "unconfirmed prepaid capture retains its budget exposure"
        );
        assert!(response.receipt.verify_signature()?);
        let receipts = self.kernel.receipt_log();
        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts.get(0).expect("retained payment receipt").id,
            response.receipt.id
        );
        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .expect("retained payment metadata");
        let financial = &metadata["financial"];
        assert_eq!(financial["authorization_id"], AUTHORIZATION_ID);
        assert_eq!(financial["payment_reference"], AUTHORIZATION_ID);
        assert_eq!(financial["release_outcome"], "not_released");
        assert_eq!(financial["payment_authorization_retained"], true);
        assert_eq!(financial["payment_capture_ambiguous"], true);
        assert_eq!(financial["payment_capture_error_code"], code);
        assert_eq!(
            metadata["chio_runtime"]["dispatch_credential_disposition"],
            "retained_after_authorization"
        );
        assert_eq!(
            metadata["chio_runtime"]["identity_disposition"], "retained",
            "capture outcome still owns the request identity"
        );
        assert!(!metadata.to_string().contains(SENSITIVE_ERROR));
        assert!(!response
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains(SENSITIVE_ERROR));
        Ok(())
    }
}

#[test]
fn capture_error_retains_prepaid_authorization_budget_and_credentials() -> TestResult {
    for error in [
        ErrorKind::Unavailable,
        ErrorKind::RailError,
        ErrorKind::Declined,
        ErrorKind::InsufficientFunds,
    ] {
        let fixture = Fixture::new(Mode::CaptureError(error))?;
        let response = fixture.reserve()?;
        fixture.assert_capture_failure_retained(&response, error.code())?;
        let retry = fixture.reserve()?;
        assert_eq!(retry.verdict, Verdict::Deny);
        assert!(retry.execution_nonce.is_none());
        assert_eq!(
            fixture.counters.authorizations.load(Ordering::SeqCst),
            1,
            "retained approval cannot mint another prepayment"
        );
        assert_eq!(fixture.counters.captures.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.exposure()?, 100);
    }
    Ok(())
}

#[test]
fn captured_then_lost_ack_retains_custody_without_execution_nonce() -> TestResult {
    let fixture = Fixture::new(Mode::CapturedThenAcknowledgementLost)?;
    let response = fixture.reserve()?;
    assert!(fixture.counters.externally_captured.load(Ordering::SeqCst));
    fixture.assert_capture_failure_retained(&response, "unavailable")
}

#[test]
fn replayed_prepayment_hold_survives_approval_denial() -> TestResult {
    let fixture = Fixture::with_dpop(Mode::CaptureError(ErrorKind::Unavailable), false)?;
    let first = fixture.reserve()?;
    assert_eq!(first.verdict, Verdict::Deny);
    assert_eq!(fixture.exposure()?, 100);
    let retry = fixture.reserve()?;
    assert_eq!(retry.verdict, Verdict::Deny);
    assert!(retry.execution_nonce.is_none());
    assert_eq!(fixture.counters.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.counters.captures.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.counters.releases.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.counters.refunds.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.exposure()?,
        100,
        "credential denial cannot reverse a prior hold"
    );
    Ok(())
}

#[test]
fn dpop_prepayment_without_a_nonce_participant_denies_before_the_rail() -> TestResult {
    let fixture = Fixture::with_dpop(Mode::CaptureError(ErrorKind::Unavailable), true)?;
    let response = fixture.reserve()?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("durable admission failed: admission store lacks the operation-owned execution nonce participant")
    );
    assert!(response.execution_nonce.is_none());
    assert_eq!(fixture.counters.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.counters.captures.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.counters.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn settled_prepayment_hold_survives_replayed_reservation_cleanup() -> TestResult {
    let fixture = Fixture::new(Mode::Settled)?;
    let first = fixture.reserve()?;
    assert_eq!(first.verdict, Verdict::Allow);
    assert!(first.execution_nonce.is_some());
    assert_eq!(fixture.exposure()?, 100);
    let retry = fixture.reserve()?;
    assert_eq!(retry.verdict, Verdict::Deny);
    assert!(retry.execution_nonce.is_none());
    assert_eq!(fixture.counters.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.counters.captures.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.counters.releases.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.counters.refunds.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.exposure()?,
        100,
        "a retry cannot reverse the earlier prepaid nonce's hold"
    );
    Ok(())
}

#[test]
fn captured_then_panicked_retains_custody_without_execution_nonce() -> TestResult {
    let fixture = Fixture::new(Mode::CapturedThenPanicked)?;
    let response = fixture.reserve()?;
    assert!(fixture.counters.externally_captured.load(Ordering::SeqCst));
    fixture.assert_capture_failure_retained(&response, "rail_error")
}

#[test]
fn settled_prepayment_mints_one_nonce_without_tool_dispatch() -> TestResult {
    let fixture = Fixture::new(Mode::Settled)?;
    let response = fixture.reserve()?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(response.execution_nonce.is_some());
    assert_eq!(fixture.counters.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.counters.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.counters.captures.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.counters.releases.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.counters.refunds.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.exposure()?, 100);
    assert!(response.receipt.verify_signature()?);
    Ok(())
}

#[test]
fn definite_authorization_decline_keeps_clean_pre_dispatch_denial() -> TestResult {
    let fixture = Fixture::new(Mode::AuthorizeDeclined)?;
    let response = fixture.reserve()?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.execution_nonce.is_none());
    assert_eq!(fixture.counters.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.counters.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.counters.captures.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.counters.releases.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.counters.refunds.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.exposure()?, 0);
    assert!(!fixture
        .counters
        .authorization_retained
        .load(Ordering::SeqCst));
    let financial = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"));
    assert!(financial
        .and_then(|financial| financial.get("authorization_id"))
        .is_none());
    assert!(response.receipt.verify_signature()?);
    Ok(())
}

#[test]
fn outcome_unknown_prepayment_signs_its_rail_evidence() -> TestResult {
    let fixture = Fixture::new(Mode::AuthorizeOutcomeUnknown)?;
    let response = fixture.reserve()?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.execution_nonce.is_none());
    assert_eq!(fixture.counters.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.counters.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.counters.captures.load(Ordering::SeqCst), 0);
    assert!(response.receipt.verify_signature()?);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or("prepayment ambiguity metadata missing")?;
    let financial = &metadata["financial"];
    assert_eq!(financial["payment_authorization_ambiguous"], true);
    assert_eq!(
        financial["payment_authorization_error_code"],
        "outcome_unknown"
    );
    assert_eq!(
        financial["payment_authorization_evidence"],
        prepayment_evidence()
    );
    assert!(!metadata.to_string().contains(SENSITIVE_ERROR));
    Ok(())
}
