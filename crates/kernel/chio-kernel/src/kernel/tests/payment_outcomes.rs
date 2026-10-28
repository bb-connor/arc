use super::*;
use tracing::instrument::WithSubscriber;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AUTHORIZATION_ID: &str = "outcome-authorization";
const CAPTURE_ID: &str = "outcome-capture";
const RELEASE_ID: &str = "outcome-release";
const SENSITIVE_ERROR: &str = "sensitive-payment-rail-detail";

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

#[derive(Clone, Copy, Debug)]
enum CaptureOutcome {
    Error(ErrorKind),
    Status(RailSettlementStatus),
}

#[derive(Clone, Copy, Debug)]
enum ReleaseOutcome {
    Error(ErrorKind),
    Status(RailSettlementStatus),
}

#[derive(Clone, Default)]
struct PaymentCounters {
    authorizations: Arc<AtomicUsize>,
    captures: Arc<AtomicUsize>,
    releases: Arc<AtomicUsize>,
    authorization_retained: Arc<AtomicBool>,
    invocations: Arc<AtomicUsize>,
}

struct OutcomePaymentAdapter {
    capture: CaptureOutcome,
    release: ReleaseOutcome,
    counters: PaymentCounters,
}

impl PaymentAdapter for OutcomePaymentAdapter {
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        assert_eq!(self.counters.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(request.amount_units, 100);
        assert_eq!(request.currency, "USD");
        self.counters.authorizations.fetch_add(1, Ordering::SeqCst);
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
        assert_eq!(
            self.counters.invocations.load(Ordering::SeqCst),
            1,
            "capture must follow invocation"
        );
        assert_eq!(authorization_id, AUTHORIZATION_ID);
        assert_eq!(amount_units, 100);
        assert_eq!(currency, "USD");
        self.counters.captures.fetch_add(1, Ordering::SeqCst);
        match self.capture {
            CaptureOutcome::Error(error) => Err(error.error()),
            CaptureOutcome::Status(settlement_status) => Ok(PaymentResult {
                transaction_id: CAPTURE_ID.to_string(),
                settlement_status,
                metadata: serde_json::Value::Null,
            }),
        }
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        assert_eq!(authorization_id, AUTHORIZATION_ID);
        self.counters.releases.fetch_add(1, Ordering::SeqCst);
        match self.release {
            ReleaseOutcome::Error(error) => Err(error.error()),
            ReleaseOutcome::Status(settlement_status) => {
                if settlement_status == RailSettlementStatus::Released {
                    self.counters
                        .authorization_retained
                        .store(false, Ordering::SeqCst);
                }
                Ok(PaymentResult {
                    transaction_id: RELEASE_ID.to_string(),
                    settlement_status,
                    metadata: serde_json::Value::Null,
                })
            }
        }
    }

    fn refund(&self, _: &str, _: u64, _: &str, _: &str) -> Result<PaymentResult, PaymentError> {
        unreachable!("post-execution capture failure has no refund authority")
    }

    fn replayed_authorization_metadata(&self, _: &str) -> Result<serde_json::Value, PaymentError> {
        Ok(serde_json::json!({}))
    }
}

#[derive(Clone, Default)]
struct AuditFaultRecorder(Arc<Mutex<Vec<String>>>);

impl tracing::Subscriber for AuditFaultRecorder {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct AuditFieldVisitor<'a>(&'a mut Vec<String>);
        impl tracing::field::Visit for AuditFieldVisitor<'_> {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "audit_fault" {
                    self.0.push(value.to_string());
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "audit_fault" {
                    self.0.push(format!("{value:?}"));
                }
            }
        }
        event.record(&mut AuditFieldVisitor(
            &mut self.0.lock().expect("audit recorder lock"),
        ));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

struct Fixture {
    kernel: ChioKernel,
    request: ToolCallRequest,
    counters: PaymentCounters,
    audit: AuditFaultRecorder,
}

impl Fixture {
    fn new(
        capture: CaptureOutcome,
        release: ReleaseOutcome,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_grant(
            capture,
            release,
            super::sim_payment::make_no_ceiling_mustprepay_grant(),
        )
    }

    fn with_grant(
        capture: CaptureOutcome,
        release: ReleaseOutcome,
        grant: ToolGrant,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut kernel = make_kernel(make_monetary_config());
        let counters = PaymentCounters::default();
        kernel.set_payment_adapter(Box::new(OutcomePaymentAdapter {
            capture,
            release,
            counters: counters.clone(),
        }));
        kernel.register_tool_server(Box::new(CountingMonetaryServer {
            id: "cost-srv".to_string(),
            invocations: Arc::clone(&counters.invocations),
        }));
        let agent = make_keypair();
        let cap = kernel.issue_capability(&agent.public_key(), make_scope(vec![grant]), 300)?;
        let mut intent = super::sim_payment::make_mustprepay_intent(
            "outcome-intent",
            "cost-srv",
            "compute",
            100,
            "USD",
        );
        let mut request = make_request("outcome-request", &cap, "compute", "cost-srv");
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
        Ok(Self {
            kernel,
            request,
            counters,
            audit: AuditFaultRecorder::default(),
        })
    }

    async fn evaluate(&self, nested: bool) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_with_metadata(nested, None).await
    }

    async fn evaluate_with_metadata(
        &self,
        nested: bool,
        metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        async {
            if nested {
                let session = self.kernel.open_session(
                    self.request.agent_id.clone(),
                    vec![self.request.capability.clone()],
                )?;
                self.kernel.activate_session(&session)?;
                if metadata.is_some() {
                    let context = make_operation_context(
                        &session,
                        &self.request.request_id,
                        &self.request.agent_id,
                    );
                    let mut operation: ToolCallOperation =
                        serde_json::from_value(serde_json::json!({
                            "capability": self.request.capability,
                            "server_id": self.request.server_id,
                            "tool_name": self.request.tool_name,
                            "arguments": self.request.arguments,
                            "governed_intent": self.request.governed_intent,
                            "approval_token": self.request.approval_token,
                        }))
                        .map_err(|error| KernelError::Internal(error.to_string()))?;
                    operation.extra_metadata = metadata;
                    return self
                        .kernel
                        .evaluate_tool_call_operation_with_nested_flow_client_async(
                            &context,
                            &operation,
                            &mut NoopNestedFlowClient,
                        )
                        .await;
                }
                let context =
                    make_operation_context(&session, "outcome-parent", &self.request.agent_id);
                self.kernel
                    .begin_session_request(&context, OperationKind::ToolCall, true)?;
                self.kernel
                    .evaluate_tool_call_with_nested_flow_client_async(
                        &context,
                        &self.request,
                        &mut NoopNestedFlowClient,
                        metadata,
                    )
                    .await
            } else {
                self.kernel
                    .evaluate_tool_call_with_metadata(&self.request, metadata)
                    .await
            }
        }
        .with_subscriber(self.audit.clone())
        .await
    }

    fn assert_dispatch_and_terminal(&self, response: &ToolCallResponse) -> TestResult {
        assert_eq!(self.counters.authorizations.load(Ordering::SeqCst), 1);
        assert_eq!(self.counters.invocations.load(Ordering::SeqCst), 1);
        assert_eq!(self.counters.captures.load(Ordering::SeqCst), 1);
        assert!(response.receipt.verify_integrity_embedded_key()?);
        let terminals: Vec<_> = self
            .kernel
            .receipt_log()
            .iter()
            .filter(|receipt| {
                receipt.capability_id == self.request.capability.id
                    && receipt.tool_server == self.request.server_id
                    && receipt.tool_name == self.request.tool_name
                    && receipt.decision.is_some()
            })
            .cloned()
            .collect();
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0].id, response.receipt.id);
        Ok(())
    }

    fn assert_audit_fault(&self, code: &str) {
        assert!(
            self.audit
                .0
                .lock()
                .expect("audit recorder lock")
                .iter()
                .any(|fault| fault == code),
            "missing audit fault {code}"
        );
    }
}

fn financial(response: &ToolCallResponse) -> &serde_json::Value {
    response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .expect("post-execution outcome must carry financial metadata")
}

async fn assert_capture_error_retains_authorization(nested: bool) -> TestResult {
    for error in [
        ErrorKind::Unavailable,
        ErrorKind::RailError,
        ErrorKind::Declined,
        ErrorKind::InsufficientFunds,
    ] {
        let fixture = Fixture::new(
            CaptureOutcome::Error(error),
            ReleaseOutcome::Status(RailSettlementStatus::Released),
        )?;
        let response = fixture.evaluate(nested).await?;
        fixture.assert_dispatch_and_terminal(&response)?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.output.is_none());
        assert_eq!(
            fixture.counters.releases.load(Ordering::SeqCst),
            0,
            "a capture error cannot authorize releasing a positive hold: {error:?}"
        );
        assert!(fixture
            .counters
            .authorization_retained
            .load(Ordering::SeqCst));
        let financial = financial(&response);
        assert_eq!(financial["authorization_id"], AUTHORIZATION_ID);
        assert_eq!(financial["payment_reference"], AUTHORIZATION_ID);
        assert_eq!(financial["release_outcome"], "not_released");
        assert_eq!(financial["payment_authorization_retained"], true);
        assert_eq!(financial["payment_capture_ambiguous"], true);
        assert_eq!(financial["payment_capture_error_code"], error.code());
        assert!(!response
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains(SENSITIVE_ERROR));
        assert!(!response
            .receipt
            .metadata
            .as_ref()
            .expect("terminal metadata")
            .to_string()
            .contains(SENSITIVE_ERROR));
        fixture.assert_audit_fault("post_execution_payment_capture_outcome_unknown");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_capture_error_retains_positive_authorization() -> TestResult {
    assert_capture_error_retains_authorization(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_capture_error_retains_positive_authorization() -> TestResult {
    assert_capture_error_retains_authorization(true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn budgeted_capture_error_records_retention_without_changing_delivery() -> TestResult {
    for nested in [false, true] {
        for error in [
            ErrorKind::Unavailable,
            ErrorKind::RailError,
            ErrorKind::Declined,
            ErrorKind::InsufficientFunds,
        ] {
            let fixture = Fixture::with_grant(
                CaptureOutcome::Error(error),
                ReleaseOutcome::Status(RailSettlementStatus::Released),
                make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
            )?;
            let response = fixture.evaluate(nested).await?;
            fixture.assert_dispatch_and_terminal(&response)?;
            assert_eq!(response.verdict, Verdict::Allow);
            assert!(response.output.is_some());
            assert_eq!(fixture.counters.releases.load(Ordering::SeqCst), 0);
            assert!(fixture
                .counters
                .authorization_retained
                .load(Ordering::SeqCst));
            let financial = financial(&response);
            assert_eq!(financial["settlement_status"], "failed");
            assert_eq!(financial["payment_reference"], AUTHORIZATION_ID);
            assert_eq!(financial["authorization_id"], AUTHORIZATION_ID);
            assert_eq!(financial["release_outcome"], "not_released");
            assert_eq!(financial["payment_authorization_retained"], true);
            assert_eq!(financial["payment_capture_ambiguous"], true);
            assert_eq!(financial["payment_capture_error_code"], error.code());
            assert!(!financial.to_string().contains(SENSITIVE_ERROR));
            fixture.assert_audit_fault("post_execution_payment_capture_outcome_unknown");
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_settled_capture_denies_and_records_confirmed_release() -> TestResult {
    for nested in [false, true] {
        for status in [
            RailSettlementStatus::Failed,
            RailSettlementStatus::Authorized,
            RailSettlementStatus::Pending,
            RailSettlementStatus::Captured,
        ] {
            let fixture = Fixture::new(
                CaptureOutcome::Status(status),
                ReleaseOutcome::Status(RailSettlementStatus::Released),
            )?;
            let response = fixture.evaluate(nested).await?;
            fixture.assert_dispatch_and_terminal(&response)?;
            assert_eq!(
                response.verdict,
                Verdict::Deny,
                "non-settled {status:?} must continue to deny output"
            );
            assert!(response.output.is_none());
            assert_eq!(fixture.counters.releases.load(Ordering::SeqCst), 1);
            assert!(!fixture
                .counters
                .authorization_retained
                .load(Ordering::SeqCst));
            let financial = financial(&response);
            assert_eq!(financial["authorization_id"], AUTHORIZATION_ID);
            assert_eq!(financial["payment_reference"], CAPTURE_ID);
            assert_eq!(financial["capture_status"], serde_json::to_value(status)?);
            assert_eq!(financial["release_outcome"], "released");
            assert_eq!(financial["payment_release_reference"], RELEASE_ID);
            assert_eq!(financial["payment_authorization_retained"], false);
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn release_error_records_unknown_outcome_and_retains_authorization() -> TestResult {
    for nested in [false, true] {
        for error in [
            ErrorKind::Unavailable,
            ErrorKind::RailError,
            ErrorKind::Declined,
            ErrorKind::InsufficientFunds,
        ] {
            let fixture = Fixture::new(
                CaptureOutcome::Status(RailSettlementStatus::Failed),
                ReleaseOutcome::Error(error),
            )?;
            let response = fixture.evaluate(nested).await?;
            fixture.assert_dispatch_and_terminal(&response)?;
            assert_eq!(response.verdict, Verdict::Deny);
            assert!(response.output.is_none());
            assert_eq!(fixture.counters.releases.load(Ordering::SeqCst), 1);
            assert!(fixture
                .counters
                .authorization_retained
                .load(Ordering::SeqCst));
            let financial = financial(&response);
            assert_eq!(financial["authorization_id"], AUTHORIZATION_ID);
            assert_eq!(financial["payment_reference"], CAPTURE_ID);
            assert_eq!(financial["release_outcome"], "outcome_unknown");
            assert_eq!(financial["payment_release_error_code"], error.code());
            assert_eq!(financial["payment_authorization_retained"], true);
            assert!(!response
                .receipt
                .metadata
                .as_ref()
                .expect("terminal metadata")
                .to_string()
                .contains(SENSITIVE_ERROR));
            fixture.assert_audit_fault("post_execution_payment_release_outcome_unknown");
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unconfirmed_release_records_actual_status_and_retains_authorization() -> TestResult {
    for nested in [false, true] {
        for status in [
            RailSettlementStatus::Pending,
            RailSettlementStatus::Captured,
            RailSettlementStatus::Failed,
            RailSettlementStatus::Settled,
        ] {
            let fixture = Fixture::new(
                CaptureOutcome::Status(RailSettlementStatus::Failed),
                ReleaseOutcome::Status(status),
            )?;
            let response = fixture.evaluate(nested).await?;
            fixture.assert_dispatch_and_terminal(&response)?;
            assert_eq!(response.verdict, Verdict::Deny);
            assert!(response.output.is_none());
            assert_eq!(fixture.counters.releases.load(Ordering::SeqCst), 1);
            assert!(fixture
                .counters
                .authorization_retained
                .load(Ordering::SeqCst));
            let financial = financial(&response);
            assert_eq!(financial["release_outcome"], serde_json::to_value(status)?);
            assert_eq!(financial["payment_release_reference"], RELEASE_ID);
            assert_eq!(financial["payment_authorization_retained"], true);
            fixture.assert_audit_fault("post_execution_payment_release_unconfirmed");
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settled_capture_allows_once_without_release() -> TestResult {
    for nested in [false, true] {
        let fixture = Fixture::new(
            CaptureOutcome::Status(RailSettlementStatus::Settled),
            ReleaseOutcome::Status(RailSettlementStatus::Released),
        )?;
        let response = fixture.evaluate(nested).await?;
        fixture.assert_dispatch_and_terminal(&response)?;
        assert_eq!(response.verdict, Verdict::Allow);
        assert!(response.output.is_some());
        assert_eq!(fixture.counters.releases.load(Ordering::SeqCst), 0);
        assert_eq!(financial(&response)["payment_reference"], CAPTURE_ID);
        assert_eq!(financial(&response)["settlement_status"], "settled");
    }
    Ok(())
}

async fn assert_non_object_metadata_is_rejected_before_custody(nested: bool) -> TestResult {
    for metadata in [
        serde_json::Value::Null,
        serde_json::json!(false),
        serde_json::json!(7),
        serde_json::json!("caller scalar"),
        serde_json::json!([]),
    ] {
        let fixture = Fixture::new(
            CaptureOutcome::Error(ErrorKind::RailError),
            ReleaseOutcome::Status(RailSettlementStatus::Released),
        )?;
        let result = fixture.evaluate_with_metadata(nested, Some(metadata)).await;
        assert!(
            matches!(result, Err(KernelError::InvalidReceiptMetadata(_))),
            "non-object metadata must be refused before it can suppress financial evidence"
        );
        assert_eq!(fixture.counters.authorizations.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.counters.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.counters.captures.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.counters.releases.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn non_object_metadata_is_rejected_before_async_payment_custody() -> TestResult {
    assert_non_object_metadata_is_rejected_before_custody(false).await
}

#[tokio::test]
async fn non_object_metadata_is_rejected_before_nested_payment_custody() -> TestResult {
    assert_non_object_metadata_is_rejected_before_custody(true).await
}
