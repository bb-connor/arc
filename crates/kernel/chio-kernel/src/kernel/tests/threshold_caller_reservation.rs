#[derive(Clone)]
struct BoundThresholdSupplementalVerifier {
    issuer: PublicKey,
}

impl crate::supplemental_quota::SupplementalQuotaVerifier
    for BoundThresholdSupplementalVerifier
{
    fn verifier_id(&self) -> &str {
        "threshold-caller-reservation-verifier"
    }

    fn verify(
        &self,
        artifact: &crate::supplemental_quota::OpaqueSignedSupplementalQuota,
        context: &crate::supplemental_quota::SupplementalQuotaVerificationContext,
    ) -> Result<
        crate::supplemental_quota::VerifiedSupplementalQuotaClaimBody,
        crate::supplemental_quota::SupplementalQuotaError,
    > {
        let negotiated_features_digest = chio_core::crypto::sha256_hex(
            &chio_core::canonical::canonical_json_bytes(&context.negotiated_features).map_err(
                |error| {
                    crate::supplemental_quota::SupplementalQuotaError::Canonicalization(
                        error.to_string(),
                    )
                },
            )?,
        );
        let broker_capability_id = "threshold-caller-reservation-broker".to_string();
        Ok(crate::supplemental_quota::VerifiedSupplementalQuotaClaimBody {
            capability_id: context.capability_id.clone(),
            capability_digest: context.capability_digest.clone(),
            subject: context.subject.clone(),
            request_id: context.request_id.clone(),
            destination: context.destination.clone(),
            arguments_digest: context.arguments_digest.clone(),
            request_binding_hash: context.request_binding_hash.clone(),
            expires_at: context.now.saturating_add(300),
            broker_capability_id: broker_capability_id.clone(),
            issuer: self.issuer.clone(),
            request_constraint_digest: "51".repeat(32),
            max_invocations: 1,
            supplemental_revocation_ids: vec![broker_capability_id],
            artifact_digest: artifact.digest(),
            negotiated_features_digest,
            profile: crate::budget_store::BudgetQuotaProfile::SupplementalBrokerExecution,
        })
    }
}

#[derive(Default)]
struct RecordingThresholdSupplementalRegistrar {
    registrations: std::sync::Mutex<Vec<String>>,
    prepared_dispatches: std::sync::Mutex<Vec<String>>,
}

impl RecordingThresholdSupplementalRegistrar {
    fn prepared_dispatches(&self) -> Vec<String> {
        self.prepared_dispatches
            .lock()
            .expect("supplemental dispatch trace")
            .clone()
    }
}

impl crate::supplemental_quota::SupplementalAdmissionRegistrar
    for RecordingThresholdSupplementalRegistrar
{
    fn prepare_admission(
        &self,
        request: crate::supplemental_quota::SupplementalAdmissionPrepareRequest<'_>,
    ) -> Result<
        crate::supplemental_quota::SupplementalAdmissionPlan,
        crate::supplemental_quota::SupplementalQuotaError,
    > {
        let prefix = format!("supplemental:{}", request.request_id);
        crate::supplemental_quota::SupplementalAdmissionPlan::new(
            format!("{prefix}:attempt"),
            format!("{prefix}:hold"),
            format!("{prefix}:authorize"),
            format!("{prefix}:reverse"),
            format!("{prefix}:capture"),
            request.authorization_artifact.as_bytes().to_vec(),
        )
    }

    fn register_admission(
        &self,
        _plan: &crate::supplemental_quota::SupplementalAdmissionPlan,
        authorization: crate::supplemental_quota::SupplementalAdmissionAuthorization<'_>,
    ) -> Result<(), crate::supplemental_quota::SupplementalQuotaError> {
        self.registrations
            .lock()
            .map_err(|_| {
                crate::supplemental_quota::SupplementalQuotaError::Verification(
                    "supplemental registration trace poisoned".to_string(),
                )
            })?
            .push(authorization.admission_operation_id().to_string());
        Ok(())
    }

    fn prepare_dispatch(
        &self,
        admission_operation_id: &str,
    ) -> Result<(), crate::supplemental_quota::SupplementalQuotaError> {
        self.prepared_dispatches
            .lock()
            .map_err(|_| {
                crate::supplemental_quota::SupplementalQuotaError::Verification(
                    "supplemental dispatch trace poisoned".to_string(),
                )
            })?
            .push(admission_operation_id.to_string());
        Ok(())
    }

    fn release_admission(
        &self,
        _admission_operation_id: &str,
    ) -> Result<(), crate::supplemental_quota::SupplementalQuotaError> {
        Ok(())
    }

    fn finalize_admission(
        &self,
        _admission_operation_id: &str,
    ) -> Result<(), crate::supplemental_quota::SupplementalQuotaError> {
        Ok(())
    }
}

#[derive(Clone)]
struct SettlingThresholdPaymentAdapter {
    inner: OperationAwareThresholdPaymentAdapter,
}

impl SettlingThresholdPaymentAdapter {
    fn new() -> Self {
        Self {
            inner: OperationAwareThresholdPaymentAdapter::new(),
        }
    }

    fn calls(&self) -> Vec<(String, String, String)> {
        self.inner.calls()
    }

    fn refunds(&self) -> Vec<(String, u64, String)> {
        self.inner.refunds()
    }

    fn authorization_mutations(&self) -> u64 {
        self.inner.authorization_mutations()
    }
}

impl PaymentAdapter for SettlingThresholdPaymentAdapter {
    fn rail_id(&self) -> &str {
        "settling-threshold-test"
    }

    fn supports_operation_authorization_recovery(&self) -> bool {
        true
    }

    fn supports_operation_payment_mutations(&self) -> bool {
        true
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.inner.authorize(request)
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner
            .capture(authorization_id, amount_units, currency, reference)
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner.release(authorization_id, reference)
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner
            .refund(transaction_id, amount_units, currency, reference)
    }

    fn authorize_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
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
        request: OperationPaymentCaptureRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        let mut result = self.inner.capture_for_operation(request)?;
        result.settlement_status = RailSettlementStatus::Settled;
        Ok(result)
    }

    fn release_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner.release_for_operation(
            operation_id,
            request_binding_hash,
            authorization_id,
            reference,
        )
    }

    fn refund_for_operation(
        &self,
        request: OperationPaymentRefundRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner.refund_for_operation(request)
    }
}

struct InCrateThresholdCaptureAuthority {
    budget: std::sync::Arc<DurableThresholdBudgetStore>,
    decisions: std::sync::Mutex<
        std::collections::HashMap<
            String,
            (
                crate::admission_capture_authority::AdmissionCaptureRequest,
                crate::admission_capture_authority::AdmissionCaptureDecision,
            ),
        >,
    >,
}

impl InCrateThresholdCaptureAuthority {
    fn new(budget: std::sync::Arc<DurableThresholdBudgetStore>) -> Self {
        Self {
            budget,
            decisions: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn locked_decisions(
        &self,
    ) -> Result<
        std::sync::MutexGuard<
            '_,
            std::collections::HashMap<
                String,
                (
                    crate::admission_capture_authority::AdmissionCaptureRequest,
                    crate::admission_capture_authority::AdmissionCaptureDecision,
                ),
            >,
        >,
        crate::admission_capture_authority::AdmissionCaptureError,
    > {
        self.decisions.lock().map_err(|_| {
            crate::admission_capture_authority::AdmissionCaptureError::Unavailable(
                "in-crate threshold capture authority lock poisoned".to_string(),
            )
        })
    }

    fn existing_decision(
        stored_request: &crate::admission_capture_authority::AdmissionCaptureRequest,
        stored_decision: &crate::admission_capture_authority::AdmissionCaptureDecision,
        request: &crate::admission_capture_authority::AdmissionCaptureRequest,
    ) -> Result<
        crate::admission_capture_authority::AdmissionCaptureDecision,
        crate::admission_capture_authority::AdmissionCaptureError,
    > {
        if stored_request != request {
            return Err(
                crate::admission_capture_authority::AdmissionCaptureError::InvalidRequest(
                    format!(
                        "operation `{}` was reused for a different combined capture",
                        request.operation_id()
                    ),
                ),
            );
        }
        Ok(stored_decision.clone())
    }
}

impl crate::admission_capture_authority::AdmissionCaptureAuthority
    for InCrateThresholdCaptureAuthority
{
    fn query_admission_capture(
        &self,
        request: &crate::admission_capture_authority::AdmissionCaptureRequest,
    ) -> Result<
        Option<crate::admission_capture_authority::AdmissionCaptureDecision>,
        crate::admission_capture_authority::AdmissionCaptureError,
    > {
        let decisions = self.locked_decisions()?;
        decisions
            .get(request.operation_id())
            .map(|(stored_request, stored_decision)| {
                Self::existing_decision(stored_request, stored_decision, request)
            })
            .transpose()
    }

    fn capture_admission(
        &self,
        request: crate::admission_capture_authority::AdmissionCaptureRequest,
    ) -> Result<
        crate::admission_capture_authority::AdmissionCaptureDecision,
        crate::admission_capture_authority::AdmissionCaptureError,
    > {
        let mut decisions = self.locked_decisions()?;
        if let Some((stored_request, stored_decision)) = decisions.get(request.operation_id()) {
            return Self::existing_decision(stored_request, stored_decision, &request);
        }
        let budget = crate::budget_store::BudgetStore::capture_invocation_reservations(
            self.budget.as_ref(),
            request.budget().clone(),
        )?;
        let metadata = crate::admission_capture_authority::AdmissionCaptureMetadata::new(
            crate::admission_capture_authority::AdmissionCaptureMetadataInput {
                operation_id: request.operation_id().to_string(),
                checked_revocation_set_digest: request
                    .bound_revocation_set_digest()
                    .to_string(),
                aggregate_root_capability_id: request
                    .aggregate_root_capability_id()
                    .map(str::to_string),
                aggregate_root_binding_digest: request
                    .aggregate_root_binding_digest()
                    .map(str::to_string),
                budget_commit: budget.metadata.clone(),
                revocation_commit_index: 1,
                authority_commit_index: 1,
                leader_epoch: None,
            },
        )?;
        let decision = crate::admission_capture_authority::AdmissionCaptureDecision::Captured {
            budget: Box::new(budget),
            metadata,
        };
        decisions.insert(
            request.operation_id().to_string(),
            (request, decision.clone()),
        );
        Ok(decision)
    }
}

fn install_threshold_caller_reservation_authorities(
    kernel: &mut ChioKernel,
    capability: &CapabilityToken,
    intent: &GovernedTransactionIntent,
    request: &mut ToolCallRequest,
    now: u64,
) -> std::sync::Arc<RecordingThresholdOperationStore> {
    install_valid_threshold_artifacts(kernel, capability, intent, request, now);
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(durable_atomic_test_budget_store(
            "threshold-caller-reservation",
        ))
        .expect("budget store");
    let nonce_config = ExecutionNonceConfig {
        require_nonce: true,
        ..ExecutionNonceConfig::default()
    };
    kernel
        .set_execution_nonce_store(
            nonce_config,
            Box::new(DurableThresholdNonceStore::new()),
        )
        .expect("execution nonce store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");
    operations
}

fn assert_threshold_caller_reserved(
    response: &ToolCallResponse,
    operations: &RecordingThresholdOperationStore,
) {
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert!(
        response.execution_nonce.is_some(),
        "caller reservation must return its private execution nonce"
    );
    assert_signed_receipt_matches_terminal_operation(
        response,
        operations,
        AdmissionOperationState::CallerReserved,
    );
    assert_eq!(
        operations.states().last(),
        Some(&AdmissionOperationState::CallerReserved)
    );
}

#[test]
fn threshold_monetary_caller_reservation_has_no_payment_effects() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    request.request_id = "threshold-caller-reserve-monetary".to_string();
    let payment = SettlingThresholdPaymentAdapter::new();
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("payment adapter");
    let operations = install_threshold_caller_reservation_authorities(
        &mut kernel,
        &capability,
        &intent,
        &mut request,
        now,
    );

    let response = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .expect("plain monetary threshold caller reservation");

    assert_threshold_caller_reserved(&response, &operations);
    assert!(
        payment.calls().iter().all(|(phase, _, _)| !matches!(
            phase.as_str(),
            "authorize" | "capture" | "release" | "refund"
        )),
        "plain monetary caller reservation must not move rail funds"
    );
    assert_eq!(payment.authorization_mutations(), 0);
    assert!(payment.refunds().is_empty());
}

#[test]
fn threshold_mustprepay_caller_reservation_authorizes_and_captures_once() {
    let (mut kernel, capability, _grant, _intent, mut request, now) = threshold_test_fixture();
    request.request_id = "threshold-caller-reserve-mustprepay".to_string();
    let intent = make_mustprepay_intent(
        "threshold-caller-reserve-mustprepay-intent",
        "payments",
        "transfer",
        100,
        "USD",
    );
    request.governed_intent = Some(intent.clone());
    let payment = SettlingThresholdPaymentAdapter::new();
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("payment adapter");
    let operations = install_threshold_caller_reservation_authorities(
        &mut kernel,
        &capability,
        &intent,
        &mut request,
        now,
    );

    let response = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .expect("MustPrepay threshold caller reservation");

    assert_threshold_caller_reserved(&response, &operations);
    let calls = payment.calls();
    let authorizations: Vec<_> = calls
        .iter()
        .filter(|(phase, _, _)| phase == "authorize")
        .collect();
    let captures: Vec<_> = calls
        .iter()
        .filter(|(phase, _, _)| phase == "capture")
        .collect();
    assert_eq!(authorizations.len(), 1);
    assert_eq!(captures.len(), 1);
    assert_eq!(
        (&authorizations[0].1, &authorizations[0].2),
        (&captures[0].1, &captures[0].2),
        "authorization and capture must share one operation binding"
    );
    assert_eq!(payment.authorization_mutations(), 1);
    assert!(
        calls.iter()
            .all(|(phase, _, _)| !matches!(phase.as_str(), "release" | "refund")),
        "a successfully prepaid reservation must retain its captured payment"
    );
    assert!(payment.refunds().is_empty());
}

#[test]
fn supplemental_threshold_caller_reservation_prepares_once_and_combines_capture() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    request.request_id = "threshold-caller-reserve-supplemental".to_string();
    request.supplemental_authorization = Some(
        chio_core::OpaqueSupplementalAuthorization::new(
            "broker:threshold-caller-reservation",
            b"signed-threshold-caller-reservation".to_vec(),
        )
        .expect("supplemental authorization"),
    );
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    let nonce_config = ExecutionNonceConfig {
        require_nonce: true,
        ..ExecutionNonceConfig::default()
    };
    kernel
        .set_execution_nonce_store(
            nonce_config,
            Box::new(DurableThresholdNonceStore::new()),
        )
        .expect("execution nonce store");
    let registrar = std::sync::Arc::new(RecordingThresholdSupplementalRegistrar::default());
    kernel
        .set_supplemental_quota_verifier(std::sync::Arc::new(
            BoundThresholdSupplementalVerifier {
                issuer: Keypair::generate().public_key(),
            },
        ))
        .expect("supplemental verifier");
    kernel
        .set_supplemental_admission_registrar(registrar.clone())
        .expect("supplemental registrar");
    kernel
        .set_admission_capture_authority(std::sync::Arc::new(
            InCrateThresholdCaptureAuthority::new(budget),
        ))
        .expect("capture authority");
    kernel
        .enable_supplemental_broker_admission()
        .expect("supplemental activation");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");

    let response = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .expect("supplemental threshold caller reservation");

    assert_threshold_caller_reserved(&response, &operations);
    let prepared_dispatches = registrar.prepared_dispatches();
    assert_eq!(prepared_dispatches.len(), 1);
    assert_eq!(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata.pointer(
                    "/protocol_admission/invocation_capture/checkedRevocationSetDigest",
                )
            })
            .and_then(serde_json::Value::as_str)
            .map(str::len),
        Some(64),
        "supplemental reserve must carry the combined budget and revocation capture"
    );
    assert_eq!(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata.pointer("/protocol_admission/admission_operation/operation_id")
            })
            .and_then(serde_json::Value::as_str),
        Some(prepared_dispatches[0].as_str()),
        "the single supplemental dispatch preparation must bind the CallerReserved operation"
    );
}

fn caller_reserved_operation_id(response: &ToolCallResponse) -> &str {
    response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| {
            metadata.pointer("/protocol_admission/admission_operation/operation_id")
        })
        .and_then(serde_json::Value::as_str)
        .expect("caller reservation operation id")
}

fn assert_no_payment_recovery_artifacts(
    budget: &dyn crate::budget_store::BudgetStore,
    operations: &dyn AdmissionOperationStore,
    request_id: &str,
    operation_id: &str,
) {
    assert!(
        budget
            .get_payment_journal(request_id)
            .expect("caller reservation payment journal lookup")
            .is_none(),
        "a non-MustPrepay caller reservation must not create a payment journal row"
    );
    assert!(
        budget
            .list_incomplete_payment_journal(u64::MAX)
            .expect("caller reservation incomplete payment journal")
            .is_empty(),
        "a non-MustPrepay caller reservation must leave no startup payment work"
    );
    assert!(
        operations
            .load_cleanup_actions(operation_id)
            .expect("caller reservation cleanup actions")
            .iter()
            .all(|action| action.kind() != AdmissionCleanupActionKind::Payment),
        "a non-MustPrepay caller reservation must not journal Payment cleanup"
    );
}

fn run_no_payment_reconstructed_kernel_pass(
    prefix: &str,
    budget: std::sync::Arc<DurableAtomicTestBudgetStore>,
    operations: std::sync::Arc<ProfiledTestStore>,
    payment: SettlingThresholdPaymentAdapter,
) -> ChioKernel {
    let mut reconstructed = make_admission_saga_kernel();
    reconstructed
        .set_budget_store_handle(budget)
        .expect("reconstructed budget store");
    reconstructed
        .set_admission_operation_store_handle(operations)
        .expect("reconstructed admission operation store");
    reconstructed
        .set_payment_adapter(Box::new(payment))
        .expect("reconstructed payment adapter");
    reconstructed
        .set_receipt_store(Box::new(
            SqliteReceiptStore::open(unique_receipt_db_path(prefix))
                .expect("reconstructed receipt store"),
        ))
        .expect("startup payment reconciliation");
    assert_eq!(
        reconstructed
            .reconcile_payment_journal(0)
            .expect("idempotent payment reconciliation"),
        crate::kernel::payment_reconcile::PaymentReconcileReport::default(),
        "startup and its idempotent retry must find no payment work"
    );
    reconstructed
}

#[test]
fn threshold_non_mustprepay_reservation_survives_kernel_reconstruction_without_payment_recovery() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    request.request_id = "threshold-caller-reserve-no-payment-reconstruction".to_string();
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    let operations =
        durable_test_admission_operation_store("threshold-no-payment-reconstruction-operations");
    let budget = durable_atomic_test_budget_store("threshold-no-payment-reconstruction-budget");
    let payment = SettlingThresholdPaymentAdapter::new();
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("threshold reconstructed operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("threshold reconstructed approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("threshold reconstructed budget store");
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("threshold reconstructed payment adapter");
    kernel
        .set_execution_nonce_store(
            ExecutionNonceConfig {
                require_nonce: true,
                ..ExecutionNonceConfig::default()
            },
            Box::new(DurableThresholdNonceStore::new()),
        )
        .expect("threshold reconstructed nonce store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold reconstructed activation");

    let response = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .expect("threshold non-MustPrepay reservation");
    assert_eq!(response.verdict, Verdict::Allow);
    let operation_id = caller_reserved_operation_id(&response).to_string();
    let operation_before = operations
        .load(&operation_id)
        .expect("threshold operation lookup")
        .expect("threshold caller-reserved operation");
    assert_eq!(operation_before.state(), AdmissionOperationState::CallerReserved);
    let hold_id = operation_before
        .budget_hold_id()
        .expect("threshold caller-reserved hold")
        .to_string();
    let hold_before = budget
        .get_budget_hold(&hold_id)
        .expect("threshold hold lookup")
        .expect("threshold caller-reserved hold");
    assert_no_payment_recovery_artifacts(
        budget.as_ref(),
        operations.as_ref(),
        &request.request_id,
        &operation_id,
    );
    assert!(payment.calls().is_empty(), "reservation moved rail funds");

    drop(kernel);
    let reconstructed = run_no_payment_reconstructed_kernel_pass(
        "threshold-no-payment-reconstruction-receipts",
        budget.clone(),
        operations.clone(),
        payment.clone(),
    );
    assert_eq!(
        budget
            .get_budget_hold(&hold_id)
            .expect("threshold reconstructed hold lookup"),
        Some(hold_before),
        "startup payment reconciliation must not reverse the caller-owned hold"
    );
    assert_eq!(
        operations
            .load(&operation_id)
            .expect("threshold reconstructed operation lookup"),
        Some(operation_before),
        "startup payment reconciliation must not mutate CallerReserved"
    );
    assert_no_payment_recovery_artifacts(
        budget.as_ref(),
        operations.as_ref(),
        &request.request_id,
        &operation_id,
    );
    assert!(
        payment.calls().is_empty(),
        "kernel reconstruction moved rail funds"
    );
    drop(reconstructed);
}

#[test]
fn ordinary_aggregate_non_mustprepay_reservation_survives_kernel_reconstruction_without_payment_recovery(
) {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let operations =
        durable_test_admission_operation_store("ordinary-no-payment-reconstruction-operations");
    let budget = durable_atomic_test_budget_store("ordinary-no-payment-reconstruction-budget");
    let payment = SettlingThresholdPaymentAdapter::new();
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("ordinary reconstructed operation store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("ordinary reconstructed budget store");
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("ordinary reconstructed payment adapter");
    kernel
        .set_execution_nonce_store(
            ExecutionNonceConfig {
                require_nonce: true,
                ..ExecutionNonceConfig::default()
            },
            Box::new(DurableThresholdNonceStore::new()),
        )
        .expect("ordinary reconstructed nonce store");
    kernel
        .enable_aggregate_invocation_admission()
        .expect("ordinary aggregate activation");

    let agent = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1_000, "USD");
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![grant]),
        300,
    );
    let capability = aggregate_limited_capability(&kernel, &capability, 2);
    let request = reserve_request(
        "ordinary-aggregate-caller-reserve-no-payment-reconstruction",
        &capability,
        &agent,
    );
    let response = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .expect("ordinary aggregate non-MustPrepay reservation");
    assert_eq!(response.verdict, Verdict::Allow);
    let operation_id = caller_reserved_operation_id(&response).to_string();
    let operation_before = operations
        .load(&operation_id)
        .expect("ordinary operation lookup")
        .expect("ordinary caller-reserved operation");
    assert_eq!(operation_before.state(), AdmissionOperationState::CallerReserved);
    let hold_id = operation_before
        .budget_hold_id()
        .expect("ordinary caller-reserved hold")
        .to_string();
    let hold_before = budget
        .get_budget_hold(&hold_id)
        .expect("ordinary hold lookup")
        .expect("ordinary caller-reserved hold");
    assert_no_payment_recovery_artifacts(
        budget.as_ref(),
        operations.as_ref(),
        &request.request_id,
        &operation_id,
    );
    assert!(payment.calls().is_empty(), "reservation moved rail funds");

    drop(kernel);
    let reconstructed = run_no_payment_reconstructed_kernel_pass(
        "ordinary-no-payment-reconstruction-receipts",
        budget.clone(),
        operations.clone(),
        payment.clone(),
    );
    assert_eq!(
        budget
            .get_budget_hold(&hold_id)
            .expect("ordinary reconstructed hold lookup"),
        Some(hold_before),
        "startup payment reconciliation must not reverse the caller-owned hold"
    );
    assert_eq!(
        operations
            .load(&operation_id)
            .expect("ordinary reconstructed operation lookup"),
        Some(operation_before),
        "startup payment reconciliation must not mutate CallerReserved"
    );
    assert_no_payment_recovery_artifacts(
        budget.as_ref(),
        operations.as_ref(),
        &request.request_id,
        &operation_id,
    );
    assert!(
        payment.calls().is_empty(),
        "kernel reconstruction moved rail funds"
    );
    drop(reconstructed);
}

#[test]
fn ordinary_noncomposite_non_mustprepay_reservation_survives_kernel_reconstruction_without_payment_recovery(
) {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let operations =
        durable_test_admission_operation_store(
            "ordinary-direct-no-payment-reconstruction-operations",
        );
    let budget =
        durable_atomic_test_budget_store("ordinary-direct-no-payment-reconstruction-budget");
    let payment = SettlingThresholdPaymentAdapter::new();
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("ordinary direct reconstructed operation store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("ordinary direct reconstructed budget store");
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("ordinary direct reconstructed payment adapter");
    kernel
        .set_execution_nonce_store(
            ExecutionNonceConfig {
                require_nonce: true,
                ..ExecutionNonceConfig::default()
            },
            Box::new(DurableThresholdNonceStore::new()),
        )
        .expect("ordinary direct reconstructed nonce store");

    let agent = Keypair::generate();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_monetary_grant(
            "cost-srv", "compute", 100, 1_000, "USD",
        )]),
        300,
    );
    let request = reserve_request(
        "ordinary-direct-caller-reserve-no-payment-reconstruction",
        &capability,
        &agent,
    );
    let response = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .expect("ordinary direct non-MustPrepay reservation");
    assert_eq!(response.verdict, Verdict::Allow);
    let hold_id = response
        .execution_nonce
        .as_ref()
        .and_then(|nonce| nonce.reserved_hold_id())
        .expect("ordinary direct reserved hold")
        .to_string();
    let hold_before = budget
        .get_budget_hold(&hold_id)
        .expect("ordinary direct hold lookup")
        .expect("ordinary direct caller-reserved hold");
    assert!(
        budget
            .get_payment_journal(&request.request_id)
            .expect("ordinary direct payment journal lookup")
            .is_none(),
        "a direct non-MustPrepay reservation must not create a payment journal row"
    );
    assert!(
        budget
            .list_incomplete_payment_journal(u64::MAX)
            .expect("ordinary direct incomplete payment journal")
            .is_empty(),
        "a direct non-MustPrepay reservation must leave no startup payment work"
    );
    assert!(
        operations
            .list_unresolved(Some(AdmissionOperationKind::ToolDispatch), 16)
            .expect("ordinary direct operation inventory")
            .is_empty(),
        "the direct reserve path must not synthesize an admission operation"
    );
    assert!(payment.calls().is_empty(), "reservation moved rail funds");

    drop(kernel);
    let reconstructed = run_no_payment_reconstructed_kernel_pass(
        "ordinary-direct-no-payment-reconstruction-receipts",
        budget.clone(),
        operations,
        payment.clone(),
    );
    assert_eq!(
        budget
            .get_budget_hold(&hold_id)
            .expect("ordinary direct reconstructed hold lookup"),
        Some(hold_before),
        "startup payment reconciliation must not reverse the direct caller-owned hold"
    );
    assert!(
        budget
            .get_payment_journal(&request.request_id)
            .expect("ordinary direct reconstructed payment journal lookup")
            .is_none()
    );
    assert!(
        payment.calls().is_empty(),
        "kernel reconstruction moved rail funds"
    );
    drop(reconstructed);
}
