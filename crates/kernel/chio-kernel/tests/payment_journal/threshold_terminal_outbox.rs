use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        GovernedToolInvocationIntentBody, GovernedTransactionIntent,
    },
    scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant},
};
use chio_core::crypto::Keypair;
use chio_core::session::OperationTerminalState;
use chio_kernel::payment::{
    OperationPaymentCaptureRequest, OperationPaymentRefundRequest, PaymentAdapter,
    PaymentAuthorization, PaymentAuthorizeRequest, PaymentError, PaymentJournalRecord,
    PaymentJournalState, PaymentResult, RailSettlementStatus,
};
use chio_kernel::threshold_approval::{
    authorization_capability_hash, ThresholdApprovalProposal, ThresholdApprovalProposalBody,
    ThresholdApprovalRequest, ThresholdApprovalRequirement,
};
use chio_kernel::{
    AdmissionCleanupActionKind, AdmissionCleanupActionState, AdmissionOperationState,
    AdmissionOperationStore, ApprovalStore, BudgetStore, ChioKernel, KernelError, NestedFlowBridge,
    ReceiptStore, ToolCallRequest, ToolInvocationCost, ToolServerConnection, Verdict,
};
use chio_store_sqlite::{
    SqliteAdmissionOperationStore, SqliteApprovalStore, SqliteBudgetStore, SqliteReceiptStore,
};

use super::support;

#[derive(Debug, Clone)]
struct ThresholdDispatchObservation {
    open_dispatch_intents: u64,
    payment_journal: PaymentJournalRecord,
}

struct ThresholdJournalProbeServer {
    request_id: String,
    budget_store: Arc<SqliteBudgetStore>,
    receipt_store: Arc<SqliteReceiptStore>,
    observations: Arc<Mutex<Vec<ThresholdDispatchObservation>>>,
}

#[async_trait::async_trait]
impl ToolServerConnection for ThresholdJournalProbeServer {
    fn server_id(&self) -> &str {
        "threshold-payments"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["transfer".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        let open_dispatch_intents = self
            .receipt_store
            .open_dispatch_intent_count()
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        let payment_journal = self
            .budget_store
            .get_payment_journal(&self.request_id)
            .map_err(KernelError::from)?
            .ok_or_else(|| {
                KernelError::Internal(
                    "threshold dispatch started without its payment journal".to_string(),
                )
            })?;
        self.observations
            .lock()
            .map_err(|_| {
                KernelError::Internal("threshold dispatch observation lock poisoned".into())
            })?
            .push(ThresholdDispatchObservation {
                open_dispatch_intents,
                payment_journal,
            });
        Ok(serde_json::json!({ "status": "transferred" }))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let output = self.invoke(tool_name, arguments, bridge).await?;
        Ok((
            output,
            Some(ToolInvocationCost {
                units: 75,
                currency: "USD".to_string(),
                breakdown: None,
            }),
        ))
    }
}

#[derive(Clone)]
struct AckLossOperationPaymentRail {
    authorization: Arc<Mutex<Option<(String, String, PaymentAuthorization)>>>,
    capture: Arc<Mutex<Option<(String, String, PaymentResult)>>>,
    lose_capture_ack: Arc<AtomicBool>,
    capture_attempts: Arc<AtomicUsize>,
    capture_mutations: Arc<AtomicUsize>,
}

impl AckLossOperationPaymentRail {
    fn new() -> Self {
        Self {
            authorization: Arc::new(Mutex::new(None)),
            capture: Arc::new(Mutex::new(None)),
            lose_capture_ack: Arc::new(AtomicBool::new(true)),
            capture_attempts: Arc::new(AtomicUsize::new(0)),
            capture_mutations: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn ensure_request_binding(
        operation_id: &str,
        request_binding_hash: &str,
        request: &PaymentAuthorizeRequest,
    ) -> Result<(), PaymentError> {
        if request.operation_id.as_deref() != Some(operation_id)
            || request.request_binding_hash.as_deref() != Some(request_binding_hash)
        {
            return Err(PaymentError::RailError(
                "threshold payment authorization changed its operation binding".to_string(),
            ));
        }
        Ok(())
    }

    fn capture_attempts(&self) -> usize {
        self.capture_attempts.load(Ordering::SeqCst)
    }

    fn capture_mutations(&self) -> usize {
        self.capture_mutations.load(Ordering::SeqCst)
    }
}

impl PaymentAdapter for AckLossOperationPaymentRail {
    fn rail_id(&self) -> &str {
        "threshold-test-rail"
    }

    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Err(PaymentError::OperationIdempotencyUnsupported("authorize"))
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::OperationIdempotencyUnsupported("capture"))
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::OperationIdempotencyUnsupported("release"))
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::OperationIdempotencyUnsupported("refund"))
    }

    fn authorize_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Self::ensure_request_binding(operation_id, request_binding_hash, request)?;
        let mut authorization = self.authorization.lock().map_err(|_| {
            PaymentError::RailError("threshold authorization lock poisoned".to_string())
        })?;
        if let Some((stored_operation_id, stored_binding_hash, stored)) = authorization.as_ref() {
            if stored_operation_id != operation_id || stored_binding_hash != request_binding_hash {
                return Err(PaymentError::RailError(
                    "threshold payment operation was rebound".to_string(),
                ));
            }
            return Ok(stored.clone());
        }
        let created = PaymentAuthorization {
            authorization_id: format!("threshold-authorization:{operation_id}"),
            settled: false,
            metadata: serde_json::json!({
                "operation_id": operation_id,
                "request_binding_hash": request_binding_hash,
            }),
        };
        *authorization = Some((
            operation_id.to_string(),
            request_binding_hash.to_string(),
            created.clone(),
        ));
        Ok(created)
    }

    fn lookup_authorization_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        let authorization = self.authorization.lock().map_err(|_| {
            PaymentError::RailError("threshold authorization lock poisoned".to_string())
        })?;
        match authorization.as_ref() {
            Some((stored_operation_id, stored_binding_hash, stored))
                if stored_operation_id == operation_id
                    && stored_binding_hash == request_binding_hash =>
            {
                Ok(Some(stored.clone()))
            }
            Some(_) => Err(PaymentError::RailError(
                "threshold authorization lookup observed a rebound operation".to_string(),
            )),
            None => Ok(None),
        }
    }

    fn capture_for_operation(
        &self,
        request: OperationPaymentCaptureRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        self.capture_attempts.fetch_add(1, Ordering::SeqCst);
        let mut capture = self
            .capture
            .lock()
            .map_err(|_| PaymentError::RailError("threshold capture lock poisoned".to_string()))?;
        let result = match capture.as_ref() {
            Some((stored_operation_id, stored_binding_hash, stored)) => {
                if stored_operation_id != request.operation_id
                    || stored_binding_hash != request.request_binding_hash
                {
                    return Err(PaymentError::RailError(
                        "threshold capture observed a rebound operation".to_string(),
                    ));
                }
                stored.clone()
            }
            None => {
                let result = PaymentResult {
                    transaction_id: format!("threshold-capture:{}", request.operation_id),
                    settlement_status: RailSettlementStatus::Settled,
                    metadata: serde_json::json!({
                        "operation_id": request.operation_id,
                        "request_binding_hash": request.request_binding_hash,
                    }),
                };
                *capture = Some((
                    request.operation_id.to_string(),
                    request.request_binding_hash.to_string(),
                    result.clone(),
                ));
                self.capture_mutations.fetch_add(1, Ordering::SeqCst);
                result
            }
        };
        drop(capture);
        if self.lose_capture_ack.swap(false, Ordering::SeqCst) {
            return Err(PaymentError::Unavailable(
                "injected threshold capture acknowledgement loss".to_string(),
            ));
        }
        Ok(result)
    }

    fn release_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: format!("threshold-release:{operation_id}"),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({
                "operation_id": operation_id,
                "request_binding_hash": request_binding_hash,
            }),
        })
    }

    fn refund_for_operation(
        &self,
        request: OperationPaymentRefundRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: request.transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({
                "operation_id": request.operation_id,
                "request_binding_hash": request.request_binding_hash,
            }),
        })
    }
}

struct ThresholdArtifacts {
    request: ToolCallRequest,
    operation_store: Arc<SqliteAdmissionOperationStore>,
    budget_store: Arc<SqliteBudgetStore>,
    receipt_store: Arc<SqliteReceiptStore>,
    payment: AckLossOperationPaymentRail,
    observations: Arc<Mutex<Vec<ThresholdDispatchObservation>>>,
    paths: Vec<std::path::PathBuf>,
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn make_threshold_intent() -> GovernedTransactionIntent {
    GovernedTransactionIntent::tool_invocation(GovernedToolInvocationIntentBody {
        id: "threshold-terminal-intent".to_string(),
        server_id: "threshold-payments".to_string(),
        tool_name: "transfer".to_string(),
        purpose: "approved threshold transfer".to_string(),
        max_amount: Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
    })
}

fn install_threshold_artifacts(
    kernel: &mut ChioKernel,
    request: &mut ToolCallRequest,
    policy_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy_authority = Keypair::generate();
    let approvers = [Keypair::generate(), Keypair::generate()];
    let requirement = ThresholdApprovalRequirement::new(
        2,
        BTreeMap::from([
            ("approver-a".to_string(), approvers[0].public_key()),
            ("approver-b".to_string(), approvers[1].public_key()),
        ]),
        900,
        policy_hash.to_string(),
        1,
    )?;
    let resolved_requirement = requirement.clone();
    kernel.set_threshold_approval_requirement_resolver(Arc::new(
        move |_: &ThresholdApprovalRequest, _: &str| Ok(resolved_requirement.clone()),
    ))?;
    kernel.set_threshold_approval_policy_authority(policy_authority.public_key())?;

    let intent = request
        .governed_intent
        .as_ref()
        .ok_or("threshold request omitted its governed intent")?;
    let intent_hash = intent.binding_hash()?;
    let capability_hash = authorization_capability_hash(&request.capability)?;
    let now = current_unix_timestamp();
    let proposal_body = ThresholdApprovalProposalBody::new(
        format!("proposal-{}", request.request_id),
        request.request_id.clone(),
        intent_hash.clone(),
        request.capability.subject.clone(),
        capability_hash,
        requirement.policy_hash().to_string(),
        requirement.required(),
        requirement.eligible_set_digest(),
        now.saturating_sub(10),
        requirement.proposal_timeout_seconds(),
        request.capability.expires_at,
        request.capability.expires_at,
    )?;
    let proposal = ThresholdApprovalProposal::sign(proposal_body, &policy_authority)?;
    let proposal_hash = proposal.proposal_hash()?;
    let proposal_deadline = proposal.body().proposal_deadline();
    request.threshold_approval_proposal = Some(proposal);
    request.approval_tokens = approvers
        .iter()
        .enumerate()
        .map(|(index, approver)| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: format!("threshold-terminal-approval-{index}"),
                    approver: approver.public_key(),
                    subject: request.capability.subject.clone(),
                    governed_intent_hash: intent_hash.clone(),
                    threshold_proposal_hash: Some(proposal_hash.clone()),
                    request_id: request.request_id.clone(),
                    issued_at: now.saturating_sub(1),
                    expires_at: proposal_deadline,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(())
}

fn threshold_fixture() -> Result<(ChioKernel, ThresholdArtifacts), Box<dyn std::error::Error>> {
    let request_id = "threshold-terminal-request-id";
    let policy_hash = "33".repeat(32);
    let receipt_path = support::unique_db_path("threshold-terminal-receipts");
    let budget_path = support::unique_db_path("threshold-terminal-budget");
    let operation_path = support::unique_db_path("threshold-terminal-operations");
    let approval_path = support::unique_db_path("threshold-terminal-approvals");
    let receipt_store = Arc::new(SqliteReceiptStore::open(&receipt_path)?);
    let budget_store = Arc::new(SqliteBudgetStore::open(&budget_path)?);
    let operation_store = Arc::new(SqliteAdmissionOperationStore::open(&operation_path)?);
    let approval_store = Arc::new(SqliteApprovalStore::open(&approval_path)?);
    let payment = AckLossOperationPaymentRail::new();
    let observations = Arc::new(Mutex::new(Vec::new()));

    let mut config = support::money_config(Keypair::generate());
    config.policy_hash = policy_hash.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.set_admission_operation_store_handle(
        Arc::clone(&operation_store) as Arc<dyn AdmissionOperationStore>
    )?;
    kernel.set_approval_store_handle(Arc::clone(&approval_store) as Arc<dyn ApprovalStore>)?;
    kernel.set_budget_store_handle(Arc::clone(&budget_store) as Arc<dyn BudgetStore>)?;
    kernel.set_receipt_store_handle(Arc::clone(&receipt_store) as Arc<dyn ReceiptStore>)?;
    kernel.set_payment_adapter(Box::new(payment.clone()))?;
    kernel.register_tool_server(Box::new(ThresholdJournalProbeServer {
        request_id: request_id.to_string(),
        budget_store: Arc::clone(&budget_store),
        receipt_store: Arc::clone(&receipt_store),
        observations: Arc::clone(&observations),
    }));

    let subject = Keypair::generate();
    let grant = ToolGrant {
        server_id: "threshold-payments".to_string(),
        tool_name: "transfer".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![
            Constraint::GovernedIntentRequired,
            Constraint::RequireApprovalAbove {
                threshold_units: 50,
            },
        ],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: 1_000,
            currency: "USD".to_string(),
        }),
        dpop_required: None,
    };
    let capability = kernel.issue_capability(
        &subject.public_key(),
        ChioScope {
            grants: vec![grant],
            ..ChioScope::default()
        },
        3_600,
    )?;
    let mut request = ToolCallRequest {
        request_id: request_id.to_string(),
        capability,
        tool_name: "transfer".to_string(),
        server_id: "threshold-payments".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: serde_json::json!({ "amount": 75 }),
        supplemental_authorization: None,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(make_threshold_intent()),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    install_threshold_artifacts(&mut kernel, &mut request, &policy_hash)?;
    kernel.enable_threshold_governed_approvals()?;

    Ok((
        kernel,
        ThresholdArtifacts {
            request,
            operation_store,
            budget_store,
            receipt_store,
            payment,
            observations,
            paths: vec![receipt_path, budget_path, operation_path, approval_path],
        },
    ))
}

#[test]
fn threshold_terminal_receipt_uses_request_id_to_close_intent_and_journal(
) -> Result<(), Box<dyn std::error::Error>> {
    let (kernel, artifacts) = threshold_fixture()?;
    let response = kernel.evaluate_tool_call_blocking(&artifacts.request)?;

    assert_eq!(response.request_id, artifacts.request.request_id);
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(response.terminal_state, OperationTerminalState::Completed);
    assert!(!response.receipt.is_incomplete());
    assert_eq!(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.pointer("/receipt_context/request_id"))
            .and_then(serde_json::Value::as_str),
        Some(artifacts.request.request_id.as_str()),
        "the signed terminal receipt must carry the exact dispatch request id"
    );

    let observations = artifacts
        .observations
        .lock()
        .map_err(|_| "threshold observations lock poisoned")?;
    assert_eq!(observations.len(), 1);
    let observation = &observations[0];
    assert_eq!(
        observation.open_dispatch_intents, 1,
        "the side effect must observe its durable dispatch intent"
    );
    assert_eq!(
        observation.payment_journal.state,
        PaymentJournalState::Authorized,
        "the side effect must observe an Authorized payment row"
    );
    assert_eq!(
        observation.payment_journal.request_id.as_str(),
        artifacts.request.request_id.as_str()
    );
    let admission_binding = observation
        .payment_journal
        .admission_operation
        .as_ref()
        .ok_or("threshold journal omitted its admission operation binding")?;
    let operation_id = admission_binding.operation_id().to_string();
    let request_binding_hash = admission_binding.request_binding_hash().to_string();
    drop(observations);
    assert_ne!(operation_id, artifacts.request.request_id);

    assert_eq!(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata.pointer("/protocol_admission/admission_operation/operation_id")
            })
            .and_then(serde_json::Value::as_str),
        Some(operation_id.as_str())
    );
    let operation = artifacts
        .operation_store
        .load(&operation_id)?
        .ok_or("threshold admission operation disappeared")?;
    assert_eq!(
        operation.request_id(),
        artifacts.request.request_id.as_str()
    );
    assert_eq!(
        operation.request_binding_hash(),
        request_binding_hash.as_str()
    );
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    let cleanup_actions = artifacts
        .operation_store
        .load_cleanup_actions(&operation_id)?;
    assert!(cleanup_actions.iter().any(|action| {
        action.kind() == AdmissionCleanupActionKind::TerminalReceipt
            && action.state() == AdmissionCleanupActionState::Completed
    }));

    assert_eq!(artifacts.payment.capture_attempts(), 2);
    assert_eq!(
        artifacts.payment.capture_mutations(),
        1,
        "capture acknowledgement recovery must not move money twice"
    );
    assert_eq!(artifacts.receipt_store.open_dispatch_intent_count()?, 0);
    assert!(artifacts
        .budget_store
        .get_payment_journal(&artifacts.request.request_id)?
        .is_none());
    assert!(artifacts
        .budget_store
        .list_incomplete_payment_journal(u64::MAX)?
        .iter()
        .all(|row| row.request_id != artifacts.request.request_id));

    let budget_path = &artifacts.paths[1];
    let journal_state: String = rusqlite::Connection::open(budget_path)?.query_row(
        "SELECT state FROM payment_journal WHERE request_id = ?1",
        [&artifacts.request.request_id],
        |row| row.get(0),
    )?;
    assert_eq!(journal_state, "closed");

    drop(kernel);
    drop(artifacts.operation_store);
    drop(artifacts.budget_store);
    drop(artifacts.receipt_store);
    for path in artifacts.paths {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}
