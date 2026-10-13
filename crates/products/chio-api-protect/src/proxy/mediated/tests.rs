use super::*;
use crate::evaluator::DurableAdmissionStores;
use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
use chio_kernel::{CallerExecutionReport, ToolInvocationCost};
use chio_test_support::prelude::*;
use tower::ServiceExt;

#[path = "tests/approvals.rs"]
mod approvals;
#[path = "tests/authenticated.rs"]
mod authenticated;
#[path = "tests/authorization.rs"]
mod authorization;
#[path = "../tests/mediated_boundary_tests.rs"]
mod boundary_tests;
#[path = "tests/reconcile_numbers.rs"]
mod reconcile_numbers;
#[path = "../tests/subject_identity.rs"]
mod subject_identity;

fn issuing_kernel(
    signer: &Keypair,
    budget: Arc<dyn BudgetStore>,
    trusted_capability_issuers: &[PublicKey],
) -> Arc<ChioKernel> {
    Arc::new(
        build_mediation_kernel(
            signer,
            MediationBudget::Configured(budget),
            super::MediationPolicy {
                issuers: trusted_capability_issuers,
                hash: None,
                receipt_store: None,
            },
            Vec::new(),
            None,
            Arc::new(clock::ProxyClock::default()),
        )
        .test_unwrap(),
    )
}

fn issue_cost_bearing_capability(
    kernel: &Arc<ChioKernel>,
    agent: &Keypair,
    server: &str,
    tool: &str,
    max_per: u64,
    max_total: u64,
    currency: &str,
) -> CapabilityToken {
    use chio_core_types::capability::scope::MonetaryAmount;
    let grant = ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: max_per,
            currency: currency.to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: max_total,
            currency: currency.to_string(),
        }),
        dpop_required: None,
    };
    let scope = ChioScope {
        grants: vec![grant],
        ..ChioScope::default()
    };
    kernel
        .issue_capability(&agent.public_key(), scope, 3600)
        .test_unwrap()
}

/// Issue an invocation-limited capability without monetary exposure.
fn issue_invocation_capability(
    kernel: &Arc<ChioKernel>,
    agent: &Keypair,
    server: &str,
    tool: &str,
    max_invocations: u32,
) -> CapabilityToken {
    let grant = ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: Some(max_invocations),
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let scope = ChioScope {
        grants: vec![grant],
        ..ChioScope::default()
    };
    kernel
        .issue_capability(&agent.public_key(), scope, 3600)
        .test_unwrap()
}

const MEDIATED_CONTROL_TOKEN: &str = "tool-server-control-token";

fn mediated_test_state(
    signer: Keypair,
    durable: DurableAdmissionStores,
    trusted_capability_issuers: Vec<PublicKey>,
) -> Arc<ProxyState> {
    mediated_test_state_with_control_token(
        signer,
        durable,
        trusted_capability_issuers,
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
    )
}

fn mediated_test_state_with_control_token(
    signer: Keypair,
    durable: DurableAdmissionStores,
    trusted_capability_issuers: Vec<PublicKey>,
    sidecar_control_token: Option<String>,
) -> Arc<ProxyState> {
    mediated_test_state_inner(
        signer,
        durable,
        trusted_capability_issuers,
        sidecar_control_token,
        None,
    )
}

fn mediated_test_state_inner(
    signer: Keypair,
    durable: DurableAdmissionStores,
    trusted_capability_issuers: Vec<PublicKey>,
    sidecar_control_token: Option<String>,
    receipt_store: Option<SqliteReceiptStore>,
) -> Arc<ProxyState> {
    mediated_test_state_core(
        signer,
        durable,
        trusted_capability_issuers,
        sidecar_control_token,
        receipt_store,
        Some(Box::new(
            chio_store_sqlite::SqliteFindingOperatorPaymentAdapter::open_in_memory().test_unwrap(),
        )),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
/// Reserve durably with the pinned executor; rail I/O starts at committed execution.
fn mediated_test_state_core(
    signer: Keypair,
    durable: DurableAdmissionStores,
    trusted_capability_issuers: Vec<PublicKey>,
    sidecar_control_token: Option<String>,
    receipt_store: Option<SqliteReceiptStore>,
    payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
    revocation_store: Option<Arc<dyn chio_kernel::RevocationStore>>,
) -> Arc<ProxyState> {
    let state = mediated_test_state_with_durable_admission(
        signer,
        MediationBudget::Durable(durable),
        trusted_capability_issuers,
        sidecar_control_token,
        receipt_store,
        payment_adapter,
        revocation_store,
    );
    state
        .mediation_kernel
        .as_ref()
        .test_unwrap()
        .try_lock()
        .test_unwrap()
        .set_caller_executor(caller_executor_identity())
        .test_unwrap();
    state
}

fn durable_admission_stores(directory: &std::path::Path) -> DurableAdmissionStores {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).test_unwrap();
    }
    let database = directory.join("admission.db");
    let locks = directory.join("locks");
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&locks).test_unwrap();
    chio_store_sqlite::SqliteAuthorityStore::provision(&database, &locks).test_unwrap();
    reopen_durable_admission_stores(directory)
}

fn reopen_durable_admission_stores(directory: &std::path::Path) -> DurableAdmissionStores {
    let authority = chio_store_sqlite::SqliteAuthorityStore::open_serving(
        directory.join("admission.db"),
        directory.join("locks"),
    )
    .test_unwrap();
    DurableAdmissionStores {
        store: Arc::new(authority.admission_operation_store()),
        outcome_store: Arc::new(authority.tool_outcome_store()),
        fence: authority.mutation_fence(),
        budget_store: Arc::new(authority.budget_store()),
    }
}

#[allow(clippy::too_many_arguments)]
fn mediated_test_state_with_durable_admission(
    signer: Keypair,
    budget: MediationBudget,
    trusted_capability_issuers: Vec<PublicKey>,
    sidecar_control_token: Option<String>,
    receipt_store: Option<SqliteReceiptStore>,
    payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
    revocation_store: Option<Arc<dyn chio_kernel::RevocationStore>>,
) -> Arc<ProxyState> {
    let budget_store = budget.store();
    let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
    let signer_public_key = signer.public_key();
    let mut trusted_capability_issuers = trusted_capability_issuers;
    if !trusted_capability_issuers.contains(&signer_public_key) {
        trusted_capability_issuers.push(signer_public_key.clone());
    }
    let trusted_receipt_signers = vec![signer_public_key];
    let evaluator = RequestEvaluator::new_ephemeral_with_approval_store(
        Vec::new(),
        signer.clone(),
        "test-policy".to_string(),
        Arc::clone(&approval_store),
    );
    let egress_contract = default_upstream_egress_contract("http://127.0.0.1:1").test_unwrap();
    let http_client = client_builder_with_contract(&egress_contract)
        .build()
        .test_unwrap();
    let mediation_kernel = Mutex::new(
        build_mediation_kernel(
            &signer,
            budget,
            super::MediationPolicy {
                issuers: &trusted_capability_issuers,
                hash: None,
                receipt_store: None,
            },
            Vec::new(),
            payment_adapter,
            Arc::new(clock::ProxyClock::default()),
        )
        .test_unwrap(),
    );
    Arc::new(ProxyState {
        clock: clock::ProxyClock::default(),
        evaluator,
        signer_keypair: signer,
        upstream: "http://127.0.0.1:1".to_string(),
        http_client,
        egress_contract,
        approval_admin: ApprovalAdmin::new(approval_store),
        approval_config: None,
        receipt_log: Mutex::new(ReceiptLog {
            receipts: Vec::new(),
        }),
        tool_receipt_log: Mutex::new(ToolReceiptLog {
            receipts: Vec::new(),
        }),
        receipt_store: receipt_store.map(Mutex::new),
        revocation_store,
        revoked_capability_ids: Mutex::new(std::collections::HashSet::new()),
        trusted_capability_issuers,
        trusted_receipt_signers,
        sidecar_control_token,
        budget_store: Some(budget_store),
        mediation_kernel: Some(Arc::new(mediation_kernel)),
        minted_request_ids: Mutex::new(MintedRequestIdWindow::new(
            chio_kernel::DEFAULT_EXECUTION_NONCE_TTL_SECS,
        )),
        allow_advisory: false,
        receipt_backend: "ephemeral",
        revocation_backend: "ephemeral",
    })
}

fn with_loopback_peer(request: axum::http::Request<Body>) -> axum::http::Request<Body> {
    use axum::extract::ConnectInfo;
    let mut request = request;
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            4100,
        ))));
    request
}

use chio_core_types::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, MeteredBillingContext, MeteredBillingQuote, MeteredSettlementMode,
};
use chio_core_types::capability::scope::{Constraint, MonetaryAmount};
use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;
use chio_kernel::dpop::{DpopProof, DpopProofBody, DPOP_SCHEMA};

fn issue_governed_capability(
    kernel: &Arc<ChioKernel>,
    agent: &Keypair,
    server: &str,
    tool: &str,
    max_per: u64,
    currency: &str,
    approval_threshold_units: u64,
) -> CapabilityToken {
    let grant = ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![
            Constraint::GovernedIntentRequired,
            Constraint::RequireApprovalAbove {
                threshold_units: approval_threshold_units,
            },
        ],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: max_per,
            currency: currency.to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: max_per,
            currency: currency.to_string(),
        }),
        dpop_required: None,
    };
    let scope = ChioScope {
        grants: vec![grant],
        ..ChioScope::default()
    };
    kernel
        .issue_capability(&agent.public_key(), scope, 3600)
        .test_unwrap()
}

fn issue_dpop_capability(
    kernel: &Arc<ChioKernel>,
    agent: &Keypair,
    server: &str,
    tool: &str,
    max_per: u64,
    currency: &str,
) -> CapabilityToken {
    issue_dpop_capability_with_total(kernel, agent, server, tool, max_per, max_per, currency)
}

fn issue_dpop_capability_with_total(
    kernel: &Arc<ChioKernel>,
    agent: &Keypair,
    server: &str,
    tool: &str,
    max_per: u64,
    max_total: u64,
    currency: &str,
) -> CapabilityToken {
    let grant = ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: max_per,
            currency: currency.to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: max_total,
            currency: currency.to_string(),
        }),
        dpop_required: Some(true),
    };
    let scope = ChioScope {
        grants: vec![grant],
        ..ChioScope::default()
    };
    kernel
        .issue_capability(&agent.public_key(), scope, 3600)
        .test_unwrap()
}

fn governed_intent(
    id: &str,
    server: &str,
    tool: &str,
    units: u64,
    currency: &str,
) -> GovernedTransactionIntent {
    GovernedTransactionIntent {
        id: id.to_string(),
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        purpose: "invoice-settlement".to_string(),
        max_amount: Some(MonetaryAmount {
            units,
            currency: currency.to_string(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    }
}

/// Bind the governed transaction to a prepaid quote.
fn governed_mustprepay_intent(
    id: &str,
    server: &str,
    tool: &str,
    units: u64,
    currency: &str,
) -> GovernedTransactionIntent {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .test_unwrap()
        .as_secs();
    let mut intent = governed_intent(id, server, tool, units, currency);
    intent.metered_billing = Some(MeteredBillingContext {
        settlement_mode: MeteredSettlementMode::MustPrepay,
        quote: MeteredBillingQuote {
            quote_id: format!("quote-{id}"),
            provider: "billing.chio".to_string(),
            billing_unit: "call".to_string(),
            quoted_units: 1,
            quoted_cost: MonetaryAmount {
                units,
                currency: currency.to_string(),
            },
            issued_at: now.saturating_sub(5),
            expires_at: Some(now + 300),
        },
        max_billed_units: Some(2),
        verified_outcome: None,
    });
    intent
}

fn governed_approval_token(
    approver: &Keypair,
    subject: &PublicKey,
    intent: &GovernedTransactionIntent,
    request_id: &str,
) -> GovernedApprovalToken {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .test_unwrap()
        .as_secs();
    GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("approval-{request_id}"),
            approver: approver.public_key(),
            subject: subject.clone(),
            governed_intent_hash: intent.binding_hash().test_unwrap(),
            request_id: request_id.to_string(),
            threshold_proposal_hash: None,
            issued_at: now.saturating_sub(1),
            expires_at: now + 300,
            decision: GovernedApprovalDecision::Approved,
        },
        approver,
    )
    .test_unwrap()
}

fn dpop_proof_for(
    agent: &Keypair,
    cap: &CapabilityToken,
    server: &str,
    tool: &str,
    parameters: &serde_json::Value,
) -> DpopProof {
    let args_bytes = chio_core_types::canonical::canonical_json_bytes(parameters).test_unwrap();
    let action_hash = chio_core_types::crypto::sha256_hex(&args_bytes);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .test_unwrap()
        .as_secs();
    DpopProof::sign(
        DpopProofBody {
            replay_authority: None,
            schema: DPOP_SCHEMA.to_string(),
            capability_id: cap.id.clone(),
            tool_server: server.to_string(),
            tool_name: tool.to_string(),
            action_hash,
            nonce: uuid::Uuid::now_v7().to_string(),
            issued_at: now,
            agent_key: agent.public_key(),
        },
        agent,
    )
    .test_unwrap()
}

async fn post_evaluate(
    state: Arc<ProxyState>,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    post_json(state, "/v1/evaluate", body).await
}

fn caller_executor_key() -> Keypair {
    Keypair::from_seed(&[19; 32])
}

fn caller_executor_identity() -> chio_kernel::caller_delivery::CallerExecutorIdentityV1 {
    chio_kernel::caller_delivery::CallerExecutorIdentityV1 {
        executor_id: chio_kernel::admission_operation::AdmissionIdentifier::try_new(
            "executor_id",
            "api-protect-test-executor",
        )
        .test_unwrap(),
        public_key: caller_executor_key().public_key(),
        key_epoch: 1,
    }
}

struct CallerExecutorFixture {
    _directory: tempfile::TempDir,
    key: Keypair,
    ledger: chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger,
}

impl CallerExecutorFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().test_unwrap();
        let ledger =
            chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger::provision(
                &directory.path().join("executor.db"),
                caller_executor_identity(),
                64,
            )
            .test_unwrap();
        Self {
            _directory: directory,
            key: caller_executor_key(),
            ledger,
        }
    }

    async fn report_request(
        &self,
        state: Arc<ProxyState>,
        nonce: &serde_json::Value,
        arguments: &serde_json::Value,
        cost: ToolInvocationCost,
    ) -> serde_json::Value {
        let (status, started) = post_json_with_bearer(
            Arc::clone(&state),
            "/v1/caller/start",
            &serde_json::json!({
                "protocol": "chio.caller-delivery.v1",
                "execution_nonce": nonce,
                "arguments": arguments,
            }),
            Some(MEDIATED_CONTROL_TOKEN),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{started}");
        let authorization: chio_kernel::caller_delivery::SignedCallerDispatchAuthorizationV1 =
            serde_json::from_value(started["authorization"].clone()).test_unwrap();
        let report = self
            .ledger
            .execute_once(
                &authorization,
                &state.signer_keypair.public_key(),
                &authorization.authorization.invocation,
                &self.key,
                || {
                    Ok(chio_kernel::CallerExecutionReport {
                        output: serde_json::json!({"returned": true, "cost_breakdown": cost.breakdown.clone()}),
                        realized_cost: Some(cost),
                    })
                },
            )
            .test_unwrap();
        serde_json::json!({
            "protocol": "chio.caller-delivery.v1",
            "authorization": authorization,
            "report": report,
        })
    }
}

async fn post_caller_report(
    state: Arc<ProxyState>,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    post_json_with_bearer(
        state,
        "/v1/caller/report",
        body,
        Some(MEDIATED_CONTROL_TOKEN),
    )
    .await
}

async fn post_json(
    state: Arc<ProxyState>,
    uri: &str,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    post_json_with_bearer(state, uri, body, None).await
}

async fn post_json_with_bearer(
    state: Arc<ProxyState>,
    uri: &str,
    body: &serde_json::Value,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    let request = with_loopback_peer(
        builder
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap(),
    );
    let response = build_app(state).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

fn open_temp_receipt_store() -> (std::path::PathBuf, SqliteReceiptStore) {
    let dir = std::env::temp_dir().join(format!("chio-receipt-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("receipts.sqlite");
    let store = SqliteReceiptStore::open(&db.to_string_lossy()).unwrap();
    (db, store)
}

fn failing_receipt_store() -> SqliteReceiptStore {
    let (db, store) = open_temp_receipt_store();
    let dropper = rusqlite::Connection::open(&db).unwrap();
    dropper
        .execute("DROP TABLE chio_tool_receipts", [])
        .unwrap();
    drop(dropper);
    store
}

#[derive(Clone, Default)]
struct RecordingPaymentAdapter {
    inner: chio_kernel::payment::SimPaymentAdapter,
    captures: Arc<std::sync::atomic::AtomicUsize>,
    releases: Arc<std::sync::atomic::AtomicUsize>,
    refunds: Arc<std::sync::atomic::AtomicUsize>,
}

impl chio_kernel::PaymentAdapter for RecordingPaymentAdapter {
    fn authorize(
        &self,
        request: &chio_kernel::PaymentAuthorizeRequest,
    ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
        let authorization = self.inner.authorize(request)?;
        if authorization.state.is_final() {
            self.captures
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(authorization)
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        self.captures
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner
            .capture(authorization_id, amount_units, currency, reference)
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        self.releases
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.release(authorization_id, reference)
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        self.refunds
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner
            .refund(transaction_id, amount_units, currency, reference)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_receipt_persistence_failure_returns_nonce_and_keeps_reservation() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
    let cap_id = cap.id.clone();
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state_inner(
        signer,
        durable.clone(),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        Some(failing_receipt_store()),
    );
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" },
        "request_id": "persist-fail",
    });

    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "reserved");
    assert_eq!(json["evidence_persisted"], false);
    assert!(
        json["execution_nonce"].is_object(),
        "a persistence failure after a successful reserve must still return the nonce"
    );

    let hold_id = json["receipt"]["metadata"]["budget_authority"]["hold_id"]
        .as_str()
        .expect("the reservation receipt must name its budget hold");
    let hold = budget.get_budget_hold(hold_id).unwrap();
    assert!(
        hold.map(|hold| hold.disposition.is_open()).unwrap_or(false),
        "a returned reservation must keep its reserved hold open"
    );
    let usage = budget.get_usage(&cap_id, 0).unwrap();
    let usage = usage.expect("the reserved hold must remain recorded in the budget store");
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        100,
        "the returned reservation must keep its reserved budget committed"
    );

    assert_eq!(
        state.minted_request_ids.lock().await.len(),
        1,
        "a returned reservation must retain its request-id claim"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_receipt_persistence_success_keeps_reservation() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
    let cap_id = cap.id.clone();
    let cap_value = serde_json::to_value(&cap).unwrap();
    let (_db, receipt_store) = open_temp_receipt_store();
    let state = mediated_test_state_inner(
        signer,
        durable.clone(),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        Some(receipt_store),
    );
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" },
        "request_id": "persist-ok",
    });

    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "reserved");
    assert_eq!(json["evidence_persisted"], true);
    assert!(json["execution_nonce"].is_object());

    let usage = budget.get_usage(&cap_id, 0).unwrap();
    let usage = usage.expect("the reserved hold must remain recorded in the budget store");
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        100,
        "a persisted authorization must keep its reserved hold"
    );
    assert_eq!(
        state.minted_request_ids.lock().await.len(),
        1,
        "a persisted authorization must retain its request-id claim"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_invocation_receipt_persistence_failure_returns_nonce_and_keeps_reservation() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
    let cap_id = cap.id.clone();
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state_inner(
        signer,
        durable.clone(),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        Some(failing_receipt_store()),
    );
    let params = serde_json::json!({ "invoice": "inv-1" });
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "invoke-persist-fail",
    });

    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "reserved");
    assert_eq!(json["evidence_persisted"], false);
    let nonce_json = json["execution_nonce"].clone();
    assert!(
        nonce_json.is_object(),
        "an invocation reserve whose receipt fails to persist must still return the nonce"
    );

    let usage = budget.get_usage(&cap_id, 0).unwrap();
    assert_eq!(
        usage.map(|usage| usage.invocation_count).unwrap_or(0),
        1,
        "the returned invocation reservation stays consumed against the grant"
    );
    let hold_id = json["receipt"]["metadata"]["budget_authority"]["hold_id"]
        .as_str()
        .expect("the reservation receipt must name its budget hold");
    let hold = budget.get_budget_hold(hold_id).unwrap();
    assert!(
        hold.map(|hold| hold.disposition.is_open()).unwrap_or(false),
        "the returned invocation reservation must keep its reserved hold open"
    );

    let caller = CallerExecutorFixture::new();
    let report_body = caller
        .report_request(
            Arc::clone(&state),
            &nonce_json,
            &params,
            ToolInvocationCost {
                units: 0,
                currency: "USD".to_string(),
                breakdown: None,
            },
        )
        .await;
    let (recon_status, reconciled) = post_caller_report(state, &report_body).await;
    assert_eq!(recon_status, StatusCode::OK);
    assert_eq!(reconciled["status"], "reconciled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_direct_approval_rejects_before_payment_and_receipt_side_effects() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_governed_capability(&kernel, &agent, "cost-srv", "compute", 100, "USD", 50);
    let cap_value = serde_json::to_value(&cap).unwrap();
    let approver = signer.clone();

    let captures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let refunds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let adapter = RecordingPaymentAdapter {
        inner: chio_kernel::payment::SimPaymentAdapter::new(),
        captures: Arc::clone(&captures),
        releases: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        refunds: Arc::clone(&refunds),
    };
    let state = mediated_test_state_core(
        signer,
        durable.clone(),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        Some(failing_receipt_store()),
        Some(Box::new(adapter)),
        None,
    );

    let request_id = "req-mustprepay-persist-fail";
    let intent =
        governed_mustprepay_intent("intent-prepay-persist", "cost-srv", "compute", 100, "USD");
    let approval = governed_approval_token(&approver, &agent.public_key(), &intent, request_id);
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" },
        "request_id": request_id,
        "governed_intent": intent,
        "approval_token": approval,
    });

    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json["message"],
        "use approval_id to redeem the retained server-built approval"
    );
    assert_eq!(captures.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(refunds.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(budget.get_usage(&cap.id, 0).test_unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_invocation_reconcile_keeps_invocation_consumed() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
    let cap_id = cap.id.clone();
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());
    let params = serde_json::json!({ "invoice": "inv-1" });

    let reserve_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "invoke-reconcile",
    });
    let (_, authorized) = post_evaluate(Arc::clone(&state), &reserve_body).await;
    assert_eq!(authorized["status"], "reserved");
    let nonce_json = authorized["execution_nonce"].clone();

    let caller = CallerExecutorFixture::new();
    let report_body = caller
        .report_request(
            Arc::clone(&state),
            &nonce_json,
            &params,
            ToolInvocationCost {
                units: 0,
                currency: "USD".to_string(),
                breakdown: None,
            },
        )
        .await;
    let (status, reconciled) = post_caller_report(Arc::clone(&state), &report_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reconciled["status"], "reconciled");

    let usage = budget.get_usage(&cap_id, 0).unwrap();
    assert_eq!(
        usage.map(|usage| usage.invocation_count).unwrap_or(0),
        1,
        "a legitimate reconcile must keep the invocation consumed, not refund it"
    );

    let after_body = serde_json::json!({
        "capability": serde_json::to_value(&cap).unwrap(),
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "invoke-reconcile-after",
    });
    let (_, after) = post_evaluate(state, &after_body).await;
    assert_eq!(
        after["status"], "deny",
        "a reconciled invocation stays consumed against max_invocations"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_open_invocation_reserve_blocks_oversubscription() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());
    let params = serde_json::json!({ "invoice": "inv-1" });

    let first_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "invoke-open-1",
    });
    let (_, first) = post_evaluate(Arc::clone(&state), &first_body).await;
    assert_eq!(first["status"], "reserved");

    let second_body = serde_json::json!({
        "capability": serde_json::to_value(&cap).unwrap(),
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "invoke-open-2",
    });
    let (_, second) = post_evaluate(state, &second_body).await;
    assert_eq!(
        second["status"], "deny",
        "an open invocation reservation must block a second reserve past max_invocations"
    );
}

#[test]
fn build_budget_store_local_sqlite_when_no_control_url() {
    let dir = std::env::temp_dir().join(format!("chio-budget-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("budget.sqlite");
    let config = ProtectConfig {
        transport: Default::default(),
        upstream: "http://127.0.0.1:1".to_string(),
        spec_content: Some("{}".to_string()),
        spec_sha256: None,
        allow_anonymous_reads: false,
        spec_path: None,
        listen_addr: "127.0.0.1:0".to_string(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: None,
        receipt_retention: None,
        signer_seed_file: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        approval: None,
        control_url: None,
        control_token: None,
        budget_db: Some(db.to_string_lossy().to_string()),
        revocation_db: None,
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };
    let configured = build_budget_store(&config, Arc::new(clock::ProxyClock::default())).unwrap();
    let configured = configured.expect("local sqlite budget store must be built");
    assert_eq!(configured.count_open_holds().test_unwrap(), 0);
}

#[test]
fn build_budget_store_remote_when_no_local_database() {
    let config = ProtectConfig {
        transport: Default::default(),
        upstream: "http://127.0.0.1:1".to_string(),
        spec_content: Some("{}".to_string()),
        spec_sha256: None,
        allow_anonymous_reads: false,
        spec_path: None,
        listen_addr: "127.0.0.1:0".to_string(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: None,
        receipt_retention: None,
        signer_seed_file: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        approval: None,
        control_url: Some("http://127.0.0.1:1".to_string()),
        control_token: Some("token".to_string()),
        budget_db: None,
        revocation_db: None,
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };
    let configured = build_budget_store(&config, Arc::new(clock::ProxyClock::default())).unwrap();
    assert!(configured.is_some());
}

#[test]
fn build_budget_store_prefers_local_when_both_configured() {
    let dir = std::env::temp_dir().join(format!("chio-budget-both-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("budget.sqlite");
    let config = ProtectConfig {
        transport: Default::default(),
        upstream: "http://127.0.0.1:1".to_string(),
        spec_content: Some("{}".to_string()),
        spec_sha256: None,
        allow_anonymous_reads: false,
        spec_path: None,
        listen_addr: "127.0.0.1:0".to_string(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: None,
        receipt_retention: None,
        signer_seed_file: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        approval: None,
        control_url: Some("http://127.0.0.1:1".to_string()),
        control_token: Some("token".to_string()),
        budget_db: Some(db.to_string_lossy().to_string()),
        revocation_db: None,
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };
    let configured = build_budget_store(&config, Arc::new(clock::ProxyClock::default())).unwrap();
    let configured = configured.expect("a budget store must be built when both are configured");
    assert_eq!(
        configured.count_open_holds().unwrap(),
        0,
        "the local budget store must answer without contacting the configured remote"
    );
}

fn revocation_db_config(revocation_db: Option<String>) -> ProtectConfig {
    ProtectConfig {
        transport: Default::default(),
        upstream: "http://127.0.0.1:1".to_string(),
        spec_content: Some("{}".to_string()),
        spec_sha256: None,
        allow_anonymous_reads: false,
        spec_path: None,
        listen_addr: "127.0.0.1:0".to_string(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: None,
        receipt_retention: None,
        signer_seed_file: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        approval: None,
        control_url: None,
        control_token: None,
        budget_db: None,
        revocation_db,
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    }
}

#[test]
fn load_revocation_db_ids_is_empty_without_configured_store() {
    let ids = load_revocation_db_ids(&revocation_db_config(None)).unwrap();
    assert!(ids.is_empty());
}

#[test]
fn load_revocation_db_ids_reads_operator_revocations() {
    let dir = std::env::temp_dir().join(format!("chio-revocation-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("revocations.sqlite3");
    let db_path = db.to_string_lossy().to_string();

    let store = chio_store_sqlite::SqliteRevocationStore::open(&db).unwrap();
    assert!(chio_kernel::RevocationStore::revoke(&store, "cap-operator-revoked").unwrap());
    drop(store);

    let ids = load_revocation_db_ids(&revocation_db_config(Some(db_path))).unwrap();
    assert!(
        ids.contains("cap-operator-revoked"),
        "durable operator revocation must be loaded into the enforced set"
    );
}

#[test]
fn load_revocation_db_ids_fails_closed_on_unreadable_store() {
    let dir = std::env::temp_dir().join(format!("chio-revocation-bad-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("not-a-db.sqlite3");
    std::fs::write(&db, b"this is not a sqlite database").unwrap();

    let result = load_revocation_db_ids(&revocation_db_config(Some(
        db.to_string_lossy().to_string(),
    )));
    assert!(
        result.is_err(),
        "an unreadable revocation-db must fail closed rather than start with no revocations"
    );
}

#[test]
fn mediation_kernel_installs_budget_store_and_strict_nonce_config() {
    let signer = Keypair::generate();
    let budget: Arc<dyn BudgetStore> =
        Arc::new(chio_kernel::budget_store::InMemoryBudgetStore::new());
    let kernel = build_mediation_kernel(
        &signer,
        MediationBudget::Configured(Arc::clone(&budget)),
        super::MediationPolicy {
            issuers: &[],
            hash: None,
            receipt_store: None,
        },
        Vec::new(),
        None,
        Arc::new(clock::ProxyClock::default()),
    )
    .unwrap();
    assert!(
        kernel.execution_nonce_required(),
        "mediation kernel must always run execution-nonce strict mode"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_report_requires_sidecar_control_token() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());
    let params = serde_json::json!({ "invoice": "inv-1" });

    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "recon-auth-gate",
    });
    let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(authorized["status"], "reserved");
    let nonce_json = authorized["execution_nonce"].clone();

    let caller = CallerExecutorFixture::new();
    let report_body = caller
        .report_request(
            Arc::clone(&state),
            &nonce_json,
            &params,
            ToolInvocationCost {
                units: 100,
                currency: "USD".to_string(),
                breakdown: None,
            },
        )
        .await;

    let (status, denied) = post_json(Arc::clone(&state), "/v1/caller/report", &report_body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(denied["error"], "chio_control_forbidden");

    let (status, reconciled) = post_caller_report(Arc::clone(&state), &report_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reconciled["status"], "reconciled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_delivery_without_configured_control_token_is_rejected() {
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let state =
        mediated_test_state_with_control_token(Keypair::generate(), durable, Vec::new(), None);
    for route in ["/v1/caller/start", "/v1/caller/report"] {
        let (status, denied) = post_json_with_bearer(
            Arc::clone(&state),
            route,
            &serde_json::json!({}),
            Some(MEDIATED_CONTROL_TOKEN),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(denied["error"], "chio_control_forbidden");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_authorization_needs_no_tool_server_registration() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let state = mediated_test_state(signer, durable.clone(), Vec::new());

    for index in 0..8 {
        let server = format!("arbitrary-srv-{index}");
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, &server, "invoke", 100, 1000, "USD");
        let body = serde_json::json!({
            "capability": cap,
            "tool_server": server,
            "tool_name": "invoke",
            "parameters": {},
            "request_id": format!("noreg-{index}"),
        });
        let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["status"], "reserved",
            "an arbitrary caller server id must authorize without any registration"
        );
        assert!(json["execution_nonce"].is_object());
    }
}

#[test]
fn minted_request_id_window_bounds_reuse_and_expiry() {
    let mut window = MintedRequestIdWindow::new(30);
    let claim = window.claim("req-a", 1000, false).test_unwrap();
    assert_eq!(
        window.claim("req-a", 1000, false),
        Err(RequestIdClaimError::Reused)
    );
    window.release(&claim);
    assert_eq!(window.len(), 0);
    window.claim("req-a", 1000, false).test_unwrap();
    window.claim("req-b", 1010, false).test_unwrap();
    window.claim("req-c", 1031, false).test_unwrap();
    assert_eq!(window.len(), 2);
    window.claim("req-a", 1031, false).test_unwrap();
    assert_eq!(window.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_denied_authorization_does_not_burn_request_id() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 40, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, durable.clone(), Vec::new());
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": {},
        "request_id": "denied-then-retry",
    });

    let (status, first) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["status"], "deny");

    let (status, second) = post_evaluate(Arc::clone(&state), &body).await;
    assert_ne!(
        status,
        StatusCode::CONFLICT,
        "a denied authorization must release its request-id claim"
    );
    assert_eq!(second["status"], "deny");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_maintenance_handle_is_retained_until_joined() {
    let signer = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let state = mediated_test_state(signer, durable.clone(), Vec::new());

    let controller = Arc::new(chio_http_serve::ShutdownController::manual());
    let mut owner = spawn_admission_maintenance(&state, controller)
        .test_unwrap()
        .expect("configured durable kernel requires owned maintenance");
    let control = owner.control();
    assert!(control.health().worker_running);
    assert!(!control.health().worker_joined);
    owner.stop_and_join(std::time::Duration::from_secs(1)).await;
    assert!(control.health().worker_joined);
    assert!(!control.health().worker_running);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_durable_hold_rejects_request_id_reuse_after_settle() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer.clone(), durable.clone(), Vec::new());
    let params = serde_json::json!({ "invoice": "inv-1" });

    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "settled-reuse",
    });
    let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(authorized["status"], "reserved");
    let nonce_json = authorized["execution_nonce"].clone();

    let caller = CallerExecutorFixture::new();
    let report_body = caller
        .report_request(
            Arc::clone(&state),
            &nonce_json,
            &params,
            ToolInvocationCost {
                units: 100,
                currency: "USD".to_string(),
                breakdown: None,
            },
        )
        .await;
    let (status, _) = post_caller_report(Arc::clone(&state), &report_body).await;
    assert_eq!(status, StatusCode::OK);

    let usage = budget.get_usage(&cap.id, 0).test_unwrap();
    drop(state);
    drop(kernel);
    drop(budget);
    drop(durable);
    let durable = reopen_durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let after = mediated_test_state(signer, durable.clone(), Vec::new());

    let (status, replay) = post_evaluate(Arc::clone(&after), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["status"], "deny");
    assert_eq!(
        replay["receipt"]["decision"]["reason"],
        "durable admission failed: execution nonce preflight cannot replay an operation in state Completed"
    );
    assert_eq!(budget.get_usage(&cap.id, 0).test_unwrap(), usage);
    assert_ne!(replay["status"], "reserved");
    assert!(
        replay["execution_nonce"].is_null(),
        "a reused settled request_id must not mint a second nonce"
    );

    let fresh_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-2" },
        "request_id": "settled-reuse-fresh",
    });
    let (status, fresh) = post_evaluate(after, &fresh_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fresh["status"], "reserved");
    assert!(fresh["execution_nonce"].is_object());
}

#[path = "tests/product_guards.rs"]
mod product_guard_tests;
