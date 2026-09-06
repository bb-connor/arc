use super::*;
use crate::evaluator::DurableAdmissionStores;
use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
use chio_test_support::prelude::*;
use tower::ServiceExt;

#[path = "tests/authorization.rs"]
mod authorization;
#[path = "../tests/mediated_boundary_tests.rs"]
mod boundary_tests;

/// Build an ephemeral kernel used only to mint capabilities in tests. It
/// shares the budget store with the state's mediation kernel; cost is never
/// resolved through an injected tool server, so capabilities carry their own
/// monetary constraints.
fn issuing_kernel(
    signer: &Keypair,
    budget: Arc<dyn BudgetStore>,
    trusted_capability_issuers: &[PublicKey],
) -> Arc<ChioKernel> {
    Arc::new(
        build_mediation_kernel(
            signer,
            budget,
            trusted_capability_issuers,
            Vec::new(),
            None,
            None,
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

/// Issue a capability whose single grant caps invocations only, with no
/// monetary ceiling. The mediated reserve path debits an invocation but
/// authorizes no monetary hold, so its reversal on tear-down and TTL reap is
/// exercised separately from the monetary reserve.
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

/// Control token the mediated test state configures so `/v1/reconcile`, now
/// behind the reconcile control gate, admits the trusted tool server that
/// presents it. `/v1/evaluate` is not gated, so evaluate tests are unaffected.
const MEDIATED_CONTROL_TOKEN: &str = "tool-server-control-token";

/// Build proxy state for the mediated route with the standard reconcile
/// control token configured.
fn mediated_test_state(
    signer: Keypair,
    budget: Arc<dyn BudgetStore>,
    trusted_capability_issuers: Vec<PublicKey>,
) -> Arc<ProxyState> {
    mediated_test_state_with_control_token(
        signer,
        budget,
        trusted_capability_issuers,
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
    )
}

/// Build proxy state for the mediated route. `signer` is the sidecar signer
/// the shared mediation kernel is built from (so capabilities minted by it
/// are trusted), and `trusted_capability_issuers` are additional external
/// issuers to trust. `sidecar_control_token` gates `/v1/reconcile`; `None`
/// leaves the sidecar with no configured token, so reconcile fails closed.
fn mediated_test_state_with_control_token(
    signer: Keypair,
    budget: Arc<dyn BudgetStore>,
    trusted_capability_issuers: Vec<PublicKey>,
    sidecar_control_token: Option<String>,
) -> Arc<ProxyState> {
    // The default in-memory budget store implements the hold APIs, so it is
    // treated as hold-capable (matching a local `--budget-db` deployment).
    mediated_test_state_inner(
        signer,
        budget,
        trusted_capability_issuers,
        sidecar_control_token,
        None,
        true,
    )
}

/// Build proxy state for the mediated route with an explicit hold-capability
/// flag. `hold_capable == false` models a remote `--control-url` budget store
/// whose hold APIs fall back to the no-op trait defaults, so the mediated
/// routes must fail closed rather than mint an unreconcilable reserved nonce.
fn mediated_test_state_inner(
    signer: Keypair,
    budget: Arc<dyn BudgetStore>,
    trusted_capability_issuers: Vec<PublicKey>,
    sidecar_control_token: Option<String>,
    receipt_store: Option<SqliteReceiptStore>,
    hold_capable: bool,
) -> Arc<ProxyState> {
    // No payment adapter by default, so governed MustPrepay stays denied
    // fail-closed; the prepayment tests build the mediation kernel with one.
    mediated_test_state_core(
        signer,
        budget,
        trusted_capability_issuers,
        sidecar_control_token,
        receipt_store,
        hold_capable,
        None,
        None,
    )
}

/// Build proxy state for the mediated route with an explicit payment adapter
/// for the shared mediation kernel. A configured adapter lets an approved
/// governed `MustPrepay` request authorize (the quote is prepaid before a
/// reserved nonce is minted); `None` keeps it denied fail-closed.
#[allow(clippy::too_many_arguments)]
fn mediated_test_state_core(
    signer: Keypair,
    budget: Arc<dyn BudgetStore>,
    trusted_capability_issuers: Vec<PublicKey>,
    sidecar_control_token: Option<String>,
    receipt_store: Option<SqliteReceiptStore>,
    hold_capable: bool,
    payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
    revocation_store: Option<Arc<dyn chio_kernel::RevocationStore>>,
) -> Arc<ProxyState> {
    mediated_test_state_with_durable_admission(
        signer,
        budget,
        trusted_capability_issuers,
        sidecar_control_token,
        receipt_store,
        hold_capable,
        payment_adapter,
        revocation_store,
        None,
    )
}

/// Provision a fresh admission authority under `directory` for a durable
/// mediation kernel.
fn durable_admission_stores(directory: &std::path::Path) -> DurableAdmissionStores {
    let database = directory.join("admission.db");
    let locks = directory.join("locks");
    std::fs::create_dir_all(&locks).test_unwrap();
    chio_store_sqlite::SqliteAuthorityStore::provision(&database, &locks).test_unwrap();
    let authority =
        chio_store_sqlite::SqliteAuthorityStore::open_serving(&database, &locks).test_unwrap();
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
    budget: Arc<dyn BudgetStore>,
    trusted_capability_issuers: Vec<PublicKey>,
    sidecar_control_token: Option<String>,
    receipt_store: Option<SqliteReceiptStore>,
    hold_capable: bool,
    payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
    revocation_store: Option<Arc<dyn chio_kernel::RevocationStore>>,
    durable_admission: Option<DurableAdmissionStores>,
) -> Arc<ProxyState> {
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
    // One shared mediation kernel for the process, matching production wiring:
    // reuse keeps the approval-token and DPoP replay stores authoritative and
    // makes the nonce minted on `/v1/evaluate` the one settled on
    // `/v1/reconcile`.
    let mediation_kernel = Mutex::new(
        build_mediation_kernel(
            &signer,
            Arc::clone(&budget),
            &trusted_capability_issuers,
            Vec::new(),
            payment_adapter,
            durable_admission,
        )
        .test_unwrap(),
    );
    Arc::new(ProxyState {
        evaluator,
        signer_keypair: signer,
        upstream: "http://127.0.0.1:1".to_string(),
        http_client,
        egress_contract,
        approval_admin: ApprovalAdmin::new(approval_store),
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
        budget_store: Some(budget),
        mediation_hold_capable: hold_capable,
        mediation_kernel: Some(mediation_kernel),
        minted_request_ids: Mutex::new(MintedRequestIdWindow::new(
            chio_kernel::DEFAULT_EXECUTION_NONCE_TTL_SECS,
        )),
        reaper_handle: Mutex::new(None),
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

// --- Scaffolding for governed and DPoP authorization tests ---

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

/// A governed intent that mandates prepayment: it carries a metered-billing
/// context in `MustPrepay` settlement mode with a quote for `units`. The
/// kernel denies it unless a payment adapter is configured to prepay the
/// quote before the reserve-for-caller path mints a nonce.
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
    // Match the kernel's action-hash computation exactly: SHA-256 hex over
    // the canonical JSON of the tool arguments.
    let args_bytes = chio_core_types::canonical::canonical_json_bytes(parameters).test_unwrap();
    let action_hash = chio_core_types::crypto::sha256_hex(&args_bytes);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .test_unwrap()
        .as_secs();
    DpopProof::sign(
        DpopProofBody {
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

/// POST a body to `/v1/evaluate` and return the status and parsed JSON.
async fn post_evaluate(
    state: Arc<ProxyState>,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    post_json(state, "/v1/evaluate", body).await
}

/// POST a body to `/v1/reconcile` presenting the standard control token, so
/// the reconcile control gate admits it, and return the status and JSON.
async fn post_reconcile(
    state: Arc<ProxyState>,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    post_json_with_bearer(state, "/v1/reconcile", body, Some(MEDIATED_CONTROL_TOKEN)).await
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

/// Open a temporary receipt store backed by a fresh SQLite database.
fn open_temp_receipt_store() -> (std::path::PathBuf, SqliteReceiptStore) {
    let dir = std::env::temp_dir().join(format!("chio-receipt-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("receipts.sqlite");
    let store = SqliteReceiptStore::open(&db.to_string_lossy()).unwrap();
    (db, store)
}

/// A receipt store whose `append_tool_receipt` fails deterministically: the
/// backing `tool_receipts` table is dropped through a second connection to
/// the same database, so every append errors.
fn failing_receipt_store() -> SqliteReceiptStore {
    let (db, store) = open_temp_receipt_store();
    let dropper = rusqlite::Connection::open(&db).unwrap();
    dropper.execute("DROP TABLE tool_receipts", []).unwrap();
    drop(dropper);
    store
}

/// A payment adapter that counts each rail action, so a test can assert a
/// captured MustPrepay prepayment is neither refunded nor re-charged. The
/// settlement behavior is delegated to the deterministic sim adapter.
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
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
    let cap_id = cap.id.clone();
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state_inner(
        signer,
        Arc::clone(&budget),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        Some(failing_receipt_store()),
        true,
    );
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" },
        "request_id": "persist-fail",
    });

    // The kernel Allowed (reserved) and minted a nonce, but the local receipt
    // append fails. The reservation is durable in the budget store and the caller
    // reconciles it at /v1/reconcile (which persists its own authoritative
    // receipt), so the handler returns 200 with the nonce rather than a 500 that
    // would strand a reservation the caller can never use.
    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "authorized");
    assert!(
        json["execution_nonce"].is_object(),
        "a persistence failure after a successful reserve must still return the nonce"
    );

    // The reserved hold stays OPEN with its budget committed: the caller holds a
    // real reservation backing the downstream execution.
    let hold_id = json["execution_nonce"]["nonce"]["reserved_hold_id"]
        .as_str()
        .expect("the returned nonce must name its reserved hold");
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

    // The request-id claim is retained: the id backs a live reservation, so a
    // reuse must still collide rather than mint a second nonce.
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
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 100, "USD");
    let cap_id = cap.id.clone();
    let cap_value = serde_json::to_value(&cap).unwrap();
    let (_db, receipt_store) = open_temp_receipt_store();
    let state = mediated_test_state_inner(
        signer,
        Arc::clone(&budget),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        Some(receipt_store),
        true,
    );
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-1" },
        "request_id": "persist-ok",
    });

    // The happy path: the receipt append succeeds, so the caller receives the
    // minted nonce and the reservation is kept for a real reconcile.
    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "authorized");
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
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
    let cap_id = cap.id.clone();
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state_inner(
        signer,
        Arc::clone(&budget),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        Some(failing_receipt_store()),
        true,
    );
    let params = serde_json::json!({ "invoice": "inv-1" });
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "invoke-persist-fail",
    });

    // An invocation-only reserve debits the single invocation and mints a nonce.
    // The receipt append fails, but the caller can still present the nonce and
    // reconcile downstream, so the handler returns 200 with the nonce and keeps
    // the invocation reserved instead of a 500 that would permanently burn the
    // invocation for a caller that never received the nonce.
    let (status, json) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "authorized");
    let nonce_json = json["execution_nonce"].clone();
    assert!(
        nonce_json.is_object(),
        "an invocation reserve whose receipt fails to persist must still return the nonce"
    );

    // The invocation stays consumed and the reserved hold stays open: the caller
    // holds the nonce that backs it.
    let usage = budget.get_usage(&cap_id, 0).unwrap();
    assert_eq!(
        usage.map(|usage| usage.invocation_count).unwrap_or(0),
        1,
        "the returned invocation reservation stays consumed against the grant"
    );
    let hold_id = nonce_json["nonce"]["reserved_hold_id"]
        .as_str()
        .expect("the returned nonce must name its reserved hold");
    let hold = budget.get_budget_hold(hold_id).unwrap();
    assert!(
        hold.map(|hold| hold.disposition.is_open()).unwrap_or(false),
        "the returned invocation reservation must keep its reserved hold open"
    );

    // The returned nonce is usable: reconciling it downstream settles the
    // reservation and produces a `reconciled` receipt.
    let reconcile_body = serde_json::json!({
        "execution_nonce": nonce_json,
        "arguments": params,
        "realized_cost": { "units": 0, "currency": "USD" },
    });
    let (recon_status, reconciled) = post_reconcile(state, &reconcile_body).await;
    assert_eq!(recon_status, StatusCode::OK);
    assert_eq!(reconciled["status"], "reconciled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_mustprepay_receipt_persistence_failure_returns_nonce_without_refund() {
    // Money-loss guard: a governed MustPrepay reserve authorizes AND captures the
    // quoted prepayment before minting the nonce. If the sidecar's local receipt
    // append then fails, tearing the reservation down would leave the captured
    // prepayment charged for a reservation the caller never received (direct
    // financial loss). The handler must return 200 with the nonce so the captured
    // prepayment backs a usable authorization, and must not refund or re-charge.
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
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
        Arc::clone(&budget),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        Some(failing_receipt_store()),
        true,
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
    assert_eq!(
        status,
        StatusCode::OK,
        "a captured MustPrepay reserve whose receipt fails to persist must not 500"
    );
    assert_eq!(json["status"], "authorized");
    assert!(
        json["execution_nonce"].is_object(),
        "the caller must receive the nonce the captured prepayment backs"
    );

    // The prepayment was captured exactly once and never refunded: the payer is
    // billed for the authorization the caller now holds, with no money lost to a
    // torn-down reservation.
    assert_eq!(
        captures.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the MustPrepay quote must be captured exactly once"
    );
    assert_eq!(
        refunds.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the captured prepayment must not be refunded: it backs the returned nonce"
    );

    // The reservation is intact: the reserved hold stays open.
    let hold_id = json["execution_nonce"]["nonce"]["reserved_hold_id"]
        .as_str()
        .expect("the returned nonce must name its reserved hold");
    let hold = budget.get_budget_hold(hold_id).unwrap();
    assert!(
        hold.map(|hold| hold.disposition.is_open()).unwrap_or(false),
        "the captured MustPrepay reservation must stay open, backing the returned nonce"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_invocation_reconcile_keeps_invocation_consumed() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
    let cap_id = cap.id.clone();
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
    let params = serde_json::json!({ "invoice": "inv-1" });

    let reserve_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "invoke-reconcile",
    });
    let (_, authorized) = post_evaluate(Arc::clone(&state), &reserve_body).await;
    assert_eq!(authorized["status"], "authorized");
    let nonce_json = authorized["execution_nonce"].clone();

    // A legitimate reconcile settles the invocation reservation: the debited
    // invocation stays consumed (the call ran), it is not refunded.
    let reconcile_body = serde_json::json!({
        "execution_nonce": nonce_json,
        "arguments": params,
        "realized_cost": { "units": 0, "currency": "USD" },
    });
    let (status, reconciled) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reconciled["status"], "reconciled");

    let usage = budget.get_usage(&cap_id, 0).unwrap();
    assert_eq!(
        usage.map(|usage| usage.invocation_count).unwrap_or(0),
        1,
        "a legitimate reconcile must keep the invocation consumed, not refund it"
    );

    // The single invocation stays consumed: a later authorization is denied.
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
async fn reaper_forfeits_expired_invocation_reserve() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
    let cap_id = cap.id.clone();
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
    let params = serde_json::json!({ "invoice": "inv-1" });

    let reserve_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "invoke-reap",
    });
    let (_, authorized) = post_evaluate(Arc::clone(&state), &reserve_body).await;
    assert_eq!(authorized["status"], "authorized");

    // Sweep with a far-future clock: the abandoned invocation reservation is
    // past its execution-nonce TTL and is settled at its (zero-money)
    // worst-case, forfeiting the invocation the same way the monetary reaper
    // forfeits reserved money.
    let settled = reap_expired_reserved_holds_once(&state, i64::MAX)
        .await
        .unwrap();
    assert_eq!(
        settled, 1,
        "the expired invocation reservation must be settled"
    );

    // Fail-closed: the forfeited invocation stays consumed, so a new
    // authorization on the single-invocation grant is still denied.
    let usage = budget.get_usage(&cap_id, 0).unwrap();
    assert_eq!(
        usage.map(|usage| usage.invocation_count).unwrap_or(0),
        1,
        "reaping an abandoned invocation reservation forfeits it (stays consumed)"
    );
    let after_body = serde_json::json!({
        "capability": serde_json::to_value(&cap).unwrap(),
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "invoke-reap-after",
    });
    let (_, after) = post_evaluate(state, &after_body).await;
    assert_eq!(
        after["status"], "deny",
        "a forfeited invocation reservation must keep the grant committed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_open_invocation_reserve_blocks_oversubscription() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_invocation_capability(&kernel, &agent, "cost-srv", "compute", 1);
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
    let params = serde_json::json!({ "invoice": "inv-1" });

    let first_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "invoke-open-1",
    });
    let (_, first) = post_evaluate(Arc::clone(&state), &first_body).await;
    assert_eq!(first["status"], "authorized");

    // While the first invocation reservation is OPEN (debited, not yet
    // reconciled or reaped), a second reserve that would exceed
    // max_invocations is denied: an in-flight reservation still counts, so
    // there is no over-subscription.
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
        upstream: "http://127.0.0.1:1".to_string(),
        spec_content: Some("{}".to_string()),
        spec_path: None,
        listen_addr: "127.0.0.1:0".to_string(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        control_url: None,
        control_token: None,
        budget_db: Some(db.to_string_lossy().to_string()),
        revocation_db: None,
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };
    let configured = build_budget_store(&config).unwrap();
    let configured = configured.expect("local sqlite budget store must be built");
    assert!(
        configured.hold_capable,
        "the local sqlite budget store implements the hold APIs and must be hold-capable"
    );
}

#[test]
fn build_budget_store_remote_is_not_hold_capable() {
    // A remote control-plane budget store forwards only
    // charge/reverse/reconcile and falls back to the no-op hold-API defaults,
    // so it must be flagged not hold-capable; the mediated routes then fail
    // closed rather than mint a reservation it can never reconcile or reap.
    let config = ProtectConfig {
        upstream: "http://127.0.0.1:1".to_string(),
        spec_content: Some("{}".to_string()),
        spec_path: None,
        listen_addr: "127.0.0.1:0".to_string(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        control_url: Some("http://127.0.0.1:1".to_string()),
        control_token: Some("token".to_string()),
        budget_db: None,
        revocation_db: None,
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };
    let configured = build_budget_store(&config).unwrap();
    let configured = configured.expect("remote budget store must be built");
    assert!(
        !configured.hold_capable,
        "the remote control-plane budget store does not implement the hold APIs"
    );
}

#[test]
fn build_budget_store_prefers_local_hold_capable_when_both_configured() {
    // An operator who configures BOTH a control plane and a local budget DB
    // must get the hold-capable local SQLite store for mediation: the remote
    // store cannot persist a reserved hold, so choosing it would disable
    // mediated authorization and reconcile. Prefer the local store.
    let dir = std::env::temp_dir().join(format!("chio-budget-both-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("budget.sqlite");
    let config = ProtectConfig {
        upstream: "http://127.0.0.1:1".to_string(),
        spec_content: Some("{}".to_string()),
        spec_path: None,
        listen_addr: "127.0.0.1:0".to_string(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        control_url: Some("http://127.0.0.1:1".to_string()),
        control_token: Some("token".to_string()),
        budget_db: Some(db.to_string_lossy().to_string()),
        revocation_db: None,
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };
    let configured = build_budget_store(&config).unwrap();
    let configured = configured.expect("a budget store must be built when both are configured");
    assert!(
        configured.hold_capable,
        "with both configured, mediation must use the hold-capable local store"
    );
    // The returned store is the working local SQLite store: it answers the
    // hold-inventory query rather than a remote endpoint that is never reached.
    assert_eq!(
        configured.store.count_open_holds().unwrap(),
        0,
        "the preferred store must be the functional local hold-capable store"
    );
}

fn revocation_db_config(revocation_db: Option<String>) -> ProtectConfig {
    ProtectConfig {
        upstream: "http://127.0.0.1:1".to_string(),
        spec_content: Some("{}".to_string()),
        spec_path: None,
        listen_addr: "127.0.0.1:0".to_string(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
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

    // Mirror `chio trust revoke --revocation-db <path>`: an operator writes
    // the revocation to the durable store the sidecar never used to read.
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
    let kernel =
        build_mediation_kernel(&signer, Arc::clone(&budget), &[], Vec::new(), None, None).unwrap();
    // Strict nonce mode is what routes every mediated request through the
    // authorization-reserve path. DPoP verification state is installed here
    // too; the `mediated_dpop_capability_requires_valid_proof` integration
    // test exercises it end to end.
    assert!(
        kernel.execution_nonce_required(),
        "mediation kernel must always run execution-nonce strict mode"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconcile_requires_sidecar_control_token() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
    let params = serde_json::json!({ "invoice": "inv-1" });

    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "recon-auth-gate",
    });
    let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(authorized["status"], "authorized");
    let nonce_json = authorized["execution_nonce"].clone();

    let reconcile_body = serde_json::json!({
        "execution_nonce": nonce_json,
        "arguments": params,
        "realized_cost": { "units": 30, "currency": "USD" },
    });

    // The controlled agent could self-reconcile at cost zero when
    // reconcile was on the public router. Without the sidecar-control token
    // the reconcile is rejected by the trusted-caller gate before it can
    // settle the hold; the gate runs ahead of the handler, so the nonce is
    // not consumed by the rejected attempt.
    let (status, denied) = post_json(Arc::clone(&state), "/v1/reconcile", &reconcile_body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(denied["error"], "chio_control_forbidden");

    // Presenting the control token (the tool server's trust boundary) settles.
    let (status, reconciled) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reconciled["status"], "reconciled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconcile_without_configured_control_token_is_rejected() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let params = serde_json::json!({ "invoice": "inv-1" });

    // Mint a genuine reserved nonce on a control-token-bearing sidecar so the
    // reconcile body deserializes; the reconcile is then attempted against a
    // sidecar with no configured control token. Evaluate itself fails closed
    // without a control token, so the nonce must come from a configured one.
    let with_token = mediated_test_state(signer.clone(), Arc::clone(&budget), Vec::new());
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "recon-no-token",
    });
    let (_, authorized) = post_evaluate(with_token, &body).await;
    let nonce_json = authorized["execution_nonce"].clone();
    assert!(nonce_json.is_object());

    // No sidecar-control token configured on this sidecar.
    let state = mediated_test_state_with_control_token(signer, budget, Vec::new(), None);

    // Fail-closed: with no control token configured there is no trusted
    // caller, so reconcile is rejected outright rather than left open.
    // Presenting any bearer cannot help because none is configured to match.
    let reconcile_body = serde_json::json!({
        "execution_nonce": nonce_json,
        "arguments": params,
        "realized_cost": { "units": 0, "currency": "USD" },
    });
    let (status, denied) = post_reconcile(state, &reconcile_body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(denied["error"], "chio_control_forbidden");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_authorization_needs_no_tool_server_registration() {
    // The reserve-for-caller path no longer requires the target
    // tool server to be registered, so the route registers nothing. Many
    // distinct caller-arbitrary server ids each authorize, and because the
    // handler holds the kernel behind a shared (non-mut) lock it cannot
    // register a server or otherwise grow the kernel's tool-server map.
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

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
            json["status"], "authorized",
            "an arbitrary caller server id must authorize without any registration"
        );
        assert!(json["execution_nonce"].is_object());
    }
}

#[test]
fn minted_request_id_window_bounds_reuse_and_expiry() {
    let mut window = MintedRequestIdWindow::new(30);
    // A fresh id is claimed; an immediate reuse inside the window is rejected.
    assert!(window.claim("req-a", 1_000));
    assert!(!window.claim("req-a", 1_000));
    assert_eq!(window.len(), 1);

    // Releasing an id (a denied/failed authorization) makes it reusable at once.
    window.release("req-a");
    assert_eq!(window.len(), 0);
    assert!(window.claim("req-a", 1_000));

    // Distinct live ids accumulate, but a later claim prunes entries whose
    // reservation TTL has lapsed, so the set stays bounded and an expired id
    // is reusable again.
    assert!(window.claim("req-b", 1_010));
    assert_eq!(window.len(), 2);
    // At 1_031, "req-a" (expires 1_030) is pruned; "req-b" (expires 1_040)
    // is still live.
    assert!(window.claim("req-c", 1_031));
    assert_eq!(window.len(), 2);
    assert!(window.claim("req-a", 1_031));
    assert_eq!(window.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_denied_authorization_does_not_burn_request_id() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    // max_cost_per_invocation (100) exceeds max_total_cost (40): the
    // reservation is refused, so the authorization is denied and places no
    // durable hold.
    let cap = issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 40, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
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

    // A denied authorization must not permanently burn the id.
    // Reusing it is NOT a 409 conflict; it is evaluated again (and denied
    // again), proving the claim was released.
    let (status, second) = post_evaluate(Arc::clone(&state), &body).await;
    assert_ne!(
        status,
        StatusCode::CONFLICT,
        "a denied authorization must release its request-id claim"
    );
    assert_eq!(second["status"], "deny");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_hold_reaper_handle_is_retained_not_detached() {
    let signer = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let state = mediated_test_state(signer, budget, Vec::new());

    // No reaper before spawn.
    assert!(state.reaper_handle.lock().await.is_none());

    // The reaper's JoinHandle is retained on the shared state,
    // not dropped/detached, so it can be aborted on shutdown.
    spawn_reserved_hold_reaper(&state).await;
    {
        let guard = state.reaper_handle.lock().await;
        let handle = guard
            .as_ref()
            .expect("the reaper handle must be retained on the state");
        assert!(
            !handle.is_finished(),
            "the retained reaper handle must reference a live, abortable task"
        );
    }

    // The retained handle is abortable; aborting cancels the reaper task.
    let handle = state.reaper_handle.lock().await.take().unwrap();
    handle.abort();
    assert!(
        handle.await.is_err(),
        "aborting the retained handle must cancel the reaper task"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconcile_returns_authoritative_receipt_when_persistence_fails() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let signer_pub = signer.public_key();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();

    // A working receipt store so the evaluate that mints the nonce persists.
    let (db, receipt_store) = open_temp_receipt_store();
    let state = mediated_test_state_inner(
        signer,
        Arc::clone(&budget),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        Some(receipt_store),
        true,
    );
    let params = serde_json::json!({ "invoice": "inv-1" });

    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "recon-persist-fail",
    });
    let (status, authorized) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(authorized["status"], "authorized");
    let nonce_json = authorized["execution_nonce"].clone();
    assert!(nonce_json.is_object());

    // The reconcile consumes the nonce and settles the reserved hold
    // IRREVERSIBLY before persisting its receipt. Drop the receipt table so the
    // post-settle append fails: unlike a reversible reservation, the settled
    // spend cannot be undone, so the authoritative receipt is the only proof.
    let dropper = rusqlite::Connection::open(&db).unwrap();
    dropper.execute("DROP TABLE tool_receipts", []).unwrap();
    drop(dropper);

    let reconcile_body = serde_json::json!({
        "execution_nonce": nonce_json.clone(),
        "arguments": params,
        "realized_cost": { "units": 30, "currency": "USD" },
    });
    let (status, reconciled) = post_reconcile(Arc::clone(&state), &reconcile_body).await;

    // The settlement already happened, so the caller must receive the
    // authoritative receipt rather than a 500 that discards the only proof.
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reconciled["status"], "reconciled");
    let receipt: ChioReceipt = serde_json::from_value(reconciled["receipt"].clone()).unwrap();
    let nonce: SignedExecutionNonce = serde_json::from_value(nonce_json).unwrap();
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer_pub], &nonce),
        Ok(()),
        "a persistence failure after settlement must still return the authoritative receipt"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconcile_still_fails_closed_on_replayed_nonce_when_persistence_fails() {
    // The receipt-persistence carve-out is scoped to a SUCCESSFUL settle: a
    // real reconcile ERROR (here a replayed, already-consumed nonce) must still
    // fail closed, never reaching receipt persistence.
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 150, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let (db, receipt_store) = open_temp_receipt_store();
    let state = mediated_test_state_inner(
        signer,
        Arc::clone(&budget),
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.to_string()),
        Some(receipt_store),
        true,
    );
    let params = serde_json::json!({ "invoice": "inv-1" });

    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "recon-replay-persist-fail",
    });
    let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
    let nonce_json = authorized["execution_nonce"].clone();

    let reconcile_body = serde_json::json!({
        "execution_nonce": nonce_json,
        "arguments": params,
        "realized_cost": { "units": 30, "currency": "USD" },
    });
    // First reconcile settles the hold and consumes the nonce.
    let (status, _) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
    assert_eq!(status, StatusCode::OK);

    // Even with receipt persistence broken, a replayed nonce is a reconcile
    // ERROR: it is rejected 4xx and never returns a receipt.
    let dropper = rusqlite::Connection::open(&db).unwrap();
    dropper.execute("DROP TABLE tool_receipts", []).unwrap();
    drop(dropper);
    let (status, replay) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(replay["error"], "chio_reconcile_rejected");
    assert!(replay.get("receipt").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_durable_hold_rejects_request_id_reuse_after_settle() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    // The durable budget store survives a restart; the ProxyState (and its
    // in-memory request-id window) is rebuilt fresh.
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let cap_value = serde_json::to_value(&cap).unwrap();
    let state = mediated_test_state(signer.clone(), Arc::clone(&budget), Vec::new());
    let params = serde_json::json!({ "invoice": "inv-1" });

    // Reserve a hold under a caller-chosen request_id, then settle it: the
    // durable hold row persists but is no longer open.
    let body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": params,
        "request_id": "settled-reuse",
    });
    let (_, authorized) = post_evaluate(Arc::clone(&state), &body).await;
    assert_eq!(authorized["status"], "authorized");
    let nonce_json = authorized["execution_nonce"].clone();

    let reconcile_body = serde_json::json!({
        "execution_nonce": nonce_json,
        "arguments": params,
        "realized_cost": { "units": 30, "currency": "USD" },
    });
    let (status, _) = post_reconcile(Arc::clone(&state), &reconcile_body).await;
    assert_eq!(status, StatusCode::OK);

    // Restart: a fresh ProxyState with an EMPTY in-memory window sharing only
    // the durable budget store, so the durable reuse guard is the only defense.
    let after = mediated_test_state(signer, Arc::clone(&budget), Vec::new());

    // Reusing the settled request_id must be rejected 409: the durable hold id
    // is already spent, so passing it through would let the kernel reject the
    // duplicate hold id and turn a valid later authorization into a 500.
    let (status, replay) = post_evaluate(Arc::clone(&after), &body).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(replay["error"], "chio_request_id_reused");
    assert_ne!(replay["status"], "authorized");
    assert!(
        replay["execution_nonce"].is_null(),
        "a reused settled request_id must not mint a second nonce"
    );

    // A fresh request_id still authorizes on the restarted sidecar.
    let fresh_body = serde_json::json!({
        "capability": cap_value,
        "tool_server": "cost-srv",
        "tool_name": "compute",
        "parameters": { "invoice": "inv-2" },
        "request_id": "settled-reuse-fresh",
    });
    let (status, fresh) = post_evaluate(after, &fresh_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fresh["status"], "authorized");
    assert!(fresh["execution_nonce"].is_object());
}
