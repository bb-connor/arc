use crate::{common::*, market::*, review};
use chio_a2a_adapter::{A2aAdapter, A2aAdapterConfig};
use chio_a2a_edge::{A2aEdgeConfig, A2aKernelExecutionContext, ChioA2aEdge};
use chio_core_types::{
    capability::{
        scope::{ChioScope, Constraint, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    },
    Keypair, PublicKey,
};
use chio_egress_contract::HttpEgressContract;
use chio_kernel::{ChioKernel, KernelError, NestedFlowBridge, ToolServerConnection};
use chio_open_market::bidding::{bid, BidMintContext, SignedAskResponse};
use chio_store_sqlite::{
    SqliteAuthorityStore, SqliteFindingOperatorPaymentAdapter, SqliteReceiptStore,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::{
    fs,
    io::Read,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tiny_http::{Header, Response, Server};

pub fn grant(state: &Path, buyer: PublicKey) -> Result<CapabilityToken> {
    grant_with_proof(state, buyer, false)
}

pub fn grant_session(state: &Path, buyer: PublicKey) -> Result<CapabilityToken> {
    grant_with_proof(state, buyer, true)
}

fn grant_with_proof(
    state: &Path,
    buyer: PublicKey,
    proof_required: bool,
) -> Result<CapabilityToken> {
    let issuer = key(state)?;
    let time = now()?;
    Ok(CapabilityToken::sign(
        CapabilityTokenBody {
            id: format!("negotiation-{}", digest(&buyer)?),
            issuer: issuer.public_key(),
            subject: buyer,
            scope: ChioScope {
                grants: ["quote", "accept", "status", "delivery"]
                    .into_iter()
                    .map(|tool| ToolGrant {
                        server_id: SERVER.into(),
                        tool_name: tool.into(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![Constraint::MaxArgsSize(256 * 1024)],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: proof_required.then_some(true),
                    })
                    .collect(),
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: time.saturating_sub(5),
            expires_at: time + 3600,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?)
}

struct WorkServer {
    key: Keypair,
    peers: Peers,
    db: Arc<Mutex<Connection>>,
    receipts: Arc<SqliteReceiptStore>,
    crash_after_accept: bool,
    fault: String,
}

impl WorkServer {
    fn handle(&self, tool: &str, args: Value) -> Result<Value> {
        let mut connection = self.db.lock().map_err(|_| "work store lock poisoned")?;
        if tool == "review" {
            let request: review::ReviewRequest = serde_json::from_value(args)?;
            request.validate(&self.peers)?;
            let mut body = request.report()?;
            if self.fault.starts_with("corrupt-") {
                body.operations[0].authentication_required =
                    !body.operations[0].authentication_required;
            }
            let report = review::SignedReport::sign(body, &self.key)?;
            connection.execute(
                "INSERT INTO review_runs(job,request,report) VALUES(?,?,?)",
                params![
                    request.acceptance.quote.agreement.job_id,
                    serde_json::to_string(&request)?,
                    serde_json::to_string(&report)?
                ],
            )?;
            if self.fault == "after-review" {
                crash()?;
            }
            review::envelope(&report)
        } else if tool == "delivery" {
            let acceptance: Acceptance = serde_json::from_value(args)?;
            acceptance.verify(&self.peers)?;
            review::delivery(&connection, &self.receipts, &self.key, &acceptance)
        } else if tool == "quote" {
            let request: QuoteRequest = serde_json::from_value(args)?;
            request.validate(&self.peers)?;
            let job = &request.agreement.job_id;
            let binding = digest(&request)?;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let stored: Option<(String, String)> = tx
                .query_row("SELECT binding,ask FROM jobs WHERE job=?", [job], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .optional()?;
            if let Some((previous, ask)) = stored {
                if previous != binding {
                    return Err("job id is already bound to different terms".into());
                }
                return Ok(serde_json::from_str(&ask)?);
            }
            let time = now()?;
            if time >= request.agreement.deadline || request.bid.body.issued_at > time {
                return Err("agreement window is not live".into());
            }
            // Do not rewrite signed bid bytes. A quote must fit the remaining
            // agreement window, even when the request was delayed in transit.
            let listing = listing(&self.key, time)?;
            let mut ask = bid(
                &request.bid,
                BidMintContext {
                    listing: &listing,
                    issuer_keypair: &self.key,
                    agent_subject: self.peers.buyer.clone(),
                    token_id: format!("work-{binding}"),
                    now: time,
                    grant_constraints: vec![],
                    dpop_required: Some(true),
                },
            )?;
            // The generic market mints a relative duration. This job profile
            // narrows its offer and token to the buyer's signed absolute deadline.
            let mut token = ask.body.token_offer.body();
            token.expires_at = token.expires_at.min(request.agreement.deadline);
            ask.body.expires_at = token.expires_at;
            ask.body.token_offer = CapabilityToken::sign(token, &self.key)?;
            ask = SignedAskResponse::sign(ask.body, &self.key)?;
            verify_ask(&request, &ask, &self.peers.provider)?;
            tx.execute(
                "INSERT INTO jobs(job,binding,ask,state) VALUES(?,?,?,'quoted')",
                params![job, binding, serde_json::to_string(&ask)?],
            )?;
            tx.commit()?;
            Ok(serde_json::to_value(ask)?)
        } else if tool == "accept" || tool == "status" {
            let acceptance: Acceptance = serde_json::from_value(args)?;
            acceptance.verify(&self.peers)?;
            let job = &acceptance.quote.agreement.job_id;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let (binding, ask, accepted, state): (String, String, Option<String>, String) = tx
                .query_row(
                    "SELECT binding,ask,accepted,state FROM jobs WHERE job=?",
                    [job],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )?;
            if binding != digest(&acceptance.quote)?
                || digest(&serde_json::from_str::<SignedAskResponse>(&ask)?)?
                    != digest(&acceptance.ask)?
            {
                return Err("acceptance does not name the retained job offer".into());
            }
            let frozen = serde_json::to_string(&acceptance)?;
            if let Some(previous) = accepted {
                if digest(&serde_json::from_str::<Acceptance>(&previous)?)? != digest(&acceptance)?
                {
                    return Err("job already has another acceptance".into());
                }
            } else if tool == "accept" {
                if now()? >= acceptance.quote.agreement.deadline {
                    return Err("new acceptance arrived after deadline".into());
                }
                let accepted_jobs: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM jobs WHERE accepted IS NOT NULL",
                    [],
                    |r| r.get(0),
                )?;
                if accepted_jobs >= 10 {
                    return Err("provider's configured credit exposure limit reached".into());
                }
                tx.execute(
                    "UPDATE jobs SET accepted=?,state='accepted' WHERE job=? AND state='quoted'",
                    params![frozen, job],
                )?;
                tx.execute("INSERT INTO acceptance_events(job) VALUES(?)", [job])?;
                tx.commit()?;
                if self.crash_after_accept {
                    crash()?;
                }
                return self.acknowledgement(&acceptance, "accepted");
            }
            self.acknowledgement(&acceptance, &state)
        } else {
            Err("unknown work protocol method".into())
        }
    }

    fn acknowledgement(&self, acceptance: &Acceptance, state: &str) -> Result<Value> {
        Ok(serde_json::to_value(
            chio_core_types::receipt::lineage::SignedExportEnvelope::sign(
                Acknowledgement {
                    schema: ACK_SCHEMA.into(),
                    job_id: acceptance.quote.agreement.job_id.clone(),
                    agreement_sha256: digest(&acceptance.quote.agreement)?,
                    accepted_bid_sha256: digest(&acceptance.accepted)?,
                    state: state.into(),
                    work_executed: false,
                    settled: false,
                },
                &self.key,
            )?,
        )?)
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for WorkServer {
    fn server_id(&self) -> &str {
        SERVER
    }
    fn tool_names(&self) -> Vec<String> {
        ["quote", "accept", "status", "review", "delivery"]
            .into_iter()
            .map(str::to_string)
            .collect()
    }
    async fn invoke(
        &self,
        tool: &str,
        args: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        self.handle(tool, args)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))
    }
}

pub fn serve(state: &Path, port: u16, crash_after_accept: bool) -> Result<()> {
    serve_with_fault(
        state,
        port,
        if crash_after_accept {
            "after-accept"
        } else {
            "none"
        },
    )
}

pub fn serve_with_fault(state: &Path, port: u16, fault: &str) -> Result<()> {
    serve_transport(state, port, fault, None)
}

pub fn serve_https(state: &Path, https: crate::https::HttpsConfig<'_>, fault: &str) -> Result<()> {
    serve_transport(state, 0, fault, Some(https))
}

fn serve_transport(
    state: &Path,
    port: u16,
    fault: &str,
    https: Option<crate::https::HttpsConfig<'_>>,
) -> Result<()> {
    if ![
        "none",
        "after-accept",
        "after-review",
        "after-capture",
        "after-settlement",
        "corrupt-report",
        "corrupt-after-release",
        "corrupt-after-denial",
    ]
    .contains(&fault)
    {
        return Err("unknown provider fault".into());
    }
    let identity = key(state)?;
    let peers: Peers = read(state.join("peers.json"))?;
    if identity.public_key() != peers.provider {
        return Err("provider key does not match configured identity".into());
    }
    let connection = Connection::open(state.join("work.sqlite"))?;
    connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
        CREATE TABLE IF NOT EXISTS jobs(job TEXT PRIMARY KEY,binding TEXT NOT NULL,ask TEXT NOT NULL,accepted TEXT,state TEXT NOT NULL CHECK(state IN ('quoted','accepted')));
        CREATE TABLE IF NOT EXISTS acceptance_events(job TEXT PRIMARY KEY REFERENCES jobs(job));
        CREATE TABLE IF NOT EXISTS review_runs(job TEXT PRIMARY KEY,request TEXT NOT NULL,report TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS deliveries(job TEXT PRIMARY KEY,artifact TEXT NOT NULL);")?;
    let connection = Arc::new(Mutex::new(connection));
    let locks = state.join("locks");
    fs::create_dir_all(&locks)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&locks, fs::Permissions::from_mode(0o700))?;
    }
    let database = state.join("authority.sqlite");
    if !database.exists() {
        SqliteAuthorityStore::provision(&database, &locks)?;
    }
    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let mut kernel = ChioKernel::new(kernel_config(identity.clone()));
    let dpop = chio_kernel::dpop::DpopConfig::default();
    kernel.set_dpop_store(
        chio_kernel::dpop::DpopNonceStore::new(
            dpop.nonce_store_capacity,
            Duration::from_secs(dpop.proof_ttl_secs + dpop.max_clock_skew_secs),
        ),
        dpop,
    );
    let receipts = Arc::new(SqliteReceiptStore::open(state.join("receipts.sqlite"))?);
    kernel.set_receipt_store_handle(receipts.clone())?;
    let payment = SqliteFindingOperatorPaymentAdapter::open(state.join("payments.sqlite"))
        .map_err(|e| -> Error { e.into() })?;
    if fault == "after-capture" || fault == "corrupt-after-release" {
        kernel.set_payment_adapter(Box::new(crate::payment::CrashAfterPayment(
            payment,
            if fault == "after-capture" {
                chio_kernel::payment::PaymentSettleAction::Capture
            } else {
                chio_kernel::payment::PaymentSettleAction::Release
            },
        )));
    } else {
        kernel.set_payment_adapter(Box::new(payment));
    }
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.set_revocation_store_handle(Arc::new(authority.revocation_store()));
    let manifest = chio_a2a_edge_manifest(&identity)?;
    kernel.add_guard(Box::new(review::ReviewGuard {
        db: connection.clone(),
        peers: peers.clone(),
    }));
    kernel.register_tool_server(Box::new(WorkServer {
        key: identity,
        peers,
        db: connection,
        receipts,
        crash_after_accept: fault == "after-accept",
        fault: fault.into(),
    }));
    // Recovery must see the same configured guards and tool implementation.
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.configure_durable_admission(
        chio_kernel::admission_operation::DurableAdmissionMode::All,
        false,
    )?;
    let require_sender_constraint = https.is_some();
    let (server, origin, _tls_runtime) = if let Some(config) = https {
        let listener = crate::https::listen(state, config)?;
        (listener.server, listener.origin, Some(listener.runtime))
    } else {
        let server = Server::http(("127.0.0.1", port))?;
        let address = server
            .server_addr()
            .to_ip()
            .ok_or("server address missing")?;
        (server, format!("http://{address}"), None)
    };
    let mut edge = ChioA2aEdge::new(
        A2aEdgeConfig {
            endpoint_url: format!("{origin}/rpc"),
            ..Default::default()
        },
        vec![manifest],
    )?;
    fs::write(
        state.join("endpoint.json"),
        serde_json::to_vec(&json!({"url":origin,"pid":std::process::id()}))?,
    )?;
    for mut request in server.incoming_requests() {
        if request.url() == "/.well-known/agent-card.json"
            && request.method() == &tiny_http::Method::Get
        {
            let _ = request.respond(
                Response::from_string(edge.agent_card_json()?).with_header(json_header()?),
            );
            continue;
        }
        if request.url() != "/rpc" || request.method() != &tiny_http::Method::Post {
            let _ = request.respond(Response::empty(404));
            continue;
        }
        let cap = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .and_then(|h| h.value.as_str().strip_prefix("Bearer "))
            .and_then(|value| serde_json::from_str::<CapabilityToken>(value).ok());
        let Some(cap) = cap else {
            let _ = request.respond(Response::empty(401));
            continue;
        };
        if require_sender_constraint
            && cap
                .scope
                .grants
                .iter()
                .any(|grant| grant.dpop_required != Some(true))
        {
            let _ = request.respond(Response::empty(401));
            continue;
        }
        if !request
            .headers()
            .iter()
            .any(|h| h.field.equiv("A2A-Version") && h.value.as_str() == "1.0")
        {
            let _ = request.respond(Response::empty(400));
            continue;
        }
        let mut bytes = Vec::new();
        if request
            .as_reader()
            .take(256 * 1024 + 1)
            .read_to_end(&mut bytes)
            .is_err()
        {
            continue;
        }
        if bytes.len() > 256 * 1024 {
            let _ = request.respond(Response::empty(413));
            continue;
        }
        let value: Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => {
                let _ = request.respond(Response::empty(400));
                continue;
            }
        };
        let proof = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Chio-Sender-Proof"))
            .map(|h| serde_json::from_str::<chio_kernel::dpop::DpopProof>(h.value.as_str()))
            .transpose();
        let proof = match proof {
            Ok(value) => value,
            Err(_) => {
                let _ = request.respond(Response::empty(400));
                continue;
            }
        };
        let context = A2aKernelExecutionContext {
            agent_id: cap.subject.to_hex(),
            capability: cap,
            dpop_proof: proof,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: vec![],
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };
        let Some(response) = edge.handle_jsonrpc(value, &kernel, &context).into_value() else {
            let _ = request.respond(Response::empty(204));
            continue;
        };
        if (fault == "after-settlement" || fault == "corrupt-after-denial")
            && response["result"]["task"]["metadata"]["chio"]["receipt"]["tool_name"] == "review"
            && (response["result"]["task"]["status"]["state"] == "TASK_STATE_COMPLETED"
                || response["result"]["task"]["status"]["state"] == "TASK_STATE_FAILED")
        {
            crash()?;
        }
        // A disconnected buyer must not stop this provider or undo its journal.
        let _ = request.respond(
            Response::from_string(serde_json::to_string(&response)?).with_header(json_header()?),
        );
    }
    Ok(())
}

fn json_header() -> Result<Header> {
    Header::from_bytes("Content-Type", "application/json").map_err(|_| "invalid header".into())
}

fn chio_a2a_edge_manifest(identity: &Keypair) -> Result<chio_manifest::ToolManifest> {
    Ok(chio_manifest::ToolManifest {
        schema: "chio.manifest.v1".into(),
        server_id: SERVER.into(),
        name: "Work negotiation".into(),
        description: Some("Negotiate a bounded security review".into()),
        version: "0.1.0".into(),
        public_key: identity.public_key().to_hex(),
        server_tools: vec![],
        required_permissions: None,
        tools: ["quote", "accept", "status", "review", "delivery"]
            .into_iter()
            .map(|name| chio_manifest::ToolDefinition {
                name: name.into(),
                description: format!("{name} a security review agreement"),
                input_schema: json!({"type":"object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: !["status", "delivery"].contains(&name),
                latency_hint: None,
            })
            .collect(),
    })
}

pub fn client(state: &Path, url: &str) -> Result<A2aAdapter> {
    client_authorized(state, url, &read(state.join("session.json"))?, None)
}

pub fn client_authorized(
    state: &Path,
    url: &str,
    cap: &CapabilityToken,
    proof: Option<&chio_kernel::dpop::DpopProof>,
) -> Result<A2aAdapter> {
    let port = url
        .strip_prefix("http://127.0.0.1:")
        .ok_or("this example only connects to loopback HTTP")?;
    if port.parse::<u16>()? == 0 {
        return Err("invalid loopback port".into());
    }
    let mut config = A2aAdapterConfig::new(url, key(state)?.public_key().to_hex())
        .with_bearer_token(serde_json::to_string(&cap)?)
        .with_task_registry_file(state.join("a2a-tasks.json"))
        .with_egress_contract(HttpEgressContract::permissive_for_tests(
            url.strip_prefix("http://")
                .ok_or("this loopback profile requires HTTP")?,
        ))
        .with_timeout(Duration::from_secs(5));
    if let Some(proof) = proof {
        config = config.with_api_key_header("Chio-Sender-Proof", serde_json::to_string(proof)?);
    }
    Ok(A2aAdapter::discover(config)?)
}
