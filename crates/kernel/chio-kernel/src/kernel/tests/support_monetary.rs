struct MonetaryCostServer {
    id: String,
    reported_cost: Option<ToolInvocationCost>,
}

struct FailingMonetaryServer {
    id: String,
}

struct CountingMonetaryServer {
    id: String,
    invocations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

struct PendingMonetaryServer {
    id: String,
    started: std::sync::Arc<tokio::sync::Notify>,
}

fn forged_budget_authority_metadata() -> serde_json::Value {
    serde_json::json!({
        "budget_authority": {
            "guarantee_level": "forged-guarantee",
            "authority_profile": "forged-authority-profile",
            "metering_profile": "forged-metering-profile",
            "hold_id": "forged-budget-hold",
            "budget_term": "forged-budget-term",
            "authority": {
                "authority_id": "forged-authority",
                "lease_id": "forged-lease",
                "lease_epoch": 999
            },
            "authorize": {
                "event_id": "forged:authorize"
            },
            "terminal": {
                "disposition": "released",
                "event_id": "forged:release"
            },
            "forged_marker": "must-not-survive"
        },
        "chio_runtime": {
            "admission_id": "legitimate-admission-metadata",
            "accepted": true
        },
        "route": {
            "bridge": "collision-test"
        }
    })
}

fn assert_forged_budget_authority_removed(metadata: &serde_json::Value) {
    let budget = &metadata["budget_authority"];
    assert!(
        budget["terminal"].is_null(),
        "a failed cleanup must not retain a caller-forged released terminal: {budget}"
    );
    assert_ne!(budget["hold_id"], "forged-budget-hold");
    assert_ne!(budget["budget_term"], "forged-budget-term");
    assert_ne!(budget["authority"]["authority_id"], "forged-authority");
    assert!(budget["forged_marker"].is_null());
    assert_eq!(
        metadata["chio_runtime"]["admission_id"],
        "legitimate-admission-metadata"
    );
    assert_eq!(
        metadata["chio_runtime"]["post_dispatch_cleanup_failed"],
        true
    );
    assert_eq!(metadata["route"]["bridge"], "collision-test");
}

struct FailingReleaseBudgetStore {
    inner: InMemoryBudgetStore,
}

impl FailingReleaseBudgetStore {
    fn new() -> Self {
        Self {
            inner: InMemoryBudgetStore::new(),
        }
    }
}

impl BudgetStore for FailingReleaseBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.inner
            .try_increment(capability_id, grant_index, max_invocations)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.inner.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner
            .reverse_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner
            .reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    fn release_budget_hold(
        &self,
        _request: crate::budget_store::BudgetReleaseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReleaseHoldDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "injected budget release failure sk_live_abcdefghijklmnopqrstuvwx".to_string(),
        ))
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.inner.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.inner.get_usage(capability_id, grant_index)
    }
}

struct StaticPriceOracle {
    rates: std::collections::BTreeMap<(String, String), Result<ExchangeRate, PriceOracleError>>,
}

impl StaticPriceOracle {
    fn new(
        rates: impl IntoIterator<Item = ((String, String), Result<ExchangeRate, PriceOracleError>)>,
    ) -> Self {
        Self {
            rates: rates.into_iter().collect(),
        }
    }
}

impl PriceOracle for StaticPriceOracle {
    fn get_rate<'a>(
        &'a self,
        base: &'a str,
        quote: &'a str,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<ExchangeRate, PriceOracleError>> + Send + 'a>,
    > {
        let response = self
            .rates
            .get(&(base.to_ascii_uppercase(), quote.to_ascii_uppercase()))
            .cloned()
            .unwrap_or_else(|| {
                Err(PriceOracleError::NoPairAvailable {
                    base: base.to_ascii_uppercase(),
                    quote: quote.to_ascii_uppercase(),
                })
            });
        Box::pin(async move { response })
    }

    fn supported_pairs(&self) -> Vec<String> {
        self.rates
            .keys()
            .map(|(base, quote)| format!("{base}/{quote}"))
            .collect()
    }
}

impl MonetaryCostServer {
    fn new(id: &str, cost_units: u64, currency: &str) -> Self {
        Self {
            id: id.to_string(),
            reported_cost: Some(ToolInvocationCost {
                units: cost_units,
                currency: currency.to_string(),
                breakdown: None,
            }),
        }
    }

    fn no_cost(id: &str) -> Self {
        Self {
            id: id.to_string(),
            reported_cost: None,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for MonetaryCostServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "compute".to_string(),
            "compute-a".to_string(),
            "compute-b".to_string(),
        ]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({"result": "ok"}))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((value, self.reported_cost.clone()))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for FailingMonetaryServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["compute".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal("tool server failure".to_string()))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let _ = (tool_name, arguments, bridge);
        Err(KernelError::Internal("tool server failure".to_string()))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingMonetaryServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["compute".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(serde_json::json!({"result": "ok"}))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((value, None))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for PendingMonetaryServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["compute".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.started.notify_waiters();
        std::future::pending::<Result<serde_json::Value, KernelError>>().await
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((value, None))
    }
}

fn make_monetary_grant(
    server: &str,
    tool: &str,
    max_cost_per_invocation: u64,
    max_total_cost: u64,
    currency: &str,
) -> ToolGrant {
    use chio_core::capability::scope::MonetaryAmount;
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: max_cost_per_invocation,
            currency: currency.to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: max_total_cost,
            currency: currency.to_string(),
        }),
        dpop_required: None,
    }
}

fn make_monetary_config() -> KernelConfig {
    KernelConfig {
        keypair: make_keypair(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "11".repeat(32),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: crate::MemoryBudgetConfig::defaults(),
    }
}

struct SiblingSumMonetaryFixture {
    kernel: ChioKernel,
    child_a: CapabilityToken,
    child_b: CapabilityToken,
    child_a_kp: Keypair,
    child_b_kp: Keypair,
    path: PathBuf,
}

fn make_sibling_sum_monetary_fixture(prefix: &str) -> SiblingSumMonetaryFixture {
    let path = unique_receipt_db_path(prefix);
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let parent_kp = make_keypair();
    let child_a_kp = make_keypair();
    let child_b_kp = make_keypair();
    let mut parent_grant = make_monetary_grant("cost-srv", "compute", 100, 1_000, "USD");
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let child_scope = make_scope(vec![make_monetary_grant(
        "cost-srv", "compute", 100, 1_000, "USD",
    )]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    let aggregate_root =
        chio_core::capability::aggregate_budget::verify_direct_aggregate_root_record(
            &parent,
            &[kernel.config.keypair.public_key()],
        )
        .unwrap();
    let aggregate_root_id = parent.id.clone();
    drop(seed_store);
    kernel
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()))
        .unwrap();
    kernel.set_aggregate_family_root_resolver(std::sync::Arc::new(move |requested_id: &str| {
        if requested_id == aggregate_root_id {
            Ok(aggregate_root.clone())
        } else {
            Err(
                chio_core::capability::aggregate_budget::AggregateFamilyRootResolutionError::Missing,
            )
        }
    }));
    kernel
        .register_budget_parent(parent.id.clone(), 5_000)
        .unwrap();
    trust_delegated_leaf_signer_for_scope(&mut kernel, &parent_kp, &parent_scope);

    let child_a_id = format!("cap-{prefix}-child-a");
    let child_a = make_v2_delegated_child(V2DelegatedChildInput {
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_a_kp,
        parent_scope: &parent_scope,
        child_scope: child_scope.clone(),
        id: &child_a_id,
        share_bps: 4_000,
    });
    let child_b_id = format!("cap-{prefix}-child-b");
    let child_b = make_v2_delegated_child(V2DelegatedChildInput {
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_b_kp,
        parent_scope: &parent_scope,
        child_scope,
        id: &child_b_id,
        share_bps: 4_000,
    });

    SiblingSumMonetaryFixture {
        kernel,
        child_a,
        child_b,
        child_a_kp,
        child_b_kp,
        path,
    }
}

struct SiblingSumInvocationFixture {
    kernel: ChioKernel,
    child_a: CapabilityToken,
    child_b: CapabilityToken,
    child_a_kp: Keypair,
    child_b_kp: Keypair,
    path: PathBuf,
}

fn make_invocation_limited_grant(server: &str, tool: &str, max_invocations: u32) -> ToolGrant {
    let mut grant = make_grant(server, tool);
    grant.max_invocations = Some(max_invocations);
    grant
}

fn make_sibling_sum_invocation_fixture(prefix: &str) -> SiblingSumInvocationFixture {
    let path = unique_receipt_db_path(prefix);
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(EchoServer::new("limited-srv", vec!["compute"])));

    let parent_kp = make_keypair();
    let child_a_kp = make_keypair();
    let child_b_kp = make_keypair();
    let mut parent_grant = make_invocation_limited_grant("limited-srv", "compute", 1);
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let child_scope = make_scope(vec![make_invocation_limited_grant(
        "limited-srv",
        "compute",
        1,
    )]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);
    kernel
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()))
        .unwrap();
    kernel
        .register_budget_parent(parent.id.clone(), 5_000)
        .unwrap();
    trust_delegated_leaf_signer_for_scope(&mut kernel, &parent_kp, &parent_scope);

    let child_a_id = format!("cap-{prefix}-child-a");
    let child_a = make_v2_delegated_child(V2DelegatedChildInput {
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_a_kp,
        parent_scope: &parent_scope,
        child_scope: child_scope.clone(),
        id: &child_a_id,
        share_bps: 4_000,
    });
    let child_b_id = format!("cap-{prefix}-child-b");
    let child_b = make_v2_delegated_child(V2DelegatedChildInput {
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_b_kp,
        parent_scope: &parent_scope,
        child_scope,
        id: &child_b_id,
        share_bps: 4_000,
    });

    SiblingSumInvocationFixture {
        kernel,
        child_a,
        child_b,
        child_a_kp,
        child_b_kp,
        path,
    }
}

fn spawn_payment_test_server(
    status_code: u16,
    body: serde_json::Value,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let address = listener
        .local_addr()
        .expect("listener should expose local address");
    let (request_tx, request_rx) = mpsc::channel();
    let body_text = body.to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("server should accept request");
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        let mut header_end = None;
        let mut content_length = 0_usize;

        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("server should configure read timeout");
        loop {
            let read = stream
                .read(&mut chunk)
                .expect("server should read request bytes");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);

            if header_end.is_none() {
                header_end = find_http_header_end(&request);
                if let Some(end) = header_end {
                    content_length = parse_http_content_length(&request[..end]);
                }
            }

            if let Some(end) = header_end {
                if request.len() >= end + content_length {
                    break;
                }
            }
        }

        request_tx
            .send(String::from_utf8_lossy(&request).into_owned())
            .expect("request should be sent to test");
        let response = format!(
            "HTTP/1.1 {status_code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            http_status_text(status_code),
            body_text.len(),
            body_text
        );
        stream
            .write_all(response.as_bytes())
            .expect("server should write response");
    });

    (format!("http://{address}"), request_rx, handle)
}

fn find_http_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_http_content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn http_status_text(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        402 => "Payment Required",
        _ => "Error",
    }
}

fn make_governed_monetary_grant(
    server: &str,
    tool: &str,
    max_cost_per_invocation: u64,
    max_total_cost: u64,
    currency: &str,
    approval_threshold_units: u64,
) -> ToolGrant {
    let mut grant = make_monetary_grant(
        server,
        tool,
        max_cost_per_invocation,
        max_total_cost,
        currency,
    );
    grant.constraints = vec![
        Constraint::GovernedIntentRequired,
        Constraint::RequireApprovalAbove {
            threshold_units: approval_threshold_units,
        },
    ];
    grant
}

fn with_minimum_runtime_assurance(mut grant: ToolGrant, tier: RuntimeAssuranceTier) -> ToolGrant {
    grant
        .constraints
        .push(Constraint::MinimumRuntimeAssurance(tier));
    grant
}

fn with_minimum_autonomy_tier(mut grant: ToolGrant, tier: GovernedAutonomyTier) -> ToolGrant {
    grant
        .constraints
        .push(Constraint::MinimumAutonomyTier(tier));
    grant
}

fn make_governed_acp_monetary_grant(
    server: &str,
    tool: &str,
    seller: &str,
    max_cost_per_invocation: u64,
    max_total_cost: u64,
    currency: &str,
    approval_threshold_units: u64,
) -> ToolGrant {
    let mut grant = make_governed_monetary_grant(
        server,
        tool,
        max_cost_per_invocation,
        max_total_cost,
        currency,
        approval_threshold_units,
    );
    grant
        .constraints
        .push(Constraint::SellerExact(seller.to_string()));
    grant
}

fn make_governed_intent(
    id: &str,
    server: &str,
    tool: &str,
    purpose: &str,
    units: u64,
    currency: &str,
) -> GovernedTransactionIntent {
    GovernedTransactionIntent::tool_invocation(
        chio_core::capability::governance::GovernedToolInvocationIntentBody {
            id: id.to_string(),
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            purpose: purpose.to_string(),
            max_amount: Some(MonetaryAmount {
                units,
                currency: currency.to_string(),
            }),
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "invoice_id": "inv-1001",
                "operator": "finance-ops",
            })),
        },
    )
}

struct GovernedAcpIntentFixture<'a> {
    id: &'a str,
    server: &'a str,
    tool: &'a str,
    purpose: &'a str,
    seller: &'a str,
    shared_payment_token_id: &'a str,
    units: u64,
    currency: &'a str,
}

fn make_governed_acp_intent(fixture: GovernedAcpIntentFixture<'_>) -> GovernedTransactionIntent {
    GovernedTransactionIntent::tool_invocation(
        chio_core::capability::governance::GovernedToolInvocationIntentBody {
            id: fixture.id.to_string(),
            server_id: fixture.server.to_string(),
            tool_name: fixture.tool.to_string(),
            purpose: fixture.purpose.to_string(),
            max_amount: Some(MonetaryAmount {
                units: fixture.units,
                currency: fixture.currency.to_string(),
            }),
            commerce: Some(chio_core::capability::governance::GovernedCommerceContext {
                seller: fixture.seller.to_string(),
                shared_payment_token_id: fixture.shared_payment_token_id.to_string(),
            }),
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "invoice_id": "inv-2002",
                "operator": "commerce-ops",
            })),
        },
    )
}

fn make_runtime_attestation(
    tier: RuntimeAssuranceTier,
) -> chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
    let now = current_unix_timestamp();
    chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.enterprise-verifier.json.v1".to_string(),
        verifier: "https://attest.chio.example".to_string(),
        tier,
        issued_at: now.saturating_sub(1),
        expires_at: now + 300,
        evidence_sha256: format!("digest-{tier:?}"),
        runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
        workload_identity: Some(
            chio_core::capability::workload_identity::WorkloadIdentity::parse_spiffe_uri(
                "spiffe://chio/runtime/test",
            )
            .expect("parse runtime workload identity"),
        ),
        claims: Some(serde_json::json!({
            "enterpriseVerifier": {
                "attestationType": "enterprise_confidential_vm",
                "hardwareModel": "AMD_SEV_SNP",
                "secureBoot": "enabled",
                "digest": format!("sha384:digest-{tier:?}")
            }
        })),
    }
}

fn make_trusted_azure_runtime_attestation(
) -> chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
    let now = current_unix_timestamp();
    chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test/".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "digest-azure-attestation".to_string(),
        runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "attestationType": "sgx"
            }
        })),
    }
}

fn make_trusted_google_runtime_attestation(
) -> chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
    let now = current_unix_timestamp();
    chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
        verifier: "https://confidentialcomputing.googleapis.com".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "digest-google-attestation".to_string(),
        runtime_identity: Some(
            "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1".to_string(),
        ),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "googleAttestation": {
                "attestationType": "confidential_vm",
                "hardwareModel": "GCP_AMD_SEV",
                "secureBoot": "enabled"
            }
        })),
    }
}

fn make_trusted_nitro_runtime_attestation(
) -> chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
    let now = current_unix_timestamp();
    chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.aws-nitro-attestation.v1".to_string(),
        verifier: "https://nitro.aws.example/".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "digest-nitro-attestation".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "awsNitro": {
                "moduleId": "nitro-enclave-1",
                "digest": "sha384:aws-measurement",
                "pcrs": { "0": "0123" }
            }
        })),
    }
}

fn make_attestation_trust_policy() -> chio_core::capability::trust_policy::AttestationTrustPolicy {
    chio_core::capability::trust_policy::AttestationTrustPolicy {
        rules: vec![
            chio_core::capability::trust_policy::AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: std::collections::BTreeMap::new(),
            },
            chio_core::capability::trust_policy::AttestationTrustRule {
                name: "google-confidential".to_string(),
                schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
                verifier: "https://confidentialcomputing.googleapis.com".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(
                    chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
                ),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: vec!["confidential_vm".to_string()],
                required_assertions: std::collections::BTreeMap::from([
                    ("hardwareModel".to_string(), "GCP_AMD_SEV".to_string()),
                    ("secureBoot".to_string(), "enabled".to_string()),
                ]),
            },
            chio_core::capability::trust_policy::AttestationTrustRule {
                name: "aws-nitro".to_string(),
                schema: "chio.runtime-attestation.aws-nitro-attestation.v1".to_string(),
                verifier: "https://nitro.aws.example".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AwsNitro),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: Vec::new(),
                required_assertions: std::collections::BTreeMap::from([(
                    "moduleId".to_string(),
                    "nitro-enclave-1".to_string(),
                )]),
            },
        ],
    }
}

fn make_attested_attestation_trust_policy(
) -> chio_core::capability::trust_policy::AttestationTrustPolicy {
    chio_core::capability::trust_policy::AttestationTrustPolicy {
        rules: vec![chio_core::capability::trust_policy::AttestationTrustRule {
            name: "azure-contoso-attested".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Attested,
            verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: Some(120),
            allowed_attestation_types: vec!["sgx".to_string()],
            required_assertions: std::collections::BTreeMap::new(),
        }],
    }
}

fn make_metered_billing_context(
    quote_id: &str,
    provider: &str,
    units: u64,
    currency: &str,
) -> chio_core::capability::governance::MeteredBillingContext {
    let now = current_unix_timestamp();
    chio_core::capability::governance::MeteredBillingContext {
        settlement_mode: chio_core::capability::governance::MeteredSettlementMode::AllowThenSettle,
        quote: chio_core::capability::governance::MeteredBillingQuote {
            quote_id: quote_id.to_string(),
            provider: provider.to_string(),
            billing_unit: "1k_tokens".to_string(),
            quoted_units: units,
            quoted_cost: MonetaryAmount {
                units: 60,
                currency: currency.to_string(),
            },
            issued_at: now.saturating_sub(5),
            expires_at: Some(now + 300),
        },
        max_billed_units: Some(units + 4),
    }
}

fn make_governed_call_chain_context(
    chain_id: &str,
    parent_request_id: &str,
) -> GovernedCallChainContext {
    GovernedCallChainContext {
        chain_id: chain_id.to_string(),
        parent_request_id: parent_request_id.to_string(),
        parent_receipt_id: Some("rc-upstream-1".to_string()),
        origin_subject: "subject-origin".to_string(),
        delegator_subject: "subject-delegator".to_string(),
    }
}

fn make_governed_upstream_call_chain_proof(
    signer: &Keypair,
    subject: &PublicKey,
    call_chain: &GovernedCallChainContext,
) -> GovernedUpstreamCallChainProof {
    let now = current_unix_timestamp();
    GovernedUpstreamCallChainProof::sign(
        GovernedUpstreamCallChainProofBody {
            signer: signer.public_key(),
            subject: subject.clone(),
            chain_id: call_chain.chain_id.clone(),
            parent_request_id: call_chain.parent_request_id.clone(),
            parent_receipt_id: call_chain.parent_receipt_id.clone(),
            origin_subject: call_chain.origin_subject.clone(),
            delegator_subject: call_chain.delegator_subject.clone(),
            issued_at: now.saturating_sub(5),
            expires_at: now + 300,
        },
        signer,
    )
    .unwrap()
}

fn attach_governed_upstream_call_chain_proof(
    intent: &mut GovernedTransactionIntent,
    proof: &GovernedUpstreamCallChainProof,
) {
    let intent = intent.as_tool_invocation_mut().expect("tool intent");
    let mut context = match intent.context.take() {
        Some(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    context.insert(
        GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY.to_string(),
        serde_json::to_value(proof).unwrap(),
    );
    intent.context = Some(serde_json::Value::Object(context));
}

struct GovernedCallChainContinuationTokenFixture<'a> {
    signer: &'a Keypair,
    subject: &'a PublicKey,
    call_chain: &'a GovernedCallChainContext,
    parent_session_anchor: SessionAnchorReference,
    parent_receipt_hash: &'a str,
    server_id: &'a str,
    tool_name: &'a str,
    governed_intent_hash: Option<&'a str>,
}

fn make_governed_call_chain_continuation_token(
    fixture: GovernedCallChainContinuationTokenFixture<'_>,
) -> CallChainContinuationToken {
    let now = current_unix_timestamp();
    CallChainContinuationToken::sign(
        CallChainContinuationTokenBody {
            schema: chio_core::capability::governance::CHIO_CALL_CHAIN_CONTINUATION_SCHEMA
                .to_string(),
            token_id: "continuation-token-1".to_string(),
            signer: fixture.signer.public_key(),
            subject: fixture.subject.clone(),
            chain_id: fixture.call_chain.chain_id.clone(),
            parent_request_id: fixture.call_chain.parent_request_id.clone(),
            parent_receipt_id: fixture.call_chain.parent_receipt_id.clone(),
            parent_receipt_hash: Some(fixture.parent_receipt_hash.to_string()),
            parent_session_anchor: Some(fixture.parent_session_anchor),
            current_subject: fixture.subject.to_hex(),
            delegator_subject: fixture.call_chain.delegator_subject.clone(),
            origin_subject: fixture.call_chain.origin_subject.clone(),
            parent_capability_id: None,
            delegation_link_hash: None,
            governed_intent_hash: fixture.governed_intent_hash.map(str::to_string),
            audience: Some(CallChainContinuationAudience {
                server_id: fixture.server_id.to_string(),
                tool_name: fixture.tool_name.to_string(),
            }),
            nonce: Some("nonce-continuation-1".to_string()),
            issued_at: now.saturating_sub(5),
            expires_at: now + 300,
        },
        fixture.signer,
    )
    .unwrap()
}

fn attach_governed_call_chain_continuation_token(
    intent: &mut GovernedTransactionIntent,
    token: &CallChainContinuationToken,
) {
    let intent = intent.as_tool_invocation_mut().expect("tool intent");
    let mut context = match intent.context.take() {
        Some(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    context.insert(
        GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY.to_string(),
        serde_json::to_value(token).unwrap(),
    );
    intent.context = Some(serde_json::Value::Object(context));
}

fn make_governed_autonomy_context(
    tier: GovernedAutonomyTier,
    bond_id: Option<&str>,
) -> GovernedAutonomyContext {
    GovernedAutonomyContext {
        tier,
        delegation_bond_id: bond_id.map(str::to_string),
    }
}

struct CreditBondFixture<'a> {
    signer: &'a Keypair,
    cap: &'a CapabilityToken,
    server: &'a str,
    tool: &'a str,
    disposition: CreditBondDisposition,
    lifecycle_state: CreditBondLifecycleState,
    expires_at: u64,
    runtime_assurance_met: bool,
}

fn make_credit_bond(fixture: CreditBondFixture<'_>) -> SignedCreditBond {
    let now = current_unix_timestamp();
    let report = CreditBondReport {
        schema: CREDIT_BOND_REPORT_SCHEMA.to_string(),
        generated_at: now.saturating_sub(1),
        filters: ExposureLedgerQuery {
            capability_id: Some(fixture.cap.id.clone()),
            agent_subject: Some(fixture.cap.subject.to_hex()),
            tool_server: Some(fixture.server.to_string()),
            tool_name: Some(fixture.tool.to_string()),
            since: None,
            until: None,
            receipt_limit: Some(10),
            decision_limit: Some(5),
        },
        exposure: ExposureLedgerSummary {
            matching_receipts: 1,
            returned_receipts: 1,
            matching_decisions: 0,
            returned_decisions: 0,
            active_decisions: 0,
            superseded_decisions: 0,
            actionable_receipts: 0,
            pending_settlement_receipts: 0,
            failed_settlement_receipts: 0,
            currencies: vec!["USD".to_string()],
            mixed_currency_book: false,
            truncated_receipts: false,
            truncated_decisions: false,
        },
        scorecard: CreditScorecardSummary {
            matching_receipts: 1,
            returned_receipts: 1,
            matching_decisions: 0,
            returned_decisions: 0,
            currencies: vec!["USD".to_string()],
            mixed_currency_book: false,
            confidence: CreditScorecardConfidence::High,
            band: CreditScorecardBand::Prime,
            overall_score: 0.95,
            anomaly_count: 0,
            probationary: false,
        },
        disposition: fixture.disposition,
        prerequisites: CreditBondPrerequisites {
            active_facility_required: true,
            active_facility_met: true,
            runtime_assurance_met: fixture.runtime_assurance_met,
            certification_required: false,
            certification_met: true,
            currency_coherent: true,
        },
        support_boundary: CreditBondSupportBoundary {
            autonomy_gating_supported: true,
            ..CreditBondSupportBoundary::default()
        },
        latest_facility_id: Some("facility-1".to_string()),
        terms: None,
        findings: Vec::new(),
    };
    SignedCreditBond::sign(
        CreditBondArtifact {
            schema: CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
            bond_id: format!("bond-{}-{}-{}", fixture.server, fixture.tool, now),
            issued_at: now.saturating_sub(5),
            expires_at: fixture.expires_at,
            lifecycle_state: fixture.lifecycle_state,
            supersedes_bond_id: None,
            report,
        },
        fixture.signer,
    )
    .unwrap()
}

fn make_governed_approval_token(
    approver: &Keypair,
    subject: &PublicKey,
    intent: &GovernedTransactionIntent,
    request_id: &str,
) -> GovernedApprovalToken {
    let now = current_unix_timestamp();
    GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("approval-{request_id}"),
            approver: approver.public_key(),
            subject: subject.clone(),
            governed_intent_hash: intent.binding_hash().unwrap(),
            threshold_proposal_hash: None,
            request_id: request_id.to_string(),
            issued_at: now.saturating_sub(1),
            expires_at: now + 300,
            decision: GovernedApprovalDecision::Approved,
        },
        approver,
    )
    .unwrap()
}

fn install_durable_legacy_governed_admission_authorities(kernel: &mut ChioKernel) {
    kernel
        .set_admission_operation_store_handle(std::sync::Arc::new(ProfiledTestStore::new(
            AdmissionOperationStoreProfile::SingleNodeDurable,
        )))
        .expect("legacy governed operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("legacy governed approval store");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("legacy governed budget store");
}

// --- Monetary enforcement tests ---

#[derive(Clone)]
struct TrackingPaymentAdapter {
    authorized: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    released: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    refunded: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl TrackingPaymentAdapter {
    fn new() -> Self {
        Self {
            authorized: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            released: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            refunded: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

impl PaymentAdapter for TrackingPaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.authorized
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentAuthorization {
            authorization_id: "auth_tracking".to_string(),
            settled: false,
            metadata: serde_json::json!({ "adapter": "tracking" }),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "tracking" }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.released
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "tracking" }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.refunded
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "tracking" }),
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_async_evaluate_after_monetary_admission_unwinds_budget_payment_and_receipt() {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    kernel.register_tool_server(Box::new(PendingMonetaryServer {
        id: "cost-srv".to_string(),
        started: std::sync::Arc::clone(&started),
    }));

    struct AbortEvidenceGuard;
    impl Guard for AbortEvidenceGuard {
        fn name(&self) -> &str {
            "abort-evidence"
        }

        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::allow_with_evidence(vec![GuardEvidence {
                guard_name: "abort-evidence".to_string(),
                verdict: true,
                details: Some("pre-invocation evidence recorded before abort".to_string()),
            }]))
        }
    }
    kernel.add_guard(Box::new(AbortEvidenceGuard));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-drop-after-admission".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    let kernel = std::sync::Arc::new(kernel);
    let eval = {
        let kernel = std::sync::Arc::clone(&kernel);
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };

    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("pending monetary tool should be invoked before abort");
    eval.abort();
    let join = eval
        .await
        .expect_err("aborted evaluation should not complete");
    assert!(join.is_cancelled());

    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        payment.refunded.load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log.get(0).unwrap();
    assert!(receipt.is_cancelled());
    assert_eq!(receipt.evidence.len(), 1);
    assert_eq!(receipt.evidence[0].guard_name, "abort-evidence");
    let terminal = &receipt.metadata.as_ref().unwrap()["budget_authority"]["terminal"];
    assert_eq!(terminal["disposition"], "released");
    assert!(terminal["event_id"]
        .as_str()
        .is_some_and(|event_id| event_id.ends_with(":release")));
}

#[derive(Clone, Copy)]
enum DropCleanupFailureSource {
    Payment,
    BudgetStore,
}

async fn assert_post_dispatch_drop_cleanup_fault(
    source: DropCleanupFailureSource,
    extra_metadata: Option<serde_json::Value>,
) {
    let has_forged_budget_authority = extra_metadata.is_some();
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let mut kernel = make_kernel(make_monetary_config());
    match source {
        DropCleanupFailureSource::Payment => {
            kernel.set_payment_adapter(Box::new(FailingReleasePaymentAdapter));
        }
        DropCleanupFailureSource::BudgetStore => {
            kernel
                .set_budget_store_handle(std::sync::Arc::new(FailingReleaseBudgetStore::new()))
                .expect("budget store");
        }
    }
    kernel.register_tool_server(Box::new(PendingMonetaryServer {
        id: "cost-srv".to_string(),
        started: std::sync::Arc::clone(&started),
    }));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = make_request(
        "req-post-dispatch-drop-cleanup-fault",
        &cap,
        "compute",
        "cost-srv",
    );

    let kernel = std::sync::Arc::new(kernel);
    let eval = {
        let kernel = std::sync::Arc::clone(&kernel);
        tokio::spawn(async move {
            kernel
                .evaluate_tool_call_with_metadata(&request, extra_metadata)
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("pending monetary tool should be entered before abort");
    eval.abort();
    assert!(eval.await.unwrap_err().is_cancelled());

    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 100);
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log.get(0).unwrap();
    assert!(receipt.is_cancelled());
    let metadata = receipt.metadata.as_ref().unwrap();
    assert!(metadata["budget_authority"]["terminal"].is_null());
    assert_eq!(
        metadata["chio_runtime"]["post_dispatch_cleanup_failed"],
        true
    );
    let fault = &metadata["chio_runtime"]["post_dispatch_cleanup_faults"][0];
    let expected_step = match source {
        DropCleanupFailureSource::Payment => "payment_release",
        DropCleanupFailureSource::BudgetStore => "budget_hold_release",
    };
    assert_eq!(fault["step"], expected_step);
    let reason = fault["reason"].as_str().unwrap();
    assert!(reason.contains("[REDACTED-API-KEY]"));
    assert!(!reason.contains("sk_live_"));
    assert!(fault["attempted_release_event_id"]
        .as_str()
        .is_some_and(|event_id| event_id.ends_with(":release")));
    let hold_ids = fault["hold_ids"].as_array().unwrap();
    assert!(hold_ids.iter().any(|id| id == &cap.id));
    let budget_hold_id = metadata["budget_authority"]["hold_id"].as_str().unwrap();
    assert!(hold_ids.iter().any(|id| id == budget_hold_id));
    if matches!(source, DropCleanupFailureSource::Payment) {
        assert!(hold_ids.iter().any(|id| id == "auth_failing_release"));
    }
    if has_forged_budget_authority {
        assert_forged_budget_authority_removed(metadata);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_dispatch_drop_payment_cleanup_failure_is_signed() {
    assert_post_dispatch_drop_cleanup_fault(DropCleanupFailureSource::Payment, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_dispatch_drop_budget_cleanup_failure_is_signed() {
    assert_post_dispatch_drop_cleanup_fault(DropCleanupFailureSource::BudgetStore, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_dispatch_drop_cleanup_failure_rejects_forged_budget_authority() {
    let metadata = forged_budget_authority_metadata();
    assert_post_dispatch_drop_cleanup_fault(DropCleanupFailureSource::Payment, Some(metadata))
        .await;
}

fn make_dpop_grant(server: &str, tool: &str) -> ToolGrant {
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: Some(true),
    }
}

/// Build a kernel that has a DPoP store configured and a single DPoP-required grant.
fn make_dpop_kernel_and_cap(
    agent_kp: &Keypair,
    server: &str,
    tool: &str,
) -> (ChioKernel, CapabilityToken) {
    let config = KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "dpop-test-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: crate::MemoryBudgetConfig::defaults(),
    };
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(EchoServer::new(server, vec![tool])));

    let nonce_store = dpop::DpopNonceStore::new(1024, std::time::Duration::from_secs(300));
    kernel.set_dpop_store(nonce_store, dpop::DpopConfig::default());

    let grant = make_dpop_grant(server, tool);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    (kernel, cap)
}

/// Build a valid DPoP proof for a given request context.
fn make_dpop_proof(
    agent_kp: &Keypair,
    cap: &CapabilityToken,
    server: &str,
    tool: &str,
    arguments: &serde_json::Value,
    nonce: &str,
) -> dpop::DpopProof {
    let args_bytes =
        chio_core::canonical::canonical_json_bytes(arguments).expect("canonical_json_bytes failed");
    let action_hash = chio_core::crypto::sha256_hex(&args_bytes);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time error")
        .as_secs();
    let body = dpop::DpopProofBody {
        schema: dpop::DPOP_SCHEMA.to_string(),
        capability_id: cap.id.clone(),
        tool_server: server.to_string(),
        tool_name: tool.to_string(),
        action_hash,
        nonce: nonce.to_string(),
        issued_at: now_secs,
        agent_key: agent_kp.public_key(),
    };
    dpop::DpopProof::sign(body, agent_kp).expect("DPoP sign failed")
}
