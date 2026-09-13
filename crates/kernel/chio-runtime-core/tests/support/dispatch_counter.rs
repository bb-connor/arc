//! A kernel wired to a tool server that counts every invocation it receives.
//!
//! The admission hook on its own returns a decision; it cannot show whether a
//! tool ran. Driving the same request through [`ChioKernel`] does, because the
//! kernel owns the dispatch seam: it resolves the registered tool server and
//! calls it only after every pre-dispatch gate has passed. A counter on that
//! server is therefore a direct reading of whether the call reached a tool.

#![allow(dead_code)]

use chio_core_types::crypto::Keypair;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, RuntimeAdmissionContext,
    RuntimeAdmissionDecision, RuntimeAdmissionHook, RuntimeAdmissionReadinessToken,
    RuntimeAdmissionRevalidationContext, ToolCallRequest, ToolServerConnection, Verdict,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// The kernel identity that hosts the tool in these corpora. Capabilities are
/// issued under this key, which the kernel trusts as its own issuer, so
/// capability admission is not what these corpora are measuring.
pub fn receiver_kernel_keypair() -> Keypair {
    Keypair::from_seed(&[0x2b; 32])
}

/// A tool server that records how many times the kernel dispatched to it.
struct CountingToolServer {
    server_id: String,
    tool_name: String,
    dispatches: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingToolServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![self.tool_name.clone()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if tool_name != self.tool_name {
            return Err(KernelError::ToolServerError(format!(
                "{tool_name} is not registered on {}",
                self.server_id
            )));
        }
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"record": "vendor-ledger-7", "status": "closed"}))
    }
}

/// What the kernel did with one request, read from the dispatch seam rather
/// than from the admission decision.
pub struct KernelDispatchOutcome {
    /// Whether the kernel returned [`Verdict::Allow`].
    pub allowed: bool,
    /// The runtime failure code the receipt carries, when the kernel recorded
    /// one.
    pub failure_code: Option<String>,
    /// The denial reason the kernel returned, when it denied.
    pub reason: Option<String>,
    /// How many times the registered tool server was invoked.
    pub dispatches: u64,
}

/// The kernel that originates a federated call. Its key is pinned as a
/// federation peer of the receiver so cross-organization requests clear the
/// peer-freshness gate and reach runtime admission.
pub fn origin_kernel_keypair() -> Keypair {
    Keypair::from_seed(&[0x3d; 32])
}

/// Where the request is going and who is hosting the tool.
pub struct KernelDispatchTarget<'a> {
    pub local_kernel_id: &'a str,
    /// The peer kernel a federated request claims to come from, pinned on the
    /// receiver before the call is evaluated.
    pub origin_kernel_id: Option<&'a str>,
    pub server_id: &'a str,
    pub tool_name: &'a str,
    pub now_unix_ms: u64,
}

/// Drive one request through a kernel whose only tool server counts its own
/// invocations, and report both the verdict and the count.
///
/// The kernel is configured with the receiver identity that issues the
/// fixtures' capabilities, so capability admission succeeds and the runtime
/// admission hook is the gate under test.
pub fn dispatch_through_kernel(
    hook: Arc<dyn RuntimeAdmissionHook>,
    request: &ToolCallRequest,
    target: &KernelDispatchTarget<'_>,
) -> Result<KernelDispatchOutcome, Box<dyn std::error::Error>> {
    let keypair = receiver_kernel_keypair();
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: keypair.clone(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "policy-live".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
    });
    kernel.set_federation_local_kernel_id(target.local_kernel_id.to_string());
    kernel.set_runtime_admission_hook(hook);

    // A cross-organization allow writes a federated receipt, which the kernel
    // refuses to do without durable storage behind it.
    let receipt_directory = tempfile::tempdir()?;
    kernel.set_receipt_store_handle(Arc::new(chio_store_sqlite::SqliteReceiptStore::open(
        receipt_directory.path().join("kernel-receipts.sqlite3"),
    )?))?;

    let now_unix_secs = target.now_unix_ms / 1000;
    if let Some(origin_kernel_id) = target.origin_kernel_id {
        let origin_key = origin_kernel_keypair();
        let exchange = chio_federation::trust_establishment::KernelTrustExchange::new(
            target.local_kernel_id,
            keypair.clone(),
        )
        .with_trusted_peer(origin_kernel_id, origin_key.public_key());
        let envelope = chio_federation::trust_establishment::PeerHandshakeEnvelope::sign(
            origin_kernel_id,
            target.local_kernel_id,
            "dispatch-counter-origin-nonce",
            now_unix_secs,
            &origin_key,
        )?;
        let peer = exchange.accept_envelope(&envelope, origin_kernel_id, now_unix_secs)?;
        kernel = kernel.with_federation_peers(vec![peer]);
        kernel.set_federation_cosigner(Arc::new(
            chio_federation::bilateral::InProcessCoSigner::new(
                origin_kernel_id,
                origin_key,
                keypair.public_key(),
            ),
        ));
    }

    let dispatches = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(CountingToolServer {
        server_id: target.server_id.to_string(),
        tool_name: target.tool_name.to_string(),
        dispatches: Arc::clone(&dispatches),
    }));

    let _fixed_runtime = chio_kernel::scope_fixed_runtime_for_current_thread(
        now_unix_secs,
        [format!("rcpt-{}", request.request_id)],
    );
    let response = kernel.evaluate_tool_call_blocking(request)?;
    let failure_code = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.pointer("/chio_runtime/failure_code"))
        .and_then(serde_json::Value::as_str)
        .map(std::string::ToString::to_string);

    Ok(KernelDispatchOutcome {
        allowed: matches!(response.verdict, Verdict::Allow),
        failure_code,
        reason: response.reason.clone(),
        dispatches: dispatches.load(Ordering::SeqCst),
    })
}

/// A hook decorator that remembers whether the decision it last returned
/// carried verified treaty material.
///
/// The kernel takes that material out of the decision on the way to dispatch,
/// so a test driving the kernel cannot read it from the response. Recording it
/// at the seam keeps the signal available without changing what the kernel
/// sees.
pub struct TreatyMaterialRecorder {
    inner: Box<dyn RuntimeAdmissionHook>,
    verified_treaty_material: AtomicBool,
}

impl TreatyMaterialRecorder {
    pub fn new(inner: Box<dyn RuntimeAdmissionHook>) -> Self {
        Self {
            inner,
            verified_treaty_material: AtomicBool::new(false),
        }
    }

    /// Whether the most recent decision carried verified treaty material.
    pub fn verified_treaty_material(&self) -> bool {
        self.verified_treaty_material.load(Ordering::SeqCst)
    }
}

impl RuntimeAdmissionHook for TreatyMaterialRecorder {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        let decision = self.inner.evaluate(context)?;
        self.verified_treaty_material
            .store(decision.has_verified_treaty_material(), Ordering::SeqCst);
        Ok(decision)
    }

    fn poll_ready_before_dispatch(
        &self,
        request: &ToolCallRequest,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        self.inner.poll_ready_before_dispatch(request, cx)
    }

    fn poll_ready_before_dispatch_with_token(
        &self,
        request: &ToolCallRequest,
        token: RuntimeAdmissionReadinessToken,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        self.inner
            .poll_ready_before_dispatch_with_token(request, token, cx)
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        self.inner.requires_dispatch_revalidation()
    }

    fn revalidate_before_dispatch(
        &self,
        context: &RuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        self.inner.revalidate_before_dispatch(context)
    }

    fn unregister_ready_before_dispatch(
        &self,
        request: &ToolCallRequest,
        token: RuntimeAdmissionReadinessToken,
    ) {
        self.inner.unregister_ready_before_dispatch(request, token);
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        self.inner.release_reserved(metadata)
    }
}
