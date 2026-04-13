use crate::*;

pub type AgentId = String;

/// A string-typed capability identifier.
pub type CapabilityId = String;

/// A string-typed server identifier.
pub type ServerId = String;

#[derive(Debug)]
pub(crate) struct ReceiptContent {
    pub(crate) content_hash: String,
    pub(crate) metadata: Option<serde_json::Value>,
}

/// Errors that can occur during kernel operations.
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("unknown session: {0}")]
    UnknownSession(SessionId),

    #[error("session error: {0}")]
    Session(#[from] SessionError),

    #[error("capability has expired")]
    CapabilityExpired,

    #[error("capability not yet valid")]
    CapabilityNotYetValid,

    #[error("capability has been revoked: {0}")]
    CapabilityRevoked(CapabilityId),

    #[error("capability signature is invalid")]
    InvalidSignature,

    #[error("capability issuer is not a trusted CA")]
    UntrustedIssuer,

    #[error("capability issuance failed: {0}")]
    CapabilityIssuanceFailed(String),

    #[error("capability issuance denied: {0}")]
    CapabilityIssuanceDenied(String),

    #[error("requested tool {tool} on server {server} is not in capability scope")]
    OutOfScope { tool: String, server: String },

    #[error("requested resource {uri} is not in capability scope")]
    OutOfScopeResource { uri: String },

    #[error("requested prompt {prompt} is not in capability scope")]
    OutOfScopePrompt { prompt: String },

    #[error("invocation budget exhausted for capability {0}")]
    BudgetExhausted(CapabilityId),

    #[error("request agent {actual} does not match capability subject {expected}")]
    SubjectMismatch { expected: String, actual: String },

    #[error("delegation chain revoked at ancestor {0}")]
    DelegationChainRevoked(CapabilityId),

    #[error("invalid capability constraint: {0}")]
    InvalidConstraint(String),

    #[error("governed transaction denied: {0}")]
    GovernedTransactionDenied(String),

    #[error("guard denied the request: {0}")]
    GuardDenied(String),

    #[error("tool server error: {0}")]
    ToolServerError(String),

    #[error("request stream incomplete: {0}")]
    RequestIncomplete(String),

    #[error("tool not registered: {0}")]
    ToolNotRegistered(String),

    #[error("resource not registered: {0}")]
    ResourceNotRegistered(String),

    #[error("resource read denied by session roots for {uri}: {reason}")]
    ResourceRootDenied { uri: String, reason: String },

    #[error("prompt not registered: {0}")]
    PromptNotRegistered(String),

    #[error("sampling is disabled by policy")]
    SamplingNotAllowedByPolicy,

    #[error("sampling was not negotiated with the client")]
    SamplingNotNegotiated,

    #[error("sampling context inclusion is not supported by the client")]
    SamplingContextNotSupported,

    #[error("sampling tool use is disabled by policy")]
    SamplingToolUseNotAllowedByPolicy,

    #[error("sampling tool use was not negotiated with the client")]
    SamplingToolUseNotNegotiated,

    #[error("elicitation is disabled by policy")]
    ElicitationNotAllowedByPolicy,

    #[error("elicitation was not negotiated with the client")]
    ElicitationNotNegotiated,

    #[error("elicitation form mode is not supported by the client")]
    ElicitationFormNotSupported,

    #[error("elicitation URL mode was not negotiated with the client")]
    ElicitationUrlNotSupported,

    #[error("{message}")]
    UrlElicitationsRequired {
        message: String,
        elicitations: Vec<CreateElicitationOperation>,
    },

    #[error("roots/list was not negotiated with the client")]
    RootsNotNegotiated,

    #[error("sampling child requests require a ready session-bound parent request")]
    InvalidChildRequestParent,

    #[error("request {request_id} was cancelled: {reason}")]
    RequestCancelled {
        request_id: RequestId,
        reason: String,
    },

    #[error("receipt signing failed: {0}")]
    ReceiptSigningFailed(String),

    #[error("receipt persistence failed: {0}")]
    ReceiptPersistence(#[from] ReceiptStoreError),

    #[error("revocation store error: {0}")]
    RevocationStore(#[from] RevocationStoreError),

    #[error("budget store error: {0}")]
    BudgetStore(#[from] BudgetStoreError),

    #[error(
        "cross-currency budget enforcement failed: no price oracle configured for {base}/{quote}"
    )]
    NoCrossCurrencyOracle { base: String, quote: String },

    #[error("cross-currency budget enforcement failed: {0}")]
    CrossCurrencyOracle(String),

    #[error("web3 evidence prerequisites unavailable: {0}")]
    Web3EvidenceUnavailable(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("DPoP proof verification failed: {0}")]
    DpopVerificationFailed(String),
}

/// A policy guard that the kernel evaluates before forwarding a tool call.
///
/// Guards are the same concept as ClawdStrike's `Guard` trait, adapted for
/// the ARC tool-call context. Each guard inspects the request and returns
/// a verdict.
pub trait Guard: Send + Sync {
    /// Human-readable guard name (e.g., "forbidden-path").
    fn name(&self) -> &str;

    /// Evaluate the guard against a tool call request.
    ///
    /// Returns `Ok(Verdict::Allow)` to pass, `Ok(Verdict::Deny)` to block,
    /// or `Err` on internal failure (which the kernel treats as deny).
    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError>;
}

/// Context passed to guards during evaluation.
pub struct GuardContext<'a> {
    /// The tool call request being evaluated.
    pub request: &'a ToolCallRequest,
    /// The verified capability scope.
    pub scope: &'a ArcScope,
    /// The agent making the request.
    pub agent_id: &'a AgentId,
    /// The target server.
    pub server_id: &'a ServerId,
    /// Session-scoped enforceable filesystem roots, when the request is being
    /// evaluated through the supported session-backed runtime path.
    pub session_filesystem_roots: Option<&'a [String]>,
    /// Index of the matched grant in the capability's scope, populated by
    /// check_and_increment_budget before guards run.
    pub matched_grant_index: Option<usize>,
}

/// Trait representing a resource provider.
pub trait ResourceProvider: Send + Sync {
    /// List the resources this provider exposes.
    fn list_resources(&self) -> Vec<ResourceDefinition>;

    /// List parameterized resource templates.
    fn list_resource_templates(&self) -> Vec<ResourceTemplateDefinition> {
        vec![]
    }

    /// Read a resource by URI. Returns `Ok(None)` when the provider does not own the URI.
    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError>;

    /// Return completions for a resource template or URI reference.
    fn complete_resource_argument(
        &self,
        _uri: &str,
        _argument_name: &str,
        _value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        Ok(None)
    }
}

/// Trait representing a prompt provider.
pub trait PromptProvider: Send + Sync {
    /// List available prompts.
    fn list_prompts(&self) -> Vec<PromptDefinition>;

    /// Retrieve a prompt by name. Returns `Ok(None)` when the provider does not own the prompt.
    fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, KernelError>;

    /// Return completions for a prompt argument.
    fn complete_prompt_argument(
        &self,
        _name: &str,
        _argument_name: &str,
        _value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        Ok(None)
    }
}

/// In-memory append-only log of signed receipts.
///
/// This remains useful for process-local inspection even when a durable
/// backend is configured.
#[derive(Default)]
pub struct ReceiptLog {
    receipts: Vec<ArcReceipt>,
}

impl ReceiptLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, receipt: ArcReceipt) {
        self.receipts.push(receipt);
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn receipts(&self) -> &[ArcReceipt] {
        &self.receipts
    }

    pub fn get(&self, index: usize) -> Option<&ArcReceipt> {
        self.receipts.get(index)
    }
}

/// In-memory append-only log of signed child-request receipts.
#[derive(Default)]
pub struct ChildReceiptLog {
    receipts: Vec<ChildRequestReceipt>,
}

impl ChildReceiptLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, receipt: ChildRequestReceipt) {
        self.receipts.push(receipt);
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn receipts(&self) -> &[ChildRequestReceipt] {
        &self.receipts
    }

    pub fn get(&self, index: usize) -> Option<&ChildRequestReceipt> {
        self.receipts.get(index)
    }
}

/// Configuration for the ARC Runtime Kernel.
pub struct KernelConfig {
    /// Ed25519 keypair for signing receipts and issuing capabilities.
    pub keypair: Keypair,

    /// Public keys of trusted Capability Authorities.
    pub ca_public_keys: Vec<arc_core::PublicKey>,

    /// Maximum allowed delegation depth.
    pub max_delegation_depth: u32,

    /// SHA-256 hash of the active policy (embedded in receipts).
    pub policy_hash: String,

    /// Whether nested sampling requests are allowed at all.
    pub allow_sampling: bool,

    /// Whether sampling requests may include tool-use affordances.
    pub allow_sampling_tool_use: bool,

    /// Whether nested elicitation requests are allowed.
    pub allow_elicitation: bool,

    /// Maximum total wall-clock duration permitted for one streamed tool result.
    pub max_stream_duration_secs: u64,

    /// Maximum total canonical payload size permitted for one streamed tool result.
    pub max_stream_total_bytes: u64,

    /// Whether durable receipts and kernel-signed checkpoints are mandatory
    /// prerequisites for this deployment.
    pub require_web3_evidence: bool,

    /// Number of receipts between Merkle checkpoint snapshots. Default: 100.
    ///
    /// Set to 0 to disable automatic checkpointing for deployments that do not
    /// require web3 evidence.
    pub checkpoint_batch_size: u64,

    /// Optional receipt retention configuration.
    ///
    /// When `None` (default), retention is disabled and receipts accumulate
    /// indefinitely. When `Some(config)`, the kernel will archive receipts
    /// that exceed the time or size threshold.
    pub retention_config: Option<crate::receipt_store::RetentionConfig>,
}

pub const DEFAULT_MAX_STREAM_DURATION_SECS: u64 = 300;
pub const DEFAULT_MAX_STREAM_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_CHECKPOINT_BATCH_SIZE: u64 = 100;
pub const DEFAULT_RETENTION_DAYS: u64 = 90;
pub const DEFAULT_MAX_SIZE_BYTES: u64 = 10_737_418_240;

/// The ARC Runtime Kernel.
///
/// This is the central component of the ARC protocol. It validates capabilities,
/// runs guards, dispatches tool calls, and signs receipts.
///
/// The kernel is designed to be the sole trusted mediator. It never exposes its
/// signing key, address, or internal state to the agent.
pub struct ArcKernel {
    config: KernelConfig,
    guards: Vec<Box<dyn Guard>>,
    budget_store: Box<dyn BudgetStore>,
    revocation_store: Box<dyn RevocationStore>,
    capability_authority: Box<dyn CapabilityAuthority>,
    tool_servers: HashMap<ServerId, Box<dyn ToolServerConnection>>,
    resource_providers: Vec<Box<dyn ResourceProvider>>,
    prompt_providers: Vec<Box<dyn PromptProvider>>,
    sessions: HashMap<SessionId, Session>,
    receipt_log: ReceiptLog,
    child_receipt_log: ChildReceiptLog,
    receipt_store: Option<Box<dyn ReceiptStore>>,
    payment_adapter: Option<Box<dyn PaymentAdapter>>,
    price_oracle: Option<Box<dyn PriceOracle>>,
    attestation_trust_policy: Option<AttestationTrustPolicy>,
    session_counter: u64,
    /// How many receipts per Merkle checkpoint batch. Default: 100.
    checkpoint_batch_size: u64,
    /// Monotonic counter for checkpoint_seq values.
    checkpoint_seq_counter: u64,
    /// seq of the last receipt included in the previous checkpoint batch.
    last_checkpoint_seq: u64,
    /// Nonce replay store for DPoP proof verification. Required when any grant has dpop_required.
    dpop_nonce_store: Option<dpop::DpopNonceStore>,
    /// Configuration for DPoP proof verification TTLs and clock skew.
    dpop_config: Option<dpop::DpopConfig>,
}

#[derive(Clone, Copy)]
pub(crate) struct MatchingGrant<'a> {
    pub(crate) index: usize,
    pub(crate) grant: &'a ToolGrant,
    pub(crate) specificity: (u8, u8, usize),
}

/// Result of a monetary budget charge attempt.
///
/// Carries the accounting info needed to populate FinancialReceiptMetadata.
pub(crate) struct BudgetChargeResult {
    grant_index: usize,
    cost_charged: u64,
    currency: String,
    budget_total: u64,
    /// Running total cost after this charge (used to compute budget_remaining).
    new_total_cost_charged: u64,
}

struct SessionNestedFlowBridge<'a, C> {
    sessions: &'a mut HashMap<SessionId, Session>,
    child_receipts: &'a mut Vec<ChildRequestReceipt>,
    parent_context: &'a OperationContext,
    allow_sampling: bool,
    allow_sampling_tool_use: bool,
    allow_elicitation: bool,
    policy_hash: &'a str,
    kernel_keypair: &'a Keypair,
    client: &'a mut C,
}

impl<C> SessionNestedFlowBridge<'_, C> {
    fn complete_child_request_with_receipt<T: serde::Serialize>(
        &mut self,
        child_context: &OperationContext,
        operation_kind: OperationKind,
        result: &Result<T, KernelError>,
    ) -> Result<(), KernelError> {
        let terminal_state = child_terminal_state(&child_context.request_id, result);
        complete_session_request_with_terminal_state_in_sessions(
            self.sessions,
            &child_context.session_id,
            &child_context.request_id,
            terminal_state.clone(),
        )?;

        let receipt = build_child_request_receipt(
            self.policy_hash,
            self.kernel_keypair,
            child_context,
            operation_kind,
            terminal_state,
            child_outcome_payload(result)?,
        )?;
        self.child_receipts.push(receipt);
        Ok(())
    }
}

impl<C: NestedFlowClient> NestedFlowBridge for SessionNestedFlowBridge<'_, C> {
    fn parent_request_id(&self) -> &RequestId {
        &self.parent_context.request_id
    }

    fn poll_parent_cancellation(&mut self) -> Result<(), KernelError> {
        self.client.poll_parent_cancellation(self.parent_context)
    }

    fn list_roots(&mut self) -> Result<Vec<RootDefinition>, KernelError> {
        let child_context = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            nested_child_request_id(&self.parent_context.request_id, "roots"),
            OperationKind::ListRoots,
            None,
            false,
        )?;

        let result = (|| {
            let session = session_from_map(self.sessions, &child_context.session_id)?;
            session.validate_context(&child_context)?;
            session.ensure_operation_allowed(OperationKind::ListRoots)?;
            if !session.peer_capabilities().supports_roots {
                return Err(KernelError::RootsNotNegotiated);
            }

            let roots = self
                .client
                .list_roots(self.parent_context, &child_context)?;
            session_mut_from_map(self.sessions, &child_context.session_id)?
                .replace_roots(roots.clone());
            Ok(roots)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_mut_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::ListRoots,
            &result,
        )?;

        result
    }

    fn create_message(
        &mut self,
        operation: CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        let child_context = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            nested_child_request_id(&self.parent_context.request_id, "sample"),
            OperationKind::CreateMessage,
            None,
            true,
        )?;

        let result = (|| {
            validate_sampling_request_in_sessions(
                self.sessions,
                self.allow_sampling,
                self.allow_sampling_tool_use,
                &child_context,
                &operation,
            )?;
            self.client
                .create_message(self.parent_context, &child_context, &operation)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_mut_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::CreateMessage,
            &result,
        )?;

        result
    }

    fn create_elicitation(
        &mut self,
        operation: CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        let child_context = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            nested_child_request_id(&self.parent_context.request_id, "elicit"),
            OperationKind::CreateElicitation,
            None,
            true,
        )?;

        let result = (|| {
            validate_elicitation_request_in_sessions(
                self.sessions,
                self.allow_elicitation,
                &child_context,
                &operation,
            )?;
            self.client
                .create_elicitation(self.parent_context, &child_context, &operation)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_mut_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::CreateElicitation,
            &result,
        )?;

        result
    }

    fn notify_elicitation_completed(&mut self, elicitation_id: &str) -> Result<(), KernelError> {
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        self.client
            .notify_elicitation_completed(self.parent_context, elicitation_id)
    }

    fn notify_resource_updated(&mut self, uri: &str) -> Result<(), KernelError> {
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        if !session.is_resource_subscribed(uri) {
            return Ok(());
        }

        self.client
            .notify_resource_updated(self.parent_context, uri)
    }

    fn notify_resources_list_changed(&mut self) -> Result<(), KernelError> {
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        self.client
            .notify_resources_list_changed(self.parent_context)
    }
}

impl ArcKernel {
    pub fn new(config: KernelConfig) -> Self {
        info!("initializing ARC kernel");
        let authority_keypair = config.keypair.clone();
        let checkpoint_batch_size = config.checkpoint_batch_size;
        Self {
            config,
            guards: Vec::new(),
            budget_store: Box::new(InMemoryBudgetStore::new()),
            revocation_store: Box::new(InMemoryRevocationStore::new()),
            capability_authority: Box::new(LocalCapabilityAuthority::new(authority_keypair)),
            tool_servers: HashMap::new(),
            resource_providers: Vec::new(),
            prompt_providers: Vec::new(),
            sessions: HashMap::new(),
            receipt_log: ReceiptLog::new(),
            child_receipt_log: ChildReceiptLog::new(),
            receipt_store: None,
            payment_adapter: None,
            price_oracle: None,
            attestation_trust_policy: None,
            session_counter: 0,
            checkpoint_batch_size,
            checkpoint_seq_counter: 0,
            last_checkpoint_seq: 0,
            dpop_nonce_store: None,
            dpop_config: None,
        }
    }

    pub fn set_receipt_store(&mut self, receipt_store: Box<dyn ReceiptStore>) {
        self.receipt_store = Some(receipt_store);
    }

    pub fn set_payment_adapter(&mut self, payment_adapter: Box<dyn PaymentAdapter>) {
        self.payment_adapter = Some(payment_adapter);
    }

    pub fn set_price_oracle(&mut self, price_oracle: Box<dyn PriceOracle>) {
        self.price_oracle = Some(price_oracle);
    }

    pub fn set_attestation_trust_policy(
        &mut self,
        attestation_trust_policy: AttestationTrustPolicy,
    ) {
        self.attestation_trust_policy = Some(attestation_trust_policy);
    }

    pub fn set_revocation_store(&mut self, revocation_store: Box<dyn RevocationStore>) {
        self.revocation_store = revocation_store;
    }

    pub fn set_capability_authority(&mut self, capability_authority: Box<dyn CapabilityAuthority>) {
        self.capability_authority = capability_authority;
    }

    pub fn set_budget_store(&mut self, budget_store: Box<dyn BudgetStore>) {
        self.budget_store = budget_store;
    }

    /// Install a DPoP nonce replay store and verification config.
    ///
    /// Once installed, any invocation whose matched grant has `dpop_required == Some(true)`
    /// must carry a valid `DpopProof` on the `ToolCallRequest`. Requests that lack a proof
    /// or whose proof fails verification are denied fail-closed.
    pub fn set_dpop_store(&mut self, nonce_store: dpop::DpopNonceStore, config: dpop::DpopConfig) {
        self.dpop_nonce_store = Some(nonce_store);
        self.dpop_config = Some(config);
    }

    pub fn requires_web3_evidence(&self) -> bool {
        self.config.require_web3_evidence
    }

    pub fn validate_web3_evidence_prerequisites(&self) -> Result<(), KernelError> {
        if !self.requires_web3_evidence() {
            return Ok(());
        }

        let Some(store) = self.receipt_store.as_deref() else {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require a durable receipt store".to_string(),
            ));
        };

        if self.checkpoint_batch_size == 0 {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require checkpoint_batch_size > 0".to_string(),
            ));
        }

        if !store.supports_kernel_signed_checkpoints() {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require local receipt persistence with kernel-signed checkpoint support; append-only remote receipt mirrors are unsupported".to_string(),
            ));
        }

        Ok(())
    }

    /// Register a policy guard. Guards are evaluated in registration order.
    /// If any guard denies, the request is denied.
    pub fn add_guard(&mut self, guard: Box<dyn Guard>) {
        self.guards.push(guard);
    }

    /// Register a tool server connection.
    pub fn register_tool_server(&mut self, connection: Box<dyn ToolServerConnection>) {
        let id = connection.server_id().to_owned();
        info!(server_id = %id, "registering tool server");
        self.tool_servers.insert(id, connection);
    }

    /// Register a resource provider.
    pub fn register_resource_provider(&mut self, provider: Box<dyn ResourceProvider>) {
        info!("registering resource provider");
        self.resource_providers.push(provider);
    }

    /// Register a prompt provider.
    pub fn register_prompt_provider(&mut self, provider: Box<dyn PromptProvider>) {
        info!("registering prompt provider");
        self.prompt_providers.push(provider);
    }

    /// Open a new logical session for an agent and bind any capabilities that
    /// were issued during setup to that session.
    fn validate_non_tool_capability(
        &self,
        capability: &CapabilityToken,
        agent_id: &str,
    ) -> Result<(), KernelError> {
        self.verify_capability_signature(capability)
            .map_err(|_| KernelError::InvalidSignature)?;
        check_time_bounds(capability, current_unix_timestamp())?;
        self.check_revocation(capability)?;
        check_subject_binding(capability, agent_id)?;
        Ok(())
    }

    /// Evaluate a tool call request.
    ///
    /// This is the kernel's main entry point. It performs the full validation
    /// pipeline:
    ///
    /// 1. Verify capability signature against known CA public keys.
    /// 2. Check time bounds (not expired, not-before satisfied).
    /// 3. Check revocation status of the capability and its delegation chain.
    /// 4. Verify the requested tool is within the capability's scope.
    /// 5. Check and decrement invocation budget.
    /// 6. Run all registered guards.
    /// 7. If all pass: forward to tool server, sign allow receipt.
    /// 8. If any fail: sign deny receipt.
    ///
    /// Every call -- whether allowed or denied -- produces exactly one signed
    /// receipt.
    pub fn evaluate_tool_call(
        &mut self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_with_session_roots(request, None)
    }

    fn evaluate_tool_call_with_session_roots(
        &mut self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        let now = current_unix_timestamp();

        debug!(
            request_id = %request.request_id,
            tool = %request.tool_name,
            server = %request.server_id,
            "evaluating tool call"
        );

        let cap = &request.capability;

        if let Err(reason) = self.verify_capability_signature(cap) {
            let msg = format!("signature verification failed: {reason}");
            warn!(request_id = %request.request_id, %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = check_time_bounds(cap, now) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = self.check_revocation(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = check_subject_binding(cap, &request.agent_id) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        let matching_grants = match resolve_matching_grants(
            cap,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
        ) {
            Ok(grants) if !grants.is_empty() => grants,
            Ok(_) => {
                let e = KernelError::OutOfScope {
                    tool: request.tool_name.clone(),
                    server: request.server_id.clone(),
                };
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                return self.build_deny_response(request, &msg, now, None);
            }
            Err(e) => {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                return self.build_deny_response(request, &msg, now, None);
            }
        };

        // DPoP enforcement before budget charge: if any matching grant requires
        // DPoP, verify the proof now so an attacker cannot drain the budget with
        // a valid capability token but missing or invalid DPoP proof.
        if matching_grants
            .iter()
            .any(|m| m.grant.dpop_required == Some(true))
        {
            if let Err(e) = self.verify_dpop_for_request(request, cap) {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "DPoP verification failed");
                return self.build_deny_response(request, &msg, now, None);
            }
        }

        if let Err(e) = self.ensure_registered_tool_target(request) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "tool target not registered");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(error) = self.record_observed_capability_snapshot(cap) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "failed to persist capability lineage");
            return self.build_deny_response(request, &msg, now, None);
        }

        let (matched_grant_index, charge_result) =
            match self.check_and_increment_budget(cap, &matching_grants) {
                Ok(result) => result,
                Err(e) => {
                    let msg = e.to_string();
                    warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                    // For monetary budget exhaustion, build a denial receipt with financial metadata.
                    return self.build_monetary_deny_response(
                        request,
                        &msg,
                        now,
                        &matching_grants,
                        cap,
                    );
                }
            };

        let matched_grant = matching_grants
            .iter()
            .find(|matching| matching.index == matched_grant_index)
            .map(|matching| matching.grant)
            .ok_or_else(|| {
                KernelError::Internal(format!(
                    "matched grant index {matched_grant_index} missing from candidate set"
                ))
            })?;

        if let Err(error) = self.validate_governed_transaction(
            request,
            cap,
            matched_grant,
            charge_result.as_ref(),
            now,
        ) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "governed transaction denied");
            if let Some(ref charge) = charge_result {
                let total_cost_charged_after_release =
                    self.reverse_budget_charge(&cap.id, charge)?;
                return self.build_pre_execution_monetary_deny_response(
                    request,
                    &msg,
                    now,
                    charge,
                    total_cost_charged_after_release,
                    cap,
                );
            }
            return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
        }

        if let Err(e) = self.run_guards(
            request,
            &cap.scope,
            session_filesystem_roots,
            Some(matched_grant_index),
        ) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "guard denied");
            if let Some(ref charge) = charge_result {
                let total_cost_charged_after_release =
                    self.reverse_budget_charge(&cap.id, charge)?;
                return self.build_pre_execution_monetary_deny_response(
                    request,
                    &msg,
                    now,
                    charge,
                    total_cost_charged_after_release,
                    cap,
                );
            }
            return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
        }

        let payment_authorization =
            match self.authorize_payment_if_needed(request, charge_result.as_ref()) {
                Ok(authorization) => authorization,
                Err(error) => {
                    let msg = format!("payment authorization failed: {error}");
                    warn!(request_id = %request.request_id, reason = %msg, "payment denied");
                    if let Some(ref charge) = charge_result {
                        let total_cost_charged_after_release =
                            self.reverse_budget_charge(&cap.id, charge)?;
                        return self.build_pre_execution_monetary_deny_response(
                            request,
                            &msg,
                            now,
                            charge,
                            total_cost_charged_after_release,
                            cap,
                        );
                    }
                    return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
                }
            };

        let tool_started_at = Instant::now();
        let has_monetary = charge_result.is_some();
        let (tool_output, reported_cost) =
            match self.dispatch_tool_call_with_cost(request, has_monetary) {
                Ok(result) => result,
                Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                    self.unwind_aborted_monetary_invocation(
                        request,
                        cap,
                        charge_result.as_ref(),
                        payment_authorization.as_ref(),
                    )?;
                    warn!(
                        request_id = %request.request_id,
                        reason = %error,
                        "tool call requires URL elicitation"
                    );
                    return Err(error);
                }
                Err(KernelError::RequestCancelled { reason, .. }) => {
                    self.unwind_aborted_monetary_invocation(
                        request,
                        cap,
                        charge_result.as_ref(),
                        payment_authorization.as_ref(),
                    )?;
                    warn!(
                        request_id = %request.request_id,
                        reason = %reason,
                        "tool call cancelled"
                    );
                    return self.build_cancelled_response(
                        request,
                        &reason,
                        now,
                        Some(matched_grant_index),
                    );
                }
                Err(KernelError::RequestIncomplete(reason)) => {
                    self.unwind_aborted_monetary_invocation(
                        request,
                        cap,
                        charge_result.as_ref(),
                        payment_authorization.as_ref(),
                    )?;
                    warn!(
                        request_id = %request.request_id,
                        reason = %reason,
                        "tool call incomplete"
                    );
                    return self.build_incomplete_response(
                        request,
                        &reason,
                        now,
                        Some(matched_grant_index),
                    );
                }
                Err(e) => {
                    self.unwind_aborted_monetary_invocation(
                        request,
                        cap,
                        charge_result.as_ref(),
                        payment_authorization.as_ref(),
                    )?;
                    let msg = e.to_string();
                    warn!(request_id = %request.request_id, reason = %msg, "tool server error");
                    return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
                }
            };
        self.finalize_tool_output_with_cost(
            request,
            tool_output,
            tool_started_at.elapsed(),
            now,
            matched_grant_index,
            charge_result,
            reported_cost,
            payment_authorization,
            cap,
        )
    }

    fn evaluate_tool_call_with_nested_flow_client<C: NestedFlowClient>(
        &mut self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
    ) -> Result<ToolCallResponse, KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        let now = current_unix_timestamp();

        debug!(
            request_id = %request.request_id,
            tool = %request.tool_name,
            server = %request.server_id,
            "evaluating tool call with nested-flow bridge"
        );

        let cap = &request.capability;

        if let Err(reason) = self.verify_capability_signature(cap) {
            let msg = format!("signature verification failed: {reason}");
            warn!(request_id = %request.request_id, %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = check_time_bounds(cap, now) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = self.check_revocation(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = check_subject_binding(cap, &request.agent_id) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        let matching_grants = match resolve_matching_grants(
            cap,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
        ) {
            Ok(grants) if !grants.is_empty() => grants,
            Ok(_) => {
                let e = KernelError::OutOfScope {
                    tool: request.tool_name.clone(),
                    server: request.server_id.clone(),
                };
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                return self.build_deny_response(request, &msg, now, None);
            }
            Err(e) => {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                return self.build_deny_response(request, &msg, now, None);
            }
        };

        // DPoP enforcement before budget charge: if any matching grant requires
        // DPoP, verify the proof now so an attacker cannot drain the budget with
        // a valid capability token but missing or invalid DPoP proof.
        if matching_grants
            .iter()
            .any(|m| m.grant.dpop_required == Some(true))
        {
            if let Err(e) = self.verify_dpop_for_request(request, cap) {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "DPoP verification failed");
                return self.build_deny_response(request, &msg, now, None);
            }
        }

        if let Err(e) = self.ensure_registered_tool_target(request) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "tool target not registered");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(error) = self.record_observed_capability_snapshot(cap) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "failed to persist capability lineage");
            return self.build_deny_response(request, &msg, now, None);
        }

        let (matched_grant_index, charge_result) =
            match self.check_and_increment_budget(cap, &matching_grants) {
                Ok(result) => result,
                Err(e) => {
                    let msg = e.to_string();
                    warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                    return self.build_monetary_deny_response(
                        request,
                        &msg,
                        now,
                        &matching_grants,
                        cap,
                    );
                }
            };

        let matched_grant = matching_grants
            .iter()
            .find(|matching| matching.index == matched_grant_index)
            .map(|matching| matching.grant)
            .ok_or_else(|| {
                KernelError::Internal(format!(
                    "matched grant index {matched_grant_index} missing from candidate set"
                ))
            })?;

        if let Err(error) = self.validate_governed_transaction(
            request,
            cap,
            matched_grant,
            charge_result.as_ref(),
            now,
        ) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "governed transaction denied");
            if let Some(ref charge) = charge_result {
                let total_cost_charged_after_release =
                    self.reverse_budget_charge(&cap.id, charge)?;
                return self.build_pre_execution_monetary_deny_response(
                    request,
                    &msg,
                    now,
                    charge,
                    total_cost_charged_after_release,
                    cap,
                );
            }
            return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
        }

        let session_roots =
            self.session_enforceable_filesystem_root_paths_owned(&parent_context.session_id)?;

        if let Err(e) = self.run_guards(
            request,
            &cap.scope,
            Some(session_roots.as_slice()),
            Some(matched_grant_index),
        ) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "guard denied");
            if let Some(ref charge) = charge_result {
                let total_cost_charged_after_release =
                    self.reverse_budget_charge(&cap.id, charge)?;
                return self.build_pre_execution_monetary_deny_response(
                    request,
                    &msg,
                    now,
                    charge,
                    total_cost_charged_after_release,
                    cap,
                );
            }
            return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
        }

        let payment_authorization =
            match self.authorize_payment_if_needed(request, charge_result.as_ref()) {
                Ok(authorization) => authorization,
                Err(error) => {
                    let msg = format!("payment authorization failed: {error}");
                    warn!(request_id = %request.request_id, reason = %msg, "payment denied");
                    if let Some(ref charge) = charge_result {
                        let total_cost_charged_after_release =
                            self.reverse_budget_charge(&cap.id, charge)?;
                        return self.build_pre_execution_monetary_deny_response(
                            request,
                            &msg,
                            now,
                            charge,
                            total_cost_charged_after_release,
                            cap,
                        );
                    }
                    return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
                }
            };

        let tool_started_at = Instant::now();
        let mut child_receipts = Vec::new();
        let tool_output_result = {
            let server = self.tool_servers.get(&request.server_id).ok_or_else(|| {
                KernelError::ToolNotRegistered(format!(
                    "server \"{}\" / tool \"{}\"",
                    request.server_id, request.tool_name
                ))
            })?;
            let mut bridge = SessionNestedFlowBridge {
                sessions: &mut self.sessions,
                child_receipts: &mut child_receipts,
                parent_context,
                allow_sampling: self.config.allow_sampling,
                allow_sampling_tool_use: self.config.allow_sampling_tool_use,
                allow_elicitation: self.config.allow_elicitation,
                policy_hash: &self.config.policy_hash,
                kernel_keypair: &self.config.keypair,
                client,
            };

            match server.invoke_stream(
                &request.tool_name,
                request.arguments.clone(),
                Some(&mut bridge),
            ) {
                Ok(Some(stream)) => Ok(ToolServerOutput::Stream(stream)),
                Ok(None) => match server.invoke(
                    &request.tool_name,
                    request.arguments.clone(),
                    Some(&mut bridge),
                ) {
                    Ok(result) => Ok(ToolServerOutput::Value(result)),
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            }
        };
        self.record_child_receipts(child_receipts)?;
        let tool_output = match tool_output_result {
            Ok(output) => output,
            Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                warn!(
                    request_id = %request.request_id,
                    reason = %error,
                    "tool call requires URL elicitation"
                );
                return Err(error);
            }
            Err(KernelError::RequestCancelled { request_id, reason }) => {
                self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                if request_id == parent_context.request_id {
                    self.session_mut(&parent_context.session_id)?
                        .request_cancellation(&parent_context.request_id)?;
                }
                warn!(
                    request_id = %request.request_id,
                    reason = %reason,
                    "tool call cancelled"
                );
                return self.build_cancelled_response(
                    request,
                    &reason,
                    now,
                    Some(matched_grant_index),
                );
            }
            Err(KernelError::RequestIncomplete(reason)) => {
                self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                warn!(
                    request_id = %request.request_id,
                    reason = %reason,
                    "tool call incomplete"
                );
                return self.build_incomplete_response(
                    request,
                    &reason,
                    now,
                    Some(matched_grant_index),
                );
            }
            Err(error) => {
                self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "tool server error");
                return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
            }
        };
        self.finalize_tool_output_with_cost(
            request,
            tool_output,
            tool_started_at.elapsed(),
            now,
            matched_grant_index,
            charge_result,
            None,
            payment_authorization,
            cap,
        )
    }

    /// Issue a new capability for an agent.
    ///
    /// The kernel delegates issuance to the configured capability authority.
    pub fn issue_capability(
        &self,
        subject: &arc_core::PublicKey,
        scope: ArcScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        let capability = self
            .capability_authority
            .issue_capability(subject, scope, ttl_seconds)?;

        info!(
            capability_id = %capability.id,
            subject = %subject.to_hex(),
            ttl = ttl_seconds,
            issuer = %capability.issuer.to_hex(),
            "issuing capability"
        );

        Ok(capability)
    }

    /// Revoke a capability and all descendants in its delegation subtree.
    ///
    /// When a root capability is revoked, every capability whose
    /// `delegation_chain` contains the revoked ID will also be rejected
    /// on presentation (the kernel checks all chain entries against the
    /// revocation store).
    pub fn revoke_capability(&mut self, capability_id: &CapabilityId) -> Result<(), KernelError> {
        info!(capability_id = %capability_id, "revoking capability");
        let _ = self.revocation_store.revoke(capability_id)?;
        Ok(())
    }

    /// Read-only access to the receipt log.
    pub fn receipt_log(&self) -> &ReceiptLog {
        &self.receipt_log
    }

    pub fn child_receipt_log(&self) -> &ChildReceiptLog {
        &self.child_receipt_log
    }

    pub fn guard_count(&self) -> usize {
        self.guards.len()
    }

    pub fn drain_tool_server_events(&self) -> Vec<ToolServerEvent> {
        let mut events = Vec::new();
        for (server_id, server) in &self.tool_servers {
            match server.drain_events() {
                Ok(mut server_events) => events.append(&mut server_events),
                Err(error) => warn!(
                    server_id = %server_id,
                    reason = %error,
                    "failed to drain tool server events"
                ),
            }
        }
        events
    }

    pub fn register_session_pending_url_elicitation(
        &mut self,
        session_id: &SessionId,
        elicitation_id: impl Into<String>,
        related_task_id: Option<String>,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?
            .register_pending_url_elicitation(elicitation_id, related_task_id);
        Ok(())
    }

    pub fn register_session_required_url_elicitations(
        &mut self,
        session_id: &SessionId,
        elicitations: &[CreateElicitationOperation],
        related_task_id: Option<&str>,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?
            .register_required_url_elicitations(elicitations, related_task_id);
        Ok(())
    }

    pub fn queue_session_elicitation_completion(
        &mut self,
        session_id: &SessionId,
        elicitation_id: &str,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?
            .queue_elicitation_completion(elicitation_id);
        Ok(())
    }

    pub fn queue_session_late_event(
        &mut self,
        session_id: &SessionId,
        event: LateSessionEvent,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?.queue_late_event(event);
        Ok(())
    }

    pub fn queue_session_tool_server_event(
        &mut self,
        session_id: &SessionId,
        event: ToolServerEvent,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?.queue_tool_server_event(event);
        Ok(())
    }

    pub fn queue_session_tool_server_events(
        &mut self,
        session_id: &SessionId,
    ) -> Result<(), KernelError> {
        let events = self.drain_tool_server_events();
        let session = self.session_mut(session_id)?;
        for event in events {
            session.queue_tool_server_event(event);
        }
        Ok(())
    }

    pub fn drain_session_late_events(
        &mut self,
        session_id: &SessionId,
    ) -> Result<Vec<LateSessionEvent>, KernelError> {
        Ok(self.session_mut(session_id)?.take_late_events())
    }

    pub fn ca_count(&self) -> usize {
        self.config.ca_public_keys.len()
    }

    pub fn public_key(&self) -> arc_core::PublicKey {
        self.config.keypair.public_key()
    }

    fn session_mut(&mut self, session_id: &SessionId) -> Result<&mut Session, KernelError> {
        self.sessions
            .get_mut(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))
    }

    /// Verify the capability's signature against the trusted CA keys or the
    /// kernel's own key (for locally-issued capabilities).
    fn verify_capability_signature(&self, cap: &CapabilityToken) -> Result<(), String> {
        let kernel_pk = self.config.keypair.public_key();
        let mut trusted = self.config.ca_public_keys.clone();
        for authority_pk in self.capability_authority.trusted_public_keys() {
            if !trusted.contains(&authority_pk) {
                trusted.push(authority_pk);
            }
        }
        if !trusted.contains(&kernel_pk) {
            trusted.push(kernel_pk);
        }

        for pk in &trusted {
            if *pk == cap.issuer {
                return match cap.verify_signature() {
                    Ok(true) => Ok(()),
                    Ok(false) => Err("signature did not verify".to_string()),
                    Err(e) => Err(e.to_string()),
                };
            }
        }

        Err("signer public key not found among trusted CAs".to_string())
    }

    /// Check the revocation store for the capability and its entire
    /// delegation chain. If any ancestor is revoked, the capability is
    /// rejected.
    fn check_revocation(&self, cap: &CapabilityToken) -> Result<(), KernelError> {
        if self.revocation_store.is_revoked(&cap.id)? {
            return Err(KernelError::CapabilityRevoked(cap.id.clone()));
        }
        for link in &cap.delegation_chain {
            if self.revocation_store.is_revoked(&link.capability_id)? {
                return Err(KernelError::DelegationChainRevoked(
                    link.capability_id.clone(),
                ));
            }
        }
        Ok(())
    }

    /// Check and decrement the invocation budget for a capability.
    ///
    /// Returns `(matched_grant_index, Option<BudgetChargeResult>)`.
    /// The charge result is populated only for monetary grants.
    fn check_and_increment_budget(
        &mut self,
        cap: &CapabilityToken,
        matching_grants: &[MatchingGrant<'_>],
    ) -> Result<(usize, Option<BudgetChargeResult>), KernelError> {
        let mut saw_exhausted_budget = false;

        for matching in matching_grants {
            let grant = matching.grant;
            let has_monetary =
                grant.max_cost_per_invocation.is_some() || grant.max_total_cost.is_some();

            if has_monetary {
                // Use worst-case max_cost_per_invocation as the pre-execution debit.
                let cost_units = grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|m| m.units)
                    .unwrap_or(0);
                let currency = grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|m| m.currency.clone())
                    .or_else(|| grant.max_total_cost.as_ref().map(|m| m.currency.clone()))
                    .unwrap_or_else(|| "USD".to_string());
                let max_total = grant.max_total_cost.as_ref().map(|m| m.units);
                let max_per = grant.max_cost_per_invocation.as_ref().map(|m| m.units);
                let budget_total = max_total.unwrap_or(u64::MAX);

                let ok = self.budget_store.try_charge_cost(
                    &cap.id,
                    matching.index,
                    grant.max_invocations,
                    cost_units,
                    max_per,
                    max_total,
                )?;
                if ok {
                    // Read the new running total from the store so budget_remaining
                    // is computed against cumulative spend, not just this invocation.
                    let new_total_cost_charged = self
                        .budget_store
                        .get_usage(&cap.id, matching.index)
                        .ok()
                        .flatten()
                        .map(|record| record.total_cost_charged)
                        .unwrap_or(cost_units);
                    let charge = BudgetChargeResult {
                        grant_index: matching.index,
                        cost_charged: cost_units,
                        currency,
                        budget_total,
                        new_total_cost_charged,
                    };
                    return Ok((matching.index, Some(charge)));
                }
                saw_exhausted_budget = true;
            } else {
                // Non-monetary path: use try_increment as before.
                if self.budget_store.try_increment(
                    &cap.id,
                    matching.index,
                    grant.max_invocations,
                )? {
                    return Ok((matching.index, None));
                }
                saw_exhausted_budget = saw_exhausted_budget || grant.max_invocations.is_some();
            }
        }

        if saw_exhausted_budget {
            Err(KernelError::BudgetExhausted(cap.id.clone()))
        } else {
            // No matching grant had any limit -- allow with the first grant's index.
            let first_index = matching_grants.first().map(|m| m.index).unwrap_or(0);
            Ok((first_index, None))
        }
    }

    fn reverse_budget_charge(
        &mut self,
        capability_id: &str,
        charge: &BudgetChargeResult,
    ) -> Result<u64, KernelError> {
        self.budget_store.reverse_charge_cost(
            capability_id,
            charge.grant_index,
            charge.cost_charged,
        )?;
        Ok(self
            .budget_store
            .get_usage(capability_id, charge.grant_index)?
            .map(|record| record.total_cost_charged)
            .unwrap_or(0))
    }

    fn reduce_budget_charge_to_actual(
        &mut self,
        capability_id: &str,
        charge: &BudgetChargeResult,
        actual_cost_units: u64,
    ) -> Result<u64, KernelError> {
        if actual_cost_units >= charge.cost_charged {
            return Ok(charge.new_total_cost_charged);
        }

        self.budget_store.reduce_charge_cost(
            capability_id,
            charge.grant_index,
            charge.cost_charged - actual_cost_units,
        )?;
        Ok(self
            .budget_store
            .get_usage(capability_id, charge.grant_index)?
            .map(|record| record.total_cost_charged)
            .unwrap_or(actual_cost_units))
    }

    fn block_on_price_oracle<T>(
        &self,
        future: impl Future<Output = Result<T, PriceOracleError>>,
    ) -> Result<T, KernelError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => match handle.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(|| {
                    handle
                        .block_on(future)
                        .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))
                }),
                tokio::runtime::RuntimeFlavor::CurrentThread => {
                    Err(KernelError::CrossCurrencyOracle(
                        "current-thread tokio runtime cannot synchronously resolve price oracles"
                            .to_string(),
                    ))
                }
                flavor => Err(KernelError::CrossCurrencyOracle(format!(
                    "unsupported tokio runtime flavor for synchronous oracle resolution: {flavor:?}"
                ))),
            },
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    KernelError::CrossCurrencyOracle(format!(
                        "failed to build synchronous oracle runtime: {error}"
                    ))
                })?
                .block_on(future)
                .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string())),
        }
    }

    fn resolve_cross_currency_cost(
        &self,
        reported_cost: &ToolInvocationCost,
        grant_currency: &str,
        timestamp: u64,
    ) -> Result<(u64, arc_core::web3::OracleConversionEvidence), KernelError> {
        let oracle =
            self.price_oracle
                .as_ref()
                .ok_or_else(|| KernelError::NoCrossCurrencyOracle {
                    base: reported_cost.currency.clone(),
                    quote: grant_currency.to_string(),
                })?;
        let rate =
            self.block_on_price_oracle(oracle.get_rate(&reported_cost.currency, grant_currency))?;
        let converted_units =
            convert_supported_units(reported_cost.units, &rate, rate.conversion_margin_bps)
                .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))?;
        let evidence = rate
            .to_conversion_evidence(
                reported_cost.units,
                reported_cost.currency.clone(),
                grant_currency.to_string(),
                converted_units,
                timestamp,
            )
            .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))?;
        Ok((converted_units, evidence))
    }

    fn ensure_registered_tool_target(&self, request: &ToolCallRequest) -> Result<(), KernelError> {
        self.tool_servers.get(&request.server_id).ok_or_else(|| {
            KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ))
        })?;
        Ok(())
    }

    fn authorize_payment_if_needed(
        &self,
        request: &ToolCallRequest,
        charge_result: Option<&BudgetChargeResult>,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        let Some(charge) = charge_result else {
            return Ok(None);
        };
        let Some(adapter) = self.payment_adapter.as_ref() else {
            return Ok(None);
        };

        let governed = request
            .governed_intent
            .as_ref()
            .map(|intent| {
                intent
                    .binding_hash()
                    .map(|intent_hash| GovernedPaymentContext {
                        intent_id: intent.id.clone(),
                        intent_hash,
                        purpose: intent.purpose.clone(),
                        server_id: intent.server_id.clone(),
                        tool_name: intent.tool_name.clone(),
                        approval_token_id: request
                            .approval_token
                            .as_ref()
                            .map(|token| token.id.clone()),
                    })
                    .map_err(|error| {
                        PaymentError::RailError(format!(
                            "failed to hash governed intent for payment authorization: {error}"
                        ))
                    })
            })
            .transpose()?;
        let commerce = request.governed_intent.as_ref().and_then(|intent| {
            intent
                .commerce
                .as_ref()
                .map(|commerce| CommercePaymentContext {
                    seller: commerce.seller.clone(),
                    shared_payment_token_id: commerce.shared_payment_token_id.clone(),
                    max_amount: intent.max_amount.clone(),
                })
        });

        adapter
            .authorize(&PaymentAuthorizeRequest {
                amount_units: charge.cost_charged,
                currency: charge.currency.clone(),
                payer: request.agent_id.clone(),
                payee: request.server_id.clone(),
                reference: request.request_id.clone(),
                governed,
                commerce,
            })
            .map(Some)
    }

    fn governed_requirements(
        grant: &ToolGrant,
    ) -> (
        bool,
        Option<u64>,
        Option<String>,
        Option<RuntimeAssuranceTier>,
        Option<GovernedAutonomyTier>,
    ) {
        let mut intent_required = false;
        let mut approval_threshold_units = None;
        let mut seller = None;
        let mut minimum_runtime_assurance = None;
        let mut minimum_autonomy_tier = None;

        for constraint in &grant.constraints {
            match constraint {
                Constraint::GovernedIntentRequired => {
                    intent_required = true;
                }
                Constraint::RequireApprovalAbove { threshold_units } => {
                    approval_threshold_units = Some(
                        approval_threshold_units.map_or(*threshold_units, |current: u64| {
                            current.max(*threshold_units)
                        }),
                    );
                }
                Constraint::SellerExact(expected_seller) => {
                    seller = Some(expected_seller.clone());
                }
                Constraint::MinimumRuntimeAssurance(required_tier) => {
                    minimum_runtime_assurance = Some(
                        minimum_runtime_assurance
                            .map_or(*required_tier, |current: RuntimeAssuranceTier| {
                                current.max(*required_tier)
                            }),
                    );
                }
                Constraint::MinimumAutonomyTier(required_tier) => {
                    minimum_autonomy_tier = Some(
                        minimum_autonomy_tier
                            .map_or(*required_tier, |current: GovernedAutonomyTier| {
                                current.max(*required_tier)
                            }),
                    );
                }
                _ => {}
            }
        }

        (
            intent_required,
            approval_threshold_units,
            seller,
            minimum_runtime_assurance,
            minimum_autonomy_tier,
        )
    }

    fn verify_governed_approval_signature(
        &self,
        approval_token: &GovernedApprovalToken,
    ) -> Result<(), String> {
        let kernel_pk = self.config.keypair.public_key();
        let mut trusted = self.config.ca_public_keys.clone();
        for authority_pk in self.capability_authority.trusted_public_keys() {
            if !trusted.contains(&authority_pk) {
                trusted.push(authority_pk);
            }
        }
        if !trusted.contains(&kernel_pk) {
            trusted.push(kernel_pk);
        }

        for pk in &trusted {
            if *pk == approval_token.approver {
                return match approval_token.verify_signature() {
                    Ok(true) => Ok(()),
                    Ok(false) => Err("signature did not verify".to_string()),
                    Err(error) => Err(error.to_string()),
                };
            }
        }

        Err("approval signer public key not found among trusted authorities".to_string())
    }

    fn resolve_runtime_assurance(
        &self,
        attestation: &arc_core::capability::RuntimeAttestationEvidence,
        now: u64,
    ) -> Result<arc_core::capability::ResolvedRuntimeAssurance, KernelError> {
        attestation
            .resolve_effective_runtime_assurance(self.attestation_trust_policy.as_ref(), now)
            .map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "runtime attestation evidence rejected by trust policy: {error}"
                ))
            })
    }

    fn validate_runtime_assurance(
        &self,
        request: &ToolCallRequest,
        required_tier: RuntimeAssuranceTier,
        now: u64,
    ) -> Result<(), KernelError> {
        let attestation = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.runtime_attestation.as_ref())
            .ok_or_else(|| {
                KernelError::GovernedTransactionDenied(format!(
                    "runtime attestation tier '{required_tier:?}' required by grant"
                ))
            })?;
        let resolved = self.resolve_runtime_assurance(attestation, now)?;

        if resolved.effective_tier < required_tier {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "runtime attestation tier '{:?}' is below required '{required_tier:?}'",
                resolved.effective_tier
            )));
        }

        Ok(())
    }

    fn validate_governed_approval_token(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        intent_hash: &str,
        approval_token: &GovernedApprovalToken,
        now: u64,
    ) -> Result<(), KernelError> {
        approval_token
            .validate_time(now)
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;

        if approval_token.request_id != request.request_id {
            return Err(KernelError::GovernedTransactionDenied(
                "approval token request binding does not match the tool call".to_string(),
            ));
        }

        if approval_token.governed_intent_hash != intent_hash {
            return Err(KernelError::GovernedTransactionDenied(
                "approval token intent binding does not match the governed intent".to_string(),
            ));
        }

        if approval_token.subject != cap.subject {
            return Err(KernelError::GovernedTransactionDenied(
                "approval token subject does not match the capability subject".to_string(),
            ));
        }

        if approval_token.decision != GovernedApprovalDecision::Approved {
            return Err(KernelError::GovernedTransactionDenied(
                "approval token does not approve the governed transaction".to_string(),
            ));
        }

        self.verify_governed_approval_signature(approval_token)
            .map_err(|reason| {
                KernelError::GovernedTransactionDenied(format!(
                    "approval token verification failed: {reason}"
                ))
            })
    }

    fn validate_metered_billing_context(
        intent: &arc_core::capability::GovernedTransactionIntent,
        charge_result: Option<&BudgetChargeResult>,
        now: u64,
    ) -> Result<(), KernelError> {
        let Some(metered) = intent.metered_billing.as_ref() else {
            return Ok(());
        };

        let quote = &metered.quote;
        if quote.quote_id.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing quote_id must not be empty".to_string(),
            ));
        }
        if quote.provider.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing provider must not be empty".to_string(),
            ));
        }
        if quote.billing_unit.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing unit must not be empty".to_string(),
            ));
        }
        if quote.quoted_units == 0 {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing quoted_units must be greater than zero".to_string(),
            ));
        }
        if quote
            .expires_at
            .is_some_and(|expires_at| expires_at <= quote.issued_at)
        {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing quote expires_at must be after issued_at".to_string(),
            ));
        }
        if quote.expires_at.is_some() && !quote.is_valid_at(now) {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing quote is missing or expired".to_string(),
            ));
        }
        if metered.max_billed_units == Some(0) {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing max_billed_units must be greater than zero when present"
                    .to_string(),
            ));
        }
        if metered
            .max_billed_units
            .is_some_and(|max_billed_units| max_billed_units < quote.quoted_units)
        {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing max_billed_units cannot be lower than quote.quoted_units"
                    .to_string(),
            ));
        }
        if let Some(intent_amount) = intent.max_amount.as_ref() {
            if intent_amount.currency != quote.quoted_cost.currency {
                return Err(KernelError::GovernedTransactionDenied(
                    "metered billing quote currency does not match governed intent currency"
                        .to_string(),
                ));
            }
        }
        if let Some(charge) = charge_result {
            if charge.currency != quote.quoted_cost.currency {
                return Err(KernelError::GovernedTransactionDenied(
                    "metered billing quote currency does not match the grant currency".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn validate_governed_call_chain_context(
        request: &ToolCallRequest,
        intent: &arc_core::capability::GovernedTransactionIntent,
    ) -> Result<(), KernelError> {
        let Some(call_chain) = intent.call_chain.as_ref() else {
            return Ok(());
        };

        if call_chain.chain_id.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.chain_id must not be empty".to_string(),
            ));
        }
        if call_chain.parent_request_id.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.parent_request_id must not be empty".to_string(),
            ));
        }
        if call_chain.parent_request_id == request.request_id {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.parent_request_id must not equal the current request_id"
                    .to_string(),
            ));
        }
        if call_chain.origin_subject.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.origin_subject must not be empty".to_string(),
            ));
        }
        if call_chain.delegator_subject.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.delegator_subject must not be empty".to_string(),
            ));
        }
        if call_chain
            .parent_receipt_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.parent_receipt_id must not be empty when present".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_governed_autonomy_bond(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        bond_id: &str,
        now: u64,
    ) -> Result<(), KernelError> {
        let store = self.receipt_store.as_deref().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "delegation bond lookup unavailable because no receipt store is configured"
                    .to_string(),
            )
        })?;
        let bond_row = store
            .resolve_credit_bond(bond_id)
            .map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "failed to resolve delegation bond `{bond_id}`: {error}"
                ))
            })?
            .ok_or_else(|| {
                KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` was not found"
                ))
            })?;

        let signed_bond = &bond_row.bond;
        let signature_valid = signed_bond.verify_signature().map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` failed signature verification: {error}"
            ))
        })?;
        if !signature_valid {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` failed signature verification"
            )));
        }
        if bond_row.lifecycle_state != CreditBondLifecycleState::Active {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` is not active"
            )));
        }
        if signed_bond.body.expires_at <= now {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` is expired"
            )));
        }

        let report = &signed_bond.body.report;
        if !report.support_boundary.autonomy_gating_supported {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` does not advertise runtime autonomy gating support"
            )));
        }
        if !report.prerequisites.active_facility_met {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` is missing an active granted facility"
            )));
        }
        if !report.prerequisites.runtime_assurance_met {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` was issued without satisfied runtime assurance prerequisites"
            )));
        }
        if report.prerequisites.certification_required && !report.prerequisites.certification_met {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` requires an active certification record"
            )));
        }
        match report.disposition {
            CreditBondDisposition::Lock | CreditBondDisposition::Hold => {}
            CreditBondDisposition::Release => {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` is released and does not back autonomous execution"
                )));
            }
            CreditBondDisposition::Impair => {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` is impaired and does not back autonomous execution"
                )));
            }
        }

        let subject_key = cap.subject.to_hex();
        let mut bound_to_subject_or_capability = false;
        if let Some(bound_subject) = report.filters.agent_subject.as_deref() {
            if bound_subject != subject_key {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` subject binding does not match the capability subject"
                )));
            }
            bound_to_subject_or_capability = true;
        }
        if let Some(bound_capability_id) = report.filters.capability_id.as_deref() {
            if bound_capability_id != cap.id {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` capability binding does not match the executing capability"
                )));
            }
            bound_to_subject_or_capability = true;
        }
        if !bound_to_subject_or_capability {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` must be bound to the current capability or subject"
            )));
        }

        let Some(bound_server) = report.filters.tool_server.as_deref() else {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` must be scoped to the current tool server"
            )));
        };
        if bound_server != request.server_id {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` tool server scope does not match the governed request"
            )));
        }
        if let Some(bound_tool) = report.filters.tool_name.as_deref() {
            if bound_tool != request.tool_name {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` tool scope does not match the governed request"
                )));
            }
        }

        Ok(())
    }

    fn validate_governed_autonomy(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        intent: &arc_core::capability::GovernedTransactionIntent,
        minimum_autonomy_tier: Option<GovernedAutonomyTier>,
        now: u64,
    ) -> Result<(), KernelError> {
        let autonomy = match (intent.autonomy.as_ref(), minimum_autonomy_tier) {
            (None, None) => return Ok(()),
            (Some(autonomy), _) => autonomy,
            (None, Some(required_tier)) => {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "governed autonomy tier '{required_tier:?}' required by grant"
                )));
            }
        };

        if let Some(required_tier) = minimum_autonomy_tier {
            if autonomy.tier < required_tier {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "governed autonomy tier '{:?}' is below required '{required_tier:?}'",
                    autonomy.tier
                )));
            }
        }

        let bond_id = autonomy
            .delegation_bond_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());

        if !autonomy.tier.requires_delegation_bond() {
            if bond_id.is_some() {
                return Err(KernelError::GovernedTransactionDenied(
                    "direct governed autonomy tier must not attach a delegation bond".to_string(),
                ));
            }
            return Ok(());
        }

        if autonomy.tier.requires_call_chain() && intent.call_chain.is_none() {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "governed autonomy tier '{:?}' requires delegated call-chain context",
                autonomy.tier
            )));
        }

        let required_runtime_assurance = autonomy.tier.minimum_runtime_assurance();
        self.validate_runtime_assurance(request, required_runtime_assurance, now)?;

        let bond_id = bond_id.ok_or_else(|| {
            KernelError::GovernedTransactionDenied(format!(
                "governed autonomy tier '{:?}' requires a delegation bond attachment",
                autonomy.tier
            ))
        })?;
        self.validate_governed_autonomy_bond(request, cap, bond_id, now)
    }

    fn validate_governed_transaction(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        grant: &ToolGrant,
        charge_result: Option<&BudgetChargeResult>,
        now: u64,
    ) -> Result<(), KernelError> {
        let (
            intent_required,
            approval_threshold_units,
            required_seller,
            minimum_runtime_assurance,
            minimum_autonomy_tier,
        ) = Self::governed_requirements(grant);
        let governed_request_present =
            request.governed_intent.is_some() || request.approval_token.is_some();

        if !intent_required
            && approval_threshold_units.is_none()
            && required_seller.is_none()
            && minimum_runtime_assurance.is_none()
            && minimum_autonomy_tier.is_none()
            && !governed_request_present
        {
            return Ok(());
        }

        let intent = request.governed_intent.as_ref().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "governed transaction intent required by grant or request".to_string(),
            )
        })?;

        if intent.server_id != request.server_id || intent.tool_name != request.tool_name {
            return Err(KernelError::GovernedTransactionDenied(
                "governed transaction intent target does not match the tool call".to_string(),
            ));
        }

        if let Some(attestation) = intent.runtime_attestation.as_ref() {
            self.resolve_runtime_assurance(attestation, now)?;
        }

        Self::validate_governed_call_chain_context(request, intent)?;

        let intent_hash = intent.binding_hash().map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "failed to hash governed transaction intent: {error}"
            ))
        })?;
        let commerce = intent.commerce.as_ref();

        if let Some(commerce) = commerce {
            if commerce.seller.trim().is_empty() {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed commerce seller scope must not be empty".to_string(),
                ));
            }
            if commerce.shared_payment_token_id.trim().is_empty() {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed commerce approval requires a shared payment token reference"
                        .to_string(),
                ));
            }
            if intent.max_amount.is_none() {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed commerce approval requires an explicit max_amount bound".to_string(),
                ));
            }
        }

        if let Some(required_seller) = required_seller.as_deref() {
            let commerce = commerce.ok_or_else(|| {
                KernelError::GovernedTransactionDenied(
                    "seller-scoped governed request requires commerce approval context".to_string(),
                )
            })?;
            if commerce.seller != required_seller {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed commerce seller does not match the grant seller scope".to_string(),
                ));
            }
        }

        if let Some(required_tier) = minimum_runtime_assurance {
            self.validate_runtime_assurance(request, required_tier, now)?;
        }
        self.validate_governed_autonomy(request, cap, intent, minimum_autonomy_tier, now)?;

        Self::validate_metered_billing_context(intent, charge_result, now)?;

        if let (Some(intent_amount), Some(charge)) = (intent.max_amount.as_ref(), charge_result) {
            if intent_amount.currency != charge.currency {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed intent currency does not match the grant currency".to_string(),
                ));
            }
            if intent_amount.units < charge.cost_charged {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed intent amount is lower than the provisional invocation charge"
                        .to_string(),
                ));
            }
        }

        let requested_units = charge_result
            .map(|charge| charge.cost_charged)
            .or_else(|| intent.max_amount.as_ref().map(|amount| amount.units))
            .unwrap_or(0);
        let approval_required = approval_threshold_units
            .map(|threshold_units| requested_units >= threshold_units)
            .unwrap_or(false);

        if let Some(approval_token) = request.approval_token.as_ref() {
            self.validate_governed_approval_token(request, cap, &intent_hash, approval_token, now)?;
        } else if approval_required {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "approval token required for governed transaction intent {}",
                intent.id
            )));
        }

        Ok(())
    }

    fn unwind_aborted_monetary_invocation(
        &mut self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        charge_result: Option<&BudgetChargeResult>,
        payment_authorization: Option<&PaymentAuthorization>,
    ) -> Result<(), KernelError> {
        let Some(charge) = charge_result else {
            return Ok(());
        };

        if let Some(authorization) = payment_authorization {
            let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "payment authorization present without configured adapter".to_string(),
                )
            })?;
            let unwind_result = if authorization.settled {
                adapter.refund(
                    &authorization.authorization_id,
                    charge.cost_charged,
                    &charge.currency,
                    &request.request_id,
                )
            } else {
                adapter.release(&authorization.authorization_id, &request.request_id)
            };
            if let Err(error) = unwind_result {
                return Err(KernelError::Internal(format!(
                    "failed to unwind payment after aborted tool invocation: {error}"
                )));
            }
        }

        self.reverse_budget_charge(&cap.id, charge)?;
        Ok(())
    }

    fn record_observed_capability_snapshot(
        &mut self,
        capability: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let parent_capability_id = capability
            .delegation_chain
            .last()
            .map(|link| link.capability_id.as_str());
        if let Some(store) = self.receipt_store.as_deref_mut() {
            store.record_capability_snapshot(capability, parent_capability_id)?;
        }
        Ok(())
    }

    /// Verify a DPoP proof carried on the request against the capability.
    ///
    /// Fails closed: if no proof is present, or if the nonce store / config is
    /// absent (misconfigured kernel), or if verification fails, the call is denied.
    fn verify_dpop_for_request(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let proof = request.dpop_proof.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed(
                "grant requires DPoP proof but none was provided".to_string(),
            )
        })?;

        let nonce_store = self.dpop_nonce_store.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed(
                "kernel DPoP nonce store not configured".to_string(),
            )
        })?;

        let config = self.dpop_config.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed("kernel DPoP config not configured".to_string())
        })?;

        // Compute action hash from the serialized arguments.
        let args_bytes = canonical_json_bytes(&request.arguments).map_err(|e| {
            KernelError::DpopVerificationFailed(format!(
                "failed to serialize arguments for action hash: {e}"
            ))
        })?;
        let action_hash = sha256_hex(&args_bytes);

        dpop::verify_dpop_proof(
            proof,
            cap,
            &request.server_id,
            &request.tool_name,
            &action_hash,
            nonce_store,
            config,
        )
    }

    /// Run all registered guards. Fail-closed: any error from a guard is
    /// treated as a deny.
    fn run_guards(
        &self,
        request: &ToolCallRequest,
        scope: &ArcScope,
        session_filesystem_roots: Option<&[String]>,
        matched_grant_index: Option<usize>,
    ) -> Result<(), KernelError> {
        let ctx = GuardContext {
            request,
            scope,
            agent_id: &request.agent_id,
            server_id: &request.server_id,
            session_filesystem_roots,
            matched_grant_index,
        };

        for guard in &self.guards {
            match guard.evaluate(&ctx) {
                Ok(Verdict::Allow) => {
                    debug!(guard = guard.name(), "guard passed");
                }
                Ok(Verdict::Deny) => {
                    return Err(KernelError::GuardDenied(format!(
                        "guard \"{}\" denied the request",
                        guard.name()
                    )));
                }
                Err(e) => {
                    // Fail closed: guard errors are treated as denials.
                    return Err(KernelError::GuardDenied(format!(
                        "guard \"{}\" error (fail-closed): {e}",
                        guard.name()
                    )));
                }
            }
        }

        Ok(())
    }

    /// Forward the validated request and optionally report actual invocation cost.
    ///
    /// When `has_monetary_grant` is true, calls `invoke_with_cost` so the server
    /// can report the actual cost incurred. For non-monetary grants the standard
    /// dispatch path is used and cost is always None.
    fn dispatch_tool_call_with_cost(
        &self,
        request: &ToolCallRequest,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        let server = self.tool_servers.get(&request.server_id).ok_or_else(|| {
            KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ))
        })?;

        // Try streaming first regardless of monetary mode.
        if let Some(stream) =
            server.invoke_stream(&request.tool_name, request.arguments.clone(), None)?
        {
            return Ok((ToolServerOutput::Stream(stream), None));
        }

        if has_monetary_grant {
            let (value, cost) =
                server.invoke_with_cost(&request.tool_name, request.arguments.clone(), None)?;
            Ok((ToolServerOutput::Value(value), cost))
        } else {
            let value = server.invoke(&request.tool_name, request.arguments.clone(), None)?;
            Ok((ToolServerOutput::Value(value), None))
        }
    }

    /// Build a denial response, including FinancialReceiptMetadata when the
    fn record_child_receipts(
        &mut self,
        receipts: Vec<ChildRequestReceipt>,
    ) -> Result<(), KernelError> {
        for receipt in receipts {
            if let Some(store) = self.receipt_store.as_deref_mut() {
                store.append_child_receipt(&receipt)?;
            }
            self.child_receipt_log.append(receipt);
        }
        Ok(())
    }
}

/// Parameters for building a receipt.
pub(crate) struct ReceiptParams<'a> {
    capability_id: &'a str,
    tool_name: &'a str,
    server_id: &'a str,
    decision: Decision,
    action: ToolCallAction,
    content_hash: String,
    metadata: Option<serde_json::Value>,
    timestamp: u64,
}

pub(crate) fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[path = "responses.rs"]
mod responses;
#[path = "session_ops.rs"]
mod session_ops;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
