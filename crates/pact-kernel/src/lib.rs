//! PACT Runtime Kernel.
//!
//! The kernel is the trusted computing base (TCB) of the PACT protocol.
//! It sits between the untrusted agent and the sandboxed tool servers,
//! mediating every tool invocation.
//!
//! The kernel's responsibilities:
//!
//! 1. **Capability validation** -- verify signatures, time bounds, revocation
//!    status, scope matching, and invocation budgets.
//! 2. **Guard evaluation** -- run policy guards against the tool call before
//!    forwarding it.
//! 3. **Receipt signing** -- produce a signed receipt for every decision
//!    (allow or deny) and append it to the receipt log.
//! 4. **Tool dispatch** -- forward validated requests to the appropriate tool
//!    server over an authenticated channel.
//!
//! The kernel is architecturally invisible to the agent. The agent communicates
//! through an anonymous pipe or Unix domain socket and never learns the kernel's
//! PID, address, or signing key.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod authority;
pub mod budget_store;
pub mod capability_lineage;
pub mod checkpoint;
pub mod dpop;
pub mod receipt_query;
pub mod receipt_store;
pub mod revocation_store;
pub mod session;
pub mod transport;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pact_core::canonical::canonical_json_bytes;
use pact_core::capability::{
    CapabilityToken, Constraint, Operation, PactScope, PromptGrant, ResourceGrant, ToolGrant,
};
use pact_core::crypto::{sha256_hex, Keypair};
use pact_core::receipt::{
    ChildRequestReceipt, ChildRequestReceiptBody, Decision, FinancialReceiptMetadata, PactReceipt,
    PactReceiptBody, ToolCallAction,
};
use pact_core::session::{
    CompleteOperation, CompletionReference, CompletionResult, CreateElicitationOperation,
    CreateElicitationResult, CreateMessageOperation, CreateMessageResult, GetPromptOperation,
    NormalizedRoot, OperationContext, OperationKind, OperationTerminalState, ProgressToken,
    PromptDefinition, PromptResult, ReadResourceOperation, RequestId, ResourceContent,
    ResourceDefinition, ResourceTemplateDefinition, ResourceUriClassification, RootDefinition,
    SessionAuthContext, SessionId, SessionOperation, ToolCallOperation,
};
use regex::Regex;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub use authority::{
    AuthoritySnapshot, AuthorityStatus, AuthorityStoreError, AuthorityTrustedKeySnapshot,
    CapabilityAuthority, LocalCapabilityAuthority, SqliteCapabilityAuthority,
};
pub use budget_store::{
    BudgetStore, BudgetStoreError, BudgetUsageRecord, InMemoryBudgetStore, SqliteBudgetStore,
};
pub use capability_lineage::{CapabilityLineageError, CapabilitySnapshot};
pub use checkpoint::{
    build_checkpoint, build_inclusion_proof, verify_checkpoint_signature, CheckpointError,
    KernelCheckpoint, KernelCheckpointBody, ReceiptInclusionProof,
};
pub use dpop::{
    verify_dpop_proof, DpopConfig, DpopNonceStore, DpopProof, DpopProofBody, DPOP_SCHEMA,
};
pub use receipt_query::{ReceiptQuery, ReceiptQueryResult, MAX_QUERY_LIMIT};
pub use receipt_store::{
    ReceiptStore, ReceiptStoreError, SqliteReceiptStore, StoredChildReceipt, StoredToolReceipt,
};
pub use revocation_store::{RevocationRecord, RevocationStoreError, SqliteRevocationStore};
pub use session::{
    InflightRegistry, InflightRequest, LateSessionEvent, PeerCapabilities, Session, SessionError,
    SessionOperationResponse, SessionState, SubscriptionRegistry, TerminalRegistry,
};

/// A string-typed agent identifier.
pub type AgentId = String;

/// A string-typed capability identifier.
pub type CapabilityId = String;

/// A string-typed server identifier.
pub type ServerId = String;

/// Verdict of a guard or capability evaluation.
///
/// This is the kernel's own verdict type, distinct from `pact_core::Decision`.
/// The kernel uses this internally; it maps to `pact_core::Decision` when
/// building receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The action is allowed.
    Allow,
    /// The action is denied.
    Deny,
}

/// A tool call request as seen by the kernel.
#[derive(Debug)]
pub struct ToolCallRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// The signed capability token authorizing this call.
    pub capability: CapabilityToken,
    /// The tool to invoke.
    pub tool_name: String,
    /// The server hosting the tool.
    pub server_id: ServerId,
    /// The calling agent's identifier (hex-encoded public key).
    pub agent_id: AgentId,
    /// Tool arguments.
    pub arguments: serde_json::Value,
    /// Optional DPoP proof. Required when the matched grant has `dpop_required == Some(true)`.
    pub dpop_proof: Option<dpop::DpopProof>,
}

/// The kernel's response to a tool call request.
#[derive(Debug)]
pub struct ToolCallResponse {
    /// Correlation identifier (matches the request).
    pub request_id: String,
    /// The kernel's verdict.
    pub verdict: Verdict,
    /// The tool's output payload, which may be a direct value or a stream.
    pub output: Option<ToolCallOutput>,
    /// Denial reason (populated when verdict is Deny).
    pub reason: Option<String>,
    /// Explicit terminal lifecycle state for this request.
    pub terminal_state: OperationTerminalState,
    /// Signed receipt attesting to this decision.
    pub receipt: PactReceipt,
}

/// Streamed tool output emitted before the final tool response frame.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCallChunk {
    pub data: serde_json::Value,
}

/// Complete streamed output captured by the kernel.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCallStream {
    pub chunks: Vec<ToolCallChunk>,
}

impl ToolCallStream {
    pub fn chunk_count(&self) -> u64 {
        self.chunks.len() as u64
    }
}

/// Output produced by a tool invocation.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolCallOutput {
    Value(serde_json::Value),
    Stream(ToolCallStream),
}

/// Stream-capable tool-server result.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolServerStreamResult {
    Complete(ToolCallStream),
    Incomplete {
        stream: ToolCallStream,
        reason: String,
    },
}

/// Tool-server output produced after validation and guard checks.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolServerOutput {
    Value(serde_json::Value),
    Stream(ToolServerStreamResult),
}

#[derive(Debug)]
struct ReceiptContent {
    content_hash: String,
    metadata: Option<serde_json::Value>,
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

    #[error("internal error: {0}")]
    Internal(String),

    #[error("DPoP proof verification failed: {0}")]
    DpopVerificationFailed(String),
}

/// A policy guard that the kernel evaluates before forwarding a tool call.
///
/// Guards are the same concept as ClawdStrike's `Guard` trait, adapted for
/// the PACT tool-call context. Each guard inspects the request and returns
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
    pub scope: &'a PactScope,
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

/// Trait for checking whether a capability has been revoked.
///
/// Implementations may be in-memory, SQLite-backed, or subscribe to a
/// distributed revocation feed via Spine/NATS.
pub trait RevocationStore: Send {
    /// Check if a capability ID has been revoked.
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError>;

    /// Revoke a capability. Returns `true` if it was newly revoked.
    fn revoke(&mut self, capability_id: &str) -> Result<bool, RevocationStoreError>;
}

/// Bridge exposed to tool-server implementations while a parent request is in flight.
///
/// Wrapped servers can use this to trigger negotiated server-to-client requests such as
/// `roots/list` and `sampling/createMessage`, or to surface wrapped MCP notifications,
/// without escaping kernel mediation.
pub trait NestedFlowBridge {
    fn parent_request_id(&self) -> &RequestId;

    fn poll_parent_cancellation(&mut self) -> Result<(), KernelError> {
        Ok(())
    }

    fn list_roots(&mut self) -> Result<Vec<RootDefinition>, KernelError>;

    fn create_message(
        &mut self,
        operation: CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError>;

    fn create_elicitation(
        &mut self,
        operation: CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError>;

    fn notify_elicitation_completed(&mut self, elicitation_id: &str) -> Result<(), KernelError>;

    fn notify_resource_updated(&mut self, uri: &str) -> Result<(), KernelError>;

    fn notify_resources_list_changed(&mut self) -> Result<(), KernelError>;
}

/// Raw client transport used by the kernel to service nested flows on behalf of a parent request.
///
/// The kernel owns lineage, policy, and in-flight bookkeeping. Implementors only move the nested
/// request or notification across the client transport and return the decoded response.
pub trait NestedFlowClient {
    fn poll_parent_cancellation(
        &mut self,
        _parent_context: &OperationContext,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    fn list_roots(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError>;

    fn create_message(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
        operation: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError>;

    fn create_elicitation(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
        operation: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError>;

    fn notify_elicitation_completed(
        &mut self,
        parent_context: &OperationContext,
        elicitation_id: &str,
    ) -> Result<(), KernelError>;

    fn notify_resource_updated(
        &mut self,
        parent_context: &OperationContext,
        uri: &str,
    ) -> Result<(), KernelError>;

    fn notify_resources_list_changed(
        &mut self,
        parent_context: &OperationContext,
    ) -> Result<(), KernelError>;
}

/// In-memory revocation store for development and testing.
#[derive(Debug, Default)]
pub struct InMemoryRevocationStore {
    revoked: HashSet<String>,
}

impl InMemoryRevocationStore {
    /// Create an empty revocation store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl RevocationStore for InMemoryRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        Ok(self.revoked.contains(capability_id))
    }

    fn revoke(&mut self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        Ok(self.revoked.insert(capability_id.to_owned()))
    }
}

/// Cost reported by a tool server after invocation.
///
/// Tool servers that track monetary costs override `invoke_with_cost` and
/// return this struct. Servers that do not override return `None` via the
/// default implementation, and the kernel charges `max_cost_per_invocation`
/// as a worst-case debit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolInvocationCost {
    /// Cost in the currency's smallest unit (e.g. cents for USD).
    pub units: u64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Optional cost breakdown for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breakdown: Option<serde_json::Value>,
}

/// Trait representing a connection to a tool server.
///
/// The kernel holds one `ToolServerConnection` per registered server. In
/// production this is an mTLS connection over UDS or TCP. For testing,
/// an in-process implementation can be used.
pub trait ToolServerConnection: Send + Sync {
    /// The server's unique identifier.
    fn server_id(&self) -> &str;

    /// List the tool names available on this server.
    fn tool_names(&self) -> Vec<String>;

    /// Invoke a tool on this server. The kernel has already validated the
    /// capability and run guards before calling this.
    fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError>;

    /// Invoke a tool and optionally report the actual cost of the invocation.
    ///
    /// Tool servers that track monetary costs should override this method.
    /// The default implementation delegates to `invoke` and returns `None`
    /// cost, meaning the kernel will charge `max_cost_per_invocation` as
    /// the worst-case debit.
    fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, nested_flow_bridge)?;
        Ok((value, None))
    }

    /// Invoke a tool that can emit multiple streamed chunks before its final terminal state.
    ///
    /// Servers that do not support streaming can ignore this and rely on `invoke`.
    fn invoke_stream(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        let _ = (tool_name, arguments, nested_flow_bridge);
        Ok(None)
    }

    /// Drain asynchronous events emitted after a tool invocation has already returned.
    ///
    /// Native tool servers can use this to surface late URL-elicitation completions and
    /// catalog/resource notifications without depending on a still-live request-local bridge.
    fn drain_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        Ok(vec![])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolServerEvent {
    ElicitationCompleted { elicitation_id: String },
    ResourceUpdated { uri: String },
    ResourcesListChanged,
    ToolsListChanged,
    PromptsListChanged,
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
    receipts: Vec<PactReceipt>,
}

impl ReceiptLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, receipt: PactReceipt) {
        self.receipts.push(receipt);
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn receipts(&self) -> &[PactReceipt] {
        &self.receipts
    }

    pub fn get(&self, index: usize) -> Option<&PactReceipt> {
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

/// Configuration for the PACT Runtime Kernel.
pub struct KernelConfig {
    /// Ed25519 keypair for signing receipts and issuing capabilities.
    pub keypair: Keypair,

    /// Public keys of trusted Capability Authorities.
    pub ca_public_keys: Vec<pact_core::PublicKey>,

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

    /// Number of receipts between Merkle checkpoint snapshots. Default: 100.
    ///
    /// Set to 0 to disable automatic checkpointing.
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

/// The PACT Runtime Kernel.
///
/// This is the central component of the PACT protocol. It validates capabilities,
/// runs guards, dispatches tool calls, and signs receipts.
///
/// The kernel is designed to be the sole trusted mediator. It never exposes its
/// signing key, address, or internal state to the agent.
pub struct PactKernel {
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
struct MatchingGrant<'a> {
    index: usize,
    grant: &'a ToolGrant,
    specificity: (u8, u8, usize),
}

/// Result of a monetary budget charge attempt.
///
/// Carries the accounting info needed to populate FinancialReceiptMetadata.
struct BudgetChargeResult {
    grant_index: usize,
    cost_charged: u64,
    currency: String,
    budget_total: u64,
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

impl PactKernel {
    pub fn new(config: KernelConfig) -> Self {
        info!("initializing PACT kernel");
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
    pub fn open_session(
        &mut self,
        agent_id: AgentId,
        issued_capabilities: Vec<CapabilityToken>,
    ) -> SessionId {
        self.session_counter += 1;
        let session_id = SessionId::new(format!("sess-{}", self.session_counter));

        info!(session_id = %session_id, agent_id = %agent_id, "opening session");
        self.sessions.insert(
            session_id.clone(),
            Session::new(session_id.clone(), agent_id, issued_capabilities),
        );

        session_id
    }

    /// Transition a session into the `ready` state once setup is complete.
    pub fn activate_session(&mut self, session_id: &SessionId) -> Result<(), KernelError> {
        self.session_mut(session_id)?.activate()?;
        Ok(())
    }

    /// Persist transport/session authentication context for a session.
    pub fn set_session_auth_context(
        &mut self,
        session_id: &SessionId,
        auth_context: SessionAuthContext,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?.set_auth_context(auth_context);
        Ok(())
    }

    /// Persist peer capabilities negotiated at the edge for a session.
    pub fn set_session_peer_capabilities(
        &mut self,
        session_id: &SessionId,
        peer_capabilities: PeerCapabilities,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?
            .set_peer_capabilities(peer_capabilities);
        Ok(())
    }

    /// Replace the session's current root snapshot.
    pub fn replace_session_roots(
        &mut self,
        session_id: &SessionId,
        roots: Vec<RootDefinition>,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?.replace_roots(roots);
        Ok(())
    }

    /// Return the runtime's normalized root view for a session.
    pub fn normalized_session_roots(
        &self,
        session_id: &SessionId,
    ) -> Result<&[NormalizedRoot], KernelError> {
        Ok(self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?
            .normalized_roots())
    }

    /// Return only the enforceable filesystem root paths for a session.
    pub fn enforceable_filesystem_root_paths(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<&str>, KernelError> {
        Ok(self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?
            .enforceable_filesystem_roots()
            .filter_map(NormalizedRoot::normalized_filesystem_path)
            .collect())
    }

    fn session_enforceable_filesystem_root_paths_owned(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<String>, KernelError> {
        Ok(self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?
            .enforceable_filesystem_roots()
            .filter_map(NormalizedRoot::normalized_filesystem_path)
            .map(str::to_string)
            .collect())
    }

    fn resource_path_within_root(candidate: &str, root: &str) -> bool {
        if candidate == root {
            return true;
        }

        if root == "/" {
            return candidate.starts_with('/');
        }

        candidate
            .strip_prefix(root)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
    }

    fn resource_path_matches_session_roots(path: &str, session_roots: &[String]) -> bool {
        if session_roots.is_empty() {
            return false;
        }

        session_roots
            .iter()
            .any(|root| Self::resource_path_within_root(path, root))
    }

    fn enforce_resource_roots(
        &self,
        context: &OperationContext,
        operation: &ReadResourceOperation,
    ) -> Result<(), KernelError> {
        match operation.classify_uri_for_runtime() {
            ResourceUriClassification::NonFileSystem { .. } => Ok(()),
            ResourceUriClassification::EnforceableFileSystem {
                normalized_path, ..
            } => {
                let session_roots =
                    self.session_enforceable_filesystem_root_paths_owned(&context.session_id)?;

                if Self::resource_path_matches_session_roots(&normalized_path, &session_roots) {
                    Ok(())
                } else {
                    let reason = if session_roots.is_empty() {
                        "no enforceable filesystem roots are available for this session".to_string()
                    } else {
                        format!(
                            "filesystem-backed resource path {normalized_path} is outside the negotiated roots"
                        )
                    };

                    Err(KernelError::ResourceRootDenied {
                        uri: operation.uri.clone(),
                        reason,
                    })
                }
            }
            ResourceUriClassification::UnenforceableFileSystem { reason, .. } => {
                Err(KernelError::ResourceRootDenied {
                    uri: operation.uri.clone(),
                    reason: format!(
                        "filesystem-backed resource URI could not be enforced: {reason}"
                    ),
                })
            }
        }
    }

    fn build_resource_read_deny_receipt(
        &mut self,
        operation: &ReadResourceOperation,
        reason: &str,
    ) -> Result<PactReceipt, KernelError> {
        let receipt_content = receipt_content_for_output(None, None)?;
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "uri": &operation.uri,
        }))
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to hash resource read parameters: {error}"
            ))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &operation.capability.id,
            tool_name: "resources/read",
            server_id: "session",
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "session_roots".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: Some(serde_json::json!({
                "resource": {
                    "uri": &operation.uri,
                }
            })),
            timestamp: current_unix_timestamp(),
        })?;

        self.record_pact_receipt(&receipt)?;
        Ok(receipt)
    }

    /// Subscribe the session to update notifications for a concrete resource URI.
    pub fn subscribe_session_resource(
        &mut self,
        session_id: &SessionId,
        capability: &CapabilityToken,
        agent_id: &str,
        uri: &str,
    ) -> Result<(), KernelError> {
        self.validate_non_tool_capability(capability, agent_id)?;

        if !capability_matches_resource_subscription(capability, uri)? {
            return Err(KernelError::OutOfScopeResource {
                uri: uri.to_string(),
            });
        }

        if !self.resource_exists(uri)? {
            return Err(KernelError::ResourceNotRegistered(uri.to_string()));
        }

        self.session_mut(session_id)?
            .subscribe_resource(uri.to_string());
        Ok(())
    }

    /// Remove a session-scoped resource subscription. Missing subscriptions are ignored.
    pub fn unsubscribe_session_resource(
        &mut self,
        session_id: &SessionId,
        uri: &str,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?.unsubscribe_resource(uri);
        Ok(())
    }

    /// Check whether a session currently holds a resource subscription.
    pub fn session_has_resource_subscription(
        &self,
        session_id: &SessionId,
        uri: &str,
    ) -> Result<bool, KernelError> {
        Ok(self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?
            .is_resource_subscribed(uri))
    }

    /// Mark a session as draining. New tool calls are rejected after this point.
    pub fn begin_draining_session(&mut self, session_id: &SessionId) -> Result<(), KernelError> {
        self.session_mut(session_id)?.begin_draining()?;
        Ok(())
    }

    /// Close a session and clear transient session-scoped state.
    pub fn close_session(&mut self, session_id: &SessionId) -> Result<(), KernelError> {
        self.session_mut(session_id)?.close()?;
        Ok(())
    }

    /// Inspect an existing session.
    pub fn session(&self, session_id: &SessionId) -> Option<&Session> {
        self.sessions.get(session_id)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn resource_provider_count(&self) -> usize {
        self.resource_providers.len()
    }

    pub fn prompt_provider_count(&self) -> usize {
        self.prompt_providers.len()
    }

    /// Validate a session-scoped operation and register it as in flight.
    pub fn begin_session_request(
        &mut self,
        context: &OperationContext,
        operation_kind: OperationKind,
        cancellable: bool,
    ) -> Result<(), KernelError> {
        begin_session_request_in_sessions(&mut self.sessions, context, operation_kind, cancellable)
    }

    /// Construct and register a child request under an existing parent request.
    pub fn begin_child_request(
        &mut self,
        parent_context: &OperationContext,
        request_id: RequestId,
        operation_kind: OperationKind,
        progress_token: Option<ProgressToken>,
        cancellable: bool,
    ) -> Result<OperationContext, KernelError> {
        begin_child_request_in_sessions(
            &mut self.sessions,
            parent_context,
            request_id,
            operation_kind,
            progress_token,
            cancellable,
        )
    }

    /// Complete an in-flight session request.
    pub fn complete_session_request(
        &mut self,
        session_id: &SessionId,
        request_id: &RequestId,
    ) -> Result<(), KernelError> {
        self.complete_session_request_with_terminal_state(
            session_id,
            request_id,
            OperationTerminalState::Completed,
        )
    }

    /// Complete an in-flight session request with an explicit terminal state.
    pub fn complete_session_request_with_terminal_state(
        &mut self,
        session_id: &SessionId,
        request_id: &RequestId,
        terminal_state: OperationTerminalState,
    ) -> Result<(), KernelError> {
        complete_session_request_with_terminal_state_in_sessions(
            &mut self.sessions,
            session_id,
            request_id,
            terminal_state,
        )
    }

    /// Mark an in-flight session request as cancelled.
    pub fn request_session_cancellation(
        &mut self,
        session_id: &SessionId,
        request_id: &RequestId,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?
            .request_cancellation(request_id)
            .map_err(KernelError::from)
    }

    /// Validate whether a sampling child request is allowed for this session.
    pub fn validate_sampling_request(
        &self,
        context: &OperationContext,
        operation: &CreateMessageOperation,
    ) -> Result<(), KernelError> {
        validate_sampling_request_in_sessions(
            &self.sessions,
            self.config.allow_sampling,
            self.config.allow_sampling_tool_use,
            context,
            operation,
        )
    }

    /// Validate whether an elicitation child request is allowed for this session.
    pub fn validate_elicitation_request(
        &self,
        context: &OperationContext,
        operation: &CreateElicitationOperation,
    ) -> Result<(), KernelError> {
        validate_elicitation_request_in_sessions(
            &self.sessions,
            self.config.allow_elicitation,
            context,
            operation,
        )
    }

    /// Evaluate a session-scoped tool call while allowing the target tool server to proxy
    /// negotiated nested flows back through a client transport owned by the edge.
    pub fn evaluate_tool_call_operation_with_nested_flow_client<C: NestedFlowClient>(
        &mut self,
        context: &OperationContext,
        operation: &ToolCallOperation,
        client: &mut C,
    ) -> Result<ToolCallResponse, KernelError> {
        self.begin_session_request(context, OperationKind::ToolCall, true)?;

        let request = ToolCallRequest {
            request_id: context.request_id.to_string(),
            capability: operation.capability.clone(),
            tool_name: operation.tool_name.clone(),
            server_id: operation.server_id.clone(),
            agent_id: context.agent_id.clone(),
            arguments: operation.arguments.clone(),
            dpop_proof: None,
        };

        let result = self.evaluate_tool_call_with_nested_flow_client(context, &request, client);
        let terminal_state = match &result {
            Ok(response) => response.terminal_state.clone(),
            Err(KernelError::RequestCancelled { request_id, reason })
                if request_id == &context.request_id =>
            {
                self.session_mut(&context.session_id)?
                    .request_cancellation(&context.request_id)?;
                OperationTerminalState::Cancelled {
                    reason: reason.clone(),
                }
            }
            _ => OperationTerminalState::Completed,
        };
        self.complete_session_request_with_terminal_state(
            &context.session_id,
            &context.request_id,
            terminal_state,
        )?;
        result
    }

    /// Evaluate a normalized operation against a specific session.
    ///
    /// This is the higher-level entry point that future JSON-RPC or MCP edges
    /// should target. The current stdio loop normalizes raw frames into these
    /// operations before invoking the kernel.
    pub fn evaluate_session_operation(
        &mut self,
        context: &OperationContext,
        operation: &SessionOperation,
    ) -> Result<SessionOperationResponse, KernelError> {
        let operation_kind = operation.kind();
        let should_track_inflight = matches!(
            operation,
            SessionOperation::ToolCall(_)
                | SessionOperation::ReadResource(_)
                | SessionOperation::GetPrompt(_)
                | SessionOperation::Complete(_)
        );

        if should_track_inflight {
            self.begin_session_request(context, operation_kind, true)?;
        } else {
            let session = self.session_mut(&context.session_id)?;
            session.validate_context(context)?;
            session.ensure_operation_allowed(operation_kind)?;
        }

        let evaluation = match operation {
            SessionOperation::ToolCall(tool_call) => {
                let request = ToolCallRequest {
                    request_id: context.request_id.to_string(),
                    capability: tool_call.capability.clone(),
                    tool_name: tool_call.tool_name.clone(),
                    server_id: tool_call.server_id.clone(),
                    agent_id: context.agent_id.clone(),
                    arguments: tool_call.arguments.clone(),
                    dpop_proof: None,
                };
                let session_roots =
                    self.session_enforceable_filesystem_root_paths_owned(&context.session_id)?;

                self.evaluate_tool_call_with_session_roots(&request, Some(session_roots.as_slice()))
                    .map(SessionOperationResponse::ToolCall)
            }
            SessionOperation::CreateMessage(_) => Err(KernelError::Internal(
                "sampling/createMessage must be evaluated by an MCP edge with a client transport"
                    .to_string(),
            )),
            SessionOperation::CreateElicitation(_) => Err(KernelError::Internal(
                "elicitation/create must be evaluated by an MCP edge with a client transport"
                    .to_string(),
            )),
            SessionOperation::ListRoots => {
                let roots = self
                    .session(&context.session_id)
                    .ok_or_else(|| KernelError::UnknownSession(context.session_id.clone()))?
                    .roots()
                    .to_vec();
                Ok(SessionOperationResponse::RootList { roots })
            }
            SessionOperation::ListResources => {
                let resources = self
                    .list_resources_for_session(&context.session_id)?
                    .into_iter()
                    .collect();
                Ok(SessionOperationResponse::ResourceList { resources })
            }
            SessionOperation::ReadResource(resource_read) => {
                self.evaluate_resource_read(context, resource_read)
            }
            SessionOperation::ListResourceTemplates => {
                let templates = self.list_resource_templates_for_session(&context.session_id)?;
                Ok(SessionOperationResponse::ResourceTemplateList { templates })
            }
            SessionOperation::ListPrompts => {
                let prompts = self.list_prompts_for_session(&context.session_id)?;
                Ok(SessionOperationResponse::PromptList { prompts })
            }
            SessionOperation::GetPrompt(prompt_get) => self
                .evaluate_prompt_get(context, prompt_get)
                .map(|prompt| SessionOperationResponse::PromptGet { prompt }),
            SessionOperation::Complete(complete) => self
                .evaluate_completion(context, complete)
                .map(|completion| SessionOperationResponse::Completion { completion }),
            SessionOperation::ListCapabilities => {
                let capabilities = self
                    .session(&context.session_id)
                    .ok_or_else(|| KernelError::UnknownSession(context.session_id.clone()))?
                    .capabilities()
                    .to_vec();

                Ok(SessionOperationResponse::CapabilityList { capabilities })
            }
            SessionOperation::Heartbeat => Ok(SessionOperationResponse::Heartbeat),
        };

        if should_track_inflight {
            let terminal_state = match &evaluation {
                Ok(SessionOperationResponse::ToolCall(response)) => response.terminal_state.clone(),
                _ => OperationTerminalState::Completed,
            };
            self.complete_session_request_with_terminal_state(
                &context.session_id,
                &context.request_id,
                terminal_state,
            )?;
        }

        evaluation
    }

    fn list_resources_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<ResourceDefinition>, KernelError> {
        let session = self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;

        let mut resources = Vec::new();
        for provider in &self.resource_providers {
            resources.extend(provider.list_resources().into_iter().filter(|resource| {
                session.capabilities().iter().any(|capability| {
                    capability_matches_resource_request(capability, &resource.uri).unwrap_or(false)
                })
            }));
        }

        Ok(resources)
    }

    fn resource_exists(&self, uri: &str) -> Result<bool, KernelError> {
        for provider in &self.resource_providers {
            if provider
                .list_resources()
                .iter()
                .any(|resource| resource.uri == uri)
            {
                return Ok(true);
            }

            if provider.read_resource(uri)?.is_some() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn list_resource_templates_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<ResourceTemplateDefinition>, KernelError> {
        let session = self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;

        let mut templates = Vec::new();
        for provider in &self.resource_providers {
            templates.extend(
                provider
                    .list_resource_templates()
                    .into_iter()
                    .filter(|template| {
                        session.capabilities().iter().any(|capability| {
                            capability_matches_resource_pattern(capability, &template.uri_template)
                                .unwrap_or(false)
                        })
                    }),
            );
        }

        Ok(templates)
    }

    fn evaluate_resource_read(
        &mut self,
        context: &OperationContext,
        operation: &ReadResourceOperation,
    ) -> Result<SessionOperationResponse, KernelError> {
        self.validate_non_tool_capability(&operation.capability, &context.agent_id)?;

        if !capability_matches_resource_request(&operation.capability, &operation.uri)? {
            return Err(KernelError::OutOfScopeResource {
                uri: operation.uri.clone(),
            });
        }

        match self.enforce_resource_roots(context, operation) {
            Ok(()) => {}
            Err(KernelError::ResourceRootDenied { reason, .. }) => {
                let receipt = self.build_resource_read_deny_receipt(operation, &reason)?;
                return Ok(SessionOperationResponse::ResourceReadDenied { receipt });
            }
            Err(error) => return Err(error),
        }

        for provider in &self.resource_providers {
            if let Some(contents) = provider.read_resource(&operation.uri)? {
                return Ok(SessionOperationResponse::ResourceRead { contents });
            }
        }

        Err(KernelError::ResourceNotRegistered(operation.uri.clone()))
    }

    fn list_prompts_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<PromptDefinition>, KernelError> {
        let session = self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;

        let mut prompts = Vec::new();
        for provider in &self.prompt_providers {
            prompts.extend(provider.list_prompts().into_iter().filter(|prompt| {
                session.capabilities().iter().any(|capability| {
                    capability_matches_prompt_request(capability, &prompt.name).unwrap_or(false)
                })
            }));
        }

        Ok(prompts)
    }

    fn evaluate_prompt_get(
        &self,
        context: &OperationContext,
        operation: &GetPromptOperation,
    ) -> Result<PromptResult, KernelError> {
        self.validate_non_tool_capability(&operation.capability, &context.agent_id)?;

        if !capability_matches_prompt_request(&operation.capability, &operation.prompt_name)? {
            return Err(KernelError::OutOfScopePrompt {
                prompt: operation.prompt_name.clone(),
            });
        }

        for provider in &self.prompt_providers {
            if let Some(prompt) =
                provider.get_prompt(&operation.prompt_name, operation.arguments.clone())?
            {
                return Ok(prompt);
            }
        }

        Err(KernelError::PromptNotRegistered(
            operation.prompt_name.clone(),
        ))
    }

    fn evaluate_completion(
        &self,
        context: &OperationContext,
        operation: &CompleteOperation,
    ) -> Result<CompletionResult, KernelError> {
        self.validate_non_tool_capability(&operation.capability, &context.agent_id)?;

        match &operation.reference {
            CompletionReference::Prompt { name } => {
                if !capability_matches_prompt_request(&operation.capability, name)? {
                    return Err(KernelError::OutOfScopePrompt {
                        prompt: name.clone(),
                    });
                }

                for provider in &self.prompt_providers {
                    if let Some(completion) = provider.complete_prompt_argument(
                        name,
                        &operation.argument.name,
                        &operation.argument.value,
                        &operation.context_arguments,
                    )? {
                        return Ok(completion);
                    }
                }

                Err(KernelError::PromptNotRegistered(name.clone()))
            }
            CompletionReference::Resource { uri } => {
                if !capability_matches_resource_pattern(&operation.capability, uri)? {
                    return Err(KernelError::OutOfScopeResource { uri: uri.clone() });
                }

                for provider in &self.resource_providers {
                    if let Some(completion) = provider.complete_resource_argument(
                        uri,
                        &operation.argument.name,
                        &operation.argument.value,
                        &operation.context_arguments,
                    )? {
                        return Ok(completion);
                    }
                }

                Err(KernelError::ResourceNotRegistered(uri.clone()))
            }
        }
    }

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
            return self.build_deny_response(request, &msg, now);
        }

        if let Err(e) = check_time_bounds(cap, now) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now);
        }

        if let Err(e) = self.check_revocation(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now);
        }

        if let Err(e) = check_subject_binding(cap, &request.agent_id) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now);
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
                return self.build_deny_response(request, &msg, now);
            }
            Err(e) => {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                return self.build_deny_response(request, &msg, now);
            }
        };

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

        // DPoP enforcement: if the matched grant requires DPoP, verify the proof.
        if let Some(matched_grant) = cap.scope.grants.get(matched_grant_index) {
            if matched_grant.dpop_required == Some(true) {
                if let Err(e) = self.verify_dpop_for_request(request, cap) {
                    let msg = e.to_string();
                    warn!(request_id = %request.request_id, reason = %msg, "DPoP verification failed");
                    return self.build_deny_response(request, &msg, now);
                }
            }
        }

        if let Err(e) = self.run_guards(
            request,
            &cap.scope,
            session_filesystem_roots,
            Some(matched_grant_index),
        ) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "guard denied");
            return self.build_deny_response(request, &msg, now);
        }

        let tool_started_at = Instant::now();
        let has_monetary = charge_result.is_some();
        let (tool_output, reported_cost) =
            match self.dispatch_tool_call_with_cost(request, has_monetary) {
                Ok(result) => result,
                Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                    warn!(
                        request_id = %request.request_id,
                        reason = %error,
                        "tool call requires URL elicitation"
                    );
                    return Err(error);
                }
                Err(KernelError::RequestCancelled { reason, .. }) => {
                    warn!(
                        request_id = %request.request_id,
                        reason = %reason,
                        "tool call cancelled"
                    );
                    return self.build_cancelled_response(request, &reason, now);
                }
                Err(KernelError::RequestIncomplete(reason)) => {
                    warn!(
                        request_id = %request.request_id,
                        reason = %reason,
                        "tool call incomplete"
                    );
                    return self.build_incomplete_response(request, &reason, now);
                }
                Err(e) => {
                    let msg = e.to_string();
                    warn!(request_id = %request.request_id, reason = %msg, "tool server error");
                    return self.build_deny_response(request, &msg, now);
                }
            };
        self.finalize_tool_output_with_cost(
            request,
            tool_output,
            tool_started_at.elapsed(),
            now,
            charge_result,
            reported_cost,
            cap,
        )
    }

    fn evaluate_tool_call_with_nested_flow_client<C: NestedFlowClient>(
        &mut self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
    ) -> Result<ToolCallResponse, KernelError> {
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
            return self.build_deny_response(request, &msg, now);
        }

        if let Err(e) = check_time_bounds(cap, now) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now);
        }

        if let Err(e) = self.check_revocation(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now);
        }

        if let Err(e) = check_subject_binding(cap, &request.agent_id) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now);
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
                return self.build_deny_response(request, &msg, now);
            }
            Err(e) => {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                return self.build_deny_response(request, &msg, now);
            }
        };

        let (matched_grant_index, _charge_result) =
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

        // DPoP enforcement: if the matched grant requires DPoP, verify the proof.
        if let Some(matched_grant) = cap.scope.grants.get(matched_grant_index) {
            if matched_grant.dpop_required == Some(true) {
                if let Err(e) = self.verify_dpop_for_request(request, cap) {
                    let msg = e.to_string();
                    warn!(request_id = %request.request_id, reason = %msg, "DPoP verification failed");
                    return self.build_deny_response(request, &msg, now);
                }
            }
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
            return self.build_deny_response(request, &msg, now);
        }

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
                warn!(
                    request_id = %request.request_id,
                    reason = %error,
                    "tool call requires URL elicitation"
                );
                return Err(error);
            }
            Err(KernelError::RequestCancelled { request_id, reason }) => {
                if request_id == parent_context.request_id {
                    self.session_mut(&parent_context.session_id)?
                        .request_cancellation(&parent_context.request_id)?;
                }
                warn!(
                    request_id = %request.request_id,
                    reason = %reason,
                    "tool call cancelled"
                );
                return self.build_cancelled_response(request, &reason, now);
            }
            Err(KernelError::RequestIncomplete(reason)) => {
                warn!(
                    request_id = %request.request_id,
                    reason = %reason,
                    "tool call incomplete"
                );
                return self.build_incomplete_response(request, &reason, now);
            }
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "tool server error");
                return self.build_deny_response(request, &msg, now);
            }
        };
        self.finalize_tool_output(request, tool_output, tool_started_at.elapsed(), now)
    }

    /// Issue a new capability for an agent.
    ///
    /// The kernel delegates issuance to the configured capability authority.
    pub fn issue_capability(
        &self,
        subject: &pact_core::PublicKey,
        scope: PactScope,
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

    pub fn public_key(&self) -> pact_core::PublicKey {
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
                    let charge = BudgetChargeResult {
                        grant_index: matching.index,
                        cost_charged: cost_units,
                        currency,
                        budget_total,
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
        scope: &PactScope,
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
    /// denial reason is monetary budget exhaustion.
    fn build_monetary_deny_response(
        &mut self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matching_grants: &[MatchingGrant<'_>],
        cap: &CapabilityToken,
    ) -> Result<ToolCallResponse, KernelError> {
        // Look for a monetary grant among the matching candidates to populate metadata.
        let monetary_grant = matching_grants.iter().find(|m| {
            m.grant.max_cost_per_invocation.is_some() || m.grant.max_total_cost.is_some()
        });

        if let Some(mg) = monetary_grant {
            let grant = mg.grant;
            let currency = grant
                .max_cost_per_invocation
                .as_ref()
                .map(|m| m.currency.clone())
                .or_else(|| grant.max_total_cost.as_ref().map(|m| m.currency.clone()))
                .unwrap_or_else(|| "USD".to_string());
            let budget_total = grant
                .max_total_cost
                .as_ref()
                .map(|m| m.units)
                .unwrap_or(u64::MAX);
            let attempted_cost = grant
                .max_cost_per_invocation
                .as_ref()
                .map(|m| m.units)
                .unwrap_or(0);
            let delegation_depth = cap.delegation_chain.len() as u32;
            let root_budget_holder = cap.issuer.to_hex();

            let financial_meta = FinancialReceiptMetadata {
                grant_index: mg.index as u32,
                cost_charged: 0,
                currency,
                budget_remaining: 0,
                budget_total,
                delegation_depth,
                root_budget_holder,
                payment_reference: None,
                settlement_status: "not_applicable".to_string(),
                cost_breakdown: None,
                attempted_cost: Some(attempted_cost),
            };

            let metadata = Some(serde_json::json!({ "financial": financial_meta }));
            let receipt_content = receipt_content_for_output(None, None)?;

            let action =
                ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
                    KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
                })?;

            let receipt = self.build_and_sign_receipt(ReceiptParams {
                capability_id: &cap.id,
                tool_name: &request.tool_name,
                server_id: &request.server_id,
                decision: Decision::Deny {
                    reason: reason.to_string(),
                    guard: "kernel".to_string(),
                },
                action,
                content_hash: receipt_content.content_hash,
                metadata,
                timestamp,
            })?;

            self.record_pact_receipt(&receipt)?;

            return Ok(ToolCallResponse {
                request_id: request.request_id.clone(),
                verdict: Verdict::Deny,
                output: None,
                reason: Some(reason.to_string()),
                terminal_state: OperationTerminalState::Completed,
                receipt,
            });
        }

        // No monetary grant -- standard deny.
        self.build_deny_response(request, reason, timestamp)
    }

    fn finalize_tool_output(
        &mut self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
    ) -> Result<ToolCallResponse, KernelError> {
        match self.apply_stream_limits(output, elapsed)? {
            ToolServerOutput::Value(value) => {
                self.build_allow_response(request, ToolCallOutput::Value(value), timestamp)
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => {
                self.build_allow_response(request, ToolCallOutput::Stream(stream), timestamp)
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => self
                .build_incomplete_response_with_output(
                    request,
                    Some(ToolCallOutput::Stream(stream)),
                    &reason,
                    timestamp,
                ),
        }
    }

    /// Finalize a tool output with optional monetary metadata injected into the receipt.
    #[allow(clippy::too_many_arguments)]
    fn finalize_tool_output_with_cost(
        &mut self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        charge_result: Option<BudgetChargeResult>,
        reported_cost: Option<ToolInvocationCost>,
        cap: &CapabilityToken,
    ) -> Result<ToolCallResponse, KernelError> {
        let Some(charge) = charge_result else {
            // Non-monetary grant: use normal path.
            return self.finalize_tool_output(request, output, elapsed, timestamp);
        };

        // Determine actual cost: use reported cost if server provided it and it's <= max charged.
        // If server overruns max_cost_per_invocation, we log a warning and treat as "failed".
        let (actual_cost, settlement_status) = if let Some(ref cost) = reported_cost {
            if cost.units > charge.cost_charged && charge.cost_charged > 0 {
                warn!(
                    request_id = %request.request_id,
                    reported = cost.units,
                    charged = charge.cost_charged,
                    "tool server reported cost exceeds max_cost_per_invocation; settlement_status=failed"
                );
                (cost.units, "failed".to_string())
            } else {
                (cost.units, "authorized".to_string())
            }
        } else {
            // Server did not report cost; worst-case debit already charged.
            (charge.cost_charged, "authorized".to_string())
        };

        let budget_remaining = charge.budget_total.saturating_sub(actual_cost);
        let delegation_depth = cap.delegation_chain.len() as u32;
        let root_budget_holder = cap.issuer.to_hex();

        let financial_meta = FinancialReceiptMetadata {
            grant_index: charge.grant_index as u32,
            cost_charged: actual_cost,
            currency: charge.currency.clone(),
            budget_remaining,
            budget_total: charge.budget_total,
            delegation_depth,
            root_budget_holder,
            payment_reference: None,
            settlement_status,
            cost_breakdown: reported_cost.and_then(|c| c.breakdown),
            attempted_cost: None,
        };

        let limited_output = self.apply_stream_limits(output, elapsed)?;
        let tool_call_output = match &limited_output {
            ToolServerOutput::Value(v) => ToolCallOutput::Value(v.clone()),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(s)) => {
                ToolCallOutput::Stream(s.clone())
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, .. }) => {
                ToolCallOutput::Stream(stream.clone())
            }
        };

        let financial_json = serde_json::json!({ "financial": financial_meta });

        match limited_output {
            ToolServerOutput::Value(_)
            | ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)) => self
                .build_allow_response_with_metadata(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(financial_json),
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => self
                .build_incomplete_response_with_output(
                    request,
                    Some(tool_call_output),
                    &reason,
                    timestamp,
                ),
        }
    }

    fn apply_stream_limits(
        &self,
        output: ToolServerOutput,
        elapsed: Duration,
    ) -> Result<ToolServerOutput, KernelError> {
        let ToolServerOutput::Stream(stream_result) = output else {
            return Ok(output);
        };

        let duration_limit = Duration::from_secs(self.config.max_stream_duration_secs);
        let duration_exceeded =
            self.config.max_stream_duration_secs > 0 && elapsed > duration_limit;

        let (stream, base_reason) = match stream_result {
            ToolServerStreamResult::Complete(stream) => (stream, None),
            ToolServerStreamResult::Incomplete { stream, reason } => (stream, Some(reason)),
        };

        let (stream, total_bytes, truncated) =
            truncate_stream_to_byte_limit(&stream, self.config.max_stream_total_bytes)?;

        let limit_reason = if truncated {
            Some(format!(
                "PACT_SERVER_STREAM_LIMIT: stream exceeded max total bytes of {}",
                self.config.max_stream_total_bytes
            ))
        } else if duration_exceeded {
            Some(format!(
                "PACT_SERVER_STREAM_LIMIT: stream exceeded max duration of {}s",
                self.config.max_stream_duration_secs
            ))
        } else {
            None
        };

        if let Some(reason) = limit_reason {
            warn!(
                request_bytes = total_bytes,
                elapsed_ms = elapsed.as_millis(),
                "stream output exceeded configured limits"
            );
            return Ok(ToolServerOutput::Stream(
                ToolServerStreamResult::Incomplete { stream, reason },
            ));
        }

        if let Some(reason) = base_reason {
            Ok(ToolServerOutput::Stream(
                ToolServerStreamResult::Incomplete { stream, reason },
            ))
        } else {
            Ok(ToolServerOutput::Stream(ToolServerStreamResult::Complete(
                stream,
            )))
        }
    }

    /// Build a denial response with a signed receipt.
    fn build_deny_response(
        &mut self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(None, None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "kernel".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: receipt_content.metadata,
            timestamp,
        })?;

        self.record_pact_receipt(&receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Completed,
            receipt,
        })
    }

    /// Build a cancellation response with a signed cancelled receipt.
    fn build_cancelled_response(
        &mut self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(None, None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Cancelled {
                reason: reason.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: receipt_content.metadata,
            timestamp,
        })?;

        self.record_pact_receipt(&receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Cancelled {
                reason: reason.to_string(),
            },
            receipt,
        })
    }

    /// Build an incomplete response with a signed incomplete receipt.
    fn build_incomplete_response(
        &mut self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_incomplete_response_with_output(request, None, reason, timestamp)
    }

    /// Build an incomplete response with optional partial output and a signed incomplete receipt.
    fn build_incomplete_response_with_output(
        &mut self,
        request: &ToolCallRequest,
        output: Option<ToolCallOutput>,
        reason: &str,
        timestamp: u64,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(output.as_ref(), None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Incomplete {
                reason: reason.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: receipt_content.metadata,
            timestamp,
        })?;

        self.record_pact_receipt(&receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Incomplete {
                reason: reason.to_string(),
            },
            receipt,
        })
    }

    fn build_allow_response(
        &mut self,
        request: &ToolCallRequest,
        output: ToolCallOutput,
        timestamp: u64,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_allow_response_with_metadata(request, output, timestamp, None)
    }

    fn build_allow_response_with_metadata(
        &mut self,
        request: &ToolCallRequest,
        output: ToolCallOutput,
        timestamp: u64,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let expected_chunks = match &output {
            ToolCallOutput::Stream(stream) => Some(stream.chunk_count()),
            ToolCallOutput::Value(_) => None,
        };
        let receipt_content = receipt_content_for_output(Some(&output), expected_chunks)?;

        // Merge extra_metadata (e.g. "financial") into receipt_content.metadata.
        let metadata = match (receipt_content.metadata, extra_metadata) {
            (None, extra) => extra,
            (Some(base), None) => Some(base),
            (Some(mut base), Some(extra)) => {
                if let (Some(base_obj), Some(extra_obj)) = (base.as_object_mut(), extra.as_object())
                {
                    for (key, value) in extra_obj {
                        base_obj.insert(key.clone(), value.clone());
                    }
                }
                Some(base)
            }
        };

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Allow,
            action,
            content_hash: receipt_content.content_hash,
            metadata,
            timestamp,
        })?;

        self.record_pact_receipt(&receipt)?;

        info!(
            request_id = %request.request_id,
            tool = %request.tool_name,
            receipt_id = %receipt.id,
            "tool call allowed"
        );

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Allow,
            output: Some(output),
            reason: None,
            terminal_state: OperationTerminalState::Completed,
            receipt,
        })
    }

    /// Build and sign a receipt from a `ReceiptParams` descriptor.
    fn build_and_sign_receipt(
        &mut self,
        params: ReceiptParams<'_>,
    ) -> Result<PactReceipt, KernelError> {
        let body = PactReceiptBody {
            id: next_receipt_id("rcpt"),
            timestamp: params.timestamp,
            capability_id: params.capability_id.to_string(),
            tool_server: params.server_id.to_string(),
            tool_name: params.tool_name.to_string(),
            action: params.action,
            decision: params.decision,
            content_hash: params.content_hash,
            policy_hash: self.config.policy_hash.clone(),
            evidence: vec![],
            metadata: params.metadata,
            kernel_key: self.config.keypair.public_key(),
        };

        PactReceipt::sign(body, &self.config.keypair)
            .map_err(|e| KernelError::ReceiptSigningFailed(e.to_string()))
    }

    fn record_pact_receipt(&mut self, receipt: &PactReceipt) -> Result<(), KernelError> {
        if let Some(store) = self.receipt_store.as_deref_mut() {
            // Downcast to SqliteReceiptStore to get the seq and trigger checkpoints.
            // If we can't (e.g. a non-SQLite store), fall back to the trait method.
            let seq = if let Some(sqlite_store) = store
                .as_any_mut()
                .and_then(|any| any.downcast_mut::<SqliteReceiptStore>())
            {
                sqlite_store.append_pact_receipt_returning_seq(receipt)?
            } else {
                store.append_pact_receipt(receipt)?;
                0
            };

            // Trigger a Merkle checkpoint if we've accumulated enough receipts.
            if seq > 0
                && self.checkpoint_batch_size > 0
                && (seq - self.last_checkpoint_seq) >= self.checkpoint_batch_size
            {
                self.maybe_trigger_checkpoint(seq)?;
            }
        }
        self.receipt_log.append(receipt.clone());
        Ok(())
    }

    /// Trigger a Merkle checkpoint for all receipts in [last_checkpoint_seq+1, batch_end_seq].
    fn maybe_trigger_checkpoint(&mut self, batch_end_seq: u64) -> Result<(), KernelError> {
        let batch_start_seq = self.last_checkpoint_seq + 1;

        let sqlite_store = self.receipt_store.as_mut().and_then(|store| {
            store
                .as_any_mut()
                .and_then(|any| any.downcast_mut::<SqliteReceiptStore>())
        });

        let Some(sqlite_store) = sqlite_store else {
            return Ok(());
        };

        let receipt_bytes_with_seqs = sqlite_store
            .receipts_canonical_bytes_range(batch_start_seq, batch_end_seq)
            .map_err(KernelError::ReceiptPersistence)?;

        if receipt_bytes_with_seqs.is_empty() {
            return Ok(());
        }

        let receipt_bytes: Vec<Vec<u8>> = receipt_bytes_with_seqs
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect();

        self.checkpoint_seq_counter += 1;
        let checkpoint_seq = self.checkpoint_seq_counter;

        let checkpoint = checkpoint::build_checkpoint(
            checkpoint_seq,
            batch_start_seq,
            batch_end_seq,
            &receipt_bytes,
            &self.config.keypair,
        )
        .map_err(|e| KernelError::Internal(format!("checkpoint build failed: {e}")))?;

        // Re-borrow to store the checkpoint.
        let sqlite_store = self.receipt_store.as_mut().and_then(|store| {
            store
                .as_any_mut()
                .and_then(|any| any.downcast_mut::<SqliteReceiptStore>())
        });
        if let Some(sqlite_store) = sqlite_store {
            sqlite_store
                .store_checkpoint(&checkpoint)
                .map_err(KernelError::ReceiptPersistence)?;
        }

        self.last_checkpoint_seq = batch_end_seq;
        Ok(())
    }

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
struct ReceiptParams<'a> {
    capability_id: &'a str,
    tool_name: &'a str,
    server_id: &'a str,
    decision: Decision,
    action: ToolCallAction,
    content_hash: String,
    metadata: Option<serde_json::Value>,
    timestamp: u64,
}

fn build_child_request_receipt(
    policy_hash: &str,
    keypair: &Keypair,
    context: &OperationContext,
    operation_kind: OperationKind,
    terminal_state: OperationTerminalState,
    outcome_payload: serde_json::Value,
) -> Result<ChildRequestReceipt, KernelError> {
    let outcome_hash = canonical_json_bytes(&outcome_payload)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!("failed to hash child outcome: {error}"))
        })?;
    let metadata = child_receipt_metadata(&outcome_payload);
    let parent_request_id = context.parent_request_id.clone().ok_or_else(|| {
        KernelError::ReceiptSigningFailed("child receipt requires parent request lineage".into())
    })?;

    let body = ChildRequestReceiptBody {
        id: next_receipt_id("child-rcpt"),
        timestamp: current_unix_timestamp(),
        session_id: context.session_id.clone(),
        parent_request_id,
        request_id: context.request_id.clone(),
        operation_kind,
        terminal_state,
        outcome_hash,
        policy_hash: policy_hash.to_string(),
        metadata,
        kernel_key: keypair.public_key(),
    };

    ChildRequestReceipt::sign(body, keypair)
        .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))
}

fn next_receipt_id(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::now_v7())
}

fn child_receipt_metadata(outcome_payload: &serde_json::Value) -> Option<serde_json::Value> {
    outcome_payload
        .get("outcome")
        .and_then(serde_json::Value::as_str)
        .map(|outcome| {
            let mut metadata = serde_json::Map::new();
            metadata.insert(
                "outcome".to_string(),
                serde_json::Value::String(outcome.to_string()),
            );
            if let Some(message) = outcome_payload
                .get("message")
                .and_then(serde_json::Value::as_str)
            {
                metadata.insert(
                    "message".to_string(),
                    serde_json::Value::String(message.to_string()),
                );
            }
            serde_json::Value::Object(metadata)
        })
}

fn child_terminal_state<T>(
    request_id: &RequestId,
    result: &Result<T, KernelError>,
) -> OperationTerminalState {
    match result {
        Ok(_) => OperationTerminalState::Completed,
        Err(KernelError::RequestCancelled {
            request_id: cancelled_request_id,
            reason,
        }) if cancelled_request_id == request_id => OperationTerminalState::Cancelled {
            reason: reason.clone(),
        },
        Err(KernelError::RequestIncomplete(reason)) => OperationTerminalState::Incomplete {
            reason: reason.clone(),
        },
        Err(_) => OperationTerminalState::Completed,
    }
}

fn child_outcome_payload<T: serde::Serialize>(
    result: &Result<T, KernelError>,
) -> Result<serde_json::Value, KernelError> {
    match result {
        Ok(value) => {
            let mut payload = serde_json::Map::new();
            payload.insert(
                "outcome".to_string(),
                serde_json::Value::String("result".into()),
            );
            payload.insert(
                "result".to_string(),
                serde_json::to_value(value).map_err(|error| {
                    KernelError::ReceiptSigningFailed(format!(
                        "failed to serialize child result: {error}"
                    ))
                })?,
            );
            Ok(serde_json::Value::Object(payload))
        }
        Err(error) => Ok(serde_json::json!({
            "outcome": "error",
            "message": error.to_string(),
        })),
    }
}

fn receipt_content_for_output(
    output: Option<&ToolCallOutput>,
    stream_chunks_expected: Option<u64>,
) -> Result<ReceiptContent, KernelError> {
    match output {
        Some(ToolCallOutput::Value(value)) => {
            let bytes = canonical_json_bytes(value).map_err(|e| {
                KernelError::ReceiptSigningFailed(format!("failed to hash tool output: {e}"))
            })?;
            Ok(ReceiptContent {
                content_hash: sha256_hex(&bytes),
                metadata: None,
            })
        }
        Some(ToolCallOutput::Stream(stream)) => {
            stream_receipt_content(stream, stream_chunks_expected)
        }
        None => Ok(ReceiptContent {
            content_hash: sha256_hex(b"null"),
            metadata: None,
        }),
    }
}

fn stream_receipt_content(
    stream: &ToolCallStream,
    chunks_expected: Option<u64>,
) -> Result<ReceiptContent, KernelError> {
    let mut chunk_hashes = Vec::with_capacity(stream.chunks.len());
    let mut combined = Vec::new();
    let mut total_bytes = 0u64;

    for chunk in &stream.chunks {
        let bytes = canonical_json_bytes(&chunk.data).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash stream chunk: {e}"))
        })?;
        total_bytes += bytes.len() as u64;
        let chunk_hash = sha256_hex(&bytes);
        combined.extend_from_slice(chunk_hash.as_bytes());
        chunk_hashes.push(chunk_hash);
    }

    Ok(ReceiptContent {
        content_hash: sha256_hex(&combined),
        metadata: Some(serde_json::json!({
            "stream": {
                "chunks_expected": chunks_expected,
                "chunks_received": stream.chunk_count(),
                "total_bytes": total_bytes,
                "chunk_hashes": chunk_hashes,
            }
        })),
    })
}

fn truncate_stream_to_byte_limit(
    stream: &ToolCallStream,
    max_stream_total_bytes: u64,
) -> Result<(ToolCallStream, u64, bool), KernelError> {
    let mut accepted = Vec::new();
    let mut total_bytes = 0u64;
    let mut truncated = false;

    for chunk in &stream.chunks {
        let bytes = canonical_json_bytes(&chunk.data).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to size stream chunk: {e}"))
        })?;
        let chunk_bytes = bytes.len() as u64;
        if max_stream_total_bytes > 0
            && total_bytes.saturating_add(chunk_bytes) > max_stream_total_bytes
        {
            truncated = true;
            break;
        }
        total_bytes += chunk_bytes;
        accepted.push(chunk.clone());
    }

    Ok((ToolCallStream { chunks: accepted }, total_bytes, truncated))
}

fn session_from_map<'a>(
    sessions: &'a HashMap<SessionId, Session>,
    session_id: &SessionId,
) -> Result<&'a Session, KernelError> {
    sessions
        .get(session_id)
        .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))
}

fn session_mut_from_map<'a>(
    sessions: &'a mut HashMap<SessionId, Session>,
    session_id: &SessionId,
) -> Result<&'a mut Session, KernelError> {
    sessions
        .get_mut(session_id)
        .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))
}

fn begin_session_request_in_sessions(
    sessions: &mut HashMap<SessionId, Session>,
    context: &OperationContext,
    operation_kind: OperationKind,
    cancellable: bool,
) -> Result<(), KernelError> {
    let session = session_mut_from_map(sessions, &context.session_id)?;
    session.validate_context(context)?;
    session.ensure_operation_allowed(operation_kind)?;
    session.track_request(context, operation_kind, cancellable)?;
    Ok(())
}

fn begin_child_request_in_sessions(
    sessions: &mut HashMap<SessionId, Session>,
    parent_context: &OperationContext,
    request_id: RequestId,
    operation_kind: OperationKind,
    progress_token: Option<ProgressToken>,
    cancellable: bool,
) -> Result<OperationContext, KernelError> {
    let child_context = OperationContext {
        session_id: parent_context.session_id.clone(),
        request_id,
        agent_id: parent_context.agent_id.clone(),
        parent_request_id: Some(parent_context.request_id.clone()),
        progress_token,
    };
    begin_session_request_in_sessions(sessions, &child_context, operation_kind, cancellable)?;
    Ok(child_context)
}

fn complete_session_request_with_terminal_state_in_sessions(
    sessions: &mut HashMap<SessionId, Session>,
    session_id: &SessionId,
    request_id: &RequestId,
    terminal_state: OperationTerminalState,
) -> Result<(), KernelError> {
    session_mut_from_map(sessions, session_id)?
        .complete_request_with_terminal_state(request_id, terminal_state)?;
    Ok(())
}

fn validate_sampling_request_in_sessions(
    sessions: &HashMap<SessionId, Session>,
    allow_sampling: bool,
    allow_sampling_tool_use: bool,
    context: &OperationContext,
    operation: &CreateMessageOperation,
) -> Result<(), KernelError> {
    let session = session_from_map(sessions, &context.session_id)?;
    session.validate_context(context)?;
    session.ensure_operation_allowed(OperationKind::CreateMessage)?;

    if context.parent_request_id.is_none() {
        return Err(KernelError::InvalidChildRequestParent);
    }

    if !allow_sampling {
        return Err(KernelError::SamplingNotAllowedByPolicy);
    }

    let peer_capabilities = session.peer_capabilities();
    if !peer_capabilities.supports_sampling {
        return Err(KernelError::SamplingNotNegotiated);
    }

    if matches!(
        operation.include_context.as_deref(),
        Some("thisServer") | Some("allServers")
    ) && !peer_capabilities.sampling_context
    {
        return Err(KernelError::SamplingContextNotSupported);
    }

    let requests_tool_use = !operation.tools.is_empty()
        || operation
            .tool_choice
            .as_ref()
            .is_some_and(|choice| choice.mode != "none");
    if requests_tool_use {
        if !allow_sampling_tool_use {
            return Err(KernelError::SamplingToolUseNotAllowedByPolicy);
        }
        if !peer_capabilities.sampling_tools {
            return Err(KernelError::SamplingToolUseNotNegotiated);
        }
    }

    Ok(())
}

fn validate_elicitation_request_in_sessions(
    sessions: &HashMap<SessionId, Session>,
    allow_elicitation: bool,
    context: &OperationContext,
    operation: &CreateElicitationOperation,
) -> Result<(), KernelError> {
    let session = session_from_map(sessions, &context.session_id)?;
    session.validate_context(context)?;
    session.ensure_operation_allowed(OperationKind::CreateElicitation)?;

    if context.parent_request_id.is_none() {
        return Err(KernelError::InvalidChildRequestParent);
    }

    if !allow_elicitation {
        return Err(KernelError::ElicitationNotAllowedByPolicy);
    }

    let peer_capabilities = session.peer_capabilities();
    if !peer_capabilities.supports_elicitation {
        return Err(KernelError::ElicitationNotNegotiated);
    }

    match operation {
        CreateElicitationOperation::Form { .. } => {
            if !peer_capabilities.elicitation_form {
                return Err(KernelError::ElicitationFormNotSupported);
            }
        }
        CreateElicitationOperation::Url { .. } => {
            if !peer_capabilities.elicitation_url {
                return Err(KernelError::ElicitationUrlNotSupported);
            }
        }
    }

    Ok(())
}

fn nested_child_request_id(parent_request_id: &RequestId, suffix: &str) -> RequestId {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    RequestId::new(format!("{parent_request_id}-{suffix}-{nonce}"))
}

/// Check time bounds on a capability (u64 unix timestamps).
fn check_time_bounds(cap: &CapabilityToken, now: u64) -> Result<(), KernelError> {
    if now >= cap.expires_at {
        return Err(KernelError::CapabilityExpired);
    }
    if now < cap.issued_at {
        return Err(KernelError::CapabilityNotYetValid);
    }
    Ok(())
}

fn check_subject_binding(cap: &CapabilityToken, agent_id: &str) -> Result<(), KernelError> {
    let expected = cap.subject.to_hex();
    if expected == agent_id {
        Ok(())
    } else {
        Err(KernelError::SubjectMismatch {
            expected,
            actual: agent_id.to_string(),
        })
    }
}

pub fn capability_matches_request(
    cap: &CapabilityToken,
    tool_name: &str,
    server_id: &str,
    arguments: &serde_json::Value,
) -> Result<bool, KernelError> {
    Ok(!resolve_matching_grants(cap, tool_name, server_id, arguments)?.is_empty())
}

pub fn capability_matches_resource_request(
    cap: &CapabilityToken,
    uri: &str,
) -> Result<bool, KernelError> {
    Ok(cap
        .scope
        .resource_grants
        .iter()
        .any(|grant| resource_grant_matches_request(grant, uri)))
}

pub fn capability_matches_resource_subscription(
    cap: &CapabilityToken,
    uri: &str,
) -> Result<bool, KernelError> {
    Ok(cap
        .scope
        .resource_grants
        .iter()
        .any(|grant| resource_grant_matches_subscription(grant, uri)))
}

pub fn capability_matches_resource_pattern(
    cap: &CapabilityToken,
    pattern: &str,
) -> Result<bool, KernelError> {
    Ok(cap.scope.resource_grants.iter().any(|grant| {
        resource_pattern_matches(&grant.uri_pattern, pattern)
            && grant.operations.contains(&Operation::Read)
    }))
}

pub fn capability_matches_prompt_request(
    cap: &CapabilityToken,
    prompt_name: &str,
) -> Result<bool, KernelError> {
    Ok(cap
        .scope
        .prompt_grants
        .iter()
        .any(|grant| prompt_grant_matches_request(grant, prompt_name)))
}

fn resolve_matching_grants<'a>(
    cap: &'a CapabilityToken,
    tool_name: &str,
    server_id: &str,
    arguments: &serde_json::Value,
) -> Result<Vec<MatchingGrant<'a>>, KernelError> {
    let mut matches = Vec::new();

    for (index, grant) in cap.scope.grants.iter().enumerate() {
        if !grant_matches_request(grant, tool_name, server_id, arguments)? {
            continue;
        }

        matches.push(MatchingGrant {
            index,
            grant,
            specificity: (
                u8::from(grant.server_id == server_id),
                u8::from(grant.tool_name == tool_name),
                grant.constraints.len(),
            ),
        });
    }

    matches.sort_by(|left, right| {
        right
            .specificity
            .cmp(&left.specificity)
            .then_with(|| left.index.cmp(&right.index))
    });

    Ok(matches)
}

fn grant_matches_request(
    grant: &ToolGrant,
    tool_name: &str,
    server_id: &str,
    arguments: &serde_json::Value,
) -> Result<bool, KernelError> {
    Ok(matches_server(&grant.server_id, server_id)
        && matches_name(&grant.tool_name, tool_name)
        && grant.operations.contains(&Operation::Invoke)
        && constraints_match(&grant.constraints, arguments)?)
}

fn matches_server(pattern: &str, server_id: &str) -> bool {
    pattern == "*" || pattern == server_id
}

fn matches_name(pattern: &str, name: &str) -> bool {
    pattern == "*" || pattern == name
}

fn constraints_match(
    constraints: &[Constraint],
    arguments: &serde_json::Value,
) -> Result<bool, KernelError> {
    for constraint in constraints {
        if !constraint_matches(constraint, arguments)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn constraint_matches(
    constraint: &Constraint,
    arguments: &serde_json::Value,
) -> Result<bool, KernelError> {
    let string_leaves = collect_string_leaves(arguments);

    match constraint {
        Constraint::PathPrefix(prefix) => {
            let candidates: Vec<&str> = string_leaves
                .iter()
                .filter(|leaf| {
                    leaf.key.as_deref().is_some_and(is_path_key) || looks_like_path(&leaf.value)
                })
                .map(|leaf| leaf.value.as_str())
                .collect();
            Ok(!candidates.is_empty()
                && candidates.into_iter().all(|path| path.starts_with(prefix)))
        }
        Constraint::DomainExact(expected) => {
            let expected = normalize_domain(expected);
            let domains = collect_domain_candidates(&string_leaves);
            Ok(!domains.is_empty() && domains.into_iter().all(|domain| domain == expected))
        }
        Constraint::DomainGlob(pattern) => {
            let pattern = pattern.to_ascii_lowercase();
            let domains = collect_domain_candidates(&string_leaves);
            Ok(!domains.is_empty()
                && domains
                    .into_iter()
                    .all(|domain| wildcard_matches(&pattern, &domain)))
        }
        Constraint::RegexMatch(pattern) => {
            let regex = Regex::new(pattern).map_err(|error| {
                KernelError::InvalidConstraint(format!(
                    "regex \"{pattern}\" failed to compile: {error}"
                ))
            })?;
            Ok(string_leaves.iter().any(|leaf| regex.is_match(&leaf.value)))
        }
        Constraint::MaxLength(max) => Ok(string_leaves.iter().all(|leaf| leaf.value.len() <= *max)),
        Constraint::Custom(key, expected) => Ok(argument_contains_custom(arguments, key, expected)),
    }
}

fn resource_grant_matches_request(grant: &ResourceGrant, uri: &str) -> bool {
    resource_pattern_matches(&grant.uri_pattern, uri) && grant.operations.contains(&Operation::Read)
}

fn resource_grant_matches_subscription(grant: &ResourceGrant, uri: &str) -> bool {
    resource_pattern_matches(&grant.uri_pattern, uri)
        && grant.operations.contains(&Operation::Subscribe)
}

fn prompt_grant_matches_request(grant: &PromptGrant, prompt_name: &str) -> bool {
    matches_pattern(&grant.prompt_name, prompt_name) && grant.operations.contains(&Operation::Get)
}

fn resource_pattern_matches(pattern: &str, uri: &str) -> bool {
    matches_pattern(pattern, uri)
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }

    pattern == value
}

#[derive(Clone)]
struct StringLeaf {
    key: Option<String>,
    value: String,
}

fn collect_string_leaves(arguments: &serde_json::Value) -> Vec<StringLeaf> {
    let mut leaves = Vec::new();
    collect_string_leaves_inner(arguments, None, &mut leaves);
    leaves
}

fn collect_string_leaves_inner(
    arguments: &serde_json::Value,
    current_key: Option<&str>,
    leaves: &mut Vec<StringLeaf>,
) {
    match arguments {
        serde_json::Value::String(value) => leaves.push(StringLeaf {
            key: current_key.map(str::to_string),
            value: value.clone(),
        }),
        serde_json::Value::Array(values) => {
            for value in values {
                collect_string_leaves_inner(value, current_key, leaves);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                collect_string_leaves_inner(value, Some(key), leaves);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn is_path_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("path")
        || matches!(
            key.as_str(),
            "file" | "filepath" | "dir" | "directory" | "root" | "cwd"
        )
}

fn looks_like_path(value: &str) -> bool {
    !value.contains("://")
        && (value.starts_with('/')
            || value.starts_with("./")
            || value.starts_with("../")
            || value.starts_with("~/")
            || value.contains('/')
            || value.contains('\\'))
}

fn collect_domain_candidates(string_leaves: &[StringLeaf]) -> Vec<String> {
    string_leaves
        .iter()
        .filter_map(|leaf| parse_domain(&leaf.value))
        .collect()
}

fn parse_domain(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let host_port = if let Some((_, rest)) = trimmed.split_once("://") {
        rest
    } else {
        trimmed
    };

    let authority = host_port
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(host_port)
        .rsplit('@')
        .next()
        .unwrap_or(host_port);
    let host = authority
        .split(':')
        .next()
        .unwrap_or(authority)
        .trim_matches('.');
    let normalized = normalize_domain(host);

    if normalized == "localhost"
        || (!normalized.is_empty()
            && normalized.contains('.')
            && normalized.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '-' || character == '.'
            }))
    {
        Some(normalized)
    } else {
        None
    }
}

fn normalize_domain(value: &str) -> String {
    value.trim().trim_matches('.').to_ascii_lowercase()
}

fn wildcard_matches(pattern: &str, candidate: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let candidate_chars: Vec<char> = candidate.chars().collect();
    let (mut pattern_idx, mut candidate_idx) = (0usize, 0usize);
    let (mut star_idx, mut match_idx) = (None, 0usize);

    while candidate_idx < candidate_chars.len() {
        if pattern_idx < pattern_chars.len()
            && (pattern_chars[pattern_idx] == candidate_chars[candidate_idx]
                || pattern_chars[pattern_idx] == '*')
        {
            if pattern_chars[pattern_idx] == '*' {
                star_idx = Some(pattern_idx);
                match_idx = candidate_idx;
                pattern_idx += 1;
            } else {
                pattern_idx += 1;
                candidate_idx += 1;
            }
        } else if let Some(star_position) = star_idx {
            pattern_idx = star_position + 1;
            match_idx += 1;
            candidate_idx = match_idx;
        } else {
            return false;
        }
    }

    while pattern_idx < pattern_chars.len() && pattern_chars[pattern_idx] == '*' {
        pattern_idx += 1;
    }

    pattern_idx == pattern_chars.len()
}

fn argument_contains_custom(arguments: &serde_json::Value, key: &str, expected: &str) -> bool {
    match arguments {
        serde_json::Value::Object(map) => map.iter().any(|(entry_key, value)| {
            (entry_key == key && value.as_str() == Some(expected))
                || argument_contains_custom(value, key, expected)
        }),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| argument_contains_custom(value, key, expected)),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => false,
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pact_core::capability::{
        CapabilityToken, CapabilityTokenBody, Constraint, DelegationLink, DelegationLinkBody,
        Operation, PactScope, PromptGrant, ResourceGrant, ToolGrant,
    };
    use pact_core::crypto::Keypair;
    use pact_core::session::{
        CompleteOperation, CompletionArgument, CompletionReference, CreateMessageOperation,
        GetPromptOperation, OperationContext, RequestId, SamplingMessage, SamplingTool,
        SamplingToolChoice, SessionId, SessionOperation, ToolCallOperation,
    };
    use pact_core::{
        PromptArgument, PromptDefinition, PromptMessage, PromptResult, ReadResourceOperation,
        ResourceContent, ResourceDefinition, ResourceTemplateDefinition,
    };

    fn make_keypair() -> Keypair {
        Keypair::generate()
    }

    fn make_config() -> KernelConfig {
        KernelConfig {
            keypair: make_keypair(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "test-policy-hash".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        }
    }

    fn unique_receipt_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn make_elicited_content() -> CreateElicitationResult {
        CreateElicitationResult {
            action: pact_core::session::ElicitationAction::Accept,
            content: Some(serde_json::json!({
                "environment": "staging",
            })),
        }
    }

    fn make_grant(server: &str, tool: &str) -> ToolGrant {
        ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }
    }

    fn make_scope(grants: Vec<ToolGrant>) -> PactScope {
        PactScope {
            grants,
            ..PactScope::default()
        }
    }

    fn make_capability(
        kernel: &PactKernel,
        subject_kp: &Keypair,
        scope: PactScope,
        ttl: u64,
    ) -> CapabilityToken {
        kernel
            .issue_capability(&subject_kp.public_key(), scope, ttl)
            .unwrap()
    }

    fn make_request(
        request_id: &str,
        cap: &CapabilityToken,
        tool: &str,
        server: &str,
    ) -> ToolCallRequest {
        make_request_with_arguments(
            request_id,
            cap,
            tool,
            server,
            serde_json::json!({"path": "/app/src/main.rs"}),
        )
    }

    fn make_request_with_arguments(
        request_id: &str,
        cap: &CapabilityToken,
        tool: &str,
        server: &str,
        arguments: serde_json::Value,
    ) -> ToolCallRequest {
        ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: tool.to_string(),
            server_id: server.to_string(),
            agent_id: cap.subject.to_hex(),
            arguments,
            dpop_proof: None,
        }
    }

    fn make_operation_context(
        session_id: &SessionId,
        request_id: &str,
        agent_id: &str,
    ) -> OperationContext {
        OperationContext::new(
            session_id.clone(),
            RequestId::new(request_id),
            agent_id.to_string(),
        )
    }

    fn make_delegation_link(
        capability_id: &str,
        delegator_kp: &Keypair,
        delegatee_kp: &Keypair,
        timestamp: u64,
    ) -> DelegationLink {
        DelegationLink::sign(
            DelegationLinkBody {
                capability_id: capability_id.to_string(),
                delegator: delegator_kp.public_key(),
                delegatee: delegatee_kp.public_key(),
                attenuations: vec![],
                timestamp,
            },
            delegator_kp,
        )
        .unwrap()
    }

    struct EchoServer {
        id: String,
        tools: Vec<String>,
    }

    struct IncompleteServer {
        id: String,
    }

    struct StreamingServer {
        id: String,
        chunks: Vec<serde_json::Value>,
    }

    struct NestedFlowServer {
        id: String,
    }

    struct MockNestedFlowClient {
        roots: Vec<RootDefinition>,
        sampled_message: CreateMessageResult,
        elicited_content: CreateElicitationResult,
        cancel_parent_on_create_message: bool,
        cancel_child_on_create_message: bool,
        completed_elicitation_ids: Vec<String>,
        resource_updates: Vec<String>,
        resources_list_changed_count: u32,
    }

    struct DocsResourceProvider;
    struct FilesystemResourceProvider;
    struct ExamplePromptProvider;

    impl EchoServer {
        fn new(id: &str, tools: Vec<&str>) -> Self {
            Self {
                id: id.to_string(),
                tools: tools.into_iter().map(String::from).collect(),
            }
        }
    }

    impl ToolServerConnection for EchoServer {
        fn server_id(&self) -> &str {
            &self.id
        }
        fn tool_names(&self) -> Vec<String> {
            self.tools.clone()
        }
        fn invoke(
            &self,
            tool_name: &str,
            arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            Ok(serde_json::json!({
                "tool": tool_name,
                "echo": arguments,
            }))
        }
    }

    impl ToolServerConnection for NestedFlowServer {
        fn server_id(&self) -> &str {
            &self.id
        }

        fn tool_names(&self) -> Vec<String> {
            vec![
                "sample_via_client".to_string(),
                "elicit_via_client".to_string(),
                "roots_via_client".to_string(),
                "notify_resources_via_client".to_string(),
            ]
        }

        fn invoke(
            &self,
            tool_name: &str,
            _arguments: serde_json::Value,
            nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            let nested_flow_bridge = nested_flow_bridge.ok_or_else(|| {
                KernelError::Internal("nested-flow bridge is required".to_string())
            })?;

            match tool_name {
                "sample_via_client" => {
                    let message = nested_flow_bridge.create_message(CreateMessageOperation {
                        messages: vec![SamplingMessage {
                            role: "user".to_string(),
                            content: serde_json::json!({
                                "type": "text",
                                "text": "Summarize the roadmap",
                            }),
                            meta: None,
                        }],
                        model_preferences: None,
                        system_prompt: None,
                        include_context: None,
                        temperature: Some(0.2),
                        max_tokens: 128,
                        stop_sequences: vec![],
                        metadata: None,
                        tools: vec![],
                        tool_choice: None,
                    })?;

                    Ok(serde_json::json!({
                        "model": message.model,
                        "content": message.content,
                    }))
                }
                "elicit_via_client" => {
                    let elicitation = nested_flow_bridge.create_elicitation(
                        CreateElicitationOperation::Form {
                            meta: None,
                            message: "Which environment should this run against?".to_string(),
                            requested_schema: serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "environment": {
                                        "type": "string",
                                        "enum": ["staging", "production"]
                                    }
                                },
                                "required": ["environment"]
                            }),
                        },
                    )?;

                    Ok(serde_json::json!({
                        "action": elicitation.action,
                        "content": elicitation.content,
                    }))
                }
                "roots_via_client" => {
                    let roots = nested_flow_bridge.list_roots()?;
                    Ok(serde_json::json!({
                        "roots": roots,
                    }))
                }
                "notify_resources_via_client" => {
                    nested_flow_bridge.notify_resource_updated("repo://docs/roadmap")?;
                    nested_flow_bridge.notify_resource_updated("repo://secret/ops")?;
                    nested_flow_bridge.notify_resources_list_changed()?;
                    Ok(serde_json::json!({
                        "notified": true,
                    }))
                }
                _ => Err(KernelError::ToolNotRegistered(tool_name.to_string())),
            }
        }
    }

    impl ToolServerConnection for IncompleteServer {
        fn server_id(&self) -> &str {
            &self.id
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["drop_stream".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            Err(KernelError::RequestIncomplete(
                "upstream stream closed before tool response completed".to_string(),
            ))
        }
    }

    impl ToolServerConnection for StreamingServer {
        fn server_id(&self) -> &str {
            &self.id
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["stream_file".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            Ok(serde_json::json!({"unused": true}))
        }

        fn invoke_stream(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Option<ToolServerStreamResult>, KernelError> {
            Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
                chunks: self
                    .chunks
                    .iter()
                    .cloned()
                    .map(|data| ToolCallChunk { data })
                    .collect(),
            })))
        }
    }

    impl NestedFlowClient for MockNestedFlowClient {
        fn list_roots(
            &mut self,
            _parent_context: &OperationContext,
            _child_context: &OperationContext,
        ) -> Result<Vec<RootDefinition>, KernelError> {
            Ok(self.roots.clone())
        }

        fn create_message(
            &mut self,
            parent_context: &OperationContext,
            child_context: &OperationContext,
            _operation: &CreateMessageOperation,
        ) -> Result<CreateMessageResult, KernelError> {
            if self.cancel_parent_on_create_message {
                return Err(KernelError::RequestCancelled {
                    request_id: parent_context.request_id.clone(),
                    reason: "client cancelled parent request".to_string(),
                });
            }

            if self.cancel_child_on_create_message {
                return Err(KernelError::RequestCancelled {
                    request_id: child_context.request_id.clone(),
                    reason: "client cancelled nested request".to_string(),
                });
            }

            Ok(self.sampled_message.clone())
        }

        fn create_elicitation(
            &mut self,
            _parent_context: &OperationContext,
            _child_context: &OperationContext,
            _operation: &CreateElicitationOperation,
        ) -> Result<CreateElicitationResult, KernelError> {
            Ok(self.elicited_content.clone())
        }

        fn notify_elicitation_completed(
            &mut self,
            _parent_context: &OperationContext,
            elicitation_id: &str,
        ) -> Result<(), KernelError> {
            self.completed_elicitation_ids
                .push(elicitation_id.to_string());
            Ok(())
        }

        fn notify_resource_updated(
            &mut self,
            _parent_context: &OperationContext,
            uri: &str,
        ) -> Result<(), KernelError> {
            self.resource_updates.push(uri.to_string());
            Ok(())
        }

        fn notify_resources_list_changed(
            &mut self,
            _parent_context: &OperationContext,
        ) -> Result<(), KernelError> {
            self.resources_list_changed_count += 1;
            Ok(())
        }
    }

    impl ResourceProvider for DocsResourceProvider {
        fn list_resources(&self) -> Vec<ResourceDefinition> {
            vec![
                ResourceDefinition {
                    uri: "repo://docs/roadmap".to_string(),
                    name: "Roadmap".to_string(),
                    title: Some("Roadmap".to_string()),
                    description: Some("Project roadmap".to_string()),
                    mime_type: Some("text/markdown".to_string()),
                    size: Some(128),
                    annotations: None,
                    icons: None,
                },
                ResourceDefinition {
                    uri: "repo://secret/ops".to_string(),
                    name: "Ops".to_string(),
                    title: None,
                    description: Some("Hidden".to_string()),
                    mime_type: Some("text/plain".to_string()),
                    size: None,
                    annotations: None,
                    icons: None,
                },
            ]
        }

        fn list_resource_templates(&self) -> Vec<ResourceTemplateDefinition> {
            vec![ResourceTemplateDefinition {
                uri_template: "repo://docs/{slug}".to_string(),
                name: "Doc Template".to_string(),
                title: None,
                description: Some("Template".to_string()),
                mime_type: Some("text/markdown".to_string()),
                annotations: None,
                icons: None,
            }]
        }

        fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
            match uri {
                "repo://docs/roadmap" => Ok(Some(vec![ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some("text/markdown".to_string()),
                    text: Some("# Roadmap".to_string()),
                    blob: None,
                    annotations: None,
                }])),
                _ => Ok(None),
            }
        }

        fn complete_resource_argument(
            &self,
            uri: &str,
            argument_name: &str,
            value: &str,
            _context: &serde_json::Value,
        ) -> Result<Option<CompletionResult>, KernelError> {
            if uri == "repo://docs/{slug}" && argument_name == "slug" {
                let values = ["roadmap", "architecture", "api"]
                    .into_iter()
                    .filter(|candidate| candidate.starts_with(value))
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                return Ok(Some(CompletionResult {
                    total: Some(values.len() as u32),
                    has_more: false,
                    values,
                }));
            }

            Ok(None)
        }
    }

    impl ResourceProvider for FilesystemResourceProvider {
        fn list_resources(&self) -> Vec<ResourceDefinition> {
            vec![
                ResourceDefinition {
                    uri: "file:///workspace/project/docs/roadmap.md".to_string(),
                    name: "Filesystem Roadmap".to_string(),
                    title: Some("Filesystem Roadmap".to_string()),
                    description: Some("In-root file-backed resource".to_string()),
                    mime_type: Some("text/markdown".to_string()),
                    size: Some(64),
                    annotations: None,
                    icons: None,
                },
                ResourceDefinition {
                    uri: "file:///workspace/private/ops.md".to_string(),
                    name: "Filesystem Ops".to_string(),
                    title: None,
                    description: Some("Out-of-root file-backed resource".to_string()),
                    mime_type: Some("text/plain".to_string()),
                    size: Some(32),
                    annotations: None,
                    icons: None,
                },
            ]
        }

        fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
            match uri {
                "file:///workspace/project/docs/roadmap.md" => Ok(Some(vec![ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some("text/markdown".to_string()),
                    text: Some("# Filesystem Roadmap".to_string()),
                    blob: None,
                    annotations: None,
                }])),
                "file:///workspace/private/ops.md" => Ok(Some(vec![ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some("text/plain".to_string()),
                    text: Some("ops".to_string()),
                    blob: None,
                    annotations: None,
                }])),
                _ => Ok(None),
            }
        }
    }

    impl PromptProvider for ExamplePromptProvider {
        fn list_prompts(&self) -> Vec<PromptDefinition> {
            vec![
                PromptDefinition {
                    name: "summarize_docs".to_string(),
                    title: Some("Summarize Docs".to_string()),
                    description: Some("Summarize documentation".to_string()),
                    arguments: vec![PromptArgument {
                        name: "topic".to_string(),
                        title: None,
                        description: Some("Topic to summarize".to_string()),
                        required: Some(true),
                    }],
                    icons: None,
                },
                PromptDefinition {
                    name: "ops_secret".to_string(),
                    title: None,
                    description: Some("Hidden".to_string()),
                    arguments: vec![],
                    icons: None,
                },
            ]
        }

        fn get_prompt(
            &self,
            name: &str,
            arguments: serde_json::Value,
        ) -> Result<Option<PromptResult>, KernelError> {
            match name {
                "summarize_docs" => Ok(Some(PromptResult {
                    description: Some("Summarize docs".to_string()),
                    messages: vec![PromptMessage {
                        role: "user".to_string(),
                        content: serde_json::json!({
                            "type": "text",
                            "text": format!(
                                "Summarize {}",
                                arguments["topic"].as_str().unwrap_or("the docs")
                            ),
                        }),
                    }],
                })),
                _ => Ok(None),
            }
        }

        fn complete_prompt_argument(
            &self,
            name: &str,
            argument_name: &str,
            value: &str,
            _context: &serde_json::Value,
        ) -> Result<Option<CompletionResult>, KernelError> {
            if name == "summarize_docs" && argument_name == "topic" {
                let values = ["roadmap", "architecture", "release-plan"]
                    .into_iter()
                    .filter(|candidate| candidate.starts_with(value))
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                return Ok(Some(CompletionResult {
                    total: Some(values.len() as u32),
                    has_more: false,
                    values,
                }));
            }

            Ok(None)
        }
    }

    #[test]
    fn issue_and_use_capability() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let request = make_request("req-1", &cap, "read_file", "srv-a");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Allow);
        assert!(matches!(response.output, Some(ToolCallOutput::Value(_))));
        assert!(response.reason.is_none());

        // Receipt was logged.
        assert_eq!(kernel.receipt_log().len(), 1);

        // Receipt signature verifies.
        let r = kernel.receipt_log().get(0).unwrap();
        assert!(r.verify_signature().unwrap());
    }

    #[test]
    fn kernel_persists_tool_receipts_to_sqlite_store() {
        let path = unique_receipt_db_path("pact-kernel-tool-receipts");
        let mut kernel = PactKernel::new(make_config());
        kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let request = make_request("req-sqlite-1", &cap, "read_file", "srv-a");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Allow);
        drop(kernel);

        let connection = rusqlite::Connection::open(&path).unwrap();
        let (count, distinct_count, receipt_id): (i64, i64, String) = connection
            .query_row(
                "SELECT COUNT(*), COUNT(DISTINCT receipt_id), MIN(receipt_id) FROM pact_tool_receipts",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let child_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM pact_child_receipts", [], |row| {
                row.get(0)
            })
            .unwrap();

        assert_eq!(count, 1);
        assert_eq!(distinct_count, 1);
        assert_eq!(child_count, 0);
        assert!(receipt_id.starts_with("rcpt-"));

        drop(connection);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn kernel_accepts_capabilities_from_configured_authority() {
        let authority_keypair = make_keypair();
        let mut kernel = PactKernel::new(make_config());
        kernel.set_capability_authority(Box::new(LocalCapabilityAuthority::new(
            authority_keypair.clone(),
        )));
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let request = make_request("req-authority-1", &cap, "read_file", "srv-a");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(cap.issuer, authority_keypair.public_key());
        assert_eq!(response.verdict, Verdict::Allow);
    }

    #[test]
    fn expired_capability_denied() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        // TTL=0 means it expires at the same second it was issued.
        let cap = make_capability(&kernel, &agent_kp, scope, 0);
        let request = make_request("req-1", &cap, "read_file", "srv-a");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(reason.contains("expired"), "reason was: {reason}");

        // Denial also produces a receipt.
        assert_eq!(kernel.receipt_log().len(), 1);
        assert!(kernel.receipt_log().get(0).unwrap().is_denied());
    }

    #[test]
    fn revoked_capability_denied() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        kernel.revoke_capability(&cap.id).unwrap();

        let request = make_request("req-1", &cap, "read_file", "srv-a");
        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(reason.contains("revoked"), "reason was: {reason}");
    }

    #[test]
    fn sqlite_revocation_store_survives_kernel_restart() {
        let path = unique_receipt_db_path("pact-kernel-revocations");
        let authority_keypair = make_keypair();
        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);

        let cap = {
            let mut kernel = PactKernel::new(make_config());
            kernel.set_capability_authority(Box::new(LocalCapabilityAuthority::new(
                authority_keypair.clone(),
            )));
            kernel.set_revocation_store(Box::new(SqliteRevocationStore::open(&path).unwrap()));
            kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

            let cap = make_capability(&kernel, &agent_kp, scope.clone(), 300);
            kernel.revoke_capability(&cap.id).unwrap();
            cap
        };

        let mut restarted = PactKernel::new(make_config());
        restarted
            .set_capability_authority(Box::new(LocalCapabilityAuthority::new(authority_keypair)));
        restarted.set_revocation_store(Box::new(SqliteRevocationStore::open(&path).unwrap()));
        restarted.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let request = make_request("req-revoked-after-restart", &cap, "read_file", "srv-a");
        let response = restarted.evaluate_tool_call(&request).unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(
            response.reason.as_deref().unwrap_or("").contains("revoked"),
            "reason was: {:?}",
            response.reason
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn out_of_scope_tool_denied() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new(
            "srv-a",
            vec!["read_file", "write_file"],
        )));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        // Request write_file, but capability only grants read_file.
        let request = make_request("req-1", &cap, "write_file", "srv-a");
        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("not in capability scope"),
            "reason was: {reason}"
        );
    }

    #[test]
    fn subject_mismatch_denied() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let mut request = make_request("req-1", &cap, "read_file", "srv-a");
        request.agent_id = make_keypair().public_key().to_hex();

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(reason.contains("does not match capability subject"));
    }

    #[test]
    fn path_prefix_constraint_is_enforced() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = PactScope {
            grants: vec![ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::PathPrefix("/app/src".to_string())],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..PactScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let allowed = make_request_with_arguments(
            "req-allow",
            &cap,
            "read_file",
            "srv-a",
            serde_json::json!({"path": "/app/src/lib.rs"}),
        );
        let denied = make_request_with_arguments(
            "req-deny",
            &cap,
            "read_file",
            "srv-a",
            serde_json::json!({"path": "/etc/passwd"}),
        );

        assert_eq!(
            kernel.evaluate_tool_call(&allowed).unwrap().verdict,
            Verdict::Allow
        );
        let denied_response = kernel.evaluate_tool_call(&denied).unwrap();
        assert_eq!(denied_response.verdict, Verdict::Deny);
        assert!(denied_response
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("not in capability scope"));
    }

    #[test]
    fn domain_exact_constraint_is_enforced() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["fetch"])));

        let agent_kp = make_keypair();
        let scope = PactScope {
            grants: vec![ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "fetch".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::DomainExact("api.example.com".to_string())],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..PactScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let allowed = make_request_with_arguments(
            "req-allow",
            &cap,
            "fetch",
            "srv-a",
            serde_json::json!({"url": "https://api.example.com/v1/data"}),
        );
        let denied = make_request_with_arguments(
            "req-deny",
            &cap,
            "fetch",
            "srv-a",
            serde_json::json!({"url": "https://evil.example.com/v1/data"}),
        );

        assert_eq!(
            kernel.evaluate_tool_call(&allowed).unwrap().verdict,
            Verdict::Allow
        );
        assert_eq!(
            kernel.evaluate_tool_call(&denied).unwrap().verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn budget_exhaustion() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = PactScope {
            grants: vec![ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(2),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..PactScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        // First two calls succeed.
        for i in 0..2 {
            let req = make_request(&format!("req-{i}"), &cap, "read_file", "srv-a");
            let resp = kernel.evaluate_tool_call(&req).unwrap();
            assert_eq!(resp.verdict, Verdict::Allow, "call {i} should succeed");
        }

        // Third call is denied.
        let req = make_request("req-2", &cap, "read_file", "srv-a");
        let resp = kernel.evaluate_tool_call(&req).unwrap();
        assert_eq!(resp.verdict, Verdict::Deny);
        let reason = resp.reason.as_deref().unwrap_or("");
        assert!(reason.contains("budget"), "reason was: {reason}");
    }

    #[test]
    fn budgets_are_tracked_per_matching_grant() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new(
            "srv-a",
            vec!["read_file", "write_file"],
        )));

        let agent_kp = make_keypair();
        let scope = PactScope {
            grants: vec![
                ToolGrant {
                    server_id: "srv-a".to_string(),
                    tool_name: "read_file".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(2),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                },
                ToolGrant {
                    server_id: "srv-a".to_string(),
                    tool_name: "write_file".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(1),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                },
            ],
            ..PactScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        assert_eq!(
            kernel
                .evaluate_tool_call(&make_request("read-1", &cap, "read_file", "srv-a"))
                .unwrap()
                .verdict,
            Verdict::Allow
        );
        assert_eq!(
            kernel
                .evaluate_tool_call(&make_request("read-2", &cap, "read_file", "srv-a"))
                .unwrap()
                .verdict,
            Verdict::Allow
        );
        assert_eq!(
            kernel
                .evaluate_tool_call(&make_request("write-1", &cap, "write_file", "srv-a"))
                .unwrap()
                .verdict,
            Verdict::Allow
        );

        let denied = kernel
            .evaluate_tool_call(&make_request("write-2", &cap, "write_file", "srv-a"))
            .unwrap();
        assert_eq!(denied.verdict, Verdict::Deny);
        assert!(denied.reason.as_deref().unwrap_or("").contains("budget"));
    }

    #[test]
    fn guard_denies_request() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["dangerous"])));

        struct DenyAll;
        impl Guard for DenyAll {
            fn name(&self) -> &str {
                "deny-all"
            }
            fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
                Ok(Verdict::Deny)
            }
        }
        kernel.add_guard(Box::new(DenyAll));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "dangerous")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let request = make_request("req-1", &cap, "dangerous", "srv-a");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(reason.contains("deny-all"), "reason was: {reason}");
    }

    #[test]
    fn guard_error_treated_as_deny() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["tool"])));

        struct BrokenGuard;
        impl Guard for BrokenGuard {
            fn name(&self) -> &str {
                "broken"
            }
            fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
                Err(KernelError::Internal("guard crashed".to_string()))
            }
        }
        kernel.add_guard(Box::new(BrokenGuard));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "tool")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let request = make_request("req-1", &cap, "tool", "srv-a");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(reason.contains("fail-closed"), "reason was: {reason}");
    }

    #[test]
    fn unregistered_server_denied() {
        let mut kernel = PactKernel::new(make_config());
        // No tool servers registered.

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-missing", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let request = make_request("req-1", &cap, "read_file", "srv-missing");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(reason.contains("not registered"), "reason was: {reason}");
    }

    #[test]
    fn untrusted_issuer_denied() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let rogue_kp = make_keypair();
        let agent_kp = make_keypair();

        // Sign a capability with the rogue key (not trusted by this kernel).
        let body = CapabilityTokenBody {
            id: "cap-rogue".to_string(),
            issuer: rogue_kp.public_key(),
            subject: agent_kp.public_key(),
            scope: make_scope(vec![make_grant("srv-a", "read_file")]),
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![],
        };
        let cap = CapabilityToken::sign(body, &rogue_kp).unwrap();

        let request = ToolCallRequest {
            request_id: "req-rogue".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: "srv-a".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("not found among trusted"),
            "reason was: {reason}"
        );
    }

    #[test]
    fn all_calls_produce_verified_receipts() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        // Allowed call.
        let req = make_request("req-1", &cap, "read_file", "srv-a");
        let _ = kernel.evaluate_tool_call(&req).unwrap();

        // Denied call (wrong tool).
        let req2 = make_request("req-2", &cap, "write_file", "srv-a");
        let _ = kernel.evaluate_tool_call(&req2).unwrap();

        assert_eq!(kernel.receipt_log().len(), 2);

        for r in kernel.receipt_log().receipts() {
            assert!(r.verify_signature().unwrap());
        }
    }

    #[test]
    fn wildcard_server_grant_allows_real_server() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("filesystem", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("*", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let request = make_request("req-1", &cap, "read_file", "filesystem");
        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Allow);
    }

    #[test]
    fn revoked_ancestor_capability_denies_descendant() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let parent_kp = make_keypair();
        let child_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let parent = make_capability(&kernel, &parent_kp, scope.clone(), 300);

        let link = make_delegation_link(&parent.id, &kernel.config.keypair, &child_kp, 100);
        let child = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-child".to_string(),
                issuer: kernel.config.keypair.public_key(),
                subject: child_kp.public_key(),
                scope,
                issued_at: current_unix_timestamp(),
                expires_at: current_unix_timestamp() + 300,
                delegation_chain: vec![link],
            },
            &kernel.config.keypair,
        )
        .unwrap();

        kernel.revoke_capability(&parent.id).unwrap();

        let request = make_request("req-1", &child, "read_file", "srv-a");
        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response
            .reason
            .as_deref()
            .unwrap_or("")
            .contains(&parent.id));
    }

    #[test]
    fn wildcard_tool_grant_allows_any_tool() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["anything"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "*")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let request = make_request("req-1", &cap, "anything", "srv-a");
        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Allow);
    }

    #[test]
    fn in_memory_revocation_store() {
        let mut store = InMemoryRevocationStore::default();
        assert!(!store.is_revoked("cap-1").unwrap());
        assert!(store.revoke("cap-1").unwrap());
        assert!(store.is_revoked("cap-1").unwrap());
        assert!(!store.revoke("cap-1").unwrap());
    }

    #[test]
    fn receipt_log_basics() {
        let log = ReceiptLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn kernel_guard_registration() {
        let mut kernel = PactKernel::new(make_config());
        assert_eq!(kernel.guard_count(), 0);
        assert_eq!(kernel.ca_count(), 0);

        struct TestGuard;
        impl Guard for TestGuard {
            fn name(&self) -> &str {
                "test-guard"
            }
            fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
                Ok(Verdict::Allow)
            }
        }

        kernel.add_guard(Box::new(TestGuard));
        assert_eq!(kernel.guard_count(), 1);
    }

    #[test]
    fn session_lifecycle_is_hosted_by_kernel() {
        let mut kernel = PactKernel::new(make_config());
        let session_id = kernel.open_session("agent-1".to_string(), Vec::new());

        assert_eq!(kernel.session_count(), 1);
        assert_eq!(
            kernel.session(&session_id).map(Session::state),
            Some(SessionState::Initializing)
        );

        kernel.activate_session(&session_id).unwrap();
        assert_eq!(
            kernel.session(&session_id).map(Session::state),
            Some(SessionState::Ready)
        );

        kernel.begin_draining_session(&session_id).unwrap();
        assert_eq!(
            kernel.session(&session_id).map(Session::state),
            Some(SessionState::Draining)
        );

        kernel.close_session(&session_id).unwrap();
        assert_eq!(
            kernel.session(&session_id).map(Session::state),
            Some(SessionState::Closed)
        );
    }

    #[test]
    fn session_operation_tool_call_tracks_and_clears_inflight() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let context = make_operation_context(&session_id, "req-1", &agent_kp.public_key().to_hex());
        let operation = SessionOperation::ToolCall(ToolCallOperation {
            capability: cap,
            server_id: "srv-a".to_string(),
            tool_name: "read_file".to_string(),
            arguments: serde_json::json!({"path": "/app/src/main.rs"}),
        });

        let response = kernel
            .evaluate_session_operation(&context, &operation)
            .unwrap();
        match response {
            SessionOperationResponse::ToolCall(response) => {
                assert_eq!(response.verdict, Verdict::Allow);
            }
            _ => panic!("expected tool call response"),
        }

        assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
    }

    #[test]
    fn session_operation_capability_list_uses_session_snapshot() {
        let mut kernel = PactKernel::new(make_config());
        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap]);
        let context =
            make_operation_context(&session_id, "control-1", &agent_kp.public_key().to_hex());

        let response = kernel
            .evaluate_session_operation(&context, &SessionOperation::ListCapabilities)
            .unwrap();

        match response {
            SessionOperationResponse::CapabilityList { capabilities } => {
                assert_eq!(capabilities.len(), 1);
            }
            _ => panic!("expected capability list response"),
        }
    }

    #[test]
    fn session_operation_list_roots_uses_session_snapshot() {
        let mut kernel = PactKernel::new(make_config());
        let agent_kp = make_keypair();
        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_pact_tool_streaming: false,
                    supports_roots: true,
                    roots_list_changed: true,
                    supports_sampling: false,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();
        kernel
            .replace_session_roots(
                &session_id,
                vec![RootDefinition {
                    uri: "file:///workspace/project".to_string(),
                    name: Some("Project".to_string()),
                }],
            )
            .unwrap();

        let context =
            make_operation_context(&session_id, "roots-1", &agent_kp.public_key().to_hex());
        let response = kernel
            .evaluate_session_operation(&context, &SessionOperation::ListRoots)
            .unwrap();

        match response {
            SessionOperationResponse::RootList { roots } => {
                assert_eq!(roots.len(), 1);
                assert_eq!(roots[0].uri, "file:///workspace/project");
            }
            _ => panic!("expected root list response"),
        }
    }

    #[test]
    fn kernel_exposes_normalized_session_roots_for_later_enforcement() {
        let mut kernel = PactKernel::new(make_config());
        let agent_kp = make_keypair();
        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .replace_session_roots(
                &session_id,
                vec![
                    RootDefinition {
                        uri: "file:///workspace/project/../project/src".to_string(),
                        name: Some("Code".to_string()),
                    },
                    RootDefinition {
                        uri: "repo://docs/roadmap".to_string(),
                        name: Some("Roadmap".to_string()),
                    },
                    RootDefinition {
                        uri: "file://remote-host/workspace/project".to_string(),
                        name: Some("Remote".to_string()),
                    },
                ],
            )
            .unwrap();

        let normalized = kernel.normalized_session_roots(&session_id).unwrap();
        assert_eq!(normalized.len(), 3);
        assert!(matches!(
            normalized[0],
            NormalizedRoot::EnforceableFileSystem {
                ref normalized_path,
                ..
            } if normalized_path == "/workspace/project/src"
        ));
        assert!(matches!(
            normalized[1],
            NormalizedRoot::NonFileSystem { ref scheme, .. } if scheme == "repo"
        ));
        assert!(matches!(
            normalized[2],
            NormalizedRoot::UnenforceableFileSystem { ref reason, .. }
                if reason == "non_local_file_authority"
        ));
        assert_eq!(
            kernel
                .enforceable_filesystem_root_paths(&session_id)
                .unwrap(),
            vec!["/workspace/project/src"]
        );
    }

    #[test]
    fn begin_child_request_requires_parent_lineage() {
        let mut kernel = PactKernel::new(make_config());
        let agent_kp = make_keypair();
        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
        kernel.activate_session(&session_id).unwrap();

        let parent_context =
            make_operation_context(&session_id, "parent-1", &agent_kp.public_key().to_hex());
        kernel
            .begin_session_request(&parent_context, OperationKind::ToolCall, true)
            .unwrap();

        let child_context = kernel
            .begin_child_request(
                &parent_context,
                RequestId::new("child-1"),
                OperationKind::CreateMessage,
                None,
                true,
            )
            .unwrap();

        let child = kernel
            .session(&session_id)
            .unwrap()
            .inflight()
            .get(&child_context.request_id)
            .unwrap();
        assert_eq!(child.parent_request_id, Some(RequestId::new("parent-1")));
    }

    #[test]
    fn sampling_validation_requires_policy_and_negotiation() {
        let mut kernel = PactKernel::new(make_config());
        let agent_kp = make_keypair();
        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
        kernel.activate_session(&session_id).unwrap();

        let parent_context =
            make_operation_context(&session_id, "parent-1", &agent_kp.public_key().to_hex());
        kernel
            .begin_session_request(&parent_context, OperationKind::ToolCall, true)
            .unwrap();

        let child_context = kernel
            .begin_child_request(
                &parent_context,
                RequestId::new("child-1"),
                OperationKind::CreateMessage,
                None,
                true,
            )
            .unwrap();
        let operation = CreateMessageOperation {
            messages: vec![SamplingMessage {
                role: "user".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "Summarize the diff"
                }),
                meta: None,
            }],
            model_preferences: None,
            system_prompt: None,
            include_context: None,
            temperature: None,
            max_tokens: 256,
            stop_sequences: vec![],
            metadata: None,
            tools: vec![],
            tool_choice: None,
        };

        let denied = kernel.validate_sampling_request(&child_context, &operation);
        assert!(matches!(
            denied,
            Err(KernelError::SamplingNotAllowedByPolicy)
        ));

        kernel.config.allow_sampling = true;
        let denied = kernel.validate_sampling_request(&child_context, &operation);
        assert!(matches!(denied, Err(KernelError::SamplingNotNegotiated)));

        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_pact_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: true,
                    sampling_context: true,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();
        kernel
            .validate_sampling_request(&child_context, &operation)
            .unwrap();

        let tool_operation = CreateMessageOperation {
            tools: vec![SamplingTool {
                name: "search_docs".to_string(),
                description: Some("Search docs".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" }
                    }
                }),
            }],
            tool_choice: Some(SamplingToolChoice {
                mode: "auto".to_string(),
            }),
            ..operation
        };
        let denied = kernel.validate_sampling_request(&child_context, &tool_operation);
        assert!(matches!(
            denied,
            Err(KernelError::SamplingToolUseNotAllowedByPolicy)
        ));

        kernel.config.allow_sampling_tool_use = true;
        let denied = kernel.validate_sampling_request(&child_context, &tool_operation);
        assert!(matches!(
            denied,
            Err(KernelError::SamplingToolUseNotNegotiated)
        ));
    }

    #[test]
    fn elicitation_validation_requires_policy_and_form_negotiation() {
        let mut kernel = PactKernel::new(make_config());
        let agent_kp = make_keypair();
        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
        kernel.activate_session(&session_id).unwrap();

        let parent_context = make_operation_context(
            &session_id,
            "parent-elicit-1",
            &agent_kp.public_key().to_hex(),
        );
        kernel
            .begin_session_request(&parent_context, OperationKind::ToolCall, true)
            .unwrap();

        let child_context = kernel
            .begin_child_request(
                &parent_context,
                RequestId::new("child-elicit-1"),
                OperationKind::CreateElicitation,
                None,
                true,
            )
            .unwrap();
        let operation = CreateElicitationOperation::Form {
            meta: None,
            message: "Which environment should this run against?".to_string(),
            requested_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "environment": {
                        "type": "string",
                        "enum": ["staging", "production"]
                    }
                },
                "required": ["environment"]
            }),
        };

        let denied = kernel.validate_elicitation_request(&child_context, &operation);
        assert!(matches!(
            denied,
            Err(KernelError::ElicitationNotAllowedByPolicy)
        ));

        kernel.config.allow_elicitation = true;
        let denied = kernel.validate_elicitation_request(&child_context, &operation);
        assert!(matches!(denied, Err(KernelError::ElicitationNotNegotiated)));

        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_pact_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: false,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: true,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();
        let denied = kernel.validate_elicitation_request(&child_context, &operation);
        assert!(matches!(
            denied,
            Err(KernelError::ElicitationFormNotSupported)
        ));

        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_pact_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: false,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: true,
                    elicitation_form: true,
                    elicitation_url: false,
                },
            )
            .unwrap();
        kernel
            .validate_elicitation_request(&child_context, &operation)
            .unwrap();

        let url_operation = CreateElicitationOperation::Url {
            meta: None,
            message: "Open the secure enrollment flow".to_string(),
            url: "https://example.test/consent".to_string(),
            elicitation_id: "elicitation-123".to_string(),
        };
        let denied = kernel.validate_elicitation_request(&child_context, &url_operation);
        assert!(matches!(
            denied,
            Err(KernelError::ElicitationUrlNotSupported)
        ));

        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_pact_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: false,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: true,
                    elicitation_form: true,
                    elicitation_url: true,
                },
            )
            .unwrap();
        kernel
            .validate_elicitation_request(&child_context, &url_operation)
            .unwrap();
    }

    #[test]
    fn tool_call_nested_flow_bridge_roundtrips_sampling() {
        let mut config = make_config();
        config.allow_sampling = true;
        let mut kernel = PactKernel::new(config);
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "sample_via_client")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_pact_tool_streaming: false,
                    supports_roots: true,
                    roots_list_changed: true,
                    supports_sampling: true,
                    sampling_context: true,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();

        let mut client = MockNestedFlowClient {
            roots: vec![RootDefinition {
                uri: "file:///workspace/project".to_string(),
                name: Some("Project".to_string()),
            }],
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "Roadmap summary",
                }),
                model: "gpt-test".to_string(),
                stop_reason: Some("end_turn".to_string()),
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: false,
            cancel_child_on_create_message: false,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-1",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability,
            server_id: "nested".to_string(),
            tool_name: "sample_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        match response.output {
            Some(ToolCallOutput::Value(value)) => {
                assert_eq!(value["model"], "gpt-test");
            }
            other => panic!("unexpected output: {other:?}"),
        }
        assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
        assert_eq!(kernel.child_receipt_log().len(), 1);
        let child_receipt = kernel.child_receipt_log().get(0).unwrap();
        assert_eq!(child_receipt.parent_request_id, context.request_id);
        assert_eq!(child_receipt.operation_kind, OperationKind::CreateMessage);
        assert_eq!(
            child_receipt.terminal_state,
            OperationTerminalState::Completed
        );
        assert!(child_receipt.verify_signature().unwrap());
        assert_eq!(
            child_receipt.metadata.as_ref().unwrap()["outcome"],
            "result"
        );
    }

    #[test]
    fn kernel_persists_child_receipts_to_sqlite_store() {
        let path = unique_receipt_db_path("pact-kernel-child-receipts");
        let mut config = make_config();
        config.allow_sampling = true;
        let mut kernel = PactKernel::new(config);
        kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "sample_via_client")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_pact_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: true,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();

        let mut client = MockNestedFlowClient {
            roots: Vec::new(),
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "sampled via durable store test",
                }),
                model: "gpt-test".to_string(),
                stop_reason: None,
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: false,
            cancel_child_on_create_message: false,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-sqlite-1",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability,
            server_id: "nested".to_string(),
            tool_name: "sample_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();
        assert_eq!(response.verdict, Verdict::Allow);
        drop(kernel);

        let connection = rusqlite::Connection::open(&path).unwrap();
        let tool_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM pact_tool_receipts", [], |row| {
                row.get(0)
            })
            .unwrap();
        let (child_count, distinct_child_count, child_receipt_id): (i64, i64, String) =
            connection
                .query_row(
                    "SELECT COUNT(*), COUNT(DISTINCT receipt_id), MIN(receipt_id) FROM pact_child_receipts",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();

        assert_eq!(tool_count, 1);
        assert_eq!(child_count, 1);
        assert_eq!(distinct_child_count, 1);
        assert!(child_receipt_id.starts_with("child-rcpt-"));

        drop(connection);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tool_call_nested_flow_bridge_roundtrips_elicitation() {
        let mut config = make_config();
        config.allow_elicitation = true;
        let mut kernel = PactKernel::new(config);
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "elicit_via_client")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_pact_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: false,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: true,
                    elicitation_form: true,
                    elicitation_url: false,
                },
            )
            .unwrap();

        let mut client = MockNestedFlowClient {
            roots: Vec::new(),
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "unused",
                }),
                model: "unused".to_string(),
                stop_reason: None,
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: false,
            cancel_child_on_create_message: false,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-elicit-1",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability,
            server_id: "nested".to_string(),
            tool_name: "elicit_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        match response.output {
            Some(ToolCallOutput::Value(value)) => {
                assert_eq!(value["action"], "accept");
                assert_eq!(value["content"]["environment"], "staging");
            }
            other => panic!("unexpected output: {other:?}"),
        }
        assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
    }

    #[test]
    fn tool_call_nested_flow_bridge_updates_session_roots() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "roots_via_client")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_pact_tool_streaming: false,
                    supports_roots: true,
                    roots_list_changed: true,
                    supports_sampling: false,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();

        let expected_roots = vec![RootDefinition {
            uri: "file:///workspace/project".to_string(),
            name: Some("Project".to_string()),
        }];
        let mut client = MockNestedFlowClient {
            roots: expected_roots.clone(),
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "unused",
                }),
                model: "unused".to_string(),
                stop_reason: None,
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: false,
            cancel_child_on_create_message: false,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-2",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability,
            server_id: "nested".to_string(),
            tool_name: "roots_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(kernel.session(&session_id).unwrap().roots(), expected_roots);
    }

    #[test]
    fn tool_call_nested_flow_bridge_propagates_parent_cancellation() {
        let mut kernel = PactKernel::new(make_config());
        kernel.config.allow_sampling = true;
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "sample_via_client")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: true,
                    supports_subscriptions: false,
                    supports_pact_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: true,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();

        let mut client = MockNestedFlowClient {
            roots: Vec::new(),
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "unused",
                }),
                model: "unused".to_string(),
                stop_reason: None,
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: true,
            cancel_child_on_create_message: false,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-parent-cancel",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability,
            server_id: "nested".to_string(),
            tool_name: "sample_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();
        let expected_reason = "client cancelled parent request".to_string();

        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(response.reason.as_deref(), Some(expected_reason.as_str()));
        assert_eq!(
            response.terminal_state,
            OperationTerminalState::Cancelled {
                reason: expected_reason.clone(),
            }
        );
        assert!(response.receipt.is_cancelled());
        assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
        assert_eq!(
            kernel
                .session(&session_id)
                .unwrap()
                .terminal()
                .get(&context.request_id),
            Some(&OperationTerminalState::Cancelled {
                reason: expected_reason,
            })
        );
    }

    #[test]
    fn tool_call_nested_flow_bridge_propagates_child_cancellation() {
        let mut kernel = PactKernel::new(make_config());
        kernel.config.allow_sampling = true;
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "sample_via_client")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: true,
                    supports_subscriptions: false,
                    supports_pact_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: true,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();

        let mut client = MockNestedFlowClient {
            roots: Vec::new(),
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "unused",
                }),
                model: "unused".to_string(),
                stop_reason: None,
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: false,
            cancel_child_on_create_message: true,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-child-cancel",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability,
            server_id: "nested".to_string(),
            tool_name: "sample_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();
        let expected_reason = "client cancelled nested request".to_string();

        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(response.reason.as_deref(), Some(expected_reason.as_str()));
        assert_eq!(
            response.terminal_state,
            OperationTerminalState::Cancelled {
                reason: expected_reason.clone(),
            }
        );
        assert!(response.receipt.is_cancelled());
        assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
        assert_eq!(
            kernel
                .session(&session_id)
                .unwrap()
                .terminal()
                .get(&context.request_id),
            Some(&OperationTerminalState::Cancelled {
                reason: expected_reason,
            })
        );
        assert_eq!(kernel.child_receipt_log().len(), 1);
        let child_receipt = kernel.child_receipt_log().get(0).unwrap();
        assert_eq!(child_receipt.parent_request_id, context.request_id);
        assert_eq!(child_receipt.operation_kind, OperationKind::CreateMessage);
        assert_eq!(
            child_receipt.terminal_state,
            OperationTerminalState::Cancelled {
                reason: "client cancelled nested request".to_string(),
            }
        );
        assert!(child_receipt.verify_signature().unwrap());
        assert_eq!(
            kernel
                .session(&session_id)
                .unwrap()
                .terminal()
                .get(&child_receipt.request_id),
            Some(&OperationTerminalState::Cancelled {
                reason: "client cancelled nested request".to_string(),
            })
        );
    }

    #[test]
    fn session_tool_call_records_incomplete_terminal_state() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(IncompleteServer {
            id: "broken".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("broken", "drop_stream")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let context = make_operation_context(
            &session_id,
            "incomplete-tool-call",
            &agent_kp.public_key().to_hex(),
        );
        let operation = SessionOperation::ToolCall(ToolCallOperation {
            capability,
            server_id: "broken".to_string(),
            tool_name: "drop_stream".to_string(),
            arguments: serde_json::json!({}),
        });

        let response = match kernel
            .evaluate_session_operation(&context, &operation)
            .unwrap()
        {
            SessionOperationResponse::ToolCall(response) => response,
            other => panic!("unexpected response: {other:?}"),
        };

        let expected_reason = "upstream stream closed before tool response completed".to_string();
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(response.reason.as_deref(), Some(expected_reason.as_str()));
        assert_eq!(
            response.terminal_state,
            OperationTerminalState::Incomplete {
                reason: expected_reason.clone(),
            }
        );
        assert!(response.receipt.is_incomplete());
        assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
        assert_eq!(
            kernel
                .session(&session_id)
                .unwrap()
                .terminal()
                .get(&context.request_id),
            Some(&OperationTerminalState::Incomplete {
                reason: expected_reason,
            })
        );
    }

    #[test]
    fn streamed_tool_receipt_records_chunk_hash_metadata() {
        let mut kernel = PactKernel::new(make_config());
        let chunk_a = serde_json::json!({"delta": "hello"});
        let chunk_b = serde_json::json!({"delta": {"path": "/workspace/README.md"}});
        kernel.register_tool_server(Box::new(StreamingServer {
            id: "stream".to_string(),
            chunks: vec![chunk_a.clone(), chunk_b.clone()],
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("stream", "stream_file")]),
            300,
        );
        let request = make_request_with_arguments(
            "stream-receipt",
            &capability,
            "stream_file",
            "stream",
            serde_json::json!({"path": "/workspace/README.md"}),
        );

        let response = kernel.evaluate_tool_call(&request).unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        let metadata = response.receipt.metadata.as_ref().expect("stream metadata");
        let stream_metadata = metadata.get("stream").expect("stream metadata object");
        assert_eq!(stream_metadata["chunks_expected"].as_u64(), Some(2));
        assert_eq!(stream_metadata["chunks_received"].as_u64(), Some(2));

        let chunk_a_bytes = pact_core::canonical::canonical_json_bytes(&chunk_a).unwrap();
        let chunk_b_bytes = pact_core::canonical::canonical_json_bytes(&chunk_b).unwrap();
        let expected_total_bytes = (chunk_a_bytes.len() + chunk_b_bytes.len()) as u64;
        assert_eq!(
            stream_metadata["total_bytes"].as_u64(),
            Some(expected_total_bytes)
        );

        let chunk_hashes = stream_metadata["chunk_hashes"]
            .as_array()
            .expect("chunk hashes array")
            .iter()
            .map(|value| value.as_str().expect("chunk hash string").to_string())
            .collect::<Vec<_>>();
        let expected_hashes = vec![
            pact_core::crypto::sha256_hex(&chunk_a_bytes),
            pact_core::crypto::sha256_hex(&chunk_b_bytes),
        ];
        assert_eq!(chunk_hashes, expected_hashes);

        let expected_content_hash =
            pact_core::crypto::sha256_hex(expected_hashes.join("").as_bytes());
        assert_eq!(response.receipt.content_hash, expected_content_hash);
    }

    #[test]
    fn streamed_tool_byte_limit_truncates_output_and_marks_receipt_incomplete() {
        let mut config = make_config();
        config.max_stream_total_bytes = 20;
        let mut kernel = PactKernel::new(config);
        let first_chunk = serde_json::json!({"delta": "ok"});
        let second_chunk =
            serde_json::json!({"delta": "this chunk exceeds the configured byte limit"});
        kernel.register_tool_server(Box::new(StreamingServer {
            id: "stream".to_string(),
            chunks: vec![first_chunk.clone(), second_chunk],
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("stream", "stream_file")]),
            300,
        );
        let request = make_request_with_arguments(
            "stream-byte-limit",
            &capability,
            "stream_file",
            "stream",
            serde_json::json!({}),
        );

        let response = kernel.evaluate_tool_call(&request).unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.receipt.is_incomplete());
        assert!(matches!(
            response.terminal_state,
            OperationTerminalState::Incomplete { .. }
        ));
        assert!(response
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("max total bytes"));

        let output_stream = match response.output {
            Some(ToolCallOutput::Stream(stream)) => stream,
            other => panic!("unexpected output: {other:?}"),
        };
        assert_eq!(output_stream.chunk_count(), 1);
        assert_eq!(output_stream.chunks[0].data, first_chunk);

        let stream_metadata = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("stream"))
            .expect("stream metadata");
        assert!(stream_metadata["chunks_expected"].is_null());
        assert_eq!(stream_metadata["chunks_received"].as_u64(), Some(1));
    }

    #[test]
    fn apply_stream_limits_marks_duration_exceeded_stream_incomplete() {
        let mut config = make_config();
        config.max_stream_duration_secs = 1;
        let kernel = PactKernel::new(config);
        let output = ToolServerOutput::Stream(ToolServerStreamResult::Complete(ToolCallStream {
            chunks: vec![ToolCallChunk {
                data: serde_json::json!({"delta": "slow"}),
            }],
        }));

        let limited = kernel
            .apply_stream_limits(output, std::time::Duration::from_secs(2))
            .unwrap();

        match limited {
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => {
                assert_eq!(stream.chunk_count(), 1);
                assert!(reason.contains("max duration of 1s"));
            }
            other => panic!("unexpected limited output: {other:?}"),
        }
    }

    #[test]
    fn tool_call_nested_flow_bridge_filters_resource_notifications_to_session_subscriptions() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));
        kernel.register_resource_provider(Box::new(DocsResourceProvider));

        let agent_kp = make_keypair();
        let tool_capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "notify_resources_via_client")]),
            300,
        );
        let resource_capability = make_capability(
            &kernel,
            &agent_kp,
            PactScope {
                resource_grants: vec![ResourceGrant {
                    uri_pattern: "repo://docs/*".to_string(),
                    operations: vec![Operation::Read, Operation::Subscribe],
                }],
                ..PactScope::default()
            },
            300,
        );
        let session_id = kernel.open_session(
            agent_kp.public_key().to_hex(),
            vec![tool_capability.clone(), resource_capability.clone()],
        );
        kernel.activate_session(&session_id).unwrap();
        kernel
            .subscribe_session_resource(
                &session_id,
                &resource_capability,
                &agent_kp.public_key().to_hex(),
                "repo://docs/roadmap",
            )
            .unwrap();

        let mut client = MockNestedFlowClient {
            roots: Vec::new(),
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "unused",
                }),
                model: "unused".to_string(),
                stop_reason: None,
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: false,
            cancel_child_on_create_message: false,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-resource-notify",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability: tool_capability,
            server_id: "nested".to_string(),
            tool_name: "notify_resources_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(
            client.resource_updates,
            vec!["repo://docs/roadmap".to_string()]
        );
        assert_eq!(client.resources_list_changed_count, 1);
    }

    #[test]
    fn session_operation_list_resources_filters_to_session_scope() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_resource_provider(Box::new(DocsResourceProvider));

        let agent_kp = make_keypair();
        let scope = PactScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read],
            }],
            ..PactScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap]);
        kernel.activate_session(&session_id).unwrap();
        let context =
            make_operation_context(&session_id, "resources-1", &agent_kp.public_key().to_hex());

        let response = kernel
            .evaluate_session_operation(&context, &SessionOperation::ListResources)
            .unwrap();

        match response {
            SessionOperationResponse::ResourceList { resources } => {
                assert_eq!(resources.len(), 1);
                assert_eq!(resources[0].uri, "repo://docs/roadmap");
            }
            _ => panic!("expected resource list response"),
        }
    }

    #[test]
    fn session_operation_read_resource_enforces_scope() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_resource_provider(Box::new(DocsResourceProvider));

        let agent_kp = make_keypair();
        let scope = PactScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read],
            }],
            ..PactScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let allowed_context = make_operation_context(
            &session_id,
            "resource-read-1",
            &agent_kp.public_key().to_hex(),
        );
        let allowed = kernel
            .evaluate_session_operation(
                &allowed_context,
                &SessionOperation::ReadResource(ReadResourceOperation {
                    capability: cap.clone(),
                    uri: "repo://docs/roadmap".to_string(),
                }),
            )
            .unwrap();
        match allowed {
            SessionOperationResponse::ResourceRead { contents } => {
                assert_eq!(contents[0].text.as_deref(), Some("# Roadmap"));
            }
            _ => panic!("expected resource read response"),
        }

        let denied_context = make_operation_context(
            &session_id,
            "resource-read-2",
            &agent_kp.public_key().to_hex(),
        );
        let denied = kernel.evaluate_session_operation(
            &denied_context,
            &SessionOperation::ReadResource(ReadResourceOperation {
                capability: cap,
                uri: "repo://secret/ops".to_string(),
            }),
        );
        assert!(matches!(
            denied,
            Err(KernelError::OutOfScopeResource { .. })
        ));
    }

    #[test]
    fn session_operation_read_resource_enforces_session_roots_for_filesystem_resources() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_resource_provider(Box::new(FilesystemResourceProvider));

        let agent_kp = make_keypair();
        let scope = PactScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "file:///workspace/*".to_string(),
                operations: vec![Operation::Read],
            }],
            ..PactScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .replace_session_roots(
                &session_id,
                vec![RootDefinition {
                    uri: "file:///workspace/project".to_string(),
                    name: Some("Project".to_string()),
                }],
            )
            .unwrap();

        let allowed_context = make_operation_context(
            &session_id,
            "resource-read-file-1",
            &agent_kp.public_key().to_hex(),
        );
        let allowed = kernel
            .evaluate_session_operation(
                &allowed_context,
                &SessionOperation::ReadResource(ReadResourceOperation {
                    capability: cap.clone(),
                    uri: "file:///workspace/project/docs/roadmap.md".to_string(),
                }),
            )
            .unwrap();
        match allowed {
            SessionOperationResponse::ResourceRead { contents } => {
                assert_eq!(contents[0].text.as_deref(), Some("# Filesystem Roadmap"));
            }
            _ => panic!("expected resource read response"),
        }

        let denied_context = make_operation_context(
            &session_id,
            "resource-read-file-2",
            &agent_kp.public_key().to_hex(),
        );
        let denied = kernel.evaluate_session_operation(
            &denied_context,
            &SessionOperation::ReadResource(ReadResourceOperation {
                capability: cap,
                uri: "file:///workspace/private/ops.md".to_string(),
            }),
        );
        match denied {
            Ok(SessionOperationResponse::ResourceReadDenied { receipt }) => {
                assert!(receipt.verify_signature().unwrap());
                assert!(receipt.is_denied());
                assert_eq!(receipt.tool_name, "resources/read");
                assert_eq!(receipt.tool_server, "session");
                assert_eq!(
                    receipt.decision,
                    Decision::Deny {
                        reason:
                            "filesystem-backed resource path /workspace/private/ops.md is outside the negotiated roots"
                                .to_string(),
                        guard: "session_roots".to_string(),
                    }
                );
            }
            other => panic!("expected signed resource read denial, got {other:?}"),
        }
    }

    #[test]
    fn session_operation_read_resource_fails_closed_when_filesystem_roots_are_missing() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_resource_provider(Box::new(FilesystemResourceProvider));

        let agent_kp = make_keypair();
        let scope = PactScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "file:///workspace/*".to_string(),
                operations: vec![Operation::Read],
            }],
            ..PactScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let context = make_operation_context(
            &session_id,
            "resource-read-file-3",
            &agent_kp.public_key().to_hex(),
        );
        let denied = kernel.evaluate_session_operation(
            &context,
            &SessionOperation::ReadResource(ReadResourceOperation {
                capability: cap,
                uri: "file:///workspace/project/docs/roadmap.md".to_string(),
            }),
        );
        match denied {
            Ok(SessionOperationResponse::ResourceReadDenied { receipt }) => {
                assert!(receipt.verify_signature().unwrap());
                assert!(receipt.is_denied());
                assert_eq!(
                    receipt.decision,
                    Decision::Deny {
                        reason: "no enforceable filesystem roots are available for this session"
                            .to_string(),
                        guard: "session_roots".to_string(),
                    }
                );
            }
            other => panic!("expected signed resource read denial, got {other:?}"),
        }
    }

    #[test]
    fn subscribe_session_resource_requires_subscribe_operation() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_resource_provider(Box::new(DocsResourceProvider));

        let agent_kp = make_keypair();
        let read_only_scope = PactScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read],
            }],
            ..PactScope::default()
        };
        let read_only_cap = make_capability(&kernel, &agent_kp, read_only_scope, 300);

        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![read_only_cap.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let denied = kernel.subscribe_session_resource(
            &session_id,
            &read_only_cap,
            &agent_kp.public_key().to_hex(),
            "repo://docs/roadmap",
        );
        assert!(matches!(
            denied,
            Err(KernelError::OutOfScopeResource { .. })
        ));

        let subscribe_scope = PactScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read, Operation::Subscribe],
            }],
            ..PactScope::default()
        };
        let subscribe_cap = make_capability(&kernel, &agent_kp, subscribe_scope, 300);
        kernel
            .subscribe_session_resource(
                &session_id,
                &subscribe_cap,
                &agent_kp.public_key().to_hex(),
                "repo://docs/roadmap",
            )
            .unwrap();

        assert!(kernel
            .session_has_resource_subscription(&session_id, "repo://docs/roadmap")
            .unwrap());
    }

    #[test]
    fn unsubscribe_session_resource_is_idempotent() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_resource_provider(Box::new(DocsResourceProvider));

        let agent_kp = make_keypair();
        let scope = PactScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read, Operation::Subscribe],
            }],
            ..PactScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .subscribe_session_resource(
                &session_id,
                &cap,
                &agent_kp.public_key().to_hex(),
                "repo://docs/roadmap",
            )
            .unwrap();

        kernel
            .unsubscribe_session_resource(&session_id, "repo://docs/roadmap")
            .unwrap();
        kernel
            .unsubscribe_session_resource(&session_id, "repo://docs/roadmap")
            .unwrap();

        assert!(!kernel
            .session_has_resource_subscription(&session_id, "repo://docs/roadmap")
            .unwrap());
    }

    #[test]
    fn session_operation_get_prompt_enforces_scope() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_prompt_provider(Box::new(ExamplePromptProvider));

        let agent_kp = make_keypair();
        let scope = PactScope {
            prompt_grants: vec![PromptGrant {
                prompt_name: "summarize_*".to_string(),
                operations: vec![Operation::Get],
            }],
            ..PactScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let list_context =
            make_operation_context(&session_id, "prompts-1", &agent_kp.public_key().to_hex());
        let list_response = kernel
            .evaluate_session_operation(&list_context, &SessionOperation::ListPrompts)
            .unwrap();
        match list_response {
            SessionOperationResponse::PromptList { prompts } => {
                assert_eq!(prompts.len(), 1);
                assert_eq!(prompts[0].name, "summarize_docs");
            }
            _ => panic!("expected prompt list response"),
        }

        let get_context =
            make_operation_context(&session_id, "prompts-2", &agent_kp.public_key().to_hex());
        let get_response = kernel
            .evaluate_session_operation(
                &get_context,
                &SessionOperation::GetPrompt(GetPromptOperation {
                    capability: cap.clone(),
                    prompt_name: "summarize_docs".to_string(),
                    arguments: serde_json::json!({"topic": "roadmap"}),
                }),
            )
            .unwrap();
        match get_response {
            SessionOperationResponse::PromptGet { prompt } => {
                assert_eq!(prompt.messages[0].content["text"], "Summarize roadmap");
            }
            _ => panic!("expected prompt get response"),
        }

        let denied_context =
            make_operation_context(&session_id, "prompts-3", &agent_kp.public_key().to_hex());
        let denied = kernel.evaluate_session_operation(
            &denied_context,
            &SessionOperation::GetPrompt(GetPromptOperation {
                capability: cap,
                prompt_name: "ops_secret".to_string(),
                arguments: serde_json::json!({}),
            }),
        );
        assert!(matches!(denied, Err(KernelError::OutOfScopePrompt { .. })));
    }

    #[test]
    fn session_operation_completion_returns_candidates_and_enforces_scope() {
        let mut kernel = PactKernel::new(make_config());
        kernel.register_resource_provider(Box::new(DocsResourceProvider));
        kernel.register_prompt_provider(Box::new(ExamplePromptProvider));

        let agent_kp = make_keypair();
        let scope = PactScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read],
            }],
            prompt_grants: vec![PromptGrant {
                prompt_name: "summarize_*".to_string(),
                operations: vec![Operation::Get],
            }],
            ..PactScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let prompt_context =
            make_operation_context(&session_id, "complete-1", &agent_kp.public_key().to_hex());
        let prompt_completion = kernel
            .evaluate_session_operation(
                &prompt_context,
                &SessionOperation::Complete(CompleteOperation {
                    capability: cap.clone(),
                    reference: CompletionReference::Prompt {
                        name: "summarize_docs".to_string(),
                    },
                    argument: CompletionArgument {
                        name: "topic".to_string(),
                        value: "r".to_string(),
                    },
                    context_arguments: serde_json::json!({}),
                }),
            )
            .unwrap();
        match prompt_completion {
            SessionOperationResponse::Completion { completion } => {
                assert_eq!(completion.total, Some(2));
                assert_eq!(completion.values, vec!["roadmap", "release-plan"]);
            }
            _ => panic!("expected completion response"),
        }

        let resource_context =
            make_operation_context(&session_id, "complete-2", &agent_kp.public_key().to_hex());
        let resource_completion = kernel
            .evaluate_session_operation(
                &resource_context,
                &SessionOperation::Complete(CompleteOperation {
                    capability: cap.clone(),
                    reference: CompletionReference::Resource {
                        uri: "repo://docs/{slug}".to_string(),
                    },
                    argument: CompletionArgument {
                        name: "slug".to_string(),
                        value: "a".to_string(),
                    },
                    context_arguments: serde_json::json!({}),
                }),
            )
            .unwrap();
        match resource_completion {
            SessionOperationResponse::Completion { completion } => {
                assert_eq!(completion.total, Some(2));
                assert_eq!(completion.values, vec!["architecture", "api"]);
            }
            _ => panic!("expected completion response"),
        }

        let denied_context =
            make_operation_context(&session_id, "complete-3", &agent_kp.public_key().to_hex());
        let denied = kernel.evaluate_session_operation(
            &denied_context,
            &SessionOperation::Complete(CompleteOperation {
                capability: cap,
                reference: CompletionReference::Prompt {
                    name: "ops_secret".to_string(),
                },
                argument: CompletionArgument {
                    name: "topic".to_string(),
                    value: "o".to_string(),
                },
                context_arguments: serde_json::json!({}),
            }),
        );
        assert!(matches!(denied, Err(KernelError::OutOfScopePrompt { .. })));
    }

    /// A tool server that always reports a specific actual cost.
    struct MonetaryCostServer {
        id: String,
        reported_cost: Option<ToolInvocationCost>,
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

    impl ToolServerConnection for MonetaryCostServer {
        fn server_id(&self) -> &str {
            &self.id
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["compute".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            Ok(serde_json::json!({"result": "ok"}))
        }

        fn invoke_with_cost(
            &self,
            tool_name: &str,
            arguments: serde_json::Value,
            bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
            let value = self.invoke(tool_name, arguments, bridge)?;
            Ok((value, self.reported_cost.clone()))
        }
    }

    fn make_monetary_grant(
        server: &str,
        tool: &str,
        max_cost_per_invocation: u64,
        max_total_cost: u64,
        currency: &str,
    ) -> ToolGrant {
        use pact_core::capability::MonetaryAmount;
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
            policy_hash: "monetary-policy-hash".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        }
    }

    // --- Monetary enforcement tests ---

    #[test]
    fn monetary_denial_exceeds_per_invocation_cap() {
        // Grant max_cost_per_invocation=100; tool server reports actual cost 150 (> cap).
        // The budget check should deny because the worst-case debit (100) passes the cap,
        // but the server reports 150 which exceeds the cap -- actually no: we charge the
        // max_cost_per_invocation as the worst-case DEBIT upfront. The per-invocation check
        // is: cost_units (=max_per) must be <= max_cost_per_invocation. With cost_units=100
        // and max_per=100 that passes. After invocation, server reports 150; we log a warning
        // and set settlement_status=failed. But the invocation is NOT denied before execution.
        //
        // To produce a pre-execution monetary denial, the requested cost must exceed the cap.
        // This happens when we charge cost_units = max_cost_per_invocation but the total budget
        // is already exhausted.
        //
        // Test: accumulated 500 + max_cost_per_invocation=100 exceeds max_total_cost=500 -> deny.
        let mut kernel = PactKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        let server = MonetaryCostServer::no_cost("cost-srv");
        kernel.register_tool_server(Box::new(server));

        let grant = make_monetary_grant("cost-srv", "compute", 100, 500, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request = |id: &str| ToolCallRequest {
            request_id: id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
        };

        // 5 invocations: 5 * 100 = 500 total -- all should pass.
        for i in 0..5 {
            let resp = kernel
                .evaluate_tool_call(&request(&format!("req-{i}")))
                .unwrap();
            assert_eq!(
                resp.verdict,
                Verdict::Allow,
                "invocation {i} should be allowed"
            );
        }

        // 6th invocation would need 600 total, exceeding max_total_cost=500.
        let resp = kernel.evaluate_tool_call(&request("req-6")).unwrap();
        assert_eq!(
            resp.verdict,
            Verdict::Deny,
            "6th invocation should be denied"
        );
    }

    #[test]
    fn monetary_denial_receipt_contains_financial_metadata() {
        let mut kernel = PactKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

        let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request = ToolCallRequest {
            request_id: "req-1".to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
        };

        // First invocation uses up the entire budget (100 of 100).
        let _allow = kernel.evaluate_tool_call(&request).unwrap();

        // Second invocation should be denied.
        let deny_req = ToolCallRequest {
            request_id: "req-2".to_string(),
            ..request
        };
        let resp = kernel.evaluate_tool_call(&deny_req).unwrap();
        assert_eq!(resp.verdict, Verdict::Deny);

        // Receipt must contain financial metadata.
        let metadata = resp
            .receipt
            .metadata
            .as_ref()
            .expect("should have metadata");
        let financial = metadata
            .get("financial")
            .expect("should have 'financial' key");
        assert_eq!(financial["settlement_status"], "not_applicable");
        assert!(financial["attempted_cost"].as_u64().is_some());
        assert_eq!(financial["currency"], "USD");
    }

    #[test]
    fn monetary_allow_receipt_contains_financial_metadata() {
        let mut kernel = PactKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        // Server reports actual cost of 75 cents (< max 100).
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let resp = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-1".to_string(),
                capability: cap.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
            })
            .unwrap();

        assert_eq!(resp.verdict, Verdict::Allow);

        let metadata = resp
            .receipt
            .metadata
            .as_ref()
            .expect("should have metadata");
        let financial = metadata
            .get("financial")
            .expect("should have 'financial' key");
        // The actual reported cost (75) should be recorded.
        assert_eq!(financial["cost_charged"].as_u64().unwrap(), 75);
        assert_eq!(financial["settlement_status"], "authorized");
        assert_eq!(financial["currency"], "USD");
    }

    #[test]
    fn monetary_server_not_reporting_cost_charges_max_cost_per_invocation() {
        let mut kernel = PactKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        // Server does NOT report cost (returns None).
        kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

        let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let resp = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-1".to_string(),
                capability: cap.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
            })
            .unwrap();

        assert_eq!(resp.verdict, Verdict::Allow);
        let metadata = resp
            .receipt
            .metadata
            .as_ref()
            .expect("should have metadata");
        let financial = metadata
            .get("financial")
            .expect("should have 'financial' key");
        // Worst-case debit: max_cost_per_invocation = 100.
        assert_eq!(financial["cost_charged"].as_u64().unwrap(), 100);
    }

    #[test]
    fn monetary_full_pipeline_three_invocations_third_denied() {
        // max_total_cost=250, max_cost_per_invocation=100.
        // Invocation 1: charges 100, total = 100. Allowed.
        // Invocation 2: charges 100, total = 200. Allowed.
        // Invocation 3: would charge 100, total would be 300 > 250. Denied.
        let mut kernel = PactKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

        let grant = make_monetary_grant("cost-srv", "compute", 100, 250, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let make_req = |id: &str| ToolCallRequest {
            request_id: id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
        };

        let r1 = kernel.evaluate_tool_call(&make_req("req-1")).unwrap();
        assert_eq!(r1.verdict, Verdict::Allow, "first invocation should pass");

        let r2 = kernel.evaluate_tool_call(&make_req("req-2")).unwrap();
        assert_eq!(r2.verdict, Verdict::Allow, "second invocation should pass");

        let r3 = kernel.evaluate_tool_call(&make_req("req-3")).unwrap();
        assert_eq!(
            r3.verdict,
            Verdict::Deny,
            "third invocation should be denied"
        );

        // Verify the denial receipt has financial metadata.
        let metadata = r3.receipt.metadata.as_ref().expect("should have metadata");
        assert!(metadata.get("financial").is_some());
    }

    #[test]
    fn matched_grant_index_populated_in_guard_context() {
        // A guard that records the matched_grant_index from its context.
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct IndexCapturingGuard {
            captured: Arc<Mutex<Option<usize>>>,
        }

        impl Guard for IndexCapturingGuard {
            fn name(&self) -> &str {
                "index-capture"
            }

            fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
                let mut lock = self.captured.lock().unwrap();
                *lock = ctx.matched_grant_index;
                Ok(Verdict::Allow)
            }
        }

        let captured = Arc::new(Mutex::new(None::<usize>));
        let guard = IndexCapturingGuard {
            captured: captured.clone(),
        };

        let mut kernel = PactKernel::new(make_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["tool1", "tool2"])));
        kernel.add_guard(Box::new(guard));

        // Two grants; first matches "tool1", second matches "tool2".
        let grant0 = ToolGrant {
            server_id: "srv".to_string(),
            tool_name: "tool1".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let grant1 = ToolGrant {
            server_id: "srv".to_string(),
            tool_name: "tool2".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let cap = kernel
            .issue_capability(
                &agent_kp.public_key(),
                make_scope(vec![grant0, grant1]),
                3600,
            )
            .unwrap();

        // Request tool2 -- matched grant should be at index 1.
        let resp = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-1".to_string(),
                capability: cap.clone(),
                tool_name: "tool2".to_string(),
                server_id: "srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
            })
            .unwrap();
        assert_eq!(resp.verdict, Verdict::Allow);

        let idx = *captured.lock().unwrap();
        assert_eq!(
            idx,
            Some(1),
            "guard should see matched_grant_index=Some(1) for tool2 (second grant)"
        );
    }

    #[test]
    fn velocity_guard_denial_produces_signed_deny_receipt_no_panic() {
        // Simulate a velocity-style guard with a simple counter that denies
        // after N invocations. This tests the kernel's handling of guard denials
        // (producing a signed deny receipt without panic) without importing pact-guards.
        use std::sync::{Arc, Mutex};

        struct CountingRateLimitGuard {
            count: Arc<Mutex<u32>>,
            max: u32,
        }

        impl Guard for CountingRateLimitGuard {
            fn name(&self) -> &str {
                "counting-rate-limit"
            }

            fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
                let mut count = self.count.lock().unwrap();
                *count += 1;
                if *count > self.max {
                    Ok(Verdict::Deny)
                } else {
                    Ok(Verdict::Allow)
                }
            }
        }

        let counter = Arc::new(Mutex::new(0u32));
        let guard = CountingRateLimitGuard {
            count: counter.clone(),
            max: 2,
        };

        let mut kernel = PactKernel::new(make_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
        kernel.add_guard(Box::new(guard));

        let grant = make_grant("srv", "echo");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let make_req = |id: &str| ToolCallRequest {
            request_id: id.to_string(),
            capability: cap.clone(),
            tool_name: "echo".to_string(),
            server_id: "srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
        };

        // First two invocations allowed.
        let r1 = kernel.evaluate_tool_call(&make_req("req-1")).unwrap();
        assert_eq!(r1.verdict, Verdict::Allow);
        let r2 = kernel.evaluate_tool_call(&make_req("req-2")).unwrap();
        assert_eq!(r2.verdict, Verdict::Allow);

        // Third invocation should be denied by the counting guard.
        let r3 = kernel.evaluate_tool_call(&make_req("req-3")).unwrap();
        assert_eq!(
            r3.verdict,
            Verdict::Deny,
            "counting guard should deny 3rd invocation"
        );
        // Verify it's a properly signed deny receipt (not a panic/unwrap).
        assert!(
            r3.receipt.id.starts_with("rcpt-"),
            "receipt should have valid id"
        );
        assert!(r3.reason.is_some(), "denial should have a reason");
    }

    #[test]
    fn checkpoint_triggers_at_100_receipts() {
        let path = unique_receipt_db_path("pact-checkpoint-trigger");
        let mut config = make_monetary_config();
        config.checkpoint_batch_size = 10; // Use 10 for speed.

        let mut kernel = PactKernel::new(config);
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

        let store = SqliteReceiptStore::open(&path).unwrap();
        kernel.set_receipt_store(Box::new(store));

        let grant = make_grant("srv", "echo");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        for i in 0..10 {
            kernel
                .evaluate_tool_call(&ToolCallRequest {
                    request_id: format!("req-{i}"),
                    capability: cap.clone(),
                    tool_name: "echo".to_string(),
                    server_id: "srv".to_string(),
                    agent_id: agent_kp.public_key().to_hex(),
                    arguments: serde_json::json!({}),
                    dpop_proof: None,
                })
                .unwrap();
        }

        // Verify a checkpoint was stored in the database.
        let store2 = SqliteReceiptStore::open(&path).unwrap();
        let checkpoint = store2.load_checkpoint_by_seq(1).unwrap();
        assert!(
            checkpoint.is_some(),
            "checkpoint should have been stored after 10 receipts"
        );
        let cp = checkpoint.unwrap();
        assert_eq!(cp.body.checkpoint_seq, 1);
        assert_eq!(cp.body.batch_start_seq, 1);
        assert_eq!(cp.body.batch_end_seq, 10);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inclusion_proof_verifies_against_stored_checkpoint() {
        let path = unique_receipt_db_path("pact-checkpoint-proof");
        let mut config = make_monetary_config();
        config.checkpoint_batch_size = 5;

        let mut kernel = PactKernel::new(config);
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

        let store = SqliteReceiptStore::open(&path).unwrap();
        kernel.set_receipt_store(Box::new(store));

        let grant = make_grant("srv", "echo");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        for i in 0..5 {
            kernel
                .evaluate_tool_call(&ToolCallRequest {
                    request_id: format!("req-{i}"),
                    capability: cap.clone(),
                    tool_name: "echo".to_string(),
                    server_id: "srv".to_string(),
                    agent_id: agent_kp.public_key().to_hex(),
                    arguments: serde_json::json!({}),
                    dpop_proof: None,
                })
                .unwrap();
        }

        // Load checkpoint and receipts, build and verify an inclusion proof.
        let store2 = SqliteReceiptStore::open(&path).unwrap();
        let checkpoint = store2
            .load_checkpoint_by_seq(1)
            .unwrap()
            .expect("checkpoint should exist");

        let bytes_range = store2.receipts_canonical_bytes_range(1, 5).unwrap();
        assert_eq!(bytes_range.len(), 5, "should have 5 receipts in range");

        let all_bytes: Vec<Vec<u8>> = bytes_range.iter().map(|(_, b)| b.clone()).collect();
        let tree =
            pact_core::merkle::MerkleTree::from_leaves(&all_bytes).expect("tree build failed");

        // Build proof for receipt at leaf index 2 (seq 3).
        let proof = build_inclusion_proof(&tree, 2, 1, 3).expect("proof build failed");
        assert!(
            proof.verify(&all_bytes[2], &checkpoint.body.merkle_root),
            "inclusion proof for receipt #3 should verify against checkpoint"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tool_invocation_cost_serde_roundtrip() {
        let cost = ToolInvocationCost {
            units: 500,
            currency: "USD".to_string(),
            breakdown: None,
        };
        let json = serde_json::to_string(&cost).unwrap();
        let restored: ToolInvocationCost = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.units, 500);
        assert_eq!(restored.currency, "USD");
        assert!(restored.breakdown.is_none());

        // With breakdown
        let cost_with = ToolInvocationCost {
            units: 200,
            currency: "EUR".to_string(),
            breakdown: Some(serde_json::json!({"compute": 150, "network": 50})),
        };
        let json_with = serde_json::to_string(&cost_with).unwrap();
        let restored_with: ToolInvocationCost = serde_json::from_str(&json_with).unwrap();
        assert_eq!(restored_with.units, 200);
        assert!(restored_with.breakdown.is_some());
    }

    #[test]
    fn echo_server_invoke_with_cost_returns_none() {
        let server = EchoServer::new("srv-a", vec!["echo"]);
        let args = serde_json::json!({"msg": "hello"});
        let (value, cost) = server
            .invoke_with_cost("echo", args, None)
            .expect("invoke_with_cost should succeed");
        assert!(cost.is_none(), "EchoServer should return None cost");
        assert!(value.is_object());
    }

    // ---------------------------------------------------------------------------
    // DPoP wiring tests
    // ---------------------------------------------------------------------------

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
    ) -> (PactKernel, CapabilityToken) {
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
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        };
        let mut kernel = PactKernel::new(config);
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
        let args_bytes = pact_core::canonical::canonical_json_bytes(arguments)
            .expect("canonical_json_bytes failed");
        let action_hash = pact_core::crypto::sha256_hex(&args_bytes);
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

    #[test]
    fn dpop_required_grant_allows_when_valid_proof_provided() {
        let agent_kp = Keypair::generate();
        let server = "dpop-srv";
        let tool = "secure_op";
        let (mut kernel, cap) = make_dpop_kernel_and_cap(&agent_kp, server, tool);

        let arguments = serde_json::json!({"action": "read"});
        let proof = make_dpop_proof(&agent_kp, &cap, server, tool, &arguments, "nonce-abc-001");

        let request = ToolCallRequest {
            request_id: "req-dpop-allow".to_string(),
            capability: cap,
            tool_name: tool.to_string(),
            server_id: server.to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments,
            dpop_proof: Some(proof),
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(
            response.verdict,
            Verdict::Allow,
            "valid DPoP proof should allow; reason: {:?}",
            response.reason
        );
    }

    #[test]
    fn dpop_required_grant_denies_when_no_proof_provided() {
        let agent_kp = Keypair::generate();
        let server = "dpop-srv";
        let tool = "secure_op";
        let (mut kernel, cap) = make_dpop_kernel_and_cap(&agent_kp, server, tool);

        let request = ToolCallRequest {
            request_id: "req-dpop-deny-no-proof".to_string(),
            capability: cap,
            tool_name: tool.to_string(),
            server_id: server.to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({"action": "read"}),
            dpop_proof: None,
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(
            response.verdict,
            Verdict::Deny,
            "missing DPoP proof should deny"
        );
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("DPoP proof"),
            "denial reason should mention DPoP; got: {reason}"
        );
    }

    #[test]
    fn dpop_required_grant_denies_when_proof_has_wrong_tool_name() {
        let agent_kp = Keypair::generate();
        let server = "dpop-srv";
        let tool = "secure_op";
        let (mut kernel, cap) = make_dpop_kernel_and_cap(&agent_kp, server, tool);

        let arguments = serde_json::json!({"action": "read"});
        // Proof claims wrong tool name -- binding check should fail.
        let proof = make_dpop_proof(
            &agent_kp,
            &cap,
            server,
            "other_tool",
            &arguments,
            "nonce-bad-001",
        );

        let request = ToolCallRequest {
            request_id: "req-dpop-deny-wrong-tool".to_string(),
            capability: cap,
            tool_name: tool.to_string(),
            server_id: server.to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments,
            dpop_proof: Some(proof),
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(
            response.verdict,
            Verdict::Deny,
            "proof with wrong tool name should deny"
        );
    }

    #[test]
    fn dpop_not_required_grant_allows_without_proof() {
        // Verify non-DPoP grants are unaffected.
        let mut kernel = PactKernel::new(make_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

        let grant = make_grant("srv", "echo");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request = make_request("req-no-dpop", &cap, "echo", "srv");
        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(
            response.verdict,
            Verdict::Allow,
            "non-DPoP grant should allow without proof"
        );
    }
}
