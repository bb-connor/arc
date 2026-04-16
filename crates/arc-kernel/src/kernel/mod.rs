use std::sync::atomic::AtomicU64;
use std::sync::{Mutex, RwLock};

use arc_appraisal::VerifiedRuntimeAttestationRecord;

use self::responses::FinalizeToolOutputCostContext;
use crate::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetCommitMetadata,
    BudgetEventAuthority, BudgetHoldMutationDecision, BudgetReconcileHoldDecision,
    BudgetReconcileHoldRequest, BudgetReverseHoldDecision, BudgetReverseHoldRequest,
};
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

#[derive(Debug, Clone, Default)]
struct ValidatedGovernedCallChainProof {
    upstream_proof: Option<arc_core::capability::GovernedUpstreamCallChainProof>,
    continuation_token_id: Option<String>,
    session_anchor_id: Option<String>,
}

#[derive(Debug, Clone)]
enum LocalReceiptArtifact {
    Tool(arc_core::receipt::ArcReceipt),
    Child(arc_core::receipt::ChildRequestReceipt),
}

impl LocalReceiptArtifact {
    fn verify_signature(&self) -> Result<bool, KernelError> {
        match self {
            Self::Tool(receipt) => receipt.verify_signature().map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "governed call_chain parent receipt failed signature verification: {error}"
                ))
            }),
            Self::Child(receipt) => receipt.verify_signature().map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "governed call_chain parent receipt failed signature verification: {error}"
                ))
            }),
        }
    }

    fn artifact_hash(&self) -> Result<String, KernelError> {
        let canonical = match self {
            Self::Tool(receipt) => canonical_json_bytes(receipt),
            Self::Child(receipt) => canonical_json_bytes(receipt),
        }
        .map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "failed to hash governed call_chain parent receipt: {error}"
            ))
        })?;
        Ok(sha256_hex(&canonical))
    }

    fn session_anchor_reference(&self) -> Option<arc_core::session::SessionAnchorReference> {
        let metadata = match self {
            Self::Tool(receipt) => receipt.metadata.as_ref(),
            Self::Child(receipt) => receipt.metadata.as_ref(),
        };
        extract_session_anchor_reference_from_metadata(metadata)
    }
}

fn extract_session_anchor_reference_from_metadata(
    metadata: Option<&serde_json::Value>,
) -> Option<arc_core::session::SessionAnchorReference> {
    let metadata = metadata?;
    let candidates = [
        metadata
            .get("governed_transaction")
            .and_then(|value| value.get("call_chain")),
        metadata.get("lineageReferences"),
    ];

    for candidate in candidates.into_iter().flatten() {
        let Some(session_anchor_id) = candidate
            .get("sessionAnchorId")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        let Some(session_anchor_hash) = candidate
            .get("sessionAnchorHash")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        return Some(arc_core::session::SessionAnchorReference::new(
            session_anchor_id,
            session_anchor_hash,
        ));
    }

    None
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct StructuredErrorReport {
    pub code: String,
    pub message: String,
    pub context: serde_json::Value,
    pub suggested_fix: String,
}

impl StructuredErrorReport {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        context: serde_json::Value,
        suggested_fix: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            context,
            suggested_fix: suggested_fix.into(),
        }
    }
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

    #[error("delegation admission failed: {0}")]
    DelegationInvalid(String),

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

impl KernelError {
    fn report_with_context(
        &self,
        code: &str,
        context: serde_json::Value,
        suggested_fix: impl Into<String>,
    ) -> StructuredErrorReport {
        StructuredErrorReport::new(code, self.to_string(), context, suggested_fix)
    }

    pub fn report(&self) -> StructuredErrorReport {
        match self {
            Self::UnknownSession(session_id) => self.report_with_context(
                "ARC-KERNEL-UNKNOWN-SESSION",
                serde_json::json!({ "session_id": session_id.to_string() }),
                "Create the session first or reuse a session ID returned by the kernel before issuing follow-up operations.",
            ),
            Self::Session(error) => self.report_with_context(
                "ARC-KERNEL-SESSION",
                serde_json::json!({ "session_error": error.to_string() }),
                "Inspect the session lifecycle and ordering of operations, then recreate the session if it is no longer valid.",
            ),
            Self::CapabilityExpired => self.report_with_context(
                "ARC-KERNEL-CAPABILITY-EXPIRED",
                serde_json::json!({}),
                "Refresh or reissue the capability so its validity window includes the current time.",
            ),
            Self::CapabilityNotYetValid => self.report_with_context(
                "ARC-KERNEL-CAPABILITY-NOT-YET-VALID",
                serde_json::json!({}),
                "Use a capability whose validity window has started, or correct the issuer clock skew if timestamps are wrong.",
            ),
            Self::CapabilityRevoked(capability_id) => self.report_with_context(
                "ARC-KERNEL-CAPABILITY-REVOKED",
                serde_json::json!({ "capability_id": capability_id }),
                "Request a new non-revoked capability or inspect the revocation record for this capability lineage.",
            ),
            Self::InvalidSignature => self.report_with_context(
                "ARC-KERNEL-INVALID-SIGNATURE",
                serde_json::json!({}),
                "Reissue the capability or receipt with the correct signing key and verify the payload was not mutated in transit.",
            ),
            Self::UntrustedIssuer => self.report_with_context(
                "ARC-KERNEL-UNTRUSTED-ISSUER",
                serde_json::json!({}),
                "Configure the issuing CA public key in the kernel trust set or use a capability issued by a trusted authority.",
            ),
            Self::CapabilityIssuanceFailed(reason) => self.report_with_context(
                "ARC-KERNEL-CAPABILITY-ISSUANCE-FAILED",
                serde_json::json!({ "reason": reason }),
                "Inspect the issuance pipeline inputs and upstream stores, then retry once the issuing dependency is healthy.",
            ),
            Self::CapabilityIssuanceDenied(reason) => self.report_with_context(
                "ARC-KERNEL-CAPABILITY-ISSUANCE-DENIED",
                serde_json::json!({ "reason": reason }),
                "Adjust the issuance request so it satisfies the policy, score, or trust requirements enforced by the authority.",
            ),
            Self::OutOfScope { tool, server } => self.report_with_context(
                "ARC-KERNEL-OUT-OF-SCOPE-TOOL",
                serde_json::json!({ "tool": tool, "server": server }),
                "Issue a capability that grants this tool on this server, or call a tool already inside the granted scope.",
            ),
            Self::OutOfScopeResource { uri } => self.report_with_context(
                "ARC-KERNEL-OUT-OF-SCOPE-RESOURCE",
                serde_json::json!({ "uri": uri }),
                "Issue a capability/resource grant that matches this URI, or request a resource already inside scope.",
            ),
            Self::OutOfScopePrompt { prompt } => self.report_with_context(
                "ARC-KERNEL-OUT-OF-SCOPE-PROMPT",
                serde_json::json!({ "prompt": prompt }),
                "Issue a capability/prompt grant that matches this prompt, or request a prompt already inside scope.",
            ),
            Self::BudgetExhausted(capability_id) => self.report_with_context(
                "ARC-KERNEL-BUDGET-EXHAUSTED",
                serde_json::json!({ "capability_id": capability_id }),
                "Increase the capability budget, wait for the budget window to reset, or lower the cost of the requested operation.",
            ),
            Self::SubjectMismatch { expected, actual } => self.report_with_context(
                "ARC-KERNEL-SUBJECT-MISMATCH",
                serde_json::json!({ "expected": expected, "actual": actual }),
                "Use a capability issued to the requesting subject, or correct the agent identity bound to the request.",
            ),
            Self::DelegationChainRevoked(capability_id) => self.report_with_context(
                "ARC-KERNEL-DELEGATION-CHAIN-REVOKED",
                serde_json::json!({ "capability_id": capability_id }),
                "Inspect the capability lineage and reissue the chain from a non-revoked ancestor.",
            ),
            Self::DelegationInvalid(reason) => self.report_with_context(
                "ARC-KERNEL-DELEGATION-INVALID",
                serde_json::json!({ "reason": reason }),
                "Reissue the delegated capability with a valid ancestor snapshot chain, delegator binding, attenuation proof, and delegated scope ceiling.",
            ),
            Self::InvalidConstraint(reason) => self.report_with_context(
                "ARC-KERNEL-INVALID-CONSTRAINT",
                serde_json::json!({ "reason": reason }),
                "Fix the capability constraint payload so it matches the kernel's supported schema and value rules.",
            ),
            Self::GovernedTransactionDenied(reason) => self.report_with_context(
                "ARC-KERNEL-GOVERNED-TRANSACTION-DENIED",
                serde_json::json!({ "reason": reason }),
                "Adjust the governed transaction intent so it satisfies the configured approval and policy requirements.",
            ),
            Self::GuardDenied(reason) => self.report_with_context(
                "ARC-KERNEL-GUARD-DENIED",
                serde_json::json!({ "reason": reason }),
                "Adjust the request or policy/guard configuration so the request satisfies the active guard pipeline.",
            ),
            Self::ToolServerError(reason) => self.report_with_context(
                "ARC-KERNEL-TOOL-SERVER",
                serde_json::json!({ "reason": reason }),
                "Inspect the wrapped tool server logs and protocol compatibility, then retry once the server is healthy.",
            ),
            Self::RequestIncomplete(reason) => self.report_with_context(
                "ARC-KERNEL-REQUEST-INCOMPLETE",
                serde_json::json!({ "reason": reason }),
                "Resubmit the request with all required fields and protocol state transitions present.",
            ),
            Self::ToolNotRegistered(tool) => self.report_with_context(
                "ARC-KERNEL-TOOL-NOT-REGISTERED",
                serde_json::json!({ "tool": tool }),
                "Register the tool on the target server or update the request to reference an exposed tool.",
            ),
            Self::ResourceNotRegistered(uri) => self.report_with_context(
                "ARC-KERNEL-RESOURCE-NOT-REGISTERED",
                serde_json::json!({ "uri": uri }),
                "Register the resource provider for this URI or request a resource that is actually exposed by the runtime.",
            ),
            Self::ResourceRootDenied { uri, reason } => self.report_with_context(
                "ARC-KERNEL-RESOURCE-ROOT-DENIED",
                serde_json::json!({ "uri": uri, "reason": reason }),
                "Expand the session filesystem roots if the access is intentional, or request a resource inside the approved root set.",
            ),
            Self::PromptNotRegistered(prompt) => self.report_with_context(
                "ARC-KERNEL-PROMPT-NOT-REGISTERED",
                serde_json::json!({ "prompt": prompt }),
                "Register the prompt provider for this prompt name or request a prompt that is actually exposed.",
            ),
            Self::SamplingNotAllowedByPolicy => self.report_with_context(
                "ARC-KERNEL-SAMPLING-NOT-ALLOWED",
                serde_json::json!({}),
                "Enable sampling in policy if this workflow requires it, or retry without a sampling request.",
            ),
            Self::SamplingNotNegotiated => self.report_with_context(
                "ARC-KERNEL-SAMPLING-NOT-NEGOTIATED",
                serde_json::json!({}),
                "Negotiate sampling support with the client before issuing sampling operations.",
            ),
            Self::SamplingContextNotSupported => self.report_with_context(
                "ARC-KERNEL-SAMPLING-CONTEXT-NOT-SUPPORTED",
                serde_json::json!({}),
                "Disable sampling context inclusion or upgrade the client to one that supports the negotiated feature.",
            ),
            Self::SamplingToolUseNotAllowedByPolicy => self.report_with_context(
                "ARC-KERNEL-SAMPLING-TOOL-USE-NOT-ALLOWED",
                serde_json::json!({}),
                "Enable sampling tool use in policy or retry without delegated tool execution inside the sampling branch.",
            ),
            Self::SamplingToolUseNotNegotiated => self.report_with_context(
                "ARC-KERNEL-SAMPLING-TOOL-USE-NOT-NEGOTIATED",
                serde_json::json!({}),
                "Negotiate sampling tool-use support with the client before attempting tool execution inside sampling.",
            ),
            Self::ElicitationNotAllowedByPolicy => self.report_with_context(
                "ARC-KERNEL-ELICITATION-NOT-ALLOWED",
                serde_json::json!({}),
                "Enable elicitation in policy or retry without requesting user input through the kernel.",
            ),
            Self::ElicitationNotNegotiated => self.report_with_context(
                "ARC-KERNEL-ELICITATION-NOT-NEGOTIATED",
                serde_json::json!({}),
                "Negotiate elicitation support with the client before attempting elicitation operations.",
            ),
            Self::ElicitationFormNotSupported => self.report_with_context(
                "ARC-KERNEL-ELICITATION-FORM-NOT-SUPPORTED",
                serde_json::json!({}),
                "Switch to a supported elicitation mode or upgrade the client to one that supports form-mode elicitation.",
            ),
            Self::ElicitationUrlNotSupported => self.report_with_context(
                "ARC-KERNEL-ELICITATION-URL-NOT-SUPPORTED",
                serde_json::json!({}),
                "Switch to a supported elicitation mode or negotiate URL-based elicitation support with the client.",
            ),
            Self::UrlElicitationsRequired {
                message,
                elicitations,
            } => self.report_with_context(
                "ARC-KERNEL-URL-ELICITATIONS-REQUIRED",
                serde_json::json!({
                    "message": message,
                    "elicitation_count": elicitations.len()
                }),
                "Complete the required URL-based elicitation flow and resubmit the request afterward.",
            ),
            Self::RootsNotNegotiated => self.report_with_context(
                "ARC-KERNEL-ROOTS-NOT-NEGOTIATED",
                serde_json::json!({}),
                "Negotiate roots/list support with the client before using root-scoped resource protections.",
            ),
            Self::InvalidChildRequestParent => self.report_with_context(
                "ARC-KERNEL-INVALID-CHILD-REQUEST-PARENT",
                serde_json::json!({}),
                "Create the child request from a ready session-bound parent request that is currently in flight.",
            ),
            Self::RequestCancelled { request_id, reason } => self.report_with_context(
                "ARC-KERNEL-REQUEST-CANCELLED",
                serde_json::json!({ "request_id": request_id.to_string(), "reason": reason }),
                "Stop using the cancelled request ID and restart the operation if the workflow still needs to continue.",
            ),
            Self::ReceiptSigningFailed(reason) => self.report_with_context(
                "ARC-KERNEL-RECEIPT-SIGNING-FAILED",
                serde_json::json!({ "reason": reason }),
                "Inspect the kernel signing key configuration and signing payload integrity, then retry receipt generation.",
            ),
            Self::ReceiptPersistence(error) => self.report_with_context(
                "ARC-KERNEL-RECEIPT-PERSISTENCE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured receipt store connectivity, permissions, and schema health before retrying.",
            ),
            Self::RevocationStore(error) => self.report_with_context(
                "ARC-KERNEL-REVOCATION-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured revocation store connectivity, permissions, and schema health before retrying.",
            ),
            Self::BudgetStore(error) => self.report_with_context(
                "ARC-KERNEL-BUDGET-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured budget store connectivity, permissions, and schema health before retrying.",
            ),
            Self::NoCrossCurrencyOracle { base, quote } => self.report_with_context(
                "ARC-KERNEL-NO-CROSS-CURRENCY-ORACLE",
                serde_json::json!({ "base": base, "quote": quote }),
                "Configure a price oracle for this currency pair or avoid a cross-currency budget path for this request.",
            ),
            Self::CrossCurrencyOracle(reason) => self.report_with_context(
                "ARC-KERNEL-CROSS-CURRENCY-ORACLE",
                serde_json::json!({ "reason": reason }),
                "Inspect the price-oracle configuration and upstream quote availability for the requested currency conversion.",
            ),
            Self::Web3EvidenceUnavailable(reason) => self.report_with_context(
                "ARC-KERNEL-WEB3-EVIDENCE-UNAVAILABLE",
                serde_json::json!({ "reason": reason }),
                "Enable the required receipt-store, checkpoint, and oracle prerequisites before running the web3 evidence path.",
            ),
            Self::Internal(reason) => self.report_with_context(
                "ARC-KERNEL-INTERNAL",
                serde_json::json!({ "reason": reason }),
                "Capture the error report and kernel logs, then treat this as a reproducible kernel bug if it persists.",
            ),
            Self::DpopVerificationFailed(reason) => self.report_with_context(
                "ARC-KERNEL-DPOP-VERIFICATION-FAILED",
                serde_json::json!({ "reason": reason }),
                "Attach a valid DPoP proof bound to the current capability, request, server, and tool before retrying.",
            ),
        }
    }
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
#[derive(Clone, Default)]
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
#[derive(Clone, Default)]
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
    budget_store: Mutex<Box<dyn BudgetStore>>,
    revocation_store: Mutex<Box<dyn RevocationStore>>,
    capability_authority: Box<dyn CapabilityAuthority>,
    tool_servers: HashMap<ServerId, Box<dyn ToolServerConnection>>,
    resource_providers: Vec<Box<dyn ResourceProvider>>,
    prompt_providers: Vec<Box<dyn PromptProvider>>,
    sessions: RwLock<HashMap<SessionId, Session>>,
    receipt_log: Mutex<ReceiptLog>,
    child_receipt_log: Mutex<ChildReceiptLog>,
    receipt_store: Option<Mutex<Box<dyn ReceiptStore>>>,
    payment_adapter: Option<Box<dyn PaymentAdapter>>,
    price_oracle: Option<Box<dyn PriceOracle>>,
    attestation_trust_policy: Option<AttestationTrustPolicy>,
    session_counter: AtomicU64,
    /// How many receipts per Merkle checkpoint batch. Default: 100.
    checkpoint_batch_size: u64,
    /// Monotonic counter for checkpoint_seq values.
    checkpoint_seq_counter: AtomicU64,
    /// seq of the last receipt included in the previous checkpoint batch.
    last_checkpoint_seq: AtomicU64,
    /// Nonce replay store for DPoP proof verification. Required when any grant has dpop_required.
    dpop_nonce_store: Option<dpop::DpopNonceStore>,
    /// Configuration for DPoP proof verification TTLs and clock skew.
    dpop_config: Option<dpop::DpopConfig>,
    /// Replay store for governed approval tokens. Prevents a signed approval
    /// from being consumed more than once. Uses the same LRU + TTL pattern as
    /// DPoP nonce verification. Key: (request_id, governed_intent_hash).
    approval_replay_store: Option<dpop::DpopNonceStore>,
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
    /// Running committed cost after this charge (used to compute budget_remaining).
    new_committed_cost_units: u64,
    budget_hold_id: String,
    authorize_metadata: BudgetCommitMetadata,
}

impl BudgetChargeResult {
    fn reverse_event_id(&self) -> String {
        format!("{}:reverse", self.budget_hold_id)
    }

    fn reconcile_event_id(&self) -> String {
        format!("{}:reconcile", self.budget_hold_id)
    }
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
    fn with_sessions_read<R>(
        &self,
        f: impl FnOnce(&HashMap<SessionId, Session>) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| KernelError::Internal("session state lock poisoned".to_string()))?;
        f(&sessions)
    }

    fn with_sessions_write<R>(
        &self,
        f: impl FnOnce(&mut HashMap<SessionId, Session>) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| KernelError::Internal("session state lock poisoned".to_string()))?;
        f(&mut sessions)
    }

    fn with_session<R>(
        &self,
        session_id: &SessionId,
        f: impl FnOnce(&Session) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        self.with_sessions_read(|sessions| {
            let session = sessions
                .get(session_id)
                .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;
            f(session)
        })
    }

    fn with_session_mut<R>(
        &self,
        session_id: &SessionId,
        f: impl FnOnce(&mut Session) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        self.with_sessions_write(|sessions| {
            let session = sessions
                .get_mut(session_id)
                .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;
            f(session)
        })
    }

    fn with_budget_store<R>(
        &self,
        f: impl FnOnce(&mut dyn BudgetStore) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        let mut store = self
            .budget_store
            .lock()
            .map_err(|_| KernelError::Internal("budget store lock poisoned".to_string()))?;
        f(store.as_mut())
    }

    fn with_revocation_store<R>(
        &self,
        f: impl FnOnce(&mut dyn RevocationStore) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        let mut store = self
            .revocation_store
            .lock()
            .map_err(|_| KernelError::Internal("revocation store lock poisoned".to_string()))?;
        f(store.as_mut())
    }

    fn with_receipt_store<R>(
        &self,
        f: impl FnOnce(&mut dyn ReceiptStore) -> Result<R, KernelError>,
    ) -> Result<Option<R>, KernelError> {
        let Some(store) = self.receipt_store.as_ref() else {
            return Ok(None);
        };
        let mut store = store
            .lock()
            .map_err(|_| KernelError::Internal("receipt store lock poisoned".to_string()))?;
        f(store.as_mut()).map(Some)
    }

    pub fn new(config: KernelConfig) -> Self {
        info!("initializing ARC kernel");
        let authority_keypair = config.keypair.clone();
        let checkpoint_batch_size = config.checkpoint_batch_size;
        Self {
            config,
            guards: Vec::new(),
            budget_store: Mutex::new(Box::new(InMemoryBudgetStore::new())),
            revocation_store: Mutex::new(Box::new(InMemoryRevocationStore::new())),
            capability_authority: Box::new(LocalCapabilityAuthority::new(authority_keypair)),
            tool_servers: HashMap::new(),
            resource_providers: Vec::new(),
            prompt_providers: Vec::new(),
            sessions: RwLock::new(HashMap::new()),
            receipt_log: Mutex::new(ReceiptLog::new()),
            child_receipt_log: Mutex::new(ChildReceiptLog::new()),
            receipt_store: None,
            payment_adapter: None,
            price_oracle: None,
            attestation_trust_policy: None,
            session_counter: AtomicU64::new(0),
            checkpoint_batch_size,
            checkpoint_seq_counter: AtomicU64::new(0),
            last_checkpoint_seq: AtomicU64::new(0),
            dpop_nonce_store: None,
            dpop_config: None,
            approval_replay_store: Some(dpop::DpopNonceStore::new(
                8192,
                std::time::Duration::from_secs(3600),
            )),
        }
    }

    pub fn set_receipt_store(&mut self, receipt_store: Box<dyn ReceiptStore>) {
        self.receipt_store = Some(Mutex::new(receipt_store));
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
        self.revocation_store = Mutex::new(revocation_store);
    }

    pub fn set_capability_authority(&mut self, capability_authority: Box<dyn CapabilityAuthority>) {
        self.capability_authority = capability_authority;
    }

    pub fn set_budget_store(&mut self, budget_store: Box<dyn BudgetStore>) {
        self.budget_store = Mutex::new(budget_store);
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

        let Some(supports_kernel_signed_checkpoints) =
            self.with_receipt_store(|store| Ok(store.supports_kernel_signed_checkpoints()))?
        else {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require a durable receipt store".to_string(),
            ));
        };

        if self.checkpoint_batch_size == 0 {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require checkpoint_batch_size > 0".to_string(),
            ));
        }

        if !supports_kernel_signed_checkpoints {
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
        self.validate_delegation_admission(capability)?;
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
    pub async fn evaluate_tool_call(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_with_session_roots(request, None, None)
    }

    pub fn evaluate_tool_call_blocking(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_with_session_roots(request, None, None)
    }

    pub fn evaluate_tool_call_blocking_with_metadata(
        &self,
        request: &ToolCallRequest,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_with_session_roots(request, None, extra_metadata)
    }

    pub fn sign_planned_deny_response(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_deny_response_with_metadata(
            request,
            reason,
            current_unix_timestamp(),
            None,
            extra_metadata,
        )
    }

    fn evaluate_tool_call_sync_with_session_roots(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
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
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = check_time_bounds(cap, now) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = self.check_revocation(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = self.validate_delegation_admission(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = check_subject_binding(cap, &request.agent_id) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
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
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    None,
                    extra_metadata.clone(),
                );
            }
            Err(e) => {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    None,
                    extra_metadata.clone(),
                );
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
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    None,
                    extra_metadata.clone(),
                );
            }
        }

        if let Err(e) = self.ensure_registered_tool_target(request) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "tool target not registered");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(error) = self.record_observed_capability_snapshot(cap) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "failed to persist capability lineage");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        let (matched_grant_index, charge_result) =
            match self.check_and_increment_budget(&request.request_id, cap, &matching_grants) {
                Ok(result) => result,
                Err(e) => {
                    let msg = e.to_string();
                    warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                    // For monetary budget exhaustion, build a denial receipt with financial metadata.
                    return self.build_monetary_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        &matching_grants,
                        cap,
                        self.merge_budget_receipt_metadata(
                            extra_metadata.clone(),
                            self.budget_backend_receipt_metadata()?,
                        ),
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

        let validated_upstream_call_chain_proof = match self.validate_governed_transaction(
            request,
            cap,
            matched_grant,
            charge_result.as_ref(),
            None,
            now,
        ) {
            Ok(validated_upstream_call_chain_proof) => validated_upstream_call_chain_proof,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "governed transaction denied");
                if let Some(ref charge) = charge_result {
                    let reverse = self.reverse_budget_charge(&cap.id, charge)?;
                    return self.build_pre_execution_monetary_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        charge,
                        reverse.committed_cost_units_after,
                        cap,
                        self.merge_budget_receipt_metadata(
                            extra_metadata.clone(),
                            self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", &reverse)),
                            ),
                        ),
                    );
                }
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    Some(matched_grant_index),
                    extra_metadata.clone(),
                );
            }
        };
        let _governed_call_chain_receipt_evidence_scope =
            scope_governed_call_chain_receipt_evidence(self.governed_call_chain_receipt_evidence(
                request,
                cap,
                None,
                validated_upstream_call_chain_proof,
            ));

        if let Err(e) = self.run_guards(
            request,
            &cap.scope,
            session_filesystem_roots,
            Some(matched_grant_index),
        ) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "guard denied");
            if let Some(ref charge) = charge_result {
                let reverse = self.reverse_budget_charge(&cap.id, charge)?;
                return self.build_pre_execution_monetary_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    charge,
                    reverse.committed_cost_units_after,
                    cap,
                    self.merge_budget_receipt_metadata(
                        extra_metadata.clone(),
                        self.budget_execution_receipt_metadata(
                            charge,
                            Some(("reversed", &reverse)),
                        ),
                    ),
                );
            }
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                Some(matched_grant_index),
                extra_metadata.clone(),
            );
        }

        let payment_authorization =
            match self.authorize_payment_if_needed(request, charge_result.as_ref()) {
                Ok(authorization) => authorization,
                Err(error) => {
                    let msg = format!("payment authorization failed: {error}");
                    warn!(request_id = %request.request_id, reason = %msg, "payment denied");
                    if let Some(ref charge) = charge_result {
                        let reverse = self.reverse_budget_charge(&cap.id, charge)?;
                        return self.build_pre_execution_monetary_deny_response_with_metadata(
                            request,
                            &msg,
                            now,
                            charge,
                            reverse.committed_cost_units_after,
                            cap,
                            self.merge_budget_receipt_metadata(
                                extra_metadata.clone(),
                                self.budget_execution_receipt_metadata(
                                    charge,
                                    Some(("reversed", &reverse)),
                                ),
                            ),
                        );
                    }
                    return self.build_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        Some(matched_grant_index),
                        extra_metadata.clone(),
                    );
                }
            };

        let tool_started_at = Instant::now();
        let has_monetary = charge_result.is_some();
        let (tool_output, reported_cost) =
            match self.dispatch_tool_call_with_cost(request, has_monetary) {
                Ok(result) => result,
                Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                    let _ = self.unwind_aborted_monetary_invocation(
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
                    let unwind = self.unwind_aborted_monetary_invocation(
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
                    return self.build_cancelled_response_with_metadata(
                        request,
                        &reason,
                        now,
                        Some(matched_grant_index),
                        match (charge_result.as_ref(), unwind.as_ref()) {
                            (Some(charge), Some(reverse)) => self.merge_budget_receipt_metadata(
                                extra_metadata.clone(),
                                self.budget_execution_receipt_metadata(
                                    charge,
                                    Some(("reversed", reverse)),
                                ),
                            ),
                            _ => extra_metadata.clone(),
                        },
                    );
                }
                Err(KernelError::RequestIncomplete(reason)) => {
                    let unwind = self.unwind_aborted_monetary_invocation(
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
                    return self.build_incomplete_response_with_output_and_metadata(
                        request,
                        None,
                        &reason,
                        now,
                        Some(matched_grant_index),
                        match (charge_result.as_ref(), unwind.as_ref()) {
                            (Some(charge), Some(reverse)) => self.merge_budget_receipt_metadata(
                                extra_metadata.clone(),
                                self.budget_execution_receipt_metadata(
                                    charge,
                                    Some(("reversed", reverse)),
                                ),
                            ),
                            _ => extra_metadata.clone(),
                        },
                    );
                }
                Err(e) => {
                    let unwind = self.unwind_aborted_monetary_invocation(
                        request,
                        cap,
                        charge_result.as_ref(),
                        payment_authorization.as_ref(),
                    )?;
                    let msg = e.to_string();
                    warn!(request_id = %request.request_id, reason = %msg, "tool server error");
                    return self.build_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        Some(matched_grant_index),
                        match (charge_result.as_ref(), unwind.as_ref()) {
                            (Some(charge), Some(reverse)) => self.merge_budget_receipt_metadata(
                                extra_metadata.clone(),
                                self.budget_execution_receipt_metadata(
                                    charge,
                                    Some(("reversed", reverse)),
                                ),
                            ),
                            _ => extra_metadata.clone(),
                        },
                    );
                }
            };
        self.finalize_budgeted_tool_output_with_cost_and_metadata(
            request,
            tool_output,
            tool_started_at.elapsed(),
            now,
            matched_grant_index,
            FinalizeToolOutputCostContext {
                charge_result,
                reported_cost,
                payment_authorization,
                cap,
            },
            extra_metadata,
        )
    }

    fn evaluate_tool_call_with_nested_flow_client<C: NestedFlowClient>(
        &self,
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

        if let Err(e) = self.validate_delegation_admission(cap) {
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
            match self.check_and_increment_budget(&request.request_id, cap, &matching_grants) {
                Ok(result) => result,
                Err(e) => {
                    let msg = e.to_string();
                    warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                    return self.build_monetary_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        &matching_grants,
                        cap,
                        Some(self.budget_backend_receipt_metadata()?),
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

        let validated_upstream_call_chain_proof = match self.validate_governed_transaction(
            request,
            cap,
            matched_grant,
            charge_result.as_ref(),
            Some(parent_context),
            now,
        ) {
            Ok(validated_upstream_call_chain_proof) => validated_upstream_call_chain_proof,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "governed transaction denied");
                if let Some(ref charge) = charge_result {
                    let reverse = self.reverse_budget_charge(&cap.id, charge)?;
                    return self.build_pre_execution_monetary_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        charge,
                        reverse.committed_cost_units_after,
                        cap,
                        Some(self.budget_execution_receipt_metadata(
                            charge,
                            Some(("reversed", &reverse)),
                        )),
                    );
                }
                return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
            }
        };
        let _governed_call_chain_receipt_evidence_scope =
            scope_governed_call_chain_receipt_evidence(self.governed_call_chain_receipt_evidence(
                request,
                cap,
                Some(parent_context),
                validated_upstream_call_chain_proof,
            ));

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
                let reverse = self.reverse_budget_charge(&cap.id, charge)?;
                return self.build_pre_execution_monetary_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    charge,
                    reverse.committed_cost_units_after,
                    cap,
                    Some(
                        self.budget_execution_receipt_metadata(
                            charge,
                            Some(("reversed", &reverse)),
                        ),
                    ),
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
                        let reverse = self.reverse_budget_charge(&cap.id, charge)?;
                        return self.build_pre_execution_monetary_deny_response_with_metadata(
                            request,
                            &msg,
                            now,
                            charge,
                            reverse.committed_cost_units_after,
                            cap,
                            Some(self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", &reverse)),
                            )),
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
            let mut sessions = self
                .sessions
                .write()
                .map_err(|_| KernelError::Internal("session state lock poisoned".to_string()))?;
            let mut bridge = SessionNestedFlowBridge {
                sessions: &mut sessions,
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
                let _ = self.unwind_aborted_monetary_invocation(
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
                let unwind = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                if request_id == parent_context.request_id {
                    self.with_session_mut(&parent_context.session_id, |session| {
                        session.request_cancellation(&parent_context.request_id)?;
                        Ok(())
                    })?;
                }
                warn!(
                    request_id = %request.request_id,
                    reason = %reason,
                    "tool call cancelled"
                );
                return self.build_cancelled_response_with_metadata(
                    request,
                    &reason,
                    now,
                    Some(matched_grant_index),
                    match (charge_result.as_ref(), unwind.as_ref()) {
                        (Some(charge), Some(reverse)) => {
                            Some(self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ))
                        }
                        _ => None,
                    },
                );
            }
            Err(KernelError::RequestIncomplete(reason)) => {
                let unwind = self.unwind_aborted_monetary_invocation(
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
                return self.build_incomplete_response_with_output_and_metadata(
                    request,
                    None,
                    &reason,
                    now,
                    Some(matched_grant_index),
                    match (charge_result.as_ref(), unwind.as_ref()) {
                        (Some(charge), Some(reverse)) => {
                            Some(self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ))
                        }
                        _ => None,
                    },
                );
            }
            Err(error) => {
                let unwind = self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "tool server error");
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    Some(matched_grant_index),
                    match (charge_result.as_ref(), unwind.as_ref()) {
                        (Some(charge), Some(reverse)) => {
                            Some(self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ))
                        }
                        _ => None,
                    },
                );
            }
        };
        self.finalize_budgeted_tool_output_with_cost_and_metadata(
            request,
            tool_output,
            tool_started_at.elapsed(),
            now,
            matched_grant_index,
            FinalizeToolOutputCostContext {
                charge_result,
                reported_cost: None,
                payment_authorization,
                cap,
            },
            None,
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
    pub fn revoke_capability(&self, capability_id: &CapabilityId) -> Result<(), KernelError> {
        info!(capability_id = %capability_id, "revoking capability");
        let _ = self.with_revocation_store(|store| Ok(store.revoke(capability_id)?))?;
        Ok(())
    }

    /// Read-only access to the receipt log.
    pub fn receipt_log(&self) -> ReceiptLog {
        match self.receipt_log.lock() {
            Ok(log) => log.clone(),
            Err(_) => panic!("receipt log lock poisoned"),
        }
    }

    pub fn child_receipt_log(&self) -> ChildReceiptLog {
        match self.child_receipt_log.lock() {
            Ok(log) => log.clone(),
            Err(_) => panic!("child receipt log lock poisoned"),
        }
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
        &self,
        session_id: &SessionId,
        elicitation_id: impl Into<String>,
        related_task_id: Option<String>,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.register_pending_url_elicitation(elicitation_id, related_task_id);
            Ok(())
        })
    }

    pub fn register_session_required_url_elicitations(
        &self,
        session_id: &SessionId,
        elicitations: &[CreateElicitationOperation],
        related_task_id: Option<&str>,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.register_required_url_elicitations(elicitations, related_task_id);
            Ok(())
        })
    }

    pub fn queue_session_elicitation_completion(
        &self,
        session_id: &SessionId,
        elicitation_id: &str,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.queue_elicitation_completion(elicitation_id);
            Ok(())
        })
    }

    pub fn queue_session_late_event(
        &self,
        session_id: &SessionId,
        event: LateSessionEvent,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.queue_late_event(event);
            Ok(())
        })
    }

    pub fn queue_session_tool_server_event(
        &self,
        session_id: &SessionId,
        event: ToolServerEvent,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.queue_tool_server_event(event);
            Ok(())
        })
    }

    pub fn queue_session_tool_server_events(
        &self,
        session_id: &SessionId,
    ) -> Result<(), KernelError> {
        let events = self.drain_tool_server_events();
        self.with_session_mut(session_id, |session| {
            for event in events {
                session.queue_tool_server_event(event);
            }
            Ok(())
        })
    }

    pub fn drain_session_late_events(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<LateSessionEvent>, KernelError> {
        self.with_session_mut(session_id, |session| Ok(session.take_late_events()))
    }

    pub fn ca_count(&self) -> usize {
        self.config.ca_public_keys.len()
    }

    pub fn public_key(&self) -> arc_core::PublicKey {
        self.config.keypair.public_key()
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
        if self.with_revocation_store(|store| Ok(store.is_revoked(&cap.id)?))? {
            return Err(KernelError::CapabilityRevoked(cap.id.clone()));
        }
        for link in &cap.delegation_chain {
            if self.with_revocation_store(|store| Ok(store.is_revoked(&link.capability_id)?))? {
                return Err(KernelError::DelegationChainRevoked(
                    link.capability_id.clone(),
                ));
            }
        }
        Ok(())
    }

    fn validate_delegation_admission(&self, cap: &CapabilityToken) -> Result<(), KernelError> {
        if cap.delegation_chain.is_empty() {
            return Ok(());
        }

        arc_core::capability::validate_delegation_chain(
            &cap.delegation_chain,
            Some(self.config.max_delegation_depth),
        )
        .map_err(|error| KernelError::DelegationInvalid(error.to_string()))?;

        let last_link = cap
            .delegation_chain
            .last()
            .expect("delegation chain checked as non-empty");
        if last_link.delegatee != cap.subject {
            return Err(KernelError::DelegationInvalid(format!(
                "leaf capability subject {} does not match final delegation delegatee {}",
                cap.subject.to_hex(),
                last_link.delegatee.to_hex()
            )));
        }

        let mut ancestor_snapshots = Vec::with_capacity(cap.delegation_chain.len());
        for (index, link) in cap.delegation_chain.iter().enumerate() {
            let snapshot = self
                .with_receipt_store(
                    |store| Ok(store.get_capability_snapshot(&link.capability_id)?),
                )?
                .flatten()
                .ok_or_else(|| {
                    KernelError::DelegationInvalid(format!(
                        "missing capability snapshot for delegation ancestor {} at link index {}",
                        link.capability_id, index
                    ))
                })?;
            let expected_depth = index as u64;
            if snapshot.delegation_depth != expected_depth {
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation ancestor {} at link index {} has stored depth {}, expected {}",
                    snapshot.capability_id, index, snapshot.delegation_depth, expected_depth
                )));
            }

            let expected_parent_capability_id = index
                .checked_sub(1)
                .map(|parent_index| cap.delegation_chain[parent_index].capability_id.as_str());
            if snapshot.parent_capability_id.as_deref() != expected_parent_capability_id {
                let observed_parent = snapshot.parent_capability_id.as_deref().unwrap_or("<root>");
                let expected_parent = expected_parent_capability_id.unwrap_or("<root>");
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation ancestor {} at link index {} is lineage-linked to {}, expected {}",
                    snapshot.capability_id, index, observed_parent, expected_parent
                )));
            }

            ancestor_snapshots.push(snapshot);
        }

        for (index, link) in cap.delegation_chain.iter().enumerate() {
            let parent_snapshot = &ancestor_snapshots[index];
            let parent_scope = scope_from_capability_snapshot(parent_snapshot)?;

            if parent_snapshot.subject_key != link.delegator.to_hex() {
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation link {} delegator {} does not match parent capability subject {}",
                    index,
                    link.delegator.to_hex(),
                    parent_snapshot.subject_key
                )));
            }
            if link.timestamp < parent_snapshot.issued_at
                || link.timestamp >= parent_snapshot.expires_at
            {
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation link {} timestamp {} is outside parent capability {} validity window [{} , {})",
                    index,
                    link.timestamp,
                    parent_snapshot.capability_id,
                    parent_snapshot.issued_at,
                    parent_snapshot.expires_at
                )));
            }

            let (
                child_capability_id,
                child_subject_key,
                child_scope,
                child_issued_at,
                child_expires_at,
                child_parent_capability_id,
            ) = if let Some(next_snapshot) = ancestor_snapshots.get(index + 1) {
                (
                    next_snapshot.capability_id.clone(),
                    next_snapshot.subject_key.clone(),
                    scope_from_capability_snapshot(next_snapshot)?,
                    next_snapshot.issued_at,
                    next_snapshot.expires_at,
                    next_snapshot.parent_capability_id.clone(),
                )
            } else {
                (
                    cap.id.clone(),
                    cap.subject.to_hex(),
                    cap.scope.clone(),
                    cap.issued_at,
                    cap.expires_at,
                    Some(link.capability_id.clone()),
                )
            };

            if child_subject_key != link.delegatee.to_hex() {
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation link {} delegatee {} does not match child capability subject {}",
                    index,
                    link.delegatee.to_hex(),
                    child_subject_key
                )));
            }
            if child_parent_capability_id.as_deref() != Some(link.capability_id.as_str()) {
                return Err(KernelError::DelegationInvalid(format!(
                    "child capability {} is not lineage-linked to parent capability {}",
                    child_capability_id, link.capability_id
                )));
            }
            if child_issued_at < link.timestamp {
                return Err(KernelError::DelegationInvalid(format!(
                    "child capability {} was issued before delegation link {} timestamp",
                    child_capability_id, index
                )));
            }
            if child_issued_at < parent_snapshot.issued_at {
                return Err(KernelError::DelegationInvalid(format!(
                    "child capability {} predates parent capability {} issuance",
                    child_capability_id, parent_snapshot.capability_id
                )));
            }
            if child_expires_at > parent_snapshot.expires_at {
                return Err(KernelError::DelegationInvalid(format!(
                    "child capability {} expires after parent capability {}",
                    child_capability_id, parent_snapshot.capability_id
                )));
            }

            validate_delegation_scope_step(
                &parent_snapshot.capability_id,
                &child_capability_id,
                &parent_scope,
                &child_scope,
                child_expires_at,
                link,
            )?;
        }

        Ok(())
    }

    fn local_budget_event_authority(&self) -> BudgetEventAuthority {
        BudgetEventAuthority {
            authority_id: format!("kernel:{}", self.config.keypair.public_key().to_hex()),
            lease_id: "single-node".to_string(),
            lease_epoch: 0,
        }
    }

    fn budget_backend_receipt_metadata(&self) -> Result<serde_json::Value, KernelError> {
        let (guarantee_level, authority_profile, metering_profile) =
            self.with_budget_store(|store| {
                Ok((
                    store.budget_guarantee_level().as_str().to_string(),
                    store.budget_authority_profile().as_str().to_string(),
                    store.budget_metering_profile().as_str().to_string(),
                ))
            })?;
        Ok(serde_json::json!({
            "budget_authority": {
                "guarantee_level": guarantee_level,
                "authority_profile": authority_profile,
                "metering_profile": metering_profile,
            }
        }))
    }

    fn budget_execution_receipt_metadata(
        &self,
        charge: &BudgetChargeResult,
        terminal_event: Option<(&str, &BudgetHoldMutationDecision)>,
    ) -> serde_json::Value {
        let mut budget_authority = serde_json::Map::new();
        budget_authority.insert(
            "guarantee_level".to_string(),
            serde_json::json!(charge.authorize_metadata.guarantee_level.as_str()),
        );
        budget_authority.insert(
            "authority_profile".to_string(),
            serde_json::json!(charge.authorize_metadata.budget_profile.as_str()),
        );
        budget_authority.insert(
            "metering_profile".to_string(),
            serde_json::json!(charge.authorize_metadata.metering_profile.as_str()),
        );
        budget_authority.insert(
            "hold_id".to_string(),
            serde_json::json!(&charge.budget_hold_id),
        );
        if let Some(budget_term) = charge.authorize_metadata.budget_term() {
            budget_authority.insert("budget_term".to_string(), serde_json::json!(budget_term));
        }
        if let Some(authority) = charge.authorize_metadata.authority.as_ref() {
            budget_authority.insert(
                "authority".to_string(),
                serde_json::json!({
                    "authority_id": &authority.authority_id,
                    "lease_id": &authority.lease_id,
                    "lease_epoch": authority.lease_epoch,
                }),
            );
        }

        let mut authorize = serde_json::Map::new();
        if let Some(event_id) = charge.authorize_metadata.event_id.as_ref() {
            authorize.insert("event_id".to_string(), serde_json::json!(event_id));
        }
        if let Some(commit_index) = charge.authorize_metadata.budget_commit_index {
            authorize.insert(
                "budget_commit_index".to_string(),
                serde_json::json!(commit_index),
            );
        }
        authorize.insert(
            "exposure_units".to_string(),
            serde_json::json!(charge.cost_charged),
        );
        authorize.insert(
            "committed_cost_units_after".to_string(),
            serde_json::json!(charge.new_committed_cost_units),
        );
        budget_authority.insert(
            "authorize".to_string(),
            serde_json::Value::Object(authorize),
        );

        if let Some((disposition, terminal_event)) = terminal_event {
            let mut terminal = serde_json::Map::new();
            terminal.insert("disposition".to_string(), serde_json::json!(disposition));
            if let Some(event_id) = terminal_event.metadata.event_id.as_ref() {
                terminal.insert("event_id".to_string(), serde_json::json!(event_id));
            }
            if let Some(commit_index) = terminal_event.metadata.budget_commit_index {
                terminal.insert(
                    "budget_commit_index".to_string(),
                    serde_json::json!(commit_index),
                );
            }
            terminal.insert(
                "exposure_units".to_string(),
                serde_json::json!(terminal_event.exposure_units),
            );
            terminal.insert(
                "realized_spend_units".to_string(),
                serde_json::json!(terminal_event.realized_spend_units),
            );
            terminal.insert(
                "committed_cost_units_after".to_string(),
                serde_json::json!(terminal_event.committed_cost_units_after),
            );
            budget_authority.insert("terminal".to_string(), serde_json::Value::Object(terminal));
        }

        serde_json::json!({ "budget_authority": budget_authority })
    }

    fn merge_budget_receipt_metadata(
        &self,
        extra_metadata: Option<serde_json::Value>,
        budget_metadata: serde_json::Value,
    ) -> Option<serde_json::Value> {
        merge_metadata_objects(extra_metadata, Some(budget_metadata))
    }

    /// Check and decrement the invocation budget for a capability.
    ///
    /// Returns `(matched_grant_index, Option<BudgetChargeResult>)`.
    /// The charge result is populated only for monetary grants.
    fn check_and_increment_budget(
        &self,
        request_id: &str,
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
                let budget_hold_id =
                    format!("budget-hold:{}:{}:{}", request_id, cap.id, matching.index);
                let authorize_event_id = format!("{budget_hold_id}:authorize");
                let authority = self.local_budget_event_authority();

                let decision = self.with_budget_store(|store| {
                    Ok(store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
                        capability_id: cap.id.clone(),
                        grant_index: matching.index,
                        max_invocations: grant.max_invocations,
                        requested_exposure_units: cost_units,
                        max_cost_per_invocation: max_per,
                        max_total_cost_units: max_total,
                        hold_id: Some(budget_hold_id.clone()),
                        event_id: Some(authorize_event_id),
                        authority: Some(authority.clone()),
                    })?)
                })?;
                match decision {
                    BudgetAuthorizeHoldDecision::Authorized(authorized) => {
                        let charge = BudgetChargeResult {
                            grant_index: matching.index,
                            cost_charged: cost_units,
                            currency,
                            budget_total,
                            new_committed_cost_units: authorized.committed_cost_units_after,
                            budget_hold_id: authorized
                                .hold_id
                                .unwrap_or_else(|| budget_hold_id.clone()),
                            authorize_metadata: authorized.metadata,
                        };
                        return Ok((matching.index, Some(charge)));
                    }
                    BudgetAuthorizeHoldDecision::Denied(_) => {
                        saw_exhausted_budget = true;
                    }
                }
            } else {
                // Non-monetary path: use try_increment as before.
                if self.with_budget_store(|store| {
                    Ok(store.try_increment(&cap.id, matching.index, grant.max_invocations)?)
                })? {
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
        &self,
        capability_id: &str,
        charge: &BudgetChargeResult,
    ) -> Result<BudgetReverseHoldDecision, KernelError> {
        let authority = charge.authorize_metadata.authority.clone();
        self.with_budget_store(|store| {
            Ok(store.reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: capability_id.to_string(),
                grant_index: charge.grant_index,
                reversed_exposure_units: charge.cost_charged,
                hold_id: Some(charge.budget_hold_id.clone()),
                event_id: Some(charge.reverse_event_id()),
                authority,
            })?)
        })
    }

    fn reconcile_budget_charge(
        &self,
        capability_id: &str,
        charge: &BudgetChargeResult,
        realized_cost_units: u64,
    ) -> Result<BudgetReconcileHoldDecision, KernelError> {
        let authority = charge.authorize_metadata.authority.clone();
        self.with_budget_store(|store| {
            Ok(store.reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: capability_id.to_string(),
                grant_index: charge.grant_index,
                exposed_cost_units: charge.cost_charged,
                realized_spend_units: realized_cost_units.min(charge.cost_charged),
                hold_id: Some(charge.budget_hold_id.clone()),
                event_id: Some(charge.reconcile_event_id()),
                authority,
            })?)
        })
    }

    #[allow(dead_code)]
    fn reduce_budget_charge_to_actual(
        &self,
        capability_id: &str,
        charge: &BudgetChargeResult,
        actual_cost_units: u64,
    ) -> Result<u64, KernelError> {
        Ok(self
            .reconcile_budget_charge(
                capability_id,
                charge,
                actual_cost_units.min(charge.cost_charged),
            )?
            .committed_cost_units_after)
    }

    fn finalize_budgeted_tool_output_with_cost_and_metadata(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
        cost_context: FinalizeToolOutputCostContext<'_>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let FinalizeToolOutputCostContext {
            charge_result,
            reported_cost,
            payment_authorization,
            cap,
        } = cost_context;
        let Some(charge) = charge_result else {
            return self.finalize_tool_output_with_metadata(
                request,
                output,
                elapsed,
                timestamp,
                matched_grant_index,
                extra_metadata,
            );
        };

        let reported_cost_ref = reported_cost.as_ref();
        let mut oracle_evidence = None;
        let mut cross_currency_note = None;
        let (actual_cost, cross_currency_failed) = if let Some(cost) =
            reported_cost_ref.filter(|cost| cost.currency != charge.currency)
        {
            match self.resolve_cross_currency_cost(cost, &charge.currency, timestamp) {
                Ok((converted_units, evidence)) => {
                    oracle_evidence = Some(evidence);
                    cross_currency_note = Some(serde_json::json!({
                        "oracle_conversion": {
                            "status": "applied",
                            "reported_currency": cost.currency,
                            "grant_currency": charge.currency,
                            "reported_units": cost.units,
                            "converted_units": converted_units
                        }
                    }));
                    (converted_units, false)
                }
                Err(error) => {
                    warn!(
                        request_id = %request.request_id,
                        reported_currency = %cost.currency,
                        charged_currency = %charge.currency,
                        reason = %error,
                        "cross-currency reconciliation failed; closing hold at authorized exposure"
                    );
                    cross_currency_note = Some(serde_json::json!({
                        "oracle_conversion": {
                            "status": "failed",
                            "reported_currency": cost.currency,
                            "grant_currency": charge.currency,
                            "reported_units": cost.units,
                            "provisional_units": charge.cost_charged,
                            "reason": error.to_string()
                        }
                    }));
                    (charge.cost_charged, true)
                }
            }
        } else {
            (
                reported_cost_ref
                    .map(|cost| cost.units)
                    .unwrap_or(charge.cost_charged),
                false,
            )
        };

        let payment_already_settled = payment_authorization
            .as_ref()
            .is_some_and(|authorization| authorization.settled);
        let cost_overrun =
            !cross_currency_failed && actual_cost > charge.cost_charged && charge.cost_charged > 0;

        if cost_overrun {
            warn!(
                request_id = %request.request_id,
                reported = actual_cost,
                charged = charge.cost_charged,
                "tool server reported cost exceeds max_cost_per_invocation; settlement_status=failed"
            );
        }

        let realized_budget_units =
            if cross_currency_failed || payment_already_settled || cost_overrun {
                charge.cost_charged
            } else {
                actual_cost.min(charge.cost_charged)
            };
        let reconcile = self.reconcile_budget_charge(&cap.id, &charge, realized_budget_units)?;
        let running_committed_cost_units = reconcile.committed_cost_units_after;

        let payment_result = if let Some(authorization) = payment_authorization.as_ref() {
            if authorization.settled || cross_currency_failed || cost_overrun {
                None
            } else {
                let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                    KernelError::Internal(
                        "payment authorization present without configured adapter".to_string(),
                    )
                })?;
                Some(if actual_cost == 0 {
                    adapter.release(&authorization.authorization_id, &request.request_id)
                } else {
                    adapter.capture(
                        &authorization.authorization_id,
                        actual_cost,
                        &charge.currency,
                        &request.request_id,
                    )
                })
            }
        } else {
            None
        };

        let settlement = if cross_currency_failed || cost_overrun {
            ReceiptSettlement {
                payment_reference: payment_authorization
                    .as_ref()
                    .map(|authorization| authorization.authorization_id.clone()),
                settlement_status: SettlementStatus::Failed,
            }
        } else if let Some(authorization) = payment_authorization.as_ref() {
            if authorization.settled {
                ReceiptSettlement::from_authorization(authorization)
            } else if let Some(payment_result) = payment_result.as_ref() {
                match payment_result {
                    Ok(result) => ReceiptSettlement::from_payment_result(result),
                    Err(error) => {
                        warn!(
                            request_id = %request.request_id,
                            reason = %error,
                            "post-execution payment settlement failed"
                        );
                        ReceiptSettlement {
                            payment_reference: Some(authorization.authorization_id.clone()),
                            settlement_status: SettlementStatus::Failed,
                        }
                    }
                }
            } else {
                warn!(
                    request_id = %request.request_id,
                    authorization_id = %authorization.authorization_id,
                    "unsettled authorization completed without a payment result"
                );
                ReceiptSettlement {
                    payment_reference: Some(authorization.authorization_id.clone()),
                    settlement_status: SettlementStatus::Failed,
                }
            }
        } else {
            ReceiptSettlement::settled()
        };
        let recorded_cost = if payment_already_settled && !cross_currency_failed && !cost_overrun {
            charge.cost_charged
        } else {
            actual_cost
        };

        let budget_remaining = charge
            .budget_total
            .saturating_sub(running_committed_cost_units);
        let delegation_depth = cap.delegation_chain.len() as u32;
        let root_budget_holder = cap.issuer.to_hex();
        let (payment_reference, settlement_status) = settlement.into_receipt_parts();
        let payment_breakdown = payment_authorization.as_ref().map(|authorization| {
            serde_json::json!({
                "payment": {
                    "authorization_id": authorization.authorization_id,
                    "adapter_metadata": authorization.metadata,
                    "preauthorized_units": charge.cost_charged,
                    "recorded_units": recorded_cost
                }
            })
        });

        let financial_meta = FinancialReceiptMetadata {
            grant_index: charge.grant_index as u32,
            cost_charged: recorded_cost,
            currency: charge.currency.clone(),
            budget_remaining,
            budget_total: charge.budget_total,
            delegation_depth,
            root_budget_holder,
            payment_reference,
            settlement_status,
            cost_breakdown: merge_metadata_objects(
                merge_metadata_objects(
                    reported_cost_ref.and_then(|cost| cost.breakdown.clone()),
                    payment_breakdown,
                ),
                cross_currency_note,
            ),
            oracle_evidence,
            attempted_cost: None,
        };

        let limited_output = self.apply_stream_limits(output, elapsed)?;
        let tool_call_output = match &limited_output {
            ToolServerOutput::Value(value) => ToolCallOutput::Value(value.clone()),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => {
                ToolCallOutput::Stream(stream.clone())
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, .. }) => {
                ToolCallOutput::Stream(stream.clone())
            }
        };

        let budget_metadata =
            self.budget_execution_receipt_metadata(&charge, Some(("reconciled", &reconcile)));
        let merged_extra_metadata =
            self.merge_budget_receipt_metadata(extra_metadata, budget_metadata);
        let financial_json = Some(serde_json::json!({ "financial": financial_meta }));
        let merged_extra_metadata = merge_metadata_objects(financial_json, merged_extra_metadata);

        match limited_output {
            ToolServerOutput::Value(_)
            | ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)) => self
                .build_allow_response_with_metadata(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(charge.grant_index),
                    merged_extra_metadata.clone(),
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => self
                .build_incomplete_response_with_output_and_metadata(
                    request,
                    Some(tool_call_output),
                    &reason,
                    timestamp,
                    Some(charge.grant_index),
                    merged_extra_metadata,
                ),
        }
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

    fn verify_governed_runtime_attestation(
        &self,
        attestation: &arc_core::capability::RuntimeAttestationEvidence,
        now: u64,
    ) -> Result<VerifiedRuntimeAttestationRecord, KernelError> {
        verify_governed_runtime_attestation_record(
            attestation,
            self.attestation_trust_policy.as_ref(),
            now,
        )
    }

    fn verify_governed_request_runtime_attestation(
        &self,
        request: &ToolCallRequest,
        now: u64,
    ) -> Result<Option<VerifiedRuntimeAttestationRecord>, KernelError> {
        request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.runtime_attestation.as_ref())
            .map(|attestation| self.verify_governed_runtime_attestation(attestation, now))
            .transpose()
    }

    fn validate_runtime_assurance(
        verified_runtime_attestation: Option<&VerifiedRuntimeAttestationRecord>,
        required_tier: RuntimeAssuranceTier,
        requirement_source: &str,
    ) -> Result<(), KernelError> {
        let Some(verified_runtime_attestation) = verified_runtime_attestation else {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "runtime attestation tier '{required_tier:?}' required by {requirement_source}"
            )));
        };

        if !verified_runtime_attestation.is_locally_accepted() {
            let reason = verified_runtime_attestation
                .policy_outcome
                .reason
                .as_deref()
                .unwrap_or(
                    "runtime attestation evidence did not cross a local verified trust boundary",
                );
            return Err(KernelError::GovernedTransactionDenied(format!(
                "runtime attestation tier '{required_tier:?}' required by {requirement_source}; {reason}"
            )));
        }

        let effective_tier = verified_runtime_attestation.effective_tier();
        if effective_tier < required_tier {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "runtime attestation tier '{effective_tier:?}' is below required '{required_tier:?}' for {requirement_source}"
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
            })?;

        // Step 7: Cap approval token lifetime. Tokens with expires_at more
        // than MAX_APPROVAL_TTL_SECS beyond issued_at are rejected to prevent
        // long-lived tokens from outliving the replay store's eviction window.
        const MAX_APPROVAL_TTL_SECS: u64 = 3600; // 1 hour max
        let token_lifetime = approval_token
            .expires_at
            .saturating_sub(approval_token.issued_at);
        if token_lifetime > MAX_APPROVAL_TTL_SECS {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "approval token lifetime ({token_lifetime}s) exceeds maximum ({MAX_APPROVAL_TTL_SECS}s)"
            )));
        }

        // Step 8: Single-use replay check. An approval token must not be
        // consumed more than once. The replay store TTL is set to
        // MAX_APPROVAL_TTL_SECS, which is >= any valid token's lifetime
        // (enforced by step 7). This guarantees a token can never be replayed
        // after cache eviction because the token itself will have expired
        // before eviction occurs.
        if let Some(ref replay_store) = self.approval_replay_store {
            let is_fresh = replay_store
                .check_and_insert(&approval_token.request_id, intent_hash)
                .map_err(|_| {
                    KernelError::GovernedTransactionDenied(
                        "approval replay store unavailable; denying as fail-closed".to_string(),
                    )
                })?;
            if !is_fresh {
                return Err(KernelError::GovernedTransactionDenied(
                    "approval token has already been consumed (replay detected)".to_string(),
                ));
            }
        }

        Ok(())
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
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        intent: &arc_core::capability::GovernedTransactionIntent,
        parent_context: Option<&OperationContext>,
        now: u64,
    ) -> Result<Option<ValidatedGovernedCallChainProof>, KernelError> {
        let Some(call_chain) = intent.call_chain.as_ref() else {
            return Ok(None);
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
        if let Some(parent_context) = parent_context {
            let local_parent_request_id = parent_context.request_id.to_string();
            if call_chain.parent_request_id != local_parent_request_id {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain.parent_request_id does not match the locally authenticated parent request".to_string(),
                ));
            }
            self.validate_parent_request_continuation(request, parent_context)?;
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
        if let Some(capability_delegator_subject) = cap
            .delegation_chain
            .last()
            .map(|link| link.delegator.to_hex())
        {
            if call_chain.delegator_subject != capability_delegator_subject {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain.delegator_subject does not match the validated capability delegation source".to_string(),
                ));
            }
        }
        if let Some(capability_origin_subject) = cap
            .delegation_chain
            .first()
            .map(|link| link.delegator.to_hex())
        {
            if call_chain.origin_subject != capability_origin_subject {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain.origin_subject does not match the validated capability lineage origin".to_string(),
                ));
            }
        }

        self.validate_governed_call_chain_upstream_proof(
            request,
            cap,
            intent,
            call_chain,
            parent_context,
            now,
        )
    }

    fn validate_governed_call_chain_upstream_proof(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        intent: &arc_core::capability::GovernedTransactionIntent,
        call_chain: &arc_core::capability::GovernedCallChainContext,
        parent_context: Option<&OperationContext>,
        now: u64,
    ) -> Result<Option<ValidatedGovernedCallChainProof>, KernelError> {
        if let Some(continuation_token) = intent.explicit_continuation_token().map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "governed call_chain continuation token is malformed: {error}"
            ))
        })? {
            let signature_valid = continuation_token.verify_signature().map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "governed call_chain continuation token failed signature verification: {error}"
                ))
            })?;
            if !signature_valid {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token failed signature verification"
                        .to_string(),
                ));
            }
            continuation_token.validate_time(now).map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "governed call_chain continuation token rejected by time bounds: {error}"
                ))
            })?;
            if continuation_token.subject != cap.subject {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token subject does not match the capability subject"
                        .to_string(),
                ));
            }
            if continuation_token.current_subject != cap.subject.to_hex() {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token current_subject does not match the capability subject"
                        .to_string(),
                ));
            }

            let signer_matches_capability_lineage = cap
                .delegation_chain
                .last()
                .is_some_and(|link| link.delegator == continuation_token.signer);
            if !self.is_trusted_governed_continuation_signer(&continuation_token.signer)
                && !signer_matches_capability_lineage
            {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token signer is not trusted".to_string(),
                ));
            }
            if continuation_token.chain_id != call_chain.chain_id {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token chain_id does not match the asserted call_chain".to_string(),
                ));
            }
            if continuation_token.parent_request_id != call_chain.parent_request_id {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token parent_request_id does not match the asserted call_chain".to_string(),
                ));
            }
            if continuation_token.parent_receipt_id != call_chain.parent_receipt_id {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token parent_receipt_id does not match the asserted call_chain".to_string(),
                ));
            }
            if continuation_token.origin_subject != call_chain.origin_subject {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token origin_subject does not match the asserted call_chain".to_string(),
                ));
            }
            if continuation_token.delegator_subject != call_chain.delegator_subject {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token delegator_subject does not match the asserted call_chain".to_string(),
                ));
            }
            if continuation_token.audience.is_some()
                && !continuation_token.matches_target(&request.server_id, &request.tool_name)
            {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token target does not match the tool call"
                        .to_string(),
                ));
            }
            if let Some(expected_intent_hash) = continuation_token.governed_intent_hash.as_deref() {
                let intent_hash = intent.binding_hash().map_err(|error| {
                    KernelError::GovernedTransactionDenied(format!(
                        "failed to hash governed transaction intent for continuation validation: {error}"
                    ))
                })?;
                if expected_intent_hash != intent_hash {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token intent_hash does not match the governed intent".to_string(),
                    ));
                }
            }
            if let Some(parent_capability_id) = continuation_token.parent_capability_id.as_deref() {
                let Some(expected_parent_capability_id) = cap
                    .delegation_chain
                    .last()
                    .map(|link| link.capability_id.as_str())
                else {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token parent_capability_id requires a delegated capability lineage".to_string(),
                    ));
                };
                if parent_capability_id != expected_parent_capability_id {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token parent_capability_id does not match the capability lineage".to_string(),
                    ));
                }
            }
            if let Some(expected_link_hash) = continuation_token.delegation_link_hash.as_deref() {
                let Some(last_link) = cap.delegation_chain.last() else {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token delegation_link_hash requires a delegated capability lineage".to_string(),
                    ));
                };
                let actual_link_hash =
                    canonical_json_bytes(&last_link.body()).map_err(|error| {
                        KernelError::GovernedTransactionDenied(format!(
                            "failed to hash capability delegation lineage for continuation validation: {error}"
                        ))
                    })?;
                if sha256_hex(&actual_link_hash) != expected_link_hash {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token delegation_link_hash does not match the capability lineage".to_string(),
                    ));
                }
            }

            let local_parent_receipt = if let Some(parent_receipt_id) =
                continuation_token.parent_receipt_id.as_deref()
            {
                match self.local_receipt_artifact(parent_receipt_id) {
                    Some(parent_receipt) => {
                        let signature_valid = parent_receipt.verify_signature()?;
                        if !signature_valid {
                            return Err(KernelError::GovernedTransactionDenied(
                                "governed call_chain parent receipt failed signature verification"
                                    .to_string(),
                            ));
                        }
                        Some(parent_receipt)
                    }
                    None => {
                        if continuation_token.parent_receipt_hash.is_some()
                            || continuation_token.parent_session_anchor.is_some()
                        {
                            return Err(KernelError::GovernedTransactionDenied(
                                "governed call_chain continuation token parent_receipt_id does not resolve to a locally persisted receipt".to_string(),
                            ));
                        }
                        None
                    }
                }
            } else {
                if continuation_token.parent_receipt_hash.is_some() {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token parent_receipt_hash requires parent_receipt_id".to_string(),
                    ));
                }
                None
            };

            if let Some(expected_parent_receipt_hash) =
                continuation_token.parent_receipt_hash.as_deref()
            {
                let Some(parent_receipt) = local_parent_receipt.as_ref() else {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token parent_receipt_hash requires a locally persisted parent receipt".to_string(),
                    ));
                };
                if parent_receipt.artifact_hash()? != expected_parent_receipt_hash {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token parent_receipt_hash does not match the authoritative parent receipt".to_string(),
                    ));
                }
            }

            let validated_session_anchor_id = if let Some(parent_session_anchor) =
                continuation_token.parent_session_anchor.as_ref()
            {
                let authoritative_parent_anchor = if let Some(parent_context) = parent_context {
                    Some(self.with_session(&parent_context.session_id, |session| {
                        session.validate_context(parent_context)?;
                        Ok(session.session_anchor().reference())
                    })?)
                } else {
                    local_parent_receipt
                        .as_ref()
                        .and_then(LocalReceiptArtifact::session_anchor_reference)
                };
                let Some(authoritative_parent_anchor) = authoritative_parent_anchor else {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token parent_session_anchor could not be verified against authoritative parent lineage".to_string(),
                    ));
                };
                if authoritative_parent_anchor != *parent_session_anchor {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token session anchor does not match the authoritative parent lineage".to_string(),
                    ));
                }
                Some(parent_session_anchor.session_anchor_id.clone())
            } else {
                None
            };

            return Ok(Some(ValidatedGovernedCallChainProof {
                upstream_proof: None,
                continuation_token_id: Some(continuation_token.token_id.clone()),
                session_anchor_id: validated_session_anchor_id,
            }));
        }

        let Some(upstream_proof) = intent.upstream_call_chain_proof().map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "governed call_chain upstream proof is malformed: {error}"
            ))
        })?
        else {
            return Ok(None);
        };

        let signature_valid = upstream_proof.verify_signature().map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "governed call_chain upstream proof failed signature verification: {error}"
            ))
        })?;
        if !signature_valid {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof failed signature verification".to_string(),
            ));
        }
        upstream_proof.validate_time(now).map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "governed call_chain upstream proof rejected by time bounds: {error}"
            ))
        })?;
        if upstream_proof.subject != cap.subject {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof subject does not match the capability subject"
                    .to_string(),
            ));
        }

        let Some(expected_signer) = cap.delegation_chain.last().map(|link| &link.delegator) else {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof requires a delegated capability lineage"
                    .to_string(),
            ));
        };
        if upstream_proof.signer != *expected_signer {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof signer does not match the validated capability delegation source".to_string(),
            ));
        }
        if upstream_proof.chain_id != call_chain.chain_id {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof chain_id does not match the asserted call_chain".to_string(),
            ));
        }
        if upstream_proof.parent_request_id != call_chain.parent_request_id {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof parent_request_id does not match the asserted call_chain".to_string(),
            ));
        }
        if upstream_proof.parent_receipt_id != call_chain.parent_receipt_id {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof parent_receipt_id does not match the asserted call_chain".to_string(),
            ));
        }
        if upstream_proof.origin_subject != call_chain.origin_subject {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof origin_subject does not match the asserted call_chain".to_string(),
            ));
        }
        if upstream_proof.delegator_subject != call_chain.delegator_subject {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof delegator_subject does not match the asserted call_chain".to_string(),
            ));
        }

        Ok(Some(ValidatedGovernedCallChainProof {
            upstream_proof: Some(upstream_proof),
            continuation_token_id: None,
            session_anchor_id: None,
        }))
    }

    fn validate_governed_autonomy_bond(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        bond_id: &str,
        now: u64,
    ) -> Result<(), KernelError> {
        let Some(bond_row) = self.with_receipt_store(|store| {
            store.resolve_credit_bond(bond_id).map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "failed to resolve delegation bond `{bond_id}`: {error}"
                ))
            })
        })?
        else {
            return Err(KernelError::GovernedTransactionDenied(
                "delegation bond lookup unavailable because no receipt store is configured"
                    .to_string(),
            ));
        };
        let bond_row = bond_row.ok_or_else(|| {
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
        verified_runtime_attestation: Option<&VerifiedRuntimeAttestationRecord>,
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
        let requirement_source = format!("governed autonomy tier '{:?}'", autonomy.tier);
        Self::validate_runtime_assurance(
            verified_runtime_attestation,
            required_runtime_assurance,
            &requirement_source,
        )?;

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
        parent_context: Option<&OperationContext>,
        now: u64,
    ) -> Result<Option<ValidatedGovernedCallChainProof>, KernelError> {
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
            return Ok(None);
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

        let verified_runtime_attestation =
            self.verify_governed_request_runtime_attestation(request, now)?;

        let validated_upstream_call_chain_proof =
            self.validate_governed_call_chain_context(request, cap, intent, parent_context, now)?;

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
            Self::validate_runtime_assurance(
                verified_runtime_attestation.as_ref(),
                required_tier,
                "grant",
            )?;
        }
        self.validate_governed_autonomy(
            request,
            cap,
            intent,
            minimum_autonomy_tier,
            verified_runtime_attestation.as_ref(),
            now,
        )?;

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

        Ok(validated_upstream_call_chain_proof)
    }

    fn governed_call_chain_receipt_evidence(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        parent_context: Option<&OperationContext>,
        validated_proof: Option<ValidatedGovernedCallChainProof>,
    ) -> Option<GovernedCallChainReceiptEvidence> {
        let call_chain = request.governed_intent.as_ref()?.call_chain.as_ref()?;
        let continuation_token_id = validated_proof
            .as_ref()
            .and_then(|proof| proof.continuation_token_id.clone());
        let session_anchor_id = validated_proof
            .as_ref()
            .and_then(|proof| proof.session_anchor_id.clone());
        let upstream_proof = validated_proof.and_then(|proof| proof.upstream_proof);
        let local_parent_request_id = parent_context
            .map(|context| context.request_id.to_string())
            .filter(|_| {
                parent_context.is_some_and(|context| {
                    self.validate_parent_request_continuation(request, context)
                        .is_ok()
                })
            });
        let local_parent_receipt_id = call_chain
            .parent_receipt_id
            .as_ref()
            .filter(|receipt_id| self.has_local_receipt_id(receipt_id))
            .cloned();
        let capability_delegator_subject = cap
            .delegation_chain
            .last()
            .map(|link| link.delegator.to_hex());
        let capability_origin_subject = cap
            .delegation_chain
            .first()
            .map(|link| link.delegator.to_hex());

        if local_parent_request_id.is_none()
            && local_parent_receipt_id.is_none()
            && capability_delegator_subject.is_none()
            && capability_origin_subject.is_none()
            && continuation_token_id.is_none()
            && session_anchor_id.is_none()
            && upstream_proof.is_none()
        {
            return None;
        }

        Some(GovernedCallChainReceiptEvidence {
            local_parent_request_id,
            local_parent_receipt_id,
            capability_delegator_subject,
            capability_origin_subject,
            upstream_proof,
            continuation_token_id,
            session_anchor_id,
        })
    }

    fn validate_parent_request_continuation(
        &self,
        request: &ToolCallRequest,
        parent_context: &OperationContext,
    ) -> Result<(), KernelError> {
        let child_request_id = RequestId::new(request.request_id.clone());
        self.with_session(&parent_context.session_id, |session| {
            session.validate_context(parent_context)?;
            session
                .validate_parent_request_lineage(&child_request_id, &parent_context.request_id)?;
            Ok(())
        })
    }

    fn has_local_receipt_id(&self, receipt_id: &str) -> bool {
        let arc_receipt_match = self.receipt_log.lock().ok().is_some_and(|log| {
            log.receipts()
                .iter()
                .any(|receipt| receipt.id == receipt_id)
        });
        if arc_receipt_match {
            return true;
        }

        self.child_receipt_log.lock().ok().is_some_and(|log| {
            log.receipts()
                .iter()
                .any(|receipt| receipt.id == receipt_id)
        })
    }

    fn is_trusted_governed_continuation_signer(&self, signer: &arc_core::PublicKey) -> bool {
        if *signer == self.config.keypair.public_key() {
            return true;
        }
        if self
            .config
            .ca_public_keys
            .iter()
            .any(|candidate| candidate == signer)
        {
            return true;
        }
        self.capability_authority
            .trusted_public_keys()
            .into_iter()
            .any(|candidate| candidate == *signer)
    }

    fn local_receipt_artifact(&self, receipt_id: &str) -> Option<LocalReceiptArtifact> {
        let tool_match = self.receipt_log.lock().ok().and_then(|log| {
            log.receipts()
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(LocalReceiptArtifact::Tool)
        });
        if tool_match.is_some() {
            return tool_match;
        }

        self.child_receipt_log.lock().ok().and_then(|log| {
            log.receipts()
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(LocalReceiptArtifact::Child)
        })
    }

    fn unwind_aborted_monetary_invocation(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        charge_result: Option<&BudgetChargeResult>,
        payment_authorization: Option<&PaymentAuthorization>,
    ) -> Result<Option<BudgetReverseHoldDecision>, KernelError> {
        let Some(charge) = charge_result else {
            return Ok(None);
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

        Ok(Some(self.reverse_budget_charge(&cap.id, charge)?))
    }

    fn record_observed_capability_snapshot(
        &self,
        capability: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let parent_capability_id = capability
            .delegation_chain
            .last()
            .map(|link| link.capability_id.as_str());
        let _ = self.with_receipt_store(|store| {
            Ok(store.record_capability_snapshot(capability, parent_capability_id)?)
        })?;
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
    fn record_child_receipts(&self, receipts: Vec<ChildRequestReceipt>) -> Result<(), KernelError> {
        for receipt in receipts {
            let _ = self.with_receipt_store(|store| Ok(store.append_child_receipt(&receipt)?))?;
            self.child_receipt_log
                .lock()
                .map_err(|_| KernelError::Internal("child receipt log lock poisoned".to_string()))?
                .append(receipt);
        }
        Ok(())
    }
}

fn scope_from_capability_snapshot(
    snapshot: &crate::capability_lineage::CapabilitySnapshot,
) -> Result<ArcScope, KernelError> {
    serde_json::from_str(&snapshot.grants_json).map_err(|error| {
        KernelError::Internal(format!(
            "invalid capability snapshot scope for {}: {error}",
            snapshot.capability_id
        ))
    })
}

fn validate_delegation_scope_step(
    parent_capability_id: &str,
    child_capability_id: &str,
    parent_scope: &ArcScope,
    child_scope: &ArcScope,
    child_expires_at: u64,
    link: &arc_core::capability::DelegationLink,
) -> Result<(), KernelError> {
    validate_delegatable_subset(
        parent_capability_id,
        child_capability_id,
        parent_scope,
        child_scope,
    )?;
    validate_declared_attenuations(child_capability_id, child_scope, child_expires_at, link)?;
    Ok(())
}

fn validate_delegatable_subset(
    parent_capability_id: &str,
    child_capability_id: &str,
    parent_scope: &ArcScope,
    child_scope: &ArcScope,
) -> Result<(), KernelError> {
    for child_grant in &child_scope.grants {
        let allowed = parent_scope.grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !allowed {
            return Err(KernelError::DelegationInvalid(format!(
                "parent capability {} does not authorize delegated tool grant {}/{} on child capability {}",
                parent_capability_id,
                child_grant.server_id,
                child_grant.tool_name,
                child_capability_id
            )));
        }
    }

    for child_grant in &child_scope.resource_grants {
        let allowed = parent_scope.resource_grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !allowed {
            return Err(KernelError::DelegationInvalid(format!(
                "parent capability {} does not authorize delegated resource grant {} on child capability {}",
                parent_capability_id, child_grant.uri_pattern, child_capability_id
            )));
        }
    }

    for child_grant in &child_scope.prompt_grants {
        let allowed = parent_scope.prompt_grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !allowed {
            return Err(KernelError::DelegationInvalid(format!(
                "parent capability {} does not authorize delegated prompt grant {} on child capability {}",
                parent_capability_id, child_grant.prompt_name, child_capability_id
            )));
        }
    }

    Ok(())
}

fn validate_declared_attenuations(
    child_capability_id: &str,
    child_scope: &ArcScope,
    child_expires_at: u64,
    link: &arc_core::capability::DelegationLink,
) -> Result<(), KernelError> {
    for attenuation in &link.attenuations {
        match attenuation {
            arc_core::capability::Attenuation::RemoveTool {
                server_id,
                tool_name,
            } => {
                if child_scope
                    .grants
                    .iter()
                    .any(|grant| tool_grant_covers_target(grant, server_id, tool_name))
                {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} still grants removed tool {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
            arc_core::capability::Attenuation::RemoveOperation {
                server_id,
                tool_name,
                operation,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && grant.operations.contains(operation)
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} still grants removed operation {:?} on {}/{}",
                        child_capability_id, operation, server_id, tool_name
                    )));
                }
            }
            arc_core::capability::Attenuation::AddConstraint {
                server_id,
                tool_name,
                constraint,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && !grant.constraints.contains(constraint)
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} is missing declared constraint on {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
            arc_core::capability::Attenuation::ReduceBudget {
                server_id,
                tool_name,
                max_invocations,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && grant
                            .max_invocations
                            .is_none_or(|value| value > *max_invocations)
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} exceeds declared invocation budget on {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
            arc_core::capability::Attenuation::ShortenExpiry { new_expires_at } => {
                if child_expires_at > *new_expires_at {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} expires after declared shortened expiry {}",
                        child_capability_id, new_expires_at
                    )));
                }
            }
            arc_core::capability::Attenuation::ReduceCostPerInvocation {
                server_id,
                tool_name,
                max_cost_per_invocation,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && grant.max_cost_per_invocation.as_ref().is_none_or(|value| {
                            value.currency != max_cost_per_invocation.currency
                                || value.units > max_cost_per_invocation.units
                        })
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} exceeds declared per-invocation cost ceiling on {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
            arc_core::capability::Attenuation::ReduceTotalCost {
                server_id,
                tool_name,
                max_total_cost,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && grant.max_total_cost.as_ref().is_none_or(|value| {
                            value.currency != max_total_cost.currency
                                || value.units > max_total_cost.units
                        })
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} exceeds declared total-cost ceiling on {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
        }
    }

    Ok(())
}

fn tool_grant_covers_target(grant: &ToolGrant, server_id: &str, tool_name: &str) -> bool {
    (grant.server_id == "*" || grant.server_id == server_id)
        && (grant.tool_name == "*" || grant.tool_name == tool_name)
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

#[allow(dead_code)]
#[path = "responses.rs"]
mod responses;
#[path = "session_ops.rs"]
mod session_ops;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
