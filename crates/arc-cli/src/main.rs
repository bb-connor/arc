// ARC CLI -- command-line interface for the ARC runtime kernel.
//
// Provides commands for:
//
// - `arc run --policy <path> -- <command> [args...]`
//   Spawn an agent subprocess, set up the length-prefixed transport over
//   stdin/stdout pipes, and run the kernel message loop.
//
// - `arc check --policy <path> --tool <name> --params <json>`
//   Load a policy, create a kernel, and evaluate a single tool call.
//
// - `arc mcp serve --policy <path> --server-id <id> -- <command> [args...]`
//   Wrap an MCP server subprocess with the ARC kernel and expose an
//   MCP-compatible edge over stdio for stock MCP clients.

mod admin;
mod did;
mod passport;

pub use arc_control_plane::{
    authority_public_key_from_seed_file, build_kernel, certify, configure_budget_store,
    configure_capability_authority, configure_receipt_store, configure_revocation_store,
    enterprise_federation, evidence_export, issuance, issue_default_capabilities,
    load_or_create_authority_keypair, passport_verifier, policy, reputation, require_control_token,
    rotate_authority_keypair, trust_control, CliError,
};
pub use arc_hosted_mcp as remote_mcp;

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;
use tracing::{debug, error, info, warn};

use arc_core::appraisal::{
    RuntimeAttestationAppraisalImportRequest, RuntimeAttestationAppraisalRequest,
    RuntimeAttestationAppraisalResultExportRequest, RuntimeAttestationImportedAppraisalPolicy,
    SignedRuntimeAttestationAppraisalResult,
};
use arc_core::capability::{
    ArcScope, GovernedAutonomyTier, MonetaryAmount, RuntimeAssuranceTier,
    RuntimeAttestationEvidence,
};
use arc_core::crypto::Keypair;
use arc_core::message::{AgentMessage, KernelMessage, ToolCallError, ToolCallResult};
use arc_core::session::{
    OperationContext, OperationTerminalState, RequestId, SessionId, SessionOperation,
    ToolCallOperation,
};
use arc_kernel::transport::{ArcTransport, TransportError};
use arc_kernel::{
    ArcKernel, RevocationStore, SessionOperationResponse, ToolCallOutput,
    ToolCallRequest as KernelToolCallRequest, ToolCallStream,
};
use arc_mcp_adapter::{AdaptedMcpServer, ArcMcpEdge, McpAdapterConfig, McpEdgeConfig};

use crate::policy::load_policy;

/// ARC -- Attested Rights Channel.
///
/// Runtime security enforcement for AI agents via capability-based
/// authorization and signed audit receipts.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format: human-readable or JSON.
    #[arg(long, global = true, default_value = "false")]
    json: bool,

    /// Optional SQLite database path for durable receipt persistence.
    #[arg(long, global = true)]
    receipt_db: Option<PathBuf>,

    /// Optional SQLite database path for durable capability revocation persistence.
    #[arg(long, global = true)]
    revocation_db: Option<PathBuf>,

    /// Optional file path for a persistent capability-authority seed.
    #[arg(long, global = true)]
    authority_seed_file: Option<PathBuf>,

    /// Optional SQLite database path for shared capability-authority state.
    #[arg(long, global = true)]
    authority_db: Option<PathBuf>,

    /// Optional SQLite database path for durable shared capability budget state.
    #[arg(long, global = true)]
    budget_db: Option<PathBuf>,

    /// Optional SQLite database path for durable remote MCP session tombstones.
    #[arg(long, global = true)]
    session_db: Option<PathBuf>,

    /// Optional shared trust-control service base URL.
    #[arg(long, global = true)]
    control_url: Option<String>,

    /// Bearer token used to authenticate to the shared trust-control service.
    #[arg(long, global = true)]
    control_token: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Spawn an agent subprocess and enforce policy via the kernel.
    Run {
        /// Path to the policy YAML file.
        #[arg(long)]
        policy: PathBuf,

        /// The agent command and its arguments.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Evaluate a single tool call against a policy (no subprocess).
    Check {
        /// Path to the policy YAML file.
        #[arg(long)]
        policy: PathBuf,

        /// Tool name to evaluate.
        #[arg(long)]
        tool: String,

        /// Tool parameters as a JSON string.
        #[arg(long, default_value = "{}")]
        params: String,

        /// Server ID to use for the evaluation.
        #[arg(long, default_value = "*")]
        server: String,
    },

    /// Serve an MCP-compatible edge backed by the ARC kernel.
    Mcp {
        #[command(subcommand)]
        command: McpCommands,
    },

    /// Manage local trust-plane state such as persisted revocations.
    Trust {
        #[command(subcommand)]
        command: TrustCommands,
    },

    /// Query and list receipts from the receipt store.
    Receipt {
        #[command(subcommand)]
        command: ReceiptCommands,
    },

    /// Export an offline evidence package from the local receipt database.
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommands,
    },

    /// Evaluate a conformance corpus and emit a signed certification artifact.
    Certify {
        #[command(subcommand)]
        command: CertifyCommands,
    },

    /// Resolve self-certifying did:arc identifiers into DID Documents.
    Did {
        #[command(subcommand)]
        command: DidCommands,
    },

    /// Create, verify, and present Agent Passport bundles.
    Passport {
        #[command(subcommand)]
        command: PassportCommands,
    },

    /// Inspect local reputation scorecards from persisted receipts and lineage state.
    Reputation {
        #[command(subcommand)]
        command: ReputationCommands,
    },
}

#[derive(Subcommand)]
enum McpCommands {
    /// Wrap an MCP server subprocess and expose a secured MCP edge over stdio.
    Serve {
        /// Path to the policy YAML file.
        #[arg(long)]
        policy: PathBuf,

        /// Server ID to assign to the wrapped MCP server inside ARC.
        #[arg(long)]
        server_id: String,

        /// Human-readable name for the wrapped MCP server.
        #[arg(long)]
        server_name: Option<String>,

        /// Version string for the wrapped MCP server.
        #[arg(long)]
        server_version: Option<String>,

        /// Override the public key embedded in the synthetic manifest.
        #[arg(long)]
        manifest_public_key: Option<String>,

        /// Page size for paginated `tools/list` responses.
        #[arg(long, default_value_t = 50)]
        page_size: usize,

        /// Whether the edge should advertise `notifications/tools/list_changed`.
        #[arg(long, default_value_t = false)]
        tools_list_changed: bool,

        /// The wrapped MCP server command and its arguments.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Wrap an MCP server subprocess and expose a secured MCP edge over Streamable HTTP.
    ServeHttp {
        /// Path to the policy YAML file.
        #[arg(long)]
        policy: PathBuf,

        /// Server ID to assign to the wrapped MCP server inside ARC.
        #[arg(long)]
        server_id: String,

        /// Human-readable name for the wrapped MCP server.
        #[arg(long)]
        server_name: Option<String>,

        /// Version string for the wrapped MCP server.
        #[arg(long)]
        server_version: Option<String>,

        /// Override the public key embedded in the synthetic manifest.
        #[arg(long)]
        manifest_public_key: Option<String>,

        /// Page size for paginated `tools/list` responses.
        #[arg(long, default_value_t = 50)]
        page_size: usize,

        /// Whether the edge should advertise `notifications/tools/list_changed`.
        #[arg(long, default_value_t = false)]
        tools_list_changed: bool,

        /// Use one shared wrapped MCP subprocess for all remote sessions.
        #[arg(long, default_value_t = false)]
        shared_hosted_owner: bool,

        /// Socket address to bind the remote MCP edge to.
        #[arg(long, default_value = "127.0.0.1:8931")]
        listen: SocketAddr,

        /// Static bearer token required for remote MCP session admission.
        #[arg(long)]
        auth_token: Option<String>,

        /// Public key used to verify externally issued JWT bearer tokens.
        #[arg(long)]
        auth_jwt_public_key: Option<String>,

        /// OIDC discovery URL used to resolve issuer metadata and JWT JWKS keys.
        #[arg(long)]
        auth_jwt_discovery_url: Option<String>,

        /// OAuth2 token introspection endpoint used to validate opaque bearer tokens.
        #[arg(long)]
        auth_introspection_url: Option<String>,

        /// Client ID used when calling the token introspection endpoint.
        #[arg(long)]
        auth_introspection_client_id: Option<String>,

        /// Client secret used when calling the token introspection endpoint.
        #[arg(long)]
        auth_introspection_client_secret: Option<String>,

        /// Optional provider profile used for principal mapping and default OIDC discovery behavior.
        #[arg(long, value_enum)]
        auth_jwt_provider_profile: Option<remote_mcp::JwtProviderProfile>,

        /// Local auth-server signing seed file. When set, `serve-http` can issue JWTs itself.
        #[arg(long)]
        auth_server_seed_file: Option<PathBuf>,

        /// Persistent seed file used to derive stable ARC subjects from authenticated OAuth bearer principals.
        #[arg(long)]
        identity_federation_seed_file: Option<PathBuf>,

        /// Optional file-backed enterprise provider registry shared with trust-control.
        #[arg(long)]
        enterprise_providers_file: Option<PathBuf>,

        /// Expected bearer-token issuer for remote MCP session admission.
        #[arg(long)]
        auth_jwt_issuer: Option<String>,

        /// Expected bearer-token audience for remote MCP session admission.
        #[arg(long)]
        auth_jwt_audience: Option<String>,

        /// Optional static bearer token for remote admin APIs.
        #[arg(long)]
        admin_token: Option<String>,

        /// Public base URL used when constructing protected-resource metadata URLs.
        #[arg(long)]
        public_base_url: Option<String>,

        /// Authorization server URL advertised via protected-resource metadata.
        #[arg(long = "auth-server")]
        auth_servers: Vec<String>,

        /// OAuth authorization endpoint advertised in colocated auth-server metadata.
        #[arg(long)]
        auth_authorization_endpoint: Option<String>,

        /// OAuth token endpoint advertised in colocated auth-server metadata.
        #[arg(long)]
        auth_token_endpoint: Option<String>,

        /// Optional dynamic client registration endpoint advertised in auth-server metadata.
        #[arg(long)]
        auth_registration_endpoint: Option<String>,

        /// Optional JWKS URI advertised in auth-server metadata.
        #[arg(long)]
        auth_jwks_uri: Option<String>,

        /// Scope hint advertised in protected-resource challenges and metadata.
        #[arg(long = "auth-scope")]
        auth_scopes: Vec<String>,

        /// Subject to embed in locally issued auth-server access tokens.
        #[arg(long, default_value = "operator")]
        auth_subject: String,

        /// Authorization-code lifetime for the hosted auth server.
        #[arg(long, default_value_t = 300)]
        auth_code_ttl_secs: u64,

        /// Access-token lifetime for the hosted auth server.
        #[arg(long, default_value_t = 600)]
        auth_access_token_ttl_secs: u64,

        /// The wrapped MCP server command and its arguments.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum TrustCommands {
    /// Serve the shared trust-control plane over HTTP.
    Serve {
        /// Socket address to bind the trust-control service to.
        #[arg(long, default_value = "127.0.0.1:8940")]
        listen: SocketAddr,

        /// Bearer token required for trust-control service requests.
        #[arg(long)]
        service_token: String,

        /// Public base URL this trust-control node advertises to peers and clients.
        #[arg(long)]
        advertise_url: Option<String>,

        /// Peer trust-control base URL. Repeat for multiple peers.
        #[arg(long = "peer-url")]
        peer_urls: Vec<String>,

        /// Background cluster sync interval in milliseconds.
        #[arg(long, default_value_t = 500)]
        cluster_sync_interval_ms: u64,

        /// Optional policy file whose reputation issuance extension is enforced by the service.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Optional file-backed enterprise provider registry shared with remote MCP edges.
        #[arg(long)]
        enterprise_providers_file: Option<PathBuf>,

        /// Optional file-backed signed verifier policy registry for remote verifier flows.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,

        /// Optional SQLite verifier challenge-state database for replay-safe remote verifier flows.
        #[arg(long)]
        verifier_challenge_db: Option<PathBuf>,

        /// Optional file-backed passport lifecycle registry for publish/resolve/revoke flows.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,

        /// Optional file-backed passport issuance registry for OID4VCI-style pre-authorized offers.
        #[arg(long)]
        passport_issuance_offers_file: Option<PathBuf>,

        /// Optional file-backed certification registry for publish/resolve/revoke flows.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,

        /// Optional multi-operator certification discovery network file.
        #[arg(long)]
        certification_discovery_file: Option<PathBuf>,

        /// Public certification metadata TTL in seconds.
        #[arg(long, default_value_t = 3600)]
        certification_public_metadata_ttl_seconds: u64,
    },

    /// Manage enterprise federation provider-admin records.
    Provider {
        #[command(subcommand)]
        command: TrustProviderCommands,
    },

    /// Inspect shared remote evidence references used by local delegated activity.
    EvidenceShare {
        #[command(subcommand)]
        command: TrustEvidenceShareCommands,
    },

    /// Render derived external authorization context from governed receipts.
    AuthorizationContext {
        #[command(subcommand)]
        command: TrustAuthorizationContextCommands,
    },

    /// Export a signed runtime-attestation appraisal report.
    Appraisal {
        #[command(subcommand)]
        command: TrustRuntimeAttestationAppraisalCommands,
    },

    /// Export a signed insurer-facing behavioral feed from canonical trust data.
    BehavioralFeed {
        #[command(subcommand)]
        command: TrustBehavioralFeedCommands,
    },

    /// Export a signed exposure ledger from canonical trust and underwriting data.
    ExposureLedger {
        #[command(subcommand)]
        command: TrustExposureLedgerCommands,
    },

    /// Export a signed subject-scoped credit scorecard from exposure and reputation data.
    CreditScorecard {
        #[command(subcommand)]
        command: TrustCreditScorecardCommands,
    },

    /// Export a signed live capital book with explicit source-of-funds attribution.
    CapitalBook {
        #[command(subcommand)]
        command: TrustCapitalBookCommands,
    },

    /// Issue one custody-neutral escrow or reserve instruction artifact.
    CapitalInstruction {
        #[command(subcommand)]
        command: TrustCapitalInstructionCommands,
    },

    /// Issue one simulation-first capital-allocation decision for a governed action.
    CapitalAllocation {
        #[command(subcommand)]
        command: TrustCapitalAllocationCommands,
    },

    /// Evaluate, issue, and list bounded credit facilities from subject-scoped evidence.
    Facility {
        #[command(subcommand)]
        command: TrustCreditFacilityCommands,
    },

    /// Evaluate, issue, and list reserve-lock bond artifacts from credit evidence.
    Bond {
        #[command(subcommand)]
        command: TrustCreditBondCommands,
    },

    /// Evaluate, issue, and list immutable bond loss-lifecycle artifacts.
    Loss {
        #[command(subcommand)]
        command: TrustCreditLossLifecycleCommands,
    },

    /// Export deterministic credit backtests over historical subject-scoped evidence.
    CreditBacktest {
        #[command(subcommand)]
        command: TrustCreditBacktestCommands,
    },

    /// Export one signed provider-facing risk package over canonical credit truth.
    ProviderRiskPackage {
        #[command(subcommand)]
        command: TrustProviderRiskPackageCommands,
    },

    /// Issue, list, and resolve curated liability-market provider registry entries.
    LiabilityProvider {
        #[command(subcommand)]
        command: TrustLiabilityProviderCommands,
    },

    /// Issue quote, placement, and bound-coverage artifacts and list workflow state.
    LiabilityMarket {
        #[command(subcommand)]
        command: TrustLiabilityMarketCommands,
    },

    /// Export a signed underwriting policy-input snapshot from canonical trust data.
    UnderwritingInput {
        #[command(subcommand)]
        command: TrustUnderwritingInputCommands,
    },

    /// Evaluate a bounded underwriting decision from canonical trust data.
    UnderwritingDecision {
        #[command(subcommand)]
        command: TrustUnderwritingDecisionCommands,
    },

    /// Create or resolve underwriting appeals against persisted decisions.
    UnderwritingAppeal {
        #[command(subcommand)]
        command: TrustUnderwritingAppealCommands,
    },

    /// Persist a capability revocation into the configured revocation database.
    Revoke {
        /// Capability ID to revoke.
        #[arg(long)]
        capability_id: String,
    },

    /// Issue one local capability after verifying a challenge-bound portable presentation.
    FederatedIssue {
        /// Signed passport presentation response from the external agent.
        #[arg(long)]
        presentation_response: PathBuf,

        /// Exact expected challenge JSON used to bind the presentation to this verifier.
        #[arg(long)]
        challenge: PathBuf,

        /// Policy file whose default capability definition is the single capability to issue.
        #[arg(long)]
        capability_policy: PathBuf,

        /// Optional enterprise identity context JSON used for provider-admin-gated admission.
        #[arg(long)]
        enterprise_identity: Option<PathBuf>,

        /// Optional signed federated delegation policy that sets the parent scope/TTL ceiling.
        #[arg(long)]
        delegation_policy: Option<PathBuf>,

        /// Optional imported upstream capability ID used as the parent for multi-hop federated delegation.
        #[arg(long)]
        upstream_capability_id: Option<String>,
    },

    /// Create a signed federated delegation policy from a single default capability.
    FederatedDelegationPolicyCreate {
        /// Output path for the signed policy JSON.
        #[arg(long)]
        output: PathBuf,

        /// Persistent seed file used to sign the federated delegation policy.
        #[arg(long)]
        signing_seed_file: PathBuf,

        /// Local issuer name or organization identifier.
        #[arg(long)]
        issuer: String,

        /// External partner name or organization identifier.
        #[arg(long)]
        partner: String,

        /// Trust-control verifier URL this policy is bound to.
        #[arg(long)]
        verifier: String,

        /// Capability policy whose single default capability becomes the delegation ceiling.
        #[arg(long)]
        capability_policy: PathBuf,

        /// Policy expiration as Unix seconds.
        #[arg(long)]
        expires_at: u64,

        /// Optional reason or purpose string embedded in the policy document.
        #[arg(long)]
        purpose: Option<String>,

        /// Optional upstream capability ID that this delegation policy is allowed to continue from.
        #[arg(long)]
        parent_capability_id: Option<String>,
    },

    /// Query whether a capability ID is currently revoked.
    Status {
        /// Capability ID to check.
        #[arg(long)]
        capability_id: String,
    },
}

#[derive(Subcommand)]
enum TrustProviderCommands {
    /// List enterprise provider records from the shared registry.
    List {
        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        enterprise_providers_file: Option<PathBuf>,
    },

    /// Read one enterprise provider record.
    Get {
        /// Provider ID to fetch.
        #[arg(long)]
        provider_id: String,

        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        enterprise_providers_file: Option<PathBuf>,
    },

    /// Create or update one enterprise provider record from JSON.
    Upsert {
        /// Input JSON file containing an EnterpriseProviderRecord.
        #[arg(long)]
        input: PathBuf,

        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        enterprise_providers_file: Option<PathBuf>,
    },

    /// Delete one enterprise provider record.
    Delete {
        /// Provider ID to delete.
        #[arg(long)]
        provider_id: String,

        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        enterprise_providers_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum TrustEvidenceShareCommands {
    /// List shared-evidence references visible from local activity or the remote trust service.
    List {
        /// Filter by local capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by local agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by local tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by local tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Filter: receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Filter: receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Filter by remote share issuer.
        #[arg(long)]
        issuer: Option<String>,
        /// Filter by remote share partner.
        #[arg(long)]
        partner: Option<String>,
        /// Maximum number of shared-evidence references to return.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum TrustAuthorizationContextCommands {
    /// Export machine-readable ARC authorization-profile metadata for enterprise IAM review.
    Metadata,

    /// List derived authorization-context mappings from local state or trust-control.
    List {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of derived authorization-context rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Export an enterprise reviewer pack tying authorization context back to governed receipt truth.
    ReviewPack {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of derived authorization-context rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum TrustRuntimeAttestationAppraisalCommands {
    /// Export a signed runtime-attestation appraisal report from local input or trust-control.
    Export {
        /// Input JSON or YAML file containing a RuntimeAttestationEvidence payload.
        #[arg(long)]
        input: PathBuf,

        /// Optional HushSpec policy used to evaluate policy-visible outcomes locally.
        #[arg(long)]
        policy_file: Option<PathBuf>,
    },
    /// Export a signed portable runtime-attestation appraisal result artifact.
    ExportResult {
        /// Issuer identifier recorded in the exported result.
        #[arg(long)]
        issuer: String,

        /// Input JSON or YAML file containing a RuntimeAttestationEvidence payload.
        #[arg(long)]
        input: PathBuf,

        /// Optional HushSpec policy used to evaluate exporter-visible outcomes locally.
        #[arg(long)]
        policy_file: Option<PathBuf>,
    },
    /// Evaluate a signed external runtime-attestation appraisal result against local import policy.
    Import {
        /// Input JSON or YAML file containing a signed appraisal result envelope.
        #[arg(long)]
        input: PathBuf,

        /// JSON or YAML file containing a RuntimeAttestationImportedAppraisalPolicy payload.
        #[arg(long)]
        policy_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum TrustBehavioralFeedCommands {
    /// Export a signed behavioral feed from local state or trust-control.
    Export {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt detail rows to embed.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
    },
}

#[derive(Subcommand)]
enum TrustExposureLedgerCommands {
    /// Export a signed exposure ledger from local state or trust-control.
    Export {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to embed.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to embed.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
    },
}

#[derive(Subcommand)]
enum TrustCreditScorecardCommands {
    /// Export a signed credit scorecard from local state or trust-control.
    Export {
        /// Subject public key to score.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
    },
}

#[derive(Subcommand)]
enum TrustCapitalBookCommands {
    /// Export a signed live capital book from canonical facility, bond, and loss posture.
    Export {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to inspect for disbursement provenance.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of facility rows to inspect.
        #[arg(long, default_value_t = 10)]
        facility_limit: usize,
        /// Maximum number of bond rows to inspect.
        #[arg(long, default_value_t = 10)]
        bond_limit: usize,
        /// Maximum number of loss-lifecycle rows to inspect.
        #[arg(long, default_value_t = 25)]
        loss_event_limit: usize,
    },
}

#[derive(Subcommand)]
enum TrustCapitalInstructionCommands {
    /// Issue one custody-neutral escrow or reserve instruction artifact from JSON or YAML input.
    Issue {
        /// JSON or YAML capital-instruction input file.
        #[arg(long)]
        input_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum TrustCapitalAllocationCommands {
    /// Issue one live capital-allocation decision artifact from JSON or YAML input.
    Issue {
        /// JSON or YAML capital-allocation input file.
        #[arg(long)]
        input_file: PathBuf,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum TrustCreditFacilityCommands {
    /// Evaluate a deterministic facility-policy report without persisting an artifact.
    Evaluate {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Issue and persist a signed facility artifact from deterministic facility policy.
    Issue {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
        /// Optional previously active facility to supersede.
        #[arg(long)]
        supersedes_facility_id: Option<String>,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// List persisted credit facility artifacts.
    List {
        /// Filter by facility ID.
        #[arg(long)]
        facility_id: Option<String>,
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Filter by disposition (`grant`, `manual_review`, `deny`).
        #[arg(long)]
        disposition: Option<String>,
        /// Filter by lifecycle state (`active`, `superseded`, `denied`, `expired`).
        #[arg(long)]
        lifecycle_state: Option<String>,
        /// Maximum number of facility rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum TrustCreditBondCommands {
    /// Evaluate a deterministic bond-policy report without persisting an artifact.
    Evaluate {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Issue and persist a signed bond artifact from deterministic bond policy.
    Issue {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
        /// Optional previously active bond to supersede.
        #[arg(long)]
        supersedes_bond_id: Option<String>,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Simulate bonded execution under an operator control policy without mutating state.
    Simulate {
        /// Bond artifact ID to evaluate.
        #[arg(long)]
        bond_id: String,
        /// Requested autonomy tier (`direct`, `delegated`, `autonomous`).
        #[arg(long)]
        autonomy_tier: String,
        /// Runtime assurance tier attached to the simulated request.
        #[arg(long)]
        runtime_assurance_tier: String,
        /// Whether delegated call-chain context is present.
        #[arg(long, default_value_t = false)]
        call_chain_present: bool,
        /// YAML or JSON operator control policy file.
        #[arg(long)]
        policy_file: PathBuf,
    },

    /// List persisted credit bond artifacts.
    List {
        /// Filter by bond ID.
        #[arg(long)]
        bond_id: Option<String>,
        /// Filter by facility ID.
        #[arg(long)]
        facility_id: Option<String>,
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Filter by disposition (`lock`, `hold`, `release`, `impair`).
        #[arg(long)]
        disposition: Option<String>,
        /// Filter by lifecycle state (`active`, `superseded`, `released`, `impaired`, `expired`).
        #[arg(long)]
        lifecycle_state: Option<String>,
        /// Maximum number of bond rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum TrustCreditLossLifecycleCommands {
    /// Evaluate a deterministic bond loss-lifecycle transition without persisting an artifact.
    Evaluate {
        /// Bond ID to evaluate against.
        #[arg(long)]
        bond_id: String,
        /// Event kind (`delinquency`, `recovery`, `reserve_release`, `reserve_slash`, `write_off`).
        #[arg(long)]
        event_kind: String,
        /// Optional explicit amount in minor units.
        #[arg(long)]
        amount_units: Option<u64>,
        /// Optional explicit amount currency.
        #[arg(long)]
        amount_currency: Option<String>,
    },

    /// Issue and persist a signed bond loss-lifecycle artifact.
    Issue {
        /// Bond ID to evaluate against.
        #[arg(long)]
        bond_id: String,
        /// Event kind (`delinquency`, `recovery`, `reserve_release`, `reserve_slash`, `write_off`).
        #[arg(long)]
        event_kind: String,
        /// Optional explicit amount in minor units.
        #[arg(long)]
        amount_units: Option<u64>,
        /// Optional explicit amount currency.
        #[arg(long)]
        amount_currency: Option<String>,
        /// Optional JSON/YAML file containing Vec<CapitalExecutionAuthorityStep>.
        #[arg(long)]
        authority_chain_file: Option<PathBuf>,
        /// Optional JSON/YAML file containing CapitalExecutionWindow.
        #[arg(long)]
        execution_window_file: Option<PathBuf>,
        /// Optional JSON/YAML file containing CapitalExecutionRail.
        #[arg(long)]
        rail_file: Option<PathBuf>,
        /// Optional JSON/YAML file containing CapitalExecutionObservation.
        #[arg(long)]
        observed_execution_file: Option<PathBuf>,
        /// Optional reserve-control appeal window close timestamp.
        #[arg(long)]
        appeal_window_ends_at: Option<u64>,
        /// Optional reserve-control description recorded on the lifecycle artifact.
        #[arg(long)]
        description: Option<String>,
    },

    /// List persisted bond loss-lifecycle artifacts.
    List {
        /// Filter by event ID.
        #[arg(long)]
        event_id: Option<String>,
        /// Filter by bond ID.
        #[arg(long)]
        bond_id: Option<String>,
        /// Filter by facility ID.
        #[arg(long)]
        facility_id: Option<String>,
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Filter by event kind (`delinquency`, `recovery`, `reserve_release`, `reserve_slash`, `write_off`).
        #[arg(long)]
        event_kind: Option<String>,
        /// Maximum number of event rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum TrustCreditBacktestCommands {
    /// Export one deterministic credit backtest report over historical evidence windows.
    Export {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate per window.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate per window.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
        /// Width of each replay window in seconds.
        #[arg(long, default_value_t = 7 * 86_400)]
        window_seconds: u64,
        /// Number of windows to replay.
        #[arg(long, default_value_t = 4)]
        window_count: usize,
        /// Evidence older than this threshold is flagged stale.
        #[arg(long, default_value_t = 30 * 86_400)]
        stale_after_seconds: u64,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum TrustProviderRiskPackageCommands {
    /// Export one signed provider-facing risk package over canonical subject-scoped evidence.
    Export {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
        /// Maximum number of recent loss events to include.
        #[arg(long, default_value_t = 10)]
        recent_loss_limit: usize,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum TrustLiabilityProviderCommands {
    /// Issue and persist a signed curated liability-provider artifact from JSON or YAML input.
    Issue {
        /// JSON or YAML provider report input file.
        #[arg(long)]
        input_file: PathBuf,
        /// Optional previously active provider record to supersede.
        #[arg(long)]
        supersedes_provider_record_id: Option<String>,
    },

    /// List persisted liability-provider artifacts.
    List {
        /// Filter by provider ID.
        #[arg(long)]
        provider_id: Option<String>,
        /// Filter by jurisdiction.
        #[arg(long)]
        jurisdiction: Option<String>,
        /// Filter by coverage class (`tool_execution`, `data_breach`, `financial_loss`, `professional_liability`, `regulatory_response`).
        #[arg(long)]
        coverage_class: Option<String>,
        /// Filter by currency.
        #[arg(long)]
        currency: Option<String>,
        /// Filter by lifecycle state (`active`, `suspended`, `superseded`, `retired`).
        #[arg(long)]
        lifecycle_state: Option<String>,
        /// Maximum number of provider rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Resolve one provider + jurisdiction + coverage + currency combination fail closed.
    Resolve {
        /// Provider ID to resolve.
        #[arg(long)]
        provider_id: String,
        /// Jurisdiction to resolve.
        #[arg(long)]
        jurisdiction: String,
        /// Coverage class to resolve.
        #[arg(long)]
        coverage_class: String,
        /// Currency to resolve.
        #[arg(long)]
        currency: String,
    },
}

#[derive(Subcommand)]
enum TrustLiabilityMarketCommands {
    /// Issue and persist a signed liability quote request from JSON or YAML input.
    QuoteRequestIssue {
        /// JSON or YAML quote-request input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability quote response from JSON or YAML input.
    QuoteResponseIssue {
        /// JSON or YAML quote-response input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed delegated pricing-authority artifact.
    PricingAuthorityIssue {
        /// JSON or YAML pricing-authority input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability placement from JSON or YAML input.
    PlacementIssue {
        /// JSON or YAML placement input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed bound-coverage artifact from JSON or YAML input.
    BoundCoverageIssue {
        /// JSON or YAML bound-coverage input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Evaluate and persist one automatic bind decision plus issued placement/bound coverage.
    AutoBindIssue {
        /// JSON or YAML auto-bind input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability claim package from JSON or YAML input.
    ClaimIssue {
        /// JSON or YAML claim input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability claim response from JSON or YAML input.
    ClaimResponseIssue {
        /// JSON or YAML claim-response input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability claim dispute from JSON or YAML input.
    DisputeIssue {
        /// JSON or YAML dispute input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability claim adjudication from JSON or YAML input.
    AdjudicationIssue {
        /// JSON or YAML adjudication input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability claim payout instruction from JSON or YAML input.
    ClaimPayoutInstructionIssue {
        /// JSON or YAML claim payout instruction input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability claim payout receipt from JSON or YAML input.
    ClaimPayoutReceiptIssue {
        /// JSON or YAML claim payout receipt input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability claim settlement instruction from JSON or YAML input.
    ClaimSettlementInstructionIssue {
        /// JSON or YAML claim settlement instruction input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability claim settlement receipt from JSON or YAML input.
    ClaimSettlementReceiptIssue {
        /// JSON or YAML claim settlement receipt input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// List quote-request to bound-coverage workflow rows.
    List {
        /// Filter by quote request ID.
        #[arg(long)]
        quote_request_id: Option<String>,
        /// Filter by provider ID.
        #[arg(long)]
        provider_id: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by jurisdiction.
        #[arg(long)]
        jurisdiction: Option<String>,
        /// Filter by coverage class (`tool_execution`, `data_breach`, `financial_loss`, `professional_liability`, `regulatory_response`).
        #[arg(long)]
        coverage_class: Option<String>,
        /// Filter by currency.
        #[arg(long)]
        currency: Option<String>,
        /// Maximum number of workflow rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// List claim-package to adjudication workflow rows.
    ClaimsList {
        /// Filter by claim ID.
        #[arg(long)]
        claim_id: Option<String>,
        /// Filter by provider ID.
        #[arg(long)]
        provider_id: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by jurisdiction.
        #[arg(long)]
        jurisdiction: Option<String>,
        /// Filter by policy number.
        #[arg(long)]
        policy_number: Option<String>,
        /// Maximum number of claim rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum TrustUnderwritingInputCommands {
    /// Export a signed underwriting policy-input snapshot from local state or trust-control.
    Export {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt references to embed.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum TrustUnderwritingDecisionCommands {
    /// Evaluate a bounded underwriting decision from local state or trust-control.
    Evaluate {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt references to inspect.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Simulate an alternative underwriting policy against canonical evidence without persisting a decision.
    Simulate {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt references to inspect.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// YAML or JSON underwriting decision policy file.
        #[arg(long)]
        policy_file: PathBuf,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Issue and persist a signed underwriting decision artifact.
    Issue {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt references to inspect.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
        /// Optional prior decision ID this new artifact supersedes.
        #[arg(long)]
        supersedes_decision_id: Option<String>,
    },

    /// List persisted underwriting decision artifacts and appeal status.
    List {
        /// Filter by decision ID.
        #[arg(long)]
        decision_id: Option<String>,
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Filter by outcome (`approve`, `reduce_ceiling`, `step_up`, `deny`).
        #[arg(long)]
        outcome: Option<String>,
        /// Filter by lifecycle state (`active`, `superseded`).
        #[arg(long)]
        lifecycle_state: Option<String>,
        /// Filter by latest appeal status (`open`, `accepted`, `rejected`).
        #[arg(long)]
        appeal_status: Option<String>,
        /// Maximum number of persisted decision rows to return.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum TrustUnderwritingAppealCommands {
    /// Create an underwriting appeal record for one persisted decision.
    Create {
        /// Decision ID to appeal.
        #[arg(long)]
        decision_id: String,
        /// Operator or system subject opening the appeal.
        #[arg(long)]
        requested_by: String,
        /// Short appeal reason.
        #[arg(long)]
        reason: String,
        /// Optional freeform note.
        #[arg(long)]
        note: Option<String>,
    },

    /// Resolve one open underwriting appeal.
    Resolve {
        /// Appeal ID to resolve.
        #[arg(long)]
        appeal_id: String,
        /// Resolution outcome (`accepted` or `rejected`).
        #[arg(long)]
        resolution: String,
        /// Operator or system subject resolving the appeal.
        #[arg(long)]
        resolved_by: String,
        /// Optional freeform note.
        #[arg(long)]
        note: Option<String>,
        /// Optional replacement decision ID when an appeal resolution references a superseding artifact.
        #[arg(long)]
        replacement_decision_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum ReceiptCommands {
    /// List receipts with optional filters. Output: one JSON receipt per line (JSON Lines).
    List {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by tool server ID.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Filter by decision outcome (allow, deny, cancelled, incomplete).
        #[arg(long)]
        outcome: Option<String>,
        /// Filter: receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Filter: receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Filter: minimum cost in minor currency units (only financial receipts).
        #[arg(long)]
        min_cost: Option<u64>,
        /// Filter: maximum cost in minor currency units (only financial receipts).
        #[arg(long)]
        max_cost: Option<u64>,
        /// Maximum number of receipts per page.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Cursor for pagination (seq value to start after).
        #[arg(long)]
        cursor: Option<u64>,
    },
}

#[derive(Subcommand)]
enum EvidenceCommands {
    /// Export a verifiable local evidence package into a directory.
    Export {
        /// Output directory for the evidence package. Must not already contain files.
        #[arg(long)]
        output: PathBuf,
        /// Filter tool receipts by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter tool receipts by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Include tool receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include tool receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Optional policy file to attach to the export package.
        #[arg(long)]
        policy_file: Option<PathBuf>,
        /// Optional signed bilateral federation policy that constrains the export scope.
        #[arg(long)]
        federation_policy: Option<PathBuf>,
        /// Fail the export if any selected tool receipt lacks checkpoint coverage.
        #[arg(long, default_value_t = false)]
        require_proofs: bool,
    },
    /// Verify an exported evidence package offline.
    Verify {
        /// Input directory containing a previously exported evidence package.
        #[arg(long)]
        input: PathBuf,
    },
    /// Import a verified bilateral evidence package for later federated delegation.
    Import {
        /// Input directory containing a previously exported evidence package.
        #[arg(long)]
        input: PathBuf,
    },
    /// Create a signed bilateral receipt-sharing policy document.
    FederationPolicy {
        #[command(subcommand)]
        command: EvidenceFederationPolicyCommands,
    },
}

#[derive(Subcommand)]
enum EvidenceFederationPolicyCommands {
    /// Create a signed bilateral federation policy for receipt sharing.
    Create {
        /// Output JSON file for the signed policy document.
        #[arg(long)]
        output: PathBuf,
        /// Persistent seed file used to sign the policy document.
        #[arg(long)]
        signing_seed_file: PathBuf,
        /// Human-readable identifier for the issuing organization.
        #[arg(long)]
        issuer: String,
        /// Human-readable identifier for the receiving organization.
        #[arg(long)]
        partner: String,
        /// Optional capability scope for the shared export.
        #[arg(long)]
        capability: Option<String>,
        /// Optional agent subject scope for the shared export.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Optional lower timestamp bound for the allowed export window.
        #[arg(long)]
        since: Option<u64>,
        /// Optional upper timestamp bound for the allowed export window.
        #[arg(long)]
        until: Option<u64>,
        /// Expiration time for the policy document, in Unix seconds.
        #[arg(long)]
        expires_at: u64,
        /// Require full checkpoint coverage for any export performed under this policy.
        #[arg(long, default_value_t = false)]
        require_proofs: bool,
        /// Optional reason or purpose string embedded in the policy document.
        #[arg(long)]
        purpose: Option<String>,
    },
}

#[derive(Subcommand)]
enum CertifyCommands {
    /// Evaluate conformance evidence and emit a signed pass/fail certification artifact.
    Check {
        /// Directory containing conformance scenario descriptor JSON files.
        #[arg(long)]
        scenarios_dir: PathBuf,
        /// Directory containing conformance result JSON files.
        #[arg(long)]
        results_dir: PathBuf,
        /// Output path for the signed certification artifact JSON.
        #[arg(long)]
        output: PathBuf,
        /// Stable identifier for the tool server being checked.
        #[arg(long)]
        tool_server_id: String,
        /// Optional human-readable name for the tool server being checked.
        #[arg(long)]
        tool_server_name: Option<String>,
        /// Optional path to write a generated markdown report for the evaluated corpus.
        #[arg(long)]
        report_output: Option<PathBuf>,
        /// Certification criteria profile to apply.
        #[arg(long, default_value = "conformance-all-pass-v1")]
        criteria_profile: String,
        /// Persistent seed file used to sign certification artifacts.
        #[arg(long)]
        signing_seed_file: PathBuf,
    },

    /// Verify a signed certification artifact.
    Verify {
        /// Input path for the signed certification artifact JSON.
        #[arg(long)]
        input: PathBuf,
    },

    /// Publish, resolve, and revoke certification artifacts in a registry.
    Registry {
        #[command(subcommand)]
        command: CertifyRegistryCommands,
    },
}

#[derive(Subcommand)]
enum CertifyRegistryCommands {
    /// Publish one signed certification artifact into a local or remote registry.
    Publish {
        /// Input path for the signed certification artifact JSON.
        #[arg(long)]
        input: PathBuf,
        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Publish one certification artifact across configured discovery-network operators.
    PublishNetwork {
        /// Input path for the signed certification artifact JSON.
        #[arg(long)]
        input: PathBuf,
        /// Local discovery-network file to use when not using --control-url.
        #[arg(long)]
        certification_discovery_file: Option<PathBuf>,
        /// Optional operator id allowlist. Repeat to target specific operators.
        #[arg(long = "operator-id")]
        operator_ids: Vec<String>,
    },

    /// List certification artifacts from a local or remote registry.
    List {
        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Read one certification artifact from a local or remote registry.
    Get {
        /// Certification artifact ID to fetch.
        #[arg(long)]
        artifact_id: String,
        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Resolve the current certification status for one tool server.
    Resolve {
        /// Stable tool-server identifier whose current certification should be resolved.
        #[arg(long)]
        tool_server_id: String,
        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Discover certification status across multiple configured operators.
    Discover {
        /// Stable tool-server identifier whose discovery state should be queried.
        #[arg(long)]
        tool_server_id: String,
        /// Local discovery-network file to use when not using --control-url.
        #[arg(long)]
        certification_discovery_file: Option<PathBuf>,
    },

    /// Search public certification listings across configured operators.
    Search {
        /// Optional local discovery-network file to use when not using --control-url.
        #[arg(long)]
        certification_discovery_file: Option<PathBuf>,
        /// Optional exact tool-server id filter.
        #[arg(long)]
        tool_server_id: Option<String>,
        /// Optional criteria profile filter.
        #[arg(long)]
        criteria_profile: Option<String>,
        /// Optional evidence profile filter.
        #[arg(long)]
        evidence_profile: Option<String>,
        /// Optional listing state filter (`active`, `superseded`, or `revoked`).
        #[arg(long)]
        status: Option<String>,
        /// Optional operator id allowlist. Repeat to target specific operators.
        #[arg(long = "operator-id")]
        operator_ids: Vec<String>,
    },

    /// Render the public certification transparency feed across configured operators.
    Transparency {
        /// Optional local discovery-network file to use when not using --control-url.
        #[arg(long)]
        certification_discovery_file: Option<PathBuf>,
        /// Optional exact tool-server id filter.
        #[arg(long)]
        tool_server_id: Option<String>,
        /// Optional operator id allowlist. Repeat to target specific operators.
        #[arg(long = "operator-id")]
        operator_ids: Vec<String>,
    },

    /// Evaluate public certification listings against a local import policy.
    Consume {
        /// Stable tool-server identifier whose public listing should be consumed.
        #[arg(long)]
        tool_server_id: String,
        /// Optional local discovery-network file to use when not using --control-url.
        #[arg(long)]
        certification_discovery_file: Option<PathBuf>,
        /// Optional operator id allowlist. Repeat to target specific operators.
        #[arg(long = "operator-id")]
        operator_ids: Vec<String>,
        /// Optional allowed criteria profile. Repeat to allow multiple profiles.
        #[arg(long = "criteria-profile")]
        allowed_criteria_profiles: Vec<String>,
        /// Optional allowed evidence profile. Repeat to allow multiple profiles.
        #[arg(long = "evidence-profile")]
        allowed_evidence_profiles: Vec<String>,
    },

    /// Revoke one certification artifact in a local or remote registry.
    Revoke {
        /// Certification artifact ID to revoke.
        #[arg(long)]
        artifact_id: String,
        /// Optional human-readable revocation reason.
        #[arg(long)]
        reason: Option<String>,
        /// Optional revocation timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        revoked_at: Option<u64>,
        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Open or resolve a public certification dispute record.
    Dispute {
        /// Certification artifact ID to update.
        #[arg(long)]
        artifact_id: String,
        /// Dispute state (`open`, `under-review`, `resolved-no-change`, `resolved-revoked`).
        #[arg(long)]
        state: String,
        /// Optional dispute note or resolution summary.
        #[arg(long)]
        note: Option<String>,
        /// Optional dispute timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        updated_at: Option<u64>,
        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum DidCommands {
    /// Resolve a did:arc identifier or Ed25519 public key into a DID Document.
    Resolve {
        /// Fully-qualified did:arc identifier to resolve.
        #[arg(long, conflicts_with = "public_key")]
        did: Option<String>,
        /// Hex-encoded Ed25519 public key to resolve as did:arc.
        #[arg(long, conflicts_with = "did")]
        public_key: Option<String>,
        /// Optional receipt log service endpoint to include in the resolved document.
        #[arg(long = "receipt-log-url")]
        receipt_log_urls: Vec<String>,
        /// Optional passport lifecycle endpoint to include in the resolved document.
        #[arg(long = "passport-status-url")]
        passport_status_urls: Vec<String>,
    },
}

#[derive(Subcommand)]
enum PassportCommands {
    /// Create a single-issuer Agent Passport from local receipt and lineage data.
    Create {
        /// Subject Ed25519 public key in hex.
        #[arg(long)]
        subject_public_key: String,
        /// Output path for the passport JSON.
        #[arg(long)]
        output: PathBuf,
        /// Persistent seed file used to sign the embedded reputation credential.
        #[arg(long)]
        signing_seed_file: PathBuf,
        /// Passport validity period in days.
        #[arg(long, default_value_t = 30)]
        validity_days: u32,
        /// Optional lower bound for the attested receipt window, in Unix seconds.
        #[arg(long)]
        since: Option<u64>,
        /// Optional upper bound for the attested receipt window, in Unix seconds.
        #[arg(long)]
        until: Option<u64>,
        /// Optional receipt log service endpoint(s) to embed in attestation evidence.
        #[arg(long = "receipt-log-url")]
        receipt_log_urls: Vec<String>,
        /// Fail if any selected receipt lacks checkpoint coverage.
        #[arg(long, default_value_t = false)]
        require_checkpoints: bool,
        /// Optional enterprise identity context JSON to embed as portable provenance.
        #[arg(long)]
        enterprise_identity: Option<PathBuf>,
    },

    /// Verify a passport and every embedded credential without external glue code.
    Verify {
        /// Passport JSON file to verify.
        #[arg(long)]
        input: PathBuf,
        /// Verification timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
        /// Local passport lifecycle registry file to inspect when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
    },

    /// Evaluate a passport against a relying-party verifier policy.
    Evaluate {
        /// Passport JSON file to evaluate.
        #[arg(long)]
        input: PathBuf,
        /// YAML or JSON verifier policy file.
        #[arg(long)]
        policy: PathBuf,
        /// Verification timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
        /// Local passport lifecycle registry file to inspect when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
    },

    /// Produce a filtered presentation from an existing passport.
    Present {
        /// Input passport JSON file.
        #[arg(long)]
        input: PathBuf,
        /// Output path for the presented passport JSON.
        #[arg(long)]
        output: PathBuf,
        /// Optional issuer DID allowlist. Repeat to allow multiple issuers.
        #[arg(long = "issuer")]
        issuers: Vec<String>,
        /// Maximum number of credentials to include in the presentation.
        #[arg(long)]
        max_credentials: Option<usize>,
    },

    /// Create, verify, and manage signed verifier-policy artifacts.
    Policy {
        #[command(subcommand)]
        command: PassportPolicyCommands,
    },

    /// Create and verify challenge-bound passport presentations.
    Challenge {
        #[command(subcommand)]
        command: PassportChallengeCommands,
    },

    /// Publish, resolve, and revoke passport lifecycle state.
    Status {
        #[command(subcommand)]
        command: PassportStatusCommands,
    },

    /// Deliver ARC passports through an OID4VCI-style pre-authorized issuance flow.
    Issuance {
        #[command(subcommand)]
        command: PassportIssuanceCommands,
    },

    /// Create and consume ARC's narrow OID4VP verifier and holder interop flow.
    Oid4vp {
        #[command(subcommand)]
        command: PassportOid4vpCommands,
    },
}

#[derive(Subcommand)]
enum PassportChallengeCommands {
    /// Create a presentation challenge for a relying party.
    Create {
        /// Output path for the challenge JSON.
        #[arg(long)]
        output: PathBuf,
        /// Relying-party identifier or audience string.
        #[arg(long)]
        verifier: String,
        /// Challenge lifetime in seconds.
        #[arg(long, default_value_t = 300)]
        ttl_secs: u64,
        /// Optional issuer DID allowlist for selective disclosure. Repeat to allow multiple issuers.
        #[arg(long = "issuer")]
        issuers: Vec<String>,
        /// Maximum number of credentials a holder may disclose.
        #[arg(long)]
        max_credentials: Option<usize>,
        /// Optional verifier policy to embed in the challenge.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Optional stored verifier policy ID to reference instead of embedding raw policy.
        #[arg(long)]
        policy_id: Option<String>,
        /// Optional verifier policy registry file used when resolving --policy-id locally.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
        /// Optional SQLite challenge-state database used for replay-safe local verification.
        #[arg(long)]
        verifier_challenge_db: Option<PathBuf>,
    },

    /// Respond to a presentation challenge using the passport subject key.
    Respond {
        /// Input passport JSON file.
        #[arg(long)]
        input: PathBuf,
        /// Input challenge JSON file.
        #[arg(long, conflicts_with = "challenge_url")]
        challenge: Option<PathBuf>,
        /// Public holder-facing challenge URL.
        #[arg(long, conflicts_with = "challenge")]
        challenge_url: Option<String>,
        /// Existing seed file for the passport subject key.
        #[arg(long)]
        holder_seed_file: PathBuf,
        /// Output path for the signed response JSON.
        #[arg(long)]
        output: PathBuf,
        /// Response timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
    },

    /// Submit a signed challenge response to a public verifier transport URL.
    Submit {
        /// Input response JSON file.
        #[arg(long)]
        input: PathBuf,
        /// Public submit URL returned by the verifier transport.
        #[arg(long)]
        submit_url: String,
    },

    /// Verify a challenge-bound passport presentation response.
    Verify {
        /// Input response JSON file.
        #[arg(long)]
        input: PathBuf,
        /// Optional expected challenge JSON file for exact-match verification.
        #[arg(long)]
        challenge: Option<PathBuf>,
        /// Optional verifier policy registry file used to resolve policy references locally.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
        /// Optional SQLite challenge-state database used for replay-safe local verification.
        #[arg(long)]
        verifier_challenge_db: Option<PathBuf>,
        /// Local passport lifecycle registry file to inspect when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
        /// Verification timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
    },
}

#[derive(Subcommand)]
enum PassportOid4vpCommands {
    /// Create a replay-safe verifier request on the running trust-control service.
    Create {
        /// Optional output path for the verifier request JSON.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Requested selective-disclosure claims. Repeat to request multiple claims.
        #[arg(long = "claim")]
        disclosure_claims: Vec<String>,
        /// Optional issuer allowlist. Repeat to allow multiple issuers.
        #[arg(long = "issuer")]
        issuer_allowlist: Vec<String>,
        /// Optional request lifetime in seconds.
        #[arg(long)]
        ttl_secs: Option<u64>,
        /// Optional continuity subject to embed in the bounded identity assertion lane.
        #[arg(long)]
        identity_subject: Option<String>,
        /// Optional continuity ID to embed in the bounded identity assertion lane.
        #[arg(long)]
        identity_continuity_id: Option<String>,
        /// Optional upstream provider label for the bounded identity assertion lane.
        #[arg(long)]
        identity_provider: Option<String>,
        /// Optional session hint for the bounded identity assertion lane.
        #[arg(long)]
        identity_session_hint: Option<String>,
        /// Optional identity-assertion lifetime in seconds. Defaults to the request TTL.
        #[arg(long)]
        identity_ttl_secs: Option<u64>,
    },

    /// Build one holder response from a verifier request or launch URL.
    Respond {
        /// Input portable SD-JWT VC credential file.
        #[arg(long)]
        input: PathBuf,
        /// Direct verifier request URI.
        #[arg(long, conflicts_with_all = ["same_device_url", "cross_device_url"])]
        request_url: Option<String>,
        /// Same-device `openid4vp://authorize?...` launch URL.
        #[arg(long, conflicts_with_all = ["request_url", "cross_device_url"])]
        same_device_url: Option<String>,
        /// Cross-device HTTPS launch URL.
        #[arg(long, conflicts_with_all = ["request_url", "same_device_url"])]
        cross_device_url: Option<String>,
        /// Existing seed file for the portable credential subject key.
        #[arg(long)]
        holder_seed_file: PathBuf,
        /// Optional output path for the signed response JWT.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Submit to the verifier's response URI after building the response.
        #[arg(long)]
        submit: bool,
        /// Override submit URL instead of using the request's response_uri.
        #[arg(long)]
        submit_url: Option<String>,
        /// Response timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
    },

    /// Submit a previously created OID4VP response JWT.
    Submit {
        /// Input response JWT file.
        #[arg(long)]
        input: PathBuf,
        /// Public verifier response URL.
        #[arg(long)]
        submit_url: String,
    },

    /// Fetch and display the public verifier metadata document.
    Metadata {
        /// Base verifier URL, for example `https://verifier.example.com`.
        #[arg(long)]
        verifier_url: String,
    },
}

#[derive(Subcommand)]
enum PassportPolicyCommands {
    /// Create a signed verifier-policy artifact from a raw policy file.
    Create {
        /// Output path for the signed verifier-policy document JSON.
        #[arg(long)]
        output: PathBuf,
        /// Stable verifier policy ID.
        #[arg(long)]
        policy_id: String,
        /// Relying-party identifier or audience string that owns this policy.
        #[arg(long)]
        verifier: String,
        /// Persistent seed file used to sign the verifier policy.
        #[arg(long)]
        signing_seed_file: PathBuf,
        /// YAML or JSON file containing the raw verifier policy body.
        #[arg(long)]
        policy: PathBuf,
        /// Policy expiration as Unix seconds.
        #[arg(long)]
        expires_at: u64,
        /// Optional local verifier policy registry to update after creation.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
    },

    /// Verify a signed verifier-policy artifact.
    Verify {
        /// Signed verifier-policy document JSON file.
        #[arg(long)]
        input: PathBuf,
        /// Verification timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
    },

    /// List verifier-policy artifacts from a local registry or remote service.
    List {
        /// Local verifier policy registry file to inspect when not using --control-url.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
    },

    /// Read one verifier-policy artifact.
    Get {
        /// Verifier policy ID to fetch.
        #[arg(long)]
        policy_id: String,
        /// Local verifier policy registry file to inspect when not using --control-url.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
    },

    /// Create or update one verifier-policy artifact in a local registry or remote service.
    Upsert {
        /// Input JSON file containing a signed verifier-policy document.
        #[arg(long)]
        input: PathBuf,
        /// Local verifier policy registry file to update when not using --control-url.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
    },

    /// Delete one verifier-policy artifact from a local registry or remote service.
    Delete {
        /// Verifier policy ID to delete.
        #[arg(long)]
        policy_id: String,
        /// Local verifier policy registry file to update when not using --control-url.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PassportStatusCommands {
    /// Publish one passport into the lifecycle registry as the current active artifact.
    Publish {
        /// Passport JSON file to publish.
        #[arg(long)]
        input: PathBuf,
        /// Local passport lifecycle registry file to update when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
        /// Optional resolve endpoint verifiers can query for lifecycle state.
        #[arg(long = "resolve-url")]
        resolve_urls: Vec<String>,
        /// Optional cache TTL verifiers may apply to lifecycle state.
        #[arg(long)]
        cache_ttl_secs: Option<u64>,
    },

    /// List lifecycle records from a local registry or remote service.
    List {
        /// Local passport lifecycle registry file to inspect when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
    },

    /// Read one lifecycle record by passport id.
    Get {
        /// Passport artifact id to fetch.
        #[arg(long)]
        passport_id: String,
        /// Local passport lifecycle registry file to inspect when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
    },

    /// Resolve lifecycle state for a passport artifact id.
    Resolve {
        /// Passport artifact id to resolve.
        #[arg(long)]
        passport_id: String,
        /// Local passport lifecycle registry file to inspect when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
    },

    /// Revoke one passport lifecycle record.
    Revoke {
        /// Passport artifact id to revoke.
        #[arg(long)]
        passport_id: String,
        /// Local passport lifecycle registry file to update when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
        /// Optional revocation reason.
        #[arg(long)]
        reason: Option<String>,
        /// Optional revocation timestamp override in Unix seconds.
        #[arg(long)]
        revoked_at: Option<u64>,
    },
}

#[derive(Subcommand)]
enum PassportIssuanceCommands {
    /// Render OID4VCI-style issuer metadata for ARC passport issuance.
    Metadata {
        /// Local credential issuer base URL when not using --control-url.
        #[arg(long)]
        issuer_url: Option<String>,
        /// Optional local signing seed used to advertise the standards-native portable credential profile.
        #[arg(long)]
        signing_seed_file: Option<PathBuf>,
        /// Optional public passport lifecycle resolve endpoint to advertise in local metadata.
        #[arg(long)]
        passport_status_url: Option<String>,
        /// Optional cache hint paired with --passport-status-url in local metadata.
        #[arg(long)]
        passport_status_cache_ttl_secs: Option<u64>,
    },

    /// Create a pre-authorized credential offer for one ARC passport.
    Offer {
        /// Input passport JSON file to deliver.
        #[arg(long)]
        input: PathBuf,
        /// Optional output path for the credential offer JSON.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Local credential issuer base URL when not using --control-url.
        #[arg(long)]
        issuer_url: Option<String>,
        /// Local issuance registry file to update when not using --control-url.
        #[arg(long)]
        passport_issuance_offers_file: Option<PathBuf>,
        /// Optional local passport lifecycle registry used to require published active status before portable issuance.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
        /// Optional local signing seed required when offering portable compact credential configurations.
        #[arg(long)]
        signing_seed_file: Option<PathBuf>,
        /// Optional credential configuration ID. Defaults to ARC's single passport profile.
        #[arg(long)]
        credential_configuration_id: Option<String>,
        /// Offer lifetime in seconds.
        #[arg(long, default_value_t = 600)]
        ttl_secs: u64,
    },

    /// Redeem a pre-authorized code into an issuance access token.
    Token {
        /// Input credential offer JSON file.
        #[arg(long)]
        offer: PathBuf,
        /// Optional output path for the token response JSON.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Local issuance registry file to update when not using --control-url.
        #[arg(long)]
        passport_issuance_offers_file: Option<PathBuf>,
    },

    /// Redeem an issuance access token into the delivered ARC passport.
    Credential {
        /// Input credential offer JSON file.
        #[arg(long)]
        offer: PathBuf,
        /// Input token response JSON file.
        #[arg(long)]
        token: PathBuf,
        /// Optional output path for the delivered passport JSON.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Local issuance registry file to update when not using --control-url.
        #[arg(long)]
        passport_issuance_offers_file: Option<PathBuf>,
        /// Optional local passport lifecycle registry used to attach portable lifecycle status references.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
        /// Optional local signing seed required when redeeming portable compact credential configurations without --control-url.
        #[arg(long)]
        signing_seed_file: Option<PathBuf>,
        /// Optional credential configuration ID override used for fail-closed validation.
        #[arg(long)]
        credential_configuration_id: Option<String>,
        /// Optional format override used for fail-closed validation.
        #[arg(long)]
        format: Option<String>,
    },
}

#[derive(Subcommand)]
enum ReputationCommands {
    /// Compute the local reputation scorecard for one subject.
    Local {
        /// Subject Ed25519 public key in hex.
        #[arg(long)]
        subject_public_key: String,
        /// Optional lower bound for the evaluated receipt window, in Unix seconds.
        #[arg(long)]
        since: Option<u64>,
        /// Optional upper bound for the evaluated receipt window, in Unix seconds.
        #[arg(long)]
        until: Option<u64>,
        /// Optional policy file whose reputation scoring config should be applied for local evaluation.
        #[arg(long)]
        policy: Option<PathBuf>,
    },

    /// Compare the live local reputation corpus against a portable passport artifact.
    Compare {
        /// Subject Ed25519 public key in hex.
        #[arg(long)]
        subject_public_key: String,
        /// Passport JSON file to compare against live local state.
        #[arg(long)]
        passport: PathBuf,
        /// Optional lower bound for the evaluated local receipt window, in Unix seconds.
        #[arg(long)]
        since: Option<u64>,
        /// Optional upper bound for the evaluated local receipt window, in Unix seconds.
        #[arg(long)]
        until: Option<u64>,
        /// Optional HushSpec policy file whose local reputation scoring config should be applied.
        #[arg(long)]
        local_policy: Option<PathBuf>,
        /// Optional YAML or JSON verifier policy used to evaluate the passport during comparison.
        #[arg(long)]
        verifier_policy: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    let receipt_db = cli.receipt_db.clone();
    let revocation_db = cli.revocation_db.clone();
    let authority_seed_file = cli.authority_seed_file.clone();
    let authority_db = cli.authority_db.clone();
    let budget_db = cli.budget_db.clone();
    let session_db = cli.session_db.clone();
    let control_url = cli.control_url.clone();
    let control_token = cli.control_token.clone();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let result = match cli.command {
        Commands::Run { policy, command } => cmd_run(
            &policy,
            &command,
            cli.json,
            receipt_db.as_deref(),
            revocation_db.as_deref(),
            authority_seed_file.as_deref(),
            authority_db.as_deref(),
            budget_db.as_deref(),
            session_db.as_deref(),
            control_url.as_deref(),
            control_token.as_deref(),
        ),
        Commands::Check {
            policy,
            tool,
            params,
            server,
        } => cmd_check(
            &policy,
            &tool,
            &params,
            &server,
            cli.json,
            receipt_db.as_deref(),
            revocation_db.as_deref(),
            authority_seed_file.as_deref(),
            authority_db.as_deref(),
            budget_db.as_deref(),
            session_db.as_deref(),
            control_url.as_deref(),
            control_token.as_deref(),
        ),
        Commands::Mcp { command } => match command {
            McpCommands::Serve {
                policy,
                server_id,
                server_name,
                server_version,
                manifest_public_key,
                page_size,
                tools_list_changed,
                command,
            } => cmd_mcp_serve(
                &policy,
                &server_id,
                server_name.as_deref(),
                server_version.as_deref(),
                manifest_public_key.as_deref(),
                page_size,
                tools_list_changed,
                &command,
                receipt_db.as_deref(),
                revocation_db.as_deref(),
                authority_seed_file.as_deref(),
                authority_db.as_deref(),
                budget_db.as_deref(),
                session_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            McpCommands::ServeHttp {
                policy,
                server_id,
                server_name,
                server_version,
                manifest_public_key,
                page_size,
                tools_list_changed,
                shared_hosted_owner,
                listen,
                auth_token,
                auth_jwt_public_key,
                auth_jwt_discovery_url,
                auth_introspection_url,
                auth_introspection_client_id,
                auth_introspection_client_secret,
                auth_jwt_provider_profile,
                auth_server_seed_file,
                identity_federation_seed_file,
                enterprise_providers_file,
                auth_jwt_issuer,
                auth_jwt_audience,
                admin_token,
                public_base_url,
                auth_servers,
                auth_authorization_endpoint,
                auth_token_endpoint,
                auth_registration_endpoint,
                auth_jwks_uri,
                auth_scopes,
                auth_subject,
                auth_code_ttl_secs,
                auth_access_token_ttl_secs,
                command,
            } => cmd_mcp_serve_http(
                &policy,
                &server_id,
                server_name.as_deref(),
                server_version.as_deref(),
                manifest_public_key.as_deref(),
                page_size,
                tools_list_changed,
                shared_hosted_owner,
                listen,
                auth_token.as_deref(),
                auth_jwt_public_key.as_deref(),
                auth_jwt_discovery_url.as_deref(),
                auth_introspection_url.as_deref(),
                auth_introspection_client_id.as_deref(),
                auth_introspection_client_secret.as_deref(),
                auth_jwt_provider_profile,
                auth_server_seed_file.as_deref(),
                identity_federation_seed_file.as_deref(),
                enterprise_providers_file.as_deref(),
                auth_jwt_issuer.as_deref(),
                auth_jwt_audience.as_deref(),
                admin_token.as_deref(),
                public_base_url.as_deref(),
                &auth_servers,
                auth_authorization_endpoint.as_deref(),
                auth_token_endpoint.as_deref(),
                auth_registration_endpoint.as_deref(),
                auth_jwks_uri.as_deref(),
                &auth_scopes,
                &auth_subject,
                auth_code_ttl_secs,
                auth_access_token_ttl_secs,
                &command,
                receipt_db.as_deref(),
                revocation_db.as_deref(),
                authority_seed_file.as_deref(),
                authority_db.as_deref(),
                budget_db.as_deref(),
                session_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
        Commands::Trust { command } => match command {
            TrustCommands::Serve {
                listen,
                service_token,
                advertise_url,
                peer_urls,
                cluster_sync_interval_ms,
                policy,
                enterprise_providers_file,
                verifier_policies_file,
                verifier_challenge_db,
                passport_statuses_file,
                passport_issuance_offers_file,
                certification_registry_file,
                certification_discovery_file,
                certification_public_metadata_ttl_seconds,
            } => cmd_trust_serve(
                listen,
                &service_token,
                policy.as_deref(),
                enterprise_providers_file.as_deref(),
                verifier_policies_file.as_deref(),
                verifier_challenge_db.as_deref(),
                passport_statuses_file.as_deref(),
                passport_issuance_offers_file.as_deref(),
                certification_registry_file.as_deref(),
                certification_discovery_file.as_deref(),
                receipt_db.as_deref(),
                revocation_db.as_deref(),
                authority_seed_file.as_deref(),
                authority_db.as_deref(),
                budget_db.as_deref(),
                session_db.as_deref(),
                advertise_url.as_deref(),
                certification_public_metadata_ttl_seconds,
                &peer_urls,
                cluster_sync_interval_ms,
            ),
            TrustCommands::Provider { command } => match command {
                TrustProviderCommands::List {
                    enterprise_providers_file,
                } => admin::cmd_trust_provider_list(
                    cli.json,
                    enterprise_providers_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustProviderCommands::Get {
                    provider_id,
                    enterprise_providers_file,
                } => admin::cmd_trust_provider_get(
                    &provider_id,
                    cli.json,
                    enterprise_providers_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustProviderCommands::Upsert {
                    input,
                    enterprise_providers_file,
                } => admin::cmd_trust_provider_upsert(
                    &input,
                    cli.json,
                    enterprise_providers_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustProviderCommands::Delete {
                    provider_id,
                    enterprise_providers_file,
                } => admin::cmd_trust_provider_delete(
                    &provider_id,
                    cli.json,
                    enterprise_providers_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::EvidenceShare { command } => match command {
                TrustEvidenceShareCommands::List {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    issuer,
                    partner,
                    limit,
                } => cmd_trust_evidence_share_list(
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    issuer.as_deref(),
                    partner.as_deref(),
                    limit,
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::AuthorizationContext { command } => match command {
                TrustAuthorizationContextCommands::Metadata => {
                    cmd_trust_authorization_context_metadata(
                        cli.json,
                        receipt_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustAuthorizationContextCommands::List {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    limit,
                } => cmd_trust_authorization_context_list(
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    limit,
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustAuthorizationContextCommands::ReviewPack {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    limit,
                } => cmd_trust_authorization_context_review_pack(
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    limit,
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::Appraisal { command } => match command {
                TrustRuntimeAttestationAppraisalCommands::Export { input, policy_file } => {
                    cmd_trust_runtime_attestation_appraisal_export(
                        &input,
                        policy_file.as_deref(),
                        cli.json,
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustRuntimeAttestationAppraisalCommands::ExportResult {
                    issuer,
                    input,
                    policy_file,
                } => cmd_trust_runtime_attestation_appraisal_result_export(
                    issuer.as_str(),
                    &input,
                    policy_file.as_deref(),
                    cli.json,
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustRuntimeAttestationAppraisalCommands::Import { input, policy_file } => {
                    cmd_trust_runtime_attestation_appraisal_import(
                        &input,
                        &policy_file,
                        cli.json,
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
            },
            TrustCommands::BehavioralFeed { command } => match command {
                TrustBehavioralFeedCommands::Export {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                } => cmd_trust_behavioral_feed_export(
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    cli.json,
                    receipt_db.as_deref(),
                    budget_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::ExposureLedger { command } => match command {
                TrustExposureLedgerCommands::Export {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                } => cmd_trust_exposure_ledger_export(
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    cli.json,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::CreditScorecard { command } => match command {
                TrustCreditScorecardCommands::Export {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                } => cmd_trust_credit_scorecard_export(
                    &agent_subject,
                    capability.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    cli.json,
                    receipt_db.as_deref(),
                    budget_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::CapitalBook { command } => match command {
                TrustCapitalBookCommands::Export {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    facility_limit,
                    bond_limit,
                    loss_event_limit,
                } => cmd_trust_capital_book_export(
                    &agent_subject,
                    capability.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    facility_limit,
                    bond_limit,
                    loss_event_limit,
                    cli.json,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::CapitalInstruction { command } => match command {
                TrustCapitalInstructionCommands::Issue { input_file } => {
                    cmd_trust_capital_instruction_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
            },
            TrustCommands::CapitalAllocation { command } => match command {
                TrustCapitalAllocationCommands::Issue {
                    input_file,
                    certification_registry_file,
                } => cmd_trust_capital_allocation_issue(
                    &input_file,
                    cli.json,
                    receipt_db.as_deref(),
                    budget_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    certification_registry_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::Facility { command } => match command {
                TrustCreditFacilityCommands::Evaluate {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    certification_registry_file,
                } => cmd_trust_credit_facility_evaluate(
                    &agent_subject,
                    capability.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    cli.json,
                    receipt_db.as_deref(),
                    budget_db.as_deref(),
                    certification_registry_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustCreditFacilityCommands::Issue {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    supersedes_facility_id,
                    certification_registry_file,
                } => cmd_trust_credit_facility_issue(
                    &agent_subject,
                    capability.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    supersedes_facility_id.as_deref(),
                    cli.json,
                    receipt_db.as_deref(),
                    budget_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    certification_registry_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustCreditFacilityCommands::List {
                    facility_id,
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    disposition,
                    lifecycle_state,
                    limit,
                } => cmd_trust_credit_facility_list(
                    facility_id.as_deref(),
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    disposition.as_deref(),
                    lifecycle_state.as_deref(),
                    limit,
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::Bond { command } => match command {
                TrustCreditBondCommands::Evaluate {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    certification_registry_file,
                } => cmd_trust_credit_bond_evaluate(
                    &agent_subject,
                    capability.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    cli.json,
                    receipt_db.as_deref(),
                    budget_db.as_deref(),
                    certification_registry_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustCreditBondCommands::Issue {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    supersedes_bond_id,
                    certification_registry_file,
                } => cmd_trust_credit_bond_issue(
                    &agent_subject,
                    capability.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    supersedes_bond_id.as_deref(),
                    cli.json,
                    receipt_db.as_deref(),
                    budget_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    certification_registry_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustCreditBondCommands::Simulate {
                    bond_id,
                    autonomy_tier,
                    runtime_assurance_tier,
                    call_chain_present,
                    policy_file,
                } => cmd_trust_credit_bond_simulate(
                    &bond_id,
                    &autonomy_tier,
                    &runtime_assurance_tier,
                    call_chain_present,
                    &policy_file,
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustCreditBondCommands::List {
                    bond_id,
                    facility_id,
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    disposition,
                    lifecycle_state,
                    limit,
                } => cmd_trust_credit_bond_list(
                    bond_id.as_deref(),
                    facility_id.as_deref(),
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    disposition.as_deref(),
                    lifecycle_state.as_deref(),
                    limit,
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::Loss { command } => match command {
                TrustCreditLossLifecycleCommands::Evaluate {
                    bond_id,
                    event_kind,
                    amount_units,
                    amount_currency,
                } => cmd_trust_credit_loss_lifecycle_evaluate(
                    &bond_id,
                    &event_kind,
                    amount_units,
                    amount_currency.as_deref(),
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustCreditLossLifecycleCommands::Issue {
                    bond_id,
                    event_kind,
                    amount_units,
                    amount_currency,
                    authority_chain_file,
                    execution_window_file,
                    rail_file,
                    observed_execution_file,
                    appeal_window_ends_at,
                    description,
                } => cmd_trust_credit_loss_lifecycle_issue(
                    &bond_id,
                    &event_kind,
                    amount_units,
                    amount_currency.as_deref(),
                    authority_chain_file.as_deref(),
                    execution_window_file.as_deref(),
                    rail_file.as_deref(),
                    observed_execution_file.as_deref(),
                    appeal_window_ends_at,
                    description.as_deref(),
                    cli.json,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustCreditLossLifecycleCommands::List {
                    event_id,
                    bond_id,
                    facility_id,
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    event_kind,
                    limit,
                } => cmd_trust_credit_loss_lifecycle_list(
                    event_id.as_deref(),
                    bond_id.as_deref(),
                    facility_id.as_deref(),
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    event_kind.as_deref(),
                    limit,
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::CreditBacktest { command } => match command {
                TrustCreditBacktestCommands::Export {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    window_seconds,
                    window_count,
                    stale_after_seconds,
                    certification_registry_file,
                } => cmd_trust_credit_backtest_export(
                    &agent_subject,
                    capability.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    window_seconds,
                    window_count,
                    stale_after_seconds,
                    cli.json,
                    receipt_db.as_deref(),
                    budget_db.as_deref(),
                    certification_registry_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::ProviderRiskPackage { command } => match command {
                TrustProviderRiskPackageCommands::Export {
                    agent_subject,
                    capability,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    recent_loss_limit,
                    certification_registry_file,
                } => cmd_trust_provider_risk_package_export(
                    &agent_subject,
                    capability.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    decision_limit,
                    recent_loss_limit,
                    cli.json,
                    receipt_db.as_deref(),
                    budget_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    certification_registry_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::LiabilityProvider { command } => match command {
                TrustLiabilityProviderCommands::Issue {
                    input_file,
                    supersedes_provider_record_id,
                } => cmd_trust_liability_provider_issue(
                    &input_file,
                    supersedes_provider_record_id.as_deref(),
                    cli.json,
                    receipt_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustLiabilityProviderCommands::List {
                    provider_id,
                    jurisdiction,
                    coverage_class,
                    currency,
                    lifecycle_state,
                    limit,
                } => cmd_trust_liability_provider_list(
                    provider_id.as_deref(),
                    jurisdiction.as_deref(),
                    coverage_class.as_deref(),
                    currency.as_deref(),
                    lifecycle_state.as_deref(),
                    limit,
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustLiabilityProviderCommands::Resolve {
                    provider_id,
                    jurisdiction,
                    coverage_class,
                    currency,
                } => cmd_trust_liability_provider_resolve(
                    &provider_id,
                    &jurisdiction,
                    &coverage_class,
                    &currency,
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::LiabilityMarket { command } => match command {
                TrustLiabilityMarketCommands::QuoteRequestIssue { input_file } => {
                    cmd_trust_liability_quote_request_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::QuoteResponseIssue { input_file } => {
                    cmd_trust_liability_quote_response_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::PricingAuthorityIssue { input_file } => {
                    cmd_trust_liability_pricing_authority_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::PlacementIssue { input_file } => {
                    cmd_trust_liability_placement_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::BoundCoverageIssue { input_file } => {
                    cmd_trust_liability_bound_coverage_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::AutoBindIssue { input_file } => {
                    cmd_trust_liability_auto_bind_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::ClaimIssue { input_file } => {
                    cmd_trust_liability_claim_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::ClaimResponseIssue { input_file } => {
                    cmd_trust_liability_claim_response_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::DisputeIssue { input_file } => {
                    cmd_trust_liability_claim_dispute_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::AdjudicationIssue { input_file } => {
                    cmd_trust_liability_claim_adjudication_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::ClaimPayoutInstructionIssue { input_file } => {
                    cmd_trust_liability_claim_payout_instruction_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::ClaimPayoutReceiptIssue { input_file } => {
                    cmd_trust_liability_claim_payout_receipt_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::ClaimSettlementInstructionIssue { input_file } => {
                    cmd_trust_liability_claim_settlement_instruction_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::ClaimSettlementReceiptIssue { input_file } => {
                    cmd_trust_liability_claim_settlement_receipt_issue(
                        &input_file,
                        cli.json,
                        receipt_db.as_deref(),
                        authority_seed_file.as_deref(),
                        authority_db.as_deref(),
                        control_url.as_deref(),
                        control_token.as_deref(),
                    )
                }
                TrustLiabilityMarketCommands::List {
                    quote_request_id,
                    provider_id,
                    agent_subject,
                    jurisdiction,
                    coverage_class,
                    currency,
                    limit,
                } => cmd_trust_liability_market_list(
                    quote_request_id.as_deref(),
                    provider_id.as_deref(),
                    agent_subject.as_deref(),
                    jurisdiction.as_deref(),
                    coverage_class.as_deref(),
                    currency.as_deref(),
                    limit,
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustLiabilityMarketCommands::ClaimsList {
                    claim_id,
                    provider_id,
                    agent_subject,
                    jurisdiction,
                    policy_number,
                    limit,
                } => cmd_trust_liability_claims_list(
                    claim_id.as_deref(),
                    provider_id.as_deref(),
                    agent_subject.as_deref(),
                    jurisdiction.as_deref(),
                    policy_number.as_deref(),
                    limit,
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::UnderwritingInput { command } => match command {
                TrustUnderwritingInputCommands::Export {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    certification_registry_file,
                } => cmd_trust_underwriting_input_export(
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    cli.json,
                    receipt_db.as_deref(),
                    budget_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    certification_registry_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::UnderwritingDecision { command } => match command {
                TrustUnderwritingDecisionCommands::Evaluate {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    certification_registry_file,
                } => cmd_trust_underwriting_decision_evaluate(
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    cli.json,
                    receipt_db.as_deref(),
                    budget_db.as_deref(),
                    certification_registry_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustUnderwritingDecisionCommands::Simulate {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    policy_file,
                    certification_registry_file,
                } => cmd_trust_underwriting_decision_simulate(
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    &policy_file,
                    certification_registry_file.as_deref(),
                    cli.json,
                    receipt_db.as_deref(),
                    budget_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustUnderwritingDecisionCommands::Issue {
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    receipt_limit,
                    certification_registry_file,
                    supersedes_decision_id,
                } => cmd_trust_underwriting_decision_issue(
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    since,
                    until,
                    receipt_limit,
                    supersedes_decision_id.as_deref(),
                    cli.json,
                    receipt_db.as_deref(),
                    budget_db.as_deref(),
                    authority_seed_file.as_deref(),
                    authority_db.as_deref(),
                    certification_registry_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustUnderwritingDecisionCommands::List {
                    decision_id,
                    capability,
                    agent_subject,
                    tool_server,
                    tool_name,
                    outcome,
                    lifecycle_state,
                    appeal_status,
                    limit,
                } => cmd_trust_underwriting_decision_list(
                    decision_id.as_deref(),
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    tool_server.as_deref(),
                    tool_name.as_deref(),
                    outcome.as_deref(),
                    lifecycle_state.as_deref(),
                    appeal_status.as_deref(),
                    limit,
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::UnderwritingAppeal { command } => match command {
                TrustUnderwritingAppealCommands::Create {
                    decision_id,
                    requested_by,
                    reason,
                    note,
                } => cmd_trust_underwriting_appeal_create(
                    &decision_id,
                    &requested_by,
                    &reason,
                    note.as_deref(),
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustUnderwritingAppealCommands::Resolve {
                    appeal_id,
                    resolution,
                    resolved_by,
                    note,
                    replacement_decision_id,
                } => cmd_trust_underwriting_appeal_resolve(
                    &appeal_id,
                    &resolution,
                    &resolved_by,
                    note.as_deref(),
                    replacement_decision_id.as_deref(),
                    cli.json,
                    receipt_db.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            TrustCommands::Revoke { capability_id } => cmd_trust_revoke(
                &capability_id,
                cli.json,
                revocation_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            TrustCommands::FederatedIssue {
                presentation_response,
                challenge,
                capability_policy,
                enterprise_identity,
                delegation_policy,
                upstream_capability_id,
            } => admin::cmd_trust_federated_issue(
                &presentation_response,
                &challenge,
                &capability_policy,
                enterprise_identity.as_deref(),
                delegation_policy.as_deref(),
                upstream_capability_id.as_deref(),
                cli.json,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            TrustCommands::FederatedDelegationPolicyCreate {
                output,
                signing_seed_file,
                issuer,
                partner,
                verifier,
                capability_policy,
                expires_at,
                purpose,
                parent_capability_id,
            } => admin::cmd_trust_federated_delegation_policy_create(
                &output,
                &signing_seed_file,
                &issuer,
                &partner,
                &verifier,
                &capability_policy,
                expires_at,
                purpose.as_deref(),
                parent_capability_id.as_deref(),
                cli.json,
            ),
            TrustCommands::Status { capability_id } => cmd_trust_status(
                &capability_id,
                cli.json,
                revocation_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
        Commands::Receipt { command } => match command {
            ReceiptCommands::List {
                capability,
                tool_server,
                tool_name,
                outcome,
                since,
                until,
                min_cost,
                max_cost,
                limit,
                cursor,
            } => cmd_receipt_list(
                capability.as_deref(),
                tool_server.as_deref(),
                tool_name.as_deref(),
                outcome.as_deref(),
                since,
                until,
                min_cost,
                max_cost,
                limit,
                cursor,
                receipt_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
        Commands::Evidence { command } => match command {
            EvidenceCommands::Export {
                output,
                capability,
                agent_subject,
                since,
                until,
                policy_file,
                federation_policy,
                require_proofs,
            } => evidence_export::cmd_evidence_export(
                &output,
                capability.as_deref(),
                agent_subject.as_deref(),
                since,
                until,
                policy_file.as_deref(),
                federation_policy.as_deref(),
                require_proofs,
                receipt_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            EvidenceCommands::Verify { input } => {
                evidence_export::cmd_evidence_verify(&input, cli.json)
            }
            EvidenceCommands::Import { input } => evidence_export::cmd_evidence_import(
                &input,
                receipt_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
                cli.json,
            ),
            EvidenceCommands::FederationPolicy { command } => match command {
                EvidenceFederationPolicyCommands::Create {
                    output,
                    signing_seed_file,
                    issuer,
                    partner,
                    capability,
                    agent_subject,
                    since,
                    until,
                    expires_at,
                    require_proofs,
                    purpose,
                } => evidence_export::cmd_evidence_federation_policy_create(
                    &output,
                    &signing_seed_file,
                    &issuer,
                    &partner,
                    capability.as_deref(),
                    agent_subject.as_deref(),
                    since,
                    until,
                    expires_at,
                    require_proofs,
                    purpose.as_deref(),
                    cli.json,
                ),
            },
        },
        Commands::Certify { command } => match command {
            CertifyCommands::Check {
                scenarios_dir,
                results_dir,
                output,
                tool_server_id,
                tool_server_name,
                report_output,
                criteria_profile,
                signing_seed_file,
            } => certify::cmd_certify_check(
                &scenarios_dir,
                &results_dir,
                &output,
                &tool_server_id,
                tool_server_name.as_deref(),
                report_output.as_deref(),
                &criteria_profile,
                &signing_seed_file,
                cli.json,
            ),
            CertifyCommands::Verify { input } => certify::cmd_certify_verify(&input, cli.json),
            CertifyCommands::Registry { command } => match command {
                CertifyRegistryCommands::Publish {
                    input,
                    certification_registry_file,
                } => admin::cmd_certify_registry_publish(
                    &input,
                    certification_registry_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::PublishNetwork {
                    input,
                    certification_discovery_file,
                    operator_ids,
                } => certify::cmd_certify_registry_publish_network(
                    &input,
                    certification_discovery_file.as_deref(),
                    &operator_ids,
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::List {
                    certification_registry_file,
                } => admin::cmd_certify_registry_list(
                    certification_registry_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Get {
                    artifact_id,
                    certification_registry_file,
                } => admin::cmd_certify_registry_get(
                    &artifact_id,
                    certification_registry_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Resolve {
                    tool_server_id,
                    certification_registry_file,
                } => admin::cmd_certify_registry_resolve(
                    &tool_server_id,
                    certification_registry_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Discover {
                    tool_server_id,
                    certification_discovery_file,
                } => certify::cmd_certify_registry_discover(
                    &tool_server_id,
                    certification_discovery_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Search {
                    certification_discovery_file,
                    tool_server_id,
                    criteria_profile,
                    evidence_profile,
                    status,
                    operator_ids,
                } => certify::cmd_certify_registry_search(
                    certification_discovery_file.as_deref(),
                    tool_server_id.as_deref(),
                    criteria_profile.as_deref(),
                    evidence_profile.as_deref(),
                    status.as_deref(),
                    &operator_ids,
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Transparency {
                    certification_discovery_file,
                    tool_server_id,
                    operator_ids,
                } => certify::cmd_certify_registry_transparency(
                    certification_discovery_file.as_deref(),
                    tool_server_id.as_deref(),
                    &operator_ids,
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Consume {
                    tool_server_id,
                    certification_discovery_file,
                    operator_ids,
                    allowed_criteria_profiles,
                    allowed_evidence_profiles,
                } => certify::cmd_certify_registry_consume(
                    certification_discovery_file.as_deref(),
                    &tool_server_id,
                    &operator_ids,
                    &allowed_criteria_profiles,
                    &allowed_evidence_profiles,
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Revoke {
                    artifact_id,
                    reason,
                    revoked_at,
                    certification_registry_file,
                } => admin::cmd_certify_registry_revoke(
                    &artifact_id,
                    certification_registry_file.as_deref(),
                    reason.as_deref(),
                    revoked_at,
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Dispute {
                    artifact_id,
                    state,
                    note,
                    updated_at,
                    certification_registry_file,
                } => certify::cmd_certify_registry_dispute(
                    &artifact_id,
                    &state,
                    note.as_deref(),
                    updated_at,
                    certification_registry_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
        },
        Commands::Did { command } => match command {
            DidCommands::Resolve {
                did,
                public_key,
                receipt_log_urls,
                passport_status_urls,
            } => did::cmd_did_resolve(
                did.as_deref(),
                public_key.as_deref(),
                &receipt_log_urls,
                &passport_status_urls,
                cli.json,
            ),
        },
        Commands::Passport { command } => match command {
            PassportCommands::Create {
                subject_public_key,
                output,
                signing_seed_file,
                validity_days,
                since,
                until,
                receipt_log_urls,
                require_checkpoints,
                enterprise_identity,
            } => passport::cmd_passport_create(
                &subject_public_key,
                &output,
                &signing_seed_file,
                validity_days,
                since,
                until,
                &receipt_log_urls,
                require_checkpoints,
                enterprise_identity.as_deref(),
                receipt_db.as_deref(),
                budget_db.as_deref(),
                cli.json,
            ),
            PassportCommands::Verify {
                input,
                at,
                passport_statuses_file,
            } => passport::cmd_passport_verify(
                &input,
                at,
                passport_statuses_file.as_deref(),
                cli.json,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportCommands::Evaluate {
                input,
                policy,
                at,
                passport_statuses_file,
            } => passport::cmd_passport_evaluate(
                &input,
                &policy,
                at,
                passport_statuses_file.as_deref(),
                cli.json,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportCommands::Present {
                input,
                output,
                issuers,
                max_credentials,
            } => {
                passport::cmd_passport_present(&input, &output, &issuers, max_credentials, cli.json)
            }
            PassportCommands::Policy { command } => match command {
                PassportPolicyCommands::Create {
                    output,
                    policy_id,
                    verifier,
                    signing_seed_file,
                    policy,
                    expires_at,
                    verifier_policies_file,
                } => passport::cmd_passport_policy_create(
                    &output,
                    &policy_id,
                    &verifier,
                    &signing_seed_file,
                    &policy,
                    expires_at,
                    verifier_policies_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportPolicyCommands::Verify { input, at } => {
                    passport::cmd_passport_policy_verify(&input, at, cli.json)
                }
                PassportPolicyCommands::List {
                    verifier_policies_file,
                } => passport::cmd_passport_policy_list(
                    cli.json,
                    verifier_policies_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportPolicyCommands::Get {
                    policy_id,
                    verifier_policies_file,
                } => passport::cmd_passport_policy_get(
                    &policy_id,
                    cli.json,
                    verifier_policies_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportPolicyCommands::Upsert {
                    input,
                    verifier_policies_file,
                } => passport::cmd_passport_policy_upsert(
                    &input,
                    cli.json,
                    verifier_policies_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportPolicyCommands::Delete {
                    policy_id,
                    verifier_policies_file,
                } => passport::cmd_passport_policy_delete(
                    &policy_id,
                    cli.json,
                    verifier_policies_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            PassportCommands::Challenge { command } => match command {
                PassportChallengeCommands::Create {
                    output,
                    verifier,
                    ttl_secs,
                    issuers,
                    max_credentials,
                    policy,
                    policy_id,
                    verifier_policies_file,
                    verifier_challenge_db,
                } => passport::cmd_passport_challenge_create(
                    &output,
                    &verifier,
                    ttl_secs,
                    &issuers,
                    max_credentials,
                    policy.as_deref(),
                    policy_id.as_deref(),
                    verifier_policies_file.as_deref(),
                    verifier_challenge_db.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportChallengeCommands::Respond {
                    input,
                    challenge,
                    challenge_url,
                    holder_seed_file,
                    output,
                    at,
                } => passport::cmd_passport_challenge_respond(
                    &input,
                    challenge.as_deref(),
                    challenge_url.as_deref(),
                    &holder_seed_file,
                    &output,
                    at,
                    cli.json,
                ),
                PassportChallengeCommands::Submit { input, submit_url } => {
                    passport::cmd_passport_challenge_submit(&input, &submit_url, cli.json)
                }
                PassportChallengeCommands::Verify {
                    input,
                    challenge,
                    verifier_policies_file,
                    verifier_challenge_db,
                    passport_statuses_file,
                    at,
                } => passport::cmd_passport_challenge_verify(
                    &input,
                    challenge.as_deref(),
                    verifier_policies_file.as_deref(),
                    verifier_challenge_db.as_deref(),
                    passport_statuses_file.as_deref(),
                    at,
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            PassportCommands::Status { command } => match command {
                PassportStatusCommands::Publish {
                    input,
                    passport_statuses_file,
                    resolve_urls,
                    cache_ttl_secs,
                } => passport::cmd_passport_status_publish(
                    &input,
                    passport_statuses_file.as_deref(),
                    &resolve_urls,
                    cache_ttl_secs,
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportStatusCommands::List {
                    passport_statuses_file,
                } => passport::cmd_passport_status_list(
                    passport_statuses_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportStatusCommands::Get {
                    passport_id,
                    passport_statuses_file,
                } => passport::cmd_passport_status_get(
                    &passport_id,
                    passport_statuses_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportStatusCommands::Resolve {
                    passport_id,
                    passport_statuses_file,
                } => passport::cmd_passport_status_resolve(
                    &passport_id,
                    passport_statuses_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportStatusCommands::Revoke {
                    passport_id,
                    passport_statuses_file,
                    reason,
                    revoked_at,
                } => passport::cmd_passport_status_revoke(
                    &passport_id,
                    passport_statuses_file.as_deref(),
                    reason.as_deref(),
                    revoked_at,
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            PassportCommands::Issuance { command } => match command {
                PassportIssuanceCommands::Metadata {
                    issuer_url,
                    signing_seed_file,
                    passport_status_url,
                    passport_status_cache_ttl_secs,
                } => passport::cmd_passport_issuance_metadata(
                    issuer_url.as_deref(),
                    signing_seed_file.as_deref(),
                    passport_status_url.as_deref(),
                    passport_status_cache_ttl_secs,
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportIssuanceCommands::Offer {
                    input,
                    output,
                    issuer_url,
                    passport_issuance_offers_file,
                    passport_statuses_file,
                    signing_seed_file,
                    credential_configuration_id,
                    ttl_secs,
                } => passport::cmd_passport_issuance_offer_create(
                    &input,
                    output.as_deref(),
                    issuer_url.as_deref(),
                    passport_issuance_offers_file.as_deref(),
                    passport_statuses_file.as_deref(),
                    signing_seed_file.as_deref(),
                    credential_configuration_id.as_deref(),
                    ttl_secs,
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportIssuanceCommands::Token {
                    offer,
                    output,
                    passport_issuance_offers_file,
                } => passport::cmd_passport_issuance_token_redeem(
                    &offer,
                    output.as_deref(),
                    passport_issuance_offers_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportIssuanceCommands::Credential {
                    offer,
                    token,
                    output,
                    passport_issuance_offers_file,
                    passport_statuses_file,
                    signing_seed_file,
                    credential_configuration_id,
                    format,
                } => passport::cmd_passport_issuance_credential_redeem(
                    &offer,
                    &token,
                    output.as_deref(),
                    passport_issuance_offers_file.as_deref(),
                    passport_statuses_file.as_deref(),
                    signing_seed_file.as_deref(),
                    credential_configuration_id.as_deref(),
                    format.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
            PassportCommands::Oid4vp { command } => match command {
                PassportOid4vpCommands::Create {
                    output,
                    disclosure_claims,
                    issuer_allowlist,
                    ttl_secs,
                    identity_subject,
                    identity_continuity_id,
                    identity_provider,
                    identity_session_hint,
                    identity_ttl_secs,
                } => passport::cmd_passport_oid4vp_request_create(
                    output.as_deref(),
                    &disclosure_claims,
                    &issuer_allowlist,
                    ttl_secs,
                    identity_subject.as_deref(),
                    identity_continuity_id.as_deref(),
                    identity_provider.as_deref(),
                    identity_session_hint.as_deref(),
                    identity_ttl_secs,
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                PassportOid4vpCommands::Respond {
                    input,
                    request_url,
                    same_device_url,
                    cross_device_url,
                    holder_seed_file,
                    output,
                    submit,
                    submit_url,
                    at,
                } => passport::cmd_passport_oid4vp_respond(
                    &input,
                    request_url.as_deref(),
                    same_device_url.as_deref(),
                    cross_device_url.as_deref(),
                    &holder_seed_file,
                    output.as_deref(),
                    submit,
                    submit_url.as_deref(),
                    at,
                    cli.json,
                ),
                PassportOid4vpCommands::Submit { input, submit_url } => {
                    passport::cmd_passport_oid4vp_submit(&input, &submit_url, cli.json)
                }
                PassportOid4vpCommands::Metadata { verifier_url } => {
                    passport::cmd_passport_oid4vp_metadata(&verifier_url, cli.json)
                }
            },
        },
        Commands::Reputation { command } => match command {
            ReputationCommands::Local {
                subject_public_key,
                since,
                until,
                policy,
            } => reputation::cmd_reputation_local(
                &subject_public_key,
                since,
                until,
                policy.as_deref(),
                cli.json,
                receipt_db.as_deref(),
                budget_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            ReputationCommands::Compare {
                subject_public_key,
                passport,
                since,
                until,
                local_policy,
                verifier_policy,
            } => reputation::cmd_reputation_compare(
                &subject_public_key,
                &passport,
                since,
                until,
                local_policy.as_deref(),
                verifier_policy.as_deref(),
                cli.json,
                receipt_db.as_deref(),
                budget_db.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
    };

    if let Err(e) = result {
        if cli.json {
            let msg = serde_json::json!({ "error": e.to_string() });
            let _ = writeln!(std::io::stderr(), "{msg}");
        } else {
            eprintln!("error: {e}");
        }
        std::process::exit(1);
    }
}

fn cmd_run(
    policy_path: &Path,
    command: &[String],
    json_output: bool,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();
    let issuance_policy = loaded_policy.issuance_policy.clone();
    let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();

    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %policy_identity.source_hash,
        runtime_policy_hash = %policy_identity.runtime_hash,
        "loaded policy"
    );

    let kernel_kp = Keypair::generate();
    let mut kernel = build_kernel(loaded_policy, &kernel_kp);
    configure_receipt_store(&mut kernel, receipt_db_path, control_url, control_token)?;
    configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
    configure_capability_authority(
        &mut kernel,
        &kernel_kp,
        authority_seed_path,
        authority_db_path,
        receipt_db_path,
        budget_db_path,
        control_url,
        control_token,
        issuance_policy,
        runtime_assurance_policy,
    )?;
    configure_budget_store(&mut kernel, budget_db_path, control_url, control_token)?;

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let session_agent_id = agent_pk.to_hex();
    let initial_caps = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;
    let session_id = kernel.open_session(session_agent_id.clone(), initial_caps.clone());

    info!(
        capability_count = initial_caps.len(),
        agent_id = %session_agent_id,
        "issued initial capabilities to agent"
    );

    let (cmd, args) = command
        .split_first()
        .ok_or_else(|| CliError::Other("empty command".to_string()))?;

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| CliError::Other("failed to open child stdin".to_string()))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::Other("failed to open child stdout".to_string()))?;

    let mut transport = ArcTransport::new(child_stdout, child_stdin);

    let init_msg = KernelMessage::CapabilityList {
        capabilities: initial_caps.clone(),
    };
    transport.send(&init_msg)?;
    kernel.activate_session(&session_id)?;

    info!("sent initial capabilities to agent, entering message loop");

    let mut stats = SessionStats::default();

    loop {
        let agent_msg = match transport.recv() {
            Ok(msg) => msg,
            Err(TransportError::ConnectionClosed) => {
                debug!("agent closed connection");
                break;
            }
            Err(e) => {
                warn!(error = %e, "transport read error");
                break;
            }
        };

        let kernel_msgs = handle_agent_message(
            &mut kernel,
            &agent_msg,
            &session_id,
            &session_agent_id,
            &mut stats,
        );

        let mut write_failed = false;
        for kernel_msg in kernel_msgs {
            if let Err(e) = transport.send(&kernel_msg) {
                warn!(error = %e, "transport write error");
                write_failed = true;
                break;
            }
        }
        if write_failed {
            break;
        }
    }

    if let Err(e) = kernel.begin_draining_session(&session_id) {
        warn!(error = %e, session_id = %session_id, "failed to mark session draining");
    }

    if let Err(e) = kernel.close_session(&session_id) {
        warn!(error = %e, session_id = %session_id, "failed to close session");
    }

    let status = child.wait()?;
    print_summary(&stats, status.code(), json_output);

    if status.success() {
        Ok(())
    } else {
        let code = status.code().unwrap_or(1);
        Err(CliError::Other(format!("agent exited with code {code}")))
    }
}

fn cmd_check(
    policy_path: &Path,
    tool: &str,
    params_str: &str,
    server: &str,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();
    let issuance_policy = loaded_policy.issuance_policy.clone();
    let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();

    let kernel_kp = Keypair::generate();
    let mut kernel = build_kernel(loaded_policy, &kernel_kp);
    configure_receipt_store(&mut kernel, receipt_db_path, control_url, control_token)?;
    configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
    configure_capability_authority(
        &mut kernel,
        &kernel_kp,
        authority_seed_path,
        authority_db_path,
        receipt_db_path,
        budget_db_path,
        control_url,
        control_token,
        issuance_policy,
        runtime_assurance_policy,
    )?;
    configure_budget_store(&mut kernel, budget_db_path, control_url, control_token)?;

    kernel.register_tool_server(Box::new(StubToolServer {
        id: server.to_string(),
    }));

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let session_agent_id = agent_pk.to_hex();
    let params: serde_json::Value = serde_json::from_str(params_str)?;
    let initial_caps = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;
    let cap = match select_capability_for_request(&initial_caps, tool, server, &params) {
        Some(capability) => capability,
        None => kernel
            .issue_capability(&agent_pk, ArcScope::default(), 300)
            .map_err(|error| {
                CliError::Other(format!(
                    "failed to issue fallback empty capability: {error}"
                ))
            })?,
    };
    let session_id = kernel.open_session(session_agent_id.clone(), initial_caps);
    kernel.activate_session(&session_id)?;

    let context = OperationContext::new(
        session_id.clone(),
        RequestId::new("check-001"),
        session_agent_id,
    );
    let operation = SessionOperation::ToolCall(ToolCallOperation {
        capability: cap,
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        arguments: params.clone(),
    });

    let response = match kernel.evaluate_session_operation(&context, &operation)? {
        SessionOperationResponse::ToolCall(response) => response,
        SessionOperationResponse::RootList { .. }
        | SessionOperationResponse::ResourceList { .. }
        | SessionOperationResponse::ResourceRead { .. }
        | SessionOperationResponse::ResourceReadDenied { .. }
        | SessionOperationResponse::ResourceTemplateList { .. }
        | SessionOperationResponse::PromptList { .. }
        | SessionOperationResponse::PromptGet { .. }
        | SessionOperationResponse::Completion { .. }
        | SessionOperationResponse::CapabilityList { .. }
        | SessionOperationResponse::Heartbeat => {
            return Err(CliError::Other(
                "unexpected non-tool response while evaluating check command".to_string(),
            ));
        }
    };

    kernel.begin_draining_session(&session_id)?;
    kernel.close_session(&session_id)?;

    if json_output {
        let output = serde_json::json!({
            "verdict": format!("{:?}", response.verdict),
            "tool": tool,
            "server": server,
            "params": params,
            "reason": response.reason,
            "receipt_id": response.receipt.id,
            "policy_hash": policy_identity.runtime_hash,
            "policy_source_hash": policy_identity.source_hash,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        let verdict_str = match response.verdict {
            arc_kernel::Verdict::Allow => "ALLOW",
            arc_kernel::Verdict::Deny => "DENY",
        };
        println!("verdict:    {verdict_str}");
        println!("tool:       {tool}");
        println!("server:     {server}");
        if let Some(reason) = &response.reason {
            println!("reason:     {reason}");
        }
        println!("receipt_id: {}", response.receipt.id);
        println!("policy:     {}", policy_identity.runtime_hash);
        println!("source:     {}", policy_identity.source_hash);
    }

    match response.verdict {
        arc_kernel::Verdict::Allow => Ok(()),
        arc_kernel::Verdict::Deny => {
            std::process::exit(2);
        }
    }
}

fn cmd_mcp_serve(
    policy_path: &Path,
    server_id: &str,
    server_name: Option<&str>,
    server_version: Option<&str>,
    manifest_public_key: Option<&str>,
    page_size: usize,
    tools_list_changed: bool,
    command: &[String],
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();
    let issuance_policy = loaded_policy.issuance_policy.clone();
    let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();

    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %policy_identity.source_hash,
        runtime_policy_hash = %policy_identity.runtime_hash,
        server_id = server_id,
        "loaded policy for MCP edge"
    );

    let kernel_kp = Keypair::generate();
    let mut kernel = build_kernel(loaded_policy, &kernel_kp);
    configure_receipt_store(&mut kernel, receipt_db_path, control_url, control_token)?;
    configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
    configure_capability_authority(
        &mut kernel,
        &kernel_kp,
        authority_seed_path,
        authority_db_path,
        receipt_db_path,
        budget_db_path,
        control_url,
        control_token,
        issuance_policy,
        runtime_assurance_policy,
    )?;
    configure_budget_store(&mut kernel, budget_db_path, control_url, control_token)?;

    let (wrapped_cmd, wrapped_args) = command
        .split_first()
        .ok_or_else(|| CliError::Other("empty MCP server command".to_string()))?;
    let wrapped_arg_refs = wrapped_args.iter().map(String::as_str).collect::<Vec<_>>();

    let manifest_public_key = manifest_public_key
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| Keypair::generate().public_key().to_hex());
    let adapted_server = AdaptedMcpServer::from_command(
        wrapped_cmd,
        &wrapped_arg_refs,
        McpAdapterConfig {
            server_id: server_id.to_string(),
            server_name: server_name.unwrap_or(server_id).to_string(),
            server_version: server_version
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .to_string(),
            public_key: manifest_public_key,
        },
    )?;
    let upstream_notification_source = adapted_server.notification_source();
    let upstream_capabilities = adapted_server.upstream_capabilities();
    let manifest = adapted_server.manifest_clone();
    if let Some(resource_provider) = adapted_server.resource_provider() {
        kernel.register_resource_provider(Box::new(resource_provider));
    }
    if let Some(prompt_provider) = adapted_server.prompt_provider() {
        kernel.register_prompt_provider(Box::new(prompt_provider));
    }
    kernel.register_tool_server(Box::new(adapted_server));

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let agent_id = agent_pk.to_hex();
    let capabilities = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;

    info!(
        capability_count = capabilities.len(),
        upstream_resources = upstream_capabilities.resources_supported,
        upstream_prompts = upstream_capabilities.prompts_supported,
        upstream_completions = upstream_capabilities.completions_supported,
        wrapped_command = wrapped_cmd,
        "initialized MCP edge session"
    );

    let mut edge = ArcMcpEdge::new(
        McpEdgeConfig {
            server_name: "ARC MCP Edge".to_string(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            page_size,
            tools_list_changed: tools_list_changed || upstream_capabilities.tools_list_changed,
            completion_enabled: Some(upstream_capabilities.completions_supported),
            resources_subscribe: upstream_capabilities.resources_subscribe,
            resources_list_changed: upstream_capabilities.resources_list_changed,
            prompts_list_changed: upstream_capabilities.prompts_list_changed,
            logging_enabled: true,
        },
        kernel,
        agent_id,
        capabilities,
        vec![manifest],
    )?;
    edge.attach_upstream_transport(upstream_notification_source);

    edge.serve_stdio(std::io::BufReader::new(std::io::stdin()), std::io::stdout())?;
    Ok(())
}

fn cmd_mcp_serve_http(
    policy_path: &Path,
    server_id: &str,
    server_name: Option<&str>,
    server_version: Option<&str>,
    manifest_public_key: Option<&str>,
    page_size: usize,
    tools_list_changed: bool,
    shared_hosted_owner: bool,
    listen: SocketAddr,
    auth_token: Option<&str>,
    auth_jwt_public_key: Option<&str>,
    auth_jwt_discovery_url: Option<&str>,
    auth_introspection_url: Option<&str>,
    auth_introspection_client_id: Option<&str>,
    auth_introspection_client_secret: Option<&str>,
    auth_jwt_provider_profile: Option<remote_mcp::JwtProviderProfile>,
    auth_server_seed_file: Option<&Path>,
    identity_federation_seed_file: Option<&Path>,
    enterprise_providers_file: Option<&Path>,
    auth_jwt_issuer: Option<&str>,
    auth_jwt_audience: Option<&str>,
    admin_token: Option<&str>,
    public_base_url: Option<&str>,
    auth_servers: &[String],
    auth_authorization_endpoint: Option<&str>,
    auth_token_endpoint: Option<&str>,
    auth_registration_endpoint: Option<&str>,
    auth_jwks_uri: Option<&str>,
    auth_scopes: &[String],
    auth_subject: &str,
    auth_code_ttl_secs: u64,
    auth_access_token_ttl_secs: u64,
    command: &[String],
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %loaded_policy.identity.source_hash,
        runtime_policy_hash = %loaded_policy.identity.runtime_hash,
        server_id = server_id,
        listen_addr = %listen,
        "loaded policy for remote MCP edge"
    );

    let (wrapped_cmd, wrapped_args) = command
        .split_first()
        .ok_or_else(|| CliError::Other("empty MCP server command".to_string()))?;

    remote_mcp::serve_http(remote_mcp::RemoteServeHttpConfig {
        listen,
        auth_token: auth_token.map(ToOwned::to_owned),
        auth_jwt_public_key: auth_jwt_public_key.map(ToOwned::to_owned),
        auth_jwt_discovery_url: auth_jwt_discovery_url.map(ToOwned::to_owned),
        auth_introspection_url: auth_introspection_url.map(ToOwned::to_owned),
        auth_introspection_client_id: auth_introspection_client_id.map(ToOwned::to_owned),
        auth_introspection_client_secret: auth_introspection_client_secret.map(ToOwned::to_owned),
        auth_jwt_provider_profile,
        auth_server_seed_path: auth_server_seed_file.map(Path::to_path_buf),
        identity_federation_seed_path: identity_federation_seed_file.map(Path::to_path_buf),
        enterprise_providers_file: enterprise_providers_file.map(Path::to_path_buf),
        auth_jwt_issuer: auth_jwt_issuer.map(ToOwned::to_owned),
        auth_jwt_audience: auth_jwt_audience.map(ToOwned::to_owned),
        admin_token: admin_token.map(ToOwned::to_owned),
        control_url: control_url.map(ToOwned::to_owned),
        control_token: control_token.map(ToOwned::to_owned),
        public_base_url: public_base_url.map(ToOwned::to_owned),
        auth_servers: auth_servers.to_vec(),
        auth_authorization_endpoint: auth_authorization_endpoint.map(ToOwned::to_owned),
        auth_token_endpoint: auth_token_endpoint.map(ToOwned::to_owned),
        auth_registration_endpoint: auth_registration_endpoint.map(ToOwned::to_owned),
        auth_jwks_uri: auth_jwks_uri.map(ToOwned::to_owned),
        auth_scopes: auth_scopes.to_vec(),
        auth_subject: auth_subject.to_string(),
        auth_code_ttl_secs,
        auth_access_token_ttl_secs,
        receipt_db_path: receipt_db_path.map(std::path::Path::to_path_buf),
        revocation_db_path: revocation_db_path.map(std::path::Path::to_path_buf),
        authority_seed_path: authority_seed_path.map(std::path::Path::to_path_buf),
        authority_db_path: authority_db_path.map(std::path::Path::to_path_buf),
        budget_db_path: budget_db_path.map(std::path::Path::to_path_buf),
        session_db_path: session_db_path.map(std::path::Path::to_path_buf),
        policy_path: policy_path.to_path_buf(),
        server_id: server_id.to_string(),
        server_name: server_name.unwrap_or(server_id).to_string(),
        server_version: server_version
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .to_string(),
        manifest_public_key: manifest_public_key.map(ToOwned::to_owned),
        page_size,
        tools_list_changed,
        shared_hosted_owner,
        wrapped_command: wrapped_cmd.clone(),
        wrapped_args: wrapped_args.to_vec(),
    })
}

fn require_revocation_db_path(revocation_db_path: Option<&Path>) -> Result<&Path, CliError> {
    revocation_db_path.ok_or_else(|| {
        CliError::Other(
            "trust commands require --revocation-db <path> so persisted trust state is explicit"
                .to_string(),
        )
    })
}

fn require_receipt_db_path(receipt_db_path: Option<&Path>) -> Result<&Path, CliError> {
    receipt_db_path.ok_or_else(|| {
        CliError::Other(
            "shared evidence commands require --receipt-db <path> when --control-url is not set"
                .to_string(),
        )
    })
}

fn cmd_trust_serve(
    listen: SocketAddr,
    service_token: &str,
    policy_path: Option<&Path>,
    enterprise_providers_file: Option<&Path>,
    verifier_policies_file: Option<&Path>,
    verifier_challenge_db: Option<&Path>,
    passport_statuses_file: Option<&Path>,
    passport_issuance_offers_file: Option<&Path>,
    certification_registry_file: Option<&Path>,
    certification_discovery_file: Option<&Path>,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    advertise_url: Option<&str>,
    certification_public_metadata_ttl_seconds: u64,
    peer_urls: &[String],
    cluster_sync_interval_ms: u64,
) -> Result<(), CliError> {
    let (issuance_policy, runtime_assurance_policy) = policy_path
        .map(load_policy)
        .transpose()?
        .map(|loaded| (loaded.issuance_policy, loaded.runtime_assurance_policy))
        .unwrap_or((None, None));
    trust_control::serve(trust_control::TrustServiceConfig {
        listen,
        service_token: service_token.to_string(),
        receipt_db_path: receipt_db_path.map(Path::to_path_buf),
        revocation_db_path: revocation_db_path.map(Path::to_path_buf),
        authority_seed_path: authority_seed_path.map(Path::to_path_buf),
        authority_db_path: authority_db_path.map(Path::to_path_buf),
        budget_db_path: budget_db_path.map(Path::to_path_buf),
        enterprise_providers_file: enterprise_providers_file.map(Path::to_path_buf),
        verifier_policies_file: verifier_policies_file.map(Path::to_path_buf),
        verifier_challenge_db_path: verifier_challenge_db.map(Path::to_path_buf),
        passport_statuses_file: passport_statuses_file.map(Path::to_path_buf),
        passport_issuance_offers_file: passport_issuance_offers_file.map(Path::to_path_buf),
        certification_registry_file: certification_registry_file.map(Path::to_path_buf),
        certification_discovery_file: certification_discovery_file.map(Path::to_path_buf),
        issuance_policy,
        runtime_assurance_policy,
        advertise_url: advertise_url.map(ToOwned::to_owned),
        certification_public_metadata_ttl_seconds,
        peer_urls: peer_urls.to_vec(),
        cluster_sync_interval: std::time::Duration::from_millis(cluster_sync_interval_ms.max(50)),
    })
}

fn cmd_trust_revoke(
    capability_id: &str,
    json_output: bool,
    revocation_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (newly_revoked, backend_label) = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::build_client(url, token)?.revoke_capability(capability_id)?;
        (response.newly_revoked, url.to_string())
    } else {
        let path = require_revocation_db_path(revocation_db_path)?;
        let mut store = arc_store_sqlite::SqliteRevocationStore::open(path)?;
        (store.revoke(capability_id)?, path.display().to_string())
    };

    if json_output {
        let output = serde_json::json!({
            "capability_id": capability_id,
            "revoked": true,
            "newly_revoked": newly_revoked,
            "revocation_backend": backend_label,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("capability_id: {capability_id}");
        println!("revoked:       true");
        println!("newly_revoked: {newly_revoked}");
        println!("backend:       {backend_label}");
    }

    Ok(())
}

fn cmd_trust_status(
    capability_id: &str,
    json_output: bool,
    revocation_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (revoked, backend_label) = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::build_client(url, token)?.list_revocations(
            &trust_control::RevocationQuery {
                capability_id: Some(capability_id.to_string()),
                limit: Some(1),
            },
        )?;
        (response.revoked.unwrap_or(false), url.to_string())
    } else {
        let path = require_revocation_db_path(revocation_db_path)?;
        let store = arc_store_sqlite::SqliteRevocationStore::open(path)?;
        (store.is_revoked(capability_id)?, path.display().to_string())
    };

    if json_output {
        let output = serde_json::json!({
            "capability_id": capability_id,
            "revoked": revoked,
            "revocation_backend": backend_label,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("capability_id: {capability_id}");
        println!("revoked:       {revoked}");
        println!("backend:       {backend_label}");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_evidence_share_list(
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    issuer: Option<&str>,
    partner: Option<&str>,
    limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::SharedEvidenceQuery {
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: agent_subject.map(ToOwned::to_owned),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        since,
        until,
        issuer: issuer.map(ToOwned::to_owned),
        partner: partner.map(ToOwned::to_owned),
        limit: Some(limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.shared_evidence_report(&query)?
    } else {
        let path = require_receipt_db_path(receipt_db_path)?;
        let store = arc_store_sqlite::SqliteReceiptStore::open(path)?;
        store.query_shared_evidence_report(&query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "matching_shares:         {}",
            report.summary.matching_shares
        );
        println!(
            "matching_references:     {}",
            report.summary.matching_references
        );
        println!(
            "matching_local_receipts: {}",
            report.summary.matching_local_receipts
        );
        println!(
            "remote_tool_receipts:    {}",
            report.summary.remote_tool_receipts
        );
        println!(
            "remote_lineage_records:  {}",
            report.summary.remote_lineage_records
        );
        for reference in report.references {
            println!(
                "- {} partner={} remote_capability={} local_anchor={} receipts={}",
                reference.share.share_id,
                reference.share.partner,
                reference.capability_id,
                reference
                    .local_anchor_capability_id
                    .as_deref()
                    .unwrap_or("n/a"),
                reference.matched_local_receipts
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_authorization_context_metadata(
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.authorization_profile_metadata()?
    } else {
        let path = require_receipt_db_path(receipt_db_path)?;
        let store = arc_store_sqlite::SqliteReceiptStore::open(path)?;
        store.authorization_profile_metadata_report()
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                     {}", report.schema);
        println!("generated_at:               {}", report.generated_at);
        println!("profile_id:                 {}", report.profile.id);
        println!("profile_schema:             {}", report.profile.schema);
        println!("report_schema:              {}", report.report_schema);
        println!(
            "discovery_informational:    {}",
            report.discovery.discovery_informational_only
        );
        println!(
            "auth_server_metadata_path:  {}",
            report.discovery.authorization_server_metadata_path_template
        );
        for path in report.discovery.protected_resource_metadata_paths {
            println!("protected_resource_path:    {path}");
        }
        println!(
            "sender_constrained:         {}",
            report.support_boundary.sender_constrained_projection
        );
        println!(
            "runtime_assurance:          {}",
            report.support_boundary.runtime_assurance_projection
        );
        println!(
            "delegated_call_chain:       {}",
            report.support_boundary.delegated_call_chain_projection
        );
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_authorization_context_list(
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::OperatorReportQuery {
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: agent_subject.map(ToOwned::to_owned),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        since,
        until,
        authorization_limit: Some(limit),
        ..arc_kernel::OperatorReportQuery::default()
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.authorization_context_report(&query)?
    } else {
        let path = require_receipt_db_path(receipt_db_path)?;
        let store = arc_store_sqlite::SqliteReceiptStore::open(path)?;
        store.query_authorization_context_report(&query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                     {}", report.schema);
        println!("profile_id:                 {}", report.profile.id);
        println!(
            "profile_source:             {}",
            report.profile.authoritative_source
        );
        println!(
            "matching_receipts:          {}",
            report.summary.matching_receipts
        );
        println!(
            "returned_receipts:          {}",
            report.summary.returned_receipts
        );
        println!(
            "approval_receipts:          {}",
            report.summary.approval_receipts
        );
        println!(
            "approved_receipts:          {}",
            report.summary.approved_receipts
        );
        println!(
            "call_chain_receipts:        {}",
            report.summary.call_chain_receipts
        );
        println!(
            "metered_billing_receipts:   {}",
            report.summary.metered_billing_receipts
        );
        println!(
            "runtime_assurance_receipts: {}",
            report.summary.runtime_assurance_receipts
        );
        println!(
            "sender_bound_receipts:      {}",
            report.summary.sender_bound_receipts
        );
        println!(
            "dpop_bound_receipts:        {}",
            report.summary.dpop_bound_receipts
        );
        for row in report.receipts {
            println!(
                "- {} intent={} tool={}/{} details={} sender={} proof={} call_chain={}",
                row.receipt_id,
                row.transaction_context.intent_id,
                row.tool_server,
                row.tool_name,
                row.authorization_details.len(),
                row.sender_constraint.subject_key,
                row.sender_constraint
                    .proof_type
                    .as_deref()
                    .unwrap_or("none"),
                row.transaction_context
                    .call_chain
                    .as_ref()
                    .map(|value| value.chain_id.as_str())
                    .unwrap_or("n/a")
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_authorization_context_review_pack(
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::OperatorReportQuery {
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: agent_subject.map(ToOwned::to_owned),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        since,
        until,
        authorization_limit: Some(limit),
        ..arc_kernel::OperatorReportQuery::default()
    };

    let pack = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.authorization_review_pack(&query)?
    } else {
        let path = require_receipt_db_path(receipt_db_path)?;
        let store = arc_store_sqlite::SqliteReceiptStore::open(path)?;
        store.query_authorization_review_pack(&query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&pack)?);
    } else {
        println!("schema:                     {}", pack.schema);
        println!("generated_at:               {}", pack.generated_at);
        println!("profile_id:                 {}", pack.metadata.profile.id);
        println!(
            "matching_receipts:          {}",
            pack.summary.matching_receipts
        );
        println!(
            "returned_receipts:          {}",
            pack.summary.returned_receipts
        );
        println!(
            "dpop_required_receipts:     {}",
            pack.summary.dpop_required_receipts
        );
        println!(
            "runtime_assurance_receipts: {}",
            pack.summary.runtime_assurance_receipts
        );
        println!(
            "delegated_call_chain:       {}",
            pack.summary.delegated_call_chain_receipts
        );
        for record in pack.records {
            println!(
                "- {} intent={} tool={}/{} approval={} sender={}",
                record.receipt_id,
                record.governed_transaction.intent_id,
                record.authorization_context.tool_server,
                record.authorization_context.tool_name,
                record
                    .governed_transaction
                    .approval
                    .as_ref()
                    .map(|value| value.token_id.as_str())
                    .unwrap_or("none"),
                record.authorization_context.sender_constraint.subject_key
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_behavioral_feed_export(
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::BehavioralFeedQuery {
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: agent_subject.map(ToOwned::to_owned),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        since,
        until,
        receipt_limit: Some(receipt_limit),
    };

    let feed = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.behavioral_feed(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "behavioral feed export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_signed_behavioral_feed(
            receipt_db_path,
            budget_db_path,
            authority_seed_path,
            authority_db_path,
            &query,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&feed)?);
    } else {
        println!("schema:                 {}", feed.body.schema);
        println!("generated_at:           {}", feed.body.generated_at);
        println!("signer_key:             {}", feed.signer_key.to_hex());
        println!(
            "matching_receipts:      {}",
            feed.body.privacy.matching_receipts
        );
        println!(
            "returned_receipts:      {}",
            feed.body.privacy.returned_receipts
        );
        println!(
            "allow_count:            {}",
            feed.body.decisions.allow_count
        );
        println!("deny_count:             {}", feed.body.decisions.deny_count);
        println!(
            "governed_receipts:      {}",
            feed.body.governed_actions.governed_receipts
        );
        if let Some(reputation) = feed.body.reputation.as_ref() {
            println!("subject_key:            {}", reputation.subject_key);
            println!("effective_score:        {:.4}", reputation.effective_score);
            println!(
                "imported_signals:       {}",
                reputation.imported_signal_count
            );
            println!(
                "accepted_imported:      {}",
                reputation.accepted_imported_signal_count
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_exposure_ledger_export(
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    decision_limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::ExposureLedgerQuery {
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: agent_subject.map(ToOwned::to_owned),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        since,
        until,
        receipt_limit: Some(receipt_limit),
        decision_limit: Some(decision_limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.exposure_ledger(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "exposure ledger export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_signed_exposure_ledger_report(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &query,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.body.schema);
        println!("generated_at:           {}", report.body.generated_at);
        println!("signer_key:             {}", report.signer_key.to_hex());
        println!(
            "matching_receipts:      {}",
            report.body.summary.matching_receipts
        );
        println!(
            "matching_decisions:     {}",
            report.body.summary.matching_decisions
        );
        println!(
            "currencies:             {}",
            if report.body.summary.currencies.is_empty() {
                "none".to_string()
            } else {
                report.body.summary.currencies.join(", ")
            }
        );
        println!(
            "mixed_currency_book:    {}",
            report.body.summary.mixed_currency_book
        );
        for position in &report.body.positions {
            println!(
                "- {} governed={} reserved={} settled={} pending={} failed={} loss={} quoted_premium={} active_premium={}",
                position.currency,
                position.governed_max_exposure_units,
                position.reserved_units,
                position.settled_units,
                position.pending_units,
                position.failed_units,
                position.provisional_loss_units,
                position.quoted_premium_units,
                position.active_quoted_premium_units
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_credit_scorecard_export(
    agent_subject: &str,
    capability_id: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    decision_limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::ExposureLedgerQuery {
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: Some(agent_subject.to_string()),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        since,
        until,
        receipt_limit: Some(receipt_limit),
        decision_limit: Some(decision_limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.credit_scorecard(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit scorecard export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_signed_credit_scorecard_report(
            receipt_db_path,
            budget_db_path,
            authority_seed_path,
            authority_db_path,
            &query,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.body.schema);
        println!("generated_at:           {}", report.body.generated_at);
        println!("signer_key:             {}", report.signer_key.to_hex());
        println!("subject_key:            {}", agent_subject);
        println!(
            "overall_score:          {:.4}",
            report.body.summary.overall_score
        );
        println!(
            "confidence:             {:?}",
            report.body.summary.confidence
        );
        println!("band:                   {:?}", report.body.summary.band);
        println!(
            "probationary:           {}",
            report.body.summary.probationary
        );
        println!(
            "matching_receipts:      {}",
            report.body.summary.matching_receipts
        );
        println!(
            "matching_decisions:     {}",
            report.body.summary.matching_decisions
        );
        println!(
            "anomaly_count:          {}",
            report.body.summary.anomaly_count
        );
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_capital_book_export(
    agent_subject: &str,
    capability_id: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    facility_limit: usize,
    bond_limit: usize,
    loss_event_limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::CapitalBookQuery {
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: Some(agent_subject.to_string()),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        since,
        until,
        receipt_limit: Some(receipt_limit),
        facility_limit: Some(facility_limit),
        bond_limit: Some(bond_limit),
        loss_event_limit: Some(loss_event_limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.capital_book(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "capital book export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_signed_capital_book_report(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &query,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.body.schema);
        println!("generated_at:           {}", report.body.generated_at);
        println!("subject_key:            {}", report.body.subject_key);
        println!("signer_key:             {}", report.signer_key.to_hex());
        println!(
            "funding_sources:        {}",
            report.body.summary.funding_sources
        );
        println!(
            "ledger_events:          {}",
            report.body.summary.ledger_events
        );
        println!(
            "currencies:             {}",
            if report.body.summary.currencies.is_empty() {
                "none".to_string()
            } else {
                report.body.summary.currencies.join(", ")
            }
        );
        for source in &report.body.sources {
            println!(
                "- {} kind={:?} owner={:?} committed={} held={} drawn={} disbursed={} released={} repaid={} impaired={}",
                source.source_id,
                source.kind,
                source.owner_role,
                source.committed_amount.as_ref().map_or(0, |amount| amount.units),
                source.held_amount.as_ref().map_or(0, |amount| amount.units),
                source.drawn_amount.as_ref().map_or(0, |amount| amount.units),
                source.disbursed_amount.as_ref().map_or(0, |amount| amount.units),
                source.released_amount.as_ref().map_or(0, |amount| amount.units),
                source.repaid_amount.as_ref().map_or(0, |amount| amount.units),
                source.impaired_amount.as_ref().map_or(0, |amount| amount.units),
            );
        }
    }

    Ok(())
}

fn cmd_trust_capital_instruction_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request: trust_control::CapitalExecutionInstructionRequest = load_json_or_yaml(input_file)?;

    let instruction = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_capital_execution_instruction(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "capital instruction issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_capital_execution_instruction(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&instruction)?);
    } else {
        println!("schema:                 {}", instruction.body.schema);
        println!(
            "instruction_id:         {}",
            instruction.body.instruction_id
        );
        println!("issued_at:              {}", instruction.body.issued_at);
        println!("subject_key:            {}", instruction.body.subject_key);
        println!("source_id:              {}", instruction.body.source_id);
        println!("action:                 {:?}", instruction.body.action);
        println!(
            "reconciled_state:       {:?}",
            instruction.body.reconciled_state
        );
        println!(
            "signer_key:             {}",
            instruction.signer_key.to_hex()
        );
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_capital_allocation_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request: trust_control::CapitalAllocationDecisionRequest = load_json_or_yaml(input_file)?;

    let allocation = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_capital_allocation_decision(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "capital allocation issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_capital_allocation_decision(
            receipt_db_path,
            budget_db_path,
            authority_seed_path,
            authority_db_path,
            certification_registry_file,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&allocation)?);
    } else {
        println!("schema:                 {}", allocation.body.schema);
        println!("allocation_id:          {}", allocation.body.allocation_id);
        println!("issued_at:              {}", allocation.body.issued_at);
        println!("subject_key:            {}", allocation.body.subject_key);
        println!(
            "governed_receipt_id:    {}",
            allocation.body.governed_receipt_id
        );
        println!("outcome:                {:?}", allocation.body.outcome);
        println!(
            "facility_id:            {}",
            allocation.body.facility_id.as_deref().unwrap_or("<none>")
        );
        println!(
            "source_id:              {}",
            allocation.body.source_id.as_deref().unwrap_or("<none>")
        );
        println!("signer_key:             {}", allocation.signer_key.to_hex());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_credit_facility_evaluate(
    agent_subject: &str,
    capability_id: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    decision_limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::ExposureLedgerQuery {
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: Some(agent_subject.to_string()),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        since,
        until,
        receipt_limit: Some(receipt_limit),
        decision_limit: Some(decision_limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.credit_facility_report(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit facility evaluation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_credit_facility_report(
            receipt_db_path,
            budget_db_path,
            certification_registry_file,
            None,
            &query,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("generated_at:           {}", report.generated_at);
        println!("subject_key:            {}", agent_subject);
        println!("disposition:            {:?}", report.disposition);
        println!("score_band:             {:?}", report.scorecard.band);
        println!(
            "overall_score:          {:.4}",
            report.scorecard.overall_score
        );
        println!(
            "runtime_prerequisite:   {:?}",
            report.prerequisites.minimum_runtime_assurance_tier
        );
        println!(
            "runtime_assurance_met:  {}",
            report.prerequisites.runtime_assurance_met
        );
        println!(
            "certification_met:      {}",
            report.prerequisites.certification_met
        );
        println!("findings:               {}", report.findings.len());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_credit_facility_issue(
    agent_subject: &str,
    capability_id: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    decision_limit: usize,
    supersedes_facility_id: Option<&str>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = trust_control::CreditFacilityIssueRequest {
        query: arc_kernel::ExposureLedgerQuery {
            capability_id: capability_id.map(ToOwned::to_owned),
            agent_subject: Some(agent_subject.to_string()),
            tool_server: tool_server.map(ToOwned::to_owned),
            tool_name: tool_name.map(ToOwned::to_owned),
            since,
            until,
            receipt_limit: Some(receipt_limit),
            decision_limit: Some(decision_limit),
        },
        supersedes_facility_id: supersedes_facility_id.map(ToOwned::to_owned),
    };

    let facility = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_credit_facility(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit facility issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_credit_facility(
            receipt_db_path,
            budget_db_path,
            authority_seed_path,
            authority_db_path,
            certification_registry_file,
            None,
            &request.query,
            request.supersedes_facility_id.as_deref(),
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&facility)?);
    } else {
        println!("schema:                 {}", facility.body.schema);
        println!("facility_id:            {}", facility.body.facility_id);
        println!("issued_at:              {}", facility.body.issued_at);
        println!("expires_at:             {}", facility.body.expires_at);
        println!("signer_key:             {}", facility.signer_key.to_hex());
        println!(
            "disposition:            {:?}",
            facility.body.report.disposition
        );
        println!(
            "lifecycle_state:        {:?}",
            facility.body.lifecycle_state
        );
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_credit_facility_list(
    facility_id: Option<&str>,
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    disposition: Option<&str>,
    lifecycle_state: Option<&str>,
    limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::CreditFacilityListQuery {
        facility_id: facility_id.map(ToOwned::to_owned),
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: agent_subject.map(ToOwned::to_owned),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        disposition: disposition
            .map(parse_credit_facility_disposition)
            .transpose()?,
        lifecycle_state: lifecycle_state
            .map(parse_credit_facility_lifecycle_state)
            .transpose()?,
        limit: Some(limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.list_credit_facilities(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit facility list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_credit_facilities(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "matching_facilities:    {}",
            report.summary.matching_facilities
        );
        println!(
            "returned_facilities:    {}",
            report.summary.returned_facilities
        );
        println!(
            "active_facilities:      {}",
            report.summary.active_facilities
        );
        println!(
            "manual_review_rows:     {}",
            report.summary.manual_review_facilities
        );
        for row in report.facilities {
            println!(
                "- {} disposition={:?} lifecycle={:?}",
                row.facility.body.facility_id,
                row.facility.body.report.disposition,
                row.lifecycle_state
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_credit_bond_evaluate(
    agent_subject: &str,
    capability_id: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    decision_limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::ExposureLedgerQuery {
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: Some(agent_subject.to_string()),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        since,
        until,
        receipt_limit: Some(receipt_limit),
        decision_limit: Some(decision_limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.credit_bond_report(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit bond evaluation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_credit_bond_report(
            receipt_db_path,
            budget_db_path,
            certification_registry_file,
            None,
            &query,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("generated_at:           {}", report.generated_at);
        println!("subject_key:            {}", agent_subject);
        println!("disposition:            {:?}", report.disposition);
        println!("score_band:             {:?}", report.scorecard.band);
        println!(
            "latest_facility_id:     {}",
            report.latest_facility_id.as_deref().unwrap_or("<none>")
        );
        println!(
            "active_facility_met:    {}",
            report.prerequisites.active_facility_met
        );
        println!(
            "runtime_assurance_met:  {}",
            report.prerequisites.runtime_assurance_met
        );
        println!(
            "certification_met:      {}",
            report.prerequisites.certification_met
        );
        println!("findings:               {}", report.findings.len());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_credit_bond_issue(
    agent_subject: &str,
    capability_id: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    decision_limit: usize,
    supersedes_bond_id: Option<&str>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = trust_control::CreditBondIssueRequest {
        query: arc_kernel::ExposureLedgerQuery {
            capability_id: capability_id.map(ToOwned::to_owned),
            agent_subject: Some(agent_subject.to_string()),
            tool_server: tool_server.map(ToOwned::to_owned),
            tool_name: tool_name.map(ToOwned::to_owned),
            since,
            until,
            receipt_limit: Some(receipt_limit),
            decision_limit: Some(decision_limit),
        },
        supersedes_bond_id: supersedes_bond_id.map(ToOwned::to_owned),
    };

    let bond = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_credit_bond(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit bond issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_credit_bond(
            receipt_db_path,
            budget_db_path,
            authority_seed_path,
            authority_db_path,
            certification_registry_file,
            None,
            &request.query,
            request.supersedes_bond_id.as_deref(),
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&bond)?);
    } else {
        println!("schema:                 {}", bond.body.schema);
        println!("bond_id:                {}", bond.body.bond_id);
        println!("issued_at:              {}", bond.body.issued_at);
        println!("expires_at:             {}", bond.body.expires_at);
        println!("signer_key:             {}", bond.signer_key.to_hex());
        println!("disposition:            {:?}", bond.body.report.disposition);
        println!("lifecycle_state:        {:?}", bond.body.lifecycle_state);
    }

    Ok(())
}

fn cmd_trust_credit_bond_simulate(
    bond_id: &str,
    autonomy_tier: &str,
    runtime_assurance_tier: &str,
    call_chain_present: bool,
    policy_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = arc_kernel::CreditBondedExecutionSimulationRequest {
        query: arc_kernel::CreditBondedExecutionSimulationQuery {
            bond_id: bond_id.to_string(),
            autonomy_tier: parse_governed_autonomy_tier(autonomy_tier)?,
            runtime_assurance_tier: parse_runtime_assurance_tier(runtime_assurance_tier)?,
            call_chain_present,
        },
        policy: load_credit_bonded_execution_control_policy(policy_file)?,
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.simulate_credit_bonded_execution(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit bond simulation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_credit_bonded_execution_simulation_report(receipt_db_path, &request)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("generated_at:           {}", report.generated_at);
        println!("bond_id:                {}", report.bond.body.bond_id);
        println!(
            "baseline_decision:      {:?}",
            report.default_evaluation.decision
        );
        println!(
            "simulated_decision:     {:?}",
            report.simulated_evaluation.decision
        );
        println!("decision_changed:       {}", report.delta.decision_changed);
        println!(
            "sandbox_ready:          {}",
            report.simulated_evaluation.sandbox_integration_ready
        );
        println!(
            "findings:               {}",
            report.simulated_evaluation.findings.len()
        );
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_credit_bond_list(
    bond_id: Option<&str>,
    facility_id: Option<&str>,
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    disposition: Option<&str>,
    lifecycle_state: Option<&str>,
    limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::CreditBondListQuery {
        bond_id: bond_id.map(ToOwned::to_owned),
        facility_id: facility_id.map(ToOwned::to_owned),
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: agent_subject.map(ToOwned::to_owned),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        disposition: disposition.map(parse_credit_bond_disposition).transpose()?,
        lifecycle_state: lifecycle_state
            .map(parse_credit_bond_lifecycle_state)
            .transpose()?,
        limit: Some(limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.list_credit_bonds(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit bond list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_credit_bonds(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("matching_bonds:         {}", report.summary.matching_bonds);
        println!("returned_bonds:         {}", report.summary.returned_bonds);
        println!("active_bonds:           {}", report.summary.active_bonds);
        println!("locked_bonds:           {}", report.summary.locked_bonds);
        println!("held_bonds:             {}", report.summary.held_bonds);
        for row in report.bonds {
            println!(
                "- {} disposition={:?} lifecycle={:?}",
                row.bond.body.bond_id, row.bond.body.report.disposition, row.lifecycle_state
            );
        }
    }

    Ok(())
}

fn build_credit_loss_lifecycle_query(
    bond_id: &str,
    event_kind: &str,
    amount_units: Option<u64>,
    amount_currency: Option<&str>,
) -> Result<arc_kernel::CreditLossLifecycleQuery, CliError> {
    let amount =
        match (amount_units, amount_currency) {
            (Some(units), Some(currency)) => Some(MonetaryAmount {
                units,
                currency: currency.to_string(),
            }),
            (None, None) => None,
            _ => return Err(CliError::Other(
                "credit loss lifecycle amount requires both --amount-units and --amount-currency"
                    .to_string(),
            )),
        };

    Ok(arc_kernel::CreditLossLifecycleQuery {
        bond_id: bond_id.to_string(),
        event_kind: parse_credit_loss_lifecycle_event_kind(event_kind)?,
        amount,
    })
}

fn cmd_trust_credit_loss_lifecycle_evaluate(
    bond_id: &str,
    event_kind: &str,
    amount_units: Option<u64>,
    amount_currency: Option<&str>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query =
        build_credit_loss_lifecycle_query(bond_id, event_kind, amount_units, amount_currency)?;

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.credit_loss_lifecycle_report(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit loss lifecycle evaluation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_credit_loss_lifecycle_report(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                       {}", report.schema);
        println!("generated_at:                 {}", report.generated_at);
        println!("bond_id:                      {}", report.summary.bond_id);
        println!(
            "event_kind:                   {:?}",
            report.query.event_kind
        );
        println!(
            "current_bond_lifecycle:       {:?}",
            report.summary.current_bond_lifecycle_state
        );
        println!(
            "projected_bond_lifecycle:     {:?}",
            report.summary.projected_bond_lifecycle_state
        );
        println!(
            "outstanding_delinquent_units: {}",
            report
                .summary
                .outstanding_delinquent_amount
                .as_ref()
                .map(|amount| amount.units)
                .unwrap_or(0)
        );
    }

    Ok(())
}

fn cmd_trust_credit_loss_lifecycle_issue(
    bond_id: &str,
    event_kind: &str,
    amount_units: Option<u64>,
    amount_currency: Option<&str>,
    authority_chain_file: Option<&Path>,
    execution_window_file: Option<&Path>,
    rail_file: Option<&Path>,
    observed_execution_file: Option<&Path>,
    appeal_window_ends_at: Option<u64>,
    description: Option<&str>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = trust_control::CreditLossLifecycleIssueRequest {
        query: build_credit_loss_lifecycle_query(
            bond_id,
            event_kind,
            amount_units,
            amount_currency,
        )?,
        authority_chain: authority_chain_file
            .map(load_json_or_yaml::<Vec<arc_kernel::CapitalExecutionAuthorityStep>>)
            .transpose()?
            .unwrap_or_default(),
        execution_window: execution_window_file
            .map(load_json_or_yaml::<arc_kernel::CapitalExecutionWindow>)
            .transpose()?,
        rail: rail_file
            .map(load_json_or_yaml::<arc_kernel::CapitalExecutionRail>)
            .transpose()?,
        observed_execution: observed_execution_file
            .map(load_json_or_yaml::<arc_kernel::CapitalExecutionObservation>)
            .transpose()?,
        appeal_window_ends_at,
        description: description.map(ToOwned::to_owned),
    };

    let event = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_credit_loss_lifecycle(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit loss lifecycle issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_credit_loss_lifecycle(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&event)?);
    } else {
        println!("schema:                       {}", event.body.schema);
        println!("event_id:                     {}", event.body.event_id);
        println!("bond_id:                      {}", event.body.bond_id);
        println!("issued_at:                    {}", event.body.issued_at);
        println!("event_kind:                   {:?}", event.body.event_kind);
        println!(
            "projected_bond_lifecycle:     {:?}",
            event.body.projected_bond_lifecycle_state
        );
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_credit_loss_lifecycle_list(
    event_id: Option<&str>,
    bond_id: Option<&str>,
    facility_id: Option<&str>,
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    event_kind: Option<&str>,
    limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::CreditLossLifecycleListQuery {
        event_id: event_id.map(ToOwned::to_owned),
        bond_id: bond_id.map(ToOwned::to_owned),
        facility_id: facility_id.map(ToOwned::to_owned),
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: agent_subject.map(ToOwned::to_owned),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        event_kind: event_kind
            .map(parse_credit_loss_lifecycle_event_kind)
            .transpose()?,
        limit: Some(limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.list_credit_loss_lifecycle(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit loss lifecycle list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_credit_loss_lifecycle(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "matching_events:              {}",
            report.summary.matching_events
        );
        println!(
            "returned_events:              {}",
            report.summary.returned_events
        );
        println!(
            "delinquency_events:           {}",
            report.summary.delinquency_events
        );
        println!(
            "recovery_events:              {}",
            report.summary.recovery_events
        );
        println!(
            "reserve_release_events:       {}",
            report.summary.reserve_release_events
        );
        println!(
            "reserve_slash_events:         {}",
            report.summary.reserve_slash_events
        );
        println!(
            "write_off_events:             {}",
            report.summary.write_off_events
        );
        for row in report.events {
            println!(
                "- {} kind={:?} bond={} projected={:?}",
                row.event.body.event_id,
                row.event.body.event_kind,
                row.event.body.bond_id,
                row.event.body.projected_bond_lifecycle_state
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_credit_backtest_export(
    agent_subject: &str,
    capability_id: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    decision_limit: usize,
    window_seconds: u64,
    window_count: usize,
    stale_after_seconds: u64,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::CreditBacktestQuery {
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: Some(agent_subject.to_string()),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        since,
        until,
        receipt_limit: Some(receipt_limit),
        decision_limit: Some(decision_limit),
        window_seconds: Some(window_seconds),
        window_count: Some(window_count),
        stale_after_seconds: Some(stale_after_seconds),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.credit_backtest(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "credit backtest export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_credit_backtest_report(
            receipt_db_path,
            budget_db_path,
            certification_registry_file,
            None,
            &query,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("generated_at:           {}", report.generated_at);
        println!("subject_key:            {}", agent_subject);
        println!(
            "windows_evaluated:      {}",
            report.summary.windows_evaluated
        );
        println!("drift_windows:          {}", report.summary.drift_windows);
        println!(
            "manual_review_windows:  {}",
            report.summary.manual_review_windows
        );
        println!("denied_windows:         {}", report.summary.denied_windows);
        println!(
            "over_utilized_windows:  {}",
            report.summary.over_utilized_windows
        );
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_provider_risk_package_export(
    agent_subject: &str,
    capability_id: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    decision_limit: usize,
    recent_loss_limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::CreditProviderRiskPackageQuery {
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: Some(agent_subject.to_string()),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        since,
        until,
        receipt_limit: Some(receipt_limit),
        decision_limit: Some(decision_limit),
        recent_loss_limit: Some(recent_loss_limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.credit_provider_risk_package(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "provider risk package export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_signed_credit_provider_risk_package(
            receipt_db_path,
            budget_db_path,
            authority_seed_path,
            authority_db_path,
            certification_registry_file,
            None,
            &query,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.body.schema);
        println!("generated_at:           {}", report.body.generated_at);
        println!("subject_key:            {}", report.body.subject_key);
        println!("signer_key:             {}", report.signer_key.to_hex());
        println!(
            "facility_disposition:   {:?}",
            report.body.facility_report.disposition
        );
        println!(
            "score_band:             {:?}",
            report.body.scorecard.body.summary.band
        );
        println!(
            "recent_loss_events:     {}",
            report.body.recent_loss_history.summary.matching_loss_events
        );
    }

    Ok(())
}

fn cmd_trust_liability_provider_issue(
    input_file: &Path,
    supersedes_provider_record_id: Option<&str>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let report = load_liability_provider_report(input_file)?;
    let provider = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let request = trust_control::LiabilityProviderIssueRequest {
            report,
            supersedes_provider_record_id: supersedes_provider_record_id.map(ToOwned::to_owned),
        };
        trust_control::build_client(url, token)?.issue_liability_provider(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability provider issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_provider(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &report,
            supersedes_provider_record_id,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&provider)?);
    } else {
        println!("provider_record_id: {}", provider.body.provider_record_id);
        println!("provider_id:        {}", provider.body.report.provider_id);
        println!("display_name:       {}", provider.body.report.display_name);
        println!("lifecycle_state:    {:?}", provider.body.lifecycle_state);
    }

    Ok(())
}

fn cmd_trust_liability_provider_list(
    provider_id: Option<&str>,
    jurisdiction: Option<&str>,
    coverage_class: Option<&str>,
    currency: Option<&str>,
    lifecycle_state: Option<&str>,
    limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::LiabilityProviderListQuery {
        provider_id: provider_id.map(ToOwned::to_owned),
        jurisdiction: jurisdiction.map(ToOwned::to_owned),
        coverage_class: coverage_class
            .map(parse_liability_coverage_class)
            .transpose()?,
        currency: currency.map(ToOwned::to_owned),
        lifecycle_state: lifecycle_state
            .map(parse_liability_provider_lifecycle_state)
            .transpose()?,
        limit: Some(limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.list_liability_providers(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability provider list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_liability_providers(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("providers: {}", report.summary.returned_providers);
        for row in report.providers {
            println!(
                "- {} [{}] lifecycle={:?}",
                row.provider.body.report.provider_id,
                row.provider.body.report.display_name,
                row.lifecycle_state
            );
        }
    }

    Ok(())
}

fn cmd_trust_liability_provider_resolve(
    provider_id: &str,
    jurisdiction: &str,
    coverage_class: &str,
    currency: &str,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::LiabilityProviderResolutionQuery {
        provider_id: provider_id.to_string(),
        jurisdiction: jurisdiction.to_string(),
        coverage_class: parse_liability_coverage_class(coverage_class)?,
        currency: currency.to_string(),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.resolve_liability_provider(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability provider resolution requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::resolve_liability_provider(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "provider_id:        {}",
            report.provider.body.report.provider_id
        );
        println!(
            "display_name:       {}",
            report.provider.body.report.display_name
        );
        println!("jurisdiction:       {}", report.matched_policy.jurisdiction);
        println!(
            "coverage_classes:   {}",
            serde_json::to_string(&report.matched_policy.coverage_classes)?
        );
        println!(
            "currencies:         {}",
            serde_json::to_string(&report.matched_policy.supported_currencies)?
        );
    }

    Ok(())
}

fn cmd_trust_liability_quote_request_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_quote_request_issue_request(input_file)?;
    let quote_request = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_quote_request(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability quote request issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_quote_request(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&quote_request)?);
    } else {
        println!(
            "quote_request_id:      {}",
            quote_request.body.quote_request_id
        );
        println!(
            "provider_id:           {}",
            quote_request.body.provider_policy.provider_id
        );
        println!(
            "jurisdiction:          {}",
            quote_request.body.provider_policy.jurisdiction
        );
        println!(
            "coverage_class:        {:?}",
            quote_request.body.provider_policy.coverage_class
        );
    }

    Ok(())
}

fn cmd_trust_liability_quote_response_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_quote_response_issue_request(input_file)?;
    let quote_response = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_quote_response(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability quote response issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_quote_response(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&quote_response)?);
    } else {
        println!(
            "quote_response_id:     {}",
            quote_response.body.quote_response_id
        );
        println!(
            "quote_request_id:      {}",
            quote_response.body.quote_request.body.quote_request_id
        );
        println!(
            "disposition:           {:?}",
            quote_response.body.disposition
        );
    }

    Ok(())
}

fn cmd_trust_liability_pricing_authority_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_pricing_authority_issue_request(input_file)?;
    let authority = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_pricing_authority(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability pricing authority issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_pricing_authority(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&authority)?);
    } else {
        println!("authority_id:          {}", authority.body.authority_id);
        println!(
            "quote_request_id:      {}",
            authority.body.quote_request.body.quote_request_id
        );
        println!("expires_at:            {}", authority.body.expires_at);
        println!(
            "auto_bind_enabled:     {}",
            authority.body.auto_bind_enabled
        );
    }

    Ok(())
}

fn cmd_trust_liability_placement_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_placement_issue_request(input_file)?;
    let placement = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_placement(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability placement issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_placement(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&placement)?);
    } else {
        println!("placement_id:          {}", placement.body.placement_id);
        println!(
            "quote_response_id:     {}",
            placement.body.quote_response.body.quote_response_id
        );
        println!("effective_from:        {}", placement.body.effective_from);
        println!("effective_until:       {}", placement.body.effective_until);
    }

    Ok(())
}

fn cmd_trust_liability_bound_coverage_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_bound_coverage_issue_request(input_file)?;
    let bound = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_bound_coverage(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability bound coverage issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_bound_coverage(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&bound)?);
    } else {
        println!("bound_coverage_id:     {}", bound.body.bound_coverage_id);
        println!(
            "placement_id:          {}",
            bound.body.placement.body.placement_id
        );
        println!("policy_number:         {}", bound.body.policy_number);
    }

    Ok(())
}

fn cmd_trust_liability_auto_bind_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_auto_bind_issue_request(input_file)?;
    let decision = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_auto_bind(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability auto-bind issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_auto_bind(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&decision)?);
    } else {
        println!("decision_id:           {}", decision.body.decision_id);
        println!("disposition:           {:?}", decision.body.disposition);
        println!(
            "authority_id:          {}",
            decision.body.authority.body.authority_id
        );
        println!(
            "placement_id:          {}",
            decision
                .body
                .placement
                .as_ref()
                .map(|placement| placement.body.placement_id.as_str())
                .unwrap_or("-"),
        );
        println!(
            "bound_coverage_id:     {}",
            decision
                .body
                .bound_coverage
                .as_ref()
                .map(|bound| bound.body.bound_coverage_id.as_str())
                .unwrap_or("-"),
        );
    }

    Ok(())
}

fn cmd_trust_liability_claim_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_issue_request(input_file)?;
    let claim = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_claim_package(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability claim issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_package(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&claim)?);
    } else {
        println!("claim_id:              {}", claim.body.claim_id);
        println!(
            "bound_coverage_id:     {}",
            claim.body.bound_coverage.body.bound_coverage_id
        );
        println!("claimant:              {}", claim.body.claimant);
    }

    Ok(())
}

fn cmd_trust_liability_claim_response_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_response_issue_request(input_file)?;
    let response = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_claim_response(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability claim response issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_response(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("claim_response_id:     {}", response.body.claim_response_id);
        println!(
            "claim_id:              {}",
            response.body.claim.body.claim_id
        );
        println!("disposition:           {:?}", response.body.disposition);
    }

    Ok(())
}

fn cmd_trust_liability_claim_dispute_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_dispute_issue_request(input_file)?;
    let dispute = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_claim_dispute(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability claim dispute issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_dispute(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&dispute)?);
    } else {
        println!("dispute_id:            {}", dispute.body.dispute_id);
        println!(
            "claim_response_id:     {}",
            dispute.body.provider_response.body.claim_response_id
        );
        println!("opened_by:             {}", dispute.body.opened_by);
    }

    Ok(())
}

fn cmd_trust_liability_claim_adjudication_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_adjudication_issue_request(input_file)?;
    let adjudication = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_claim_adjudication(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability claim adjudication issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_adjudication(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&adjudication)?);
    } else {
        println!(
            "adjudication_id:       {}",
            adjudication.body.adjudication_id
        );
        println!(
            "dispute_id:            {}",
            adjudication.body.dispute.body.dispute_id
        );
        println!("outcome:               {:?}", adjudication.body.outcome);
    }

    Ok(())
}

fn cmd_trust_liability_claim_payout_instruction_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_payout_instruction_issue_request(input_file)?;
    let payout_instruction = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?
            .issue_liability_claim_payout_instruction(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability claim payout instruction issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_payout_instruction(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&payout_instruction)?);
    } else {
        println!(
            "payout_instruction_id: {}",
            payout_instruction.body.payout_instruction_id
        );
        println!(
            "adjudication_id:       {}",
            payout_instruction.body.adjudication.body.adjudication_id
        );
        println!(
            "capital_instruction_id:{}",
            payout_instruction
                .body
                .capital_instruction
                .body
                .instruction_id
        );
    }

    Ok(())
}

fn cmd_trust_liability_claim_payout_receipt_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_payout_receipt_issue_request(input_file)?;
    let payout_receipt = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_liability_claim_payout_receipt(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability claim payout receipt issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_payout_receipt(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&payout_receipt)?);
    } else {
        println!(
            "payout_receipt_id:     {}",
            payout_receipt.body.payout_receipt_id
        );
        println!(
            "payout_instruction_id: {}",
            payout_receipt
                .body
                .payout_instruction
                .body
                .payout_instruction_id
        );
        println!(
            "reconciliation_state:  {:?}",
            payout_receipt.body.reconciliation_state
        );
    }

    Ok(())
}

fn cmd_trust_liability_claim_settlement_instruction_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_settlement_instruction_issue_request(input_file)?;
    let settlement_instruction = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?
            .issue_liability_claim_settlement_instruction(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability claim settlement instruction issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_settlement_instruction(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&settlement_instruction)?);
    } else {
        println!(
            "settlement_instruction_id: {}",
            settlement_instruction.body.settlement_instruction_id
        );
        println!(
            "payout_receipt_id:        {}",
            settlement_instruction
                .body
                .payout_receipt
                .body
                .payout_receipt_id
        );
        println!(
            "settlement_kind:          {:?}",
            settlement_instruction.body.settlement_kind
        );
    }

    Ok(())
}

fn cmd_trust_liability_claim_settlement_receipt_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_settlement_receipt_issue_request(input_file)?;
    let settlement_receipt = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?
            .issue_liability_claim_settlement_receipt(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability claim settlement receipt issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_settlement_receipt(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&settlement_receipt)?);
    } else {
        println!(
            "settlement_receipt_id:    {}",
            settlement_receipt.body.settlement_receipt_id
        );
        println!(
            "settlement_instruction_id:{}",
            settlement_receipt
                .body
                .settlement_instruction
                .body
                .settlement_instruction_id
        );
        println!(
            "reconciliation_state:     {:?}",
            settlement_receipt.body.reconciliation_state
        );
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_liability_market_list(
    quote_request_id: Option<&str>,
    provider_id: Option<&str>,
    agent_subject: Option<&str>,
    jurisdiction: Option<&str>,
    coverage_class: Option<&str>,
    currency: Option<&str>,
    limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::LiabilityMarketWorkflowQuery {
        quote_request_id: quote_request_id.map(ToOwned::to_owned),
        provider_id: provider_id.map(ToOwned::to_owned),
        agent_subject: agent_subject.map(ToOwned::to_owned),
        jurisdiction: jurisdiction.map(ToOwned::to_owned),
        coverage_class: coverage_class
            .map(parse_liability_coverage_class)
            .transpose()?,
        currency: currency.map(ToOwned::to_owned),
        limit: Some(limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.liability_market_workflows(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability market list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_liability_market_workflows(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "matching_requests:     {}",
            report.summary.matching_requests
        );
        println!(
            "returned_requests:     {}",
            report.summary.returned_requests
        );
        println!("quote_responses:       {}", report.summary.quote_responses);
        println!(
            "pricing_authorities:   {}",
            report.summary.pricing_authorities
        );
        println!(
            "auto_bind_decisions:   {}",
            report.summary.auto_bind_decisions
        );
        println!(
            "auto_bound_decisions:  {}",
            report.summary.auto_bound_decisions
        );
        println!("placements:            {}", report.summary.placements);
        println!("bound_coverages:       {}", report.summary.bound_coverages);
        for workflow in report.workflows {
            println!(
                "- {} provider={} response={} authority={} auto_bind={} placement={} bound={}",
                workflow.quote_request.body.quote_request_id,
                workflow.quote_request.body.provider_policy.provider_id,
                workflow
                    .latest_quote_response
                    .as_ref()
                    .map(|response| response.body.quote_response_id.as_str())
                    .unwrap_or("-"),
                workflow
                    .pricing_authority
                    .as_ref()
                    .map(|authority| authority.body.authority_id.as_str())
                    .unwrap_or("-"),
                workflow
                    .latest_auto_bind_decision
                    .as_ref()
                    .map(|decision| decision.body.decision_id.as_str())
                    .unwrap_or("-"),
                workflow
                    .placement
                    .as_ref()
                    .map(|placement| placement.body.placement_id.as_str())
                    .unwrap_or("-"),
                workflow
                    .bound_coverage
                    .as_ref()
                    .map(|bound| bound.body.bound_coverage_id.as_str())
                    .unwrap_or("-"),
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_liability_claims_list(
    claim_id: Option<&str>,
    provider_id: Option<&str>,
    agent_subject: Option<&str>,
    jurisdiction: Option<&str>,
    policy_number: Option<&str>,
    limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::LiabilityClaimWorkflowQuery {
        claim_id: claim_id.map(ToOwned::to_owned),
        provider_id: provider_id.map(ToOwned::to_owned),
        agent_subject: agent_subject.map(ToOwned::to_owned),
        jurisdiction: jurisdiction.map(ToOwned::to_owned),
        policy_number: policy_number.map(ToOwned::to_owned),
        limit: Some(limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.liability_claim_workflows(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "liability claims list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_liability_claim_workflows(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("matching_claims:       {}", report.summary.matching_claims);
        println!("returned_claims:       {}", report.summary.returned_claims);
        println!(
            "provider_responses:    {}",
            report.summary.provider_responses
        );
        println!(
            "accepted_responses:    {}",
            report.summary.accepted_responses
        );
        println!("denied_responses:      {}", report.summary.denied_responses);
        println!("disputes:              {}", report.summary.disputes);
        println!("adjudications:         {}", report.summary.adjudications);
        println!(
            "payout_instructions:   {}",
            report.summary.payout_instructions
        );
        println!("payout_receipts:       {}", report.summary.payout_receipts);
        println!(
            "matched_payouts:       {}",
            report.summary.matched_payout_receipts
        );
        println!(
            "mismatched_payouts:    {}",
            report.summary.mismatched_payout_receipts
        );
        println!(
            "settlement_instructions:{}",
            report.summary.settlement_instructions
        );
        println!(
            "settlement_receipts:   {}",
            report.summary.settlement_receipts
        );
        println!(
            "matched_settlements:   {}",
            report.summary.matched_settlement_receipts
        );
        println!(
            "mismatched_settlements:{}",
            report.summary.mismatched_settlement_receipts
        );
        println!(
            "counterparty_mismatch_settlements:{}",
            report.summary.counterparty_mismatch_settlement_receipts
        );
        for claim in report.claims {
            println!(
                "- {} policy={} response={} dispute={} adjudication={} payout_instruction={} payout_receipt={} settlement_instruction={} settlement_receipt={}",
                claim.claim.body.claim_id,
                claim.claim.body.bound_coverage.body.policy_number,
                claim.provider_response
                    .as_ref()
                    .map(|response| response.body.claim_response_id.as_str())
                    .unwrap_or("-"),
                claim.dispute
                    .as_ref()
                    .map(|dispute| dispute.body.dispute_id.as_str())
                    .unwrap_or("-"),
                claim.adjudication
                    .as_ref()
                    .map(|adjudication| adjudication.body.adjudication_id.as_str())
                    .unwrap_or("-"),
                claim.payout_instruction
                    .as_ref()
                    .map(|instruction| instruction.body.payout_instruction_id.as_str())
                    .unwrap_or("-"),
                claim.payout_receipt
                    .as_ref()
                    .map(|receipt| receipt.body.payout_receipt_id.as_str())
                    .unwrap_or("-"),
                claim.settlement_instruction
                    .as_ref()
                    .map(|instruction| instruction.body.settlement_instruction_id.as_str())
                    .unwrap_or("-"),
                claim.settlement_receipt
                    .as_ref()
                    .map(|receipt| receipt.body.settlement_receipt_id.as_str())
                    .unwrap_or("-"),
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_underwriting_input_export(
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::UnderwritingPolicyInputQuery {
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: agent_subject.map(ToOwned::to_owned),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        since,
        until,
        receipt_limit: Some(receipt_limit),
    };

    let input = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.underwriting_policy_input(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "underwriting input export requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_signed_underwriting_policy_input(
            receipt_db_path,
            budget_db_path,
            authority_seed_path,
            authority_db_path,
            certification_registry_file,
            &query,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&input)?);
    } else {
        println!("schema:                 {}", input.body.schema);
        println!("generated_at:           {}", input.body.generated_at);
        println!("signer_key:             {}", input.signer_key.to_hex());
        println!(
            "matching_receipts:      {}",
            input.body.receipts.matching_receipts
        );
        println!(
            "returned_receipts:      {}",
            input.body.receipts.returned_receipts
        );
        println!(
            "governed_receipts:      {}",
            input.body.receipts.governed_receipts
        );
        println!(
            "runtime_assurance:      {}",
            input.body.receipts.runtime_assurance_receipts
        );
        println!("signals:                {}", input.body.signals.len());
        if let Some(reputation) = input.body.reputation.as_ref() {
            println!("subject_key:            {}", reputation.subject_key);
            println!("effective_score:        {:.4}", reputation.effective_score);
            println!("probationary:           {}", reputation.probationary);
        }
        if let Some(certification) = input.body.certification.as_ref() {
            println!("certification_state:    {:?}", certification.state);
        }
        for signal in &input.body.signals {
            println!(
                "- {:?} {:?}: {}",
                signal.class, signal.reason, signal.description
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_underwriting_decision_evaluate(
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::UnderwritingPolicyInputQuery {
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: agent_subject.map(ToOwned::to_owned),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        since,
        until,
        receipt_limit: Some(receipt_limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.underwriting_decision(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "underwriting decision evaluation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_underwriting_decision_report(
            receipt_db_path,
            budget_db_path,
            certification_registry_file,
            &query,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("generated_at:           {}", report.generated_at);
        println!("outcome:                {:?}", report.outcome);
        println!("risk_class:             {:?}", report.risk_class);
        println!("policy_version:         {}", report.policy.version);
        if let Some(factor) = report.suggested_ceiling_factor {
            println!("ceiling_factor:         {:.2}", factor);
        }
        println!(
            "matching_receipts:      {}",
            report.input.receipts.matching_receipts
        );
        println!("findings:               {}", report.findings.len());
        for finding in &report.findings {
            println!(
                "- {:?} {:?}: {}",
                finding.outcome, finding.reason, finding.description
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_underwriting_decision_simulate(
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    policy_file: &Path,
    certification_registry_file: Option<&Path>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = arc_kernel::UnderwritingSimulationRequest {
        query: arc_kernel::UnderwritingPolicyInputQuery {
            capability_id: capability_id.map(ToOwned::to_owned),
            agent_subject: agent_subject.map(ToOwned::to_owned),
            tool_server: tool_server.map(ToOwned::to_owned),
            tool_name: tool_name.map(ToOwned::to_owned),
            since,
            until,
            receipt_limit: Some(receipt_limit),
        },
        policy: load_underwriting_decision_policy(policy_file)?,
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.simulate_underwriting_decision(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "underwriting simulation requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::build_underwriting_simulation_report(
            receipt_db_path,
            budget_db_path,
            certification_registry_file,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("generated_at:           {}", report.generated_at);
        println!(
            "baseline_outcome:       {:?}",
            report.default_evaluation.outcome
        );
        println!(
            "simulated_outcome:      {:?}",
            report.simulated_evaluation.outcome
        );
        println!("outcome_changed:        {}", report.delta.outcome_changed);
        println!(
            "risk_class_changed:     {}",
            report.delta.risk_class_changed
        );
        println!(
            "matching_receipts:      {}",
            report.input.receipts.matching_receipts
        );
        println!(
            "added_reasons:          {}",
            report.delta.added_reasons.len()
        );
        println!(
            "removed_reasons:        {}",
            report.delta.removed_reasons.len()
        );
    }

    Ok(())
}

fn parse_underwriting_decision_outcome(
    value: &str,
) -> Result<arc_kernel::UnderwritingDecisionOutcome, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::Other(format!("invalid underwriting outcome `{value}`")))
}

fn parse_credit_facility_disposition(
    value: &str,
) -> Result<arc_kernel::CreditFacilityDisposition, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::Other(format!("invalid credit facility disposition `{value}`")))
}

fn parse_credit_facility_lifecycle_state(
    value: &str,
) -> Result<arc_kernel::CreditFacilityLifecycleState, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::Other(format!("invalid credit facility lifecycle state `{value}`")))
}

fn parse_credit_bond_disposition(
    value: &str,
) -> Result<arc_kernel::CreditBondDisposition, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::Other(format!("invalid credit bond disposition `{value}`")))
}

fn parse_credit_bond_lifecycle_state(
    value: &str,
) -> Result<arc_kernel::CreditBondLifecycleState, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::Other(format!("invalid credit bond lifecycle state `{value}`")))
}

fn parse_credit_loss_lifecycle_event_kind(
    value: &str,
) -> Result<arc_kernel::CreditLossLifecycleEventKind, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::Other(format!(
            "invalid credit loss lifecycle event kind `{value}`"
        ))
    })
}

fn parse_underwriting_lifecycle_state(
    value: &str,
) -> Result<arc_kernel::UnderwritingDecisionLifecycleState, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::Other(format!("invalid underwriting lifecycle state `{value}`")))
}

fn parse_underwriting_appeal_status(
    value: &str,
) -> Result<arc_kernel::UnderwritingAppealStatus, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::Other(format!("invalid underwriting appeal status `{value}`")))
}

fn parse_underwriting_appeal_resolution(
    value: &str,
) -> Result<arc_kernel::UnderwritingAppealResolution, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::Other(format!("invalid underwriting appeal resolution `{value}`")))
}

fn load_underwriting_decision_policy(
    path: &Path,
) -> Result<arc_kernel::UnderwritingDecisionPolicy, CliError> {
    let contents = fs::read_to_string(path)?;
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
    {
        Ok(serde_yaml::from_str(&contents)?)
    } else if let Ok(policy) = serde_json::from_str(&contents) {
        Ok(policy)
    } else {
        Ok(serde_yaml::from_str(&contents)?)
    }
}

fn load_json_or_yaml<T: DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    let contents = fs::read_to_string(path)?;
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
    {
        Ok(serde_yaml::from_str(&contents)?)
    } else if let Ok(value) = serde_json::from_str(&contents) {
        Ok(value)
    } else {
        Ok(serde_yaml::from_str(&contents)?)
    }
}

fn load_credit_bonded_execution_control_policy(
    path: &Path,
) -> Result<arc_kernel::CreditBondedExecutionControlPolicy, CliError> {
    let contents = fs::read_to_string(path)?;
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
    {
        Ok(serde_yaml::from_str(&contents)?)
    } else if let Ok(policy) = serde_json::from_str(&contents) {
        Ok(policy)
    } else {
        Ok(serde_yaml::from_str(&contents)?)
    }
}

fn load_liability_provider_report(
    path: &Path,
) -> Result<arc_kernel::LiabilityProviderReport, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_quote_request_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityQuoteRequestIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_quote_response_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityQuoteResponseIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_pricing_authority_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityPricingAuthorityIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_placement_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityPlacementIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_bound_coverage_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityBoundCoverageIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_auto_bind_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityAutoBindIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_claim_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimPackageIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_claim_response_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimResponseIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_claim_dispute_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimDisputeIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_claim_adjudication_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimAdjudicationIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_claim_payout_instruction_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimPayoutInstructionIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_claim_payout_receipt_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimPayoutReceiptIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_claim_settlement_instruction_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimSettlementInstructionIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn load_liability_claim_settlement_receipt_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimSettlementReceiptIssueRequest, CliError> {
    load_json_or_yaml(path)
}

fn parse_liability_coverage_class(
    value: &str,
) -> Result<arc_kernel::LiabilityCoverageClass, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::Other(format!("invalid liability coverage class `{value}`")))
}

fn parse_liability_provider_lifecycle_state(
    value: &str,
) -> Result<arc_kernel::LiabilityProviderLifecycleState, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::Other(format!(
            "invalid liability provider lifecycle state `{value}`"
        ))
    })
}

fn parse_governed_autonomy_tier(value: &str) -> Result<GovernedAutonomyTier, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::Other(format!("invalid governed autonomy tier `{value}`")))
}

fn parse_runtime_assurance_tier(value: &str) -> Result<RuntimeAssuranceTier, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::Other(format!("invalid runtime assurance tier `{value}`")))
}

fn load_runtime_attestation_evidence(path: &Path) -> Result<RuntimeAttestationEvidence, CliError> {
    let contents = fs::read_to_string(path)?;
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
    {
        Ok(serde_yaml::from_str(&contents)?)
    } else if let Ok(evidence) = serde_json::from_str(&contents) {
        Ok(evidence)
    } else {
        Ok(serde_yaml::from_str(&contents)?)
    }
}

fn load_signed_runtime_attestation_appraisal_result(
    path: &Path,
) -> Result<SignedRuntimeAttestationAppraisalResult, CliError> {
    load_json_or_yaml(path)
}

fn load_runtime_attestation_import_policy(
    path: &Path,
) -> Result<RuntimeAttestationImportedAppraisalPolicy, CliError> {
    load_json_or_yaml(path)
}

fn cmd_trust_runtime_attestation_appraisal_export(
    input_path: &Path,
    policy_file: Option<&Path>,
    json_output: bool,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let evidence = load_runtime_attestation_evidence(input_path)?;
    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalRequest {
                runtime_attestation: evidence,
            },
        )?
    } else {
        let runtime_assurance_policy = policy_file
            .map(load_policy)
            .transpose()?
            .and_then(|loaded| loaded.runtime_assurance_policy);
        trust_control::build_signed_runtime_attestation_appraisal_report(
            authority_seed_path,
            authority_db_path,
            runtime_assurance_policy.as_ref(),
            &evidence,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.body.schema);
        println!("generated_at:           {}", report.body.generated_at);
        println!("signer_key:             {}", report.signer_key.to_hex());
        println!(
            "evidence_schema:        {}",
            report.body.appraisal.evidence.schema
        );
        println!(
            "verifier:               {}",
            report.body.appraisal.evidence.verifier
        );
        println!(
            "verifier_family:        {:?}",
            report.body.appraisal.verifier_family
        );
        println!(
            "verdict:                {:?}",
            report.body.appraisal.verdict
        );
        println!(
            "policy_configured:      {}",
            report.body.policy_outcome.trust_policy_configured
        );
        println!(
            "policy_accepted:        {}",
            report.body.policy_outcome.accepted
        );
        println!(
            "effective_tier:         {:?}",
            report.body.policy_outcome.effective_tier
        );
        if let Some(reason) = report.body.policy_outcome.reason.as_deref() {
            println!("policy_reason:          {reason}");
        }
    }

    Ok(())
}

fn cmd_trust_runtime_attestation_appraisal_result_export(
    issuer: &str,
    input_path: &Path,
    policy_file: Option<&Path>,
    json_output: bool,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let evidence = load_runtime_attestation_evidence(input_path)?;
    let result = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.runtime_attestation_appraisal_result(
            &RuntimeAttestationAppraisalResultExportRequest {
                issuer: issuer.to_string(),
                runtime_attestation: evidence,
            },
        )?
    } else {
        let runtime_assurance_policy = policy_file
            .map(load_policy)
            .transpose()?
            .and_then(|loaded| loaded.runtime_assurance_policy);
        trust_control::build_signed_runtime_attestation_appraisal_result(
            authority_seed_path,
            authority_db_path,
            runtime_assurance_policy.as_ref(),
            &RuntimeAttestationAppraisalResultExportRequest {
                issuer: issuer.to_string(),
                runtime_attestation: evidence,
            },
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("schema:                 {}", result.body.schema);
        println!("result_id:              {}", result.body.result_id);
        println!("exported_at:            {}", result.body.exported_at);
        println!("issuer:                 {}", result.body.issuer);
        println!("signer_key:             {}", result.signer_key.to_hex());
        println!(
            "verifier_family:        {:?}",
            result.body.appraisal.verifier.verifier_family
        );
        println!(
            "exporter_accepted:      {}",
            result.body.exporter_policy_outcome.accepted
        );
        println!(
            "effective_tier:         {:?}",
            result.body.exporter_policy_outcome.effective_tier
        );
    }

    Ok(())
}

fn cmd_trust_runtime_attestation_appraisal_import(
    input_path: &Path,
    policy_path: &Path,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = RuntimeAttestationAppraisalImportRequest {
        signed_result: load_signed_runtime_attestation_appraisal_result(input_path)?,
        local_policy: load_runtime_attestation_import_policy(policy_path)?,
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.import_runtime_attestation_appraisal(&request)?
    } else {
        trust_control::build_runtime_attestation_appraisal_import_report(
            &request,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| CliError::Other(error.to_string()))?
                .as_secs(),
        )
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("schema:                 {}", report.schema);
        println!("evaluated_at:           {}", report.evaluated_at);
        println!("result_id:              {}", report.result.result_id);
        println!("issuer:                 {}", report.result.issuer);
        println!("signer_key:             {}", report.signer_key_hex);
        println!(
            "disposition:            {:?}",
            report.local_policy_outcome.disposition
        );
        println!(
            "effective_tier:         {:?}",
            report.local_policy_outcome.effective_tier
        );
        for reason in &report.local_policy_outcome.reasons {
            println!("- {:?}: {}", reason.code, reason.description);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_underwriting_decision_issue(
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    receipt_limit: usize,
    supersedes_decision_id: Option<&str>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = trust_control::UnderwritingDecisionIssueRequest {
        query: arc_kernel::UnderwritingPolicyInputQuery {
            capability_id: capability_id.map(ToOwned::to_owned),
            agent_subject: agent_subject.map(ToOwned::to_owned),
            tool_server: tool_server.map(ToOwned::to_owned),
            tool_name: tool_name.map(ToOwned::to_owned),
            since,
            until,
            receipt_limit: Some(receipt_limit),
        },
        supersedes_decision_id: supersedes_decision_id.map(ToOwned::to_owned),
    };

    let decision = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.issue_underwriting_decision(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "underwriting decision issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_underwriting_decision(
            receipt_db_path,
            budget_db_path,
            authority_seed_path,
            authority_db_path,
            certification_registry_file,
            &request.query,
            request.supersedes_decision_id.as_deref(),
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&decision)?);
    } else {
        println!("schema:                 {}", decision.body.schema);
        println!("decision_id:            {}", decision.body.decision_id);
        println!("issued_at:              {}", decision.body.issued_at);
        println!("signer_key:             {}", decision.signer_key.to_hex());
        println!(
            "outcome:                {:?}",
            decision.body.evaluation.outcome
        );
        println!("review_state:           {:?}", decision.body.review_state);
        println!("budget_action:          {:?}", decision.body.budget.action);
        println!("premium_state:          {:?}", decision.body.premium.state);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_underwriting_decision_list(
    decision_id: Option<&str>,
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    outcome: Option<&str>,
    lifecycle_state: Option<&str>,
    appeal_status: Option<&str>,
    limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = arc_kernel::UnderwritingDecisionQuery {
        decision_id: decision_id.map(ToOwned::to_owned),
        capability_id: capability_id.map(ToOwned::to_owned),
        agent_subject: agent_subject.map(ToOwned::to_owned),
        tool_server: tool_server.map(ToOwned::to_owned),
        tool_name: tool_name.map(ToOwned::to_owned),
        outcome: outcome
            .map(parse_underwriting_decision_outcome)
            .transpose()?,
        lifecycle_state: lifecycle_state
            .map(parse_underwriting_lifecycle_state)
            .transpose()?,
        appeal_status: appeal_status
            .map(parse_underwriting_appeal_status)
            .transpose()?,
        limit: Some(limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.list_underwriting_decisions(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "underwriting decision list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_underwriting_decisions(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "matching_decisions:     {}",
            report.summary.matching_decisions
        );
        println!(
            "returned_decisions:     {}",
            report.summary.returned_decisions
        );
        println!("open_appeals:           {}", report.summary.open_appeals);
        for row in report.decisions {
            println!(
                "- {} outcome={:?} lifecycle={:?} open_appeals={}",
                row.decision.body.decision_id,
                row.decision.body.evaluation.outcome,
                row.lifecycle_state,
                row.open_appeal_count
            );
        }
    }

    Ok(())
}

fn cmd_trust_underwriting_appeal_create(
    decision_id: &str,
    requested_by: &str,
    reason: &str,
    note: Option<&str>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = arc_kernel::UnderwritingAppealCreateRequest {
        decision_id: decision_id.to_string(),
        requested_by: requested_by.to_string(),
        reason: reason.to_string(),
        note: note.map(ToOwned::to_owned),
    };
    let record = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.create_underwriting_appeal(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "underwriting appeal create requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::create_underwriting_appeal(receipt_db_path, &request)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("appeal_id:              {}", record.appeal_id);
        println!("decision_id:            {}", record.decision_id);
        println!("status:                 {:?}", record.status);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_trust_underwriting_appeal_resolve(
    appeal_id: &str,
    resolution: &str,
    resolved_by: &str,
    note: Option<&str>,
    replacement_decision_id: Option<&str>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = arc_kernel::UnderwritingAppealResolveRequest {
        appeal_id: appeal_id.to_string(),
        resolution: parse_underwriting_appeal_resolution(resolution)?,
        resolved_by: resolved_by.to_string(),
        note: note.map(ToOwned::to_owned),
        replacement_decision_id: replacement_decision_id.map(ToOwned::to_owned),
    };
    let record = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.resolve_underwriting_appeal(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::Other(
                "underwriting appeal resolve requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::resolve_underwriting_appeal(receipt_db_path, &request)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("appeal_id:              {}", record.appeal_id);
        println!("status:                 {:?}", record.status);
        if let Some(replacement_decision_id) = record.replacement_decision_id.as_deref() {
            println!("replacement_decision:   {}", replacement_decision_id);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_receipt_list(
    capability: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
    outcome: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    min_cost: Option<u64>,
    max_cost: Option<u64>,
    limit: usize,
    cursor: Option<u64>,
    receipt_db: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let client = trust_control::build_client(url, token)?;
        let query = trust_control::ReceiptQueryHttpQuery {
            capability_id: capability.map(ToOwned::to_owned),
            tool_server: tool_server.map(ToOwned::to_owned),
            tool_name: tool_name.map(ToOwned::to_owned),
            outcome: outcome.map(ToOwned::to_owned),
            since,
            until,
            min_cost,
            max_cost,
            cursor,
            limit: Some(limit),
            agent_subject: None,
        };
        let response = client.query_receipts(&query)?;
        for receipt in &response.receipts {
            println!("{}", serde_json::to_string(receipt)?);
        }
        if let Some(next_cursor) = response.next_cursor {
            eprintln!(
                "next_cursor={next_cursor} total_count={}",
                response.total_count
            );
        }
    } else {
        let path = receipt_db.ok_or_else(|| {
            CliError::Other(
                "receipt commands require --receipt-db <path> or --control-url".to_string(),
            )
        })?;
        let store = arc_store_sqlite::SqliteReceiptStore::open(path)?;
        let kernel_query = arc_kernel::ReceiptQuery {
            capability_id: capability.map(ToOwned::to_owned),
            tool_server: tool_server.map(ToOwned::to_owned),
            tool_name: tool_name.map(ToOwned::to_owned),
            outcome: outcome.map(ToOwned::to_owned),
            since,
            until,
            min_cost,
            max_cost,
            cursor,
            limit,
            agent_subject: None,
        };
        let result = store.query_receipts(&kernel_query)?;
        for stored in &result.receipts {
            println!("{}", serde_json::to_string(&stored.receipt)?);
        }
        if let Some(next_cursor) = result.next_cursor {
            eprintln!(
                "next_cursor={next_cursor} total_count={}",
                result.total_count
            );
        }
    }
    Ok(())
}

fn select_capability_for_request(
    capabilities: &[arc_core::CapabilityToken],
    tool: &str,
    server: &str,
    params: &serde_json::Value,
) -> Option<arc_core::CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            arc_kernel::capability_matches_request(capability, tool, server, params)
                .unwrap_or(false)
        })
        .cloned()
        .or_else(|| capabilities.first().cloned())
}

fn handle_agent_message(
    kernel: &mut ArcKernel,
    msg: &AgentMessage,
    session_id: &SessionId,
    session_agent_id: &str,
    stats: &mut SessionStats,
) -> Vec<KernelMessage> {
    let is_tool_call = matches!(msg, AgentMessage::ToolCallRequest { .. });
    if is_tool_call {
        stats.requests += 1;
    }

    let (context, operation) = normalize_agent_message(msg, session_id, session_agent_id);
    match kernel.evaluate_session_operation(&context, &operation) {
        Ok(SessionOperationResponse::ToolCall(response)) => {
            match response.verdict {
                arc_kernel::Verdict::Allow => stats.allowed += 1,
                arc_kernel::Verdict::Deny => stats.denied += 1,
            }

            tool_response_messages(context.request_id.to_string(), response)
        }
        Ok(SessionOperationResponse::CapabilityList { capabilities }) => {
            vec![KernelMessage::CapabilityList { capabilities }]
        }
        Ok(
            SessionOperationResponse::RootList { .. }
            | SessionOperationResponse::ResourceList { .. }
            | SessionOperationResponse::ResourceRead { .. }
            | SessionOperationResponse::ResourceReadDenied { .. }
            | SessionOperationResponse::ResourceTemplateList { .. }
            | SessionOperationResponse::PromptList { .. }
            | SessionOperationResponse::PromptGet { .. }
            | SessionOperationResponse::Completion { .. },
        ) => {
            error!(
                request_id = %context.request_id,
                "unexpected non-tool session response on ARC stdio transport"
            );
            vec![KernelMessage::Heartbeat]
        }
        Ok(SessionOperationResponse::Heartbeat) => vec![KernelMessage::Heartbeat],
        Err(e) => match operation {
            SessionOperation::ToolCall(tool_call) => {
                stats.denied += 1;
                error!(
                    request_id = %context.request_id,
                    error = %e,
                    "kernel session evaluation error"
                );

                let request = KernelToolCallRequest {
                    request_id: context.request_id.to_string(),
                    capability: tool_call.capability,
                    tool_name: tool_call.tool_name,
                    server_id: tool_call.server_id,
                    agent_id: session_agent_id.to_string(),
                    arguments: tool_call.arguments,
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                };

                match make_error_receipt(kernel, &request) {
                    Ok(receipt) => vec![KernelMessage::ToolCallResponse {
                        id: context.request_id.to_string(),
                        result: ToolCallResult::Err {
                            error: ToolCallError::InternalError(e.to_string()),
                        },
                        receipt: Box::new(receipt),
                    }],
                    Err(sign_err) => {
                        error!(
                            error = %sign_err,
                            request_id = %context.request_id,
                            "failed to sign error receipt; dropping tool call response"
                        );
                        vec![]
                    }
                }
            }
            SessionOperation::ListCapabilities => {
                error!(error = %e, session_id = %session_id, "failed to list capabilities");
                vec![KernelMessage::CapabilityList {
                    capabilities: vec![],
                }]
            }
            SessionOperation::CreateMessage(_)
            | SessionOperation::CreateElicitation(_)
            | SessionOperation::ListRoots
            | SessionOperation::ListResources
            | SessionOperation::ReadResource(_)
            | SessionOperation::ListResourceTemplates
            | SessionOperation::ListPrompts
            | SessionOperation::GetPrompt(_)
            | SessionOperation::Complete(_) => {
                error!(
                    error = %e,
                    request_id = %context.request_id,
                    "unexpected resource/prompt session failure on ARC stdio transport"
                );
                vec![KernelMessage::Heartbeat]
            }
            SessionOperation::Heartbeat => {
                error!(error = %e, session_id = %session_id, "failed to handle heartbeat");
                vec![KernelMessage::Heartbeat]
            }
        },
    }
}

fn tool_response_messages(
    request_id: String,
    response: arc_kernel::ToolCallResponse,
) -> Vec<KernelMessage> {
    let mut messages = match response.output.as_ref() {
        Some(ToolCallOutput::Stream(ToolCallStream { chunks })) => chunks
            .iter()
            .enumerate()
            .map(|(chunk_index, chunk)| KernelMessage::ToolCallChunk {
                id: request_id.clone(),
                chunk_index: chunk_index as u64,
                data: chunk.data.clone(),
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };

    let chunks_received = match response.output.as_ref() {
        Some(ToolCallOutput::Stream(stream)) => stream.chunk_count(),
        _ => 0,
    };

    let result = match (
        response.verdict,
        response.terminal_state.clone(),
        response.output,
    ) {
        (arc_kernel::Verdict::Allow, _, Some(ToolCallOutput::Value(value))) => {
            ToolCallResult::Ok { value }
        }
        (arc_kernel::Verdict::Allow, _, Some(ToolCallOutput::Stream(_))) => {
            ToolCallResult::StreamComplete {
                total_chunks: chunks_received,
            }
        }
        (arc_kernel::Verdict::Deny, OperationTerminalState::Cancelled { reason }, _) => {
            ToolCallResult::Cancelled {
                reason,
                chunks_received,
            }
        }
        (arc_kernel::Verdict::Deny, OperationTerminalState::Incomplete { reason }, _) => {
            ToolCallResult::Incomplete {
                reason,
                chunks_received,
            }
        }
        (arc_kernel::Verdict::Deny, OperationTerminalState::Completed, _) => ToolCallResult::Err {
            error: ToolCallError::PolicyDenied {
                guard: "kernel".to_string(),
                reason: response
                    .reason
                    .unwrap_or_else(|| "denied by policy".to_string()),
            },
        },
        (arc_kernel::Verdict::Allow, _, None) => ToolCallResult::Ok {
            value: serde_json::Value::Null,
        },
    };

    messages.push(KernelMessage::ToolCallResponse {
        id: request_id,
        result,
        receipt: Box::new(response.receipt),
    });
    messages
}

fn normalize_agent_message(
    msg: &AgentMessage,
    session_id: &SessionId,
    session_agent_id: &str,
) -> (OperationContext, SessionOperation) {
    match msg {
        AgentMessage::ToolCallRequest {
            id,
            capability_token,
            server_id,
            tool,
            params,
        } => (
            OperationContext::new(
                session_id.clone(),
                RequestId::new(id.clone()),
                session_agent_id.to_string(),
            ),
            SessionOperation::ToolCall(ToolCallOperation {
                capability: *capability_token.clone(),
                server_id: server_id.clone(),
                tool_name: tool.clone(),
                arguments: params.clone(),
            }),
        ),
        AgentMessage::ListCapabilities => (
            OperationContext::new(
                session_id.clone(),
                control_request_id(session_id, "list_capabilities"),
                session_agent_id.to_string(),
            ),
            SessionOperation::ListCapabilities,
        ),
        AgentMessage::Heartbeat => (
            OperationContext::new(
                session_id.clone(),
                control_request_id(session_id, "heartbeat"),
                session_agent_id.to_string(),
            ),
            SessionOperation::Heartbeat,
        ),
    }
}

fn control_request_id(session_id: &SessionId, suffix: &str) -> RequestId {
    RequestId::new(format!("{session_id}::{suffix}"))
}

/// Build an error receipt when the kernel fails internally.
fn make_error_receipt(
    _kernel: &mut ArcKernel,
    request: &KernelToolCallRequest,
) -> Result<arc_core::ArcReceipt, arc_core::error::Error> {
    // Attempt to build a proper deny receipt through the kernel.
    // If that also fails (unlikely), produce a minimal placeholder.
    let action = arc_core::receipt::ToolCallAction::from_parameters(request.arguments.clone());
    let action = match action {
        Ok(a) => a,
        Err(_) => arc_core::receipt::ToolCallAction::from_parameters(serde_json::json!({}))
            .unwrap_or_else(|_| {
                // This path should never be reached, but if it is, we have a
                // truly minimal fallback.
                arc_core::receipt::ToolCallAction {
                    parameter_hash: "error".to_string(),
                    parameters: serde_json::json!({}),
                }
            }),
    };

    // Sign a receipt with the kernel's key by issuing a capability for this
    // purpose and using the kernel's existing receipt-signing infrastructure.
    // Since we only have pub methods, we use a simplified approach.
    let kp = Keypair::generate();
    let body = arc_core::receipt::ArcReceiptBody {
        id: format!("rcpt-error-{}", request.request_id),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        capability_id: request.capability.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        action,
        decision: arc_core::receipt::Decision::Deny {
            reason: "internal kernel error".to_string(),
            guard: "kernel".to_string(),
        },
        content_hash: arc_core::sha256_hex(b"null"),
        policy_hash: "error".to_string(),
        evidence: vec![],
        metadata: None,
        kernel_key: kp.public_key(),
    };

    arc_core::receipt::ArcReceipt::sign(body, &kp)
}

struct StubToolServer {
    id: String,
}

impl arc_kernel::ToolServerConnection for StubToolServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["*".to_string()]
    }

    fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn arc_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, arc_kernel::KernelError> {
        Ok(serde_json::json!({
            "stub": true,
            "tool": tool_name,
            "arguments": arguments,
        }))
    }
}

#[cfg(test)]
struct StubStreamingToolServer {
    id: String,
    incomplete: bool,
}

#[cfg(test)]
impl arc_kernel::ToolServerConnection for StubStreamingToolServer {
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
        _nested_flow_bridge: Option<&mut dyn arc_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, arc_kernel::KernelError> {
        Ok(serde_json::json!({"unused": true}))
    }

    fn invoke_stream(
        &self,
        _tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn arc_kernel::NestedFlowBridge>,
    ) -> Result<Option<arc_kernel::ToolServerStreamResult>, arc_kernel::KernelError> {
        let stream = ToolCallStream {
            chunks: vec![
                arc_kernel::ToolCallChunk {
                    data: serde_json::json!({"delta": "hello"}),
                },
                arc_kernel::ToolCallChunk {
                    data: serde_json::json!({"delta": arguments}),
                },
            ],
        };

        if self.incomplete {
            Ok(Some(arc_kernel::ToolServerStreamResult::Incomplete {
                stream,
                reason: "stream source ended before final frame".to_string(),
            }))
        } else {
            Ok(Some(arc_kernel::ToolServerStreamResult::Complete(stream)))
        }
    }
}

#[derive(Default)]
struct SessionStats {
    requests: u64,
    allowed: u64,
    denied: u64,
}

fn print_summary(stats: &SessionStats, exit_code: Option<i32>, json_output: bool) {
    if json_output {
        let output = serde_json::json!({
            "summary": {
                "requests": stats.requests,
                "allowed": stats.allowed,
                "denied": stats.denied,
                "exit_code": exit_code,
            }
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        eprintln!();
        eprintln!("--- arc session summary ---");
        eprintln!("requests: {}", stats.requests);
        eprintln!("allowed:  {}", stats.allowed);
        eprintln!("denied:   {}", stats.denied);
        if let Some(code) = exit_code {
            eprintln!("exit:     {code}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn load_test_policy_runtime(policy: &policy::ArcPolicy) -> policy::LoadedPolicy {
        let default_capabilities = policy::build_runtime_default_capabilities(policy).unwrap();

        policy::LoadedPolicy {
            format: policy::PolicyFormat::ArcYaml,
            identity: policy::PolicyIdentity {
                source_hash: "test-source-hash".to_string(),
                runtime_hash: "test-runtime-hash".to_string(),
            },
            kernel: policy.kernel.clone(),
            default_capabilities,
            guard_pipeline: policy::build_guard_pipeline(&policy.guards),
            issuance_policy: None,
            runtime_assurance_policy: None,
        }
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/policies")
            .join(name)
    }

    fn unique_db_path(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn unique_seed_path(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.seed"))
    }

    fn first_default_capability(
        kernel: &ArcKernel,
        policy: &policy::ArcPolicy,
        agent_kp: &Keypair,
    ) -> arc_core::CapabilityToken {
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        issue_default_capabilities(kernel, &agent_kp.public_key(), &default_capabilities)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    }

    fn open_ready_session(
        kernel: &mut ArcKernel,
        agent_id: &str,
        capabilities: Vec<arc_core::CapabilityToken>,
    ) -> SessionId {
        let session_id = kernel.open_session(agent_id.to_string(), capabilities);
        kernel.activate_session(&session_id).unwrap();
        session_id
    }

    fn only_message(messages: Vec<KernelMessage>) -> KernelMessage {
        assert_eq!(messages.len(), 1, "expected exactly one kernel message");
        messages.into_iter().next().unwrap()
    }

    #[test]
    fn check_builds_kernel_with_guards() {
        let yaml = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
guards:
  forbidden_path:
    enabled: true
  shell_command:
    enabled: true
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        assert_eq!(kernel.guard_count(), 1); // pipeline counts as 1
    }

    #[test]
    fn configure_revocation_store_survives_restart() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let revocation_db_path = unique_db_path("arc-cli-revocations");
        let kp = Keypair::generate();

        let agent_kp = Keypair::generate();
        let cap = {
            let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
            configure_revocation_store(&mut kernel, Some(&revocation_db_path), None, None).unwrap();
            kernel.register_tool_server(Box::new(StubToolServer {
                id: "*".to_string(),
            }));

            let cap = first_default_capability(&kernel, &policy, &agent_kp);
            kernel.revoke_capability(&cap.id).unwrap();
            cap
        };

        let mut restarted = build_kernel(load_test_policy_runtime(&policy), &kp);
        configure_revocation_store(&mut restarted, Some(&revocation_db_path), None, None).unwrap();
        restarted.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let request = KernelToolCallRequest {
            request_id: "revoked-after-restart".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: "*".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({"path": "/app/src/main.rs"}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        };

        let response = restarted.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, arc_kernel::Verdict::Deny);
        assert!(response.reason.as_deref().unwrap_or("").contains("revoked"));

        let _ = std::fs::remove_file(revocation_db_path);
    }

    #[test]
    fn authority_seed_file_persists_public_key_across_loads_and_rotation() {
        let seed_path = unique_seed_path("arc-cli-authority");
        let original = load_or_create_authority_keypair(&seed_path)
            .unwrap()
            .public_key();
        let reloaded = load_or_create_authority_keypair(&seed_path)
            .unwrap()
            .public_key();
        assert_eq!(original, reloaded);

        let rotated = rotate_authority_keypair(&seed_path).unwrap();
        assert_ne!(original, rotated);
        assert_eq!(
            authority_public_key_from_seed_file(&seed_path).unwrap(),
            Some(rotated)
        );

        let _ = std::fs::remove_file(seed_path);
    }

    #[test]
    fn configure_capability_authority_changes_issued_capability_issuer() {
        let seed_path = unique_seed_path("arc-cli-configure-authority");
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        configure_capability_authority(
            &mut kernel,
            &kp,
            Some(&seed_path),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let agent_kp = Keypair::generate();
        let capability =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();

        assert_eq!(
            capability.issuer,
            authority_public_key_from_seed_file(&seed_path)
                .unwrap()
                .expect("authority public key")
        );

        let _ = std::fs::remove_file(seed_path);
    }

    #[test]
    fn configure_capability_authority_supports_shared_sqlite_backend() {
        let authority_db_path = unique_db_path("arc-cli-authority-db");
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let first_kp = Keypair::generate();
        let mut first_kernel = build_kernel(load_test_policy_runtime(&policy), &first_kp);
        configure_capability_authority(
            &mut first_kernel,
            &first_kp,
            None,
            Some(&authority_db_path),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let first_capability = issue_default_capabilities(
            &first_kernel,
            &Keypair::generate().public_key(),
            &default_capabilities,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
        let original_issuer = first_capability.issuer.clone();

        let authority =
            arc_store_sqlite::SqliteCapabilityAuthority::open(&authority_db_path).unwrap();
        let rotated = authority.rotate().unwrap();

        let second_kp = Keypair::generate();
        let mut second_kernel = build_kernel(load_test_policy_runtime(&policy), &second_kp);
        configure_capability_authority(
            &mut second_kernel,
            &second_kp,
            None,
            Some(&authority_db_path),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let second_capability = issue_default_capabilities(
            &second_kernel,
            &Keypair::generate().public_key(),
            &default_capabilities,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

        assert_ne!(original_issuer, second_capability.issuer);
        assert_eq!(second_capability.issuer, rotated.public_key);

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn check_command_allow() {
        let yaml = r#"
kernel:
  max_capability_ttl: 3600
guards:
  forbidden_path:
    enabled: true
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let cap = first_default_capability(&kernel, &policy, &agent_kp);

        let request = KernelToolCallRequest {
            request_id: "test-1".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: "*".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({"path": "/app/src/main.rs"}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, arc_kernel::Verdict::Allow);
    }

    #[test]
    fn check_command_deny_forbidden_path() {
        let yaml = r#"
kernel:
  max_capability_ttl: 3600
guards:
  forbidden_path:
    enabled: true
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let cap = first_default_capability(&kernel, &policy, &agent_kp);

        let request = KernelToolCallRequest {
            request_id: "test-2".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: "*".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({"path": "/home/user/.ssh/id_rsa"}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, arc_kernel::Verdict::Deny);
    }

    #[test]
    fn handle_heartbeat() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);

        let agent_kp = Keypair::generate();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &AgentMessage::Heartbeat,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        assert!(matches!(response, KernelMessage::Heartbeat));
        assert_eq!(stats.requests, 0);
    }

    #[test]
    fn handle_list_capabilities() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);

        let agent_kp = Keypair::generate();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &AgentMessage::ListCapabilities,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        match response {
            KernelMessage::CapabilityList { capabilities } => {
                assert_eq!(capabilities.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn handle_tool_call_uses_explicit_server_id() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "srv-a"
        tool: "read_file"
        operations: [invoke]
        ttl: 300
      - server: "srv-b"
        tool: "read_file"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "srv-b".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let cap = caps[0].clone();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let message = AgentMessage::ToolCallRequest {
            id: "req-1".to_string(),
            capability_token: Box::new(cap),
            server_id: "srv-b".to_string(),
            tool: "read_file".to_string(),
            params: serde_json::json!({"path": "/app/src/main.rs"}),
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Ok { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn handle_tool_call_uses_session_agent_id_not_presented_subject() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "srv-a"
        tool: "read_file"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "srv-a".to_string(),
        }));

        let session_agent_kp = Keypair::generate();
        let stolen_agent_kp = Keypair::generate();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let caps = issue_default_capabilities(
            &kernel,
            &session_agent_kp.public_key(),
            &default_capabilities,
        )
        .unwrap();
        let session_agent_id = session_agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &session_agent_id, caps.clone());
        let stolen_capability = first_default_capability(&kernel, &policy, &stolen_agent_kp);

        let message = AgentMessage::ToolCallRequest {
            id: "req-1".to_string(),
            capability_token: Box::new(stolen_capability),
            server_id: "srv-a".to_string(),
            tool: "read_file".to_string(),
            params: serde_json::json!({"path": "/app/src/main.rs"}),
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &session_agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn hushspec_policy_drives_tool_access_via_session_runtime_path() {
        let loaded_policy = policy::load_policy(&fixture_path("hushspec-tool-allow.yaml")).unwrap();
        let default_capabilities = loaded_policy.default_capabilities.clone();

        let kp = Keypair::generate();
        let mut kernel = build_kernel(loaded_policy, &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let allowed_cap = select_capability_for_request(
            &caps,
            "read_file",
            "*",
            &serde_json::json!({"path": "/workspace/README.md"}),
        )
        .unwrap();

        let allowed = AgentMessage::ToolCallRequest {
            id: "req-allow".to_string(),
            capability_token: Box::new(allowed_cap),
            server_id: "*".to_string(),
            tool: "read_file".to_string(),
            params: serde_json::json!({"path": "/workspace/README.md"}),
        };

        let denied = AgentMessage::ToolCallRequest {
            id: "req-deny".to_string(),
            capability_token: Box::new(caps[0].clone()),
            server_id: "*".to_string(),
            tool: "write_file".to_string(),
            params: serde_json::json!({"path": "/workspace/README.md", "content": "nope"}),
        };

        let mut stats = SessionStats::default();
        let allowed_response = only_message(handle_agent_message(
            &mut kernel,
            &allowed,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        let denied_response = only_message(handle_agent_message(
            &mut kernel,
            &denied,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match allowed_response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Ok { .. }));
            }
            _ => panic!("wrong variant"),
        }

        match denied_response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn yaml_tool_access_drives_tool_access_via_session_runtime_path() {
        let policy = policy::parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - read_file
      - list_directory
"#,
        )
        .unwrap();

        let loaded_policy = load_test_policy_runtime(&policy);
        let default_capabilities = loaded_policy.default_capabilities.clone();

        let kp = Keypair::generate();
        let mut kernel = build_kernel(loaded_policy, &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let allowed_cap = select_capability_for_request(
            &caps,
            "read_file",
            "*",
            &serde_json::json!({"path": "/workspace/README.md"}),
        )
        .unwrap();

        let allowed = AgentMessage::ToolCallRequest {
            id: "req-allow".to_string(),
            capability_token: Box::new(allowed_cap),
            server_id: "*".to_string(),
            tool: "read_file".to_string(),
            params: serde_json::json!({"path": "/workspace/README.md"}),
        };

        let denied = AgentMessage::ToolCallRequest {
            id: "req-deny".to_string(),
            capability_token: Box::new(caps[0].clone()),
            server_id: "*".to_string(),
            tool: "write_file".to_string(),
            params: serde_json::json!({"path": "/workspace/README.md", "content": "nope"}),
        };

        let mut stats = SessionStats::default();
        let allowed_response = only_message(handle_agent_message(
            &mut kernel,
            &allowed,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        let denied_response = only_message(handle_agent_message(
            &mut kernel,
            &denied,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match allowed_response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Ok { .. }));
            }
            _ => panic!("wrong variant"),
        }

        match denied_response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn handle_tool_call_streams_chunks_before_terminal_response() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "stream_file"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubStreamingToolServer {
            id: "*".to_string(),
            incomplete: false,
        }));

        let agent_kp = Keypair::generate();
        let cap = first_default_capability(&kernel, &policy, &agent_kp);
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, vec![cap.clone()]);

        let message = AgentMessage::ToolCallRequest {
            id: "stream-1".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "stream_file".to_string(),
            params: serde_json::json!({"path": "/workspace/README.md"}),
        };

        let mut stats = SessionStats::default();
        let messages =
            handle_agent_message(&mut kernel, &message, &session_id, &agent_id, &mut stats);

        assert_eq!(messages.len(), 3);
        assert!(matches!(
            &messages[0],
            KernelMessage::ToolCallChunk { chunk_index: 0, .. }
        ));
        assert!(matches!(
            &messages[1],
            KernelMessage::ToolCallChunk { chunk_index: 1, .. }
        ));
        match &messages[2] {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(
                    result,
                    ToolCallResult::StreamComplete { total_chunks: 2 }
                ));
            }
            other => panic!("unexpected terminal message: {other:?}"),
        }
    }

    #[test]
    fn handle_tool_call_surfaces_incomplete_stream_terminal_response() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "stream_file"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubStreamingToolServer {
            id: "*".to_string(),
            incomplete: true,
        }));

        let agent_kp = Keypair::generate();
        let cap = first_default_capability(&kernel, &policy, &agent_kp);
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, vec![cap.clone()]);

        let message = AgentMessage::ToolCallRequest {
            id: "stream-2".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "stream_file".to_string(),
            params: serde_json::json!({"path": "/workspace/README.md"}),
        };

        let mut stats = SessionStats::default();
        let messages =
            handle_agent_message(&mut kernel, &message, &session_id, &agent_id, &mut stats);

        assert_eq!(messages.len(), 3);
        match &messages[2] {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(
                    result,
                    ToolCallResult::Incomplete {
                        chunks_received: 2,
                        ..
                    }
                ));
            }
            other => panic!("unexpected terminal message: {other:?}"),
        }
    }

    #[test]
    fn hushspec_policy_compiles_shell_guard_into_runtime_path() {
        let loaded_policy =
            policy::load_policy(&fixture_path("hushspec-guard-heavy.yaml")).unwrap();
        let default_capabilities = loaded_policy.default_capabilities.clone();

        let kp = Keypair::generate();
        let mut kernel = build_kernel(loaded_policy, &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let cap = select_capability_for_request(
            &caps,
            "bash",
            "*",
            &serde_json::json!({"command": "rm -rf /"}),
        )
        .unwrap();

        let message = AgentMessage::ToolCallRequest {
            id: "req-1".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "bash".to_string(),
            params: serde_json::json!({"command": "rm -rf /"}),
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }
}
