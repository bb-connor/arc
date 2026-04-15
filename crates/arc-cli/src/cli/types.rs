pub use arc_control_plane::{
    authority_public_key_from_seed_file, build_kernel, certify, configure_budget_store,
    configure_capability_authority, configure_receipt_store, configure_revocation_store,
    enterprise_federation, evidence_export, federation_policy, issuance,
    issue_default_capabilities, load_or_create_authority_keypair, passport_verifier, policy,
    reputation, require_control_token, rotate_authority_keypair, scim_lifecycle, trust_control,
    CliError,
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

use arc_api_protect::{ProtectConfig, ProtectProxy};
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Backward-compatible alias for `--format json`.
    #[arg(long, global = true, default_value_t = false)]
    json: bool,

    /// Output format for command results and terminal error reporting.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

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

impl Cli {
    fn json_output(&self) -> bool {
        self.json || matches!(self.format, OutputFormat::Json)
    }
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

    /// Scaffold a runnable ARC example project with a governed demo flow.
    Init {
        /// Directory to create for the scaffolded project.
        path: PathBuf,
    },

    /// Protect an HTTP API with ARC using an OpenAPI spec-backed sidecar.
    Api {
        #[command(subcommand)]
        command: ApiCommands,
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

    /// Generate, verify, and inspect ACP session compliance certificates.
    Cert {
        #[command(subcommand)]
        command: CertCommands,
    },

    /// Guard development lifecycle: scaffold, build, and inspect WASM guards.
    Guard {
        #[command(subcommand)]
        command: GuardCommands,
    },
}

/// Guard development lifecycle commands.
#[derive(Subcommand)]
enum GuardCommands {
    /// Scaffold a new guard project with Cargo.toml, src/lib.rs, and guard-manifest.yaml.
    New {
        /// Name of the guard project to create.
        name: String,
    },

    /// Compile the guard in the current directory to wasm32-unknown-unknown.
    Build,

    /// Inspect a compiled .wasm guard binary and print exports, ABI compatibility, and memory config.
    Inspect {
        /// Path to the .wasm file to inspect.
        path: PathBuf,
    },

    /// Run YAML test fixtures against a compiled .wasm guard.
    Test {
        /// Path to the .wasm file to test.
        #[arg(long)]
        wasm: PathBuf,
        /// Glob or paths to YAML fixture files.
        fixtures: Vec<PathBuf>,
        /// Fuel limit per fixture evaluation (default: 1_000_000).
        #[arg(long, default_value = "1000000")]
        fuel_limit: u64,
    },

    /// Benchmark a compiled .wasm guard for fuel consumption and latency.
    Bench {
        /// Path to the .wasm file to benchmark.
        path: PathBuf,
        /// Number of iterations (default: 100).
        #[arg(long, default_value = "100")]
        iterations: u32,
        /// Fuel limit per evaluation (default: 1_000_000).
        #[arg(long, default_value = "1000000")]
        fuel_limit: u64,
    },

    /// Package a guard project into a distributable .arcguard archive.
    Pack,

    /// Install a .arcguard archive to the guard directory.
    Install {
        /// Path to the .arcguard archive file.
        path: PathBuf,
        /// Target directory to extract into (default: ./guards/).
        #[arg(long, default_value = "guards")]
        target_dir: PathBuf,
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
enum ApiCommands {
    /// Start the ARC HTTP sidecar/reverse proxy.
    Protect {
        /// Upstream base URL to proxy to.
        #[arg(long)]
        upstream: String,

        /// Optional local OpenAPI spec path. Auto-discovered when omitted.
        #[arg(long)]
        spec: Option<PathBuf>,

        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:9090")]
        listen: String,

        /// Optional SQLite receipt store path.
        #[arg(long = "receipt-store")]
        receipt_store: Option<PathBuf>,
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

        /// Optional file-backed permissionless federation policy registry.
        #[arg(long)]
        federation_policies_file: Option<PathBuf>,

        /// Optional file-backed SCIM lifecycle registry for external IdP provisioning and deprovisioning.
        #[arg(long)]
        scim_lifecycle_file: Option<PathBuf>,

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

    /// Manage permissionless federation admission policies.
    FederationPolicy {
        #[command(subcommand)]
        command: TrustFederationPolicyCommands,
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
enum TrustFederationPolicyCommands {
    /// List published permissionless federation policies.
    List {
        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        federation_policies_file: Option<PathBuf>,
    },

    /// Read one published permissionless federation policy.
    Get {
        /// Policy ID to fetch.
        #[arg(long)]
        policy_id: String,

        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        federation_policies_file: Option<PathBuf>,
    },

    /// Create or update one permissionless federation policy record from JSON.
    Upsert {
        /// Input JSON file containing a FederationAdmissionPolicyRecord.
        #[arg(long)]
        input: PathBuf,

        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        federation_policies_file: Option<PathBuf>,
    },

    /// Delete one permissionless federation policy record.
    Delete {
        /// Policy ID to delete.
        #[arg(long)]
        policy_id: String,

        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        federation_policies_file: Option<PathBuf>,
    },

    /// Evaluate admission for one peer under a published federation policy.
    Evaluate {
        /// Input JSON file containing a FederationAdmissionEvaluationRequest.
        #[arg(long)]
        input: PathBuf,
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
        #[arg(long = "credential-format")]
        credential_format: Option<String>,
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

#[derive(Subcommand)]
enum CertCommands {
    /// Generate a compliance certificate for an ACP session.
    Generate {
        /// ACP session ID to certify.
        #[arg(long)]
        session_id: String,

        /// Path to the receipt database.
        #[arg(long)]
        receipt_db: PathBuf,

        /// Maximum invocation budget (0 = unlimited).
        #[arg(long, default_value_t = 0)]
        budget_limit: u64,

        /// Output file for the certificate JSON.
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Verify a compliance certificate.
    Verify {
        /// Path to the certificate JSON file.
        #[arg(long)]
        certificate: PathBuf,

        /// Enable full-bundle verification (re-verify all receipt signatures).
        #[arg(long, default_value_t = false)]
        full: bool,

        /// Path to the receipt database (required for full-bundle mode).
        #[arg(long)]
        receipt_db: Option<PathBuf>,
    },

    /// Inspect a compliance certificate and display its contents.
    Inspect {
        /// Path to the certificate JSON file.
        #[arg(long)]
        certificate: PathBuf,
    },
}
