//! PACT CLI -- command-line interface for the PACT runtime kernel.
//!
//! Provides commands for:
//!
//! - `pact run --policy <path> -- <command> [args...]`
//!   Spawn an agent subprocess, set up the length-prefixed transport over
//!   stdin/stdout pipes, and run the kernel message loop.
//!
//! - `pact check --policy <path> --tool <name> --params <json>`
//!   Load a policy, create a kernel, and evaluate a single tool call.
//!
//! - `pact mcp serve --policy <path> --server-id <id> -- <command> [args...]`
//!   Wrap an MCP server subprocess with the PACT kernel and expose an
//!   MCP-compatible edge over stdio for stock MCP clients.

#![allow(clippy::large_enum_variant, clippy::too_many_arguments)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

mod certify;
mod did;
mod enterprise_federation;
mod evidence_export;
mod issuance;
mod passport;
mod passport_verifier;
mod policy;
mod remote_mcp;
mod reputation;
mod trust_control;

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Parser, Subcommand};
use tracing::{debug, error, info, warn};

use pact_core::capability::PactScope;
use pact_core::crypto::Keypair;
use pact_core::message::{AgentMessage, KernelMessage, ToolCallError, ToolCallResult};
use pact_core::session::{
    OperationContext, OperationTerminalState, RequestId, SessionId, SessionOperation,
    ToolCallOperation,
};
use pact_kernel::transport::{PactTransport, TransportError};
use pact_kernel::{
    KernelConfig, PactKernel, RevocationStore, SessionOperationResponse, ToolCallOutput,
    ToolCallRequest as KernelToolCallRequest, ToolCallStream,
};
use pact_mcp_adapter::{AdaptedMcpServer, McpAdapterConfig, McpEdgeConfig, PactMcpEdge};

use crate::enterprise_federation::{EnterpriseProviderRecord, EnterpriseProviderRegistry};
use crate::policy::{load_policy, DefaultCapability, LoadedPolicy};

/// PACT -- Provable Agent Capability Transport.
///
/// Runtime security enforcement for AI agents via capability-based
/// authorization and signed audit receipts.
#[derive(Parser)]
#[command(name = "pact", version, about)]
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

    /// Serve an MCP-compatible edge backed by the PACT kernel.
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

    /// Resolve self-certifying did:pact identifiers into DID Documents.
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

        /// Server ID to assign to the wrapped MCP server inside PACT.
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

        /// Server ID to assign to the wrapped MCP server inside PACT.
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

        /// Persistent seed file used to derive stable PACT subjects from authenticated OAuth bearer principals.
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

        /// Optional file-backed certification registry for publish/resolve/revoke flows.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
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
}

#[derive(Subcommand)]
enum DidCommands {
    /// Resolve a did:pact identifier or Ed25519 public key into a DID Document.
    Resolve {
        /// Fully-qualified did:pact identifier to resolve.
        #[arg(long, conflicts_with = "public_key")]
        did: Option<String>,
        /// Hex-encoded Ed25519 public key to resolve as did:pact.
        #[arg(long, conflicts_with = "did")]
        public_key: Option<String>,
        /// Optional receipt log service endpoint to include in the resolved document.
        #[arg(long = "receipt-log-url")]
        receipt_log_urls: Vec<String>,
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
    },

    /// Verify a passport and every embedded credential without external glue code.
    Verify {
        /// Passport JSON file to verify.
        #[arg(long)]
        input: PathBuf,
        /// Verification timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
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
        #[arg(long)]
        challenge: PathBuf,
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
        /// Verification timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
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
                certification_registry_file,
            } => cmd_trust_serve(
                listen,
                &service_token,
                policy.as_deref(),
                enterprise_providers_file.as_deref(),
                verifier_policies_file.as_deref(),
                verifier_challenge_db.as_deref(),
                certification_registry_file.as_deref(),
                receipt_db.as_deref(),
                revocation_db.as_deref(),
                authority_seed_file.as_deref(),
                authority_db.as_deref(),
                budget_db.as_deref(),
                session_db.as_deref(),
                advertise_url.as_deref(),
                &peer_urls,
                cluster_sync_interval_ms,
            ),
            TrustCommands::Provider { command } => match command {
                TrustProviderCommands::List {
                    enterprise_providers_file,
                } => cmd_trust_provider_list(
                    cli.json,
                    enterprise_providers_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustProviderCommands::Get {
                    provider_id,
                    enterprise_providers_file,
                } => cmd_trust_provider_get(
                    &provider_id,
                    cli.json,
                    enterprise_providers_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustProviderCommands::Upsert {
                    input,
                    enterprise_providers_file,
                } => cmd_trust_provider_upsert(
                    &input,
                    cli.json,
                    enterprise_providers_file.as_deref(),
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                TrustProviderCommands::Delete {
                    provider_id,
                    enterprise_providers_file,
                } => cmd_trust_provider_delete(
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
            } => cmd_trust_federated_issue(
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
            } => cmd_trust_federated_delegation_policy_create(
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
                } => cmd_certify_registry_publish(
                    &input,
                    certification_registry_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::List {
                    certification_registry_file,
                } => cmd_certify_registry_list(
                    certification_registry_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Get {
                    artifact_id,
                    certification_registry_file,
                } => cmd_certify_registry_get(
                    &artifact_id,
                    certification_registry_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Resolve {
                    tool_server_id,
                    certification_registry_file,
                } => cmd_certify_registry_resolve(
                    &tool_server_id,
                    certification_registry_file.as_deref(),
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                CertifyRegistryCommands::Revoke {
                    artifact_id,
                    reason,
                    revoked_at,
                    certification_registry_file,
                } => cmd_certify_registry_revoke(
                    &artifact_id,
                    certification_registry_file.as_deref(),
                    reason.as_deref(),
                    revoked_at,
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
            } => did::cmd_did_resolve(
                did.as_deref(),
                public_key.as_deref(),
                &receipt_log_urls,
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
            } => passport::cmd_passport_create(
                &subject_public_key,
                &output,
                &signing_seed_file,
                validity_days,
                since,
                until,
                &receipt_log_urls,
                require_checkpoints,
                receipt_db.as_deref(),
                budget_db.as_deref(),
                cli.json,
            ),
            PassportCommands::Verify { input, at } => {
                passport::cmd_passport_verify(&input, at, cli.json)
            }
            PassportCommands::Evaluate { input, policy, at } => {
                passport::cmd_passport_evaluate(&input, &policy, at, cli.json)
            }
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
                    holder_seed_file,
                    output,
                    at,
                } => passport::cmd_passport_challenge_respond(
                    &input,
                    &challenge,
                    &holder_seed_file,
                    &output,
                    at,
                    cli.json,
                ),
                PassportChallengeCommands::Verify {
                    input,
                    challenge,
                    verifier_policies_file,
                    verifier_challenge_db,
                    at,
                } => passport::cmd_passport_challenge_verify(
                    &input,
                    challenge.as_deref(),
                    verifier_policies_file.as_deref(),
                    verifier_challenge_db.as_deref(),
                    at,
                    cli.json,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
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

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Core(#[from] pact_core::error::Error),

    #[error("{0}")]
    Policy(#[from] policy::PolicyError),

    #[error("adapter error: {0}")]
    Adapter(#[from] pact_mcp_adapter::AdapterError),

    #[error("kernel error: {0}")]
    Kernel(#[from] pact_kernel::KernelError),

    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] pact_kernel::CheckpointError),

    #[error("evidence export error: {0}")]
    EvidenceExport(#[from] pact_kernel::EvidenceExportError),

    #[error("credential error: {0}")]
    Credential(#[from] pact_credentials::CredentialError),

    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] pact_kernel::ReceiptStoreError),

    #[error("conformance load error: {0}")]
    ConformanceLoad(#[from] pact_conformance::LoadError),

    #[error("revocation store error: {0}")]
    RevocationStore(#[from] pact_kernel::RevocationStoreError),

    #[error("authority store error: {0}")]
    AuthorityStore(#[from] pact_kernel::AuthorityStoreError),

    #[error("budget store error: {0}")]
    BudgetStore(#[from] pact_kernel::BudgetStoreError),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("http error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("{0}")]
    Other(String),
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

    let mut transport = PactTransport::new(child_stdout, child_stdin);

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
            .issue_capability(&agent_pk, PactScope::default(), 300)
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
            pact_kernel::Verdict::Allow => "ALLOW",
            pact_kernel::Verdict::Deny => "DENY",
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
        pact_kernel::Verdict::Allow => Ok(()),
        pact_kernel::Verdict::Deny => {
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

    let mut edge = PactMcpEdge::new(
        McpEdgeConfig {
            server_name: "PACT MCP Edge".to_string(),
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

pub(crate) fn build_kernel(loaded_policy: LoadedPolicy, kernel_kp: &Keypair) -> PactKernel {
    let LoadedPolicy {
        identity,
        kernel: kernel_policy,
        guard_pipeline,
        ..
    } = loaded_policy;

    let config = KernelConfig {
        keypair: kernel_kp.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: kernel_policy.delegation_depth_limit,
        policy_hash: identity.runtime_hash,
        allow_sampling: kernel_policy.allow_sampling,
        allow_sampling_tool_use: kernel_policy.allow_sampling_tool_use,
        allow_elicitation: kernel_policy.allow_elicitation,
        max_stream_duration_secs: pact_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: pact_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        checkpoint_batch_size: pact_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };

    let mut kernel = PactKernel::new(config);

    if !guard_pipeline.is_empty() {
        info!(
            guard_count = guard_pipeline.len(),
            "registering guard pipeline"
        );
        kernel.add_guard(Box::new(guard_pipeline));
    }

    kernel
}

pub(crate) fn configure_receipt_store(
    kernel: &mut PactKernel,
    receipt_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (receipt_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --receipt-db or --control-url for receipt persistence, not both"
                    .to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_receipt_store(Box::new(pact_kernel::SqliteReceiptStore::open(path)?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_receipt_store(trust_control::build_remote_receipt_store(url, token)?);
        }
        (None, None) => {}
    }
    Ok(())
}

pub(crate) fn configure_revocation_store(
    kernel: &mut PactKernel,
    revocation_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (revocation_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --revocation-db or --control-url for revocation state, not both"
                    .to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_revocation_store(Box::new(pact_kernel::SqliteRevocationStore::open(path)?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_revocation_store(trust_control::build_remote_revocation_store(url, token)?);
        }
        (None, None) => {}
    }
    Ok(())
}

pub(crate) fn configure_capability_authority(
    kernel: &mut PactKernel,
    default_authority_keypair: &Keypair,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    issuance_policy: Option<policy::ReputationIssuancePolicy>,
) -> Result<(), CliError> {
    if control_url.is_some() && (authority_seed_path.is_some() || authority_db_path.is_some()) {
        return Err(CliError::Other(
            "use either local authority flags or --control-url, not both".to_string(),
        ));
    }
    if let Some(url) = control_url {
        if issuance_policy.is_some() {
            return Err(CliError::Other(
                "reputation-gated issuance must be enforced by the trust-control service itself; start `pact trust serve --policy <path>` instead of relying on client-side --control-url issuance".to_string(),
            ));
        }
        let token = require_control_token(control_token)?;
        kernel.set_capability_authority(trust_control::build_remote_capability_authority(
            url, token,
        )?);
        return Ok(());
    }

    match (authority_seed_path, authority_db_path) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --authority-seed-file or --authority-db, not both".to_string(),
            ));
        }
        (Some(path), None) => {
            let keypair = load_or_create_authority_keypair(path)?;
            kernel.set_capability_authority(issuance::wrap_capability_authority(
                Box::new(pact_kernel::LocalCapabilityAuthority::new(keypair)),
                issuance_policy,
                receipt_db_path,
                budget_db_path,
            ));
        }
        (None, Some(path)) => {
            kernel.set_capability_authority(issuance::wrap_capability_authority(
                Box::new(pact_kernel::SqliteCapabilityAuthority::open(path)?),
                issuance_policy,
                receipt_db_path,
                budget_db_path,
            ));
        }
        (None, None) => {
            if issuance_policy.is_some() || receipt_db_path.is_some() {
                kernel.set_capability_authority(issuance::wrap_capability_authority(
                    Box::new(pact_kernel::LocalCapabilityAuthority::new(
                        default_authority_keypair.clone(),
                    )),
                    issuance_policy,
                    receipt_db_path,
                    budget_db_path,
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn configure_budget_store(
    kernel: &mut PactKernel,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (budget_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --budget-db or --control-url for budget state, not both".to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_budget_store(Box::new(pact_kernel::SqliteBudgetStore::open(path)?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_budget_store(trust_control::build_remote_budget_store(url, token)?);
        }
        (None, None) => {}
    }
    Ok(())
}

fn require_control_token(control_token: Option<&str>) -> Result<&str, CliError> {
    control_token.ok_or_else(|| {
        CliError::Other(
            "--control-url requires --control-token so trust-service authentication is explicit"
                .to_string(),
        )
    })
}

pub(crate) fn authority_public_key_from_seed_file(
    path: &Path,
) -> Result<Option<pact_core::PublicKey>, CliError> {
    match fs::read_to_string(path) {
        Ok(seed_hex) => Ok(Some(Keypair::from_seed_hex(seed_hex.trim())?.public_key())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::Io(error)),
    }
}

pub(crate) fn rotate_authority_keypair(path: &Path) -> Result<pact_core::PublicKey, CliError> {
    let keypair = Keypair::generate();
    write_authority_seed_file(path, &keypair)?;
    Ok(keypair.public_key())
}

pub(crate) fn load_or_create_authority_keypair(path: &Path) -> Result<Keypair, CliError> {
    match authority_public_key_from_seed_file(path)? {
        Some(_) => {
            let seed_hex = fs::read_to_string(path)?;
            Keypair::from_seed_hex(seed_hex.trim()).map_err(CliError::from)
        }
        None => {
            let keypair = Keypair::generate();
            write_authority_seed_file(path, &keypair)?;
            Ok(keypair)
        }
    }
}

fn write_authority_seed_file(path: &Path, keypair: &Keypair) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = path.with_extension(format!(
        "{}tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| format!("{ext}."))
            .unwrap_or_default()
    ));
    fs::write(&temp_path, format!("{}\n", keypair.seed_hex()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(temp_path, path)?;
    Ok(())
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
    certification_registry_file: Option<&Path>,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    advertise_url: Option<&str>,
    peer_urls: &[String],
    cluster_sync_interval_ms: u64,
) -> Result<(), CliError> {
    let issuance_policy = policy_path
        .map(load_policy)
        .transpose()?
        .and_then(|loaded| loaded.issuance_policy);
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
        certification_registry_file: certification_registry_file.map(Path::to_path_buf),
        issuance_policy,
        advertise_url: advertise_url.map(ToOwned::to_owned),
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
        let mut store = pact_kernel::SqliteRevocationStore::open(path)?;
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
        let store = pact_kernel::SqliteRevocationStore::open(path)?;
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
    let query = pact_kernel::SharedEvidenceQuery {
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
        let store = pact_kernel::SqliteReceiptStore::open(path)?;
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

fn require_enterprise_providers_file(path: Option<&Path>) -> Result<&Path, CliError> {
    path.ok_or_else(|| {
        CliError::Other(
            "provider admin requires --enterprise-providers-file when --control-url is not set"
                .to_string(),
        )
    })
}

fn require_certification_registry_file(path: Option<&Path>) -> Result<&Path, CliError> {
    path.ok_or_else(|| {
        CliError::Other(
            "certification registry commands require --certification-registry-file when --control-url is not set"
                .to_string(),
        )
    })
}

fn load_enterprise_provider_registry_local(
    path: &Path,
) -> Result<EnterpriseProviderRegistry, CliError> {
    if path.exists() {
        EnterpriseProviderRegistry::load(path)
    } else {
        Ok(EnterpriseProviderRegistry::default())
    }
}

fn load_admission_policy(path: &Path) -> Result<Option<pact_policy::HushSpec>, CliError> {
    let contents = fs::read_to_string(path)?;
    if pact_policy::is_hushspec_format(&contents) {
        return pact_policy::resolve_from_path(path)
            .map(Some)
            .map_err(|error| CliError::Other(error.to_string()));
    }
    Ok(None)
}

fn cmd_trust_provider_list(
    json_output: bool,
    enterprise_providers_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let response = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.list_enterprise_providers()?
    } else {
        let path = require_enterprise_providers_file(enterprise_providers_file)?;
        let registry = load_enterprise_provider_registry_local(path)?;
        trust_control::EnterpriseProviderListResponse {
            configured: true,
            count: registry.providers.len(),
            providers: registry.providers.into_values().collect(),
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("providers: {}", response.count);
        for provider in response.providers {
            println!(
                "- {} [{}] enabled={} valid={}",
                provider.provider_id,
                serde_json::to_string(&provider.kind).unwrap_or_default(),
                provider.enabled,
                provider.validation_errors.is_empty()
            );
        }
    }

    Ok(())
}

fn cmd_trust_provider_get(
    provider_id: &str,
    json_output: bool,
    enterprise_providers_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let provider = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.get_enterprise_provider(provider_id)?
    } else {
        let path = require_enterprise_providers_file(enterprise_providers_file)?;
        let registry = load_enterprise_provider_registry_local(path)?;
        registry
            .providers
            .get(provider_id)
            .cloned()
            .ok_or_else(|| {
                CliError::Other(format!("enterprise provider `{provider_id}` was not found"))
            })?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&provider)?);
    } else {
        println!("provider_id: {}", provider.provider_id);
        println!(
            "kind:        {}",
            serde_json::to_string(&provider.kind).unwrap_or_default()
        );
        println!("enabled:     {}", provider.enabled);
        println!(
            "validated:   {}",
            if provider.validation_errors.is_empty() {
                "true"
            } else {
                "false"
            }
        );
    }

    Ok(())
}

fn cmd_trust_provider_upsert(
    input_path: &Path,
    json_output: bool,
    enterprise_providers_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let provider: EnterpriseProviderRecord = serde_json::from_slice(&fs::read(input_path)?)?;
    let response = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?
            .upsert_enterprise_provider(&provider.provider_id, &provider)?
    } else {
        let path = require_enterprise_providers_file(enterprise_providers_file)?;
        let mut registry = load_enterprise_provider_registry_local(path)?;
        registry.upsert(provider.clone());
        registry.save(path)?;
        registry
            .providers
            .get(&provider.provider_id)
            .cloned()
            .ok_or_else(|| {
                CliError::Other("provider upsert did not persist the requested record".to_string())
            })?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("provider upserted: {}", response.provider_id);
    }

    Ok(())
}

fn cmd_trust_provider_delete(
    provider_id: &str,
    json_output: bool,
    enterprise_providers_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let response = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::build_client(url, token)?.delete_enterprise_provider(provider_id)?
    } else {
        let path = require_enterprise_providers_file(enterprise_providers_file)?;
        let mut registry = load_enterprise_provider_registry_local(path)?;
        let deleted = registry.remove(provider_id);
        registry.save(path)?;
        trust_control::EnterpriseProviderDeleteResponse {
            provider_id: provider_id.to_string(),
            deleted,
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("provider_deleted: {}", response.deleted);
        println!("provider_id:      {}", response.provider_id);
    }

    Ok(())
}

fn cmd_certify_registry_publish(
    input_path: &Path,
    certification_registry_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let artifact: certify::SignedCertificationCheck =
            serde_json::from_slice(&fs::read(input_path)?)?;
        let entry = trust_control::build_client(url, token)?.publish_certification(&artifact)?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&entry)?);
        } else {
            println!("published certification artifact");
            println!("artifact_id:     {}", entry.artifact_id);
            println!("tool_server_id:  {}", entry.tool_server_id);
            println!("verdict:         {}", entry.verdict.label());
            println!("status:          {}", entry.status.label());
        }
        Ok(())
    } else {
        let path = require_certification_registry_file(certification_registry_file)?;
        certify::cmd_certify_registry_publish_local(input_path, path, json_output)
    }
}

fn cmd_certify_registry_list(
    certification_registry_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::build_client(url, token)?.list_certifications()?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&response)?);
        } else {
            println!("certifications: {}", response.count);
            for artifact in response.artifacts {
                println!(
                    "- {} server={} verdict={} status={}",
                    artifact.artifact_id,
                    artifact.tool_server_id,
                    artifact.verdict.label(),
                    artifact.status.label()
                );
            }
        }
        Ok(())
    } else {
        let path = require_certification_registry_file(certification_registry_file)?;
        certify::cmd_certify_registry_list_local(path, json_output)
    }
}

fn cmd_certify_registry_get(
    artifact_id: &str,
    certification_registry_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let entry = trust_control::build_client(url, token)?.get_certification(artifact_id)?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&entry)?);
        } else {
            println!("certification artifact");
            println!("artifact_id:     {}", entry.artifact_id);
            println!("tool_server_id:  {}", entry.tool_server_id);
            println!("verdict:         {}", entry.verdict.label());
            println!("status:          {}", entry.status.label());
        }
        Ok(())
    } else {
        let path = require_certification_registry_file(certification_registry_file)?;
        certify::cmd_certify_registry_get_local(artifact_id, path, json_output)
    }
}

fn cmd_certify_registry_resolve(
    tool_server_id: &str,
    certification_registry_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::build_client(url, token)?
            .resolve_certification(tool_server_id)?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&response)?);
        } else {
            println!("tool_server_id: {}", response.tool_server_id);
            let state = match response.state {
                certify::CertificationResolutionState::Active => "active",
                certify::CertificationResolutionState::Superseded => "superseded",
                certify::CertificationResolutionState::Revoked => "revoked",
                certify::CertificationResolutionState::NotFound => "not-found",
            };
            println!("state:          {state}");
            println!("total_entries:  {}", response.total_entries);
            if let Some(current) = response.current {
                println!("artifact_id:    {}", current.artifact_id);
                println!("verdict:        {}", current.verdict.label());
                println!("status:         {}", current.status.label());
            }
        }
        Ok(())
    } else {
        let path = require_certification_registry_file(certification_registry_file)?;
        certify::cmd_certify_registry_resolve_local(tool_server_id, path, json_output)
    }
}

fn cmd_certify_registry_revoke(
    artifact_id: &str,
    certification_registry_file: Option<&Path>,
    reason: Option<&str>,
    revoked_at: Option<u64>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let entry = trust_control::build_client(url, token)?.revoke_certification(
            artifact_id,
            &certify::CertificationRevocationRequest {
                reason: reason.map(str::to_string),
                revoked_at,
            },
        )?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&entry)?);
        } else {
            println!("revoked certification artifact");
            println!("artifact_id:     {}", entry.artifact_id);
            println!("tool_server_id:  {}", entry.tool_server_id);
            println!("status:          {}", entry.status.label());
            if let Some(revoked_at) = entry.revoked_at {
                println!("revoked_at:      {revoked_at}");
            }
        }
        Ok(())
    } else {
        let path = require_certification_registry_file(certification_registry_file)?;
        certify::cmd_certify_registry_revoke_local(
            artifact_id,
            path,
            reason,
            revoked_at,
            json_output,
        )
    }
}

fn cmd_trust_federated_issue(
    presentation_response_path: &Path,
    challenge_path: &Path,
    capability_policy_path: &Path,
    enterprise_identity_path: Option<&Path>,
    delegation_policy_path: Option<&Path>,
    upstream_capability_id: Option<&str>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let control_url = control_url.ok_or_else(|| {
        CliError::Other(
            "federated issuance requires --control-url so the trust-control service enforces verifier and issuance policy centrally"
                .to_string(),
        )
    })?;
    let token = require_control_token(control_token)?;
    let presentation: pact_credentials::PassportPresentationResponse =
        serde_json::from_slice(&fs::read(presentation_response_path)?)?;
    let expected_challenge: pact_credentials::PassportPresentationChallenge =
        serde_json::from_slice(&fs::read(challenge_path)?)?;
    let capability = load_single_default_capability(capability_policy_path)?;
    let admission_policy = load_admission_policy(capability_policy_path)?;
    let enterprise_identity = enterprise_identity_path
        .map(|path| {
            serde_json::from_slice::<pact_core::EnterpriseIdentityContext>(&fs::read(path)?)
                .map_err(CliError::from)
        })
        .transpose()?;
    let delegation_policy = delegation_policy_path
        .map(|path| {
            serde_json::from_slice::<trust_control::FederatedDelegationPolicyDocument>(&fs::read(
                path,
            )?)
            .map_err(CliError::from)
        })
        .transpose()?;

    let response = trust_control::build_client(control_url, token)?.federated_issue(
        &trust_control::FederatedIssueRequest {
            presentation,
            expected_challenge,
            capability,
            admission_policy,
            enterprise_identity,
            delegation_policy,
            upstream_capability_id: upstream_capability_id.map(str::to_string),
        },
    )?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("federated capability issued");
        println!("subject:             {}", response.subject);
        println!("subject_public_key:  {}", response.subject_public_key);
        println!("verifier:            {}", response.verification.verifier);
        println!("nonce:               {}", response.verification.nonce);
        println!("presentation_accepted: {}", response.verification.accepted);
        println!("capability_id:       {}", response.capability.id);
        println!(
            "issuer:              {}",
            response.capability.issuer.to_hex()
        );
        println!("expires_at:          {}", response.capability.expires_at);
        if let Some(audit) = response.enterprise_audit.as_ref() {
            println!("enterprise_provider: {}", audit.provider_id);
            if let Some(profile) = audit.matched_origin_profile.as_deref() {
                println!("origin_profile:      {profile}");
            }
        }
        if let Some(anchor_id) = response.delegation_anchor_capability_id.as_deref() {
            println!("delegation_anchor:   {anchor_id}");
        }
    }

    Ok(())
}

fn cmd_trust_federated_delegation_policy_create(
    output_path: &Path,
    signing_seed_file: &Path,
    issuer: &str,
    partner: &str,
    verifier: &str,
    capability_policy_path: &Path,
    expires_at: u64,
    purpose: Option<&str>,
    parent_capability_id: Option<&str>,
    json_output: bool,
) -> Result<(), CliError> {
    let capability = load_single_default_capability(capability_policy_path)?;
    let keypair = load_or_create_authority_keypair(signing_seed_file)?;
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let body = trust_control::FederatedDelegationPolicyBody {
        schema: "pact.federated-delegation-policy.v1".to_string(),
        issuer: issuer.to_string(),
        partner: partner.to_string(),
        verifier: verifier.to_string(),
        signer_public_key: keypair.public_key(),
        created_at,
        expires_at,
        ttl_seconds: capability.ttl,
        scope: capability.scope,
        purpose: purpose.map(str::to_string),
        parent_capability_id: parent_capability_id.map(str::to_string),
    };
    let (signature, _) = keypair.sign_canonical(&body)?;
    let policy = trust_control::FederatedDelegationPolicyDocument { body, signature };
    trust_control::verify_federated_delegation_policy(&policy)?;
    fs::write(output_path, serde_json::to_vec_pretty(&policy)?)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&policy)?);
    } else {
        println!("federated delegation policy created");
        println!("output:              {}", output_path.display());
        println!("issuer:              {}", policy.body.issuer);
        println!("partner:             {}", policy.body.partner);
        println!("verifier:            {}", policy.body.verifier);
        println!(
            "signer_public_key:   {}",
            policy.body.signer_public_key.to_hex()
        );
        println!("ttl_seconds:         {}", policy.body.ttl_seconds);
        println!("expires_at:          {}", policy.body.expires_at);
        if let Some(parent_capability_id) = policy.body.parent_capability_id.as_deref() {
            println!("parent_capability_id: {parent_capability_id}");
        }
    }

    Ok(())
}

fn load_single_default_capability(path: &Path) -> Result<DefaultCapability, CliError> {
    let loaded = load_policy(path)?;
    match loaded.default_capabilities.as_slice() {
        [capability] => Ok(capability.clone()),
        [] => Err(CliError::Other(
            "federated issuance requires a capability policy with exactly one default capability"
                .to_string(),
        )),
        _ => Err(CliError::Other(
            "federated issuance currently supports exactly one default capability per request"
                .to_string(),
        )),
    }
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
        let store = pact_kernel::SqliteReceiptStore::open(path)?;
        let kernel_query = pact_kernel::ReceiptQuery {
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

pub(crate) fn issue_default_capabilities(
    kernel: &PactKernel,
    agent_pk: &pact_core::PublicKey,
    default_capabilities: &[DefaultCapability],
) -> Result<Vec<pact_core::CapabilityToken>, CliError> {
    default_capabilities
        .iter()
        .cloned()
        .map(|default_capability| {
            kernel
                .issue_capability(agent_pk, default_capability.scope, default_capability.ttl)
                .map_err(|error| {
                    CliError::Other(format!("failed to issue initial capability: {error}"))
                })
        })
        .collect()
}

fn select_capability_for_request(
    capabilities: &[pact_core::CapabilityToken],
    tool: &str,
    server: &str,
    params: &serde_json::Value,
) -> Option<pact_core::CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            pact_kernel::capability_matches_request(capability, tool, server, params)
                .unwrap_or(false)
        })
        .cloned()
        .or_else(|| capabilities.first().cloned())
}

fn handle_agent_message(
    kernel: &mut PactKernel,
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
                pact_kernel::Verdict::Allow => stats.allowed += 1,
                pact_kernel::Verdict::Deny => stats.denied += 1,
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
                "unexpected non-tool session response on PACT stdio transport"
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
                    "unexpected resource/prompt session failure on PACT stdio transport"
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
    response: pact_kernel::ToolCallResponse,
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
        (pact_kernel::Verdict::Allow, _, Some(ToolCallOutput::Value(value))) => {
            ToolCallResult::Ok { value }
        }
        (pact_kernel::Verdict::Allow, _, Some(ToolCallOutput::Stream(_))) => {
            ToolCallResult::StreamComplete {
                total_chunks: chunks_received,
            }
        }
        (pact_kernel::Verdict::Deny, OperationTerminalState::Cancelled { reason }, _) => {
            ToolCallResult::Cancelled {
                reason,
                chunks_received,
            }
        }
        (pact_kernel::Verdict::Deny, OperationTerminalState::Incomplete { reason }, _) => {
            ToolCallResult::Incomplete {
                reason,
                chunks_received,
            }
        }
        (pact_kernel::Verdict::Deny, OperationTerminalState::Completed, _) => ToolCallResult::Err {
            error: ToolCallError::PolicyDenied {
                guard: "kernel".to_string(),
                reason: response
                    .reason
                    .unwrap_or_else(|| "denied by policy".to_string()),
            },
        },
        (pact_kernel::Verdict::Allow, _, None) => ToolCallResult::Ok {
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
    _kernel: &mut PactKernel,
    request: &KernelToolCallRequest,
) -> Result<pact_core::PactReceipt, pact_core::error::Error> {
    // Attempt to build a proper deny receipt through the kernel.
    // If that also fails (unlikely), produce a minimal placeholder.
    let action = pact_core::receipt::ToolCallAction::from_parameters(request.arguments.clone());
    let action = match action {
        Ok(a) => a,
        Err(_) => pact_core::receipt::ToolCallAction::from_parameters(serde_json::json!({}))
            .unwrap_or_else(|_| {
                // This path should never be reached, but if it is, we have a
                // truly minimal fallback.
                pact_core::receipt::ToolCallAction {
                    parameter_hash: "error".to_string(),
                    parameters: serde_json::json!({}),
                }
            }),
    };

    // Sign a receipt with the kernel's key by issuing a capability for this
    // purpose and using the kernel's existing receipt-signing infrastructure.
    // Since we only have pub methods, we use a simplified approach.
    let kp = Keypair::generate();
    let body = pact_core::receipt::PactReceiptBody {
        id: format!("rcpt-error-{}", request.request_id),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        capability_id: request.capability.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        action,
        decision: pact_core::receipt::Decision::Deny {
            reason: "internal kernel error".to_string(),
            guard: "kernel".to_string(),
        },
        content_hash: pact_core::sha256_hex(b"null"),
        policy_hash: "error".to_string(),
        evidence: vec![],
        metadata: None,
        kernel_key: kp.public_key(),
    };

    pact_core::receipt::PactReceipt::sign(body, &kp)
}

struct StubToolServer {
    id: String,
}

impl pact_kernel::ToolServerConnection for StubToolServer {
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
        _nested_flow_bridge: Option<&mut dyn pact_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, pact_kernel::KernelError> {
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
impl pact_kernel::ToolServerConnection for StubStreamingToolServer {
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
        _nested_flow_bridge: Option<&mut dyn pact_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, pact_kernel::KernelError> {
        Ok(serde_json::json!({"unused": true}))
    }

    fn invoke_stream(
        &self,
        _tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn pact_kernel::NestedFlowBridge>,
    ) -> Result<Option<pact_kernel::ToolServerStreamResult>, pact_kernel::KernelError> {
        let stream = ToolCallStream {
            chunks: vec![
                pact_kernel::ToolCallChunk {
                    data: serde_json::json!({"delta": "hello"}),
                },
                pact_kernel::ToolCallChunk {
                    data: serde_json::json!({"delta": arguments}),
                },
            ],
        };

        if self.incomplete {
            Ok(Some(pact_kernel::ToolServerStreamResult::Incomplete {
                stream,
                reason: "stream source ended before final frame".to_string(),
            }))
        } else {
            Ok(Some(pact_kernel::ToolServerStreamResult::Complete(stream)))
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
        eprintln!("--- pact session summary ---");
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

    fn load_test_policy_runtime(policy: &policy::PactPolicy) -> policy::LoadedPolicy {
        let default_capabilities = policy::build_runtime_default_capabilities(policy).unwrap();

        policy::LoadedPolicy {
            format: policy::PolicyFormat::PactYaml,
            identity: policy::PolicyIdentity {
                source_hash: "test-source-hash".to_string(),
                runtime_hash: "test-runtime-hash".to_string(),
            },
            kernel: policy.kernel.clone(),
            default_capabilities,
            guard_pipeline: policy::build_guard_pipeline(&policy.guards),
            issuance_policy: None,
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
        kernel: &PactKernel,
        policy: &policy::PactPolicy,
        agent_kp: &Keypair,
    ) -> pact_core::CapabilityToken {
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
        kernel: &mut PactKernel,
        agent_id: &str,
        capabilities: Vec<pact_core::CapabilityToken>,
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
        let revocation_db_path = unique_db_path("pact-cli-revocations");
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
        };

        let response = restarted.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, pact_kernel::Verdict::Deny);
        assert!(response.reason.as_deref().unwrap_or("").contains("revoked"));

        let _ = std::fs::remove_file(revocation_db_path);
    }

    #[test]
    fn authority_seed_file_persists_public_key_across_loads_and_rotation() {
        let seed_path = unique_seed_path("pact-cli-authority");
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
        let seed_path = unique_seed_path("pact-cli-configure-authority");
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
        let authority_db_path = unique_db_path("pact-cli-authority-db");
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

        let authority = pact_kernel::SqliteCapabilityAuthority::open(&authority_db_path).unwrap();
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
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, pact_kernel::Verdict::Allow);
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
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, pact_kernel::Verdict::Deny);
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
