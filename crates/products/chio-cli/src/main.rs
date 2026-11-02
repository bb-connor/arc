#![allow(clippy::large_enum_variant, clippy::too_many_arguments)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

// Chio CLI -- command-line interface for the Chio runtime kernel.
//
// Provides commands for:
//
// - `chio run --policy <path> -- <command> [args...]`
//   Spawn an agent subprocess, set up the length-prefixed transport over
//   stdin/stdout pipes, and run the kernel message loop.
//
// - `chio check --policy <path> --tool <name> --params <json>`
//   Load a policy, create a kernel, and evaluate one tool call in preflight
//   mode, or in full mode with an explicit output fixture.
//
// - `chio mcp serve --policy <path> --server-id <id> -- <command> [args...]`
//   Wrap an MCP server subprocess with the Chio kernel and expose an
//   MCP-compatible edge over stdio for stock MCP clients.

mod active_defense_migration;
mod active_response_authority;
mod admin;
mod archive;
mod cert;
mod commands {
    pub mod bind;
    pub mod guard_blocklist;
}
mod did;
mod doctor;
mod guard;
mod guards;
mod lineage;
mod market;
mod passport;
mod policies;
mod scaffold;
mod settle;
mod supervise;

// Shared imports for the CLI module tree. These live at the crate root so the
// `cli/*` submodules (which each begin with `use super::*;`) inherit them,
// matching the single coherent `#[path] mod` strategy. The `pub use`
// re-exports keep `crate::CliError`, `crate::policy`, and the sibling
// control-plane modules reachable from the standalone `src/*.rs` command
// modules.
pub use chio_control_plane::{
    authority_public_key_from_seed_file, build_kernel, certify, configure_budget_store,
    configure_capability_authority, configure_receipt_store, configure_revocation_store,
    durable_admission_sidecar_path, enterprise_federation, evidence_export, federation_policy,
    issuance, issue_default_capabilities, load_existing_authority_keypair,
    load_or_create_authority_keypair, open_durable_admission_runtime, passport_verifier, policy,
    reputation, require_control_token, rotate_authority_keypair, scim_lifecycle, trust_control,
    validate_distinct_database_paths, validate_durable_admission_participant_paths, CliError,
    DurableAdmissionRuntime,
};
pub use chio_mcp_remote as remote_mcp;

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;
use tracing::{debug, error, info, warn};

use chio_api_protect::{ProtectConfig, ProtectProxy};
use chio_core::appraisal::{
    RuntimeAttestationAppraisalImportRequest, RuntimeAttestationAppraisalRequest,
    RuntimeAttestationAppraisalResultExportRequest, RuntimeAttestationImportedAppraisalPolicy,
    SignedRuntimeAttestationAppraisalResult,
};
use chio_core::capability::{
    governance::GovernedAutonomyTier,
    runtime_attestation::{RuntimeAssuranceTier, RuntimeAttestationEvidence},
    scope::{ChioScope, MonetaryAmount},
};
use chio_core::crypto::Keypair;
use chio_core::message::{AgentMessage, KernelMessage, ToolCallError, ToolCallResult};
use chio_core::session::{
    OperationContext, OperationTerminalState, RequestId, SessionId, SessionOperation,
    ToolCallOperation,
};
use chio_kernel::transport::{ChioTransport, TransportError};
use chio_kernel::{
    ChioKernel, RevocationStore, SessionOperationResponse, ToolCallOutput, ToolCallStream,
};
use chio_mcp_adapter::adapter::McpAdapterConfig;
use chio_mcp_adapter::edge::{ChioMcpEdge, McpEdgeConfig};
use chio_mcp_adapter::server::AdaptedMcpServer;

use crate::policy::load_policy;

#[path = "cli/types.rs"]
mod types_cli;
pub(crate) use types_cli::{
    ApiCommands, ArenaCommands, AuthorityDeploymentCommands, AuthorityStoreCommands, CertCommands,
    CertifyCommands, CertifyRegistryCommands, CheckMode, ChioAttestCommands, ChioBuyerCommands,
    ChioFederationCommands, ChioRuntimeQuoteCommands, ChioSupplyChainCommands, Cli, Commands,
    CommerceCommands, ConformanceCommands, DidCommands, EvidenceCommands,
    EvidenceFederationPolicyCommands, GuardBlocklistCommands, GuardCommands, GuardMarketCommands,
    LineageCommands, McpCommands, OutputFormat, PassportChallengeCommands, PassportCommands,
    PassportIssuanceCommands, PassportOid4vpCommands, PassportPolicyCommands,
    PassportStatusCommands, PolicyAnalysisFailOn, PolicyCommands, ProofCollectKind, ProofCommands,
    ProofDoctorScenario, ProofExportRedactProfile, ProofFixtureCommands, ProofVerifyRequirement,
    ReceiptCheckpointCommands, ReceiptCommands, ReceiptRetentionCommands, ReplayArgs,
    ReplaySubcommand, ReputationCommands, SecurityCommands, SettleCommands, TrafficArgs,
    TrustAuthorizationContextCommands, TrustBehavioralFeedCommands, TrustCapitalAllocationCommands,
    TrustCapitalBookCommands, TrustCapitalInstructionCommands, TrustCommands, TrustConfigCommands,
    TrustCreditBacktestCommands, TrustCreditBondCommands, TrustCreditFacilityCommands,
    TrustCreditLossLifecycleCommands, TrustCreditScorecardCommands, TrustEmergencyCommands,
    TrustEvidenceShareCommands, TrustExposureLedgerCommands, TrustFederationPolicyCommands,
    TrustLiabilityMarketCommands, TrustLiabilityProviderCommands, TrustProviderCommands,
    TrustProviderRiskPackageCommands, TrustRuntimeAttestationAppraisalCommands,
    TrustUnderwritingAppealCommands, TrustUnderwritingDecisionCommands,
    TrustUnderwritingInputCommands, WorkflowCommands,
};
#[cfg(feature = "finding-market")]
pub(crate) use types_cli::{
    FindingChallengeClassArg, FindingCommands, FindingOperatorCommands, FindingPackageCommands,
};
#[path = "cli/chio/types.rs"]
mod chio_types;
use chio_types::{
    ChioAuthorityCommands, ChioPheromoneCommands, ChioPheromoneRelayAlertAssuranceArchiveCommands,
    ChioPheromoneRelayAlertAssuranceArchivePackageCommands,
    ChioPheromoneRelayAlertAssuranceArchiveRestoreDrillCommands,
    ChioPheromoneRelayAlertAssuranceCloseoutCommands, ChioPheromoneRelayAlertAssuranceCommands,
    ChioPheromoneRelayAlertAssurancePhysicalDrillCommands,
    ChioPheromoneRelayAlertAssuranceRetentionCommands,
    ChioPheromoneRelayAlertAssuranceRetentionHandoffCommands, ChioPheromoneRelayAlertCommands,
    ChioPheromoneRelayAlertDeliveryCommands, ChioPheromoneRelayCommands,
    ChioPheromoneRelayDirectoryCommands, ChioPheromoneRelaySupervisorCommands, ChioRuntimeCommands,
    ChioRuntimeOpsCommands, ChioRuntimeOpsRetentionCommands, ChioRuntimeOrchestrateCommands,
    ChioRuntimePeerWeightsCommands, ChioRuntimePheromoneCommands, ChioRuntimePolicyCommands,
    ChioTreatyCommands, ChioTrustBundleCommands,
};
#[path = "cli/doctor.rs"]
mod doctor_cli;
#[path = "cli/security_preflight.rs"]
mod security_preflight_cli;
pub(crate) use security_preflight_cli::{cmd_security_preflight, PreflightArgs, PreflightStores};
#[path = "cli/security_supervise.rs"]
mod security_supervise_cli;
pub(crate) use doctor_cli::{cmd_doctor, render_doctor_json, render_titled_human, DoctorArgs};
pub(crate) use security_supervise_cli::{cmd_security_supervise, SuperviseArgs};
#[path = "cli/dispatch/mod.rs"]
mod dispatch_cli;
#[cfg(test)]
pub(crate) use dispatch_cli::{cmd_chio_attest_runtime_quote_verify, write_cli_error};
#[path = "cli/chio/dispatch.rs"]
mod chio_dispatch;
use chio_dispatch::*;

fn main() {
    #[cfg(not(windows))]
    dispatch_cli::run();

    // The Windows process main thread has a smaller default stack than the
    // generated clap parser needs as the command surface grows. Keep parsing
    // and dispatch on an explicitly bounded worker so even lightweight
    // commands such as `chio init` cannot overflow before dispatch.
    #[cfg(windows)]
    {
        let worker = match std::thread::Builder::new()
            .name("chio-cli-dispatch".to_owned())
            .stack_size(8 * 1024 * 1024)
            .spawn(dispatch_cli::run)
        {
            Ok(worker) => worker,
            Err(error) => {
                eprintln!("fatal: failed to start CLI dispatch: {error}");
                std::process::exit(1);
            }
        };
        if worker.join().is_err() {
            eprintln!("fatal: CLI dispatch panicked");
            std::process::exit(1);
        }
    }
}
#[path = "cli/process_host.rs"]
mod process_host;
#[path = "cli/runtime.rs"]
mod runtime_cli;
pub(crate) use runtime_cli::{
    cmd_api_protect, cmd_check, cmd_mcp_serve, cmd_mcp_serve_http, cmd_run, cmd_start,
    cmd_trust_revoke, cmd_trust_serve, cmd_trust_status, load_roster_policy,
    parse_capital_authority_keys, require_local_capital_authority, require_receipt_db_path,
};
#[path = "cli/runtime/trust_reports.rs"]
mod runtime_trust_reports;
#[path = "cli/trust_commands.rs"]
mod trust_commands_cli;
#[path = "cli/trust_config_check.rs"]
mod trust_config_check;
pub(crate) use trust_commands_cli::{
    cmd_receipt_audit, cmd_receipt_checkpoint_create, cmd_receipt_checkpoint_status,
    cmd_receipt_explain, cmd_receipt_flush, cmd_receipt_health, cmd_receipt_list,
    cmd_receipt_retention_repair, cmd_trust_credit_backtest_export,
    cmd_trust_credit_loss_lifecycle_evaluate, cmd_trust_credit_loss_lifecycle_issue,
    cmd_trust_credit_loss_lifecycle_list, cmd_trust_liability_auto_bind_issue,
    cmd_trust_liability_bound_coverage_issue, cmd_trust_liability_claim_adjudication_issue,
    cmd_trust_liability_claim_dispute_issue, cmd_trust_liability_claim_issue,
    cmd_trust_liability_claim_payout_instruction_issue,
    cmd_trust_liability_claim_payout_receipt_issue, cmd_trust_liability_claim_response_issue,
    cmd_trust_liability_claim_settlement_instruction_issue,
    cmd_trust_liability_claim_settlement_receipt_issue, cmd_trust_liability_claims_list,
    cmd_trust_liability_market_list, cmd_trust_liability_placement_issue,
    cmd_trust_liability_pricing_authority_issue, cmd_trust_liability_provider_issue,
    cmd_trust_liability_provider_list, cmd_trust_liability_provider_resolve,
    cmd_trust_liability_quote_request_issue, cmd_trust_liability_quote_response_issue,
    cmd_trust_provider_risk_package_export, cmd_trust_runtime_attestation_appraisal_export,
    cmd_trust_runtime_attestation_appraisal_import,
    cmd_trust_runtime_attestation_appraisal_result_export, cmd_trust_underwriting_appeal_create,
    cmd_trust_underwriting_appeal_resolve, cmd_trust_underwriting_decision_evaluate,
    cmd_trust_underwriting_decision_issue, cmd_trust_underwriting_decision_list,
    cmd_trust_underwriting_decision_simulate, cmd_trust_underwriting_input_export,
    load_credit_bonded_execution_control_policy, load_json_or_yaml, parse_credit_bond_disposition,
    parse_credit_bond_lifecycle_state, parse_credit_facility_disposition,
    parse_credit_facility_lifecycle_state, parse_credit_loss_lifecycle_event_kind,
    parse_governed_autonomy_tier, parse_runtime_assurance_tier, trusted_kernel_keys_from_authority,
    BudgetQueryBackend, CreditBacktestExportArgs, CreditLossLifecycleListArgs,
    LiabilityClaimsListArgs, LiabilityMarketListArgs, ProviderRiskPackageExportArgs, QueryBackend,
    ReceiptExplainArgs, ReceiptListArgs, SignedQueryBackend, UnderwritingAppealResolveArgs,
    UnderwritingDecisionIssueArgs, UnderwritingDecisionListArgs, UnderwritingDecisionSimulateArgs,
    UnderwritingPolicyInputArgs,
};
#[cfg(test)]
pub(crate) use trust_commands_cli::{
    load_runtime_attestation_evidence, load_signed_runtime_attestation_appraisal_result,
    load_underwriting_decision_policy,
};
#[path = "cli/session/mod.rs"]
mod session_cli;
pub(crate) use session_cli::{
    handle_agent_message, print_summary, select_capability_for_request, SessionStats,
};
#[path = "cli/conformance.rs"]
mod conformance_cli;
pub(crate) use conformance_cli::{cmd_conformance_fetch_peers, cmd_conformance_run};
#[path = "cli/mcp.rs"]
mod mcp_cli;
pub(crate) use mcp_cli::{cmd_mcp_governed_sim, cmd_mcp_wrap, GovernedSimArgs, McpWrapArgs};
#[path = "cli/replay.rs"]
mod replay_cli;
pub(crate) use replay_cli::{cmd_replay, load_trusted_kernel_pubkey};

#[path = "cli/arena.rs"]
mod arena_cli;
#[path = "cli/input.rs"]
mod input;
#[path = "cli/process_response_verify.rs"]
mod process_response_verify;
#[path = "cli/receipt_verify.rs"]
mod receipt_verify;
pub(crate) use arena_cli::{cmd_arena_evolve, cmd_arena_replay, cmd_arena_run};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "main_tests_support.rs"]
mod cli_entrypoint_support;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "main_tests_parsing.rs"]
mod cli_entrypoint_parsing_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "main_tests_surfaces.rs"]
mod cli_entrypoint_surface_tests;
