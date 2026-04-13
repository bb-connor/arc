//! HushSpec policy schema types.
//!
//! Ported from the HushSpec reference implementation. These types define the
//! canonical YAML schema for AI agent security policies.

use std::collections::BTreeMap;

use arc_core::appraisal::AttestationVerifierFamily;
use arc_core::capability::{
    MonetaryAmount, RuntimeAssuranceTier, WorkloadCredentialKind, WorkloadIdentityScheme,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MergeStrategy {
    Replace,
    Merge,
    #[default]
    DeepMerge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    Error,
    Warn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    Allow,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ComputerUseMode {
    Observe,
    #[default]
    Guardrail,
    FailClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionTrigger {
    UserApproval,
    UserDenial,
    CriticalViolation,
    AnyViolation,
    Timeout,
    BudgetExhausted,
    PatternMatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OriginDefaultBehavior {
    #[default]
    Deny,
    MinimalProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionLevel {
    Safe,
    Suspicious,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Draft,
    Review,
    Approved,
    Deployed,
    Deprecated,
    Archived,
}

// ---------------------------------------------------------------------------
// Top-level spec
// ---------------------------------------------------------------------------

/// A HushSpec policy document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HushSpec {
    pub hushspec: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_strategy: Option<MergeStrategy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Rules>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<GovernanceMetadata>,
}

impl HushSpec {
    /// Parse a HushSpec document from a YAML string.
    pub fn parse(yaml: &str) -> Result<Self, serde_yml::Error> {
        serde_yml::from_str(yaml)
    }

    /// Serialize this spec to a YAML string.
    pub fn to_yaml(&self) -> Result<String, serde_yml::Error> {
        serde_yml::to_string(self)
    }
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forbidden_paths: Option<ForbiddenPathsRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_allowlist: Option<PathAllowlistRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_patterns: Option<SecretPatternsRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch_integrity: Option<PatchIntegrityRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_commands: Option<ShellCommandsRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_access: Option<ToolAccessRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computer_use: Option<ComputerUseRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_desktop_channels: Option<RemoteDesktopChannelsRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_injection: Option<InputInjectionRule>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenPathsRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub exceptions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathAllowlistRule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub patch: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default = "default_block")]
    pub default: DefaultAction,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPattern {
    pub name: String,
    pub pattern: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPatternsRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub patterns: Vec<SecretPattern>,
    #[serde(default)]
    pub skip_paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchIntegrityRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_1000")]
    pub max_additions: usize,
    #[serde(default = "default_500")]
    pub max_deletions: usize,
    #[serde(default)]
    pub forbidden_patterns: Vec<String>,
    #[serde(default)]
    pub require_balance: bool,
    #[serde(default = "default_imbalance_ratio")]
    pub max_imbalance_ratio: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellCommandsRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub forbidden_patterns: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAccessRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub require_confirmation: Vec<String>,
    #[serde(default = "default_allow")]
    pub default: DefaultAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_args_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_runtime_assurance_tier: Option<RuntimeAssuranceTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer_runtime_assurance_tier: Option<RuntimeAssuranceTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_workload_identity: Option<WorkloadIdentityMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer_workload_identity: Option<WorkloadIdentityMatch>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentityMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<WorkloadIdentityScheme>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub credential_kinds: Vec<WorkloadCredentialKind>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputerUseRule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_guardrail")]
    pub mode: ComputerUseMode,
    #[serde(default)]
    pub allowed_actions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteDesktopChannelsRule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub clipboard: bool,
    #[serde(default)]
    pub file_transfer: bool,
    #[serde(default = "default_true")]
    pub audio: bool,
    #[serde(default)]
    pub drive_mapping: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputInjectionRule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_types: Vec<String>,
    #[serde(default)]
    pub require_postcondition_probe: bool,
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Extensions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureExtension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origins: Option<OriginsExtension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection: Option<DetectionExtension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation: Option<ReputationExtension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance: Option<RuntimeAssuranceExtension>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureExtension {
    pub initial: String,
    pub states: BTreeMap<String, PostureState>,
    pub transitions: Vec<PostureTransition>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub budgets: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureTransition {
    pub from: String,
    pub to: String,
    pub on: TransitionTrigger,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginsExtension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_behavior: Option<OriginDefaultBehavior>,
    #[serde(default)]
    pub profiles: Vec<OriginProfile>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginProfile {
    pub id: String,
    #[serde(rename = "match", default, skip_serializing_if = "Option::is_none")]
    pub match_rules: Option<OriginMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_access: Option<ToolAccessRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<OriginDataPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budgets: Option<OriginBudgets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<BridgePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_participants: Option<bool>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginDataPolicy {
    #[serde(default)]
    pub allow_external_sharing: bool,
    #[serde(default)]
    pub redact_before_send: bool,
    #[serde(default)]
    pub block_sensitive_outputs: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginBudgets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_calls: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_commands: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgePolicy {
    #[serde(default)]
    pub allow_cross_origin: bool,
    #[serde(default)]
    pub allowed_targets: Vec<BridgeTarget>,
    #[serde(default)]
    pub require_approval: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionExtension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_injection: Option<PromptInjectionDetection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jailbreak: Option<JailbreakDetection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_intel: Option<ThreatIntelDetection>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationExtension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoring: Option<ReputationScoringConfig>,
    #[serde(default)]
    pub tiers: BTreeMap<String, ReputationTier>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationScoringConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weights: Option<ReputationWeights>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporal_decay_half_life_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probationary_receipt_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probationary_score_ceiling: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probationary_min_days: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationWeights {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary_pressure: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_stewardship: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub least_privilege: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_depth: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_diversity: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_hygiene: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_correlation: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationTier {
    pub score_range: [f64; 2],
    pub max_scope: ReputationTierScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion: Option<ReputationPromotion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demotion: Option<ReputationDemotion>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationTierScope {
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_per_invocation: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_cost: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u32>,
    pub ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints_required: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationPromotion {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_receipts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_metrics: Option<ReputationRequiredMetrics>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationRequiredMetrics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary_pressure_max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability_min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub least_privilege_min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_hygiene_min: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationDemotion {
    pub target: String,
    #[serde(default)]
    pub triggers: Vec<ReputationTrigger>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationTrigger {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAssuranceExtension {
    #[serde(default)]
    pub tiers: BTreeMap<String, RuntimeAssuranceTierRule>,
    #[serde(default)]
    pub trusted_verifiers: BTreeMap<String, RuntimeAssuranceVerifierRule>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAssuranceTierRule {
    pub minimum_attestation_tier: RuntimeAssuranceTier,
    pub max_scope: ReputationTierScope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAssuranceVerifierRule {
    pub schema: String,
    pub verifier: String,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_family: Option<AttestationVerifierFamily>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_evidence_age_seconds: Option<u64>,
    #[serde(default)]
    pub allowed_attestation_types: Vec<String>,
    #[serde(default)]
    pub required_assertions: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptInjectionDetection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_at_or_above: Option<DetectionLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_at_or_above: Option<DetectionLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_scan_bytes: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailbreakDetection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_threshold: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_threshold: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_bytes: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatIntelDetection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern_db: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub similarity_threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<usize>,
}

// ---------------------------------------------------------------------------
// Governance metadata
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<Classification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_ticket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<LifecycleState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_date: Option<String>,
}

// ---------------------------------------------------------------------------
// Default value helpers
// ---------------------------------------------------------------------------

fn default_1000() -> usize {
    1000
}

fn default_500() -> usize {
    500
}

fn default_allow() -> DefaultAction {
    DefaultAction::Allow
}

fn default_block() -> DefaultAction {
    DefaultAction::Block
}

fn default_guardrail() -> ComputerUseMode {
    ComputerUseMode::Guardrail
}

fn default_imbalance_ratio() -> f64 {
    10.0
}

fn default_true() -> bool {
    true
}
