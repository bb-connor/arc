//! HushSpec-to-Chio compiler.
//!
//! This is the key bridge between HushSpec policies and Chio's guard pipeline.
//! It translates HushSpec rule blocks into configured Chio guards and builds
//! a default capability scope from the policy's tool_access rules.
//!
//! # Guard coverage
//!
//! The compiler materializes 12 distinct guard types from a HushSpec
//! document. The first seven are driven directly by the `rules` section; the
//! remaining five are driven either by the `extensions.detection`
//! sub-section or by auxiliary semantics layered on top of existing rule
//! blocks (SSRF protection on egress, per-agent velocity from origin
//! budgets).
//!
//! | # | Guard | Triggered by |
//! |---|----------------------------|----------------------------------------|
//! | 1 | `ForbiddenPathGuard`       | `rules.forbidden_paths` |
//! | 2 | `ShellCommandGuard`        | `rules.shell_commands` |
//! | 3 | `EgressAllowlistGuard`     | `rules.egress` |
//! | 4 | `McpToolGuard`             | `rules.tool_access` |
//! | 5 | `SecretLeakGuard`          | `rules.secret_patterns` |
//! | 6 | `PatchIntegrityGuard`      | `rules.patch_integrity` |
//! | 7 | `PathAllowlistGuard`       | `rules.path_allowlist` |
//! | 8 | `PromptInjectionGuard`     | `extensions.detection.prompt_injection`|
//! | 9 | `JailbreakGuard`           | `extensions.detection.jailbreak` |
//! |10 | `EmbeddingAnomalyGuard`         | `extensions.detection.threat_intel` |
//! |11 | `InternalNetworkGuard`     | `rules.egress` (SSRF companion) |
//! |12 | `AgentVelocityGuard`       | `extensions.origins.profiles[].budgets` |

mod budgets;
mod detection;
mod patterns;
mod rules;
mod scope;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::models::HushSpec;

use chio_core::capability::scope::ChioScope;
use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequirement, ThresholdApprovalRequirementResolver,
    ThresholdApprovalResolutionError, DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS,
};
use chio_core::crypto::{PublicKey, SigningAlgorithm};
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_guards::{GuardPipeline, PostInvocationPipeline};
use chio_kernel::MemoryBudgetConfig;

use budgets::compile_budget_guards;
use detection::compile_detection_guards;
use rules::compile_rule_guards;
use scope::compile_scope;

/// Errors that can occur during policy compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("invalid policy: {0}")]
    Invalid(String),
}

/// The result of compiling a HushSpec policy into Chio primitives.
pub struct CompiledPolicy {
    /// A guard pipeline configured from the policy's rule blocks.
    pub guards: GuardPipeline,
    /// A post-invocation pipeline configured from the policy's rule blocks.
    pub post_invocation: PostInvocationPipeline,
    /// A default capability scope derived from the policy's tool_access rules.
    pub default_scope: ChioScope,
    /// Ordered list of guard names emitted by compilation.
    ///
    /// The compiler is required to emit a
    /// `Vec<Box<dyn Guard>>` containing all 12 guard types; because
    /// [`GuardPipeline`] does not publicly expose its contained guards,
    /// this sidecar records the `Guard::name()` of each guard added to the
    /// pipeline in insertion order. Deduplicated, this is the set of
    /// concrete guard types that compiled successfully.
    pub guard_names: Vec<String>,
    /// Policy-authoritative governed-approval requirement, when configured.
    pub threshold_approval: Option<ThresholdApprovalResolverSnapshot>,
}

/// Authenticated, immutable approver-directory view used during compilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedApproverDirectorySnapshot {
    version: u64,
    entries: BTreeMap<String, PublicKey>,
}

impl AuthenticatedApproverDirectorySnapshot {
    /// Build the initial directory profile from self-authenticating Ed25519 IDs.
    pub fn from_self_authenticating_hex_keys(
        version: u64,
        approver_ids: Vec<String>,
    ) -> Result<Self, CompileError> {
        if version == 0 {
            return Err(CompileError::Invalid(
                "approver directory version must be non-zero".to_string(),
            ));
        }
        let mut entries = BTreeMap::new();
        let mut fingerprints = BTreeSet::new();
        for approver_id in approver_ids {
            if approver_id.is_empty() || approver_id.trim() != approver_id {
                return Err(CompileError::Invalid(
                    "approver directory identifier is empty or not normalized".to_string(),
                ));
            }
            let public_key = PublicKey::from_hex(&approver_id).map_err(|_| {
                CompileError::Invalid(format!(
                    "approver directory identifier `{approver_id}` is not a supported self-authenticating hex public key"
                ))
            })?;
            if public_key.algorithm() != SigningAlgorithm::Ed25519 {
                return Err(CompileError::Invalid(format!(
                    "approver directory identifier `{approver_id}` uses an unsupported key algorithm"
                )));
            }
            if entries
                .insert(approver_id.clone(), public_key.clone())
                .is_some()
            {
                return Err(CompileError::Invalid(format!(
                    "approver directory contains duplicate identifier `{approver_id}`"
                )));
            }
            if !fingerprints.insert(public_key.to_hex()) {
                return Err(CompileError::Invalid(
                    "approver directory contains the same public key more than once".to_string(),
                ));
            }
        }
        Ok(Self { version, entries })
    }

    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    fn resolve(&self, approver_id: &str) -> Option<&PublicKey> {
        self.entries.get(approver_id)
    }
}

/// Immutable resolver materialization bound to one loaded policy version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdApprovalResolverSnapshot {
    requirement: ThresholdApprovalRequirement,
}

impl ThresholdApprovalResolverSnapshot {
    #[must_use]
    pub fn requirement(&self) -> Option<ThresholdApprovalRequirement> {
        Some(self.requirement.clone())
    }

    #[must_use]
    pub fn policy_hash(&self) -> &str {
        self.requirement.policy_hash()
    }

    /// Rebind compilation output to the composition layer's complete runtime hash.
    pub fn with_policy_hash(self, policy_hash: impl Into<String>) -> Result<Self, CompileError> {
        let requirement = ThresholdApprovalRequirement::new(
            self.requirement.required(),
            self.requirement.eligible().clone(),
            self.requirement.proposal_timeout_seconds(),
            policy_hash,
            self.requirement.approver_directory_version(),
        )
        .map_err(|error| CompileError::Invalid(error.to_string()))?;
        Ok(Self { requirement })
    }
}

/// Atomically replaceable trusted resolver installed by the composition layer.
#[derive(Clone)]
pub struct ThresholdApprovalResolver {
    snapshot: Arc<RwLock<ThresholdApprovalResolverSnapshot>>,
}

impl ThresholdApprovalResolver {
    #[must_use]
    pub fn new(snapshot: ThresholdApprovalResolverSnapshot) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(snapshot)),
        }
    }

    pub fn replace_snapshot(
        &self,
        replacement: ThresholdApprovalResolverSnapshot,
    ) -> Result<(), ThresholdApprovalResolutionError> {
        let mut snapshot = self.snapshot.write().map_err(|_| {
            ThresholdApprovalResolutionError::Corrupt(
                "threshold approval resolver lock is poisoned".to_string(),
            )
        })?;
        let current_version = snapshot.requirement.approver_directory_version();
        let replacement_version = replacement.requirement.approver_directory_version();
        if replacement_version < current_version {
            return Err(ThresholdApprovalResolutionError::Corrupt(format!(
                "approver directory version regressed from {current_version} to {replacement_version}"
            )));
        }
        *snapshot = replacement;
        Ok(())
    }
}

impl ThresholdApprovalRequirementResolver for ThresholdApprovalResolver {
    fn resolve_threshold_approval_requirement(
        &self,
        _matched_request: &chio_core::capability::threshold_approval::ThresholdApprovalRequest,
        policy_hash: &str,
    ) -> Result<ThresholdApprovalRequirement, ThresholdApprovalResolutionError> {
        let snapshot = self.snapshot.read().map_err(|_| {
            ThresholdApprovalResolutionError::Corrupt(
                "threshold approval resolver lock is poisoned".to_string(),
            )
        })?;
        if snapshot.requirement.policy_hash() != policy_hash {
            return Err(ThresholdApprovalResolutionError::StalePolicy {
                expected: snapshot.requirement.policy_hash().to_string(),
                received: policy_hash.to_string(),
            });
        }
        Ok(snapshot.requirement.clone())
    }
}

/// Compile a HushSpec policy into a Chio guard pipeline and default scope.
///
/// This maps HushSpec rule blocks and detection-extension blocks to Chio
/// guard configurations. See the module-level documentation for the full
/// mapping table. Missing sections compile to an empty pipeline; no error
/// is raised for policies that do not exercise every guard type.
///
/// Uses the DEFAULT process memory budget for bounded-collection caps (e.g. the
/// velocity guard's bucket cap). Deployments that lower the process memory budget
/// should use [`compile_policy_with_memory_budget`] so the configured caps reach
/// the compiled guards.
pub fn compile_policy(policy: &HushSpec) -> Result<CompiledPolicy, CompileError> {
    compile_policy_with_source(policy, None)
}

/// Compile a HushSpec policy with an optional source path used to resolve
/// relative auxiliary assets referenced by the policy. Uses the DEFAULT process
/// memory budget; see [`compile_policy_with_memory_budget`].
pub fn compile_policy_with_source(
    policy: &HushSpec,
    source_path: Option<&Path>,
) -> Result<CompiledPolicy, CompileError> {
    compile_policy_with_memory_budget(policy, source_path, &MemoryBudgetConfig::defaults())
}

/// Compile a HushSpec policy threading a CONFIGURED process memory budget into
/// the bounded-collection guards. Lowering `velocity_bucket_cap` on `budget`
/// tightens the compiled velocity guard's bucket cap instead of it silently
/// using the compiled-in default.
pub fn compile_policy_with_memory_budget(
    policy: &HushSpec,
    source_path: Option<&Path>,
    budget: &MemoryBudgetConfig,
) -> Result<CompiledPolicy, CompileError> {
    compile_policy_with_authorities(policy, source_path, budget, None)
}

/// Compile policy-owned approvers against an authenticated directory snapshot.
pub fn compile_policy_with_approver_directory(
    policy: &HushSpec,
    directory: &AuthenticatedApproverDirectorySnapshot,
) -> Result<CompiledPolicy, CompileError> {
    compile_policy_with_authorities(
        policy,
        None,
        &MemoryBudgetConfig::defaults(),
        Some(directory),
    )
}

/// Compile with source-relative assets and an authenticated approver directory.
pub fn compile_policy_with_source_and_approver_directory(
    policy: &HushSpec,
    source_path: Option<&Path>,
    directory: &AuthenticatedApproverDirectorySnapshot,
) -> Result<CompiledPolicy, CompileError> {
    compile_policy_with_authorities(
        policy,
        source_path,
        &MemoryBudgetConfig::defaults(),
        Some(directory),
    )
}

fn compile_policy_with_authorities(
    policy: &HushSpec,
    source_path: Option<&Path>,
    budget: &MemoryBudgetConfig,
    approver_directory: Option<&AuthenticatedApproverDirectorySnapshot>,
) -> Result<CompiledPolicy, CompileError> {
    ensure_compilable_policy(policy)?;

    let mut builder = PipelineBuilder::new();
    let mut post_invocation = PostInvocationPipeline::new();
    let source_dir = source_path.and_then(|path| path.parent());
    compile_rule_guards(policy, &mut builder, &mut post_invocation, budget)?;
    compile_detection_guards(policy, &mut builder, source_dir)?;
    compile_budget_guards(policy, &mut builder, budget)?;
    let default_scope = compile_scope(policy)?;
    let threshold_approval = compile_threshold_approval(policy, approver_directory)?;
    let (guards, guard_names) = builder.finish();
    Ok(CompiledPolicy {
        guards,
        post_invocation,
        default_scope,
        guard_names,
        threshold_approval,
    })
}

fn compile_threshold_approval(
    policy: &HushSpec,
    directory: Option<&AuthenticatedApproverDirectorySnapshot>,
) -> Result<Option<ThresholdApprovalResolverSnapshot>, CompileError> {
    let Some(approvers) = policy
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.chio.as_ref())
        .and_then(|chio| chio.human_in_loop.as_ref())
        .and_then(|human_in_loop| human_in_loop.approvers.as_ref())
    else {
        return Ok(None);
    };
    let directory = directory.ok_or_else(|| {
        CompileError::Invalid(
            "threshold approval policy requires an authenticated approver directory".to_string(),
        )
    })?;
    let eligible = approvers
        .of
        .iter()
        .map(|approver_id| {
            directory
                .resolve(approver_id)
                .cloned()
                .map(|public_key| (approver_id.clone(), public_key))
                .ok_or_else(|| {
                    CompileError::Invalid(format!(
                        "approver `{approver_id}` is not present in approver directory version {}",
                        directory.version()
                    ))
                })
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let canonical_policy = canonical_json_bytes(policy).map_err(|error| {
        CompileError::Invalid(format!(
            "threshold approval policy canonicalization failed: {error}"
        ))
    })?;
    let policy_hash = sha256_hex(&canonical_policy);
    let requirement = ThresholdApprovalRequirement::new(
        approvers.n,
        eligible,
        approvers
            .timeout_seconds
            .unwrap_or(DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS),
        policy_hash,
        directory.version(),
    )
    .map_err(|error| CompileError::Invalid(error.to_string()))?;
    Ok(Some(ThresholdApprovalResolverSnapshot { requirement }))
}

fn ensure_compilable_policy(policy: &HushSpec) -> Result<(), CompileError> {
    let validation = crate::validate::validate(policy);
    if validation.is_valid() {
        return Ok(());
    }

    let messages = validation
        .errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    Err(CompileError::Invalid(format!(
        "HushSpec validation failed: {messages}"
    )))
}

// ---------------------------------------------------------------------------
// Pipeline builder
// ---------------------------------------------------------------------------

/// Helper that keeps the [`GuardPipeline`] and the parallel `guard_names`
/// list in lockstep so callers cannot forget to record a guard's name when
/// they add it.
struct PipelineBuilder {
    pipeline: GuardPipeline,
    names: Vec<String>,
}

impl PipelineBuilder {
    fn new() -> Self {
        Self {
            pipeline: GuardPipeline::new(),
            names: Vec::new(),
        }
    }

    fn add<G: chio_kernel::Guard + 'static>(&mut self, guard: G) {
        self.names.push(guard.name().to_string());
        self.pipeline.add(Box::new(guard));
    }

    fn finish(self) -> (GuardPipeline, Vec<String>) {
        (self.pipeline, self.names)
    }
}
