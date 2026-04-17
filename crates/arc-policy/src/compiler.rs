//! HushSpec-to-ARC compiler.
//!
//! This is the key bridge between HushSpec policies and ARC's guard pipeline.
//! It translates HushSpec rule blocks into configured ARC guards and builds
//! a default capability scope from the policy's tool_access rules.
//!
//! # Guard coverage
//!
//! The compiler materializes 12 distinct guard types from a HushSpec
//! document. The first seven are driven directly by the `rules` section; the
//! remaining five are driven either by the `extensions.detection`
//! sub-section or by auxiliary semantics layered on top of existing rule
//! blocks (SSRF protection on egress, output sanitization on secret
//! patterns, per-agent velocity from origin budgets).
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
//! |10 | `InternalNetworkGuard`     | `rules.egress` (SSRF companion) |
//! |11 | `ResponseSanitizationGuard`| `rules.secret_patterns` (output path) |
//! |12 | `AgentVelocityGuard`       | `extensions.origins.profiles[].budgets` |

use crate::models::{DefaultAction, DetectionLevel, HushSpec, JailbreakDetection, PromptInjectionDetection};

use arc_core::capability::{ArcScope, Operation, ToolGrant};
use arc_guards::{
    agent_velocity::AgentVelocityConfig,
    jailbreak::{DetectorConfig as JailbreakDetectorConfig, JailbreakGuardConfig},
    prompt_injection::PromptInjectionConfig,
    response_sanitization::{SanitizationAction, SensitivityLevel},
    AgentVelocityGuard, EgressAllowlistGuard, ForbiddenPathGuard, GuardPipeline,
    InternalNetworkGuard, JailbreakGuard, McpToolGuard, PatchIntegrityGuard, PathAllowlistGuard,
    PromptInjectionGuard, ResponseSanitizationGuard, SecretLeakGuard, ShellCommandGuard,
};

/// Errors that can occur during policy compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("invalid policy: {0}")]
    Invalid(String),
}

/// The result of compiling a HushSpec policy into ARC primitives.
pub struct CompiledPolicy {
    /// A guard pipeline configured from the policy's rule blocks.
    pub guards: GuardPipeline,
    /// A default capability scope derived from the policy's tool_access rules.
    pub default_scope: ArcScope,
    /// Ordered list of guard names emitted by compilation.
    ///
    /// The acceptance criteria for phase 5.5 requires the compiler to emit a
    /// `Vec<Box<dyn Guard>>` containing all 12 guard types; because
    /// [`GuardPipeline`] does not publicly expose its contained guards,
    /// this sidecar records the `Guard::name()` of each guard added to the
    /// pipeline in insertion order. Deduplicated, this is the set of
    /// concrete guard types that compiled successfully.
    pub guard_names: Vec<String>,
}

/// Compile a HushSpec policy into a ARC guard pipeline and default scope.
///
/// This maps HushSpec rule blocks and detection-extension blocks to ARC
/// guard configurations. See the module-level documentation for the full
/// mapping table. Missing sections compile to an empty pipeline; no error
/// is raised for policies that simply do not exercise every guard type.
pub fn compile_policy(policy: &HushSpec) -> Result<CompiledPolicy, CompileError> {
    let mut builder = PipelineBuilder::new();
    compile_rule_guards(policy, &mut builder)?;
    compile_detection_guards(policy, &mut builder)?;
    compile_budget_guards(policy, &mut builder)?;
    let default_scope = compile_scope(policy);
    let (guards, guard_names) = builder.finish();
    Ok(CompiledPolicy {
        guards,
        default_scope,
        guard_names,
    })
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

    fn add<G: arc_kernel::Guard + 'static>(&mut self, guard: G) {
        self.names.push(guard.name().to_string());
        self.pipeline.add(Box::new(guard));
    }

    fn finish(self) -> (GuardPipeline, Vec<String>) {
        (self.pipeline, self.names)
    }
}

// ---------------------------------------------------------------------------
// Rule-driven guards (1-7 + InternalNetworkGuard + ResponseSanitizationGuard)
// ---------------------------------------------------------------------------

fn compile_rule_guards(
    policy: &HushSpec,
    builder: &mut PipelineBuilder,
) -> Result<(), CompileError> {
    let Some(rules) = &policy.rules else {
        return Ok(());
    };

    // 1. forbidden_paths -> ForbiddenPathGuard
    if let Some(fp) = &rules.forbidden_paths {
        if fp.enabled {
            if fp.patterns.is_empty() {
                builder.add(ForbiddenPathGuard::new());
            } else {
                builder.add(ForbiddenPathGuard::with_patterns(
                    fp.patterns.clone(),
                    fp.exceptions.clone(),
                ));
            }
        }
    }

    // 2. shell_commands -> ShellCommandGuard
    if let Some(sc) = &rules.shell_commands {
        if sc.enabled {
            if sc.forbidden_patterns.is_empty() {
                builder.add(ShellCommandGuard::new());
            } else {
                builder.add(ShellCommandGuard::with_patterns(
                    sc.forbidden_patterns.clone(),
                    true,
                ));
            }
        }
    }

    // 3. egress -> EgressAllowlistGuard
    // 10. egress -> InternalNetworkGuard (SSRF companion)
    //
    // When the policy opts into egress control we also add an internal-
    // network guard that blocks RFC1918 / cloud-metadata endpoints. This
    // matches ClawdStrike's layered defense where the allowlist catches
    // unknown domains and the internal-network guard catches raw IPs.
    if let Some(eg) = &rules.egress {
        if eg.enabled {
            if eg.allow.is_empty() && eg.block.is_empty() {
                builder.add(EgressAllowlistGuard::new());
            } else {
                builder.add(EgressAllowlistGuard::with_lists(
                    eg.allow.clone(),
                    eg.block.clone(),
                ));
            }
            builder.add(InternalNetworkGuard::new());
        }
    }

    // 4. tool_access -> McpToolGuard
    if let Some(ta) = &rules.tool_access {
        if ta.enabled {
            let mcp_default = match ta.default {
                DefaultAction::Allow => arc_guards::mcp_tool::McpDefaultAction::Allow,
                DefaultAction::Block => arc_guards::mcp_tool::McpDefaultAction::Block,
            };
            let config = arc_guards::mcp_tool::McpToolConfig {
                enabled: true,
                allow: ta.allow.clone(),
                block: ta.block.clone(),
                default_action: mcp_default,
                max_args_size: ta.max_args_size,
            };
            builder.add(McpToolGuard::with_config(config));
        }
    }

    // 5. secret_patterns -> SecretLeakGuard
    // 11. secret_patterns -> ResponseSanitizationGuard
    //
    // SecretLeakGuard handles the write path (detect secrets in outbound
    // file writes) while ResponseSanitizationGuard handles the read path
    // (redact PII/PHI/secrets in tool results before the agent sees them).
    // Both are activated by the same HushSpec rule so operators need
    // configure only one block to cover both directions.
    if let Some(sp) = &rules.secret_patterns {
        if sp.enabled {
            let config = arc_guards::secret_leak::SecretLeakConfig {
                enabled: true,
                skip_paths: sp.skip_paths.clone(),
            };
            builder.add(SecretLeakGuard::with_config(config));
            builder.add(ResponseSanitizationGuard::new(
                SensitivityLevel::High,
                SanitizationAction::Redact,
            ));
        }
    }

    // 6. patch_integrity -> PatchIntegrityGuard
    if let Some(pi) = &rules.patch_integrity {
        if pi.enabled {
            let config = arc_guards::patch_integrity::PatchIntegrityConfig {
                enabled: true,
                max_additions: pi.max_additions,
                max_deletions: pi.max_deletions,
                forbidden_patterns: pi.forbidden_patterns.clone(),
                require_balance: pi.require_balance,
                max_imbalance_ratio: pi.max_imbalance_ratio,
            };
            builder.add(PatchIntegrityGuard::with_config(config));
        }
    }

    // 7. path_allowlist -> PathAllowlistGuard
    if let Some(pa) = &rules.path_allowlist {
        if pa.enabled {
            let config = arc_guards::path_allowlist::PathAllowlistConfig {
                enabled: true,
                file_access_allow: pa.read.clone(),
                file_write_allow: pa.write.clone(),
                patch_allow: pa.patch.clone(),
            };
            builder.add(PathAllowlistGuard::with_config(config));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Detection-extension guards (8, 9)
// ---------------------------------------------------------------------------

fn compile_detection_guards(
    policy: &HushSpec,
    builder: &mut PipelineBuilder,
) -> Result<(), CompileError> {
    let Some(extensions) = &policy.extensions else {
        return Ok(());
    };
    let Some(detection) = &extensions.detection else {
        return Ok(());
    };

    // 8. detection.prompt_injection -> PromptInjectionGuard
    if let Some(pi) = &detection.prompt_injection {
        if pi.enabled.unwrap_or(true) {
            builder.add(PromptInjectionGuard::with_config(
                prompt_injection_config_from(pi),
            ));
        }
    }

    // 9. detection.jailbreak -> JailbreakGuard
    if let Some(jb) = &detection.jailbreak {
        if jb.enabled.unwrap_or(true) {
            builder.add(JailbreakGuard::with_config(jailbreak_config_from(jb)?));
        }
    }

    Ok(())
}

fn prompt_injection_config_from(pi: &PromptInjectionDetection) -> PromptInjectionConfig {
    let mut config = PromptInjectionConfig::default();
    if let Some(block_at) = pi.block_at_or_above {
        config.score_threshold = prompt_level_to_score_threshold(block_at);
    }
    if let Some(max_scan_bytes) = pi.max_scan_bytes {
        // Clamp to at least one byte so the guard is well-formed; zero would
        // short-circuit the scanner to a no-op and silently allow everything.
        config.max_scan_bytes = max_scan_bytes.max(1);
    }
    config
}

/// Convert a HushSpec `DetectionLevel` into a PromptInjectionGuard score
/// threshold in `[0.0, 1.0]`. Higher levels require stronger signals before
/// the guard denies.
fn prompt_level_to_score_threshold(level: DetectionLevel) -> f32 {
    match level {
        DetectionLevel::Safe => 0.1,
        DetectionLevel::Suspicious => 0.4,
        DetectionLevel::High => 0.8,
        DetectionLevel::Critical => 1.0,
    }
}

fn jailbreak_config_from(jb: &JailbreakDetection) -> Result<JailbreakGuardConfig, CompileError> {
    let mut config = JailbreakGuardConfig::default();
    let mut detector = JailbreakDetectorConfig::default();

    if let Some(block) = jb.block_threshold {
        // HushSpec expresses thresholds as integer percentages (0-100 in
        // practice; ClawdStrike used 0-255). Map that onto the `[0.0, 1.0]`
        // jailbreak-guard space, capping at 1.0 so out-of-range values
        // fail closed rather than produce an unreachable threshold.
        let capped = u32::try_from(block).unwrap_or(0).min(100);
        config.threshold = (capped as f32) / 100.0;
    }

    // `warn_threshold` has no dedicated field on ARC's `JailbreakGuardConfig`;
    // the guard emits advisory signals based on detector-level statistical
    // thresholds. We accept the HushSpec value for schema compatibility but
    // do not wire it in here -- if the warn value would exceed the configured
    // block threshold we conservatively ignore it rather than fail closed,
    // matching the ClawdStrike `compile_detection` semantics that clamp
    // partial overlays on merge.
    let _ = jb.warn_threshold;

    if let Some(max_bytes) = jb.max_input_bytes {
        detector.max_scan_bytes = max_bytes;
    }

    config.detector = detector;
    Ok(config)
}

// ---------------------------------------------------------------------------
// Budget-driven guards (12)
// ---------------------------------------------------------------------------

fn compile_budget_guards(
    policy: &HushSpec,
    builder: &mut PipelineBuilder,
) -> Result<(), CompileError> {
    let Some(extensions) = &policy.extensions else {
        return Ok(());
    };
    let Some(origins) = &extensions.origins else {
        return Ok(());
    };

    // 12. origin budgets -> AgentVelocityGuard
    //
    // Take the most restrictive `tool_calls` budget across all profiles and
    // use it as the per-agent request ceiling within a 60-second window.
    // This is a coarse mapping -- richer modelling would require a per-
    // origin guard factory -- but it provides a single policy-driven way to
    // exercise the guard type from a HushSpec document.
    let mut tightest_tool_calls: Option<u32> = None;
    for profile in &origins.profiles {
        let Some(budgets) = &profile.budgets else {
            continue;
        };
        if let Some(tool_calls) = budgets.tool_calls {
            let as_u32 = u32::try_from(tool_calls).unwrap_or(u32::MAX);
            tightest_tool_calls = Some(match tightest_tool_calls {
                Some(current) => current.min(as_u32),
                None => as_u32,
            });
        }
    }

    if let Some(limit) = tightest_tool_calls {
        let config = AgentVelocityConfig {
            max_requests_per_agent: Some(limit),
            max_requests_per_session: None,
            window_secs: 60,
            burst_factor: 1.0,
        };
        builder.add(AgentVelocityGuard::new(config));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Scope compilation (unchanged from phase 5.0)
// ---------------------------------------------------------------------------

/// Build a default ArcScope from the policy's tool_access rules.
///
/// If tool_access has an allow list, each entry becomes a wildcard ToolGrant
/// with `Invoke` permission. If not specified, returns a permissive wildcard
/// scope.
fn compile_scope(policy: &HushSpec) -> ArcScope {
    let Some(rules) = &policy.rules else {
        return permissive_scope();
    };

    let Some(ta) = &rules.tool_access else {
        return permissive_scope();
    };

    if !ta.enabled {
        return permissive_scope();
    }

    if ta.allow.is_empty() && ta.default == DefaultAction::Allow {
        return permissive_scope();
    }

    if ta.allow.is_empty() && ta.default == DefaultAction::Block {
        // Block-by-default with no allowlist: empty scope
        return ArcScope::default();
    }

    // Each allowed tool pattern becomes a grant on a wildcard server
    let grants = ta
        .allow
        .iter()
        .map(|tool_pattern| ToolGrant {
            server_id: "*".to_string(),
            tool_name: tool_pattern.clone(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        })
        .collect();

    ArcScope {
        grants,
        ..ArcScope::default()
    }
}

fn permissive_scope() -> ArcScope {
    ArcScope {
        grants: vec![ToolGrant {
            server_id: "*".to_string(),
            tool_name: "*".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ArcScope::default()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn compile_empty_policy() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
name: empty
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guards.len(), 0);
        assert!(compiled.guard_names.is_empty());
        assert_eq!(compiled.default_scope.grants.len(), 1);
        assert_eq!(compiled.default_scope.grants[0].tool_name, "*");
    }

    #[test]
    fn compile_forbidden_paths_guard() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.env"
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guards.len(), 1);
        assert_eq!(compiled.guard_names, vec!["forbidden-path".to_string()]);
    }

    #[test]
    fn compile_egress_adds_internal_network_companion() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  egress:
    enabled: true
    allow: ["*.github.com"]
    default: block
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guards.len(), 2);
        assert_eq!(
            compiled.guard_names,
            vec![
                "egress-allowlist".to_string(),
                "internal-network".to_string()
            ]
        );
    }

    #[test]
    fn compile_secret_patterns_adds_response_sanitization() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    enabled: true
    patterns:
      - name: aws
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guards.len(), 2);
        assert_eq!(
            compiled.guard_names,
            vec![
                "secret-leak".to_string(),
                "response-sanitization".to_string()
            ]
        );
    }

    #[test]
    fn compile_detection_prompt_injection_adds_guard() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
      block_at_or_above: high
      max_scan_bytes: 100000
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guard_names, vec!["prompt-injection".to_string()]);
    }

    #[test]
    fn compile_detection_jailbreak_adds_guard() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      enabled: true
      block_threshold: 70
      warn_threshold: 30
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guard_names, vec!["jailbreak".to_string()]);
    }

    #[test]
    fn compile_origin_budget_adds_agent_velocity() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
extensions:
  origins:
    profiles:
      - id: default
        budgets:
          tool_calls: 120
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guard_names, vec!["agent-velocity".to_string()]);
    }

    #[test]
    fn compile_all_12_guard_types() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: true
    patterns: ["**/.ssh/**"]
  path_allowlist:
    enabled: true
    read: ["/app/**"]
  shell_commands:
    enabled: true
    forbidden_patterns: ["rm -rf /"]
  egress:
    enabled: true
    allow: ["*.example.com"]
    default: block
  tool_access:
    enabled: true
    allow: [read_file]
    default: block
  secret_patterns:
    enabled: true
    patterns:
      - name: aws
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
  patch_integrity:
    enabled: true
extensions:
  detection:
    prompt_injection:
      enabled: true
      block_at_or_above: high
    jailbreak:
      enabled: true
      block_threshold: 70
  origins:
    profiles:
      - id: default
        budgets:
          tool_calls: 1000
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();

        let expected: std::collections::HashSet<&str> = [
            "forbidden-path",
            "shell-command",
            "egress-allowlist",
            "internal-network",
            "mcp-tool",
            "secret-leak",
            "response-sanitization",
            "patch-integrity",
            "path-allowlist",
            "prompt-injection",
            "jailbreak",
            "agent-velocity",
        ]
        .into_iter()
        .collect();

        let actual: std::collections::HashSet<&str> = compiled
            .guard_names
            .iter()
            .map(String::as_str)
            .collect();

        assert_eq!(
            actual, expected,
            "all 12 guard types should compile; got {actual:?}"
        );
        assert_eq!(compiled.guards.len(), 12);
    }

    #[test]
    fn compile_disabled_guards_excluded() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: false
  shell_commands:
    enabled: false
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guards.len(), 0);
    }

    #[test]
    fn compile_tool_access_scope() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: [read_file, write_file, shell_exec]
    default: block
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.default_scope.grants.len(), 3);
        assert_eq!(compiled.default_scope.grants[0].tool_name, "read_file");
        assert_eq!(compiled.default_scope.grants[1].tool_name, "write_file");
        assert_eq!(compiled.default_scope.grants[2].tool_name, "shell_exec");
    }

    #[test]
    fn compile_block_default_empty_allow_produces_empty_scope() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: block
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert!(compiled.default_scope.grants.is_empty());
    }

    #[test]
    fn prompt_level_ordering() {
        assert!(
            prompt_level_to_score_threshold(DetectionLevel::Safe)
                < prompt_level_to_score_threshold(DetectionLevel::Suspicious)
        );
        assert!(
            prompt_level_to_score_threshold(DetectionLevel::Suspicious)
                < prompt_level_to_score_threshold(DetectionLevel::High)
        );
        assert!(
            prompt_level_to_score_threshold(DetectionLevel::High)
                <= prompt_level_to_score_threshold(DetectionLevel::Critical)
        );
    }

    #[test]
    fn jailbreak_block_threshold_maps_to_zero_one() {
        let jb = JailbreakDetection {
            enabled: Some(true),
            block_threshold: Some(70),
            warn_threshold: Some(30),
            max_input_bytes: Some(100_000),
        };
        let cfg = jailbreak_config_from(&jb).unwrap();
        assert!((cfg.threshold - 0.70).abs() < f32::EPSILON);
        assert_eq!(cfg.detector.max_scan_bytes, 100_000);
    }

    #[test]
    fn jailbreak_oversize_threshold_clamped() {
        let jb = JailbreakDetection {
            enabled: Some(true),
            block_threshold: Some(200),
            warn_threshold: None,
            max_input_bytes: None,
        };
        let cfg = jailbreak_config_from(&jb).unwrap();
        assert!(cfg.threshold <= 1.0 + f32::EPSILON);
    }
}
