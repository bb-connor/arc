//! HushSpec-to-PACT compiler.
//!
//! This is the key bridge between HushSpec policies and PACT's guard pipeline.
//! It translates HushSpec rule blocks into configured PACT guards and builds
//! a default capability scope from the policy's tool_access rules.

use crate::models::{DefaultAction, HushSpec};

use pact_core::capability::{Operation, PactScope, ToolGrant};
use pact_guards::{
    EgressAllowlistGuard, ForbiddenPathGuard, GuardPipeline, McpToolGuard, PatchIntegrityGuard,
    PathAllowlistGuard, SecretLeakGuard, ShellCommandGuard,
};

/// Errors that can occur during policy compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("invalid policy: {0}")]
    Invalid(String),
}

/// The result of compiling a HushSpec policy into PACT primitives.
pub struct CompiledPolicy {
    /// A guard pipeline configured from the policy's rule blocks.
    pub guards: GuardPipeline,
    /// A default capability scope derived from the policy's tool_access rules.
    pub default_scope: PactScope,
}

/// Compile a HushSpec policy into a PACT guard pipeline and default scope.
///
/// This maps HushSpec rule blocks to PACT guard configurations:
/// - `forbidden_paths` -> `ForbiddenPathGuard`
/// - `egress` -> `EgressAllowlistGuard`
/// - `shell_commands` -> `ShellCommandGuard`
/// - `tool_access` -> `McpToolGuard`
/// - `secret_patterns` -> `SecretLeakGuard`
/// - `patch_integrity` -> `PatchIntegrityGuard`
/// - `path_allowlist` -> `PathAllowlistGuard`
pub fn compile_policy(policy: &HushSpec) -> Result<CompiledPolicy, CompileError> {
    let guards = compile_guards(policy)?;
    let default_scope = compile_scope(policy);
    Ok(CompiledPolicy {
        guards,
        default_scope,
    })
}

/// Compile the guard pipeline from a HushSpec policy.
fn compile_guards(policy: &HushSpec) -> Result<GuardPipeline, CompileError> {
    let mut pipeline = GuardPipeline::new();

    let Some(rules) = &policy.rules else {
        return Ok(pipeline);
    };

    // forbidden_paths -> ForbiddenPathGuard
    if let Some(fp) = &rules.forbidden_paths {
        if fp.enabled {
            if fp.patterns.is_empty() {
                pipeline.add(Box::new(ForbiddenPathGuard::new()));
            } else {
                pipeline.add(Box::new(ForbiddenPathGuard::with_patterns(
                    fp.patterns.clone(),
                    fp.exceptions.clone(),
                )));
            }
        }
    }

    // shell_commands -> ShellCommandGuard
    if let Some(sc) = &rules.shell_commands {
        if sc.enabled {
            if sc.forbidden_patterns.is_empty() {
                pipeline.add(Box::new(ShellCommandGuard::new()));
            } else {
                pipeline.add(Box::new(ShellCommandGuard::with_patterns(
                    sc.forbidden_patterns.clone(),
                    true, // enforce forbidden paths in shell commands
                )));
            }
        }
    }

    // egress -> EgressAllowlistGuard
    if let Some(eg) = &rules.egress {
        if eg.enabled {
            if eg.allow.is_empty() && eg.block.is_empty() {
                pipeline.add(Box::new(EgressAllowlistGuard::new()));
            } else {
                pipeline.add(Box::new(EgressAllowlistGuard::with_lists(
                    eg.allow.clone(),
                    eg.block.clone(),
                )));
            }
        }
    }

    // tool_access -> McpToolGuard
    if let Some(ta) = &rules.tool_access {
        if ta.enabled {
            let default_action = match ta.default {
                DefaultAction::Allow => pact_guards::McpToolGuard::new(),
                DefaultAction::Block => {
                    let config = pact_guards::mcp_tool::McpToolConfig {
                        enabled: true,
                        allow: ta.allow.clone(),
                        block: ta.block.clone(),
                        default_action: pact_guards::mcp_tool::McpDefaultAction::Block,
                        max_args_size: ta.max_args_size,
                    };
                    McpToolGuard::with_config(config)
                }
            };
            // For Allow default with lists, also use with_config
            if ta.default == DefaultAction::Allow
                && (!ta.allow.is_empty() || !ta.block.is_empty() || ta.max_args_size.is_some())
            {
                let config = pact_guards::mcp_tool::McpToolConfig {
                    enabled: true,
                    allow: ta.allow.clone(),
                    block: ta.block.clone(),
                    default_action: pact_guards::mcp_tool::McpDefaultAction::Allow,
                    max_args_size: ta.max_args_size,
                };
                pipeline.add(Box::new(McpToolGuard::with_config(config)));
            } else {
                pipeline.add(Box::new(default_action));
            }
        }
    }

    // secret_patterns -> SecretLeakGuard
    if let Some(sp) = &rules.secret_patterns {
        if sp.enabled {
            let config = pact_guards::secret_leak::SecretLeakConfig {
                enabled: true,
                skip_paths: sp.skip_paths.clone(),
            };
            pipeline.add(Box::new(SecretLeakGuard::with_config(config)));
        }
    }

    // patch_integrity -> PatchIntegrityGuard
    if let Some(pi) = &rules.patch_integrity {
        if pi.enabled {
            let config = pact_guards::patch_integrity::PatchIntegrityConfig {
                enabled: true,
                max_additions: pi.max_additions,
                max_deletions: pi.max_deletions,
                forbidden_patterns: pi.forbidden_patterns.clone(),
                require_balance: pi.require_balance,
                max_imbalance_ratio: pi.max_imbalance_ratio,
            };
            pipeline.add(Box::new(PatchIntegrityGuard::with_config(config)));
        }
    }

    // path_allowlist -> PathAllowlistGuard
    if let Some(pa) = &rules.path_allowlist {
        if pa.enabled {
            let config = pact_guards::path_allowlist::PathAllowlistConfig {
                enabled: true,
                file_access_allow: pa.read.clone(),
                file_write_allow: pa.write.clone(),
                patch_allow: pa.patch.clone(),
            };
            pipeline.add(Box::new(PathAllowlistGuard::with_config(config)));
        }
    }

    Ok(pipeline)
}

/// Build a default PactScope from the policy's tool_access rules.
///
/// If tool_access has an allow list, each entry becomes a wildcard ToolGrant
/// with `Invoke` permission. If not specified, returns a permissive wildcard
/// scope.
fn compile_scope(policy: &HushSpec) -> PactScope {
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
        return PactScope::default();
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

    PactScope {
        grants,
        ..PactScope::default()
    }
}

fn permissive_scope() -> PactScope {
    PactScope {
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
        ..PactScope::default()
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
    }

    #[test]
    fn compile_multiple_guards() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: true
    patterns: ["**/.ssh/**"]
  shell_commands:
    enabled: true
  egress:
    enabled: true
    allow: ["*.github.com"]
    default: block
  patch_integrity:
    enabled: true
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guards.len(), 4);
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
}
