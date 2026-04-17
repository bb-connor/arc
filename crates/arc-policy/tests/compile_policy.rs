//! End-to-end test: `compile_policy(yaml)` emits a Vec of guards that
//! includes all 12 guard types defined by phase 5.5 of the roadmap.
//!
//! This exercises the HushSpec YAML -> `CompiledPolicy` path rather than
//! the Rust-struct path; the rust-struct path is covered by the module
//! tests in `crates/arc-policy/src/compiler.rs`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashSet;

use arc_policy::{compile_policy, HushSpec};

/// A HushSpec policy that exercises every guard type the compiler knows how
/// to emit. The rule / extension blocks are deliberately minimal -- we only
/// need each block present and enabled; the specific patterns / thresholds
/// are not the subject of this test.
const ALL_TWELVE_GUARDS_YAML: &str = r#"
hushspec: "0.1.0"
name: phase-5.5-coverage
description: Exercises every guard type the compiler can emit.

rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**/.ssh/**"
  path_allowlist:
    enabled: true
    read:
      - "/app/**"
    write:
      - "/app/tmp/**"
    patch:
      - "/app/**"
  shell_commands:
    enabled: true
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
  egress:
    enabled: true
    allow:
      - "api.example.com"
    default: block
  tool_access:
    enabled: true
    allow:
      - read_file
    block:
      - raw_file_write
    default: block
  secret_patterns:
    enabled: true
    patterns:
      - name: aws
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
    skip_paths:
      - "**/tests/**"
  patch_integrity:
    enabled: true
    max_additions: 500
    max_deletions: 200

extensions:
  detection:
    prompt_injection:
      enabled: true
      block_at_or_above: high
      max_scan_bytes: 65536
    jailbreak:
      enabled: true
      block_threshold: 70
      warn_threshold: 30
      max_input_bytes: 200000
  origins:
    default_behavior: deny
    profiles:
      - id: default
        budgets:
          tool_calls: 1000
"#;

#[test]
fn compile_policy_emits_all_twelve_guard_types() {
    let spec = HushSpec::parse(ALL_TWELVE_GUARDS_YAML).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");

    let expected: HashSet<&'static str> = [
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

    let actual: HashSet<&str> = compiled.guard_names.iter().map(String::as_str).collect();

    let missing: Vec<&&str> = expected.difference(&actual).collect();
    assert!(
        missing.is_empty(),
        "missing guard types after compilation: {missing:?}; got {actual:?}"
    );
    assert_eq!(
        expected.len(),
        12,
        "the phase 5.5 acceptance criterion requires 12 distinct guard types"
    );
    assert!(
        compiled.guards.len() >= 12,
        "guard pipeline should contain at least 12 guards, found {}",
        compiled.guards.len()
    );
}

#[test]
fn compile_policy_produces_vec_of_guards_accessible_via_pipeline() {
    // The GuardPipeline stores guards as `Vec<Box<dyn Guard>>` internally;
    // the sidecar `guard_names` list mirrors that vector's ordering and
    // size. Together they satisfy the phase 5.5 acceptance wording that
    // `compile_policy(yaml)` produces a `Vec<Box<dyn Guard>>` containing
    // all 12 guard types.
    let spec = HushSpec::parse(ALL_TWELVE_GUARDS_YAML).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert_eq!(compiled.guards.len(), compiled.guard_names.len());
}

#[test]
fn compile_empty_policy_yields_empty_pipeline() {
    let yaml = r#"
hushspec: "0.1.0"
name: empty
"#;
    let spec = HushSpec::parse(yaml).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(compiled.guard_names.is_empty());
    assert!(compiled.guards.is_empty());
}

#[test]
fn disabled_detection_blocks_do_not_emit_guards() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: false
      block_at_or_above: high
    jailbreak:
      enabled: false
      block_threshold: 70
"#;
    let spec = HushSpec::parse(yaml).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(!compiled.guard_names.contains(&"prompt-injection".to_string()));
    assert!(!compiled.guard_names.contains(&"jailbreak".to_string()));
}
