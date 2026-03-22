---
phase: 07-schema-compatibility-and-monetary-foundation
plan: "01"
subsystem: pact-core
tags:
  - schema-compatibility
  - forward-compatibility
  - serde
  - deny_unknown_fields
  - cross-version
dependency_graph:
  requires: []
  provides:
    - "Forward-compatible pact-core wire types (CapabilityToken, PactReceipt, ToolManifest)"
    - "Cross-version round-trip tests proving unknown fields tolerated"
  affects:
    - crates/pact-kernel
    - crates/pact-mcp-adapter
    - crates/pact-manifest
tech_stack:
  added: []
  patterns:
    - "serde_json::Value injection pattern for forward-compatibility testing"
key_files:
  created:
    - crates/pact-core/tests/forward_compat.rs
  modified:
    - crates/pact-core/src/capability.rs
    - crates/pact-core/src/receipt.rs
    - crates/pact-core/src/manifest.rs
decisions:
  - "Removed all 18 deny_unknown_fields annotations without replacement -- serde default behavior (silently ignore) is the correct v2.0 wire protocol posture"
  - "Tests use serde_json::Value mutation strategy rather than raw string manipulation -- cleaner and less brittle"
  - "Verified signature round-trips after unknown field injection -- proves body() extraction is unaffected by extra fields in the outer struct"
metrics:
  duration: "7 minutes"
  completed_date: "2026-03-22"
  tasks_completed: 2
  files_changed: 4
---

# Phase 7 Plan 01: Schema Forward Compatibility Summary

Removed all 18 `deny_unknown_fields` serde annotations from pact-core serialized types and added a 7-test integration suite proving cross-version deserialization and signature verification work correctly.

## What Was Built

**Task 1: Annotation removal (feat commit e36ee02)**

Removed `#[serde(deny_unknown_fields)]` from exactly 18 struct definitions across three files:

- `crates/pact-core/src/capability.rs` -- 8 structs: CapabilityToken, CapabilityTokenBody, PactScope, ToolGrant, ResourceGrant, PromptGrant, DelegationLink, DelegationLinkBody
- `crates/pact-core/src/receipt.rs` -- 6 structs: PactReceipt, PactReceiptBody, ChildRequestReceipt, ChildRequestReceiptBody, ToolCallAction, GuardEvidence
- `crates/pact-core/src/manifest.rs` -- 4 structs: ToolManifest, ToolManifestBody, ToolDefinition, ToolAnnotations

All 123 pre-existing pact-core unit tests continue to pass.

**Task 2: Forward-compatibility tests (test commit f8b4576)**

Created `crates/pact-core/tests/forward_compat.rs` with 7 integration tests:

| Test | Type Family | Unknown Fields Injected | Sig Verified |
|------|------------|------------------------|--------------|
| v1_token_accepted_by_v2 | CapabilityToken | None (baseline) | Yes |
| v2_token_with_unknown_fields_accepted | CapabilityToken + ToolGrant | Top-level + nested | Yes |
| v2_receipt_with_unknown_fields_accepted | PactReceipt + GuardEvidence + ToolCallAction | Top-level + nested | Yes |
| v2_manifest_with_unknown_fields_accepted | ToolManifest + ToolDefinition + ToolAnnotations | All three levels | Yes |
| unknown_fields_not_preserved_on_reserialize | CapabilityToken | "ghost_field" | N/A |
| delegation_link_with_unknown_fields | DelegationLink | Top-level | Yes |
| child_receipt_with_unknown_fields | ChildRequestReceipt | Top-level | Yes |

Test strategy: serialize struct to `serde_json::Value`, inject `future_field`, `v3_data`, and monetary-flavored fields (e.g., `max_cost_per_invocation`, `billing_ref`) to simulate v2.0/v3.0 wire formats, deserialize back, assert known fields match and signatures verify.

## Verification Results

```
grep -r "deny_unknown_fields" crates/pact-core/src/  ->  zero matches (PASS)
cargo test -p pact-core                              ->  123 passed (PASS)
cargo test -p pact-core --test forward_compat        ->  7 passed (PASS)
cargo test --workspace                               ->  0 failed across all crates (PASS)
cargo clippy --workspace -- -D warnings              ->  0 warnings (PASS)
```

## Decisions Made

1. **Silent ignore is the correct posture.** Replacing `deny_unknown_fields` with no attribute (serde default) is correct for protocol types that will evolve. Explicit `#[serde(flatten)]` into a remainder map was considered but rejected -- it changes the serde contract and is only needed if unknown fields must be re-emitted.

2. **serde_json::Value injection over raw string manipulation.** Tests mutate a deserialized Value before re-serializing to string. This is more robust than regex/string patching of JSON output and handles nested injection cleanly.

3. **Signature verification as the hard invariant.** The key correctness property is that `body()` extraction strips unknown fields before signing/verifying. Tests assert `verify_signature()` returns `Ok(true)` after round-tripping with unknown fields injected -- this proves the TCB signing invariant is preserved.

## Deviations from Plan

None - plan executed exactly as written.

## Self-Check: PASSED

- crates/pact-core/tests/forward_compat.rs: FOUND
- crates/pact-core/src/capability.rs: FOUND
- crates/pact-core/src/receipt.rs: FOUND
- crates/pact-core/src/manifest.rs: FOUND
- Commit e36ee02 (feat - annotation removal): FOUND
- Commit f8b4576 (test - forward compat tests): FOUND
