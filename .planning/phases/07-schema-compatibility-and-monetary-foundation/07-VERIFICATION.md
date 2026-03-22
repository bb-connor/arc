---
phase: 07-schema-compatibility-and-monetary-foundation
verified: 2026-03-22T00:00:00Z
status: gaps_found
score: 9/10 must-haves verified
gaps:
  - truth: "cargo fmt --all -- --check passes (workspace clean)"
    status: failed
    reason: "crates/pact-core/tests/forward_compat.rs has two formatting violations: (1) import group ordering -- pact_core::session and pact_core::crypto use-statements appear after the main pact_core use-block instead of before it; (2) two .expect() call chains are not wrapped per rustfmt line-length rules"
    artifacts:
      - path: "crates/pact-core/tests/forward_compat.rs"
        issue: "Import order and line-length wrapping violate rustfmt defaults. `cargo fmt -p pact-core -- --check` exits 1 with diffs at lines 11-22 and 225, 265."
    missing:
      - "Run `cargo fmt -p pact-core` to auto-fix; no logic change required"
human_verification: []
---

# Phase 7: Schema Compatibility and Monetary Foundation Verification Report

**Phase Goal:** pact-core types tolerate unknown fields and carry monetary budget primitives, unblocking all subsequent v2.0 wire-format additions.
**Verified:** 2026-03-22
**Status:** gaps_found (1 formatting gap; all functional goals achieved)
**Re-verification:** No -- initial verification

---

## Goal Achievement

### Observable Truths

| #  | Truth                                                                                           | Status     | Evidence                                                                                    |
|----|-------------------------------------------------------------------------------------------------|------------|---------------------------------------------------------------------------------------------|
| 1  | A v2.0 kernel deserializes a v1.0-shaped CapabilityToken without error                         | VERIFIED   | `v1_token_accepted_by_v2` test passes; no deny_unknown_fields in source                    |
| 2  | A v1.0 kernel (simulated) deserializes a v2.0 token containing unknown fields without error    | VERIFIED   | `v2_token_with_unknown_fields_accepted` injects `future_field`, `v3_data`, `v3_billing_ref`; passes |
| 3  | Existing pact-core unit tests pass without regression                                           | VERIFIED   | 123 unit tests pass; 0 failures                                                             |
| 4  | All 18 deny_unknown_fields annotations are removed from pact-core serialized types             | VERIFIED   | `grep -r "deny_unknown_fields" crates/pact-core/src/` returns zero matches (exit 1 = no output) |
| 5  | ToolGrant carries optional max_cost_per_invocation and max_total_cost fields that round-trip via canonical JSON | VERIFIED | Fields present in capability.rs lines 185-189; `tool_grant_with_monetary_fields_roundtrip` passes |
| 6  | MonetaryAmount holds u64 minor-unit integers with an ISO 4217 currency string                  | VERIFIED   | `pub struct MonetaryAmount` at capability.rs line 162; `monetary_amount_serde_roundtrip` passes |
| 7  | Attenuation::ReduceCostPerInvocation and Attenuation::ReduceTotalCost serialize and deserialize correctly | VERIFIED | Both variants at capability.rs lines 444-454; tests 5 and 6 in monetary_types.rs pass |
| 8  | ToolGrant::is_subset_of enforces that child monetary caps do not exceed parent caps             | VERIFIED   | Logic at capability.rs lines 239-256; 6 subset tests pass including currency-mismatch and uncapped-child cases |
| 9  | Existing tokens without monetary fields still deserialize and function identically             | VERIFIED   | `tool_grant_without_monetary_fields_backward_compat` passes with v1.0 JSON (no monetary keys) |
| 10 | cargo fmt --all -- --check exits 0                                                              | FAILED     | forward_compat.rs has import ordering and line-wrap violations; `cargo fmt -p pact-core -- --check` exits 1 |

**Score:** 9/10 truths verified

---

### Required Artifacts

| Artifact                                          | Expected                                                                              | Status     | Details                                                                                     |
|---------------------------------------------------|---------------------------------------------------------------------------------------|------------|---------------------------------------------------------------------------------------------|
| `crates/pact-core/src/capability.rs`              | Forward-compatible types + MonetaryAmount + extended ToolGrant + Attenuation variants | VERIFIED   | Contains `pub struct CapabilityToken`, `pub struct MonetaryAmount`, `ReduceCostPerInvocation`, `ReduceTotalCost`, monetary is_subset_of logic |
| `crates/pact-core/src/receipt.rs`                 | Forward-compatible PactReceipt, PactReceiptBody, ChildRequestReceipt, ToolCallAction, GuardEvidence | VERIFIED | Contains `pub struct PactReceipt`; zero deny_unknown_fields |
| `crates/pact-core/src/manifest.rs`                | Forward-compatible ToolManifest, ToolManifestBody, ToolDefinition, ToolAnnotations   | VERIFIED   | Contains `pub struct ToolManifest`; zero deny_unknown_fields |
| `crates/pact-core/src/lib.rs`                     | Re-export of MonetaryAmount                                                           | VERIFIED   | Line 25: `MonetaryAmount` present in capability re-export block |
| `crates/pact-core/tests/forward_compat.rs`        | 7 cross-version round-trip tests proving unknown fields tolerated                    | VERIFIED   | Contains `fn v1_token_accepted_by_v2`; all 7 tests pass; FORMAT VIOLATION (import order) |
| `crates/pact-core/tests/monetary_types.rs`        | 13 monetary type integration tests                                                    | VERIFIED   | Contains `fn monetary_amount_serde_roundtrip`; all 13 tests pass                           |

---

### Key Link Verification

| From                                             | To                                          | Via                                             | Status  | Details                                                                                 |
|--------------------------------------------------|---------------------------------------------|-------------------------------------------------|---------|-----------------------------------------------------------------------------------------|
| `tests/forward_compat.rs`                        | `src/capability.rs`                         | `serde_json::from_str` to `CapabilityToken`     | WIRED   | Line 144 and 182 in forward_compat.rs call `serde_json::from_str::<CapabilityToken>` with unknown-field-injected JSON |
| `tests/forward_compat.rs`                        | `src/receipt.rs`                            | `serde_json::from_str` to `PactReceipt`         | WIRED   | Line 228 calls `serde_json::from_str::<PactReceipt>` with injected fields               |
| `src/capability.rs` is_subset_of                 | `src/capability.rs` MonetaryAmount          | `max_cost_per_invocation` and `max_total_cost` checks | WIRED | Lines 239-256: both monetary fields checked with currency-equality and units-comparison  |
| `tests/monetary_types.rs`                        | `src/capability.rs`                         | `serde_json` round-trip and `is_subset_of` assertions | WIRED | Imports `MonetaryAmount`, `ToolGrant` from `pact_core`; exercises is_subset_of in 6 tests |

---

### Requirements Coverage

| Requirement | Source Plan | Description                                                                              | Status    | Evidence                                                                          |
|-------------|-------------|------------------------------------------------------------------------------------------|-----------|-----------------------------------------------------------------------------------|
| SCHEMA-01   | 07-01       | pact-core types tolerate unknown fields (deny_unknown_fields removed from 18 types)     | SATISFIED | Zero occurrences of deny_unknown_fields in pact-core/src/; 7 forward-compat tests pass |
| SCHEMA-02   | 07-02       | ToolGrant supports monetary budget fields (max_cost_per_invocation, max_total_cost as MonetaryAmount with u64 minor-unit amounts) | SATISFIED | Both fields present in ToolGrant struct; backward-compat test passes; round-trip test passes |
| SCHEMA-03   | 07-02       | Attenuation enum supports cost reduction variants (ReduceCostPerInvocation, ReduceTotalCost) | SATISFIED | Both variants in Attenuation enum at capability.rs lines 444-454; round-trip tests 5 and 6 pass |

**Orphaned requirements check:** REQUIREMENTS.md Traceability table maps SCHEMA-01, SCHEMA-02, SCHEMA-03 all to Phase 7 status Complete. No orphaned requirements found.

---

### Anti-Patterns Found

| File                                            | Line  | Pattern                                     | Severity | Impact                                                |
|-------------------------------------------------|-------|---------------------------------------------|----------|-------------------------------------------------------|
| `crates/pact-core/tests/forward_compat.rs`      | 14-22 | Import group ordering wrong for rustfmt     | WARNING  | `cargo fmt --all -- --check` exits 1; CI would fail if fmt check is gated |
| `crates/pact-core/tests/forward_compat.rs`      | 228, 268 | Line-length wrap style for .expect() chains | WARNING | Same fmt check failure; no logic impact |
| `crates/pact-core/tests/monetary_types.rs`      | 46    | Unused helper function `make_grant_no_monetary` | INFO   | Compiler warning only (`dead_code`); not denied by clippy in test code |

No stub implementations found. No TODO/FIXME/placeholder comments in any phase-07 files. No empty `return null` / `return {}` implementations.

---

### Human Verification Required

None. All observable behaviors are verifiable programmatically:
- Unknown-field tolerance: tested by injecting JSON fields and asserting deserialization succeeds
- Monetary subset logic: tested with 6 boundary-condition cases
- Signature verification through round-trips: asserted in all 7 forward-compat and test 13 monetary tests

---

### Gaps Summary

**One gap blocks a clean workspace build with `--check` gates:**

The file `crates/pact-core/tests/forward_compat.rs` has formatting violations that cause `cargo fmt --all -- --check` to exit 1. The violations are:

1. **Import group ordering** (lines 14-22): `use pact_core::session` and `use pact_core::crypto` sub-imports appear *after* the main `use pact_core::{...}` block. Rustfmt expects them to appear *before* the consolidated block (alphabetical group ordering).

2. **Line-length wrapping** (lines 225-229 and 265-269): Two `.expect("...")` calls at the end of `serde_json::from_str(...)` chains exceed the line limit and need wrapping in rustfmt's style.

This is a cosmetic issue only. All 7 forward-compat tests pass. The underlying protocol behavior (unknown-field tolerance with signature verification) is correct and tested. A single `cargo fmt -p pact-core` run auto-fixes all violations with no logic change required.

The 13 monetary tests all pass. The `make_grant_no_monetary` dead-code warning in monetary_types.rs is a compiler info-level warning, not a clippy denial (test code exempts `unused` via test harness context).

**No functional goals are blocked.** The phase goal -- "pact-core types tolerate unknown fields and carry monetary budget primitives" -- is fully achieved. The fmt gap must be resolved before shipping to unblock `cargo fmt --all -- --check` CI gates.

---

_Verified: 2026-03-22_
_Verifier: Claude (gsd-verifier)_
