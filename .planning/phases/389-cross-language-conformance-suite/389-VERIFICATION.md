---
phase: 389-cross-language-conformance-suite
verified: 2026-04-14T00:00:00Z
status: gaps_found
score: 4/5 must-haves verified
re_verification: false
gaps:
  - truth: "Allow verdicts, Deny verdicts with reason substring matching, and enriched request fields are all covered by fixtures"
    status: partial
    reason: "The ROADMAP success criterion 1 explicitly requires fixtures covering 'host function calls (log, get_config, get_time)'. Neither tool-gate.yaml nor enriched-fields.yaml includes any fixture exercising host function calls. All other fixture coverage (Allow, Deny with reason, enriched fields) is present."
    artifacts:
      - path: "tests/conformance/fixtures/guard/tool-gate.yaml"
        issue: "No fixture exercises host function calls (arc.log, arc.get_config, arc.get_time)"
      - path: "tests/conformance/fixtures/guard/enriched-fields.yaml"
        issue: "No fixture exercises host function calls"
    missing:
      - "At least one fixture in either YAML file that invokes a guard which calls arc.log, arc.get_config, or arc.get_time, confirming host function dispatch is exercised cross-language"
  - truth: "The test fails if any language exceeds 2x the fuel of the most efficient language for the same fixture"
    status: partial
    reason: "The plan-02 must_haves state '2x threshold'. The ROADMAP success criterion 3 states 'fails if any language exceeds 2x the fuel'. The implementation uses FUEL_PARITY_THRESHOLD = 100 (100x). The deviation is documented and technically justified (TypeScript ~88x vs Rust is inherent to SpiderMonkey embedding), but the contract in REQUIREMENTS.md and ROADMAP still reads '2x'. The threshold is not wrong but the requirement text has not been updated to reflect the actual enforcement boundary."
    artifacts:
      - path: "crates/arc-wasm-guards/tests/conformance_runner.rs"
        issue: "FUEL_PARITY_THRESHOLD = 100 while ROADMAP success criterion 3 and plan-02 must_haves both specify 2x. The REQUIREMENTS.md entry for CONF-03 text reads 'within 2x' but the implementation enforces 100x."
    missing:
      - "Either update REQUIREMENTS.md CONF-03 text to state the documented threshold (100x regression detector) or add a per-language-pair sub-threshold table that meets the 2x spirit for intra-tier comparisons (TS vs Python, Rust vs Rust)"
human_verification: []
---

# Phase 389: Cross-Language Conformance Suite Verification Report

**Phase Goal:** A single conformance test suite proves that all four language SDKs (Rust, TypeScript, Python, Go) produce identical guard verdicts and comparable fuel consumption for the same policy scenarios
**Verified:** 2026-04-14
**Status:** gaps_found
**Re-verification:** No -- initial verification

## Goal Achievement

### Observable Truths (from PLAN must_haves + ROADMAP success criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|---------|
| 1 | A single cargo test invocation runs every YAML fixture against all available language guards | VERIFIED | `cargo test --package arc-wasm-guards --test conformance_runner --features wasmtime-runtime -- --nocapture` produced `test result: ok. 2 passed; 0 failed` with 21/21 fixtures across Rust+TS+Python, Go skipped |
| 2 | Each guard language is tested against every fixture in the set | VERIFIED | Live output shows [PASS] for all 7 tool-gate.yaml fixtures for each of rust, typescript, python; Go shows [SKIP] with message "guard WASM not found" |
| 3 | Allow verdicts, Deny verdicts with reason substring matching, and enriched request fields are all covered -- including host function calls | PARTIAL | Allow/Deny/reason/enriched fields are covered; host function calls (arc.log, arc.get_config, arc.get_time) are absent from all fixtures despite being listed in ROADMAP success criterion 1 |
| 4 | Guards that are not compiled (Go without TinyGo) are gracefully skipped | VERIFIED | Live output: "[SKIP] go: guard WASM not found"; test does not panic |
| 5 | Per-guard per-fixture pass/fail is printed to stdout | VERIFIED | Each fixture prints "[PASS] rust / allow_safe_tool (fuel: 8512)" format with fuel data |
| 6 | Fuel consumption is measured for each guard on each fixture | VERIFIED | Every [PASS] line includes `(fuel: N)` with real values; fuel summary table printed after each test |
| 7 | The test fails if any language exceeds the configured fuel parity threshold | PARTIAL | Fuel parity check is implemented and enforced at 100x (FUEL_PARITY_THRESHOLD = 100). ROADMAP success criterion 3 and plan-02 must_haves specify "2x". Threshold deviation is documented in code comments but the requirement text has not been updated. |
| 8 | Fuel comparison only applies to fixtures where at least 2 guards reported fuel data | VERIFIED | `check_fuel_parity()` contains `if entries.len() < 2 { continue; }` guard |
| 9 | Unavailable guards are gracefully skipped | VERIFIED | Go WASM absent; test prints [SKIP], increments skipped_guards, continues without panic |

**Score:** 7/9 truths fully verified, 2 partial

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `tests/conformance/fixtures/guard/tool-gate.yaml` | Shared YAML fixtures for tool-gate deny-list policy, contains `expected_verdict` | VERIFIED | 7 fixtures present: allow_safe_tool, deny_dangerous_tool, deny_rm_rf, deny_drop_database, allow_unknown_tool, allow_with_scopes, allow_with_arguments. All deny fixtures include deny_reason_contains. Parses as valid YAML array. |
| `tests/conformance/fixtures/guard/enriched-fields.yaml` | Shared YAML fixtures exercising enriched request fields, contains `action_type` | VERIFIED | 4 fixtures present: allow_non_file_write, allow_file_read, deny_write_to_etc, allow_write_to_tmp. Exercises action_type and extracted_path. Deny fixture includes deny_reason_contains. |
| `crates/arc-wasm-guards/tests/conformance_runner.rs` | Integration test loading all 4 guards and running fixtures, contains `fn conformance_` | VERIFIED | 506 lines. Contains `fn conformance_tool_gate_all_languages` (line 337) and `fn conformance_enriched_inspector_rust` (line 429). |

All three artifacts exist, are substantive, and are wired.

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `conformance_runner.rs` | `tests/conformance/fixtures/guard/*.yaml` | `serde_yml::from_str` deserialization of TestFixture structs | VERIFIED | `load_fixtures()` at line 157 reads path via `CARGO_MANIFEST_DIR/../../tests/conformance/fixtures/guard/{relative_path}`, deserializes with `serde_yml::from_str` at line 164 |
| `conformance_runner.rs` | `WasmtimeBackend` and `ComponentBackend` | `make_backend` factory + `backend.evaluate()` per fixture | VERIFIED | `backend.evaluate(&fixture.request)` at line 367 (tool-gate test) and line 453 (enriched test). Fresh backend created per fixture via `(entry.make_backend)(engine.clone(), &entry.wasm_bytes)` at line 366. |
| `conformance_runner.rs` | `WasmGuardAbi::last_fuel_consumed()` | fuel reading after each `evaluate()` call | VERIFIED | `backend.last_fuel_consumed()` called at line 370 (tool-gate) and line 456 (enriched). Both `WasmtimeBackend` (runtime.rs:705) and `ComponentBackend` (component.rs:141) implement this method returning `Some(fuel)`. |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|---------|
| CONF-01 | 389-01-PLAN.md | Cross-language conformance test suite with shared YAML fixtures exercising Allow, Deny, deny-reason, host function calls, and enriched request fields | PARTIAL | Allow, Deny, deny-reason, and enriched request fields are exercised. Host function calls (arc.log, arc.get_config, arc.get_time) are not covered by any fixture. |
| CONF-02 | 389-01-PLAN.md | Conformance suite runs all four language guards against the same fixture set and reports pass/fail per guard per fixture | VERIFIED | Live test: 21/21 pass across Rust+TS+Python, Go gracefully skipped. Per-guard per-fixture [PASS]/[SKIP] output confirmed. |
| CONF-03 | 389-02-PLAN.md | Conformance suite validates that fuel consumption is within 2x across languages for the same fixture | PARTIAL | Fuel validation implemented but threshold is 100x not 2x. REQUIREMENTS.md CONF-03 text reads "within 2x". Implementation is a regression detector at 100x, not enforcement of the 2x contract. Deviation is justified (inherent runtime overhead) but the requirement text is out of sync with implementation. |

**Requirement mapping note:** REQUIREMENTS.md maps CONF-01/02/03 to "Phase 384" in the coverage table (line 3568-3570), but Phase 384 was `cli-scaffolding-new-build-inspect`. The correct phase is 389. This is a stale mapping in the coverage table -- the requirements are properly claimed by 389-01-PLAN.md and 389-02-PLAN.md.

### Anti-Patterns Found

Scanned `conformance_runner.rs`, `tool-gate.yaml`, `enriched-fields.yaml`.

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `conformance_runner.rs` | 279 | `FUEL_PARITY_THRESHOLD = 100` with comment "The plan specified 2x" | Warning | Threshold diverges from ROADMAP success criterion 3 and plan-02 must_haves. Code is deliberate and documented, but CONF-03 requirement text remains "2x". |

No TODOs, FIXMEs, placeholder returns, or empty implementations found.

### Human Verification Required

None. All observable behaviors are programmatically verifiable. The tests ran to completion with live output confirming all pass/fail statuses.

### Compilation Status Note

At time of verification, `cargo build` for the workspace fails due to uncommitted WIP changes in `crates/arc-kernel/src/kernel/responses.rs` introduced by a subsequent phase (377). The `arc-wasm-guards` crate depends on `arc-kernel`, so a fresh compile of the conformance tests is currently blocked. The conformance tests passed against a cached binary built at 2026-04-15T00:42 (phase 389 completion timestamp), before the arc-kernel WIP was introduced. This compilation breakage originates from phase 377 work-in-progress, not from phase 389.

### Gaps Summary

**Gap 1: Missing host function call fixtures (CONF-01 partial)**

The ROADMAP success criterion 1 explicitly lists "host function calls (log, get_config, get_time)" as required fixture coverage. No fixture in either YAML file exercises a guard that calls `arc.log`, `arc.get_config`, or `arc.get_time`. The guard examples in examples/guards/ do call these host functions, but the conformance fixtures only cover tool-gate deny-list logic and enriched field inspection. The enriched-inspector test (Rust only) covers enriched fields but not host function dispatch. This means host ABI dispatch is not cross-language-validated by the conformance suite.

**Gap 2: Fuel parity threshold mismatch with stated requirement (CONF-03 partial)**

The implementation enforces 100x fuel parity. The ROADMAP success criterion 3, plan-02 must_haves truth 2, and REQUIREMENTS.md CONF-03 all state "2x". The deviation is justified (TypeScript's SpiderMonkey runtime consumes ~88x more fuel than Rust's direct WASM execution -- this is structural, not a compilation quality problem). However, the formal requirement text has not been updated. Either the requirement text needs updating to reflect "100x regression detector" semantics, or a per-tier comparison needs to be added that enforces stricter ratios within the same execution tier (e.g., TS vs Python should be within 20x, not 100x).

The root cause for both gaps is scope decisions made during execution: the plan's fixture list did not include host function call scenarios, and the fuel threshold was adjusted without updating the requirement text.

---

_Verified: 2026-04-14_
_Verifier: Claude (gsd-verifier)_
