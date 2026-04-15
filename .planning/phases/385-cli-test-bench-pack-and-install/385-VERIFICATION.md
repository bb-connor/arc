---
phase: 385-cli-test-bench-pack-and-install
verified: 2026-04-14T00:00:00Z
status: passed
score: 6/6 must-haves verified
---

# Phase 385: CLI Test, Bench, Pack, and Install -- Verification Report

**Phase Goal:** Guard authors can test against fixtures, benchmark fuel consumption, package for distribution, and install from archives -- completing the guard development lifecycle from authoring through deployment.
**Verified:** 2026-04-14
**Status:** passed
**Re-verification:** No -- initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `arc guard test` loads a .wasm, runs it against YAML fixture files, and reports pass/fail per fixture with expected verdict matching | VERIFIED | `cmd_guard_test` in guard.rs lines 314-382: reads wasm bytes, iterates fixture paths, deserializes `Vec<TestFixture>`, creates fresh `WasmtimeBackend` per fixture, calls `evaluate`, calls `check_verdict`, prints `[PASS]`/`[FAIL]` with summary |
| 2 | YAML fixture format specifies request fields, expected verdict (allow/deny), and optional deny reason substring | VERIFIED | `TestFixture` struct (lines 300-312) with `request: GuardRequest`, `expected_verdict: String`, `deny_reason_contains: Option<String>`; unit tests confirm full GuardRequest field deserialization |
| 3 | `arc guard bench` loads a .wasm and runs it against a sample request N iterations, reporting p50/p99 latency and fuel statistics | VERIFIED | `cmd_guard_bench` (lines 435-532): 5-iteration warmup, fresh backend per measured iteration, collects `durations_ns` and `fuel_values`, sorts both, prints p50/p99/min/max/mean for both |
| 4 | `arc guard pack` creates a .arcguard archive (gzipped tar) from guard-manifest.yaml and the .wasm binary | VERIFIED | `pack_from_dir` (lines 577-655): reads manifest via `serde_yml`, resolves wasm path, creates `{name}-{version}.arcguard` using `GzEncoder` + `tar::Builder`, stores manifest and wasm-filename-only as separate entries |
| 5 | `arc guard install` extracts a .arcguard archive to the configured guard directory, placing guard-manifest.yaml and the .wasm binary | VERIFIED | `cmd_guard_install` (lines 657-765): opens archive with `GzDecoder` + `tar::Archive`, extracts to temp dir, reads manifest for guard name, creates `{target_dir}/{guard_name}/`, copies both files, rewrites `wasm_path` in manifest |
| 6 | The .arcguard archive round-trips: pack then install produces the original files | VERIFIED | `test_pack_and_install_round_trip` (lines 1178-1253): creates real files in tempdir, calls `pack_from_dir`, then `cmd_guard_install`, asserts wasm bytes identical and `wasm_path` field updated to co-located filename |

**Score:** 6/6 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/arc-cli/src/guard.rs` | `cmd_guard_test` and `cmd_guard_bench` functions | VERIFIED | Both present and substantive (lines 314-382 and 435-532 respectively); 1292 lines total |
| `crates/arc-cli/src/guard.rs` | `cmd_guard_pack` and `cmd_guard_install` functions | VERIFIED | Both present and substantive (lines 573-575 and 657-765); `pack_from_dir` is the testable internal helper |
| `crates/arc-cli/src/cli/types.rs` | Test, Bench, Pack, Install variants in GuardCommands enum | VERIFIED | All four variants present at lines 233-267 with documented clap args |
| `crates/arc-cli/src/cli/dispatch.rs` | Dispatch arms for all four new commands | VERIFIED | Lines 2208-2211 dispatch all four to `guard::cmd_guard_*` functions |
| `crates/arc-cli/Cargo.toml` | `arc-wasm-guards` with `wasmtime-runtime` feature, `flate2`, `tar` | VERIFIED | Line 59: `arc-wasm-guards` with `wasmtime-runtime`; line 61: `flate2 = "1"`; line 62: `tar = "0.4"` |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `guard.rs` | `arc_wasm_guards::abi::GuardRequest` | YAML fixture deserialized into GuardRequest | VERIFIED | Import at line 7; `TestFixture.request: GuardRequest` used in `cmd_guard_test` |
| `guard.rs` | `arc_wasm_guards::runtime::WasmtimeBackend` | Backend loads .wasm and evaluates for test/bench | VERIFIED | Import at line 9; used in both `cmd_guard_test` (line 345) and `cmd_guard_bench` (line 460/474) |
| `dispatch.rs` | `guard.rs` | GuardCommands::Test and Bench dispatch to cmd_guard_test/cmd_guard_bench | VERIFIED | Lines 2208-2209 confirmed |
| `cmd_guard_pack` | guard-manifest.yaml + .wasm | reads manifest, resolves wasm_path, creates gzipped tar | VERIFIED | `GzEncoder` at line 616; `tar::Builder` at line 617 |
| `cmd_guard_install` | target directory | reads .arcguard archive, extracts gzipped tar to target dir | VERIFIED | `GzDecoder` at line 664; `tar::Archive` at line 665 |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| GCLI-04 | 385-01-PLAN.md | `arc guard test` loads .wasm and runs YAML test fixtures with expected verdicts | SATISFIED | `cmd_guard_test` fully implemented; `test_fixture_yaml_deserializes`, `test_check_verdict_*` tests pass |
| GCLI-05 | 385-01-PLAN.md | Fixture YAML format specifies request fields, expected verdict, optional deny reason substring | SATISFIED | `TestFixture` struct with all GuardRequest fields, `expected_verdict`, `deny_reason_contains`; `test_fixture_all_guard_request_fields` confirms full field coverage |
| GCLI-06 | 385-01-PLAN.md | `arc guard bench` measures fuel consumption and execution time, reports p50/p99 | SATISFIED | `cmd_guard_bench` with p50/p99/min/max/mean for latency and fuel; `test_percentile_basic/single/empty` tests pass |
| GCLI-07 | 385-02-PLAN.md | `arc guard pack` creates a distributable `.arcguard` archive (gzipped tar) | SATISFIED | `pack_from_dir` creates `{name}-{version}.arcguard` using flate2+tar; round-trip test confirms valid archive |
| GCLI-08 | 385-02-PLAN.md | `arc guard install` extracts an `.arcguard` archive to the configured guard directory | SATISFIED | `cmd_guard_install` extracts to `{target_dir}/{guard_name}/` with wasm_path rewrite; round-trip test confirms extraction |

**Note on REQUIREMENTS.md traceability table:** The traceability table lists GCLI-04 through GCLI-08 as "Phase 380" -- this is a pre-existing numbering discrepancy in the REQUIREMENTS.md. The ROADMAP.md correctly maps these requirements to Phase 385, the plans for this phase explicitly claim these IDs, and the implementations exist and are verified. The requirements themselves are marked `[x]` (complete) in the requirements list, confirming intent matches reality.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `guard.rs` | 671 | `unwrap_or("arc-install")` in production `cmd_guard_install` | Info | Cosmetic only -- falls back to a safe string if archive has no stem |
| `guard.rs` | 651 | `unwrap_or(0)` for archive size in print statement | Info | Cosmetic only -- display fallback, does not affect archive validity |

Both are in display/fallback paths, not in correctness-critical code paths. Clippy `-D warnings` passes cleanly (clippy confirmed zero warnings on `cargo clippy -p arc-cli`).

### Human Verification Required

None -- all behaviors are verifiable programmatically. The round-trip test exercises the full pack + install lifecycle with real file I/O. No external service integration is required.

### Test Results

All 24 guard unit tests pass:
- Fixture YAML deserialization (3 tests)
- Verdict checking (5 tests)
- Percentile/bench helpers (5 tests)
- Pack/install lifecycle (4 tests)
- Pre-existing guard tests (7 tests including `cmd_guard_new_*`)

`cargo clippy -p arc-cli` finishes with zero errors and zero warnings.

### Gaps Summary

None. All truths verified, all artifacts exist and are substantive, all key links are wired, all five GCLI requirements (04-08) are satisfied with test evidence. The guard development lifecycle is complete: new, build, inspect, test, bench, pack, install.

---

_Verified: 2026-04-14_
_Verifier: Claude (gsd-verifier)_
