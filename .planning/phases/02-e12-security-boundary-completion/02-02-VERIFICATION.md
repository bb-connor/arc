---
phase: 02-e12-security-boundary-completion
plan: 02
verified: 2026-03-19T19:38:56Z
status: passed
score: 2/2 must-haves verified
---

# Phase 2 Plan 02-02 Verification Report

**Phase Goal:** Turn negotiated roots into enforced runtime boundaries for filesystem-shaped tools and filesystem-backed resources.
**Scoped Gate:** Plan 02-02 - Enforce roots for tool calls with path-bearing arguments and fail-closed receipts (`SEC-02`, `SEC-04` tool-call slice).
**Verified:** 2026-03-19T19:38:56Z
**Status:** passed
**Re-verification:** No - initial slice verification.

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Filesystem-shaped tool access outside allowed roots is denied. | ✓ VERIFIED | [`crates/arc-kernel/src/lib.rs#L1281`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1281) through [`crates/arc-kernel/src/lib.rs#L1294`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1294) routes session-backed tool calls through `evaluate_tool_call_with_session_roots`, [`crates/arc-kernel/src/lib.rs#L1998`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1998) through [`crates/arc-kernel/src/lib.rs#L2010`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L2010) injects `session_filesystem_roots` into `GuardContext`, and [`crates/arc-guards/src/path_allowlist.rs#L186`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L186) through [`crates/arc-guards/src/path_allowlist.rs#L195`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L195) denies any filesystem action whose normalized path is not contained by the session roots. [`crates/arc-guards/tests/integration.rs#L351`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L351) through [`crates/arc-guards/tests/integration.rs#L400`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L400) proves an out-of-root `filesystem` call returns `Verdict::Deny`, while [`crates/arc-kernel/src/lib.rs#L2141`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L2141) through [`crates/arc-kernel/src/lib.rs#L2177`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L2177) shows the deny path is emitted as a signed receipt-backed response. |
| 2 | The runtime fails closed when it cannot prove a filesystem-shaped tool path is in-root. | ✓ VERIFIED | [`crates/arc-guards/src/path_allowlist.rs#L124`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L124) through [`crates/arc-guards/src/path_allowlist.rs#L127`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L127) collapses an empty root set to `false`, and [`crates/arc-kernel/src/lib.rs#L1290`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1290) through [`crates/arc-kernel/src/lib.rs#L1294`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1294) always passes the session's enforceable filesystem roots, even when that list is empty. [`crates/arc-guards/tests/integration.rs#L404`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L404) through [`crates/arc-guards/tests/integration.rs#L445`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L445) verifies the missing-roots case denies instead of widening access. The nested-flow runtime path also preserves this behavior by fetching the parent session roots before guard evaluation at [`crates/arc-kernel/src/lib.rs#L1761`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1761) through [`crates/arc-kernel/src/lib.rs#L1767`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1767). |

**Score:** 2/2 truths verified

Scope note: Plan `02-02` is the tool-call enforcement slice. It does not cover filesystem-backed resource reads; that work remains correctly deferred to `02-03`. Within the scoped tool runtime, the plan's acceptance criteria are satisfied: in-root access remains possible when otherwise permitted, out-of-root access denies, and missing roots fail closed.

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `crates/arc-kernel/src/lib.rs` | Session-backed tool evaluation must consume enforceable filesystem roots through the shared guard path and keep deny receipts signed. | ✓ VERIFIED | Substantive and wired. [`#L318`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L318) through [`#L330`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L330) extends `GuardContext` with `session_filesystem_roots`; [`#L1281`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1281) through [`#L1294`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1294) and [`#L1761`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1761) through [`#L1767`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1767) pass session roots into guard evaluation for both session-backed runtime paths; [`#L2141`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L2141) through [`#L2177`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L2177) signs deny receipts. |
| `crates/arc-guards/src/action.rs` | Existing filesystem tool classification must expose a shared path-bearing helper for root enforcement. | ✓ VERIFIED | Substantive and wired. [`#L33`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/action.rs#L33) through [`#L42`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/action.rs#L42) adds `filesystem_path()`, and [`#L79`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/action.rs#L79) through [`#L105`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/action.rs#L105) keeps the existing `filesystem` tool classification aligned with read/write inference. |
| `crates/arc-guards/src/path_allowlist.rs` | The guard must enforce session-root containment before optional allowlist matching and deny when containment cannot be proven. | ✓ VERIFIED | Substantive and wired. [`#L109`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L109) through [`#L150`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L150) normalize and compare candidate paths against session roots, and [`#L186`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L186) through [`#L213`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L213) deny on root mismatch before checking the configured allowlist. |
| `crates/arc-cli/src/policy.rs` | The supported operator YAML path must be able to instantiate the root-aware guard in the runtime pipeline. | ✓ VERIFIED | Substantive and wired. [`#L147`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/policy.rs#L147) through [`#L200`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/policy.rs#L200) adds `path_allowlist` to the supported ARC YAML surface, [`#L429`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/policy.rs#L429) through [`#L438`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/policy.rs#L438) wires it into `build_guard_pipeline`, and [`#L797`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/policy.rs#L797) through [`#L845`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/policy.rs#L797) proves the resulting pipeline denies an out-of-root session-scoped filesystem tool call. |
| `crates/arc-guards/tests/integration.rs` | Tool-side coverage must prove in-root allow, out-of-root deny, and missing-root fail-closed behavior. | ✓ VERIFIED | Substantive and wired. [`#L297`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L297) through [`#L347`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L347) verifies in-root allow, [`#L351`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L351) through [`#L400`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L400) verifies out-of-root deny, and [`#L404`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L404) through [`#L445`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L445) verifies fail-closed denial when roots are missing. |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `crates/arc-kernel/src/lib.rs` | `crates/arc-guards/src/path_allowlist.rs` | `session_enforceable_filesystem_root_paths_owned` -> `evaluate_tool_call_with_session_roots` -> `run_guards` -> `GuardContext.session_filesystem_roots` | ✓ WIRED | [`crates/arc-kernel/src/lib.rs#L1290`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1290) through [`crates/arc-kernel/src/lib.rs#L1294`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1294) and [`crates/arc-kernel/src/lib.rs#L1998`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1998) through [`crates/arc-kernel/src/lib.rs#L2010`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L2010) connect the session root model directly to guard evaluation. |
| `crates/arc-guards/src/action.rs` | `crates/arc-guards/src/path_allowlist.rs` | `extract_action(...)` plus `ToolAction::filesystem_path()` | ✓ WIRED | [`crates/arc-guards/src/action.rs#L33`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/action.rs#L33) through [`crates/arc-guards/src/action.rs#L42`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/action.rs#L42) and [`crates/arc-guards/src/path_allowlist.rs#L186`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L186) through [`crates/arc-guards/src/path_allowlist.rs#L190`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L190) ensure existing filesystem classification is what feeds root enforcement. |
| `crates/arc-cli/src/policy.rs` | Supported runtime guard path | `build_guard_pipeline` adds `PathAllowlistGuard::with_config(...)` | ✓ WIRED | [`crates/arc-cli/src/policy.rs#L429`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/policy.rs#L429) through [`crates/arc-cli/src/policy.rs#L438`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/policy.rs#L438) make the root-aware guard reachable through the supported ARC YAML path instead of a disconnected policy surface. |
| Guard denial in `run_guards` | Signed deny response | `evaluate_tool_call_with_session_roots` -> `build_deny_response` | ✓ WIRED | [`crates/arc-kernel/src/lib.rs#L1649`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1649) through [`crates/arc-kernel/src/lib.rs#L1652`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1652) route guard failures into the common deny path, and [`crates/arc-kernel/src/lib.rs#L2141`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L2141) through [`crates/arc-kernel/src/lib.rs#L2177`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L2177) produce the signed receipt-backed denial instead of falling through to allow. |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| `SEC-02` | `02-02-PLAN.md` | Filesystem-shaped tool access outside allowed roots fails closed with signed evidence. | ✓ SATISFIED | Root mismatch denial is enforced in [`crates/arc-guards/src/path_allowlist.rs#L192`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L192) through [`crates/arc-guards/src/path_allowlist.rs#L195`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L195), verified by [`crates/arc-guards/tests/integration.rs#L351`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L351) through [`crates/arc-guards/tests/integration.rs#L400`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L400), and returned as a signed deny receipt by [`crates/arc-kernel/src/lib.rs#L2141`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L2141) through [`crates/arc-kernel/src/lib.rs#L2177`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L2177). |
| `SEC-04` | `02-02-PLAN.md` | Missing, empty, or stale roots never silently widen access. | ✓ SATISFIED | For the scoped tool-call path, empty root sets fail closed in [`crates/arc-guards/src/path_allowlist.rs#L124`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L124) through [`crates/arc-guards/src/path_allowlist.rs#L127`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/src/path_allowlist.rs#L127) and are exercised by [`crates/arc-guards/tests/integration.rs#L404`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L404) through [`crates/arc-guards/tests/integration.rs#L445`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-guards/tests/integration.rs#L445). Resource-side enforcement remains Phase `02-03`, so the broader phase requirement is not fully closed by this slice alone. |

### Anti-Patterns Found

No placeholder, TODO, FIXME, stub, or logging-only anti-patterns were found in the scoped plan, summary, code, or planning files reviewed for this slice.

### Commands Run

| Command | Result |
| --- | --- |
| `cargo test -p arc-guards filesystem_tool` | Exit `0`. Ran 11 relevant tests: 5 action-classification unit tests and 6 integration tests covering in-root allow, out-of-root deny, forbidden-path regression coverage, and missing-roots fail-closed behavior; all passed. |
| `cargo test -p arc-cli policy` | Exit `0`. Ran 18 `policy`-filtered unit tests in `src/main.rs`, including `policy_path_allowlist_guard_denies_out_of_root_session_tool`, plus 1 matching integration test in `tests/mcp_serve.rs`; all passed. |
| `cargo fmt --all -- --check` | Exit `0`. No formatting diffs reported. |

### Human Verification Required

None. The slice goal is a code-path and policy-wiring change, and the required automated checks cover the relevant runtime behavior directly.

### Gaps Summary

No scoped gaps were found for Plan `02-02`. The current tree satisfies the slice acceptance criteria: session-backed filesystem tool calls consume the normalized session root model, in-root access still works when otherwise permitted, out-of-root access denies, missing roots fail closed, and the supported ARC YAML loader can instantiate the root-aware guard. Direct `evaluate_tool_call(...)` still lacks session identity by design, so this enforcement remains intentionally scoped to the supported session-backed runtime path and nested-flow path; that is consistent with the plan rather than a verification failure. Filesystem-backed resource enforcement remains future work for `02-03`.

---

_Verified: 2026-03-19T19:38:56Z_
_Verifier: Codex (gsd-verifier)_
