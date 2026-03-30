---
phase: 02-e12-security-boundary-completion
plan: 04
verified: 2026-03-19T20:17:13Z
status: passed
score: 3/3 truths verified
---

# Phase 2 Plan 02-04 Verification Report

**Phase Goal:** Turn negotiated roots into enforced runtime boundaries for filesystem-shaped tools and filesystem-backed resources.
**Scoped Gate:** Plan 02-04 - Carry signed filesystem-boundary deny evidence through the supported transport path, prove fail-closed resource semantics in the live wrapped runtime, and close the remaining roots-as-metadata documentation gap (`SEC-01`, `SEC-03`, `SEC-04` phase-close gate).
**Verified:** 2026-03-19T20:17:13Z
**Status:** passed
**Re-verification:** Yes - local fallback after the independent verifier sidecar stalled without writing an artifact.

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Filesystem-backed resource-root denials now produce signed receipts at the session/kernel boundary instead of plain transport-only errors. | ✓ VERIFIED | [`crates/arc-kernel/src/session.rs#L502`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/session.rs#L502) through [`crates/arc-kernel/src/session.rs#L515`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/session.rs#L515) adds `SessionOperationResponse::ResourceReadDenied { receipt }`. [`crates/arc-kernel/src/lib.rs#L1108`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1108) through [`crates/arc-kernel/src/lib.rs#L1142`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1142) builds and records a signed deny receipt for `resources/read` with guard `session_roots`. [`crates/arc-kernel/src/lib.rs#L1533`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1533) through [`crates/arc-kernel/src/lib.rs#L1550`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/lib.rs#L1550) converts `ResourceRootDenied` into that signed response variant. |
| 2 | The MCP/JSON-RPC transport preserves the signed deny evidence and the live wrapped `mcp serve` path proves in-root allow, out-of-root deny, and missing-roots fail-closed behavior. | ✓ VERIFIED | [`crates/arc-mcp-adapter/src/edge.rs#L2327`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mcp-adapter/src/edge.rs#L2327) through [`crates/arc-mcp-adapter/src/edge.rs#L2355`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mcp-adapter/src/edge.rs#L2355) maps `ResourceReadDenied` into a JSON-RPC error whose `error.data.receipt` carries the signed receipt. [`crates/arc-cli/tests/mcp_serve.rs#L2091`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/tests/mcp_serve.rs#L2091) through [`crates/arc-cli/tests/mcp_serve.rs#L2129`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/tests/mcp_serve.rs#L2129) proves in-root allow plus out-of-root deny receipt propagation on the live wrapped path, and [`crates/arc-cli/tests/mcp_serve.rs#L2217`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/tests/mcp_serve.rs#L2217) through [`crates/arc-cli/tests/mcp_serve.rs#L2240`](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/tests/mcp_serve.rs#L2240) proves the missing-roots fail-closed case with a verified signed receipt. |
| 3 | Phase 2 documentation now describes roots as an enforced boundary, not metadata-only session state, and explicitly calls out signed filesystem-backed deny evidence. | ✓ VERIFIED | [`docs/epics/E12-security-boundary-completion.md#L29`](/Users/connor/Medica/backbay/standalone/arc/docs/epics/E12-security-boundary-completion.md#L29) through [`docs/epics/E12-security-boundary-completion.md#L35`](/Users/connor/Medica/backbay/standalone/arc/docs/epics/E12-security-boundary-completion.md#L35) states that roots are enforced as a runtime boundary and that filesystem-backed resource denials carry signed evidence. [`docs/epics/E12-security-boundary-completion.md#L140`](/Users/connor/Medica/backbay/standalone/arc/docs/epics/E12-security-boundary-completion.md#L140) through [`docs/epics/E12-security-boundary-completion.md#L176`](/Users/connor/Medica/backbay/standalone/arc/docs/epics/E12-security-boundary-completion.md#L176) keeps that contract in the task breakdown and acceptance criteria. [`docs/POST_REVIEW_EXECUTION_PLAN.md#L34`](/Users/connor/Medica/backbay/standalone/arc/docs/POST_REVIEW_EXECUTION_PLAN.md#L34) through [`docs/POST_REVIEW_EXECUTION_PLAN.md#L39`](/Users/connor/Medica/backbay/standalone/arc/docs/POST_REVIEW_EXECUTION_PLAN.md#L39) and [`docs/POST_REVIEW_EXECUTION_PLAN.md#L131`](/Users/connor/Medica/backbay/standalone/arc/docs/POST_REVIEW_EXECUTION_PLAN.md#L131) through [`docs/POST_REVIEW_EXECUTION_PLAN.md#L136`](/Users/connor/Medica/backbay/standalone/arc/docs/POST_REVIEW_EXECUTION_PLAN.md#L136) now describe roots as a hard boundary and require transport propagation of signed deny evidence. |

**Score:** 3/3 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `crates/arc-kernel/src/session.rs` | Session response surface can carry signed `resources/read` denials. | ✓ VERIFIED | The new `ResourceReadDenied` variant makes the deny path explicit and typed. |
| `crates/arc-kernel/src/lib.rs` | Kernel signs and records filesystem-backed resource deny receipts before transport rendering. | ✓ VERIFIED | The deny receipt is signed, annotated with the `session_roots` guard, and recorded in the receipt store. |
| `crates/arc-mcp-adapter/src/edge.rs` | JSON-RPC `resources/read` denials carry signed receipt evidence in `error.data`. | ✓ VERIFIED | The edge now returns `resource read denied: ...` plus `error.data.receipt`. |
| `crates/arc-cli/tests/mcp_serve.rs` | Live wrapped transport covers in-root allow, out-of-root deny, and missing-roots fail-closed with receipt verification. | ✓ VERIFIED | Both deny paths deserialize and verify the signed receipt. |
| `docs/epics/E12-security-boundary-completion.md` | The epic no longer describes roots as metadata-only and explicitly states the signed-evidence contract. | ✓ VERIFIED | Outcome, task, and acceptance language all match the implemented boundary. |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| `SEC-01` | `02-04-PLAN.md` | Roots are normalized consistently across supported transports and platforms for filesystem-shaped access. | ✓ PHASE SATISFIED | The phase-close proof still runs through the shared session-root model introduced earlier in Phase 2, and the live wrapped transport path now proves that the same root contract is enforced at runtime rather than remaining documentation-only. |
| `SEC-03` | `02-04-PLAN.md` | Filesystem-backed resource reads outside allowed roots fail closed with signed evidence. | ✓ SATISFIED | Signed deny receipts are created in kernel/session code and propagated through JSON-RPC `error.data.receipt`, with live wrapped-path tests verifying both out-of-root and missing-roots denials. |
| `SEC-04` | `02-04-PLAN.md` | Missing, empty, or stale roots never silently widen access. | ✓ PHASE SATISFIED | The live `mcp serve` test now proves that missing roots deny a filesystem-backed `resources/read` call with a signed deny receipt instead of silently allowing or downgrading the boundary. |

### Commands Run

| Command | Result |
| --- | --- |
| `cargo test -p arc-kernel read_resource` | Exit `0`. Ran the kernel resource-read scope tests; all 3 relevant tests passed. |
| `cargo test -p arc-mcp-adapter resources_read` | Exit `0`. Ran the JSON-RPC edge resource-read tests; all 4 relevant tests passed. |
| `cargo test -p arc-cli mcp_serve` | Exit `0`. Ran the live wrapped CLI transport tests, including the new signed-evidence resource-root cases; all relevant tests passed. |
| `cargo fmt --all -- --check` | Exit `0`. No formatting diffs reported. |

### Human Verification Required

None. The remaining gap was a transport/runtime evidence contract, and the scoped automated tests now exercise that contract end-to-end.

### Conclusion

Plan `02-04` closes the last open Phase 2 gap. Filesystem-backed resource-root denials are now signed where the decision is made, the transport preserves that evidence instead of flattening it into a plain error, and the live wrapped runtime proves both out-of-root and missing-roots fail-closed behavior. The earlier review finding that roots were metadata-only is no longer true for the supported filesystem-shaped surfaces in scope for E12.

---

_Verified: 2026-03-19T20:17:13Z_
_Verifier: Codex local fallback after stalled gsd-verifier sidecar_
