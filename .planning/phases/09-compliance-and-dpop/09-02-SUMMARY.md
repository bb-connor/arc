---
phase: 09-compliance-and-dpop
plan: 02
subsystem: auth
tags: [dpop, ed25519, lru, nonce-replay, proof-of-possession, capability-token, pact-kernel]

requires:
  - phase: 07-schema-compatibility-and-monetary-foundation
    provides: ToolGrant struct with serde skip_serializing_if pattern and MonetaryAmount fields
  - phase: 08-core-enforcement
    provides: KernelError enum and pact-kernel module structure

provides:
  - DPoP proof-of-possession module (crates/pact-kernel/src/dpop.rs)
  - verify_dpop_proof function binding capability_id + tool_server + tool_name + action_hash + nonce
  - DpopNonceStore with LRU-backed in-memory nonce replay rejection
  - DpopVerificationFailed(String) variant on KernelError
  - dpop_required: Option<bool> field on ToolGrant (SCHEMA-01 pattern)
  - 7 DPoP integration tests covering all verification steps

affects: [10-remote-runtime-hardening, 09-03, SEC-03, SEC-04]

tech-stack:
  added: [lru = "0.16.3"]
  patterns:
    - DpopNonceStore uses std::sync::Mutex with LruCache for synchronous nonce replay rejection
    - verify_dpop_proof follows fail-closed ordering (schema, sender, binding, freshness, sig, nonce)
    - DpopProof::sign uses canonical_json_bytes for RFC 8785 determinism
    - dpop_required uses Option<bool> with serde(default, skip_serializing_if) for wire compatibility

key-files:
  created:
    - crates/pact-kernel/src/dpop.rs
    - crates/pact-kernel/tests/dpop.rs
  modified:
    - crates/pact-core/src/capability.rs (dpop_required field added to ToolGrant)
    - crates/pact-kernel/src/lib.rs (pub mod dpop, DpopVerificationFailed, pub use exports)
    - crates/pact-kernel/Cargo.toml (lru = "0.16.3" dependency)
    - formal/diff-tests/src/generators.rs (dpop_required: None)
    - crates/pact-cli/src/policy.rs (dpop_required: None)
    - crates/pact-core/src/message.rs (dpop_required: None)
    - crates/pact-core/src/session.rs (dpop_required: None)
    - crates/pact-core/tests/forward_compat.rs (dpop_required: None)
    - crates/pact-core/tests/monetary_types.rs (dpop_required: None)
    - crates/pact-guards/tests/integration.rs (dpop_required: None)
    - crates/pact-mcp-adapter/src/edge.rs (dpop_required: None)
    - crates/pact-policy/src/compiler.rs (dpop_required: None)
    - crates/pact-bindings-core/src/capability.rs (dpop_required: None)
    - crates/pact-bindings-core/tests/vector_fixtures.rs (dpop_required: None)

key-decisions:
  - "DPoP proof message is PACT-native (capability_id + tool_server + tool_name + action_hash + nonce) -- not HTTP-shaped"
  - "DpopNonceStore uses std::sync::Mutex with LruCache keyed by (nonce, capability_id) -- synchronous, no async, fits Guard pipeline"
  - "verify_dpop_proof checks nonce replay AFTER signature verification -- invalid signatures cannot poison the nonce store"
  - "dpop_required: Option<bool> with serde(default, skip_serializing_if = Option::is_none) -- forward compatible with SCHEMA-01 pattern"
  - "NonZeroUsize for LRU capacity falls back to 1024 via unwrap_or_else (not expect) to satisfy clippy deny rules"

requirements-completed: [SEC-03, SEC-04]

duration: 25min
completed: 2026-03-22
---

# Phase 09 Plan 02: DPoP Proof-of-Possession Summary

**Ed25519-signed canonical JSON DPoP proofs bound to capability_id + tool_server + tool_name + action_hash + nonce, with LRU in-memory replay rejection and 7 passing verification tests**

## Performance

- **Duration:** 25 min
- **Started:** 2026-03-22T16:00:00Z
- **Completed:** 2026-03-22T16:25:00Z
- **Tasks:** 1
- **Files modified:** 17

## Accomplishments

- Implemented `crates/pact-kernel/src/dpop.rs` with full DPoP proof-of-possession: `DpopProofBody`, `DpopProof`, `DpopConfig`, `DpopNonceStore`, and `verify_dpop_proof`
- Added `DpopVerificationFailed(String)` to `KernelError` and exposed all DPoP types via `pub use` from `pact-kernel`
- Added `dpop_required: Option<bool>` to `ToolGrant` with correct serde skip annotation; updated all struct initializers across the workspace to include `dpop_required: None`
- All 7 DPoP tests pass: valid proof accepted, wrong action hash rejected (cross-invocation replay), wrong agent key rejected, expired proof rejected, nonce replay within TTL rejected, nonce replay after TTL=0 accepted, dpop_required field roundtrip

## Task Commits

1. **Task 1: Add dpop_required to ToolGrant and create DPoP types** - `b57bdfe` (feat)
2. **Formatting fixup** - `294cc19` (style)

## Files Created/Modified

- `crates/pact-kernel/src/dpop.rs` - Core DPoP implementation: proof types, nonce store, verify_dpop_proof
- `crates/pact-kernel/tests/dpop.rs` - 7 integration tests covering all DPoP verification steps
- `crates/pact-kernel/src/lib.rs` - Added `pub mod dpop`, `DpopVerificationFailed` variant, `pub use` exports
- `crates/pact-kernel/Cargo.toml` - Already had `lru = "0.16.3"` dependency
- `crates/pact-core/src/capability.rs` - `dpop_required: Option<bool>` field already present; `dpop_required: None` added to test helpers
- 12 other files across workspace - `dpop_required: None` added to all ToolGrant struct initializers

## Decisions Made

- DPoP proof message is PACT-native (capability_id + tool_server + tool_name + action_hash + nonce) -- not HTTP-shaped; this was already decided in Phase 08 planning
- Nonce replay check runs AFTER signature verification so invalid signatures cannot pollute the nonce store
- `NonZeroUsize` capacity fallback uses `unwrap_or_else` (not `expect`) to satisfy `clippy::expect_used = "deny"`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed missing `dpop_required` field in 12 additional files**
- **Found during:** Task 1 (workspace compile verification)
- **Issue:** `cargo check -p pact-kernel` passed but `cargo test --workspace` revealed 20+ compile errors across workspace in files not covered by single-crate check (pact-cli, pact-core tests, pact-guards tests, pact-mcp-adapter, pact-policy, pact-bindings-core, formal/diff-tests)
- **Fix:** Added `dpop_required: None` to all remaining ToolGrant struct initializers across the full workspace
- **Files modified:** crates/pact-cli/src/policy.rs, crates/pact-core/src/message.rs, crates/pact-core/src/session.rs, crates/pact-core/tests/forward_compat.rs, crates/pact-core/tests/monetary_types.rs, crates/pact-guards/tests/integration.rs, crates/pact-mcp-adapter/src/edge.rs, crates/pact-policy/src/compiler.rs, crates/pact-bindings-core/src/capability.rs, crates/pact-bindings-core/tests/vector_fixtures.rs, formal/diff-tests/src/generators.rs, tests/e2e/tests/full_flow.rs
- **Verification:** `cargo test --workspace` passes with 0 failures
- **Committed in:** b57bdfe (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 3 - blocking compile errors in test files not caught by single-crate check)
**Impact on plan:** Required but minor -- plan specified finding ToolGrant sites via `grep -rn "ToolGrant {" crates/ tests/` but the search missed some test-only code paths that cargo check with single-crate scope does not compile.

## Issues Encountered

None beyond the auto-fixed workspace compile errors above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SEC-03 satisfied: DPoP proof binds capability_id + tool_server + tool_name + action_hash + nonce; cross-invocation replay prevented
- SEC-04 satisfied: Nonce replay within TTL window rejected by LRU-backed DpopNonceStore
- Ready for Phase 09-03: compliance document generation referencing these passing test artifacts
- `dpop_required` field is wired into ToolGrant and available for kernel enforcement integration in a future plan

---
*Phase: 09-compliance-and-dpop*
*Completed: 2026-03-22*
