---
phase: 374-security-hardening-and-request-enrichment
plan: 02
subsystem: security
tags: [wasm, guard-request, action-extraction, enrichment, abi]

requires:
  - phase: 374-01
    provides: WasmGuardConfig with resource limits, import validation, security error variants
  - phase: 373-wasm-runtime-host-foundation
    provides: WasmHostState, shared Arc<Engine>, host functions, WasmtimeBackend

provides:
  - GuardRequest enriched with action_type, extracted_path, extracted_target, filesystem_roots, matched_grant_index
  - arc-guards dependency in arc-wasm-guards for extract_action() integration
  - session_metadata field removal from GuardRequest ABI
  - build_request() calling extract_action() to auto-classify tool actions

affects: [wasm-guards, guard-sdk, 374-03]

tech-stack:
  added: [arc-guards dependency in arc-wasm-guards]
  patterns: [host-side action extraction before WASM boundary crossing, enriched request ABI with optional serde-skip fields]

key-files:
  created: []
  modified:
    - crates/arc-wasm-guards/Cargo.toml
    - crates/arc-wasm-guards/src/abi.rs
    - crates/arc-wasm-guards/src/runtime.rs

key-decisions:
  - "build_request() uses a function-local import of ToolAction to keep the use-site localized and avoid polluting the module namespace"
  - "Unrecognized tools map to action_type 'mcp_tool' via extract_action's fallback rather than 'unknown', matching the actual extract_action semantics"
  - "build_request promoted to pub(crate) visibility to enable direct enrichment unit tests without mock backend ceremony"

patterns-established:
  - "Host-extracted action classification: call extract_action() on the host side and pass structured results to WASM guests so guards never re-derive action types"
  - "Optional serde fields with skip_serializing_if: backward-compatible ABI extension without breaking existing deserialization"

requirements-completed: [WGREQ-01, WGREQ-02, WGREQ-03, WGREQ-04, WGREQ-05, WGREQ-06]

duration: 15min
completed: 2026-04-14
---

# Phase 374 Plan 02: WASM Guard Request Enrichment Summary

**GuardRequest enriched with host-extracted action_type, extracted_path, extracted_target, filesystem_roots, and matched_grant_index via arc_guards::extract_action() integration**

## Performance

- **Duration:** 15 min
- **Started:** 2026-04-14T21:35:43Z
- **Completed:** 2026-04-14T21:51:16Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- GuardRequest struct updated with five new enrichment fields and session_metadata removed (ABI cleanup)
- build_request() now calls arc_guards::extract_action() to classify tool actions and populate action_type, extracted_path, extracted_target
- filesystem_roots and matched_grant_index populated from GuardContext session and capability data
- 9 new tests (3 serialization round-trip + 6 enrichment unit tests) covering all WGREQ requirements
- All 53 crate tests pass, clippy clean, workspace tests pass

## Task Commits

Each task was committed atomically:

1. **Task 1: Update GuardRequest struct with enrichment fields and remove session_metadata** - `4bc4b0f` (test)
2. **Task 2: Wire extract_action() into build_request() and update all test fixtures** - `c9cd0a2` (feat)

## Files Created/Modified
- `crates/arc-wasm-guards/Cargo.toml` - Added arc-guards dependency for extract_action()
- `crates/arc-wasm-guards/src/abi.rs` - Replaced session_metadata with 5 enrichment fields, added 3 serialization tests
- `crates/arc-wasm-guards/src/runtime.rs` - Rewrote build_request() with extract_action(), updated all test fixtures, added 6 enrichment tests

## Decisions Made
- Used function-local import of ToolAction in build_request() to keep the module namespace clean
- Unrecognized tools map to "mcp_tool" (not "unknown") because extract_action() treats unknown tools as generic MCP tool invocations as a fallback
- Promoted build_request() from private to pub(crate) to enable direct enrichment tests without needing a mock backend that captures the request

## Deviations from Plan

None -- plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None -- no external service configuration required.

## Next Phase Readiness
- Request enrichment complete; all WGREQ-01 through WGREQ-06 requirements verified and tested
- WASM guards now receive pre-classified action context, enabling policy decisions without duplicating host extraction logic
- Ready for guard SDK development (v4.1) or additional guard policy phases

---
*Phase: 374-security-hardening-and-request-enrichment*
*Completed: 2026-04-14*
