# Phase 389: Cross-Language Conformance Suite - Context

**Gathered:** 2026-04-15
**Status:** Ready for planning

<domain>
## Phase Boundary

Shared YAML fixture set exercising Allow, Deny, deny-reason, host function calls,
and enriched request fields. Conformance runner loads all four language guards
(Rust, TypeScript, Python, Go) against every fixture and reports pass/fail per
guard per fixture. Fuel consumption parity validation (no language exceeds 2x
the most efficient).

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key constraints:

- Shared YAML fixtures in tests/conformance/fixtures/
- Conformance runner as Rust integration test (or standalone binary)
- Tests all four language guards against the same fixture set
- Reports pass/fail per guard per fixture in single invocation
- Fuel consumption comparison with 2x threshold
- Guards that are not compiled (Go without TinyGo) should be gracefully skipped

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- Example guards in all 4 languages with identical deny-list logic
- WasmtimeBackend and ComponentBackend for loading both core and component modules
- create_backend() for auto-detecting module type
- Existing integration tests as patterns (example_guard_integration.rs, ts/py/go tests)
- arc-cli guard test fixture YAML format (Phase 385)

### Integration Points
- Compiled .wasm binaries from Rust, TypeScript, Python (Go conditional)
- TestFixture YAML format from guard.rs
- WasmGuardAbi::last_fuel_consumed() for fuel tracking

</code_context>

<specifics>
## Specific Ideas

No specific requirements -- infrastructure phase

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
