# Phase 376: Benchmark Validation - Context

**Gathered:** 2026-04-14
**Status:** Ready for planning

<domain>
## Phase Boundary

Performance benchmark spike for the WASM guard runtime: module compilation
time, per-call instantiation overhead, p50/p99 evaluate latency, fuel metering
overhead percentage, and ResourceLimiter memory cap validation under adversarial
allocation. Results documented with pass/fail against decision record thresholds.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key constraints from docs/guards/05-V1-DECISION.md:

- Module compilation threshold: 50ms for representative guard sizes
- Per-call p99 latency threshold: 5ms
- Benchmark representative sizes: 50 KiB Rust guard, 5 MiB large module
- Fuel metering overhead: quantify percentage (fuel-enabled vs disabled)
- ResourceLimiter: validate under adversarial guest allocation patterns
- Use Criterion for benchmarks (already in workspace)
- Document results with pass/fail verdicts

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-wasm-guards/src/runtime.rs` -- WasmtimeBackend with all security and host function features
- `crates/arc-wasm-guards/src/host.rs` -- WasmHostState with ResourceLimiter
- Criterion benchmarks already exist in other crates (arc-core benches/)
- WAT inline modules for test fixtures (established in Phases 373-374)

### Established Patterns
- Criterion benchmark harness in benches/ directory
- cargo bench --bench <name> invocation
- WAT modules compiled inline for self-contained benchmarks

### Integration Points
- Cargo.toml: criterion dev-dependency, [[bench]] entries
- WasmtimeBackend::new() and evaluate() are the hot paths to benchmark

</code_context>

<specifics>
## Specific Ideas

No specific requirements -- infrastructure phase

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
