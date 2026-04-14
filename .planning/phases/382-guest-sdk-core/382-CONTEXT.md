# Phase 382: Guest SDK Core - Context

**Gathered:** 2026-04-14
**Status:** Ready for planning

<domain>
## Phase Boundary

Create the arc-guard-sdk crate providing guest-side types (GuardRequest,
GuardVerdict), a guest allocator (arc_alloc, arc_free), typed host function
bindings (arc::log, arc::get_config, arc::get_time), JSON serde glue for
linear memory, and arc_deny_reason export for structured deny reporting.
Guard authors import this crate and never touch raw pointer/length ABI glue.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key constraints:

- Target: wasm32-unknown-unknown (no_std friendly but std is acceptable for JSON serde)
- Types must match host ABI exactly (GuardRequest JSON schema from arc-wasm-guards/src/abi.rs)
- Guest allocator: simple bump or vec-based allocator exported as arc_alloc/arc_free
- Host bindings: extern "C" declarations matching the arc.log, arc.get_config, arc.get_time_unix_secs imports registered in host.rs
- Serde: deserialize GuardRequest from (ptr, len) in linear memory, encode GuardVerdict back
- arc_deny_reason: export function that returns structured deny reason string
- No dependency on wasmtime or any host-side crate
- This crate compiles to wasm32-unknown-unknown target

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-wasm-guards/src/abi.rs` -- Host-side GuardRequest/GuardVerdict (source of truth for ABI)
- `crates/arc-wasm-guards/src/host.rs` -- Host function signatures (arc.log, arc.get_config, arc.get_time_unix_secs)
- `crates/arc-wasm-guards/src/runtime.rs` -- How host calls evaluate(ptr, len) and reads arc_alloc/arc_deny_reason

### Established Patterns
- JSON over linear memory for request/verdict exchange
- arc_alloc(size: i32) -> i32 returns pointer to allocated memory
- arc_deny_reason(ptr: i32, len: i32) -> i32 returns structured deny JSON
- VERDICT_ALLOW = 0, VERDICT_DENY = 1

### Integration Points
- Must compile to wasm32-unknown-unknown
- Host detects arc_alloc/arc_deny_reason exports via get_typed_func
- Host registers arc.log(level, ptr, len), arc.get_config(key_ptr, key_len, val_ptr, val_len) -> i32, arc.get_time_unix_secs() -> i64

</code_context>

<specifics>
## Specific Ideas

No specific requirements -- infrastructure phase

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
