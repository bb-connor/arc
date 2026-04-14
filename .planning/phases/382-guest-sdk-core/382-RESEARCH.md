# Phase 382: Guest SDK Core - Research

**Researched:** 2026-04-14
**Domain:** Rust WASM guest-side SDK (wasm32-unknown-unknown), ABI compatibility with arc-wasm-guards host
**Confidence:** HIGH

## Summary

Phase 382 creates a new `arc-guard-sdk` crate that guard authors import to
write WASM guards without touching raw pointer/length ABI glue. The crate
provides guest-side mirrors of the host's `GuardRequest` and `GuardVerdict`
types, a guest allocator (`arc_alloc`/`arc_free`), typed host function
bindings (`arc::log`, `arc::get_config`, `arc::get_time_unix_secs`),
JSON serde glue for linear memory, and the `arc_deny_reason` export for
structured deny reason reporting.

The host-side ABI is fully implemented and tested in `arc-wasm-guards`
(phases 373-376, all complete). Every contract the guest must satisfy is
visible in `runtime.rs` (how the host probes for `arc_alloc`, calls
`evaluate(ptr, len)`, and reads `arc_deny_reason(buf_ptr, buf_len)`). The
guest SDK is a pure new crate with zero host-side dependencies -- it must
compile to `wasm32-unknown-unknown` and export the exact function signatures
the host expects.

**Primary recommendation:** Build `crates/arc-guard-sdk/` as a std-based
Rust library crate (crate-type `["lib"]` for SDK consumption, but guard
projects will set `crate-type = ["cdylib"]`). Use serde + serde_json for
JSON (both compile cleanly for wasm32-unknown-unknown with std). Implement
a Vec-based guest allocator rather than a bump allocator -- simplicity and
correctness over micro-optimization since guards are short-lived
(fresh Store per invocation).

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
None -- all implementation choices are at Claude's discretion.

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

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| GSDK-01 | `arc-guard-sdk` provides `GuardRequest` and `GuardVerdict` types matching the host ABI | Guest-side types mirror exact JSON schema from `abi.rs` -- all 11 fields on GuardRequest, Allow/Deny enum on GuardVerdict. Serde derive with matching `skip_serializing_if` and `default` annotations. |
| GSDK-02 | Guest-side allocator exported as `arc_alloc` and `arc_free` | Vec-based allocator with `#[no_mangle] pub extern "C"` exports. Host probes via `get_typed_func::<i32, i32>(..., "arc_alloc")`. Signature: `arc_alloc(size: i32) -> i32`, `arc_free(ptr: i32, size: i32)`. |
| GSDK-03 | Typed host function bindings for `arc::log`, `arc::get_config`, `arc::get_time` | `extern "C"` block with `#[link(wasm_import_module = "arc")]` declarations matching host.rs signatures exactly. Wrapped in safe Rust functions. |
| GSDK-04 | GuardRequest deserialization from linear memory and GuardVerdict encoding back to host | Helper function reads `(ptr, len)` from linear memory via `core::slice::from_raw_parts`, deserializes JSON, user function returns GuardVerdict, SDK returns VERDICT_ALLOW (0) or VERDICT_DENY (1). |
| GSDK-05 | `arc_deny_reason` export for structured deny reason reporting | `#[no_mangle] pub extern "C" fn arc_deny_reason(buf_ptr: i32, buf_len: i32) -> i32` writes JSON `GuestDenyResponse` into the host-provided buffer. Host calls this after evaluate returns 1. |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| serde | 1.0.228 | Derive Serialize/Deserialize for ABI types | Workspace standard, wasm32 compatible |
| serde_json | 1.0.149 | JSON serialization across the WASM boundary | Host uses JSON; workspace standard; wasm32 compatible with std |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| (none) | -- | -- | The SDK should have minimal dependencies to keep .wasm binary size small |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| serde_json (std) | miniserde or nanoserde (no_std) | Would reduce binary size but lose compatibility with host's exact serde_json output; not worth the schema drift risk |
| Vec-based allocator | Bump allocator | Bump is simpler but cannot free individual allocations; Vec-based is better for correctness and works fine given per-invocation lifetime |
| Vec-based allocator | wee_alloc (custom global allocator) | wee_alloc is unmaintained; not needed since wasm32-unknown-unknown uses dlmalloc by default with std |

**Installation (new crate, no npm):**
```bash
# Add to workspace Cargo.toml members list:
# "crates/arc-guard-sdk"

# Guard authors add to their Cargo.toml:
# [dependencies]
# arc-guard-sdk = { path = "../arc-guard-sdk" }
```

**Version verification:**
- serde 1.0.228 -- resolved in Cargo.lock
- serde_json 1.0.149 -- resolved in Cargo.lock
- Rust toolchain: 1.93.0 (workspace minimum: 1.93)
- wasm32-unknown-unknown target: installed and verified

## Architecture Patterns

### Recommended Project Structure
```
crates/arc-guard-sdk/
  Cargo.toml
  src/
    lib.rs           # Public API: re-exports, prelude module
    types.rs         # GuardRequest, GuardVerdict, GuestDenyResponse
    alloc.rs         # arc_alloc / arc_free guest-side allocator
    host.rs          # Typed bindings for arc.log, arc.get_config, arc.get_time
    glue.rs          # ABI glue: __evaluate_impl, arc_deny_reason, memory helpers
```

### Pattern 1: Guest-Side Type Mirrors (GSDK-01)

**What:** GuardRequest and GuardVerdict types that produce/consume identical
JSON to the host-side types in `arc-wasm-guards/src/abi.rs`.

**When to use:** Every guard imports these types.

**Example:**
```rust
// Source: derived from crates/arc-wasm-guards/src/abi.rs lines 28-58
use serde::{Deserialize, Serialize};

/// Read-only request context passed to the WASM guard by the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardRequest {
    pub tool_name: String,
    pub server_id: String,
    pub agent_id: String,
    pub arguments: serde_json::Value,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracted_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracted_target: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filesystem_roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_grant_index: Option<usize>,
}

/// Verdict returned by a guard evaluation.
pub enum GuardVerdict {
    Allow,
    Deny { reason: String },
}

impl GuardVerdict {
    pub fn allow() -> Self { Self::Allow }
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny { reason: reason.into() }
    }
}
```

**Critical ABI contract:** The `#[serde(...)]` annotations on all fields
MUST match the host side exactly. Mismatched `skip_serializing_if` or
missing `default` will cause deserialization failures at runtime.

### Pattern 2: Vec-Based Guest Allocator (GSDK-02)

**What:** A simple allocator that the host calls via `arc_alloc(size) -> ptr`
to allocate space in guest linear memory for the request JSON. The host
probes for this export via `get_typed_func::<i32, i32>(&mut store, "arc_alloc").ok()`.

**When to use:** Exported by every guard that uses the SDK.

**Example:**
```rust
// Source: derived from host-side probing in runtime.rs lines 526-528
use std::cell::RefCell;

thread_local! {
    static ALLOCATIONS: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::new());
}

/// Allocate `size` bytes in guest memory and return a stable pointer.
///
/// The host calls this to allocate space for the serialized GuardRequest
/// instead of writing at offset 0. The Vec is kept alive in thread-local
/// storage until arc_free is called.
#[no_mangle]
pub extern "C" fn arc_alloc(size: i32) -> i32 {
    if size <= 0 {
        return 0;
    }
    let buf = vec![0u8; size as usize];
    let ptr = buf.as_ptr() as i32;
    ALLOCATIONS.with(|allocs| {
        allocs.borrow_mut().push(buf);
    });
    ptr
}

/// Free memory previously allocated by arc_alloc.
#[no_mangle]
pub extern "C" fn arc_free(ptr: i32, size: i32) {
    ALLOCATIONS.with(|allocs| {
        let mut allocs = allocs.borrow_mut();
        allocs.retain(|buf| buf.as_ptr() as i32 != ptr || buf.len() != size as usize);
    });
}
```

**Why Vec-based:** Each guard invocation runs in a fresh Store, so
allocations never accumulate across calls. The Vec-based approach leverages
Rust's standard allocator (dlmalloc on wasm32-unknown-unknown) and avoids
implementing a custom allocator from scratch. `mem::forget` is not needed
because the Vec is held in thread-local storage.

### Pattern 3: Host Function Bindings (GSDK-03)

**What:** Safe Rust wrappers around the `extern "C"` host function imports.

**Example:**
```rust
// Source: host signatures from crates/arc-wasm-guards/src/host.rs lines 108-230

// Raw FFI declarations matching the host's registered functions
#[link(wasm_import_module = "arc")]
extern "C" {
    #[link_name = "log"]
    fn arc_log_raw(level: i32, ptr: i32, len: i32);

    #[link_name = "get_config"]
    fn arc_get_config_raw(
        key_ptr: i32, key_len: i32,
        val_out_ptr: i32, val_out_len: i32,
    ) -> i32;

    #[link_name = "get_time_unix_secs"]
    fn arc_get_time_raw() -> i64;
}

/// Log levels matching the host's expected values.
pub mod log_level {
    pub const TRACE: i32 = 0;
    pub const DEBUG: i32 = 1;
    pub const INFO: i32 = 2;
    pub const WARN: i32 = 3;
    pub const ERROR: i32 = 4;
}

/// Emit a log message at the given level via the host's tracing system.
pub fn log(level: i32, msg: &str) {
    unsafe {
        arc_log_raw(level, msg.as_ptr() as i32, msg.len() as i32);
    }
}

/// Read a guard-specific config value by key.
///
/// Returns `Some(value)` if the key exists in the guard manifest config,
/// `None` if the key does not exist or the value is too large for the
/// internal buffer.
pub fn get_config(key: &str) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let actual_len = unsafe {
        arc_get_config_raw(
            key.as_ptr() as i32,
            key.len() as i32,
            buf.as_mut_ptr() as i32,
            buf.len() as i32,
        )
    };
    if actual_len < 0 {
        return None;
    }
    let len = (actual_len as usize).min(buf.len());
    buf.truncate(len);
    String::from_utf8(buf).ok()
}

/// Read the current wall-clock time as Unix seconds.
pub fn get_time() -> i64 {
    unsafe { arc_get_time_raw() }
}
```

**Key detail:** The `#[link(wasm_import_module = "arc")]` attribute is what
makes these resolve to the `arc.log`, `arc.get_config`, and
`arc.get_time_unix_secs` imports that the host registers on the Linker.
The `#[link_name = "..."]` attribute maps Rust function names to the exact
import names the host expects.

### Pattern 4: ABI Glue -- evaluate and arc_deny_reason (GSDK-04, GSDK-05)

**What:** Internal functions that bridge the raw WASM ABI to the user's
typed guard function. The evaluate entrypoint is NOT exported by the SDK
directly -- it will be generated by the proc macro in Phase 383. For
Phase 382, the SDK provides building blocks that the proc macro (or a
manual user) composes.

**Example:**
```rust
// Source: host calls evaluate(ptr, len) per runtime.rs lines 572-577
//         host calls arc_deny_reason(buf_ptr, buf_len) per runtime.rs lines 605-614

use std::cell::RefCell;

/// ABI constants matching the host's expectations.
pub const VERDICT_ALLOW: i32 = 0;
pub const VERDICT_DENY: i32 = 1;

thread_local! {
    /// Stores the deny reason from the most recent evaluation.
    static LAST_DENY_REASON: RefCell<Option<String>> = RefCell::new(None);
}

/// Deserialize a GuardRequest from guest linear memory at (ptr, len).
///
/// # Safety
/// The caller must ensure ptr and len describe a valid memory region
/// containing UTF-8 JSON written by the host.
pub unsafe fn read_request(ptr: i32, len: i32) -> Result<GuardRequest, String> {
    let slice = core::slice::from_raw_parts(ptr as *const u8, len as usize);
    serde_json::from_slice(slice).map_err(|e| e.to_string())
}

/// Encode a GuardVerdict as the i32 return value for the host.
/// If the verdict is Deny, stores the reason for arc_deny_reason to read.
pub fn encode_verdict(verdict: GuardVerdict) -> i32 {
    match verdict {
        GuardVerdict::Allow => {
            LAST_DENY_REASON.with(|r| *r.borrow_mut() = None);
            VERDICT_ALLOW
        }
        GuardVerdict::Deny { reason } => {
            LAST_DENY_REASON.with(|r| *r.borrow_mut() = Some(reason));
            VERDICT_DENY
        }
    }
}

/// Structured deny reason export called by the host after evaluate returns 1.
///
/// The host passes (buf_ptr, buf_len) pointing to a region in guest memory.
/// This function writes a JSON GuestDenyResponse into that buffer and returns
/// the number of bytes written, or -1 if no reason is available.
///
/// Host contract (from runtime.rs read_structured_deny_reason):
/// - Signature: (i32, i32) -> i32
/// - buf_ptr = 65536, buf_len = 4096 (constants in host)
/// - Return value > 0 and <= buf_len: success, host reads that many bytes
/// - Return value <= 0: no reason available
#[no_mangle]
pub extern "C" fn arc_deny_reason(buf_ptr: i32, buf_len: i32) -> i32 {
    LAST_DENY_REASON.with(|r| {
        let reason = match r.borrow().as_ref() {
            Some(reason) => reason.clone(),
            None => return -1,
        };

        let response = serde_json::json!({"reason": reason});
        let json_bytes = match serde_json::to_vec(&response) {
            Ok(b) => b,
            Err(_) => return -1,
        };

        if json_bytes.len() > buf_len as usize {
            return -1;
        }

        // Write into the buffer region
        let dest = unsafe {
            core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len as usize)
        };
        dest[..json_bytes.len()].copy_from_slice(&json_bytes);

        json_bytes.len() as i32
    })
}
```

### Anti-Patterns to Avoid

- **Depending on arc-core, arc-kernel, or arc-wasm-guards:** The guest SDK
  must have ZERO dependencies on host-side crates. Those crates pull in
  wasmtime, tokio, ed25519-dalek, getrandom, and other libraries that do
  not compile for wasm32-unknown-unknown.
- **Using `unwrap()` or `expect()`:** Workspace-wide clippy lint
  `unwrap_used = "deny"` and `expect_used = "deny"` apply. Use
  `Result`/`Option` combinators or match statements.
- **Using `panic!` paths in allocator:** A panic in the guest causes a WASM
  trap. The host treats traps as deny (fail-closed), which is safe, but the
  allocator should be infallible where possible (return 0 on failure rather
  than panic).
- **Sharing types via a common crate:** Do NOT create a shared types crate
  between host and guest. The host types are in arc-wasm-guards (behind
  wasmtime feature flag). The guest types must be independent but
  JSON-schema-compatible. This is the same pattern used by Extism PDK.
- **Using `#[global_allocator]` with wee_alloc:** wee_alloc is unmaintained
  since 2021. The default dlmalloc on wasm32-unknown-unknown is fine.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| JSON serialization | Custom JSON parser | serde + serde_json | Must produce bit-identical JSON to host; serde_json is the host's serializer |
| Memory allocation | Custom bump allocator | Vec-based with std's dlmalloc | dlmalloc is the default allocator for wasm32-unknown-unknown with std; Vec gives correct deallocation semantics |
| Host function FFI | Manual raw syscalls | `#[link(wasm_import_module)]` | Rust's wasm import module attribute is the standard way to declare host imports |

**Key insight:** The guest SDK's correctness is defined by ABI compatibility
with the host. Every design choice must be validated against the exact
function signatures, buffer layouts, and return value conventions in
`runtime.rs`. There is no room for creative interpretation -- the host
dictates the contract.

## Common Pitfalls

### Pitfall 1: Serde Annotation Mismatch
**What goes wrong:** Guest `GuardRequest` uses `#[serde(default)]` on a
field where the host has no default, or vice versa. Deserialization fails
silently or panics.
**Why it happens:** The types are duplicated, not shared. Drift is easy.
**How to avoid:** Copy the exact struct definition from `abi.rs` and add a
unit test that serializes a `GuardRequest` with the host's serde_json and
deserializes it with the guest's serde_json (cross-crate round-trip test
in Phase 383's integration tests).
**Warning signs:** `serde_json::from_slice` returns Err in the evaluate path.

### Pitfall 2: Pointer Truncation on 64-bit Hosts
**What goes wrong:** Using `as i32` to cast pointers in the guest.
wasm32-unknown-unknown is 32-bit, so `*const u8 as i32` is correct. But
if someone accidentally tests the SDK on a 64-bit native target, pointers
are 64 bits and truncation occurs.
**Why it happens:** CI might run `cargo test` on the host target by default.
**How to avoid:** Guard the `extern "C"` functions and raw pointer casts
behind `#[cfg(target_arch = "wasm32")]` or ensure the crate only compiles
for wasm32 targets. For unit tests of non-ABI logic, use `cfg(test)` with
mock implementations.
**Warning signs:** Tests pass on native but guards crash when loaded as WASM.

### Pitfall 3: arc_deny_reason Buffer Overflow
**What goes wrong:** The guest writes more bytes than `buf_len` into the
host-provided buffer, corrupting guest memory.
**Why it happens:** The JSON-encoded deny reason is larger than the 4096-byte
buffer the host provides.
**How to avoid:** Always check `json_bytes.len() <= buf_len as usize` before
writing. Return -1 if it does not fit. The host treats -1 as "no reason"
which is safe (fail-closed with generic message).
**Warning signs:** Traps or corrupted deny reason strings on the host side.

### Pitfall 4: Thread-Local Storage in WASM
**What goes wrong:** `thread_local!` might not work as expected on
wasm32-unknown-unknown.
**Why it happens:** wasm32-unknown-unknown is single-threaded. Thread-local
storage is supported but resolves to regular static storage.
**How to avoid:** This is actually fine -- WASM modules are single-threaded,
so thread_local! degenerates to static storage. But be aware that
`RefCell` borrow panics are still possible if the evaluate and
arc_deny_reason paths are somehow reentrant. Since the host calls evaluate
first, then arc_deny_reason sequentially (never concurrently), this is safe.
**Warning signs:** None in practice, but document the single-threaded assumption.

### Pitfall 5: Forgetting `#[no_mangle]` on Exports
**What goes wrong:** The host's `get_typed_func(&mut store, "arc_alloc")`
probe returns None because Rust mangled the function name.
**Why it happens:** Omitting `#[no_mangle]` on `pub extern "C" fn arc_alloc`.
**How to avoid:** Every function that must be visible to the host needs
`#[no_mangle] pub extern "C"`. The required exports are: `arc_alloc`,
`arc_free`, `arc_deny_reason`, and `evaluate` (the last generated by the
proc macro in Phase 383, but testable manually in Phase 382).
**Warning signs:** Host falls back to offset-0 protocol when arc_alloc is
expected to be present.

## Code Examples

Verified patterns from host-side source code:

### Host Probes arc_alloc (What Guest Must Export)
```rust
// Source: crates/arc-wasm-guards/src/runtime.rs lines 526-528
let arc_alloc_fn = instance
    .get_typed_func::<i32, i32>(&mut store, "arc_alloc")
    .ok();
// Signature expected: arc_alloc(size: i32) -> i32
```

### Host Calls evaluate (What Guest Must Export)
```rust
// Source: crates/arc-wasm-guards/src/runtime.rs lines 572-577
let evaluate_fn = instance
    .get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")
    .map_err(|e| WasmGuardError::MissingExport(format!("evaluate: {e}")))?;
let result = evaluate_fn.call(&mut store, (request_ptr, request_len))?;
// Return: 0 = Allow, 1 = Deny, negative = error
```

### Host Probes arc_deny_reason (What Guest Must Export)
```rust
// Source: crates/arc-wasm-guards/src/runtime.rs lines 604-614
let deny_reason_fn = instance
    .get_typed_func::<(i32, i32), i32>(&mut store, "arc_deny_reason")
    .ok();
// Signature: arc_deny_reason(buf_ptr: i32, buf_len: i32) -> i32
// Host calls with (65536, 4096) -- fixed constants
// Guest writes JSON {"reason":"..."} into buffer, returns bytes written
```

### Host Registers arc.log (What Guest Imports)
```rust
// Source: crates/arc-wasm-guards/src/host.rs lines 108-152
// Signature: arc.log(level: i32, ptr: i32, len: i32) -> void
// level: 0=trace, 1=debug, 2=info, 3=warn, 4=error
// ptr: pointer to UTF-8 message in guest memory
// len: byte length of message (max 4096)
```

### Host Registers arc.get_config (What Guest Imports)
```rust
// Source: crates/arc-wasm-guards/src/host.rs lines 157-214
// Signature: arc.get_config(key_ptr: i32, key_len: i32, val_out_ptr: i32, val_out_len: i32) -> i32
// Returns: actual value length (may exceed val_out_len if truncated), or -1 if key missing
// Key length max: 1024 bytes
```

### Host Registers arc.get_time_unix_secs (What Guest Imports)
```rust
// Source: crates/arc-wasm-guards/src/host.rs lines 219-230
// Signature: arc.get_time_unix_secs() -> i64
// Returns: Unix timestamp in seconds
```

### GuestDenyResponse JSON Schema (What arc_deny_reason Must Write)
```rust
// Source: crates/arc-wasm-guards/src/abi.rs lines 128-132
// Host expects: {"reason": "human-readable denial reason"}
// Parsed via serde_json::from_slice::<GuestDenyResponse>
// Fallback: if not valid JSON, host tries plain UTF-8 string
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| offset-0 memory write | arc_alloc guest allocator (with offset-0 fallback) | Phase 373 (v4.0) | Guards with arc_alloc get proper memory safety |
| offset-64K NUL-terminated deny string | arc_deny_reason structured JSON export (with offset-64K fallback) | Phase 373 (v4.0) | Structured deny reasons with JSON schema |
| `Store<()>` with no host functions | `Store<WasmHostState>` with arc.log, arc.get_config, arc.get_time | Phase 373 (v4.0) | Guards can log, read config, and get time |
| One Engine per guard | Shared `Arc<Engine>` | Phase 373 (v4.0) | Reduced memory and compilation overhead |
| wee_alloc recommended for WASM | dlmalloc (Rust std default for wasm32) | 2023+ | wee_alloc unmaintained; dlmalloc is fine |

**Deprecated/outdated:**
- `session_metadata` field: removed from GuardRequest in Phase 374 (WGREQ-06)
- wee_alloc: unmaintained since 2021, do not use

## Open Questions

1. **Crate type: `lib` vs `cdylib`**
   - What we know: Guard projects need `crate-type = ["cdylib"]` to produce
     a .wasm binary. The SDK itself is a library consumed by guard projects.
   - What's unclear: Whether the SDK crate needs any special crate-type
     annotation.
   - Recommendation: Use default `[lib]` crate type for the SDK. Guard
     projects (created in Phase 383+) set `crate-type = ["cdylib"]` in
     their own Cargo.toml.

2. **Unit testing strategy on native target**
   - What we know: The `extern "C"` functions with `#[link(wasm_import_module)]`
     cannot be linked on native targets. The allocator and glue code involve
     raw pointers that are 32-bit on wasm32 but 64-bit on native.
   - What's unclear: How to unit test type serialization and non-ABI logic
     without a wasm32 test runner.
   - Recommendation: Use `#[cfg(target_arch = "wasm32")]` to gate all ABI
     exports. Place pure logic (type definitions, serde round-trips) in
     modules that compile on all targets. Integration testing (loading
     compiled .wasm into WasmtimeBackend) happens in Phase 383.

3. **Prelude module scope**
   - What we know: Phase 383's proc macro expects users to
     `use arc_guard_sdk::prelude::*` (per 03-IMPLEMENTATION-PLAN.md).
   - What's unclear: Exact items to export in prelude.
   - Recommendation: Export `GuardRequest`, `GuardVerdict`, `log`,
     `log_level`, `get_config`, `get_time`, and the ABI constants. Keep
     prelude narrow -- guard authors should not need to import allocator
     internals.

## Sources

### Primary (HIGH confidence)
- `crates/arc-wasm-guards/src/abi.rs` -- GuardRequest/GuardVerdict/GuestDenyResponse structs (ABI source of truth)
- `crates/arc-wasm-guards/src/host.rs` -- Host function signatures (arc.log, arc.get_config, arc.get_time_unix_secs)
- `crates/arc-wasm-guards/src/runtime.rs` -- Host evaluate flow, arc_alloc probing, arc_deny_reason probing
- `docs/guards/05-V1-DECISION.md` -- Design authority for v1 WASM guards
- `docs/guards/03-IMPLEMENTATION-PLAN.md` -- Long-range SDK architecture (Phase 2 = guest SDK)
- `.planning/REQUIREMENTS.md` v4.1 section -- GSDK-01 through GSDK-05 definitions
- `.planning/ROADMAP.md` Phase 382 definition -- success criteria

### Secondary (MEDIUM confidence)
- [Rust wasm32-unknown-unknown platform docs](https://doc.rust-lang.org/beta/rustc/platform-support/wasm32-unknown-unknown.html) -- target capabilities, std support, dlmalloc default
- [Extism Rust PDK](https://github.com/extism/rust-pdk) -- reference guest SDK architecture pattern
- Verified: serde 1.0.228 + serde_json 1.0.149 compile cleanly for wasm32-unknown-unknown (tested locally)

### Tertiary (LOW confidence)
- [C ABI Changes for wasm32-unknown-unknown](https://blog.rust-lang.org/2025/04/04/c-abi-changes-for-wasm32-unknown-unknown/) -- Future extern "C" ABI changes; current Rust 1.93 is not affected but worth monitoring

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- serde/serde_json are the host's serializer, verified to compile for wasm32
- Architecture: HIGH -- every host-side contract is visible in runtime.rs and host.rs; patterns derived directly from source code
- Pitfalls: HIGH -- derived from code analysis of actual host behavior and WASM platform constraints

**Research date:** 2026-04-14
**Valid until:** 2026-05-14 (stable ABI, unlikely to change before v4.2 WIT migration)
