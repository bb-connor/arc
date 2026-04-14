# Phase 373: WASM Runtime Host Foundation - Research

**Researched:** 2026-04-14
**Domain:** Wasmtime host-side runtime for ARC WASM guard execution
**Confidence:** HIGH

## Summary

This phase transforms the Phase 347 WASM guard skeleton into a proper host
execution environment. The existing `WasmtimeBackend` creates one `Engine`
per guard and uses `Store<()>` with no host functions. Phase 373 introduces
shared `Arc<Engine>`, typed `WasmHostState` in the `Store`, three host
function imports (`arc.log`, `arc.get_config`, `arc.get_time_unix_secs`),
and detection of optional guest exports (`arc_alloc`, `arc_deny_reason`).

All seven requirements (WGRT-01 through WGRT-07) are pure host-side changes
within `crates/arc-wasm-guards`. The ABI contract (raw core-WASM, JSON over
linear memory, `evaluate(ptr, len) -> i32`) is unchanged. The kernel `Guard`
trait interface is unchanged. The changes are internal to `WasmtimeBackend`
and its surrounding module.

**Primary recommendation:** Implement in three waves -- (1) shared Engine +
WasmHostState + StoreLimits, (2) host function registration on the Linker,
(3) arc_alloc / arc_deny_reason guest export detection. Each wave is
independently testable.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
None -- all implementation choices are at Claude's discretion.

### Claude's Discretion
All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key design constraints from docs/guards/05-V1-DECISION.md:

- Raw core-WASM ABI (not WIT/Component Model)
- Stateless per-call: fresh Store per invocation
- Sync only: kernel Guard trait is synchronous
- Fail-closed everywhere
- JSON over linear memory
- No WASI: guards get only arc.* host function imports

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| WGRT-01 | WasmtimeBackend shares a single `Arc<Engine>` across all loaded WASM guards instead of creating one Engine per guard | Wasmtime `Engine` is thread-safe and designed for sharing via `Arc`. Current code creates one per `WasmtimeBackend::new()`. Refactor constructor to accept `Arc<Engine>`. |
| WGRT-02 | WasmtimeBackend uses a `WasmHostState` struct in the Store instead of `()`, carrying guard config and a log buffer | Wasmtime `Store<T>` accepts any `T: Send + Sync`. Host state accessible via `Caller::data()` / `Caller::data_mut()` in host functions. `StoreLimitsBuilder` integrates with host state via `Store::limiter()`. |
| WGRT-03 | WASM guards can call `arc.log(level, msg_ptr, msg_len)` host function to emit structured tracing log lines | `Linker::func_wrap("arc", "log", \|caller: Caller<WasmHostState>, level: i32, ptr: i32, len: i32\| {...})`. Read UTF-8 from guest memory, append to host state log buffer, emit via `tracing`. |
| WGRT-04 | WASM guards can call `arc.get_config(key_ptr, key_len, val_out_ptr, val_out_len)` host function to read manifest config values | `Linker::func_wrap("arc", "get_config", ...)`. Use `Memory::data_and_store_mut()` to read key from guest memory + access config HashMap simultaneously. Return actual length or -1. |
| WGRT-05 | WASM guards can call `arc.get_time_unix_secs()` host function to read wall-clock time | `Linker::func_wrap("arc", "get_time_unix_secs", ...)` returning `i64`. Use `std::time::SystemTime::now()`. Trivial host function. |
| WGRT-06 | Host checks for guest-exported `arc_alloc` and uses it for request memory allocation, falling back to offset-0 write when absent | After instantiation, probe `instance.get_typed_func::<i32, i32>("arc_alloc")`. If present, call it to allocate; otherwise write at offset 0 (current behavior). |
| WGRT-07 | Host checks for guest-exported `arc_deny_reason` and uses it to read structured deny reasons, falling back to offset-64K NUL-terminated string when absent | After evaluate returns DENY, probe `instance.get_typed_func::<(i32, i32), i32>("arc_deny_reason")`. If present, call it; otherwise fall back to current `read_deny_reason()` at offset 64K. |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| wasmtime | 29.0.1 | WASM runtime engine | Already integrated in arc-wasm-guards, Bytecode Alliance reference implementation, fuel metering, StoreLimits, Linker host functions |
| arc-kernel | workspace | Guard trait, GuardContext, Verdict | Existing integration point -- WasmGuard implements Guard |
| arc-core | workspace | Shared ARC types | Existing dependency |
| tracing | workspace | Structured logging | Existing dependency, used for arc.log host function output |
| serde_json | workspace | JSON serialization | Existing dependency for GuardRequest serialization |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| thiserror | workspace | Error types | Already used for WasmGuardError |
| std::collections::HashMap | stdlib | Config key-value store | For WasmHostState config field |
| std::time::SystemTime | stdlib | Wall clock for arc.get_time_unix_secs | No external dep needed |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| HashMap<String,String> for config | BTreeMap<String,String> | BTreeMap gives sorted keys but HashMap is simpler and sufficient for small config maps |
| Vec<(Level, String)> for logs | bounded VecDeque | VecDeque allows O(1) eviction but Vec is simpler; bound via max capacity check |

**Installation:**
No new dependencies needed. All are already in the workspace.

**Version verification:**
```
wasmtime = 29.0.1 (verified via cargo tree)
```

## Architecture Patterns

### Recommended File Structure
```
crates/arc-wasm-guards/src/
  lib.rs           # Crate root -- add `pub mod host;`
  abi.rs           # GuardRequest, GuardVerdict, WasmGuardAbi trait (minor changes)
  config.rs        # WasmGuardConfig (unchanged)
  error.rs         # WasmGuardError (add HostFunction variant)
  runtime.rs       # WasmGuard, WasmGuardRuntime, WasmtimeBackend (major changes)
  host.rs          # NEW: WasmHostState, host function implementations, log buffer
```

### Pattern 1: Shared Engine via Arc
**What:** Single `Arc<Engine>` created once and passed to all `WasmtimeBackend`
instances rather than each backend creating its own.
**When to use:** Always -- Engine holds the compiler/JIT configuration and is
expensive to create.
**Example:**
```rust
// Source: wasmtime docs + existing WasmtimeBackend pattern
use std::sync::Arc;
use wasmtime::Engine;

pub struct WasmtimeBackend {
    engine: Arc<Engine>,       // Shared across all guards
    module: Option<Module>,    // Per-guard compiled module
    fuel_limit: u64,
}

impl WasmtimeBackend {
    pub fn with_engine(engine: Arc<Engine>) -> Self {
        Self {
            engine,
            module: None,
            fuel_limit: 0,
        }
    }
}
```

### Pattern 2: Typed Host State in Store
**What:** Replace `Store<()>` with `Store<WasmHostState>` carrying config,
log buffer, and StoreLimits.
**When to use:** Every evaluate() call creates a fresh Store with this state.
**Example:**
```rust
// Source: wasmtime Store<T> docs + 05-V1-DECISION.md design
use wasmtime::{Store, StoreLimits, StoreLimitsBuilder};

pub struct WasmHostState {
    /// Guard-specific config key-value pairs from manifest.
    pub config: HashMap<String, String>,
    /// Captured log lines from arc.log calls (drained after invocation).
    pub logs: Vec<(i32, String)>,  // (level, message)
    /// Maximum log entries per invocation (bounded).
    pub max_log_entries: usize,
    /// Resource limits for memory/table growth.
    pub limits: StoreLimits,
}

// In evaluate():
let limits = StoreLimitsBuilder::new()
    .memory_size(16 * 1024 * 1024)  // 16 MiB max
    .build();
let host_state = WasmHostState {
    config: guard_config.clone(),
    logs: Vec::new(),
    max_log_entries: 256,
    limits,
};
let mut store = Store::new(&self.engine, host_state);
store.limiter(|state| &mut state.limits);
store.set_fuel(self.fuel_limit)?;
```

### Pattern 3: Host Function Registration on Linker
**What:** Register `arc.*` host functions on the `Linker<WasmHostState>` before
instantiation. Functions access host state via `Caller<'_, WasmHostState>`.
**When to use:** Once per Linker creation (can be cached if Linker is reused).
**Example:**
```rust
// Source: wasmtime Linker::func_wrap docs
fn register_host_functions(
    linker: &mut Linker<WasmHostState>,
) -> Result<(), WasmGuardError> {
    linker.func_wrap("arc", "log",
        |mut caller: Caller<'_, WasmHostState>, level: i32, ptr: i32, len: i32| {
            let memory = caller.get_export("memory")
                .and_then(|e| e.into_memory());
            let memory = match memory {
                Some(m) => m,
                None => return,
            };
            let mut buf = vec![0u8; len as usize];
            if memory.read(&caller, ptr as usize, &mut buf).is_err() {
                return;
            }
            let msg = String::from_utf8_lossy(&buf).to_string();
            let state = caller.data_mut();
            if state.logs.len() < state.max_log_entries {
                state.logs.push((level, msg));
            }
        }
    ).map_err(|e| WasmGuardError::Trap(e.to_string()))?;

    // ... similar for get_config and get_time_unix_secs
    Ok(())
}
```

### Pattern 4: Guest Export Detection with Fallback
**What:** After instantiation, probe for optional guest exports (`arc_alloc`,
`arc_deny_reason`). Use them if present, fall back to legacy conventions.
**When to use:** During every evaluate() call after `linker.instantiate()`.
**Example:**
```rust
// Source: wasmtime Instance docs + 05-V1-DECISION.md
// Check for arc_alloc export
let arc_alloc = instance
    .get_typed_func::<i32, i32>(&mut store, "arc_alloc")
    .ok();

let request_ptr = if let Some(alloc_fn) = &arc_alloc {
    // Guest has an allocator -- use it
    alloc_fn.call(&mut store, request_len)?
} else {
    // Fallback: write at offset 0
    0
};

memory.write(&mut store, request_ptr as usize, &request_json)?;
```

### Anti-Patterns to Avoid
- **Creating Engine per backend:** Each Engine holds a full compiler config
  and JIT state. Creating one per guard wastes memory and startup time.
  Always share via `Arc<Engine>`.
- **Using `data_mut()` while holding memory slice:** Wasmtime borrows the
  entire store context when you call `memory.data()`. Use `Memory::read()`
  and `Memory::write()` instead, or `Memory::data_and_store_mut()` when
  simultaneous access is required.
- **Unbounded log buffer:** A malicious WASM guard could spam `arc.log` to
  exhaust host memory. Always bound the log buffer (e.g., 256 entries max).
- **Trusting guest pointers without bounds checking:** Always validate that
  `(ptr, len)` falls within `memory.data_size()` before reading. The
  `Memory::read()` method does this automatically (returns Err on OOB).
- **Using `unwrap()` or `expect()`:** Project lints deny these. All fallible
  operations must use `?`, `map_err`, or match.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Memory limits | Custom memory tracking | `StoreLimitsBuilder::new().memory_size(N).build()` + `store.limiter()` | Wasmtime's built-in ResourceLimiter handles all edge cases including initial memory size, growth requests, and table limits |
| Fuel metering | Custom instruction counting | `store.set_fuel()` / `store.get_fuel()` | Built into wasmtime, deterministic, handles all WASM opcodes |
| Host function binding | Manual Func::new with raw Val | `Linker::func_wrap()` with typed closures | Type-safe, handles ABI conversion automatically |
| Guest memory access | Raw pointer arithmetic on `data()` slice | `Memory::read()` / `Memory::write()` | Bounds-checked, returns Result on OOB |

**Key insight:** Wasmtime provides ergonomic, safe abstractions for every
host-guest interaction pattern needed here. The main engineering work is
wiring these abstractions together correctly with the ARC-specific types
and fail-closed error handling.

## Common Pitfalls

### Pitfall 1: Borrow Conflicts Between Memory and Store State
**What goes wrong:** Calling `memory.data(&caller)` borrows the entire store.
You cannot then call `caller.data_mut()` to access host state.
**Why it happens:** Wasmtime's safety model requires exclusive borrows.
**How to avoid:** Use `Memory::read()` / `Memory::write()` (they take
snapshots and release the borrow) or use `Memory::data_and_store_mut()`
which splits the borrow.
**Warning signs:** Rust compiler errors about conflicting borrows on Caller.

### Pitfall 2: Linker Reuse Across Different Store Types
**What goes wrong:** Creating a `Linker<()>` and trying to instantiate with
a `Store<WasmHostState>`.
**Why it happens:** The Linker and Store must agree on the type parameter T.
**How to avoid:** Change `Linker<()>` to `Linker<WasmHostState>` when
switching the Store type.
**Warning signs:** Type mismatch compilation errors.

### Pitfall 3: Forgetting to Set Fuel After Store Creation
**What goes wrong:** Store is created but fuel is not set. Guest runs with
no fuel limit (infinite execution).
**Why it happens:** `Store::new()` does not set fuel automatically even when
`Config::consume_fuel(true)` is set.
**How to avoid:** Always call `store.set_fuel(self.fuel_limit)` immediately
after creating the Store.
**Warning signs:** Guards hang or consume excessive CPU.

### Pitfall 4: Guest arc_alloc Returns Out-of-Bounds Pointer
**What goes wrong:** A buggy guest `arc_alloc` returns a pointer past the
end of linear memory.
**Why it happens:** Guest allocator bug or malicious module.
**How to avoid:** After calling `arc_alloc`, validate that
`(ptr + request_len) <= memory.data_size()`. If not, fall back to offset 0
or fail closed.
**Warning signs:** Memory write traps or data corruption.

### Pitfall 5: Host Function Panics Kill the Host Process
**What goes wrong:** A panic inside a `func_wrap` closure crashes the entire
ARC process.
**Why it happens:** Wasmtime host functions run in the host's Rust runtime.
Panics propagate up.
**How to avoid:** Never panic in host function closures. All error paths
should return gracefully (for void functions, silently drop; for functions
returning i32/i64, return an error sentinel value like -1). The project
bans `unwrap()` and `expect()` via clippy lints, which helps.
**Warning signs:** Compilation should catch most cases via clippy lints.

### Pitfall 6: UTF-8 Validation on Guest-Provided Strings
**What goes wrong:** Guest writes non-UTF-8 bytes for log messages or deny
reasons.
**Why it happens:** Non-Rust guest languages may produce invalid UTF-8.
**How to avoid:** Use `String::from_utf8_lossy()` for log messages (replace
invalid bytes). For config key lookups, require valid UTF-8 and return -1
on invalid input.
**Warning signs:** Log entries contain replacement characters.

## Code Examples

### Shared Engine Construction
```rust
// Source: wasmtime Engine docs + project pattern
use std::sync::Arc;
use wasmtime::{Config, Engine};

pub fn create_shared_engine() -> Result<Arc<Engine>, WasmGuardError> {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config)
        .map_err(|e| WasmGuardError::Compilation(e.to_string()))?;
    Ok(Arc::new(engine))
}
```

### WasmHostState Definition
```rust
// Source: 05-V1-DECISION.md Section 3.3 + wasmtime StoreLimits docs
use std::collections::HashMap;
use wasmtime::StoreLimits;

/// Maximum log entries per guard invocation.
const MAX_LOG_ENTRIES: usize = 256;

/// Maximum memory a single guard invocation can consume (16 MiB).
const MAX_MEMORY_BYTES: usize = 16 * 1024 * 1024;

pub struct WasmHostState {
    pub config: HashMap<String, String>,
    pub logs: Vec<(i32, String)>,
    pub max_log_entries: usize,
    pub limits: StoreLimits,
}

impl WasmHostState {
    pub fn new(config: HashMap<String, String>) -> Self {
        let limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(MAX_MEMORY_BYTES)
            .build();
        Self {
            config,
            logs: Vec::new(),
            max_log_entries: MAX_LOG_ENTRIES,
            limits,
        }
    }
}
```

### Host Function: arc.log
```rust
// Source: wasmtime Linker::func_wrap + Caller docs
linker.func_wrap("arc", "log",
    |mut caller: Caller<'_, WasmHostState>, level: i32, ptr: i32, len: i32| {
        // Validate level range (0=trace..4=error)
        if !(0..=4).contains(&level) {
            return;
        }
        // Validate length is reasonable
        let len_usize = len as usize;
        if len < 0 || len_usize > 4096 {
            return;
        }
        let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return,
        };
        let mut buf = vec![0u8; len_usize];
        if memory.read(&caller, ptr as usize, &mut buf).is_err() {
            return;
        }
        let msg = String::from_utf8_lossy(&buf).to_string();

        // Emit via tracing
        match level {
            0 => tracing::trace!(target: "wasm_guard", "{msg}"),
            1 => tracing::debug!(target: "wasm_guard", "{msg}"),
            2 => tracing::info!(target: "wasm_guard", "{msg}"),
            3 => tracing::warn!(target: "wasm_guard", "{msg}"),
            4 => tracing::error!(target: "wasm_guard", "{msg}"),
            _ => {} // unreachable due to range check above
        }

        // Buffer in host state
        let state = caller.data_mut();
        if state.logs.len() < state.max_log_entries {
            state.logs.push((level, msg));
        }
    }
)?;
```

### Host Function: arc.get_config
```rust
// Source: wasmtime Memory::data_and_store_mut docs
linker.func_wrap("arc", "get_config",
    |mut caller: Caller<'_, WasmHostState>,
     key_ptr: i32, key_len: i32,
     val_out_ptr: i32, val_out_len: i32| -> i32 {
        let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return -1,
        };

        // Read key from guest memory
        let key_len_usize = key_len as usize;
        if key_len < 0 || key_len_usize > 1024 {
            return -1;
        }
        let mut key_buf = vec![0u8; key_len_usize];
        if memory.read(&caller, key_ptr as usize, &mut key_buf).is_err() {
            return -1;
        }
        let key = match std::str::from_utf8(&key_buf) {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        };

        // Look up in config
        let (mem_data, state) = memory.data_and_store_mut(&mut caller);
        let value = match state.config.get(&key) {
            Some(v) => v.as_bytes(),
            None => return -1,
        };

        let actual_len = value.len();
        let out_len = val_out_len as usize;
        let out_ptr = val_out_ptr as usize;

        // Write as much as fits into the output buffer
        let copy_len = actual_len.min(out_len);
        if out_ptr + copy_len <= mem_data.len() {
            mem_data[out_ptr..out_ptr + copy_len].copy_from_slice(&value[..copy_len]);
        }

        // Return actual length so guest knows if buffer was too small
        actual_len as i32
    }
)?;
```

### Host Function: arc.get_time_unix_secs
```rust
// Source: std::time::SystemTime docs
linker.func_wrap("arc", "get_time_unix_secs",
    |_caller: Caller<'_, WasmHostState>| -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
)?;
```

### Guest Export Detection: arc_alloc
```rust
// Source: wasmtime Instance::get_typed_func docs
// After instantiation:
let arc_alloc_fn = instance
    .get_typed_func::<i32, i32>(&mut store, "arc_alloc")
    .ok();

let request_ptr: i32 = if let Some(ref alloc_fn) = arc_alloc_fn {
    let ptr = alloc_fn.call(&mut store, request_len)
        .map_err(|e| WasmGuardError::Memory(format!("arc_alloc failed: {e}")))?;
    // Validate returned pointer
    let mem_size = memory.data_size(&store);
    if ptr < 0 || (ptr as usize).saturating_add(request_len as usize) > mem_size {
        // Fallback to offset 0
        0
    } else {
        ptr
    }
} else {
    // No arc_alloc -- use legacy offset-0 protocol
    0
};
```

### Guest Export Detection: arc_deny_reason
```rust
// Source: 03-IMPLEMENTATION-PLAN.md Section 3.2
// After evaluate() returns VERDICT_DENY:
let deny_reason_fn = instance
    .get_typed_func::<(i32, i32), i32>(&mut store, "arc_deny_reason")
    .ok();

let reason = if let Some(ref reason_fn) = deny_reason_fn {
    // Guest exports structured deny reason function.
    // Allocate two i32 slots in host-side buffer for ptr and len.
    // Write slot addresses into guest memory, call function.
    read_structured_deny_reason(&reason_fn, &memory, &mut store)
} else {
    // Fallback to legacy offset-64K NUL-terminated string
    read_deny_reason_legacy(&memory, &store)
};
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Engine per guard | Arc<Engine> shared | This phase | Reduces memory footprint, faster guard loading |
| Store<()> | Store<WasmHostState> | This phase | Enables host functions, config, log buffer |
| No host functions | arc.log, arc.get_config, arc.get_time_unix_secs | This phase | Guards can log, read config, check time |
| Offset-0 only | arc_alloc with offset-0 fallback | This phase | Safe memory allocation for guests with allocators |
| Offset-64K only | arc_deny_reason with offset-64K fallback | This phase | Structured deny reasons for guests that support it |

**Deprecated/outdated:**
- `WasmtimeBackend::new()` creating its own Engine: will be replaced by
  `WasmtimeBackend::with_engine(Arc<Engine>)`
- `Store<()>` usage: replaced by `Store<WasmHostState>`
- `Linker<()>`: replaced by `Linker<WasmHostState>` to match Store type

## Open Questions

1. **Linker caching across invocations**
   - What we know: Linker host function registration is cheap but repeated
     per evaluate() call. The Linker is parameterized on T and is
     store-independent.
   - What's unclear: Whether caching a Linker per guard (alongside the
     compiled Module) would measurably improve performance. The Linker must
     be created from the same Engine as the Store.
   - Recommendation: Create a fresh Linker per call for simplicity in the
     initial implementation. The Linker could be cached on WasmtimeBackend
     if benchmarks show registration overhead matters. The `func_wrap` calls
     are closure registrations, not compilations, so overhead should be
     minimal.

2. **arc.get_config output semantics for oversized values**
   - What we know: The function returns actual length even if it exceeds
     val_out_len, allowing the guest to detect truncation.
   - What's unclear: Should the function write partial data when the buffer
     is too small, or write nothing?
   - Recommendation: Write as much as fits (truncate). This matches POSIX
     read() semantics and avoids a second call in the common case where the
     buffer is large enough.

3. **Log level enum representation**
   - What we know: 05-V1-DECISION.md defines 0=trace, 1=debug, 2=info,
     3=warn, 4=error.
   - What's unclear: Whether to map to tracing::Level directly or keep as
     i32 in the log buffer.
   - Recommendation: Store as i32 in the buffer (it is the ABI contract).
     Map to tracing::Level only when emitting. This keeps the host state
     simple.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | cargo test (Rust built-in) |
| Config file | `crates/arc-wasm-guards/Cargo.toml` (lints section) |
| Quick run command | `cargo test -p arc-wasm-guards --features wasmtime-runtime --lib` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| WGRT-01 | Shared Arc<Engine> across guards | unit | `cargo test -p arc-wasm-guards --features wasmtime-runtime --lib -- shared_engine` | No -- Wave 0 |
| WGRT-02 | WasmHostState in Store | unit | `cargo test -p arc-wasm-guards --features wasmtime-runtime --lib -- host_state` | No -- Wave 0 |
| WGRT-03 | arc.log host function | unit | `cargo test -p arc-wasm-guards --features wasmtime-runtime --lib -- host_log` | No -- Wave 0 |
| WGRT-04 | arc.get_config host function | unit | `cargo test -p arc-wasm-guards --features wasmtime-runtime --lib -- host_get_config` | No -- Wave 0 |
| WGRT-05 | arc.get_time_unix_secs host function | unit | `cargo test -p arc-wasm-guards --features wasmtime-runtime --lib -- host_get_time` | No -- Wave 0 |
| WGRT-06 | arc_alloc guest export detection | unit | `cargo test -p arc-wasm-guards --features wasmtime-runtime --lib -- arc_alloc` | No -- Wave 0 |
| WGRT-07 | arc_deny_reason guest export detection | unit | `cargo test -p arc-wasm-guards --features wasmtime-runtime --lib -- deny_reason` | No -- Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p arc-wasm-guards --features wasmtime-runtime --lib`
- **Per wave merge:** `cargo test --workspace && cargo clippy --workspace -- -D warnings`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] Test WASM modules (minimal `.wasm` binaries) for integration testing.
  Options: (a) hand-written WAT compiled via `wat` crate, (b) pre-compiled
  `.wasm` fixtures checked into the repo, (c) inline WAT in tests using
  `wasmtime::Module::new(&engine, "(module ...)")`. Recommendation: use
  inline WAT for unit tests -- it is self-contained and requires no build
  toolchain.
- [ ] Tests for each host function using a WAT module that imports `arc.*`
  functions and calls them during `evaluate`.
- [ ] Tests for arc_alloc / arc_deny_reason detection with and without those
  guest exports.
- [ ] Tests for WasmHostState log buffer bounding.
- [ ] Tests for memory limit enforcement via StoreLimits.

**Note on WAT test modules:** Wasmtime can compile WAT (WebAssembly Text
Format) directly via `Module::new()`. This allows tests to define minimal
WASM modules inline without needing a separate build step. Example:

```rust
let module = Module::new(&engine, r#"
    (module
        (import "arc" "log" (func $log (param i32 i32 i32)))
        (memory (export "memory") 1)
        (func (export "evaluate") (param i32 i32) (result i32)
            (call $log (i32.const 2) (i32.const 0) (i32.const 5))
            (i32.const 0)
        )
    )
"#)?;
```

## Sources

### Primary (HIGH confidence)
- wasmtime 29.0.1 crate docs: Linker, Store, Memory, Caller, StoreLimits
  APIs verified via docs.rs
- `crates/arc-wasm-guards/` source code: current implementation reviewed
  in full
- `docs/guards/05-V1-DECISION.md`: authoritative design decisions
- `docs/guards/03-IMPLEMENTATION-PLAN.md`: architectural context
- `docs/guards/01-CURRENT-GUARD-SYSTEM.md`: Guard trait and pipeline

### Secondary (MEDIUM confidence)
- `docs/guards/02-WASM-RUNTIME-LANDSCAPE.md`: wasmtime capabilities,
  ResourceLimiter trait details, fuel vs epoch tradeoffs

### Tertiary (LOW confidence)
- None -- all findings verified against wasmtime 29.0.1 docs and project
  source

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- wasmtime 29.0.1 already integrated, all APIs
  verified against docs.rs
- Architecture: HIGH -- design authority (05-V1-DECISION.md) is explicit,
  existing code structure is clear
- Pitfalls: HIGH -- borrow conflicts and host function patterns verified
  against wasmtime documentation

**Research date:** 2026-04-14
**Valid until:** 2026-05-14 (stable -- wasmtime 29.x API is released and
unlikely to change)
