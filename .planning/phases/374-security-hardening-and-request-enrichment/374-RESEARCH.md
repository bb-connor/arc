# Phase 374: Security Hardening and Request Enrichment - Research

**Researched:** 2026-04-14
**Domain:** WASM guard runtime security (wasmtime resource limiting, module import validation, request enrichment)
**Confidence:** HIGH

## Summary

Phase 374 adds three security hardening measures (ResourceLimiter memory caps, module import validation, module size validation) and enriches the GuardRequest struct with host-extracted action context fields. The foundation is solid: Phase 373 already wired `StoreLimits` into `WasmHostState`, created the shared `Arc<Engine>`, and established the per-invocation `Store<WasmHostState>` pattern. The security work is primarily about activating and testing enforcement that is partially plumbed, plus adding pre-compilation validation. The request enrichment work requires adding `arc-guards` as a dependency and calling `extract_action()` in `build_request()`.

The critical constraint is that `WasmGuardEntry` in `arc-config` uses `deny_unknown_fields`, so config fields like `max_memory_bytes` and `max_module_size` cannot be added to `arc.yaml` in this phase (deferred to v4.0.1). Instead, these limits live on `WasmGuardConfig` (the crate-internal config struct) and `WasmHostState`, with hard defaults (16 MiB memory, 10 MiB module size).

**Primary recommendation:** Split into two waves -- Wave 1 handles security hardening (WGSEC-01/02/03 + new error variants), Wave 2 handles request enrichment (WGREQ-01-06 + arc-guards dependency). Both are straightforward code changes with WAT-based tests.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
None -- all implementation choices are at Claude's discretion (pure infrastructure phase).

### Claude's Discretion
All implementation choices are at Claude's discretion -- pure infrastructure phase. Key design constraints from docs/guards/05-V1-DECISION.md:

- ResourceLimiter caps at configurable limit, default 16 MiB
- No WASI: modules importing outside arc namespace must be rejected at load time
- Module size validated before compilation (configurable max)
- GuardRequest enrichment uses existing extract_action() from arc-guards
- session_metadata removal is a breaking ABI change but acceptable (always None)
- Fail-closed: memory cap violation, import validation failure, oversized modules all deny

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| WGSEC-01 | ResourceLimiter caps guest linear memory growth (configurable, default 16 MiB) | StoreLimits already wired in WasmHostState via StoreLimitsBuilder::new().memory_size(MAX_MEMORY_BYTES). Need: make configurable via WasmGuardConfig, add trap_on_grow_failure(true), add WAT test with memory.grow loop |
| WGSEC-02 | Module import validation rejects WASM modules importing outside arc namespace | Use Module::imports() iterator, check import.module() == "arc" for all imports. Run after Module::new() but before instantiation. New error variant needed. |
| WGSEC-03 | Module size validated at load time against configurable maximum | Check wasm_bytes.len() before calling Module::new(). Default 10 MiB. New error variant needed. |
| WGREQ-01 | GuardRequest includes action_type field pre-extracted by host | Add arc-guards dep, call extract_action() in build_request(), map ToolAction variants to string: "file_access", "file_write", "network_egress", "shell_command", "mcp_tool", "patch", "unknown" |
| WGREQ-02 | GuardRequest includes extracted_path field with normalized file path | ToolAction::filesystem_path() already provides this for FileAccess/FileWrite/Patch variants |
| WGREQ-03 | GuardRequest includes extracted_target field with domain string for network egress | ToolAction::NetworkEgress(host, port) provides the host string |
| WGREQ-04 | GuardRequest includes filesystem_roots field from session context | GuardContext.session_filesystem_roots provides Option<&[String]> -- map to Vec<String> |
| WGREQ-05 | GuardRequest includes matched_grant_index field from capability scope | GuardContext.matched_grant_index provides Option<usize> -- direct mapping |
| WGREQ-06 | session_metadata removed from GuardRequest | Remove the field from GuardRequest struct, update all test fixtures that reference it |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| wasmtime | 29.0.1 | WASM runtime engine | Already in use, provides Module::imports(), StoreLimits, ResourceLimiter |
| arc-guards | workspace | Action extraction | Provides extract_action() and ToolAction -- the canonical action classification |
| arc-kernel | workspace | Guard trait, GuardContext | Already a dependency, provides context fields |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| serde / serde_json | workspace | GuardRequest serialization | Already in use for ABI boundary |
| thiserror | workspace | Error variants | Already in use for WasmGuardError |
| tracing | workspace | Structured logging | Already in use for host function logging |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| StoreLimits (built-in) | Custom ResourceLimiter impl | Custom impl gives per-call metrics but adds complexity; StoreLimits is sufficient for v1 |
| String action_type | Enum with serde tag | String is simpler for WASM ABI, matches the decision doc verbatim, avoids serde complexity at the boundary |

**No new dependencies to install.** `arc-guards` is an internal workspace crate. `wasmtime` is already present at version 29.0.1.

## Architecture Patterns

### File Changes Required
```
crates/arc-wasm-guards/
  src/
    abi.rs          # GuardRequest field changes (WGREQ-01-06)
    host.rs         # Make MAX_MEMORY_BYTES configurable via WasmHostState::new() parameter
    runtime.rs      # build_request() enrichment, import validation, module size check
    config.rs       # Add max_memory_bytes, max_module_size to WasmGuardConfig
    error.rs        # New error variants: ImportViolation, ModuleTooLarge
  Cargo.toml        # Add arc-guards dependency
```

### Pattern 1: Module Import Validation (WGSEC-02)
**What:** After `Module::new()` compiles the WASM bytes, iterate `module.imports()` and reject any import whose module name is not `"arc"`.
**When to use:** Every time a module is loaded via `load_module()`.
**Example:**
```rust
// After Module::new() succeeds:
for import in module.imports() {
    if import.module() != "arc" {
        return Err(WasmGuardError::ImportViolation {
            module: import.module().to_string(),
            name: import.name().to_string(),
        });
    }
}
```
**Placement:** In `WasmtimeBackend::load_module()`, between `Module::new()` and storing `self.module = Some(module)`.

### Pattern 2: Module Size Validation (WGSEC-03)
**What:** Check `wasm_bytes.len()` against configured maximum before any compilation.
**When to use:** At the top of `load_module()` or `WasmGuardRuntime::load_guard()`.
**Example:**
```rust
if wasm_bytes.len() > self.max_module_size {
    return Err(WasmGuardError::ModuleTooLarge {
        size: wasm_bytes.len(),
        limit: self.max_module_size,
    });
}
```
**Placement:** In `WasmtimeBackend::load_module()`, before `Module::new()`. Also in `WasmGuardRuntime::load_guard()` after `std::fs::read()`.

### Pattern 3: Memory Cap via Configurable StoreLimits (WGSEC-01)
**What:** `WasmHostState::new()` already creates `StoreLimits` with `memory_size(MAX_MEMORY_BYTES)`. Make this configurable.
**Example:**
```rust
impl WasmHostState {
    pub fn new(config: HashMap<String, String>) -> Self {
        Self::with_memory_limit(config, MAX_MEMORY_BYTES)
    }

    pub fn with_memory_limit(config: HashMap<String, String>, max_memory: usize) -> Self {
        let limits = StoreLimitsBuilder::new()
            .memory_size(max_memory)
            .trap_on_grow_failure(true)  // NEW: trap instead of returning -1
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
**Key detail:** `trap_on_grow_failure(true)` ensures that exceeding the memory cap causes a WASM trap (which the host catches and maps to WasmGuardError::Trap, fail-closed) rather than silently returning -1 to the guest.

### Pattern 4: GuardRequest Enrichment (WGREQ-01-05)
**What:** In `WasmGuard::build_request()`, call `arc_guards::extract_action()` and populate new fields.
**Example:**
```rust
fn build_request(ctx: &GuardContext<'_>) -> GuardRequest {
    let scopes = ctx.scope.grants.iter()
        .map(|g| format!("{}:{}", g.server_id, g.tool_name))
        .collect();

    let action = arc_guards::extract_action(&ctx.request.tool_name, &ctx.request.arguments);

    let (action_type, extracted_path, extracted_target) = match &action {
        ToolAction::FileAccess(path) => (Some("file_access".to_string()), Some(path.clone()), None),
        ToolAction::FileWrite(path, _) => (Some("file_write".to_string()), Some(path.clone()), None),
        ToolAction::NetworkEgress(host, _port) => (Some("network_egress".to_string()), None, Some(host.clone())),
        ToolAction::ShellCommand(_) => (Some("shell_command".to_string()), None, None),
        ToolAction::McpTool(_, _) => (Some("mcp_tool".to_string()), None, None),
        ToolAction::Patch(path, _) => (Some("patch".to_string()), Some(path.clone()), None),
        ToolAction::Unknown => (Some("unknown".to_string()), None, None),
    };

    let filesystem_roots = ctx.session_filesystem_roots
        .map(|roots| roots.to_vec())
        .unwrap_or_default();

    GuardRequest {
        tool_name: ctx.request.tool_name.clone(),
        server_id: ctx.server_id.clone(),
        agent_id: ctx.agent_id.clone(),
        arguments: ctx.request.arguments.clone(),
        scopes,
        action_type,
        extracted_path,
        extracted_target,
        filesystem_roots,
        matched_grant_index: ctx.matched_grant_index,
    }
}
```

### Anti-Patterns to Avoid
- **Implementing ResourceLimiter manually:** StoreLimits + StoreLimitsBuilder already implement the trait. No custom impl needed for v1.
- **Checking imports before compilation:** Module::imports() requires a compiled Module. The check happens after Module::new(), not on raw bytes.
- **Adding config fields to WasmGuardEntry in arc-config:** This struct has `deny_unknown_fields`. Schema changes are deferred to v4.0.1.
- **Using unwrap/expect:** Clippy denies these in all crates. Every fallible path must use `?`, `map_err`, or explicit matching.
- **Re-deriving action in WASM guests:** The whole point of WGREQ-01-05 is that the host pre-extracts action context so guests don't have to.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Memory limiting | Custom allocation tracker | `StoreLimitsBuilder::new().memory_size(N).trap_on_grow_failure(true).build()` | Wasmtime handles all edge cases: initial memory, growth requests, table limits, trap on failure |
| Action classification | Pattern matching on tool names in WASM guest | `arc_guards::extract_action()` in the host | Canonical heuristic, handles path normalization, maintained in one place |
| Import namespace checking | Manual byte-level WASM parsing | `Module::imports()` iterator after `Module::new()` | Wasmtime's parser handles all WASM formats and validates structure |
| Module size check | Complex file metadata inspection | `wasm_bytes.len()` before `Module::new()` | Simple, direct, no allocation overhead |

**Key insight:** All three security hardening requirements use existing wasmtime primitives. The engineering work is wiring them into the correct points in the load/evaluate pipeline and adding proper error handling.

## Common Pitfalls

### Pitfall 1: Import Validation Timing
**What goes wrong:** Trying to check imports on raw WASM bytes before compilation.
**Why it happens:** Module::imports() is only available on a compiled Module.
**How to avoid:** Call Module::new() first (which validates WASM structure), then iterate imports(). If imports are invalid, discard the compiled module.
**Warning signs:** Trying to parse WASM binary format manually.

### Pitfall 2: Memory Limit vs Trap Behavior
**What goes wrong:** Guest calls memory.grow, gets -1 (failure), continues executing with limited memory -- potentially in a confused state.
**Why it happens:** Default StoreLimits behavior returns false from memory_growing, which causes memory.grow to return -1 (not a trap).
**How to avoid:** Use `trap_on_grow_failure(true)` on StoreLimitsBuilder. This causes memory.grow failures to trap, which the host catches as a WasmGuardError::Trap and denies (fail-closed).
**Warning signs:** Tests that check for specific error types may need updating if the trap message changes.

### Pitfall 3: Breaking Test Fixtures on GuardRequest Change
**What goes wrong:** Removing `session_metadata` and adding new fields breaks existing test fixtures that construct GuardRequest manually.
**Why it happens:** Many tests in runtime.rs create GuardRequest literals with `session_metadata: None`.
**How to avoid:** Update all test fixtures in one pass. Use `..Default::default()` or add `#[derive(Default)]` to GuardRequest if beneficial. The new optional fields use `#[serde(default)]` so deserialization won't break.
**Warning signs:** Compilation errors in test modules after struct field changes.

### Pitfall 4: Circular Dependency arc-wasm-guards -> arc-guards
**What goes wrong:** Adding arc-guards as a dependency could create a cycle if arc-guards depends on arc-wasm-guards.
**Why it happens:** Crate dependency graphs must be acyclic.
**How to avoid:** Verify the dependency direction. arc-guards depends on arc-kernel but NOT on arc-wasm-guards. The dependency arc-wasm-guards -> arc-guards is safe and expected.
**Warning signs:** Cargo refusing to compile with cycle errors.

### Pitfall 5: deny_unknown_fields on WasmGuardEntry
**What goes wrong:** Adding `max_memory_bytes` or `max_module_size` to `WasmGuardEntry` in arc-config breaks existing arc.yaml files.
**Why it happens:** The struct has `#[serde(deny_unknown_fields)]`.
**How to avoid:** Do NOT modify WasmGuardEntry in this phase. Config fields go on `WasmGuardConfig` (the crate-internal struct in arc-wasm-guards/src/config.rs) which does NOT have deny_unknown_fields. Schema changes to arc-config are deferred to v4.0.1.
**Warning signs:** CONTEXT.md and REQUIREMENTS.md explicitly note this constraint.

## Code Examples

### New Error Variants (error.rs)
```rust
// Source: Design decision from docs/guards/05-V1-DECISION.md
/// A WASM module imports from a forbidden namespace.
#[error("module imports from forbidden namespace \"{module}\": import \"{name}\"")]
ImportViolation { module: String, name: String },

/// A WASM module exceeds the configured size limit.
#[error("module size {size} bytes exceeds limit of {limit} bytes")]
ModuleTooLarge { size: usize, limit: usize },
```

### Updated GuardRequest (abi.rs)
```rust
// Source: docs/guards/05-V1-DECISION.md section 3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardRequest {
    pub tool_name: String,
    pub server_id: String,
    pub agent_id: String,
    pub arguments: serde_json::Value,
    #[serde(default)]
    pub scopes: Vec<String>,

    // v1 additions: host-extracted action context
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
    // session_metadata: REMOVED (was always None)
}
```

### Updated WasmGuardConfig (config.rs)
```rust
// Source: Phase 374 design -- crate-internal config, NOT arc-config schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmGuardConfig {
    pub name: String,
    pub path: String,
    #[serde(default = "default_fuel_limit")]
    pub fuel_limit: u64,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default)]
    pub advisory: bool,

    // NEW: security limits
    /// Maximum guest linear memory in bytes. Default: 16 MiB.
    #[serde(default = "default_max_memory_bytes")]
    pub max_memory_bytes: usize,
    /// Maximum WASM module size in bytes. Default: 10 MiB.
    #[serde(default = "default_max_module_size")]
    pub max_module_size: usize,
}

fn default_max_memory_bytes() -> usize { 16 * 1024 * 1024 } // 16 MiB
fn default_max_module_size() -> usize { 10 * 1024 * 1024 }  // 10 MiB
```

### Import Validation in load_module
```rust
// Source: wasmtime Module::imports() API docs
fn load_module(&mut self, wasm_bytes: &[u8], fuel_limit: u64) -> Result<(), WasmGuardError> {
    // WGSEC-03: Module size validation
    if wasm_bytes.len() > self.max_module_size {
        return Err(WasmGuardError::ModuleTooLarge {
            size: wasm_bytes.len(),
            limit: self.max_module_size,
        });
    }

    let module = Module::new(&self.engine, wasm_bytes)
        .map_err(|e| WasmGuardError::Compilation(e.to_string()))?;

    // WGSEC-02: Import validation
    for import in module.imports() {
        if import.module() != "arc" {
            return Err(WasmGuardError::ImportViolation {
                module: import.module().to_string(),
                name: import.name().to_string(),
            });
        }
    }

    self.module = Some(module);
    self.fuel_limit = fuel_limit;
    Ok(())
}
```

### WAT Test: Memory Growth Denied
```rust
// Test that memory.grow beyond the limit traps (with trap_on_grow_failure)
let wat = r#"
    (module
        (import "arc" "log" (func $log (param i32 i32 i32)))
        (import "arc" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
        (import "arc" "get_time_unix_secs" (func $get_time (result i64)))
        (memory (export "memory") 1)  ;; starts at 64 KiB
        (func (export "evaluate") (param i32 i32) (result i32)
            ;; Try to grow memory by 1000 pages (64 MiB) -- should trap
            (drop (memory.grow (i32.const 1000)))
            (i32.const 0)
        )
    )
"#;
```

### WAT Test: Import Validation Rejection
```rust
// Module that imports from "wasi" namespace -- should be rejected at load time
let wat_with_wasi = r#"
    (module
        (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "evaluate") (param i32 i32) (result i32)
            (i32.const 0)
        )
    )
"#;
// load_module should return Err(WasmGuardError::ImportViolation { .. })
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Store<()> with no limits | Store<WasmHostState> with StoreLimits | Phase 373 | StoreLimits wired but not yet configurable or enforced via trap |
| session_metadata: Option<Value> on GuardRequest | Removed; replaced by structured fields | Phase 374 (this phase) | Breaking ABI change, acceptable since field was always None |
| Guest re-derives action from tool_name + args | Host pre-extracts via extract_action() | Phase 374 (this phase) | Guests receive action_type, extracted_path, extracted_target |
| No module validation before instantiation | Import validation + size validation at load time | Phase 374 (this phase) | Fail-closed rejection of non-arc imports and oversized modules |

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | cargo test (Rust built-in) |
| Config file | Cargo.toml lints (unwrap_used = deny, expect_used = deny) |
| Quick run command | `cargo test -p arc-wasm-guards` |
| Full suite command | `cargo test --workspace && cargo clippy --workspace -- -D warnings` |

### Phase Requirements to Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| WGSEC-01 | Memory growth beyond limit traps (fail-closed) | unit (WAT) | `cargo test -p arc-wasm-guards --features wasmtime-runtime memory_growth` | Wave 0 |
| WGSEC-01 | Configurable memory limit respected | unit | `cargo test -p arc-wasm-guards --features wasmtime-runtime configurable_memory` | Wave 0 |
| WGSEC-02 | Module with WASI imports rejected at load | unit (WAT) | `cargo test -p arc-wasm-guards --features wasmtime-runtime import_validation` | Wave 0 |
| WGSEC-02 | Module with only arc imports accepted | unit (WAT) | `cargo test -p arc-wasm-guards --features wasmtime-runtime arc_imports_accepted` | Wave 0 |
| WGSEC-03 | Oversized module rejected before compilation | unit | `cargo test -p arc-wasm-guards module_too_large` | Wave 0 |
| WGSEC-03 | Module within size limit accepted | unit | `cargo test -p arc-wasm-guards module_size_ok` | Wave 0 |
| WGREQ-01 | GuardRequest includes action_type from extract_action | unit | `cargo test -p arc-wasm-guards build_request_action_type` | Wave 0 |
| WGREQ-02 | GuardRequest includes extracted_path for file actions | unit | `cargo test -p arc-wasm-guards build_request_extracted_path` | Wave 0 |
| WGREQ-03 | GuardRequest includes extracted_target for network actions | unit | `cargo test -p arc-wasm-guards build_request_extracted_target` | Wave 0 |
| WGREQ-04 | GuardRequest includes filesystem_roots from context | unit | `cargo test -p arc-wasm-guards build_request_filesystem_roots` | Wave 0 |
| WGREQ-05 | GuardRequest includes matched_grant_index from context | unit | `cargo test -p arc-wasm-guards build_request_matched_grant_index` | Wave 0 |
| WGREQ-06 | session_metadata field removed from GuardRequest | unit | `cargo test -p arc-wasm-guards guard_request_serialization` | Exists (needs update) |

### Sampling Rate
- **Per task commit:** `cargo test -p arc-wasm-guards --features wasmtime-runtime`
- **Per wave merge:** `cargo test --workspace && cargo clippy --workspace -- -D warnings`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- Tests for WGSEC-01 (memory growth trap), WGSEC-02 (import validation), WGSEC-03 (module size) do not exist yet -- will be created alongside implementation
- Tests for WGREQ-01-05 (build_request enrichment) do not exist yet -- will be created alongside implementation
- Existing test `guard_request_serialization` needs updating for field changes (WGREQ-06)
- No new framework or fixture infrastructure needed -- existing WAT inline test pattern from Phase 373 is sufficient

## Open Questions

1. **trap_on_grow_failure behavior with existing tests**
   - What we know: Enabling `trap_on_grow_failure(true)` changes memory.grow behavior from returning -1 to trapping
   - What's unclear: Whether any existing WAT test modules rely on memory.grow returning -1 gracefully
   - Recommendation: Audit existing tests in Phase 373 -- none appear to test memory.grow explicitly, so enabling trap should be safe

2. **Default max_module_size value**
   - What we know: The decision doc mentions 50 KiB Rust and 5 MiB Python-via-componentize-py as representative sizes
   - What's unclear: Whether 10 MiB is the right default or if it should be higher
   - Recommendation: Use 10 MiB (2x the largest expected module). This is generous enough for real workloads while still preventing abuse. Configurable via WasmGuardConfig.

3. **Configurable limits propagation path**
   - What we know: WasmGuardConfig gets max_memory_bytes and max_module_size. WasmtimeBackend needs these values.
   - What's unclear: How to thread config values from WasmGuardConfig into WasmtimeBackend (currently the factory closure in load_guard gets wasm_bytes + fuel_limit only)
   - Recommendation: Add max_memory_bytes and max_module_size to WasmtimeBackend struct fields, set via constructor or a new with_limits method. The load_guard factory can receive the full WasmGuardConfig or the relevant fields.

## Sources

### Primary (HIGH confidence)
- `crates/arc-wasm-guards/src/host.rs` -- WasmHostState with StoreLimits already wired
- `crates/arc-wasm-guards/src/runtime.rs` -- WasmtimeBackend evaluate() flow, build_request()
- `crates/arc-wasm-guards/src/abi.rs` -- Current GuardRequest struct
- `crates/arc-guards/src/action.rs` -- extract_action() and ToolAction enum
- `crates/arc-kernel/src/kernel/mod.rs` -- GuardContext with session_filesystem_roots, matched_grant_index
- `docs/guards/05-V1-DECISION.md` -- Design authority for v1 decisions
- `docs/guards/01-CURRENT-GUARD-SYSTEM.md` -- Guard system technical reference

### Secondary (MEDIUM confidence)
- [Wasmtime Module::imports() docs](https://docs.wasmtime.dev/api/wasmtime/struct.Module.html) -- ImportType.module() returns namespace string
- [Wasmtime StoreLimitsBuilder docs](https://docs.rs/wasmtime/latest/wasmtime/struct.StoreLimitsBuilder.html) -- memory_size(), trap_on_grow_failure()
- [Wasmtime ResourceLimiter trait](https://docs.wasmtime.dev/api/wasmtime/trait.ResourceLimiter.html) -- StoreLimits implements this

### Tertiary (LOW confidence)
None -- all findings verified against code and official docs.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all crates already exist, no new external deps
- Architecture: HIGH -- patterns follow Phase 373 precedent, wasmtime APIs verified against official docs
- Pitfalls: HIGH -- deny_unknown_fields constraint documented in decision doc and CONTEXT.md, borrow patterns well-understood from Phase 373

**Research date:** 2026-04-14
**Valid until:** 2026-05-14 (stable -- wasmtime 29 API unlikely to change)
