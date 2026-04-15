# Phase 386: WIT Interface and Dual-Mode Host - Research

**Researched:** 2026-04-14
**Domain:** WebAssembly Component Model, WIT interface definition, wasmtime host bindings
**Confidence:** HIGH

## Summary

This phase defines the `arc:guard@0.1.0` WIT interface for guard evaluation, implements the host-side Component Model support via `wasmtime::component::bindgen!`, and adds dual-mode loading that detects whether a `.wasm` file is a core module (legacy raw ABI) or a Component Model component (WIT ABI) and routes through the correct evaluation path.

Wasmtime 29.0.1 (already pinned in the workspace) includes full Component Model support via its `component-model` Cargo feature (enabled by default). The `wasmtime::component` module provides `Component::new()`, `component::Linker`, and the `bindgen!` macro which generates Rust types from WIT definitions. The current `arc-wasm-guards` crate uses only core module APIs (`wasmtime::Module`, `wasmtime::Linker`). The component path requires a parallel set of types but shares the same `Engine`.

Detection of core module vs component at load time is straightforward: the `wasmparser` crate (already a transitive dependency at 0.221.3) exposes `Parser::is_core_wasm()` and `Parser::is_component()` static methods that inspect the first 8 bytes of a `.wasm` binary. The Engine config must call `config.wasm_component_model(true)` -- this is **false by default** even when the `component-model` Cargo feature is enabled.

**Primary recommendation:** Define WIT at `wit/arc-guard/world.wit`, generate host bindings with `bindgen!`, add `wasmparser` as an explicit dependency for format detection, enable `wasm_component_model(true)` on the shared Engine, and implement a `ComponentBackend` that wraps the generated bindings alongside the existing `WasmtimeBackend` for core modules.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
None -- all implementation choices are at Claude's discretion.

### Claude's Discretion
All implementation choices are at Claude's discretion -- pure infrastructure phase. Key constraints:

- WIT package at wit/arc-guard/world.wit defines arc:guard@0.1.0 world
- evaluate function accepts guard-request record, returns verdict variant
- Host uses wasmtime::component::bindgen! to generate Rust types from WIT
- Dual-mode: detect core module vs component at load time
- Existing raw-ABI guards continue to work unchanged
- WIT package includes versioned world definition with doc comments
- SDK toolchains (jco, componentize-py, TinyGo) can consume the WIT

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| WIT-01 | Guard WIT interface defined (`arc:guard@0.1.0`) with `evaluate` function, `guard-request` record, and `verdict` variant types | WIT syntax reference, type mapping from existing `GuardRequest`/`GuardVerdict`, WIT package conventions |
| WIT-02 | Host implements the WIT interface using `wasmtime::component::bindgen!` with generated Rust types | bindgen! macro configuration, wasmtime 29 add_to_linker pattern, Component instantiation flow |
| WIT-03 | Host supports dual-mode loading: raw core-WASM modules (legacy ABI) and Component Model components (WIT ABI) detected at load time | wasmparser `is_core_wasm()`/`is_component()` detection, Engine config `wasm_component_model(true)`, parallel backend implementation |
| WIT-04 | WIT package published in-repo under `wit/arc-guard/` with versioned world definition | WIT directory layout conventions, package declaration syntax, toolchain consumability requirements |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| wasmtime | 29.0.1 | WASM runtime with Component Model support | Already pinned in workspace; `component-model` feature is default |
| wasmparser | 0.221.3 | Binary format detection (core vs component) | Already transitive dep; provides `Parser::is_core_wasm()`/`is_component()` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| serde | 1.x | Serialization for config types | Already in deps |
| serde_json | 1.x | JSON serialization for `arguments` field passthrough | Already in deps |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| wasmparser for detection | Manual magic byte check | wasmparser is authoritative and already a dep; manual bytes fragile |
| Component Model | Continue raw ABI only | Loses type safety, multi-language SDK generation, interface versioning |

**Installation:**
```bash
# wasmparser needs to be added as an explicit dependency
# In crates/arc-wasm-guards/Cargo.toml:
wasmparser = "0.221"  # Match the version already in Cargo.lock
```

**Version verification:** wasmtime 29.0.1 confirmed in Cargo.lock. wasmparser 0.221.3 confirmed as transitive dependency. Both are current for this workspace.

## Architecture Patterns

### Recommended Project Structure
```
wit/
  arc-guard/
    world.wit            # arc:guard@0.1.0 -- WIT package definition

crates/arc-wasm-guards/
  src/
    abi.rs               # Existing GuardRequest/GuardVerdict (raw ABI types)
    component.rs         # NEW: Component Model backend using bindgen!
    host.rs              # Existing WasmHostState, shared Engine creation
    runtime.rs           # Modified: dual-mode detection + dispatch
    ...
```

### Pattern 1: WIT Interface Definition
**What:** The `arc:guard@0.1.0` world defines the contract between host and guard component.
**When to use:** This is the canonical interface for all WIT-based guards.
**Example:**
```wit
// wit/arc-guard/world.wit
// Source: WIT specification + existing GuardRequest/GuardVerdict types

package arc:guard@0.1.0;

/// The verdict a guard returns after evaluating a tool-call request.
variant verdict {
    /// The guard allows the request to proceed.
    allow,
    /// The guard denies the request with a human-readable reason.
    deny(string),
}

/// Read-only request context provided to the guard by the host.
record guard-request {
    /// Tool being invoked.
    tool-name: string,
    /// Server hosting the tool.
    server-id: string,
    /// Agent making the request.
    agent-id: string,
    /// Tool arguments as a JSON-encoded string.
    arguments: string,
    /// Capability scopes granted (serialized scope names).
    scopes: list<string>,
    /// Host-extracted action type (e.g. "file_access", "network_egress").
    action-type: option<string>,
    /// Normalized file path for filesystem actions.
    extracted-path: option<string>,
    /// Target domain string for network egress actions.
    extracted-target: option<string>,
    /// Session-scoped filesystem roots from the kernel context.
    filesystem-roots: list<string>,
    /// Index of the matched grant in the capability scope.
    matched-grant-index: option<u32>,
}

/// The world a guard component targets.
world guard {
    /// Evaluate a tool-call request and return a verdict.
    export evaluate: func(request: guard-request) -> verdict;
}
```

### Pattern 2: Host-Side bindgen! Usage (Wasmtime 29)
**What:** The `bindgen!` macro generates Rust types and instantiation helpers from the WIT definition.
**When to use:** In the component backend module.
**Example:**
```rust
// Source: wasmtime 29.0.1 docs, bindgen_examples
// In crates/arc-wasm-guards/src/component.rs

use wasmtime::component::{bindgen, Component, Linker};
use wasmtime::{Engine, Store};

// Generate bindings from the WIT file.
// The path is relative to this crate's Cargo.toml.
bindgen!({
    path: "../../wit/arc-guard",
    world: "guard",
});

// The macro generates:
// - `Guard` struct with `instantiate()` and `call_evaluate()` methods
// - `Verdict` enum matching the WIT variant
// - `GuardRequest` struct matching the WIT record
// - No import traits needed (guard world has no imports in v0.1.0)
```

### Pattern 3: Dual-Mode Detection
**What:** Inspect .wasm bytes to determine core module vs component, then route to the correct backend.
**When to use:** At module load time in the backend.
**Example:**
```rust
// Source: wasmparser docs
use wasmparser::Parser;

pub fn detect_wasm_format(bytes: &[u8]) -> WasmFormat {
    if Parser::is_component(bytes) {
        WasmFormat::Component
    } else if Parser::is_core_wasm(bytes) {
        WasmFormat::CoreModule
    } else {
        WasmFormat::Unknown
    }
}

pub enum WasmFormat {
    CoreModule,
    Component,
    Unknown,
}
```

### Pattern 4: Component Backend Implementation
**What:** A new `WasmGuardAbi` implementation that uses Component Model APIs.
**When to use:** When the loaded .wasm is detected as a component.
**Example:**
```rust
// Source: wasmtime 29 component API docs
use std::sync::Arc;
use wasmtime::{Engine, Store};
use wasmtime::component::{Component, Linker};

pub struct ComponentBackend {
    engine: Arc<Engine>,
    component: Option<Component>,
    fuel_limit: u64,
    max_memory_bytes: usize,
    last_fuel_consumed: Option<u64>,
}

impl WasmGuardAbi for ComponentBackend {
    fn load_module(&mut self, wasm_bytes: &[u8], fuel_limit: u64) -> Result<(), WasmGuardError> {
        let component = Component::new(&self.engine, wasm_bytes)
            .map_err(|e| WasmGuardError::Compilation(e.to_string()))?;
        self.component = Some(component);
        self.fuel_limit = fuel_limit;
        Ok(())
    }

    fn evaluate(&mut self, request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError> {
        let component = self.component.as_ref()
            .ok_or(WasmGuardError::BackendUnavailable)?;

        // Create a fresh Store per invocation (same pattern as core backend)
        let mut store = Store::new(&self.engine, ());
        store.set_fuel(self.fuel_limit)
            .map_err(|e| WasmGuardError::Trap(e.to_string()))?;

        // The guard world has no imports, so linker is empty
        let linker: Linker<()> = Linker::new(&self.engine);
        let bindings = Guard::instantiate(&mut store, component, &linker)
            .map_err(|e| WasmGuardError::Trap(e.to_string()))?;

        // Convert GuardRequest (abi.rs) -> generated GuardRequest (WIT)
        let wit_request = to_wit_request(request);

        let wit_verdict = bindings.call_evaluate(&mut store, &wit_request)
            .map_err(|e| WasmGuardError::Trap(e.to_string()))?;

        // Track fuel
        let remaining = store.get_fuel().unwrap_or(0);
        self.last_fuel_consumed = Some(self.fuel_limit.saturating_sub(remaining));

        // Convert WIT verdict -> GuardVerdict (abi.rs)
        Ok(from_wit_verdict(wit_verdict))
    }

    fn backend_name(&self) -> &str { "wasmtime-component" }
    fn last_fuel_consumed(&self) -> Option<u64> { self.last_fuel_consumed }
}
```

### Pattern 5: Engine Configuration for Dual-Mode
**What:** The shared Engine must enable both core module and component model support.
**When to use:** In `create_shared_engine()`.
**Example:**
```rust
pub fn create_shared_engine() -> Result<Arc<Engine>, WasmGuardError> {
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    config.wasm_component_model(true);  // Required for Component::new()
    let engine = Engine::new(&config)
        .map_err(|e| WasmGuardError::Compilation(e.to_string()))?;
    Ok(Arc::new(engine))
}
```

### Anti-Patterns to Avoid
- **Separate Engines for core and component:** Use ONE shared `Arc<Engine>` with `wasm_component_model(true)`. A core-module-enabled Engine can also load core modules; the config flag is additive.
- **Parsing WIT at runtime:** The `bindgen!` macro runs at compile time. Never parse WIT files at runtime.
- **Reimplementing type conversion:** Map between `abi::GuardRequest` and the generated WIT `GuardRequest` with simple field-by-field conversion functions. Do not duplicate the type definitions.
- **Blocking on component model for core module path:** The existing raw ABI path must remain completely untouched. Dual-mode is additive, not a rewrite.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| WASM format detection | Manual magic byte parser | `wasmparser::Parser::is_core_wasm()` / `is_component()` | Authoritative, handles edge cases, version-aware |
| WIT-to-Rust type generation | Manual struct definitions matching WIT | `wasmtime::component::bindgen!` macro | Type-safe, auto-generated, stays in sync with WIT |
| Component instantiation | Manual export lookup and typed function extraction | `bindgen!`-generated `Guard::instantiate()` + `call_evaluate()` | Compile-time type checking, handles canonical ABI automatically |
| WIT syntax/validation | Custom WIT parser | Standard WIT toolchain (wasm-tools, wit-bindgen) | Specification-grade parsing |

**Key insight:** The `bindgen!` macro eliminates the entire class of serialization/deserialization bugs that plague the raw ABI path. WIT record fields map directly to Rust struct fields, and WIT variants map to Rust enums. No JSON, no pointer/length math, no manual memory management for the component path.

## Common Pitfalls

### Pitfall 1: Engine Config Missing wasm_component_model
**What goes wrong:** `Component::new()` returns an error because the Engine was created without `wasm_component_model(true)`.
**Why it happens:** The `component-model` Cargo feature enables the code to exist, but the Engine runtime flag defaults to `false`.
**How to avoid:** Always set `config.wasm_component_model(true)` in `create_shared_engine()`.
**Warning signs:** Error message like "component model support is not enabled" from `Component::new()`.

### Pitfall 2: bindgen! Path Resolution
**What goes wrong:** The `bindgen!` macro cannot find the WIT files because paths are relative to the crate's `Cargo.toml`, not the workspace root.
**Why it happens:** `arc-wasm-guards` is at `crates/arc-wasm-guards/`, so `../../wit/arc-guard` is needed to reach the workspace-level `wit/` directory.
**How to avoid:** Use `path: "../../wit/arc-guard"` in the bindgen! config. Test with `cargo check -p arc-wasm-guards --features wasmtime-runtime`.
**Warning signs:** Compile error about missing WIT files.

### Pitfall 3: Naming Collision Between Generated and Existing Types
**What goes wrong:** The `bindgen!` macro generates a `GuardRequest` type that collides with `abi::GuardRequest`.
**Why it happens:** Both represent the same concept but in different type systems.
**How to avoid:** Put the `bindgen!` invocation in its own module (`component.rs`) and use fully-qualified paths. The generated types live in the `bindgen!`-generated module namespace. Conversion functions bridge the two.
**Warning signs:** Compile errors about ambiguous types.

### Pitfall 4: WIT Identifier Conventions
**What goes wrong:** WIT uses kebab-case for identifiers (`tool-name`, `server-id`) while Rust uses snake_case.
**Why it happens:** WIT specification requires kebab-case.
**How to avoid:** `bindgen!` automatically converts kebab-case to snake_case in generated Rust types. Write WIT in kebab-case; use the generated snake_case in Rust.
**Warning signs:** If you try to use underscores in WIT, the parser rejects them.

### Pitfall 5: Component Linker vs Core Linker
**What goes wrong:** Using `wasmtime::Linker` (core) when you need `wasmtime::component::Linker` for components.
**Why it happens:** Both types are named `Linker` but serve different WASM formats.
**How to avoid:** Always use `wasmtime::component::Linker` for component instantiation and `wasmtime::Linker` for core module instantiation. Import with explicit module paths.
**Warning signs:** Type mismatch errors at instantiation.

### Pitfall 6: option and list Mapping in WIT
**What goes wrong:** WIT `option<T>` maps to `Option<T>` and `list<T>` maps to `Vec<T>` in Rust, but the canonical ABI encoding is not JSON.
**Why it happens:** Component Model uses its own canonical ABI for data transfer, not JSON.
**How to avoid:** Let `bindgen!` handle all encoding. The `arguments` field is deliberately kept as a `string` (JSON-encoded) in the WIT record because it carries opaque JSON data.
**Warning signs:** Trying to pass `serde_json::Value` across the component boundary.

## Code Examples

### Complete WIT Package Layout
```
wit/
  arc-guard/
    world.wit
```

The `world.wit` file contains the full package definition (see Pattern 1 above). No `deps/` subdirectory needed because the guard interface is self-contained.

### Type Conversion Between Raw ABI and WIT
```rust
// Source: mapping between existing abi.rs types and bindgen!-generated types

/// Convert an abi::GuardRequest into the WIT-generated GuardRequest.
fn to_wit_request(req: &crate::abi::GuardRequest) -> GuardRequest {
    GuardRequest {
        tool_name: req.tool_name.clone(),
        server_id: req.server_id.clone(),
        agent_id: req.agent_id.clone(),
        arguments: serde_json::to_string(&req.arguments)
            .unwrap_or_default(),
        scopes: req.scopes.clone(),
        action_type: req.action_type.clone(),
        extracted_path: req.extracted_path.clone(),
        extracted_target: req.extracted_target.clone(),
        filesystem_roots: req.filesystem_roots.clone(),
        matched_grant_index: req.matched_grant_index.map(|i| i as u32),
    }
}

/// Convert a WIT-generated Verdict into an abi::GuardVerdict.
fn from_wit_verdict(v: Verdict) -> crate::abi::GuardVerdict {
    match v {
        Verdict::Allow => crate::abi::GuardVerdict::Allow,
        Verdict::Deny(reason) => crate::abi::GuardVerdict::Deny {
            reason: Some(reason),
        },
    }
}
```

### Dual-Mode Load Path in WasmGuardRuntime
```rust
// Source: architecture pattern for dual-mode dispatch

use wasmparser::Parser;

pub fn create_backend(
    engine: Arc<Engine>,
    wasm_bytes: &[u8],
    fuel_limit: u64,
    config: HashMap<String, String>,
) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError> {
    if Parser::is_component(wasm_bytes) {
        let mut backend = ComponentBackend::with_engine(engine);
        backend.load_module(wasm_bytes, fuel_limit)?;
        Ok(Box::new(backend))
    } else if Parser::is_core_wasm(wasm_bytes) {
        let mut backend = WasmtimeBackend::with_engine_and_config(engine, config);
        backend.load_module(wasm_bytes, fuel_limit)?;
        Ok(Box::new(backend))
    } else {
        Err(WasmGuardError::Compilation(
            "unrecognized WASM format: neither core module nor component".to_string(),
        ))
    }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Raw `evaluate(ptr, len) -> i32` ABI | Component Model with WIT-defined types | WASI P2 stable Jan 2024 | Type-safe bindings, multi-language SDK generation |
| Manual JSON serde across boundary | Canonical ABI (automatic via bindgen!) | wasmtime Component Model stable 2024+ | No more pointer math, no JSON encoding bugs |
| Single module format | Dual-mode: core modules + components | This phase | Backward-compatible migration path |
| `wasm32-unknown-unknown` only | `wasm32-wasip2` for components | 2024+ | Richer toolchain support (jco, componentize-py, TinyGo) |

**Deprecated/outdated:**
- Raw ABI is not deprecated but becomes "legacy". All new guard authors should target WIT.
- The `session_metadata` field was already removed from GuardRequest in earlier phases.

## Open Questions

1. **Store state for component backend**
   - What we know: The guard world has no imports in v0.1.0, so `Store<()>` suffices. If we add `import arc:guard/logging@0.1.0` later, we need `Store<WasmHostState>` plus a component::Linker with host function implementations.
   - What's unclear: Whether to include `arc.log` as a WIT import in v0.1.0 or defer to v0.2.0.
   - Recommendation: Start with no imports (simplest). Add logging import in a follow-up phase when the guard SDK phase needs it. This keeps WIT-01/WIT-02 focused.

2. **ResourceLimiter for component Store**
   - What we know: The core module backend uses `StoreLimits` for memory capping. Component Model uses the same `Store` type, so `store.limiter()` should work identically.
   - What's unclear: Whether Component Model components have the same memory growth patterns as core modules.
   - Recommendation: Apply the same `StoreLimits` to component Stores. Verify in tests.

3. **matched_grant_index type: usize vs u32**
   - What we know: The existing `abi::GuardRequest` uses `Option<usize>` but WIT does not have a `usize` type. WIT has `u32` and `u64`.
   - What's unclear: Whether any real grant index would exceed u32 range.
   - Recommendation: Use `option<u32>` in WIT. Convert with `as u32` in the mapping function. No realistic capability scope will have 4 billion grants.

## Sources

### Primary (HIGH confidence)
- [wasmtime 29.0.1 docs - component module](https://docs.rs/wasmtime/29.0.1/wasmtime/component/index.html) - Component Model API surface, types, features
- [wasmtime 29.0.1 docs - bindgen! macro](https://docs.rs/wasmtime/29.0.1/wasmtime/component/macro.bindgen.html) - Macro configuration options, path resolution
- [wasmtime 29.0.1 bindgen examples](https://docs.wasmtime.dev/api/wasmtime/component/bindgen_examples/index.html) - Complete code patterns for host implementation
- [wasmtime 29.0.1 Cargo.toml](https://docs.rs/crate/wasmtime/29.0.1/source/Cargo.toml.orig) - Feature flags: `component-model` in default features, `wasm_component_model` config is false by default
- [wasmparser docs - Parser](https://docs.rs/wasmparser/latest/wasmparser/struct.Parser.html) - `is_core_wasm()` and `is_component()` static methods
- [WIT Reference - Component Model](https://component-model.bytecodealliance.org/design/wit.html) - WIT syntax: package, world, record, variant, enum, function signatures
- [WIT Specification](https://github.com/WebAssembly/component-model/blob/main/design/mvp/WIT.md) - Canonical WIT syntax reference

### Secondary (MEDIUM confidence)
- [wasmtime Config docs](https://docs.wasmtime.dev/api/wasmtime/struct.Config.html) - `wasm_component_model(true)` method documentation
- [jco / ComponentizeJS](https://github.com/bytecodealliance/jco) - JS/TS toolchain consuming WIT packages
- [componentize-py](https://github.com/bytecodealliance/componentize-py) - Python toolchain consuming WIT packages
- Existing project docs: `docs/guards/02-WASM-RUNTIME-LANDSCAPE.md` Sections 3-4 - Component Model rationale and WIT sketch

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - wasmtime 29.0.1 and wasmparser 0.221.3 confirmed in Cargo.lock; APIs verified against official docs
- Architecture: HIGH - dual-mode pattern is well-established (try Component::new, fall back to Module::new); bindgen! API stable in wasmtime 29
- Pitfalls: HIGH - Engine config gotcha (`wasm_component_model` defaults false) verified against official docs; path resolution verified; type collision pattern documented

**Research date:** 2026-04-14
**Valid until:** 2026-05-14 (wasmtime 29 is stable; WIT spec is stable)
