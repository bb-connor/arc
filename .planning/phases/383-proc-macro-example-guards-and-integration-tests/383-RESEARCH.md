# Phase 383: Proc Macro, Example Guards, and Integration Tests - Research

**Researched:** 2026-04-14
**Domain:** Rust proc macros, WASM ABI code generation, guard SDK ergonomics
**Confidence:** HIGH

## Summary

This phase creates three interconnected deliverables: (1) an `arc-guard-sdk-macros` proc-macro crate that generates WASM ABI exports from a single `#[arc_guard]`-annotated function, (2) example guards demonstrating the SDK surface area, and (3) integration tests that compile examples to `wasm32-unknown-unknown` and run them through the WasmtimeBackend host runtime.

The proc macro is straightforward: it takes a function with signature `fn(GuardRequest) -> GuardVerdict` and generates the `#[no_mangle] pub extern "C" fn evaluate(ptr: i32, len: i32) -> i32` export plus re-exports of `arc_alloc`, `arc_free`, and `arc_deny_reason` from the SDK. The existing SDK already provides all the building blocks (`read_request`, `encode_verdict`, allocator, deny-reason glue) -- the macro just wires them together.

Example guards should be minimal crate(s) under `examples/guards/` that depend on `arc-guard-sdk` and `arc-guard-sdk-macros`, compile to `wasm32-unknown-unknown`, and exercise the three usage patterns: tool-name inspection (GEXM-01), enriched field reading (GEXM-02), and host function calls (GEXM-03). Integration tests live alongside the `arc-wasm-guards` crate (or as a dedicated test binary) and load compiled `.wasm` binaries into the WasmtimeBackend to verify round-trip correctness.

**Primary recommendation:** Build the proc macro to generate exactly the manual ABI glue that a guard author would otherwise copy-paste, using `syn 2` + `quote` for code generation. Keep examples in a single crate with multiple guard functions (one lib.rs with separate `#[arc_guard]` functions won't work since each needs its own crate for independent wasm compilation). Use a build script or test harness to compile examples to `.wasm` before running integration tests.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
None -- all implementation choices are at Claude's discretion.

### Claude's Discretion
All implementation choices are at Claude's discretion -- pure infrastructure phase. Key constraints:
- #[arc_guard] proc macro generates: evaluate ABI export, arc_alloc, arc_free, arc_deny_reason
- Guard author writes: #[arc_guard] fn evaluate(req: GuardRequest) -> GuardVerdict { ... }
- Example guards: tool-name allow/deny, enriched field inspection, host function usage
- Examples must compile to wasm32-unknown-unknown and produce valid .wasm binaries
- Integration tests load compiled .wasm into WasmtimeBackend and verify verdicts
- Proc macro crate type: proc-macro (separate crate required by Rust)
- wasm32-unknown-unknown target must be installed for compilation

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| GSDK-06 | `arc-guard-sdk-macros` provides `#[arc_guard]` proc macro generating evaluate export, allocator, and ABI glue | Proc macro architecture pattern documented; exact code generation template derived from existing SDK glue |
| GEXM-01 | Example guard demonstrates allowing/denying based on tool name inspection | `GuardRequest.tool_name` field verified in SDK types; allow/deny pattern documented |
| GEXM-02 | Example guard demonstrates reading `action_type` and `extracted_path` from enriched GuardRequest | `GuardRequest.action_type` and `extracted_path` are `Option<String>` fields verified in SDK types |
| GEXM-03 | Example guard demonstrates calling `arc::log` and `arc::get_config` host functions | `host::log()` and `host::get_config()` wrappers verified; `log_level` constants documented |
| GEXM-04 | Example guards compile to `wasm32-unknown-unknown` and produce valid .wasm binaries | `wasm32-unknown-unknown` target confirmed installed; SDK designed for dual-target compilation |
| GEXM-05 | Integration test loads example guard .wasm into WasmtimeBackend, evaluates against test requests, verifies Allow/Deny verdicts | WasmtimeBackend API documented; `load_module()` + `evaluate()` flow verified |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| syn | 2.0.117 | Rust syntax parsing for proc macro | De facto standard for proc macros; full visitors/folders |
| quote | 1.0.45 | Quasi-quoting for token stream generation | Paired with syn; `quote!{}` macro is the standard way to produce tokens |
| proc-macro2 | 1.0.106 | Compiler proc_macro API wrapper | Required by syn/quote; enables unit testing of token streams |
| wasmtime | 29 | WASM runtime for integration tests | Already used by `arc-wasm-guards`; feature-gated behind `wasmtime-runtime` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| serde | 1 (workspace) | JSON serialization in guards | Already depended on by arc-guard-sdk |
| serde_json | 1 (workspace) | JSON value handling in guards | Already depended on by arc-guard-sdk |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| syn 2 (full feature) | syn 2 (derive feature only) | `derive` feature is enough for parsing ItemFn; avoid full parser overhead |
| Multiple example crates | Single crate with features | Each .wasm binary needs its own cdylib crate; no workaround |

**Installation (proc-macro crate):**
```bash
# No install needed -- Cargo workspace members
# Proc macro crate deps (not workspace-managed):
# syn = { version = "2", features = ["full"] }
# quote = "1"
# proc-macro2 = "1"
```

**Version verification:** syn 2.0.117, quote 1.0.45, proc-macro2 1.0.106 confirmed via `cargo search` on 2026-04-14. wasmtime 29 confirmed from `arc-wasm-guards/Cargo.toml`.

## Architecture Patterns

### Recommended Project Structure
```
crates/
  arc-guard-sdk-macros/         # NEW: proc-macro crate
    Cargo.toml                  # [lib] proc-macro = true
    src/
      lib.rs                    # #[proc_macro_attribute] pub fn arc_guard(...)
examples/
  guards/
    tool-gate/                  # NEW: example guard (GEXM-01)
      Cargo.toml                # [lib] crate-type = ["cdylib"]
      src/lib.rs                # #[arc_guard] fn evaluate(req) -> verdict
    enriched-inspector/         # NEW: example guard (GEXM-02, GEXM-03)
      Cargo.toml                # [lib] crate-type = ["cdylib"]
      src/lib.rs                # Uses action_type, extracted_path, log, get_config
tests/
  guard-integration/            # OR: tests/ dir inside arc-wasm-guards
    ...
```

### Pattern 1: Proc Macro Code Generation

**What:** The `#[arc_guard]` attribute macro transforms a user function into a complete WASM guard binary by generating the ABI exports.

**When to use:** Every guard crate that wants to avoid manual ABI wiring.

**User writes:**
```rust
use arc_guard_sdk::prelude::*;

#[arc_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    if req.tool_name == "dangerous_tool" {
        GuardVerdict::deny("tool is blocked by policy")
    } else {
        GuardVerdict::allow()
    }
}
```

**Macro generates (conceptually):**
```rust
// Re-export allocator from SDK
pub use arc_guard_sdk::alloc::{arc_alloc, arc_free};

// Re-export deny reason glue from SDK
pub use arc_guard_sdk::glue::arc_deny_reason;

// The user's function (renamed to avoid collision)
fn __arc_guard_user_evaluate(req: arc_guard_sdk::GuardRequest) -> arc_guard_sdk::GuardVerdict {
    // ... user's body ...
}

// Generated ABI export
#[no_mangle]
pub extern "C" fn evaluate(ptr: i32, len: i32) -> i32 {
    let req = match unsafe { arc_guard_sdk::read_request(ptr, len) } {
        Ok(r) => r,
        Err(_) => return arc_guard_sdk::VERDICT_DENY,
    };
    let verdict = __arc_guard_user_evaluate(req);
    arc_guard_sdk::encode_verdict(verdict)
}
```

**Key decisions in generation:**
- The user function is renamed internally (e.g. prefixed with `__arc_guard_user_`) to avoid symbol collision with the `evaluate` ABI export
- `arc_alloc` and `arc_free` are re-exported via `pub use` from `arc_guard_sdk::alloc` -- not re-implemented
- `arc_deny_reason` is re-exported via `pub use` from `arc_guard_sdk::glue` -- not re-implemented
- On deserialization failure, the macro generates a fail-closed `VERDICT_DENY` path (consistent with host-side fail-closed design)
- The `unsafe` block is limited to the `read_request` call only

### Pattern 2: Example Guard as cdylib Crate

**What:** Each example guard is a standalone crate with `crate-type = ["cdylib"]` that compiles to a `.wasm` binary.

**When to use:** Every guard that needs to be compiled to WASM.

**Example Cargo.toml:**
```toml
[package]
name = "arc-example-tool-gate"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
arc-guard-sdk = { path = "../../crates/arc-guard-sdk" }
arc-guard-sdk-macros = { path = "../../crates/arc-guard-sdk-macros" }
```

**Build command:**
```bash
cargo build --target wasm32-unknown-unknown --release -p arc-example-tool-gate
```

**Output:** `target/wasm32-unknown-unknown/release/arc_example_tool_gate.wasm`

### Pattern 3: Integration Test Loading Compiled WASM

**What:** Integration tests compile example guards to `.wasm`, then load them into `WasmtimeBackend` and assert verdicts.

**When to use:** GEXM-05 -- verifying end-to-end guard correctness.

**Approach options:**
1. **Build script (build.rs)** -- compile `.wasm` as part of the test crate build
2. **Cargo test with pre-built artifacts** -- require `.wasm` to exist in a known path
3. **In-test compilation** -- call `cargo build --target wasm32-unknown-unknown` from the test itself

**Recommended: Option 2 with CI compilation step.** The integration test reads `.wasm` from `target/wasm32-unknown-unknown/release/`. A CI workflow step compiles examples before running tests. For local development, the developer runs `cargo build --target wasm32-unknown-unknown -p <example>` first. This avoids nested cargo calls and build script complexity.

**Test structure:**
```rust
#[cfg(feature = "wasmtime-runtime")]
#[test]
fn tool_gate_guard_allows_safe_tool() {
    let wasm_bytes = std::fs::read(
        "../../target/wasm32-unknown-unknown/release/arc_example_tool_gate.wasm"
    ).expect("build example with: cargo build --target wasm32-unknown-unknown -p arc-example-tool-gate");

    let engine = create_shared_engine().unwrap();
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm_bytes, 1_000_000).unwrap();

    let request = GuardRequest {
        tool_name: "safe_tool".into(),
        server_id: "test".into(),
        agent_id: "agent".into(),
        arguments: serde_json::json!({}),
        scopes: vec![],
        action_type: None,
        extracted_path: None,
        extracted_target: None,
        filesystem_roots: vec![],
        matched_grant_index: None,
    };

    let verdict = backend.evaluate(&request).unwrap();
    assert!(verdict.is_allow());
}
```

### Anti-Patterns to Avoid

- **Single cdylib crate with multiple guards:** Each guard function needs its own `evaluate` symbol. A single crate can only export one `evaluate` function. Separate crates are mandatory.
- **Using `#[proc_macro_derive]` instead of `#[proc_macro_attribute]`:** Derive macros work on structs/enums. We need an attribute macro on functions.
- **Generating `arc_alloc`/`arc_free` as inline code:** The SDK already exports these as `#[no_mangle]` functions. The macro should re-export them via `pub use`, not duplicate the implementation.
- **Running `cargo build` inside test code:** Nested cargo invocations are fragile and slow. Pre-compile `.wasm` artifacts instead.
- **Using `unwrap()` or `expect()` in generated code:** Workspace clippy lint `unwrap_used = "deny"` applies. Generated code must use `match` or `if let`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Token stream parsing | Manual string manipulation | `syn::parse_macro_input!` | syn handles all Rust syntax edge cases |
| Code generation | String concatenation of Rust code | `quote::quote!{}` | Hygienic, type-safe, handles spans |
| Function signature extraction | Manual token inspection | `syn::ItemFn` | Full fn parsing including generics, attrs |
| WASM allocation | Custom allocator in each guard | `pub use arc_guard_sdk::alloc::*` | SDK allocator is tested and correct |
| Deny reason plumbing | Per-guard deny reason code | `pub use arc_guard_sdk::glue::arc_deny_reason` | SDK glue handles thread-local storage |

**Key insight:** The proc macro's job is purely mechanical wiring. Every piece of runtime logic already exists in `arc-guard-sdk`. The macro generates zero runtime code beyond a thin `evaluate` wrapper that calls SDK functions.

## Common Pitfalls

### Pitfall 1: Proc Macro Crate Cannot Depend on Runtime Types
**What goes wrong:** Trying to make `arc-guard-sdk-macros` depend on `arc-guard-sdk` for type definitions. Proc-macro crates can only export proc macros; they cannot also export regular items.
**Why it happens:** Developer wants to share types between macro and runtime.
**How to avoid:** The macro generates code that *references* `arc_guard_sdk::*` paths. It does not import or use those types at macro-expansion time. The macro crate depends only on `syn`, `quote`, `proc-macro2`.
**Warning signs:** Compile errors about "proc-macro crate types cannot export other items."

### Pitfall 2: Symbol Collision Between User Function and ABI Export
**What goes wrong:** If the user names their function `evaluate`, the generated `#[no_mangle] extern "C" fn evaluate(...)` collides.
**Why it happens:** The macro needs to generate a function named `evaluate` (the ABI contract) but the user also wrote a function.
**How to avoid:** Rename the user's function internally. The macro rewrites it to `__arc_guard_user_evaluate` or similar, then calls it from the generated `evaluate` export.
**Warning signs:** "duplicate symbol" or "function already defined" linker errors.

### Pitfall 3: Clippy Lint Violations in Generated Code
**What goes wrong:** Generated code uses patterns that trigger workspace clippy lints (`unwrap_used`, `expect_used`, `cast_possible_truncation`).
**Why it happens:** `quote!{}` generates code at the call site, inheriting the call site's lint configuration.
**How to avoid:** The generated code must use `match`/`if let` instead of `unwrap()`/`expect()`. Add `#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]` to the generated `evaluate` function for the `ptr as *const u8` cast. Or better, delegate entirely to `read_request` which already handles this.
**Warning signs:** Clippy failures on the example guard crates.

### Pitfall 4: Forgetting `pub use` for `#[no_mangle]` Exports
**What goes wrong:** The `arc_alloc`, `arc_free`, and `arc_deny_reason` symbols don't appear in the `.wasm` binary because they're not re-exported from the guard crate root.
**Why it happens:** Rust's linkage model requires `#[no_mangle]` items to be reachable from the crate root for WASM exports.
**How to avoid:** The macro generates `pub use arc_guard_sdk::alloc::{arc_alloc, arc_free};` and `pub use arc_guard_sdk::glue::arc_deny_reason;` at the crate root scope.
**Warning signs:** `WasmtimeBackend` falls back to offset-0 write (no `arc_alloc`), generic deny reasons (no `arc_deny_reason`).

### Pitfall 5: Example Crate Not in Workspace Members
**What goes wrong:** `cargo build --target wasm32-unknown-unknown -p <example>` fails because the example crate is not listed in `Cargo.toml` workspace members.
**Why it happens:** New crates added to filesystem but not to workspace config.
**How to avoid:** Add each example guard crate to the `[workspace]` `members` array in the root `Cargo.toml`.
**Warning signs:** "package `arc-example-*` is not a member of the workspace."

### Pitfall 6: wasm32-unknown-unknown Breaking Non-WASM Dependencies
**What goes wrong:** Example guard crates pull in dependencies that don't compile on `wasm32-unknown-unknown` (e.g., tokio, reqwest, std::net).
**Why it happens:** Transitive dependencies from the workspace or SDK.
**How to avoid:** `arc-guard-sdk` is already designed for `wasm32-unknown-unknown` -- it only depends on `serde` and `serde_json`. Example guards should depend ONLY on `arc-guard-sdk` and `arc-guard-sdk-macros`. Do not add workspace-wide deps like `tokio`.
**Warning signs:** Compilation errors mentioning `not found for target wasm32-unknown-unknown`.

## Code Examples

### Proc Macro Implementation (arc-guard-sdk-macros/src/lib.rs)

```rust
// Source: Derived from arc-guard-sdk glue.rs + alloc.rs API surface
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn arc_guard(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let fn_body = &input_fn.block;
    let fn_inputs = &input_fn.sig.inputs;
    let fn_output = &input_fn.sig.output;
    let fn_attrs = &input_fn.attrs;
    let fn_vis = &input_fn.vis;

    // Generate an internal name to avoid collision with the ABI `evaluate`
    let internal_name = quote::format_ident!("__arc_guard_user_{}", fn_name);

    let expanded = quote! {
        // Re-export allocator so host can probe arc_alloc/arc_free
        pub use arc_guard_sdk::alloc::{arc_alloc, arc_free};

        // Re-export deny reason glue so host can probe arc_deny_reason
        pub use arc_guard_sdk::glue::arc_deny_reason;

        // The user's guard logic under an internal name
        #(#fn_attrs)*
        #fn_vis fn #internal_name(#fn_inputs) #fn_output
            #fn_body

        // ABI export: evaluate(ptr, len) -> i32
        #[no_mangle]
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        pub extern "C" fn evaluate(ptr: i32, len: i32) -> i32 {
            let req = match unsafe { arc_guard_sdk::read_request(ptr, len) } {
                Ok(r) => r,
                Err(_) => return arc_guard_sdk::VERDICT_DENY,
            };
            let verdict = #internal_name(req);
            arc_guard_sdk::encode_verdict(verdict)
        }
    };

    TokenStream::from(expanded)
}
```

### Example Guard: Tool Gate (GEXM-01)

```rust
// Source: Derived from arc-guard-sdk types + prelude
use arc_guard_sdk::prelude::*;
use arc_guard_sdk_macros::arc_guard;

#[arc_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    match req.tool_name.as_str() {
        "dangerous_tool" | "rm_rf" => {
            GuardVerdict::deny("tool is blocked by policy")
        }
        _ => GuardVerdict::allow(),
    }
}
```

### Example Guard: Enriched Inspector (GEXM-02, GEXM-03)

```rust
// Source: Derived from arc-guard-sdk host + types API
use arc_guard_sdk::prelude::*;
use arc_guard_sdk_macros::arc_guard;

#[arc_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    // GEXM-03: Use host functions
    log(log_level::INFO, "enriched inspector evaluating request");

    let blocked_path = get_config("blocked_path");

    // GEXM-02: Read enriched fields
    if let Some(ref action) = req.action_type {
        if action == "file_write" {
            if let Some(ref path) = req.extracted_path {
                log(log_level::WARN, "file write detected");

                // Check against configured blocked path
                if let Some(ref bp) = blocked_path {
                    if path.starts_with(bp.as_str()) {
                        return GuardVerdict::deny(
                            "write to protected path blocked by policy"
                        );
                    }
                }

                // Default: block writes to /etc
                if path.starts_with("/etc") {
                    return GuardVerdict::deny(
                        "write to /etc blocked"
                    );
                }
            }
        }
    }

    GuardVerdict::allow()
}
```

### Integration Test Pattern (GEXM-05)

```rust
// Source: Derived from arc-wasm-guards runtime.rs WasmtimeBackend API
use arc_wasm_guards::abi::GuardRequest;
use arc_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;
use arc_wasm_guards::host::create_shared_engine;

fn load_example_wasm(name: &str) -> Vec<u8> {
    let path = format!(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/wasm32-unknown-unknown/release/{}.wasm"),
        name
    );
    std::fs::read(&path).unwrap_or_else(|_| {
        panic!("Missing .wasm: build with: cargo build --target wasm32-unknown-unknown --release -p {}", name)
    })
}

#[test]
fn tool_gate_allows_safe_tool() {
    let wasm = load_example_wasm("arc_example_tool_gate");
    let engine = create_shared_engine().expect("engine");
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm, 1_000_000).expect("load");

    let request = GuardRequest { /* safe tool fields */ };
    let verdict = backend.evaluate(&request).expect("evaluate");
    assert!(verdict.is_allow());
}

#[test]
fn tool_gate_denies_dangerous_tool() {
    let wasm = load_example_wasm("arc_example_tool_gate");
    let engine = create_shared_engine().expect("engine");
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(&wasm, 1_000_000).expect("load");

    let request = GuardRequest {
        tool_name: "dangerous_tool".into(),
        /* ... */
    };
    let verdict = backend.evaluate(&request).expect("evaluate");
    assert!(verdict.is_deny());
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Manual ABI glue per guard | `#[arc_guard]` proc macro | Phase 383 (this phase) | Guard authors write one function, macro handles all ABI |
| WAT-based test guards | Real Rust-compiled .wasm guards | Phase 383 (this phase) | Integration tests validate the full SDK-to-host round trip |
| syn 1.x for proc macros | syn 2.x | 2023 | Breaking API change; use `parse_macro_input!` not `parse_macro_derive_input!` |

**Deprecated/outdated:**
- syn 1.x: Still works but syn 2.x is current. Use syn 2.

## Open Questions

1. **Integration test WASM artifact location**
   - What we know: Compiled `.wasm` files end up in `target/wasm32-unknown-unknown/release/`
   - What's unclear: Whether to use `env!("CARGO_MANIFEST_DIR")` relative paths or absolute paths in tests
   - Recommendation: Use `env!("CARGO_MANIFEST_DIR")` + relative path to target dir. Document the required `cargo build --target wasm32-unknown-unknown` step.

2. **Example guards as workspace members vs exclude**
   - What we know: Workspace members compile for the host target by default. Example guards target `wasm32-unknown-unknown` only.
   - What's unclear: Whether `cargo test --workspace` will fail trying to build cdylib examples for the host target.
   - Recommendation: Add example guards as workspace members. They should compile fine for the host target too (cdylib on native is valid). The `cfg(target_arch = "wasm32")` gating in the SDK handles host function stubs. Integration tests will separately compile them for the wasm target.

3. **Proc macro error handling for invalid function signatures**
   - What we know: The macro expects `fn(GuardRequest) -> GuardVerdict`
   - What's unclear: How strict to be about signature validation
   - Recommendation: Accept any single-argument function and let type checking catch mismatches. This is simpler and more flexible.

## Sources

### Primary (HIGH confidence)
- `crates/arc-guard-sdk/src/lib.rs` -- SDK public API surface
- `crates/arc-guard-sdk/src/glue.rs` -- `read_request`, `encode_verdict`, `arc_deny_reason` implementation
- `crates/arc-guard-sdk/src/alloc.rs` -- `arc_alloc`, `arc_free` implementation
- `crates/arc-guard-sdk/src/host.rs` -- `log()`, `get_config()`, `get_time()` wrappers
- `crates/arc-guard-sdk/src/types.rs` -- `GuardRequest`, `GuardVerdict` type definitions
- `crates/arc-wasm-guards/src/runtime.rs` -- `WasmtimeBackend` evaluate flow
- `crates/arc-wasm-guards/src/host.rs` -- Host function registration
- `crates/arc-wasm-guards/src/abi.rs` -- Host-side ABI trait and types
- `docs/guards/05-V1-DECISION.md` -- Design authority for raw WASM ABI

### Secondary (MEDIUM confidence)
- `cargo search` results for syn/quote/proc-macro2 versions (2026-04-14)
- Rust toolchain version check: rustc 1.93.0

### Tertiary (LOW confidence)
- None -- all findings verified against codebase

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all deps verified via registry and existing workspace usage
- Architecture: HIGH -- derived directly from existing SDK code and host runtime
- Pitfalls: HIGH -- identified from actual codebase patterns and Rust proc-macro conventions

**Research date:** 2026-04-14
**Valid until:** 2026-05-14 (stable Rust ecosystem; proc-macro patterns are mature)
