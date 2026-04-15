# Phase 388: Python and Go Guard SDKs - Research

**Researched:** 2026-04-14
**Domain:** WebAssembly Component Model guest SDKs (componentize-py, TinyGo wasip2)
**Confidence:** MEDIUM

## Summary

This phase ships two new guard SDKs -- `arc-guard-py` and `arc-guard-go` -- that
compile Python and Go guard implementations to WASM Component Model binaries
loadable by the existing `ComponentBackend` host runtime. The established pattern
from `arc-guard-ts` (Phase 387) provides the template: generate typed bindings
from `wit/arc-guard/world.wit`, implement the `evaluate` export, compile to a
`.wasm` component, and verify the round trip through integration tests.

The two toolchains present fundamentally different challenges. **componentize-py**
bundles the CPython interpreter into the component, producing ~10-35 MiB binaries
but offering straightforward `--stub-wasi` support to eliminate WASI imports.
**TinyGo wasip2** produces much smaller (~500 KiB-2 MiB) binaries but currently
hard-requires `wasi:cli/imports@0.2.0` in the WIT world, which conflicts with
the ARC guard world that has zero imports. The Go SDK requires either (a)
extending the guard WIT to include WASI CLI imports for TinyGo, then using
`wasi-virt` to strip them post-compilation, or (b) adding `wasmtime-wasi` to
the host linker. Option (a) is recommended to keep the host linker pure.

**Primary recommendation:** Follow the TS SDK pattern exactly. Generate typed
bindings from the canonical WIT, implement a `tool-gate` example guard in each
language, compile to `.wasm`, and add Rust integration tests that load the
compiled components through `ComponentBackend`.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key constraints:

- Python SDK at packages/sdk/arc-guard-py/ using componentize-py
- Go SDK at packages/sdk/arc-guard-go/ using TinyGo with wasip2 target
- Types generated from WIT definition (arc:guard@0.1.0)
- Example guards for both languages with build instructions
- Compiled guards load and evaluate in host dual-mode runtime
- Build from zero to .wasm in under 5 commands per language

### Claude's Discretion
All implementation choices are at Claude's discretion -- pure infrastructure phase.

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| PYDK-01 | Python guard SDK provides typed dataclasses matching WIT contract | componentize-py `bindings` subcommand generates Python protocol classes from WIT; SDK wraps these with ergonomic dataclasses |
| PYDK-02 | Python guards compile to WASM components via componentize-py | `componentize-py -d wit -w guard componentize --stub-wasi app -o guard.wasm` produces self-contained component |
| PYDK-03 | Python SDK includes example guard with build instructions | Tool-gate example mirrors TS SDK pattern; build script wraps 3-4 commands |
| PYDK-04 | Python-compiled guard loads and evaluates correctly in host | ComponentBackend with raised module-size limits (like TS guard at 15 MiB); integration test pattern from `ts_guard_integration.rs` |
| GODK-01 | Go guard SDK provides typed structs matching WIT contract | wit-bindgen-go generates Go structs from WIT; SDK re-exports or wraps these |
| GODK-02 | Go guards compile to WASM components via TinyGo wasip2 | `tinygo build -target=wasip2 --wit-package ... --wit-world guard -o guard.wasm` with WASI included in world + wasi-virt post-processing |
| GODK-03 | Go SDK includes example guard with build instructions | Tool-gate example using init() pattern; build script wraps 4-5 commands |
| GODK-04 | Go-compiled guard loads and evaluates correctly in host | ComponentBackend loads the post-virtualized component; integration test follows TS pattern |
</phase_requirements>

## Standard Stack

### Core

| Tool | Version | Purpose | Why Standard |
|------|---------|---------|--------------|
| componentize-py | >=0.19 (latest ~0.21) | Compile Python to WASM Component Model | Bytecode Alliance official tool; only viable Python-to-component path |
| TinyGo | >=0.34.0 (latest 0.40.1) | Compile Go to WASM with wasip2 target | Only Go compiler supporting Component Model output; standard Go compiler lacks WASM component support |
| wit-bindgen-go | v0.7.0 | Generate Go type bindings from WIT | Bytecode Alliance official Go binding generator |
| wasi-virt | latest git | Strip WASI imports from TinyGo output | Required to produce pure-export components from TinyGo's WASI-mandatory output |
| wasm-tools | >=1.225.0 | WIT encoding, component inspection | Standard CLI for Component Model operations; TinyGo recommends 1.225.0 for compatibility |

### Supporting

| Tool | Version | Purpose | When to Use |
|------|---------|---------|-------------|
| wkg | latest | WIT dependency resolution | When TinyGo needs bundled WIT with WASI deps resolved |
| Python | >=3.11 | Runtime for componentize-py | componentize-py requires Python 3.10+; project already uses 3.11+ |
| Go | >=1.24 | Required for `go tool` directive | wit-bindgen-go uses `go tool` pattern from Go 1.24+ |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| wasi-virt (for Go) | wasmtime-wasi in host linker | Would add WASI dependency to host runtime; violates zero-import guard security model |
| wasi-virt (for Go) | wasm-tools compose | Lower-level, same concept; wasi-virt is the purpose-built tool |
| componentize-py | Pyodide/emscripten | Produces core module not component; no WIT support |

**Installation (Python SDK development):**
```bash
pip install componentize-py
```

**Installation (Go SDK development):**
```bash
# TinyGo: follow https://tinygo.org/getting-started/
brew install tinygo  # macOS

# wit-bindgen-go: added as go tool in go.mod
go get -tool go.bytecodealliance.org/cmd/wit-bindgen-go

# wasi-virt: from Bytecode Alliance
cargo install --git https://github.com/bytecodealliance/wasi-virt

# wasm-tools: for WIT operations
cargo install --locked wasm-tools@1.225.0
```

## Architecture Patterns

### Recommended Project Structure

```
packages/sdk/
  arc-guard-py/
    pyproject.toml          # Package metadata (no runtime deps)
    src/
      arc_guard/
        __init__.py         # Re-exports Verdict, GuardRequest types
        types.py            # Ergonomic Python dataclasses wrapping WIT types
    examples/
      tool-gate/
        guard.py            # Example guard implementation
    scripts/
      build-guard.sh        # Build script: bindings -> componentize
      generate-types.sh     # Just the bindings step
    dist/                   # .gitignored, build output
      tool-gate.wasm
    README.md

  arc-guard-go/
    go.mod                  # Module with wit-bindgen-go tool dep
    go.sum
    guard.go                # SDK types and helpers
    wit/
      guard-go.wit          # Extended WIT with wasi:cli/imports included
    internal/               # .gitignored, generated bindings from wit-bindgen-go
    examples/
      tool-gate/
        main.go             # Example guard using init() pattern
    scripts/
      build-guard.sh        # Build script: bindgen -> tinygo -> wasi-virt
    dist/                   # .gitignored, build output
      tool-gate.wasm
    README.md
```

### Pattern 1: Python Guard Implementation

**What:** Python guard targeting the `arc:guard@0.1.0` world
**When to use:** Any Python-based guard implementation

```python
# guard.py -- implements arc:guard/guard world's evaluate export
# Source: componentize-py bindings pattern from official docs

from wit_world.exports import Evaluate
from wit_world.types import Verdict_Allow, Verdict_Deny, GuardRequest

BLOCKED_TOOLS = frozenset(["dangerous_tool", "rm_rf", "drop_database"])

class Evaluate(Evaluate):
    def evaluate(self, request: GuardRequest) -> "Verdict_Allow | Verdict_Deny":
        if request.tool_name in BLOCKED_TOOLS:
            return Verdict_Deny("tool is blocked by policy")
        return Verdict_Allow()
```

**Note:** The exact generated type names depend on componentize-py's output. The
bindings subcommand generates a `wit_world/` directory with protocol classes.
Verify actual names after running `componentize-py bindings`.

### Pattern 2: Go Guard Implementation

**What:** Go guard targeting the `arc:guard@0.1.0` world
**When to use:** Any Go-based guard implementation

```go
// main.go -- implements arc:guard/guard world's evaluate export
// Source: Go Component Model docs pattern

package main

import (
    guard "example.com/internal/arc/guard/guard"
)

var blockedTools = map[string]bool{
    "dangerous_tool": true,
    "rm_rf":          true,
    "drop_database":  true,
}

func init() {
    guard.Exports.Evaluate = func(request guard.GuardRequest) guard.Verdict {
        if blockedTools[request.ToolName] {
            return guard.VerdictDeny("tool is blocked by policy")
        }
        return guard.VerdictAllow()
    }
}

func main() {}
```

**Note:** The exact generated type paths depend on wit-bindgen-go's output for the
`arc:guard@0.1.0` world. The `internal/` directory structure will be generated.
The empty `main()` is required by TinyGo's wasip2 target.

### Pattern 3: Integration Test (Rust host-side)

**What:** Round-trip test loading compiled guards in ComponentBackend
**When to use:** Verification of PYDK-04 and GODK-04

```rust
// Following the pattern from ts_guard_integration.rs
fn load_py_guard_wasm() -> Vec<u8> {
    let path = format!(
        "{}/../../packages/sdk/arc-guard-py/dist/tool-gate.wasm",
        env!("CARGO_MANIFEST_DIR"),
    );
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!("Missing .wasm at {path}: {e}. Build with: \
               cd packages/sdk/arc-guard-py && ./scripts/build-guard.sh")
    })
}
```

### Anti-Patterns to Avoid

- **Adding wasmtime-wasi to the host linker:** The guard world has zero imports.
  Keep it that way. Use wasi-virt to strip WASI imports from TinyGo output
  rather than making the host provide WASI.
- **Runtime imports in Python:** componentize-py requires all imports to be
  resolvable at build time. Lazy imports inside class methods will fail. Move
  all imports to module top level.
- **Sharing generated bindings in git:** Generated type directories (`wit_world/`
  for Python, `internal/` for Go) should be `.gitignored` and regenerated
  during build, like the TS SDK's `src/types/`.
- **Skipping --stub-wasi for Python:** CPython's stdlib needs WASI internally.
  Without `--stub-wasi`, the component will import `wasi:cli` which the ARC
  host linker cannot satisfy.
- **Using standard Go compiler:** Only TinyGo supports WASM Component Model.
  The standard `go build` GOOS=wasip1 produces core modules, not components.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Python WIT type bindings | Manual Python dataclasses from reading WIT | `componentize-py bindings` subcommand | Generates correct protocol classes matching WIT variant/record semantics |
| Go WIT type bindings | Manual Go structs from reading WIT | `wit-bindgen-go generate` | Generates correct Go types with `cm` helper package for variant/result/option |
| Python-to-WASM compilation | CPython + emscripten hacks | `componentize-py componentize` | Handles CPython embedding, shared-everything linking, native extensions |
| WASI import stripping | Manual wasm-tools binary editing | `wasi-virt` | Purpose-built tool that composes a virtualizer component to satisfy imports |
| WIT dependency resolution | Manual copy of WASI WIT files | `wkg wit build` | Resolves and bundles all WIT imports (wasi:cli, wasi:io, etc.) |

**Key insight:** The entire Component Model toolchain exists to make cross-language
WASM compilation tractable. Every piece of manual ABI glue is a bug waiting to
happen. Use the official tools.

## Common Pitfalls

### Pitfall 1: TinyGo Requires wasi:cli/imports in the WIT World

**What goes wrong:** TinyGo's wasip2 target hard-wires `wasi:cli/command@0.2.0`.
Compiling against a WIT world that lacks `include wasi:cli/imports@0.2.0` fails.
**Why it happens:** TinyGo's runtime needs WASI for basic operations (memory
allocation, panic handling) even if the guest code does not use WASI APIs.
**How to avoid:** Create a separate `guard-go.wit` that includes both the ARC
guard exports AND `wasi:cli/imports@0.2.0`. After compilation, run `wasi-virt`
to produce a component that no longer imports WASI.
**Warning signs:** `tinygo build` error about unresolved imports or missing world.

### Pitfall 2: componentize-py Binary Size Exceeds Default Module Limit

**What goes wrong:** componentize-py output is ~10-35 MiB (bundles CPython).
The `ComponentBackend` default `max_module_size` is 10 MiB.
**Why it happens:** CPython interpreter + wasi-libc + stdlib = large binary.
**How to avoid:** Use `ComponentBackend::with_limits()` to raise the max module
size, exactly as done for the TS guard (which embeds SpiderMonkey at ~11 MiB).
Set Python limit to 40 MiB to be safe.
**Warning signs:** `WasmGuardError::ModuleTooLarge` when loading the guard.

### Pitfall 3: Python Lazy Imports Fail at Runtime

**What goes wrong:** Python code that does `import json` inside a function body
(rather than at module top level) may fail because componentize-py resolves
all imports at build time.
**Why it happens:** componentize-py snapshots the Python environment during
componentization. Dynamic imports are not supported.
**How to avoid:** All imports at the top of the module file. No conditional or
lazy imports.
**Warning signs:** `ImportError` or `ModuleNotFoundError` at WASM runtime.

### Pitfall 4: wit-bindgen-go Version Mismatch with TinyGo

**What goes wrong:** Generated Go bindings are incompatible with TinyGo's WASM
output, causing link errors or runtime panics.
**Why it happens:** wit-bindgen-go and TinyGo evolve independently. The `cm`
package's memory representation may conflict with TinyGo's GC.
**How to avoid:** Pin compatible versions. TinyGo 0.40.x works with
go.bytecodealliance.org v0.7.x. Test after any version bump.
**Warning signs:** Compilation succeeds but component fails to instantiate in
wasmtime with type or link errors.

### Pitfall 5: wasi-virt Output Still Has Residual WASI Imports

**What goes wrong:** After wasi-virt, the component still imports some WASI
interfaces that the host cannot satisfy.
**Why it happens:** wasi-virt may not cover all WASI interfaces used by TinyGo.
**How to avoid:** After wasi-virt, inspect with `wasm-tools component wit` to
verify the output component's imports. It should have zero imports (matching
the `arc:guard/guard` world).
**Warning signs:** `ComponentBackend` instantiation fails with missing import
errors.

### Pitfall 6: Go Module Path Mismatch

**What goes wrong:** `go tool wit-bindgen-go generate` produces bindings with
import paths that don't match the module's `go.mod` path.
**Why it happens:** wit-bindgen-go infers package paths from the module name.
**How to avoid:** Set `--package-root` flag when generating, or ensure
`go.mod` module path matches what wit-bindgen-go expects.
**Warning signs:** `go build` fails with "package not found" for generated code.

## Code Examples

### Python Build Script (scripts/build-guard.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Generating types from WIT..."
componentize-py -d ../../../wit/arc-guard -w guard bindings .

echo "==> Compiling example guard to WASM component..."
componentize-py \
    -d ../../../wit/arc-guard \
    -w guard \
    componentize \
    --stub-wasi \
    examples/tool-gate/guard \
    -o dist/tool-gate.wasm

echo "==> Done. Output: dist/tool-gate.wasm"
ls -lh dist/tool-gate.wasm
```

### Go Build Script (scripts/build-guard.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Resolving WIT dependencies..."
wkg wit build -d wit/ -o dist/arc-guard-go.wasm

echo "==> Generating Go bindings..."
go tool wit-bindgen-go generate \
    --world guard \
    --out internal \
    dist/arc-guard-go.wasm

echo "==> Compiling with TinyGo..."
tinygo build \
    -target=wasip2 \
    -no-debug \
    --wit-package dist/arc-guard-go.wasm \
    --wit-world guard \
    -o dist/tool-gate-raw.wasm \
    examples/tool-gate/main.go

echo "==> Stripping WASI imports with wasi-virt..."
wasi-virt dist/tool-gate-raw.wasm -o dist/tool-gate.wasm

echo "==> Verifying component exports..."
wasm-tools component wit dist/tool-gate.wasm

echo "==> Done. Output: dist/tool-gate.wasm"
ls -lh dist/tool-gate.wasm
```

### Python pyproject.toml

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "arc-guard-py"
version = "0.1.0"
description = "Python SDK for writing ARC guard components compiled to WASM"
requires-python = ">=3.11"
license = "Apache-2.0"
# No runtime dependencies -- componentize-py is a build-time tool only
```

### Go go.mod

```
module github.com/backbay-labs/arc/packages/sdk/arc-guard-go

go 1.24

tool go.bytecodealliance.org/cmd/wit-bindgen-go
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Raw core-WASM ABI (evaluate ptr/len -> i32) | WIT Component Model (evaluate GuardRequest -> Verdict) | Phase 386 (2026-04) | Type-safe cross-language bindings; no manual JSON serde |
| Manual JSON serialization in guest | Automatic canonical ABI via bindgen | Phase 386 | Zero manual ABI code in guest SDKs |
| wasm32-unknown-unknown target | wasm32-wasip2 / componentize | Phase 386 | Component Model format understood by host |
| Rust-only guards | TS (Phase 387) + Python + Go (this phase) | 2026-04 | Multi-language guard ecosystem |

**Deprecated/outdated:**
- Raw ABI guard SDK (`arc-guard-sdk` at `crates/arc-guard-sdk`): Still exists
  for `wasm32-unknown-unknown` Rust guards. Component Model SDKs are the
  forward path for multi-language support.

## WASI Handling Strategy (Critical Design Decision)

The ARC guard world (`arc:guard/guard@0.1.0`) has **zero imports**. The host
`ComponentBackend` uses an **empty linker**. This is by security design -- guard
functions are pure computations receiving a request and returning a verdict.

### Python (componentize-py)

componentize-py internally needs WASI (CPython's stdlib uses filesystem, clocks,
etc.), but the `--stub-wasi` flag provides internal stub implementations that
satisfy these needs without importing WASI from the host. The resulting component
exports only `evaluate` with no WASI imports. This works out of the box.

### Go (TinyGo)

TinyGo's wasip2 target **mandates** that the WIT world includes
`wasi:cli/imports@0.2.0`. There is no flag to disable this. Two approaches:

**Approach A (Recommended): wasi-virt post-processing**
1. Create `wit/guard-go.wit` that extends the ARC guard world with
   `include wasi:cli/imports@0.2.0`
2. Compile with TinyGo targeting this extended world
3. Run `wasi-virt` on the output to satisfy/strip WASI imports
4. Verify with `wasm-tools component wit` that the result has zero imports

**Approach B (Not recommended): Host-side WASI**
1. Add `wasmtime-wasi` dependency to `arc-wasm-guards` crate
2. Populate the linker with stub WASI implementations
3. This breaks the zero-import security model and adds complexity

**Approach A is strongly recommended.** It keeps the host pure and moves the
WASI satisfaction to build time rather than runtime.

### Expected Binary Sizes

| Language | Expected Size | Module Limit Needed | Reason |
|----------|--------------|--------------------|----|
| TypeScript (existing) | ~11 MiB | 15 MiB | Embeds SpiderMonkey JS engine |
| Python | ~10-35 MiB | 40 MiB | Bundles CPython interpreter + wasi-libc |
| Go | ~500 KiB - 2 MiB | 10 MiB (default) | TinyGo runtime is lightweight; -no-debug reduces further |
| Rust (existing) | ~50-150 KiB | 10 MiB (default) | Native WASM, no interpreter embedded |

## Open Questions

1. **Exact componentize-py binary size with --stub-wasi on a pure-function world**
   - What we know: General range is 10-35 MiB; --stub-wasi stubs but doesn't eliminate CPython internals
   - What's unclear: Exact size for a minimal guard with no stdlib dependencies
   - Recommendation: Build and measure during implementation. Set module limit to 40 MiB initially, tighten after measurement.

2. **wasi-virt completeness for TinyGo output**
   - What we know: wasi-virt can strip WASI imports by providing virtualized stubs
   - What's unclear: Whether TinyGo's specific WASI usage (random, clocks, env) is fully covered by wasi-virt's default deny-all mode
   - Recommendation: Test early. If wasi-virt cannot fully strip imports, the fallback is adding minimal wasmtime-wasi to the host.

3. **wit-bindgen-go type naming for variant types**
   - What we know: WIT `variant verdict { allow, deny(string) }` maps to Go types
   - What's unclear: Exact generated Go type names and constructors (e.g., VerdictAllow() vs verdict_allow())
   - Recommendation: Generate bindings first, then adapt example code to match actual generated types.

## Sources

### Primary (HIGH confidence)
- `wit/arc-guard/world.wit` -- canonical WIT definition, read directly
- `packages/sdk/arc-guard-ts/` -- TS SDK pattern (Phase 387), read directly
- `crates/arc-wasm-guards/src/component.rs` -- ComponentBackend host code, read directly
- `crates/arc-wasm-guards/tests/ts_guard_integration.rs` -- integration test pattern, read directly
- `docs/guards/02-WASM-RUNTIME-LANDSCAPE.md` -- toolchain research doc, read directly

### Secondary (MEDIUM confidence)
- [componentize-py GitHub](https://github.com/bytecodealliance/componentize-py) -- official repo, CLI commands and --stub-wasi flag
- [Python Component Model docs](https://component-model.bytecodealliance.org/language-support/building-a-simple-component/python.html) -- Bytecode Alliance official guide
- [Go Component Model docs](https://component-model.bytecodealliance.org/language-support/building-a-simple-component/go.html) -- Bytecode Alliance official guide
- [TinyGo releases](https://github.com/tinygo-org/tinygo/releases) -- version 0.40.1, wasip2 support since 0.33.0
- [go.bytecodealliance.org](https://github.com/bytecodealliance/go-modules) -- wit-bindgen-go v0.7.0
- [WASI-Virt](https://github.com/bytecodealliance/WASI-Virt) -- WASI import virtualization/stripping tool
- [TinyGo custom world issue #4843](https://github.com/tinygo-org/tinygo/issues/4843) -- confirmed wasi:cli/imports requirement

### Tertiary (LOW confidence)
- Binary size estimates for componentize-py (10-35 MiB range from community reports, not officially benchmarked for pure-function worlds)
- wasi-virt completeness for TinyGo output (inferred from tool documentation, not tested against this specific use case)

## Metadata

**Confidence breakdown:**
- Standard stack: MEDIUM - tools are correct and verified, but version pinning
  and compatibility between TinyGo/wit-bindgen-go may need runtime validation
- Architecture: HIGH - pattern established by TS SDK, directly observed in codebase
- Pitfalls: MEDIUM - TinyGo WASI requirement confirmed via issue tracker;
  wasi-virt solution is the documented approach but untested in this specific context
- Binary sizes: LOW - ranges from multiple sources but no first-hand measurements

**Research date:** 2026-04-14
**Valid until:** 2026-05-14 (stable toolchains, but TinyGo releases frequently)
