# Phase 387: TypeScript Guard SDK - Research

**Researched:** 2026-04-14
**Domain:** jco/ComponentizeJS toolchain, WIT-to-TypeScript type generation, TS-to-WASM component compilation
**Confidence:** HIGH

## Summary

The TypeScript guard SDK (`packages/sdk/arc-guard-ts`) uses the Bytecode Alliance `jco` toolchain to generate TypeScript types from the existing `wit/arc-guard/world.wit` definition and compile TypeScript guard implementations into WASM components. The host already has full dual-mode support: `create_backend()` in `arc-wasm-guards` auto-detects Component Model binaries via `wasmparser::Parser::is_component()` and routes them to `ComponentBackend`, which uses `wasmtime::component::bindgen!`-generated bindings. No host-side changes are needed.

The build pipeline is: (1) `jco types` generates `.d.ts` from WIT, (2) guard author implements the exported `evaluate` function in TypeScript using generated types, (3) a bundler (esbuild) compiles TS to a single ESM JS file, (4) `jco componentize` wraps the JS into a WASM component embedding the StarlingMonkey/SpiderMonkey engine. The resulting `.wasm` file is a Component Model binary (~5-12 MiB due to the embedded JS engine) that the host loads via `ComponentBackend` with zero special handling.

**Primary recommendation:** Use `jco types` for WIT-to-TS generation, `esbuild` for TS-to-JS bundling, and `jco componentize` with `--disable all` for JS-to-WASM compilation. Package at `packages/sdk/arc-guard-ts/` following the existing `packages/sdk/arc-ts/` patterns.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
All implementation choices are at Claude's discretion -- pure infrastructure phase.

### Claude's Discretion
- Package at packages/sdk/arc-guard-ts/
- Types generated from WIT definition (arc:guard@0.1.0) via jco
- TypeScript guard compiles to WASM component via jco componentize
- Example guard with build instructions (zero to .wasm in under 5 commands)
- Compiled guard loads and evaluates correctly in host dual-mode runtime
- Types must match WIT contract, not be hand-maintained

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TSDK-01 | TypeScript guard SDK provides typed GuardRequest and GuardVerdict interfaces matching WIT contract | `jco types` generates `.d.ts` from `wit/arc-guard/world.wit`; WIT record/variant types map to TS interfaces with tag/val pattern for variants |
| TSDK-02 | TypeScript guards compile to WASM components via jco/ComponentizeJS | `jco componentize` with `--wit` and `--world-name guard` produces Component Model .wasm; StarlingMonkey embeds SpiderMonkey engine |
| TSDK-03 | TypeScript SDK includes example guard with build instructions | Example guard follows pattern from Rust `examples/guards/tool-gate/`; build pipeline: types -> bundle -> componentize in npm scripts |
| TSDK-04 | TypeScript-compiled guard loads and evaluates correctly in host dual-mode runtime | `create_backend()` auto-detects Component format via `wasmparser::Parser::is_component()` and routes to `ComponentBackend` which uses `bindgen!` |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `@bytecodealliance/jco` | 1.17.6 | CLI for WIT type gen + componentize | Official Bytecode Alliance JS/WASM Component toolchain |
| `@bytecodealliance/componentize-js` | 0.20.0 | JS-to-WASM component compilation engine | Required by `jco componentize` (dynamically imported) |
| `esbuild` | 0.28.0 | Bundle TypeScript to single ESM JS file | Fast, zero-config TS bundling; industry standard |
| `typescript` | ~5.7.0 | Type checking (matches existing arc-ts) | Project standard per `packages/sdk/arc-ts/package.json` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `@types/node` | ^22.0.0 | Node.js type definitions | Only if build scripts need Node types; matches arc-ts |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| esbuild | rolldown | rolldown is at 1.0.0-rc.15 (not yet stable); esbuild is proven and simpler |
| esbuild | tsc | tsc does not bundle to a single file; jco needs one ESM entry point |
| esbuild | rollup | heavier, slower; esbuild is sufficient for single-file bundling |

**Installation:**
```bash
npm install --save-dev @bytecodealliance/jco @bytecodealliance/componentize-js esbuild typescript
```

**Version verification:** Verified 2026-04-14 via `npm view`:
- `@bytecodealliance/jco`: 1.17.6 (latest)
- `@bytecodealliance/componentize-js`: 0.20.0 (latest)
- `esbuild`: 0.28.0 (latest)

## Architecture Patterns

### Recommended Project Structure
```
packages/sdk/arc-guard-ts/
  package.json              # SDK package with build scripts
  tsconfig.json             # TypeScript config (matches arc-ts patterns)
  README.md                 # Guard authoring guide
  src/
    types/                  # jco-generated .d.ts from WIT (gitignored or committed)
      guard.d.ts            # Generated: GuardRequest, Verdict, evaluate export
    index.ts                # Re-exports generated types + convenience helpers
  examples/
    tool-gate/
      guard.ts              # Example guard implementation
      build.sh              # Zero-to-wasm build script
  scripts/
    generate-types.sh       # Runs jco types from WIT
    build-example.sh        # Full pipeline: types -> bundle -> componentize
```

### Pattern 1: WIT-to-TypeScript Type Generation
**What:** `jco types` reads the WIT definition and generates TypeScript type declarations.
**When to use:** Whenever the WIT definition changes; run as a pre-build step.
**Example:**
```bash
# Source: jco CLI documentation
npx jco types \
  --world-name guard \
  --out-dir ./src/types \
  ../../wit/arc-guard
```

This generates `.d.ts` files from `wit/arc-guard/world.wit`. The WIT types map to TypeScript as follows:

| WIT Type | TypeScript |
|----------|-----------|
| `record guard-request { ... }` | `interface GuardRequest { toolName: string; serverId: string; ... }` |
| `variant verdict { allow, deny(string) }` | `type Verdict = { tag: 'allow' } \| { tag: 'deny'; val: string }` |
| `option<string>` | `string \| undefined` |
| `option<u32>` | `number \| undefined` |
| `list<string>` | `string[]` |
| `func(request: guard-request) -> verdict` | `export function evaluate(request: GuardRequest): Verdict` |

**Note:** WIT uses kebab-case (`tool-name`, `server-id`) which jco converts to camelCase (`toolName`, `serverId`) in the generated TypeScript.

### Pattern 2: Guard Implementation
**What:** Guard author implements the `evaluate` export using generated types.
**When to use:** This is the developer-facing API.
**Example:**
```typescript
// examples/tool-gate/guard.ts
// Source: adapted from WIT contract and jco type generation patterns

// Import types generated by jco from the WIT definition
import type { GuardRequest, Verdict } from '../../src/types/guard';

// The evaluate function is the guard entry point.
// It receives a request and returns a verdict.
export function evaluate(request: GuardRequest): Verdict {
  const blocked = ['dangerous_tool', 'rm_rf', 'drop_database'];
  if (blocked.includes(request.toolName)) {
    return { tag: 'deny', val: 'tool is blocked by policy' };
  }
  return { tag: 'allow' };
}
```

### Pattern 3: Build Pipeline (TS -> JS -> WASM Component)
**What:** Three-step compilation from TypeScript to a WASM component.
**When to use:** Every time a guard is built for deployment.
**Example:**
```bash
# Step 1: Generate types from WIT (only if WIT changed)
npx jco types --world-name guard --out-dir ./src/types ../../wit/arc-guard

# Step 2: Bundle TypeScript to a single ESM JavaScript file
npx esbuild examples/tool-gate/guard.ts \
  --bundle --format=esm --outfile=dist/tool-gate.js

# Step 3: Componentize the JS into a WASM component
npx jco componentize dist/tool-gate.js \
  --wit ../../wit/arc-guard \
  --world-name guard \
  --out dist/tool-gate.wasm \
  --disable all
```

The `--disable all` flag removes all WASI capabilities (stdio, random, clocks, http, fetch-event), creating a minimal pure-computation component. Guards should have zero ambient authority.

### Pattern 4: Host Integration (already working)
**What:** The host auto-detects and loads Component Model .wasm files.
**When to use:** No new code needed -- existing `create_backend()` handles this.
**Example (Rust host side -- already exists):**
```rust
// Source: crates/arc-wasm-guards/src/runtime.rs lines 399-419
pub fn create_backend(
    engine: Arc<Engine>,
    wasm_bytes: &[u8],
    fuel_limit: u64,
    config: HashMap<String, String>,
) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError> {
    let format = detect_wasm_format(wasm_bytes)?;
    match format {
        WasmFormat::CoreModule => { /* WasmtimeBackend */ }
        WasmFormat::Component => {
            let mut backend = ComponentBackend::with_engine(engine);
            backend.load_module(wasm_bytes, fuel_limit)?;
            Ok(Box::new(backend))
        }
    }
}
```

The `ComponentBackend` uses `wasmtime::component::bindgen!` with the same `wit/arc-guard` path, ensuring type compatibility between host and guest.

### Anti-Patterns to Avoid
- **Hand-maintaining TypeScript types:** Types MUST be generated from WIT via `jco types`. Hand-written types will drift from the WIT contract and cause runtime failures.
- **Bundling with tsc alone:** `tsc` does not produce a single-file bundle. `jco componentize` expects a single ESM entry point. Always use a bundler (esbuild) between tsc and componentize.
- **Skipping `--disable all`:** Without disabling WASI features, the component will import WASI interfaces that the ARC host does not provide (the guard world has no imports). This causes instantiation failure.
- **Committing generated types to git without a rebuild script:** If the WIT changes and someone forgets to regenerate, types silently drift. Prefer generating in the build pipeline.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| WIT-to-TS types | Manual `interface GuardRequest { ... }` | `jco types --world-name guard` | WIT has 11 fields with option/list types; manual maintenance is error-prone and drifts |
| TS-to-WASM compilation | Custom compilation scripts | `jco componentize` | Embeds StarlingMonkey engine, handles Component Model encoding, canonical ABI |
| JS bundling | Manual concatenation or tsc output | `esbuild --bundle --format=esm` | Resolves imports, tree-shakes, produces single ESM file in <100ms |
| Component format detection | Magic byte parsing | `wasmparser::Parser::is_component()` | Already implemented in host `detect_wasm_format()` |

**Key insight:** The entire TS-to-WASM pipeline is handled by the Bytecode Alliance jco/ComponentizeJS toolchain. The only custom code needed is the guard implementation itself and the npm package scaffolding.

## Common Pitfalls

### Pitfall 1: jco componentize Requires a Single ESM Entry Point
**What goes wrong:** Passing a TypeScript file or multi-file JS project to `jco componentize` fails.
**Why it happens:** ComponentizeJS expects a single JavaScript ES module file, not TypeScript or a directory of files.
**How to avoid:** Always bundle with esbuild first: `esbuild guard.ts --bundle --format=esm --outfile=guard.js`, then componentize the bundled JS.
**Warning signs:** Error messages about module resolution or unexpected tokens.

### Pitfall 2: WIT Kebab-Case to TS CamelCase Conversion
**What goes wrong:** Guard author writes `request.tool_name` (snake_case, matching Rust) but the WIT-generated types use `request.toolName` (camelCase).
**Why it happens:** WIT uses kebab-case (`tool-name`, `server-id`), which jco converts to camelCase in TypeScript. The Rust SDK uses snake_case. These are different conventions.
**How to avoid:** Always import and use the jco-generated types. Document the field name mapping prominently in the README.
**Warning signs:** TypeScript type errors on field access, or runtime `undefined` when accessing wrong field names.

### Pitfall 3: Large Binary Size (~5-12 MiB)
**What goes wrong:** The WASM component is much larger than Rust guards (~50 KiB), causing slow load times.
**Why it happens:** ComponentizeJS embeds the StarlingMonkey (SpiderMonkey-based) JS engine into every component. This is ~8 MiB of engine overhead.
**How to avoid:** This is inherent to the approach and documented in the landscape doc. Pre-compile and cache the module (the host's `Engine` + `Module` caching already handles this). Set appropriate `max_module_size` on `ComponentBackend` (current default is 10 MiB, may need bumping to 15 MiB).
**Warning signs:** `WasmGuardError::ModuleTooLarge` if default 10 MiB limit is hit.

### Pitfall 4: WASI Imports Without Host Support
**What goes wrong:** Component fails to instantiate with "unknown import" errors.
**Why it happens:** Without `--disable all`, ComponentizeJS includes WASI imports (wasi:cli, wasi:io, wasi:random, etc.) that the ARC guard host does not provide. The guard world has no imports.
**How to avoid:** Always use `--disable all` (or `--disable stdio --disable random --disable clocks --disable http --disable fetch-event`) when componentizing guards.
**Warning signs:** Instantiation errors mentioning `wasi:cli`, `wasi:io`, or `wasi:random` imports.

### Pitfall 5: ComponentBackend max_module_size Default May Be Too Low
**What goes wrong:** Loading a TS-compiled guard fails with `ModuleTooLarge`.
**Why it happens:** `ComponentBackend::with_engine()` defaults to `max_module_size: 10 * 1024 * 1024` (10 MiB). TS-compiled components can be 5-12 MiB. Components near or above 10 MiB will be rejected.
**How to avoid:** Either (a) accept 10 MiB as the limit and ensure `--disable all` keeps size under that, or (b) use `ComponentBackend::with_limits()` to raise the cap for known TS guards, or (c) raise the default to 15 MiB.
**Warning signs:** TS guard loads fail but Rust guards with same WIT succeed.

## Code Examples

### Expected Generated Types (from jco types)
```typescript
// src/types/guard.d.ts -- generated by: jco types --world-name guard ../../wit/arc-guard
// Source: WIT type mapping rules from jco documentation

export interface GuardRequest {
  toolName: string;
  serverId: string;
  agentId: string;
  arguments: string;
  scopes: string[];
  actionType: string | undefined;
  extractedPath: string | undefined;
  extractedTarget: string | undefined;
  filesystemRoots: string[];
  matchedGrantIndex: number | undefined;
}

export type Verdict = { tag: 'allow' } | { tag: 'deny'; val: string };

export function evaluate(request: GuardRequest): Verdict;
```

### Example Guard Implementation
```typescript
// examples/tool-gate/guard.ts
import type { GuardRequest, Verdict } from '../../src/types/guard';

export function evaluate(request: GuardRequest): Verdict {
  const blockedTools = ['dangerous_tool', 'rm_rf', 'drop_database'];

  if (blockedTools.includes(request.toolName)) {
    return { tag: 'deny', val: `tool '${request.toolName}' is blocked by policy` };
  }

  return { tag: 'allow' };
}
```

### package.json Build Scripts
```json
{
  "name": "@arc-protocol/guard-ts",
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "generate-types": "jco types --world-name guard --out-dir ./src/types ../../wit/arc-guard",
    "build:example": "npm run generate-types && esbuild examples/tool-gate/guard.ts --bundle --format=esm --outfile=dist/tool-gate.js && jco componentize dist/tool-gate.js --wit ../../wit/arc-guard --world-name guard --out dist/tool-gate.wasm --disable all",
    "typecheck": "tsc --noEmit"
  },
  "devDependencies": {
    "@bytecodealliance/jco": "^1.17.6",
    "@bytecodealliance/componentize-js": "^0.20.0",
    "esbuild": "^0.28.0",
    "typescript": "~5.7.0"
  }
}
```

### Rust Integration Test Pattern (for TSDK-04)
```rust
// Extends existing crates/arc-wasm-guards/tests/example_guard_integration.rs pattern
// Source: existing test pattern in the codebase

fn load_ts_example_wasm() -> Vec<u8> {
    let path = format!(
        "{}/../../packages/sdk/arc-guard-ts/dist/tool-gate.wasm",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!("Missing TS guard .wasm at {path}: {e}. Build with: \
               cd packages/sdk/arc-guard-ts && npm run build:example")
    })
}

// Then use create_backend() which auto-detects Component format
// and routes to ComponentBackend
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Raw ABI only (evaluate ptr/len) | Dual-mode: raw ABI + Component Model | Phase 386 (2026-04) | TS guards compile as components, host auto-detects |
| AssemblyScript for TS-to-WASM | jco/ComponentizeJS (full JS via StarlingMonkey) | 2024-2025 | Standard TypeScript works, not a subset language |
| Manual type authoring per language | WIT + language-specific bindgen | 2024+ | Single WIT definition generates types for all SDKs |
| `jco componentize` experimental | jco 1.17.6 stable enough for production components | 2025-2026 | Still marked experimental but widely used |

**Deprecated/outdated:**
- AssemblyScript: The landscape doc mentions it as "Raw ABI only" with no Component Model support. Not recommended.
- Manual JSON ABI: The raw `evaluate(ptr, len) -> i32` approach still works via `WasmtimeBackend` but Component Model is preferred for new SDKs.

## Open Questions

1. **Exact generated type output from jco types**
   - What we know: jco types generates `.d.ts` files from WIT; WIT kebab-case becomes TS camelCase; variant maps to tagged union.
   - What's unclear: The exact file names and export structure generated by `jco types` for the `arc:guard@0.1.0` world. Need to run the command to see actual output.
   - Recommendation: Run `jco types` in Wave 0 and inspect output before writing example guard. Adjust imports accordingly.

2. **ComponentizeJS binary size with --disable all**
   - What we know: Without disabling, ~5-12 MiB. With full disable, should be smaller but still includes the SpiderMonkey engine core.
   - What's unclear: Exact size with `--disable all` for a trivial guard.
   - Recommendation: Build the example guard early and check size. If >10 MiB, bump `ComponentBackend::with_limits()` or default.

3. **jco guest-types vs jco types**
   - What we know: Both generate TS types from WIT. `guest-types` is marked experimental and seems targeted specifically at guest-side (component authoring) types.
   - What's unclear: Whether `guest-types` generates the correct export signatures for implementing a WIT world vs `types` which may generate import-side signatures.
   - Recommendation: Try `jco types` first (documented workflow). If types do not match export expectations, try `jco guest-types`.

## Sources

### Primary (HIGH confidence)
- `wit/arc-guard/world.wit` -- actual WIT definition (11 fields, variant verdict)
- `crates/arc-wasm-guards/src/component.rs` -- ComponentBackend with `bindgen!` using same WIT
- `crates/arc-wasm-guards/src/runtime.rs` -- `create_backend()` dual-mode factory, `detect_wasm_format()`
- `crates/arc-wasm-guards/src/lib.rs` -- dual-mode documentation
- `crates/arc-guard-sdk/src/types.rs` -- Rust SDK types for reference
- `examples/guards/tool-gate/src/lib.rs` -- Rust example guard pattern
- `crates/arc-wasm-guards/tests/example_guard_integration.rs` -- Rust integration test pattern
- `packages/sdk/arc-ts/package.json` -- existing TS SDK package patterns (Node >=22, TS ~5.7.0)
- npm registry: `@bytecodealliance/jco` 1.17.6, `@bytecodealliance/componentize-js` 0.20.0

### Secondary (MEDIUM confidence)
- [jco example workflow](https://bytecodealliance.github.io/jco/example.html) -- official Bytecode Alliance docs
- [jco WIT type representations](https://bytecodealliance.github.io/jco/wit-type-representations.html) -- WIT-to-TS mapping rules
- [ComponentizeJS GitHub](https://github.com/bytecodealliance/ComponentizeJS) -- StarlingMonkey embedding, ~8 MiB size, API
- [Component Model JS guide](https://component-model.bytecodealliance.org/language-support/building-a-simple-component/javascript.html) -- jco componentize flags, TS requires tsc first
- [TypeScript component workflow (dev.to)](https://dev.to/topheman/webassembly-component-model-writing-components-in-typescript-with-jco-183j) -- real-world TS+jco workflow with rolldown

### Tertiary (LOW confidence)
- `docs/guards/02-WASM-RUNTIME-LANDSCAPE.md` Section 4.4 -- jco overview from research phase (general, not prescriptive)
- `docs/guards/03-IMPLEMENTATION-PLAN.md` Phase 4 -- long-range plan for non-Rust SDKs (directional only)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- npm versions verified, jco/ComponentizeJS are the canonical Bytecode Alliance toolchain, no viable alternative
- Architecture: HIGH -- host dual-mode support already exists and tested; pipeline is well-documented
- Pitfalls: HIGH -- binary size, WASI imports, and kebab-to-camelCase conversion are documented in official sources and landscape doc
- Generated types: MEDIUM -- WIT-to-TS mapping rules are documented but exact output for this specific WIT has not been verified by running the tool

**Research date:** 2026-04-14
**Valid until:** 2026-05-14 (jco releases monthly; pin versions in package.json)
