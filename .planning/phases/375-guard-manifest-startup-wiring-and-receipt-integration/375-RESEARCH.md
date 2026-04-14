# Phase 375: Guard Manifest, Startup Wiring, and Receipt Integration - Research

**Researched:** 2026-04-14
**Domain:** WASM guard manifest parsing, kernel startup pipeline wiring, receipt metadata integration
**Confidence:** HIGH

## Summary

Phase 375 bridges the gap between the WASM guard runtime (completed in Phases 373-374) and the kernel's guard pipeline and receipt system. It has three distinct sub-domains: (1) a guard manifest format (`guard-manifest.yaml`) with SHA-256 integrity verification and ABI version gating, (2) startup wiring that orchestrates HushSpec-compiled guards, priority-sorted WASM guards, and advisory guards into the correct pipeline order, and (3) receipt metadata enrichment that records fuel consumption and manifest SHA-256 for audit trails.

The codebase already provides all the necessary building blocks: `WasmHostState` carries config and log buffers (Phase 373), `WasmtimeBackend` tracks fuel limits and creates fresh Stores per call (Phase 374), `compile_policy()` in `arc-policy` produces HushSpec guard pipelines, `WasmGuardEntry` in `arc-config` defines the config schema for WASM guards, and `ArcReceipt` carries both `metadata: Option<serde_json::Value>` and `evidence: Vec<GuardEvidence>`. The primary implementation work is: (a) a new `manifest.rs` module in `arc-wasm-guards`, (b) a startup wiring function (likely in `arc-wasm-guards` or `arc-cli`) that composes the three pipeline tiers, and (c) extending `WasmGuard::evaluate()` to capture and surface fuel consumed and manifest hash.

**Primary recommendation:** Create `manifest.rs` for parsing/verification, extend `WasmGuard` to carry manifest hash and return fuel metadata, and add a public startup wiring function that enforces HushSpec-first/WASM-by-priority/advisory-last ordering.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
None -- all choices at Claude's discretion.

### Claude's Discretion
All implementation choices are at Claude's discretion -- pure infrastructure phase. Key constraints:

- guard-manifest.yaml format: name, version, abi_version, wasm_path, config, wasm_sha256
- SHA-256 verification of .wasm binary against declared hash at load time
- abi_version validation: reject unsupported versions
- Config values from manifest config block loaded into WasmHostState
- HushSpec-first pipeline order: compile_policy() guards -> WASM by priority -> advisory
- WasmGuardEntry sorted by priority field before loading (fix known gotcha)
- Fuel consumed and manifest SHA-256 in receipt metadata
- Use arc_policy::compiler::compile_policy() for HushSpec guards (not default_pipeline)

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| WGMAN-01 | Guard manifest format (guard-manifest.yaml) defines name, version, abi_version, wasm path, config schema, and wasm_sha256 | New `GuardManifest` struct in `manifest.rs` with serde deserialization from YAML |
| WGMAN-02 | Host verifies wasm_sha256 against actual .wasm binary at load time and rejects mismatches | `sha2` crate already in workspace; compute SHA-256 of wasm bytes and compare to declared hash |
| WGMAN-03 | Host validates abi_version from manifest and rejects unsupported versions | Const `SUPPORTED_ABI_VERSIONS` check before module loading |
| WGMAN-04 | Guard config values are loaded from manifest config block and made available via arc.get_config | Manifest `config: HashMap<String, String>` feeds into `WasmHostState::new(config)` |
| WGWIRE-01 | Startup code loads HushSpec-compiled guards via compile_policy() and registers them first | `arc_policy::compile_policy()` returns `CompiledPolicy { guards: GuardPipeline, default_scope }` |
| WGWIRE-02 | Startup code sorts WasmGuardEntry list by priority field before loading | `entries.sort_by_key(|e| e.priority)` before calling load_guard for each |
| WGWIRE-03 | Startup code registers WASM guards after HushSpec guards and before advisory pipeline | Ordered composition in a wiring function |
| WGWIRE-04 | Startup code loads guard-manifest.yaml adjacent to each .wasm path and passes config to WasmHostState | Path resolution: replace `.wasm` extension with directory lookup for `guard-manifest.yaml` |
| WGRCPT-01 | When a WASM guard evaluates, fuel consumed is recorded and available for receipt metadata | Compute `fuel_limit - store.get_fuel()` after evaluate, store on WasmGuard |
| WGRCPT-02 | When a WASM guard evaluates, guard manifest SHA-256 hash is recorded and available for receipt metadata | Store manifest hash on WasmGuard, expose via method |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `sha2` | 0.10 (workspace) | SHA-256 hash of .wasm binary for integrity verification | Already used by 10+ crates in workspace |
| `serde_yml` | 0.0.12 (workspace) | Parse guard-manifest.yaml | Already used by arc-config, arc-policy, arc-cli |
| `serde` + `serde_json` | 1 (workspace) | Struct serialization, receipt metadata JSON | Standard workspace deps |
| `wasmtime` | 29 (optional, feature-gated) | WASM runtime backend | Already used by arc-wasm-guards |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `thiserror` | 1 (workspace) | Error type derivation | New error variants for manifest failures |
| `tracing` | 0.1 (workspace) | Structured logging for manifest loading | Already in arc-wasm-guards |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `serde_yml` | `serde_yaml` | `serde_yaml` is deprecated; workspace already migrated to `serde_yml` |
| Inline SHA-256 | External checksum file | guard-manifest.yaml already carries hash; separate file adds complexity |

**Installation:**
```bash
# No new dependencies needed -- sha2 and serde_yml already in workspace
# Just add to arc-wasm-guards/Cargo.toml:
sha2 = { workspace = true }
serde_yml = { workspace = true }
```

## Architecture Patterns

### New Files
```
crates/arc-wasm-guards/
  src/
    manifest.rs     # NEW: GuardManifest struct, parse, verify, load
    runtime.rs      # MODIFY: WasmGuard gains manifest_hash + fuel tracking
    host.rs         # EXISTING (unchanged)
    abi.rs          # EXISTING (unchanged)
    config.rs       # EXISTING (unchanged)
    error.rs        # MODIFY: New manifest-related error variants
    lib.rs          # MODIFY: pub mod manifest
```

### Pattern 1: Guard Manifest Structure
**What:** A `GuardManifest` struct that deserializes from `guard-manifest.yaml`.
**When to use:** Every time a WASM guard is loaded from disk.
**Example:**
```rust
// crates/arc-wasm-guards/src/manifest.rs
use std::collections::HashMap;
use serde::Deserialize;

/// Supported ABI versions. Currently only v1.
pub const SUPPORTED_ABI_VERSIONS: &[&str] = &["1"];

/// Guard manifest parsed from guard-manifest.yaml.
#[derive(Debug, Clone, Deserialize)]
pub struct GuardManifest {
    /// Human-readable guard name.
    pub name: String,
    /// Semantic version of the guard.
    pub version: String,
    /// ABI version this guard targets (must be in SUPPORTED_ABI_VERSIONS).
    pub abi_version: String,
    /// Path to the .wasm binary (relative to manifest location or absolute).
    pub wasm_path: String,
    /// SHA-256 hex digest of the .wasm binary for integrity verification.
    pub wasm_sha256: String,
    /// Guard-specific configuration passed to the guest via arc.get_config.
    #[serde(default)]
    pub config: HashMap<String, String>,
}
```

### Pattern 2: Manifest-Aware Guard Loading
**What:** Load manifest adjacent to .wasm path, verify SHA-256, validate ABI, pass config.
**When to use:** In the startup wiring function when processing each `WasmGuardEntry`.
**Example:**
```rust
/// Load and verify a guard manifest adjacent to a .wasm path.
///
/// Given path "/etc/arc/guards/pii_guard.wasm", looks for
/// "/etc/arc/guards/guard-manifest.yaml".
pub fn load_manifest(wasm_path: &str) -> Result<GuardManifest, WasmGuardError> {
    let parent = std::path::Path::new(wasm_path)
        .parent()
        .ok_or_else(|| /* error */)?;
    let manifest_path = parent.join("guard-manifest.yaml");
    let content = std::fs::read_to_string(&manifest_path)
        .map_err(|e| /* ModuleLoad error */)?;
    let manifest: GuardManifest = serde_yml::from_str(&content)
        .map_err(|e| /* ManifestParse error */)?;
    Ok(manifest)
}

/// Verify SHA-256 of wasm bytes against the manifest declaration.
pub fn verify_wasm_hash(wasm_bytes: &[u8], expected_hex: &str) -> Result<(), WasmGuardError> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(wasm_bytes);
    let actual_hex = hex::encode(hasher.finalize());
    if actual_hex != expected_hex {
        return Err(WasmGuardError::HashMismatch { expected, actual });
    }
    Ok(())
}
```

### Pattern 3: Fuel Consumption Tracking
**What:** After WASM evaluate() call, compute fuel consumed and store it on the WasmGuard.
**When to use:** Every evaluate() call in `WasmtimeBackend`.
**Critical insight:** The `WasmGuardAbi` trait currently returns `Result<GuardVerdict, WasmGuardError>`. To carry fuel metadata back, extend the return type or add a side-channel. The cleanest approach is an `EvaluationResult` struct that wraps the verdict plus optional metadata (fuel consumed).
**Example:**
```rust
/// Result of a WASM guard evaluation with optional metadata.
pub struct EvaluationResult {
    pub verdict: GuardVerdict,
    /// Fuel consumed during this evaluation (fuel_limit - remaining_fuel).
    pub fuel_consumed: Option<u64>,
}
```

However, changing the `WasmGuardAbi` trait signature is a breaking change. The alternative (and the v1 approach per the decision doc) is to store metadata on the `WasmtimeBackend` itself after each evaluate() call and expose it via a getter. Since the backend is behind a `Mutex<Box<dyn WasmGuardAbi>>` in `WasmGuard`, the guard can read the metadata after the evaluate lock is released.

**Recommended approach:** Add a `last_fuel_consumed() -> Option<u64>` method to `WasmGuardAbi` trait (with a default returning `None`), and implement it on `WasmtimeBackend` to track fuel after each call. The `WasmGuard::evaluate()` method can then read this and propagate it.

### Pattern 4: Startup Wiring Function
**What:** A public function that composes the full guard pipeline in the correct order.
**When to use:** At kernel startup in the CLI/proxy.
**Example:**
```rust
/// Build the complete guard pipeline: HushSpec first, then WASM by priority,
/// then advisory.
pub fn build_wasm_aware_pipeline(
    hushspec: &HushSpec,
    wasm_entries: &[WasmGuardEntry],
    engine: Arc<Engine>,
) -> Result<Vec<Box<dyn Guard>>, Box<dyn std::error::Error>> {
    let mut guards: Vec<Box<dyn Guard>> = Vec::new();

    // 1. HushSpec-compiled guards (native Rust, fast, catches the 80% case)
    let compiled = arc_policy::compile_policy(hushspec)?;
    guards.push(Box::new(compiled.guards));

    // 2. WASM guards sorted by priority
    let mut sorted_entries = wasm_entries.to_vec();
    sorted_entries.sort_by_key(|e| e.priority);
    
    for entry in &sorted_entries {
        let manifest = load_manifest(&entry.path)?;
        verify_abi_version(&manifest.abi_version)?;
        let wasm_bytes = std::fs::read(&entry.path)?;
        verify_wasm_hash(&wasm_bytes, &manifest.wasm_sha256)?;
        
        let backend = WasmtimeBackend::with_engine_and_config(
            engine.clone(),
            manifest.config.clone(),
        );
        // ... load module, create WasmGuard with manifest hash
    }

    // 3. Advisory pipeline (always last)
    // ... advisory guards added here

    Ok(guards)
}
```

### Anti-Patterns to Avoid
- **Using `default_pipeline()` for HushSpec guards:** This creates guards with hard-coded defaults, ignoring the HushSpec policy. Always use `compile_policy()`.
- **Not sorting WASM entries externally:** `WasmGuardRuntime` does NOT sort by priority despite its doc-comment. Sort `WasmGuardEntry` by priority before loading.
- **Storing fuel metadata globally:** Fuel is per-invocation. Store it on the backend and read it after each evaluate() call before another call overwrites it.
- **Panicking in manifest parsing:** All parsing errors must be propagated as `WasmGuardError`, never panic. Clippy enforces `unwrap_used = "deny"`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| SHA-256 hashing | Manual digest implementation | `sha2` crate (workspace) | Audited crypto, already depended on by 10+ crates |
| YAML parsing | Manual string parsing | `serde_yml` (workspace) | Handles edge cases, schema validation, deny_unknown_fields |
| Hex encoding | Manual hex formatting | `hex` crate (workspace) | Consistent with rest of codebase |
| Canonical JSON for receipts | Custom serializer | `arc_core::crypto::canonical_json_bytes` | Already used by all receipt signing paths |

**Key insight:** Every library needed for this phase is already in the workspace. Zero new external dependencies are required (only adding existing workspace deps to `arc-wasm-guards/Cargo.toml`).

## Common Pitfalls

### Pitfall 1: WasmGuardEntry deny_unknown_fields
**What goes wrong:** Adding a `config` field to `WasmGuardEntry` in `arc-config/src/schema.rs` would be a natural choice but would break existing YAML that omits it.
**Why it happens:** `WasmGuardEntry` uses `#[serde(deny_unknown_fields)]` -- any new field must have `#[serde(default)]`.
**How to avoid:** For v1, config lives in `guard-manifest.yaml`, NOT in `WasmGuardEntry`. The schema change is deferred to v1.1 per `05-V1-DECISION.md`. Do not touch `WasmGuardEntry` in this phase.
**Warning signs:** If you find yourself adding fields to `WasmGuardEntry`, you are going off-spec.

### Pitfall 2: Fuel Tracking Across the Mutex Boundary
**What goes wrong:** `WasmGuard` wraps its backend in `Mutex<Box<dyn WasmGuardAbi>>`. If fuel is tracked inside the backend, you need to read it while still holding the lock.
**Why it happens:** The `evaluate()` method locks the mutex, calls `backend.evaluate()`, then needs the fuel data before releasing the lock.
**How to avoid:** Read fuel consumed from the backend (via a new trait method or backend-specific accessor) within the same lock scope, before the `MutexGuard` drops.
**Warning signs:** If fuel is always `None`, the read is happening after the lock releases.

### Pitfall 3: Manifest Path Resolution
**What goes wrong:** Assuming `guard-manifest.yaml` is always in the same directory as the `.wasm` file.
**Why it happens:** The manifest's `wasm_path` field could be a different relative or absolute path.
**How to avoid:** The design decision (doc 05, Section 4) says: "The loader looks for `guard-manifest.yaml` adjacent to the `.wasm` file". The manifest `wasm_path` field is informational metadata, not used for loading -- the `WasmGuardEntry.path` in `arc.yaml` is the authoritative path to the wasm binary. The manifest is always looked up relative to the wasm binary's parent directory.
**Warning signs:** If manifest loading fails with "file not found", check the path resolution logic.

### Pitfall 4: Clippy Strictness
**What goes wrong:** Using `unwrap()` or `expect()` anywhere outside `#[cfg(test)]`.
**Why it happens:** Natural Rust idiom conflicts with the crate's lint configuration.
**How to avoid:** All error handling must use `?`, `map_err()`, or `ok_or_else()`. The crate already has `#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]` in `lib.rs` -- tests can use unwrap, production code cannot.
**Warning signs:** Clippy errors on CI.

### Pitfall 5: Receipt Metadata Is Optional serde_json::Value
**What goes wrong:** Trying to create a typed metadata struct for WASM guard receipt data.
**Why it happens:** `ArcReceipt.metadata` is `Option<serde_json::Value>`, and the kernel uses `merge_metadata_objects` to compose metadata from different sources.
**How to avoid:** WASM guard fuel and manifest hash should be injected as JSON into the existing `metadata` field via the kernel's merge pattern. The `GuardEvidence` struct (per-guard in `evidence: Vec<GuardEvidence>`) can carry the guard name and verdict, while `metadata` carries the WASM-specific fuel/hash data. Key question: does this go in `evidence` or `metadata`? Given that `evidence` only has `guard_name`, `verdict: bool`, and `details: Option<String>`, the WASM-specific data (fuel_consumed, manifest_sha256) best fits in `metadata` as a "wasm_guards" key, or the `details` field of `GuardEvidence` as JSON.
**Warning signs:** If receipt metadata is getting overwritten instead of merged.

### Pitfall 6: Guard Trait Does Not Return Metadata
**What goes wrong:** The `Guard` trait's `evaluate()` returns `Result<Verdict, KernelError>` -- there is no channel for returning metadata like fuel consumed.
**Why it happens:** The trait was designed for simple allow/deny verdicts.
**How to avoid:** The requirement says fuel/hash must be "available for receipt metadata", not necessarily injected by the kernel itself. Two options: (a) `WasmGuard` stores last-evaluation metadata in a `Mutex<Option<WasmGuardMetadata>>` field that the kernel can query after the guard runs, or (b) the receipt metadata is populated at the wiring layer, not at the kernel trait level. Option (a) is simpler and more encapsulated. The kernel's `run_guards` loop could be extended (or the wiring function can wrap the guard to collect metadata).

**Recommended approach for WGRCPT-01/02:** Add `fuel_consumed` and `manifest_sha256` fields to `WasmGuard` behind a `Mutex`, populate them during `evaluate()`, and expose them via public getters. A future phase or the planner can decide whether the kernel's `run_guards` queries these or if a wrapper guard collects them.

## Code Examples

### Manifest File Format (guard-manifest.yaml)
```yaml
# Source: docs/guards/05-V1-DECISION.md Section 4, Section 6
name: pii-guard
version: "1.2.0"
abi_version: "1"
wasm_path: pii_guard.wasm
wasm_sha256: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
config:
  region: us-east-1
  sensitivity: high
```

### SHA-256 Verification
```rust
// Source: sha2 crate API (workspace dep)
use sha2::{Sha256, Digest};

pub fn compute_wasm_sha256(wasm_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(wasm_bytes);
    hex::encode(hasher.finalize())
}
```

### Fuel Consumption After Evaluate
```rust
// Source: wasmtime Store::get_fuel() API, existing runtime.rs pattern
// Inside WasmtimeBackend::evaluate(), after evaluate_fn.call():
let remaining = store.get_fuel().unwrap_or(0);
let consumed = self.fuel_limit.saturating_sub(remaining);
self.last_fuel_consumed = Some(consumed);
```

### Priority Sorting of WASM Entries
```rust
// Source: docs/guards/04-HUSHSPEC-CLAWDSTRIKE-INTEGRATION.md Section 1
// CRITICAL: WasmGuardRuntime does NOT sort. Sort externally.
let mut entries = config.wasm_guards.clone();
entries.sort_by_key(|e| e.priority);
```

### Manifest-Adjacent Path Resolution
```rust
// Source: docs/guards/05-V1-DECISION.md Section 4
// Given: entry.path = "/etc/arc/guards/pii/pii_guard.wasm"
// Look for: "/etc/arc/guards/pii/guard-manifest.yaml"
let wasm_path = std::path::Path::new(&entry.path);
let manifest_path = wasm_path
    .parent()
    .map(|p| p.join("guard-manifest.yaml"))
    .ok_or_else(|| WasmGuardError::ManifestLoad {
        path: entry.path.clone(),
        reason: "no parent directory".to_string(),
    })?;
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Store<()> per backend | Store<WasmHostState> per invocation | Phase 373 | Enables config + log buffer in guest |
| Per-backend Engine | Shared Arc<Engine> | Phase 373 | Reduces compilation overhead |
| Raw GuardRequest (5 fields) | Enriched GuardRequest (10 fields) | Phase 374 | Guests get pre-extracted action context |
| No security enforcement | ResourceLimiter + import validation + module size cap | Phase 374 | Fail-closed security boundaries |
| No manifest format | guard-manifest.yaml (this phase) | Phase 375 | Integrity-verified guard loading |
| No pipeline ordering | HushSpec-first explicit ordering (this phase) | Phase 375 | Correctness + performance |

**Deprecated/outdated:**
- `GuardPipeline::default_pipeline()`: Creates guards with hard-coded defaults. Use `compile_policy()` instead.
- `session_metadata` field on GuardRequest: Removed in Phase 374.
- `serde_yaml`: Deprecated; workspace uses `serde_yml` 0.0.12.

## Open Questions

1. **Receipt metadata injection mechanism**
   - What we know: `ArcReceipt.metadata` is `Option<serde_json::Value>` composed via `merge_metadata_objects`. The kernel's `run_guards()` loop does not collect per-guard metadata today. `GuardEvidence` has `guard_name`, `verdict`, `details` fields.
   - What's unclear: Whether fuel/hash should go in `GuardEvidence.details` as JSON, in the top-level `metadata` as a "wasm_guards" key, or via a new mechanism. The `Guard` trait returns only `Verdict`.
   - Recommendation: For v1, make fuel and manifest hash "available" on the `WasmGuard` struct via public getters. The actual injection into receipts can use `GuardEvidence.details` (JSON-encoded fuel + hash) for the guard that runs. The kernel can be extended to collect evidence from guards that implement an optional `evidence()` method, but that can be a separate concern. The requirement says "available for receipt metadata", not "automatically injected into receipts".

2. **Where the startup wiring function lives**
   - What we know: `arc-cli/src/policy.rs` has `build_guard_pipeline()` and `load_hushspec_policy()`. The `LoadedPolicy` struct has a `guard_pipeline: GuardPipeline` field.
   - What's unclear: Whether to extend `arc-cli/src/policy.rs` or create a standalone wiring module in `arc-wasm-guards`.
   - Recommendation: Add the WASM-aware pipeline composition to `arc-wasm-guards` as a public `wiring` module (keeps all WASM guard logic in one crate). The CLI's `LoadedPolicy` path can call into this module. This avoids making `arc-cli` depend on wasmtime.

3. **Advisory pipeline identity**
   - What we know: The design says advisory guards go last. But there is no explicit `AdvisoryPipeline` type in the codebase today. Individual guards can be marked `advisory: true` on `WasmGuardConfig`.
   - What's unclear: What "advisory pipeline" means concretely in the current code.
   - Recommendation: For v1, advisory WASM guards are simply loaded after non-advisory WASM guards (both sorted by priority). There is no separate advisory pipeline to compose -- advisory-ness is handled per-guard in `WasmGuard::evaluate()` which returns `Allow` on deny when `self.advisory` is true.

## Sources

### Primary (HIGH confidence)
- `docs/guards/05-V1-DECISION.md` -- Authoritative design document for v1 WASM guard scope, ABI, manifest format, pipeline ordering, receipt integration
- `docs/guards/04-HUSHSPEC-CLAWDSTRIKE-INTEGRATION.md` -- HushSpec integration patterns, pipeline ordering rationale, receipt audit integration
- `crates/arc-wasm-guards/src/runtime.rs` -- Current WasmtimeBackend implementation with fuel tracking, evaluate() flow
- `crates/arc-wasm-guards/src/host.rs` -- WasmHostState with config HashMap, host function registration
- `crates/arc-policy/src/compiler.rs` -- compile_policy() producing CompiledPolicy { guards, default_scope }
- `crates/arc-config/src/schema.rs` -- WasmGuardEntry with deny_unknown_fields
- `crates/arc-core-types/src/receipt.rs` -- ArcReceipt with metadata and evidence fields

### Secondary (MEDIUM confidence)
- Phase 373-01 and 374-01/02 summaries -- Confirm completed work and established patterns
- `crates/arc-cli/src/policy.rs` -- Existing guard pipeline construction patterns

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all dependencies already in workspace, verified in Cargo.toml
- Architecture: HIGH -- design authority document (05-V1-DECISION.md) is explicit about manifest format, pipeline ordering, and receipt integration
- Pitfalls: HIGH -- verified by reading actual source code (deny_unknown_fields, Guard trait signature, Mutex patterns, fuel tracking)

**Research date:** 2026-04-14
**Valid until:** 2026-05-14 (stable domain, no external API dependencies)
