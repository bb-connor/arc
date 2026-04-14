# Phase 376: Benchmark Validation - Research

**Researched:** 2026-04-14
**Domain:** WASM guard runtime performance benchmarking (Criterion + Wasmtime)
**Confidence:** HIGH

## Summary

Phase 376 is the final phase of v4.0 WASM Guard Runtime Completion. It validates
performance characteristics of the `arc-wasm-guards` crate's `WasmtimeBackend`
against thresholds defined in `docs/guards/05-V1-DECISION.md`: module compilation
under 50ms, per-call p99 latency under 5ms, quantified fuel metering overhead,
and verified ResourceLimiter memory caps.

The crate already has a proven pattern for Criterion benchmarks in `arc-core/benches/core_primitives.rs`:
Criterion 0.5.1 with `criterion_group!` / `criterion_main!` macros, `[[bench]]`
entries in Cargo.toml with `harness = false`. The `WasmtimeBackend` is behind
the `wasmtime-runtime` feature flag, so the bench entry in Cargo.toml must use
`required-features = ["wasmtime-runtime"]`. WAT inline modules are the
established pattern for self-contained WASM test fixtures in this crate (used
extensively in `runtime.rs` tests and `host.rs` tests).

All five requirement benchmarks (WGBENCH-01 through WGBENCH-05) can be
implemented using inline WAT modules of varying complexity -- no external `.wasm`
binaries are needed. For WGBENCH-04 (fuel overhead), a second Engine with
`consume_fuel(false)` is needed alongside the standard fuel-enabled Engine. For
WGBENCH-05 (ResourceLimiter), the benchmark is really a correctness assertion
that runs adversarial `memory.grow` and verifies the trap occurs.

**Primary recommendation:** Single benchmark file `crates/arc-wasm-guards/benches/wasm_guard_perf.rs` using Criterion 0.5 with benchmark groups, WAT inline modules, and `required-features = ["wasmtime-runtime"]` in the Cargo.toml `[[bench]]` entry.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key constraints from docs/guards/05-V1-DECISION.md:

- Module compilation threshold: 50ms for representative guard sizes
- Per-call p99 latency threshold: 5ms
- Benchmark representative sizes: 50 KiB Rust guard, 5 MiB large module
- Fuel metering overhead: quantify percentage (fuel-enabled vs disabled)
- ResourceLimiter: validate under adversarial guest allocation patterns
- Use Criterion for benchmarks (already in workspace)
- Document results with pass/fail verdicts

### Claude's Discretion
All implementation choices (WAT module design, benchmark group structure,
threshold assertion approach, file organization).

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| WGBENCH-01 | Benchmark measures Module::new() compilation time for representative .wasm guard binaries (50 KiB Rust, 5 MiB large) | WAT modules with data segments / nop-padding to reach target sizes; Criterion bench_function with iter_batched for per-iteration fresh compilation |
| WGBENCH-02 | Benchmark measures Linker::instantiate() per-call overhead | Pre-compiled Module reused; Criterion bench measures only instantiate() call per iteration using iter_batched |
| WGBENCH-03 | Benchmark measures p50/p99 evaluate latency for trivial guard (immediate Allow) and realistic guard (JSON parse + pattern match + Deny) | Two WAT modules: trivial (return 0) and realistic (byte scanning + conditional deny); Criterion reports median and percentile stats in JSON output |
| WGBENCH-04 | Benchmark measures fuel metering overhead percentage (fuel enabled vs disabled) | Two Engines: one with consume_fuel(true), one with consume_fuel(false); same WAT module evaluated on both; percentage computed from Criterion results |
| WGBENCH-05 | Benchmark verifies ResourceLimiter actually caps memory growth under adversarial guest allocation | WAT module with loop calling memory.grow; assert trap occurs; this is a correctness benchmark, not a latency benchmark |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| criterion | 0.5.1 | Statistical benchmarking | Already used by arc-core; workspace dependency |
| wasmtime | 29.0.1 | WASM runtime | Already the project's WASM engine |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| serde_json | workspace | Serialize GuardRequest for evaluate benchmarks | WGBENCH-02, WGBENCH-03 |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Criterion | divan or pbench | Criterion is already in workspace; switching would add a dep for no benefit. pbench offers p50/p99 directly but Criterion's JSON output gives the same data |
| WAT inline | Pre-compiled .wasm files | WAT keeps benchmarks self-contained; no external binary management |

**Installation:**
```bash
# No new deps needed -- criterion is already a workspace dependency
# Just add it to arc-wasm-guards/Cargo.toml [dev-dependencies]
```

## Architecture Patterns

### Recommended Project Structure
```
crates/arc-wasm-guards/
  Cargo.toml               # Add [[bench]] entry + criterion dev-dep
  benches/
    wasm_guard_perf.rs      # Single file with all 5 benchmark groups
```

### Pattern 1: Feature-Gated Benchmark Entry
**What:** The `[[bench]]` entry in Cargo.toml uses `required-features` to gate on the wasmtime backend.
**When to use:** Always -- WasmtimeBackend is behind `wasmtime-runtime` feature.
**Example:**
```toml
# Source: arc-core/Cargo.toml pattern
[[bench]]
name = "wasm_guard_perf"
harness = false
required-features = ["wasmtime-runtime"]
```

### Pattern 2: Criterion Benchmark Groups
**What:** Group related benchmarks into named groups for organized output.
**When to use:** When measuring multiple related operations (compilation, instantiation, evaluation).
**Example:**
```rust
// Source: arc-core/benches/core_primitives.rs pattern
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_module_compilation(c: &mut Criterion) {
    let mut group = c.benchmark_group("wasm_guards/compilation");
    group.bench_function("50kib_module", |b| {
        b.iter(|| {
            black_box(Module::new(&engine, black_box(&wat_bytes)));
        });
    });
    group.finish();
}
```

### Pattern 3: iter_batched for Fresh-State Benchmarks
**What:** Use `iter_batched` when each iteration needs fresh state (e.g., fresh Store per evaluate call).
**When to use:** WGBENCH-02 (fresh instantiate per call), WGBENCH-03 (fresh evaluate per call).
**Example:**
```rust
b.iter_batched(
    || {
        // Setup: create fresh store + linker each iteration (matches production path)
        let host_state = WasmHostState::new(HashMap::new());
        let mut store = Store::new(&engine, host_state);
        store.limiter(|s| &mut s.limits);
        store.set_fuel(10_000_000).ok();
        let mut linker = Linker::new(&engine);
        register_host_functions(&mut linker).ok();
        (store, linker)
    },
    |(mut store, linker)| {
        // Measured: instantiate + evaluate
        let instance = linker.instantiate(&mut store, &module).unwrap();
        // ... call evaluate ...
    },
    criterion::BatchSize::SmallInput,
);
```

### Pattern 4: WAT Modules with Controlled Size
**What:** Generate WAT modules of specific sizes using data segments and nop padding.
**When to use:** WGBENCH-01 (50 KiB and 5 MiB modules).
**Example:**
```rust
// ~50 KiB module: use a data segment with ~50K of zeroed bytes
fn build_sized_wat(target_bytes: usize) -> String {
    // Each data byte in WAT "(data (i32.const 0) \"\\00\")" is ~1 byte of module
    // Use a large data segment to reach the target size
    let padding_size = target_bytes.saturating_sub(200); // subtract WAT overhead
    let padding = "\\00".repeat(padding_size);
    format!(r#"
        (module
            (import "arc" "log" (func $log (param i32 i32 i32)))
            (import "arc" "get_config" (func $gc (param i32 i32 i32 i32) (result i32)))
            (import "arc" "get_time_unix_secs" (func $gt (result i64)))
            (memory (export "memory") {pages})
            (data (i32.const 0) "{padding}")
            (func (export "evaluate") (param i32 i32) (result i32)
                (i32.const 0)
            )
        )
    "#, pages = (target_bytes / 65536) + 1)
}
```

**Important:** WAT text format compiles to a binary `.wasm` that may differ in size from the WAT text length. For accurate sizing, compile the WAT to bytes first and verify the binary size, then adjust padding. Alternatively, generate raw `.wasm` bytes programmatically using `wat::parse_str()` and check `wasm_bytes.len()`.

### Pattern 5: Fuel-Disabled Engine for Overhead Comparison
**What:** Create a second Engine with `consume_fuel(false)` for WGBENCH-04.
**When to use:** Measuring fuel metering overhead percentage.
**Example:**
```rust
fn create_no_fuel_engine() -> Arc<Engine> {
    // Default Config has consume_fuel = false
    let config = wasmtime::Config::new();
    let engine = Engine::new(&config).unwrap();
    Arc::new(engine)
}

fn create_fuel_engine() -> Arc<Engine> {
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).unwrap();
    Arc::new(engine)
}
```

### Anti-Patterns to Avoid
- **Reusing Store across iterations:** Each evaluate() call MUST create a fresh Store (matches production behavior and gives accurate per-call measurements).
- **Including Module::new() in evaluate benchmarks:** Pre-compile the module once; measure only the per-call path (instantiate + evaluate) for WGBENCH-02 and WGBENCH-03.
- **Using unwrap()/expect():** The crate has `clippy::unwrap_used = "deny"` and `clippy::expect_used = "deny"`. The benchmark file is `#[cfg(test)]`-adjacent but benchmarks are NOT test code -- they compile as a separate binary. Use `.ok()` with fallback or handle errors explicitly in benchmark setup, OR allow the lint at the crate level for benchmarks via `#![cfg_attr(not(test), allow(clippy::unwrap_used, clippy::expect_used))]` at the top of the bench file.
- **Forgetting to import all three host functions:** WAT modules that import any `arc.*` function must import all three (`arc.log`, `arc.get_config`, `arc.get_time_unix_secs`) because `register_host_functions()` registers all three on the Linker, and the module must match.

**CRITICAL CLIPPY NOTE:** Benchmark binaries are NOT compiled under `#[cfg(test)]`, so the `#![cfg_attr(test, allow(...))]` in `lib.rs` does NOT apply. The bench file needs its own lint suppression: `#![allow(clippy::unwrap_used, clippy::expect_used)]` at the file top. This is the same approach used by the `arc-core` benchmarks (which also use `.unwrap()` freely).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Statistical benchmarking | Manual timing loops | Criterion 0.5 | Handles warm-up, outlier detection, statistical significance |
| WAT-to-WASM compilation | Manual binary construction | `wasmtime::Module::new()` accepts WAT text directly | Wasmtime's Module::new() handles both WAT and binary WASM |
| p50/p99 extraction | Custom percentile calculation | Criterion JSON output + manual review | Criterion stores raw measurements; `--output-format=verbose` shows percentiles |
| Module size control | Manual wasm binary builder | WAT data segments with `\00` padding | WAT data segments embed arbitrary bytes into the module |

**Key insight:** Criterion handles all the statistical rigor. The benchmark code only needs to set up the right WAT fixtures and measure the right code paths. Don't build custom timing infrastructure.

## Common Pitfalls

### Pitfall 1: WAT vs Binary Size Mismatch
**What goes wrong:** A WAT module with 50 KiB of text does not produce a 50 KiB binary module. The binary encoding is more compact for some constructs and less compact for others (data segments are similar size, but instruction encoding differs).
**Why it happens:** WAT is text format; WASM is binary format. They are not 1:1 in size.
**How to avoid:** After constructing the WAT, compile it with `Module::new()` and check `wasm_bytes.len()` (or use `wat::parse_str()` to get the binary). Adjust padding until the binary reaches the target size. Alternatively, accept approximate sizes -- the decision record says "representative," not exact.
**Warning signs:** Benchmark results showing compilation times far below or above expectations for the stated module size.

### Pitfall 2: Clippy Lint Failures in Benchmark Binary
**What goes wrong:** `cargo bench --features wasmtime-runtime` fails with clippy errors about `unwrap_used` / `expect_used` in the benchmark file.
**Why it happens:** Benchmark binaries are separate executables, not test code. The `#![cfg_attr(test, allow(...))]` in `lib.rs` does not apply.
**How to avoid:** Add `#![allow(clippy::unwrap_used, clippy::expect_used)]` at the top of the bench file.
**Warning signs:** CI failures on `cargo clippy --workspace` that only appear after adding the benchmark.

### Pitfall 3: Fuel Not Set on No-Fuel Engine Store
**What goes wrong:** For WGBENCH-04, the no-fuel-engine path must NOT call `store.set_fuel()` because fuel is not enabled on that engine. Calling `set_fuel()` on a store whose engine has `consume_fuel = false` returns an error.
**Why it happens:** The `set_fuel()` method checks whether fuel is enabled.
**How to avoid:** Conditionally skip `store.set_fuel()` when benchmarking with fuel disabled. The no-fuel path simply omits the call entirely.
**Warning signs:** `Err` from `store.set_fuel()` in benchmark setup.

### Pitfall 4: Including Host Function Registration in Measured Code
**What goes wrong:** If `register_host_functions()` and `Linker::new()` are included in the measured loop, the benchmark measures Linker setup overhead, not just instantiation/evaluation overhead.
**Why it happens:** Production code creates a fresh Linker per call (line 509 of `runtime.rs`). If benchmarks want to isolate instantiation, they should pre-build the linker.
**How to avoid:** For WGBENCH-02 (pure instantiation), pre-create the Linker with host functions in the setup closure. For WGBENCH-03 (full evaluate latency), include Linker creation in the measured path since that matches the actual production code path.
**Warning signs:** Instantiation benchmarks showing higher-than-expected times because Linker setup is included.

### Pitfall 5: ResourceLimiter Benchmark Not Asserting Trap
**What goes wrong:** WGBENCH-05 runs the adversarial allocation but doesn't verify the trap actually occurred -- the benchmark "passes" even if ResourceLimiter is broken.
**Why it happens:** Criterion benchmarks normally measure latency, not correctness. WGBENCH-05 is a correctness assertion disguised as a benchmark.
**How to avoid:** Use a Criterion benchmark that runs the adversarial module and asserts the error path (trap). The benchmark measures how fast the ResourceLimiter detects and traps the violation. Alternatively, implement WGBENCH-05 as a `#[test]` alongside the benchmarks and reference it in the benchmark report.
**Warning signs:** WGBENCH-05 showing "Allow" verdict instead of a trap/deny.

### Pitfall 6: WAT Modules Missing Required Imports
**What goes wrong:** WAT module compiles but `linker.instantiate()` fails because the module declares imports that don't match what the linker provides, or vice versa.
**Why it happens:** `register_host_functions()` registers all three `arc.*` functions. If a WAT module imports only `arc.log`, the linker works fine (extra registered functions are ignored). But if the module imports something NOT registered, instantiation fails.
**How to avoid:** WAT modules should import only functions from the `arc` namespace. For trivial benchmarks that don't need host functions, don't import any. The linker only fails if the module declares an import that the linker can't satisfy.
**Warning signs:** "unknown import" errors during instantiation.

## Code Examples

Verified patterns from official sources and existing codebase:

### WAT: Trivial Allow Guard (WGBENCH-03 trivial)
```wat
;; Source: pattern from arc-wasm-guards/src/runtime.rs tests
(module
    (import "arc" "log" (func $log (param i32 i32 i32)))
    (import "arc" "get_config" (func $gc (param i32 i32 i32 i32) (result i32)))
    (import "arc" "get_time_unix_secs" (func $gt (result i64)))
    (memory (export "memory") 1)
    (func (export "evaluate") (param i32 i32) (result i32)
        (i32.const 0) ;; VERDICT_ALLOW
    )
)
```

### WAT: Realistic Pattern-Matching Deny Guard (WGBENCH-03 realistic)
```wat
;; Scans input bytes for a pattern and denies if found
(module
    (import "arc" "log" (func $log (param i32 i32 i32)))
    (import "arc" "get_config" (func $gc (param i32 i32 i32 i32) (result i32)))
    (import "arc" "get_time_unix_secs" (func $gt (result i64)))
    (memory (export "memory") 2)
    (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
        (local $i i32)
        (local $found i32)
        ;; Scan input bytes looking for '{' (0x7B) as proxy for JSON parsing
        (local.set $i (local.get $ptr))
        (block $done
            (loop $scan
                (br_if $done (i32.ge_u (local.get $i)
                    (i32.add (local.get $ptr) (local.get $len))))
                ;; Load byte and check for pattern
                (if (i32.eq (i32.load8_u (local.get $i)) (i32.const 0x7B))
                    (then (local.set $found (i32.const 1)))
                )
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $scan)
            )
        )
        ;; Return DENY (1) if pattern found, ALLOW (0) otherwise
        (local.get $found)
    )
)
```

### WAT: Adversarial Memory Growth (WGBENCH-05)
```wat
;; Attempts to grow memory until ResourceLimiter traps
(module
    (import "arc" "log" (func $log (param i32 i32 i32)))
    (import "arc" "get_config" (func $gc (param i32 i32 i32 i32) (result i32)))
    (import "arc" "get_time_unix_secs" (func $gt (result i64)))
    (memory (export "memory") 1) ;; starts at 1 page = 64 KiB
    (func (export "evaluate") (param i32 i32) (result i32)
        (local $i i32)
        ;; Try to grow memory 1024 pages at a time (64 MiB each attempt)
        ;; With ResourceLimiter set to 16 MiB, this should trap
        (block $done
            (loop $grow
                (br_if $done (i32.ge_u (local.get $i) (i32.const 100)))
                (drop (memory.grow (i32.const 1024)))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $grow)
            )
        )
        (i32.const 0)
    )
)
```
Note: With `trap_on_grow_failure(true)` set in `WasmHostState`, the first `memory.grow` that exceeds the limit will trap, causing `evaluate` to return an error. The benchmark should assert that the error occurs.

### Benchmark Skeleton: Compilation Timing (WGBENCH-01)
```rust
fn bench_module_compilation(c: &mut Criterion) {
    let engine = create_shared_engine().unwrap();
    let small_wat = build_small_guard_wat(); // ~50 KiB binary target
    let large_wat = build_large_guard_wat(); // ~5 MiB binary target

    let mut group = c.benchmark_group("wasm_guards/compilation");
    group.bench_function("50kib_module", |b| {
        b.iter(|| {
            let _ = black_box(Module::new(black_box(&engine), black_box(small_wat.as_bytes())));
        });
    });
    group.bench_function("5mib_module", |b| {
        // Increase measurement time for slow compilations
        b.iter(|| {
            let _ = black_box(Module::new(black_box(&engine), black_box(large_wat.as_bytes())));
        });
    });
    group.finish();
}
```

### Benchmark Skeleton: Fuel Overhead Comparison (WGBENCH-04)
```rust
fn bench_fuel_overhead(c: &mut Criterion) {
    let fuel_engine = create_shared_engine().unwrap(); // consume_fuel(true)
    let no_fuel_engine = {
        let config = wasmtime::Config::new(); // consume_fuel defaults to false
        Arc::new(Engine::new(&config).unwrap())
    };

    let wat = /* representative guard WAT */;

    let fuel_module = Module::new(&fuel_engine, wat.as_bytes()).unwrap();
    let no_fuel_module = Module::new(&no_fuel_engine, wat.as_bytes()).unwrap();

    let mut group = c.benchmark_group("wasm_guards/fuel_overhead");
    group.bench_function("fuel_enabled", |b| {
        b.iter_batched(
            || make_store_with_fuel(&fuel_engine),
            |mut store| { /* instantiate + evaluate fuel_module */ },
            criterion::BatchSize::SmallInput,
        );
    });
    group.bench_function("fuel_disabled", |b| {
        b.iter_batched(
            || make_store_no_fuel(&no_fuel_engine),
            |mut store| { /* instantiate + evaluate no_fuel_module */ },
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| One Engine per WasmtimeBackend | Shared Arc&lt;Engine&gt; (Phase 373) | 2026-04-14 | Compilation cost amortized; Engine construction not in hot path |
| Store&lt;()&gt; | Store&lt;WasmHostState&gt; (Phase 373) | 2026-04-14 | Per-call overhead includes config clone + StoreLimits construction |
| No memory limits | ResourceLimiter with trap_on_grow_failure(true) (Phase 374) | 2026-04-14 | Each Store has a limiter; overhead is minimal per-grow-check |
| No fuel metering in receipts | Fuel consumed tracked per evaluate (Phase 375) | 2026-04-14 | store.get_fuel() called after evaluate; negligible overhead |

**Current production hot path per evaluate call:**
1. `WasmHostState::with_memory_limit(config.clone(), max_memory)` -- allocates HashMap + StoreLimits
2. `Store::new(&engine, host_state)` -- creates fresh Store
3. `store.limiter(|s| &mut s.limits)` -- sets limiter
4. `store.set_fuel(fuel_limit)` -- configures fuel
5. `Linker::new(&engine)` -- creates fresh Linker
6. `register_host_functions(&mut linker)` -- registers 3 host functions
7. `linker.instantiate(&mut store, module)` -- instantiates module
8. Serialize GuardRequest to JSON
9. Write request into guest memory (via arc_alloc or offset 0)
10. `evaluate_fn.call(&mut store, (ptr, len))` -- runs the guest
11. Read fuel consumed, read deny reason if needed

Steps 1-10 are all within the measured latency for WGBENCH-03.

## Open Questions

1. **Exact WAT binary sizes for 50 KiB / 5 MiB targets**
   - What we know: WAT data segments with `\00` padding produce roughly 1:1 binary size for the data payload. Module overhead (header, type section, import section, function section) adds ~200-500 bytes.
   - What's unclear: The exact padding needed to hit precisely 50 KiB and 5 MiB binary. May need iterative adjustment.
   - Recommendation: Build the WAT, compile it, check binary size, adjust. Accept approximate sizes (within 10%) -- the decision record says "representative," not exact.

2. **Criterion p50/p99 reporting format**
   - What we know: Criterion reports median (p50) and confidence intervals in its default text output. The `--output-format=verbose` flag and the JSON files in `target/criterion/` contain detailed statistics.
   - What's unclear: Whether Criterion directly reports p99 in its standard output.
   - Recommendation: Document the benchmark results from Criterion's output (which includes mean, median, and confidence intervals). For explicit p99, use `criterion-perf-events` or parse the raw JSON. Alternatively, simply note that Criterion's "high estimate" is a reasonable proxy for tail latency.

3. **5 MiB module compilation time**
   - What we know: The 50ms threshold in the decision record is for "representative guard sizes." A 5 MiB module (Python-via-componentize-py) is acknowledged as potentially slow.
   - What's unclear: Whether the 50ms threshold applies to the 5 MiB case or only the 50 KiB case.
   - Recommendation: Benchmark both. If 5 MiB exceeds 50ms, document the result and note it as expected for large modules. The threshold is primarily about the common-case 50 KiB Rust guard.

## Sources

### Primary (HIGH confidence)
- `crates/arc-core/benches/core_primitives.rs` -- existing Criterion 0.5 benchmark pattern in this workspace
- `crates/arc-core/Cargo.toml` -- `[[bench]]` entry format with `harness = false`
- `crates/arc-wasm-guards/src/runtime.rs` lines 371-648 -- WasmtimeBackend struct and evaluate() hot path
- `crates/arc-wasm-guards/src/host.rs` -- WasmHostState, create_shared_engine(), register_host_functions()
- `crates/arc-wasm-guards/Cargo.toml` -- feature flag `wasmtime-runtime = ["dep:wasmtime"]`
- `docs/guards/05-V1-DECISION.md` section 7 -- benchmark thresholds and validation scope
- Wasmtime 29.0.1 Config::consume_fuel API -- confirmed default is false, enabling adds instruction counting overhead

### Secondary (MEDIUM confidence)
- [Criterion BenchmarkGroup docs](https://docs.rs/criterion/latest/criterion/struct.BenchmarkGroup.html) -- measurement_time, sample_size configuration
- [Criterion BatchSize docs](https://docs.rs/criterion/latest/criterion/enum.BatchSize.html) -- SmallInput for per-iteration setup
- [Wasmtime Config docs](https://docs.wasmtime.dev/api/wasmtime/struct.Config.html) -- consume_fuel setting and overhead description

### Tertiary (LOW confidence)
- None -- all findings verified against codebase and official docs.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- Criterion 0.5.1 and Wasmtime 29.0.1 are already in use; versions verified via cargo tree
- Architecture: HIGH -- Pattern directly follows existing arc-core benchmark structure and established WAT test patterns
- Pitfalls: HIGH -- Identified from direct codebase analysis (feature flags, clippy lints, host function registration, ResourceLimiter behavior)

**Research date:** 2026-04-14
**Valid until:** 2026-05-14 (stable -- crate versions and patterns unlikely to change)
