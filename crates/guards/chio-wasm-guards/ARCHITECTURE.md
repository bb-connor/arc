# chio-wasm-guards architecture

## Responsibility and boundary

The crate owns WebAssembly guest execution and its adapter to `chio_kernel::Guard`.
`WasmGuardAbi` defines loading and evaluation; `WasmGuard` supplies kernel request
conversion, blocking/advisory behavior, module epochs, and evaluation metadata.
`WasmGuardRuntime` collects guards, while `load_wasm_guards` and
`build_guard_pipeline` connect configured guards to the native pipeline.
The kernel retains capability-token validation, dispatch, and receipt signing.

`create_backend` routes core modules and components by binary format.
`load_signed_guard` adds manifest checks and detached Ed25519 signature policy.
`load_guards_from_policy` is a separate core-module loading path with declared
host-function capabilities and an operator allowlist. Callers select the loading
surface and supply trust configuration explicitly.

## Structure

- `abi`, `config`, `error`, and `manifest` define requests, limits, errors,
  manifest validation, and the `.wasm.sig` signature envelope.
- `runtime/backend`, `runtime/guard`, and `runtime/module` own guard collections,
  kernel adaptation, loaded snapshots, and serialized backend access.
- `runtime/wasmtime_backend` implements core execution and policy loading.
- `component` maps WIT requests/verdicts; `host` registers core and WIT imports.
- `bundle_store` supplies bounded opaque bundle access to component guests.
- `hot_reload`, `epoch`, `blocklist`, and `incident` own reload publication,
  provenance, digest rejection, and incident output.
- `metrics` and `observability` expose counters, bounded labels, and tracing spans.
- `input` performs bounded reads and strict document decoding;
  `placeholders` resolves operator configuration values.

## Data and control flow

`load_signed_guard` reads bounded module bytes, validates the declared WIT world
for both core modules and components, checks signing policy and module hash,
then delegates format detection and backend construction to `create_backend`.
Direct callers must invoke `manifest::verify_abi_version` when they require
manifest ABI validation. The signing message has a fixed domain separator and
newline-separated hash, name, version, and signer key fields.
It is a dedicated byte envelope, separate from canonical JSON payload signing.

`load_wasm_guards` loads the manifest (including its declared WIT-world check),
then explicitly validates the ABI version before reading module bytes with
`std::fs::read`. It checks the hash and signing policy and constructs a core
backend. The backend enforces its byte limit after this unbounded file read.

Core evaluation serializes `GuardRequest` to JSON in guest memory and invokes
`evaluate(ptr, len)`. Component evaluation converts the request to generated WIT
types and maps the resulting verdict. Both paths create invocation stores,
install fuel, and apply host memory limits. `WasmGuard::evaluate` captures a
loaded snapshot and records the epoch, module hash, and consumed fuel.

Reload publication swaps an `Arc<LoadedModule>` through `ArcSwap` and invalidates
the prior preinstantiation cache. Completed evaluation evidence retains its
producing module identity across reload. Canary and watchdog APIs support
candidate checking and restoration of the preceding snapshot.

## Trust and invariants

Core imports must use the `chio` namespace; linking supplies the known host
functions. Policy loading also requires every declared capability in the
operator allowlist and checks imports against those declarations. Empty declared
capabilities are permitted. This policy path constructs `WasmtimeBackend` and
should be used with core modules.

The component linker provides the WIT host surface without installing WASI.
Configuration, logging, time, and bundle access follow the implemented host APIs.
Memory defaults to 16 MiB per linear memory, module size to 10 MiB, and config
fuel to 10,000,000 units. Fuel measures Wasmtime consumption rather than elapsed
time. `with_limits` changes backend byte limits; the host traps failed memory
growth and bounds logs and bundle reads.

Signature verification defaults to requiring a pinned signer. Explicit unsigned
loading is available when no signer pin exists. A signature authenticates bytes
and identity; the guest still runs under execution limits. Blocking guards deny
guest errors and deny verdicts. Advisory guards allow those outcomes. Malformed
host action extraction denies before guest evaluation even in advisory mode.

## Dependencies

Wasmtime and wasmparser provide execution, format handling, and generated WIT
bindings. Ed25519, SHA-256, and hex implement module authentication.
`chio-kernel` supplies guard interfaces; `chio-guards` extracts native actions.
`arc-swap` supports snapshot replacement, `notify` supports file reload triggers,
and Chio metrics plus tracing expose evaluation and reload observations.

## Verification

Run `cargo test -p chio-wasm-guards --lib` for host, runtime, manifest, and
configuration tests. `cargo test -p chio-wasm-guards --test escape` exercises
undeclared imports, fuel exhaustion, memory/table growth, recursion, reentry,
malformed components, and signed malicious fixtures.
Integration tests cover policy loading, reader boundaries, signing, reload races,
canary provenance, rollback, and evidence across reload.
Rust example tests automatically build guests and require the
`wasm32-unknown-unknown` target. Python and Go integrations require separately
built SDK artifacts and skip when absent. Python uses 40 MiB module and 64 MiB
memory limits. The benchmark targets measure guard evaluation and pool checkout;
their results depend on the selected host and fixtures.
