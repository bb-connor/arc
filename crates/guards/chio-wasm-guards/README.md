# chio-wasm-guards

Executes WebAssembly guards inside the Chio kernel guard pipeline.
Core modules use a JSON memory ABI; components use the
`chio:guard/guard@0.2.0` WIT contract. The crate owns guest execution,
signed module loading, reload state, and evaluation evidence.

## Usage

Load a small core module through the default Wasmtime backend:

```rust
use std::collections::HashMap;
use chio_wasm_guards::{create_backend, host::create_shared_engine};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wasm = wat::parse_str(r#"(module
        (memory (export "memory") 1)
        (func (export "evaluate") (param i32 i32) (result i32)
            i32.const 0))"#)?;
    let backend = create_backend(create_shared_engine()?, &wasm, 10_000,
                                 HashMap::new())?;
    assert_eq!(backend.backend_name(), "wasmtime");
    Ok(())
}
```

This repository example uses the existing `wat` dev dependency and default
features. It compiles an in-memory fixture without reading files or invoking
external services. Applications can pass their own compiled bytes.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Enables `wasmtime-runtime`. |
| `wasmtime-runtime` | Yes | Wasmtime core/component backends, host functions, policy loading, and pipeline wiring. |
| `tracing-opentelemetry` | No | Declares stable tracing spans for exporters configured by the embedding binary. |
| `test-support` | No | Exposes deterministic mock runtime support. |
| `fuzz` | No | Exposes fuzz entrypoints and enables Wasmtime plus generator dependencies. |

## Guarantees

- `create_backend` selects the core or component backend from the WASM format.
- `load_signed_guard` reads bounded module bytes and validates the declared WIT
  world for both core modules and components, signing policy, and module hash.
  Direct callers must invoke `manifest::verify_abi_version` for ABI validation.
  `load_wasm_guards` performs that ABI check separately when loading configuration.
  `verify_guard_signature` requires a pinned signer unless unsigned loading is
  explicitly enabled without a signer pin.
- `WasmtimeBackend` and `ComponentBackend` bound module bytes before compilation,
  meter evaluation fuel, and apply host memory limits. Defaults are 10 MiB of
  module bytes and 16 MiB per linear memory; configuration defaults to
  10,000,000 fuel units per invocation.
- `load_guards_from_policy` rejects requested host functions outside the operator
  allowlist and undeclared core-module imports. It constructs core backends.
- `WasmGuard::evaluate` denies guest errors for blocking guards. Advisory guards
  allow guest denials and execution errors; malformed host action arguments deny.

## Status

Core and component execution, signatures, hot reload, canary checks, and watchdog
rollback are implemented. Without default features the backend abstractions
remain available. Guest execution requires `wasmtime-runtime`.
Rust example integration tests build guests using `wasm32-unknown-unknown`.
Python and Go tests skip when their separately built artifacts are absent;
Python fixtures raise the default component limits for the embedded interpreter.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [Guard registry](../chio-guard-registry/README.md)
- [Guard SDK](../../sdk/chio-guard-sdk/README.md)

[License](../../../LICENSE)
