# chio-config

Loads `chio.yaml` into typed runtime configuration. It connects operator
file settings to Chio kernel configuration and keeps adapter, edge, guard,
receipt, and telemetry declarations together.

## Usage

Parse a configuration and lower its kernel settings without opening the
declared upstream or creating a receipt store. `generate` creates a fresh
signing key when `to_kernel_config` resolves the key.

```rust
use chio_config::load_from_str;

let config = load_from_str(r#"
kernel:
  signing_key: generate
adapters:
  - id: catalog
    protocol: openapi
    upstream: http://localhost:8000
"#)?;
assert_eq!(config.adapters[0].id, "catalog");
assert_eq!(config.receipts.checkpoint_interval, 100);
let kernel = config.to_kernel_config()?;
assert!(!kernel.allow_ephemeral_receipt_log);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Enabled | Empty feature set. |
| `fuzz` | Disabled | Enables `fuzz` and the optional `arbitrary` dependency. |

## Guarantees

`load_from_str` performs loader-safe environment interpolation, rejects YAML
syntax tabs, deserializes strict schema structs, and calls
`validation::validate`. Validation checks required adapters, duplicate IDs,
edge references, auth blocks, logging settings, and selected deadline
bounds.

`ChioConfig::to_kernel_config` carries receipt checkpoint/retention settings
and scalar deadlines into `chio_kernel::KernelConfig`. It disables ephemeral
receipt and revocation stores. Hex signing seeds are parsed during lowering,
after YAML loading.

## Status

Implemented configuration loader and kernel conversion. Callers still
construct adapters, wire durable stores, and configure programmatic kernel
settings. `load_from_file` reads the entire file before validation; this API
supplies no byte limit.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [chio-http-core](../chio-http-core/README.md)
- [License](../../../LICENSE)
