# chio-guard-sdk

Guest types, host-import wrappers, and memory glue for Rust WASM guards.
The SDK carries tool context into a guard and encodes its allow or deny
verdict for `chio-wasm-guards`. The host kernel owns capability admission
and receipt signing.

## Usage

Evaluate a deserialized request without a WASM runtime:

```rust
use chio_guard_sdk::{encode_verdict, GuardRequest, GuardVerdict, VERDICT_DENY};

let request: GuardRequest = serde_json::from_str(r#"{
    "tool_name": "delete_file",
    "server_id": "files",
    "agent_id": "agent-1",
    "arguments": {"path": "/workspace/report.txt"}
}"#)?;
let verdict = if request.tool_name == "delete_file" {
    GuardVerdict::deny("deletion is blocked")
} else {
    GuardVerdict::allow()
};
assert_eq!(encode_verdict(verdict), VERDICT_DENY);
# Ok::<(), serde_json::Error>(())
```

For a guest module, compile a `cdylib` for `wasm32-unknown-unknown`.
Wire its `evaluate(ptr, len)` export manually or use
[`chio-guard-sdk-macros`](../chio-guard-sdk-macros/README.md).
The host must provide the imports used by the guard and valid memory regions.
Native host wrappers supply test fallbacks: logging does nothing, config
returns `None`, time returns zero, and blob reads return an error.

## Guarantees

- `GuardVerdict::deny` and `encode_verdict` trim denial reasons and replace
  whitespace-only reasons with `guard denied request`.
- `read_request` rejects nonpositive pointers and negative lengths before
  reading. Its unsafe contract still requires a live, readable memory region.
- `chio_deny_reason` returns `-1` for absent reasons, invalid signed bounds,
  serialization failure, or insufficient capacity. Positive bounds must
  describe a valid writable region supplied by the host.
- `chio_free` releases only a tracked allocation matching both pointer and
  size. Unmatched frees leave tracked allocations untouched.

## Status

The guest ABI and native test fallbacks are implemented. The crate declares
no Cargo features and is unpublished (`publish = false`). `PolicyContext`
reads through a host handle; `close` consumes the wrapper without a host
destructor call. Host runtimes must reclaim the bundle resource.
Native tests exercise JSON and verdict logic; use the WASM host tests to
exercise guest execution and imports.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [WASM host](../../guards/chio-wasm-guards/README.md)
- [Tool-gate example](../../../examples/guards/tool-gate/src/lib.rs)

Licensed under [Apache-2.0](../../../LICENSE).
