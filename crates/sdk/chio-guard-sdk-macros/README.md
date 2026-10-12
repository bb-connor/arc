# chio-guard-sdk-macros

`#[chio_guard]` generates the WASM entry point around a Rust guard function.
It checks the function's signature, connects request decoding to verdict
encoding, and re-exports the SDK's allocator and deny-reason functions.
It runs during compilation; guest runtime behavior comes from the SDK.

## Usage

Guard crates must depend on both `chio-guard-sdk` and
`chio-guard-sdk-macros`. Apply the attribute once in the guest module:

```rust
use chio_guard_sdk::{GuardRequest, GuardVerdict};
use chio_guard_sdk_macros::chio_guard;

#[chio_guard]
fn evaluate(request: GuardRequest) -> GuardVerdict {
    if request.tool_name == "delete_file" {
        GuardVerdict::deny("deletion is blocked")
    } else {
        GuardVerdict::allow()
    }
}

fn main() {
    // Invalid signed bounds are rejected before guest memory is read.
    assert_eq!(evaluate(0, -1), chio_guard_sdk::VERDICT_DENY);
}
```

Compile a guest `cdylib` for `wasm32-unknown-unknown`. A WASM host supplies
the request memory and invokes the generated `evaluate(i32, i32) -> i32`.
The [tool-gate example](../../../examples/guards/tool-gate/src/lib.rs)
shows a workspace consumer with both dependencies.

## Guarantees

- `validate_guard_fn` requires a function named `evaluate`, exactly one
  `GuardRequest` argument, and a `GuardVerdict` return type. It rejects
  async, const, unsafe, explicit ABI, generic, variadic, and receiver forms.
- `type_path_ends_with_ident` checks the final type-path identifier.
  Rust type checking resolves the actual SDK types in the expansion.
- The generated entry point returns `VERDICT_DENY` when `read_request`
  returns an error. It invokes user logic only after successful decoding.
  Valid positive pointer bounds remain the host's safety responsibility.

## Status

The attribute and signature validator are implemented, with no declared
Cargo features. The crate is unpublished (`publish = false`). Attribute
arguments are ignored. Decode failure returns the deny code directly;
it does not replace a previously stored structured deny reason.
Fixed exported symbol names require a single evaluation entry point per
guest binary. The macro's unit tests cover accepted and wrong-name signatures.

## Related

- [Architecture](ARCHITECTURE.md)
- [Guard SDK](../chio-guard-sdk/README.md)
- [WASM host](../../guards/chio-wasm-guards/README.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)

Licensed under [Apache-2.0](../../../LICENSE).
