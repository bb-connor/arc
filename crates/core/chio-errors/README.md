# chio-errors

`chio-errors` provides typed diagnostic fields and the generated Chio error
registry. Kernel, transport, and product callers can carry a code, domain,
severity, message, and optional help through one shared error vocabulary.

## Usage

Build a registry-bound diagnostic when the registry metadata is authoritative:

```rust
use chio_errors::{lookup_error_code, Diagnostic, Domain};

let spec = lookup_error_code("urn:chio:error:capability:expired")
    .ok_or("missing registry entry")?;
let diagnostic = Diagnostic::from_spec(spec, "token expired before evaluation");
assert_eq!(diagnostic.domain(), Domain::Capability);
assert_eq!(diagnostic.registry_spec(), Some(spec));
let error = diagnostic.into_error();
assert_eq!(error.code().as_str(), spec.urn);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Free-form constructors accept caller-provided codes. Use `registry_spec()` to
check whether both the code and its metadata agree with the registry.

## Guarantees

- `Diagnostic::from_spec` copies the registry URN, domain, severity, and help.
- `Diagnostic::registry_spec` rejects mismatched domain or severity metadata.
- `lookup_string_code` returns `None` for ambiguous legacy string codes.
- `jsonrpc_bridge::from_jsonrpc_code` returns `None` for unmapped integers.

## Status

Implemented shared error types and registry lookups, with integration tests for
metadata preservation, ambiguity, and JSON-RPC mappings. The crate declares no optional Cargo features. Enforcement callers
own access denial; constructing an error does not perform authorization.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [Core types](../chio-core/README.md)

[License](../../../LICENSE)
