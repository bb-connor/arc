# chio-a2a-adapter

Discovers A2A agent cards and exposes advertised skills as Chio tool-server calls.
It connects outbound JSON-RPC and HTTP+JSON requests to kernel dispatch.

## Usage

```rust
use chio_a2a_adapter::{A2aAdapter, A2aAdapterConfig};
use chio_core::crypto::Keypair;

let key = Keypair::generate();
let config = A2aAdapterConfig::new(
    "https://agent.example/.well-known/agent-card.json",
    key.public_key().to_hex(),
);
// Missing egress authority fails before an outbound request.
assert!(A2aAdapter::discover(config).is_err());
```

The example exercises discovery rejection offline. Successful discovery requires
a tenant egress contract, an available agent card, and supported interface data.
Configure credentials and optional partner policy before discovery.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `fuzz` | Off | Enables the arbitrary-based envelope fuzz entry point. |

## Guarantees

- `A2aAdapter::discover` rejects empty skill sets and unsupported interfaces.
- Every request goes through a `BlockingContractAgent`. A missing contract fails
  closed before dispatch, each redirect target passes the contract before it is
  followed, and resolved addresses are checked and pinned before dialing.
  Custom roots and the mTLS identity extend server verification and never
  disable it.
- `build_manifest` validates the derived manifest shape. The configured public
  key is metadata; discovery does not authenticate a signed agent card.

## Status

Implemented outbound adapter with authentication, SSE handling, task operations,
and optional file-backed task tracking. Kernel admission, guards, and receipts
require mediated invocation through the kernel.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [chio-egress-contract](../chio-egress-contract/README.md)

## License

[Workspace license](../../../LICENSE).
