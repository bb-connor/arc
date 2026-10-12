# chio-federation

`chio-federation` provides cross-operator trust artifacts, pinned peer
handshakes, treaty admission, bilateral receipt verification, and FROST
execution authorization. It sits above transports and supplies contracts used
by listing, governance, and runtime integrations.

## Usage

Accept a signed handshake against an explicitly configured peer key. These
fixed seeds are example identities; provision separate keys for deployment.

```rust
use chio_core_types::Keypair;
use chio_federation::trust_establishment::{KernelTrustExchange, PeerHandshakeEnvelope};

let local = Keypair::from_seed(&[1; 32]);
let remote = Keypair::from_seed(&[2; 32]);
let exchange = KernelTrustExchange::new("kernel-a", local)
    .with_trusted_peer("kernel-b", remote.public_key());
let envelope = PeerHandshakeEnvelope::sign(
    "kernel-b", "kernel-a", "unique-handshake-nonce", 1_000, &remote,
)?;
let peer = exchange.accept_envelope(&envelope, "kernel-b", 1_000)?;
assert_eq!(exchange.resolve("kernel-b", 1_001)?.public_key, peer.public_key);
# Ok::<(), Box<dyn std::error::Error>>(())
```

The default peer store is process-local. The caller supplies time in Unix
seconds and must prevent nonce replay within the handshake freshness window.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `demo` | Off | Exposes fixture helpers, including an allow-all revocation oracle. |
| `pq` | Off | Enables post-quantum signing support in `chio-core-types`. |
| `typestate` | Off | Exposes the generated bilateral DSSE producer state machine. |

No crate features are enabled by default. FROST support is unconditional.

## Guarantees

- `KernelTrustExchange::accept_envelope` checks the signed challenge, recipient,
  expected kernel ID, clock skew, and configured or previously pinned key.
  `accept_envelope_with_policy` also enforces a conformance tier floor.
- Activation and admission validators require explicit local review and
  activation controls. Their inputs describe policy and artifact references;
  callers verify signatures, resolve referenced artifacts, and enforce import.
- `verify_chio_bilateral_invocation` adds peer pins, epoch revocation,
  receipt and lease resolution, policy agreement, and governance checks to DSSE
  signature verification.
- `frost::verify_for_execution` requires current anchored epoch and completed
  slot state, expected execution bindings, and a valid group signature.
  Historical verification returns separate evidence types.

## Status

The library implements bounded federation contracts and verification APIs.
It leaves scheduling, network delivery, durable stores, and local activation
to its integrations. `demo` helpers serve examples and tests. Signed tier
advertisements and qualification matrices carry assertions that operators
must substantiate with the protocol's required conformance evidence.

## Related

- [Architecture](ARCHITECTURE.md)
- [Portable trust and federation](../../../spec/PROTOCOL.md#10-portable-trust-and-federation)
- [Certification contract](../../../spec/PROTOCOL.md#12-certification-contract)
- [Iroh transport](../chio-federation-transport-iroh/README.md)
- [Authority issuance](../chio-federation-authority/README.md)

[License](../../../LICENSE)
