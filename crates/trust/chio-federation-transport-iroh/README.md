# chio-federation-transport-iroh

`chio-federation-transport-iroh` carries federation traffic over Iroh QUIC,
Iroh Gossip, and Iroh Blobs. An issuer-signed directory binds transport
endpoint IDs to long-term passport keys. Chio admission and frame verifiers
then authorize the authenticated transport peer.

## Usage

Build a fail-closed gate before loading trusted directory material. This
example opens no endpoint and performs no network operations.

```rust
use std::sync::Arc;
use chio_federation_transport_iroh::{admission::DirectoryGate, identity::VerifiedDirectory};
use iroh::{endpoint::AfterHandshakeOutcome, SecretKey};

let gate = DirectoryGate::new(Arc::new(VerifiedDirectory::empty_deny_all()));
let peer = SecretKey::from_bytes(&[7; 32]).public();
assert!(gate.resolve(&peer).is_none());
assert!(matches!(
    gate.decide(&peer),
    AfterHandshakeOutcome::Reject { .. }
));
```

To admit peers, call `TransportDirectoryBundleDocument::verify_bundle` with
pinned issuers, a version floor, predecessor hash, and current Unix milliseconds.
Install the resulting directory in the gate and register the gate with the
Iroh endpoint's `hooks` before mounting lane handlers.

## Guarantees

- `verify_bundle` checks schema, canonical directory hash, issuer signature,
  validity window, rollback pins, active-entry passport endorsements, and
  duplicate identity bindings before returning `VerifiedDirectory`.
- `DirectoryGate::decide` rejects unknown and removed endpoints with code 403.
  It reads the current verified snapshot; expiry handling requires a reloader.
- `RevocationHandler::verify_batch` checks recipient, signer-to-endpoint binding,
  envelope consistency, and pinned oracle signatures before returning roots.
- `BlobCatchupClient` checks downloaded content addresses, signatures, epoch
  order, and bounded ranges. A content hash alone grants no oracle authority.
- Pheromone handlers preserve relay receiver verification and SQLite inbox/
  outbox handling. Bilateral handlers verify the directory-bound remote key
  before requesting a DSSE co-signature.

## Status

The CLI's opt-in Iroh path supports directed pheromone batches on relay serve
and relay tick. Revocation, blob catch-up, and bilateral co-sign APIs are
library surfaces requiring application collaborators. The CLI lane parser
rejects revocation and bilateral selections; fan-out is experimental and
library-only.

Fan-out checks local subscription and received origin treaty membership.
Iroh Gossip 0.101 provides no inbound per-topic admission hook, so a
federation-admitted non-party can passively observe forwarded treaty traffic.
Applications must account for this confidentiality limit.

This crate declares no Cargo features. Its Iroh dependency disables default
features and selects `tls-ring`.

## Related

- [Architecture](ARCHITECTURE.md)
- [Federation contracts](../chio-federation/README.md)
- [Pheromone relay](../chio-pheromone-relay/README.md)
- [Portable trust and federation](../../../spec/PROTOCOL.md#10-portable-trust-and-federation)

[License](../../../LICENSE)
