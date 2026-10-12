# chio-web3-bindings

`chio-web3-bindings` packages Alloy call/event types and compiled artifacts for
Chio's root registry, identity registry, escrow, bond vault, and price resolver.
The bindings are generated from bundled interface JSON at compile time.
Anchor and settlement runtimes use them to encode and decode contract data.

## Usage

Encode a root-registry read locally with the default `web3` feature:

```rust
use alloy::{primitives::Address, sol_types::SolCall};
use chio_web3_bindings::IChioRootRegistry;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let call = IChioRootRegistry::getRootCall {
        operator: Address::from([0x11; 20]),
        checkpointSeq: 42,
    };
    let encoded = call.abi_encode();
    let decoded = IChioRootRegistry::getRootCall::abi_decode(&encoded)?;
    assert_eq!(decoded.checkpointSeq, 42);
    assert_eq!(decoded.operator, call.operator);
    Ok(())
}
```

This produces calldata; the application supplies a reviewed contract address,
provider, and chain configuration for an actual call.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Enables `web3`. |
| `web3` | Yes | Enables Alloy and `serde_json` and the whole crate API. Without it the crate exposes no public items. |

## Guarantees

`interfaces` derives function/event shapes from the five interface artifacts.
`ChioMerkleProof` converts into each generated proof type for the root registry,
escrow, and bond vault, preserving audit path and indexes. Conversion performs
no Merkle verification.

Artifact tests check nonempty implementation bytecode and recompute its hashes.
Parity tests compare generated signatures/selectors with interface JSON and
check that implementations cover the interface surface. Those tests do not
query deployed contract code.

## Status

Compiled interface and implementation artifacts are embedded as string
constants. Bundled local-devnet deployment and qualification JSON serve as test
fixtures. Applications must collect current deployment/codehash evidence and
verify trust before dispatch. This crate provides no signer, RPC transport,
transaction submission, or runtime persistence.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [Solidity contracts](../../../contracts/README.md)
- [Anchor runtime](../chio-anchor/README.md)
- [License](../../../LICENSE)
