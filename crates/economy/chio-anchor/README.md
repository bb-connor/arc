# chio-anchor

`chio-anchor` builds signed checkpoint-ID batches and normalizes checkpoint
proofs across EVM root registries, Bitcoin OTS, and Solana memo records.
It consumes kernel checkpoints and evidence exports, with separate APIs for
local proof checks, EVM publication, and public-witness verification.

## Usage

Build and verify a local batch without contacting a witness service:

```rust
use chio_anchor::{
    build_anchor_batch, verify_anchor_batch, AnchorBatchWitness,
    AnchorBatchWitnessKind, WitnessState,
};
use chio_core::{hashing::Hash, Keypair};

fn main() -> Result<(), chio_anchor::AnchorError> {
    let signer = Keypair::generate();
    let batch = build_anchor_batch(
        vec!["checkpoint-1".into(), "checkpoint-2".into()],
        AnchorBatchWitness {
            kind: AnchorBatchWitnessKind::Rekor,
            witness_id: "local-pending".into(),
            root: Hash::zero(),
            observed_at: None,
        },
        1_700_000_000,
        &signer,
    )?;
    verify_anchor_batch(&batch)?;
    assert_eq!(batch.body.witness_state, WitnessState::Pending);
    Ok(())
}
```

The builder replaces the supplied witness root with the computed Merkle root.
The pending descriptor records an intended lane; public-witness acceptance
requires the asynchronous policy verifier and a trusted lane client.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Enables nothing. |
| `web3` | No | Enables the entire crate API and its cryptographic, HTTP, kernel, and contract-binding dependencies. Disabling it leaves no public items. |
| `fuzz` | No | Enables `web3`, `arbitrary`, and the public verifier fuzz entry point. |
| `kani` | No | Enables `web3`; harness code additionally requires the Kani toolchain's `cfg(kani)`. |

## Guarantees

`verify_anchor_batch` reconstructs the Merkle root, checks ordered inclusions
and witness-root binding, and verifies the canonical body signature using the
embedded signer key. Callers independently authorize that key.
`verify_anchor_batch_with_witness_policy` rejects required public-witness
policies; use `verify_anchor_batch_with_witness_policy_async` for that route.
Its stale fallback uses verifier-owned cache times keyed by `batch_body_hash`.

`confirm_root_publication` checks the transaction receipt, matching
`RootPublished` event, and registry state at the publication block.
`verify_proof_bundle` checks carried proof material locally; external chain
observations and finality remain separate inputs.

## Status

EVM RPC dispatch and Rekor HTTP clients are implemented. Rekor authenticates
signed-entry timestamps and validates any supplied Merkle inclusion path
against the response root. It does not authenticate that root as a checkpoint.
`OtsClient` yields advisory receipts and rejects required-witness verification.
Solana support prepares memo data and validates records supplied by the caller.
The application owns durable checkpoint storage, scheduling, and key trust.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol anchor batches](../../../spec/PROTOCOL.md#651-anchor-batch-v1)
- [Contract bindings](../chio-web3-bindings/README.md)
- [Kernel checkpoints](../../kernel/chio-kernel/README.md)
- [License](../../../LICENSE)
