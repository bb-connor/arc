# chio-credit

`chio-credit` owns credit, capital, IOU, obligation, factoring, and clearing
contracts. It connects signed receipt evidence to credit decisions and exposes
store interfaces for downstream persistence. Appraisal and underwriting supply
input evidence; SQLite stores and the control plane consume these contracts.

## Usage

Create one signed capital authority step and verify it against a pinned
capital authority trust set. The fixed seed is for this local example;
deployed signers need their own protected keys.

```rust
use chio_credit::{
    crypto::Keypair, CapitalExecutionAuthorityStep, CapitalExecutionRole,
    TrustedCapitalAuthority,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Keypair::from_seed(&[7; 32]);
    let trusted = TrustedCapitalAuthority::new(vec![signer.public_key()])?;
    let step = CapitalExecutionAuthorityStep::signed(
        CapitalExecutionRole::OperatorTreasury, &signer, 100, 200, None,
    )?;
    trusted.verify_step(&step)?;
    Ok(())
}
```

`TrustedCapitalAuthority` refuses an empty key set, a step signed outside the
set, and a proof that does not verify under the matched trusted key.
`validate_capital_execution_envelope` checks issuance timing, execution-window
coverage, and custody-provider approval; it does not establish signer trust.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Empty; enables no additional features. |
| `kani` | No | Declared marker with no dependency effects; proof harnesses use `cfg(kani)`. |

## Guarantees

- `LocalCreditAccount::evaluate` checks the receipt signature, content-derived
  identity, action hash, and configured kernel signer before minting. Only an
  allowed receipt with nonzero financial metadata produces an IOU.
- `LocalCreditAccount::new` starts with an empty trusted kernel key set. Use an
  explicit trust constructor before receipt evaluation.
- `verify_receivable_iou` checks issuer trust, receipt and obligation bindings,
  the embedded three-party facility bind, and a matching committed admission.
  `SignedReceivableIou::from_canonical_bytes` only decodes and validates shape.
- `IouEnvelopeStore` requires idempotent insertion by receipt ID and conflict
  rejection. Its backend must implement persistence and concurrent-write safety.

## Status

The crate implements contracts, validators, arithmetic, and local IOU minting.
Credit admission requires an authoritative reservation store. Clearing and
capital artifacts require downstream lifecycle and rail integration; creating
an artifact does not execute settlement. The capital instruction's default
support boundary disables automatic dispatch and external execution authority.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol credit artifacts](../../../spec/PROTOCOL.md#signed-artifact-registry)
- [Underwriting](../chio-underwriting/README.md)
- [Financial credential types](../chio-fincred/README.md)
- [SQLite stores](../../platform/chio-store-sqlite/README.md)

License: [Apache-2.0](../../../LICENSE).
