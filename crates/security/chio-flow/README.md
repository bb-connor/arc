# chio-flow

`chio-flow` evaluates Chio information labels before dispatch and after output
classification. It joins principal, lineage, and session taint and prepares
requests for the runtime's flow store and egress fence.

## Usage

Check a restricted label against an explicit destination clearance. This
example uses the default `no_std` library surface and requires no flow store.

```rust
use chio_flow::{authorize_egress, InformationFlowLattice};
use chio_security_types::{InformationLabel, PrincipalId};
use std::collections::{BTreeMap, BTreeSet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let owner = PrincipalId::new("owner-a")?;
    let restricted = InformationLabel::try_known(
        BTreeMap::from([(owner.clone(), BTreeSet::from([owner]))]),
        BTreeSet::new(),
    )?;
    let source = InformationLabel::bottom().join(&restricted)?;
    authorize_egress(&source, Some(&restricted))?;
    assert!(authorize_egress(&source, Some(&InformationLabel::bottom())).is_err());
    assert!(authorize_egress(&source, None).is_err());
    Ok(())
}
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Empty; the library uses `no_std` with `alloc`. |
| `std` | No | Enables classification ports, post-invocation evaluation, and declassification consumption; enables dependency `std` support. |

## Guarantees

- `authorize_egress` rejects missing clearance, `Top` source or clearance,
  and a source that cannot flow to the destination.
- `prepare_pre_invocation` validates the manifest, joins observed input with
  stored taint, and checks every policy clearance for effective egress.
  A supplied manifest input clearance adds another check.
- `verify_declassification` checks signed grant bindings and a strict label
  downgrade. With `std`, consumption delegates one-shot state to
  `DeclassificationUseStore` and rejects an already consumed result.
- `prepare_egress_fence` requires matching flow keys and persisted joined taint
  before producing a request bound to the persisted context generation.

## Status

Implemented label evaluation and artifact validation. The crate supplies no
classifier, flow database, network filter, or connector. Callers persist taint,
consume grants, acquire fences, and enforce them before releasing data.

## Related

- [Architecture](ARCHITECTURE.md)
- [Manifest contract](../../../spec/PROTOCOL.md#7-manifest-contract)
- [Security types](../chio-security-types/README.md)

[License](../../../LICENSE)
