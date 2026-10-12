# chio-finding-market-port

Store-neutral contracts for the hosted Chio finding market. The HTTP edge
uses these traits to request authentication records and domain writes;
PostgreSQL implements them without exposing SQLx to the edge.

## Usage

Resolve a wire event to its aggregate and artifact schema before selecting
an adapter operation. This example needs no storage service.

```rust
use chio_finding_market_port::{
    HostedAggregateKind, HostedMarketDomainEventKind, HostedTenantId,
};

let tenant = HostedTenantId::new("tenant:acme-1")?;
let event = HostedMarketDomainEventKind::from_event_kind("finding.published")
    .ok_or("unknown event")?;
assert_eq!(tenant.as_str(), "tenant:acme-1");
assert_eq!(event.aggregate_kind(), HostedAggregateKind::Finding);
assert_eq!(event.artifact_schema(), "chio.finding.v1");
assert!(HostedMarketDomainEventKind::from_event_kind("finding.unknown").is_none());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

- `HostedTenantId::new` accepts 1-128 ASCII bytes from the identifier
  alphabet: alphanumerics, hyphen, underscore, period, colon, and slash.
- `HostedMarketDomainEventKind` maps 23 closed event kinds to their
  aggregate family and artifact schema. Parsing unknown wire labels fails.
- `HostedDomainMutation` rejects unknown JSON members and excludes
  `artifact_authority_id` from serialization and deserialization.
- `HostedCapabilityAdmission` names the nonce, request binding, validity
  bounds, invocation budget, and tenant capacity consumed by an adapter.

## Status

Implemented interface library with unit tests for identity and grammar.
The traits specify asynchronous operations and error categories. Adapter
implementations supply persistence, replay fencing, and artifact verification;
constructing a mutation or looking up a grammar entry grants no authority.
`HostedTenantId` also derives transparent deserialization, so callers taking
untrusted tenant strings should enter through its validating constructor.

## Related

- [Architecture](ARCHITECTURE.md)
- [Finding artifact contract](../../../spec/PROTOCOL.md#647-finding-artifact-family)
- [PostgreSQL adapter](../chio-finding-market-store-postgres/README.md)
- [Hosted edge](../chio-finding-hosted-edge/README.md)

Licensed under [Apache-2.0](../../../LICENSE).
