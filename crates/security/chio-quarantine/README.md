# chio-quarantine

`chio-quarantine` loads temporal detection rules, correlates verified security
events, and coordinates Chio response admission, scheduling, effects, and
rollback. It connects the pure response model to caller-provided stores and ports.

## Usage

Parse a bounded two-stage rule and reproduce its canonical version locally.
Parsing installs no detector and applies no response effects.

```rust
use chio_quarantine::{GroupingKey, RuleLimits, TemporalRule};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = br#"{
      "rule_id":"credential-egress","policy_version":"policy-v1",
      "group_by":"session_id","max_groups":8,
      "max_partial_matches_per_group":4,"allow_event_reuse":false,
      "stages":[
        {"name":"read","event_kind":"credential_access","minimum_severity":"medium"},
        {"name":"send","event_kind":"egress_attempt","minimum_severity":"high",
         "after":"read","within_ms":30000}
      ]
    }"#;
    let rule = TemporalRule::parse_json(input, &RuleLimits::default())?;
    assert_eq!(rule.group_by(), GroupingKey::SessionId);
    let copy = TemporalRule::parse_json(&rule.canonical_bytes()?, &RuleLimits::default())?;
    assert_eq!(rule.version_hash(), copy.version_hash());
    Ok(())
}
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Empty; normal detection and response APIs remain available. |
| `fuzz` | No | Exposes the `fuzz` support module used by fuzz harnesses. |

## Guarantees

- `TemporalRule::parse_json` bounds input to 1 MiB, rejects ambiguous signed
  JSON, and checks stage graphs, timing, group bounds, and estimated state size.
- `TemporalCorrelator` partitions by tenant and rule, checks canonical event-body bindings,
  and reports detector health when corruption, capacity, or store failures
  suppress automatic response.
- `ResponseStateMachine::create` requires `FreshLiveAdmission`.
  `ResponseExecutor::execute` requires live execution and validates scheduled
  work before effect processing.
- `ResponseApprovalCoordinator` validates plan and reservation bindings before
  invoking the governed approval port. Its commit returns the retained binding.
- `ResponseScheduler` uses leases and fencing tokens through its store contract;
  `ResponseExecutor` journals apply and rollback progress through that store.

## Status

Implemented orchestration with injected `SecurityEventStore`, response stores,
`EffectPort`, receipt sinks, and alert ports. Durable transactions and actual
host effects depend on those implementations.

## Related

- [Architecture](ARCHITECTURE.md)
- [Trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [Decoy](../chio-decoy/README.md)

[License](../../../LICENSE)
