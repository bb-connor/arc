# chio-security-types

Portable records, validation rules, and service ports for Chio active defense.
The crate supplies the shared vocabulary for security events, information flow,
response plans, restrictive overlays, dispatch, and recovery. Its default build
uses `no_std` with `alloc`; stores and enforcement adapters live in other crates.

## Usage

This repository example reads the response-plan wire fixture, validates its
shape, and extracts the compact authorization commitment. It uses the crate's
existing `serde_json` development dependency and works with default features.
The fixture has illustrative digests; shape validation does not verify them.

```rust
use chio_security_types::{
    FreshLiveAdmission, ResponseExecutionBinding, ResponseExecutionMode, ResponsePlan,
};

let encoded = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/bindings/vectors/security/active-defense/positive/response-plan-v1.json"
));
let mut plan: ResponsePlan = serde_json::from_str(encoded)?;
plan.validate_shape()?;
let body = plan.authorization_body();
assert_eq!(body.execution.mode(), ResponseExecutionMode::Live);
assert_eq!(body.effects.len(), plan.effects.len());
assert!(FreshLiveAdmission::new(plan.clone()).is_ok());

plan.execution = ResponseExecutionBinding::new(ResponseExecutionMode::DryRun);
assert!(FreshLiveAdmission::new(plan).is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes, empty | Portable types and pure validation with `alloc`. |
| `std` | No | Enables Serde's standard-library support, JSON/SHA-256 helpers, system clocks, and the gated service ports. |

## Guarantees

- `ResponseExecutionBinding` has private fields and rejects unknown wire fields
  and schema versions. `ResponsePlan` requires an explicit execution binding.
- `ResponsePlan::authorization_body()` retains execution mode and contribution
  hashes, and excludes `plan_hash` and raw contribution bytes. Consumers must
  canonicalize and hash this body when validating the authorization commitment.
- `ResponsePlan::validate_shape()` checks effect ordering, target kinds, time
  ranges, nonzero commitments, and the leading issuance-fence rule.
- `FreshLiveAdmission::new()` requires live mode. Capability, approval, signature,
  and contribution-content verification remain admission responsibilities.
- `BoundedVec`, `CanonicalBody`, and identifier constructors enforce their own
  size or representation limits during construction and decoding.

## Status

Implemented shared contracts with unit, wire-shape, and port-compatibility tests.
Many aggregate records have public fields: callers must invoke the relevant
validator after construction or decoding. The crate supplies no signing service
or persistent store, and its validators do not establish deployment acceptance.

## Related

- [Architecture](ARCHITECTURE.md)
- [Canonical JSON contract](../../../spec/PROTOCOL.md#41-canonical-json)
- [Kernel adapters](../chio-security-kernel/README.md)
- [Authority service](../chio-active-response-authority/README.md)

License: [Apache-2.0](../../../LICENSE).
