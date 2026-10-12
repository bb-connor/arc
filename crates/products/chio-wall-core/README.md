# chio-wall-core

`chio-wall-core` defines the typed JSON artifacts used by Chio-Wall to describe
a research-to-execution tool-access boundary. It owns schemas and explicit
validation; `chio-wall` builds packages, evaluates a guard, and writes evidence.
This library has no I/O or dependency on another Chio crate.

## Usage

Validate a control profile and reject a profile whose domains are identical:

```rust
use chio_wall_core::{
    ChioWallBuyerMotion, ChioWallControlProfile, ChioWallControlSurface,
    ChioWallInformationDomain, CHIO_WALL_CONTROL_PROFILE_SCHEMA,
};

let profile = ChioWallControlProfile {
    schema: CHIO_WALL_CONTROL_PROFILE_SCHEMA.into(),
    profile_id: "research-barrier".into(),
    workflow_id: "research-to-execution".into(),
    buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview,
    control_surface: ChioWallControlSurface::ToolAccessDomainBoundary,
    source_domain: ChioWallInformationDomain::Research,
    protected_domain: ChioWallInformationDomain::Execution,
    retained_artifact_policy: "retain-denied-access-record".into(),
    intended_use: "control-room review".into(),
    fail_closed: true,
};
profile.validate()?;
let invalid = ChioWallControlProfile {
    protected_domain: ChioWallInformationDomain::Research,
    ..profile
};
assert!(invalid.validate().is_err());
# Ok::<(), chio_wall_core::ChioWallContractError>(())
```

Deserializing JSON does not run `validate()`. Call it after decoding or changing
public fields and before accepting the artifact into a package.

## Guarantees

- Each schema-bearing artifact's `validate` method checks its exact
  `CHIO_WALL_*_SCHEMA` constant and required strings. Helpers reject empty,
  padded, and control-character-bearing string values.
- `ChioWallControlProfile`, `ChioWallAuthorizationContext`, and
  `ChioWallDeniedAccessRecord` require different source and target domains.
  Fields named `fail_closed` must be true wherever present.
- `ChioWallPolicySnapshot` and `ChioWallGuardOutcome` require nonempty,
  unique tool lists. A denial cannot name a tool in its allowlist; an allow
  outcome has no corresponding membership requirement.
- `ChioWallControlPackage::validate` requires all seven artifact kinds exactly
  once. `ChioWallArtifact::validate` checks the path string; filesystem
  containment, existence, cross-file identity, and receipt verification belong
  to package consumers.

## Status

The contract types and validators are implemented with unit tests and a profile
integration smoke test. Buyer motion and control surface each have one enum
variant. Validation establishes local artifact consistency. Enforcement, signer
trust, persistence, and operational control ownership must be supplied by the
application consuming these artifacts.

## Related

- [Architecture](ARCHITECTURE.md)
- [Wall CLI](../chio-wall/README.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)

License: [root license](../../../LICENSE).
