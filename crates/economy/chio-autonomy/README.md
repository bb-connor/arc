# chio-autonomy

`chio-autonomy` defines and validates artifacts for autonomous pricing,
capital-pool optimization, execution records, comparison, drift, and rollback.
It combines monetary and receipt types from `chio-core-types`, coverage classes
from `chio-market`, and, with the `web3` feature, settlement lifecycle states
from `chio-web3`.

The crate contains data models and synchronous validators. Applications own
model execution, evidence retrieval, signing, persistence, and effect dispatch.

## Usage

Construct and validate a rollback plan without services or runtime state:

```rust
use chio_autonomy::{
    validate_autonomous_rollback_plan, AutonomousDriftKind,
    AutonomousRollbackAction, AutonomousRollbackPlanArtifact,
    AutonomousSafeState, CHIO_AUTONOMOUS_ROLLBACK_PLAN_SCHEMA,
};

let plan = AutonomousRollbackPlanArtifact {
    schema: CHIO_AUTONOMOUS_ROLLBACK_PLAN_SCHEMA.into(),
    plan_id: "rollback-1".into(),
    issued_at: 1,
    subject_key: "agent-1".into(),
    safe_state: AutonomousSafeState::FullPause,
    triggers: vec![AutonomousDriftKind::SettlementFailureRate],
    actions: vec![AutonomousRollbackAction::RequireHumanApproval],
    requires_operator_ack: true,
    note: None,
};
validate_autonomous_rollback_plan(&plan)?;
# Ok::<(), chio_autonomy::AutonomyContractError>(())
```

Validation checks the plan's schema, identifiers, and nonempty unique trigger
and action lists. The caller executes the declared rollback actions.

## Guarantees

- `validate_autonomous_pricing_input` requires underwriting, exposure, credit
  scorecard, and capital-book evidence kinds; loss or settlement state adds
  conditional evidence requirements. References are checked as identifiers.
- `validate_autonomous_pricing_decision` checks nested input and authority,
  matching subject/provider/currency, monetary ceilings, explanation factors,
  shadow review state, and bind permission/human-review constraints.
- `validate_autonomous_execution_decision` requires all gates to pass for
  `Executed`, at least one to fail for `Blocked`, and a settlement dispatch
  reference for an executed bind.
- `validate_autonomous_drift_report` requires critical signals to declare an
  engaged fail-safe and appear among the nested rollback plan's triggers.

## Status

The artifact and validation surface is implemented. `SignedAutonomous*` and
`SignedCapitalPool*` aliases use `SignedExportEnvelope`; callers must verify
signatures and resolve referenced authority independently. Validators do not
prove that an action ran, a reserve exists, or a rollback occurred. Authority
limits such as daily decision counts require runtime accounting by the caller.

`cargo test -p chio-autonomy` covers reference fixtures, validator regressions,
and construction through the public API. No Cargo features are declared.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [Autonomous pricing profile](../../../docs/standards/CHIO_AUTONOMOUS_PRICING_PROFILE.md)
- [Market artifacts](../chio-market/README.md)
- [License](../../../LICENSE)
