# chio-workflow-preflight

Evaluates a supplied parent/child workflow plan before execution. It checks
scope containment, planning gates, schema support, budgets, and declared
revocation status, returning a report classified as planning evidence.

## Usage

Evaluate the repository’s valid child-scope fixture offline. The example
embeds the tracked fixture at compile time and needs no runtime services.

```rust
use chio_workflow_preflight::{evaluate_workflow_preflight,
    WorkflowPreflightPlan, WorkflowPreflightVerdict};

let bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),
    "/../../../fixtures/proof-room/workflow-preflight/",
    "valid-child-scope/preflight-plan.json"));
let plan: WorkflowPreflightPlan = serde_json::from_slice(bytes)?;
let report = evaluate_workflow_preflight(&plan)?;
assert_eq!(report.verdict, WorkflowPreflightVerdict::Accepted);
assert_eq!(report.evidence_class, "planning");
assert!(report.live_authority_claims.is_empty());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

`evaluate_workflow_preflight` first calls `validate_plan_shape`. Shape
errors return `Err`; gate failures return a `Rejected` report with
individual check codes.

`collect_child_scope_checks` enforces parent identity, scope membership,
matching currency, individual budgets, and aggregate child budget. Gate
checks reject unsupported routes, unapproved references, missing schemas,
pool overflow, conflicting gate entries, and planning artifacts that claim
live authority. Every report has an empty `live_authority_claims` list.

## Status

Implemented read-only planning verifier. Route support, approval status,
registry schemas, and revocation freshness are caller-supplied facts. The
evaluator checks their consistency without querying live services, verifying
signatures, reading a trusted clock, or reserving budget.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [chio-workflow](../chio-workflow/README.md)
- [License](../../../LICENSE)
