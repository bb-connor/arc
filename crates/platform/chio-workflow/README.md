# chio-workflow

Coordinates declared skill steps and produces signed workflow receipts. It
adds step authorization, ordering, supplied-cost accounting, execution
limits, and a workflow trace above individual Chio tool calls.

## Usage

Record a synthetic one-step result and sign the workflow trace offline. In a
runtime, the caller invokes the tool through the kernel between validation
and recording, then supplies its receipt ID and measured result.

```rust
use chio_core::Keypair;
use chio_workflow::{SkillGrant, SkillManifest, SkillStep, WorkflowAuthority};
use chio_workflow::authority::StepExecutionRecordInput;
use chio_workflow::receipt::{StepOutcome, WorkflowOutcome};

let step = SkillStep {
    index: 0, server_id: "catalog".into(), tool_name: "lookup".into(),
    label: None, input_contract: None, output_contract: None,
    budget_limit: None, retryable: false, max_retries: None,
};
let manifest = SkillManifest::new("lookup".into(), "1".into(),
    "Lookup".into(), vec![step.clone()]);
let grant = SkillGrant::new("lookup".into(), "1".into(),
    vec!["catalog:lookup".into()]);
let authority = WorkflowAuthority::new(Keypair::from_seed(&[5; 32]));
let mut execution = authority.begin(&manifest, &grant,
    "agent-demo".into(), "cap-demo".into(), None)?;
authority.validate_step(&execution, &step, &grant)?;
authority.record_step(&mut execution, &step, StepExecutionRecordInput {
    outcome: StepOutcome::Success, duration_ms: 1, cost: None,
    tool_receipt_id: None, output_hash: None,
})?;
let receipt = authority.finalize(execution)?;
assert!(matches!(receipt.outcome, WorkflowOutcome::Completed));
assert!(receipt.verify()?);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

`begin` checks skill ID/version and authorized tool pairs, then reserves
limited execution capacity per capability ID. `validate_step` checks active
state, authorized pair, ordering, and elapsed time.

`record_step` records the supplied result before reporting budget or time
failure, preserving the offending step. `finalize` signs canonical receipt
bytes. Callers authenticate grants and must run manifest I/O validation
separately; these lifecycle methods do not validate a capability token.

## Status

Implemented in-memory workflow authority and receipt primitives. Execution
counters live with the authority object. Finalization derives an outcome
from recorded results without comparing them against the original manifest
step count. Callers ensure every intended step is recorded and enforce real
tool dispatch through the kernel.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [chio-workflow-preflight](../chio-workflow-preflight/README.md)
- [License](../../../LICENSE)
