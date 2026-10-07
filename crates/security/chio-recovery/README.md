# chio-recovery

Pure, deterministic recovery advice for Chio. The crate defaults to `no_std + alloc`
and depends only on portable security data types. Its additive `std` feature does
not introduce a runtime, storage, transport, clock, signer or random-number source.

The planner and workflow use separate vocabularies and a bounded observation
reducer. Every input is an untrusted claim. Recommendations cannot allocate a native
operation, dispatch a connector, close an admission intent, consume a grant or release
protected bytes. Those actions remain in the existing kernel's admission/capture path.
Unknown operations preserve their identity through cancellation; settled partial
effects and withheld results never produce advice to submit another effect.

Snapshot evaluation, bounded remedy search and report verification are pure functions.
Callers supply time, selected trust roots and audience data. Durable identity,
authoritative observations, admission closure and execution belong to the native
kernel and control plane.

`plan` validates a classified registry of symbolic dependency graphs and returns
ordered `CandidatePlanV1` advice through `PlanDecision`. It preserves the supplied
scope, workflow and intent, checks every referenced template and declared cost, and
never treats a planned step as evidence that a future prerequisite has succeeded.

Deployment limits may lower the protocol ceilings of 16 alternatives, 8 top-level
steps, 32 expanded operation nodes per plan, depth 8 and 4,096 shared work units.
The current `DependencyGraphV1` representation has a stricter 16-node ceiling.
Exhaustion names the specific bound and keeps the incomplete result classified as
`Top`; it does not declare the task impossible. Classified plans have redacted
debug output and no signing or execution conversion.
