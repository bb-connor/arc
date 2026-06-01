# chio-policy Architecture Notes

## Boundary

`chio-policy` owns HushSpec parsing, validation, merge resolution, reference
evaluation, and compilation into Chio guard pipelines plus default capability
scope fragments. It should translate policy intent into existing Chio kernel
and guard primitives without owning guard internals, receipt signing, budget
mutation, capability verification, or persistent runtime state.

## Current Pain Point

Policy compilation has two different security surfaces: emitted guard pipelines
and the compiled `ChioScope`. Guard pipelines can express allow, block, warning,
runtime, workload, and size rules. Capability scopes are positive grants with
constraints, and have no negative grant form. That makes `tool_access` deny-list
semantics security-sensitive: compiling an allow-list grant while ignoring a
block list can issue a capability that is broader than the policy intent if the
allow and block patterns overlap and a caller consumes `default_scope` outside
the full guard pipeline.

## Security And API Constraints

- Invalid HushSpec documents must reject before guard or scope materialization.
- Public parser, validator, compiler, and evaluator APIs should remain
  compatible.
- Default scope compilation must not silently widen access when workload
  identity, deny-list, or other unrepresentable semantics are present. It may
  emit constrained grants only for semantics that `ChioScope` can enforce
  directly.
- Existing guard ordering, fail-closed regex validation, and policy evaluator
  decisions must remain stable unless a test proves the current behavior drops
  policy intent.

## Affected Dependents

The owning-crate change is internal to `chio-policy`. It affects callers that
consume `compile_policy(...).default_scope` to issue initial capabilities,
including CLI and runtime policy-loading paths. No dependent API change is
planned.

## Planned Improvement

Make block-by-default scope compilation fail closed when `tool_access.block`
overlaps the grants that would otherwise be emitted. The guard pipeline should
still enforce the complete policy, but `default_scope` should emit no grants
when a deny-list would be required to make those grants faithful.
