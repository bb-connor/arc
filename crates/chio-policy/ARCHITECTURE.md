# chio-policy Architecture Notes

## Boundary

`chio-policy` owns HushSpec parsing, validation, merge resolution, reference
evaluation, and compilation into Chio guard pipelines plus default capability
scope fragments. It should translate policy intent into existing Chio kernel
and guard primitives without owning guard internals, receipt signing, budget
mutation, capability verification, or persistent runtime state.

## Current Pain Point

Policy compilation has two different security surfaces: emitted guard pipelines
and the compiled `ChioScope`. Approval rules from `human_in_loop` and
`tool_access.require_confirmation` are enforced through scope constraints rather
than a standalone guard. That makes default-allow scope compilation
security-sensitive: a wildcard grant must carry representable approval
constraints, but must not be materialized when other policy semantics cannot be
represented on that grant.

## Security And API Constraints

- Invalid HushSpec documents must reject before guard or scope materialization.
- Public parser, validator, compiler, and evaluator APIs should remain
  compatible.
- Default scope compilation must not silently widen access when workload
  identity, runtime assurance, argument-size, or deny-list semantics are
  present. It may emit a constrained wildcard only when approval semantics are
  exactly representable on a wildcard grant.
- Existing guard ordering, fail-closed regex validation, and policy evaluator
  decisions must remain stable unless a test proves the current behavior drops
  policy intent.

## Affected Dependents

The owning-crate change is internal to `chio-policy`. It affects callers that
consume `compile_policy(...).default_scope` to issue initial capabilities,
including CLI and runtime policy-loading paths. No dependent API change is
planned.

## Planned Improvement

Make default-allow scope compilation account for both top-level
human-in-the-loop approval requirements and `tool_access.require_confirmation`
before emitting a wildcard grant. Representable approval requirements should
produce a constrained wildcard grant; unrepresentable security semantics should
keep the guard pipeline but produce an empty default scope rather than issuing
an unconstrained wildcard capability.
