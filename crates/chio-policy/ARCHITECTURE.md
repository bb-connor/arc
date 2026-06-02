# chio-policy Architecture Notes

## Boundaries

- `models.rs` owns the HushSpec schema, YAML parser hardening, rule-block
  inventory, and extension structs.
- `validate.rs` owns schema and semantic validation before policies are
  compiled or evaluated.
- `merge.rs` and `resolve.rs` own inheritance, deep merge, and filesystem
  resolution.
- `evaluate/*` owns the reference allow, warn, and deny evaluator, including
  condition filtering, posture transitions, and origin profile selection.
- `compiler.rs` owns translation from HushSpec intent into Chio guard
  pipelines, post-invocation hooks, and default `ChioScope` fragments.
- `receipt.rs` owns audited evaluation receipts. The crate does not own guard
  internals, receipt signing, capability verification, or persistent runtime
  state.

## Current Pain Point

Origin profiles are represented as first-class HushSpec extension state and
carry a `default_behavior` whose schema default is deny. The evaluator selects
the best matching origin profile and passes its id into rule evaluation, but
unmatched or missing origin context currently falls through to the base policy
as if no origin admission decision existed. That makes `default_behavior: deny`
advisory instead of load-bearing and can allow actions from origins that failed
profile admission.

## Security And API Constraints

- Invalid HushSpec documents must reject before guard or scope materialization.
- Public parser, validator, compiler, and evaluator APIs should remain
  compatible.
- `extensions.origins.default_behavior: deny` must fail closed for unmatched
  or missing origin context before action-specific rules can allow the request.
- `default_behavior: minimal_profile` should preserve the current fallback
  behavior for callers that intentionally want base-rule evaluation without a
  matched profile.
- Existing guard ordering, regex fail-closed behavior, posture checks,
  conditions, and default-scope compilation must remain stable unless a test
  proves the current behavior drops policy intent.

## Affected Dependents

The owning-crate change is internal to `chio-policy` and affects callers of the
reference evaluator, audited evaluator, and any control-plane or CLI path that
uses `evaluate` / `evaluate_with_context` for HushSpec decisions. No public API
change is planned.

## Planned Improvement

Add an explicit origin admission step before posture and action evaluation.
When an origins extension is configured with deny behavior, requests without a
matching origin profile should return a deny result naming the origins boundary.
Requests with a matching profile and policies that opt into `minimal_profile`
fallback should continue through the existing evaluator path.

## Default-Allow Confirmation Projection Follow-up

### Boundary

`compiler.rs` translates HushSpec `tool_access` and `human_in_loop` intent into
default `ChioScope` grants. A single wildcard grant can faithfully carry global
constraints such as max-argument size, minimum runtime assurance, global
approval thresholds, or confirmation rules that apply to every tool. It cannot
faithfully carry a selective confirmation glob such as `git_push` or `shell_*`
without over-applying approval to unrelated default-allowed tools.

### Planned Improvement

Keep default-allow scopes permissive when the only unrepresentable constraint is
a selective confirmation glob. Continue emitting constrained wildcard grants for
global confirmation (`*`) and other constraints that truly apply to the entire
default-allowed tool set.
