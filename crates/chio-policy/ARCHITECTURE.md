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

`rules.secret_patterns` feeds two downstream enforcement paths: pre-invocation
`SecretLeakGuard` configuration and post-invocation `SanitizerHook` denylist
configuration. The compiler can only preserve policy intent if validation has
already rejected ambiguous pattern shape. Blank pattern names must not reach
guard materialization because they create empty evidence names. Regex
diagnostics must also stay independent from caller-controlled names; otherwise
an invalid or blank name can collapse a validation path to unstable strings such
as `rules.secret_patterns.patterns.`.

## Security And API Constraints

- Invalid HushSpec documents must reject before guard or scope materialization.
- Public parser, validator, compiler, and evaluator APIs should remain
  compatible.
- Secret pattern names must be non-empty before guard evidence can reference
  them.
- Secret pattern regex diagnostics should use stable array indices rather than
  caller-controlled names, especially when the name itself is invalid.
- Existing regex safety, guard ordering, sanitizer denylist projection,
  posture checks, conditions, and default-scope compilation must remain stable
  unless a test proves the current behavior drops policy intent.

## Affected Dependents

The owning-crate change is internal to `chio-policy` and affects callers of the
validator, compiler, and any control-plane or CLI path that loads HushSpec
documents before building guard pipelines. `chio-guards` remains unchanged
because policy validation owns the schema boundary.

## Implemented Improvement

Validation now rejects blank secret pattern names, keeps existing regex
fail-closed validation, and reports pattern regex errors by `patterns[index]`
paths. `compile_policy` fails before constructing a `SecretLeakGuard` or
`SanitizerHook` from invalid secret-pattern shape.
