# chio-guards Architecture Notes

## Boundary

`chio-guards` owns Chio's built-in pre-invocation and post-invocation guard
implementations. The crate converts kernel `GuardContext` values into typed
action categories, evaluates policy-specific guard logic, and returns
fail-closed `Verdict` values to the hosted kernel. It should not own receipt
signing, capability validation, budget mutation, or persistent kernel state.

## Current Pain Point

The response sanitizer exposes `OutputSanitizerConfig::redaction_strategies`
for category-level policy. That policy boundary must not apply equally to every
secret finding. Ordinary built-in detectors can follow category defaults, but
explicit denylist matches and fail-closed findings are mandatory redaction
findings. If those findings take the same `SensitiveCategory::Secret` strategy
path as ordinary detectors, a caller can set `Secret -> Keep` and downgrade a
forced-redaction match to no redaction. `SanitizerHook` feeds sanitized JSON and
finding summaries into the post-invocation pipeline, so this boundary is part of
agent-visible output control rather than local formatting only.

## Security And API Constraints

- Guard evaluation must remain fail-closed for malformed guard configuration.
- Public guard constructors, config structs, result structs, and re-exports
  must remain compatible.
- Category-level redaction policy can still weaken ordinary built-in detectors
  when the caller explicitly chooses that policy, but explicit denylist matches
  and fail-closed redaction-unavailable findings must not be downgraded.
- Receipt evidence must never include raw secret material, and sanitizer
  evidence must remain consistent with the transformed output.
- Post-invocation behavior must preserve JSON structure and existing
  `SanitizerHook` integration.

## Affected Dependents

The owning-crate change is internal to `chio-guards`. It affects callers that
install `OutputSanitizer` or `SanitizerHook` directly or through post-invocation
policy paths. No dependent API change is planned; dependent behavior should
only become stricter for explicit denylist matches.

## Implemented Improvement

Redaction strategy selection now sits behind an internal policy boundary that
distinguish configurable detector recommendations from mandatory denylist and
fail-closed findings. Regression coverage proves exact and regex denylist
matches remain redacted even when the caller sets `SensitiveCategory::Secret` to
`Keep`.
