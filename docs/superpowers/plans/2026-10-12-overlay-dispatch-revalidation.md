# Overlay dispatch revalidation

> Use superpowers:executing-plans and test-driven-development. Root integrates and pushes; Claude reviews and merges.

Implement the existing KSPEC-04 section 4.3 rule 6 contract (KDEF-D6): containment and capability-set suspension must be consulted immediately before dispatch, including immediately ready admissions. Revalidation is read-only, preserves the configured missing-context policy, and denies on unavailable or malformed authority evidence.

## Scope

Production files are `crates/security/chio-security-kernel/src/containment.rs` and `capability_set_suspension.rs`. Use their existing `evaluate` implementation to opt into the existing `Guard` dispatch revalidation interface. No kernel dispatch-loop change or new authority API is needed.

Tests live in `crates/security/chio-security-kernel/tests/dispatch_revalidation.rs` and `dispatch_revalidation/support.rs`. Mutate the actual overlay-store result from a runtime admission readiness hook after initial guard evaluation. Count real tool invocations and authority queries.

## Tasks

1. Commit Original controls against main `61bb9eb715`: late active overlay, late authority outage, malformed authority result, and unchanged Allow. Cover both guards, ordinary/nested evaluation, immediately Ready/delayed Ready, direct/compound guard composition. A one-use invocation quota must still permit the unchanged Allow case.
2. Root runs the focused Original to establish runtime RED. Add the two guard overrides, preserving existing deny evidence and missing-context behavior.
3. Run focused GREEN and strict owning Clippy. Verify existing containment and suspension suites. Review the exact source, compose actual main once, and publish the bounded slice.

## Boundaries

This repairs the last read-only dispatch check. It is not a same-writer closure fence and does not claim linearization across an independent remote store write. D5 delegated mint authority and the broader KSPEC-04 closure/drain phases remain separate work. Do not introduce an optional delegation wrapper or claim control over offline signature construction.
