# Delegation freeze and overlay dispatch revalidation

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

This repairs the last read-only dispatch check. It is not a same-writer closure fence and does not claim linearization across an independent remote store write. The broader KSPEC-04 closure/drain phases remain separate work. Delegation presentation enforcement is included below. Do not introduce an optional delegation wrapper or claim control over offline signature construction.

## Qualification

- Original `e0f694afcc`: two unchanged-authority controls passed; six late active, unavailable or malformed authority cases failed after one actual tool invocation.
- Repair `06721c1db2`: all eight focused tests passed across 64 ordinary/nested, direct/pipeline and Ready/delayed cells. The full owning integration suite passed 93 tests.
- The first strict run rejected an ambiguous test `RequestId` glob import. `0541a42da7` makes session imports explicit. Actual-main composition `6e265388eb` includes the prepayment custody repair and the new repository rules; its focused tests and strict lint remain pending.
- Claude reviews the 28-line production delta. No proof, same-writer linearization or closure/drain acceptance is implied.

## Delegation admission

The public non-tool validator admits issuer-signed delegated resource capabilities. Tool invocation independently refuses security-bound delegation. Freeze enforcement therefore belongs after signature, ancestry and attenuation validation in the common delegation-admission path.

- With a configured freeze authority, every delegated token must carry signed tenant and lineage fields. Query `Delegate` with the final link's parent capability id; authority refusal denies admission.
- A bound delegation without a freeze authority denies admission.
- A standalone kernel without a freeze authority continues to admit its current unbound local capabilities. Issued roots are not delegation operations.
- The tool invocation ban remains in force. No new capability minting interface is added.
- Freeze-window replay after lift remains open because the authority has no retained interval history. Current presentation checks do not prove when an offline signature was created.

Public Original `87238093c2` (unchanged delegation admission plus `fe2704734e` tests) passed three positive controls and failed four refusal controls: frozen subscription, frozen parent registration, missing authority and configured authority without signed binding. `6a01f759dd` implements the common admission check. `e65aeb0917` adds the public tool-ban control; `8fddc6c502` asserts the exact public error boundary. All eight public tests pass at `8fddc6c502`; combined strict qualification remains pending.
