# Candidate identity workflow definitions

This prerequisite updates the trusted capture, finalizer, revocation and landing-audit definitions for the process/security foundation in PR #1160. It does not authorize a source candidate, publish an approval, or qualify the foundation.

## Contract

The dedicated security App posts one `Security contract` namespace on the committed evidence head `E`. Successful authority binds the canonical candidate identity and its digest, the retained base and tree, the reviewed source `S`, the trusted definition `D`, the original source-CI attempt and all five original check IDs. Capture and CI merge observations remain distinct. The auditor checks the retained landing against those bindings and the actual artifact bytes.

Positive publication retains live pull-request, base, tree, source, App and current-check validation. Authenticated negative history is scoped to `E` and can deny existing authority after a pull request closes or its test merge changes. Existing authority metadata stays intact when denied. Ordinary Actions checks are not replaced by App-created copies.

History discovery compares the workflow-specific and repository-wide inventories. It refuses incomplete inventories, retains authenticated failures from retired workflow registrations, and inspects at most 100 attempts per run. An observed authenticated failure remains a denial even when another history read is unavailable. A later successful retry cannot erase a recorded failure for the same evidence head.

## Ordered activation

1. Qualify and land these definitions on `main`, retaining the exact merge commit as `D`. Keep the current ordinary CI checks enabled.
2. Update the foundation caller to that landed definition. Freeze and locally qualify the reviewed source `S`, including the definition regression suite, composed publication/revocation/audit controls and the source contract tests.
3. Freeze the committed-evidence authorization at its documented all-zero value and drain existing publication attempts before rotating the authorized source and trusted definition. Preserve and inspect those attempts; the old merge-keyed and new evidence-keyed concurrency groups do not share a lock. Publish a durable ref for the reviewed source before authorizing it. Reconcile the committed evidence head through the existing protected configuration and capture procedure, preserving source and evidence commit distinctions.
4. Obtain actual native execution and the protected capture/finalizer results for the final tuple. Before the first qualifying CI event for `E`, make its authorization and evidence policy coherent. A failed candidate needs its legitimate repair and a new evidence commit; no namespace deletion or status rewriting restores it.
5. Require terminal checks, independent review, verified evidence and the final exact-source protected landing procedure for PR #1160. Retain all failed, incomplete, unavailable and skipped results separately.

This definition update does not establish per-pull-request enforcement for pull requests sharing one head. The retained landing auditor, duplicate-head checks and actual App/protection acceptance remain distinct requirements. It also does not provision the external App used by isolated platform experiments.

## Validation boundary

The four runtime files are the same bytes reviewed and exercised in the foundation composition. The existing `scripts/tests/check-security-definitions.test.py` stays in ordinary CI and is ported to the new dedicated-check and bounded-history contract. The foundation's complete source contract checker stays with the foundation; it is not imported as an unrelated prerequisite. Exact validation receipts and prerequisite PR checks determine acceptance.
