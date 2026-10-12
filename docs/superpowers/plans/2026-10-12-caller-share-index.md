# Caller-share index reconciliation plan

> Execute with superpowers:executing-plans in Root's native thread. Claude
> supplies an isolated test-only control and reviews the final source.

**Goal:** Close F038's unrelated-operation scan cost while retaining complete
caller-share accounting and the existing external-write custody fence.

**Baseline:** Private `fix/caller-share-index`, based on reviewed `9544a33d29`.
Current admission schema is v36. The preserved producer `be0d2b7ac0` is absent
from main and supersedes the earlier train5 pair. A current merge-tree check
applies it cleanly. This branch is the only v37 integration owner. Keep the
active #1201 / standby #1202 queue unchanged; no third PR or publication.

**Design:** Index immutable caller-share parent attribution in the same
transaction that first funds an operation. Query only the requested parent's
live/outcome-unknown operations plus every unresolved funded row. Fully verify
each selected operation and its retained request, and reject mismatched index
attribution. Backfill v37 atomically and verify index ownership/completeness on
restart. Keep existing store ownership, trusted clock and external-write checks.

**Boundary:** The earlier external-writer omission claim is withdrawn. External
connection writes must close serving-owner custody before indexed reads. This
proposal relies on the trusted owning connection, immutable retained requests,
central commit path and restart verification, not per-query authentication of
the whole index. Owner-connection corruption is an explicitly artificial
fault-isolation control. Same-parent history and outcome-unknown verification
costs remain; this is not full cold-state readiness or a globally constant-cost
snapshot. No cap, schema, clock, authority or proof waiver.

## Task 1: Genuine current Originals

- [x] Port the cfg(test) decoded-operation counter and existing O1 work control,
  without the index repair. Require evidence of 8 then 16 unrelated decodes.
- [x] Review and integrate Claude's isolated O2 fixture: funded parent A
  corruption through the owning test connection must leave actual parent B
  shares readable, while A refuses. Keep external-writer refusal as a separate
  positive security control. Do not add a public injection API.
- [x] Run current-base runtime Originals and preserve failures and successful
  controls. Compile/environment refusals are separate evidence.

## Task 2: Compose and verify the preserved v37 repair

- [x] Apply the single producer semantically on current source; keep current
  security fixes, canonical data, arithmetic checks and trusted clock usage.
- [x] Run O1/O2 to green plus index-once, unresolved refusal, parent parity,
  indexed query plan, v36 migration and missing/forged-row restart controls.
- [x] Renew external-write omission/tamper controls against the final candidate;
  retain the withdrawn allegation and the trusted-owner model explicitly.

## Task 3: Owning qualification and review

- [x] Run admission-store owning tests, execution_nonce_caller_execution,
  strict owning Clippy, formatting, clock/trust-boundary/static gates.
- [x] Obtain independent complete-source review; repair confirmed P0/P1/P2
  findings and renew affected evidence without ratchet exceptions.
- [x] Freeze the private candidate with a source/evidence audit, update the
  board/mailbox and release claims. Actual-main composition and exact-head
  hosted qualification remain future acceptance.

## Local completion

Both current Original controls failed at their intended assertions. The repaired
index and delegated-share controls passed, followed by the owning store and
caller execution suites and strict all-target Clippy. Claude approved the full
source with no P0/P1/P2 findings. The unchanged trust-boundary checker passes
after a separately reviewed, order-preserving correction to inherited F041
and F071 metadata. No raw debt or gate contract was weakened.

The source, review, failed attempts and command evidence are bound by
`docs/security/audits/caller-share-index-20261012.json`. This candidate stays
private pending actual-main composition, fresh hosted qualification and landing.
