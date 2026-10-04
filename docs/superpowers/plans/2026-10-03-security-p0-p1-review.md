# Security P0/P1 review and repair plan

> Execute inline under the user's explicit review-and-fix authorization. Keep new
> roadmap features paused. Read-only reviewers inspect existing security changes;
> one implementation and Cargo owner applies and verifies the repairs.

**Goal:** Review the existing security changes at `a99437b3ea`, repair confirmed
P0/P1 defects, retain regression evidence, and publish the qualified repairs.

**Architecture:** Preserve the current authority owners and public cursor
contracts. Revalidate mutable conditions at their existing commit boundaries.
Do not introduce Mercury proof-format work or expand lower-severity findings.

**Tech stack:** Rust, SQLite, Tokio, existing native HTTP and receipt fixtures.

**Requirements:** September 25 assurance closeout, September 26 engineering
standard, October 1 execution/compliance reviews, and the user's October 3
instruction to fix P0/P1 issues before further roadmap execution.

## Constraints and review focus

- Fail closed with an exact rejection and no downstream effect or lost row.
- Preserve valid initialization, ordinary encoded path values, retained cursor
  pagination, and completed retention rotations.
- Keep lifecycle admission and terminal transitions under the same state lock.
- Check retention eligibility again under the destructive transaction's lock.
- Authenticate archive payloads and validate their unsigned cursor projections.
- Retain every failed command separately. Local checks do not establish hosted,
  merge, release or operational acceptance. Preserve untracked historical evidence.

## Review and publication preflight

- [x] Refresh origin and inspect security worktrees and branch publication.
- [x] Verify all 28 selected security branch tips are already published; no
  pending security source edits precede this review.
- [x] Complete authority, storage, runtime and release/gate review dispositions,
  preserving the two incomplete independent review attempts.

## Candidate repair tasks

Each candidate requires a failing production-boundary regression before a fix.
The execution record assigns final severity and records refuted candidates.

1. **Retained receipt cursors.** In `receipt_store/retained_projection.rs`,
   validate archived source sequences against the live allocator and live rows
   and count every committed source/lineage candidate without trusting archive DDL
   before merging. Add collision and future-sequence controls in
   `evidence_export/tests/retained_tests.rs`; preserve valid single-row pages and
   copied but uncommitted archive tails.
2. **Retention eligibility race.** In
   `receipt_store/evidence_retention.rs::delete_archived_prefix_in_tx`, recompute
   `compute_archival_watermark` bounded by the exact selected checkpoint under
   the immediate transaction before deletion. Apply the verified ceiling inside
   candidate selection because dependency eligibility is not monotone.
   Add `delete_races.rs` coverage for a nonterminal reconciliation added after
   selection but before copying; assert exact refusal and surviving live rows.
3. **MCP lifecycle admission.** In `session_core/session.rs::send`, serialize
   current lifecycle/deadline validation and enqueue with terminal transitions.
   Test stale handles after close/drain/expiry with a live input receiver, plus
   initialization and ready-state positive controls and queued HTTP requests.
4. **API path interpretation.** In `evaluator.rs` route matching, reject encoded
   path structures that can be decoded into a different authorization target.
   Add native proxy tests proving refusal before upstream effects and preserving
   ordinary escaped parameter values. Do not broaden route authority.
5. **EV1 paging disclosure.** The existing review calls raw receipt paging High
   for deployments using alerts. Reproduce blocked arguments, denial text, guard
   details and metadata reaching both paging HTTP bodies. Replace automatic
   full-receipt notification payloads with a receipt-reference allowlist and
   remove raw denial reasons from summaries. Keep critical severity and receipt
   correlation. Full signed-receipt minimization, erasable storage and general
   SIEM projections remain the separate, uncompleted EV1/EV2 work.

## Qualification and delivery

- [x] Reproduce each accepted defect, apply minimal owner fixes, and rerun controls.
- [x] Run affected owner suites, strict Clippy, formatting and changed source gates.
  Retain the failed broad run and match every failed test to a passing rerun.
- [x] Resolve reviewer findings, record lower-priority and unqualified boundaries.
- [x] Correct the current queue to exclude the withdrawn Mercury follow-on.
- [x] Archive review/commands, commit and push, verify exact remote head and clean
  tracked state. Stop before new roadmap feature work.
