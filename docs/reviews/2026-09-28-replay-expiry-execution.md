# Replay, expiry and lease accounting execution

Date: September 28, 2026. Base: `253be7fe04e72068e287aa6affee44dff8d8128f`.
Branch: `packet/3-retention-accounting` in `/tmp/arc-security-launch`.
Scope: the approved five-part replay/expiry batch from engineering-excellence
corrections 3A, 4A and 4B, Packet 8, and rejection provenance in these owners.

## Delivered behavior

Durable nonce and governed-approval stores, replay-source opening, finding receipt
outbox leases, kernel nonce/delegation admission, and the serving owner accept the
shared `Clock` port. Clock failures retain their source. Wall and monotonic
regression deny access; neither becomes a zero or clamped timestamp. Budget
handles, including handles composed by admission operations, share their serving
owner's clock and fence. The fence starts with the serving-open observation, so
regression before the first budget mutation is also refused.

Replay retention uses the shared 300-second unexplained-skew policy. It does not
widen a signed authorization window. The durable replay clock retains the existing
two-sample stable-forward-jump rebaseline policy and validates the durable lower
bound before publishing a new anchor. Stores resample and validate time inside
the serialized reservation after any writer-lock wait. Expiry, clock failure and
capacity refusal roll back the attempted mutation. Owner-specific pre-effect
rollback remains available during clock failure.

`ExecutionNonceStore` now requires signed expiry, owned dispatch reservation,
exact-owner rollback and consumption lookup. The expiry-free API, capability
probe/default implementations and delayed consumption state machine are removed.
Existing nonce databases require current schema metadata and ownership/clock
columns; the store refuses obsolete schemas without silently adopting them. The
in-memory implementation keeps exact epoch deadlines in a bounded map. It never
evicts a live marker, extends a retained nonce on retry, or admits with zero
capacity. Kernel commitment prevents later rollback from erasing replay custody.

Checked arithmetic covers replay retention and skew/correction bounds, approval
lifetimes, revocation-snapshot age, cumulative seconds-to-milliseconds conversion,
the original 30-second finding claim window, outbox elapsed time and lease expiry,
the scheduler scan successor and lineage-renewal cutoff. The cutoff must fit the
SQLite integer domain before scheduler rows can change.

Clock, nonce, approval-window/lifetime and revocation freshness failures retain
distinct codes through kernel error reports. Public nonce verification preserves
the underlying store error, including capacity and clock anomalies. A failed
credential cleanup retains the original cause and records the cleanup failure.
Root and nested denial receipts carry `chio_kernel.rejection_code`, covered by the
receipt signature; operator warnings carry the same code.

## Inventory and source gates

The retained 638-site arithmetic census has 238 classified entries: 107 fixed,
six removed APIs, 85 fixture-only entries, and 40 other reviewed bounds or
bookkeeping dispositions. This batch adds 25 fixes, two removed APIs and 65
fixture classifications. The remaining 400 entries are explicitly pending.
Fixture classification is not a claim of 65 production fixes.

The ambient-clock inventory shrinks from 206 to 198 sites without additions. It
includes fixtures and is not a count of fully migrated production owners. Trust
boundaries remain at 44 constructors, 85 tenant tables and 170 SQL principal
contracts. No SQL principal contract was weakened. Oversized test fragments in
the native nonce fixture become ordinary modules; file/fragment caps and expiry
dates are not increased.

## Verification

Evidence directory: `/tmp/chio-replay-expiry-20260928/`.

| Boundary | Final local evidence |
| --- | --- |
| Kernel nonce, credentials, delegation, approvals, finding and root/nested dispatch | `kernel-focused-final.log`: 175 passed. Includes signature verification of denial receipts with exact clock/window codes and no tool invocation. |
| Durable replay, finding outbox and transaction-time lease checks | `sqlite-focused-final.log`: 105 passed. Includes restart, no window extension, clock faults, writer-wait expiry, rollback ownership and SQLite-range overflow without new scheduler rows. |
| Public nonce store API | `nonce-integration-final.log`: eight passed through the required signed-expiry/owned-custody interface. |
| Budget and serving clock ownership | `budget-clock-final.log`: five passed, including an authority-bound hold, regression immediately after serving open, shared fencing across handles and clock failure on a newly derived handle. |
| Strict library lint | `clippy-final.log`: security types, kernel, SQLite and control plane pass `-D warnings` after the final serving-fence change. |
| Downstream API compilation | `control-plane-test-check.log`: control-plane unit/integration test targets type-check. `downstream-check.log`: CLI binary and Rust verdict-matrix driver type-check. These are compile results, not native or conformance runtime qualification. |
| Registry and source gates | `error-codegen-check.log`: generated error registry is synchronized. Clock, arithmetic, negative-assertion, trust-boundary and file-hygiene gates pass. The negative baseline shrinks from 1,282 to 1,278 assertions without raising caps or extending expiry. Formatting passes for all 59 changed Rust files; `git diff --check` passes. |

The 293 owner and integration cases above are distinct tests, not accumulated
counts across retries. The arithmetic checker reports zero unchecked sites in its
configured scope; the separate 400-entry pending semantic census remains open.
Downstream API checks precede the private serving-fence initialization correction;
the refreshed owner build, five budget-clock cases and strict lint verify that
final implementation. No public signature changed in that correction.

Early compiler and test failures remain in that directory. Compiler corrections
covered moved fixture imports, helper visibility, the serving-owner clock shared
by admission-derived budget handles, and removal of old nonce implementations.
Earlier test failures exposed old deferred-consumption/error expectations and
an expiry fixture depending on ambient thread-local time. That fixture now drives
the injected clock. The new serving-owner test must use the same private lock
and database-directory permissions as production provisioning. Its initial use of
the standalone increment API was refused by the serving owner before time
evaluation. The final test uses an authority-bound composite hold and checks its
positive authorization before testing cached-retry clock refusal.

## Remaining acceptance

This batch does not complete corrections 3A/4A or the entire roadmap. The remaining
arithmetic census, ambient-clock and deadline classification, full signed-reader
and tenant matrices, broad module/pool work, historical retention stall,
sustained fuzz/scale campaigns, privileged native execution and hosted candidate
qualification remain separate work. Existing explicit replay-source transfer
protocols are unchanged. No push, merge, publication or operational activation is
part of this execution.

Work was performed inline without subagents. Verification targets changed owners
and consumers; a broad workspace suite and costly graph-index rebuild are not
acceptance claims for this batch. The preexisting `output/` directory is preserved.
