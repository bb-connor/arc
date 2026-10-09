# Final foundation review repairs

**Objective:** Repair FINAL-F01 through FINAL-F11 from the independent review of
candidate `63ae9a4f5c`, preserving receipt and authority integrity. Publish only
after the repaired candidate has local acceptance and independent delta review.

**Execution:** Root remains the only integration writer. Existing authorization
covers implementation, integration, qualification and protected landing. Claude
and two isolated Rust helpers deliver source-bound commits. The coordination
board records path ownership and handoffs. No proof campaigns are authorized;
KANI-PROOF-QUAL remains OPEN/UNPROVED under the recorded owner amendment.

## Contracts and ownership

| Findings | Owner | Required behavior |
| --- | --- | --- |
| F01 | Claude | Distinct native sessions cannot exhaust current-state rows permanently. Preserve taint, membership, replay protection, pending fences and authenticated recovery. Never silently reset a reused session ID. |
| F02 | Claude | Every admitted passport and certification record retains enough capacity for terminal revocation and exact read-after-reopen. A shared fixed reserve is insufficient. |
| F03 | Export helper | Tenant evidence export uses authenticated, bounded request work independent of unrelated history. Preserve complete selected evidence, attribution, proofs and tenant boundaries. Full local operator exports remain explicit offline work. |
| F04 | Root | Transient backing exhaustion is recoverable and distinct from the configured quota. Actual quota exhaustion retains finite limits and an explicit recovery contract; no permanent silent latch or automatic unbounded allocation. |
| F05-F08 | Root | Reconcile current acceptance with the owner proof amendment and completed capacity evidence, explicitly distinguish encoding noncollision from SHA assumptions, account for duplicate review IDs, and remove internal host aliases. Preserve historical source/evidence hashes and prior states. |
| F09 | Root | Public health uses nonblocking, process-owned telemetry. It never takes receipt admission or the snapshot database lock, and its watermark identifies the sampled observation. Authenticated reads keep their original integrity checks. |
| F10 | Cluster helper | Public forwarding has an independent bounded lane; cancellation retains its permit until work terminates. Authenticated forwarding retains its own capacity. |
| F11 | Cluster helper | Explicit bounded issue-time tolerance does not weaken expiry, signatures, epochs or replay. A stale replicated authority refuses trust reads and reports degraded health until verified synchronization recovers. |

## Task 1: Complete report and fixture acceptance

1. Verify producer hashes, review and integrate `0c82063475` report repair.
2. Run the three owning script suites using their inert proof-tool fixtures.
   Expected: all pass, open residual named last, decision inputs source-bound,
   and ordinary crate names cannot be confused with internal record tags.
3. Integrate the related Creusot contract fixture dependency repair after its
   unchanged-source failure and passing repaired fixture are retained.
4. Record terminal CLI tests and strict lint; keep hosted acceptance separate.

## Task 2: Repair receipt health and snapshot recovery

**Files:** `receipt_query_snapshot/service.rs`, a focused service health module,
`receipt_query_snapshot/db.rs`, owning snapshot tests, control-plane
`receipt_query_service.rs` and `receipt_query_snapshot_tests.rs`.

1. Reproduce public health's dependency on an exhausted receipt read lane.
   Expected Original: health reports busy instead of ready.
2. Add walker-maintained resource telemetry and a nonblocking health read;
   retain the existing inspecting status API for operators and integrity tests.
3. Test held snapshot locks, exhausted admission, invalid/stopped phases, and
   coherent sampled watermarks without timing-based success claims.
4. Reproduce SQLite FULL misclassification without filling the host filesystem,
   and reproduce failure to resume after a one-shot capacity fault clears.
5. Implement explicit bounded resource retry/recovery. Test transient recovery,
   actual quota refusal, cancellation during backoff, and unchanged tamper refusal.
6. Run focused snapshot and HTTP tests, owning strict Clippy, format and boundary
   scanners. Retain all failures; do not amend baselines to waive them.

## Task 3: Integrate independent runtime repairs

1. Obtain F01/F02/F03/F10/F11 source contracts and Original RED witnesses.
2. Review each commit and evidence, check released paths, and cherry-pick in
   dependency order. Resolve conflicts explicitly with the owning lane.
3. Run composition tests at the touched boundaries and strict owning lint.
   Expected: session churn, terminal revocation, bounded tenant export, separated
   forwarding and skew/stale-authority controls pass without weakening refusals.

## Task 4: Reconcile the authoritative record

1. Archive the seven stale current states before updating acceptance. Preserve
   their historical requirement objects and existing evidence.
2. State encoding noncollision as UNPROVED independently of ASSUME-SHA256.
3. Record V13-V15 as consolidated duplicates of V10-V12, citing the planner's
   disposition. Keep the 28 distinct original findings unchanged.
4. Replace internal host aliases with generic execution-host descriptions;
   record old/new document hashes so existing historical bindings remain clear.
5. Add every new finding, repair, test evidence and remaining acceptance to the
   canonical ledger; renew generated coverage only after source changes settle.

## Task 5: Qualify the exact landing candidate

1. Refresh mailbox, PR threads and main; preserve new relevant review obligations.
2. Verify clean candidate, source-bound local evidence and no baseline waivers.
3. Request planner review of `63ae9a4f5c..candidate` and address confirmed blockers.
4. Publish the single integration candidate, verify the four protected checks at
   that exact SHA, and use the normal protected merge path.
5. Keep unproved Kani work and native/trusted/release follow-ups explicitly open.
   No release readiness claim follows from this foundation landing.

## Review focus

Check cancellation ownership, cross-tenant effects, snapshot publication and
freshness, recovery without resource-limit removal, registry worst-case terminal
growth, session-ID reuse, and future-issued versus expired authority envelopes.
Review ledger transitions as evidence changes, not as a rewrite of history.
