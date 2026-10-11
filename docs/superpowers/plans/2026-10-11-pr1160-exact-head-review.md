# PR #1160 exact-head review repair plan

> **For agentic workers:** Use superpowers:executing-plans for Root integration and superpowers:test-driven-development for each repair. Claude owns isolated producers; Root alone integrates and pushes.

**Goal:** Address all four findings in the review of `9e9cf98942`, retain honest evidence, and qualify one replacement candidate.

**Architecture:** Preserve typed refusal at authority and payment boundaries. Maintenance returns safe scan progress without skipping deferred work. Authenticated checkpoint deltas bound retained row growth while preserving the five-event replay cadence and immutable v1 history.

**Tech Stack:** Rust, SQLite, existing signed canonical records, GitHub Actions.

**Spec:** [Exact-source review](https://github.com/bb-connor/arc/pull/1160#issuecomment-6109135494), existing security landing ledger, and coordination decisions in `coord/pr1160`.

## Constraints and review focus

- No acceptance, ratchet, byte, clock, or proof-domain waivers. No new manual proof campaign or authorization rotation.
- Preserve errors when a first eligible row cannot fit; distinguish safe cursor progress from payload erasure.
- A poisoned rotated signer must not install a stale trust key or issue a capability.
- Checkpoint growth controls must cover growing live state, authenticated deletions, legacy history, corrupt delta chains, and reopen.
- Missing original payment debit must retain liability and quarantine, never substitute exposure for a debit.
- Local results are source-scoped. Four required checks must report before the next batch push; landing requires exact-head green checks, classified residuals, addressed review, and user go-ahead.

## Task 1: Retained-prefix compaction progress (Root)

Files: `crates/platform/chio-store-sqlite/src/tool_outcome_store/payload_compaction.rs`, `tool_outcome_store_tests/compaction_cursor.rs`, fixture helper and test module wiring.

- [x] Trace `ReplayOwners::ByteDeferred`: `page.compacted == 0` discards safely retained prefix progress.
- [x] Add actual signed stream/value completions with deterministic request identities and both clock domains; measure the value's replay reads and restore its exact raw bytes.
- [x] Observe Original refusing the first page instead of returning its retained-prefix cursor.
- [x] Refuse replay byte deferral only when the scan cursor has not advanced. Keep the deferred row after the returned cursor.
- [x] Prove a zero-compaction first page resumes under the identical cap, stream bytes remain, value bytes are erased only after verification, and existing first-row refusal controls still pass.
- [x] Run owning compaction tests and strict store Clippy; get independent review and enroll the regression in the existing gate if applicable.

## Task 2: Fallible current signing identity (Claude)

Files: `crates/core/chio-core-types` signing backend trait, `crates/security/chio-keyring/src/router.rs`, kernel governed authority, owning tests and `scripts/check-keyring-transparency.sh`.

- [x] Reproduce rotation then real lock poison with the independent-services fixture.
- [x] Add fallible `SigningBackend::current_public_key`; override router lookup; use it for governed trust and issuance. Errors produce an empty trust set or typed issuance refusal.
- [x] Pin public composition trust/issuance failure and document remaining compatibility identity accessors with their consumer scope.
- [x] Run owner tests and strict lint, update exact inventory, and independently review the composed change.

## Task 3: Authenticated delta checkpoints (Claude, shared pins Root)

Files: `admission_operation_store/security_participant_state/checkpoint{.rs,/record.rs,/rows.rs,/delta.rs}`, wire fixtures, store tests, `scripts/check-flow-security.sh`. Root owns `spec/wire-schemas.lock`, formal source anchors, coverage and landing ledger.

- [ ] Demonstrate growing-live-set full-image archive amplification on Original.
- [ ] Keep v1 keyframes byte-identical; add v2 authenticated deltas and size-triggered keyframes. Preserve cadence, immutability, current-image authentication and schema compatibility refusal.
- [ ] Verify tombstones, duplicate/missing/reordered/mixed-base rejection, burst keyframes, bounded latest reconstruction, growing-state retained rows, crash/reopen and legacy v1.
- [ ] Quantify retained rows and verification work independently; do not claim linear CPU merely because delta storage is linear.
- [ ] Run owning tests/strict and unchanged native cadence controls. Review before shared pin renewal; no new manual proof execution.

## Task 4: Exact legacy prepaid quarantine control (Claude)

Files: `crates/kernel/chio-kernel/src/kernel/tests/durable_admission/payment_recovery/legacy_settled_prepaid.rs` and test module wiring. Production payment code remains fail-closed.

- [ ] Pair real SQLite v11-to-v12 migration/backfill controls with a kernel settled-PrepaidFinal recovery control modeling the resulting legacy row.
- [ ] Require exact `LegacyPaymentAmountAbsent`, retained Finalizing operation/settled journal/hold/exposure, no refund/capture/release, and one original invocation.
- [ ] Label this existing-behavior evidence as a control, not a failing Original. Disclose the unavailable original-debit/operator-recovery limitation.
- [ ] Run owner tests/strict and review; reply to the finding with exact evidence.

## Task 5: One qualified replacement (Root with Claude triage)

- [ ] Review and compose isolated commits; reconcile all four findings in the ledger and PR response.
- [ ] Renew affected inventories, source anchors and generated coverage without changing models; run local changed-boundary and static gates.
- [ ] Classify every hosted failure on `9e9cf98942`; wait for its four required checks to report, then publish one reviewed batch.
- [ ] Verify replacement head, required checks, review feedback and residual classifications. Report readiness and await explicit merge approval.

### Root qualification checkpoint

Source `7f9273387b`: final original-production regression fails as intended;
repaired compaction **23/0** and strict all-target store lint pass. Claude
approves production `14d2f8c935` and deterministic fixture `4180df8fb7`.
Static checker repair `7f9273387b` also has approval, eight positive checks
and three rejected mutations; run `python3 scripts/check-apalache-formal-slice.py`
in final local prepublication gates. See the source-scoped
[repair audit](../../security/audits/compaction-static-repairs-20261011.json).
Keyring, checkpoint, prepaid control and final composition remain pending.

### Keyring source qualification

Source `b4af756f20` has 73 passing composed owner tests, a passing exact-panic
renewal and strict all-target lint for core types, keyring, kernel and control
plane. The [audit](../../security/audits/keyring-current-selector-20261011.json)
retains the genuine Original and initial static failures. Claude approved the
exact source and final panic assertion. Checkpoint and prepaid acceptance stay
open. The prepaid control will call periodic recovery after the initial tool
call, because that call already completes the startup latch; this exercises the
shared recovery page without resetting private runtime state.
