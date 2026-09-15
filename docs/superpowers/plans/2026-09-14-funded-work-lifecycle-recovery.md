# Funded Work Lifecycle Recovery Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` inline in the existing isolated research worktree. No agent dispatch or changes to the active security worktree.

**Goal:** Preserve the exact signed transaction across actual rail-worker loss at claim submission, verifier decision, earned payment and refund, including later re-observation after contract state advances.

**Architecture:** Extend the existing recovery harness through one optional `railAction` callback in `runW0`. Keep one durable outbox per relay/seller actor so consecutive operations share immutable nonce ownership. Reuse the keyless worker and existing private-chain verifier; do not add another financial state machine. A lifecycle runner executes real W0, kills each action worker at the selected boundary, recovers, and re-observes earlier operations after later effects.

**Tech Stack:** Existing Python/SQLite, locked Node/ethers/Ganache and Solidity fixture, existing Rust/Python checker. No dependency or native schema changes.

**Spec:** P13/P14 in [roadmap](../../market/open-agent-work/04-roadmap.md), [F1 contract](../../market/open-agent-work/execution/02-contract-draft.md), [recovery profile](../../../examples/funded-work/RECOVERY.md).

## Constraints

- Native Tasks 3-4 remain gated until Security M4 has a committed qualified checkpoint. Local passing gates in an uncommitted closeout are progress, not a selected integration base.
- Only private in-process Ganache and mock tokens. Owner-local journals, trusted host/verifier/RPC and no public finality claim.
- Keep existing payment-only reproduction/API and historical evidence working.
- No replacement transaction or nonce, no journal reset/eviction, no synthetic W0 decisions in lifecycle tests.
- Kill only owned rail-worker processes; the orchestration parent and chain remain alive. Funding/deployment/setup are still outside this recovery slice.
- Exact transaction observations can remain verifiable after later contract transitions; do not require the allocation to remain Submitted or Payable forever.

## Task 1: execute every post-funding action through the durable worker

Files: `contracts/scripts/work-claim-w0.mjs`, `work-claim-recovery-harness.mjs`, new `work-claim-lifecycle.mjs` and `work-claim-lifecycle.test.mjs`.

- [x] Add a failing actual accepted-W0 test requiring recovery records for `submit`, `decision`, `pay`, three SIGKILL signals, stable transaction/hash/nonce, exact balances and one included transaction per operation. Run only this test and retain the expected failure.
- [x] Generalize `recoverPayment`'s existing mechanism into `recoverRailAction({f, allocation, actor, agreement, action, args}, state, killPoint)`, using `rail-<actor>` directories. Preserve the old wrapper's `rail.sqlite`/config layout. Check an existing config against reconstructed owner/domain/path and reuse it without overwriting.
- [x] Add `railAction` to `runW0`; route submit, decision, payment, rejected refund, timeout refund and parent refund through it when selected. Preserve direct behavior and old payment-only callback. Return ordered `railRecoveries` with action labels and prepared intents.
- [x] Add `runLifecycle(scenario,state,killPoint)` and a standalone CLI. After each recovered action, reopen all earlier operations with the keyless worker against the live chain; require identical inclusion and no broadcast. Return these actual re-observations with the run.
- [x] Run accepted W0 and all existing payment-only/W0 checks. Commit the bounded implementation after review.

## Task 2: qualify the complete crash matrix and negative boundaries

Files: lifecycle tests plus existing rail-core/journal tests when a reproduced defect requires a repair.

- [x] Parameterize actual accepted, rejected, missing-custody and child runs over all four kill points. Accepted actions are submit/decision/pay; rejected submit/decision/refund; missing-custody submit/refund; child submit/decision/parent-refund/pay. Verify 16 cases and 48 killed workers, stable original authority, no extra send, exact terminal accounting and unique occupied nonce per actor.
- [x] Ensure rejection retains a negative signed decision; custody outage retains no decision; child parent refund occurs while the child remains unpaid and Payable. Re-observe prior inclusion after Paid/Refunded transitions.
- [x] Exercise existing action/calldata/agreement/receipt substitution guards with non-payment actions if the existing core tests leave those bindings untested. A deliberately removed relevant guard must fail the intended test in an isolated copy.
- [x] Run the targeted Python suite, lifecycle matrix, recovery core, payment-only and existing W0/contract regressions. Retain source hashes and selected commands; do not claim untouched native suites were rerun.

## Task 3: record results and refresh the next integration decision

- [x] Retain a standalone child lifecycle and reopen the real outboxes after all worker processes exit. Publish public signed artifacts and crash/chain evidence, never generated fixture keys.
- [x] Refresh M4 local/PR source and closeout status read-only. If qualification is still incomplete, record the concrete pending requirements; if committed closeout becomes available, assess the separate integration candidate before native edits.
- [x] Verify original source and historical evidence preservation. Commit the execution report, manifest, updated program/vertical-slice status and reproduction instructions. Native completion remains a separate claim.

## Execution result

Implementation: `331bd1bf8cd347c3b2cc70aaee459894bc5218df`. All tasks in this
independent lifecycle plan completed. See the [execution report](../../market/open-agent-work/execution/12-lifecycle-recovery-results.md)
and [manifest](../../market/open-agent-work/execution/13-lifecycle-results.json).
The read-only merge-tree adds a concrete conflict inventory. No combined native
candidate, security-worktree change or native-store migration was performed.
