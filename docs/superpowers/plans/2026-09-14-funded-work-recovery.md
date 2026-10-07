# Funded Work Review and Rail Recovery Plan

> **For agentic workers:** Use `superpowers:executing-plans` inline in the existing isolated research worktree. Do not dispatch agents or edit the active security worktree.

**Goal:** Fix custody decision starvation and preserve one exact financial transaction across actual worker process loss, without duplicate payment.

**Architecture:** Extend the independent F1 artifact/private-rail experiment while native integration remains gated. Reserve decision space when accepting a submission. Keep a separate owner-local SQLite journal of immutable transaction intents, exact signed bytes, occupied signer nonces and terminal observations. A recovery worker with no signing key validates retained bytes, observes the private chain and rebroadcasts only the original transaction when needed. The harness owns Ganache and forwards a narrow RPC set over local process IPC, so tests kill an actual worker without losing chain state or exposing a network RPC endpoint.

**Tech Stack:** Existing Python/SQLite, locked ethers/Ganache/Solidity, existing Rust/Python W0 checker. No dependencies or native kernel changes.

**Spec:** [F1 contract](../../market/open-agent-work/execution/02-contract-draft.md), [artifact profile](../../../examples/funded-work/PROFILE.md), native [integration gate](../../market/open-agent-work/execution/06-native-integration.md).

## Constraints and review findings

- Existing funded W0 happy/rejection/timeout/child behavior remains required.
- Review finding R1: the object byte quota can consume the space needed to record a pending claim's decision. Reserve bounded decision bytes atomically with claim binding; unrelated custody writes cannot consume that reserve. Retain existing decisions and fingerprints when upgrading only the known example custody schema.
- Review finding R2: the private rail harness has no durable transaction correlation. Signing a replacement after an uncertain broadcast could use a second nonce. Persist before broadcasting; bind operation, allocation, role, chain/deployment/code, payload, nonce, exact raw transaction and hash. Keep nonce ownership forever in this prototype.
- Review finding R3: local private-chain observations are trusted inputs, not a public finality proof. Recheck chain, deployment code, exact transaction and canonical block at reconciliation. Missing, reorged, unavailable or mismatched observations cannot create a financial terminal.
- Only local mock tokens. No external RPC, private external keys or live deployment. Recovery workers receive no signing key and may only resend the retained raw transaction.
- Full native funding admission, actual parent tool-process loss, Finding facets and original native hold correlation remain gated on qualified M4. A killed rail worker does not establish native execution recovery.
- Preserve source/security worktrees and historical evidence. New reports record current hashes and exact test scope. No em dashes.

- Review finding R4: hashing the expected checker file did not establish which module Python imported. Reproduced false acceptance with a shadow checker, then loaded and executed the exact pinned source bytes and explicit local dependency paths. Added subprocess shadow-import regressions.
- Review finding R5: future signer nonces could dispatch before earlier nonces resolved, and a corrupt nonce index could disagree with retained bytes. Added failing regressions; recovery now waits for the exact nonce and preparation audits every retained index before assigning another.

## Tasks

### 1. Fix custody liveness under capacity exhaustion

Files: `examples/funded-work/custody.py`, `test_custody.py`, `test_verifier.py`, `PROFILE.md`.

- [x] Reproduce a valid pending claim stranded by subsequent evidence filling the byte quota.
- [x] Reserve 4096 bytes per pending decision before accepting the submission. Enforce that decision bound and atomically consume its reservation only with durable decision storage.
- [x] Fingerprint the exact known v1 layout and upgrade to v2 transactionally. Reject unknown layouts or a legacy store unable to reserve outstanding decisions without deleting evidence.
- [x] Test capacity, exact retry, oversized decision, populated migration and failed-migration preservation; run existing custody/verifier checks and commit.

### 2. Add a durable transaction outbox and reconciliation worker

Files: `examples/funded-work/rail_journal.py`, `test_rail_journal.py`, `contracts/scripts/work-claim-recovery.mjs`, `work-claim-recovery-worker.mjs`, test files and fixture helpers.

- [x] Add failing immutable-intent, nonce-reuse, conflicting transaction/terminal and reopen tests.
- [x] Store one signed transaction and reserved terminal space per operation before any RPC broadcast. Bind one journal to one local owner and rail deployment. Never regenerate, replace or expire occupied signer nonces.
- [x] Validate retained raw transaction signature, chain, signer, nonce, destination and exact data before sending. Check pinned deployment/runtime and exact receipt/transaction/canonical block before recording observed inclusion. Do not label private-chain inclusion final.
- [x] Drive actual SIGKILL before broadcast, after broadcast before response, after receipt observation before journal commit and after durable terminal. Reopen and recover the same operation/hash/nonce, with at most one transaction included and one payment.
- [x] Test unavailable observations, deployment substitution, reorged inclusion, receipt mismatch and reverted transactions. Preserve uncertainty and deny replacement.
- [x] Run recovery around real W0 decisions and accepted payout; retain actual chain receipts/events, killed process signals, journal state and exact balances. Keep native claims gated.

### 3. Reconcile and retain evidence

- [x] Run targeted Python and Node regressions and an intentional negative calibration; review source and actual outcomes.
- [x] Refresh security local/PR heads and qualification read-only, verify original source preservation, and update the next-step map.
- [x] Commit implementation and public evidence with exact hashes, commands, trust assumptions and outstanding integration requirements.

## Execution result

All tasks above completed in the isolated research worktree. See the
[review and execution report](../../market/open-agent-work/execution/10-recovery-review-results.md)
and [source/evidence manifest](../../market/open-agent-work/execution/11-recovery-results.json).
This closes only this independent recovery plan; native Tasks 3-4 of the
vertical-slice plan remain gated. No security-worktree changes or merge occurred.
