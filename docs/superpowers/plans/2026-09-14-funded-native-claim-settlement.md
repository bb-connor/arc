# Native Finding, claim and settlement implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline, task by task. The user has authorized execution and local qualification.

**Goal:** Complete the private funded W0 path through independently checked Finding submission, observed claim, payout and refund without replacing the original native identities.

**Architecture:** Export the exact retained native outcome into bounded content-addressed custody. A signed experimental submission binds that evidence, a native Finding artifact, the original agreement, allocation, request, operation, hold and authorization. A separate verifier checks the artifact and custody, reruns the pinned Python W0 checker, and signs one decision. Persist exact signed EVM transactions before broadcasting, then independently verify inclusion, immutable terms, events and token transfers before acknowledging money to the native rail.

**Tech Stack:** Rust, existing SQLite authorities, RFC 8785/Ed25519, existing Python W0 checker, ethers, local Ganache and the existing experimental ERC20 escrow.

**Spec:** Task 4 of `2026-09-14-funded-work-claim-escrow.md`, continued from `2026-09-14-funded-native-admission.md`.

## Constraints and evidence boundaries

- Preserve the source checkout and security worktree; work only in the existing funded integration worktree.
- No external chain, real money, public finality, deployment, push or merge.
- Keep the existing funding-only CLI and SIGKILL witnesses valid.
- Strict canonical bytes, exact signatures and identities; bounded custody and insert-once journals.
- No fabricated completed native receipts. Before payment the native outcome is durable but the final receipt is not available. The prepayment Finding therefore makes `asserted` evidence/guarantee claims. Payment additionally requires explicit native-outcome, custody and independent W0 checks. This experimental decision is not a general 13-facet Finding verifier report, bond backing, runtime attestation or status-liveness qualification.
- Missing authority or custody produces no decision. A retrieved, authenticated incorrect result may receive a signed rejection.
- A verified ERC20 refund is release of this rail's reversible allocation, never a successful native capture. Preserve any native capture intent or unknown execution until its own authority can resolve it; financial closure must not erase execution state.
- Implementation changes reject old experimental state. Reproductions start new state with this implementation, then retain those same identities through the entire run and recovery.

## Task 1: Evidence and Finding decision

Files: `examples/federated-work/src/funded_work/{evidence.rs,verification.rs,journal.rs,native.rs,agreement.rs}`, `examples/funded-work/native_checker.py`, Rust tests.

- [x] Add failing tests for canonical Finding/submission verification, exact original binding, missing custody, substituted native outcomes and incorrect retrieved results.
- [x] Read retained native outcomes through the qualified store API, verify content references and retain bounded custody blobs and insert-once submissions/decisions.
- [x] Issue conservative native Finding artifacts; sign an experimental decision with a separately pinned verifier key only after independent Python W0 reproduction.
- [x] Run the focused Rust and checker tests.

## Task 2: Observed claim and money

Files: `funded_work/{settlement.rs,settlement_observer.rs,rail.rs,local_chain.rs}`, `contracts/scripts/work-claim-native-observer.mjs` and tests.

- [x] Add failing tests for altered allocation, original hold, transaction, commitment, decision, event, amount, inclusion and stale/unavailable observations.
- [x] Persist exact prepared transactions before broadcast. Reuse the existing transaction decoder/reconciler and validate every retained transaction before reuse.
- [x] Observe timely claim, verifier decision and exact outgoing ERC20 payout/refund under the existing two-descendant private-chain profile.
- [x] Make native capture acknowledge only a verified payout; make release acknowledge only a verified refund on the original identities. Retain uncertain and incompatible native state.

## Task 3: Process recovery and qualification

Files: new lifecycle CLI/harness, `FUNDED.md`, new execution report and source-hashed public evidence.

- [x] Reproduce valid payout, authenticated invalid-result refund, absent-submission timeout and unavailable-verifier timeout.
- [x] Kill the native worker around submission persistence, transaction preparation/broadcast, observed claim, decision persistence and payment observation. Restart with exact original artifacts, transactions and native identities; never edit databases to recover.
- [x] Independently reconstruct balances, transaction counts, native operation/hold counts and actual execution count.
- [x] Run formatting, standalone tests and strict Clippy, existing Python/contract regressions and relevant native SQLite tests; expand only for shared changes.
- [x] Obtain independent review, address findings, record source hashes and results, and commit locally.

## Result

The bounded slice is locally qualified. The [execution report](../../market/open-agent-work/execution/19-native-finding-claim-settlement.md) and [source-bound manifest](../../market/open-agent-work/execution/20-native-claim-evidence.json) record the implementation, selected checks, actual worker losses, review corrections and remaining Task 4 boundaries. The original source and other worktrees remain preserved; integration stays on the local funded branch.
