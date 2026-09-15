# Native contractual resolution and earned child implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development for independent native work, with inline integration and independent review. The user explicitly authorized this delivery block; continue through local qualification and commit.

**Goal:** Resolve observed contractual refunds without falsifying native execution or consumed budget, then prove a separately funded child remains payable after the native parent dies.

**Architecture:** Add a qualified, append-only capture-waiver successor to the original native payment. Original signed terms authorize the bounded resolution; receiver-owned verification supplies exact refund evidence. Ordinary finalization recognizes the completed successor while preserving the original positive pricing and budget event. A parent native tool invokes a separately authorized child, the child reaches observed Payable, the parent receives actual SIGKILL before returning, and retained child authority collects after the parent allocation refunds.

**Tech Stack:** Existing Rust kernel and SQLite owner fencing, canonical JSON and Ed25519, funded W0 example, pinned Python checker, owned Ganache and existing mock ERC20 escrow.

**Spec:** The accepted next-delivery instructions and the remaining boundaries in `docs/market/open-agent-work/execution/19-native-finding-claim-settlement.md`; Task 4 of `2026-09-14-funded-work-claim-escrow.md`.

## Constraints and design rulings

- Work only in `/home/connor/backbay/arc-funded-integration` on the existing funded branch, starting at `5257f963d869d89c7a54384ea88628cf727c32c8`.
- Preserve the original paper checkout and other agents' worktrees. Review committed security deltas read-only before selecting any prerequisite.
- No external chain, real money, push, PR, merge or deployment. Local commits and disposable owned fixture processes are authorized.
- A refund is not a successful capture. Keep original capture intent, raw outcome, pricing and positive budget reconciliation. Do not reuse unknown release or contractual zero-charge semantics.
- Require explicit original signed waiver authorization, exact original capability/request/operation/hold/authorization and receiver-pinned observation authority. A decoded record or RPC response alone cannot authorize resolution.
- Store acceptance and completion are fenced, append-only, source-validated, globally committed and recoverable. New transitions must fail closed on missing or conflicting authority.
- Financial metadata reports zero paid for waived capture and independently retains consumed budget. Unknown execution stays unknown.
- Parent and child have separate agreements, allocations, native authorities and original requests on one owned chain. The child payout uses retained child authority after parent death. Report exact payer/intermediary/child balances and losses.
- This remains a one-host private-chain witness. Registered general work formats, complete Finding facets, independent companies and sustained capacity remain later gates.
- No em dashes; no production unwrap/expect; strict Clippy; no fabricated state or database edits for recovery.

## Task 1: Qualified native capture waiver

Files: new `crates/kernel/chio-kernel/src/payment/contractual_resolution*.rs`, payment journal/terminal code; new SQLite successor store/schema and existing owner-chain/participant checks; focused unit and SQLite integration tests.

- [x] Write tests showing a positive captured-cost intent cannot be resolved by an ordinary refund/release or forged authority.
- [x] Implement signed scoped terms, verified resolution, distinct effective terminal journal, append-only acceptance/completion and exact positive budget-source validation.
- [x] Make native finalization and replay accept only the qualified financial successor, report zero paid and preserve actual consumed cost and original outcome.
- [x] Exercise altered identities/signatures/policy/evidence, stale owner/time, already-paid refusal, active-owner capture exclusion and a synchronized conflicting-waiver race, source tampering, restart and no second budget event.
- [x] Run selected Rust tests and strict Clippy; obtain independent source review before integrating.

## Task 2: Funded resolution adapter

Files: funded agreement/policy, native/journal/rail, new resolution module and lifecycle harness.

- [x] Extend original signed funding terms with the explicit waiver policy; qualify evidence only after independently observing the exact refund.
- [x] Retain the original resolution request before native acceptance; resume it after process loss without issuing replacement authority.
- [x] Exercise rejection, absent claim, unavailable verifier and missed deadline through completed native financial resolution. Preserve unknown and undispatched distinctions.
- [x] Kill workers after retained resolution, native acceptance and completion; check original identities, immutable capture/budget history, zero paid and unchanged execution count.

## Task 3: Native parent loss and independently payable child

Files: owned chain observer and tests, funded native tool hook/child module, process harness and CLI.

- [x] Write a failing subprocess witness for a child still Payable and unpaid at actual parent SIGKILL.
- [x] Provision separate parent/child funding and native authorities, a signed dependency over original requests/agreements and exact shared input, and fixed receiver-owned observer sockets.
- [x] Execute the child through its kernel from the parent tool; independently verify Finding and record acceptance, then kill the parent before native return recording.
- [x] Refund the parent allocation, then restart child collection from its retained authority. Assert parent unknown without replay, child executes once and completes, and one exact payout survives parent failure.
- [x] Independently inventory all mined transactions and balances, verify no parent signature/new authority is needed after death, and exercise child payout loss before/after broadcast.

## Task 4: Review, qualification and local closeout

- [x] Reconcile the pinned security audit and incorporate only necessary committed prerequisites with explicit source records.
- [x] Run all standalone Rust tests including external-chain tests, native SQLite/payment recovery tests, affected store/kernel tests, existing funding/lifecycle/Python/contract regressions and the new child witnesses.
- [x] Run required format, Clippy, schema/generated/formal/source hygiene checks selected by the actual shared diff. Record unavailable gates accurately.
- [x] Obtain independent review, fix findings, retain public source-hashed evidence, update the broad roadmap and commit locally with a clean worktree.
