# Funded W0 Artifacts and Custody Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` inline in the existing isolated research worktree. Do not dispatch agents or edit the active security worktree.

**Goal:** Produce a real bounded W0 result, verify its exact agreement and retained bytes, and authorize one private-chain escrow decision using the canonical decision digest.

**Execution status (2026-09-14):** Implemented and locally checked on the isolated research branch. Four actual work/payment scenarios, 23 artifact/custody/CLI tests, 30 existing buyer tests, 11 Rust tests and 147 Node checks pass. Clippy and formatting pass. The checker-bypass negative calibration fails as expected. A parent/child artifact-identity regression failed before repair and passes on final source. Native integration remains gated. See [W0 results](../../market/open-agent-work/execution/08-funded-w0-results.md).

**Architecture:** This extracts the independent artifact/checker/custody work from Task 4 of the [claim plan](2026-09-14-funded-work-claim-escrow.md). Native admission, Finding assurance, funding finality and crash reconciliation remain gated by Tasks 3-4. Joint Ed25519 agreement signatures pin the checker and settlement terms. A provider signs its submission after a local custodian durably stores the exact input/output. The verifier retrieves those bytes, reruns the existing Python checker and signs a bounded decision. The private-chain harness binds that digest into the existing EIP-712 authorization. The Rust checker supplies the provider's observations through a standalone command.

**Tech Stack:** Existing locked Python RFC 8785/Ed25519 dependencies, SQLite custody, existing Rust declaration checker, locked Node/ethers/Ganache/Solidity environment. No new dependencies.

**Spec:** [F1 draft](../../market/open-agent-work/execution/02-contract-draft.md). New encodings stay example-local experimental profiles pending registry/SDK integration. This is an artifact-only assurance profile, never an assertion of native Finding facets.

## Constraints and boundaries

- Preserve source and security worktrees. Only local mock tokens and private development chain.
- Canonical signed JSON, duplicate-key rejection, UTF-8, maximum 256 KiB and depth 16. Input/output each 64 KiB. Exact decimal money capped at `2^53 - 1`.
- Freeze distinct buyer/provider keys, verifier/custodian keys, payout addresses, chain/deployment/runtime pin, deadlines, input, checker profile and optional parent digest in joint terms.
- One exact signed submission and decision per allocation. Unavailable custody or unsupported assurance prevents acceptance. Wrong output produces a signed rejection only after valid authority, binding and custody checks.
- Local SQLite custody provides transactional persistence, owner-only files, immutable content hashes and reopen/retrieval checks. No deletion/GC API: retain indefinitely in this prototype. Signed retention floor is at least 30 days after refund deadline; ongoing claims remain retained. No claim of independent administration, remote access control, rollback resistance or long-duration availability.
- The verifier signs only after persisted submission and decision evidence can be retrieved. Signed decisions bind exact submission commitment, input/output, amount and recipient; EVM authorization uses that same SHA-256 digest as bytes32.
- Actual contract reads and code pin checks are private-chain observations, not public finality or native pre-admission.
- No em dashes. Conventional commits. TDD and targeted verification. Record checker time and actual gas separately from service amounts.

## Tasks

### 1. Canonical agreement and submission boundary

Files: `examples/funded-work/artifacts.py`, `test_protocol.py`, `PROFILE.md`.

- [x] Add failing parser, signature, amount, identity/domain, unknown-field and depth vectors.
- [x] Implement exact example-local agreement/submission/decision grammars with existing cryptographic helpers and strict wire bounds.
- [x] Verify both agreement signatures against locally supplied pins; reject unsupported checker or native-assurance promises.
- [x] Run boundary tests and retain canonical positive/malformed fixtures.

### 2. Durable custody and actual checker decision

Files: `examples/funded-work/custody.py`, `verifier.py`, `fixture.py`, `test_custody.py`, `test_verifier.py`; standalone Rust command in `examples/federated-work/src/main.rs`.

- [x] Add failing durable reopen, missing/tampered evidence, signature substitution, exact retry and conflicting-decision tests.
- [x] Store content and one decision transactionally in SQLite; deny unsafe file ownership/modes and symlink stores. Never overwrite existing authority or offer eviction.
- [x] Verify exact retained input/output/submission and rerun the existing Python W0 checker. Preserve unsupported/unavailable denial; only predicate mismatch receives a negative financial decision.
- [x] Expose the existing Rust checker through a bounded file command; no kernel or financial admission changes.
- [x] Run Python and selected standalone Rust checks.

### 3. Private-chain work-to-payment reproduction

Files: `contracts/scripts/work-claim-w0.mjs`, `work-claim-w0.test.mjs`; `examples/funded-work/README.md`; execution report and public evidence.

- [x] Drive actual Rust output, joint agreement, funding, signed submission, reopened custody retrieval, Python verification, EIP-712 decision and exact payout.
- [x] Exercise incorrect output rejection/refund and unavailable custody timeout. Demonstrate earned child withdrawal after unsubmitted parent refund without claiming a parent process crash.
- [x] Reconstruct all token deltas and retain canonical artifacts, receipts, public signatures and source hashes. No private keys in retained evidence.
- [x] Run targeted regressions and a checker-bypass negative calibration, review the diff, commit implementation and evidence.
- [x] Refresh the M4 gate read-only and state the remaining native integration requirements.
