# Dynamic Delegation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Make runtime-selected and recursively delegated work use one durable, receiver-checked allocation contract, then update the paper to reflect the actual result.

**Architecture:** A holder-authenticated SQLite allocation tree lives in chio-workflow. The allocator seals portable evidence; an opt-in chio-kernel guard verifies it locally, binds each leaf to its original receiver-issued invocation and checks its exact output. Existing kernel authority, recovery, receipts and payments retain their roles.

**Tech Stack:** Rust, existing chio-core crypto/canonical JSON, serde, rusqlite, native kernel guards, LaTeX and Python artifact tooling.

**Spec:** `docs/superpowers/specs/2026-10-02-dynamic-delegation-design.md`

## Global Constraints

- Fail closed; no unsafe Rust; no new external dependencies; reuse workspace rusqlite.
- Signed payloads use RFC 8785; no em dashes; no unqualified breakthrough claim.
- Retain all meaningful failed evidence. No real funds or outside outreach.
- Existing isolated worktree `/tmp/chio-verifiable-work-paper`; base `96c25e99a188bb8d1d084c7324a30050a2fd496d`.
- User explicitly authorized design, execution, review and manuscript edits continuously.

## Review Focus

- Replayed signed mutation with a changed holder, root or request cannot reuse authority.
- Two database connections cannot concurrently overallocate or replace a dispatched slot.
- Malformed contract, expiry, maximum integers and SQLite errors fail closed.
- A native capability wider than the selected offer cannot bypass the work contract.
- Acceptance after an output transform checks the bytes actually delivered; predicate satisfaction does not imply task utility.

## Task 1: Durable holder-authenticated allocation tree

**Files:** Create `crates/platform/chio-workflow/src/delegation/{mod,types,store}.rs`, `crates/platform/chio-workflow/tests/delegation.rs`; modify `src/lib.rs` and `Cargo.toml`.

**Interfaces:** `DelegationStore::open(path)`, `create_root(Slot)`, `subdivide(SignedSubdivision, now)`, `select(SignedSelection, now, qualified_receivers)`, `claim_dispatch(DispatchBinding, now)`, `seal_dispatch(DispatchBinding, now, issuer)`, `verify_dispatch_permit`, `slot(id)`, `allocation_digest(id)`; `Acceptance::validate/check`; signed offer/subdivision/selection constructors. Exact structs follow the spec; errors use one typed enum. Store operations return immutable slot/binding records, never capabilities.

- [x] Write tests for dynamic nested allocation, sibling overspend, wrong signer, malformed predicates, integer overflow, changed replay and expiry. Run and retain the missing implementation failure.
- [x] Implement bounded serializable types, signatures and canonical digests; SQLite immediate transactions, immutable slots and exact dispatch binding.
- [x] Add two-connection race, reopen, replacement-before-dispatch and no replacement after dispatch tests. Observe failures before corrections where applicable.
- [x] Run `cargo test --locked -p chio-workflow`, focused clippy and formatting. Expected: all applicable tests pass; initial failures retained.
- [x] Commit `feat: add durable dynamic work delegation`.

## Task 2: Native receiver binding and runnable dynamic workflow

**Files:** Create `crates/kernel/chio-kernel/src/delegated_work.rs`, `crates/kernel/chio-kernel/tests/dynamic_delegation.rs`, `crates/kernel/chio-kernel/examples/dynamic_delegation.rs`; modify kernel lib/Cargo metadata and lockfile for existing workspace dependencies only.

**Interfaces:** `install_delegated_work(&mut ChioKernel, Vec<PublicKey>)` activates accepted allocator keys and requires durable admission. A private guard consumes portable Task 1 permits. `Guard::evaluate/revalidate_before_dispatch/validate_output_before_release` enforce native request and result checks. A shared example fixture may live under the integration test directory if it is only demonstration code.

- [x] Write failing native tests for selected-provider dispatch, holder/capability/request tampering, output rejection, receiver substitution and attempted retry through a new identity.
- [x] Implement opt-in guard with fresh time checks and native monetary ceiling matching. Keep allocation evidence distinct from capability authority and settlement.
- [x] Exercise signed provider offers obtained after root creation, recursive holder delegation, pre-dispatch replacement, persisted unknown allocation and useful sibling completion; assert native receipts and dispatch counts.
- [x] Run native integration tests and the runnable example; test the changed crate boundary with focused clippy/formatting. Expected: authorized output delivered, altered calls/outputs denied, retained binding after reopen.
- [x] Commit `feat: enforce delegated work at native dispatch`.

## Task 3: Protocol argument, evidence and manuscript

**Files:** Create `docs/research/dynamic-delegation/{README,PROTOCOL,RESULTS}.md`, evidence logs and source inventory. Update `docs/papers/verifiable-work/{paper.tex,sections,bib.bib,README.md,CLAIMS.json,PUBLICATION.json,ARTIFACT.md,tools/check.py}` and rebuilt PDF/artifact manifest.

**Interfaces:** Consume Task 1/2 public APIs and terminal results. Historical qualification remains bound to historical source commits; current evidence gets its own source inventory. Paper check validates both rather than rewriting old records.

- [x] State the invariant argument, conventional counterdesign, changed capability and current limitations. Use primary sources for related work.
- [x] Rewrite the abstract and main argument around dynamic delegation with explicit assumptions and precise evidence. Preserve the title and negative capital/escrow comparison conclusions.
- [x] Adapt artifact validation with regression tests before changing its handling of historical source inventories. Preserve fail-closed publication checks.
- [x] Rebuild and visually inspect PDF; run artifact tests/checks and confirm publication still refuses open gates. Expected: complete internally consistent manuscript, not fabricated external validation.
- [x] Commit `docs: center verifiable work on dynamic delegation`.

## Task 4: Fresh review and qualification

**Files:** `docs/research/dynamic-delegation/REVIEW.md`, final retained checks and source/output manifests.

- [x] Dispatch one fresh reviewer for base-to-head code, protocol and manuscript claims, with the five Review Focus inputs.
- [x] Regrade by actual effect; fix Important/Critical findings in one regression-driven pass. Record all findings and scope rulings.
- [x] Run final changed-boundary suites, clippy, format, example and manuscript checks; bind evidence to exact final source. Expected: terminal success, open external gates unchanged.
- [x] Commit corrections and retain the branch, plan and evidence for continuation. Report the implemented capability and remaining scientific judgment plainly.

Completion: implementation, fresh combined review, regression repair and all 11
source-bound qualification commands complete. PDF and artifact checks pass.
The isolated paper branch is retained as planned; independent operators,
unified D1/S1/F1 execution and the requested breakthrough judgment remain open.
See docs/research/swarm-evolution/REVIEW.md for exact scope and evidence.
