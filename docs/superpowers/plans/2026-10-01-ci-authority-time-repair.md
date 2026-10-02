# CI and authority-time repair implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Restore the recorded CI and CLI qualification boundaries and close RC1 and AC1 without weakening security enforcement.

**Architecture:** Authority decisions read explicit injected clocks at the point of use. Test fixtures supply real custody and enforcement prerequisites. Structural checks validate current production ownership and exercise their negative controls.

**Tech Stack:** Rust, Tokio, SQLite, Python, shell, Cargo and GitHub Actions.

**Spec:** `docs/reviews/2026-10-01-regression-recovery-execution.md`, RC1 in `docs/reviews/2026-10-01-execution-review-reader-closures.md`, AC1 in `docs/reviews/2026-10-01-execution-review-accounting-clocks.md`, and `docs/security/trusted-time.md`.

## Global constraints

- Fail closed on authority, clock, custody and enforcement failures.
- Canonical JSON for signed payloads; preserve original strict input bytes.
- No new unwrap/expect, lint allowances, artificial skips or enforcement exceptions.
- No em dashes in new code, comments or documentation.
- Existing authorization permits committing and pushing this security branch. No merge or operator activation.
- Preserve `output/`, unrelated worktrees and terminal evidence. Raw logs live outside Git.
- Host-specific enforcing qualification requires its real prerequisites; local compilation does not qualify it.

## Review focus

- A client can complete a signed challenge after its filing deadline or after clock failure.
- Receipt formatting must not alter capability expiry, issuance time or durable high-water fences.
- Corrected fixtures must exercise actual custody checks, including wrong permissions and linked paths.
- CI classifiers must accept current valid source and reject injected security violations.
- Integration reports must preserve authorization and checked arithmetic when records are absent or malformed.

### Task 1: Authority-time regressions

**Files:** `crates/platform/chio-control-plane/src/trust_control/finding_challenge_handlers.rs`, its service runtime tests, `crates/kernel/chio-kernel/src/kernel/clock.rs`, `src/authority.rs`, `src/receipt_support/receipt_scopes.rs`, `crates/platform/chio-store-sqlite/src/admission_operation_store/schema/clock.rs`, `crates/kernel/chio-runtime-harness/src/kernel.rs`, and owning clock fixtures.
**Interfaces:** Consume the existing `Clock` port and `ClockFence`; produce point-of-use challenge time and explicit clock injection with receipt identifiers independently scoped.

- [x] Add delayed-body and failed-clock regression controls and demonstrate failure.
- [x] Sample challenge time immediately before coordinator submission after upload and blocking-pool wait.
- [x] Add receipt-scope versus expired authority, issuance and clock-regression controls and demonstrate failure.
- [x] Remove the ambient authority-time override; migrate deterministic fixture owners to explicit injected clocks.
- [x] Run affected challenge, kernel clock, SQLite clock and runtime harness suites. Expect successful controls without scope-based time authority.

### Task 2: Existing Clippy diagnostics

**Files:** The 26 exact diagnostic sites in `docs/reviews/artifacts/2026-10-01-regression-recovery/qualification.json`.
**Interfaces:** Preserve existing public behavior and error ownership.

- [x] Fix redundant closures/conversions/borrows, archive counter, test-module placement and test clock error propagation.
- [x] Run all-target Clippy for changed owners with `-D warnings`. Expect exit 0; record additional diagnostics explicitly.

### Task 3: Structural CI source and fixture contracts

**Files:** The 19 failed gate commands and their source/fixture owners in the preceding qualification artifact, `.github/workflows/ci.yml`, `deploy/docker/chio-workspace/`, architecture documents.
**Interfaces:** Preserve aggregate gate status; the kernel cannot depend on a security-engine implementation through quarantine.

- [x] Reproduce failures from retained evidence and trace each owner.
- [x] Repair custody, generated Docker inputs, source paths, classifications, inventories and source contracts; repair forbidden dependency ownership instead of allowlisting it.
- [x] Run each repaired gate and its negative controls. Expect legitimate source accepted and mutations rejected.
- [x] Run the full structural step. Expect every gate to execute with terminal outcomes.

### Task 4: CLI custody, native launch and process fixtures

**Files:** `crates/products/chio-cli/tests/support/mcp_security.rs`, federation/passport fixtures, `tests/process_host/`, process evidence/state targets, `tests/reference_runtime_provision.rs`, native conformance provisioning.
**Interfaces:** Generate fresh private seeds and directories; launch enforced runtime with explicit authority, identity, cage and anchor material.

- [x] Use the retained failing test names to trace fixture producers to production rejections.
- [x] Correct fixture custody, journal version, process environment and launch contracts without production bypasses.
- [x] Run the complete affected non-native integration targets and compile all five native targets with real enforcement enabled.
- [ ] Execute the native integration targets on the qualified Linux x86_64 host; distinguish genuine host prerequisite failures from source failures.

### Task 5: CLI proof and report regressions

**Files:** CLI `proof_cli_contract`, `proof_verify`, `proof_verify_public_settlement_online`, `receipt_query_authorization`, `receipt_query_export`, `receipt_query_underwriting` targets and the production owners their failures identify.
**Interfaces:** Keep signed evidence verification and report authorization intact.

- [x] Trace each recorded failure through its production owner; add a focused reproduction for real defects.
- [x] Repair producers or production logic according to the actual contract.
- [x] Run the complete affected targets. Expect successful valid flows and retained rejection controls.

### Task 6: Qualification, independent review and publication

**Files:** New execution report and compact qualification artifact under `docs/reviews/`.
**Interfaces:** All earlier tasks feed exact commands, terminal outcomes, source hashes and remaining external requirements.

- [x] Run formatting, changed-owner verification and the required structural boundary once on final source; schedule Cargo graphs serially.
- [x] Obtain one fresh independent review and repair Important/Critical findings with regression evidence.
- [ ] Commit conventional changes and push the existing security branch; verify local and remote SHA.
- [ ] Report each task's actual completion state and propose the next reconciled reader/decode-contract batch. Do not claim hosted, merge, milestone or release completion from local results.
