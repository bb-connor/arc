# PR 1173 Guard-Failure Review Closure

> Execute inline with superpowers:executing-plans. No subagents.

**Goal:** Preserve the first contractual output rejection when another ordinary
guard or frozen output preparation temporarily fails. The actual regression on
`2b608eb2d1a29f17e4e42288955d262f29a1bed4` produces Allow after recovery where
the work contract requires a signed redacted Deny.

**Architecture:** Reuse the installed guards and existing durable outcome.
Separate fallible ordinary preparation from infallible contractual classification.
Keep all new types private to the kernel output-guard implementation.

**Tech Stack:** Rust 1.95, existing Guard traits and durable admission stores.

**Spec:** The fail-closed and zero-charge contract in
`docs/superpowers/plans/2026-10-06-pr1173-checked-output-review.md`, the existing
Guard trait, and the user's requirement to close every P0/P1/P2 inline.

## Global constraints

No subagents, new dependencies, durable fields, public APIs, authority bypasses,
new Vet exemptions, em dashes, or changes to the external security owner's lane.
Pre-record ordinary refusals retain their existing uncertainty and hold semantics.

## Files and interfaces

- `crates/kernel/chio-kernel/src/kernel/output_guard.rs`: private borrowed guard
  selection, ordinary validation and infallible contractual aggregation.
- `crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal.rs`:
  consume the selection after ordinary preparation and retain the aggregate in
  the existing `DurableEvaluatedOutput` and resolved-outcome path.
- `crates/kernel/chio-kernel/src/kernel/tests/durable_admission/checked_output.rs`:
  real failures and signed denial/replay assertions using existing fixtures.
- Both flow gate scripts: exact module inventory and mutation controls.
- Formal manifest/coverage: only resulting reviewed mirror changes, if any.
- Security CI checker and Docker definition: retain a static digest for the
  genuinely audited workspace lockfile; reject content and pin mutations.
- Response recovery runner and contract: select the canonical scheduler test
  identity through its private module and retain zero-match rejection.
- Federation-policy CLI fixture: diagnose its actual HTTP failure and use
  authenticated, typed reputation responses and private fixture custody.
- Local reputation, reputation issuance and passport rotation fixtures: retain
  private temporary storage until the child services stop.
- Shared receipt-query fixture helper: create private directories through the
  existing test-support helper and retain callers' cleanup ownership.

## Review focus

Ordinary errors and panics before contractual checks must retain the hold.
Frozen transforms must finish before observing a contractual rejection.
All guard-role probes must finish before the first contractual validator.
Exact released-output guards must preserve raw-skip behavior with transforms.
Retained denial must skip fresh checkers and preserve replay/settlement identity.

**Cause:** Durable evaluation still invokes contractual checkers before later
ordinary checks and transforms. A subsequent error discards the contractual
rejection before the resolved outcome is retained. Recovery reruns the checker.

**Design:** Snapshot guard roles and raw-output applicability before invoking any
contractual output checker. Borrow the installed guards and original context;
retain no independent authority or mutable denial cache. Ordinary raw and
released-output validation, frozen transforms, canonicalization and step-count
validation finish first. Contractual raw and released-output checks then return
an infallible aggregate rejection (including checker errors or panics), with no
remaining fallible guard-role probes or ordinary validators between them.
Persist denial through the existing resolved-outcome and settlement machinery.
Retained denials continue to skip fresh guard evaluation during replay.

An added durable observation schema would widen the storage and recovery
protocol. An in-memory denial cache would lose its guarantee on restart.
The selected design places checker evaluation at the existing authoritative
boundary after ordinary preparation, preserving current storage failure and
fencing semantics. It does not claim that an uncommitted observation survives a
failed durable write or process loss; the resolved-outcome commit remains the
durability boundary.

## Execution

1. Preserve the actual old-source regression: transient ordinary rejection after
   a contractual checker, followed by recovery, must never produce output or
   capture. Confirm actual zero-pass/one-failure Allow-versus-Deny reproduction.
2. Introduce a private borrowed guard selection and move all ordinary preparation
   ahead of contractual validation. Keep release and pre-record validation
   fail-closed. Do not add public APIs, durable fields or financial authority.
3. Cover the same failure with a panicking contractual checker and cover a
   temporary post-invocation preparation failure where existing fixtures permit
   it. Require one invocation, one release, no capture/output and identical
   retained signed denial on replay. Preserve ordinary-error hold retention.
4. Register the complete checked-output inventory and strengthen actual
   omission/substitution controls. Run complete kernel tests, strict Clippy,
   complete flow gate and its negative controls, then formatting and hygiene.
5. Inspect all resulting formal mirror drifts against complete model boundaries.
   Bless only reviewed anchors; retain the distinction from Rust refinement.
   Regenerate and verify proof coverage.
6. Close the three actual owned hosted CI failures before the source checkpoint.
   Update both static lockfile pins to the audited root digest, preserving exact
   content checks and testing actual lockfile/pin mutation rejection. Retain the
   original failing checker and self-test results. Reproduce the scheduler's
   zero-match failure, correct both selectors to the full module identity, run
   all response-dispatch cases and the complete recovery gate. Reproduce the
   federation-policy failure, inspect its HTTP response and repair the fixture
   using existing private storage and the typed response contract. Run the
   complete CLI suite and retain actual unavailable native cases separately.
   The broad campaign exposes the same custody defect in local reputation,
   reputation issuance, passport rotation and shared receipt-query fixtures.
   Repair their existing helpers and rerun all affected targets, including every
   receipt-query consumer, with strict all-target Clippy. Preserve passing
   coverage for unchanged code and every failed campaign's original scope.
   No production trust policy or external authority may be weakened. Both final
   hosted workspace and MSRV must execute the native cases with their existing
   qualified enforcing-host fixture.
7. Preserve the preceding 550 records, source-bound package and hosted results
   with their actual scope. Commit the repaired source, renew all 21 native
   commands and the receipt verifier, freeze the paper/PDF and push normally.
8. Require fresh final-head hosted acceptance and review. Keep the native lifetime
   thread open until the actual unignored x86 test passes. The security owner
   retains the coherent source and signed Linux package handoff. No policy,
   exemption, variable or evidence-digest bypass is permitted.

## Required validation

- [x] Focused new regression: cargo101 and Allow-versus-Deny before the repair;
  cargo0 and one actual pass after it.
- [x] `cargo test --locked -p chio-kernel --lib`: all actual cases pass; no ignored
  or failing kernel cases.
- [x] `cargo clippy --locked -p chio-kernel --all-targets -- -D warnings`: exit0.
- [x] `bash scripts/tests/check-flow-security.test.sh`: exit0 with actual omission
  and substitution mutants rejected.
- [x] `bash scripts/check-flow-security.sh`: all exact declared inventories pass.
- [x] Formal mirrors, proof coverage, file hygiene, formatting and diff: exit0.
- [x] Static security CI contract and all mutation controls: exit0.
- [x] Recovery selector has one actual pass, complete dispatch/recovery gates and
  their negative controls pass.
- [x] Broad CLI results retained; all affected independent fixtures and shared
  helper consumers pass, strict Clippy passes, and native cases remain explicitly
  unqualified locally until final hosted acceptance.
- [ ] Source-bound native21, receipt verifier and reproducible artifact: exit0;
  publication still fails exactly the four research gates and two readiness flags.

**Tracking:** Freeze this plan before native qualification; record later status
in its excluded execution ledger. Preserve Ready/Open/unmerged PR state and all
actual failed, skipped, interrupted and successful campaign results.
