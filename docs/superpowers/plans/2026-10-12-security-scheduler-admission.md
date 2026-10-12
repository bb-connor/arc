# Scheduler tenant and admission repair plan

> Execute with superpowers:executing-plans in Root's native thread. Claude
> reviews the complete candidate. Root remains sole integrator and publisher.

**Goal:** Close the preserved F045 and F007/T12 defects on the current source.

**Baseline:** Private `fix/security-scheduler-admission`, based on the reviewed
alert-delivery candidate `bd65e56273`. Preserved producers `37b1a7e519` and
`6f4c0ade1e` are absent from main. Prior evidence does not qualify this base.
Keep #1201 and #1202 frozen; no third PR or publication before queue advancement.

**Design:** Reject event and receipt producers whose tenant differs from the
single scheduler tenant, before publishing a host. Isolate the existing durable
ingress/planning pass behind a private interface. After bounded terminal lease
cleanup reports `TerminalSchedulerCleanupPending`, allow that pass to run but
return the original error so readiness stays closed. All other scheduler
failures still stop admission. Shutdown ticks never admit new work. Preserve
runtime publication and coordinator readiness checks, recovery before admission,
ingress-error independence of planning, and bounded pass sizes.

## Task 1: Current Originals

Files: `security/orchestration.rs`, its new `planning_recovery_tests.rs`, and
`security/active_defense_host_tests/producer_tenant.rs`.

- [x] Port the three F045 controls (two tenant mismatches, one valid setup).
- [x] Extract the private admission seam without changing current tick behavior.
  Review its equivalence before adding T12 controls. No public abstraction.
- [x] Commit the behavior-preserving seam and regression tests. Run genuine
  runtime Originals: mismatched hosts start, cleanup ticks skip admission.
  Preserve positive/error/readiness controls and compile refusals separately.

## Task 2: Bounded repairs

Files: `security/orchestration.rs` and the owning regression tests.

- [x] Add scheduler-tenant checks for both producer classes.
- [x] Continue admission only for terminal cleanup backlog, retaining its error
  even when admission also fails. Propagate admission errors on a clean tick.
- [x] Explicitly skip admission on every shutdown outcome. Preserve stop,
  clock, storage, integrity and declassification error behavior.
- [x] Run regression controls to green, including actual worker degradation
  and continued progress through repeated backlog ticks.

## Task 3: Qualification and independent review

- [x] Run owning orchestration/host/worker tests, strict all-target Clippy,
  formatting, Rust hygiene, negative assertions and security CI contracts.
- [x] Obtain Claude's review of the complete source, address confirmed findings,
  and retain exact source hashes plus Original and repaired evidence.
- [x] Commit the bounded repair and audit; update mailbox, board and claims.
  Local qualification remains distinct from future actual-base CI and landing.

## Local completion

Current Originals at `5f371a7da2` produced six intended runtime failures and
five positive/error passes. The repaired controls passed 11/11, and the owning
host, orchestration, worker and simulation suite passed 143/143. Strict Clippy
first found a preserved test-helper type-complexity warning. A private type alias
fixed it without changing production; the final focused 11/11 and strict Clippy
passed. Static gates passed. Claude approved the complete source and alias
amendment with no P0/P1/P2 findings.

The audit in `docs/security/audits/security-scheduler-admission-20261012.json`
binds the source, review, retained failures and local evidence. This private
batch still needs actual-base hosted qualification and landing.
