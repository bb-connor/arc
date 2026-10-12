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

- [ ] Port the three F045 controls (two tenant mismatches, one valid setup).
- [ ] Extract the private admission seam without changing current tick behavior.
  Review its equivalence before adding T12 controls. No public abstraction.
- [ ] Commit the behavior-preserving seam and regression tests. Run genuine
  runtime Originals: mismatched hosts start, cleanup ticks skip admission.
  Preserve positive/error/readiness controls and compile refusals separately.

## Task 2: Bounded repairs

Files: `security/orchestration.rs` and the owning regression tests.

- [ ] Add scheduler-tenant checks for both producer classes.
- [ ] Continue admission only for terminal cleanup backlog, retaining its error
  even when admission also fails. Propagate admission errors on a clean tick.
- [ ] Explicitly skip admission on every shutdown outcome. Preserve stop,
  clock, storage, integrity and declassification error behavior.
- [ ] Run regression controls to green, including actual worker degradation
  and continued progress through repeated backlog ticks.

## Task 3: Qualification and independent review

- [ ] Run owning orchestration/host/worker tests, strict all-target Clippy,
  formatting, Rust hygiene, negative assertions and security CI contracts.
- [ ] Obtain Claude's review of the complete source, address confirmed findings,
  and retain exact source hashes plus Original and repaired evidence.
- [ ] Commit the bounded repair and audit; update mailbox, board and claims.
  Local qualification remains distinct from future actual-base CI and landing.
