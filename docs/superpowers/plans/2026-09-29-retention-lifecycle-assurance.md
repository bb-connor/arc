# Retention and production lifecycle assurance implementation plan

Goal: implement the three approved follow-ups from the SQLite batch: usable
retention ownership capture, lifecycle traces at real durable boundaries, and
resolution of the larger revocation temporal-model timeout.

Spec: docs/superpowers/plans/2026-09-25-security-assurance-closeout.md Packet 4;
formal/response-lifecycle.md; docs/reviews/2026-09-28-remaining-security-work.md item 6.

Global constraints: existing isolated worktree; inline implementation with one
fresh final review; bounded changed-owner checks; preserve output/; local commits
only. Do not report synthetic traces, incomplete runs or a reduced model as full
implementation refinement or historical incident resolution. No compatibility
layers or speculative production liveness repair.

## Review focus

- Observation covers delegated sync completion and teardown without owning or
  canceling accepted writes. No diagnostic lock is held across a real I/O call.
- Lifecycle evidence links committed response generations, native effect results
  and verified signed receipts across restart and lost acknowledgement.
- Trace refusal catches reordered, missing, substituted and fabricated evidence.
- Temporal success names the actual scope, fairness premises and terminal solver
  result. Mutants must violate their named obligation, not fail to parse.

### Task 1: Retention ownership capture

Files: tests/receipt_retention_liveness/{sync_shim.rs,workload.rs}, a named safe
sync diagnostic module and focused ownership tests; bounded diagnostic runner.
Interfaces: existing SyncShim snapshots/lock ledger and Watchdog steps.

- [x] Fail a real gated writer regression requiring an active-sync observation.
- [x] Retain in-process stack/owner observations until real xSync returns; clear
      them with RAII. Cover open, health, receipt reads and teardown with watchdogs.
- [x] Run deterministic ownership regressions and a bounded current workload;
      preserve terminal counts and keep issue 1045 open unless reproduced/repaired.

### Task 2: Durable lifecycle trace linkage

Files: SQLite response journal, native effect/receipt boundaries, named
control-plane lifecycle tests, scripts/check-response-lifecycle.py and its tests,
formal/response-lifecycle.toml and the owning workflow.
Interfaces: production ResponseStore, SessionThrottleBackend, native signed
receipt sink and durable executor; versioned trace validation.

- [ ] Add refusal regressions for missing real commits, effect/receipt mismatch,
      reordering, false completion and replay/restart substitution.
- [ ] Emit bounded structured events at committed production boundaries. Exercise
      the real stores, backend and signer through activation, rollback and recovery.
- [ ] Validate generated artifacts and require the trace in the assurance lane;
      retain the separate finite-model claim and actual Rust evidence.

### Task 3: Larger temporal model timeout

Files: formal/tla revocation progress obligations, bounded solver/checker runner,
calibrated counterexamples and scheduled workflow evidence.
Interfaces: original Revoke/Propagate/Attenuate/Evaluate actions and fairness.

- [x] Identify the solver explosion and use action-level progress obligations
      rather than extending the historical hour-long search.
- [x] Mechanically check source-linked obligations at four authorities and eight
      capabilities, with nonvacuous negative controls and explicit fairness.
- [x] Run the complete bounded acceptance set, record exact scope and update the
      original timeout disposition without calling a different check the old run.
