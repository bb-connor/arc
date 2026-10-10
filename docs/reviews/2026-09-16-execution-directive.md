# Progress review and execution directive

Latest implementation checkpoint: [September 20 regress continuation](2026-09-20-regress-continuation.md).
It contains a tested local backport, verified import bundle, and current
qualification blockers. Reconcile that checkpoint before repeating dependency work.

Reviewed September 16, 2026, 16:41 UTC. This continues the September 15
[execution handoff](2026-09-15-execution-handoff.md) and supersedes the immediate
queue in the [previous review](2026-09-16-progress-review-followup.md).

## Decision

Keep executing. The last two review findings are repaired, but a new failure in
the active foundation run requires diagnosis. The next deliverable is a qualified
foundation and complete M5 evidence. Do not stop after updating this plan, waiting
for another user prompt, or publishing another checkpoint.

This is a direct review of the newest six-file commit and current qualification
evidence, not a new full-codebase security audit. No new correctness defect was
found in that commit. Confidence is high for the repaired CI checks and observed
failure; the new test failure's root cause remains unknown.

## Exact source and completed change review

- Published [ARC #1160](https://github.com/bb-connor/arc/pull/1160):
  `471e91ef05398388691b131292340b12ade4e3fc`, open draft.
- Current clean execution checkout: `/tmp/arc-m5-evidence`.
- Frozen Linux foundation source: `94e0da1fb758c6759dd78439a6d34d3358ba638a`.
  Preserve its running process, source and evidence. The latest commit is a
  separate checkpoint and must not inherit an invented exact-source pass.
- Reviewed delta: one commit, six files, 120 insertions and 35 deletions.
  The Rust changes format three process modules and reorder module declarations;
  the remaining changes document the repair and re-encode a retained patch.

Both previous P2 findings are closed in source:

1. All three direct rustfmt invocations used by the process workflow pass this
   review's rerun. The accumulated `git diff --check f5566d9a7...471e91ef0`
   also passes.
2. Both old and new dependency patches were independently applied to fresh
   source extracted from the checksum-verified `enumflags2_derive-0.7.12.crate`.
   The zero-context patch passes check/apply with `--unidiff-zero` and
   `--whitespace=error-all`. Both produce identical repaired source SHA-256
   `efe17e60fb3c1748e08492e7d782790b970d5586144a6da9515ff8525cadef40`.

This patch remains a repair proposal outside Chio's selected dependency graph.
Formatting it does not install the repair or certify the affected packages.

Review evidence is retained under the primary checkout's
`output/process-security-20260915/progress-review-directive-20260916/`.

## New priority-one investigation: foundation capture expiry failure

The active `94e0da1fb` workspace run has passed compilation and reached tests.
Its log explicitly reports:

```text
security::adapters::tests::native_flow::support::capture::combined_credentials::expiry::runtime_expiry_after_native_verification_rolls_back_physical_capture ... FAILED
```

Owner:
`crates/platform/chio-control-plane/src/security/adapters/native_flow_capture_expiry_tests.rs:6`.
The test verifies refusal at the injected runtime-expiry cutpoint, zero tool
effects, uncaptured quota, retained credential custody and reopenable ledger.
The assertion/error details have not yet been emitted at this snapshot. Do not
infer that any particular safety assertion failed merely from the test name.

This case passed in the original `810664017` full run and was not one of the six
control-plane cases previously retried. Those passing retries do not dispose of
this failure. Recent guest load observations are below 1, so the earlier severe
host-contention explanation cannot simply be reused.

The full workspace run is still active with `--no-fail-fast`; retain its terminal
result and all failures. Its inventory queue explicitly requires `all_passed`,
and its fuzz queue also stops on a failed predecessor. Neither queue should be
assumed to advance automatically after this failed run.

### Required execution

1. Let the current run finish. Read the complete failure output and preserve the
   exact executable hash, environment, source, resource observations and log.
2. After the active test owner releases the machine, rerun this exact test from
   that same executable with `--exact --nocapture`. Reproduce under the owning
   test target as well if the isolated case passes. Investigate clock inputs,
   expiry cutpoint execution, fixture lifetime, cleanup and shared state according
   to the actual error; these are hypotheses, not established causes.
3. Fix a reproduced implementation or fixture defect with a regression preserving
   the test's required boundary. Do not weaken expiry enforcement, broaden a
   deadline blindly, add an ignore, or equate one lucky retry with resolution.
4. Requalify the affected target and complete the workspace gate on the selected
   source. Re-arm the exact worker/mailbox, flow-security, native-restart and fuzz
   inventories explicitly after prerequisites pass. Keep all original failures.

## Hosted progress: the hygiene repairs worked

At the initial 16:37 UTC check-run snapshot, the current head has 132 observed
checks: 104 successful, 15 skipped, six failed and seven running. This counts
observed jobs, not every possible required acceptance gate.

- [Process host recovery](https://github.com/bb-connor/arc/actions/runs/35116248890/job/104862290238)
  passed the CLI/recovery step that previously failed formatting. Installed
  mini-SWE-agent recovery and installed coding-session recovery also passed.
  Repository review is executing; later package/shared-resource/AI SDK/benchmark
  steps remain pending. Do not describe the whole job as passed yet.
- [Cognition-market qualification](https://github.com/bb-connor/arc/actions/runs/35116249125/job/104862292550)
  passed patch integrity, runtime suites, PostgreSQL integration, SDK tests,
  strict Clippy, code generation, release-evidence tests and cargo-deny. It now
  fails at cargo-vet on the same 26 unvetted dependencies. The PostgreSQL
  integration target reports one passed test with zero ignored/failed tests.
- [Cargo-vet](https://github.com/bb-connor/arc/actions/runs/35116250604/job/104868449150)
  and its second dedicated job fail on those same 26 dependencies. Together
  with cognition-market, three failed jobs have this common blocker.
- [Build/structural gate](https://github.com/bb-connor/arc/actions/runs/35116250604/job/104868448476)
  still stops at `workspace Cargo.lock digest ratchet changed`.
- [Merge-binding attestation](https://github.com/bb-connor/arc/actions/runs/35116250604/job/104868449291)
  still executes the old workflow without `GH_TOKEN` and exits 4.
- [Capture controller](https://github.com/bb-connor/arc/actions/runs/35116256935/job/104862314226)
  exits 1 before dispatch. The exact failed shell assertion is not printed.
  Its log retains the old authorized workflow definition; source/image/workflow
  prerequisite discrepancies remain separately documented.

## Execution queue after immediate failure triage

### A. Work on dependency closure while the existing run owns Cargo

Do source review and prepare scoped dependency changes without interrupting the
frozen build. Record an exact-version disposition for every missing package.
Finish actual audits or import records allowed by the current policy. Do not
convert a reproduction note into a `safe-to-deploy` certification.

Start with the confinement chain because a real defect already has a prepared
repair: enumflags2/derive, landlock, nono and seccompiler. Select and substantiate
the actual repaired dependency revision, run its upstream negative/positive
inventory and downstream cage tests, and then update the candidate graph. The
existing note explicitly says the repair is not installed. Review the remaining
AWS-LC/TLS, Sigstore/ASN.1, typify, ignore and regress packages against the live
26-item inventory. Reconcile the separately patched sigstore-verify ownership
under the repository policy as needed.

Exit: `cargo vet check --locked` passes for the selected package graph with
substantive records, and affected runtime evidence identifies the new binaries.
The current frozen test run remains useful diagnostic evidence after a package
change, but cannot certify a different final dependency graph.

### B. Prepare the image and trusted-workflow change for a concrete decision

Resolve the lock-input/image discrepancy through a reproducible image-input
update and verification. Do not edit the expected digest merely to silence the
structural gate.

The candidate already includes the merge-binding token fix. The caller still
pins `enterprise-hardening.yml` at
`eba8cdf3fb2e16501947c58415a4739a23cc12b3`, which lacks it. Prepare the reviewed
complete workflow-definition set and exact old/new pins, source identity, image
digest and validation evidence required by
`docs/security/committed-linux-evidence.md:46`. That document requires the
workflow set on main, matching immutable caller/definition identities and
separate authorized source configuration. A PR cannot establish those trust
roots by editing itself.

Complete the engineering and present the concrete authority change only when it
is ready. If activating it needs operator action, keep that one operation pending
and continue other unblocked work. Do not repeatedly rediscover missing GH_TOKEN
or relaunch the unchanged unauthorized controller.

### C. Close the remaining M5 evidence joins

Use the existing reference swarm and verifier. The seven-scenario local matrix
and repaired policy binding are established progress; avoid rebuilding the same
demo without a changed acceptance requirement.

`examples/reference-swarm/process_matrix_evidence.py:644` still sets
`m5_acceptance_complete=false` and lists four unchecked claims: designated-runner
authorization, combined foundation, execution nonces and receipt-log inclusion.
Map each to its owning acceptance artifact. Extend the existing export/verifier
for the missing nonce and log-inclusion joins, or document the separate strict
verifier supplying those claims; do not remove them from `unchecked` without
evidence. Add substitutions at those boundaries and verify the complete run
artifact with the finalized source/binaries on the designated authorized runner.

Exit: the documented command demonstrates the required governed, confined swarm
and every required evidence join, with terminal combined-foundation and runner
acceptance. A hard-coded boolean change is not acceptance.

### D. Continue the existing roadmap

After the foundation/M5 prerequisites stabilize, proceed into M6's real
keyring/broker/cage invocation with one composite hold and receipt join, M7's
dry-run response/rollback topology, and M8 recovery. Resume the full million-entry
recovery campaign once the machine is available. The 1,000-entry calibration and
million-entry append are different passed claims; retention issue #1045 remains
open. Then finish the existing M9/M10 packaging and consumer gates.

Do not create a new framework, another orchestrator wrapper or a new PR chain for
these tasks. Keep changes on the reconciled delivery path, checkpoint meaningful
fixes, and preserve the planned merge/release authority boundaries.

## Reporting contract

Report concrete exits: repaired failure with regression, completed audit group,
reproducible image update, qualified evidence join, or terminal milestone gate.
State the source and binary scope of reused evidence. Documentation-only and
formatting changes justify scoped verification; dependency or runtime changes
invalidate their affected acceptance results. Maintain one Cargo owner and keep
cheap checks ahead of expensive qualification.

Do not stop at this handoff. Begin the failure diagnosis and dependency work,
then continue the queue until the next real external boundary.
