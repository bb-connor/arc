# Progress and repair review, September 16, 2026

Snapshot: 15:20 UTC. Reviewed candidate:
`94e0da1fb758c6759dd78439a6d34d3358ba638a`.
Previous review: `ee81b3ace998346253604567c1507fb73d0fcaa8`.

## Assessment

The previous launch-policy binding defect is fixed and independently rechecked
against fresh retained runtime evidence. The latest candidate has been published
to [ARC #1160](https://github.com/bb-connor/arc/pull/1160), so the earlier gap
between local work and the PR is closed. No additional correctness defect was
found in the two repair commits reviewed here.

The candidate remains an open draft and is not ready to merge. Two reproducible
CI hygiene defects remain in the accumulated candidate, alongside supply-chain
and trusted-workflow prerequisites. Complete workspace qualification is pending.

Confidence: high for repair verification and reproduced CI blockers. The
individual foundation reruns establish passing cases, not a complete workspace
pass or a definitive common cause for all earlier failures.

## Current review findings

These two findings predate the latest two repair commits. They are observable
failures in the newly published candidate, not regressions introduced by the
policy-binding repair.

### P2: Format the process modules using the owning CI command

Locations:

- `/tmp/arc-m5-evidence/crates/products/chio-cli/src/cli/process_host/run_evidence/native.rs:169`
- `/tmp/arc-m5-evidence/crates/products/chio-cli/src/cli/process_host/swarm/plan.rs:50`
- `/tmp/arc-m5-evidence/crates/products/chio-cli/src/cli/process_host/swarm.rs:3`

The MCP process-host lane fails at its direct rustfmt check. Reproduced locally:

```sh
rustfmt --edition 2021 --check crates/products/chio-cli/src/cli/process_host.rs
```

The command returns 1 and prints differences in all three modules. The workflow
requires this command at `.github/workflows/process-workers.yml:130`. Recorded
`cargo fmt --all -- --check` passes do not cover this additional direct check.
This failure prevents the later installed recovery/consumer steps in that job
from running. Apply the owning formatter, then check the exact lane commands.

[Hosted failure](https://github.com/bb-connor/arc/actions/runs/35102063090/job/104813690814).
Local reproduction output is retained under
`output/process-security-20260915/progress-review-followup-20260916/process-format.log`.

### P2: Make the retained enumflags patch pass patch-integrity validation

Location:
`/tmp/arc-m5-evidence/supply-chain/reviews/enumflags2-0.7.12-default-type.patch:5`
and line 9.

Both blank context lines contain a space. The cognition-market qualification
script runs `git diff --check` over the full candidate before its substantive
qualification. That command exits 2 on these lines. The same failure reproduced
locally against the accumulated candidate.

Preserve a usable dependency repair patch while making its representation pass
the owning whitespace gate; verify that the resulting patch still applies. Do
not treat this hosted failure as evidence of a PostgreSQL isolation defect.

[Hosted failure](https://github.com/bb-connor/arc/actions/runs/35102063015/job/104813690025).

## Previous finding: closed for the reviewed candidate

Production repair: `f3a9a558eab15751c092f73c17e90a3ce93eb179`.
Fresh evidence/test checkpoint: `94e0da1fb`.

Reviewed the complete production path:

1. The loader authenticates canonical policy bytes and hashes that exact signed
   envelope in `cage_policy.rs`.
2. The receipt-signing context retains `admitted_policy_digest` through descriptor
   rebinding. `prepare_cage_receipt` includes it before constructing the content
   hash and signed receipt, and rejects a conflicting preexisting commitment.
3. The common native verifier requires the submitted policy digest to match the
   signed launch commitment. Enforcement and terminal receipts must agree.
4. Historical receipts still decode but cannot prove a complete-policy commitment
   they never contained. The old fixture remains intact, with an explicit
   rejection test; the replacement positive fixture comes from a fresh run.

This review reran the same-operator test on a fresh, unchanged cage receipt:

| Input | Result |
| --- | --- |
| Original signed policy | Pass; `admitted_policy_binding` present |
| Different signed argv | Rejected at complete-policy binding |
| Different signed working directory | Rejected at complete-policy binding |
| Different signed resource limits | Rejected at complete-policy binding |

The observer binary SHA-256 is
`4bd0253dc3655154a4a910faf515538843478dcd36bdbd2430eb68cb2e7e405c`.
Results: `output/process-security-20260915/progress-review-followup-20260916/same-operator-verification.json`.

This review also reran the repaired seven-scenario matrix's baseline and all 15
negative cases successfully. Results: `progress-review-followup-20260916/matrix-rerun.json`
under the same evidence root. The matrix still explicitly reports
`m5_acceptance_complete=false`.

## Progress since the previous review

| Area | Current evidence |
| --- | --- |
| Publication | #1160 head now equals local M5 branch head `94e0da1fb`. Two commits since the previous review, 16 files changed, 652 additions and 17 deletions including tests, fixtures and review documents. |
| Fresh M5 runtime | All seven scenarios passed on repaired Linux/x86_64 source `f3a9a558e`, with 17 worker outcomes. Fresh positive and same-operator substitution evidence retained. |
| Cage enforcement | Repaired-source gate completed at 13:59:53 UTC: 69 all-target tests and ten mutation probes passed. The 26 enforcement probes are included in the 69, not additional tests. |
| Previous foundation failures | Original full run ended failed in two targets: six control-plane cases and four anchored-root cases. All six control-plane cases pass individually from the unchanged original executable; all four anchored-root cases pass after supplying the repository-pinned Bun prerequisite. |
| Current foundation | On `94e0da1fb`, workspace build, workspace format, security vectors, strict workspace Clippy and proof-coverage checks all pass. Workspace tests are still compiling; no terminal test result is available. |
| Repair regressions | Native-policy tests, outcome tests, strict CLI/cage Clippy, workspace format and proof coverage pass at `94e0da1fb`. |
| M8 | Million-receipt append result remains passed. The 1,000-receipt recovery calibration now passes. Full million-receipt recovery is deferred; retention issue #1045 remains open. |

The old `/tmp/arc-security-launch` checkout remains at `178667e50`, 47 commits
behind its now-updated remote branch. Continue from `/tmp/arc-m5-evidence` or a
checkout of the verified published candidate; do not mistake the older local
integration directory for current source. Both execution worktrees were clean.

Current result directories under `output/process-security-20260915/`:

- `linux-x86-policy-binding-matrix-f3a9a558e/`
- `linux-x86-cage-policy-binding-f3a9a558e/`
- `linux-foundation-review-retry-810664017/`
- `linux-foundation-bun-retry-810664017/`
- `linux-foundation-94e0da1fb/`
- `macos-policy-fixture-94e0da1fb/`
- `macos-history-recovery-15cd4178e/`

## Current hosted checks and remaining prerequisites

Live check-run snapshot for `94e0da1fb`: **133 total, 108 successful, 15 skipped,
seven failed, three running**. Running jobs are MSRV and the two sidecar image
builds. These are observed check runs, not a claim that every required gate has
been scheduled or completed.

The seven failures group as follows:

| Failure | Observed cause / status |
| --- | --- |
| MCP process host recovery | Direct rustfmt failure described above |
| Cognition market PostgreSQL isolation | Patch-integrity whitespace failure described above |
| Build, lint, test | Structural gate stops at `workspace Cargo.lock digest ratchet changed`; it does not establish a Rust compilation failure |
| cargo-vet, two jobs | 26 dependencies lack `safe-to-deploy` audits |
| Exact merge-binding attestation | Executed workflow invokes `gh` without `GH_TOKEN` and exits 4 |
| Isolated enterprise Linux capture dispatch | Controller exits 1 before dispatch; exact failing shell assertion is not printed |

The token failure requires attention to the executed workflow version. The
candidate's `enterprise-hardening.yml:88` already supplies `GH_TOKEN`, but
`.github/workflows/ci.yml:508` still invokes the immutable older definition at
`eba8cdf3fb2e16501947c58415a4739a23cc12b3`, whose corresponding step lacks it.
Publishing the candidate did not activate its corrected reusable workflow.
Resolve this through the existing reviewed definition/authorization process.

The retained capture prerequisite audit also confirms that the workspace lock
digest differs from the execution-image lock and that capture authorization is
not ready. Keep these prerequisites distinct from the passing local cage run.

Relevant hosted evidence:

- [Build/structural gate](https://github.com/bb-connor/arc/actions/runs/35102063789/job/104813695468)
- [Missing dependency audits](https://github.com/bb-connor/arc/actions/runs/35102063789/job/104813695780)
- [Merge-binding token failure](https://github.com/bb-connor/arc/actions/runs/35102063789/job/104813695970)
- [Capture controller failure](https://github.com/bb-connor/arc/actions/runs/35102058857/job/104813675818)

## Recommended next steps

1. Close the two reproducible CI hygiene failures and rerun their owning lanes.
2. Finish the current candidate workspace run and exact foundation inventories.
   Keep its terminal result separate from the successful older targeted reruns.
3. Complete the reviewed dependency audits, execution-image lock update and
   trusted workflow/source authorization work. The merge-binding fix already
   exists in candidate code but is not in the executed pinned definition.
4. Complete designated capture and remaining M5 acceptance. Then resume M6/M7
   composition and the deferred M8 recovery campaign.

The repair follows the prior review's requested direction and has useful fresh
positive evidence. The next bottleneck is completing qualification and its CI
prerequisites, not expanding the feature set.

## Scope and workspace effects

Reviewed both new commits, their production receipt/verification path, regression
tests and fixture provenance; inspected retained gate outputs and current hosted
failure logs. Reran fresh policy substitution checks, matrix verification and
negative cases, direct process rustfmt, and accumulated diff whitespace checks.
No broad Cargo job was launched alongside the active foundation campaign.

Only this follow-up report and its isolated local evidence were added. Runtime
source, execution branches, remote PRs and unrelated dirty work were preserved.
