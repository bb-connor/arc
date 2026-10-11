# FV-E5 promotion runbook, executed against the Kani lanes

Status: Executed locally (2026-09-26); the posture flip is one CODEOWNERS
change away and is written out below.
Feeds: [FV-B5](FV-B5-verus-concurrency-evaluation.md) (its enforcement
precondition is "one existing lane has completed this runbook"),
[FV-E5](FV-E5-lane-ratchets.md) (the runbook this document executes).
Related: `releases.toml` (`[gates.kani-public-nightly]`, `[gates.kani-public-pr]`),
`scripts/lane-gate.sh`, `.github/workflows/nightly.yml`,
`.github/workflows/formal-pr-smoke.yml`, `.github/workflows/ci.yml`,
`.kani/harnesses.toml`, `scripts/run-kani-manifest.sh`.

## Why this document exists

FV-E5 built the promotion machinery and registered fifteen advisory lanes.
None has been promoted. FV-B5 proved the concurrent conservation law under
Verus and then declined to add a lane, because the estate's rule is that no
seventh proof toolchain is added until one existing lane has completed the
promotion runbook: the enforcement layer has to be exercised before the
estate widens. The hardening toolchain spec (H6) names the PR-tier Kani lane
as the natural candidate.

This document is that runbook written as a checklist, with the evidence each
step requires, executed as far as it can be from a checkout with GitHub API
access, and with every outcome recorded against the commit and time it was
observed. It changes no registry entry: `releases.toml` is CODEOWNERS-gated
and the flip must be its own reviewed change. Everything that change needs is
below.

Every command was run from `packet/k-gates` at base `3788269c6a` on
2026-09-26 between 19:20 and 19:40 UTC, with `gh` authenticated as the
repository owner.

## Step 0: which Kani lane

There are two registered Kani lanes and one unregistered Kani job.

| Identity | Where it runs | Event | Registry posture | Notes |
| --- | --- | --- | --- | --- |
| `kani-public-nightly`, job `kani-public-nightly (lanes.pr + lanes.nightly_only)` | `nightly.yml` | `schedule` | advisory, reset after run 29003108285, 48 h freshness | all 49 `lane = "pr"` harnesses plus the nightly-only set |
| `kani-public-pr`, job `kani-public-pr (lanes.pr sweep)` | `formal-pr-smoke.yml` | `pull_request` | advisory, **frozen**: "the path-scoped workflow has no run-always aggregator or real-execution marker uploader" | path-filtered; a PR that touches no proof path skips it |
| job `kani-public-pr (all lane=pr harnesses)` | `ci.yml` | every PR and push to `main` | **not registered** | run-always; required through the `Security contract` aggregate job |

The lane that actually gates every pull request is the third row, and the
registry does not know it. The registered PR entry points at the path-scoped
twin, which is why it is frozen and always will be until it is re-pointed.
The nightly lane is the only Kani lane whose registry entry can be promoted as
it stands, and a scheduled lane is exactly what FV-B5's precondition needs:
"completed the runbook" means posture `required` with reviewed
`promotion_evidence`, and for a scheduled lane that is the whole of it (no
ruleset step, per runbook step 6).

Decision for this execution: run the runbook against `kani-public-nightly`,
and record what unfreezing `kani-public-pr` takes so the PR-tier lane can
follow.

Evidence for the row facts: `releases.toml` lines 139 to 146 and 255 to 266;
`nightly.yml:259` and `formal-pr-smoke.yml:282` (terminal `lane-gate.sh`
steps); `ci.yml` job `kani-public-pr` (no `lane-gate.sh` step, no
`lane-executed-` artifact anywhere under `.github/workflows/`);
`scripts/run-kani-manifest.sh --lane pr --list` (49 harnesses: 32 in
`chio-kernel-core`, 5 `chio-anchor`, 4 `chio-attest-verify`, 4 `chio-weights`,
2 `chio-credit`, 1 `chio-web3`, 1 `chio-open-market`).

## Step 1: a fresh streak of `required_streak` successes after the reset

**Action.** `scripts/lane-gate.sh kani-public-nightly --report`.

**Evidence required.** `streak=7/7`, `freshness=fresh`, every evidence row
`conclusion=success` on its latest attempt, all run IDs newer than
`evidence_after_run_id`.

**Executed.** 2026-09-26, output verbatim (eight lines; the SHA-256 of this
exact text, with a trailing newline, is
`85185c2d387fa258667476a3d0a210f8626f8d68763a1bbb2b58ada769fda325`):

```
lane-gate: lane=kani-public-nightly posture=advisory event=schedule job="kani-public-nightly (lanes.pr + lanes.nightly_only)" streak=7/7 activation_target=n/a latest=36232713853 freshness=fresh reset_after=29003108285 current=not_applicable verdict=report
lane-gate-evidence: lane=kani-public-nightly run_id=36232713853 attempt=1 created_at=2026-09-26T09:25:10Z conclusion=success strict=n/a real_execution=n/a scored=n/a url=https://github.com/bb-connor/arc/actions/runs/36232713853
lane-gate-evidence: lane=kani-public-nightly run_id=36119808172 attempt=1 created_at=2026-09-25T09:41:03Z conclusion=success strict=n/a real_execution=n/a scored=n/a url=https://github.com/bb-connor/arc/actions/runs/36119808172
lane-gate-evidence: lane=kani-public-nightly run_id=35980925019 attempt=1 created_at=2026-09-24T09:23:21Z conclusion=success strict=n/a real_execution=n/a scored=n/a url=https://github.com/bb-connor/arc/actions/runs/35980925019
lane-gate-evidence: lane=kani-public-nightly run_id=35842603647 attempt=1 created_at=2026-09-23T09:23:01Z conclusion=success strict=n/a real_execution=n/a scored=n/a url=https://github.com/bb-connor/arc/actions/runs/35842603647
lane-gate-evidence: lane=kani-public-nightly run_id=35709994662 attempt=1 created_at=2026-09-22T09:22:22Z conclusion=success strict=n/a real_execution=n/a scored=n/a url=https://github.com/bb-connor/arc/actions/runs/35709994662
lane-gate-evidence: lane=kani-public-nightly run_id=35586686351 attempt=1 created_at=2026-09-21T10:03:45Z conclusion=success strict=n/a real_execution=n/a scored=n/a url=https://github.com/bb-connor/arc/actions/runs/35586686351
lane-gate-evidence: lane=kani-public-nightly run_id=35502065763 attempt=1 created_at=2026-09-20T09:21:07Z conclusion=success strict=n/a real_execution=n/a scored=n/a url=https://github.com/bb-connor/arc/actions/runs/35502065763
```

**Outcome: met.** Seven consecutive scheduled successes, 2026-09-20 through
2026-09-26, every one a first attempt, all after the reset.

The same command for the PR lane, for the record:

```
lane-gate: lane=kani-public-pr posture=advisory event=pull_request job="kani-public-pr (lanes.pr sweep)" streak=0/7 activation_target=n/a latest=36262048464 freshness=fresh reset_after=0 current=not_applicable verdict=report
lane-gate-barrier: lane=kani-public-pr run_id=36262048464 attempt=1 created_at=2026-09-26T18:18:05Z conclusion=cancelled reason=job_not_successful
```

**Outcome for the PR lane: not met**, and not meetable while frozen: the
latest run was cancelled, the streak is 0, and even seven greens would not
count without the execution marker (step 3).

## Step 2: the posture-flip change

**Action.** A change that edits only `releases.toml`: set
`posture = "required"` and add `promotion_evidence` with exactly
`required_streak` run IDs newer than the reset and the digest of the exact
`--report` output. Paste that output in the change description. CODEOWNERS
review applies because `releases.toml` is CODEOWNERS-gated.

**Evidence required.** The `--report` output and its SHA-256 from step 1,
taken at flip time.

**Executed: no.** This lane owns no registry file. The edit, as of the
step 1 report, is:

```toml
[gates.kani-public-nightly]
workflow = "nightly.yml"
job = "kani-public-nightly (lanes.pr + lanes.nightly_only)"
event = "schedule"
posture = "required"
required_streak = 7
evidence_after_run_id = 29003108285
max_age_hours = 48
promotion_evidence = { run_ids = [36232713853, 36119808172, 35980925019, 35842603647, 35709994662, 35586686351, 35502065763], report_sha256 = "85185c2d387fa258667476a3d0a210f8626f8d68763a1bbb2b58ada769fda325" }
```

The window moves nightly. Whoever lands the flip re-runs step 1 that day,
takes the seven run IDs and digest it prints, and uses those; the values
above are correct for 2026-09-26 and will be stale by the time they are
reviewed. `scripts/lane-gate.sh` verifies at load time that the list has
exactly seven unique IDs newer than the reset, so a stale list fails closed
rather than silently.

**Outcome: ready.** One reviewed change completes the runbook for this lane
and satisfies FV-B5's precondition.

## Step 3: unfreezing the pull-request lane

**Action.** In one reviewed change: replace the path-scoped job with a
run-always one, bind the registry entry to `main`, and make the real proof
job upload `lane-executed-kani-public-pr-<run_id>-<run_attempt>` only after
the verification command succeeds. A successful skip must upload nothing.

**Evidence required.** The registry entry points at the run-always job;
`--report` shows `real_execution=yes` on new runs.

**Executed: no**, and deliberately not half-executed. The workflow half is
in this lane's ownership; the registry half is not. Adding a marker upload to
`ci.yml` while the registry still names `formal-pr-smoke.yml` would produce an
artifact nothing looks for, and adding a terminal `lane-gate.sh kani-public-pr`
step to the `ci.yml` job would report the path-scoped twin's history under the
run-always job's name. Both halves land together or the evidence is wrong.

The change, when it is made:

Registry (`releases.toml`, `[gates.kani-public-pr]`): `workflow = "ci.yml"`,
`job = "kani-public-pr (all lane=pr harnesses)"`, drop `frozen` and
`frozen_reason`, keep `base_branch = "main"` and
`execution_artifact_prefix = "lane-executed-kani-public-pr-"`, and set
`evidence_after_run_id` to the last run before the change so the old job's
history cannot count.

Workflow (`ci.yml`, job `kani-public-pr`), after `run-kani-manifest.sh` and
before anything that could fail for another reason:

```yaml
      - name: Record real execution
        run: |
          mkdir -p target/lane-markers
          printf '%s %s\n' "${GITHUB_RUN_ID}" "${GITHUB_RUN_ATTEMPT}" > target/lane-markers/kani-public-pr
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: lane-executed-kani-public-pr-${{ github.run_id }}-${{ github.run_attempt }}
          path: target/lane-markers/kani-public-pr
          retention-days: 8
      - name: Record Kani PR lane posture
        if: always()
        env:
          GH_TOKEN: ${{ github.token }}
          LANE_EXIT: ${{ job.status == 'success' && '0' || '1' }}
          LANE_GATE_RATE_LIMIT_MODE: warn
        run: bash scripts/lane-gate.sh kani-public-pr
```

The job needs `actions: read` for the terminal step, and the marker step
must not be reachable from a skipped verification (the `ci.yml` job has no
path filter, so there is no skip path to guard today). Retention must exceed
`max_age_hours` (168 h) or a fresh success carries an expired marker.

## Step 4: branch protection

**Action.** Add the exact check name to the ruleset in the repository UI
after the posture flip merges.

**Executed: not applicable** to the nightly lane (scheduled lanes are
required in the fleet sense only, step 6). For the PR lane, after step 3,
the check name is `kani-public-pr (all lane=pr harnesses)`; it is already
required indirectly through `Security contract`, so the ruleset change is a
direct requirement in addition, not a new gate.

## Step 5: demotion path

**Action.** Set `posture = "advisory"`, remove `promotion_evidence`, add an
incident note. A frozen lane stays unpromotable until the same reviewed
change resolves its reason.

**Executed: not applicable** (nothing is promoted). Recorded so the flip
change can cite the reversal it commits to.

## Step 6: what a required scheduled lane gates

**Action.** `scripts/lane-gate.sh --fleet`, which release qualification runs
after strict workspace qualification.

**Executed.** 2026-09-26T19:36:40Z:

```
lane-gate: fleet required=0 verdict=pass
```

**Outcome.** No lane is required, so the fleet gate passes vacuously; after
step 2 it evaluates `kani-public-nightly` and fails a release whose latest
nightly Kani run is missing, older than 48 hours or unsuccessful. That is the
teeth the precondition is asking to see.

## The lane itself, run locally

The runbook promotes evidence about a lane; it is worth checking the lane
holds at the commit the evidence is being written against.

**Action.** `scripts/run-kani-manifest.sh --lane pr` with `cargo-kani 0.67.0`
(the `CHIO_KANI_VERSION` pinned in `ci.yml`), in an isolated target
directory, time-boxed to one hour.

**Executed.** 2026-09-26, `CARGO_TARGET_DIR` set to a directory used for
nothing else, `CARGO_BUILD_JOBS=3`, on the aarch64 host while other lanes were
building (load average between 8 and 21).

**Outcome.** `run-kani-manifest.sh: 49 harnesses passed (lane=pr)`, exit 0,
2,842 s wall clock including compilation, no harness failed. The
`kani-public-nightly` evidence above was produced by the same harness set
plus the nightly-only set on the hosted runner; this local run confirms the
PR set holds at the commit the promotion evidence is being written against.

## What this changes for FV-B5

Nothing yet. The precondition reads "at least one existing lane has completed
the FV-E5 promotion runbook", and completion is the merged posture flip. As
of this document every step that does not require a CODEOWNERS edit or a
repository-settings change is executed and green, and the edit is written
out. The Verus lane decision in FV-B5 stays where it is until that change
merges; this document is the evidence it needs.
