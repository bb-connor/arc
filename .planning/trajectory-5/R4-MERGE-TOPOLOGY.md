# R4 Merge Topology and Planning Ownership

Date: 2026-05-08
Scope owner: Wave 1 Worker A, graph and PR topology
Audit source: `reviews/FOURTH-ROUND-CODE-SECURITY-AUDIT-2026-05-08.md`

## Verdict

The old advertised merge train is invalid and must not be used. The release
source train starts with Lane B enforcement, not with a planning-led release
sequence. PR #620 is the sole owner for `.planning/trajectory-5/**`; source,
evidence, mutation, and threat PRs must not carry planning files.

Do not tag `v0.1.0-bounded-chiodome` from the current PR set. The #618
deferred package seed is not a release vehicle; it remains last and must be
regenerated from merged `main` after upstream source and evidence branches
land.

RW5 correction: Trajectory 5 is not a product release or tag vehicle. It is a
source-integration and assurance program with this order: Lane B integration
first, Lane A assurance regenerated from the merged Lane B source state second,
Lane C canary after Lane B, then #618 deferred package seed (not a release
vehicle) only after merged-main regeneration.

## RW6 Merge Policy

The machine-readable train policy is `MERGE-TRAIN.toml`. The human-readable
rules are:

1. Use merge commits only: `gh pr merge <number> --merge`. Do not squash, do not
   rebase-merge, and do not enable automerge.
2. Merge in the exact manifest order. A clean conflict simulation is not
   permission to skip or reorder a semantic dependency.
3. Stop before every step unless GitHub state is clean: PR is not draft, merge
   state is clean, required checks are successful, required reviews are
   satisfied, and no unresolved actionable review thread remains.
4. If any step fails local merge simulation or GitHub state, stop the train and
   repair the owning PR. Do not side-select through the failure on a tail branch.
5. PRs #627 and #628 are draft aggregate tails. They are quarantined deferred
   tails, not release-review units, not security-review units, and not fallback
   merge vehicles for Trajectory 5 qualification.

The active order is:

```text
#620
-> #606 -> #612 -> #611 -> #609 -> #610
-> #601 -> #602 -> #605 -> #613 -> #607
-> #603 -> #619 -> #621 -> #622 -> #623 -> #626 -> #624 -> #625
-> #604 -> #608 -> #616
-> #614 -> #615 -> #617
```

#618 is excluded from release qualification as a deferred packaging seed. It can
only be reconsidered after Lane B has landed on `main`, Lane A evidence has been
regenerated from merged `main`, Lane C canary fixtures have been regenerated from
merged `main`, and the package owner records bounded package metadata.

## Planning Ownership

PR #620 owns all trajectory-5 planning truth:

- `.planning/trajectory-5/**`
- legacy ship-bar planning ledgers, now assurance-matrix compatibility records
- readiness and closeout coordination docs
- merge-topology records and simulation logs

Current non-planning branch cleanup result:

| PR | Role | Planning paths after cleanup |
|---|---|---:|
| #602 | TLA evidence | 0 |
| #603 | mutation aggregate owner | 0 |
| #604 | threat batch 1 | 0 |
| #608 | threat batch 2 | 0 |
| #616 | threat batch 3 | 0 |
| #619 | chio-attest-verify mutation evidence | 0 |
| #621 | chio-guards mutation evidence | 0 |
| #622 | chio-anchor mutation evidence | 0 |
| #623 | chio-policy mutation evidence | 0 |
| #626 | chio-kernel-core mutation evidence | 0 |

Per-crate mutation PRs are narrowed to their own
`audits/evidence/mutants/<crate>/**` tree plus matching
`audits/mutation/per-crate-configs/<crate>.toml`. Shared aggregate state,
the root README mutation banner, and Lane A triage scripts belong to #603.

## Security-Reviewable Replacement Strategy

The old 28-PR autonomous train is not a security review unit. A graph that
merges cleanly is only a conflict result; it is not release readiness. Reviewers
must be able to inspect one integrated source posture, then regenerated evidence,
then a canary, then packaging.

1. Merge or keep #620 as the planning truth record. Treat it as planning
   control data, not as a release signal.
2. Create a clean Lane B enforcement integration branch from current `main`.
   Land enforcement sources before canary/demo/deferred package seed work. The
   source order is:
   - #606 async trait foundation
   - #612 single-entry verifier, rebased to B1-only if needed
   - #611 receipt v2 fail-closed
   - #609 anchor batch async-only
   - #610 DSSE signing foundation
3. Regenerate and merge Lane A assurance evidence after Lane B enforcement is
   real on the merged source state:
   - #601 and #602 formal evidence
   - #605, #613, and #607 Kani harness and CI evidence
   - #603 mutation aggregate owner
   - #619, #621, #622, #623, #626 per-crate mutation evidence
   - #624 and #625 after their owners confirm the same ownership rule
4. Threat evidence is now merge-clean in the Worker G chain. The refreshed
   sequence #604 -> #608 -> #616 is active and ordered. #608 and #616 are not
   branch-enforced ancestry guarantees; the train policy enforces the order. Do
   not treat the older #608 conflict note as current without a fresh simulation
   transcript and current branch-tip SHAs.
5. Lane C is a canary only after Lane B is merged and evidence is rerun.
   Rebase #614, #615, and #617 after #610 and #612 land. C5 selective
   disclosure is not a closure row; it remains future work outside this
   topology unless a later protocol-owned branch supplies real proof evidence.
6. #618 deferred package seed is last, is not a release vehicle, and is not
   active package evidence. Regenerate release notes, fixtures, and the
   assurance matrix from merged `main` only if a package owner later promotes the
   seed. If package metadata is authored, root `releases.toml`
   `[v0_1_0_bounded_chiodome]` is updated by the release owner then, not by
   #620.
7. Keep #627 and #628 quarantined. They may preserve aggregate-tail scratch
   work, but they must not ratify side-selection conflict resolutions. Useful
   changes must be split back into owned PRs or a new explicitly scoped PR before
   release or security review.

## Fix Wave 2 Lane B Sequencing

Refresh time: 2026-05-08T22:53:03Z

Worker A's Lane B slice is now explicitly stacked after #620 in this order:

| Step | PR | Head used for simulation | Role | Sequencing note |
|---:|---|---|---|---|
| 1 | #620 | `c2c06ec0fc` | planning and assurance-matrix coordination | Latest observed planning head before this refresh commit. |
| 2 | #606 | `76865083bb` | async trait foundation | Base for the protocol stack. |
| 3 | #612 | `63b63dafe5` | single-entry verifier | Merge parent includes #606 and carries the narrowed current-thread runtime diagnostic. |
| 4 | #611 | `05165c11d4` | receipt v2 fail-closed | Merge parent includes #612 and preserves receipt admission snapshots. |
| 5 | #609 | `246345f66e` | anchor batch async-only | Merge parent includes #611; CI anchor lint is a separate step so it can coexist with #620 assurance-checker wiring. |

The required local integration order for this slice is therefore:

```text
#620 -> #606 -> #612 -> #611 -> #609
```

Do not merge #609 before #612. Its protocol text assumes the #612
`verify_capability_full` production-admission wording and its branch head now
records that ancestry explicitly.

## Local Merge Simulation

Command shape:

```bash
SIM_WORKTREE="$(mktemp -d -t arc-r4-sim.XXXXXX)/work"
git worktree add --detach "$SIM_WORKTREE" origin/main
git -C "$SIM_WORKTREE" merge --no-edit --no-stat <origin/pr/N>
```

Simulation metadata:

```text
base=708c7bb33d origin/main
refs_refreshed=2026-05-08T21:35:24Z
```

Owned branch sequence:

```text
merge #620 (c2c06ec0fc) ... OK
merge #606 (76865083bb) ... OK
merge #612 (63b63dafe5) ... OK
merge #611 (05165c11d4) ... OK
merge #609 (246345f66e) ... OK
```

Earlier evidence-branch simulation, retained for context:

```text
merge #620 (cbe1736e5a) ... OK
merge #602 (124d8a8869) ... OK
merge #603 (d9b0219f75) ... OK
merge #619 (0dc573e6e9) ... OK
merge #621 (6f4095b600) ... OK
merge #622 (1c0317bcc0) ... OK
merge #623 (feb4559c19) ... OK
merge #626 (ed3e772bfe) ... OK
```

Threat branch current state after Worker G refresh:

```text
refs_refreshed=2026-05-08T22:37:11Z
merge #604 (40324814a6) ... OK
merge #608 (28792e5db1) ... OK
merge #616 (6c6270f9fa) ... OK
```

The older #608 conflict is closed for this planning topology record. Any future
threat-chain conflict should be reopened with a fresh simulation transcript and
the current branch-tip SHAs.

## RW6 Tail Quarantine

PR #627 (`codex/wave4a-base-hygiene`) and PR #628
(`codex/wave4a-evidence-gates-formal-kani`) are draft aggregate tails. Their
current role is deferred scratch aggregation only.

This topology chooses quarantine over a side-selection ledger. That means:

- No conflict resolution inside #627 or #628 is accepted as release truth.
- No side-selected file from #627 or #628 may override an owned active-train PR.
- #627 and #628 are excluded from ordered merge simulation pass/fail.
- #627 and #628 are excluded from the security-reviewable unit list.
- Any useful tail change must be split into the owning branch class: planning
  into #620, source into the Lane B or Lane C source PR, evidence into the Lane A
  evidence PR, or packaging into a later package-owner PR after #618 promotion.

## RW6 Graph Closure

| Issue | Status after this update |
|---|---|
| RW6-MG-P0-001 | Closed by `MERGE-TRAIN.toml` and RW6 Merge Policy: merge commits only, exact order, no squash, no rebase-merge, no automerge, and stop on any failing GitHub state. |
| RW6-MG-P1-001 | Closed by quarantining #627 and #628 as deferred aggregate tails instead of accepting side-selection conflict resolutions. |
| RW6-MG-P2-001 | Closed for #608/#616: both remain active ordered threat evidence items, but the ordering is graph-policy enforced rather than branch-ancestry enforced. |
| RW6-MG-P2-002 | Closed for #618: it is a deferred packaging seed excluded from release qualification until package-owner promotion after merged-main regeneration. |
| RW6-BI-P0-003 | Closed for graph scope: release/security review units are the active ordered PRs, not aggregate tails. |
| RW6-BI-P0-004 | Closed for graph scope: #627/#628 cannot be used as release/security review substitutes. |
| RW6-BI-P2-001 | Closed for graph scope: the manifest distinguishes active, excluded, and quarantined PR dispositions. |

## review finding Status

| Finding | Status after this update |
|---|---|
| R4-P0-001 | Closed for this Lane B slice. The false advertised train is replaced with the explicit #620 -> #606 -> #612 -> #611 -> #609 order above. Full-graph status still depends on other owners' lanes. |
| R5-P0-001 | Fixed-pending-review for this Lane B slice after local ordered simulation. Other R5 full-graph edges remain outside this slice. |
| R4-P1-008 | Fixed-pending-review for this slice. The #606 current-thread runtime diagnostic was propagated through #612's branch head. |
| P0-008 | Closed for planning truth. The plan now separates Lane B enforcement, Lane A evidence, Lane C canary, and deferred package seed work that is not a release vehicle. |
| P1-011 | Closed for owned branches. `.planning/trajectory-5/**` is centralized in #620 for the target PR set. |
| P1-013 | Partial. Titles can be cleaned, but AI/trajectory branch names still require PR recreation or branch rename outside this planning-file cleanup. |
| P2-003 | Partial. Per-crate mutation branches no longer carry aggregate README or shared triage files. Known source duplicate cleanup outside the owned set remains with source/evidence owners. |

## R6 Release-Architecture Closure

| Issue | Status |
|---|---|
| R6-P0-001 | Closed. Trajectory 5 is planning and assurance control data, not a product release or tag vehicle. |
| R6-P0-003 | Closed. The integration order is Lane B, then Lane A assurance, then Lane C canary. |
| R6-P0-004 | Closed. Executable gates do not use lane ticket inventories as release evidence. |
| R6-P1-005 | Closed. The old aggregate bar is replaced by `SHIP-BAR-TRACKER.md` claim-by-claim assurance matrix. |
| R6-P2-001 | Closed. Bounded package status namespace is documented as `[v0_1_0_bounded_chiodome].release_status`; #620 does not author root package truth. |
| R6-P2-002 | Closed. The load-bearing mutation evidence path is `audits/evidence/mutants/**`. |
| R6-P2-003 | Closed. The current checker is `scripts/check-bounded-ship-bar.sh`; stale script names are not part of the load-bearing contract. |
| R6-P2-007 | Closed. Lane C is a post-Lane-B canary. |
| R6-P2-009 | Closed. #618 deferred package seed is last, is not a release vehicle, and is regenerated from merged `main`. |

## RW5 Release-Architecture Closure

| Issue | Status |
|---|---|
| RW5-BI-P0-001 | Closed. Closure is planning/integration map or assurance matrix only, not release readiness. |
| RW5-BI-P0-002 | Closed. The review unit is Lane B integration, regenerated Lane A evidence, Lane C canary, and #618 deferred package seed last, not a release vehicle. |
| RW5-BI-P1-003 | Closed. C5 is future work outside the closure topology. |
| RW5-BI-P2-003 | Closed. `ship-bar` is treated as legacy compatibility naming only. |
