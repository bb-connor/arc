# Trajectory 5 Readiness Summary

**Date**: 2026-05-08.
**Baseline SHA**: `708c7bb33df43594f5e76542b05fca7a56d9689e`.
**Status**: planning-map-ready, release-blocked.

This summary supersedes earlier wording that treated Trajectory 5 as a
release/tag vehicle. Trajectory 5 is an assurance and integration program whose
only closure modes are accepted planning/integration map or accepted assurance
matrix.

## Current Truth

- PR #620 owns planning truth for `.planning/trajectory-5/**`.
- `MERGE-TRAIN.toml` owns the exact Trajectory 5 train policy.
- Merge operations are merge-commit-only and stop on any non-clean GitHub state.
- Lane B source enforcement must integrate first.
- Lane A evidence is regenerated from merged Lane B source after ownership is
  clean.
- Lane C is a canary demo after Lane B, not a release driver.
- #618 deferred package seed remains last; it is not a release vehicle, not
  active package evidence, and remains excluded from release qualification until
  package-owner promotion after merged-main regeneration.
- #627 and #628 are draft aggregate tails quarantined outside release/security
  review units.
- C5 selective disclosure is future work outside the current closure matrix.
- `docs/release/RELEASE_AUDIT.md` local-go posture does not apply to this
  trajectory.
- The bounded package status namespace is
  `releases.toml` `[v0_1_0_bounded_chiodome].release_status`, but PR #620 does
  not author that root package truth.

## Readiness Posture

| Area | Status | Reason |
|---|---|---|
| Planning ownership | READY | #620 is the sole planning owner and can close only as planning/assurance truth. |
| Merge policy | READY | `MERGE-TRAIN.toml` requires merge commits only, exact order, no squash/rebase/automerge, and stop on any failing GitHub state. |
| Lane B integration | BLOCKING | Source enforcement must land before canary or packaging. |
| Lane A assurance | BLOCKED/PARTIAL | Evidence must be regenerated from merged Lane B source; the current #620 diagnostic also fails because the bounded assurance manifest is missing and threat-mutants evidence is still bootstrap-placeholder only. |
| Lane C canary | BLOCKED | Canary evidence is downstream of Lane B. |
| #618 deferred/non-release package seed | DEFERRED/BLOCKED | Excluded from release qualification until a package owner promotes and regenerates it from merged `main`; it is not a release/tag vehicle. |
| #627/#628 aggregate tails | QUARANTINED | Draft aggregate tails only; not release-review units and not security-review units. |
| C5 selective disclosure | FUTURE | Not a closure row and not release evidence. |

## Merge-Train Policy

The active train is #620, then Lane B (#606, #612, #611, #609, #610), then Lane
A assurance (#601, #602, #605, #613, #607, #603, #619, #621, #622, #623, #626,
#624, #625, #604, #608, #616), then Lane C canary (#614, #615, #617).

#608 and #616 remain active ordered threat-evidence items. Their order is
enforced by the train policy, not by a branch-ancestry guarantee.

#618, #627, and #628 are outside the active train: #618 is a deferred packaging
seed, while #627/#628 are quarantined draft aggregate tails.

## Assurance Matrix

The live claim matrix is `SHIP-BAR-TRACKER.md`. It defines three claims:

1. Claim B: Lane B hot-path enforcement.
2. Claim A: Lane A assurance addendum.
3. Claim C: Lane C post-Lane-B canary.

The checker remains named `scripts/check-bounded-ship-bar.sh` for compatibility,
but it validates assurance evidence rather than release-tag readiness. Legacy C5
checker output is not a Trajectory 5 closure requirement.

## Executable Checks

- `bash .planning/trajectory-5/tools/planning-preflight.sh`
- `bash scripts/tests/check-bounded-ship-bar.test.sh`
- `bash scripts/check-bounded-ship-bar.sh --diagnostic` (expected FAIL while
  `audits/evidence/bounded-assurance-manifest.json` and non-placeholder
  threat-mutants evidence are missing)

Strict `scripts/check-bounded-ship-bar.sh` must fail while any claim is partial.
The diagnostic mode must also fail while real `FAIL` rows remain.

## RW5 Closure

Closed for PR #620 prose: RW5-BI-P0-001, RW5-BI-P0-002, RW5-BI-P1-003,
RW5-BI-P1-004, RW5-BI-P2-002, and RW5-BI-P2-003.

## RW6 Closure

Closed for graph/topology scope: RW6-MG-P0-001, RW6-MG-P1-001,
RW6-MG-P2-001, RW6-MG-P2-002, RW6-BI-P0-003, graph/topology scope of
RW6-BI-P0-004, and graph/topology scope of RW6-BI-P2-001.
