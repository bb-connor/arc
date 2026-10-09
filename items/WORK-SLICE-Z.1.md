---
id: "WORK-SLICE-Z.1"
title: "Slice zeta: security and CI triage against #1160"
severity: "P2"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-0.1"]
paths: ["docs/research/work-abstraction/SLICES.json"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice zeta (security and CI: re-derived from #1160 or dropped; about 75 conflicting CI, scripts, deploy, formal, xtask, supply-chain and SDK package files). Mark each zeta file `in #1160`, `re-derive` or `drop` in the manifest. For each `re-derive` (for example return-context caller custody from commit 93a2552c3, unused-cumulative and DPoP rules), write a one-paragraph follow-up note in the manifest naming target paths and tests so it can be filed as a backlog item; AWS-LC and npm repairs go to REL-1; regenerated SDK files are never merged (regenerate).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Every zeta file has a disposition; `python3 -I scripts/check-work-slices.py` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
