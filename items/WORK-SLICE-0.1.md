---
id: "WORK-SLICE-0.1"
title: "Archive #1173 refs and write the slice manifest"
severity: "P1"
wave: 1
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["docs/research/work-abstraction/SLICES.json", "scripts/check-work-slices.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Roadmap: Lane WORK (#1173 split by path into alpha, beta, gamma, c, d, delta; epsilon and zeta re-derived or dropped; close when slices land). Before any slice closes #1173, create archive tags so the paper checker's pinned commits stay reachable: `archive/pr1173-cafdc970e`, `archive/paper-historical-71e5cbc3b`, `archive/paper-foundation-7755d376`, and one for 611660eb2 (`docs/papers/verifiable-work/tools/provenance.py:11` and `check.py:306` pin them; they are reachable only from #1173). Write a manifest assigning each of the 6,637 files to alpha/beta/gamma/c/d/delta/epsilon/zeta with a disposition (land, re-derive, drop, archive) and record the 113-file conflict classification against #1160 (roadmap says 112): alpha about 9 core conflicts, delta about 10, zeta about 5 plus about 75 CI/scripts files, epsilon 12, beta 2, gamma 0. The #1162 outcome-continuation code (`chio-runtime-core/src/outcome_continuation.rs`, `store/sqlite/outcome_continuation.rs`) is assigned to no roadmap slice: mark it `parked` (UR-PK-1162-OUTCOME).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 -I scripts/check-work-slices.py` proves full coverage of `git diff --name-only 75d679670 cafdc970e` with no duplicates; `git ls-remote --tags origin 'archive/*'` lists the four tags.

## Log
- 2026-10-09T04:51:58Z connor: created
