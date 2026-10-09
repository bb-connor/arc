---
id: "WORK-SLICE-D.1"
title: "Slice d: verifiable-work paper documents"
severity: "P2"
wave: 2
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-0.1"]
paths: ["docs/papers/verifiable-work/**", ".github/workflows/paper-artifact-check.yml"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice d (paper and research documents; separate docs PR). The paper checker pins commits reachable only from #1173: make the workflow fetch the archive tags (WORK-SLICE-0.1) with `fetch-depth: 0`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `make -C docs/papers/verifiable-work test` and `make -C docs/papers/verifiable-work check` pass on main.

## Log
- 2026-10-09T04:51:58Z connor: created
