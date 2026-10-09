---
id: "WORK-SLICE-D.2"
title: "Slice d: research documents and history plans (summaries; raw evidence archived)"
severity: "P3"
wave: 3
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-0.1"]
paths: ["docs/research/dynamic-delegation/**", "docs/research/kernel-work/**", "docs/research/kernel-continuation/**", "docs/research/evolving-funded-work/**", "docs/research/swarm-evolution/**", "docs/papers/review-2026-09/**", "docs/papers/evidence-crosses/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Land summaries only; archive raw evidence (about 1.59M inserted lines under dynamic-delegation) by tag with hashes. The 2026-09/10 history plans go here too (narrow at claim time). `docs/market/open-agent-work/**` (913 files) contains go-to-market material and waits for D15 (parked UR-D15).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Docs links resolve; archive tag and hash list committed; no market material imported.

## Log
- 2026-10-09T04:51:58Z connor: created
