---
id: "WORK-SLICE-B.3"
title: "Beta: S1 swarm extension verifier"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["crates/kernel/chio-swarm-authority/src/evolution.rs", "crates/kernel/chio-swarm-authority/src/lib.rs", "crates/kernel/chio-swarm-authority/README.md", "crates/kernel/chio-swarm-authority/tests/swarm_authority_stage0.rs", "crates/kernel/chio-swarm-authority/tests/swarm_authority_stage0/evolution.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 5.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice beta (D1 dynamic delegation, S1 swarm evolution, A2A v1 edge; lands right after Gate 0; 2 conflicts). None of the beta paths reference alpha or delta symbols. Resolve the `mod` line conflict in `tests/swarm_authority_stage0.rs` by keeping both #1160's `graph_bounds` and #1173's `evolution`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-swarm-authority --test swarm_authority_stage0` passes (5 evolution tests plus #1160's graph_bounds tests).

## Log
- 2026-10-09T04:51:58Z connor: created
