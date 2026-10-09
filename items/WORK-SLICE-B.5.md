---
id: "WORK-SLICE-B.5"
title: "Beta: A2A v1 edge core"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["crates/protocol/chio-a2a-edge/README.md", "crates/protocol/chio-a2a-edge/src/bridge.rs", "crates/protocol/chio-a2a-edge/src/config.rs", "crates/protocol/chio-a2a-edge/src/conversion.rs", "crates/protocol/chio-a2a-edge/src/edge.rs", "crates/protocol/chio-a2a-edge/src/error.rs", "crates/protocol/chio-a2a-edge/src/lib.rs", "crates/protocol/chio-a2a-edge/src/task_completion.rs", "crates/protocol/chio-a2a-edge/src/v1.rs", "crates/protocol/chio-a2a-edge/src/tests/**", "crates/tooling/chio-conformance/tests/a2a_client_edge_interop.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice beta (D1 dynamic delegation, S1 swarm evolution, A2A v1 edge; lands right after Gate 0; 2 conflicts). None of the beta paths reference alpha or delta symbols. Merge with #1160's `jsonrpc.rs` and `tests/boundaries.rs` in that crate.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-a2a-edge` (14 v1 tests, for example `v1_get_observes_legacy_tasks_without_dispatching_them`) and `cargo test -p chio-conformance --test a2a_client_edge_interop` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
