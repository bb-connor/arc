---
id: "WORK-SLICE-G.3"
title: "Gamma: federation remote projection and kernel treaty fixtures"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-G.1", "WORK-SLICE-A.3"]
paths: ["crates/kernel/chio-kernel/src/admission_operation/remote_projection.rs", "crates/kernel/chio-kernel/src/admission_operation/projection.rs", "crates/kernel/chio-kernel/src/admission_operation/projection/participant_presence.rs", "crates/kernel/chio-kernel/src/admission_operation_tests/terminal_projection.rs", "crates/kernel/chio-kernel/tests/support/treaty_dsse.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice gamma (federation, bilateral DSSE, iroh lanes, treaty runtime-core; roadmap: after alpha and beta, needed for the remote co-signer). No crate-level conflicts with #1160. Remote projection of federated admission for the receiver-owned door.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-kernel terminal_projection` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
