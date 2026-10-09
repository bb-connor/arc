---
id: "WORK-SLICE-E.1"
title: "Slice epsilon: broker launch-owner parent-death protection (re-derive against #1160)"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["crates/security/chio-secret-broker/src/native_mcp.rs", "crates/security/chio-secret-broker/src/native_mcp/launch_owner.rs", "crates/security/chio-secret-broker/src/native_mcp/launch_owner/tests.rs", "crates/security/chio-secret-broker/src/process_boundary_tests/native_confined.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice epsilon (confined PostgreSQL and broker: re-derived from #1160 or dropped). Keep only the broker fix that preserves Linux parent-death protection across Tokio worker retirement; it is the same defect class as `MINISW-PDEATH` in the process host (SEC-POSTMERGE.4), so share the approach. Drop the PostgreSQL campaign files (owner choice parked as UR-PK-PG-CAMPAIGN).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- New launch-owner tests pass on Linux (`cargo test -p chio-secret-broker launch_owner`), including a test that the child survives retirement of the Tokio worker thread that spawned it.

## Log
- 2026-10-09T04:51:58Z connor: created
