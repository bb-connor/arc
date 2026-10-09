---
id: "G3-REHEARSAL"
title: "G3 exit run: HOST-M2 on Linux with recorded evidence"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-1.4", "SHARE-1.5", "SHARE-1.6", "SHARE-2.2", "SHARE-2.3", "SHARE-2.4", "SHARE-3.1", "SHARE-3.2", "SHARE-3.3", "SHARE-3.4", "KERN-3.D5", "KERN-3.D6", "KERN-3.EXIT", "KSPEC-04.P2.2", "KSPEC-07.S1", "KSPEC-07.S2b", "KSPEC-07.BK", "REL-3.1", "REL-3.2", "REL-3.3", "REL-3.5", "WORK-SLICE-B.6", "OUT-4.2"]
paths: ["tests/integration/linux/g3/**", "docs/records/g3/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G3 (one root grant across Claude Code and Codex on one Linux host; family money cap and model spend held; restart never replenishes; live cancel and revoke cascade; swarm admission on the serving path; isolation evidence recorded by KSPEC-07 kind). Script the whole G3 run on a clean Linux host (container or VM), capture receipts and isolation evidence, and file a record under `docs/records/g3/` with the gate claims from `docs/records/gate-claims.yaml` (G3 rows) and their `boundary_class`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `tests/integration/linux/g3/run.sh` completes on a clean Linux host and emits a machine-readable result; every G3 bullet maps to a passing check.
- The record cites KSPEC-07 backend kinds for every isolation claim; anything unconfined is rendered "unconfined".

## Log
- 2026-10-09T04:51:58Z connor: created
