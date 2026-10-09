---
id: "G4-DRILLS"
title: "G4 drills: lost reply, crash, co-signer down, stop, revoke mid-work"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["G4-RUN", "KSPEC-08.P1.11", "SHARE-3.2", "REC-P3.N24"]
paths: ["tests/integration/host-m3/drills/**", "docs/records/g4/drills/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G4 drills ("lost reply; crash; co-signer down; stop; revoke mid-work"). On the G4-RUN topology: (1) drop B's reply after dispatch commit; A recovers by original identity with exactly one effect and no second dispatch (REC-EXIT, WORK-W2.4); (2) kill B's host mid-run; restart never replenishes a pool and recovery completes; (3) take A's co-signer down; work reports Pending, never redispatches, and completes when it returns (COOP-3.3a); (4) operator stop on B via route and socket; restart comes up `ready_stopped`; resume releases withheld output once (KERN-1); (5) revoke A's grant mid-work; the subtree is denied before effect and cancelled through the fence (SHARE-3.2, KSPEC-04). Every drill produces receipts that A verifies offline.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Each of the five drills has a script under `tests/integration/host-m3/drills/` that passes on two hosts and asserts its invariant (effect count, pool size, Pending state, stop state, deny-before-effect).
- Drill results are recorded under `docs/records/g4/drills/`.

## Log
- 2026-10-09T04:51:58Z connor: created
