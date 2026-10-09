---
id: "WORK-W2.5b"
title: "W2.5: separate-host run, owner-boundary review and external handoff kit"
severity: "P2"
wave: 4
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W2.5a", "G4-DRILLS"]
paths: ["examples/owner-work/HANDOFF.md", "docs/papers/verifiable-work/trial/README.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Run the package on two separately operated hosts (Backbay-operated for now), review the owner boundary, and write the handoff an outside team receives. The handoff itself to outside teams is parked (UR-PK-G5-RUNS).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Separate-host run recorded with an independent-operation record (OUT-4.1 format); handoff kit reviewed.

## Log
- 2026-10-09T04:51:58Z connor: created
