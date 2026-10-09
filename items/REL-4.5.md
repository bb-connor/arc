---
id: "REL-4.5"
title: "Operator onboarding kit and runbooks for HOST-M1 pairs"
severity: "P1"
wave: 2
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-2.9", "COOP-1.9", "COOP-2.1", "COOP-1.8c", "OUT-4.1", "REL-1.8"]
paths: ["docs/operator-runbook/onboarding-kit/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-4 ("plus the onboarding kit and runbooks"), G2. One kit an outside operator follows end to end: install the preview (REL-1), run `chio trust serve` as a service (COOP-1.6 packaging), set up key custody (COOP-1.8a to COOP-1.8c), exchange partner cards (`chio partner add`, COOP-2.1), configure the door, run the six G2 steps, publish the independent-operation record (OUT-4.1). Link the rotation runbook and TLS recipe (COOP-2.9) rather than duplicating them.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- An agent following only the kit on two clean hosts completes the six G2 steps (proved by G2-REHEARSAL, which uses this kit verbatim).
- No em dashes; every command in the kit is copy-paste runnable and tested by a shellcheck pass.

## Log
- 2026-10-09T04:51:58Z connor: created
