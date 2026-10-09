---
id: "G5-KIT"
title: "Outside-team HOST-M3 kit (self-serve, repeatable without Backbay's help)"
severity: "P2"
wave: 4
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["G5-PREVIEW", "G5-QUALIFY", "REL-4.5", "WORK-W3.3c"]
paths: ["docs/operator-runbook/host-m3-kit/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G5 ("two outside teams each complete a qualifying run ... at least one team repeats its run unassisted"), section 1 criterion (g), OUT-1 ("teams onboard at G2 so that their infrastructure, keys and working relationship already exist by G5"). Extend the HOST-M1 onboarding kit to the full M3 run: install the HOST-M3 preview, enable the work owner service and co-signer, write a treaty profile, run an agent proposing work with the WORK-W3 client or the reference applications, act as evaluator, export and verify the package, run `scripts/check-qualifying-run.py`, file the record. Include a "repeat run" checklist that needs no Backbay involvement. No go-to-market content.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- An agent with no prior context completes a full M3 run on two clean hosts using only the kit, and `check-qualifying-run.py` passes criteria (a) to (f) for it (recorded as internal).

## Log
- 2026-10-09T04:51:58Z connor: created
