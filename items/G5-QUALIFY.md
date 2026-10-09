---
id: "G5-QUALIFY"
title: "Qualifying-run checker for success-test criteria (a) to (g)"
severity: "P2"
wave: 4
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["G4-RUN", "OUT-4.1", "OUT-4.2", "COOP-1.7"]
paths: ["scripts/check-qualifying-run.py", "scripts/tests/check-qualifying-run.test.py", "docs/records/QUALIFYING-RUN.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 1 (qualifying run criteria a to g), G5 ("the records are published and reviewed"), OUT-4. Mechanize what can be checked from an evidence package plus an independent-operation record: (a) separate domains, hosts and custody, no shared or Backbay-held partner keys, no party with both co-signer keys; (b) the requester's agent proposed the work and the executor admitted it at its own door under a co-signed attenuated commitment; (c) one root grant with holds, a lost reply recovered by original identity with no second dispatch; (d) named evaluator decision, at least one out-of-scope deny, a signed receipt per decision; (e) offline verification including the door's receipts; (f) tagged preview and a published record; (g) a repeat run flagged as unassisted. List explicitly which criteria need human attestation (for example "without Backbay's hands-on help").

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/tests/check-qualifying-run.test.py` passes with fixtures for a qualifying run and one failing fixture per criterion; G4-RUN's package passes criteria (a) to (e) with Backbay as both parties flagged as internal.

## Log
- 2026-10-09T04:51:58Z connor: created
