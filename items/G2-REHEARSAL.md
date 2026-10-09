---
id: "G2-REHEARSAL"
title: "G2 rehearsal: internal two-domain HOST-M1 run with revocation and rotation drills"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-1.10", "COOP-1.8b", "COOP-1.8c", "COOP-1.9", "COOP-2.3", "COOP-2.5", "COOP-2.6b", "COOP-2.7", "COOP-2.8", "COOP-2.9", "COOP-4.3", "REL-4.1", "REL-4.2", "REL-4.3", "REL-4.4", "REL-4.5", "OUT-4.1", "OUT-4.2", "G1-REHEARSAL"]
paths: ["docs/runbooks/cooperate/HOST-M1-RUNBOOK.md", "scripts/cooperate0/**", "docs/records/g2/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G2 ("an outside team and its counterparty each run their own domain end to end: passport; challenge; inbox; holder pickup; allow and deny at the door; offline verification against a pinned partner card"; exit also requires live revocation propagation, an exercised rotation and a published independent-operation record). This item rehearses G2 internally so the outside run (parked UR-PK-G2-OUTSIDE, which also needs UR-D13 and UR-D14) only exercises the outside team. Two internal operators on a Linux host and a macOS host, each with its own domain (`chio trust serve`), OS key custody (no plaintext seeds), and partner cards exchanged with `chio partner add`. Run the six steps using only the onboarding kit (REL-4.5), then drill: A revokes a passport mid-run and B's door denies within the feed TTL; B rotates its authority key and the door keeps serving. File an independent-operation record (OUT-4.1 format) labelled "internal rehearsal" (it never counts as G2), and review it against the G2 rows of `docs/records/gate-claims.yaml`. Uses candidate artifacts; re-run against the tag once REL-1.9 publishes.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `scripts/cooperate0/host-a.sh` and `host-b.sh` complete all six steps on two hosts and emit a machine-readable result.
- Revocation drill: deny receipt observed within the configured TTL; rotation drill: zero failed admissions during rotation.
- The record passes `python3 scripts/check-independent-operation-record.py` and is committed under `docs/records/g2/`.

## Log
- 2026-10-09T04:51:58Z connor: created
