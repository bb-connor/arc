---
id: "UR-LEDGER-CARRY"
title: "PR ledger carry-forward register for every PR the roadmap closes"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["docs/operations/PR-CARRY-FORWARD.md", "docs/operations/pr-carry-forward.json", "scripts/carry-forward-requirements.py", "scripts/tests/carry-forward-requirements.test.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 7 rule ("no PR closes until its ledger requirements are carried forward"). The requirements live in `docs/security/landing-ledger.json` (on #1160 head; schema `chio.security-landing-ledger.v1`), array `requirements`, keyed by `landing_pr` and `landing_unit`. Counts on #1160 head: #957 25, #958 57, #959 54 (total 136, matching the roadmap), #956 27, #1164 12, #1046 2, #1073 1. The ledger also holds rows the roadmap's rule omits: #1159 15, #1171 5, #1172 2, #1158 1 and #1168 25; include them.

Write `scripts/carry-forward-requirements.py` that reads the ledger (read-only; never rewrite the ledger) and emits `docs/operations/pr-carry-forward.json` plus a human `PR-CARRY-FORWARD.md`: one row per requirement ID with source PR, label, disposition, and the destination backlog item ID (for example ECON-SALVAGE-959, REL-1.SALVAGE-1046, REL-SALVAGE-1164.*), or `owner-adjudication` when no item owns it. Also record the two non-row obligations: the FV-D3 dependency on #959's netting code, and #1029's singular-approval ADR decision (owner pending, see parked UR-PK-1029-ADR).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/carry-forward-requirements.py --check` exits 0 and prints per-PR counts equal to the ledger (25/57/54/27/12/2/1/15/5/2/1/25).
- `scripts/tests/carry-forward-requirements.test.py` covers: count parity, every requirement mapped to exactly one destination, unknown destination IDs rejected.
- The JSON validates against a schema embedded in the script; no requirement text is altered.

## Log
- 2026-10-09T04:51:58Z connor: created
