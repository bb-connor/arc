---
id: "UR-D8-LEDGER"
title: "Amend #1160's landing ledger for the D8 preview exception (release_permitted for labelled previews)"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["docs/security/audits/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 2
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Owner decision D8 (2026-10-09) allows tagged `0.2.0-alpha.N` previews before #1160's full-release obligations close, labelled as previews with claims limited under ADR-0011. #1160's landing ledger (`docs/security/audits/foundation-landing-boundary-20261008.json` and its ruling) records `release_permitted: false`. Amend the ledger so previews are permitted only under D8's conditions, and keep full releases blocked until the obligations close.

## Acceptance

- The ledger and its ruling text permit labelled previews under D8 and still refuse full releases.
- The release gates that read the ledger (for example scripts/check-release-source-gates.py) enforce the distinction, with a test for each case.

## Log
- 2026-10-09T15:24:04Z connor: created
