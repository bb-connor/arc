---
id: "OUT-3.1"
title: "WIMSE and ODIS position notes"
severity: "P3"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["DOCS-1171.1"]
paths: ["docs/standards/WIMSE.md", "docs/standards/ODIS.md", "docs/standards/README.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: OUT-3 (WIMSE and ODIS positions; standards bodies get no tagline, artifact names only, section 9). Write two public position notes mapping Chio artifacts (capability, passport, receipt, co-sign, evidence package, partner card) to WIMSE workload identity concepts and to the ODIS profile fields, naming gaps honestly (for example ODIS MUST fields Chio lacks, recorded in #1170's research). Reference interop vectors from CT-WIRE where they exist. No commercial or go-to-market content.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Both notes cite concrete schema paths under `spec/` for every mapped artifact and list open gaps as issues.
- No tagline, no market claims; `python3 scripts/check-native-host-docs.py --rule retired-phrases --rule em-dash` passes on `docs/standards/`.

## Log
- 2026-10-09T04:51:58Z connor: created
