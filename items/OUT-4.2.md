---
id: "OUT-4.2"
title: "Machine-readable gate claim registry with ADR-0011 fields"
severity: "P1"
wave: 2
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["OUT-4.1"]
paths: ["docs/records/gate-claims.yaml", "scripts/check-gate-claims.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: rule 3 (every planning item touching a trust boundary carries `boundary_class` and `planning_status`; anything claimed as shipped also carries qualification status), section 5 "Claims each gate permits", ADR-0011 (`docs/adr/ADR-0011-boundary-taxonomy-product-wording.md`, which asks for these fields but has no registry). Encode the section 5 claim table (G1 to G5 and After G5 rows) with `boundary_class`, `planning_status`, the contract or ADR each depends on, and a `qualification` field (initially `unqualified`). The checker rejects unknown enum values and any claim marked shipped without qualification evidence.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/check-gate-claims.py` validates the file; tests cover bad enum, shipped-without-qualification, and missing dependency.
- Every row of roadmap section 5's claim table is present verbatim in meaning.

## Log
- 2026-10-09T04:51:58Z connor: created
