---
id: "OUT-4.1"
title: "Independent-operation record format, template and checker"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["docs/records/README.md", "docs/records/independent-operation-record.schema.json", "docs/records/templates/**", "scripts/check-independent-operation-record.py", "scripts/tests/check-independent-operation-record.test.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: OUT-4, section 1 criteria (a) and (f), G2 exit ("an independent-operation record is published"). Define a record format (JSON Schema plus a Markdown template) for operators, hosts, domains (`chio trust serve` URLs), key fingerprints (authority, receipt-signer, co-signer), key custody backend, Chio version and tag, and harness versions. The checker enforces what can be checked mechanically: no key fingerprint appears under two parties; Backbay is not listed as custodian of an outside party's key; no party holds both co-signer keys (STRAT-F15); every version is a tagged preview (`0.2.0-alpha.N`). Boundary: the record is evidence, `boundary_class: detect_only`, `planning_status: ready_after_adr`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `scripts/tests/check-independent-operation-record.test.py` covers a valid two-party record and each rejected case (shared fingerprint, Backbay custody of partner key, one party with both co-signer keys, untagged version).
- `docs/records/README.md` explains how G2, G4 and G5 records are filed and reviewed against ADR-0011.

## Log
- 2026-10-09T04:51:58Z connor: created
