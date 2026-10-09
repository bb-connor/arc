---
id: "CT-WIRE.1"
title: "CT-WIRE freeze-list inventory and checker"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["spec/versions/chio-preview-freeze.v0.json", "scripts/check-preview-freeze.py", "scripts/tests/check-preview-freeze.test.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-WIRE ("the freeze list for the preview window: receipt, capability, passport, challenge, issuance, evidence and co-sign bytes; process ABI v4; `chio.work.v1`"). Current state on #1160: receipt (`chio.receipt.v1`, `spec/schemas/chio-wire/v1/receipt/record.schema.json`, vectors `tests/bindings/vectors/receipt/v1.json`) and capability (`chio.capability.v1`, `chio-wire/v1/capability/token.schema.json`, vectors) are covered; passport (`chio.agent-passport.v1`), challenge (`chio.agent-passport-presentation-challenge.v1`/`-response.v1`), issuance (unversioned `FederatedIssueRequest/Response` plus `chio.federated-delegation-policy.v1`), evidence (`chio.evidence_export_manifest.v1` and siblings) and co-sign predicate (`chio.bilateral-cosign-invocation.v1`) have no schema or vectors. `spec/wire-schemas.lock` says it is "not a compatibility statement" and 166 of 527 identifier constants are unpinned. Create the inventory with identifiers, schema, vectors, conformance tests, status (`frozen | gap | pending-contract`) and owner item; every identifier must be in `spec/wire-schemas.lock`. The preview version lives here, not in `spec/schemas/VERSION`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/check-preview-freeze.py` passes in draft mode; `--publish` fails while any gap remains; `python3 scripts/tests/check-preview-freeze.test.py` covers a mutated frozen schema (fails) and an added identifier (passes).

## Log
- 2026-10-09T04:51:58Z connor: created
