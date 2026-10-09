---
id: "CT-ABI.3"
title: "`chio.process.v1` schemas for worker frames and host documents"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-G0-SPECTOOL.1", "CT-ABI.2"]
paths: ["spec/schemas/chio-process/v1/**", "spec/CHIO_PROCESS_ABI.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-ABI ("`chio.process.v1` schemas in `spec/schemas` (39 identifiers are unspecified today)"). The count 39 has no source document; a census of #1160 finds 37 distinct production `"chio.process*"` literals (42 with test-only), none with a schema, mixing wire frames, host documents, evidence documents and digest domains. Hand-write schemas for the request envelope (7 ops, `additionalProperties: false`), ok and error responses with the 12 error codes, the invoke result (verdict, terminal_state, output kinds, `output_withheld`, `receipt_json` as a string), and the host and evidence documents (`host.v1`, `run.v1`, `run-status.v1`, `status.v1`, `logs.v1`, `run-report.v2`, `relocation.v1`, `connection.v1`, `worker-bootstrap.v1`, `swarm-plan.v2`, `swarm-profile.v1`, `call-observation.v3`, `worker-outcomes.v3`, `completed-fanout.v3`, the `*-verification` documents). Digest domains get vectors (CT-ABI.4), not schemas. Kept outside `chio-wire/v1` so codegen outputs do not churn. Classify every literal in `spec/CHIO_PROCESS_ABI.md` (append a table; CT-ABI.2 owns the rest of that file and has landed first).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `bash scripts/check-chio-schema-registry.sh` passes; every production `chio.process*` literal is classified as schema, domain or retired (a script in the PR proves zero unclassified).

## Log
- 2026-10-09T04:51:58Z connor: created
