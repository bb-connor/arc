---
id: "KSPEC-07.BK"
title: "ConfinementBackendKind and ConfinementRecord projection in code (incl. AgentHostBwrap, Seatbelt)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-07.AMEND", "KSPEC-07.S2a"]
paths: ["crates/security/chio-security-types/src/confinement_record.rs", "crates/security/chio-security-types/src/lib.rs", "spec/schemas/chio-wire/v1/security/confinement-record-v1.schema.json", "tests/bindings/vectors/security/confinement/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-5 (KSPEC-07 steps 1 and 2, plus `AgentHostBwrap` and `Seatbelt` backend kinds, before any HOST-M2 isolation claim). Spec: `docs/superpowers/specs/2026-10-04-microkernel-isolation-backend-design.md` (KSPEC-07). G3 requires isolation evidence recorded by KSPEC-07 kind; the Linux launchers (REL-3.2, REL-3.3) emit these records.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Proptest projection determinism; `FullyEnforced` rejected when any surface is `SameDomain`; closed enum with `deny_unknown_fields`.

## Log
- 2026-10-09T04:51:58Z connor: created
