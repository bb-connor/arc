---
id: "KSPEC-07.S2a"
title: "Signed container launch record (KSPEC-07 5.3, KDEF-N9)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-07.AMEND"]
paths: ["crates/products/chio-cli/src/cli/process_host/runner/container.rs", "crates/products/chio-cli/PROCESS_CONTAINERS.md", "spec/schemas/chio-wire/v1/security/process-container-launch-v1.schema.json"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-5 (KSPEC-07 steps 1 and 2, plus `AgentHostBwrap` and `Seatbelt` backend kinds, before any HOST-M2 isolation claim). Spec: `docs/superpowers/specs/2026-10-04-microkernel-isolation-backend-design.md` (KSPEC-07). Decision gate: KSPEC-07 open decision 2 (launch record signer; spec recommendation: a dedicated runner identity registered as a KSPEC-01 component) is parked (UR-PK-KSPEC07-SIGNER). Implement against the recommendation; the merge waits for the decision. The runner journal (`runner/journal.rs`) is leased by KERN-3.EXIT; add the record write with a minimal hook.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Single-field comparator rejections; a start failure produces a signed `BootstrapFailed`; no worker call happens before the success record exists.

## Log
- 2026-10-09T04:51:58Z connor: created
