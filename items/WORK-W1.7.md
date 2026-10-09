---
id: "WORK-W1.7"
title: "W1.7: public client conversion and programming docs"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W1.5b", "WORK-W1.6b", "WORK-W1.1b"]
paths: ["crates/kernel/chio-runtime/README.md", "crates/kernel/chio-runtime/ARCHITECTURE.md", "docs/reference/WORK_PROGRAMMING.md", "examples/work-client/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Write a new `examples/work-client` instead of editing #1173's federated-work example (slice delta).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The plan's clippy command across all three features, `cargo fmt --all -- --check`, and a feature-graph comparison against W1.0 pass.

## Log
- 2026-10-09T04:51:58Z connor: created
