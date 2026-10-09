---
id: "WORK-W2.2.P"
title: "W2.2 prototype: remote co-sign and durable bilateral delivery (riskiest piece)"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-G.1", "CT-CROSS.2"]
paths: ["labs/work-cosign-prototype/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Roadmap: section 5 ("the two riskiest unproven pieces get the largest swarm allocation and the earliest prototypes: #1179's rebase and requalification; WORK-W2.2's durable bilateral delivery"); W2.2 "has not yet succeeded in a composed run". Build a standalone lab with two processes and no shared keys over CT-CROSS HTTPS (D4 recommendation): kill the co-signer after local completion, reopen, re-request the same statement; lose the response after the remote commit. Feeds CT-CROSS hardening and COOP-3.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `labs/work-cosign-prototype/RESULTS.md` records: one tool call, no second payment, honest `Pending` state, across every kill point; the lab's tests pass with `cargo test --manifest-path labs/work-cosign-prototype/Cargo.toml`.

## Log
- 2026-10-09T04:51:58Z connor: created
