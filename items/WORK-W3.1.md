---
id: "WORK-W3.1"
title: "W3: work profile across protocols (MCP, A2A, ACP)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W2.1a", "REL-2.2"]
paths: ["crates/protocol/chio-cross-protocol/src/work_profile.rs", "crates/protocol/chio-cross-protocol/src/lifecycle.rs", "crates/protocol/chio-cross-protocol/src/semantic_hints.rs", "crates/protocol/chio-cross-protocol/src/lib.rs", "crates/protocol/chio-cross-protocol/tests/work_contract.rs", "fixtures/work-contract/*.json", "docs/standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Map `chio.work.v1` onto the cross-protocol lifecycle and semantic hints.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cross-protocol --test work_contract` passes; the qualification matrix rows validate.

## Log
- 2026-10-09T04:51:58Z connor: created
