---
id: "WORK-W1.4a"
title: "W1.4: binding validation and allocation"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W1.2a", "WORK-W1.3a"]
paths: ["crates/kernel/chio-runtime-core/src/work/bindings.rs", "crates/platform/chio-control-plane/src/work/allocation.rs", "crates/platform/chio-control-plane/tests/work_allocation.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Port `composition::validate` by reading #1173's `examples/federated-work` (that example is slice delta and will not be on main).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Zero native dispatches for every substitution case in `work_allocation.rs`.

## Log
- 2026-10-09T04:51:58Z connor: created
