---
id: "WORK-W1.1b"
title: "W1.1: WorkClient facade in chio-runtime"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W1.1a", "WORK-SLICE-B.4"]
paths: ["crates/kernel/chio-runtime/Cargo.toml", "crates/kernel/chio-runtime/src/lib.rs", "crates/kernel/chio-runtime/src/stores.rs", "crates/kernel/chio-runtime/src/work.rs", "crates/kernel/chio-runtime/tests/work_public_surface.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). `WorkClient<T: WorkTransport>`, bounded byte wrappers and the `extend_swarm_authority_bundle` wrapper behind a new `work` feature. Compile-fail tests prove callers cannot construct `WorkSession` or verified bindings.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test --locked -p chio-runtime --features work --test work_public_surface` and `--test runtime_boundary` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
