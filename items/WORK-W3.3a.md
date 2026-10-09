---
id: "WORK-W3.3a"
title: "W3: the `chio work` CLI"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W2.1a"]
paths: ["crates/products/chio-cli/src/cli/work.rs", "crates/products/chio-cli/src/cli/types/work.rs", "crates/products/chio-cli/src/cli/types.rs", "crates/products/chio-cli/src/cli/dispatch/mod.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Subcommands `init`, `serve`, `submit`, `inspect`, `collect`, `export`. `cli/types.rs` (`Commands`) and `dispatch/mod.rs` are shared CLI serialization points.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- CLI integration tests cover each subcommand against a local owner service.

## Log
- 2026-10-09T04:51:58Z connor: created
