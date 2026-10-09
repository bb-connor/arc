---
id: "WORK-W1.1a"
title: "W1.1: checked work contracts in runtime-core"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-WORK.3", "WORK-W1.0"]
paths: ["crates/kernel/chio-runtime-core/Cargo.toml", "crates/kernel/chio-runtime-core/src/lib.rs", "crates/kernel/chio-runtime-core/src/work/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Roadmap: WORK-W1 (W1.1 to W1.4). Closed variants, checked constructors, rejection codes, 64/65 profile vectors, the unpaid Agreement (CT-WORK.3). Types must round-trip CT-WORK.2 vectors.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- CT-WORK vectors pass through the Rust types; nested duplicate keys and unknown variants are rejected (`cargo test -p chio-runtime-core work::`).

## Log
- 2026-10-09T04:51:58Z connor: created
