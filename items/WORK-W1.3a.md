---
id: "WORK-W1.3a"
title: "W1.3: profiles and catalog (no recovery semantics)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W1.1a"]
paths: ["crates/platform/chio-control-plane/Cargo.toml", "crates/platform/chio-control-plane/src/work/mod.rs", "crates/platform/chio-control-plane/src/work/host.rs", "crates/platform/chio-control-plane/src/work/session.rs", "crates/platform/chio-control-plane/src/work/profiles.rs", "crates/platform/chio-control-plane/tests/work_profiles.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Resolve profiles from manifest, treaty, D1 and acceptance sources. The semantic generation stays `Unavailable` until W1.3b (which needs #1179's `SemanticPackageV1`). One `mod work;` line in `chio-control-plane/src/lib.rs`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `resolved_profile_preserves_each_authority_basis`, `catalog_scope_and_generation`, `stale_generation_refuses_resolution`, `remote_claim_is_not_local_enforcement` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
