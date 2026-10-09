---
id: "WORK-W1.0"
title: "W1.0: INTEGRATION.md inventory of real constructors and ports"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-C.1", "WORK-SLICE-B.2", "WORK-SLICE-B.4", "CT-WORK.1"]
paths: ["docs/research/work-abstraction/INTEGRATION.md", "docs/research/work-abstraction/CURRENT-STATE.md", "docs/research/work-abstraction/SOURCES.json"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Roadmap: WORK-W1.0 ("creates `docs/research/work-abstraction/INTEGRATION.md`, the inventory of real constructors and ports"). Record real constructors and line references on post-#1160 main plus beta: `crates/kernel/chio-runtime/src/{lib,stores}.rs` (no `[features]` yet; `work` feature is new), `SqliteAuthorityStore` (`chio-store-sqlite/src/serving_owner.rs:294`), `WorkerService` and `InvocationPreparer` (`chio-process/src/worker.rs:46,55`), `ProcessRuntime` (`lib.rs:76`), `BilateralCoSigningProtocol` (`chio-federation/src/bilateral.rs:368`), `TreatyScope` (`treaty.rs:79`), `mint_swarm_join_receipt` (`chio-swarm-authority/src/verifier.rs:378`), the `ToolCallRequest` field/digest/custody table (`chio-kernel/src/runtime.rs`), SDK packages `sdks/python/chio-process` and `sdks/typescript/packages/process` (`@chio-protocol/process`). Record which recovery seams are still pending (real names per CT-WORK.1), choose aggregate bounds, record feature trees.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The plan's baseline commands pass on main plus beta: `cargo test --locked -p chio-workflow`, `cargo test --locked -p chio-runtime-core --test runtime_admission`, `cargo test --locked -p chio-kernel --features admission-test-support --test dynamic_delegation`; every line reference in INTEGRATION.md resolves (script in PR).

## Log
- 2026-10-09T04:51:58Z connor: created
