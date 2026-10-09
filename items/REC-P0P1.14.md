---
id: "REC-P0P1.14"
title: "Control-plane recovery runtime, command-pool P1 and KDEF-N15 fixes"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P0P1.10", "REC-P0P1.11", "REC-P0P1.13"]
paths: ["crates/platform/chio-control-plane/src/recovery/runtime*", "crates/platform/chio-control-plane/src/recovery/runtime/**", "crates/platform/chio-control-plane/src/recovery/command_executor*", "crates/platform/chio-control-plane/src/recovery/transport*", "crates/platform/chio-control-plane/src/recovery/connector*", "crates/platform/chio-control-plane/src/recovery/settlement.rs", "crates/platform/chio-control-plane/src/recovery/actor_authentication.rs", "crates/platform/chio-control-plane/src/recovery/native_store_errors.rs", "crates/platform/chio-control-plane/src/recovery/materialize.rs", "crates/platform/chio-control-plane/src/security/adapters/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. Port the 8 modify/delete adapter files to #1160's current locations. Move `recovery/runtime/native_work.rs:16`, `recovery/materialize.rs:25` and `recovery/transport/authentication.rs:118` onto `kernel.authority_clock()` (KDEF-N15; KDEF-CLOCK-GATE enforces). Command-pool P1 (greptile thread at `native_work.rs:44`): a source fix exists (`CommandExecutor::shared_provider_finality()`, `command_executor.rs:131`, used by `execute_settlement`); verify, then resolve the thread. Trust-control recovery hooks go in a dedicated router fragment if routes are needed.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `saturated_commands_keep_reserved_native_data_work_available` passes; `python3 scripts/check-security-clocks.py` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
